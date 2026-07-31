#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 3 ]]; then
    exit 64
fi
if [[ -z "${FIREBLOCKS_BRAIN_WRITE_TOKEN:-}" ]]; then
    exit 78
fi

RUN_ID="$1"
ATTEMPT="$2"
COUNT="$3"
for value in "${RUN_ID}" "${ATTEMPT}" "${COUNT}"; do
    [[ "${value}" =~ ^[0-9]+$ ]] || exit 64
done
(( COUNT == 1 || COUNT == 5 || COUNT == 15 || COUNT == 25 )) || exit 64

TMP="$(mktemp -d)"
cleanup() {
    [[ "${TMP}" == /tmp/* ]] && rm -rf -- "${TMP}"
}
trap cleanup EXIT

AUTH_HEADER="AUTHORIZATION: basic $(printf 'x-access-token:%s' \
    "${FIREBLOCKS_BRAIN_WRITE_TOKEN}" | base64 -w0)"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
export GIT_CONFIG_VALUE_0="${AUTH_HEADER}"

STAGE="${TMP}/brain"
git init -q "${STAGE}"
git -C "${STAGE}" remote add origin \
    https://github.com/creador777/fireblocks-mpc-brain.git
git -C "${STAGE}" fetch -q --depth=1 origin corpus-pool
git -C "${STAGE}" checkout -q -b corpus-pool FETCH_HEAD
BASE="$(git -C "${STAGE}" rev-parse HEAD)"
[[ -z "$(git -C "${STAGE}" status --porcelain=v1)" ]]

for (( shard=0; shard<COUNT; shard++ )); do
    branch="ingest/run-${RUN_ID}/attempt-${ATTEMPT}/shard-${shard}"
    ref="refs/remotes/ingest/${shard}"
    git -C "${STAGE}" fetch -q --depth=1 origin \
        "refs/heads/${branch}:${ref}"

    while IFS=$'\t' read -r status path; do
        [[ "${status}" == "A" ]]
        if [[ "${path}" =~ ^corpus/cmp_ecdsa_online/([0-9a-f]{40})$ ]]; then
            name="${BASH_REMATCH[1]}"
            candidate="${TMP}/candidate-${shard}-${name}"
            git -C "${STAGE}" show "${ref}:${path}" > "${candidate}"
            [[ "$(sha1sum "${candidate}" | cut -d' ' -f1)" == "${name}" ]]
            target="${STAGE}/${path}"
            if [[ -e "${target}" ]]; then
                [[ -f "${target}" && ! -L "${target}" ]]
                cmp -s -- "${candidate}" "${target}"
            else
                mkdir -p "$(dirname -- "${target}")"
                cp -- "${candidate}" "${target}"
                chmod 0644 "${target}"
                git -C "${STAGE}" add -- "${path}"
            fi
        elif [[ "${path}" =~ ^incidents/run-${RUN_ID}/attempt-${ATTEMPT}-shard-${shard}\.gpg$ ]]; then
            target="${STAGE}/${path}"
            [[ ! -e "${target}" ]]
            mkdir -p "$(dirname -- "${target}")"
            git -C "${STAGE}" show "${ref}:${path}" > "${target}"
            [[ -s "${target}" && ! -L "${target}" ]]
            chmod 0644 "${target}"
            git -C "${STAGE}" add -- "${path}"
        else
            exit 65
        fi
    done < <(git -C "${STAGE}" diff --name-status --no-renames "${BASE}" "${ref}")
done

git -C "${STAGE}" diff --cached --quiet --diff-filter=DR
! git -C "${STAGE}" diff --cached --quiet
git -C "${STAGE}" -c user.name=fireblocks-hunt \
    -c user.email=noreply@invalid commit -q -m \
    "aggregate run ${RUN_ID} attempt ${ATTEMPT}"
git -C "${STAGE}" push -q origin HEAD:refs/heads/corpus-pool
