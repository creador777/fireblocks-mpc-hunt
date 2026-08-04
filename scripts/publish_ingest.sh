#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 6 ]]; then
    exit 64
fi
if [[ -z "${FIREBLOCKS_BRAIN_WRITE_TOKEN:-}" ]]; then
    exit 78
fi

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Autoridad UNICA de rutas. Este script no construye ninguna por su
# cuenta: si lo hiciera, podria volver a divergir del agregador, que es
# exactamente lo que rompio el canary del run 30868170486.
. "${ROOT}/scripts/brain_paths.sh"
CORPUS_INPUT="$1"
BUNDLE_INPUT="$2"
RUN_ID="$3"
ATTEMPT="$4"
SHARD="$5"
# La lane es la entrada; el harness se deriva. Nunca se aceptan juntos.
LANE="$6"
HARNESS="$(lane_to_harness "${LANE}")" || exit 64

for value in "${RUN_ID}" "${ATTEMPT}" "${SHARD}"; do
    [[ "${value}" =~ ^[0-9]+$ ]] || exit 64
done
(( SHARD >= 0 && SHARD < 25 )) || exit 64
[[ -d "${CORPUS_INPUT}" && ! -L "${CORPUS_INPUT}" ]] || exit 65
[[ -f "${BUNDLE_INPUT}" && ! -L "${BUNDLE_INPUT}" ]] || exit 65
[[ "$(basename -- "${BUNDLE_INPUT}")" =~ ^incident-[0-9]+-[0-9]+-[0-9]+\.gpg$ ]] ||
    exit 65

CORPUS_LOGICAL="$(realpath -e -s -- "${CORPUS_INPUT}")"
CORPUS_DIR="$(realpath -e -- "${CORPUS_INPUT}")"
BUNDLE_LOGICAL="$(realpath -e -s -- "${BUNDLE_INPUT}")"
BUNDLE_FILE="$(realpath -e -- "${BUNDLE_INPUT}")"
[[ "${CORPUS_LOGICAL}" == "${CORPUS_DIR}" ]] || exit 65
[[ "${BUNDLE_LOGICAL}" == "${BUNDLE_FILE}" ]] || exit 65

TMP="$(mktemp -d)"
cleanup() {
    [[ "${TMP}" == /tmp/* ]] && rm -rf -- "${TMP}"
}
trap cleanup EXIT

mkdir "${TMP}/validated"
python3 "${ROOT}/scripts/materialize_corpus.py" \
    "${TMP}/validated" "${CORPUS_DIR}"

GPG_HOME="${TMP}/gpg"
mkdir -m 700 "${GPG_HOME}"
gpg --homedir "${GPG_HOME}" --batch --no-tty \
    --import-options import-minimal --import \
    "${ROOT}/keys/artifact-recipient.asc" >/dev/null 2>&1
gpg --homedir "${GPG_HOME}" --batch --no-tty \
    --list-only --decrypt "${BUNDLE_FILE}" >/dev/null 2>&1

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
git -C "${STAGE}" checkout -q -b candidate FETCH_HEAD
[[ -z "$(git -C "${STAGE}" status --porcelain=v1)" ]]

CORPUS_REL="$(corpus_dir_for "${HARNESS}")" || exit 64
DESTINATION="${STAGE}/${CORPUS_REL}"
mkdir -p "${DESTINATION}"
while IFS= read -r -d '' source; do
    name="$(basename -- "${source}")"
    target="${DESTINATION}/${name}"
    if [[ -e "${target}" ]]; then
        [[ -f "${target}" && ! -L "${target}" ]]
        cmp -s -- "${source}" "${target}"
    else
        cp -- "${source}" "${target}"
        chmod 0644 "${target}"
        unit_rel="$(corpus_unit_for "${HARNESS}" "${name}")" || exit 65
        git -C "${STAGE}" add -- "${unit_rel}"
    fi
done < <(find "${TMP}/validated" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z)

INCIDENT_REL="$(incident_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" \
    "${SHARD}")" || exit 64
mkdir -p "${STAGE}/$(dirname -- "${INCIDENT_REL}")"
[[ ! -e "${STAGE}/${INCIDENT_REL}" ]]
cp -- "${BUNDLE_FILE}" "${STAGE}/${INCIDENT_REL}"
chmod 0644 "${STAGE}/${INCIDENT_REL}"
git -C "${STAGE}" add -- "${INCIDENT_REL}"

git -C "${STAGE}" diff --cached --quiet --diff-filter=DR
while IFS=$'\t' read -r status path; do
    [[ "${status}" == "A" ]]
    # Sin regex propia: se pregunta a la autoridad si la ruta es una que
    # ella misma habria generado.
    if [[ "${path}" == corpus/* ]]; then
        [[ "${path}" == "$(corpus_unit_for "${HARNESS}" \
            "${path##*/}")" ]]
    else
        parse_incident "${path}" > /dev/null
    fi
done < <(git -C "${STAGE}" diff --cached --name-status --no-renames)
! git -C "${STAGE}" diff --cached --quiet

git -C "${STAGE}" -c user.name=fireblocks-hunt \
    -c user.email=noreply@invalid commit -q -m \
    "ingest run ${RUN_ID} attempt ${ATTEMPT} shard ${SHARD}"

BRANCH="$(branch_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")" ||
    exit 64
git -C "${STAGE}" push -q origin "HEAD:refs/heads/${BRANCH}"
