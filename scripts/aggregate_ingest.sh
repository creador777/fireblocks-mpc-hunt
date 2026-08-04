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

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Misma autoridad que el publicador. El agregador NO interpreta rutas por
# su cuenta: pregunta a quien las genero.
. "${ROOT}/scripts/brain_paths.sh"

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

# Se enumeran las ramas de ingesta REALES del remoto y se interpreta cada
# una con parse_branch. Construir el nombre esperado a mano fue lo que
# hizo que el agregador buscara una rama que el publicador ya no escribia.
#
# Una ref DENTRO de ingest/ que no case el formato canonico es
# fail-closed: es corpus publicado que nadie sabe leer, y saltarsela lo
# perderia en silencio. Las de fuera de ingest/ se ignoran.
mapfile -t ALL_REFS < <(git -C "${STAGE}" ls-remote --heads origin \
    'refs/heads/ingest/*' | awk '{print $2}' | sed 's|^refs/heads/||')
declare -i matched=0
for branch in "${ALL_REFS[@]}"; do
    tuple="$(parse_branch "${branch}")" || exit 65
    read -r b_run b_attempt b_harness b_shard <<<"${tuple}"
    [[ "${b_run}" == "${RUN_ID}" && "${b_attempt}" == "${ATTEMPT}" ]] ||
        continue
    matched+=1
    shard="${b_shard}"
    ref="refs/remotes/ingest/${b_harness}-${b_shard}"
    git -C "${STAGE}" fetch -q --depth=1 origin \
        "refs/heads/${branch}:${ref}"

    # Contribution = entries in the branch tree that the pool does not
    # already have. Both trees are enumerated with ls-tree instead of
    # diffing against BASE: an ingest branch is pinned to the brain_sha the
    # plan job resolved, so whenever another wave merges first the branch is
    # based on an older pool and a diff would report a 'D' for every unit
    # the pool gained since, aborting the sweep precisely on the branches
    # that need rescuing.
    #
    # Correct because the pool is append-only and content-addressed: a path
    # the pool already holds with the same oid is skipped; the same path
    # with a different oid is a modification and stays inexpressible
    # (exit 65). Paths the pool holds but the branch lacks are NOT deletions
    # by the branch (it is simply older) and ignoring them is safe: those
    # units stay in the pool.
    declare -A base_oid=()
    while IFS=$'\t' read -r meta path; do
        base_oid["${path}"]="${meta##* }"
    done < <(git -C "${STAGE}" ls-tree -r --full-tree "${BASE}")

    while IFS=$'\t' read -r meta path; do
        mode="${meta%% *}"
        rest="${meta#* }"
        otype="${rest%% *}"
        oid="${rest##* }"
        [[ "${mode}" == "100644" && "${otype}" == "blob" ]] || exit 65
        if [[ -v "base_oid[${path}]" ]]; then
            [[ "${base_oid[${path}]}" == "${oid}" ]] || exit 65
            continue
        fi
        # Misma pregunta a la autoridad, no una regex paralela.
        if [[ "${path}" == corpus/* ]]; then
            name="${path##*/}"
            [[ "${path}" == "$(corpus_unit_for "${b_harness}" \
                "${name}")" ]] || exit 65
            candidate="${TMP}/candidate-${shard}-${name}"
            git -C "${STAGE}" cat-file blob "${oid}" > "${candidate}"
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
        elif [[ "${path}" == "$(incident_for "${RUN_ID}" "${ATTEMPT}" \
            "${b_harness}" "${b_shard}")" ]]; then
            target="${STAGE}/${path}"
            [[ ! -e "${target}" ]]
            mkdir -p "$(dirname -- "${target}")"
            git -C "${STAGE}" cat-file blob "${oid}" > "${target}"
            [[ -s "${target}" && ! -L "${target}" ]]
            chmod 0644 "${target}"
            git -C "${STAGE}" add -- "${path}"
        else
            exit 65
        fi
    done < <(git -C "${STAGE}" ls-tree -r --full-tree "${ref}")
done

git -C "${STAGE}" diff --cached --quiet --diff-filter=DR
! git -C "${STAGE}" diff --cached --quiet
git -C "${STAGE}" -c user.name=fireblocks-hunt \
    -c user.email=noreply@invalid commit -q -m \
    "aggregate run ${RUN_ID} attempt ${ATTEMPT}"
git -C "${STAGE}" push -q origin HEAD:refs/heads/corpus-pool
