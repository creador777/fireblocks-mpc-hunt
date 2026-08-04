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
CORPUS_INPUT="$1"
BUNDLE_INPUT="$2"
RUN_ID="$3"
ATTEMPT="$4"
SHARD="$5"
# Sexto argumento: la SUPERFICIE. Cada lane escribe en su propio subarbol
# de corpus y en su propio espacio de incidentes. Un corpus t<n dentro de
# la lane n=n no es mas corpus: es otro fixture, y mezclarlos invalida
# las dos superficies.
HARNESS="$6"
case "${HARNESS}" in
    cmp_ecdsa_online|cmp_ecdsa_online_r4_tn) ;;
    *) exit 64 ;;
esac

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

DESTINATION="${STAGE}/corpus/${HARNESS}"
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
        git -C "${STAGE}" add -- "corpus/${HARNESS}/${name}"
    fi
done < <(find "${TMP}/validated" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z)

INCIDENT_DIRECTORY="${STAGE}/incidents/run-${RUN_ID}"
INCIDENT_NAME="${HARNESS}-attempt-${ATTEMPT}-shard-${SHARD}.gpg"
mkdir -p "${INCIDENT_DIRECTORY}"
[[ ! -e "${INCIDENT_DIRECTORY}/${INCIDENT_NAME}" ]]
cp -- "${BUNDLE_FILE}" "${INCIDENT_DIRECTORY}/${INCIDENT_NAME}"
chmod 0644 "${INCIDENT_DIRECTORY}/${INCIDENT_NAME}"
git -C "${STAGE}" add -- "incidents/run-${RUN_ID}/${INCIDENT_NAME}"

git -C "${STAGE}" diff --cached --quiet --diff-filter=DR
while IFS=$'\t' read -r status path; do
    [[ "${status}" == "A" ]]
    [[ "${path}" =~ ^corpus/"${HARNESS}"/[0-9a-f]{40}$ ||
       "${path}" =~ ^incidents/run-[0-9]+/attempt-[0-9]+-shard-[0-9]+\.gpg$ ]]
done < <(git -C "${STAGE}" diff --cached --name-status --no-renames)
! git -C "${STAGE}" diff --cached --quiet

git -C "${STAGE}" -c user.name=fireblocks-hunt \
    -c user.email=noreply@invalid commit -q -m \
    "ingest run ${RUN_ID} attempt ${ATTEMPT} shard ${SHARD}"

BRANCH="ingest/run-${RUN_ID}/attempt-${ATTEMPT}/${HARNESS}/shard-${SHARD}"
git -C "${STAGE}" push -q origin "HEAD:refs/heads/${BRANCH}"
