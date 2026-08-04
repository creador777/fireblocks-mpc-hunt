#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${PUBLISH_TEST_ROOT:-/lab}"
REMOTE="${LAB}/brain.git"
HOME_DIR="${LAB}/home"
SEED="${LAB}/seed"
CORPUS="${LAB}/corpus"
OUTPUT="${LAB}/output"
TOKEN="synthetic-test-token"
RUN_ID=9001
ATTEMPT=1
SHARD=0

mkdir -p "${HOME_DIR}" "${SEED}" "${CORPUS}" "${OUTPUT}"
export HOME="${HOME_DIR}"

git config --global user.name synthetic-test
git config --global user.email synthetic@example.invalid
git config --global protocol.file.allow always
git config --global \
    url."file://${REMOTE}".insteadOf \
    "https://github.com/creador777/fireblocks-mpc-brain.git"

git init -q --bare "${REMOTE}"
git init -q "${SEED}"
printf 'private brain test\n' > "${SEED}/README.md"
git -C "${SEED}" add -- README.md
git -C "${SEED}" commit -q -m seed
git -C "${SEED}" branch -M corpus-pool
git -C "${SEED}" remote add origin "file://${REMOTE}"
git -C "${SEED}" push -q origin corpus-pool

printf 'synthetic-valid-corpus\n' > "${LAB}/valid"
VALID_NAME="$(sha1sum "${LAB}/valid" | cut -d' ' -f1)"
cp -- "${LAB}/valid" "${CORPUS}/${VALID_NAME}"

PRIVATE="${LAB}/private_plain"
mkdir "${PRIVATE}"
printf 'synthetic private log\n' > "${PRIVATE}/fuzzer.raw.log"
printf '0\n' > "${PRIVATE}/exit_code"
BUNDLE="${OUTPUT}/incident-${RUN_ID}-${ATTEMPT}-${SHARD}.gpg"
python3 "${ROOT}/scripts/package_incident.py" \
    "${PRIVATE}" \
    "${ROOT}/keys/artifact-recipient.asc" \
    "${ROOT}/keys/artifact-recipient.fingerprint" \
    "${BUNDLE}"
test -s "${BUNDLE}"
test ! -e "${PRIVATE}"

set +e
"${ROOT}/scripts/publish_ingest.sh" \
    "${CORPUS}" "${BUNDLE}" "${RUN_ID}" "${ATTEMPT}" "${SHARD}" cmp_general
NO_TOKEN_RC=$?
set -e
test "${NO_TOKEN_RC}" -eq 78
test -z "$(git --git-dir="${REMOTE}" for-each-ref \
    --format='%(refname)' refs/heads/ingest/)"

FIREBLOCKS_BRAIN_WRITE_TOKEN="${TOKEN}" \
    "${ROOT}/scripts/publish_ingest.sh" \
    "${CORPUS}" "${BUNDLE}" "${RUN_ID}" "${ATTEMPT}" "${SHARD}" cmp_general

# La ref esperada la genera la autoridad de rutas. Construirla a
# mano aqui reintroduciria, dentro de un test, el mismo defecto que
# rompio el canary: un segundo generador que puede divergir.
. "${ROOT}/scripts/brain_paths.sh"
HARNESS="$(lane_to_harness cmp_general)"
INGEST_REF="refs/heads/$(branch_for "${RUN_ID}" "${ATTEMPT}" \
    "${HARNESS}" "${SHARD}")"
test -n "$(git --git-dir="${REMOTE}" rev-parse --verify "${INGEST_REF}")"
INGEST_BEFORE="$(git --git-dir="${REMOTE}" rev-parse "${INGEST_REF}")"

mapfile -t INGEST_PATHS < <(
    git --git-dir="${REMOTE}" ls-tree -r --name-only "${INGEST_REF}" | sort
)
EXPECTED_INGEST=(
    "README.md"
    "$(corpus_unit_for "${HARNESS}" "${VALID_NAME}")"
    "$(incident_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")"
)
test "${INGEST_PATHS[*]}" = "${EXPECTED_INGEST[*]}"
while read -r mode type _ path; do
    test "${type}" = blob
    test "${mode}" = 100644
    # Las rutas permitidas las genera la autoridad. Escribirlas a mano aqui
    # reintroduciria, dentro de un test, el defecto que rompio el canary: un
    # segundo generador capaz de divergir del real.
    case "${path}" in
        README.md|\
"$(corpus_unit_for "${HARNESS}" "${VALID_NAME}")"|\
"$(incident_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")")
            ;;
        *)
            exit 1
            ;;
    esac
done < <(git --git-dir="${REMOTE}" ls-tree -r "${INGEST_REF}")

FIREBLOCKS_BRAIN_WRITE_TOKEN="${TOKEN}" \
    "${ROOT}/scripts/aggregate_ingest.sh" \
    "${RUN_ID}" "${ATTEMPT}" 1

POOL_REF="refs/heads/corpus-pool"
POOL_AFTER="$(git --git-dir="${REMOTE}" rev-parse "${POOL_REF}")"
test "${POOL_AFTER}" != "$(git -C "${SEED}" rev-parse HEAD)"
test "$(git --git-dir="${REMOTE}" show \
    "${POOL_REF}:$(corpus_unit_for "${HARNESS}" "${VALID_NAME}")" | sha1sum | cut -d' ' -f1)" \
    = "${VALID_NAME}"
test -n "$(git --git-dir="${REMOTE}" show \
    "${POOL_REF}:$(incident_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")" |
    sha256sum | cut -d' ' -f1)"

set +e
FIREBLOCKS_BRAIN_WRITE_TOKEN="${TOKEN}" \
    "${ROOT}/scripts/publish_ingest.sh" \
    "${CORPUS}" "${BUNDLE}" "${RUN_ID}" "${ATTEMPT}" "${SHARD}" cmp_general
COLLISION_RC=$?
set -e
test "${COLLISION_RC}" -ne 0
test "$(git --git-dir="${REMOTE}" rev-parse "${INGEST_REF}")" = "${INGEST_BEFORE}"
test "$(git --git-dir="${REMOTE}" rev-parse "${POOL_REF}")" = "${POOL_AFTER}"

BAD_CORPUS="${LAB}/bad-corpus"
mkdir "${BAD_CORPUS}"
printf 'wrong content\n' > \
    "${BAD_CORPUS}/0000000000000000000000000000000000000000"
set +e
FIREBLOCKS_BRAIN_WRITE_TOKEN="${TOKEN}" \
    "${ROOT}/scripts/publish_ingest.sh" \
    "${BAD_CORPUS}" "${BUNDLE}" 9002 1 0 cmp_general
BAD_HASH_RC=$?
set -e
test "${BAD_HASH_RC}" -ne 0
test -z "$(git --git-dir="${REMOTE}" for-each-ref \
    --format='%(refname)' refs/heads/ingest/run-9002/)"

ln -s "${CORPUS}" "${LAB}/corpus-link"
set +e
FIREBLOCKS_BRAIN_WRITE_TOKEN="${TOKEN}" \
    "${ROOT}/scripts/publish_ingest.sh" \
    "${LAB}/corpus-link" "${BUNDLE}" 9003 1 0 cmp_general
SYMLINK_RC=$?
set -e
test "${SYMLINK_RC}" -eq 65

printf 'PRIVATE_PUBLISH_TESTS_PASS cases=7 paths=%s\n' \
    "${#INGEST_PATHS[@]}"
