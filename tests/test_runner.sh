#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${1:-${ROOT}/scripts/run_fuzzer_shard.sh}"
TMP="$(mktemp -d)"
BIN_ROOT="${FAKE_EXEC_ROOT:-${BIN_ROOT}}"
trap 'rm -rf -- "${TMP}"' EXIT

mkdir -p "${BIN_ROOT}" "${TMP}/corpus" "${TMP}/out"
printf 'synthetic\n' > "${TMP}/corpus/unit"

cat > "${BIN_ROOT}/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${FAKE_DOCKER_ARGS}"
printf 'Base64:SYNTHETIC_PRIVATE_ONLY\n'
exit "${FAKE_DOCKER_RC:-0}"
FAKE
chmod +x "${BIN_ROOT}/docker"

expect_rc() {
    local expected="$1"
    shift
    local actual
    set +e
    PATH="${BIN_ROOT}:${PATH}" FAKE_DOCKER_ARGS="${TMP}/docker.args" \
        "${RUNNER}" "$@" >"${TMP}/public.out" 2>"${TMP}/public.err"
    actual=$?
    set -e
    [[ "${actual}" -eq "${expected}" ]]
}

expect_rc 64 image abc 60 "${TMP}/corpus" "${TMP}/out-invalid-shard"
[[ ! -e "${TMP}/docker.args" ]]
expect_rc 64 image 0 nope "${TMP}/corpus" "${TMP}/out-invalid-seconds"
expect_rc 64 image 0 59 "${TMP}/corpus" "${TMP}/out-short-seconds"
expect_rc 64 image 0 20701 "${TMP}/corpus" "${TMP}/out-long-seconds"

ln -s "${TMP}/corpus" "${TMP}/corpus-link"
expect_rc 65 image 0 60 "${TMP}/corpus-link" "${TMP}/out-corpus-link"

mkdir -p "${TMP}/parent-real/corpus"
ln -s "${TMP}/parent-real" "${TMP}/parent-link"
expect_rc 65 image 0 60 "${TMP}/parent-link/corpus" "${TMP}/out-parent-link"

mkdir -p "${TMP}/output-real"
ln -s "${TMP}/output-real" "${TMP}/output-link"
expect_rc 65 image 0 60 "${TMP}/corpus" "${TMP}/output-link"

rm -f "${TMP}/docker.args"
set +e
PATH="${BIN_ROOT}:${PATH}" \
FAKE_DOCKER_ARGS="${TMP}/docker.args" \
FAKE_DOCKER_RC=77 \
    "${RUNNER}" image 4 60 "${TMP}/corpus" "${TMP}/out-finding" \
    >"${TMP}/public.out" 2>"${TMP}/public.err"
RUN_RC=$?
set -e
[[ "${RUN_RC}" -eq 77 ]]
[[ "$(cat "${TMP}/out-finding/private_plain/exit_code")" == "77" ]]
[[ "$(cat "${TMP}/public.out")" == "SHARD_RUN_COMPLETE shard=4 exit_code=77" ]]
! grep -q 'Base64:' "${TMP}/public.out"
grep -q 'Base64:SYNTHETIC_PRIVATE_ONLY' \
    "${TMP}/out-finding/private_plain/fuzzer.raw.log"

for argument in \
    --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --memory 12g --cpus 4 /work/corpus; do
    grep -Fxq -- "${argument}" "${TMP}/docker.args"
done

printf 'RUNNER_SECURITY_TESTS_PASS cases=8\n'
