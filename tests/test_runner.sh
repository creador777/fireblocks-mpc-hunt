#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${1:-${ROOT}/scripts/run_fuzzer_shard.sh}"
TMP="$(mktemp -d)"
BIN_ROOT="${FAKE_EXEC_ROOT:-${BIN_ROOT}}"
trap 'rm -rf -- "${TMP}"' EXIT

mkdir -p "${BIN_ROOT}" "${TMP}/corpus" "${TMP}/out"
printf 'synthetic\n' > "${TMP}/corpus/unit"

# El ciclo actual del runner es run -> inspect -> rm -f (sin --rm), con una
# limpieza previa de contenedores rezagados. El fake registra CADA invocacion
# en un fichero propio, numerado en orden, en vez de sobrescribir un unico
# archivo: asi las banderas del `run` no se pierden tras el `rm -f` final.
# Ademas responde a `inspect` como Docker de verdad (true/false para
# .State.OOMKilled) y solo escribe el marcador privado en el `run`, que es
# donde el runner captura el log crudo.
cat > "${BIN_ROOT}/docker" <<'FAKE'
#!/usr/bin/env bash
dir="${FAKE_DOCKER_ARGS}.d"
mkdir -p "${dir}"
n="$(find "${dir}" -type f | wc -l)"
printf '%s\n' "$@" > "${dir}/$(printf '%03d' "${n}")"
case "${1:-}" in
    inspect)
        printf '%s\n' "${FAKE_DOCKER_OOM_KILLED:-false}"
        ;;
    run)
        printf 'Base64:SYNTHETIC_PRIVATE_ONLY\n'
        ;;
esac
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
[[ ! -e "${TMP}/docker.args" && ! -d "${TMP}/docker.args.d" ]]
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
rm -rf "${TMP}/docker.args.d"
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
# El estado del contenedor se leyo y quedo registrado (inspect respondio
# false: no hubo OOM de cgroup en esta corrida).
[[ "$(cat "${TMP}/out-finding/private_plain/oom_killed")" == "false" ]]

# Clasificar las invocaciones por subcomando y exigir el ciclo completo:
# rm -f (limpieza previa) -> run -> inspect -> rm -f (borrado final).
shopt -s nullglob
RUN_FILE=""
INSPECT_FILE=""
RM_FILES=()
for f in "${TMP}/docker.args.d"/0*; do
    case "$(head -1 -- "${f}")" in
        run)     RUN_FILE="${f}" ;;
        inspect) INSPECT_FILE="${f}" ;;
        rm)      RM_FILES+=("${f}") ;;
        *)       printf 'invocacion docker inesperada: %s\n' "${f}" >&2; exit 1 ;;
    esac
done
[[ -n "${RUN_FILE}" ]]
[[ -n "${INSPECT_FILE}" ]]
[[ "${#RM_FILES[@]}" -eq 2 ]]
[[ "${RM_FILES[0]}" < "${RUN_FILE}" ]]
[[ "${RUN_FILE}" < "${INSPECT_FILE}" ]]
[[ "${INSPECT_FILE}" < "${RM_FILES[1]}" ]]
# El inspect lee el estado OOM del contenedor ANTES del borrado final.
grep -Fxq -- '--format' "${INSPECT_FILE}"
grep -Fxq -- '{{.State.OOMKilled}}' "${INSPECT_FILE}"

# Las banderas de contencion se verifican sobre la invocacion `run`, no sobre
# lo que quede de ultimo en el registro.
for argument in \
    --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --memory 12g --cpus 4 /work/corpus; do
    grep -Fxq -- "${argument}" "${RUN_FILE}"
done
# Y el contenedor NO se autodestruye: el estado tiene que sobrevivir al run.
! grep -Fxq -- '--rm' "${RUN_FILE}"

printf 'RUNNER_SECURITY_TESTS_PASS cases=8\n'
