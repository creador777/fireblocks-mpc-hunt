#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_UPSTREAM="${1:-${ROOT}/_upstream}"
IMAGE="${2:-fireblocks-mpc-hunt:local}"

[[ -d "${SOURCE_UPSTREAM}/.git" ]]
EXPECTED="$(awk -F= '$1=="commit" {print $2}' "${ROOT}/UPSTREAM.lock")"
[[ "$(git -C "${SOURCE_UPSTREAM}" rev-parse HEAD)" == "${EXPECTED}" ]]
[[ -z "$(git -C "${SOURCE_UPSTREAM}" status --porcelain=v1)" ]]

FIREBLOCKS_UPSTREAM_DIR="${SOURCE_UPSTREAM}" \
    "${ROOT}/scripts/build_fuzzer_image.sh" "${IMAGE}"

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT
# Las DOS lanes se ejercitan, cada una con su corpus y su salida. El gate del
# Dockerfile prueba los binarios, no el despacho: sin este bucle la superficie
# r4_tn viajaria compilada y jamas ejecutada a traves del ENTRYPOINT, que es
# exactamente como quedo el canary que fallo.
for lane in cmp_general cmp_r4_tn; do
    corpus="${TMP}/${lane}/corpus"
    output="${TMP}/${lane}/output"
    mkdir -p "${corpus}" "${output}"
    printf 'CMPSEED00' > "${corpus}/seed"

    "${ROOT}/scripts/run_fuzzer_shard.sh" \
        "${IMAGE}" 0 60 "${corpus}" "${output}" "${lane}"

    test -s "${output}/private_plain/fuzzer.raw.log"
    test "$(tr -d '\r\n' < "${output}/private_plain/exit_code")" = "0"
    # Que haya ejecutado unidades: un ENTRYPOINT que arranca y sale limpio no
    # demuestra que la lane este cableada a un fuzzer de verdad.
    grep -q 'stat::number_of_executed_units:' \
        "${output}/private_plain/fuzzer.raw.log"
done

printf 'LOCAL_BUILD_SMOKE_PASS image=%s lanes=2\n' "${IMAGE}"
