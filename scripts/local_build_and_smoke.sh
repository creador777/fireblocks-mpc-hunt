#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_UPSTREAM="${1:-${ROOT}/_upstream}"
IMAGE="${2:-fireblocks-mpc-hunt:local}"

[[ -d "${SOURCE_UPSTREAM}/.git" ]]
EXPECTED="$(awk -F= '$1=="commit" {print $2}' "${ROOT}/UPSTREAM.lock" | tr -d '\r')"
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
for lane in cmp_general cmp_r4_tn cmp_dual; do
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

    # Las lanes semanticas cuentan celdas. Exigir selected>0 las separa de
    # "arranco y no exploto": sin telemetria o sin alcanzar el decodificador
    # podrian salir limpias sin haber medido nada.
    if [[ "${lane}" != cmp_general ]]; then
        test -s "${output}/telemetry/telemetry-job0.json"
        python3 - "${output}/telemetry/telemetry-job0.json" <<'PY'
import json, sys
counters = json.load(open(sys.argv[1]))["counters"]
selected = sum(counters["selected"].values())
applied = sum(counters["applied"].values())
if selected <= 0 or applied <= 0:
    raise SystemExit(f"lane sin alcance: selected={selected} applied={applied}")
print(f"SEMANTIC_REACH selected={selected} applied={applied}")
PY
    fi
done

printf 'LOCAL_BUILD_SMOKE_PASS image=%s lanes=3\n' "${IMAGE}"
