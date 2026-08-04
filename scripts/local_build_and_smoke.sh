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
mkdir -p "${TMP}/corpus" "${TMP}/output"
printf 'CMPSEED00' > "${TMP}/corpus/seed"

# Lane explicita tambien en el humo local: sin ella el shard sale 64.
"${ROOT}/scripts/run_fuzzer_shard.sh" \
    "${IMAGE}" 0 60 "${TMP}/corpus" "${TMP}/output" "${FIREBLOCKS_LANE:-cmp_general}"

test -s "${TMP}/output/private_plain/fuzzer.raw.log"
test "$(tr -d '\r\n' < "${TMP}/output/private_plain/exit_code")" = "0"
grep -q 'stat::number_of_executed_units:' \
    "${TMP}/output/private_plain/fuzzer.raw.log"
printf 'LOCAL_BUILD_SMOKE_PASS image=%s\n' "${IMAGE}"
