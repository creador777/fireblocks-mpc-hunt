#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 5 ]]; then
    printf 'usage: %s IMAGE SHARD SECONDS CORPUS_DIR OUTPUT_DIR\n' "$0" >&2
    exit 64
fi

IMAGE="$1"
SHARD="$2"
SECONDS_LIMIT="$3"
CORPUS_INPUT="$4"
OUTPUT_INPUT="$5"

if [[ ! "${SHARD}" =~ ^[0-9]+$ ]] || (( SHARD < 0 || SHARD >= 25 )); then
    exit 64
fi
if [[ ! "${SECONDS_LIMIT}" =~ ^[0-9]+$ ]] ||
    (( SECONDS_LIMIT < 60 || SECONDS_LIMIT > 20700 )); then
    exit 64
fi
if [[ ! -d "${CORPUS_INPUT}" || -L "${CORPUS_INPUT}" ]]; then
    exit 65
fi
if [[ -L "${OUTPUT_INPUT}" ]]; then
    exit 65
fi

CORPUS_LOGICAL="$(realpath -e -s -- "${CORPUS_INPUT}")"
CORPUS_DIR="$(realpath -e -- "${CORPUS_INPUT}")"
OUTPUT_LOGICAL="$(realpath -m -s -- "${OUTPUT_INPUT}")"
OUTPUT_DIR="$(realpath -m -- "${OUTPUT_INPUT}")"
if [[ "${CORPUS_LOGICAL}" != "${CORPUS_DIR}" ||
      "${OUTPUT_LOGICAL}" != "${OUTPUT_DIR}" ]]; then
    exit 65
fi

mkdir -p "${OUTPUT_DIR}/private_plain"
if [[ ! -d "${OUTPUT_DIR}/private_plain" ||
      -L "${OUTPUT_DIR}/private_plain" ]]; then
    exit 65
fi
PRIVATE_LOGICAL="$(realpath -e -s -- "${OUTPUT_DIR}/private_plain")"
PRIVATE_DIR="$(realpath -e -- "${OUTPUT_DIR}/private_plain")"
if [[ "${PRIVATE_LOGICAL}" != "${PRIVATE_DIR}" ]]; then
    exit 65
fi

HOST_CORPUS="${CORPUS_DIR}"
HOST_PRIVATE="${PRIVATE_DIR}"
if command -v cygpath >/dev/null 2>&1; then
    HOST_CORPUS="$(cygpath -am "${CORPUS_DIR}")"
    HOST_PRIVATE="$(cygpath -am "${PRIVATE_DIR}")"
fi

RAW_LOG="${PRIVATE_DIR}/fuzzer.raw.log"
RUN_ID="${GITHUB_RUN_ID:-local}"
if [[ ! "${RUN_ID}" =~ ^(local|[0-9]+)$ ]]; then
    exit 64
fi
CONTAINER_NAME="fireblocks-hunt-${RUN_ID}-${SHARD}"

set +e
MSYS_NO_PATHCONV=1 docker run --rm \
    --name "${CONTAINER_NAME}" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 12g \
    --cpus 4 \
    --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    --mount "type=bind,src=${HOST_CORPUS},dst=/work/corpus" \
    --mount "type=bind,src=${HOST_PRIVATE},dst=/work/private" \
    --env "FIREBLOCKS_SHARD_SEED=${SHARD}" \
    "${IMAGE}" \
    /work/corpus \
    "-max_total_time=${SECONDS_LIMIT}" \
    -timeout=30 \
    -rss_limit_mb=10240 \
    -print_final_stats=1 \
    -use_value_profile=1 \
    -error_exitcode=77 \
    -timeout_exitcode=70 \
    -oom_exitcode=71 \
    -artifact_prefix=/work/private/ \
    >"${RAW_LOG}" 2>&1
RC=$?
set -e

printf '%s\n' "${RC}" > "${PRIVATE_DIR}/exit_code"
printf 'SHARD_RUN_COMPLETE shard=%s exit_code=%s\n' "${SHARD}" "${RC}"
exit "${RC}"
