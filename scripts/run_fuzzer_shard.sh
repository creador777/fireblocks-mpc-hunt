#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 6 ]]; then
    printf 'usage: %s IMAGE SHARD SECONDS CORPUS_DIR OUTPUT_DIR LANE\n' "$0" >&2
    exit 64
fi

IMAGE="$1"
SHARD="$2"
SECONDS_LIMIT="$3"
CORPUS_INPUT="$4"
OUTPUT_INPUT="$5"
# La lane es la ENTRADA; el harness se deriva del mapping cerrado. No se
# aceptan por separado: una combinacion incoherente publicaria corpus de
# una superficie en el subarbol de la otra.
LANE="$6"
# Autoridad UNICA del mapping. Tener una segunda copia fue lo que
# desincronizo generador y parser en el canary anterior.
. "$(dirname -- "${BASH_SOURCE[0]}")/brain_paths.sh"
HARNESS="$(lane_to_harness "${LANE}")" || exit 64
[[ -n "${HARNESS}" ]] || exit 64

if [[ ! "${SHARD}" =~ ^[0-9]+$ ]] || (( SHARD < 0 || SHARD >= 25 )); then
    exit 64
fi
if [[ ! "${SECONDS_LIMIT}" =~ ^[0-9]+$ ]] ||
    (( SECONDS_LIMIT < 60 || SECONDS_LIMIT > 20700 )); then
    exit 64
fi

# Workers via validated environment variable; the positional interface stays
# at five arguments. Unset means 1 (current cloud/default behavior). The
# range is closed at 1..8: 0, 9, text, or an explicitly empty value all fail
# closed. Fork mode additionally requires an explicit validated profile:
# "local" (2..8 workers, margin kept) or "cloud" (exactly 4 workers, full
# subscription of the dedicated hosted runner). No profile is ever inherited.
WORKERS="${FIREBLOCKS_HUNT_WORKERS-1}"
PROFILE="${FIREBLOCKS_HUNT_PROFILE-}"
if [[ ! "${WORKERS}" =~ ^[0-9]+$ ]] || (( WORKERS < 1 || WORKERS > 8 )); then
    exit 64
fi
if (( WORKERS == 1 )) && [[ -n "${PROFILE}" ]]; then
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

# From here on private_plain exists, so every failure still leaves exit_code
# metadata. 64 = invalid invocation/config, 65 = invalid paths,
# 69 = resource profile not satisfiable (never reused for bad paths).
fail_rc() {
    printf '%s\n' "$1" > "${PRIVATE_DIR}/exit_code"
    exit "$1"
}

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

# Cancellation (SIGTERM/SIGINT from the runner): leave the minimum evidence
# (exit_code=143 = 128+SIGTERM, raw log) and remove the container. Nothing is
# printed: stdout/stderr of this script belong to a closed one-line grammar.
on_cancel() {
    trap - TERM INT
    set +e
    printf '%s\n' "143" > "${PRIVATE_DIR}/exit_code" 2>/dev/null
    [[ -e "${RAW_LOG}" ]] || : > "${RAW_LOG}" 2>/dev/null
    docker rm -f -- "${CONTAINER_NAME}" >> "${RAW_LOG}" 2>&1
    exit 143
}
trap on_cancel TERM INT

# Resource profiles. WORKERS=1 is bit-identical to the current cloud/default
# profile. The "local" profile budgets against the local Docker VM (8 x 768
# MiB of RSS plus ~0.5 GiB of parent below 7168 MiB) and keeps a 2-CPU
# margin. The "cloud" profile budgets per process against the hosted
# runner's documented 16 GiB: 4 x 2560 MiB = 10240 MiB of worker RSS plus
# the parent stays under the 12g container cap, with full 4-vCPU
# subscription on the dedicated VM. Both CPU guards fail closed with 69.
# rss_limit_mb and malloc_limit_mb are SEPARATE oracles: the malloc oracle
# stays at the current 10240 in every profile until real measurement.
MEMORY_LIMIT="12g"
CPU_LIMIT="4"
RSS_LIMIT_MB="10240"
MALLOC_LIMIT_MB="10240"
FORK_ARGS=()
if (( WORKERS > 1 )); then
    DOCKER_CPUS="$(docker info --format '{{.NCPU}}' 2>/dev/null)" || fail_rc 69
    [[ "${DOCKER_CPUS}" =~ ^[0-9]+$ ]] || fail_rc 69
    case "${PROFILE}" in
        cloud)
            (( WORKERS == 4 )) || fail_rc 64
            (( DOCKER_CPUS >= WORKERS )) || fail_rc 69
            MEMORY_LIMIT="12g"
            CPU_LIMIT="4"
            RSS_LIMIT_MB="2560"
            ;;
        local)
            (( WORKERS >= 2 && WORKERS <= 8 )) || fail_rc 64
            (( DOCKER_CPUS >= WORKERS + 2 )) || fail_rc 69
            MEMORY_LIMIT="7168m"
            CPU_LIMIT="${WORKERS}"
            RSS_LIMIT_MB="768"
            ;;
        *)
            fail_rc 64
            ;;
    esac
    FORK_ARGS=("-fork=${WORKERS}" "-ignore_crashes=0" "-ignore_timeouts=0" "-ignore_ooms=0")
fi

# libFuzzer's logical deadline cannot interrupt a target invocation that does
# not return. An independent host-side deadline is therefore mandatory.
command -v timeout >/dev/null 2>&1 || fail_rc 69
WATCHDOG_SECONDS=$((SECONDS_LIMIT + 60))

set +e
# No --rm: the container state (.State.OOMKilled) is the only way to tell a
# cgroup OOM apart from a watchdog kill, because both surface here as 137.
# With --rm that read races the automatic removal. Any stale container from
# an interrupted previous attempt is removed first, and this run's container
# is removed below, always, after its state has been read.
docker rm -f -- "${CONTAINER_NAME}" >> "${RAW_LOG}" 2>&1 || true
MSYS_NO_PATHCONV=1 timeout --signal=TERM --kill-after=15 "${WATCHDOG_SECONDS}" docker run \
    --name "${CONTAINER_NAME}" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory "${MEMORY_LIMIT}" \
    --cpus "${CPU_LIMIT}" \
    --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    --mount "type=bind,src=${HOST_CORPUS},dst=/work/corpus" \
    --mount "type=bind,src=${HOST_PRIVATE},dst=/work/private" \
    --env "FIREBLOCKS_SHARD_SEED=${SHARD}" \
    --env "FIREBLOCKS_LANE=${LANE}" \
    "${IMAGE}" \
    /work/corpus \
    "-max_total_time=${SECONDS_LIMIT}" \
    "${FORK_ARGS[@]}" \
    -timeout=30 \
    "-rss_limit_mb=${RSS_LIMIT_MB}" \
    "-malloc_limit_mb=${MALLOC_LIMIT_MB}" \
    -print_final_stats=1 \
    -use_value_profile=1 \
    -error_exitcode=77 \
    -timeout_exitcode=70 \
    -oom_exitcode=71 \
    -artifact_prefix=/work/private/ \
    >"${RAW_LOG}" 2>&1
RC=$?

# C1 exit classification. The container state is read BEFORE any removal.
# 70/71/77 come from libFuzzer itself (findings) and are never rewritten.
# 124 is GNU timeout's own report that the watchdog expired, so it needs no
# further evidence. A 137 is ambiguous: it becomes 73 (CGROUP_OOM) when
# Docker recorded the OOM kill, 72 (HOST_WATCHDOG) when the container is
# still present, was not OOM-killed and the fuzzer was producing output
# (the watchdog escalated to SIGKILL), and 74 (UNKNOWN_FAIL_CLOSED) when
# there is not enough evidence to name a cause without inventing one.
OOM_KILLED="$(docker inspect --format '{{.State.OOMKilled}}' -- \
    "${CONTAINER_NAME}" 2>> "${RAW_LOG}" || true)"
printf '%s\n' "${OOM_KILLED:-unknown}" > "${PRIVATE_DIR}/oom_killed"

timeout --signal=TERM --kill-after=5 20 \
    docker rm -f -- "${CONTAINER_NAME}" >> "${RAW_LOG}" 2>&1 || true

if (( RC == 124 || RC == 137 )); then
    if [[ "${OOM_KILLED}" == "true" ]]; then
        RC=73
    elif (( RC == 124 )); then
        RC=72
    elif [[ "${OOM_KILLED}" == "false" ]] &&
         grep -qE '^#[0-9]+[[:space:]]' "${RAW_LOG}" 2>/dev/null; then
        RC=72
    else
        RC=74
    fi
fi
set -e

printf '%s\n' "${RC}" > "${PRIVATE_DIR}/exit_code"
# El harness va al directorio privado para que el resumen y la
# publicacion usen el DERIVADO, no uno suministrado aparte.
printf '%s\n' "${HARNESS}" > "${PRIVATE_DIR}/harness"
printf 'SHARD_RUN_COMPLETE shard=%s exit_code=%s\n' "${SHARD}" "${RC}"
exit "${RC}"
