#!/usr/bin/env bash
# plan_wave.sh COUNT WORKERS SECONDS APPROVED_TUPLE APPROVED_UNTIL_EPOCH --
# closed wave planner for .github/workflows/hunt.yml. Authorization binds
# COUNT x WORKERS x SECONDS as ONE exact tuple, valid only until an explicit
# expiry epoch (R3-6): an exact, short-lived authorization, NOT a sticky
# stage and NOT single-use (the workflow cannot prove single-use; the
# operator must clear tuple+expiry when the wave ends).
#
# Stage-0 tuples (1x1x300 and the legacy Nx1 waves production already admits)
# need no manual authorization and ignore both authorization variables
# completely (the schedule path never passes them). Scaled four-worker
# tuples are approved only when APPROVED_TUPLE matches the request EXACTLY
# and APPROVED_UNTIL_EPOCH is a strict decimal epoch with
# now <= until <= now + 900 (maximum authorization window: 15 minutes).
# Missing, non-decimal, expired, or too-far expiry: exit 64. The wave is
# never reduced to make a request fit.
set -euo pipefail
umask 077

if [[ "$#" -ne 5 ]]; then
    printf 'usage: %s COUNT WORKERS SECONDS APPROVED_TUPLE APPROVED_UNTIL_EPOCH\n' "$0" >&2
    exit 64
fi

COUNT="$1"
WORKERS="$2"
SECONDS_ARG="$3"
APPROVED_TUPLE="$4"
APPROVED_UNTIL_EPOCH="$5"

[[ "${COUNT}" =~ ^[0-9]+$ ]] || exit 64
[[ "${WORKERS}" =~ ^[0-9]+$ ]] || exit 64
[[ "${SECONDS_ARG}" =~ ^[0-9]+$ ]] || exit 64
if [[ -n "${APPROVED_TUPLE}" && ! "${APPROVED_TUPLE}" =~ ^[0-9]+x[0-9]+x[0-9]+$ ]]; then
    exit 64
fi

TUPLE="${COUNT}x${WORKERS}x${SECONDS_ARG}"

case "${TUPLE}" in
    # Stage 0: canary and the legacy one-worker waves production already
    # admits. No manual authorization is consumed; tuple and expiry are
    # ignored completely on this path (the schedule never passes them).
    1x1x300|1x1x3600|1x1x20700| \
    5x1x300|5x1x3600|5x1x20700| \
    15x1x300|15x1x3600|15x1x20700| \
    25x1x300|25x1x3600|25x1x20700)
        ;;
    # Scaled tuples: only these six are authorizable at all, and only via an
    # exact APPROVED_TUPLE match plus a valid short-lived expiry. 25x4x20700
    # is deliberately NOT listed: rejected even if the variables name it.
    1x4x300|5x4x300|5x4x900|15x4x900|25x4x900|25x4x7200)
        [[ -n "${APPROVED_TUPLE}" && "${APPROVED_TUPLE}" == "${TUPLE}" ]] || exit 64
        [[ "${APPROVED_UNTIL_EPOCH}" =~ ^[0-9]+$ ]] || exit 64
        now="$(date +%s)"
        (( now <= APPROVED_UNTIL_EPOCH )) || exit 64
        (( APPROVED_UNTIL_EPOCH <= now + 900 )) || exit 64
        ;;
    *)
        exit 64
        ;;
esac

case "${COUNT}" in
    1)  matrix='[0]' ;;
    5)  matrix='[0,1,2,3,4]' ;;
    15) matrix='[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]' ;;
    25) matrix='[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]' ;;
    *)  exit 64 ;;
esac

# Explicit profile selection: four workers always means the cloud profile;
# one worker means the default profile (empty string).
PROFILE=""
if (( WORKERS > 1 )); then
    PROFILE="cloud"
fi

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"
{
    printf 'count=%s\n' "${COUNT}"
    printf 'matrix=%s\n' "${matrix}"
    printf 'seconds=%s\n' "${SECONDS_ARG}"
    printf 'workers=%s\n' "${WORKERS}"
    printf 'profile=%s\n' "${PROFILE}"
} >> "${GITHUB_OUTPUT}"
