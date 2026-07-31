#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${ROOT}/UPSTREAM.lock"

declare -A value=()
while IFS='=' read -r key item; do
    [[ -n "${key}" && -n "${item}" ]] || continue
    value["${key}"]="${item}"
done < "${LOCK}"

[[ "${value[repository]:-}" == "https://github.com/fireblocks/mpc-lib" ]]
[[ "${value[commit]:-}" =~ ^[0-9a-f]{40}$ ]]

UPSTREAM="${FIREBLOCKS_UPSTREAM_DIR:-${ROOT}/_upstream}"
[[ -d "${UPSTREAM}/.git" ]]
[[ "$(git -C "${UPSTREAM}" rev-parse HEAD)" == "${value[commit]}" ]]
[[ -z "$(git -C "${UPSTREAM}" status --porcelain=v1)" ]]

# Export only tracked bytes. Passing .git as a BuildKit context is both slow
# and unnecessary; the exact commit was already verified above.
EXPORT="$(mktemp -d)"
cleanup() {
    [[ "${EXPORT}" == /tmp/* ]] && rm -rf -- "${EXPORT}"
}
trap cleanup EXIT
git -C "${UPSTREAM}" archive --format=tar "${value[commit]}" |
    tar -xf - -C "${EXPORT}"
printf '%s\n' "${value[commit]}" > "${EXPORT}/.pinned-commit"

IMAGE="${1:-fireblocks-mpc-hunt:${value[commit]:0:12}}"
docker build \
    --build-context "upstream=${EXPORT}" \
    --file "${ROOT}/docker/Dockerfile.fuzzer" \
    --tag "${IMAGE}" \
    "${ROOT}"

DIGEST="$(docker image inspect "${IMAGE}" --format '{{.Id}}')"
[[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
printf 'BUILD_IMAGE_PASS image=%s digest=%s\n' "${IMAGE}" "${DIGEST}"
