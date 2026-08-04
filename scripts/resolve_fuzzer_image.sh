#!/usr/bin/env bash
# resolve_fuzzer_image.sh TAG -- deja lista la imagen del fuzzer e imprime la
# referencia que debe usarse para ejecutarla.
#
# Dos modos, decididos exclusivamente por docker/BASE_IMAGE.lock:
#
#   reference=unpinned          -> construye localmente (comportamiento actual)
#   reference=<repo>@sha256:... -> descarga esa imagen exacta, sin construir
#
# El segundo modo es la solucion definitiva al fallo que costo 6 de 15 shards:
# la ola deja de depender de que los mirrors de paquetes respondan una vez por
# shard. Un pull por digest tampoco puede traer otra cosa que la imagen
# auditada, cosa que una etiqueta no garantiza.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${ROOT}/docker/BASE_IMAGE.lock"
TAG="${1:-fireblocks-mpc-hunt:local}"

REFERENCE=""
while IFS='=' read -r key item; do
    [[ "${key}" == "reference" ]] || continue
    REFERENCE="${item}"
done < "${LOCK}"
[[ -n "${REFERENCE}" ]] || exit 64

if [[ "${REFERENCE}" == "unpinned" ]]; then
    FIREBLOCKS_UPSTREAM_DIR="${FIREBLOCKS_UPSTREAM_DIR:-${ROOT}/_upstream}" \
        "${ROOT}/scripts/build_fuzzer_image.sh" "${TAG}" >&2
    printf '%s\n' "${TAG}"
    exit 0
fi

# Forma exigida: repositorio@sha256:<64 hex>. Nada mas se acepta, para que
# "fijado por digest" no degrade en silencio a "fijado por etiqueta".
[[ "${REFERENCE}" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || exit 64

docker pull --quiet -- "${REFERENCE}" >&2

# El digest local tiene que coincidir con el pedido: si docker resolviera otra
# cosa, ejecutar igualmente convertiria el pin en decorativo.
RESOLVED="$(docker image inspect "${REFERENCE}" \
    --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
[[ "${RESOLVED}" == "${REFERENCE}" ]] || exit 65

docker tag -- "${REFERENCE}" "${TAG}"
printf '%s\n' "${TAG}"
