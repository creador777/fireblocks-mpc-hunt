#!/bin/sh
# Selector de lane del contenedor. Mapping CERRADO, sin valor por defecto.
#
#   cmp_general -> cmp_ecdsa_online        + snapshot.bin     (n=n)
#   cmp_r4_tn   -> cmp_ecdsa_online_r4_tn  + snapshot_tn.bin  (t<n)
#
# El harness se DERIVA de la lane. Que se pudieran dar por separado
# permitiria una combinacion incoherente que nadie detectaria despues.
#
# Gemelo del lado host: la funcion lane_to_harness de
# scripts/brain_paths.sh. Hay dos copias por necesidad -- el contenedor
# no puede leer el arbol del host -- y tests/test_harness_contract.py
# exige que coincidan.
#
# Codigos: 64 = lane vacia o desconocida; 69 = binario o snapshot ausente.
set -eu

LANE="${FIREBLOCKS_LANE-}"
case "${LANE}" in
    cmp_general)
        FIREBLOCKS_HARNESS=cmp_ecdsa_online
        FIREBLOCKS_SNAPSHOT=/opt/fireblocks/data/snapshot.bin
        FIREBLOCKS_BIN=/opt/fireblocks/bin/opus_cmp_fuzzer
        ;;
    cmp_r4_tn)
        FIREBLOCKS_HARNESS=cmp_ecdsa_online_r4_tn
        FIREBLOCKS_SNAPSHOT=/opt/fireblocks/data/snapshot_tn.bin
        FIREBLOCKS_BIN=/opt/fireblocks/bin/opus_cmp_fuzzer_reachability_v2
        ;;
    *)
        printf 'status=fail_closed code=unknown_lane\n' >&2
        exit 64
        ;;
esac

test -x "${FIREBLOCKS_BIN}" || {
    printf 'status=fail_closed code=lane_binary_missing\n' >&2
    exit 69
}
test -s "${FIREBLOCKS_SNAPSHOT}" || {
    printf 'status=fail_closed code=lane_snapshot_missing\n' >&2
    exit 69
}
export FIREBLOCKS_SNAPSHOT FIREBLOCKS_HARNESS
exec "${FIREBLOCKS_BIN}" "$@"
