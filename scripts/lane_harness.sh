#!/usr/bin/env bash
# Mapping CERRADO lane -> harness, lado HOST.
#
# La lane identifica la CONFIGURACION de ejecucion; el harness identifica
# la SUPERFICIE que esa configuracion expone. El segundo se DERIVA del
# primero: suministrarlos por separado permitiria una combinacion
# incoherente -- por ejemplo publicar corpus t<n en el subarbol n=n --
# que ningun control posterior podria detectar.
#
# Sin valor por defecto: una lane vacia o desconocida sale 64.
# Su gemelo dentro del contenedor es docker/lane-entrypoint.sh y
# tests/test_harness_contract.py exige que los dos coincidan.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
    exit 64
fi

case "$1" in
    cmp_general) printf '%s\n' cmp_ecdsa_online ;;
    cmp_r4_tn)   printf '%s\n' cmp_ecdsa_online_r4_tn ;;
    *)           exit 64 ;;
esac
