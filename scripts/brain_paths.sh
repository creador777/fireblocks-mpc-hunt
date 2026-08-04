#!/usr/bin/env bash
# Autoridad UNICA de rutas del brain. Nadie mas construye ni interpreta una
# ruta de ingesta.
#
# POR QUE EXISTE. El canary del run 30868170486 fallo porque el generador de
# nombres de rama vivia en publish_ingest.sh y el parser en
# aggregate_ingest.sh. Al separar las superficies se cambio el generador y no
# el parser: el publicador escribio
#     ingest/run-<id>/attempt-<n>/<harness>/shard-<k>
# y el agregador siguio buscando
#     ingest/run-<id>/attempt-<n>/shard-<k>
# Ninguna prueba lo vio porque las dos mitades se probaban por separado.
#
# Aqui las dos mitades son la misma funcion y su inversa, y el round-trip se
# comprueba. Cambiar una sin la otra deja de ser posible.
#
# CONTRATO
#   formato canonico:
#     ingest/run-<run_id>/attempt-<attempt>/<harness>/shard-<shard>
#   run_id, attempt, shard : enteros canonicos, sin ceros a la izquierda,
#                            sin signo, sin espacios
#   harness                : exactamente uno de los dos allowlisted
#   sin fallback: cualquier desviacion sale 64
#
# Este fichero se USA SOURCEADO. No fija `set -e`: hacerlo se lo impondria a
# quien lo carga, y una funcion que devuelve 64 a proposito -- que es como
# rechaza -- abortaria al llamador en vez de dejarle decidir. Los dos
# consumidores de produccion fijan `set -euo pipefail` por su cuenta antes de
# cargarlo, asi que no se relaja nada.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -euo pipefail
fi

#: Superficies conocidas. Identica a HARNESSES de public_summary.py y a
#: RULES["harness"] de emit_summary.py; tests/test_harness_contract.py exige
#: que las tres coincidan.
BRAIN_HARNESSES="cmp_ecdsa_online cmp_ecdsa_online_r4_tn"

#: Entero canonico: 0, o un digito no nulo seguido de digitos. Excluye "007",
#: "+1", " 1", "1 ", vacio y cualquier cosa con salto de linea.
_brain_is_uint() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

_brain_is_harness() {
    local candidate="$1" known
    for known in ${BRAIN_HARNESSES}; do
        [[ "${candidate}" == "${known}" ]] && return 0
    done
    return 1
}

# --- mapping lane -> harness ---------------------------------------------
# La lane es la ENTRADA; el harness se DERIVA. Suministrarlos por separado
# permitiria publicar corpus de una superficie en el subarbol de la otra.
lane_to_harness() {
    [[ "$#" -eq 1 ]] || return 64
    case "$1" in
        cmp_general) printf '%s\n' cmp_ecdsa_online ;;
        cmp_r4_tn)   printf '%s\n' cmp_ecdsa_online_r4_tn ;;
        *)           return 64 ;;
    esac
}

# --- generador ------------------------------------------------------------
# branch_for RUN_ID ATTEMPT HARNESS SHARD
branch_for() {
    [[ "$#" -eq 4 ]] || return 64
    local run_id="$1" attempt="$2" harness="$3" shard="$4" branch
    _brain_is_uint "${run_id}"  || return 64
    _brain_is_uint "${attempt}" || return 64
    _brain_is_uint "${shard}"   || return 64
    _brain_is_harness "${harness}" || return 64

    branch="ingest/run-${run_id}/attempt-${attempt}/${harness}/shard-${shard}"
    # git decide que es un nombre de referencia legal, no nosotros.
    git check-ref-format "refs/heads/${branch}" || return 64
    printf '%s\n' "${branch}"
}

# --- parser (inversa exacta) ---------------------------------------------
# parse_branch BRANCH -> imprime "RUN_ID ATTEMPT HARNESS SHARD"
parse_branch() {
    [[ "$#" -eq 1 ]] || return 64
    local branch="$1"
    # Sin saltos de linea ni espacios: una ref con un \n partiria cualquier
    # consumidor que lea linea a linea.
    [[ "${branch}" != *$'\n'* ]] || return 64
    [[ "${branch}" != *' '* ]]   || return 64
    [[ "${branch}" != *'..'* ]]  || return 64
    git check-ref-format "refs/heads/${branch}" || return 64

    local pattern='^ingest/run-([0-9]+)/attempt-([0-9]+)/([a-z0-9_]+)/shard-([0-9]+)$'
    [[ "${branch}" =~ ${pattern} ]] || return 64
    local run_id="${BASH_REMATCH[1]}" attempt="${BASH_REMATCH[2]}"
    local harness="${BASH_REMATCH[3]}" shard="${BASH_REMATCH[4]}"

    # La regex admite digitos; la canonicidad la exige _brain_is_uint, que
    # rechaza "007" y compania. Sin esto, dos ramas distintas describirian la
    # misma tupla y la reconciliacion las contaria dos veces.
    _brain_is_uint "${run_id}"  || return 64
    _brain_is_uint "${attempt}" || return 64
    _brain_is_uint "${shard}"   || return 64
    _brain_is_harness "${harness}" || return 64

    printf '%s %s %s %s\n' "${run_id}" "${attempt}" "${harness}" "${shard}"
}

# --- formato legado (solo lectura) ---------------------------------------
# parse_branch_legacy BRANCH -> imprime "RUN_ID ATTEMPT HARNESS SHARD"
#
# Antes de las lanes las ramas no llevaban segmento de harness:
#     ingest/run-<id>/attempt-<n>/shard-<k>
# El brain conserva 203 ramas de esa epoca. El agregador falla cerrado ante
# cualquier ref de ingest que no sepa interpretar -- correcto, porque saltarla
# perderia corpus en silencio -- asi que sin esta funcion ninguna agregacion
# vuelve a completarse.
#
# El harness se completa con cmp_ecdsa_online: era la unica superficie que
# existia, y el CONTENIDO de esas ramas ya esta bajo corpus/cmp_ecdsa_online/,
# asi que la comprobacion de rutas del agregador sigue siendo la real y no una
# concesion. No hay generador legado: nada vuelve a escribir este formato, y
# cada rama desaparece en cuanto se consolida.
parse_branch_legacy() {
    [[ "$#" -eq 1 ]] || return 64
    local branch="$1"
    [[ "${branch}" != *$'\n'* ]] || return 64
    [[ "${branch}" != *' '* ]]   || return 64
    [[ "${branch}" != *'..'* ]]  || return 64
    git check-ref-format "refs/heads/${branch}" || return 64

    local pattern='^ingest/run-([0-9]+)/attempt-([0-9]+)/shard-([0-9]+)$'
    [[ "${branch}" =~ ${pattern} ]] || return 64
    local run_id="${BASH_REMATCH[1]}" attempt="${BASH_REMATCH[2]}"
    local shard="${BASH_REMATCH[3]}"
    _brain_is_uint "${run_id}"  || return 64
    _brain_is_uint "${attempt}" || return 64
    _brain_is_uint "${shard}"   || return 64

    printf '%s %s %s %s\n' "${run_id}" "${attempt}" cmp_ecdsa_online "${shard}"
}

# --- rutas derivadas ------------------------------------------------------
# Corpus e incidentes salen del MISMO harness validado, nunca de una cadena
# recibida aparte.
corpus_dir_for() {
    [[ "$#" -eq 1 ]] || return 64
    _brain_is_harness "$1" || return 64
    printf 'corpus/%s\n' "$1"
}

corpus_unit_for() {
    [[ "$#" -eq 2 ]] || return 64
    _brain_is_harness "$1" || return 64
    [[ "$2" =~ ^[0-9a-f]{40}$ ]] || return 64
    printf 'corpus/%s/%s\n' "$1" "$2"
}

# incident_for RUN_ID ATTEMPT HARNESS SHARD
incident_for() {
    [[ "$#" -eq 4 ]] || return 64
    local run_id="$1" attempt="$2" harness="$3" shard="$4"
    _brain_is_uint "${run_id}"  || return 64
    _brain_is_uint "${attempt}" || return 64
    _brain_is_uint "${shard}"   || return 64
    _brain_is_harness "${harness}" || return 64
    printf 'incidents/run-%s/%s-attempt-%s-shard-%s.gpg\n' \
        "${run_id}" "${harness}" "${attempt}" "${shard}"
}

parse_incident() {
    [[ "$#" -eq 1 ]] || return 64
    local path="$1"
    local pattern='^incidents/run-([0-9]+)/([a-z0-9_]+)-attempt-([0-9]+)-shard-([0-9]+)\.gpg$'
    [[ "${path}" =~ ${pattern} ]] || return 64
    local run_id="${BASH_REMATCH[1]}" harness="${BASH_REMATCH[2]}"
    local attempt="${BASH_REMATCH[3]}" shard="${BASH_REMATCH[4]}"
    _brain_is_uint "${run_id}"  || return 64
    _brain_is_uint "${attempt}" || return 64
    _brain_is_uint "${shard}"   || return 64
    _brain_is_harness "${harness}" || return 64
    printf '%s %s %s %s\n' "${run_id}" "${attempt}" "${harness}" "${shard}"
}

# --- clasificacion de refs -------------------------------------------------
# Una ref DENTRO de ingest/ que no case el formato canonico es fail-closed:
# es una rama de ingesta que nadie sabe interpretar, y saltarsela perderia
# corpus en silencio. Una ref FUERA de ingest/ se ignora sin ruido.
is_ingest_ref() {
    [[ "$#" -eq 1 ]] || return 64
    [[ "$1" == ingest/* ]]
}

# Uso como ejecutable: brain_paths.sh <funcion> [args...]
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ "$#" -ge 1 ]] || exit 64
    command="$1"; shift
    case "${command}" in
        lane_to_harness|branch_for|parse_branch|corpus_dir_for|corpus_unit_for|\
        incident_for|parse_incident|is_ingest_ref)
            "${command}" "$@" ;;
        *) exit 64 ;;
    esac
fi
