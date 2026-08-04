#!/usr/bin/env bash
# Contrato de scripts/brain_paths.sh: mapping cerrado, round-trip, vectores
# adversarios y separacion lane/harness.
#
# Sin red, sin git remoto, sin datos que no sean sinteticos. Rapido: es todo
# evaluacion de cadenas.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
. "${ROOT}/scripts/brain_paths.sh"

PASS=0
FAIL=0
check() { # descripcion resultado [detalle]
    if [[ "$2" -eq 0 ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s %s\n' "$1" "${3:-}"
    fi
}

# --- mapping cerrado lane -> harness -------------------------------------
[[ "$(lane_to_harness cmp_general)" == cmp_ecdsa_online ]]
check "lane cmp_general" $?
[[ "$(lane_to_harness cmp_r4_tn)" == cmp_ecdsa_online_r4_tn ]]
check "lane cmp_r4_tn" $?

for bad_lane in '' select_lane cmp_ CMP_GENERAL cmp_general_x ' cmp_general' \
                'cmp_general ' cmp_r4 general; do
    lane_to_harness "${bad_lane}" >/dev/null 2>&1
    [[ "$?" -ne 0 ]]
    check "lane rechazada: '${bad_lane}'" $?
done

# El harness NUNCA se acepta como entrada donde se espera una lane: si lo
# fuera, quien llama podria elegir superficie y configuracion por separado.
lane_to_harness cmp_ecdsa_online >/dev/null 2>&1
[[ "$?" -ne 0 ]]
check "un harness no vale como lane" $?

# --- round-trip obligatorio ----------------------------------------------
for tuple in "100 1 cmp_ecdsa_online 0" \
             "7 2 cmp_ecdsa_online_r4_tn 24" \
             "0 0 cmp_ecdsa_online 0" \
             "4294967296 10 cmp_ecdsa_online_r4_tn 3"; do
    set -- ${tuple}
    branch="$(branch_for "$1" "$2" "$3" "$4")"
    check "branch_for ${tuple}" $?
    parsed="$(parse_branch "${branch}")"
    check "parse_branch ${branch}" $?
    [[ "${parsed}" == "$1 $2 $3 $4" ]]
    check "parse(branch_for(t)) == t" $? "-> ${parsed}"
    again="$(branch_for ${parsed})"
    [[ "${again}" == "${branch}" ]]
    check "branch_for(parse(b)) == b" $? "-> ${again}"
done

# Telemetria: mismo generador, misma inversa, y disjunta de las otras rutas.
for tuple in "100 1 cmp_ecdsa_online 0" "9 3 cmp_ecdsa_online_r4_tn 12"; do
    set -- ${tuple}
    path="$(telemetry_for "$1" "$2" "$3" "$4")"
    check "telemetry_for ${tuple}" $?
    [[ "$(parse_telemetry "${path}")" == "$1 $2 $3 $4" ]]
    check "parse_telemetry round-trip" $? "${path}"
    [[ "${path}" != "$(incident_for "$1" "$2" "$3" "$4")" ]]
    check "telemetria e incidente no colisionan" $?
done

for bad in \
    'telemetry/run-007/cmp_ecdsa_online-attempt-1-shard-0.json' \
    'telemetry/run-1/cmp_ecdsa_offline-attempt-1-shard-0.json' \
    'telemetry/run-1/cmp_ecdsa_online-attempt-1-shard-0.gpg' \
    'telemetry/run-1/cmp_ecdsa_online-attempt-1-shard-0.json/x' \
    'incidents/run-1/cmp_ecdsa_online-attempt-1-shard-0.json'
do
    parse_telemetry "${bad}" >/dev/null 2>&1
    [[ "$?" -ne 0 ]]
    check "parse_telemetry rechaza: ${bad}" $?
done

# Lo mismo para incidentes: mismo generador, misma inversa.
for tuple in "100 1 cmp_ecdsa_online 0" "9 3 cmp_ecdsa_online_r4_tn 12"; do
    set -- ${tuple}
    path="$(incident_for "$1" "$2" "$3" "$4")"
    check "incident_for ${tuple}" $?
    [[ "$(parse_incident "${path}")" == "$1 $2 $3 $4" ]]
    check "parse_incident round-trip" $? "${path}"
done

# --- vectores adversarios -------------------------------------------------
# Enteros no canonicos: dos ramas distintas no pueden describir una tupla, o
# la reconciliacion contaria la misma contribucion dos veces.
for bad in \
    'ingest/run-007/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-01/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-00' \
    'ingest/run-+1/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run--1/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_offline/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online_r4_tn_x/shard-0' \
    'ingest/run-1/attempt-1/CMP_ECDSA_ONLINE/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0/extra' \
    'ingest/run-1/attempt-1/../cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/../../shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0 ' \
    ' ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0' \
    'xingest/run-1/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0x' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-' \
    'ingest/run-/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0.lock' \
    'refs/heads/ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/cmp_ecdsa_online/shard-0' \
    'ingest/run-1/attempt-1/shard-0'
do
    parse_branch "${bad}" >/dev/null 2>&1
    [[ "$?" -ne 0 ]]
    check "rechaza: ${bad}" $?
done

# Un salto de linea partiria cualquier consumidor que lea linea a linea.
parse_branch "$(printf 'ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0\nx')" \
    >/dev/null 2>&1
[[ "$?" -ne 0 ]]
check "rechaza una ref con salto de linea" $?

# Generador: la tupla invalida no llega a producir cadena.
for bad_tuple in "007 1 cmp_ecdsa_online 0" \
                 "1 1 cmp_ecdsa_offline 0" \
                 "1 1 cmp_ecdsa_online -1" \
                 "1 1 cmp_ecdsa_online 0x0" \
                 "a 1 cmp_ecdsa_online 0"; do
    set -- ${bad_tuple}
    branch_for "$1" "$2" "$3" "$4" >/dev/null 2>&1
    [[ "$?" -ne 0 ]]
    check "branch_for rechaza: ${bad_tuple}" $?
done

# --- separacion lane / harness -------------------------------------------
general_branch="$(branch_for 1 1 cmp_ecdsa_online 0)"
r4_branch="$(branch_for 1 1 cmp_ecdsa_online_r4_tn 0)"
[[ "${general_branch}" != "${r4_branch}" ]]
check "las dos superficies dan ramas distintas" $?

[[ "$(corpus_dir_for cmp_ecdsa_online)" != "$(corpus_dir_for cmp_ecdsa_online_r4_tn)" ]]
check "subarboles de corpus disjuntos" $?

[[ "$(incident_for 1 1 cmp_ecdsa_online 0)" != \
   "$(incident_for 1 1 cmp_ecdsa_online_r4_tn 0)" ]]
check "nombres de incidente disjuntos" $?

# Ni una superficie es prefijo aceptable de la otra en una ruta de corpus.
digest="$(printf 'sintetico' | sha1sum | cut -d' ' -f1)"
[[ "$(corpus_unit_for cmp_ecdsa_online "${digest}")" == "corpus/cmp_ecdsa_online/${digest}" ]]
check "corpus_unit_for general" $?
corpus_unit_for cmp_ecdsa_online "${digest}x" >/dev/null 2>&1
[[ "$?" -ne 0 ]]
check "corpus_unit_for rechaza un hash mal formado" $?
corpus_unit_for cmp_ecdsa_online_r4_tn_x "${digest}" >/dev/null 2>&1
[[ "$?" -ne 0 ]]
check "corpus_unit_for rechaza una superficie desconocida" $?

# Clasificacion de refs: dentro de ingest/ se exige formato; fuera se ignora.
is_ingest_ref "ingest/run-1/attempt-1/cmp_ecdsa_online/shard-0"
check "is_ingest_ref reconoce una de ingesta" $?
is_ingest_ref "corpus-pool" 2>/dev/null
[[ "$?" -ne 0 ]]
check "is_ingest_ref ignora una ajena" $?

printf 'BRAIN_PATHS_CONTRACT %s checks=%d failures=%d\n' \
    "$([[ "${FAIL}" -eq 0 ]] && echo PASS || echo FAIL)" \
    "$((PASS + FAIL))" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
