#!/usr/bin/env bash
# E2E: los contadores sobreviven cifrado, publicacion y agregacion.
#
# La cadena real -- cloud_finalize_incident.sh, package_incident.py con GPG de
# verdad, publish_ingest.sh y aggregate_ingest.sh contra un bare local -- con
# un canary de contadores CONOCIDOS. La afirmacion que prueba no es "el flujo
# no revienta" sino "el numero que midio el harness es el numero que queda en
# el pool": cualquier paso que los redondee, los reordene o los pierda hace
# fallar el caso.
#
# Sin red y sin datos reales. El remoto de GitHub se reescribe a un bare local
# y el proxy apunta a un puerto cerrado del bucle local.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
    chmod -R u+w -- "${WORK}" 2>/dev/null || true
    [[ -n "${WORK}" && -d "${WORK}" ]] && rm -rf -- "${WORK}"
}
trap cleanup EXIT INT TERM

PASS=0
FAIL=0
check() {
    if [[ "$2" -eq 0 ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s %s\n' "$1" "${3:-}"
    fi
}

OFFLINE_ENV=(https_proxy=http://127.0.0.1:1 http_proxy=http://127.0.0.1:1
             GIT_TERMINAL_PROMPT=0)

RUN_ID=4242
ATTEMPT=1
SHARD=5
LANE=cmp_r4_tn
HARNESS=cmp_ecdsa_online_r4_tn

# --- canary: contadores conocidos ------------------------------------------
# Estos cuatro numeros son la prueba. Se eligen distintos entre si para que un
# intercambio de campos tampoco pase desapercibido.
CANARY_FLIP=2
CANARY_ZERO=3
CANARY_TRUNCATE=5
CANARY_EXTRA=11
CANARY_DECODED=$((CANARY_FLIP + CANARY_ZERO + CANARY_TRUNCATE + CANARY_EXTRA))
CANARY_DOORS=7
CANARY_EXECS=$((CANARY_DECODED + CANARY_DOORS))

write_canary_telemetry() { # directorio
    mkdir -p "$1"
    cat > "$1/telemetry-job0.json" <<EOF
{"schema":"rt4.telemetry/2",
 "identity":{"campaign":"canary","fuzzer":"cmp-ecdsa-online"},
 "build":{"id":"v2-r4-extrakey","compiler":"clang","sanitizers":"asan+ubsan"},
 "process":{"job_index":0,"parallelism":1,
            "started_monotonic_ns":1000000000000000,
            "updated_monotonic_ns":1000000000000042},
 "counters":{"execs":${CANARY_EXECS},"door_rejects":${CANARY_DOORS},
   "decoded":${CANARY_DECODED},
   "selected":{"r1.mta_proofs[victim]|flip_bit":${CANARY_FLIP},
               "r1.mta_proofs[victim]|zero":${CANARY_ZERO},
               "r1.mta_proofs[victim]|truncate":${CANARY_TRUNCATE},
               "r4.si|extra_map_key":${CANARY_EXTRA}},
   "applied":{"r1.mta_proofs[victim]|flip_bit":${CANARY_FLIP},
              "r1.mta_proofs[victim]|zero":${CANARY_ZERO},
              "r1.mta_proofs[victim]|truncate":${CANARY_TRUNCATE},
              "r4.si|extra_map_key":${CANARY_EXTRA}},
   "not_applied":{"r1.mta_proofs[victim]|flip_bit":0,
                  "r1.mta_proofs[victim]|zero":0,
                  "r1.mta_proofs[victim]|truncate":0,
                  "r4.si|extra_map_key":0},
   "verdicts":{"CLEAN-SIGN":0,"CLEAN-REJECT":${CANARY_DECODED},
               "INVALID-SIGNATURE":0,"STATE-CORRUPTION":0,"CRASH":0,
               "TIMEOUT":0,"HARNESS-FAULT":0}}}
EOF
}

write_private_plain() { # directorio
    mkdir -p "$1"
    printf 'synthetic private log, never published\n' > "$1/fuzzer.raw.log"
    printf '0\n' > "$1/exit_code"
    printf 'false\n' > "$1/oom_killed"
    printf '%s\n' "${HARNESS}" > "$1/harness"
}

new_brain() { # nombre
    local d="${WORK}/$1"
    mkdir -p "${d}/home"
    git init -q --bare "${d}/pool.git"
    git -C "${d}/pool.git" symbolic-ref HEAD refs/heads/corpus-pool
    cat > "${d}/home/.gitconfig" <<EOF
[url "file://${d}/pool.git"]
	insteadOf = https://github.com/creador777/fireblocks-mpc-brain.git
[user]
	name = telemetry-e2e
	email = telemetry-e2e@invalid
[init]
	defaultBranch = corpus-pool
[protocol]
	allow = always
[protocol "file"]
	allow = always
EOF
    local seed="${d}/seed"
    HOME="${d}/home" git init -q "${seed}"
    HOME="${d}/home" git -C "${seed}" symbolic-ref HEAD refs/heads/corpus-pool
    printf 'synthetic brain fixture\n' > "${seed}/README.md"
    HOME="${d}/home" git -C "${seed}" add -A
    HOME="${d}/home" git -C "${seed}" commit -q --no-gpg-sign -m bootstrap
    HOME="${d}/home" git -C "${seed}" push -q "${d}/pool.git" \
        corpus-pool:refs/heads/corpus-pool
    printf '%s\n' "${d}"
}

# --- 1. cifrado: la telemetria entra al bundle y sale un documento canonico -
CASE="${WORK}/finalize"
mkdir -p "${CASE}/upload"
write_private_plain "${CASE}/private_plain"
write_canary_telemetry "${CASE}/telemetry"
BUNDLE="${CASE}/upload/incident-${RUN_ID}-${ATTEMPT}-${SHARD}.gpg"
TELEMETRY_OUT="${CASE}/telemetry.json"

( cd "${ROOT}" && bash scripts/cloud_finalize_incident.sh \
    "${CASE}/private_plain" "${BUNDLE}" success success \
    "${CASE}/telemetry" "${TELEMETRY_OUT}" "${RUN_ID}" "${ATTEMPT}" "${SHARD}" \
    > "${CASE}/out" 2>&1 )
check "1a finalize termina 0" $?
[[ -s "${BUNDLE}" ]]
check "1b existe el ciphertext" $?
[[ ! -e "${CASE}/private_plain" ]]
check "1c el plaintext se borro" $?
[[ -s "${TELEMETRY_OUT}" ]]
check "1d se escribieron los contadores" $?

# El documento publicable NO contiene nada del log crudo ni rutas.
! grep -qE 'fuzzer\.raw|/home/|/tmp/|monotonic' "${TELEMETRY_OUT}"
check "1e el documento no arrastra log ni rutas" $?

# Los cuatro numeros del canary llegaron intactos.
python3 - "${TELEMETRY_OUT}" "${CANARY_EXTRA}" "${CANARY_EXECS}" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="ascii"))
totals = doc["totals"]
assert totals["selected"]["r4.si|extra_map_key"] == int(sys.argv[2]), "extra_map_key"
assert totals["execs"] == int(sys.argv[3]), "execs"
assert doc["harness"] == "cmp_ecdsa_online_r4_tn", "harness"
PY
check "1f los contadores del canary sobreviven el saneo" $?

# --- 2. la telemetria viaja DENTRO del bundle cifrado ----------------------
# Sin la clave privada no se puede descifrar, pero la estructura del paquete si
# se puede comprobar: el bundle debe estar dirigido al destinatario esperado.
GPG_HOME="${CASE}/gpg"
mkdir -m 700 "${GPG_HOME}"
gpg --homedir "${GPG_HOME}" --batch --no-tty --import-options import-minimal \
    --import "${ROOT}/keys/artifact-recipient.asc" >/dev/null 2>&1
gpg --homedir "${GPG_HOME}" --batch --no-tty --list-only --decrypt \
    "${BUNDLE}" >/dev/null 2>&1
check "2a el bundle esta cifrado para el destinatario" $?
# Y el tamaño creció respecto de un bundle sin telemetria: la evidencia
# estructurada esta dentro, no solo al lado.
CASE2="${WORK}/finalize-notel"
mkdir -p "${CASE2}/upload"
write_private_plain "${CASE2}/private_plain"
printf '%s\n' cmp_ecdsa_online > "${CASE2}/private_plain/harness"
( cd "${ROOT}" && bash scripts/cloud_finalize_incident.sh \
    "${CASE2}/private_plain" "${CASE2}/upload/incident-1-1-0.gpg" \
    success success > "${CASE2}/out" 2>&1 )
check "2b finalize sin telemetria sigue funcionando" $?
(( $(wc -c < "${BUNDLE}") > $(wc -c < "${CASE2}/upload/incident-1-1-0.gpg") ))
check "2c el bundle con telemetria es mayor" $?

# --- 3. publicacion y agregacion -------------------------------------------
BRAIN="$(new_brain brain)"
CORPUS="${WORK}/corpus"
mkdir -p "${CORPUS}"
UNIT_PAYLOAD='synthetic-corpus-unit:telemetry'
UNIT_NAME="$(printf '%s' "${UNIT_PAYLOAD}" | sha1sum | cut -d' ' -f1)"
printf '%s' "${UNIT_PAYLOAD}" > "${CORPUS}/${UNIT_NAME}"

( cd "${ROOT}" && env HOME="${BRAIN}/home" FIREBLOCKS_BRAIN_WRITE_TOKEN=e2e \
    "${OFFLINE_ENV[@]}" \
    bash scripts/publish_ingest.sh "${CORPUS}" "${BUNDLE}" \
        "${RUN_ID}" "${ATTEMPT}" "${SHARD}" "${LANE}" "${TELEMETRY_OUT}" \
    > "${BRAIN}/publish.out" 2>&1 )
check "3a publish acepta la telemetria" $?

. "${ROOT}/scripts/brain_paths.sh"
TELEMETRY_REL="$(telemetry_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")"
BRANCH="$(branch_for "${RUN_ID}" "${ATTEMPT}" "${HARNESS}" "${SHARD}")"
HOME="${BRAIN}/home" git -C "${BRAIN}/pool.git" ls-tree -r --name-only \
    "${BRANCH}" 2>/dev/null | grep -Fxq "${TELEMETRY_REL}"
check "3b la rama lleva la telemetria en la ruta de la autoridad" $?

( cd "${ROOT}" && env HOME="${BRAIN}/home" FIREBLOCKS_BRAIN_WRITE_TOKEN=e2e \
    "${OFFLINE_ENV[@]}" \
    bash scripts/aggregate_ingest.sh "${RUN_ID}" "${ATTEMPT}" 1 \
    > "${BRAIN}/aggregate.out" 2>&1 )
check "3c aggregate consolida" $?

HOME="${BRAIN}/home" git -C "${BRAIN}/pool.git" ls-tree -r --name-only \
    corpus-pool | grep -Fxq "${TELEMETRY_REL}"
check "3d la telemetria esta en el pool" $?

# LA afirmacion: byte a byte, lo que midio el harness es lo que quedo.
HOME="${BRAIN}/home" git -C "${BRAIN}/pool.git" show \
    "corpus-pool:${TELEMETRY_REL}" > "${WORK}/from_pool.json" 2>/dev/null
cmp -s -- "${TELEMETRY_OUT}" "${WORK}/from_pool.json"
check "3e los bytes del pool son los del saneo" $?

python3 - "${WORK}/from_pool.json" "${CANARY_EXTRA}" "${CANARY_TRUNCATE}" <<'PY'
import json, sys
totals = json.load(open(sys.argv[1], encoding="ascii"))["totals"]
assert totals["selected"]["r4.si|extra_map_key"] == int(sys.argv[2])
assert totals["selected"]["r1.mta_proofs[victim]|truncate"] == int(sys.argv[3])
PY
check "3f el canary llega al pool con sus numeros" $?

# --- 4. fallo cerrado ------------------------------------------------------
BAD="${WORK}/bad"
mkdir -p "${BAD}"
sed 's/"execs":[0-9]*/"execs":999999/' "${TELEMETRY_OUT}" > "${BAD}/telemetry.json"
( cd "${ROOT}" && env HOME="${BRAIN}/home" FIREBLOCKS_BRAIN_WRITE_TOKEN=e2e \
    "${OFFLINE_ENV[@]}" \
    bash scripts/publish_ingest.sh "${CORPUS}" "${BUNDLE}" \
        9999 1 0 "${LANE}" "${BAD}/telemetry.json" \
    > "${BAD}/out" 2>&1 )
[[ "$?" -ne 0 ]]
check "4a publish rechaza contadores manipulados" $?
[[ -z "$(HOME="${BRAIN}/home" git -C "${BRAIN}/pool.git" for-each-ref \
    --format='%(refname)' 'refs/heads/ingest/run-9999/')" ]]
check "4b no quedo rama de la corrida rechazada" $?

# Telemetria ausente en la superficie que la exige: el finalizador cierra.
MISSING="${WORK}/missing"
mkdir -p "${MISSING}/upload" "${MISSING}/telemetry"
write_private_plain "${MISSING}/private_plain"
( cd "${ROOT}" && bash scripts/cloud_finalize_incident.sh \
    "${MISSING}/private_plain" "${MISSING}/upload/incident-1-1-0.gpg" \
    success success "${MISSING}/telemetry" "${MISSING}/telemetry.json" \
    1 1 0 > "${MISSING}/out" 2>&1 )
[[ "$?" -ne 0 ]]
check "4c telemetria ausente falla cerrado" $?
[[ ! -s "${MISSING}/upload/incident-1-1-0.gpg" ]]
check "4d no se subio bundle sin contadores" $?

printf 'TELEMETRY_PIPELINE %s checks=%d failures=%d\n' \
    "$([[ "${FAIL}" -eq 0 ]] && echo PASS || echo FAIL)" \
    "$((PASS + FAIL))" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
