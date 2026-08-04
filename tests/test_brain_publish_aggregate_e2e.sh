#!/usr/bin/env bash
# E2E: publish_ingest.sh y aggregate_ingest.sh REALES contra repositorios git
# bare locales. Sin mocks de git.
#
# Existe porque el canary del run que introdujo las dos superficies fallo en la
# publicacion y ninguna prueba lo vio: las dos mitades del flujo se ejercitaban
# por separado y publish_ingest.sh solo se corria hasta el borde de la red.
# Aqui el flujo va entero, y el primer caso es exactamente el que fallo.
#
# Sin red: el remoto de GitHub se reescribe a un bare local con
# url.<local>.insteadOf en un HOME aislado, y el proxy apunta a un puerto
# cerrado del bucle local para que cualquier intento de salir falle al
# instante. Todos los datos son sinteticos.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
    # Los bares se crean de solo lectura en un caso; hay que poder borrarlos.
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

new_brain() { # nombre
    local d="${WORK}/$1"
    mkdir -p "${d}/home"
    # --initial-branch existe desde git 2.28; symbolic-ref funciona en
    # cualquier version, y la imagen de CI puede traer una mas vieja.
    git init -q --bare "${d}/pool.git"
    git -C "${d}/pool.git" symbolic-ref HEAD refs/heads/corpus-pool
    # Identidad explicita: el banco no depende de que el entorno tenga una
    # global configurada. Sin esto, `git commit` falla con "empty ident name"
    # en cualquier CI limpio.
    cat > "${d}/home/.gitconfig" <<EOF
[url "file://${d}/pool.git"]
	insteadOf = https://github.com/creador777/fireblocks-mpc-brain.git
[user]
	name = brain-e2e
	email = brain-e2e@invalid
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

synthetic_unit() { # directorio etiqueta -> imprime el nombre
    local payload="synthetic-corpus-unit:$2" name
    name="$(printf '%s' "${payload}" | sha1sum | cut -d' ' -f1)"
    printf '%s' "${payload}" > "$1/${name}"
    printf '%s\n' "${name}"
}

synthetic_bundle() { # ruta
    # Packet tag GPG valido seguido de relleno sintetico. No es evidencia.
    printf '\x85\x02\x0c\x03synthetic-bundle-not-evidence' > "$1"
}

publish() { # brain lane run attempt shard etiquetas...
    local d="$1" lane="$2" run="$3" attempt="$4" shard="$5"
    shift 5
    local corpus="${d}/corpus-${lane}-${run}-${shard}"
    mkdir -p "${corpus}"
    local tag
    for tag in "$@"; do synthetic_unit "${corpus}" "${tag}" >/dev/null; done
    local bundle="${d}/incident-${run}-${attempt}-${shard}.gpg"
    synthetic_bundle "${bundle}"
    ( cd "${ROOT}" && env HOME="${d}/home" FIREBLOCKS_BRAIN_WRITE_TOKEN=e2e \
        "${OFFLINE_ENV[@]}" \
        bash scripts/publish_ingest.sh "${corpus}" "${bundle}" \
            "${run}" "${attempt}" "${shard}" "${lane}" \
        >> "${d}/public.out" 2>&1 )
}

aggregate() { # brain run attempt count
    ( cd "${ROOT}" && env HOME="$1/home" FIREBLOCKS_BRAIN_WRITE_TOKEN=e2e \
        "${OFFLINE_ENV[@]}" \
        bash scripts/aggregate_ingest.sh "$2" "$3" "$4" \
        >> "$1/public.out" 2>&1 )
}

pool_paths() { HOME="$1/home" git -C "$1/pool.git" ls-tree -r --name-only corpus-pool 2>/dev/null; }
pool_head()  { HOME="$1/home" git -C "$1/pool.git" rev-parse corpus-pool 2>/dev/null; }
pool_commits() { HOME="$1/home" git -C "$1/pool.git" rev-list --count corpus-pool 2>/dev/null; }
ingest_refs() {
    HOME="$1/home" git -C "$1/pool.git" for-each-ref \
        --format='%(refname:short)' refs/heads/ingest 2>/dev/null
}

# --- 1. el caso exacto que fallo -----------------------------------------
B="$(new_brain c1)"
publish "${B}" cmp_r4_tn 100 1 0 alfa
check "1a publish lane-aware" $?
branch="$(ingest_refs "${B}")"
expected="$(cd "${ROOT}" && bash scripts/brain_paths.sh branch_for 100 1 \
    cmp_ecdsa_online_r4_tn 0)"
[[ "${branch}" == "${expected}" ]]
check "1b la rama publicada es branch_for(tupla)" $? "${branch}"
aggregate "${B}" 100 1 1
check "1c aggregate encuentra ESA misma rama" $?
pool_paths "${B}" | grep -q '^corpus/cmp_ecdsa_online_r4_tn/'
check "1d la unidad quedo consolidada" $?
pool_paths "${B}" | grep -q '^incidents/run-100/cmp_ecdsa_online_r4_tn-attempt-1-shard-0\.gpg$'
check "1e el incidente quedo consolidado" $?

# --- 2. publish sin aggregate, y reconciliacion posterior ----------------
B="$(new_brain c2)"
publish "${B}" cmp_general 200 1 0 beta
before="$(pool_head "${B}")"
[[ -n "$(ingest_refs "${B}")" && "$(pool_head "${B}")" == "${before}" ]]
check "2a publicado: rama viva y pool intacto" $?
aggregate "${B}" 200 1 1
check "2b la reconciliacion posterior consolida" $?
ingest_refs "${B}" | grep -q 'cmp_ecdsa_online/shard-0$'
check "2c la rama sobrevive al aggregate" $?

# --- 3. brain ausente y vacio -> fail-closed -----------------------------
D="${WORK}/c3a"; mkdir -p "${D}/home"
cat > "${D}/home/.gitconfig" <<EOF
[url "file://${D}/missing.git"]
	insteadOf = https://github.com/creador777/fireblocks-mpc-brain.git
[user]
	name = brain-e2e
	email = brain-e2e@invalid
[protocol "file"]
	allow = always
EOF
publish "${D}" cmp_r4_tn 1 1 0 gamma
[[ "$?" -ne 0 ]]
check "3a brain ausente: falla cerrado" $?

B="$(new_brain c3b)"
HOME="${B}/home" git -C "${B}/pool.git" update-ref -d refs/heads/corpus-pool
publish "${B}" cmp_r4_tn 1 1 0 delta
[[ "$?" -ne 0 ]]
check "3b brain sin corpus-pool: falla cerrado" $?

# --- 4. concurrencia -----------------------------------------------------
B="$(new_brain c4)"
publish "${B}" cmp_r4_tn 400 1 0 uno
publish "${B}" cmp_r4_tn 400 1 0 dos
[[ "$?" -ne 0 ]]
check "4a segunda publicacion a la misma rama: falla cerrado" $?
publish "${B}" cmp_r4_tn 400 1 1 tres
check "4b un shard distinto publica sin colisionar" $?
[[ "$(ingest_refs "${B}" | wc -l)" -eq 2 ]]
check "4c quedan dos ramas disjuntas" $?

# --- 5. idempotencia -----------------------------------------------------
B="$(new_brain c5)"
publish "${B}" cmp_r4_tn 500 1 0 epsilon
aggregate "${B}" 500 1 1
paths_once="$(pool_paths "${B}" | sort)"
commits_once="$(pool_commits "${B}")"
head_once="$(pool_head "${B}")"
aggregate "${B}" 500 1 1
[[ "$(pool_paths "${B}" | sort)" == "${paths_once}" ]]
check "5a segunda pasada: mismas rutas" $?
[[ "$(pool_commits "${B}")" == "${commits_once}" ]]
check "5b segunda pasada: sin commit nuevo" $?
[[ "$(pool_head "${B}")" == "${head_once}" ]]
check "5c segunda pasada: el HEAD no avanza" $?
[[ "$(pool_paths "${B}" | grep -c '^corpus/cmp_ecdsa_online_r4_tn/')" -eq 1 ]]
check "5d el corpus no se duplica" $?

# --- 6. separacion de lanes ----------------------------------------------
B="$(new_brain c6)"
publish "${B}" cmp_general 600 1 0 general_unit
publish "${B}" cmp_r4_tn   600 1 1 r4tn_unit
aggregate "${B}" 600 1 5
[[ "$(pool_paths "${B}" | grep -c '^corpus/cmp_ecdsa_online/')" -eq 1 ]]
check "6a la unidad general vive en su subarbol" $?
[[ "$(pool_paths "${B}" | grep -c '^corpus/cmp_ecdsa_online_r4_tn/')" -eq 1 ]]
check "6b la unidad r4_tn vive en el suyo" $?
[[ "$(pool_paths "${B}" | grep -c 'incidents/run-600/cmp_ecdsa_online-')" -eq 1 &&
   "$(pool_paths "${B}" | grep -c 'incidents/run-600/cmp_ecdsa_online_r4_tn-')" -eq 1 ]]
check "6c los incidentes llevan su superficie" $?
[[ "$(ingest_refs "${B}" | grep -c '/cmp_ecdsa_online/')" -eq 1 &&
   "$(ingest_refs "${B}" | grep -c '/cmp_ecdsa_online_r4_tn/')" -eq 1 ]]
check "6d las ramas llevan su superficie" $?

# --- 7. fallo antes de publish -------------------------------------------
B="$(new_brain c7)"
before="$(pool_head "${B}")"
publish "${B}" cmp_r4_tn 1 1 99 zeta        # shard fuera del rango cerrado
[[ "$?" -ne 0 && "$(pool_head "${B}")" == "${before}" && -z "$(ingest_refs "${B}")" ]]
check "7a fallo antes de publicar: nada escrito" $?
publish "${B}" cmp_no_existe 1 1 0 eta      # lane desconocida
[[ "$?" -ne 0 && -z "$(ingest_refs "${B}")" ]]
check "7b lane desconocida: nada escrito" $?

# --- 8. aggregate interrumpido -------------------------------------------
# Interrupcion determinista: el bare pasa a solo lectura, asi que el agregador
# hace su fetch y su commit local pero su push es rechazado. Un timeout por
# reloj no sirve: contra un bare local el agregado termina en decimas.
B="$(new_brain c8)"
publish "${B}" cmp_r4_tn 800 1 0 theta
before="$(pool_head "${B}")"
chmod -R a-w "${B}/pool.git"
aggregate "${B}" 800 1 1
chmod -R u+w "${B}/pool.git"
[[ "$(pool_head "${B}")" == "${before}" ]]
check "8a interrumpido: el pool no avanzo" $?
ingest_refs "${B}" | grep -q 'cmp_ecdsa_online_r4_tn'
check "8b la rama sigue recuperable" $?
aggregate "${B}" 800 1 1
check "8c al reintentar, consolida" $?
pool_paths "${B}" | grep -q '^corpus/cmp_ecdsa_online_r4_tn/'
check "8d la unidad llego al pool" $?

# --- 9. leak scan de la salida publica -----------------------------------
# Se excluye la ruta del banco: existe porque el remoto de ESTE test es
# file://, y en produccion es una URL. Lo que se busca es contenido privado.
leaks=0
for log in "${WORK}"/*/public.out; do
    [[ -f "${log}" ]] || continue
    if grep -vF "${WORK}" "${log}" |
       grep -qE 'Base64:|artifact_prefix|Test unit written|synthetic-corpus-unit|/home/runner/'; then
        leaks=$((leaks + 1))
    fi
done
[[ "${leaks}" -eq 0 ]]
check "9a ningun marcador prohibido en la salida" $? "logs=${leaks}"

printf 'BRAIN_E2E %s checks=%d failures=%d\n' \
    "$([[ "${FAIL}" -eq 0 ]] && echo PASS || echo FAIL)" \
    "$((PASS + FAIL))" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
