#pragma once

// Dos ceremonias de firma CONCURRENTES sobre la misma clave y los mismos
// jugadores, con el intercalado como unica variable.
//
// POR QUE EXISTE. El harness de alcance mide que la libreria rechaza entradas
// corruptas, y esa frontera se sostiene: en una medicion de 180 s, las 134
// mutaciones aplicadas murieron en la ronda donde se inyectaron (76 en la 2,
// 58 en la 5) y ninguna avanzo. Mandar mas corrupciones contra esa puerta
// explora mas entradas del mismo camino rechazado; el codigo profundo -- la
// maquina de estados despues de validar, el ensamblado de firma -- nunca corre
// con estado influido por el atacante.
//
// Aqui las dos ceremonias COMPLETAN. Lo que se prueba no es si la libreria
// rechaza basura, sino si dos ceremonias validas simultaneas se contaminan.
//
// QUE COMPARTEN, que es lo que hace que esto pueda encontrar algo:
//   - el store de firma va indexado por txid (store/load/update/delete
//     _cmp_signing_data), asi que los dos txid viven en el mismo mapa por
//     jugador: leer, escribir o borrar el txid equivocado corrompe a la otra;
//   - platform_service es uno por jugador y lo comparten las dos, y ahi vive
//     gen_random();
//   - el key store es el mismo, porque las dos firman con la MISMA clave.
//
// Esa ultima decision es deliberada. Con claves distintas las sesiones casi no
// comparten nada y el oraculo de nonce seria teorico. Con la misma clave y dos
// mensajes distintos, dos firmas que compartan r revelan la clave privada: es
// el hallazgo que paga, no el crash.
//
// ALCANCE. Un solo hilo. Esto prueba CONFUSION DE ESTADO -- reentrada de una
// maquina de estados determinista -- no data races. Para races harian falta
// hilos y TSan, y TSan no combina con ASan.

#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/snapshot.h"

#include "cosigner/types.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace opus {

enum class ceremony_state {
    PENDING,     // no ha empezado
    RUNNING,     // avanzo alguna ronda
    COMPLETED,   // produjo firma
    REJECTED,    // la libreria lanzo (rechazo limpio)
    FAULTED,     // el harness no pudo construir el caso
};

const char* to_string(ceremony_state s);

struct ceremony_report
{
    ceremony_state state = ceremony_state::PENDING;
    int  rounds_completed = 0;              // 0..5
    bool signature_produced = false;
    std::string exception_type;
    std::string detail;
};

struct dual_oracle_observation
{
    bool both_completed = false;
    bool signatures_observed = false;
    bool signature_a_valid = false;
    bool signature_b_valid = false;
    bool cross_ab = false;
    bool cross_ba = false;
    bool messages_distinct = false;
    bool nonce_equal = false;
    bool other_records_unchanged = true;
    bool rollback_a_clean = true;
    bool rollback_b_clean = true;
    bool key_stores_unchanged = true;
    bool harness_fault = false;
};

struct dual_oracle_verdict
{
    bool signatures_valid = false;
    bool cross_session_verification = false;
    bool nonce_reuse = false;
    bool state_isolation = true;
    bool rollback_clean = true;
    bool key_store_unchanged = true;
    bool harness_fault = false;
};

dual_oracle_verdict evaluate_dual_oracles(const dual_oracle_observation& observation);

struct dual_result
{
    // --- progreso ---------------------------------------------------------
    bool both_completed = false;
    int  max_round_reached = 0;             // maximo entre las dos
    // Pasos ejecutados DESPUES del primer cruce real de ceremonia. Cero
    // significa que el schedule degenero en secuencial y el caso no probo
    // intercalado: no cuenta como cobertura.
    int  advanced_past_injection = 0;
    int  interleave_points = 0;             // cuantas veces cambio el turno

    // --- oraculos ---------------------------------------------------------
    bool signatures_valid = false;          // cada firma verifica su mensaje
    bool cross_session_verification = false; // true = HALLAZGO: A verifica B
    bool nonce_reuse = false;               // true = HALLAZGO: mismo r
    bool state_isolation = true;            // false = HALLAZGO: B toco a A
    bool rollback_clean = true;             // false = HALLAZGO: resto parcial
    bool key_store_unchanged = true;
    bool harness_fault = false;

    ceremony_report a;
    ceremony_report b;

    // Traza real del turno concedido, para reproducir. Solo indices 0/1.
    std::vector<uint8_t> schedule;
    uint64_t elapsed_ms = 0;
    // Motivo fijo del codigo, NUNCA contenido derivado de la entrada.
    std::string detail;

    bool any_finding() const
    {
        return cross_session_verification || nonce_reuse || !state_isolation ||
               !rollback_clean || !key_store_unchanged ||
               (both_completed && !signatures_valid);
    }
};

// Compares every semantic field and deliberately excludes elapsed_ms.
bool semantic_equal(const ceremony_report& lhs, const ceremony_report& rhs);
bool semantic_equal(const dual_result& lhs, const dual_result& rhs);

// Mundo compartido por las dos ceremonias: un player_ctx por jugador, con su
// platform_service y su store de firma. Que sea UNO solo es la premisa del
// harness -- con contextos separados las ceremonias no comparten nada y el
// intercalado seria equivalente a correrlas en serie.
class dual_session
{
public:
    dual_session(const snapshot& snap, const std::string& key_id, std::string& err);

    bool ok() const { return _ok; }
    const std::vector<uint64_t>& ids() const { return _ids; }

    // schedule: cada byte concede el turno a la ceremonia (byte & 1). Se
    // consume hasta que ambas terminan o se agota; al agotarse se completa lo
    // que falte en orden fijo, para que un schedule corto no invente un
    // rechazo que la libreria no produjo.
    dual_result run(uint64_t seed, const std::vector<uint8_t>& schedule);

private:
    bool _ok = false;
    std::string _key_id;
    snapshot _snap;
    std::vector<uint64_t> _ids;
    std::map<uint64_t, det_key_persistency> _key_stores;
};

} // namespace opus
