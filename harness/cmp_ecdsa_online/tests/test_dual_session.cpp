// Control del harness dual: dos ceremonias validas concurrentes.
//
// Esta es la puerta FAIL-CLOSED de todo el diseño. Si dos ceremonias sobre la
// misma clave no pueden completar y verificar de forma independiente, no hay
// nada que fuzzear: cualquier "hallazgo" posterior seria el fixture, no la
// libreria. Por eso el control se comprueba ANTES que cualquier intercalado
// interesante, y su fallo detiene el harness en vez de degradarlo.
//
// Todo sintetico: snapshot determinista, mensajes fijos, cero red.

#include "opus/dual_session.h"
#include "opus/snapshot.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(const char* what, bool ok, const std::string& extra = "")
{
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s %s\n", what, extra.c_str());
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_dual_session SNAPSHOT\n");
        return 64;
    }

    opus::snapshot snap;
    std::string err;
    if (!opus::read_snapshot(argv[1], snap, err) ||
        !opus::verify_snapshot(snap, err)) {
        std::fprintf(stderr, "DUAL_CONTROL_FAIL_CLOSED reason=snapshot_invalid\n");
        return 65;
    }

    opus::dual_session dual(snap, "opus-key", err);
    if (!dual.ok()) {
        std::fprintf(stderr, "DUAL_CONTROL_FAIL_CLOSED reason=session_invalid\n");
        return 65;
    }

    // --- 1. control secuencial: sin intercalado, ambas deben completar ------
    // Se prueba primero porque separa dos causas: si esto falla, el problema
    // es ejecutar dos ceremonias sobre la misma clave, no el intercalado.
    {
        std::vector<uint8_t> sequential;
        for (int i = 0; i < 5; ++i) sequential.push_back(0);
        for (int i = 0; i < 5; ++i) sequential.push_back(1);
        const opus::dual_result r = dual.run(1, sequential);

        check("control secuencial completa las dos", r.both_completed,
              std::string(opus::to_string(r.a.state)) + "/" + opus::to_string(r.b.state) +
              " a[" + r.a.exception_type + ":" + r.a.detail + "]" +
              " b[" + r.b.exception_type + ":" + r.b.detail + "]");
        check("control secuencial: firmas validas", r.signatures_valid);
        check("control secuencial: sin harness fault", !r.harness_fault, r.detail);
        check("control secuencial: alcanza la ronda 5", r.max_round_reached == 5,
              std::to_string(r.max_round_reached));
        check("control secuencial: sin verificacion cruzada", !r.cross_session_verification);
        check("control secuencial: sin reutilizacion de nonce", !r.nonce_reuse);
        check("control secuencial: aislamiento de estado", r.state_isolation, r.detail);
        check("control secuencial: rollback limpio", r.rollback_clean);
        check("control secuencial: key store intacto", r.key_store_unchanged);
    }

    // --- 2. control intercalado: alternancia estricta -----------------------
    {
        std::vector<uint8_t> alternating;
        for (int i = 0; i < 12; ++i) alternating.push_back(static_cast<uint8_t>(i & 1));
        const opus::dual_result r = dual.run(1, alternating);

        check("intercalado completa las dos", r.both_completed,
              std::string(opus::to_string(r.a.state)) + "/" + opus::to_string(r.b.state));
        check("intercalado: firmas validas", r.signatures_valid);
        check("intercalado: sin harness fault", !r.harness_fault, r.detail);
        // La afirmacion central: hubo cruce real y se ejecutaron pasos DESPUES.
        check("intercalado: hubo cruces de turno", r.interleave_points > 0,
              std::to_string(r.interleave_points));
        check("intercalado: avanzo tras el primer cruce", r.advanced_past_injection > 0,
              std::to_string(r.advanced_past_injection));
        check("intercalado: sin verificacion cruzada", !r.cross_session_verification);
        check("intercalado: sin reutilizacion de nonce", !r.nonce_reuse);
        check("intercalado: aislamiento de estado", r.state_isolation, r.detail);
        check("intercalado: rollback limpio", r.rollback_clean);
    }

    // --- 3. determinismo: todos los campos semanticos, nunca el reloj -------
    {
        std::vector<uint8_t> s{0, 1, 1, 0, 0, 1, 0, 1, 1, 0};
        const opus::dual_result first = dual.run(7, s);
        for (int repeat = 0; repeat < 5; ++repeat) {
            const opus::dual_result again = dual.run(7, s);
            check("determinista: resultado semantico completo",
                  opus::semantic_equal(first, again), std::to_string(repeat));
        }

        std::vector<uint8_t> ab(5, 0);
        ab.insert(ab.end(), 5, 1);
        std::vector<uint8_t> ba(5, 1);
        ba.insert(ba.end(), 5, 0);
        const opus::dual_result first_a = dual.run(9, ab);
        const opus::dual_result first_b = dual.run(9, ba);
        check("orden A-B completa", first_a.both_completed && first_a.signatures_valid);
        check("orden B-A completa", first_b.both_completed && first_b.signatures_valid);
        check("orden no cambia oraculos",
              first_a.cross_session_verification == first_b.cross_session_verification &&
              first_a.nonce_reuse == first_b.nonce_reuse &&
              first_a.state_isolation == first_b.state_isolation &&
              first_a.rollback_clean == first_b.rollback_clean &&
              first_a.key_store_unchanged == first_b.key_store_unchanged &&
              first_a.harness_fault == first_b.harness_fault);
    }

    // --- 4. un schedule corto no puede inventar un rechazo -----------------
    {
        const opus::dual_result r = dual.run(3, std::vector<uint8_t>{0});
        check("schedule corto: igual completa las dos", r.both_completed,
              std::string(opus::to_string(r.a.state)) + "/" + opus::to_string(r.b.state));
        check("schedule corto: sin harness fault", !r.harness_fault, r.detail);
    }

    // --- 5. las dos ceremonias son distinguibles ---------------------------
    // Mensajes iguales harian que el oraculo de nonce no significara nada.
    {
        std::vector<uint8_t> alternating;
        for (int i = 0; i < 12; ++i) alternating.push_back(static_cast<uint8_t>(i & 1));
        const opus::dual_result r = dual.run(11, alternating);
        check("las dos completan con mensajes distintos", r.both_completed);
        check("y sus firmas no comparten r", !r.nonce_reuse);
    }

    if (failures != 0) {
        std::fprintf(stderr, "DUAL_CONTROL_FAIL_CLOSED failures=%d\n", failures);
        return 1;
    }
    std::printf("DUAL_CONTROL_PASS cases=5\n");
    return 0;
}
