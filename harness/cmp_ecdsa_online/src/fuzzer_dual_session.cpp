// Punto de entrada libFuzzer de la lane cmp_dual.
//
// La entrada controla UNA sola cosa: el orden en que se conceden los turnos a
// dos ceremonias validas. No hay corrupcion de mensajes, ni replay, ni cruce
// de sesiones -- esas familias se añaden despues, una por una, para que cuando
// algo aparezca se sepa cual lo produjo.
//
// La telemetria reutiliza el registro de celdas existente sin cambiarle la
// forma: exactamente UNA celda seleccionada por ejecucion decodificada (la
// clase de schedule), applied cuando el caso realmente intercalo, y el
// veredicto en el vocabulario que ya validan validate_rt4.py y
// telemetry_evidence.py. Inventar campos nuevos habria obligado a tocar el
// esquema, el validador, el saneador y sus pruebas para no ganar nada.

#include "opus/dual_session.h"
#include "opus/snapshot.h"
#include "opus/telemetry_v2.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct runtime_dual
{
    opus::snapshot snap;
    std::unique_ptr<opus::dual_session> session;
    uint64_t shard_seed = 0;
};

runtime_dual& state() { static runtime_dual value; return value; }

[[noreturn]] void fail_closed(const char* reason)
{
    std::fprintf(stderr, "FIREBLOCKS_HARNESS_FAIL_CLOSED reason=%s\n", reason);
    std::fflush(stderr);
    std::_Exit(86);
}

[[noreturn]] void signal_finding(const char* oracle)
{
    // Solo el NOMBRE del oraculo, que es una cadena fija de este fichero.
    // Nunca r, s, mensaje, txid, share ni traza.
    std::fprintf(stderr, "FIREBLOCKS_HIGH_SIGNAL oracle=%s\n", oracle);
    std::fflush(stderr);
    std::abort();
}

uint64_t fnv1a64(const uint8_t* data, size_t size)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

// Clase de schedule. Es la celda: exactamente una por ejecucion decodificada,
// que es lo que mantienen ciertas las ecuaciones del validador.
const char* schedule_cell(int crossings, size_t steps)
{
    if (crossings == 0)
        return "dual.schedule|sequential";
    if (steps > 0 && static_cast<size_t>(crossings) * 2 >= steps)
        return "dual.schedule|alternating";
    return "dual.schedule|blocked";
}

void publish_telemetry_at_exit()
{
    opus::telemetry_v2::publish();
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    const char* snapshot_path = std::getenv("FIREBLOCKS_SNAPSHOT");
    if (!snapshot_path || !*snapshot_path)
        fail_closed("snapshot_path_missing");

    runtime_dual& rt = state();
    std::string error;
    if (!opus::read_snapshot(snapshot_path, rt.snap, error) ||
        !opus::verify_snapshot(rt.snap, error))
        fail_closed("snapshot_invalid");

    if (const char* shard = std::getenv("FIREBLOCKS_SHARD_SEED"))
        rt.shard_seed = static_cast<uint64_t>(std::strtoull(shard, nullptr, 10));

    rt.session = std::make_unique<opus::dual_session>(rt.snap, "opus-key", error);
    if (!rt.session || !rt.session->ok())
        fail_closed("session_invalid");

    // PUERTA DE ARRANQUE. Antes de aceptar un solo input se exige que dos
    // ceremonias validas completen y verifiquen. Si el fixture no puede
    // producir el control, cualquier "hallazgo" posterior seria el harness:
    // mas vale no arrancar que reportar ruido.
    {
        std::vector<uint8_t> alternating;
        for (int i = 0; i < 12; ++i)
            alternating.push_back(static_cast<uint8_t>(i & 1));
        const opus::dual_result control = rt.session->run(rt.shard_seed, alternating);
        if (!control.both_completed || !control.signatures_valid ||
            control.harness_fault || control.any_finding())
            fail_closed("dual_control_failed");
    }

    int fork_flag = 0;
    if (argc && argv && *argv) {
        for (int i = 0; i < *argc; ++i) {
            const std::string arg((*argv)[i]);
            if (arg.rfind("-fork=", 0) == 0)
                fork_flag = std::atoi(arg.c_str() + 6);
        }
    }
    const char* tdir = std::getenv("FIREBLOCKS_TELEMETRY_DIR");
    if (tdir && *tdir && fork_flag <= 0) {
        const char* control_dir = std::getenv("FIREBLOCKS_TELEMETRY_CONTROL_DIR");
        const char* fc = std::getenv("FIREBLOCKS_FORK_COUNT");
        if (!control_dir || !*control_dir ||
            !opus::telemetry_v2::configure(tdir, control_dir, "v3-dual-session",
                                           "clang", "asan+ubsan",
                                           fc ? std::atoi(fc) : 1))
            fail_closed("telemetry_config_invalid");
        std::atexit(publish_telemetry_at_exit);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Puerta lo mas ancha posible. Un solo byte YA es un schedule util: cede
    // un turno y el bucle completa el resto en orden fijo, asi que el caso
    // intercala igual. Con el minimo en dos bytes se descartaba el 13.3% de
    // las ejecuciones -- libFuzzer genera muchas entradas de un byte al
    // principio -- y eso es presupuesto tirado, no seguridad. Solo se rechaza
    // lo que no puede formar un schedule: vacio, o mas largo que el limite.
    if (!data || size < 1 || size > 4096) {
        if (!opus::telemetry_v2::record_door_reject())
            fail_closed("telemetry_publish_failed");
        return 0;
    }

    runtime_dual& rt = state();
    if (!rt.session)
        fail_closed("runtime_not_initialized");

    // El seed sale de TODO el input, para que dos schedules distintos no
    // compartan la aleatoriedad y un hallazgo sea reproducible desde el fichero.
    const uint64_t seed = rt.shard_seed ^ fnv1a64(data, size);
    const std::vector<uint8_t> schedule(data, data + size);

    const opus::dual_result r = rt.session->run(seed, schedule);

    if (r.harness_fault)
        fail_closed("harness_fault");

    const char* cell = schedule_cell(r.interleave_points, r.schedule.size());
    // applied = el caso intercalo de verdad y siguio avanzando. Un schedule
    // que degenero en secuencial no probo nada y no debe contarse como
    // cobertura, igual que una mutacion que no cambio un byte.
    const bool applied = (r.advanced_past_injection > 0);

    const char* verdict = nullptr;
    if (applied) {
        if (r.cross_session_verification)  verdict = "INVALID-SIGNATURE";
        else if (r.nonce_reuse)            verdict = "STATE-CORRUPTION";
        else if (!r.state_isolation)       verdict = "STATE-CORRUPTION";
        else if (!r.rollback_clean)        verdict = "STATE-CORRUPTION";
        else if (!r.key_store_unchanged)   verdict = "STATE-CORRUPTION";
        else if (r.both_completed && !r.signatures_valid) verdict = "INVALID-SIGNATURE";
        else if (r.both_completed)         verdict = "CLEAN-SIGN";
        else                               verdict = "CLEAN-REJECT";
    }

    if (!opus::telemetry_v2::record_case(cell, applied, verdict))
        fail_closed("telemetry_publish_failed");

    // Se aborta DESPUES de contabilizar, para que el contador del hallazgo
    // viaje en el bundle aunque el proceso muera aqui.
    if (applied) {
        if (r.cross_session_verification) signal_finding("cross_session_verification");
        if (r.nonce_reuse)                signal_finding("nonce_reuse");
        if (!r.state_isolation)           signal_finding("state_isolation");
        if (!r.rollback_clean)            signal_finding("rollback_clean");
        if (!r.key_store_unchanged)       signal_finding("key_store_changed");
        if (r.both_completed && !r.signatures_valid)
            signal_finding("signature_invalid");
    }
    return 0;
}
