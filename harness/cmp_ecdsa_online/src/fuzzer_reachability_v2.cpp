// R4 canary-only V2 fuzzer. V1 remains untouched.
#include "opus/det_rand.h"
#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/snapshot.h"
#include "opus/telemetry_v2.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace {

struct field_spec { int round; opus::wire_field field; bool byte_vector; };
constexpr std::array<field_spec, 2> FIELDS_V2{{
    {1, opus::wire_field::R1_MTA_PROOFS_ENTRY, true},
    {4, opus::wire_field::R4_SI, false},
}};

struct runtime_v2 {
    opus::snapshot snap;
    std::unique_ptr<opus::session> session;
    uint64_t shard_seed = 0;
};

runtime_v2& state() { static runtime_v2 value; return value; }

[[noreturn]] void fail_closed(const char* reason)
{
    std::fprintf(stderr, "FIREBLOCKS_HARNESS_FAIL_CLOSED reason=%s\n", reason);
    std::fflush(stderr);
    std::_Exit(86);
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

[[noreturn]] void signal_finding(const opus::run_result& result)
{
    std::fprintf(stderr,
                 "FIREBLOCKS_HIGH_SIGNAL verdict=%s round=%d mutations_applied=%zu\n",
                 opus::to_string(result.v), result.failed_round,
                 result.mutations_applied);
    std::fflush(stderr);
    std::abort();
}

const char* cell_key(const field_spec& f, opus::wire_op op)
{
    if (f.field == opus::wire_field::R1_MTA_PROOFS_ENTRY) {
        switch (op) {
        case opus::wire_op::FLIP_BIT: return "r1.mta_proofs[victim]|flip_bit";
        case opus::wire_op::ZERO: return "r1.mta_proofs[victim]|zero";
        default: return "r1.mta_proofs[victim]|truncate";
        }
    }
    if (f.field == opus::wire_field::R4_SI && op == opus::wire_op::EXTRA_MAP_KEY)
        return "r4.si|extra_map_key";
    return "";
}

void publish_telemetry_at_exit() { (void)opus::telemetry_v2::publish(); }

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    opus::silence_library_logging();
    if (!opus::install_deterministic_rand() || !opus::self_test())
        fail_closed("deterministic_rng_unavailable");

    const char* snapshot_path = std::getenv("FIREBLOCKS_SNAPSHOT");
    if (!snapshot_path || !*snapshot_path)
        fail_closed("snapshot_path_missing");

    std::string error;
    runtime_v2& rt = state();
    if (!opus::read_snapshot(snapshot_path, rt.snap, error) ||
        !opus::verify_snapshot(rt.snap, error))
        fail_closed("snapshot_invalid");

    std::string rng_detail;
    if (!opus::rng_is_effective(rt.snap, rng_detail))
        {
            std::fprintf(stderr, "FIREBLOCKS_RNG_PROBE_STAGE stage=%s\n",
                         opus::rng_probe_stage());
            std::fflush(stderr);
            fail_closed("rng_not_effective");
        }
    // UNSUPPORTED_CONFIGURATION. Esta lane necesita al menos tres jugadores:
    // con dos no hay forma de tener un firmante, un atacante y un no-firmante
    // a la vez, que es lo que la superficie R4 exige. La combinacion se mide
    // igual en d39ae6e, asi que no es una regresion: es una precondicion.
    //
    // Motivo PROPIO, distinto del invariante de ejecucion de mas abajo: los
    // dos compartian "insufficient_players" y el triage no podia separarlos.
    if (rt.snap.players.size() < 3)
        fail_closed("unsupported_fixture_players");

    if (const char* shard = std::getenv("FIREBLOCKS_SHARD_SEED"))
        rt.shard_seed = std::strtoull(shard, nullptr, 10);

    rt.session = std::make_unique<opus::session>(rt.snap, "opus-key", error);
    if (!rt.session->ok())
        fail_closed("session_invalid");

    int fork_flag = -1;
    if (argc && argv && *argv) {
        for (int i = 0; i < *argc; ++i) {
            const std::string arg((*argv)[i]);
            if (arg.rfind("-fork=", 0) == 0)
                fork_flag = std::atoi(arg.c_str() + 6);
        }
    }
    const char* tdir = std::getenv("FIREBLOCKS_TELEMETRY_DIR");
    if (tdir && *tdir && fork_flag <= 0) {
        const char* control = std::getenv("FIREBLOCKS_TELEMETRY_CONTROL_DIR");
        const char* fc = std::getenv("FIREBLOCKS_FORK_COUNT");
        if (!control || !*control ||
            !opus::telemetry_v2::configure(tdir, control, "v2-r4-extrakey",
                                           "clang", "asan+ubsan",
                                           fc ? std::atoi(fc) : 1))
            fail_closed("telemetry_config_invalid");
        std::atexit(publish_telemetry_at_exit);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size < 8 || size > 4096) {
        if (!opus::telemetry_v2::record_door_reject())
            fail_closed("telemetry_publish_failed");
        return 0;
    }

    runtime_v2& rt = state();
    if (!rt.session)
        fail_closed("runtime_not_initialized");
    const field_spec& selected = FIELDS_V2[data[0] % FIELDS_V2.size()];
    const size_t blocks = 1 + (data[1] % 5);
    const auto& players = rt.session->ids();
    if (players.size() < 2)
        fail_closed("insufficient_players");

    // For a t < n snapshot the ceremony runs with the designated signer set:
    // the first t player ids, the same convention generate_snapshot uses for
    // the aggregate public key. The attacker is always a ceremony
    // participant; a fixture-only player has no wire presence to tamper from.
    std::vector<uint64_t> signers;
    if (static_cast<size_t>(rt.snap.t) < players.size())
        signers.assign(players.begin(), players.begin() + rt.snap.t);
    const std::vector<uint64_t>& participants = signers.empty() ? players : signers;
    const uint64_t attacker = participants[data[2] % participants.size()];

    opus::wire_op operation;
    if (selected.byte_vector) {
        constexpr opus::wire_op BYTE_OPS[] = {
            opus::wire_op::FLIP_BIT, opus::wire_op::ZERO,
            opus::wire_op::TRUNCATE,
        };
        operation = BYTE_OPS[data[3] % 3];
    } else {
        operation = opus::wire_op::EXTRA_MAP_KEY;
    }

    const uint64_t digest = fnv1a64(data, size) ^ rt.shard_seed;
    opus::run_config config;
    config.seed = digest;
    config.txid = "fz2-" + std::to_string(digest);
    config.blocks = blocks;
    config.metadata_json = (data[4] & 1) ? "positive_r" : "";
    config.malicious_ids = {attacker};
    config.signers_ids = signers;   // empty when the fixture is n-of-n
    config.timeout_ms = 30000;

    opus::mutation mutation;
    mutation.round = selected.round;
    mutation.attacker = attacker;
    mutation.field = selected.field;
    mutation.op = operation;
    mutation.block = data[5] % blocks;
    mutation.byte_index = (static_cast<size_t>(data[6]) << 8) | data[7];
    mutation.bit = static_cast<uint8_t>((size > 8 ? data[8] : data[7]) & 7);
    config.mutations.push_back(mutation);

    const opus::run_result result = rt.session->run(config);
    if (result.v == opus::verdict::HARNESS_FAULT)
        fail_closed("harness_fault");
    if (result.mutations_applied == 0) {
        if (!opus::telemetry_v2::record_case(cell_key(selected, operation), false, nullptr))
            fail_closed("telemetry_publish_failed");
        return 0;
    }
    if (!opus::telemetry_v2::record_case(cell_key(selected, operation), true,
                                         opus::to_string(result.v)))
        fail_closed("telemetry_publish_failed");

    // LAB-ONLY: solo el numero de ronda, un entero acotado. Nada mas.
    std::fprintf(stderr, "FIREBLOCKS_ROUND verdict=%s round=%d\n",
                 opus::to_string(result.v), result.failed_round);
    std::fflush(stderr);

    switch (result.v) {
    case opus::verdict::CLEAN_REJECT:
    case opus::verdict::CLEAN_SIGN:
        return 0;
    case opus::verdict::INVALID_SIGNATURE:
    case opus::verdict::STATE_CORRUPTION:
    case opus::verdict::CRASH:
    case opus::verdict::TIMEOUT:
        signal_finding(result);
    case opus::verdict::HARNESS_FAULT:
        fail_closed("harness_fault");
    }
    fail_closed("unknown_verdict");
}
