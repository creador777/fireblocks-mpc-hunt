// Coverage-guided adapter for the validated deterministic CMP ECDSA harness.
// Input bytes select one authenticated malicious peer and one bounded wire mutation.

#include "opus/det_rand.h"
#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/snapshot.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

namespace {

struct field_spec {
    int round;
    opus::wire_field field;
    bool byte_vector;
};

constexpr std::array<field_spec, 15> FIELDS{{
    {1, opus::wire_field::R1_MTA_MESSAGE, true},
    {1, opus::wire_field::R1_MTA_COMMITMENT, true},
    {1, opus::wire_field::R1_MTA_PROOFS_ENTRY, true},
    {1, opus::wire_field::R1_POINT_A, false},
    {1, opus::wire_field::R1_POINT_B, false},
    {1, opus::wire_field::R1_POINT_Z, false},
    {2, opus::wire_field::R2_ACK, false},
    {2, opus::wire_field::R2_K_GAMMA_MTA_MESSAGE, true},
    {2, opus::wire_field::R2_K_X_MTA_MESSAGE, true},
    {2, opus::wire_field::R2_GAMMA, false},
    {2, opus::wire_field::R2_GAMMA_PROOFS_ENTRY, true},
    {3, opus::wire_field::R3_DELTA, false},
    {3, opus::wire_field::R3_DELTA_POINT, false},
    {3, opus::wire_field::R3_PROOF, true},
    {4, opus::wire_field::R4_SI, false},
}};

struct runtime {
    opus::snapshot snap;
    std::unique_ptr<opus::session> session;
    uint64_t shard_seed = 0;
};

runtime& state()
{
    static runtime value;
    return value;
}

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

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    opus::silence_library_logging();
    if (!opus::install_deterministic_rand() || !opus::self_test())
        fail_closed("deterministic_rng_unavailable");

    const char* snapshot_path = std::getenv("FIREBLOCKS_SNAPSHOT");
    if (!snapshot_path || !*snapshot_path)
        fail_closed("snapshot_path_missing");

    std::string error;
    runtime& rt = state();
    if (!opus::read_snapshot(snapshot_path, rt.snap, error) ||
        !opus::verify_snapshot(rt.snap, error))
        fail_closed("snapshot_invalid");

    std::string rng_detail;
    if (!opus::rng_is_effective(rt.snap, rng_detail))
        fail_closed("rng_not_effective");
    if (rt.snap.players.size() < 2)
        fail_closed("insufficient_players");

    if (const char* shard = std::getenv("FIREBLOCKS_SHARD_SEED"))
        rt.shard_seed = std::strtoull(shard, nullptr, 10);

    rt.session = std::make_unique<opus::session>(rt.snap, "opus-key", error);
    if (!rt.session->ok())
        fail_closed("session_unavailable");
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size < 8 || size > 4096)
        return 0;

    runtime& rt = state();
    if (!rt.session)
        fail_closed("runtime_not_initialized");

    const field_spec& selected = FIELDS[data[0] % FIELDS.size()];
    const size_t blocks = 1 + (data[1] % 5);
    const uint64_t attacker =
        rt.snap.players[data[2] % rt.snap.players.size()].id;

    opus::wire_op operation;
    if (selected.byte_vector) {
        constexpr opus::wire_op BYTE_OPS[] = {
            opus::wire_op::FLIP_BIT,
            opus::wire_op::ZERO,
            opus::wire_op::TRUNCATE,
        };
        operation = BYTE_OPS[data[3] % 3];
    } else {
        operation = (data[3] & 1) ? opus::wire_op::ZERO
                                  : opus::wire_op::FLIP_BIT;
    }

    const uint64_t digest = fnv1a64(data, size) ^ rt.shard_seed;
    opus::run_config config;
    config.seed = digest;
    config.txid = "fz-" + std::to_string(digest);
    config.blocks = blocks;
    config.metadata_json = (data[4] & 1) ? "positive_r" : "";
    config.malicious_ids = {attacker};
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
    if (result.mutations_applied == 0)
        return 0;

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
