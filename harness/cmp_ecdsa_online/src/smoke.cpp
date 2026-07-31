// Bounded deterministic local hunting smoke.
// Prints metadata only; never serializes messages, signatures, keys, or inputs.

#include "opus/det_rand.h"
#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/snapshot.h"

#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

struct field_spec {
    const char* name;
    int round;
    opus::wire_field field;
    bool byte_vector;
};

struct case_spec {
    std::string name;
    int round;
    opus::wire_field field;
    opus::wire_op op;
    size_t byte_index;
    uint8_t bit;
};

const field_spec FIELDS[] = {
    {"r1-mta-message",       1, opus::wire_field::R1_MTA_MESSAGE,          true},
    {"r1-mta-commitment",    1, opus::wire_field::R1_MTA_COMMITMENT,       true},
    {"r1-mta-proof-entry",   1, opus::wire_field::R1_MTA_PROOFS_ENTRY,     true},
    {"r1-A",                 1, opus::wire_field::R1_POINT_A,               false},
    {"r1-B",                 1, opus::wire_field::R1_POINT_B,               false},
    {"r1-Z",                 1, opus::wire_field::R1_POINT_Z,               false},
    {"r2-ack",               2, opus::wire_field::R2_ACK,                   false},
    {"r2-k-gamma-message",   2, opus::wire_field::R2_K_GAMMA_MTA_MESSAGE,  true},
    {"r2-k-x-message",       2, opus::wire_field::R2_K_X_MTA_MESSAGE,      true},
    {"r2-gamma",             2, opus::wire_field::R2_GAMMA,                 false},
    {"r2-gamma-proof-entry", 2, opus::wire_field::R2_GAMMA_PROOFS_ENTRY,   true},
    {"r3-delta",             3, opus::wire_field::R3_DELTA,                 false},
    {"r3-DELTA",             3, opus::wire_field::R3_DELTA_POINT,           false},
    {"r3-proof",             3, opus::wire_field::R3_PROOF,                 true},
    {"r4-si",                4, opus::wire_field::R4_SI,                    false},
};

std::vector<case_spec> make_cases()
{
    std::vector<case_spec> out;
    const size_t offsets[] = {0, 1, 7, 31};
    const uint8_t bits[] = {0, 1, 7, 3};
    const size_t truncations[] = {0, 1, 7};

    for (const auto& f : FIELDS) {
        for (size_t i = 0; i < 4; ++i) {
            out.push_back({std::string(f.name) + "-flip-" + std::to_string(i),
                           f.round, f.field, opus::wire_op::FLIP_BIT,
                           offsets[i], bits[i]});
        }
        out.push_back({std::string(f.name) + "-zero",
                       f.round, f.field, opus::wire_op::ZERO, 0, 0});
        if (f.byte_vector) {
            for (size_t keep : truncations) {
                out.push_back({std::string(f.name) + "-truncate-" + std::to_string(keep),
                               f.round, f.field, opus::wire_op::TRUNCATE,
                               keep, 0});
            }
        }
    }
    return out;
}

bool clean_control(opus::session& sess, const std::string& txid, uint64_t seed,
                   uint64_t& elapsed_ms)
{
    opus::run_config cfg;
    cfg.txid = txid;
    cfg.seed = seed;
    const opus::run_result r = sess.run(cfg);
    std::cout << "CONTROL txid=" << txid << " verdict=" << opus::to_string(r.v)
              << " exit_class=" << (r.v == opus::verdict::CLEAN_SIGN ? 0 : 1)
              << " ms=" << r.elapsed_ms << "\n";
    elapsed_ms = r.elapsed_ms ? r.elapsed_ms : 1;
    return r.v == opus::verdict::CLEAN_SIGN;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: opus_cmp_smoke <synthetic-snapshot>\n";
        return 2;
    }

    opus::silence_library_logging();
    if (!opus::install_deterministic_rand() || !opus::self_test()) {
        std::cerr << "FAIL_CLOSED reason=deterministic_rng_unavailable\n";
        return 2;
    }

    opus::snapshot snap;
    std::string err;
    if (!opus::read_snapshot(argv[1], snap, err) ||
        !opus::verify_snapshot(snap, err)) {
        std::cerr << "FAIL_CLOSED reason=snapshot_invalid\n";
        return 2;
    }

    std::string rng_detail;
    if (!opus::rng_is_effective(snap, rng_detail)) {
        std::cerr << "FAIL_CLOSED reason=rng_not_effective\n";
        return 2;
    }

    opus::session sess(snap, "opus-key", err);
    if (!sess.ok() || snap.players.size() < 2) {
        std::cerr << "FAIL_CLOSED reason=session_unavailable\n";
        return 2;
    }

    uint64_t control_ms = 0;
    if (!clean_control(sess, "smoke-control-pre", 0x510000, control_ms))
        return 2;

    const uint64_t attacker = snap.players[1].id;
    const auto cases = make_cases();
    std::map<std::string, size_t> tally;

    for (size_t i = 0; i < cases.size(); ++i) {
        if (i != 0 && i % 26 == 0) {
            uint64_t ignored = 0;
            if (!clean_control(sess, "smoke-control-" + std::to_string(i),
                               0x520000 + i, ignored))
                return 2;
        }

        const auto& cs = cases[i];
        opus::run_config cfg;
        cfg.seed = 0x530000 + i;
        cfg.txid = "smoke-case-" + std::to_string(i);
        cfg.blocks = 1;
        cfg.malicious_ids = {attacker};
        cfg.timeout_ms = control_ms * 40 + 1000;

        opus::mutation m;
        m.round = cs.round;
        m.attacker = attacker;
        m.field = cs.field;
        m.op = cs.op;
        m.block = 0;
        m.byte_index = cs.byte_index;
        m.bit = cs.bit;
        cfg.mutations.push_back(m);

        const opus::run_result r = sess.run(cfg);
        const std::string label = opus::to_string(r.v);
        ++tally[label];
        std::cout << "CASE id=" << i << " name=" << cs.name
                  << " verdict=" << label
                  << " round=" << r.failed_round
                  << " applied=" << r.mutations_applied
                  << " ms=" << r.elapsed_ms << "\n";

        if (r.mutations_applied == 0 || r.v == opus::verdict::HARNESS_FAULT) {
            std::cerr << "FAIL_CLOSED reason=invalid_test_case case=" << i << "\n";
            return 2;
        }
        if (r.v == opus::verdict::CRASH ||
            r.v == opus::verdict::TIMEOUT ||
            r.v == opus::verdict::INVALID_SIGNATURE ||
            r.v == opus::verdict::STATE_CORRUPTION) {
            std::cerr << "HIGH_SIGNAL case=" << i << " verdict=" << label << "\n";
            return 3;
        }
        if (r.v == opus::verdict::CLEAN_SIGN) {
            std::cerr << "REVIEW_ACCEPTED_MUTATION case=" << i << "\n";
            return 4;
        }
    }

    uint64_t ignored = 0;
    if (!clean_control(sess, "smoke-control-post", 0x540000, ignored))
        return 2;

    std::cout << "SMOKE_PASS cases=" << cases.size();
    for (const auto& [label, count] : tally)
        std::cout << " " << label << "=" << count;
    std::cout << "\n";
    return 0;
}
