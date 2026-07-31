// Case runner. Executes a small, explicit, bounded list of cases and prints one
// classified line per case. This is NOT a fuzzing loop and does not attempt to
// search: it demonstrates that the instrument works end to end.
//
//   opus_cmp_harness <snapshot-path> [--cases=N]

#include "opus/det_rand.h"
#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/snapshot.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

struct case_spec
{
    std::string name;
    int round;
    opus::wire_field field;
    opus::wire_op op;
};

const case_spec CASES[] = {
    {"r1-proof-flip",      1, opus::wire_field::R1_MTA_PROOFS_ENTRY,    opus::wire_op::FLIP_BIT},
    {"r1-commitment-flip", 1, opus::wire_field::R1_MTA_COMMITMENT,      opus::wire_op::FLIP_BIT},
    {"r1-A-flip",          1, opus::wire_field::R1_POINT_A,             opus::wire_op::FLIP_BIT},
    {"r1-B-zero",          1, opus::wire_field::R1_POINT_B,             opus::wire_op::ZERO},
    {"r2-ack-flip",        2, opus::wire_field::R2_ACK,                 opus::wire_op::FLIP_BIT},
    {"r2-gamma-flip",      2, opus::wire_field::R2_GAMMA,               opus::wire_op::FLIP_BIT},
    {"r2-kx-msg-flip",     2, opus::wire_field::R2_K_X_MTA_MESSAGE,     opus::wire_op::FLIP_BIT},
    {"r3-delta-flip",      3, opus::wire_field::R3_DELTA,               opus::wire_op::FLIP_BIT},
    {"r3-DELTA-flip",      3, opus::wire_field::R3_DELTA_POINT,         opus::wire_op::FLIP_BIT},
    {"r3-proof-flip",      3, opus::wire_field::R3_PROOF,               opus::wire_op::FLIP_BIT},
    {"r4-si-flip",         4, opus::wire_field::R4_SI,                  opus::wire_op::FLIP_BIT},
    {"r4-si-zero",         4, opus::wire_field::R4_SI,                  opus::wire_op::ZERO},
};

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: opus_cmp_harness <snapshot-path> [--cases=N]\n";
        return 2;
    }
    const std::string snap_path = argv[1];

    size_t limit = sizeof(CASES) / sizeof(CASES[0]);
    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--cases=", 8) == 0) {
            const size_t n = strtoul(argv[i] + 8, nullptr, 10);
            if (n && n < limit) limit = n;
        }
    }

    opus::silence_library_logging();

    if (!opus::install_deterministic_rand() || !opus::self_test()) {
        std::cerr << "FATAL: deterministic RNG could not be established\n";
        return 1;
    }

    opus::snapshot snap;
    std::string err;
    if (!opus::read_snapshot(snap_path, snap, err)) {
        std::cerr << "FATAL: " << err << "\n";
        return 1;
    }
    if (!opus::verify_snapshot(snap, err)) {
        std::cerr << "FATAL: snapshot invariants failed: " << err << "\n";
        return 1;
    }

    std::string rng_detail;
    if (!opus::rng_is_effective(snap, rng_detail)) {
        std::cerr << "FATAL: determinism is not in force: " << rng_detail << "\n";
        return 1;
    }
    std::cout << "determinism: VERIFIED (same seed -> identical wire bytes)\n";

    opus::session sess(snap, "opus-key", err);
    if (!sess.ok()) {
        std::cerr << "FATAL: session: " << err << "\n";
        return 1;
    }

    // ---- honest control BEFORE the batch -----------------------------------
    opus::run_config control;
    control.seed = 0xC0;
    control.txid = "run-control-pre";
    opus::run_result pre = sess.run(control);
    std::cout << "control(pre) : " << pre.summary() << "\n";
    if (pre.v != opus::verdict::CLEAN_SIGN) {
        std::cerr << "FATAL: honest control failed; the batch would be meaningless\n";
        return 1;
    }
    const uint64_t control_ms = pre.elapsed_ms ? pre.elapsed_ms : 1;

    const uint64_t attacker = snap.players.size() > 1 ? snap.players[1].id : snap.players[0].id;

    std::map<std::string, int> tally;
    for (size_t i = 0; i < limit; ++i) {
        const case_spec& cs = CASES[i];

        opus::run_config cfg;
        cfg.seed = 0x1000 + i;
        cfg.txid = "run-" + cs.name;
        cfg.blocks = 1;
        cfg.malicious_ids = {attacker};
        cfg.timeout_ms = control_ms * 30 + 1000;  // 30x the control median

        opus::mutation m;
        m.round = cs.round;
        m.attacker = attacker;
        m.field = cs.field;
        m.op = cs.op;
        m.block = 0;
        m.byte_index = 3 + i;
        m.bit = static_cast<uint8_t>(i & 7);
        cfg.mutations.push_back(m);

        opus::run_result r = sess.run(cfg);
        tally[opus::to_string(r.v)]++;
        std::cout << cs.name << " : " << r.summary() << "\n";
    }

    // ---- honest control AFTER the batch ------------------------------------
    control.txid = "run-control-post";
    opus::run_result post = sess.run(control);
    std::cout << "control(post): " << post.summary() << "\n";
    if (post.v != opus::verdict::CLEAN_SIGN) {
        std::cerr << "HARNESS FAULT: control regressed after the batch; discard these results\n";
        return 1;
    }

    std::cout << "\n--- tally ---\n";
    for (const auto& [label, n] : tally)
        std::cout << "  " << label << ": " << n << "\n";
    std::cout << "\nNOTE: CLEAN-REJECT and CLEAN-SIGN are EXPECTED outcomes, not findings.\n"
              << "No claim of any vulnerability is made or implied by this output.\n";
    return 0;
}
