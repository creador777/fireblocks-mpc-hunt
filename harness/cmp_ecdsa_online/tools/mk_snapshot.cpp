// One-shot deterministic snapshot generator.
//
// Runs the library's own Paillier / ring-Pedersen key generators once under the
// deterministic RNG, freezes the result, and verifies every internal-consistency
// invariant before writing. NEVER run this inside a test loop: safe-prime search
// is an unbounded retry loop with high wall-clock variance.
//
//   mk_snapshot <out-path> [seed] [id1 id2 ...]

#include "opus/det_rand.h"
#include "opus/fixtures.h"
#include "opus/snapshot.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: mk_snapshot <out-path> [seed] [player-ids...]\n";
        return 2;
    }

    const std::string out_path = argv[1];
    const uint64_t seed = (argc >= 3) ? std::strtoull(argv[2], nullptr, 0) : 1;

    std::vector<uint64_t> ids;
    for (int i = 3; i < argc; ++i)
        ids.push_back(std::strtoull(argv[i], nullptr, 0));
    if (ids.empty())
        ids = {1, 2};

    opus::silence_library_logging();

    if (!opus::install_deterministic_rand()) {
        std::cerr << "FATAL: could not install the deterministic RAND_METHOD\n";
        return 1;
    }
    if (!opus::self_test()) {
        std::cerr << "FATAL: deterministic RNG self-test failed\n";
        return 1;
    }

    std::cout << "generating snapshot: seed=" << seed << " players=" << ids.size()
              << " paillier=" << opus::PAILLIER_KEY_BITS
              << " ring_pedersen=" << opus::RING_PEDERSEN_KEY_BITS << "\n"
              << "(safe-prime generation is slow; this is expected)\n" << std::flush;

    std::string err;
    opus::snapshot snap = opus::generate_snapshot(seed, ids, err);
    if (!err.empty()) {
        std::cerr << "FATAL: generate_snapshot: " << err << "\n";
        return 1;
    }

    if (!opus::verify_snapshot(snap, err)) {
        std::cerr << "FATAL: snapshot failed its own consistency check: " << err << "\n";
        return 1;
    }
    std::cout << "snapshot invariants OK\n";

    if (!opus::write_snapshot(snap, out_path, err)) {
        std::cerr << "FATAL: write_snapshot: " << err << "\n";
        return 1;
    }

    // Read it back and re-verify, so a serialization bug cannot ship silently.
    opus::snapshot reloaded;
    if (!opus::read_snapshot(out_path, reloaded, err)) {
        std::cerr << "FATAL: read-back failed: " << err << "\n";
        return 1;
    }
    if (!opus::verify_snapshot(reloaded, err)) {
        std::cerr << "FATAL: reloaded snapshot failed verification: " << err << "\n";
        return 1;
    }

    std::cout << "wrote " << out_path << " and verified the read-back\n";
    for (const auto& p : reloaded.players) {
        std::cout << "  player " << p.id
                  << " paillier_pub=" << p.paillier_pub.size()
                  << "B paillier_priv=" << p.paillier_priv.size()
                  << "B rp_pub=" << p.rp_pub.size()
                  << "B rp_priv=" << p.rp_priv.size() << "B\n";
    }
    return 0;
}
