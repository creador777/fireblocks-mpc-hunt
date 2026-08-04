#pragma once

#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/snapshot.h"

#include "cosigner/types.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace opus {

// Exactly one label per run, evaluated top-down. CLEAN_* are expected
// outcomes, not findings. HARNESS_FAULT invalidates the batch.
enum class verdict {
    CLEAN_SIGN,
    CLEAN_REJECT,
    INVALID_SIGNATURE,
    STATE_CORRUPTION,
    CRASH,
    TIMEOUT,
    HARNESS_FAULT,
};

const char* to_string(verdict v);

struct run_config
{
    uint64_t    seed = 1;
    std::string key_id = "opus-key";
    std::string txid = "opus-tx-0";
    std::string metadata_json;              // "" or "positive_r"

    // <= 5 keeps mta::new_response_verifier on single_response_verifier, which
    // consumes ZERO randomness (mta.h:170, MIN_BATCH_SIZE = 6). Going to 6+
    // switches to the batch verifier and pulls in mta.cpp:1141,1261.
    size_t blocks = 1;

    // BIP44-shaped, length 5. Path length is a CALLER parameter, not peer
    // input; the only guard is a compiled-out assert. Never mutate it.
    std::vector<uint32_t> path{44, 0, 0, 0, 0};

    // Structural guard: must be a STRICT subset of the player set. The
    // all-malicious case is explicitly out of scope (SECURITY-MODEL 1.1).
    std::set<uint64_t> malicious_ids;

    std::vector<mutation> mutations;

    uint64_t timeout_ms = 0;                // 0 = no budget enforced

    bool honest_only() const { return malicious_ids.empty(); }
};

struct run_result
{
    verdict     v = verdict::HARNESS_FAULT;
    int         failed_round = 0;           // 1..5; 0 = no failure
    uint64_t    failed_player = 0;
    std::string exception_type;             // "cosigner_exception", "std::out_of_range", ...
    std::string detail;
    uint64_t    elapsed_ms = 0;

    // Signatures as produced at an HONEST player. Oracles never read library
    // state to decide validity.
    std::vector<fireblocks::common::cosigner::recoverable_signature> sigs;
    bool signature_produced = false;

    // O4 evidence.
    std::string key_digest_before;
    std::string key_digest_after;
    bool        key_store_unchanged = true;
    bool        sig_state_consistent = true;

    // How many mutations actually changed a byte. A case where this is 0 tested
    // nothing and must not be counted as coverage.
    size_t mutations_applied = 0;

    std::string summary() const;
};

// A complete, self-contained signing session: fresh player contexts, fresh
// signing store, snapshot re-installed from frozen bytes.
class session
{
public:
    // `snap` must already have passed verify_snapshot().
    session(const snapshot& snap, const std::string& key_id, std::string& err);

    bool ok() const { return _ok; }
    const std::vector<uint64_t>& ids() const { return _ids; }

    run_result run(const run_config& cfg);

private:
    bool _ok = false;
    std::string _key_id;
    snapshot _snap;                          // frozen expected public key / algorithm
    std::vector<uint64_t> _ids;
    std::map<uint64_t, det_key_persistency> _key_stores;
};

// Confirms the RAND_METHOD override actually reaches the library: runs
// start_signing twice under the same seed and requires byte-identical wire
// output. If libcrypto were statically absorbed into libcosigner.so, this is
// the check that catches it. Returns false if determinism is not in force.
bool rng_is_effective(const snapshot& snap, std::string& detail);

} // namespace opus
