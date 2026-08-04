#include "opus/driver.h"
#include "opus/det_rand.h"
#include "opus/oracles.h"

#include "cosigner/cosigner_exception.h"
#include "cosigner/mpc_globals.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>

using namespace fireblocks::common::cosigner;

namespace opus {

const char* to_string(verdict v)
{
    switch (v) {
    case verdict::CLEAN_SIGN:        return "CLEAN-SIGN";
    case verdict::CLEAN_REJECT:      return "CLEAN-REJECT";
    case verdict::INVALID_SIGNATURE: return "INVALID-SIGNATURE";
    case verdict::STATE_CORRUPTION:  return "STATE-CORRUPTION";
    case verdict::CRASH:             return "CRASH";
    case verdict::TIMEOUT:           return "TIMEOUT";
    case verdict::HARNESS_FAULT:     return "HARNESS-FAULT";
    }
    return "?";
}

std::string run_result::summary() const
{
    std::ostringstream os;
    os << to_string(v);
    if (failed_round)
        os << " round=" << failed_round << " player=" << failed_player;
    if (!exception_type.empty())
        os << " exc=" << exception_type;
    os << " applied=" << mutations_applied << " ms=" << elapsed_ms;
    if (!detail.empty())
        os << " :: " << detail;
    return os.str();
}

namespace {

using Clock = std::chrono::steady_clock;

struct call_outcome
{
    bool threw = false;
    bool fatal = false;             // an exception outside the enumerated surface
    std::string type;
    std::string what;
};

// The full exception surface reachable from the online signing path:
//   cosigner_exception (21 codes)
//   everything funnelled through throw_cosigner_exception
//   bare std::out_of_range from std::map::at (the round-4 repeat detector
//     asserts exactly this -- upstream ecdsa_online_test.cpp:227)
//   std::bad_alloc
// Anything else is not a clean rejection and is escalated.
template <typename Fn>
call_outcome guarded(Fn&& fn)
{
    call_outcome o;
    try {
        fn();
    } catch (const cosigner_exception& e) {
        o.threw = true; o.type = "cosigner_exception"; o.what = e.what();
    } catch (const std::out_of_range& e) {
        o.threw = true; o.type = "std::out_of_range"; o.what = e.what();
    } catch (const std::bad_alloc& e) {
        o.threw = true; o.type = "std::bad_alloc"; o.what = e.what();
    } catch (const std::exception& e) {
        o.threw = true; o.fatal = true; o.type = "std::exception"; o.what = e.what();
    } catch (...) {
        o.threw = true; o.fatal = true; o.type = "unknown"; o.what = "non-standard exception";
    }
    return o;
}

std::vector<uint8_t> block_message(size_t index)
{
    // Fixed synthetic message bytes. Not a hash of anything real; no real data
    // ever enters the harness.
    std::vector<uint8_t> m(32, 0);
    for (size_t i = 0; i < m.size(); ++i)
        m[i] = static_cast<uint8_t>((0xA0 + index + i) & 0xFF);
    return m;
}

} // namespace

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

session::session(const snapshot& snap, const std::string& key_id, std::string& err)
    : _key_id(key_id), _snap(snap)
{
    silence_library_logging();

    _ids = snap.player_ids();
    for (uint64_t id : _ids)
        _key_stores[id];                       // default-construct one store per player

    if (!install_snapshot(snap, key_id, _key_stores, err))
        return;

    _ok = true;
}

run_result session::run(const run_config& cfg)
{
    run_result res;
    const auto t0 = Clock::now();

    // ---- structural guards -------------------------------------------------
    // At least one honest party is a PRECONDITION of the whole threat model.
    // The all-malicious case is explicitly out of scope, so the harness refuses
    // to construct it rather than producing results that cannot be reported.
    std::vector<uint64_t> honest;
    for (uint64_t id : _ids)
        if (cfg.malicious_ids.find(id) == cfg.malicious_ids.end())
            honest.push_back(id);

    if (honest.empty()) {
        res.v = verdict::HARNESS_FAULT;
        res.detail = "refused: every player is malicious (out of scope by SECURITY-MODEL 1.1)";
        return res;
    }
    for (uint64_t m : cfg.malicious_ids) {
        if (std::find(_ids.begin(), _ids.end(), m) == _ids.end()) {
            res.v = verdict::HARNESS_FAULT;
            res.detail = "malicious id " + std::to_string(m) + " is not a player";
            return res;
        }
    }
    if (cfg.blocks == 0 || cfg.blocks > MAX_BLOCKS_TO_SIGN) {
        res.v = verdict::HARNESS_FAULT;
        res.detail = "block count out of the caller-contract range";
        return res;
    }

    // Reseeding per case makes case N reproducible regardless of how many draws
    // case N-1 consumed (draw counts are data-dependent: retry loops in
    // mta.cpp, range_proofs.c, paillier.c).
    reseed_with_label(cfg.seed, cfg.txid);

    // Fresh service instances and a fresh signing store per run.
    std::map<uint64_t, std::unique_ptr<player_ctx>> players;
    for (uint64_t id : _ids)
        players.emplace(id, std::make_unique<player_ctx>(id, _key_stores.at(id)));

    res.key_digest_before = _key_stores.at(honest.front()).digest();

    // ---- local signing request (caller-side, never mutated) ----------------
    signing_data data;
    memset(data.chaincode, 0, sizeof(HDChaincode));
    std::vector<std::vector<uint8_t>> expected_messages;
    for (size_t i = 0; i < cfg.blocks; ++i) {
        signing_block_data blk;
        blk.data = block_message(i);
        blk.path = cfg.path;
        expected_messages.push_back(blk.data);
        data.blocks.push_back(std::move(blk));
    }

    std::set<uint64_t> players_ids(_ids.begin(), _ids.end());
    std::set<std::string> players_str;
    for (uint64_t id : _ids)
        players_str.insert(std::to_string(id));

    const bool want_positive_r = (cfg.metadata_json == "positive_r");

    auto find_mut = [&](int round) -> const mutation* {
        for (const auto& m : cfg.mutations)
            if (m.round == round && m.enabled())
                return &m;
        return nullptr;
    };

    auto fail = [&](verdict v, int round, uint64_t pid, const call_outcome& o, const std::string& extra) {
        res.v = v;
        res.failed_round = round;
        res.failed_player = pid;
        res.exception_type = o.type;
        res.detail = extra.empty() ? o.what : (extra + " (" + o.what + ")");
    };

    // =======================================================================
    // Round 1 -- start_signing. No peer bytes enter; output is the first wire
    // message. Out-params are only reserve()d by the library, never cleared,
    // so every call gets a fresh vector.
    // =======================================================================
    std::map<uint64_t, std::vector<cmp_mta_request>> requests;
    for (uint64_t id : _ids) {
        std::vector<cmp_mta_request> out;
        auto o = guarded([&] {
            players.at(id)->service.start_signing(_key_id, cfg.txid,
                                                  static_cast<cosigner_sign_algorithm>(0),
                                                  data, cfg.metadata_json,
                                                  players_str, players_ids, out);
        });
        if (o.threw) {
            // A throw during round 1 with no mutation applied means the
            // snapshot or fixture is wrong, not the library.
            fail(o.fatal ? verdict::CRASH : verdict::CLEAN_REJECT, 1, id, o,
                 cfg.honest_only() ? "honest round 1 must not throw" : "");
            if (cfg.honest_only() && !o.fatal)
                res.v = verdict::HARNESS_FAULT;
            res.elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            res.key_digest_after = _key_stores.at(honest.front()).digest();
            res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
            return res;
        }
        requests[id] = std::move(out);
    }

    // The attacker computes honestly and tampers ON THE WIRE. Its own local view
    // therefore stays honest; only what honest players receive is altered.
    auto view_r1 = [&](uint64_t viewer) {
        auto copy = requests;
        if (cfg.malicious_ids.count(viewer))
            return copy;                       // attacker sees its own honest data
        if (const mutation* m = find_mut(1))
            if (apply_r1(*m, copy, viewer))
                ++res.mutations_applied;
        return copy;
    };

    // =======================================================================
    // Round 2 -- mta_response
    // =======================================================================
    std::map<uint64_t, cmp_mta_responses> responses;
    for (uint64_t id : _ids) {
        auto in = view_r1(id);
        cmp_mta_responses out;
        auto o = guarded([&] {
            players.at(id)->service.mta_response(cfg.txid, in, MPC_PROTOCOL_VERSION, out);
        });
        if (o.threw) {
            const bool honest_victim = !cfg.malicious_ids.count(id);
            if (o.fatal) { fail(verdict::CRASH, 2, id, o, ""); }
            else if (honest_victim) { fail(verdict::CLEAN_REJECT, 2, id, o, ""); }
            else { fail(verdict::CLEAN_REJECT, 2, id, o, "attacker self-harm"); }
            if (cfg.honest_only() && !o.fatal) res.v = verdict::HARNESS_FAULT;
            res.elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            res.key_digest_after = _key_stores.at(honest.front()).digest();
            res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
            return res;
        }
        responses[id] = std::move(out);
    }

    auto view_r2 = [&](uint64_t viewer) {
        auto copy = responses;                 // deep copy: round 3 const_casts
        if (cfg.malicious_ids.count(viewer))   // and moves out of its input, so
            return copy;                       // the object cannot be reused
        if (const mutation* m = find_mut(2))
            if (apply_r2(*m, copy, viewer))
                ++res.mutations_applied;
        return copy;
    };

    // =======================================================================
    // Round 3 -- mta_verify
    // =======================================================================
    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    for (uint64_t id : _ids) {
        auto in = view_r2(id);
        std::vector<cmp_mta_deltas> out;
        auto o = guarded([&] {
            players.at(id)->service.mta_verify(cfg.txid, in, out);
        });
        if (o.threw) {
            fail(o.fatal ? verdict::CRASH : verdict::CLEAN_REJECT, 3, id, o, "");
            if (cfg.honest_only() && !o.fatal) res.v = verdict::HARNESS_FAULT;
            res.elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            res.key_digest_after = _key_stores.at(honest.front()).digest();
            res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
            return res;
        }
        deltas[id] = std::move(out);
    }

    auto view_r3 = [&](uint64_t viewer) {
        auto copy = deltas;
        if (cfg.malicious_ids.count(viewer))
            return copy;
        if (const mutation* m = find_mut(3))
            if (apply_r3(*m, copy, viewer))
                ++res.mutations_applied;
        return copy;
    };

    // =======================================================================
    // Round 4 -- get_si
    // =======================================================================
    std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
    for (uint64_t id : _ids) {
        auto in = view_r3(id);
        std::vector<elliptic_curve_scalar> out;
        auto o = guarded([&] {
            players.at(id)->service.get_si(cfg.txid, in, out);
        });
        if (o.threw) {
            fail(o.fatal ? verdict::CRASH : verdict::CLEAN_REJECT, 4, id, o, "");
            if (cfg.honest_only() && !o.fatal) res.v = verdict::HARNESS_FAULT;
            res.elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            res.key_digest_after = _key_stores.at(honest.front()).digest();
            res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
            return res;
        }
        sis[id] = std::move(out);
    }

    auto view_r4 = [&](uint64_t viewer) {
        auto copy = sis;
        if (cfg.malicious_ids.count(viewer))
            return copy;
        if (const mutation* m = find_mut(4))
            if (apply_r4(*m, copy, viewer))
                ++res.mutations_applied;
        return copy;
    };

    // =======================================================================
    // Round 5 -- get_cmp_signature. Evaluated at an HONEST player only.
    // =======================================================================
    const uint64_t observer = honest.front();
    {
        auto in = view_r4(observer);
        std::vector<recoverable_signature> out;
        auto o = guarded([&] {
            players.at(observer)->service.get_cmp_signature(cfg.txid, in, out);
        });
        if (o.threw) {
            fail(o.fatal ? verdict::CRASH : verdict::CLEAN_REJECT, 5, observer, o, "");
            if (cfg.honest_only() && !o.fatal) res.v = verdict::HARNESS_FAULT;
            res.elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            res.key_digest_after = _key_stores.at(honest.front()).digest();
            res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
            return res;
        }
        res.sigs = std::move(out);
        res.signature_produced = true;
    }

    res.elapsed_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());

    // ---- O4: the key store must be byte-identical. cmp_key_persistency has no
    // mutating method at all, so any change is a harness bug or memory
    // corruption -- never normal behaviour.
    res.key_digest_after = _key_stores.at(observer).digest();
    res.key_store_unchanged = (res.key_digest_before == res.key_digest_after);
    if (!res.key_store_unchanged) {
        res.v = verdict::STATE_CORRUPTION;
        res.detail = "key store digest changed across a run";
        return res;
    }

    // ---- O4b: after a successful round 5 the temporary record must be gone
    // (deleted at cmp_ecdsa_online_signing_service.cpp:503).
    if (players.at(observer)->signing_store.has(cfg.txid)) {
        res.v = verdict::STATE_CORRUPTION;
        res.sig_state_consistent = false;
        res.detail = "temporary signing record survived a successful get_cmp_signature";
        return res;
    }

    // ---- O1: independent validity, against the message and key the HARNESS
    // asked for -- not against the library's stored notion.
    if (res.sigs.size() != cfg.blocks) {
        res.v = verdict::INVALID_SIGNATURE;
        res.detail = "produced " + std::to_string(res.sigs.size()) +
                     " signatures for " + std::to_string(cfg.blocks) + " blocks";
        return res;
    }

    for (size_t i = 0; i < cfg.blocks; ++i) {
        std::string detail;
        if (!oracle_signature_valid(_snap, expected_messages[i], cfg.path,
                                    data.chaincode, res.sigs[i], want_positive_r, detail)) {
            res.v = verdict::INVALID_SIGNATURE;
            res.detail = "block " + std::to_string(i) + ": " + detail;
            return res;
        }
        if (!oracle_no_canary_forgery(_snap, cfg.path, data.chaincode,
                                      res.sigs[i], detail)) {
            res.v = verdict::INVALID_SIGNATURE;
            res.detail = "block " + std::to_string(i) + ": " + detail;
            return res;
        }
    }

    if (cfg.timeout_ms && res.elapsed_ms > cfg.timeout_ms) {
        res.v = verdict::TIMEOUT;
        res.detail = "exceeded budget of " + std::to_string(cfg.timeout_ms) + " ms";
        return res;
    }

    res.v = verdict::CLEAN_SIGN;
    return res;
}

// ---------------------------------------------------------------------------
// rng_is_effective
//
// The single highest-risk assumption in the whole design is that
// RAND_set_rand_method() actually reaches the randomness the library consumes.
// It does NOT if libcrypto ends up statically absorbed into libcosigner.so,
// because that copy would carry its own RNG state.
//
// Rather than trusting the linkage, this drives the real code path twice under
// the same seed and requires byte-identical wire output. start_signing pulls
// from every round-1 sink (algebra->rand for k/a/b/gamma, Paillier encryption
// randomness, range-proof randomness), so agreement here is strong evidence.
// ---------------------------------------------------------------------------
namespace {

void flatten(const cmp_mta_request& r, std::string& out)
{
    auto put = [&out](const uint8_t* p, size_t n) {
        out.append(reinterpret_cast<const char*>(p), n);
    };
    auto put_len = [&out](size_t n) {
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<char>((n >> (8 * i)) & 0xFF));
    };
    put_len(r.mta.message.size());    put(r.mta.message.data(), r.mta.message.size());
    put_len(r.mta.commitment.size()); put(r.mta.commitment.data(), r.mta.commitment.size());
    put_len(r.mta.proof.size());      put(r.mta.proof.data(), r.mta.proof.size());
    put_len(r.mta_proofs.size());
    for (const auto& [id, proof] : r.mta_proofs) {
        put_len(id);
        put_len(proof.size());
        put(proof.data(), proof.size());
    }
    put(r.A.data, sizeof(elliptic_curve256_point_t));
    put(r.B.data, sizeof(elliptic_curve256_point_t));
    put(r.Z.data, sizeof(elliptic_curve256_point_t));
}

} // namespace

bool rng_is_effective(const snapshot& snap, std::string& detail)
{
    detail.clear();
    silence_library_logging();

    const std::string key_id = "opus-rng-probe";
    const auto ids = snap.player_ids();
    if (ids.empty()) { detail = "snapshot has no players"; return false; }

    std::map<uint64_t, det_key_persistency> stores;
    for (uint64_t id : ids)
        stores[id];
    std::string err;
    if (!install_snapshot(snap, key_id, stores, err)) {
        detail = "install_snapshot failed: " + err;
        return false;
    }

    signing_data data;
    memset(data.chaincode, 0, sizeof(HDChaincode));
    signing_block_data blk;
    blk.data.assign(32, 0x42);
    blk.path = {44, 0, 0, 0, 0};
    data.blocks.push_back(blk);

    std::set<uint64_t> players_ids(ids.begin(), ids.end());
    std::set<std::string> players_str;
    for (uint64_t id : ids)
        players_str.insert(std::to_string(id));

    auto one_shot = [&](uint64_t seed, std::string& flat) -> bool {
        reseed_with_label(seed, "rng-probe");
        player_ctx ctx(ids.front(), stores.at(ids.front()));
        std::vector<cmp_mta_request> out;
        try {
            ctx.service.start_signing(key_id, "rng-probe-tx",
                                      static_cast<cosigner_sign_algorithm>(snap.algorithm),
                                      data, "", players_str, players_ids, out);
        } catch (const std::exception& e) {
            detail = std::string("start_signing threw during the RNG probe: ") + e.what();
            return false;
        }
        if (out.size() != 1) { detail = "unexpected request count"; return false; }
        flat.clear();
        flatten(out[0], flat);
        return true;
    };

    std::string a, b, c;
    if (!one_shot(0xC0FFEEull, a)) return false;
    if (!one_shot(0xC0FFEEull, b)) return false;
    if (a != b) {
        detail = "same seed produced different wire bytes -- the RAND_METHOD override is NOT "
                 "reaching the library (most likely libcrypto is statically linked into "
                 "libcosigner.so; check ldd/nm on the built .so)";
        return false;
    }
    if (!one_shot(0xBADC0DEull, c)) return false;
    if (a == c) {
        detail = "different seeds produced identical wire bytes -- the RNG appears stuck";
        return false;
    }
    return true;
}

} // namespace opus
