// Synthetic self-tests of the HARNESS -- not of the library.
//
// Every check here is about whether the instrument is trustworthy. Nothing in
// this file asserts anything about the security of fireblocks/mpc-lib, and a
// failure here means the harness is broken, never that a vulnerability exists.
//
//   opus_selftest [snapshot-path]

#include "opus/det_rand.h"
#include "opus/driver.h"
#include "opus/fixtures.h"
#include "opus/mutators.h"
#include "opus/oracles.h"
#include "opus/snapshot.h"

#include <iostream>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& name, const std::string& detail = "")
{
    ++g_checks;
    if (cond) {
        std::cout << "  [ ok ] " << name << "\n";
    } else {
        ++g_failures;
        std::cout << "  [FAIL] " << name;
        if (!detail.empty())
            std::cout << " -- " << detail;
        std::cout << "\n";
    }
}

void section(const std::string& s)
{
    std::cout << "\n== " << s << " ==\n";
}

} // namespace

int main(int argc, char** argv)
{
    const std::string snap_path = (argc >= 2) ? argv[1] : "snapshot.bin";

    opus::silence_library_logging();

    // -----------------------------------------------------------------------
    section("T1 deterministic RNG instrument");
    // -----------------------------------------------------------------------
    check(opus::install_deterministic_rand(), "RAND_METHOD installs");
    check(opus::self_test(), "RNG self-test (same seed identical, different seed differs, stream continuous)");

    // -----------------------------------------------------------------------
    section("T2 snapshot loads and is internally consistent");
    // -----------------------------------------------------------------------
    opus::snapshot snap;
    std::string err;
    const bool loaded = opus::read_snapshot(snap_path, snap, err);
    check(loaded, "snapshot reads from " + snap_path, err);
    if (!loaded) {
        std::cout << "\nCannot continue without a snapshot. Run mk_snapshot first.\n";
        return 1;
    }
    check(opus::verify_snapshot(snap, err), "snapshot invariants hold", err);
    check(snap.players.size() >= 2, "snapshot has at least 2 players");

    // -----------------------------------------------------------------------
    section("T3 RNG override actually reaches the library");
    // -----------------------------------------------------------------------
    std::string rng_detail;
    const bool rng_ok = opus::rng_is_effective(snap, rng_detail);
    check(rng_ok, "two identical seeds produce identical wire bytes", rng_detail);
    if (!rng_ok) {
        std::cout << "\nDeterminism is NOT in force. Every downstream result would be noise.\n";
        return 1;
    }

    // -----------------------------------------------------------------------
    section("T4 honest control run completes and produces a valid signature");
    // -----------------------------------------------------------------------
    opus::session sess(snap, "opus-key", err);
    check(sess.ok(), "session installs the snapshot", err);
    if (!sess.ok())
        return 1;

    // Conjunto de firmantes designado del fixture: los primeros t ids, la
    // misma convencion que generate_snapshot y el fuzzer de alcanzabilidad.
    // Sobre un fixture n=n queda VACIO y run() se comporta exactamente igual
    // que antes; sobre uno t<n es lo que start_signing exige
    // (cmp_ecdsa_online_signing_service.cpp:59). Sin esto, los tests
    // principales rechazan con "signer count n != snapshot threshold t" y el
    // selftest entero deja de ser un control util sobre t<n.
    std::vector<uint64_t> selftest_signers;
    if (static_cast<size_t>(snap.t) < snap.players.size()) {
        const std::vector<uint64_t> all = snap.player_ids();
        selftest_signers.assign(all.begin(), all.begin() + snap.t);
    }

    opus::run_config control;
    control.signers_ids = selftest_signers;
    control.seed = 0x1111;
    control.txid = "selftest-control-1";
    control.blocks = 1;

    opus::run_result r_control = sess.run(control);
    std::cout << "  control: " << r_control.summary() << "\n";
    check(r_control.v == opus::verdict::CLEAN_SIGN,
          "honest control is CLEAN-SIGN", r_control.detail);
    check(r_control.signature_produced, "a signature was produced");
    check(r_control.key_store_unchanged, "key store digest unchanged (O4: D_key)");

    // -----------------------------------------------------------------------
    section("T5 the control is reproducible under the same seed");
    // -----------------------------------------------------------------------
    opus::run_config control2 = control;
    control2.txid = "selftest-control-2";   // fresh txid: replay of a txid is rejected by contract
    opus::run_result r_control2 = sess.run(control2);
    check(r_control2.v == opus::verdict::CLEAN_SIGN, "second control also CLEAN-SIGN",
          r_control2.detail);

    bool sigs_match = r_control.sigs.size() == r_control2.sigs.size();
    if (sigs_match) {
        for (size_t i = 0; i < r_control.sigs.size() && sigs_match; ++i) {
            sigs_match = (memcmp(r_control.sigs[i].r, r_control2.sigs[i].r, 32) == 0) &&
                         (memcmp(r_control.sigs[i].s, r_control2.sigs[i].s, 32) == 0) &&
                         (r_control.sigs[i].v == r_control2.sigs[i].v);
        }
    }
    // NOTE: the txid feeds build_aad and the per-case reseed label, so two runs
    // with different txids are NOT expected to produce identical signatures.
    // This check records the observed behaviour rather than asserting it.
    std::cout << "  (same seed, different txid -> signatures "
              << (sigs_match ? "identical" : "differ") << ", as expected for txid-bound AAD)\n";

    // -----------------------------------------------------------------------
    section("T6 benign alteration by a malicious peer is REJECTED cleanly");
    // -----------------------------------------------------------------------
    // A single bit flipped in the ZK proof that player 2 sends to player 1.
    // This is a minimal, well-formed, structurally valid message that must not
    // be accepted. Rejecting it is the CORRECT behaviour and confirms the
    // harness can distinguish "rejected" from "accepted".
    {
        opus::run_config tampered;
        tampered.signers_ids = selftest_signers;
        tampered.seed = 0x2222;
        tampered.txid = "selftest-tamper-r1-proof";
        tampered.blocks = 1;
        tampered.malicious_ids = {snap.players[1].id};

        opus::mutation m;
        m.round = 1;
        m.attacker = snap.players[1].id;
        m.field = opus::wire_field::R1_MTA_PROOFS_ENTRY;
        m.op = opus::wire_op::FLIP_BIT;
        m.block = 0;
        m.byte_index = 7;
        m.bit = 3;
        tampered.mutations.push_back(m);

        opus::run_result rt = sess.run(tampered);
        std::cout << "  tampered: " << rt.summary() << "\n";
        check(rt.mutations_applied > 0, "the mutation actually changed a byte");
        check(rt.v == opus::verdict::CLEAN_REJECT,
              "tampered ZK proof is rejected, not accepted", rt.detail);
        check(rt.v != opus::verdict::CLEAN_SIGN,
              "no signature was produced after the tamper (O3)");
        check(rt.key_store_unchanged, "key store digest still unchanged after a rejected run");
    }

    // -----------------------------------------------------------------------
    section("T7 tampering the R2 ack is rejected (round binding holds)");
    // -----------------------------------------------------------------------
    {
        opus::run_config tampered;
        tampered.signers_ids = selftest_signers;
        tampered.seed = 0x3333;
        tampered.txid = "selftest-tamper-r2-ack";
        tampered.blocks = 1;
        tampered.malicious_ids = {snap.players[1].id};

        opus::mutation m;
        m.round = 2;
        m.attacker = snap.players[1].id;
        m.field = opus::wire_field::R2_ACK;
        m.op = opus::wire_op::FLIP_BIT;
        m.byte_index = 0;
        m.bit = 0;
        tampered.mutations.push_back(m);

        opus::run_result rt = sess.run(tampered);
        std::cout << "  tampered: " << rt.summary() << "\n";
        check(rt.mutations_applied > 0, "the ack mutation was applied");
        check(rt.v == opus::verdict::CLEAN_REJECT, "mismatched ack is rejected", rt.detail);
    }

    // -----------------------------------------------------------------------
    section("T8 the harness refuses an all-malicious configuration");
    // -----------------------------------------------------------------------
    {
        opus::run_config bad;
        bad.signers_ids = selftest_signers;
        bad.seed = 0x4444;
        bad.txid = "selftest-all-malicious";
        for (const auto& p : snap.players)
            bad.malicious_ids.insert(p.id);

        opus::run_result rb = sess.run(bad);
        check(rb.v == opus::verdict::HARNESS_FAULT,
              "all-malicious is refused as out of scope", rb.detail);
    }

    // -----------------------------------------------------------------------
    section("T9 duplicate txid is rejected (integrator contract C1/C3)");
    // -----------------------------------------------------------------------
    {
        opus::det_signing_persistency store;
        auto& contract =
            static_cast<fireblocks::common::cosigner::cmp_ecdsa_online_signing_service::
                            signing_persistency&>(store);
        fireblocks::common::cosigner::cmp_signing_metadata live{};
        contract.store_cmp_signing_data("selftest-live-txid", live);

        bool rejected = false;
        try {
            contract.store_cmp_signing_data("selftest-live-txid", live);
        } catch (const fireblocks::common::cosigner::cosigner_exception& e) {
            rejected =
                e.error_code() ==
                fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION;
        }

        check(rejected, "a second store for a still-live txid throws INVALID_TRANSACTION");
        check(store.has("selftest-live-txid"), "the original live record remains present");
        check(store.store_calls() == 2, "both store attempts reached the persistency guard");
    }

    // -----------------------------------------------------------------------
    section("T10 oracle O1 rejects a corrupted signature");
    // -----------------------------------------------------------------------
    {
        // Feed the oracle a signature that is valid, but flip a bit first. The
        // oracle MUST call it invalid; otherwise it cannot detect the real thing.
        if (!r_control.sigs.empty()) {
            auto bad_sig = r_control.sigs[0];
            bad_sig.s[31] ^= 0x01;

            uint8_t chaincode[32] = {0};
            std::vector<uint8_t> msg(32, 0);
            for (size_t i = 0; i < msg.size(); ++i)
                msg[i] = static_cast<uint8_t>((0xA0 + 0 + i) & 0xFF);

            std::string d;
            const bool accepted = opus::oracle_signature_valid(
                snap, msg, control.path, chaincode, bad_sig, false, d);
            check(!accepted, "O1 rejects a bit-flipped signature", "oracle wrongly accepted it");

            const bool good = opus::oracle_signature_valid(
                snap, msg, control.path, chaincode, r_control.sigs[0], false, d);
            check(good, "O1 accepts the genuine control signature", d);
        } else {
            check(false, "control produced a signature to test the oracle with");
        }
    }

    // -----------------------------------------------------------------------
    section("T11 EXTRA_MAP_KEY on a t<n fixture is applied, then rejected by the consumer");
    // -----------------------------------------------------------------------
    // The fixture's designated signer set (the first t player ids) runs the
    // ceremony; the remaining fixture players never sign. The mutation inserts
    // an si entry attributed to one of those non-signers. The consumer's own
    // signer-count guard (cmp_ecdsa_online_signing_service.cpp:437) must
    // reject the enlarged map: this test asserts the rejection end-to-end
    // rather than assuming it, so a silent acceptance would surface as FAIL.
    if (static_cast<size_t>(snap.t) < snap.players.size()) {
        const std::vector<uint64_t> ids = snap.player_ids();
        const std::vector<uint64_t> signers(ids.begin(), ids.begin() + snap.t);

        // Control: the t<n fixture itself must sign honestly. Without this, a
        // broken fixture could masquerade as a correct rejection below.
        {
            opus::run_config tn_control;
            tn_control.seed = 0x5555;
            tn_control.txid = "selftest-tn-control";
            tn_control.blocks = 1;
            tn_control.signers_ids = signers;

            opus::run_result rc = sess.run(tn_control);
            std::cout << "  t<n control: " << rc.summary() << "\n";
            check(rc.v == opus::verdict::CLEAN_SIGN,
                  "t<n honest control is CLEAN-SIGN", rc.detail);
            check(rc.key_store_unchanged, "t<n control leaves the key store unchanged");
        }

        {
            opus::run_config tampered;
        tampered.signers_ids = selftest_signers;
            tampered.seed = 0x6666;
            tampered.txid = "selftest-extra-map-key";
            tampered.blocks = 1;
            tampered.malicious_ids = {signers.back()};
            tampered.signers_ids = signers;

            opus::mutation m;
            m.round = 4;
            m.attacker = signers.back();
            m.field = opus::wire_field::R4_SI;
            m.op = opus::wire_op::EXTRA_MAP_KEY;
            tampered.mutations.push_back(m);

            opus::run_result rt = sess.run(tampered);
            std::cout << "  extra_map_key: " << rt.summary() << "\n";
            check(rt.mutations_applied > 0, "EXTRA_MAP_KEY actually inserted an entry");
            check(rt.v == opus::verdict::CLEAN_REJECT,
                  "the enlarged si map is rejected, not accepted", rt.detail);
            check(rt.failed_round == 5,
                  "the rejection fires at get_cmp_signature (round 5)", rt.detail);
            check(rt.key_store_unchanged, "key store digest unchanged after the rejected run");
        }
    } else {
        std::cout << "  (snapshot is n-of-n; T11 skipped -- regenerate with mk_snapshot --t to enable it)\n";
    }

    // -----------------------------------------------------------------------
    std::cout << "\n===============================================\n";
    std::cout << "checks: " << g_checks << "   failures: " << g_failures << "\n";
    std::cout << (g_failures == 0 ? "SELFTEST PASS\n" : "SELFTEST FAIL\n");
    std::cout << "===============================================\n";
    return g_failures == 0 ? 0 : 1;
}
