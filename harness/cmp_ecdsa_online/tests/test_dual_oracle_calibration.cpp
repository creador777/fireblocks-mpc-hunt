#include "opus/dual_session.h"
#include "opus/fixtures.h"

#include "cosigner/types.h"

#include <cstdio>
#include <map>
#include <string>
#include <vector>

using fireblocks::common::cosigner::cmp_key_metadata;
using fireblocks::common::cosigner::cmp_signing_metadata;

namespace {
int failures = 0;

void check(const char* name, bool ok)
{
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", name);
    }
}

opus::dual_oracle_observation healthy()
{
    opus::dual_oracle_observation o;
    o.both_completed = true;
    o.signatures_observed = true;
    o.signature_a_valid = true;
    o.signature_b_valid = true;
    o.messages_distinct = true;
    return o;
}

std::vector<std::string> fired(const opus::dual_oracle_observation& o,
                               const opus::dual_oracle_verdict& v)
{
    std::vector<std::string> out;
    if (o.both_completed && !v.signatures_valid) out.push_back("signature_invalid");
    if (v.cross_session_verification) out.push_back("cross_session");
    if (v.nonce_reuse) out.push_back("nonce_reuse");
    if (!v.state_isolation) out.push_back("state_isolation");
    if (!v.rollback_clean) out.push_back("rollback");
    if (!v.key_store_unchanged) out.push_back("key_store");
    if (v.harness_fault) out.push_back("harness_fault");
    return out;
}

void neutralize(opus::dual_oracle_verdict& v, const std::string& detector)
{
    if (detector == "signature_invalid") v.signatures_valid = true;
    else if (detector == "cross_session") v.cross_session_verification = false;
    else if (detector == "nonce_reuse") v.nonce_reuse = false;
    else if (detector == "state_isolation") v.state_isolation = true;
    else if (detector == "rollback") v.rollback_clean = true;
    else if (detector == "key_store") v.key_store_unchanged = true;
    else if (detector == "harness_fault") v.harness_fault = false;
}

void calibrate(const std::string& detector,
               const opus::dual_oracle_observation& injected,
               const opus::dual_oracle_observation& nearby)
{
    const auto base = healthy();
    check((detector + " healthy").c_str(),
          fired(base, opus::evaluate_dual_oracles(base)).empty());

    const auto injected_v = opus::evaluate_dual_oracles(injected);
    const auto actual = fired(injected, injected_v);
    check((detector + " directed").c_str(),
          actual.size() == 1 && actual.front() == detector);

    check((detector + " nearby").c_str(),
          fired(nearby, opus::evaluate_dual_oracles(nearby)).empty());

    auto mutant = injected_v;
    neutralize(mutant, detector);
    check((detector + " mutation-sensitive").c_str(),
          fired(injected, mutant) != actual);
}

std::map<uint64_t, opus::det_key_persistency> empty_key_stores()
{
    std::map<uint64_t, opus::det_key_persistency> stores;
    stores.try_emplace(1);
    stores.try_emplace(2);
    stores.try_emplace(3);
    return stores;
}
} // namespace

int main()
{
    {
        opus::dual_result a;
        opus::dual_result b;
        a.elapsed_ms = 1;
        b.elapsed_ms = 999999;
        check("elapsed time excluded from semantic equality", opus::semantic_equal(a, b));
        b.nonce_reuse = true;
        check("semantic equality observes oracle fields", !opus::semantic_equal(a, b));
    }
    {
        auto o = healthy(); o.signature_a_valid = false;
        auto near = healthy(); near.both_completed = false; near.signatures_observed = false;
        calibrate("signature_invalid", o, near);
    }
    {
        auto o = healthy(); o.cross_ab = true;
        auto near = healthy(); near.both_completed = false;
        near.signatures_observed = false; near.cross_ab = true;
        calibrate("cross_session", o, near);
    }
    {
        auto o = healthy(); o.nonce_equal = true;
        auto near = healthy(); near.nonce_equal = true; near.messages_distinct = false;
        calibrate("nonce_reuse", o, near);
    }
    {
        auto o = healthy(); o.other_records_unchanged = false;
        calibrate("state_isolation", o, healthy());
    }
    {
        auto o = healthy(); o.rollback_b_clean = false;
        calibrate("rollback", o, healthy());
    }
    {
        auto o = healthy(); o.key_stores_unchanged = false;
        calibrate("key_store", o, healthy());
    }
    {
        auto o = healthy(); o.harness_fault = true;
        calibrate("harness_fault", o, healthy());
    }

    cmp_signing_metadata before{};
    before.key_id = "calibration-key";
    before.version = 1;
    cmp_signing_metadata after = before;
    after.version = 2;
    const std::string d1 = opus::canonical_signing_record_digest("tx-a", before);
    const std::string d2 = opus::canonical_signing_record_digest("tx-a", after);
    check("record content digest changes without presence change", d1 != d2);
    auto record_observation = healthy();
    record_observation.other_records_unchanged = (d1 == d2);
    check("record mutation reaches shared evaluator",
          !opus::evaluate_dual_oracles(record_observation).state_isolation);

    const auto baseline_stores = empty_key_stores();
    const std::string baseline = opus::aggregate_key_store_digest(baseline_stores);
    for (uint64_t player = 1; player <= 3; ++player) {
        auto stores = empty_key_stores();
        elliptic_curve256_scalar_t private_key{};
        cmp_key_metadata metadata{};
        metadata.algorithm = ECDSA_SECP256K1;
        metadata.t = 2;
        metadata.n = 3;
        stores.at(player).preload_key("calibration-key", ECDSA_SECP256K1,
                                     private_key, metadata);
        check(("aggregate sees player " + std::to_string(player)).c_str(),
              opus::aggregate_key_store_digest(stores) != baseline);
    }

    if (failures) {
        std::fprintf(stderr, "DUAL_ORACLE_CALIBRATION_FAIL failures=%d\n", failures);
        return 1;
    }
    std::printf("DUAL_ORACLE_CALIBRATION_PASS detectors=7 mutations=7\n");
    return 0;
}
