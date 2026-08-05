#pragma once

#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/types.h"

#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace opus {

// The tenant string must be identical in platform_service::get_current_tenantid
// and cmp_key_persistency::get_tenantid_from_keyid, otherwise every round
// throws UNAUTHORIZED from verify_tenant_id (upstream utils.cpp:16-24).
extern const std::string TENANT_ID;

// Fixed wall-clock reading. TimingMap subtracts unsigned (timing_map.cpp:52),
// so the clock must never appear to move backwards.
constexpr uint64_t FIXED_NOW_MSEC = 1700000000000ULL;

// ---------------------------------------------------------------------------
// platform_service: 16 pure virtuals + 1 override for the clock.
// One instance per player.
// ---------------------------------------------------------------------------
class det_platform final : public fireblocks::common::cosigner::platform_service
{
public:
    explicit det_platform(uint64_t id) : _id(id) {}

    // Fault-injection hook for on_start_signing (exercises the pre-store abort
    // path: upstream calls it at :89, stores at :125).
    void set_throw_on_start_signing(bool v) { _throw_on_start = v; }

private:
    void gen_random(size_t len, uint8_t* random_data) const override;
    const std::string get_current_tenantid() const override;
    uint64_t get_id_from_keyid(const std::string& key_id) const override;

    void on_start_signing(const std::string& key_id,
                          const std::string& txid,
                          const fireblocks::common::cosigner::signing_data& data,
                          const std::string& metadata_json,
                          const std::set<std::string>& players,
                          const signing_type signature_type) override;

    void prepare_for_signing(const std::string& key_id, const std::string tx_id) override;

    void fill_signing_info_from_metadata(const std::string& metadata,
                                         std::vector<uint32_t>& flags) const override;
    void fill_eddsa_signing_info_from_metadata(
        std::vector<fireblocks::common::cosigner::eddsa_signature_data>& info,
        const std::string& metadata) const override;
    void fill_bam_signing_info_from_metadata(
        std::vector<fireblocks::common::cosigner::bam_signing_properties>& info,
        const std::string& metadata) const override;
    void fill_frost_signing_info_from_metadata(
        std::vector<fireblocks::common::cosigner::frost_signing_properties>& info,
        const std::string& metadata) const override;

    void derive_initial_share(const fireblocks::common::cosigner::share_derivation_args& derive_from,
                              cosigner_sign_algorithm algorithm,
                              elliptic_curve256_scalar_t* key) const override;

    fireblocks::common::cosigner::byte_vector_t encrypt_for_player(
        const uint64_t id,
        const fireblocks::common::cosigner::byte_vector_t& data,
        const std::optional<std::string>& verify_modulus = std::nullopt) const override;

    fireblocks::common::cosigner::byte_vector_t decrypt_message(
        const fireblocks::common::cosigner::byte_vector_t& encrypted_data) const override;

    bool backup_key(const std::string& key_id,
                    cosigner_sign_algorithm algorithm,
                    const elliptic_curve256_scalar_t& private_key,
                    const fireblocks::common::cosigner::cmp_key_metadata& metadata,
                    const fireblocks::common::cosigner::auxiliary_keys& aux) override;

    void mark_key_setup_in_progress(const std::string& key_id) const override;
    void clear_key_setup_in_progress(const std::string& key_id) const override;
    bool is_client_id(uint64_t player_id) const override;
    uint64_t now_msec() const override { return FIXED_NOW_MSEC; }

    const uint64_t _id;
    bool _throw_on_start = false;
};

// ---------------------------------------------------------------------------
// cmp_key_persistency: 5 const readers. The interface has NO mutating method,
// which is what makes oracle O4's "D_key never changes" invariant meaningful.
// ---------------------------------------------------------------------------
class det_key_persistency final : public fireblocks::common::cosigner::cmp_key_persistency
{
public:
    // Snapshot installers -- non-virtual, harness-only. These are the only way
    // key material enters the store.
    void preload_key(const std::string& key_id,
                     cosigner_sign_algorithm algorithm,
                     const elliptic_curve256_scalar_t& private_key,
                     const fireblocks::common::cosigner::cmp_key_metadata& metadata);
    void preload_aux(const std::string& key_id,
                     const fireblocks::common::cosigner::auxiliary_keys& aux);

    // Canonical digest of the entire store, for oracle O4 (D_key).
    std::string digest() const;

private:
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id,
                  cosigner_sign_algorithm& algorithm,
                  elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id,
                           fireblocks::common::cosigner::cmp_key_metadata& metadata,
                           bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id,
                             fireblocks::common::cosigner::auxiliary_keys& aux) const override;

    struct key_info {
        cosigner_sign_algorithm algorithm{};
        elliptic_curve256_scalar_t private_key{};
        fireblocks::common::cosigner::cmp_key_metadata metadata;
        fireblocks::common::cosigner::auxiliary_keys aux_keys;
        bool has_metadata = false;
    };

    mutable std::shared_mutex _mutex;
    std::map<std::string, key_info> _keys;
};

// ---------------------------------------------------------------------------
// signing_persistency. The bundled upstream test
// (test/cosigner/ecdsa_online_test.cpp:95-131) is a NORMATIVE statement of the
// integrator contract, so this reproduces its semantics exactly:
//   store_  throws INVALID_TRANSACTION on duplicate txid  (contract C1 / C3)
//   load_   throws INVALID_TRANSACTION when absent, deep-copies out
//   update_ throws INVALID_TRANSACTION when absent
//   delete_ never throws
// A permissive upsert here would invalidate every result the harness produces.
// ---------------------------------------------------------------------------
class det_signing_persistency final
    : public fireblocks::common::cosigner::cmp_ecdsa_online_signing_service::signing_persistency
{
public:
    // Canonical digest of the whole map, for oracle O4 (D_sig).
    std::string digest() const;

    // Canonical digest of exactly one transaction record. Absence stays
    // distinct from every possible digest.
    std::optional<std::string> digest_for_txid(const std::string& txid) const;

    // Read-only inspection for the state-machine oracle.
    bool has(const std::string& txid) const;
    bool try_get(const std::string& txid,
                 fireblocks::common::cosigner::cmp_signing_metadata& out) const;

    // Counters let O4 distinguish "record absent because completed" from
    // "record absent because something deleted it".
    size_t store_calls() const  { return _store_calls; }
    size_t update_calls() const { return _update_calls; }
    size_t delete_calls() const { return _delete_calls; }

private:
    void store_cmp_signing_data(
        const std::string& txid,
        const fireblocks::common::cosigner::cmp_signing_metadata& data) override;
    void load_cmp_signing_data(
        const std::string& txid,
        fireblocks::common::cosigner::cmp_signing_metadata& data) const override;
    void update_cmp_signing_data(
        const std::string& txid,
        const fireblocks::common::cosigner::cmp_signing_metadata& data) override;
    void delete_temporary_signing_data(const std::string& txid) override;

    mutable std::shared_mutex _mutex;
    std::map<std::string, fireblocks::common::cosigner::cmp_signing_metadata> _metadata;
    size_t _store_calls = 0;
    size_t _update_calls = 0;
    size_t _delete_calls = 0;
};

std::string canonical_signing_record_digest(
    const std::string& txid,
    const fireblocks::common::cosigner::cmp_signing_metadata& data);

std::string aggregate_key_store_digest(
    const std::map<uint64_t, det_key_persistency>& stores);

// One player's complete instance. Declaration order matters: the service
// constructor binds references to the two members above it.
struct player_ctx
{
    player_ctx(uint64_t id, const det_key_persistency& keys)
        : platform(id), signing_store(), service(platform, keys, signing_store) {}

    det_platform platform;
    det_signing_persistency signing_store;
    fireblocks::common::cosigner::cmp_ecdsa_online_signing_service service;
};

// Silences the library's LOG_* output so runs are reproducible and the console
// stays readable. Idempotent.
void silence_library_logging();

} // namespace opus
