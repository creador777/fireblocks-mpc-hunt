#include "opus/fixtures.h"
#include "opus/det_rand.h"

#include "cosigner/bam_ecdsa_cosigner.h"       // complete type: bam_signing_properties
#include "cosigner/eddsa_online_signing_service.h" // complete type: eddsa_signature_data
#include "cosigner/frost_cosigner.h"           // complete type: frost_signing_properties
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/paillier/paillier.h"
#include "logging/logging_t.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <sstream>
#include <stdexcept>

using namespace fireblocks::common::cosigner;

namespace opus {

const std::string TENANT_ID("opus harness tenant");

namespace {

void append_u64(std::string& out, uint64_t v)
{
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

void append_bytes(std::string& out, const uint8_t* p, size_t n)
{
    out.append(reinterpret_cast<const char*>(p), n);
}

// Length-prefixed so that concatenation is unambiguous.
void append_blob(std::string& out, const uint8_t* p, size_t n)
{
    append_u64(out, n);
    append_bytes(out, p, n);
}

std::string sha256_hex(const std::string& in)
{
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(in.data()), in.size(), md);
    static const char* hexmap = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char c : md) {
        out.push_back(hexmap[c >> 4]);
        out.push_back(hexmap[c & 0x0F]);
    }
    return out;
}

// Serialize a paillier public key into the digest. Returns nothing on null.
void append_paillier_pub(std::string& out, const paillier_public_key_t* pub)
{
    if (!pub) { append_u64(out, 0); return; }
    uint32_t need = 0;
    paillier_public_key_serialize(pub, nullptr, 0, &need);
    std::vector<uint8_t> buf(need ? need : 1);
    uint32_t real = 0;
    if (paillier_public_key_serialize(pub, buf.data(), need, &real))
        append_blob(out, buf.data(), real);
    else
        append_u64(out, 0);
}

void append_rp_pub(std::string& out, const ring_pedersen_public_t* pub)
{
    if (!pub) { append_u64(out, 0); return; }
    uint32_t need = 0;
    ring_pedersen_public_serialize(pub, nullptr, 0, &need);
    std::vector<uint8_t> buf(need ? need : 1);
    uint32_t real = 0;
    if (ring_pedersen_public_serialize(pub, buf.data(), need, &real))
        append_blob(out, buf.data(), real);
    else
        append_u64(out, 0);
}

void null_log_sink(int, const char*, int, const char*, const char*, void*) {}

} // namespace

void silence_library_logging()
{
    static bool done = false;
    if (done)
        return;
    cosigner_log_init(null_log_sink, nullptr);
    done = true;
}

// ---------------------------------------------------------------------------
// det_platform
// ---------------------------------------------------------------------------

void det_platform::gen_random(size_t len, uint8_t* random_data) const
{
    // Never reached on the online signing path (verified: the library's only
    // gen_random call sites are in setup/refresh). Routed through the same
    // deterministic stream anyway so nothing can silently reintroduce entropy.
    if (len && random_data)
        RAND_bytes(random_data, static_cast<int>(len));
}

const std::string det_platform::get_current_tenantid() const { return TENANT_ID; }

uint64_t det_platform::get_id_from_keyid(const std::string&) const { return _id; }

void det_platform::on_start_signing(const std::string&,
                                    const std::string&,
                                    const signing_data&,
                                    const std::string&,
                                    const std::set<std::string>&,
                                    const signing_type)
{
    if (_throw_on_start)
        throw cosigner_exception(cosigner_exception::UNAUTHORIZED);
}

void det_platform::prepare_for_signing(const std::string&, const std::string) {}

void det_platform::fill_signing_info_from_metadata(const std::string& metadata,
                                                   std::vector<uint32_t>& flags) const
{
    // Pure function of `metadata`. The vector arrives pre-sized by the library
    // (upstream :121-124); write in place and NEVER resize.
    const uint32_t v = (metadata == "positive_r") ? POSITIVE_R : NONE;
    for (auto& f : flags)
        f = v;
}

void det_platform::fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>&,
                                                          const std::string&) const {}
void det_platform::fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>&,
                                                        const std::string&) const {}
void det_platform::fill_frost_signing_info_from_metadata(std::vector<frost_signing_properties>&,
                                                          const std::string&) const {}

void det_platform::derive_initial_share(const share_derivation_args&,
                                        cosigner_sign_algorithm,
                                        elliptic_curve256_scalar_t*) const
{
    // Deliberately NOT assert(0): asserts vanish under NDEBUG, which would turn
    // an unreachable-path bug into silent garbage instead of a loud failure.
    throw std::logic_error("derive_initial_share is unreachable on the CMP online signing path");
}

byte_vector_t det_platform::encrypt_for_player(const uint64_t,
                                               const byte_vector_t& data,
                                               const std::optional<std::string>&) const
{
    return data; // never called on this path; identity matches upstream tests
}

byte_vector_t det_platform::decrypt_message(const byte_vector_t& encrypted_data) const
{
    return encrypted_data;
}

bool det_platform::backup_key(const std::string&,
                              cosigner_sign_algorithm,
                              const elliptic_curve256_scalar_t&,
                              const cmp_key_metadata&,
                              const auxiliary_keys&)
{
    return true;
}

void det_platform::mark_key_setup_in_progress(const std::string&) const {}
void det_platform::clear_key_setup_in_progress(const std::string&) const {}
bool det_platform::is_client_id(uint64_t) const { return false; }

// ---------------------------------------------------------------------------
// det_key_persistency
// ---------------------------------------------------------------------------

void det_key_persistency::preload_key(const std::string& key_id,
                                      cosigner_sign_algorithm algorithm,
                                      const elliptic_curve256_scalar_t& private_key,
                                      const cmp_key_metadata& metadata)
{
    std::unique_lock lock(_mutex);
    auto& info = _keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
    info.metadata = metadata;
    info.has_metadata = true;
}

void det_key_persistency::preload_aux(const std::string& key_id, const auxiliary_keys& aux)
{
    std::unique_lock lock(_mutex);
    _keys[key_id].aux_keys = aux;
}

bool det_key_persistency::key_exist(const std::string& key_id) const
{
    std::shared_lock lock(_mutex);
    return _keys.find(key_id) != _keys.end();
}

void det_key_persistency::load_key(const std::string& key_id,
                                   cosigner_sign_algorithm& algorithm,
                                   elliptic_curve256_scalar_t& private_key) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY); // documented at cmp_key_persistency.h:57
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}

const std::string det_key_persistency::get_tenantid_from_keyid(const std::string&) const
{
    return TENANT_ID;
}

void det_key_persistency::load_key_metadata(const std::string& key_id,
                                            cmp_key_metadata& metadata,
                                            bool /*full_load*/) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    // Throw BAD_KEY rather than letting a bare std::bad_optional_access escape
    // (which is what the upstream test fixture does at setup_test.cpp:83) --
    // an unexpected exception type would be misclassified as CRASH.
    if (it == _keys.end() || !it->second.has_metadata)
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    metadata = it->second.metadata;
}

void det_key_persistency::load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    aux = it->second.aux_keys;
}

std::string det_key_persistency::digest() const
{
    std::shared_lock lock(_mutex);
    std::string acc;
    for (const auto& [key_id, info] : _keys) {          // std::map => ordered
        append_blob(acc, reinterpret_cast<const uint8_t*>(key_id.data()), key_id.size());
        append_u64(acc, static_cast<uint64_t>(info.algorithm));
        append_bytes(acc, info.private_key, sizeof(elliptic_curve256_scalar_t));
        append_u64(acc, info.has_metadata ? 1 : 0);
        if (info.has_metadata) {
            const cmp_key_metadata& md = info.metadata;
            append_bytes(acc, md.public_key, sizeof(elliptic_curve256_point_t));
            append_u64(acc, static_cast<uint64_t>(md.algorithm));
            append_u64(acc, md.t);
            append_u64(acc, md.n);
            append_u64(acc, md.flags);
            append_u64(acc, md.ttl);
            append_bytes(acc, md.seed, sizeof(commitments_sha256_t));
            for (const auto& [pid, pinfo] : md.players_info) {  // ordered
                append_u64(acc, pid);
                append_bytes(acc, pinfo.public_share.data, sizeof(elliptic_curve256_point_t));
                append_paillier_pub(acc, pinfo.paillier.get());
                append_rp_pub(acc, pinfo.ring_pedersen.get());
            }
        }
        // Aux private keys: record only presence + the public projection, so the
        // digest never materialises private key bytes it does not need.
        append_u64(acc, info.aux_keys.paillier ? 1 : 0);
        append_u64(acc, info.aux_keys.ring_pedersen ? 1 : 0);
        if (info.aux_keys.paillier)
            append_paillier_pub(acc, paillier_private_key_get_public(info.aux_keys.paillier.get()));
        if (info.aux_keys.ring_pedersen)
            append_rp_pub(acc, ring_pedersen_private_key_get_public(info.aux_keys.ring_pedersen.get()));
    }
    return sha256_hex(acc);
}

// ---------------------------------------------------------------------------
// det_signing_persistency -- semantics mirror ecdsa_online_test.cpp:95-131
// ---------------------------------------------------------------------------

void det_signing_persistency::store_cmp_signing_data(const std::string& txid,
                                                     const cmp_signing_metadata& data)
{
    std::unique_lock lock(_mutex);
    ++_store_calls;
    if (_metadata.find(txid) != _metadata.end())
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION); // contract C1/C3
    _metadata[txid] = data;
}

void det_signing_persistency::load_cmp_signing_data(const std::string& txid,
                                                    cmp_signing_metadata& data) const
{
    std::shared_lock lock(_mutex);
    auto it = _metadata.find(txid);
    if (it == _metadata.end())
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    data = it->second; // deep copy: library mutates its own copy then writes back
}

void det_signing_persistency::update_cmp_signing_data(const std::string& txid,
                                                      const cmp_signing_metadata& data)
{
    std::unique_lock lock(_mutex);
    ++_update_calls;
    auto it = _metadata.find(txid);
    if (it == _metadata.end())
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    it->second = data;
}

void det_signing_persistency::delete_temporary_signing_data(const std::string& txid)
{
    std::unique_lock lock(_mutex);
    ++_delete_calls;
    _metadata.erase(txid);
}

bool det_signing_persistency::has(const std::string& txid) const
{
    std::shared_lock lock(_mutex);
    return _metadata.find(txid) != _metadata.end();
}

bool det_signing_persistency::try_get(const std::string& txid, cmp_signing_metadata& out) const
{
    std::shared_lock lock(_mutex);
    auto it = _metadata.find(txid);
    if (it == _metadata.end())
        return false;
    out = it->second;
    return true;
}

std::string det_signing_persistency::digest() const
{
    std::shared_lock lock(_mutex);
    std::string acc;
    for (const auto& [txid, md] : _metadata) {          // ordered
        append_blob(acc, reinterpret_cast<const uint8_t*>(txid.data()), txid.size());
        append_blob(acc, reinterpret_cast<const uint8_t*>(md.key_id.data()), md.key_id.size());
        append_bytes(acc, md.chaincode, sizeof(HDChaincode));
        append_bytes(acc, md.ack, sizeof(commitments_sha256_t));
        append_u64(acc, md.version);
        for (uint64_t sid : md.signers_ids)             // std::set => ordered
            append_u64(acc, sid);
        append_u64(acc, md.sig_data.size());
        for (const auto& sd : md.sig_data) {
            append_u64(acc, sd.flags);
            append_bytes(acc, sd.message, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.R.data, sizeof(elliptic_curve256_point_t));
            append_u64(acc, sd.path.size());
            for (uint32_t p : sd.path)
                append_u64(acc, p);
            append_bytes(acc, sd.k.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.gamma.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.a.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.b.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.delta.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.chi.data, sizeof(elliptic_curve256_scalar_t));
            append_bytes(acc, sd.GAMMA.data, sizeof(elliptic_curve256_point_t));
            append_u64(acc, sd.mta_request.size());
            for (const auto& [pid, proof] : sd.G_proofs) {
                append_u64(acc, pid);
                append_u64(acc, proof.size());
            }
            for (const auto& [pid, pd] : sd.public_data) {
                append_u64(acc, pid);
                append_bytes(acc, pd.A.data, sizeof(elliptic_curve256_point_t));
                append_bytes(acc, pd.B.data, sizeof(elliptic_curve256_point_t));
                append_bytes(acc, pd.Z.data, sizeof(elliptic_curve256_point_t));
                append_bytes(acc, pd.GAMMA.data, sizeof(elliptic_curve256_point_t));
                append_u64(acc, pd.gamma_commitment.size());
            }
        }
    }
    return sha256_hex(acc);
}

} // namespace opus
