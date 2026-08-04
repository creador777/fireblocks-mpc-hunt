#include "opus/snapshot.h"
#include "opus/det_rand.h"

#include "crypto/commitments/ring_pedersen.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/paillier/paillier.h"

#include <openssl/sha.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>

using namespace fireblocks::common::cosigner;

namespace opus {
namespace {

using algebra_ptr = std::unique_ptr<elliptic_curve256_algebra_ctx_t,
                                    void (*)(elliptic_curve256_algebra_ctx_t*)>;

algebra_ptr make_secp256k1()
{
    return algebra_ptr(elliptic_curve256_new_secp256k1_algebra(),
                       elliptic_curve256_algebra_ctx_free);
}

// ---- little serialization helpers -----------------------------------------

void put_u32(std::vector<uint8_t>& b, uint32_t v)
{
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
void put_u64(std::vector<uint8_t>& b, uint64_t v)
{
    for (int i = 7; i >= 0; --i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
void put_blob(std::vector<uint8_t>& b, const std::vector<uint8_t>& v)
{
    put_u32(b, static_cast<uint32_t>(v.size()));
    b.insert(b.end(), v.begin(), v.end());
}

struct reader
{
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    uint32_t u32()
    {
        if (end - p < 4) { ok = false; return 0; }
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | *p++;
        return v;
    }
    uint64_t u64()
    {
        if (end - p < 8) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | *p++;
        return v;
    }
    std::vector<uint8_t> blob()
    {
        const uint32_t n = u32();
        if (!ok || static_cast<size_t>(end - p) < n) { ok = false; return {}; }
        std::vector<uint8_t> v(p, p + n);
        p += n;
        return v;
    }
};

// ---- serialize an opaque key object through the exported API --------------

template <typename T, typename SizeFn, typename SerFn>
bool ser_obj(const T* obj, SizeFn /*size_fn*/, SerFn ser_fn, std::vector<uint8_t>& out)
{
    uint32_t need = 0;
    ser_fn(obj, nullptr, 0, &need);   // query length
    if (need == 0)
        return false;
    out.assign(need, 0);
    uint32_t real = 0;
    if (!ser_fn(obj, out.data(), need, &real))
        return false;
    out.resize(real);
    return true;
}

bool ser_paillier_pub(const paillier_public_key_t* k, std::vector<uint8_t>& out)
{
    uint32_t need = 0;
    paillier_public_key_serialize(k, nullptr, 0, &need);
    if (!need) return false;
    out.assign(need, 0);
    uint32_t real = 0;
    if (!paillier_public_key_serialize(k, out.data(), need, &real)) return false;
    out.resize(real);
    return true;
}
bool ser_paillier_priv(const paillier_private_key_t* k, std::vector<uint8_t>& out)
{
    uint32_t need = 0;
    paillier_private_key_serialize(k, nullptr, 0, &need);
    if (!need) return false;
    out.assign(need, 0);
    uint32_t real = 0;
    if (!paillier_private_key_serialize(k, out.data(), need, &real)) return false;
    out.resize(real);
    return true;
}
bool ser_rp_pub(const ring_pedersen_public_t* k, std::vector<uint8_t>& out)
{
    uint32_t need = 0;
    ring_pedersen_public_serialize(k, nullptr, 0, &need);
    if (!need) return false;
    out.assign(need, 0);
    uint32_t real = 0;
    if (!ring_pedersen_public_serialize(k, out.data(), need, &real)) return false;
    out.resize(real);
    return true;
}
bool ser_rp_priv(const ring_pedersen_private_t* k, std::vector<uint8_t>& out)
{
    uint32_t need = 0;
    ring_pedersen_private_serialize(k, nullptr, 0, &need);
    if (!need) return false;
    out.assign(need, 0);
    uint32_t real = 0;
    if (!ring_pedersen_private_serialize(k, out.data(), need, &real)) return false;
    out.resize(real);
    return true;
}

} // namespace

std::vector<uint64_t> snapshot::player_ids() const
{
    std::vector<uint64_t> ids;
    ids.reserve(players.size());
    for (const auto& p : players) ids.push_back(p.id);
    return ids;
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

snapshot generate_snapshot(uint64_t seed, const std::vector<uint64_t>& ids, uint8_t t, std::string& err)
{
    snapshot s;
    err.clear();

    if (ids.size() < 2) {
        err = "need at least 2 players (a run with fewer cannot have both an honest and a malicious party)";
        return s;
    }
    if (t == 0)
        t = static_cast<uint8_t>(ids.size());
    if (t < 2 || t > ids.size()) {
        err = "threshold out of range: need 2 <= t <= player count";
        return s;
    }

    reseed_with_label(seed, "opus-snapshot-v1");

    auto algebra = make_secp256k1();
    if (!algebra) { err = "failed to create secp256k1 algebra"; return s; }

    s.algorithm = static_cast<uint32_t>(ECDSA_SECP256K1);
    s.t = t;
    s.n = static_cast<uint8_t>(ids.size());
    s.seed.assign(sizeof(commitments_sha256_t), 0); // all-zero seed, as upstream setup does

    // Additive shares: derived deterministically from the seed, then reduced
    // into the scalar field. Synthetic values only -- no real key material.
    //
    // The aggregate key accumulates ONLY the first t players' shares (the
    // designated signer set); the remaining n - t players are fixture-only
    // and never sign. For t == n this is exactly the historical behaviour.
    elliptic_curve256_scalar_t sum;
    memset(sum, 0, sizeof(sum));
    bool first = true;
    size_t signer_idx = 0;

    for (uint64_t id : ids) {
        const bool designated_signer = (signer_idx++ < t);
        snapshot_player p;
        p.id = id;

        uint8_t material[SHA256_DIGEST_LENGTH];
        {
            std::string label = "opus-share-" + std::to_string(id);
            uint8_t buf[64];
            const size_t n = std::min(sizeof(buf), label.size());
            memcpy(buf, label.data(), n);
            SHA256(buf, n, material);
        }
        elliptic_curve256_scalar_t raw, reduced;
        memcpy(raw, material, sizeof(elliptic_curve256_scalar_t));
        if (algebra->reduce(algebra.get(), &reduced, &raw) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            err = "algebra->reduce failed for player " + std::to_string(id);
            return s;
        }
        p.share.assign(reduced, reduced + sizeof(elliptic_curve256_scalar_t));

        elliptic_curve256_point_t pub_share;
        memset(pub_share, 0, sizeof(pub_share));
        if (algebra->generator_mul(algebra.get(), &pub_share, &reduced) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            err = "generator_mul failed for player " + std::to_string(id);
            return s;
        }
        p.public_share.assign(pub_share, pub_share + sizeof(elliptic_curve256_point_t));

        // Only the designated signer set feeds the aggregate public key; the
        // ceremony later runs with exactly those t players.
        if (designated_signer) {
            if (first) {
                memcpy(sum, reduced, sizeof(sum));
                first = false;
            } else if (algebra->add_scalars(algebra.get(), &sum,
                                            sum, sizeof(sum),
                                            reduced, sizeof(reduced)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
                err = "add_scalars failed for player " + std::to_string(id);
                return s;
            }
        }

        // --- auxiliary material: produced by the library's own generators ---
        paillier_public_key_t* pp = nullptr;
        paillier_private_key_t* ps = nullptr;
        const long pres = paillier_generate_key_pair(PAILLIER_KEY_BITS, &pp, &ps);
        if (pres != PAILLIER_SUCCESS || !pp || !ps) {
            err = "paillier_generate_key_pair failed: " + std::to_string(pres);
            if (pp) paillier_free_public_key(pp);
            if (ps) paillier_free_private_key(ps);
            return s;
        }
        const bool pub_ok  = ser_paillier_pub(pp, p.paillier_pub);
        const bool priv_ok = ser_paillier_priv(ps, p.paillier_priv);
        paillier_free_public_key(pp);
        paillier_free_private_key(ps);
        if (!pub_ok || !priv_ok) { err = "paillier serialization failed"; return s; }

        ring_pedersen_public_t* rpp = nullptr;
        ring_pedersen_private_t* rps = nullptr;
        const ring_pedersen_status rres =
            ring_pedersen_generate_key_pair(RING_PEDERSEN_KEY_BITS, &rpp, &rps);
        if (rres != RING_PEDERSEN_SUCCESS || !rpp || !rps) {
            err = "ring_pedersen_generate_key_pair failed: " + std::to_string(rres);
            if (rpp) ring_pedersen_free_public(rpp);
            if (rps) ring_pedersen_free_private(rps);
            return s;
        }
        const bool rpub_ok  = ser_rp_pub(rpp, p.rp_pub);
        const bool rpriv_ok = ser_rp_priv(rps, p.rp_priv);
        ring_pedersen_free_public(rpp);
        ring_pedersen_free_private(rps);
        if (!rpub_ok || !rpriv_ok) { err = "ring pedersen serialization failed"; return s; }

        s.players.push_back(std::move(p));
    }

    elliptic_curve256_point_t X;
    memset(X, 0, sizeof(X));
    if (algebra->generator_mul(algebra.get(), &X, &sum) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        err = "generator_mul failed for the aggregate public key";
        return s;
    }
    s.public_key.assign(X, X + sizeof(elliptic_curve256_point_t));

    return s;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

bool verify_snapshot(const snapshot& s, std::string& err)
{
    err.clear();
    auto algebra = make_secp256k1();
    if (!algebra) { err = "no algebra"; return false; }

    if (s.players.size() < 2)                     { err = "fewer than 2 players"; return false; }
    // The library requires the ceremony's players_ids.size() == metadata.t
    // (cmp_ecdsa_online_signing_service.cpp:59). t may be SMALLER than the
    // player count: the first t players are then the designated signer set
    // and the remaining n - t players are fixture-only (they never sign).
    if (s.t < 2 || s.t > s.players.size())        { err = "t outside 2..player count"; return false; }
    if (s.n != s.players.size())                  { err = "n != player count"; return false; }
    if (s.public_key.size() != sizeof(elliptic_curve256_point_t)) { err = "bad public key length"; return false; }
    if (s.seed.size() != sizeof(commitments_sha256_t))            { err = "bad seed length"; return false; }

    elliptic_curve256_scalar_t sum;
    memset(sum, 0, sizeof(sum));
    bool first = true;
    size_t signer_idx = 0;

    for (const auto& p : s.players) {
        const bool designated_signer = (signer_idx++ < s.t);
        if (p.share.size() != sizeof(elliptic_curve256_scalar_t)) { err = "bad share length"; return false; }
        if (p.public_share.size() != sizeof(elliptic_curve256_point_t)) { err = "bad public_share length"; return false; }

        // public_share_i == g^{share_i}. The library re-derives this during
        // mta_verify (cmp_ecdsa_signing_service.cpp:201 -> mta.cpp:1643-1661);
        // a mismatch would surface as a bogus INVALID_PARAMETERS.
        elliptic_curve256_scalar_t x;
        memcpy(x, p.share.data(), sizeof(x));
        elliptic_curve256_point_t expect;
        memset(expect, 0, sizeof(expect));
        if (algebra->generator_mul(algebra.get(), &expect, &x) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            err = "generator_mul failed while verifying player " + std::to_string(p.id);
            return false;
        }
        if (memcmp(expect, p.public_share.data(), sizeof(expect)) != 0) {
            err = "public_share != g^share for player " + std::to_string(p.id);
            return false;
        }

        if (designated_signer) {
            if (first) { memcpy(sum, x, sizeof(sum)); first = false; }
            else if (algebra->add_scalars(algebra.get(), &sum, sum, sizeof(sum), x, sizeof(x))
                     != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
                err = "add_scalars failed"; return false;
            }
        }

        // Aux private material must round-trip and its public projection must
        // equal the stored public. Otherwise round 3 decrypts garbage and the
        // failure looks like a library bug.
        std::unique_ptr<paillier_private_key_t, void (*)(paillier_private_key_t*)> ppriv(
            paillier_private_key_deserialize(p.paillier_priv.data(),
                                             static_cast<uint32_t>(p.paillier_priv.size())),
            paillier_free_private_key);
        if (!ppriv) { err = "paillier private deserialize failed for player " + std::to_string(p.id); return false; }

        std::vector<uint8_t> derived_pub;
        if (!ser_paillier_pub(paillier_private_key_get_public(ppriv.get()), derived_pub)) {
            err = "paillier public projection failed"; return false;
        }
        if (derived_pub != p.paillier_pub) {
            err = "paillier public != public(private) for player " + std::to_string(p.id);
            return false;
        }

        std::unique_ptr<ring_pedersen_private_t, void (*)(ring_pedersen_private_t*)> rpriv(
            ring_pedersen_private_deserialize(p.rp_priv.data(),
                                              static_cast<uint32_t>(p.rp_priv.size())),
            ring_pedersen_free_private);
        if (!rpriv) { err = "ring pedersen private deserialize failed for player " + std::to_string(p.id); return false; }

        std::vector<uint8_t> derived_rp;
        if (!ser_rp_pub(ring_pedersen_private_key_get_public(rpriv.get()), derived_rp)) {
            err = "ring pedersen public projection failed"; return false;
        }
        if (derived_rp != p.rp_pub) {
            err = "ring pedersen public != public(private) for player " + std::to_string(p.id);
            return false;
        }
    }

    // public_key == g^{sum of the DESIGNATED SIGNER shares} (the first t
    // players). Enforced by the library's own final signature verification
    // (cmp_ecdsa_online_signing_service.cpp:493-498), which runs over exactly
    // the ceremony's signers.
    elliptic_curve256_point_t X;
    memset(X, 0, sizeof(X));
    if (algebra->generator_mul(algebra.get(), &X, &sum) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        err = "generator_mul failed for aggregate"; return false;
    }
    if (memcmp(X, s.public_key.data(), sizeof(X)) != 0) {
        err = "public_key != g^(sum of shares)";
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// file I/O
// ---------------------------------------------------------------------------

bool write_snapshot(const snapshot& s, const std::string& path, std::string& err)
{
    std::vector<uint8_t> b;
    b.insert(b.end(), SNAPSHOT_MAGIC, SNAPSHOT_MAGIC + sizeof(SNAPSHOT_MAGIC));
    put_u32(b, SNAPSHOT_FORMAT_VERSION);
    put_u32(b, s.algorithm);
    put_blob(b, s.public_key);
    put_blob(b, s.seed);
    put_u32(b, s.t);
    put_u32(b, s.n);
    put_u32(b, static_cast<uint32_t>(s.players.size()));
    for (const auto& p : s.players) {
        put_u64(b, p.id);
        put_blob(b, p.share);
        put_blob(b, p.public_share);
        put_blob(b, p.paillier_pub);
        put_blob(b, p.paillier_priv);
        put_blob(b, p.rp_pub);
        put_blob(b, p.rp_priv);
    }

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { err = "cannot open " + path + " for writing"; return false; }
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    if (!f) { err = "write failed for " + path; return false; }
    return true;
}

bool read_snapshot(const std::string& path, snapshot& out, std::string& err)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "cannot open " + path + " for reading"; return false; }
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    if (b.size() < sizeof(SNAPSHOT_MAGIC) ||
        memcmp(b.data(), SNAPSHOT_MAGIC, sizeof(SNAPSHOT_MAGIC)) != 0) {
        err = "bad snapshot magic";
        return false;
    }

    reader r{b.data() + sizeof(SNAPSHOT_MAGIC), b.data() + b.size()};
    const uint32_t fmt = r.u32();
    if (fmt != SNAPSHOT_FORMAT_VERSION) { err = "unsupported snapshot format " + std::to_string(fmt); return false; }

    out = snapshot{};
    out.algorithm  = r.u32();
    out.public_key = r.blob();
    out.seed       = r.blob();
    out.t          = static_cast<uint8_t>(r.u32());
    out.n          = static_cast<uint8_t>(r.u32());
    const uint32_t count = r.u32();
    if (!r.ok) { err = "truncated snapshot header"; return false; }

    for (uint32_t i = 0; i < count; ++i) {
        snapshot_player p;
        p.id            = r.u64();
        p.share         = r.blob();
        p.public_share  = r.blob();
        p.paillier_pub  = r.blob();
        p.paillier_priv = r.blob();
        p.rp_pub        = r.blob();
        p.rp_priv       = r.blob();
        if (!r.ok) { err = "truncated snapshot player record"; return false; }
        out.players.push_back(std::move(p));
    }
    if (r.p != r.end) { err = "trailing bytes in snapshot"; return false; }
    return true;
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

bool install_snapshot(const snapshot& s,
                      const std::string& key_id,
                      std::map<uint64_t, det_key_persistency>& stores,
                      std::string& err)
{
    err.clear();

    // One metadata object, identical for every player. build_aad hashes
    // metadata.seed, and the round-2 ack is computed over the shared request
    // set -- divergent metadata would break the ack comparison at :258-262.
    cmp_key_metadata md;
    memcpy(md.public_key, s.public_key.data(), sizeof(elliptic_curve256_point_t));
    md.algorithm = static_cast<cosigner_sign_algorithm>(s.algorithm);
    md.t = s.t;
    md.n = s.n;
    md.flags = 0;   // additive n-of-n; THRESHOLD is only read by the EdDSA path
    md.ttl = 0;
    memcpy(md.seed, s.seed.data(), sizeof(commitments_sha256_t));

    for (const auto& p : s.players) {
        cmp_player_info info;
        memcpy(info.public_share.data, p.public_share.data(), sizeof(elliptic_curve256_point_t));

        paillier_public_key_t* ppub =
            paillier_public_key_deserialize(p.paillier_pub.data(),
                                            static_cast<uint32_t>(p.paillier_pub.size()));
        if (!ppub) { err = "paillier public deserialize failed for " + std::to_string(p.id); return false; }
        info.paillier = std::shared_ptr<paillier_public_key_t>(ppub, paillier_free_public_key);

        ring_pedersen_public_t* rpub =
            ring_pedersen_public_deserialize(p.rp_pub.data(),
                                             static_cast<uint32_t>(p.rp_pub.size()));
        if (!rpub) { err = "ring pedersen public deserialize failed for " + std::to_string(p.id); return false; }
        info.ring_pedersen = std::shared_ptr<ring_pedersen_public_t>(rpub, ring_pedersen_free_public);

        md.players_info[p.id] = std::move(info);
    }

    for (const auto& p : s.players) {
        auto it = stores.find(p.id);
        if (it == stores.end()) { err = "no key store for player " + std::to_string(p.id); return false; }

        elliptic_curve256_scalar_t share;
        memcpy(share, p.share.data(), sizeof(share));
        it->second.preload_key(key_id, static_cast<cosigner_sign_algorithm>(s.algorithm), share, md);

        paillier_private_key_t* ppriv =
            paillier_private_key_deserialize(p.paillier_priv.data(),
                                             static_cast<uint32_t>(p.paillier_priv.size()));
        if (!ppriv) { err = "paillier private deserialize failed for " + std::to_string(p.id); return false; }

        ring_pedersen_private_t* rpriv =
            ring_pedersen_private_deserialize(p.rp_priv.data(),
                                              static_cast<uint32_t>(p.rp_priv.size()));
        if (!rpriv) {
            paillier_free_private_key(ppriv);
            err = "ring pedersen private deserialize failed for " + std::to_string(p.id);
            return false;
        }

        auxiliary_keys aux;
        aux.paillier      = std::shared_ptr<paillier_private_key_t>(ppriv, paillier_free_private_key);
        aux.ring_pedersen = std::shared_ptr<ring_pedersen_private_t>(rpriv, ring_pedersen_free_private);
        it->second.preload_aux(key_id, aux);
    }

    return true;
}

} // namespace opus
