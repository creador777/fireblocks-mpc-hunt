#pragma once

#include "opus/fixtures.h"

#include "cosigner/cmp_key_persistency.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace opus {

// ---------------------------------------------------------------------------
// A deterministic, minimal, VALID starting state for CMP ECDSA online signing.
//
// Built ONCE by tools/mk_snapshot and frozen to a file. Loaded verbatim at the
// start of every run, so no key generation ever happens inside the test loop.
//
// The expensive, high-variance part is the auxiliary material -- Paillier
// (2048-bit) and ring-Pedersen (1024-bit, SAFE primes, unbounded-loop prime
// search). Those are produced by the library's own generators and then frozen
// via the exported serialize/deserialize API.
//
// The cheap part -- the additive secret shares and the public key -- is chosen
// by hand: x_i are fixed constants reduced mod the group order,
// X = g^(sum x_i), and public_share_i = g^(x_i).
//
// KEY SIZES ARE NEVER REDUCED. PAILLIER_KEY_SIZE=2048 and
// RING_PEDERSEN_KEY_SIZE=1024 match upstream cmp_setup_service.cpp:24-25
// exactly. Shrinking them would manufacture out-of-scope "small key" findings
// (SECURITY-MODEL 6.1).
// ---------------------------------------------------------------------------

constexpr uint32_t PAILLIER_KEY_BITS      = 32 * 8 * 8; // 2048, = upstream
constexpr uint32_t RING_PEDERSEN_KEY_BITS = 32 * 8 * 4; // 1024, = upstream

constexpr char SNAPSHOT_MAGIC[8] = {'O','C','M','P','S','N','A','P'};
constexpr uint32_t SNAPSHOT_FORMAT_VERSION = 1;

struct snapshot_player
{
    uint64_t id = 0;
    std::vector<uint8_t> share;          // 32 bytes, big-endian scalar
    std::vector<uint8_t> public_share;   // 33 bytes, compressed point
    std::vector<uint8_t> paillier_pub;
    std::vector<uint8_t> paillier_priv;
    std::vector<uint8_t> rp_pub;
    std::vector<uint8_t> rp_priv;
};

struct snapshot
{
    uint32_t algorithm = 0;              // cosigner_sign_algorithm; 0 = ECDSA_SECP256K1
    std::vector<uint8_t> public_key;     // 33 bytes
    std::vector<uint8_t> seed;           // 32 bytes, feeds build_aad
    uint8_t t = 0;
    uint8_t n = 0;
    std::vector<snapshot_player> players; // ordered by id

    std::vector<uint64_t> player_ids() const;
};

// Produce a snapshot from scratch. SLOW (Paillier + safe-prime generation).
// Runs under the deterministic RNG, so a given seed yields identical bytes.
snapshot generate_snapshot(uint64_t seed, const std::vector<uint64_t>& ids, std::string& err);

bool write_snapshot(const snapshot& s, const std::string& path, std::string& err);
bool read_snapshot(const std::string& path, snapshot& out, std::string& err);

// Rebuild the in-memory cmp_key_metadata shared by every player, plus install
// each player's private share and auxiliary keys into its own key store.
//
// `stores` must already contain one entry per player id.
bool install_snapshot(const snapshot& s,
                      const std::string& key_id,
                      std::map<uint64_t, det_key_persistency>& stores,
                      std::string& err);

// Re-derives the public data from the private material and checks every
// internal-consistency invariant the library will later rely on. A snapshot
// that fails this must never be used: it would produce library rejections that
// look like findings but are really harness faults.
bool verify_snapshot(const snapshot& s, std::string& err);

} // namespace opus
