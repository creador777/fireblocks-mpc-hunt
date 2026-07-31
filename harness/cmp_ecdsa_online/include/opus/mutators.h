#pragma once

#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace opus {

// ---------------------------------------------------------------------------
// The mutation surface is EXACTLY the set of structures a malicious peer can
// put on the wire during CMP ECDSA online signing. All four are declared in the
// PUBLIC header include/cosigner/cmp_ecdsa_signing_service.h, which is the same
// API surface a real integrator sees.
//
// DELIBERATELY OUT OF SCOPE, and not reachable through this type:
//   * key_id / txid / algorithm / signing_data / metadata_json / players_ids
//     -- caller-supplied, 100% local at start_signing. Corrupting them tests
//     the caller contract, not the protocol (SECURITY-MODEL 2.4).
//   * cmp_key_metadata / auxiliary_keys -- loaded from persistency, never peer
//     supplied. Corrupting them violates the honest-party premise (1.3).
//   * key sizes -- shrinking them manufactures known non-findings (6.1).
// ---------------------------------------------------------------------------

enum class wire_field {
    // round 1 -- cmp_mta_request
    R1_MTA_MESSAGE,
    R1_MTA_COMMITMENT,
    R1_MTA_PROOF,
    R1_MTA_PROOFS_ENTRY,   // mta_proofs[victim]
    R1_POINT_A,
    R1_POINT_B,
    R1_POINT_Z,
    // round 2 -- cmp_mta_responses
    R2_ACK,
    R2_K_GAMMA_MTA_MESSAGE,
    R2_K_X_MTA_MESSAGE,
    R2_GAMMA,
    R2_GAMMA_PROOFS_ENTRY,
    // round 3 -- cmp_mta_deltas
    R3_DELTA,
    R3_DELTA_POINT,
    R3_PROOF,
    // round 4 -- the s share
    R4_SI,
};

enum class wire_op {
    NONE,
    FLIP_BIT,      // single bit, the minimal perturbation
    ZERO,          // all-zero the field
    TRUNCATE,      // drop trailing bytes of a byte_vector_t
    EXTRA_MAP_KEY, // round 4 only: add a delta entry for an id that is not a signer
};

struct mutation
{
    int        round = 0;                 // 1..4; 0 = disabled
    uint64_t   attacker = 0;              // whose outbound slot is altered
    wire_field field = wire_field::R1_MTA_MESSAGE;
    wire_op    op = wire_op::NONE;
    size_t     block = 0;                 // which signing block
    size_t     byte_index = 0;            // for FLIP_BIT / TRUNCATE
    uint8_t    bit = 0;                   // 0..7, for FLIP_BIT

    bool enabled() const { return round != 0 && op != wire_op::NONE; }
    std::string describe() const;
};

// Each apply_* returns true if it actually changed something. A mutation that
// silently no-ops (index out of range, empty buffer) must NOT be counted as a
// tested case -- otherwise the campaign reports coverage it never had.
bool apply_r1(const mutation& m,
              std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_request>>& requests,
              uint64_t victim);

bool apply_r2(const mutation& m,
              std::map<uint64_t, fireblocks::common::cosigner::cmp_mta_responses>& responses,
              uint64_t victim);

bool apply_r3(const mutation& m,
              std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_deltas>>& deltas,
              uint64_t victim);

bool apply_r4(const mutation& m,
              std::map<uint64_t, std::vector<fireblocks::common::cosigner::elliptic_curve_scalar>>& sis,
              uint64_t victim);

} // namespace opus
