#include "opus/mutators.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <sstream>

using namespace fireblocks::common::cosigner;

namespace opus {
namespace {

bool flip_in(uint8_t* p, size_t len, size_t idx, uint8_t bit)
{
    if (!p || len == 0)
        return false;
    p[idx % len] ^= static_cast<uint8_t>(1u << (bit & 7));
    return true;
}

bool zero_in(uint8_t* p, size_t len)
{
    if (!p || len == 0)
        return false;
    memset(p, 0, len);
    return true;
}

bool apply_to_bytes(const mutation& m, byte_vector_t& v)
{
    switch (m.op) {
    case wire_op::FLIP_BIT: return flip_in(v.data(), v.size(), m.byte_index, m.bit);
    case wire_op::ZERO:     return zero_in(v.data(), v.size());
    case wire_op::TRUNCATE:
        if (v.empty()) return false;
        v.resize(m.byte_index % v.size());
        return true;
    default: return false;
    }
}

bool apply_to_point(const mutation& m, elliptic_curve_point& p)
{
    switch (m.op) {
    case wire_op::FLIP_BIT:
        return flip_in(p.data, sizeof(elliptic_curve256_point_t), m.byte_index, m.bit);
    case wire_op::ZERO:
        // An all-zero compressed point is the library's encoding of infinity.
        // Standalone acceptance of infinity is NOT a finding (SECURITY-MODEL
        // 3.2 / 6.6) -- this exists to confirm the downstream compensating
        // checks fire, not to claim a break.
        return zero_in(p.data, sizeof(elliptic_curve256_point_t));
    default: return false;
    }
}

bool apply_to_scalar(const mutation& m, elliptic_curve_scalar& s)
{
    switch (m.op) {
    case wire_op::FLIP_BIT:
        return flip_in(s.data, sizeof(elliptic_curve256_scalar_t), m.byte_index, m.bit);
    case wire_op::ZERO:
        return zero_in(s.data, sizeof(elliptic_curve256_scalar_t));
    default: return false;
    }
}

const char* field_name(wire_field f)
{
    switch (f) {
    case wire_field::R1_MTA_MESSAGE:         return "r1.mta.message";
    case wire_field::R1_MTA_COMMITMENT:      return "r1.mta.commitment";
    case wire_field::R1_MTA_PROOF:           return "r1.mta.proof";
    case wire_field::R1_MTA_PROOFS_ENTRY:    return "r1.mta_proofs[victim]";
    case wire_field::R1_POINT_A:             return "r1.A";
    case wire_field::R1_POINT_B:             return "r1.B";
    case wire_field::R1_POINT_Z:             return "r1.Z";
    case wire_field::R2_ACK:                 return "r2.ack";
    case wire_field::R2_K_GAMMA_MTA_MESSAGE: return "r2.k_gamma_mta[victim].message";
    case wire_field::R2_K_X_MTA_MESSAGE:     return "r2.k_x_mta[victim].message";
    case wire_field::R2_GAMMA:               return "r2.GAMMA";
    case wire_field::R2_GAMMA_PROOFS_ENTRY:  return "r2.gamma_proofs[victim]";
    case wire_field::R3_DELTA:               return "r3.delta";
    case wire_field::R3_DELTA_POINT:         return "r3.DELTA";
    case wire_field::R3_PROOF:               return "r3.proof";
    case wire_field::R4_SI:                  return "r4.si";
    }
    return "?";
}

const char* op_name(wire_op o)
{
    switch (o) {
    case wire_op::NONE:          return "none";
    case wire_op::FLIP_BIT:      return "flip_bit";
    case wire_op::ZERO:          return "zero";
    case wire_op::TRUNCATE:      return "truncate";
    case wire_op::EXTRA_MAP_KEY: return "extra_map_key";
    }
    return "?";
}

} // namespace

std::string mutation::describe() const
{
    if (!enabled())
        return "none";
    std::ostringstream os;
    os << "r" << round << ':' << field_name(field) << ':' << op_name(op)
       << " by=" << attacker << " blk=" << block;
    if (op == wire_op::FLIP_BIT)
        os << " byte=" << byte_index << " bit=" << unsigned(bit);
    if (op == wire_op::TRUNCATE)
        os << " keep=" << byte_index;
    return os.str();
}

bool apply_r1(const mutation& m,
              std::map<uint64_t, std::vector<cmp_mta_request>>& requests,
              uint64_t victim)
{
    if (m.round != 1 || !m.enabled())
        return false;
    auto it = requests.find(m.attacker);
    if (it == requests.end() || m.block >= it->second.size())
        return false;
    cmp_mta_request& req = it->second[m.block];

    switch (m.field) {
    case wire_field::R1_MTA_MESSAGE:    return apply_to_bytes(m, req.mta.message);
    case wire_field::R1_MTA_COMMITMENT: return apply_to_bytes(m, req.mta.commitment);
    case wire_field::R1_MTA_PROOF:      return apply_to_bytes(m, req.mta.proof);
    case wire_field::R1_MTA_PROOFS_ENTRY: {
        // The entry the victim actually reads (upstream looks up find(my_id)
        // at :180). Mutating any other entry is attacker self-harm.
        auto e = req.mta_proofs.find(victim);
        return e == req.mta_proofs.end() ? false : apply_to_bytes(m, e->second);
    }
    case wire_field::R1_POINT_A: return apply_to_point(m, req.A);
    case wire_field::R1_POINT_B: return apply_to_point(m, req.B);
    case wire_field::R1_POINT_Z: return apply_to_point(m, req.Z);
    default: return false;
    }
}

bool apply_r2(const mutation& m,
              std::map<uint64_t, cmp_mta_responses>& responses,
              uint64_t victim)
{
    if (m.round != 2 || !m.enabled())
        return false;
    auto it = responses.find(m.attacker);
    if (it == responses.end())
        return false;
    cmp_mta_responses& r = it->second;

    if (m.field == wire_field::R2_ACK) {
        switch (m.op) {
        case wire_op::FLIP_BIT:
            return flip_in(r.ack, sizeof(commitments_sha256_t), m.byte_index, m.bit);
        case wire_op::ZERO:
            return zero_in(r.ack, sizeof(commitments_sha256_t));
        default: return false;
        }
    }

    if (m.block >= r.response.size())
        return false;
    cmp_mta_response& resp = r.response[m.block];

    switch (m.field) {
    case wire_field::R2_K_GAMMA_MTA_MESSAGE: {
        auto e = resp.k_gamma_mta.find(victim);
        return e == resp.k_gamma_mta.end() ? false : apply_to_bytes(m, e->second.message);
    }
    case wire_field::R2_K_X_MTA_MESSAGE: {
        auto e = resp.k_x_mta.find(victim);
        return e == resp.k_x_mta.end() ? false : apply_to_bytes(m, e->second.message);
    }
    case wire_field::R2_GAMMA: return apply_to_point(m, resp.GAMMA);
    case wire_field::R2_GAMMA_PROOFS_ENTRY: {
        auto e = resp.gamma_proofs.find(victim);
        return e == resp.gamma_proofs.end() ? false : apply_to_bytes(m, e->second);
    }
    default: return false;
    }
}

bool apply_r3(const mutation& m,
              std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas,
              uint64_t victim)
{
    (void)victim;
    if (m.round != 3 || !m.enabled())
        return false;
    auto it = deltas.find(m.attacker);
    if (it == deltas.end() || m.block >= it->second.size())
        return false;
    cmp_mta_deltas& d = it->second[m.block];

    switch (m.field) {
    case wire_field::R3_DELTA:       return apply_to_scalar(m, d.delta);
    case wire_field::R3_DELTA_POINT: return apply_to_point(m, d.DELTA);
    case wire_field::R3_PROOF:       return apply_to_bytes(m, d.proof);
    default: return false;
    }
}

bool apply_r4(const mutation& m,
              std::map<uint64_t, std::vector<elliptic_curve_scalar>>& sis,
              uint64_t victim,
              const std::vector<uint64_t>& fixture_player_ids,
              const std::vector<uint64_t>& signer_ids)
{
    (void)victim;
    if (m.round != 4 || !m.enabled())
        return false;
    if (m.field != wire_field::R4_SI)
        return false;

    if (m.op == wire_op::EXTRA_MAP_KEY) {
        // The extra entry is attributed to a fixture player that is NOT a
        // signer. Both id sets are CALLER-supplied fixture context, never
        // wire bytes. Sorted copies so the caller need not guarantee order.
        std::vector<uint64_t> players_sorted = fixture_player_ids;
        std::vector<uint64_t> signers_sorted = signer_ids;
        std::sort(players_sorted.begin(), players_sorted.end());
        std::sort(signers_sorted.begin(), signers_sorted.end());

        std::vector<uint64_t> non_signers;
        std::set_difference(players_sorted.begin(), players_sorted.end(),
                            signers_sorted.begin(), signers_sorted.end(),
                            std::back_inserter(non_signers));
        if (non_signers.empty())
            return false;      // t == n fixture: nothing to add; not applied
        const uint64_t extra = non_signers.front();

        // Defense in depth: `extra` is derived from fixture_player_ids, so
        // membership holds by construction. Refuse anyway if it ever does not.
        if (!std::binary_search(players_sorted.begin(), players_sorted.end(), extra))
            return false;      // unknown player: refuse
        if (sis.find(extra) != sis.end())
            return false;      // collision: NEVER overwrite an existing entry

        // Insert exactly one zero scalar. Existing entries are untouched, so
        // the honest wire bytes are preserved byte-exactly. The consumer's
        // signer-count guard (cmp_ecdsa_online_signing_service.cpp:437) is
        // expected to reject the enlarged map; the selftest asserts that
        // rejection end-to-end rather than assuming it.
        std::vector<elliptic_curve_scalar> v(1);
        memset(v[0].data, 0, sizeof(elliptic_curve256_scalar_t));
        sis.emplace(extra, std::move(v));
        return true;
    }

    auto it = sis.find(m.attacker);
    if (it == sis.end() || m.block >= it->second.size())
        return false;
    return apply_to_scalar(m, it->second[m.block]);
}

} // namespace opus
