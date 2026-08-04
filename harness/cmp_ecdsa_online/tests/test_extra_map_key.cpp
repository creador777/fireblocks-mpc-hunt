// Unit tests of the EXTRA_MAP_KEY mutation contract in apply_r4.
//
// Pure mutation-layer tests: no signing session, no snapshot, no library
// state. They assert the contract documented in mutators.h:
//   * inserts exactly one all-zero scalar attributed to a fixture player
//     that is NOT a signer (fixture_player_ids - signer_ids);
//   * never overwrites, reorders or alters an existing entry (byte-exact
//     preservation of the honest wire data);
//   * returns false -- NOT applied -- on collision, on a t == n fixture,
//     and on structurally wrong mutations (round/field);
//   * leaves the classic scalar ops (FLIP_BIT/ZERO) untouched.
//
//   opus_test_extra_map_key   (no arguments)

#include "opus/mutators.h"

#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using fireblocks::common::cosigner::elliptic_curve_scalar;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& name)
{
    ++g_checks;
    if (cond) {
        std::cout << "  [ ok ] " << name << "\n";
    } else {
        ++g_failures;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

using si_map = std::map<uint64_t, std::vector<elliptic_curve_scalar>>;

elliptic_curve_scalar make_scalar(uint8_t fill)
{
    elliptic_curve_scalar s;
    memset(s.data, fill, sizeof(s.data));
    return s;
}

bool scalar_equal(const elliptic_curve_scalar& a, const elliptic_curve_scalar& b)
{
    return memcmp(a.data, b.data, sizeof(a.data)) == 0;
}

bool scalar_zero(const elliptic_curve_scalar& a)
{
    return scalar_equal(a, make_scalar(0));
}

bool map_equal(const si_map& a, const si_map& b)
{
    if (a.size() != b.size())
        return false;
    auto ia = a.begin();
    auto ib = b.begin();
    for (; ia != a.end(); ++ia, ++ib) {
        if (ia->first != ib->first)
            return false;
        if (ia->second.size() != ib->second.size())
            return false;
        for (size_t i = 0; i < ia->second.size(); ++i)
            if (!scalar_equal(ia->second[i], ib->second[i]))
                return false;
    }
    return true;
}

opus::mutation extra_key_mutation(uint64_t attacker)
{
    opus::mutation m;
    m.round = 4;
    m.attacker = attacker;
    m.field = opus::wire_field::R4_SI;
    m.op = opus::wire_op::EXTRA_MAP_KEY;
    return m;
}

} // namespace

int main()
{
    const std::vector<uint64_t> fixture = {1, 2, 3}; // 3-player fixture, t = 2
    const std::vector<uint64_t> signers = {1, 2};    // designated signer set

    std::cout << "== U1 positive: inserts one zero entry for the non-signer ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        sis[2] = {make_scalar(0x22)};
        const si_map before = sis;

        const bool applied =
            opus::apply_r4(extra_key_mutation(1), sis, /*victim=*/2, fixture, signers);

        check(applied, "EXTRA_MAP_KEY reports applied on a t<n fixture");
        check(sis.size() == before.size() + 1, "exactly one entry was added");
        check(sis.count(3) == 1 && sis.at(3).size() == 1,
              "the new entry is attributed to the non-signer fixture player");
        check(sis.count(3) == 1 && scalar_zero(sis.at(3).front()),
              "the inserted scalar is all-zero");
        check(scalar_equal(sis.at(1).front(), before.at(1).front()) &&
                  scalar_equal(sis.at(2).front(), before.at(2).front()),
              "existing entries are preserved byte-exactly");
    }

    std::cout << "== U2 negative: collision with an existing entry ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        sis[2] = {make_scalar(0x22)};
        sis[3] = {make_scalar(0x33)}; // the non-signer id is already present
        const si_map before = sis;

        const bool applied =
            opus::apply_r4(extra_key_mutation(1), sis, 2, fixture, signers);

        check(!applied, "collision is NOT applied");
        check(map_equal(sis, before), "the map is untouched after a collision refusal");
    }

    std::cout << "== U3 negative: t == n fixture has no non-signer ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        sis[2] = {make_scalar(0x22)};
        sis[3] = {make_scalar(0x33)};
        const si_map before = sis;
        const std::vector<uint64_t> all_sign = {1, 2, 3};

        const bool applied =
            opus::apply_r4(extra_key_mutation(1), sis, 2, fixture, all_sign);

        check(!applied, "no non-signer available is NOT applied (fail-closed)");
        check(map_equal(sis, before), "the map is untouched on a t == n fixture");
    }

    std::cout << "== U4 negative: wrong round and wrong field are refused ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        sis[2] = {make_scalar(0x22)};
        const si_map before = sis;

        opus::mutation bad_round = extra_key_mutation(1);
        bad_round.round = 3;
        check(!opus::apply_r4(bad_round, sis, 2, fixture, signers) && map_equal(sis, before),
              "round != 4 is refused");

        opus::mutation bad_field = extra_key_mutation(1);
        bad_field.field = opus::wire_field::R3_DELTA;
        check(!opus::apply_r4(bad_field, sis, 2, fixture, signers) && map_equal(sis, before),
              "field != R4_SI is refused");
    }

    std::cout << "== U5 determinism: unordered id sets select the same non-signer ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        sis[2] = {make_scalar(0x22)};

        const std::vector<uint64_t> fixture_shuffled = {3, 1, 2};
        const std::vector<uint64_t> signers_shuffled = {2, 1};

        const bool applied =
            opus::apply_r4(extra_key_mutation(2), sis, 1, fixture_shuffled, signers_shuffled);

        check(applied && sis.count(3) == 1,
              "the selected non-signer is identical regardless of input order");
    }

    std::cout << "== U6 regression: classic scalar ops keep working ==\n";
    {
        si_map sis;
        sis[1] = {make_scalar(0x11)};
        const si_map before = sis;

        opus::mutation flip;
        flip.round = 4;
        flip.attacker = 1;
        flip.field = opus::wire_field::R4_SI;
        flip.op = opus::wire_op::FLIP_BIT;
        flip.block = 0;
        flip.byte_index = 0;
        flip.bit = 0;

        check(opus::apply_r4(flip, sis, 2, fixture, signers),
              "FLIP_BIT on the attacker's si still applies");
        check(sis.at(1).front().data[0] == static_cast<uint8_t>(0x11 ^ 0x01),
              "the flipped byte has the expected value");
        check(sis.size() == before.size(), "FLIP_BIT adds no map entries");

        opus::mutation missing = flip;
        missing.attacker = 99; // no outbound slot for this id
        check(!opus::apply_r4(missing, sis, 2, fixture, signers),
              "FLIP_BIT with an unknown attacker slot is NOT applied");
    }

    std::cout << "\nchecks: " << g_checks << "   failures: " << g_failures << "\n";
    std::cout << (g_failures == 0 ? "EXTRA_MAP_KEY UNIT PASS\n" : "EXTRA_MAP_KEY UNIT FAIL\n");
    return g_failures == 0 ? 0 : 1;
}
