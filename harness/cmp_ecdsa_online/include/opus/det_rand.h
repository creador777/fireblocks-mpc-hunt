#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace opus {

// ---------------------------------------------------------------------------
// Deterministic randomness for the whole process.
//
// WHY THIS EXISTS (verified against the pinned tree):
//   platform_service::gen_random is NEVER called on the CMP ECDSA online
//   signing path. The three call sites in the library are
//   cmp_setup_service.cpp:108, cmp_setup_service.cpp:696 and
//   cmp_offline_refresh_service.cpp:69 -- all key setup / refresh, not signing.
//
//   Every random draw made while signing terminates inside OpenSSL:
//     - algebra->rand      -> GFp_curve_algebra.c:788-799 BN_rand_range
//     - inline BN_rand_range
//     - inline RAND_bytes  (mta.cpp:713, 1141, 1261; commitments.c:20,52;
//                           ring_pedersen.c:1142,1256; paillier_zkp.c:1230)
//
//   BN_rand_range funnels through bnrand() -> RAND_bytes() ->
//   RAND_get_rand_method(), a runtime function-pointer dispatch. Installing a
//   RAND_METHOD is therefore the only lever that captures all sinks without
//   modifying upstream. Requires a SHARED libcrypto -- see CMakeLists.txt.
//
// This is a TEST INSTRUMENT. Any behaviour that depends on the RNG being
// predictable is a harness artifact and must never be reported as a finding.
// ---------------------------------------------------------------------------

// Installs the deterministic RAND_METHOD process-wide. Idempotent.
// Returns false if OpenSSL refused the method.
bool install_deterministic_rand();

// Reseeds the stream. Call at the start of every case so that case N is
// reproducible independently of how many draws case N-1 consumed.
void reseed(uint64_t seed);
void reseed_with_label(uint64_t seed, const std::string& label);

// Number of bytes drawn since the last reseed. Diagnostic only: draw counts
// are data-dependent (retry loops at mta.cpp:469-477, :491-499,
// range_proofs.c:475-480, :967-972, paillier.c:928-937), so this is NOT a
// stable invariant across different inputs.
uint64_t bytes_drawn();

// Verifies the override is actually in force: draws twice under the same seed
// and requires byte-identical output, then confirms OpenSSL dispatches
// RAND_bytes to us. Returns false if determinism cannot be guaranteed.
bool self_test();

} // namespace opus
