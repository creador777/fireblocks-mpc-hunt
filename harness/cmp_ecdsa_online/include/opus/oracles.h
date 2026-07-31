#pragma once

#include "opus/snapshot.h"

#include "cosigner/types.h"

#include <string>
#include <vector>

namespace opus {

// ---------------------------------------------------------------------------
// O1 -- the final signature is valid for the message and public key the HARNESS
// asked for.
//
// This is recomputed independently. It deliberately does NOT trust the
// library's own verification at cmp_ecdsa_online_signing_service.cpp:493-498,
// because that check uses the library's stored notion of the message and key.
// A signature that is valid for a DIFFERENT message than the one the honest
// party agreed to sign would pass the library's check and fail this one --
// which is exactly the class of defect worth detecting.
//
// `expected_message` is the harness's own copy of the block data, never
// re-read from library state.
// ---------------------------------------------------------------------------
bool oracle_signature_valid(const snapshot& snap,
                            const std::vector<uint8_t>& expected_message,
                            const std::vector<uint32_t>& path,
                            const uint8_t* chaincode,
                            const fireblocks::common::cosigner::recoverable_signature& sig,
                            bool require_positive_r,
                            std::string& detail);

// Stronger form for the unforgeability property: the signature must NOT verify
// for any message in a canary set the honest party never agreed to sign.
// Returns true when no canary verifies (the safe outcome).
bool oracle_no_canary_forgery(const snapshot& snap,
                              const std::vector<uint32_t>& path,
                              const uint8_t* chaincode,
                              const fireblocks::common::cosigner::recoverable_signature& sig,
                              std::string& detail);

// Curve-dependent positive-R predicate, mirroring the library's own rule at
// cmp_ecdsa_signing_service.h:153-163. The test-local helper in
// ecdsa_online_test.cpp:90-93 only implements the secp256k1 case and would give
// wrong answers on r1/stark.
bool is_positive_scalar(cosigner_sign_algorithm algorithm,
                        const elliptic_curve256_scalar_t& n);

} // namespace opus
