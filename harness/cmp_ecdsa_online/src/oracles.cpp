#include "opus/oracles.h"

#include "blockchain/mpc/hd_derive.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <cstring>
#include <memory>

using namespace fireblocks::common::cosigner;

namespace opus {
namespace {

using algebra_ptr = std::unique_ptr<elliptic_curve256_algebra_ctx_t,
                                    void (*)(elliptic_curve256_algebra_ctx_t*)>;

algebra_ptr make_algebra(cosigner_sign_algorithm t)
{
    elliptic_curve256_algebra_ctx_t* ctx = nullptr;
    switch (t) {
    case ECDSA_SECP256K1: ctx = elliptic_curve256_new_secp256k1_algebra(); break;
    case ECDSA_SECP256R1: ctx = elliptic_curve256_new_secp256r1_algebra(); break;
    case ECDSA_STARK:     ctx = elliptic_curve256_new_stark_algebra();     break;
    default:              ctx = nullptr;                                   break;
    }
    return algebra_ptr(ctx, elliptic_curve256_algebra_ctx_free);
}

bool is_greater_or_equal(const uint8_t* a, const uint8_t* b, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        if (a[i] < b[i]) return false;
        if (a[i] > b[i]) return true;
    }
    return true;
}

} // namespace

bool is_positive_scalar(cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& n)
{
    if (algorithm == ECDSA_STARK)
        return n[0] < 4; // stark curve is 252 bit
    if (algorithm == ECDSA_SECP256R1) {
        static const uint8_t half_n_first_8_bytes[] = {0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00};
        return is_greater_or_equal(n, half_n_first_8_bytes, sizeof(half_n_first_8_bytes)) == false;
    }
    return (n[0] & 0x80) == 0;
}

bool oracle_signature_valid(const snapshot& snap,
                            const std::vector<uint8_t>& expected_message,
                            const std::vector<uint32_t>& path,
                            const uint8_t* chaincode,
                            const recoverable_signature& sig,
                            bool require_positive_r,
                            std::string& detail)
{
    detail.clear();
    const auto algo = static_cast<cosigner_sign_algorithm>(snap.algorithm);

    if (expected_message.size() != sizeof(elliptic_curve256_scalar_t)) {
        detail = "expected message is not 32 bytes";
        return false;
    }

    auto algebra = make_algebra(algo);
    if (!algebra) { detail = "no algebra for algorithm"; return false; }

    elliptic_curve256_point_t root;
    memcpy(root, snap.public_key.data(), sizeof(root));

    PubKey derived;
    memset(derived, 0, sizeof(derived));
    const hd_derive_status ds = derive_public_key_generic(
        algebra.get(), derived, root, chaincode, path.data(), path.size());
    if (ds != HD_DERIVE_SUCCESS) {
        detail = "derive_public_key_generic failed: " + std::to_string(static_cast<int>(ds));
        return false;
    }

    elliptic_curve256_scalar_t msg;
    memcpy(msg, expected_message.data(), sizeof(msg));

    const elliptic_curve_algebra_status st = GFp_curve_algebra_verify_signature(
        reinterpret_cast<GFp_curve_algebra_ctx_t*>(algebra->ctx),
        &derived, &msg, &sig.r, &sig.s);
    if (st != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        detail = "signature does not verify for the requested message and derived public key (status "
                 + std::to_string(static_cast<int>(st)) + ")";
        return false;
    }

    if (require_positive_r && !is_positive_scalar(algo, sig.r)) {
        detail = "POSITIVE_R was requested but r is negative";
        return false;
    }

    return true;
}

bool oracle_no_canary_forgery(const snapshot& snap,
                              const std::vector<uint32_t>& path,
                              const uint8_t* chaincode,
                              const recoverable_signature& sig,
                              std::string& detail)
{
    detail.clear();
    const auto algo = static_cast<cosigner_sign_algorithm>(snap.algorithm);

    auto algebra = make_algebra(algo);
    if (!algebra) { detail = "no algebra for algorithm"; return false; }

    elliptic_curve256_point_t root;
    memcpy(root, snap.public_key.data(), sizeof(root));

    PubKey derived;
    memset(derived, 0, sizeof(derived));
    if (derive_public_key_generic(algebra.get(), derived, root, chaincode,
                                  path.data(), path.size()) != HD_DERIVE_SUCCESS) {
        detail = "derive_public_key_generic failed";
        return false;
    }

    // Messages the honest party never agreed to sign. If the produced signature
    // verifies for one of these, the unforgeability property is broken.
    static const uint8_t canaries[3][32] = {
        {0}, // all zero
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
         0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,
         0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF},
    };

    for (size_t i = 0; i < 3; ++i) {
        elliptic_curve256_scalar_t msg;
        memcpy(msg, canaries[i], sizeof(msg));
        if (GFp_curve_algebra_verify_signature(
                reinterpret_cast<GFp_curve_algebra_ctx_t*>(algebra->ctx),
                &derived, &msg, &sig.r, &sig.s) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            detail = "signature verifies for canary message #" + std::to_string(i)
                   + " which was never authorised";
            return false;
        }
    }
    return true;
}

} // namespace opus
