#include "opus/det_rand.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <vector>

namespace opus {
namespace {

// SHA-512(key || counter) counter-mode expander. Same shape as the library's
// own drng (src/common/crypto/drng/drng.c) but owned by the harness so the
// instrument is independent of the code under test.
struct drbg_state {
    uint8_t  key[SHA512_DIGEST_LENGTH] = {0};
    uint64_t counter = 0;
    uint8_t  block[SHA512_DIGEST_LENGTH] = {0};
    size_t   block_used = SHA512_DIGEST_LENGTH; // force refill on first use
    uint64_t drawn = 0;
    bool     seeded = false;
};

drbg_state g_state;
bool g_installed = false;

void refill(drbg_state& st)
{
    uint8_t buf[SHA512_DIGEST_LENGTH + sizeof(uint64_t)];
    memcpy(buf, st.key, SHA512_DIGEST_LENGTH);
    // little-endian counter, fixed width: byte order must not depend on host
    for (size_t i = 0; i < sizeof(uint64_t); ++i)
        buf[SHA512_DIGEST_LENGTH + i] = static_cast<uint8_t>((st.counter >> (8 * i)) & 0xFF);

    SHA512(buf, sizeof(buf), st.block);
    ++st.counter;
    st.block_used = 0;
}

int det_bytes(unsigned char* out, int num)
{
    if (num < 0)
        return 0;
    if (!g_state.seeded)
        return 0; // fail closed: never hand back unseeded bytes

    size_t remaining = static_cast<size_t>(num);
    while (remaining > 0) {
        if (g_state.block_used >= SHA512_DIGEST_LENGTH)
            refill(g_state);
        const size_t take = std::min(remaining, SHA512_DIGEST_LENGTH - g_state.block_used);
        memcpy(out, g_state.block + g_state.block_used, take);
        g_state.block_used += take;
        out += take;
        remaining -= take;
        g_state.drawn += take;
    }
    return 1;
}

int det_seed(const void*, int)          { return 1; } // entropy additions ignored on purpose
int det_add(const void*, int, double)   { return 1; } // ditto -- determinism must not be perturbable
void det_cleanup(void)                  {}
int det_status(void)                    { return 1; }

RAND_METHOD g_method = {
    det_seed,
    det_bytes,
    det_cleanup,
    det_add,
    det_bytes,   // pseudorand -- same stream
    det_status
};

} // namespace

bool install_deterministic_rand()
{
    if (g_installed)
        return true;
    if (RAND_set_rand_method(&g_method) != 1)
        return false;
    g_installed = true;
    return true;
}

void reseed(uint64_t seed)
{
    uint8_t material[sizeof(uint64_t)];
    for (size_t i = 0; i < sizeof(uint64_t); ++i)
        material[i] = static_cast<uint8_t>((seed >> (8 * i)) & 0xFF);

    SHA512(material, sizeof(material), g_state.key);
    g_state.counter = 0;
    g_state.block_used = SHA512_DIGEST_LENGTH;
    g_state.drawn = 0;
    g_state.seeded = true;
}

void reseed_with_label(uint64_t seed, const std::string& label)
{
    std::vector<uint8_t> material;
    material.reserve(sizeof(uint64_t) + label.size());
    for (size_t i = 0; i < sizeof(uint64_t); ++i)
        material.push_back(static_cast<uint8_t>((seed >> (8 * i)) & 0xFF));
    material.insert(material.end(), label.begin(), label.end());

    SHA512(material.data(), material.size(), g_state.key);
    g_state.counter = 0;
    g_state.block_used = SHA512_DIGEST_LENGTH;
    g_state.drawn = 0;
    g_state.seeded = true;
}

uint64_t bytes_drawn() { return g_state.drawn; }

bool self_test()
{
    if (!install_deterministic_rand())
        return false;

    // 1. The method OpenSSL reports must be ours. If libcrypto were statically
    //    absorbed into libcosigner.so, the library would keep a second RNG that
    //    this check cannot see -- hence the driver ALSO cross-checks by running
    //    two identical signing rounds (see driver.cpp, rng_is_effective()).
    if (RAND_get_rand_method() != &g_method)
        return false;

    // 2. Same seed must give the same stream.
    uint8_t a[96] = {0}, b[96] = {0};
    reseed(0xA5A5A5A5u);
    if (RAND_bytes(a, sizeof(a)) != 1) return false;
    reseed(0xA5A5A5A5u);
    if (RAND_bytes(b, sizeof(b)) != 1) return false;
    if (memcmp(a, b, sizeof(a)) != 0) return false;

    // 3. A different seed must give a different stream (guards against a
    //    constant-output bug that would trivially satisfy check 2).
    uint8_t c[96] = {0};
    reseed(0x5A5A5A5Au);
    if (RAND_bytes(c, sizeof(c)) != 1) return false;
    if (memcmp(a, c, sizeof(a)) == 0) return false;

    // 4. Split draws must be stream-continuous, not block-aligned resets.
    uint8_t d[96] = {0};
    reseed(0xA5A5A5A5u);
    if (RAND_bytes(d, 33) != 1) return false;
    if (RAND_bytes(d + 33, 63) != 1) return false;
    if (memcmp(a, d, sizeof(a)) != 0) return false;

    return true;
}

} // namespace opus
