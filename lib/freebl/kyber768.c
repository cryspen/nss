/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/
 *
 * Based on the CC0-licensed reference implementation from
 *
 * https://github.com/pq-crystals/kyber/commit/1ee0baa2100a545ac852edea2e4441b8f742814d
 */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapi.h"
#include "secerr.h"

#include "Libcrux_Kyber_768.h"

#include "kyber-params.h"
PR_STATIC_ASSERT(KYBER768_PUBLIC_KEY_BYTES == PUBLIC_KEY_BYTES);
PR_STATIC_ASSERT(KYBER768_PRIVATE_KEY_BYTES == PRIVATE_KEY_BYTES);
PR_STATIC_ASSERT(KYBER768_CIPHERTEXT_BYTES == CIPHERTEXT_BYTES);
PR_STATIC_ASSERT(KYBER768_SHARED_SECRET_BYTES == SHARED_SECRET_BYTES);

/* This function is not static because it is needed for KAT testing
 * in the FreeBL gtest.
 */
void
kyber768_new_key_from_seed(uint8_t pk[KYBER768_PUBLIC_KEY_BYTES], uint8_t sk[KYBER768_PRIVATE_KEY_BYTES], const uint8_t seed[KEY_GENERATION_SEED_BYTES])
{
    Libcrux_Kyber_768_GenerateKeyPair(pk, sk, seed);
}

SECStatus
Kyber768_NewKey(uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES],
                uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES])
{
    uint8_t seed[KEY_GENERATION_SEED_BYTES];

    SECStatus rv = RNG_GenerateGlobalRandomBytes(seed, sizeof(seed));
    if (rv != SECSuccess) {
        return SECFailure;
    }

    kyber768_new_key_from_seed(publicKey, privateKey, seed);
    return SECSuccess;
}

/* This function is not static because it is needed for KAT testing
 * in the FreeBL gtest.
 */
void
kyber768_encapsulate_from_seed(uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES],
                               uint8_t ss[KYBER768_SHARED_SECRET_BYTES],
                               const uint8_t pk[KYBER768_PUBLIC_KEY_BYTES],
                               const uint8_t seed[KYBER768_SHARED_SECRET_BYTES])
{
    Libcrux_Kyber_768_Encapsulate(ciphertext, ss, pk, seed);
}

SECStatus
Kyber768_Encapsulate(uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES],
                     uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES],
                     const uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES])
{
    uint8_t seed[KYBER768_SHARED_SECRET_BYTES];

    SECStatus rv = RNG_GenerateGlobalRandomBytes(seed, sizeof(seed));
    if (rv != SECSuccess) {
        return SECFailure;
    }

    kyber768_encapsulate_from_seed(ciphertext, sharedSecret, publicKey, seed);

    return SECSuccess;
}

SECStatus
Kyber768_Decapsulate(uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES],
                     const uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES],
                     const uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES])
{
    Libcrux_Kyber_768_Decapsulate(sharedSecret, ciphertext, privateKey);
    return SECSuccess;
}
