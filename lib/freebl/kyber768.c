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

#define KYBER_K 3
#include "kyber.h"

#include "kyber-params.h"
PR_STATIC_ASSERT(KYBER768_PUBLIC_KEY_BYTES == KYBER_PUBLICKEYBYTES);
PR_STATIC_ASSERT(KYBER768_PRIVATE_KEY_BYTES == KYBER_SECRETKEYBYTES);
PR_STATIC_ASSERT(KYBER768_CIPHERTEXT_BYTES == KYBER_CIPHERTEXTBYTES);
PR_STATIC_ASSERT(KYBER768_SHARED_SECRET_BYTES == KYBER_SSBYTES);

/* This function is not static because it is needed for KAT testing
 * in the FreeBL gtest.
 */
void
kyber768_new_key_from_seed(uint8_t pk[KYBER768_PUBLIC_KEY_BYTES], uint8_t sk[KYBER768_PRIVATE_KEY_BYTES], const uint8_t seed[KYBER_GENERATE_KEY_BYTES])
{
    size_t i;

    indcpa_keypair(pk, sk, seed);
    for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
        sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
    hash_h(sk + KYBER768_PRIVATE_KEY_BYTES - 2 * KYBER_SYMBYTES, pk, KYBER768_PUBLIC_KEY_BYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + KYBER768_PRIVATE_KEY_BYTES - KYBER_SYMBYTES, seed + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

SECStatus
Kyber768_NewKey(uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES],
                uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES])
{
    uint8_t seed[KYBER_GENERATE_KEY_BYTES];

    SECStatus rv = RNG_GenerateGlobalRandomBytes(seed, KYBER_GENERATE_KEY_BYTES);
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
kyber768_encapsulate_from_seed(uint8_t out_ciphertext[KYBER768_CIPHERTEXT_BYTES],
                               uint8_t ss[KYBER768_SHARED_SECRET_BYTES],
                               const uint8_t pk[KYBER768_PUBLIC_KEY_BYTES],
                               const uint8_t seed[KYBER_ENCAP_BYTES])
{
    uint8_t *ct = out_ciphertext;

    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, seed, KYBER_SYMBYTES);
    /* Don't release system RNG output */
    hash_h(buf, buf, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + KYBER_SYMBYTES, pk, KYBER768_PUBLIC_KEY_BYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, ct, KYBER768_CIPHERTEXT_BYTES);
    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2 * KYBER_SYMBYTES);
}

SECStatus
Kyber768_Encapsulate(uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES],
                     uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES],
                     const uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES])
{
    uint8_t seed[KYBER_ENCAP_BYTES];

    SECStatus rv = RNG_GenerateGlobalRandomBytes(seed, KYBER_ENCAP_BYTES);
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
    size_t i;
    int fail = 1;
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER768_CIPHERTEXT_BYTES];
    const uint8_t *publicKey = privateKey + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ciphertext, privateKey);

    /* Multitarget countermeasure for coins + contributory KEM */
    for (i = 0; i < KYBER_SYMBYTES; i++)
        buf[KYBER_SYMBYTES + i] = privateKey[KYBER768_PRIVATE_KEY_BYTES - 2 * KYBER_SYMBYTES + i];
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, publicKey, kr + KYBER_SYMBYTES);

    fail = NSS_SecureMemcmp(ciphertext, cmp, KYBER768_CIPHERTEXT_BYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, ciphertext, KYBER768_CIPHERTEXT_BYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, privateKey + KYBER768_PRIVATE_KEY_BYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    kdf(sharedSecret, kr, 2 * KYBER_SYMBYTES);

    return SECSuccess;
}
