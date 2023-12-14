// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include "gtest/gtest.h"

#include "blapi.h"
#include "kat/kyber768_kat.h"

#define KYBER_SHARED_SECRET_SIZE 32

namespace nss_test {

extern "C" {
void kyber768_new_key_from_seed(
    uint8_t pk[KYBER768_PUBLIC_KEY_BYTES],
    uint8_t sk[KYBER768_PRIVATE_KEY_BYTES],
    const uint8_t seed[KYBER768_KEY_GENERATION_SEED_SIZE]);

void kyber768_encapsulate_from_seed(
    uint8_t out_ciphertext[KYBER768_CIPHERTEXT_BYTES],
    uint8_t ss[KYBER768_SHARED_SECRET_BYTES],
    const uint8_t pk[KYBER768_PUBLIC_KEY_BYTES],
    const uint8_t seed[KYBER768_SHARED_SECRET_BYTES]);
}

class Kyber768Test : public ::testing::Test {};

TEST(Kyber768Test, ConsistencyTest) {
  uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES];
  uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES];

  SECStatus rv = Kyber768_NewKey(publicKey, privateKey);
  EXPECT_EQ(SECSuccess, rv);

  uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Encapsulate(ciphertext, sharedSecret, publicKey);
  EXPECT_EQ(SECSuccess, rv);

  uint8_t sharedSecret2[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Decapsulate(sharedSecret2, privateKey, ciphertext);
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_EQ(0,
            memcmp(sharedSecret, sharedSecret2, KYBER768_SHARED_SECRET_BYTES));
}

TEST(Kyber768Test, InvalidCiphertextTest) {
  uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES];
  uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES];

  SECStatus rv = Kyber768_NewKey(publicKey, privateKey);
  EXPECT_EQ(SECSuccess, rv);

  uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Encapsulate(ciphertext, sharedSecret, publicKey);
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the ciphertext
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  ciphertext[pos % KYBER768_CIPHERTEXT_BYTES] ^= (byte | 1);

  uint8_t sharedSecret2[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Decapsulate(sharedSecret2, privateKey, ciphertext);
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_NE(0,
            memcmp(sharedSecret, sharedSecret2, KYBER768_SHARED_SECRET_BYTES));
}

TEST(Kyber768Test, InvalidPrivateKeyTest) {
  uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES];
  uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES];

  SECStatus rv = Kyber768_NewKey(publicKey, privateKey);
  EXPECT_EQ(SECSuccess, rv);

  uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Encapsulate(ciphertext, sharedSecret, publicKey);
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the private key
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  // Modifying the implicit rejection key will not cause decapsulation failure.
  privateKey[pos % (KYBER768_PRIVATE_KEY_BYTES - KYBER_SHARED_SECRET_SIZE)] ^=
      (byte | 1);

  uint8_t sharedSecret2[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Decapsulate(sharedSecret2, privateKey, ciphertext);
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_NE(0,
            memcmp(sharedSecret, sharedSecret2, KYBER768_SHARED_SECRET_BYTES));
}

TEST(Kyber768Test, DecapsulationWithModifiedRejectionKeyTest) {
  uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES];
  uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES];

  SECStatus rv = Kyber768_NewKey(publicKey, privateKey);
  EXPECT_EQ(SECSuccess, rv);

  uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Encapsulate(ciphertext, sharedSecret, publicKey);
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the ciphertext and decapsulate it
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  ciphertext[pos % KYBER768_CIPHERTEXT_BYTES] ^= (byte | 1);

  uint8_t sharedSecret2[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Decapsulate(sharedSecret2, privateKey, ciphertext);
  EXPECT_EQ(SECSuccess, rv);

  // Now, modify a random byte in the implicit rejection key and try
  // the decapsulation again. The result should be different.
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  pos = (KYBER768_PRIVATE_KEY_BYTES - KYBER_SHARED_SECRET_SIZE) +
        (pos % KYBER_SHARED_SECRET_SIZE);
  privateKey[pos] ^= (byte | 1);

  uint8_t sharedSecret3[KYBER768_SHARED_SECRET_BYTES];
  rv = Kyber768_Decapsulate(sharedSecret3, privateKey, ciphertext);
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_NE(0,
            memcmp(sharedSecret2, sharedSecret3, KYBER768_SHARED_SECRET_BYTES));
}

TEST(Kyber768Test, KnownAnswersTest) {
  uint8_t publicKey[KYBER768_PUBLIC_KEY_BYTES];
  uint8_t privateKey[KYBER768_PRIVATE_KEY_BYTES];
  uint8_t ciphertext[KYBER768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[KYBER768_SHARED_SECRET_BYTES];
  uint8_t sharedSecret2[KYBER768_SHARED_SECRET_BYTES];
  SECStatus rv;

  for (const auto& kat : Kyber768NISTKATs) {
    kyber768_new_key_from_seed(publicKey, privateKey, kat.newKeySeed);
    EXPECT_EQ(0, memcmp(publicKey, kat.publicKey, KYBER768_PUBLIC_KEY_BYTES));
    EXPECT_EQ(0,
              memcmp(privateKey, kat.privateKey, KYBER768_PRIVATE_KEY_BYTES));

    kyber768_encapsulate_from_seed(ciphertext, sharedSecret, publicKey,
                                   kat.encapsSeed);
    EXPECT_EQ(0, memcmp(ciphertext, kat.ciphertext, KYBER768_CIPHERTEXT_BYTES));
    EXPECT_EQ(0, memcmp(sharedSecret, kat.sharedSecret,
                        KYBER768_SHARED_SECRET_BYTES));

    rv = Kyber768_Decapsulate(sharedSecret2, privateKey, ciphertext);
    EXPECT_EQ(SECSuccess, rv);

    EXPECT_EQ(
        0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHARED_SECRET_BYTES));
  }
}

}  // namespace nss_test
