/* MIT License
 *
 * Copyright (c) 2023 Cryspen SARL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __Libcrux_Kyber_768_H
#define __Libcrux_Kyber_768_H

#include <string.h>

#include "internal/Libcrux_Kyber_768.h"

#define PUBLIC_KEY_BYTES libcrux_kyber_kyber768_CPA_PKE_PUBLIC_KEY_SIZE_768
#define PRIVATE_KEY_BYTES libcrux_kyber_kyber768_SECRET_KEY_SIZE_768
#define KEY_GENERATION_SEED_BYTES libcrux_kyber_KEY_GENERATION_SEED_SIZE
#define ENCAPSULATION_SEED_BYTES libcrux_kyber_constants_SHARED_SECRET_SIZE
#define CIPHERTEXT_BYTES libcrux_kyber_kyber768_CPA_PKE_CIPHERTEXT_SIZE_768
#define SHARED_SECRET_BYTES libcrux_kyber_constants_SHARED_SECRET_SIZE

void
Libcrux_Kyber_768_GenerateKeyPair(uint8_t publicKey[PUBLIC_KEY_BYTES],
                                  uint8_t privateKey[PRIVATE_KEY_BYTES],
                                  const uint8_t randomness[KEY_GENERATION_SEED_BYTES])
{
    libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t result =
        libcrux_kyber_kyber768_generate_key_pair_768((uint8_t*)randomness);

    memcpy(publicKey, result.pk, PUBLIC_KEY_BYTES);
    memcpy(privateKey, result.sk, PRIVATE_KEY_BYTES);
}

void
Libcrux_Kyber_768_Encapsulate(uint8_t ciphertext[CIPHERTEXT_BYTES],
                              uint8_t sharedSecret[SHARED_SECRET_BYTES],
                              const uint8_t publicKey[PUBLIC_KEY_BYTES],
                              const uint8_t randomness[SHARED_SECRET_BYTES])
{
    K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t_
        result = libcrux_kyber_kyber768_encapsulate_768((uint8_t(*)[PUBLIC_KEY_BYTES])publicKey, (uint8_t*)randomness);
    memcpy(ciphertext, result.fst, CIPHERTEXT_BYTES);
    memcpy(sharedSecret, result.snd, SHARED_SECRET_BYTES);
}

void
Libcrux_Kyber_768_Decapsulate(uint8_t sharedSecret[SHARED_SECRET_BYTES],
                              const uint8_t ciphertext[CIPHERTEXT_BYTES],
                              const uint8_t privateKey[PRIVATE_KEY_BYTES])
{
    libcrux_kyber_kyber768_decapsulate_768((uint8_t(*)[PRIVATE_KEY_BYTES])privateKey, (uint8_t(*)[CIPHERTEXT_BYTES])ciphertext, sharedSecret);
}

#endif
