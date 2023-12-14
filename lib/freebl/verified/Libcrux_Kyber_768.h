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

#define KYBER768_KEY_GENERATION_SEED_SIZE 64
#define KYBER768_ENCAPSULATION_SEED_SIZE 32

void
Libcrux_Kyber_768_GenerateKeyPair(uint8_t* pk,
                                 uint8_t* sk,
                                 const uint8_t randomness[KYBER768_KEY_GENERATION_SEED_SIZE])
{
  libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t result =
    libcrux_kyber_kyber768_generate_key_pair_768((uint8_t*)randomness);

  memcpy(pk, result.pk, 1184);
  memcpy(sk, result.sk, 2400);
}

void
Libcrux_Kyber_768_Encapsulate(uint8_t* ct,
                             uint8_t ss[32],
                             const uint8_t *pk,
                             const uint8_t randomness[32])
{
  K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t_
    result = libcrux_kyber_kyber768_encapsulate_768((uint8_t (*)[1184])pk, (uint8_t*)randomness);
  memcpy(ct, result.fst, 1088);
  memcpy(ss, result.snd, 32);
}

void
Libcrux_Kyber_768_Decapsulate(uint8_t ss[32],
                              const uint8_t *ct,
                              const uint8_t *sk)
{
  libcrux_kyber_kyber768_decapsulate_768((uint8_t (*)[2400])sk, (uint8_t (*)[1088])ct, ss);
}

#endif
