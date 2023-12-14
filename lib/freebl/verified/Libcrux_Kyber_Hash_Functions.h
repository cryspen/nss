#ifndef __Libcrux_Kyber_Hash_Functions_H
#define __Libcrux_Kyber_Hash_Functions_H

#include "Hacl_Hash_SHA3.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_SHA3_Simd256.h"
#endif

typedef struct
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__s
{
  uint8_t fst[840U];
  uint8_t snd[840U];
  uint8_t thd[840U];
  uint8_t f3[840U];
} __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_;

bool libcrux_platform_simd256_support(void) {
    // TODO(goutam): Replace this with HACL platform support.
    return false;
}

static inline void
libcrux_digest_shake256(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_SHA3_shake256_hacl(input.len, input.ptr, (uint32_t)len, out);
}

static inline void
libcrux_digest_shake128(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_SHA3_shake128_hacl(input.len, input.ptr, (uint32_t)len, out);
}

static inline __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4(size_t len,
                          Eurydice_slice input0,
                          Eurydice_slice input1,
                          Eurydice_slice input2,
                          Eurydice_slice input3)
{
#ifdef HACL_CAN_COMPILE_VEC256
// TODO(goutam): Make this work
  Hacl_Hash_SHA3_Simd256_shake128(input0.len,
                                  input0.ptr,
                                  input1.ptr,
                                  input2.ptr,
                                  input3.ptr,
                                  (uint32_t)len,
                                  out);
#else
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
    out =
      (__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_)
  {
    .fst = { 0 }, .snd = { 0 }, .thd = { 0 }, .f3 = { 0 }
  };
  Hacl_SHA3_shake128_hacl(
    input0.len, input0.ptr, (uint32_t)len, out.fst);
  Hacl_SHA3_shake128_hacl(
    input1.len, input1.ptr, (uint32_t)len, out.snd);
  Hacl_SHA3_shake128_hacl(
    input2.len, input2.ptr, (uint32_t)len, out.thd);
  Hacl_SHA3_shake128_hacl(input3.len, input3.ptr, (uint32_t)len, out.f3);
  return out;
#endif
}

static inline void
libcrux_digest_sha3_512(Eurydice_slice x0, uint8_t x1[64U])
{
  Hacl_SHA3_sha3_512((uint32_t)x0.len, x0.ptr, x1);
}

static inline void
libcrux_digest_sha3_256(Eurydice_slice x0, uint8_t x1[32U])
{
  Hacl_SHA3_sha3_256((uint32_t)x0.len, x0.ptr, x1);
}

#endif //__Libcrux_Kyber_Hash_Functions_H
