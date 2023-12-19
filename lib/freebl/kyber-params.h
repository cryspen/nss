/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/
 *
 * Based on the CC0-licensed reference implementation from
 *
 * https://github.com/pq-crystals/kyber/commit/1ee0baa2100a545ac852edea2e4441b8f742814d
 *
 * This file contains constant definitions for the Kyber function declarations in
 * blapi.h and their corresponding definitions in kyber768.c. Since these
 * (and only these) values are needed both in blapi.h and kyber768.c, they
 * have been moved into a separate header.
 */

#ifndef _KYBER_PARAMS_H
#define _KYBER_PARAMS_H

#define KYBER768_PUBLIC_KEY_BYTES 1184
#define KYBER768_PRIVATE_KEY_BYTES 2400
#define KYBER768_CIPHERTEXT_BYTES 1088
#define KYBER768_SHARED_SECRET_BYTES 32

#endif /* _KYBER_PARAMS_H */
