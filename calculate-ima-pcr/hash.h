/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef HASH_H_
#define HASH_H_

#include <openssl/evp.h>

#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32

void
sha256(uint8_t *hash, uint8_t *data, size_t len);

void
hash_buf(const EVP_MD *md, uint8_t *hash, uint8_t *data, size_t len);

int
hash_file(const EVP_MD *md, uint8_t *file_hash, const char *filename);

void
sha256_extend(uint8_t *pcr_value, uint8_t *pcr_extend);

void
hash_extend(const EVP_MD *md, uint8_t *pcr_value, uint8_t *pcr_extend, size_t len);

#endif // HASH_H_