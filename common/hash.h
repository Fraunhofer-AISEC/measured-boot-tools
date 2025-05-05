/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef HASH_H_
#define HASH_H_

#include <openssl/evp.h>
#include <openssl/sha.h>

typedef enum {
    HASH_ALGO_MD4,
    HASH_ALGO_MD5,
    HASH_ALGO_SHA1,
    HASH_ALGO_RIPE_MD_160,
    HASH_ALGO_SHA256,
    HASH_ALGO_SHA384,
    HASH_ALGO_SHA512,
    HASH_ALGO_SHA224,
    HASH_ALGO_RIPE_MD_128,
    HASH_ALGO_RIPE_MD_256,
    HASH_ALGO_RIPE_MD_320,
    HASH_ALGO_WP_256,
    HASH_ALGO_WP_384,
    HASH_ALGO_WP_512,
    HASH_ALGO_TGR_128,
    HASH_ALGO_TGR_160,
    HASH_ALGO_TGR_192,
    HASH_ALGO_SM3_256,
    HASH_ALGO_STREEBOG_256,
    HASH_ALGO_STREEBOG_512,
    HASH_ALGO__LAST
} hash_algo_t;

void
hash_buf(const EVP_MD *md, uint8_t *hash, uint8_t *data, size_t len);

void
hash_extend(const EVP_MD *md, uint8_t *pcr_value, uint8_t *pcr_extend, size_t len);

int
hash_file(const EVP_MD *md, uint8_t *file_hash, const char *filename);

int
hash_and_dump(const EVP_MD *md, uint8_t *hash, uint8_t *data, size_t len, const char *dump_path);

void
sha256(uint8_t *hash, uint8_t *data, size_t len);

void
sha256_extend(uint8_t *pcr_value, uint8_t *pcr_extend);

void
sha384(uint8_t *hash, uint8_t *data, size_t len);

void
sha384_extend(uint8_t *pcr_value, uint8_t *pcr_extend);

#endif // HASH_H_