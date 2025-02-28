/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include "hash.h"

#define FILE_CHUNK 1024

void
hash_buf(const EVP_MD *md, uint8_t *hash, uint8_t *data, size_t len)
{
    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

void
hash_extend(const EVP_MD *md, uint8_t *pcr_value, uint8_t *pcr_extend, size_t len)
{
    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, pcr_value, len);
    EVP_DigestUpdate(ctx, pcr_extend, len);
    EVP_DigestFinal_ex(ctx, pcr_value, NULL);
    EVP_MD_CTX_free(ctx);
}

int
hash_file(const EVP_MD *md, uint8_t *file_hash, const char *filename)
{
    size_t bytes;
    uint8_t *data[FILE_CHUNK];
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Error: Failed to open %s\n", filename);
        return -1;
    }

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    while ((bytes = fread(data, 1, FILE_CHUNK, f)) != 0) {
        EVP_DigestUpdate(ctx, data, bytes);
    }
    EVP_DigestFinal_ex(ctx, file_hash, NULL);
    EVP_MD_CTX_free(ctx);

    fclose(f);
    return 0;
}

void
sha256(uint8_t *hash, uint8_t *data, size_t len)
{
    hash_buf(EVP_sha256(), hash, data, len);
}

void
sha384(uint8_t *hash, uint8_t *data, size_t len)
{
    hash_buf(EVP_sha384(), hash, data, len);
}

void
sha256_extend(uint8_t *pcr_value, uint8_t *pcr_extend)
{
    hash_extend(EVP_sha256(), pcr_value, pcr_extend, SHA256_DIGEST_LENGTH);
}

void
sha384_extend(uint8_t *pcr_value, uint8_t *pcr_extend)
{
    hash_extend(EVP_sha384(), pcr_value, pcr_extend, SHA384_DIGEST_LENGTH);
}