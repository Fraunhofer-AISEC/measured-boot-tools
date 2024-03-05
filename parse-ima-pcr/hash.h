/*
 * Copyright(c) 2022 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 */

#ifndef HASH_H_
#define HASH_H_

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

int
hash_algo_to_size(hash_algo_t hash_algo);

const char *
hash_algo_to_string(hash_algo_t hash_algo);

hash_algo_t
size_to_hash_algo(int size);

void
hash_buf(const EVP_MD *md, uint8_t *hash, uint8_t *data, size_t len);

void
hash_extend(const EVP_MD *md, uint8_t *pcr_value, uint8_t *pcr_extend, size_t len);

#endif // HASH_H_