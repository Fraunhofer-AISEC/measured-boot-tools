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

#ifndef MODSIG_H_
#define MODSIG_H_

typedef struct {
    size_t key_id_len;
    uint8_t *key_id;
    size_t sig_len;
    uint8_t *sig;
    char *signer;
    const char *hash_algo;
    const char *sig_algo;
} sig_info_t;

sig_info_t *
modsig_parse_new(const char *pkcs7_raw, size_t len);

void
modsig_free(sig_info_t *s);

#endif // MODSIG_H_