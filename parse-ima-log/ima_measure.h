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

#ifndef IMA_VERIFY_H_
#define IMA_VERIFY_H_

int
ima_verify_binary_runtime_measurements(uint8_t *buf, size_t size, const char *cert,
                                       hash_algo_t template_hash_algo, uint8_t *pcr_tpm);

char *
ima_create_json_list_new(uint8_t *buf, size_t size);

int
ima_parse_binary_runtime_measurements(uint8_t *buf, size_t size);

#endif // IMA_VERIFY_H_