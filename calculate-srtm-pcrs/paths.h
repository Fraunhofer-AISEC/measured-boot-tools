/* SPDX-License-Identifier: BSD-2-Clause-Patent */

int
calculate_paths(uint8_t *pcr, eventlog_t *evlog, char **paths, size_t num_paths);

char16_t *
convert_to_char16(const char *in, size_t *out_len);