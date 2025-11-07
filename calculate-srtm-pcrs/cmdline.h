/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

int
calculate_cmdline(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, size_t trailing_zeros,
                            bool strip_newline, const char *initrd, bool qemu, int pcr_num,
                            const char *event_type);