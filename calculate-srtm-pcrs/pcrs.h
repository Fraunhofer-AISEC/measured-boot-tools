/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "acpi.h"

int
calculate_pcr0(uint8_t *pcr, eventlog_t *evlog, const char *ovmf_file, const char *dump_pei_path,
               const char *dump_dxe_path);

int
calculate_pcr1(uint8_t *pcr, eventlog_t *evlog, acpi_files_t *cfg, uint16_t *boot_order,
               size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx);

int
calculate_pcr2(uint8_t *pcr, eventlog_t *evlog, char **drivers, size_t num_drivers);

int
calculate_pcr3(uint8_t *pcr, eventlog_t *evlog);

int
calculate_pcr4(uint8_t *pcr, eventlog_t *evlog, const char *kernel_file, const char *config_file,
               const char **bootloader_files, size_t num_bootloader_files);

int
calculate_pcr5(uint8_t *pcr, eventlog_t *evlog, const char *efi_partition_table);

int
calculate_pcr6(uint8_t *pcr, eventlog_t *evlog);

int
calculate_pcr7(uint8_t *pcr, eventlog_t *evlog, const char *sbat_level, const char *secure_boot,
               const char *pk, const char *kek, const char *db, const char *dbx);

int
calculate_pcr8(uint8_t *pcr, eventlog_t *evlog, const char *grubcmds_file);

int
calculate_pcr9(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, size_t trailing_zeros, bool strip_newline,
               const char *initrd, char **paths, size_t num_paths, bool qemu);