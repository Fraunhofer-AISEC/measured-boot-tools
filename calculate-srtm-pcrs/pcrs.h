/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

typedef struct {
    uint8_t *acpi_tables;
    ssize_t acpi_tables_size;
    uint8_t *acpi_rsdp;
    ssize_t acpi_rsdp_size;
    uint8_t *table_loader;
    ssize_t table_loader_size;
    uint8_t *tpm_log;
    ssize_t tpm_log_size;
} pcr1_config_files_t;

int
calculate_pcr0(uint8_t *pcr, eventlog_t *evlog, const char *ovmf_file, const char *dump_pei_path,
               const char *dump_dxe_path);

int
calculate_pcr1(uint8_t *pcr, eventlog_t *evlog, pcr1_config_files_t *cfg);

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
calculate_pcr7(uint8_t *pcr, eventlog_t *evlog, const char *sbat_level);

int
calculate_pcr8(uint8_t *pcr, eventlog_t *evlog, const char *grubcmds_file);

int
calculate_pcr9(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, size_t trailing_zeros,
               const char *initrd, char **paths, size_t num_paths);