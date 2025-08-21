/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "acpi.h"

int
calculate_mrseam(uint8_t *mr, eventlog_t *evlog, const char *tdx_module, const char *mrseam);

int
calculate_mrtd(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file, const char *mrtd, const char *qemu_version);

int
calculate_rtmr0(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file,
                acpi_files_t *cfg, const char *ovmf_version,
                uint16_t *boot_order, size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx,
                const char *secure_boot, const char *pk, const char *kek, const char *db, const char *dbx);

int
calculate_rtmr1(uint8_t *mr, eventlog_t *evlog, const char *kernel_file, const char *config_file,
                const char *dump_kernel_path, const char *ovmf_version);

int
calculate_rtmr2(uint8_t *mr, eventlog_t *evlog, const char *cmdline_file, size_t trailing_zeros);

int
calculate_rtmr3(uint8_t *mr, eventlog_t *evlog);