/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "eventlog.h"

typedef struct {
    uint8_t *acpi_tables;
    ssize_t acpi_tables_size;
    uint8_t *acpi_rsdp;
    ssize_t acpi_rsdp_size;
    uint8_t *table_loader;
    ssize_t table_loader_size;
    uint8_t *tpm_log;
    ssize_t tpm_log_size;
} acpi_files_t;

int
calculate_acpi_tables(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog, acpi_files_t *cfg);