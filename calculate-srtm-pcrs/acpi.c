/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/sha.h>

#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "pcrs.h"

int
calculate_acpi_tables(uint8_t *pcr, eventlog_t *evlog, pcr1_config_files_t *cfg)
{
    // EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
    if (cfg->table_loader_size > 0) {
        uint8_t hash_table_loader[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_table_loader, cfg->table_loader, cfg->table_loader_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_table_loader, "etc/table-loader");
        hash_extend(EVP_sha256(), pcr, hash_table_loader, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
    if (cfg->acpi_rsdp_size > 0) {
        uint8_t hash_acpi_rsdp[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_acpi_rsdp, cfg->acpi_rsdp, cfg->acpi_rsdp_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_rsdp, "etc/acpi/rsdp");
        hash_extend(EVP_sha256(), pcr, hash_acpi_rsdp, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/tpm/log
    if (cfg->tpm_log_size > 0) {
        uint8_t hash_tpm_log[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_tpm_log, cfg->tpm_log, cfg->tpm_log_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_tpm_log, "etc/tpm/log");
        hash_extend(EVP_sha256(), pcr, hash_tpm_log, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
    if (cfg->acpi_tables_size > 0) {
        uint8_t hash_acpi_tables[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_acpi_tables, cfg->acpi_tables, cfg->acpi_tables_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_tables, "etc/acpi/tables");
        hash_extend(EVP_sha256(), pcr, hash_acpi_tables, SHA256_DIGEST_LENGTH);
    }

    return 0;
}