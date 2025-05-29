/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "acpi.h"

int
calculate_acpi_tables(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog, acpi_files_t *cfg)
{
    // EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
    if (cfg->table_loader && (cfg->table_loader_size > 0)) {
        uint8_t hash_table_loader[EVP_MD_size(md)];
        hash_buf(md, hash_table_loader, cfg->table_loader, cfg->table_loader_size);
        evlog_add(evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", hash_table_loader, "etc/table-loader");
        hash_extend(md, mr, hash_table_loader, EVP_MD_size(md));
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
    if (cfg->acpi_rsdp && (cfg->acpi_rsdp_size > 0)) {
        uint8_t hash_acpi_rsdp[EVP_MD_size(md)];
        hash_buf(md, hash_acpi_rsdp, cfg->acpi_rsdp, cfg->acpi_rsdp_size);
        evlog_add(evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_rsdp, "etc/acpi/rsdp");
        hash_extend(md, mr, hash_acpi_rsdp, EVP_MD_size(md));
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/tpm/log
    if (cfg->tpm_log && (cfg->tpm_log_size > 0)) {
        uint8_t hash_tpm_log[EVP_MD_size(md)];
        hash_buf(md, hash_tpm_log, cfg->tpm_log, cfg->tpm_log_size);
        evlog_add(evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", hash_tpm_log, "etc/tpm/log");
        hash_extend(md, mr, hash_tpm_log, EVP_MD_size(md));
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
    if (cfg->acpi_tables && (cfg->acpi_tables_size > 0)) {
        uint8_t hash_acpi_tables[EVP_MD_size(md)];
        hash_buf(md, hash_acpi_tables, cfg->acpi_tables, cfg->acpi_tables_size);
        evlog_add(evlog, mr_index, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_tables, "etc/acpi/tables");
        hash_extend(md, mr, hash_acpi_tables, EVP_MD_size(md));
    }

    return 0;
}