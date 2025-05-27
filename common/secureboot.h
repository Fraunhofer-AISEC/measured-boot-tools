/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

typedef struct {
    char *event_type;
    CHAR16 *variable_name;
    EFI_GUID *vendor_guid;
    const char *path;
    uint8_t *data;
    size_t data_size;
} variable_type_t;

int
measure_variable(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                 variable_type_t var_type);

int
measure_secure_boot_variables(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                              const char *secure_boot, const char *pk, const char *kek,
                              const char *db, const char *dbx);