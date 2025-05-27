/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "string.h"

#include "GlobalVariable.h"
#include "ImageAuthentication.h"
#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "UefiTcgPlatform.h"

#include "common.h"
#include "hash.h"
#include "eventlog.h"
#include "secureboot.h"

EFI_GUID gEfiGlobalVariableGuid = EFI_GLOBAL_VARIABLE;

EFI_GUID gEfiImageSecurityDatabaseGuid = EFI_IMAGE_SECURITY_DATABASE_GUID;

static UEFI_VARIABLE_DATA *
create_uefi_variable(variable_type_t var_type, size_t *size)
{
    size_t name_len = char16_strlen(var_type.variable_name);
    size_t name_size = name_len * sizeof(char16_t);

    uint8_t *tmpbuf = NULL;
    uint8_t *var_data = NULL;
    size_t var_data_size = 0;
    if (var_type.path) {
        // Variable file was given
        int ret = read_file(&tmpbuf, &var_data_size, var_type.path);
        if (ret) {
            printf("failed to read file %s\n", var_type.path);
            return NULL;
        }
        // Variable data starts at index 4
        var_data = tmpbuf + 4;
        var_data_size -= 4;
    } else if (var_type.data) {
        // Variable data was given
        var_data = var_type.data;
        var_data_size = var_type.data_size;
    } // Else empty variable data

    // Calculate total required memory for UEFI variable: EFI_GUID + unicode name length + variable data length
    *size = sizeof(EFI_GUID) + sizeof(UINT64) + sizeof(UINT64) + name_size + var_data_size;

    // Allocate memory
    UEFI_VARIABLE_DATA *variable = (UEFI_VARIABLE_DATA *)malloc(*size);
    if (!variable) {
        printf("Memory allocation failed for UEFI variable\n");
        goto out;
    }

    // Initialize structure
    variable->VariableName = *var_type.vendor_guid;
    variable->UnicodeNameLength = name_len;
    variable->VariableDataLength = var_data_size;
    memcpy(variable->UnicodeName, var_type.variable_name, name_size);
    if (var_data) {
        memcpy(variable->UnicodeName + name_len, var_data, var_data_size);
    }

out:
    if (tmpbuf) {
        free(tmpbuf);
    }

    return variable;
}

int
measure_variable(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                 variable_type_t var_type)
{
    size_t name_length = char16_strlen(var_type.variable_name);
    char name_narrow[name_length + 1];
    memset(name_narrow, 0x0, sizeof(name_narrow));
    for (size_t j = 0; j < name_length; j++) {
        name_narrow[j] = var_type.variable_name[j] & 0xFF;
    }

    size_t data_size;
    UEFI_VARIABLE_DATA *data = create_uefi_variable(var_type, &data_size);
    if (!data) {
        printf("Failed to calculate UEFI secure boot variable %s\n", name_narrow);
        return -1;
    }

    print_data_debug((uint8_t *)data, data_size, name_narrow);

    uint8_t hash[EVP_MD_size(md)];
    hash_buf(md, hash, (uint8_t *)data, data_size);

    evlog_add(evlog, mr_index, var_type.event_type, hash, name_narrow);

    hash_extend(md, mr, hash, EVP_MD_size(md));

    free(data);

    return 0;
}

int
measure_secure_boot_variables(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                              const char *secure_boot, const char *pk, const char *kek,
                              const char *db, const char *dbx)
{
    variable_type_t vars[] = {
        { "EV_EFI_VARIABLE_DRIVER_CONFIG", EFI_SECURE_BOOT_MODE_NAME,    &gEfiGlobalVariableGuid,        secure_boot, NULL, 0 },
        { "EV_EFI_VARIABLE_DRIVER_CONFIG", EFI_PLATFORM_KEY_NAME,        &gEfiGlobalVariableGuid,        pk,          NULL, 0 },
        { "EV_EFI_VARIABLE_DRIVER_CONFIG", EFI_KEY_EXCHANGE_KEY_NAME,    &gEfiGlobalVariableGuid,        kek,         NULL, 0 },
        { "EV_EFI_VARIABLE_DRIVER_CONFIG", EFI_IMAGE_SECURITY_DATABASE,  &gEfiImageSecurityDatabaseGuid, db,          NULL, 0 },
        { "EV_EFI_VARIABLE_DRIVER_CONFIG", EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid, dbx,         NULL, 0 },
    };

    for (size_t i = 0; i < ARRAY_LEN(vars); i++) {
        int ret = measure_variable(md, mr, mr_index, evlog, vars[i]);
        if (ret) {
            printf("Failed to measure variable\n");
            return -1;
        }
    }

    return 0;
}