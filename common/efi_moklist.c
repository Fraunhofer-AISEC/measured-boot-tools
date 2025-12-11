/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "PiHob.h"
#include "MeasureBootPeCoff.h"
#include "SecMain.h"
#include "ImageAuthentication.h"
#include "UefiTcgPlatform.h"
#include "GlobalVariable.h"

#include "hash.h"
#include "common.h"
#include "efi_boot.h"
#include "eventlog.h"

EFI_GUID gEfiImageSecurityDatabase1VariableGuid = EFI_IMAGE_SECURITY_DATABASE1_SBATLEVEL_GUID;

int
calculate_efi_moklist_vars(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                        char **moklists, size_t num_moklists)
{
    int ret = -1;

    for (size_t i = 0; i < num_moklists; i++) {
        uint8_t *file_buf = NULL;
        size_t file_size = 0;
        uint8_t hash_efi_variable_moklist[EVP_MD_size(md)];

        // Read file with binary efi variable data. Variable data can either be with a
        // full UEFI_VARIABLE_DATA header or with a 4-byte efi variable attributes header
        // as written to /sys/firmware/efi/efivars
        ret = read_file(&file_buf, &file_size, moklists[i]);
        if (ret) {
            printf("failed to read file %s\n", moklists[i]);
            return -1;
        }

        // Data in the format as written to /sys/firmware/efi/efivars has a 4-byte
        // efi variable attributes header
        size_t offset = 4;

        // Check if variable begins with UEFI_VARIABLE_DATA header, which is not extended
        if (file_size > sizeof(UEFI_VARIABLE_DATA)) {
            UEFI_VARIABLE_DATA *var_data = (UEFI_VARIABLE_DATA *)file_buf;

            // Check if VariableName is the EFI global variable GUID
            if (memcmp(&var_data->VariableName, &gEfiImageSecurityDatabase1VariableGuid, sizeof(EFI_GUID)) == 0) {
                // If so, deliver the offset where VariableData starts, which is extended
                offset = sizeof(EFI_GUID) +
                    sizeof(var_data->UnicodeNameLength) +
                    sizeof(var_data->VariableDataLength) +
                    var_data->UnicodeNameLength * sizeof(CHAR16);

                DEBUG("VariableData offset: %zu (0x%zx)\n", offset, offset);
            }
        }

        print_data_debug(file_buf + offset, file_size - offset, "MokList");
        hash_buf(md, hash_efi_variable_moklist, file_buf + offset, file_size - offset);
        evlog_add(evlog, mr_index, "EV_IPL", hash_efi_variable_moklist,
                    "VariableName - MokList, VendorGuid - 605dab50-e046-4300-abb6-3dd810dd8b23");
        hash_extend(md, mr, hash_efi_variable_moklist, EVP_MD_size(md));
        free(file_buf);
    }

    ret = 0;
    return ret;
}
