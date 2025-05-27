/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

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

#include "common.h"
#include "efi_boot.h"

// TODO
#define MEDIA_PROTOCOL_TYPE 4
#define PIWG_FIRMWARE_FILE_SUBTYPE 6
#define PIWG_FIRMWARE_VOLUME_SUBTYPE 7
#define END_OF_PATH_TYPE 0x7F

#define LOAD_OPTION_ACTIVE (1 << 0)
#define LOAD_OPTION_HIDDEN (1 << 3)
#define LOAD_OPTION_CATEGORY_APP (1 << 8)

#define FV_NAME_GUID                                                                               \
    {                                                                                              \
        0x7cb8bdc9, 0xf8eb, 0x4f34,                                                                \
        {                                                                                          \
            0xaa, 0xea, 0x3e, 0xe4, 0xaf, 0x65, 0x16, 0xa1                                         \
        }                                                                                          \
    }

#define FILE_GUID                                                                                  \
    {                                                                                              \
        0x462caa21, 0x7614, 0x4503,                                                                \
        {                                                                                          \
            0x83, 0x6e, 0x8a, 0xb6, 0xf4, 0x66, 0x23, 0x31                                         \
        }                                                                                          \
    }

EFI_GUID gFvNameGuid = FV_NAME_GUID;

EFI_GUID gFileGuid = FILE_GUID;

int
create_node(uint8_t *dest, size_t destlen, uint8_t type, uint8_t subtype, uint8_t *data,
            size_t datalen)
{
    uint16_t len = datalen + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);

    if (destlen < len) {
        printf("input buffer too small\n");
        return -1;
    }

    dest[0] = type;
    dest[1] = subtype;
    memcpy(dest + sizeof(uint8_t) + sizeof(uint8_t), &len, sizeof(uint16_t));
    if (data) {
        memcpy(dest + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t), data, datalen);
    }

    return 0;
}

int
create_file_path_list(uint8_t *dest, size_t destlen)
{
    if (destlen < 44) {
        printf("input buffer too small\n");
        return -1;
    }

    // UEFI Platform Initialization Specification, Version 1.8 Errata A, II-8.2
    // Firmware Volume Media Device Path: PIWG Firmware Volume Device Path node
    uint8_t piwg_fv[20] = { 0x0 };
    if (create_node(piwg_fv, sizeof(piwg_fv), MEDIA_PROTOCOL_TYPE, PIWG_FIRMWARE_VOLUME_SUBTYPE,
                    (uint8_t *)&gFvNameGuid, sizeof(EFI_GUID)) != 0) {
        printf("failed to create PIWG Firmware Volume Device Path node\n");
        return -1;
    }

    // UEFI Platform Initialization Specification, Version 1.8 Errata A, II-8.3
    // Firmware File Media Device Path: PIWG Firmware File Device Path node
    uint8_t piwg_fw_file[20] = { 0x0 };
    if (create_node(piwg_fw_file, sizeof(piwg_fw_file), MEDIA_PROTOCOL_TYPE,
                    PIWG_FIRMWARE_FILE_SUBTYPE, (uint8_t *)&gFileGuid, sizeof(EFI_GUID)) != 0) {
        printf("failed to create PIWG Firmware File Device Path node\n");
        return -1;
    }

    // UEFI Specification, Release 2.10 Errata A, 10.3.1 Generic Device Path Structures,
    // Table 10.2: Device Path End Structure: End Entire Device Path node
    uint8_t end_of_path[4] = { 0x0 };
    if (create_node(end_of_path, sizeof(end_of_path), END_OF_PATH_TYPE, 0xff, NULL, 0) != 0) {
        printf("failed to create end of path node\n");
        return -1;
    }

    memcpy(dest, piwg_fv, sizeof(piwg_fv));
    memcpy(dest + sizeof(piwg_fv), piwg_fw_file, sizeof(piwg_fw_file));
    memcpy(dest + sizeof(piwg_fv) + sizeof(piwg_fw_file), end_of_path, sizeof(end_of_path));

    return 0;
}

/**
 * UEFI Specification, Release 2.10 Errata A, 3.1.3 Load Options: EFI_LOAD_OPTION
 */
uint8_t *
calculate_efi_load_option(size_t *out_len)
{
    uint32_t attributes = LOAD_OPTION_ACTIVE | LOAD_OPTION_HIDDEN | LOAD_OPTION_CATEGORY_APP;
    const char16_t *description = u"UiApp\0";
    size_t description_size = (char16_strlen(description) + 1) * sizeof(char16_t);
    uint8_t *optional_data = NULL;
    size_t optional_data_len = 0;

    uint8_t file_path_list[44];
    uint16_t file_path_list_len = (uint16_t)sizeof(file_path_list);
    int ret = create_file_path_list(file_path_list, sizeof(file_path_list));
    if (ret) {
        printf("failed to create file path list\n");
        return NULL;
    }

    //           attribtues +       len filepathlist + description +      file_path_list +         optional data
    size_t len = sizeof(uint32_t) + sizeof(uint16_t) + description_size + sizeof(file_path_list) +
                 optional_data_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) {
        printf("Failed to allocate memory\n");
        return NULL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &attributes, sizeof(uint32_t));
    offset = sizeof(uint32_t);
    memcpy(buf + offset, &file_path_list_len, sizeof(uint16_t));
    offset = sizeof(uint32_t) + sizeof(uint16_t);
    memcpy(buf + offset, description, description_size);
    offset = sizeof(uint32_t) + sizeof(uint16_t) + description_size;
    memcpy(buf + offset, file_path_list, sizeof(file_path_list));
    if (optional_data) {
        offset = sizeof(uint32_t) + sizeof(uint16_t) + description_size + sizeof(file_path_list);
        memcpy(buf + offset, optional_data, optional_data_len);
    }

    *out_len = len;

    return buf;
}
