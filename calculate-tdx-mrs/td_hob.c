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
#include "td_hob.h"

#define RESOURCE_DESCRIPTOR_LEN 9

size_t
get_td_hob_size()
{
    return sizeof(EFI_HOB_HANDOFF_INFO_TABLE) +
           sizeof(EFI_HOB_RESOURCE_DESCRIPTOR) * RESOURCE_DESCRIPTOR_LEN;
}

int
create_td_hob(uint8_t *dest, size_t dest_len)
{
    // Create TD handoff block
    size_t len = get_td_hob_size();
    if (dest_len < len) {
        printf("Failed to create TD HOB: provided buffer too small\n");
        return -1;
    }

    EFI_HOB_HANDOFF_INFO_TABLE tbl = { .Header = { .HobType = EFI_HOB_TYPE_HANDOFF,
                                                   .HobLength = sizeof(EFI_HOB_HANDOFF_INFO_TABLE),
                                                   .Reserved = 0x0 },
                                       .Version = EFI_HOB_HANDOFF_TABLE_VERSION,
                                       .BootMode = BOOT_WITH_FULL_CONFIGURATION,
                                       .EfiMemoryTop = 0x0,
                                       .EfiMemoryBottom = 0x0,
                                       .EfiFreeMemoryTop = 0x0,
                                       .EfiFreeMemoryBottom = 0x0,
                                       .EfiEndOfHobList = 0x8091f0 };

    memcpy(dest, (uint8_t *)&tbl, sizeof(EFI_HOB_HANDOFF_INFO_TABLE));

    size_t hob_offset = sizeof(EFI_HOB_HANDOFF_INFO_TABLE);

    // Sizes: OvmfPkg/OvmfPkgX64.fdf
    // Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/ResetVector/ResetVector/DEBUG/Autogen.h
    // Build/OvmfX64/DEBUG_GCC5/X64/OvmfPkg/Sec/SecMain/DEBUG/AutoGen.h
    // Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/PlatformPei/PlatformPei/DEBUG/PlatformPei.debug
    size_t physical_start[RESOURCE_DESCRIPTOR_LEN] = {
        0x0,         // Size: 0x800000       ?? Reserved BIOS Legacy
        0x800000,    // Size: 0x6000         _PCD_VALUE_PcdOvmfSecPageTablesBase
        0x806000,    // Size: 0x3000         _PCD_VALUE_PcdOvmfLockBoxStorageBase
        0x809000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfSecGhcbBase
        0x80b000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfWorkAreaBase
        0x80d000,    // Size: 0x4000         _PCD_VALUE_PcdOvmfSnpSecretsBase
        0x811000,    // Size: 0xF000         _PCD_VALUE_PcdOvmfSecPeiTempRamBase
        0x820000,    // Size: 0x7F7E0000     _PCD_VALUE_PcdOvmfPeiMemFvBase
        0x100000000, // Size: 0x80000000     ?? PCI MMIO
    };

    size_t resource_length[RESOURCE_DESCRIPTOR_LEN] = {
        0x800000, // Base: 0x0            ??
        0x6000, // Base: 0x800000       _PCD_VALUE_PcdOvmfSecPageTablesBase         _PCD_VALUE_PcdOvmfSecPageTablesSize
        0x3000, // Base: 0x806000       _PCD_VALUE_PcdOvmfLockBoxStorageBase        _PCD_VALUE_PcdOvmfLockBoxStorageSize (0x1000) + _PCD_VALUE_PcdGuidedExtractHandlerTableSize (0x1000) + _PCD_VALUE_PcdOvmfSecGhcbPageTableSize (0x1000)
        0x2000, // Base: 0x809000       _PCD_VALUE_PcdOvmfSecGhcbBase               _PCD_VALUE_PcdOvmfSecGhcbSize
        0x2000, // Base: 0x80b000       _PCD_VALUE_PcdOvmfWorkAreaBase              _PCD_VALUE_PcdOvmfWorkAreaSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000)
        0x4000, // Base: 0x80d000       _PCD_VALUE_PcdOvmfSnpSecretsBase            _PCD_VALUE_PcdOvmfSnpSecretsSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000) + _PCD_VALUE_PcdOvmfSecSvsmCaaSize (0x1000) + _PCD_VALUE_PcdOvmfSecApicPageTableSize (0x1000)
        0xF000, // Base: 0x811000       _PCD_VALUE_PcdOvmfSecPeiTempRamBase         _PCD_VALUE_PcdOvmfSecPeiTempRamSize
        0x7F7E0000, // Base: 0x820000       _PCD_VALUE_PcdOvmfPeiMemFvBase              ?? _PCD_VALUE_PcdOvmfPeiMemFvSize (0xE0000) + _PCD_VALUE_PcdOvmfDxeMemFvSize (0xE80000)
        0x80000000, // Base: 0x100000000    ??
    };

    EFI_RESOURCE_TYPE resource_type[RESOURCE_DESCRIPTOR_LEN] = {
        EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
        EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
        EFI_RESOURCE_SYSTEM_MEMORY,     EFI_RESOURCE_MEMORY_UNACCEPTED,
        EFI_RESOURCE_SYSTEM_MEMORY,     EFI_RESOURCE_MEMORY_UNACCEPTED,
        EFI_RESOURCE_MEMORY_UNACCEPTED
    };

    for (size_t i = 0; i < RESOURCE_DESCRIPTOR_LEN; i++) {
        EFI_HOB_RESOURCE_DESCRIPTOR rd = {
            .Header = { .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                        .HobLength = sizeof(EFI_HOB_RESOURCE_DESCRIPTOR),
                        .Reserved = 0x0 },
            .Owner = { .Data1 = 0x0, .Data2 = 0x0, .Data3 = 0x0, .Data4 = { 0x0 } },
            .ResourceType = resource_type[i],
            .ResourceAttribute = EFI_RESOURCE_ATTRIBUTE_PRESENT |
                                 EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED,
            .PhysicalStart = physical_start[i],
            .ResourceLength = resource_length[i]
        };

        memcpy(dest + hob_offset, (uint8_t *)&rd, sizeof(EFI_HOB_RESOURCE_DESCRIPTOR));
        hob_offset += sizeof(EFI_HOB_RESOURCE_DESCRIPTOR);
    }
    print_td_hob(dest, len);

    return 0;
}

void
print_td_hob(uint8_t *data, size_t len)
{
    DEBUG("Printing EFI handoff tables\n");
    size_t offset = 0;
    while (offset < len) {
        EFI_HOB_GENERIC_HEADER *hdr = (EFI_HOB_GENERIC_HEADER *)((uint8_t *)data + offset);
        switch (hdr->HobType) {
        case EFI_HOB_TYPE_HANDOFF:
            EFI_HOB_HANDOFF_INFO_TABLE *hob =
                (EFI_HOB_HANDOFF_INFO_TABLE *)((uint8_t *)data + offset);
            DEBUG("EFI_HOB_HANDOFF_INFO_TABLE:\n");
            DEBUG("\tHobType: %d\n", hob->Header.HobType);
            DEBUG("\tHobLength: %d\n", hob->Header.HobLength);
            DEBUG("\tVersion: %d\n", hob->Version);
            DEBUG("\tBoot Mode: %d\n", hob->BootMode);
            DEBUG("\tEfiMemoryTop: 0x%llx\n", hob->EfiMemoryTop);
            DEBUG("\tEfiMemoryBottom: 0x%llx\n", hob->EfiMemoryBottom);
            DEBUG("\tEfiFreeMemoryTop: 0x%llx\n", hob->EfiFreeMemoryTop);
            DEBUG("\tEfiFreememoryBottom: 0x%llx\n", hob->EfiFreeMemoryBottom);
            DEBUG("\tEfiEndOfHobList: 0x%llx\n", hob->EfiEndOfHobList);
            break;

        case EFI_HOB_TYPE_RESOURCE_DESCRIPTOR:
            EFI_HOB_RESOURCE_DESCRIPTOR *rd =
                (EFI_HOB_RESOURCE_DESCRIPTOR *)((uint8_t *)data + offset);
            DEBUG("EFI_HOB_RESOURCE_DESCRIPTOR:\n");
            DEBUG("\tHobType: %d\n", hob->Header.HobType);
            DEBUG("\tHobLength: %d\n", hob->Header.HobLength);
            DEBUG("\tGUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", rd->Owner.Data1,
                  rd->Owner.Data2, rd->Owner.Data3, rd->Owner.Data4[0], rd->Owner.Data4[1],
                  rd->Owner.Data4[2], rd->Owner.Data4[3], rd->Owner.Data4[4], rd->Owner.Data4[5],
                  rd->Owner.Data4[6], rd->Owner.Data4[7]);
            DEBUG("\tResourceType: %x\n", rd->ResourceType);
            DEBUG("\tResourceAttribute: %x\n", rd->ResourceAttribute);
            DEBUG("\tPhysicalStart: %llx\n", rd->PhysicalStart);
            DEBUG("\tResourceLength: %llx\n", rd->ResourceLength);
            break;
        }

        offset += hdr->HobLength;
    }
}