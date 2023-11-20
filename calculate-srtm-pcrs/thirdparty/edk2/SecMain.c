/** @file
  Main SEC phase code.  Transitions to PEI.

  Copyright (c) 2008 - 2015, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2020, Advanced Micro Devices, Inc. All rights reserved.<BR>

  Copyright (c) 2022, Fraunhofer AISEC
  Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.<BR>

  This is a strongly modified version of the original file to be used
  in the tpm-pcr-tools. The purpose is to measure the OVMF PEI Firmware Volume
  as well as the OVMF DXE Firmware Volume to pre-calculate the hashes which are
  expected to be extended into the TPM PCR0 during a measured boot.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "LzmaDec.h"

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "LzmaDecompressLibInternal.h"
#include "SecMain.h"

#include "common.h"
#include "hash.h"
#include "guid.h"

#define EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE  0x0B

#define EFI_SECTION_COMPRESSION   0x01
#define EFI_SECTION_GUID_DEFINED  0x02
#define EFI_SECTION_FIRMWARE_VOLUME_IMAGE  0x17

#define SECTION2_SIZE(SectionHeaderPtr) \
    (((EFI_COMMON_SECTION_HEADER2 *) (UINTN) SectionHeaderPtr)->ExtendedSize)

#define IS_SECTION2(SectionHeaderPtr) \
    (SECTION_SIZE (SectionHeaderPtr) == 0x00ffffff)

typedef struct {
  ///
  /// This GUID is the file name. It is used to uniquely identify the file.
  ///
  EFI_GUID                   Name;
  ///
  /// Used to verify the integrity of the file.
  ///
  UINT16    IntegrityCheck;
  ///
  /// Identifies the type of file.
  ///
  UINT8            Type;
  ///
  /// Declares various file attribute bits.
  ///
  UINT8    Attributes;
  ///
  /// The length of the file in bytes, including the FFS header.
  ///
  UINT8                      Size[3];
  ///
  /// Used to track the state of the file throughout the life of the file from creation to deletion.
  ///
  UINT8         State;
} EFI_FFS_FILE_HEADER;

typedef struct {
  ///
  /// A 24-bit unsigned integer that contains the total size of the section in bytes,
  /// including the EFI_COMMON_SECTION_HEADER.
  ///
  UINT8               Size[3];

  UINT8    Type;

  ///
  /// If Size is 0xFFFFFF, then ExtendedSize contains the size of the section. If
  /// Size is not equal to 0xFFFFFF, then this field does not exist.
  ///
  UINT32              ExtendedSize;
} EFI_COMMON_SECTION_HEADER2;

///
/// The argument passed as the SectionHeaderPtr parameter to the SECTION_SIZE()
/// and IS_SECTION2() function-like macros below must not have side effects:
/// SectionHeaderPtr is evaluated multiple times.
///
#define SECTION_SIZE(SectionHeaderPtr)  ((UINT32) (\
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[0]      ) | \
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[1] <<  8) | \
    (((EFI_COMMON_SECTION_HEADER *) (UINTN) (SectionHeaderPtr))->Size[2] << 16)))

///
/// The argument passed as the FfsFileHeaderPtr parameter to the
/// FFS_FILE_SIZE() function-like macro below must not have side effects:
/// FfsFileHeaderPtr is evaluated multiple times.
///
#define FFS_FILE_SIZE(FfsFileHeaderPtr)  ((UINT32) (\
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[0]      ) | \
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[1] <<  8) | \
    (((EFI_FFS_FILE_HEADER *) (UINTN) (FfsFileHeaderPtr))->Size[2] << 16)))

EFI_GUID lzma_decrompress_guid = { 0xEE4E5898, 0x3914, 0x4259, { 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF }};
EFI_GUID ovmf_platform_info_hob_guid = {0xdec9b486, 0x1f16, 0x47c7, {0x8f, 0x68, 0xdf, 0x1a, 0x41, 0x88, 0x8b, 0xa5}};
EFI_GUID efi_firmware_ffs2_guid = { 0x8c8ce578, 0x8a3d, 0x4f1c, { 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3 }};

EFI_STATUS
FindFfsSectionInstance (
  IN  VOID                       *Sections,
  IN  UINTN                      SizeOfSections,
  IN  UINT8           SectionType,
  IN  UINTN                      Instance,
  OUT EFI_COMMON_SECTION_HEADER  **FoundSection
  )
{
  EFI_PHYSICAL_ADDRESS       CurrentAddress;
  UINT32                     Size;
  EFI_PHYSICAL_ADDRESS       EndOfSections;
  EFI_COMMON_SECTION_HEADER  *Section;
  EFI_PHYSICAL_ADDRESS       EndOfSection;

  //
  // Loop through the FFS file sections within the PEI Core FFS file
  //
  EndOfSection  = (EFI_PHYSICAL_ADDRESS)(UINTN)Sections;
  EndOfSections = EndOfSection + SizeOfSections;
  for ( ; ;) {
    if (EndOfSection == EndOfSections) {
      break;
    }

    CurrentAddress = (EndOfSection + 3) & ~(3ULL);
    if (CurrentAddress >= EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    Section = (EFI_COMMON_SECTION_HEADER *)(UINTN)CurrentAddress;

    Size = SECTION_SIZE (Section);
    if (Size < sizeof (*Section)) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfSection = CurrentAddress + Size;
    if (EndOfSection > EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the requested section type
    //
    if (Section->Type == SectionType) {
      if (Instance == 0) {
        *FoundSection = Section;
        return EFI_SUCCESS;
      } else {
        Instance--;
      }
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
FindFfsSectionInSections (
  IN  VOID                       *Sections,
  IN  UINTN                      SizeOfSections,
  IN  UINT8           SectionType,
  OUT EFI_COMMON_SECTION_HEADER  **FoundSection
  )
{
  return FindFfsSectionInstance (
           Sections,
           SizeOfSections,
           SectionType,
           0,
           FoundSection
           );
}

int FindFfsFileAndSection (
    IN  EFI_FIRMWARE_VOLUME_HEADER  *Fv,
    IN  UINT8             FileType,
    IN  UINT8            SectionType,
    OUT EFI_COMMON_SECTION_HEADER   **FoundSection
    )
{
    EFI_STATUS            Status;
    EFI_PHYSICAL_ADDRESS  CurrentAddress;
    EFI_PHYSICAL_ADDRESS  EndOfFirmwareVolume;
    EFI_FFS_FILE_HEADER   *File;
    UINT32                Size;
    EFI_PHYSICAL_ADDRESS  EndOfFile;

    if (Fv->Signature != EFI_FVH_SIGNATURE) {
        DEBUG ("FV at %p does not have FV header signature\n", Fv);
        return -1;
    }

    CurrentAddress      = (EFI_PHYSICAL_ADDRESS)(UINTN)Fv;
    EndOfFirmwareVolume = CurrentAddress + Fv->FvLength;

    //
    // Loop through the FFS files in the Boot Firmware Volume
    //
    for (EndOfFile = CurrentAddress + Fv->HeaderLength; ; ) {
        CurrentAddress = (EndOfFile + 7) & ~(7ULL);
        if (CurrentAddress > EndOfFirmwareVolume) {
            DEBUG ("Address larger than end of FV\n");
            return -1;
        }

        File = (EFI_FFS_FILE_HEADER *)(UINTN)CurrentAddress;
        Size = FFS_FILE_SIZE (File);
        if (Size < (sizeof (*File) + sizeof (EFI_COMMON_SECTION_HEADER))) {
            DEBUG("Size smaller than header\n");
            return -1;
        }

        EndOfFile = CurrentAddress + Size;
        if (EndOfFile > EndOfFirmwareVolume) {
            DEBUG("End of file larger than end of FV\n");
            return -1;
        }

        //
        // Look for the request file type
        //
        if (File->Type != FileType) {
            continue;
        }

        Status = FindFfsSectionInSections (
                (VOID *)(File + 1),
                (UINTN)EndOfFile - (UINTN)(File + 1),
                SectionType,
                FoundSection
                );
        if (!EFI_ERROR (Status)) {
            DEBUG("FOUND FFS Section\n");
            return 0;
        } else if (Status == EFI_VOLUME_CORRUPTED) {
            DEBUG("EFI_VOLUME_CORRUPTED\n");
            return -1;
        }
    }
    DEBUG("Not found\n");
    return -1;
}

uint8_t *
extract_lzma_fvmain_new (EFI_FIRMWARE_VOLUME_HEADER  *Fv, size_t *extracted_size)
{
    EFI_GUID_DEFINED_SECTION *section;
    uint8_t *fvmain = NULL;

    int ret = FindFfsFileAndSection (
                Fv,
                EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE,
                EFI_SECTION_GUID_DEFINED,
                (EFI_COMMON_SECTION_HEADER **)&section
                );
    if (ret != 0) {
        DEBUG("Unable to find GUID defined section\n");
        return NULL;
    }

    uint32_t size =   (section->CommonHeader.Size[0] << 0) |
                        (section->CommonHeader.Size[1] << 8) |
                        (section->CommonHeader.Size[2] << 16);

    DEBUG("Section->DataOffset: %d\n", section->DataOffset);
    DEBUG("Section->CommonHeader.Type: %d\n", section->CommonHeader.Type);
    DEBUG("Section->CommonHeader.Size: %d (0x%x)\n", size, size);

    if (!compare_guid (
        &lzma_decrompress_guid,
        &(((EFI_GUID_DEFINED_SECTION *)section)->SectionDefinitionGuid)
        ))
    {
      printf("GUIDs do not match\n");
      return NULL;
    }

    UINT32 output_buf_size = 0;
    UINT32 scratch_buf_size = 0;

    ret = LzmaUefiDecompressGetInfo (
        (UINT8 *)section + ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
        SECTION_SIZE (section) - ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
        &output_buf_size,
        &scratch_buf_size);
    if (ret != 0) {
        printf("Failed to get LZMA GUIDed section info %d\n", ret);
        return NULL;
    }

    fvmain = (uint8_t *)malloc(output_buf_size);
    ASSERT(fvmain);
    uint8_t *scratch_buf = (uint8_t *)malloc(scratch_buf_size);
    ASSERT(scratch_buf);

    ret = LzmaUefiDecompress (
            (UINT8 *)section + ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
            SECTION_SIZE (section) - ((EFI_GUID_DEFINED_SECTION *)section)->DataOffset,
            fvmain,
            scratch_buf);
    if (ret != 0) {
        printf("Failed to decompress LZMA compressed volume\n");
    }

    *extracted_size = output_buf_size;

    DEBUG("Extracted FVMAIN_COMPACT.Fv\n");

    free(scratch_buf);
    return fvmain;
}

///
/// Details the location of a firmware volume that was extracted
/// from a file within another firmware volume.
///
typedef struct {
  ///
  /// The HOB generic header. Header.HobType = EFI_HOB_TYPE_FV2.
  ///
  EFI_HOB_GENERIC_HEADER    Header;
  ///
  /// The physical memory-mapped base address of the firmware volume.
  ///
  EFI_PHYSICAL_ADDRESS      BaseAddress;
  ///
  /// The length in bytes of the firmware volume.
  ///
  UINT64                    Length;
  ///
  /// The name of the firmware volume.
  ///
  EFI_GUID                  FvName;
  ///
  /// The name of the firmware file that contained this firmware volume.
  ///
  EFI_GUID                  FileName;
} EFI_HOB_FIRMWARE_VOLUME2;

///
/// Contains general state information used by the HOB producer phase.
/// This HOB must be the first one in the HOB list.
///
typedef struct {
  ///
  /// The HOB generic header. Header.HobType = EFI_HOB_TYPE_HANDOFF.
  ///
  EFI_HOB_GENERIC_HEADER    Header;
  ///
  /// The version number pertaining to the PHIT HOB definition.
  /// This value is four bytes in length to provide an 8-byte aligned entry
  /// when it is combined with the 4-byte BootMode.
  ///
  UINT32                    Version;
  ///
  /// The system boot mode as determined during the HOB producer phase.
  ///
  UINT32             BootMode;
  ///
  /// The highest address location of memory that is allocated for use by the HOB producer
  /// phase. This address must be 4-KB aligned to meet page restrictions of UEFI.
  ///
  EFI_PHYSICAL_ADDRESS      EfiMemoryTop;
  ///
  /// The lowest address location of memory that is allocated for use by the HOB producer phase.
  ///
  EFI_PHYSICAL_ADDRESS      EfiMemoryBottom;
  ///
  /// The highest address location of free memory that is currently available
  /// for use by the HOB producer phase.
  ///
  EFI_PHYSICAL_ADDRESS      EfiFreeMemoryTop;
  ///
  /// The lowest address location of free memory that is available for use by the HOB producer phase.
  ///
  EFI_PHYSICAL_ADDRESS      EfiFreeMemoryBottom;
  ///
  /// The end of the HOB list.
  ///
  EFI_PHYSICAL_ADDRESS      EfiEndOfHobList;
} EFI_HOB_HANDOFF_INFO_TABLE;

#define EFI_HOB_TYPE_HANDOFF              0x0001
#define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
#define EFI_HOB_TYPE_FV                   0x0005
#define EFI_HOB_TYPE_CPU                  0x0006
#define EFI_HOB_TYPE_MEMORY_POOL          0x0007
#define EFI_HOB_TYPE_FV2                  0x0009
#define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
#define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
#define EFI_HOB_TYPE_FV3                  0x000C
#define EFI_HOB_TYPE_UNUSED               0xFFFE
#define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

///
/// Value of version  in EFI_HOB_HANDOFF_INFO_TABLE.
///
#define EFI_HOB_HANDOFF_TABLE_VERSION  0x0009

int
measure_peifv(uint8_t hash[SHA256_DIGEST_LENGTH], uint8_t *fvmain)
{
    // Find PEIFV (header)
    uint8_t *peifv = ((uint8_t *)fvmain + 0x80);
    size_t peifv_size = 896 * 1024;

    sha256(hash, peifv, peifv_size);

    return 0;
}

int measure_dxefv(uint8_t hash[SHA256_DIGEST_LENGTH], uint8_t *fvmain)
{
    // Find DXE (header), DXE is located after the 896 KB of PEI
    uint8_t *dxefv = ((uint8_t *)fvmain + 0x90 + 896 * 1024);
    size_t dxefv_size = 0xD00000;

    sha256(hash, dxefv, dxefv_size);

    return 0;
}