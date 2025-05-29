/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <openssl/sha.h>

// GUID Partition Table as defined in TGC PC Client Platform Firmware Profile Specification
// Version 1.05,Revision 23, Table 10. andION_ENTRY UEFI Specification Version 2.9, Section 5.3.
typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 HeaderCRC32;
    UINT32 Reserved;
    UINT64 MyLBA;
    UINT64 AlternateLBA;
    UINT64 FirstUsableLBA;
    UINT64 LastUsableLBA;
    EFI_GUID DiskGUID;
    UINT64 PartitionEntryLBA;
    UINT32 NumberOfPartitionEntries;
    UINT32 SizeOfPartitionEntry;
    UINT32 PartitionEntryArrayCRC32;
} PACKED UEFI_PARTITION_TABLE_HEADER;

typedef struct {
    EFI_GUID PartitionTypeGUID;
    EFI_GUID UniquePartitionGUID;
    UINT64 StartingLBA;
    UINT64 EndingLBA;
    UINT64 Attributes;
    CHAR16 PartitionName[36];
} PACKED UEFI_PARTITION_ENTRY;

char *
write_gpt_header(UEFI_PARTITION_TABLE_HEADER *hdr);

void
print_gpt_header(UEFI_PARTITION_TABLE_HEADER *hdr);