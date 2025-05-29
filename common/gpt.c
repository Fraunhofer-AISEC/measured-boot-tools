/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <zlib.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "UefiBaseType.h"
#include "hash.h"
#include "common.h"
#include "gpt.h"

#define BUF_SIZE 1024

static void
print_guid(const void *guid_ptr)
{
    const uint8_t *g = (const uint8_t *)guid_ptr;
    printf("Disk GUID: %08x-%04x-%04x-", *(uint32_t *)&g[0], *(uint16_t *)&g[4],
           *(uint16_t *)&g[6]);
    for (int i = 8; i < 10; i++) {
        printf("%02x", g[i]);
    }
    printf("-");
    for (int i = 10; i < 16; i++) {
        printf("%02x", g[i]);
    }
    printf("\n");
}

static void
write_guid(EFI_GUID *guid, char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid->Data1,
             guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2],
             guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

char *
write_gpt_header(UEFI_PARTITION_TABLE_HEADER *hdr)
{
    char *buf = (char *)malloc(BUF_SIZE);
    if (buf == NULL) {
        return NULL;
    }

    char guid_str[64];
    int ret = snprintf(buf, BUF_SIZE,
                       "UEFI Partition Table: "
                       "Signature: %s, "
                       "Revision: 0x%x, "
                       "HeaderSize: %u, "
                       "HeaderCRC32: 0x%x, "
                       "MyLBA: 0x%llx, "
                       "AlternateLBA: 0x%llx, "
                       "FirstUsableLBA: 0x%llx, "
                       "LastUsableLBA: 0x%llx, ",
                       (char *)&hdr->Signature, hdr->Revision, hdr->HeaderSize, hdr->HeaderCRC32,
                       hdr->MyLBA, hdr->AlternateLBA, hdr->FirstUsableLBA, hdr->LastUsableLBA);
    write_guid(&hdr->DiskGUID, guid_str, sizeof(guid_str));
    snprintf(buf + ret, BUF_SIZE - ret, "DiskGUID: %s, ", guid_str);
    ret = snprintf(buf + ret, BUF_SIZE - ret,
                   "PartitionEntryLBA: 0x%llx, "
                   "NumberOfPartitionEntries: %u, "
                   "SizeOfPartitionEntry: %u, "
                   "PartitionEntryArrayCRC32: 0x%x",
                   hdr->PartitionEntryLBA, hdr->NumberOfPartitionEntries, hdr->SizeOfPartitionEntry,
                   hdr->PartitionEntryArrayCRC32);

    return buf;
}

void
print_gpt_header(UEFI_PARTITION_TABLE_HEADER *hdr)
{
    printf("Signature: 0x%llx\n", hdr->Signature);
    printf("Revision: 0x%x\n", hdr->Revision);
    printf("HeaderSize: %u\n", hdr->HeaderSize);
    printf("HeaderCRC32: 0x%x\n", hdr->HeaderCRC32);
    printf("MyLBA: %llu\n", hdr->MyLBA);
    printf("AlternateLBA: 0x%llx\n", hdr->AlternateLBA);
    printf("FirstUsableLBA: 0x%llx\n", hdr->FirstUsableLBA);
    printf("LastUsableLBA: 0x%llx\n", hdr->LastUsableLBA);
    print_guid(&hdr->DiskGUID);
    printf("PartitionEntryLBA: 0x%llx\n", hdr->PartitionEntryLBA);
    printf("NumberOfPartitionEntries: %u\n", hdr->NumberOfPartitionEntries);
    printf("SizeOfPartitionEntry: %u\n", hdr->SizeOfPartitionEntry);
    printf("PartitionEntryArrayCRC32: 0x%x\n", hdr->PartitionEntryArrayCRC32);
}