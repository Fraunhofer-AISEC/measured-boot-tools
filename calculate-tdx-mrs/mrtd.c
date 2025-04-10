/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "UefiBaseType.h"

#include "common.h"
#include "hash.h"

#define SHA384_DIGEST_SIZE 0x30

#define TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD 0x2

#define TD_INFO_STRUCT_RESERVED_SIZE 0x70
#define TDVF_DESCRIPTOR_OFFSET 0x20
#define MRTD_EXTENSION_BUFFER_SIZE 0x80
#define TDH_MR_EXTEND_GRANULARITY 0x100
#define PAGE_SIZE 0x1000

#define MEM_PAGE_ADD_ASCII_SIZE 0xc
#define MEM_PAGE_ADD_GPA_OFFSET 0x10
#define MEM_PAGE_ADD_GPA_SIZE 0x8
#define MR_EXTEND_ASCII_SIZE 0x9
#define MR_EXTEND_GPA_OFFSET 0x10
#define MR_EXTEND_GPA_SIZE 0x8
#define OVMF_TABLE_FOOTER_GUID_OFFSET 0x30

#define TDX_METADATA_SECTION_TYPE_TDVF 1
#define TDX_METADATA_SECTION_TYPE_TD_INFO 7
#define TDX_METADATA_SECTION_TYPE_TD_PARAMS 8
#define TDX_METADATA_SECTION_TYPE_MAX 9

#define TDX_METADATA_ATTRIBUTES_EXTENDMR 0x00000001
#define TDX_METADATA_ATTRIBUTES_PAGE_AUG 0x00000002

#define TDX_METADATA_SIGNATURE 0x46564454

const EFI_GUID OVMF_TABLE_FOOTER_GUID = { 0x96b582de,
                                          0x1fb2,
                                          0x45f7,
                                          { 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d } };

const EFI_GUID OVMF_TABLE_TDX_METADATA_GUID = { 0xe47a6535,
                                                0x984a,
                                                0x4798,
                                                { 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e,
                                                  0xc2 } };

typedef struct {
    uint32_t signature;
    uint32_t length;
    uint32_t version;
    uint32_t number_of_section_entry;
} tdx_metadata_descriptor_t;

typedef struct {
    uint32_t data_offset;
    uint32_t raw_data_size;
    uint64_t memory_address;
    uint64_t memory_data_size;
    uint32_t type;
    uint32_t attributes;
} tdx_metadata_section_t;

static bool
is_valid_descriptor(tdx_metadata_descriptor_t *d)
{
    if (d->signature != TDX_METADATA_SIGNATURE) {
        printf("invalid signature: %x (expected: %x)\n", d->signature, TDX_METADATA_SIGNATURE);
        return false;
    }
    if (d->version != 1) {
        printf("invalid version %d (expected %d)\n", d->version, 1);
        return false;
    }
    if (d->number_of_section_entry == 0) {
        printf("number of section entries is zero\n");
        return false;
    }
    return true;
}

static void
td_call_mem_page_add(uint8_t buf[MRTD_EXTENSION_BUFFER_SIZE], uint64_t gpa)
{
    memset(buf, 0, MRTD_EXTENSION_BUFFER_SIZE);

    memcpy(buf, "MEM.PAGE.ADD", MEM_PAGE_ADD_ASCII_SIZE);

    // Copy the GPA in little-endian format
    memcpy(&buf[MEM_PAGE_ADD_GPA_OFFSET], &gpa, MEM_PAGE_ADD_GPA_SIZE);
}

static int
td_call_mr_extend(uint8_t buf[3][MRTD_EXTENSION_BUFFER_SIZE], uint64_t gpa, uint8_t *raw_image,
                  uint64_t raw_image_size, uint64_t data_offset)
{
    if (data_offset + 2 * MRTD_EXTENSION_BUFFER_SIZE > raw_image_size) {
        printf("data offset larger than raw image\n");
        return -1;
    }

    memset(buf[0], 0, MRTD_EXTENSION_BUFFER_SIZE);
    memset(buf[1], 0, MRTD_EXTENSION_BUFFER_SIZE);
    memset(buf[2], 0, MRTD_EXTENSION_BUFFER_SIZE);

    // Byte 0-8: ASCII string 'MR.EXTEND'
    memcpy(buf[0], "MR.EXTEND", MR_EXTEND_ASCII_SIZE);
    // Byte 16-23: GPA (in little-endian format).
    memcpy(buf[0] + MR_EXTEND_GPA_OFFSET, &gpa, MR_EXTEND_GPA_SIZE);

    memcpy(buf[1], raw_image + data_offset, MRTD_EXTENSION_BUFFER_SIZE);
    memcpy(buf[2], raw_image + data_offset + MRTD_EXTENSION_BUFFER_SIZE,
           MRTD_EXTENSION_BUFFER_SIZE);

    return 0;
}

static uint16_t
read_u16_le(uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static uint32_t
read_u32_le(uint8_t *buf)
{
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

static int
get_ovmf_metadata_offset(uint64_t *out_metadata_offset, uint8_t *raw_image, uint64_t raw_image_size)
{
    uint64_t offset = 0;

    uint64_t table_footer_offset = raw_image_size - OVMF_TABLE_FOOTER_GUID_OFFSET;
    if (table_footer_offset + sizeof(EFI_GUID) > raw_image_size) {
        printf("invalid offset\n");
        return -1;
    }

    uint8_t footer_guid_buf[sizeof(EFI_GUID)] = { 0 };
    memcpy(footer_guid_buf, raw_image + table_footer_offset, sizeof(EFI_GUID));

    if (memcmp(&OVMF_TABLE_FOOTER_GUID, footer_guid_buf, sizeof(EFI_GUID)) == 0) {
        uint64_t ovmf_table_offset =
            raw_image_size - OVMF_TABLE_FOOTER_GUID_OFFSET - sizeof(uint16_t);

        uint16_t table_len =
            read_u16_le(raw_image + ovmf_table_offset) - sizeof(EFI_GUID) - sizeof(uint16_t);

        uint16_t count = 0;
        while (count < table_len) {
            uint8_t guid_buf[sizeof(EFI_GUID)] = { 0 };
            memcpy(guid_buf, raw_image + ovmf_table_offset - sizeof(EFI_GUID), sizeof(EFI_GUID));

            uint16_t len =
                read_u16_le(raw_image + (ovmf_table_offset - sizeof(EFI_GUID) - sizeof(uint16_t)));
            if (memcmp(&OVMF_TABLE_TDX_METADATA_GUID, guid_buf, sizeof(EFI_GUID)) == 0) {
                offset = raw_image_size -
                         read_u32_le(raw_image + (ovmf_table_offset - sizeof(EFI_GUID) -
                                                  sizeof(uint16_t) - sizeof(uint32_t))) -
                         sizeof(EFI_GUID);
                break;
            }
            ovmf_table_offset -= len;
            count += len;
        }
    } else {
        offset =
            read_u32_le(raw_image + (raw_image_size - TDVF_DESCRIPTOR_OFFSET) - sizeof(EFI_GUID));
    }

    *out_metadata_offset = offset;

    return 0;
}

int
measure_ovmf(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image, uint64_t raw_image_size)
{
    DEBUG("Measuring OVMF size %ld\n", raw_image_size);

    uint64_t metadata_offset = 0;
    int ret = get_ovmf_metadata_offset(&metadata_offset, raw_image, raw_image_size);
    if (ret) {
        printf("failed to get metadata offset\n");
        return -1;
    }

    DEBUG("OVMF metadata offset: %ld\n", metadata_offset);

    uint8_t desc_buf[sizeof(EFI_GUID) + sizeof(tdx_metadata_descriptor_t)] = { 0 };
    memcpy(desc_buf, raw_image + metadata_offset, sizeof(desc_buf));
    uint8_t *desc = desc_buf + sizeof(EFI_GUID);

    // Signature            0    CHAR8[4]           4       'TDVF'
    // Length               4    UINT32             4       Size of the structure
    // Version              8    UINT32             4       Version 1
    // NumberOfSectionEntry 12   UINT32             4       Number of the section entry (n)
    // SectionEntries       16   TDVF_SECTION[n]    32*n    n section entries
    size_t desc_offset = 0;
    tdx_metadata_descriptor_t descriptor;
    memcpy(&descriptor, desc + desc_offset, sizeof(tdx_metadata_descriptor_t));
    if (!is_valid_descriptor(&descriptor)) {
        printf("Descriptor is not valid!\n");
        return -1;
    }

    uint8_t *metadata_buf = malloc(descriptor.length);
    if (!metadata_buf) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(metadata_buf, raw_image + metadata_offset + sizeof(EFI_GUID), descriptor.length);
    uint8_t *desc_ptr = metadata_buf;

    desc_offset += sizeof(tdx_metadata_descriptor_t);

    uint8_t buffer128[MRTD_EXTENSION_BUFFER_SIZE] = { 0 };
    uint8_t buffer3_128[3][MRTD_EXTENSION_BUFFER_SIZE] = { { 0 } };

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("EVP_MD_CTX_new failed\n");
        goto out;
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha384(), NULL)) {
        printf("EVP_DigestInit_ex failed\n");
        goto out;
    }

    for (uint32_t i = 0; i < descriptor.number_of_section_entry; i++) {
        // DataOffset       0   UINT32  4    Offset to the raw section
        // RawDataSize      4   UINT32  4    size of the raw section
        // MemoryAddress    8   UINT64  8    GPA of the section loaded
        // MemoryDataSize   16  UINT64  8    size of the section loaded
        // Type             24  UINT32  4    type of the TDVF_SECTION
        // Attributes       28  UINT32  4    attribute of the section
        tdx_metadata_section_t sec;
        memcpy(&sec, desc_ptr + desc_offset, sizeof(tdx_metadata_section_t));
        desc_offset += sizeof(tdx_metadata_section_t);

        // sanity check
        if (sec.memory_address % PAGE_SIZE != 0) {
            printf("Memory address must be 4K aligned!\n");
            goto out;
        }

        if ((sec.type != TDX_METADATA_SECTION_TYPE_TD_INFO) &&
            ((sec.memory_address != 0 || sec.memory_data_size != 0) &&
             (sec.memory_data_size < sec.raw_data_size))) {
            printf("Memory data size must exceed or equal the raw data size!\n");
            goto out;
        }

        if (sec.memory_data_size % PAGE_SIZE != 0) {
            printf("Memory data size must be 4K aligned!\n");
            goto out;
        }

        if (sec.type >= TDX_METADATA_SECTION_TYPE_MAX) {
            printf("Invalid type value!\n");
            goto out;
        }

        uint64_t nr_pages = sec.memory_data_size / PAGE_SIZE;

        DEBUG(
            "Measure Offset %x, Size %x, GPA %lx, Memory Size %lx, Type %x, Attributes %x, NR pages: %ld\n",
            sec.data_offset, sec.raw_data_size, sec.memory_address, sec.memory_data_size, sec.type,
            sec.attributes, nr_pages);

        for (uint64_t iter = 0; iter < nr_pages; iter++) {
            if ((sec.attributes & TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD) == 0) {
                DEBUG("\tMEM.PAGE.ADD\n");
                td_call_mem_page_add(buffer128, sec.memory_address + iter * PAGE_SIZE);
                EVP_DigestUpdate(ctx, buffer128, MRTD_EXTENSION_BUFFER_SIZE);
            }

            if (sec.attributes & TDX_METADATA_ATTRIBUTES_EXTENDMR) {
                uint32_t granularity = TDH_MR_EXTEND_GRANULARITY;
                uint32_t iteration = PAGE_SIZE / granularity;
                DEBUG("\tMR.EXTEND %d pages\n", iteration);
                for (uint32_t chunk_iter = 0; chunk_iter < iteration; chunk_iter++) {
                    td_call_mr_extend(
                        buffer3_128,
                        sec.memory_address + iter * PAGE_SIZE + chunk_iter * granularity, raw_image,
                        raw_image_size,
                        sec.data_offset + iter * PAGE_SIZE + chunk_iter * granularity);
                    EVP_DigestUpdate(ctx, buffer3_128[0], MRTD_EXTENSION_BUFFER_SIZE);
                    EVP_DigestUpdate(ctx, buffer3_128[1], MRTD_EXTENSION_BUFFER_SIZE);
                    EVP_DigestUpdate(ctx, buffer3_128[2], MRTD_EXTENSION_BUFFER_SIZE);
                }
            }
        }
    }
    EVP_DigestFinal_ex(ctx, digest, NULL);

    ret = 0;

out:
    if (metadata_buf)
        free(metadata_buf);
    if (ctx)
        EVP_MD_CTX_free(ctx);

    return ret;
}

int
measure_cfv(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image, uint64_t raw_image_size)
{
    uint64_t metadata_offset = 0;
    int ret = get_ovmf_metadata_offset(&metadata_offset, raw_image, raw_image_size);
    if (ret) {
        printf("failed to get metadata offset\n");
        return -1;
    }

    uint8_t desc_buf[sizeof(EFI_GUID) + sizeof(tdx_metadata_descriptor_t)] = { 0 };
    memcpy(desc_buf, raw_image + metadata_offset, sizeof(desc_buf));
    uint8_t *desc = desc_buf + sizeof(EFI_GUID);

    size_t desc_offset = 0;
    tdx_metadata_descriptor_t descriptor;
    memcpy(&descriptor, desc + desc_offset, sizeof(tdx_metadata_descriptor_t));
    if (!is_valid_descriptor(&descriptor)) {
        printf("Descriptor is not valid!\n");
        return -1;
    }

    uint8_t *metadata_buf = malloc(descriptor.length);
    if (!metadata_buf) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(metadata_buf, raw_image + metadata_offset + sizeof(EFI_GUID), descriptor.length);
    uint8_t *desc_ptr = metadata_buf;

    desc_offset += sizeof(tdx_metadata_descriptor_t);

    for (uint32_t i = 0; i < descriptor.number_of_section_entry; i++) {
        tdx_metadata_section_t sec;
        memcpy(&sec, desc_ptr + desc_offset, sizeof(tdx_metadata_section_t));
        desc_offset += sizeof(tdx_metadata_section_t);

        if (sec.memory_address % PAGE_SIZE != 0) {
            printf("Memory address must be 4K aligned!\n");
            goto out;
        }
        if (sec.memory_data_size % PAGE_SIZE != 0) {
            printf("Memory data size must be 4K aligned!\n");
            goto out;
        }
        if (sec.data_offset + sec.raw_data_size > raw_image_size) {
            printf("data section calculation exceeds image size\n");
            goto out;
        }

        if (sec.type != TDX_METADATA_SECTION_TYPE_TDVF) {
            continue;
        }

        hash_buf(EVP_sha384(), digest, raw_image + sec.data_offset, sec.raw_data_size);
        break;
    }

    ret = 0;

out:
    if (metadata_buf)
        free(metadata_buf);

    return ret;
}
