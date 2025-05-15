/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>
#include <libgen.h>
#include <wchar.h>
#include <uchar.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "hash.h"
#include "main.h"
#include "snp.h"

typedef struct __attribute__((__packed__)) snp_launch_update_page_info_t // digest
{
    uint8_t digest_cur[SHA384_DIGEST_LENGTH];
    uint8_t contents[48];
    uint16_t length;
    uint8_t page_type;
    uint8_t imi_page : 1; // bit 0
    uint8_t reserved : 7; // bits 1 to 7
    uint8_t reserved2;
    uint8_t vmpl_1_perms;
    uint8_t vmpl_2_perms;
    uint8_t vmpl_3_perms;
    uint64_t gpa;
} snp_launch_update_page_info;

typedef enum SNP_LAUNCH_UPDATE_PAGE {
    SNP_PAGE_TYPE_RESERVED = 0x0,
    SNP_PAGE_TYPE_NORMAL = 0x1,     // Normal data page
    SNP_PAGE_TYPE_VMSA = 0x2,       // VMSA page
    SNP_PAGE_TYPE_ZERO = 0x3,       // Page full of zeros
    SNP_PAGE_TYPE_UNMEASURED = 0x4, // Encrypted but not measured
    SNP_PAGE_TYPE_SECRETS = 0x5,    // Where firmware stores secrets for the Guest
    SNP_PAGE_TYPE_CPUID = 0x6,      // Where hypervisor provides CPUID function values
} SNP_LAUNCH_UPDATE_PAGE;

#define __packed __attribute__((__packed__))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

struct vmcb_seg {
    u16 selector;
    u16 attrib;
    u32 limit;
    u64 base;
} __packed;

// from AMD snp-host-latest host kernel, arch/x86/include/asm/svm.h, struct sev_es_save_area
struct vmcb_save_area {
    struct vmcb_seg es;
    struct vmcb_seg cs;
    struct vmcb_seg ss;
    struct vmcb_seg ds;
    struct vmcb_seg fs;
    struct vmcb_seg gs;
    struct vmcb_seg gdtr;
    struct vmcb_seg ldtr;
    struct vmcb_seg idtr;
    struct vmcb_seg tr;
    u64 vmpl0_ssp;
    u64 vmpl1_ssp;
    u64 vmpl2_ssp;
    u64 vmpl3_ssp;
    u64 u_cet;
    u8 reserved_0xc8[2];
    u8 vmpl;
    u8 cpl;
    u8 reserved_0xcc[4];
    u64 efer;
    u8 reserved_0xd8[104];
    u64 xss;
    u64 cr4;
    u64 cr3;
    u64 cr0;
    u64 dr7;
    u64 dr6;
    u64 rflags;
    u64 rip;
    u64 dr0;
    u64 dr1;
    u64 dr2;
    u64 dr3;
    u64 dr0_addr_mask;
    u64 dr1_addr_mask;
    u64 dr2_addr_mask;
    u64 dr3_addr_mask;
    u8 reserved_0x1c0[24];
    u64 rsp;
    u64 s_cet;
    u64 ssp;
    u64 isst_addr;
    u64 rax;
    u64 star;
    u64 lstar;
    u64 cstar;
    u64 sfmask;
    u64 kernel_gs_base;
    u64 sysenter_cs;
    u64 sysenter_esp;
    u64 sysenter_eip;
    u64 cr2;
    u8 reserved_0x248[32];
    u64 g_pat;
    u64 dbgctl;
    u64 br_from;
    u64 br_to;
    u64 last_excp_from;
    u64 last_excp_to;
    u8 reserved_0x298[80];
    u32 pkru;
    u32 tsc_aux;
    u8 reserved_0x2f0[24];
    u64 rcx;
    u64 rdx;
    u64 rbx;
    u64 reserved_0x320; /* rsp already available at 0x01d8 */
    u64 rbp;
    u64 rsi;
    u64 rdi;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u8 reserved_0x380[16];
    u64 guest_exit_info_1;
    u64 guest_exit_info_2;
    u64 guest_exit_int_info;
    u64 guest_nrip;
    u64 sev_features;
    u64 vintr_ctrl;
    u64 guest_exit_code;
    u64 virtual_tom;
    u64 tlb_id;
    u64 pcpu_id;
    u64 event_inj;
    u64 xcr0;
    u8 reserved_0x3f0[16];

    /* Floating point area */
    u64 x87_dp;
    u32 mxcsr;
    u16 x87_ftw;
    u16 x87_fsw;
    u16 x87_fcw;
    u16 x87_fop;
    u16 x87_ds;
    u16 x87_cs;
    u64 x87_rip;
    u8 fpreg_x87[80];
    u8 fpreg_xmm[256];
    u8 fpreg_ymm[256];
} __packed;

struct sev_hash_table_entry {
    uint8_t guid[16];
    uint16_t length;
    uint8_t hash[256 / 8];
} __packed;

struct sev_hash_table {
    uint8_t guid[16];
    uint16_t length;
    struct sev_hash_table_entry cmdline;
    struct sev_hash_table_entry initrd;
    struct sev_hash_table_entry kernel;
} __packed;

static void
vmcb_save_area_init(uint8_t *page, uint64_t eip, vmm_type_t vmm_type)
{
    struct vmcb_save_area *save = (void *)page;

    ASSERT(sizeof(*save) <= 4096);
    memset(page, 0, 4096);

    save->es.attrib = 0x93;
    save->es.limit = 0xffff;
    save->cs.selector = 0xf000;
    save->cs.attrib = 0x9b;
    save->cs.limit = 0xffff;
    save->cs.base = eip & 0xffff0000;
    save->ss.limit = 0xffff;
    save->ds.attrib = 0x93;
    save->ds.limit = 0xffff;
    save->fs.attrib = 0x93;
    save->fs.limit = 0xffff;
    save->gs.attrib = 0x93;
    save->gs.limit = 0xffff;
    save->gdtr.limit = 0xffff;
    save->ldtr.attrib = 0x82;
    save->ldtr.limit = 0xffff;
    save->idtr.limit = 0xffff;
    save->tr.limit = 0xffff;
    save->efer = 0x1000;
    save->cr4 = 0x40;
    save->cr0 = 0x10;
    save->dr7 = 0x400;
    save->dr6 = 0xffff0ff0;
    save->rflags = 0x2;
    save->rip = eip & 0xffff;
    save->g_pat = 0x7040600070406;
    save->sev_features = 0x1;
    save->xcr0 = 0x1;

    if (vmm_type == qemu) {
        save->ss.attrib = 0x93;
        save->tr.attrib = 0x8b;
        save->rdx = 0x800f12; // For CPU type EpycV4, will crash for other CPU types
        save->mxcsr = 0x1f80;
        save->x87_fcw = 0x37f;
    } else if (vmm_type == ec2) {
        if (eip == 0xfffffff0) {
            save->cs.attrib = 0x9a;
        }
        save->ss.attrib = 0x92;
        save->tr.attrib = 0x83;
        save->rdx = 0x0;
        save->mxcsr = 0x0;
        save->x87_fcw = 0x0;
    }

}

static const char *
page_type_str(uint8_t type)
{
    switch (type) {
    case SNP_PAGE_TYPE_RESERVED:
        return "SNP_PAGE_TYPE_RESERVED";
    case SNP_PAGE_TYPE_NORMAL:
        return "SNP_PAGE_TYPE_NORMAL";
    case SNP_PAGE_TYPE_VMSA:
        return "SNP_PAGE_TYPE_VMSA";
    case SNP_PAGE_TYPE_ZERO:
        return "SNP_PAGE_TYPE_ZERO";
    case SNP_PAGE_TYPE_UNMEASURED:
        return "SNP_PAGE_TYPE_UNMEASURED";
    case SNP_PAGE_TYPE_SECRETS:
        return "SNP_PAGE_TYPE_SECRETS";
    case SNP_PAGE_TYPE_CPUID:
        return "SNP_PAGE_TYPE_CPUID";
    default:
        return "???";
    }
}

static void
page_info_print(const snp_launch_update_page_info *info)
{
    DEBUG("PAGE INFO:\n");
    print_data_debug(info->digest_cur, sizeof(info->digest_cur), "  digest_cur  ");
    print_data_debug(info->contents, sizeof(info->contents), "  contents    ");
    DEBUG("  length      : 0x%04x\n", info->length);
    DEBUG("  page_type   : 0x%02x (%s)\n", info->page_type, page_type_str(info->page_type));
    DEBUG("  imi_page    : %x\n", info->imi_page);
    DEBUG("  reserved    : 0x%02x\n", info->reserved);
    DEBUG("  reserved2   : 0x%02x\n", info->reserved2);
    DEBUG("  vmpl_1_perms: 0x%02x\n", info->vmpl_1_perms);
    DEBUG("  vmpl_2_perms: 0x%02x\n", info->vmpl_2_perms);
    DEBUG("  vmpl_3_perms: 0x%02x\n", info->vmpl_3_perms);
    DEBUG("  gpa         : 0x%016lx\n", info->gpa);
}

static void
page_info_update(snp_launch_update_page_info *info, const uint8_t *page, uint8_t type, uint64_t gpa)
{
    if (page == NULL)
        memset(info->contents, 0, sizeof(info->contents));
    else
        sha384(info->contents, (uint8_t *)page, 4096);

    ASSERT(sizeof(*info) == 0x70);
    info->length = sizeof(*info);
    info->page_type = type;
    info->imi_page = 0;
    info->reserved = 0;
    info->reserved2 = 0; //0x0f;
    info->vmpl_1_perms = 0;
    info->vmpl_2_perms = 0;
    info->vmpl_3_perms = 0;
    info->gpa = gpa;

    page_info_print(info);

    sha384(info->digest_cur, (uint8_t *)info, sizeof(*info));
}

static uint8_t guid_header[16] = { 0x06, 0xd6, 0x38, 0x94, 0x22, 0x4f, 0xc9, 0x4c,
                                   0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21 };
static uint8_t guid_kernel[16] = { 0x37, 0x94, 0xe7, 0x4d, 0xd2, 0xab, 0x7f, 0x42,
                                   0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b };
static uint8_t guid_initrd[16] = { 0x31, 0xf7, 0xba, 0x44, 0x2f, 0x3a, 0xd7, 0x4b,
                                   0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d };
static uint8_t guid_cmdline[16] = { 0xd8, 0x2d, 0xd0, 0x97, 0x20, 0xbd, 0x94, 0x4c,
                                    0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a };

static void
hashes_init(uint8_t *page, uint8_t *cmdline, size_t cmdline_size, const char *kernel,
            const char *initrd)
{
    struct sev_hash_table *hashes = (void *)(page + 3072);

    ASSERT(sizeof(*hashes) <= 1024);

    memset(page, 0, 4096);
    memcpy(hashes->guid, guid_header, 16);
    hashes->length = sizeof(struct sev_hash_table);
    memcpy(hashes->cmdline.guid, guid_cmdline, 16);
    hashes->cmdline.length = sizeof(struct sev_hash_table_entry);
    sha256(hashes->cmdline.hash, cmdline, cmdline_size);
    memcpy(hashes->initrd.guid, guid_initrd, 16);
    hashes->initrd.length = sizeof(struct sev_hash_table_entry);
    if (initrd) {
        hash_file(EVP_sha256(), hashes->initrd.hash, initrd);
    } else {
        sha256(hashes->initrd.hash, NULL, 0);
    }
    memcpy(hashes->kernel.guid, guid_kernel, 16);
    hashes->kernel.length = sizeof(struct sev_hash_table_entry);
    hash_file(EVP_sha256(), hashes->kernel.hash, kernel);

    DEBUG("cmdline size: %ld\n", cmdline_size);
    print_data_debug(cmdline, cmdline_size, "cmdline");

    print_data_debug(hashes->kernel.hash, 32, "kernel hash");
    print_data_debug(hashes->cmdline.hash, 32, "cmdline hash");
    print_data_debug(hashes->initrd.hash, 32, "initrd hash");
}

int
calculate_mr(uint8_t *mr, const char *ovmf_file, const char *kernel_file, const char *initrd_file,
             const char *cmdline_file, size_t vcpus, vmm_type_t vmm_type)
{
    snp_launch_update_page_info info;
    uint8_t *ovmf = NULL;
    uint8_t *cmdline = NULL;
    size_t ovmf_size = 0;
    size_t cmdline_size = 0;
    uint8_t vmsa[4096];
    uint8_t hashes[4096];
    uint64_t gpa, offset;
    int ret = -1;

    ret = read_file(&ovmf, &ovmf_size, ovmf_file);
    if (ret) {
        printf("Failed to read ovmf file %s\n", ovmf_file);
        goto out;
    }
    DEBUG("ovmf size: %ld\n", ovmf_size);

    if (cmdline_file) {
        uint8_t *tmp = NULL;
        ret = read_file(&tmp, &cmdline_size, cmdline_file);
        if (ret) {
            printf("Failed to read cmdline file %s\n", cmdline_file);
            goto out;
        }
        // add trailing zero
        cmdline = (uint8_t *)calloc(++cmdline_size, sizeof(uint8_t));
        memcpy(cmdline, tmp, cmdline_size - 1);
        free(tmp);
        DEBUG("cmdline size: %ld\n", cmdline_size);
    }

    if (kernel_file) {
        hashes_init(hashes, cmdline, cmdline_size, kernel_file, initrd_file);
    }

    memset(&info, 0, sizeof(info));

    for (offset = 0; offset < ovmf_size; offset += 4096) {
        gpa = 0x100000000 - ovmf_size + offset;
        page_info_update(&info, ovmf + offset, SNP_PAGE_TYPE_NORMAL, gpa);
    }

    for (gpa = 0x00800000; gpa < 0x00809000; gpa += 4096)
        page_info_update(&info, NULL, SNP_PAGE_TYPE_ZERO, gpa);

    for (gpa = 0x0080a000; gpa < 0x0080d000; gpa += 4096)
        page_info_update(&info, NULL, SNP_PAGE_TYPE_ZERO, gpa);

    page_info_update(&info, NULL, SNP_PAGE_TYPE_SECRETS, 0x0080d000);

    if (vmm_type == qemu) {
        page_info_update(&info, NULL, SNP_PAGE_TYPE_CPUID, 0x0080e000);
    }

    if (kernel_file) {
        page_info_update(&info, NULL, SNP_PAGE_TYPE_ZERO, 0x80f000);
        page_info_update(&info, hashes, SNP_PAGE_TYPE_NORMAL, 0x810000);
        for (gpa = 0x00811000; gpa < 0x00820000; gpa += 4096)
            page_info_update(&info, NULL, SNP_PAGE_TYPE_ZERO, gpa);
    } else {
        for (gpa = 0x0080f000; gpa < 0x00820000; gpa += 4096)
            page_info_update(&info, NULL, SNP_PAGE_TYPE_ZERO, gpa);
    }

    if (vmm_type == ec2) {
        page_info_update(&info, NULL, SNP_PAGE_TYPE_CPUID, 0x0080e000);
    }

    vmcb_save_area_init(vmsa, 0xfffffff0, vmm_type);
    page_info_update(&info, vmsa, SNP_PAGE_TYPE_VMSA, 0xfffffffff000);

    vmcb_save_area_init(vmsa, 0x80b004, vmm_type);
    for (size_t i = 1; i < vcpus; i++)
        page_info_update(&info, vmsa, SNP_PAGE_TYPE_VMSA, 0xfffffffff000);


    memcpy(mr, info.digest_cur, SHA384_DIGEST_LENGTH);

out:
    if (cmdline) {
        free(cmdline);
    }
    if (ovmf) {
        free(ovmf);
    }

    return 0;
}