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

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
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

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "td_hob.h"
#include "mrtd.h"
#include "efi_boot.h"
#include "secureboot.h"
#include "mrs.h"

extern EFI_GUID gEfiImageSecurityDatabaseGuid;

/**
 * Calculates the measurement register for the TDX SEAM module (MRSEAM)
 *
 * The MRTD contains the digest of the TDX-module as measured by the SEAM loader
 *
 */
int
calculate_mrseam(uint8_t *mr, eventlog_t *evlog, const char *tdx_module, const char *mrseam)
{
    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    if (tdx_module) {

        uint8_t hash_mrseam[SHA384_DIGEST_LENGTH];
        int ret = hash_file(EVP_sha384(), hash_mrseam, tdx_module);
        if (ret) {
            printf("Failed to measure the TDX-module\n");
            return -1;
        }

        evlog_add(evlog, INDEX_MRSEAM, "TDX-Module", hash_mrseam, "SEAMLDR Measurement: TDX-Module");
        memcpy(mr, hash_mrseam, SHA384_DIGEST_LENGTH);

    } else if (mrseam) {

       uint8_t hash_mrseam[SHA384_DIGEST_LENGTH];
        int ret = convert_hex_to_bin(mrseam, strlen(mrseam), hash_mrseam, sizeof(hash_mrseam));
        if (ret) {
            printf("Failed to convert MRTD hash\n");
            return ret;
        }

        evlog_add(evlog, INDEX_MRSEAM, "TDX-Module", hash_mrseam, "SEAMLDR Measurement: TDX-Module");
        memcpy(mr, hash_mrseam, SHA384_DIGEST_LENGTH);

    } else {
        printf("Neither TDX-Module nor MRSEAM hash specified\n");
    }

    return 0;
}

/**
 * Calculates the TDX Build-Time Measurement Register (MRTD)
 *
 * The MRTD contains the digest of the OVMF as hashed by the Intel TDX module.
 *
 */
int
calculate_mrtd(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file, const char *mrtd, const char *qemu_version)
{
    int ret = -1;
    uint8_t *ovmf_buf = NULL;

    DEBUG("Calculating MRTD...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    if (ovmf_file)  {

        uint64_t ovmf_size = 0;
        ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
        if (ret) {
            goto out;
        }

        uint8_t hash_mrtd[SHA384_DIGEST_LENGTH];
        ret = measure_ovmf(hash_mrtd, ovmf_buf, ovmf_size, qemu_version);
        if (ret) {
            printf("Failed to measure ovmf\n");
            goto out;
        }

        evlog_add(evlog, INDEX_MRTD, "OVMF", hash_mrtd,
                "TDX Module Measurement: Initial TD contents (OVMF)");
        memcpy(mr, hash_mrtd, SHA384_DIGEST_LENGTH);

        ret = 0;
    } else if (mrtd) {

        uint8_t hash_mrtd[SHA384_DIGEST_LENGTH];
        ret = convert_hex_to_bin(mrtd, strlen(mrtd), hash_mrtd, sizeof(hash_mrtd));
        if (ret) {
            printf("Failed to convert MRTD hash\n");
            goto out;
        }

        evlog_add(evlog, INDEX_MRTD, "Firmware", hash_mrtd,
                "TDX Module Measurement: Initial TD contents (firmware)");
        memcpy(mr, hash_mrtd, SHA384_DIGEST_LENGTH);

    } else {
        printf("Neither OVMF nor MRTD hash specified\n");
    }

out:
    if (ovmf_buf)
        free(ovmf_buf);

    return ret;
}

/**
 * Calculates RTMR0
 *
 * RTMR0 contains the following artifacts:
 * - EFI TD handoff block
 * - EFI Configuration FV
 * - EFI Secure Boot variables
 * - QEMU FW Cfg Files as passed to OVMF
 * - EFI Boot variables
 */
int
calculate_rtmr0(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file,
                acpi_files_t *cfg, const char *ovmf_version,
                uint16_t *boot_order, size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx,
                const char *secure_boot, const char *pk, const char *kek, const char *db, const char *dbx)
{
    int ret = -1;
    long len = 0;

    DEBUG("Calculating RTMR0...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // Measure EFI TD Handoff Block:
    // UEFI Platform Initialization Specification, Vol. 3, Chapter 5 5 HOB Code Definitions
    len = get_td_hob_size();
    uint8_t td_hob[len];
    ret = create_td_hob(td_hob, len);
    if (ret) {
        return -1;
    }
    uint8_t hash_td_hob[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_td_hob, td_hob, len);
    evlog_add(evlog, INDEX_RTMR0, "TD Hob", hash_td_hob,
              "TD Hob passed from host VMM to guest firmware");
    hash_extend(EVP_sha384(), mr, hash_td_hob, SHA384_DIGEST_LENGTH);

    // Configuration Firmware Volume (CFV)
    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    if (ovmf_file) {
        ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
        if (ret) {
            printf("Failed to load %s\n", ovmf_file);
            goto out;
        }
        uint8_t hash_cfv[SHA384_DIGEST_LENGTH];
        ret = measure_cfv(hash_cfv, ovmf_buf, ovmf_size);
        if (ret) {
            printf("Failed to measure ovmf\n");
            goto out;
        }
        evlog_add(evlog, INDEX_RTMR0, "Configuration FV", hash_cfv, "Configuration Firmware Volume");
        hash_extend(EVP_sha384(), mr, hash_cfv, SHA384_DIGEST_LENGTH);
    }

    // Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
    ret = measure_secure_boot_variables(EVP_sha384(), mr, INDEX_RTMR0, evlog, secure_boot, pk, kek, db, dbx);
    if (ret) {
        printf("Failed to measure secure boot variables\n");
        goto out;
    }

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        goto out;
    }
    uint8_t hash_ev_separator[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, INDEX_RTMR0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
    hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);

    // EV_PLATFORM_CONFIG_FLAGS: ACPI tables
    ret = calculate_acpi_tables(EVP_sha384(), mr, INDEX_RTMR0, evlog, cfg);
    if (ret) {
        printf("failed to calculate acpi tables\n");
        goto out;
    }

    // EV_EFI_VARIABLE_BOOT boot variables
    ret = calculate_efi_boot_vars(EVP_sha384(), mr, INDEX_RTMR0, evlog, boot_order, len_boot_order, bootxxxx, num_bootxxxx);
    if (ret) {
        printf("Failed to calculate EFI boot variables\n");
        goto out;
    }

    // Terminating EV_SEPARATOR is extended only in edk2-stable202408.01
    if (!strcmp(ovmf_version, "edk2-stable202408.01")) {
        // EV_SEPARATOR
        hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
        evlog_add(evlog, INDEX_RTMR0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
        hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);
    }

    ret = 0;

out:
    if (ovmf_buf)
        free(ovmf_buf);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates RTMR1
 *
 * RTMR1 contains the Linux kernel PE/COFF image measurement as well as some boot strings.
 *
 */
int
calculate_rtmr1(uint8_t *mr, eventlog_t *evlog, const char *kernel_file, const char *config_file,
                const char *dump_kernel_path, const char *ovmf_version)
{
    int ret = -1;

    DEBUG("Calculating RTMR1...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // Measure kernel
    uint8_t hash_kernel[SHA384_DIGEST_LENGTH] = { 0 };
    uint8_t *kernel_buf = NULL;
    uint64_t kernel_size = 0;

    ret = LoadPeImage(&kernel_buf, &kernel_size, kernel_file);
    if (ret != 0) {
        goto out;
    }

    if (config_file) {
        // Load configuration variables
        config_t config = { 0 };
        if (config_file) {
            ret = config_load(&config, config_file);
            if (ret != 0) {
                printf("Failed to load configuration\n");
                goto out;
            }
        }

        ret = config_prepare_kernel_pecoff(kernel_buf, kernel_size, &config);
        if (ret != 0) {
            printf("Failed to prepare kernel PE/COFF image\n");
            goto out;
        }
    }

    EFI_STATUS status = MeasurePeImage(EVP_sha384(), hash_kernel, kernel_buf, kernel_size);
    if (EFI_ERROR(status)) {
        printf("printf: Failed to measure PE Image: %llx\n", status);
        goto out;
    }
    evlog_add(evlog, INDEX_RTMR1, basename((char *)kernel_file), hash_kernel,
              "Linux Kernel PE/COFF Image");

    hash_extend(EVP_sha384(), mr, hash_kernel, SHA384_DIGEST_LENGTH);

    if (dump_kernel_path) {
        if (write_file(kernel_buf, kernel_size, dump_kernel_path)) {
            printf("Failed to write kernel to %s\n", dump_kernel_path);
            goto out;
        }
        DEBUG("Wrote PEIFV to %s\n", dump_kernel_path);
    }

    // TCG PCClient Firmware Spec:
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    char *action_data0 = EFI_CALLING_EFI_APPLICATION;
    uint8_t hash_efi_action0[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action0, (uint8_t *)action_data0, strlen(action_data0));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action0, action_data0);
    hash_extend(EVP_sha384(), mr, hash_efi_action0, SHA384_DIGEST_LENGTH);

    // Terminating EV_SEPARATOR is extended only in newer versions
    uint8_t *ev_separator = NULL;
    if (strcmp(ovmf_version, "edk2-stable202408.01")) {
        ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
        if (!ev_separator) {
            printf("Failed to allocate memory for ev separator\n");
            goto out;
        }
        uint8_t hash_ev_separator[SHA384_DIGEST_LENGTH];
        hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
        evlog_add(evlog, INDEX_RTMR1, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
        hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);
    }

    char *action_data1 = EFI_EXIT_BOOT_SERVICES_INVOCATION;
    uint8_t hash_efi_action1[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action1, (uint8_t *)action_data1, strlen(action_data1));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action1, action_data1);
    hash_extend(EVP_sha384(), mr, hash_efi_action1, SHA384_DIGEST_LENGTH);

    char *action_data2 = EFI_EXIT_BOOT_SERVICES_SUCCEEDED;
    uint8_t hash_efi_action2[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action2, (uint8_t *)action_data2, strlen(action_data2));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action2, action_data2);
    hash_extend(EVP_sha384(), mr, hash_efi_action2, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (kernel_buf)
        OPENSSL_free(kernel_buf);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates RTMR2
 *
 * RTMR2 contains the Linux kernel command line.
 *
 */
int
calculate_rtmr2(uint8_t *mr, eventlog_t *evlog, const char *cmdline_file, size_t trailing_zeros, bool strip_newline)
{
    int ret = -1;

    DEBUG("Calculating RTMR2...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
    DEBUG("Reading cmdline from: %s\n", cmdline_file);

    uint8_t *cmdline_buf;
    size_t cmdline_size = 0;
    ret = read_file(&cmdline_buf, &cmdline_size, cmdline_file);
    if (ret != 0 || cmdline_size == 0) {
        printf("Failed to load %s\n", cmdline_file);
        return -1;
    }

    // Strip trailing newline if specified
    if (strip_newline && cmdline_buf[cmdline_size - 1] == '\n') {
        cmdline_buf[cmdline_size - 1] = '\0';
        cmdline_size--;
    }

    DEBUG("cmdline size: %ld\n", cmdline_size);

    size_t cmdline_len = 0;
    char16_t *wcmdline =
        convert_to_char16((const char *)cmdline_buf, cmdline_size, &cmdline_len, trailing_zeros);
    if (!wcmdline) {
        printf("Failed to convert to wide character string\n");
        goto out;
    }

    char *cmdline_str = (char *)malloc(cmdline_size + 1);
    memset(cmdline_str, 0x0, cmdline_size + 1);
    memcpy(cmdline_str, cmdline_buf, cmdline_size);

    uint8_t hash_ev_event_tag[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_ev_event_tag, (uint8_t *)wcmdline, cmdline_len);
    evlog_add(evlog, INDEX_RTMR2, "EV_EVENT_TAG", hash_ev_event_tag, cmdline_str);

    hash_extend(EVP_sha384(), mr, hash_ev_event_tag, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (cmdline_buf) {
        free(cmdline_buf);
    }
    if (cmdline_str) {
        free(cmdline_str);
    }
    if (wcmdline) {
        free(wcmdline);
    }

    return ret;
}

/**
 * Calculates RTMR3
 *
 * RTMR3 is currently empty.
 *
 */
int
calculate_rtmr3(uint8_t *mr, eventlog_t *evlog)
{
    (void)evlog;

    int ret = -1;

    DEBUG("Calculating RTMR3...\n");

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    ret = 0;

    return ret;
}