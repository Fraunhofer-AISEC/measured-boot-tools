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

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "MeasureBootPeCoff.h"
#include "Tcg2Dxe.h"
#include "SecMain.h"

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "paths.h"

#define MAX_PCRS 24

typedef struct {
    uint8_t *acpi_tables;
    ssize_t acpi_tables_size;
    uint8_t *acpi_rsdp;
    ssize_t acpi_rsdp_size;
    uint8_t *table_loader;
    ssize_t table_loader_size;
    uint8_t *tpm_log;
    ssize_t tpm_log_size;
} pcr1_config_files_t;

volatile bool debug_output = false;

/**
 * Calculates PCR 0
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 * @param ovmf_file The path to the OVMF.fd file that should be used for the calculations
 */
static int
calculate_pcr0(uint8_t *pcr, eventlog_t *evlog, const char *ovmf_file, const char *dump_pei_path,
    const char *dump_dxe_path)
{
    int ret = -1;
    uint8_t *fvmain_compact_buf = NULL;
    uint8_t *fvmain = NULL;
    uint8_t *ev_separator = NULL;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_S_CRTM_VERSION
    // Note: OEMs should get real CRTM version string and measure it.
    // edk2: https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec
    // edk2: MeasureCRTMVersion()
    // edk2: gEfiMdeModulePkgTokenSpaceGuid.PcdFirmwareVersionString|L""|VOID*|0x00010052
    uint8_t ev_s_crtm_version[2] = { 0 };
    uint8_t hash_ev_s_crtm_version[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_s_crtm_version, (uint8_t *)ev_s_crtm_version,
             sizeof(ev_s_crtm_version));
    evlog_add(evlog, 0, "EV_S_CRTM_VERSION", hash_ev_s_crtm_version,
                 "CRTM Version String");

    DEBUG("Extracting FVMAIN_COMPACT.Fv from OVMF.fd\n");
    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
    if (ret != 0) {
        printf("Failed to load %s\n", ovmf_file);
        goto out;
    }

    // 128 KB Non-volatile data storage, 1712KB FVMAIN_COMPACT consisting of 896 KB PEIFV and 8192 DXEFV
    uint64_t fvmain_compact_start = 128 * 1024;
    uint64_t fvmain_compact_size = 1712 * 1024;
    fvmain_compact_buf = malloc(fvmain_compact_size + 10000);
    if (!fvmain_compact_buf) {
        printf("Failed to allocate memory for FVMAIN_COMPACT.Fv\n");
        ret = -1;
        goto out;
    }
    if (fvmain_compact_start > ovmf_size ||
        fvmain_compact_size > (ovmf_size - fvmain_compact_start)) {
        printf("OVMF smaller than expected (0x%lx, must at least be 0x%lx)\n", ovmf_size,
               fvmain_compact_start + fvmain_compact_size);
        ret = -1;
        goto out;
    }
    memcpy(fvmain_compact_buf, &ovmf_buf[fvmain_compact_start], fvmain_compact_size);

    // Extract Firmware File System (FFS) and lzma-compressed file from FVMAIN_COMPACT
    EFI_FIRMWARE_VOLUME_HEADER *Fv = (EFI_FIRMWARE_VOLUME_HEADER *)fvmain_compact_buf;
    size_t extracted_size = 0;
    fvmain = extract_lzma_fvmain_new(Fv, &extracted_size);
    if (!fvmain) {
        printf("Failed to extract LZMA compressed FVMAIN\n");
        ret = -1;
        goto out;
    }

    // Measure PEIFV
    uint8_t peifv_hash[SHA256_DIGEST_LENGTH];
    ret = measure_peifv(peifv_hash, fvmain, dump_pei_path);
    if (ret) {
        printf("Failed to measure PEIFV\n");
        goto out;
    }
    evlog_add(evlog, 0, "PEIFV", peifv_hash, "OVMF UEFI PEI Firmware Volume");

    // Measure DXEFV
    uint8_t dxefv_hash[SHA256_DIGEST_LENGTH];
    ret = measure_dxefv(dxefv_hash, fvmain, dump_dxe_path);
    if (ret) {
        printf("Failed to measure DXEFV\n");
        goto out;
    }
    evlog_add(evlog, 0, "DXEFV", dxefv_hash, "OVMF UEFI DXE Firmware Volume");

    // EV_SEPARATOR
    ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        ret = -1;
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, 0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    // Extend all values
    hash_extend(EVP_sha256(), pcr, hash_ev_s_crtm_version, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, peifv_hash, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, dxefv_hash, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    ret = 0;

out:
    if (fvmain_compact_buf)
        free(fvmain_compact_buf);
    if (ovmf_buf)
        free(ovmf_buf);
    if (fvmain)
        free(fvmain);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates PCR 1
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr1(uint8_t *pcr, eventlog_t *evlog, pcr1_config_files_t *cfg)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
    if (cfg->table_loader_size > 0) {
        uint8_t hash_table_loader[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_table_loader, cfg->table_loader, cfg->table_loader_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_table_loader, "etc/table-loader");
        hash_extend(EVP_sha256(), pcr, hash_table_loader, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
    if (cfg->acpi_rsdp_size > 0) {
        uint8_t hash_acpi_rsdp[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_acpi_rsdp, cfg->acpi_rsdp, cfg->acpi_rsdp_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_rsdp, "etc/acpi/rsdp");
        hash_extend(EVP_sha256(), pcr, hash_acpi_rsdp, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/tpm/log
    if (cfg->tpm_log_size > 0) {
        uint8_t hash_tpm_log[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_tpm_log, cfg->tpm_log, cfg->tpm_log_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_tpm_log, "etc/tpm/log");
        hash_extend(EVP_sha256(), pcr, hash_tpm_log, SHA256_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
    if (cfg->acpi_tables_size > 0) {
        uint8_t hash_acpi_tables[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_acpi_tables, cfg->acpi_tables, cfg->acpi_tables_size);
        evlog_add(evlog, 1, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_tables, "etc/acpi/tables");
        hash_extend(EVP_sha256(), pcr, hash_acpi_tables, SHA256_DIGEST_LENGTH);
    }

    // EV_EFI_VARIABLE_BOOT TODO replace hardcoded data
    uint8_t efi_variable_boot[2] = { 0 };
    uint8_t hash_efi_variable_boot[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_variable_boot, (uint8_t *)efi_variable_boot,
             sizeof(efi_variable_boot));
    evlog_add(evlog, 1, "EV_EFI_VARIABLE_BOOT", hash_efi_variable_boot,
                 "Hash EFI Variable Boot: Hash(0000)");
    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot, SHA256_DIGEST_LENGTH);

    // EV_EFI_VARIABLE_BOOT TODO replace hardcoded data
    long len = 0;
    uint8_t *efi_variable_boot2 = OPENSSL_hexstr2buf(
        "090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400",
        &len);
    if (!efi_variable_boot2) {
        printf("Failed to allocate memory for efi boot variable\n");
        goto out;
    }
    uint8_t hash_efi_variable_boot2[SHA256_DIGEST_LENGTH];
    // Hash: 3197be1e300fa1600d1884c3a4bd4a90a15405bfb546cf2e6cf6095f8c362a93
    hash_buf(EVP_sha256(), hash_efi_variable_boot2, (uint8_t *)efi_variable_boot2, len);
    evlog_add(
        evlog, 1, "EV_EFI_VARIABLE_BOOT", hash_efi_variable_boot2,
        "HASH(090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400)");
    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot2, SHA256_DIGEST_LENGTH);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, 1, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    ret = 0;

out:
    if (efi_variable_boot2)
        OPENSSL_free(efi_variable_boot2);
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates PCR 2
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of th PCR
 * @param evlog The event log to record the extend operations in
 * @param ovmf_file The path to the OVMF.fd file that should be used for the calculations
 */
static int
calculate_pcr2(uint8_t *pcr, eventlog_t *evlog, char **drivers, size_t num_drivers)
{
    int ret = -1;
    uint8_t *ev_separator = NULL;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_EFI_BOOT_SERVICES_DRIVER
    for (size_t i = 0; i < num_drivers; i++) {
        uint8_t *driver_buf = NULL;
        uint64_t driver_size = 0;
        uint8_t hash_driver[SHA256_DIGEST_LENGTH] = { 0 };

        ret = LoadPeImage(&driver_buf, &driver_size, drivers[i]);
        if (ret != 0) {
            printf("Failed to load UEFI driver image %s\n", drivers[i]);
            return -1;
        }

        EFI_STATUS status = MeasurePeImage(hash_driver, driver_buf, driver_size);
        if (EFI_ERROR(status)) {
            printf("printf: Failed to measure PE Image: %llx\n", status);
            return -1;
        }
        evlog_add(evlog, 2, "EV_EFI_BOOT_SERVICES_DRIVER", hash_driver,
                     basename((char *)drivers[i]));

        hash_extend(EVP_sha256(), pcr, hash_driver, SHA256_DIGEST_LENGTH);

        free(driver_buf);
    }

    // EV_SEPARATOR
    ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        ret = -1;
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, 2, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    ret = 0;

out:
    if (ev_separator)
        OPENSSL_free(ev_separator);

    return ret;
}

/**
 * Calculates PCR 3
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr3(uint8_t *pcr, eventlog_t *evlog)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 3, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 4 for systems without bootloader
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 * @param kernel_file The path of the kernel image (.bzImage) to use for the calculations
 */
static int
calculate_pcr4(uint8_t *pcr, eventlog_t *evlog, const char *kernel_file,
               config_t *config)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_EFI_BOOT_SERVICES_APPLICATION
    uint8_t hash_kernel[SHA256_DIGEST_LENGTH] = { 0 };
    uint8_t *kernel_buf = NULL;
    uint64_t kernel_size = 0;

    ret = LoadPeImage(&kernel_buf, &kernel_size, kernel_file);
    if (ret != 0) {
        printf("Failed to load kernel image %s\n", kernel_file);
        return -1;
    }

    ret = config_prepare_kernel_pecoff(kernel_buf, kernel_size, config);
    if (ret != 0) {
        printf("Failed to prepare kernel PE/COFF image\n");
        goto out;
    }

    EFI_STATUS status = MeasurePeImage(hash_kernel, kernel_buf, kernel_size);
    if (EFI_ERROR(status)) {
        printf("printf: Failed to measure PE Image: %llx\n", status);
        goto out;
    }
    evlog_add(evlog, 4, "EV_EFI_BOOT_SERVICES_APPLICATION", hash_kernel,
                 basename((char *)kernel_file));

    // TCG PCClient Firmware Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    // EV_EFI_ACTION "Calling EFI Application from Boot Option"
    char *action_data = "Calling EFI Application from Boot Option";
    uint8_t hash_efi_action[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action, (uint8_t *)action_data, strlen(action_data));
    evlog_add(evlog, 4, "EV_EFI_ACTION", hash_efi_action,
                 "HASH('Calling EFI Application from Boot Option')");

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 4, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_kernel, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_efi_action, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    ret = 0;

out:
    free(kernel_buf);

    return ret;
}

/**
 * Calculates PCR 5 for systems without bootloader
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr5(uint8_t *pcr, eventlog_t *evlog)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 5, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    // EV_EFI_ACTION "Exit Boot Services Invocation"
    char *efi_action_boot_invocation = "Exit Boot Services Invocation";
    uint8_t hash_efi_action_boot_invocation[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action_boot_invocation, (uint8_t *)efi_action_boot_invocation,
             strlen(efi_action_boot_invocation));
    evlog_add(evlog, 5, "EV_EFI_ACTION", hash_efi_action_boot_invocation,
                 "HASH('Exit Boot Services Invocation')");

    // EV_EFI_ACTION "Exit Boot Services Returned with Success"
    char *efi_action_boot_exit = "Exit Boot Services Returned with Success";
    uint8_t hash_efi_action_boot_exit[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action_boot_exit, (uint8_t *)efi_action_boot_exit,
             strlen(efi_action_boot_exit));
    evlog_add(evlog, 5, "EV_EFI_ACTION", hash_efi_action_boot_exit,
                 "HASH('Exit Boot Services Returned with Success')");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_efi_action_boot_invocation, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_efi_action_boot_exit, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 6
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr6(uint8_t *pcr, eventlog_t *evlog)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 6, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 7
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr7(uint8_t *pcr, eventlog_t *evlog)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // TODO: Support secure boot

    MeasureAllSecureVariables(pcr, evlog);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 7, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 8 for systems without grub
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr8(uint8_t *pcr, eventlog_t *evlog)
{
    (void)evlog;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 9
 *
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
static int
calculate_pcr9(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, char **paths, size_t num_paths)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    if (cmdline) {
        // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
        size_t cmdline_len = 0;
        char16_t *wcmdline = convert_to_char16(cmdline, &cmdline_len);
        if (!wcmdline) {
            printf("Failed to convert to wide character string\n");
            return -1;
        }

        uint8_t hash_ev_event_tag[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_ev_event_tag, (uint8_t *)wcmdline, cmdline_len);
        evlog_add(evlog, 9, "EV_EVENT_TAG", hash_ev_event_tag, cmdline);

        hash_extend(EVP_sha256(), pcr, hash_ev_event_tag, SHA256_DIGEST_LENGTH);
    }

    if (paths) {
        ret = calculate_paths(pcr, evlog, paths, num_paths);
        if (ret) {
            printf("Failed to calculate paths\n");
            return ret;
        }
    }

    ret = 0;

    return ret;
}

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s --pcrs <num[,num...]> [options...]\n", progname);
    printf("\t-k,  --kernel <file>\t\tThe filename of the kernel image\n");
    printf("\t-r,  --ramdisk <file>\t\tThe filename of the initramfs\n");
    printf("\t-o,  --ovmf <file>\t\tThe filename of the OVMF.fd file\n");
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-e,  --eventlog\t\t\tPrint detailed eventlog\n");
    printf("\t-s,  --summary\t\t\tPrint final PCR values\n");
    printf("\t     --aggregate\t\tPrint aggregate PCR value\n");
    printf("\t-p,  --pcrs <num[,num...]>\tPCRs to be calculated\n");
    printf("\t-d,  --driver\t\t\tPath to 3rd party UEFI driver file (multiple possible)\n");
    printf("\t     --verbose\t\t\tPrint verbose debug output\n");
    printf("\t-c,  --config\t\t\tPath to configuration file\n");
    printf("\t     --cmdline\t\t\tKernel commandline, required for some PCR 9 calculations\n");
    printf("\t-a,  --acpirsdp\t\t\tPath to QEMU etc/acpi/rsdp file for PCR1\n");
    printf("\t-t,  --acpitables\t\tPath to QEMU etc/acpi/tables file for PCR1\n");
    printf("\t-l,  --tableloader\t\tPath to QEMU etc/table-loader file for PCR1\n");
    printf("\t-g,  --tpmlog\t\t\tPath to QEMU etc/tpm/log file for PCR1\n");
    printf("\t     --path\t\t\t Path to folder or file to be extended into PCR9 (multiple possible)\n");
    printf("\t     --dumppei\t\t\t Optional path to folder to dump the PEIFV that was hashed\n");
    printf("\t     --dumpdxe\t\t\t Optional path to folder to dump the DXEFV that was hashed\n");
    printf("\n");
}

static bool
contains(uint32_t *pcr_nums, uint32_t len, uint32_t value)
{
    for (uint32_t i = 0; i < len; i++) {
        if (pcr_nums[i] == value) {
            return true;
        }
    }
    return false;
}

long
file_size(const char *filename)
{
    struct stat st = { 0 };
    int ret = stat(filename, &st);
    if (ret < 0) {
        return -1;
    }
    return st.st_size;
}

int
main(int argc, char *argv[])
{
    int ret = -1;
    const char *config_file = NULL;
    const char *kernel = NULL;
    const char *ramdisk = NULL;
    const char *cmdline = NULL;
    const char *ovmf = NULL;
    const char *dump_pei_path = NULL;
    const char *dump_dxe_path = NULL;
    bool print_event_log = false;
    bool print_summary = false;
    bool print_aggregate = false;
    uint32_t *pcr_nums = NULL;
    size_t len_pcr_nums = 0;
    const char *progname = argv[0];
    char *pcr_str = NULL;
    char **uefi_drivers = NULL;
    size_t num_uefi_drivers = 0;
    char **paths = NULL;
    size_t num_paths = 0;
    eventlog_t evlog = {
        .format = FORMAT_TEXT,
        .log = { 0 }
    };
    pcr1_config_files_t pcr1_cfg = {
        .acpi_rsdp_size = -1,
        .acpi_tables_size = -1,
        .table_loader_size = -1,
        .tpm_log_size = -1
     };

    argv++;
    argc--;

    if (argc < 2) {
        print_usage(progname);
        return -1;
    }

    while (argc > 0) {
        if ((!strcmp(argv[0], "-c") || !strcmp(argv[0], "--config")) && argc >= 2) {
            config_file = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-k") || !strcmp(argv[0], "--kernel")) && argc >= 2) {
            kernel = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--cmdline") && argc >= 2) {
            cmdline = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-r") || !strcmp(argv[0], "--ramdisk")) && argc >= 2) {
            ramdisk = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-o") || !strcmp(argv[0], "--ovmf")) && argc >= 2) {
            ovmf = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-d") || !strcmp(argv[0], "--driver")) && argc >= 2) {
            uefi_drivers = (char **)realloc(uefi_drivers, sizeof(char *) * (num_uefi_drivers + 1));
            uefi_drivers[num_uefi_drivers++] = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-f") || !strcmp(argv[0], "--format")) && argc >= 2) {
            if (!strcmp(argv[1], "json")) {
                evlog.format = FORMAT_JSON;
            } else if (!strcmp(argv[1], "text")) {
                evlog.format = FORMAT_TEXT;
            } else {
                printf("Unknown format '%s'\n", argv[1]);
                print_usage(progname);
                goto out;
            }
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-e") || !strcmp(argv[0], "--eventlog"))) {
            print_event_log = true;
            argv++;
            argc--;
        } else if ((!strcmp(argv[0], "-s") || !strcmp(argv[0], "--summary"))) {
            print_summary = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "--aggregate")) {
            print_aggregate = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "--dumppei")) {
            dump_pei_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--dumpdxe")) {
            dump_dxe_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-p") || !strcmp(argv[0], "--pcrs")) && argc >= 2) {
            pcr_str = (char *)malloc(strlen(argv[1]) + 1);
            if (!pcr_str) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(pcr_str, argv[1], strlen(argv[1]) + 1);
            char *pch = strtok(pcr_str, ",");
            while (pch) {
                pcr_nums = (uint32_t *)realloc(pcr_nums, sizeof(uint32_t) * (len_pcr_nums + 1));
                pcr_nums[len_pcr_nums] = (uint32_t)strtol(pch, NULL, 0);
                pch = strtok(NULL, ",");
                len_pcr_nums++;
            }
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else if ((!strcmp(argv[0], "-a") || !strcmp(argv[0], "--acpirsdp")) && argc >= 2) {
            pcr1_cfg.acpi_rsdp_size = file_size(argv[1]);
            if (pcr1_cfg.acpi_rsdp_size < 0) {
                printf("Failed to get file size of ACPI RSDP file %s\n", argv[1]);
                goto out;
            }
            pcr1_cfg.acpi_rsdp = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-t") || !strcmp(argv[0], "--acpitables")) && argc >= 2) {
            pcr1_cfg.acpi_tables_size = file_size(argv[1]);
            if (pcr1_cfg.acpi_tables_size < 0) {
                printf("Failed to get file size of ACPI tables file %s\n", argv[1]);
                goto out;
            }
            pcr1_cfg.acpi_tables = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-l") || !strcmp(argv[0], "--tableloader")) && argc >= 2) {
            pcr1_cfg.table_loader_size = file_size(argv[1]);
            if (pcr1_cfg.table_loader_size < 0) {
                printf("Failed to get file size of table loader file %s\n", argv[1]);
                goto out;
            }
            pcr1_cfg.table_loader = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-g") || !strcmp(argv[0], "--tpmlog")) && argc >= 2) {
            pcr1_cfg.tpm_log_size = file_size(argv[1]);
            if (pcr1_cfg.tpm_log_size < 0) {
                printf("Failed to get file size of TPM log file %s\n", argv[1]);
                goto out;
            }
            pcr1_cfg.tpm_log = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "--path")) && argc >= 2) {
            paths = (char **)realloc(paths, sizeof(char *) * (num_paths + 1));
            paths[num_paths] = argv[1];
            if (paths[num_paths][strlen(paths[num_paths]) - 1] == '/') {
                paths[num_paths][strlen(paths[num_paths]) - 1] = '\0';
            }
            num_paths++;
            argv += 2;
            argc -= 2;
        } else {
            printf("Invalid option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    if (!config_file && contains(pcr_nums, len_pcr_nums, 4)) {
        printf("Config file must be specified to calculate PCR4\n");
        print_usage(progname);
        goto out;
    }

    if (pcr1_cfg.acpi_rsdp_size == -1  && contains(pcr_nums, len_pcr_nums, 1)) {
        printf("PCR1 Config file ACPI RSDP must be specified to calculate PCR1\n");
        print_usage(progname);
        goto out;
    }
    if (pcr1_cfg.acpi_tables_size == -1  && contains(pcr_nums, len_pcr_nums, 1)) {
        printf("PCR1 Config file ACPI tables must be specified to calculate PCR1\n");
        print_usage(progname);
        goto out;
    }
    if (pcr1_cfg.table_loader_size == -1  && contains(pcr_nums, len_pcr_nums, 1)) {
        printf("PCR1 Config file table loader must be specified to calculate PCR1\n");
        print_usage(progname);
        goto out;
    }
    if (pcr1_cfg.tpm_log_size == -1  && contains(pcr_nums, len_pcr_nums, 1)) {
        printf("PCR1 Config file TPM log must be specified to calculate PCR1\n");
        print_usage(progname);
        goto out;
    }

    if (!kernel && contains(pcr_nums, len_pcr_nums, 4)) {
        printf("Kernel must be specified to calculate PCR4\n");
        print_usage(progname);
        goto out;
    }
    if (!ovmf && contains(pcr_nums, len_pcr_nums, 0)) {
        printf("OVMF must specified for calculating PCR0\n");
        print_usage(progname);
        goto out;
    }

    // Load configuration variables
    config_t config = { 0 };
    if (config_file) {
        ret = config_load(&config, config_file);
        if (ret != 0) {
            printf("Failed to load configuration\n");
            goto out;
        }
    }

    DEBUG("Calculating PCRs [ ");
    for (uint32_t i = 0; i < len_pcr_nums; i++) {
        DEBUG("%d ", pcr_nums[i]);
    }
    DEBUG("] using:\n");
    DEBUG("\tKernel:    %s\n", kernel);
    if (ramdisk) {
        DEBUG("\tInitramfs: %s\n", ramdisk);
    } if (cmdline) {
        DEBUG("\tCmdline: %s\n", cmdline);
    }
    DEBUG("\tOVMF: %s\n", ovmf);
    DEBUG("\tEventlog:  %d\n", print_event_log);
    DEBUG("\tSummary:   %d\n", print_summary);
    DEBUG("\tAggregate: %d\n", print_aggregate);
    for (size_t i = 0; i < num_uefi_drivers; i++) {
        DEBUG("\tUEFI driver: %s\n", uefi_drivers[i]);
    }
    for (size_t i = 0; i < num_paths; i++) {
        DEBUG("\tPath: %s\n", paths[i]);
    }

    uint8_t pcr[MAX_PCRS][SHA256_DIGEST_LENGTH];

    if (contains(pcr_nums, len_pcr_nums, 0)) {
        if (calculate_pcr0(pcr[0], &evlog, ovmf, dump_pei_path, dump_dxe_path)) {
            printf("Failed to calculate event log for PCR 0\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 1)) {
        if (calculate_pcr1(pcr[1], &evlog, &pcr1_cfg)) {
            printf("Failed to calculate event log for PCR 1\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 2)) {
        if (calculate_pcr2(pcr[2], &evlog, uefi_drivers, num_uefi_drivers)) {
            printf("Failed to calculate event log for PCR 2\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 3)) {
        if (calculate_pcr3(pcr[3], &evlog)) {
            printf("Failed to calculate event log for PCR 3\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 4)) {
        if (calculate_pcr4(pcr[4], &evlog, kernel, &config)) {
            printf("Failed to calculate event log for PCR 4\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 5)) {
        if (calculate_pcr5(pcr[5], &evlog)) {
            printf("Failed to calculate event log for PCR 5\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 6)) {
        if (calculate_pcr6(pcr[6], &evlog)) {
            printf("Failed to calculate event log for PCR 6\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 7)) {
        if (calculate_pcr7(pcr[7], &evlog)) {
            printf("Failed to calculate event log for PCR 7\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 8)) {
        if (calculate_pcr8(pcr[8], &evlog)) {
            printf("Failed to calculate event log for PCR 8\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 9)) {
        if (calculate_pcr9(pcr[9], &evlog, cmdline, paths, num_paths)) {
            printf("Failed to calculate event log for PCR 9\n");
            goto out;
        }
    }

    // Print event log with all extend operations if requested
    if (print_event_log) {
        DEBUG("\nPCR EVENT LOG: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < len_pcr_nums; i++) {
            if (!evlog.log[pcr_nums[i]]) {
                printf("Failed to print Event Log for PCR %d\n", pcr_nums[i]);
                goto out;
            }
            // Remove last colon on final event log entry if format is json
            if ((evlog.format == FORMAT_JSON) && (i == (len_pcr_nums)-1)) {
                evlog.log[pcr_nums[i]][strlen(evlog.log[pcr_nums[i]]) - 2] = ']';
                evlog.log[pcr_nums[i]][strlen(evlog.log[pcr_nums[i]]) - 1] = '\0';
            }
            printf("%s", evlog.log[pcr_nums[i]]);
        }
        printf("\n");
    }

    // Print final PCRs if requested
    if (print_summary) {
        DEBUG("\nPCR SUMMARY: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (uint32_t i = 0; i < len_pcr_nums; i++) {
            if (evlog.format == FORMAT_JSON) {
                printf(
                    "{\n\t\"type\":\"TPM Reference Value\",\n\t\"name\":\"PCR%d\",\n\t\"pcr\":%d,\n\t\"sha256\":\"",
                    pcr_nums[i], pcr_nums[i]);
                print_data_no_lf(pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
                printf("\"\n\t\"description\":\"PCR%d\"\n}", pcr_nums[i]);
                if (i < len_pcr_nums - 1) {
                    printf(",\n");
                }
            } else if (evlog.format == FORMAT_TEXT) {
                printf("PCR%d: ", pcr_nums[i]);
                print_data(pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
            } else {
                printf("Unknown output format\n");
                goto out;
            }
        }
        if (evlog.format == FORMAT_JSON) {
            printf("]\n");
        }
    }

    // Print aggregated PCR value over all specified PCRs if requested
    if (print_aggregate) {
        DEBUG("\nPCR AGGREGATE: \n");
        uint8_t aggregate[SHA256_DIGEST_LENGTH] = { 0x0 };

        EVP_MD_CTX *ctx;
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (uint32_t i = 0; i < len_pcr_nums; i++) {
            EVP_DigestUpdate(ctx, pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH);
        }
        EVP_DigestFinal_ex(ctx, aggregate, NULL);
        EVP_MD_CTX_free(ctx);

        if (evlog.format == FORMAT_JSON) {
            printf("{\n\t\"type\":\"TPM PCR Aggregate\",\n\t\"sha256\":\"");
            print_data_no_lf(aggregate, SHA256_DIGEST_LENGTH, NULL);
            printf("\"\n}\n");
        } else if (evlog.format == FORMAT_TEXT) {
            printf("PCR Aggregate: ");
            print_data(aggregate, SHA256_DIGEST_LENGTH, NULL);
        } else {
            printf("Unknown output format\n");
            goto out;
        }
    }

    ret = 0;

out:
    if (pcr_nums)
        free(pcr_nums);
    if (pcr_str)
        free(pcr_str);
    for (size_t i = 0; i < MAX_PCRS; i++) {
        if (evlog.log[i]) {
            free(evlog.log[i]);
        }
    }
    if (uefi_drivers)
        free(uefi_drivers);
    if (pcr1_cfg.acpi_rsdp)
        free(pcr1_cfg.acpi_rsdp);
    if (pcr1_cfg.acpi_tables)
        free(pcr1_cfg.acpi_tables);
    if (pcr1_cfg.table_loader)
        free(pcr1_cfg.table_loader);
    if (pcr1_cfg.tpm_log)
        free(pcr1_cfg.tpm_log);

    return ret;
}
