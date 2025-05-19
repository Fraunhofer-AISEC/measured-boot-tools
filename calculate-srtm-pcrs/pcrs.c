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
#include "ImageAuthentication.h"

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "paths.h"
#include "efi_boot.h"
#include "pcrs.h"
#include "gpt.h"
#include "acpi.h"

/**
 * Calculates PCR 0
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 * @param ovmf_file The path to the OVMF.fd file that should be used for the calculations
 */
int
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
    evlog_add(evlog, 0, "EV_S_CRTM_VERSION", hash_ev_s_crtm_version, "CRTM Version String");
    hash_extend(EVP_sha256(), pcr, hash_ev_s_crtm_version, SHA256_DIGEST_LENGTH);

    DEBUG("Extracting FVMAIN_COMPACT.Fv from OVMF.fd\n");
    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
    if (ret != 0) {
        printf("Failed to load %s\n", ovmf_file);
        goto out;
    }

    // OVMF Layout: Variable Store | FVMAIN_COMPACT | SECFV
    EFI_FIRMWARE_VOLUME_HEADER *var_store_hdr = (EFI_FIRMWARE_VOLUME_HEADER *)ovmf_buf;
    uint64_t fvmain_start = var_store_hdr->FvLength;
    EFI_FIRMWARE_VOLUME_HEADER *fvmain_hdr =
        (EFI_FIRMWARE_VOLUME_HEADER *)(ovmf_buf + fvmain_start);

    DEBUG("FVMAIN_COMPACT Start: 0x%llx\n", var_store_hdr->FvLength);
    DEBUG("FVMAIN_COMPACT Size: 0x%llx\n", fvmain_hdr->FvLength);

    fvmain_compact_buf = malloc(fvmain_hdr->FvLength);
    if (!fvmain_compact_buf) {
        printf("Failed to allocate memory for FVMAIN_COMPACT.Fv\n");
        ret = -1;
        goto out;
    }
    if (fvmain_start > ovmf_size || fvmain_hdr->FvLength > (ovmf_size - fvmain_start)) {
        printf("OVMF smaller than expected (0x%lx, must at least be 0x%llx)\n", ovmf_size,
               fvmain_start + fvmain_hdr->FvLength);
        ret = -1;
        goto out;
    }
    memcpy(fvmain_compact_buf, &ovmf_buf[fvmain_start], fvmain_hdr->FvLength);

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
    uint8_t *peifv = ((uint8_t *)fvmain + 0x80);
    EFI_FIRMWARE_VOLUME_HEADER *pei_hdr = (EFI_FIRMWARE_VOLUME_HEADER *)peifv;
    DEBUG("PEIFV length: %llx\n", pei_hdr->FvLength);

    uint8_t peifv_hash[SHA256_DIGEST_LENGTH];
    ret = hash_and_dump(EVP_sha256(), peifv_hash, peifv, pei_hdr->FvLength, dump_pei_path);
    if (ret) {
        printf("Failed to measure PEIFV\n");
        goto out;
    }
    evlog_add(evlog, 0, "PEIFV", peifv_hash, "OVMF UEFI PEI Firmware Volume");
    hash_extend(EVP_sha256(), pcr, peifv_hash, SHA256_DIGEST_LENGTH);

    // Measure DXEFV
    uint8_t *dxefv = ((uint8_t *)fvmain + pei_hdr->FvLength + 0x90);
    EFI_FIRMWARE_VOLUME_HEADER *dxe_hdr = (EFI_FIRMWARE_VOLUME_HEADER *)dxefv;
    DEBUG("DXEFV length: %llx\n", dxe_hdr->FvLength);

    uint8_t dxefv_hash[SHA256_DIGEST_LENGTH];
    ret = hash_and_dump(EVP_sha256(), dxefv_hash, dxefv, dxe_hdr->FvLength, dump_dxe_path);
    if (ret) {
        printf("Failed to measure DXEFV\n");
        goto out;
    }
    evlog_add(evlog, 0, "DXEFV", dxefv_hash, "OVMF UEFI DXE Firmware Volume");
    hash_extend(EVP_sha256(), pcr, dxefv_hash, SHA256_DIGEST_LENGTH);

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
int
calculate_pcr1(uint8_t *pcr, eventlog_t *evlog, pcr1_config_files_t *cfg)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_PLATFORM_CONFIG_FLAGS
    ret = calculate_acpi_tables(pcr, evlog, cfg);
    if (ret) {
        printf("failed to calculate acpi tables\n");
        goto out;
    }

    // EV_EFI_VARIABLE_BOOT Boot Order
    uint8_t efi_variable_boot[2] = { 0x0, 0x0 };
    uint8_t hash_efi_variable_boot[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_variable_boot, (uint8_t *)efi_variable_boot,
             sizeof(efi_variable_boot));
    evlog_add(evlog, 1, "EV_EFI_VARIABLE_BOOT", hash_efi_variable_boot,
              "Hash EFI Variable Boot: Hash(0000)");
    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot, SHA256_DIGEST_LENGTH);

    // EV_EFI_VARIABLE_BOOT Boot0000
    long len = 0;
    uint8_t *efi_variable_boot0000 = calculate_efi_load_option((size_t *)&len);
    if (!efi_variable_boot0000) {
        printf("failed to calculate efi load option\n");
        goto out;
    }
    uint8_t hash_efi_variable_boot0000[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_variable_boot0000, efi_variable_boot0000, len);
    evlog_add(evlog, 1, "EV_EFI_VARIABLE_BOOT", hash_efi_variable_boot0000,
              "VariableName - Boot0000, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot0000, SHA256_DIGEST_LENGTH);

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
    if (efi_variable_boot0000)
        free(efi_variable_boot0000);
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
int
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

        EFI_STATUS status = MeasurePeImage(EVP_sha256(), hash_driver, driver_buf, driver_size);
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
int
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
int
calculate_pcr4(uint8_t *pcr, eventlog_t *evlog, const char *kernel_file, const char *config_file,
               const char **bootloader_files, size_t num_bootloader_files)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // Either kernel or bootloader must be present
    if (!kernel_file && !bootloader_files) {
        printf("No kernel or bootloader provided\n");
        return -1;
    }

    // EV_EFI_BOOT_SERVICES_APPLICATION: If bootloaders are NOT present, measure Linux kernel
    if (!bootloader_files) {
        uint8_t hash_kernel[SHA256_DIGEST_LENGTH] = { 0 };
        uint8_t *kernel_buf = NULL;
        uint64_t kernel_size = 0;

        ret = LoadPeImage(&kernel_buf, &kernel_size, kernel_file);
        if (ret != 0) {
            printf("Failed to load kernel image %s\n", kernel_file);
            return -1;
        }

        if (config_file) {
                // Load configuration variables
                config_t config = { 0 };
                if (config_file) {
                    ret = config_load(&config, config_file);
                    if (ret != 0) {
                        printf("Failed to load kernel setup header configuration\n");
                        return -1;
                    }
                }

            ret = config_prepare_kernel_pecoff(kernel_buf, kernel_size, &config);
            if (ret != 0) {
                printf("Failed to prepare kernel PE/COFF image\n");
                free(kernel_buf);
                return -1;
            }
        }

        EFI_STATUS status = MeasurePeImage(EVP_sha256(), hash_kernel, kernel_buf, kernel_size);
        if (EFI_ERROR(status)) {
            printf("printf: Failed to measure PE Image: %llx\n", status);
            free(kernel_buf);
            return -1;
        }
        evlog_add(evlog, 4, "EV_EFI_BOOT_SERVICES_APPLICATION", hash_kernel,
                  basename((char *)kernel_file));

        hash_extend(EVP_sha256(), pcr, hash_kernel, SHA256_DIGEST_LENGTH);
        free(kernel_buf);
    }

    // TCG PCClient Firmware Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    // EV_EFI_ACTION "Calling EFI Application from Boot Option"
    char *action_data = "Calling EFI Application from Boot Option";
    uint8_t hash_efi_action[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action, (uint8_t *)action_data, strlen(action_data));
    evlog_add(evlog, 4, "EV_EFI_ACTION", hash_efi_action,
              "HASH('Calling EFI Application from Boot Option')");
    hash_extend(EVP_sha256(), pcr, hash_efi_action, SHA256_DIGEST_LENGTH);

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    evlog_add(evlog, 4, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    // Measure bootloaders if present
    if (bootloader_files) {
        for (size_t i = 0; i < num_bootloader_files; i++) {
            if (!bootloader_files[i]) {
                printf("bootloader file is nil\n");
                return -1;
            }

            uint8_t hash_bl[SHA256_DIGEST_LENGTH] = { 0 };
            uint8_t *bl_buf = NULL;
            uint64_t bl_size = 0;

            ret = LoadPeImage(&bl_buf, &bl_size, bootloader_files[i]);
            if (ret != 0) {
                printf("Failed to load bootloader image %s\n", bootloader_files[i]);
                return -1;
            }

            EFI_STATUS status = MeasurePeImage(EVP_sha256(), hash_bl, bl_buf, bl_size);
            if (EFI_ERROR(status)) {
                printf("printf: Failed to measure PE Image: %llx\n", status);
                free(bl_buf);
            }
            evlog_add(evlog, 4, "EV_EFI_BOOT_SERVICES_APPLICATION", hash_bl,
                      basename((char *)bootloader_files[i]));

            hash_extend(EVP_sha256(), pcr, hash_bl, SHA256_DIGEST_LENGTH);
            free(bl_buf);
        }
    }

    return 0;
}

/**
 * Calculates PCR 5 for systems without bootloader
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 * @param efi_partition_table The path to the EFI partition table file
 */
int
calculate_pcr5(uint8_t *pcr, eventlog_t *evlog, const char *efi_partition_table)
{
    int ret = -1;
    char *description = NULL;
    uint8_t *gpt_buf = NULL;
    uint64_t gpt_size = 0;

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

    // Calculate UEFI GPT partition table if provided. The table must be provided in the
    // measurement format, i.e. the header followed by an 8-byte little endian number
    // of partion entries followed by all non-zero entries (as defined in OVMF EFI_GPT_DATA
    // struct and measured in Tcg2MeasureGptTable())
    if (efi_partition_table) {
        int ret = read_file(&gpt_buf, &gpt_size, efi_partition_table);
        if (ret != 0) {
            printf("Failed to load %s\n", efi_partition_table);
            return -1;
        }
        if (gpt_size < 92) {
            printf("GPT file too small\n");
            goto out;
        }

        uint8_t hash_gpt[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_gpt, gpt_buf, gpt_size);

        char *description = write_gpt_header((UEFI_PARTITION_TABLE_HEADER *)gpt_buf);
        if (!description) {
            printf("Failed to write GPT header\n");
            goto out;
        }

        evlog_add(evlog, 5, "EV_EFI_GPT_EVENT", hash_gpt, description);
        hash_extend(EVP_sha256(), pcr, hash_gpt, SHA256_DIGEST_LENGTH);
        free(description);
    }

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

    ret = 0;

out:
    if (gpt_buf)
        free(gpt_buf);
    if (description)
        free(description);

    return ret;
}

/**
 * Calculates PCR 6
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param evlog The event log to record the extend operations in
 */
int
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
int
calculate_pcr7(uint8_t *pcr, eventlog_t *evlog, const char *sbat_level)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // TODO: Support enabled secure boot

    // Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
    EFI_STATUS status = MeasureAllSecureVariables(EVP_sha256(), pcr, 7, evlog);
    if (status != EFI_SUCCESS) {
        printf("Failed to measure secure boot variables\n");
        return -1;
    }

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

    // Measure dbx authority (EV_EFI_VARIABLE_AUTHORITY)
    if (sbat_level) {
        EFI_GUID efiImageSecurityDatabase1SbatLevelGuid =
            EFI_IMAGE_SECURITY_DATABASE1_SBATLEVEL_GUID;
        ;
        status = MeasureVariable(EVP_sha256(), pcr, 7, evlog, EV_EFI_VARIABLE_AUTHORITY,
                                 EFI_IMAGE_SECURITY_DATABASE1_SBATLEVEL,
                                 &efiImageSecurityDatabase1SbatLevelGuid, (char *)sbat_level,
                                 strlen(sbat_level));
        if (status != EFI_SUCCESS) {
            printf("Failed to measure dbx authority\n");
            return -1;
        }
    }

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
int
calculate_pcr8(uint8_t *pcr, eventlog_t *evlog, const char *grubcmds_file)
{
    (void)evlog;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    if (grubcmds_file) {
        uint8_t *grubcmds_buf = NULL;
        uint64_t grubcmds_size = 0;
        int ret = read_file(&grubcmds_buf, &grubcmds_size, grubcmds_file);
        if (ret != 0) {
            printf("Failed to load %s\n", grubcmds_file);
            return -1;
        }

        char *cmd = strtok((char *)grubcmds_buf, "\n");
        while (cmd != NULL) {
            uint8_t hash_grub_cmd[SHA256_DIGEST_LENGTH];
            hash_buf(EVP_sha256(), hash_grub_cmd, (uint8_t *)cmd, strlen(cmd));
            evlog_add(evlog, 8, "EV_IPL", hash_grub_cmd, cmd);
            hash_extend(EVP_sha256(), pcr, hash_grub_cmd, SHA256_DIGEST_LENGTH);
            cmd = strtok(NULL, "\n");
        }
        free(grubcmds_buf);
    }

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
int
calculate_pcr9(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, size_t trailing_zeros,
               const char *initrd, char **paths, size_t num_paths)
{
    int ret = -1;
    char16_t *wcmdline = NULL;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    if (paths) {
        ret = calculate_paths(pcr, evlog, paths, num_paths);
        if (ret) {
            printf("Failed to calculate paths\n");
            return ret;
        }
    }

    if (cmdline) {
        uint8_t *cmdline_buf = NULL;
        uint64_t cmdline_size = 0;
        ret = read_file(&cmdline_buf, &cmdline_size, cmdline);
        if (ret != 0) {
            printf("Failed to load %s\n", cmdline);
            goto out;
        }

        // OvmfPkg/Library/X86QemuLoadImageLib/X86QemuLoadImageLib.c#L570
        // OVMF appends initrd=initrd if initial ramdisk was specified
        if (initrd) {
            uint64_t old_size = cmdline_size;
            const char *append = " initrd=initrd";
            cmdline_size += strlen(append);
            cmdline_buf = (uint8_t *)realloc(cmdline_buf, cmdline_size);
            memcpy(cmdline_buf + old_size, append, strlen(append));
        }

        char *cmdline_str = (char *)malloc(cmdline_size + 1);
        memset(cmdline_str, 0x0, cmdline_size + 1);
        memcpy(cmdline_str, cmdline_buf, cmdline_size);

        // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
        size_t cmdline_len = 0;
        wcmdline = convert_to_char16((const char *)cmdline_buf, cmdline_size, &cmdline_len,
                                     trailing_zeros);
        if (!wcmdline) {
            printf("Failed to convert to wide character string\n");
            free(cmdline_buf);
            free(cmdline_str);
            return -1;
        }

        DEBUG("cmdline file size: %lu\n", cmdline_size);
        DEBUG("cmdline strlen: %lu\n", strlen(cmdline_str));
        DEBUG("cmdline wchar len: %lu\n", cmdline_len);
        print_data_debug((const uint8_t *)wcmdline, cmdline_len, "cmdline");

        uint8_t hash_ev_event_tag[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_ev_event_tag, (uint8_t *)wcmdline, cmdline_len);
        evlog_add(evlog, 9, "EV_EVENT_TAG", hash_ev_event_tag, (const char *)cmdline_str);

        hash_extend(EVP_sha256(), pcr, hash_ev_event_tag, SHA256_DIGEST_LENGTH);
        free(cmdline_buf);
        free(cmdline_str);
    }

    if (initrd) {
        uint8_t *initrd_buf = NULL;
        uint64_t initrd_size = 0;
        ret = read_file(&initrd_buf, &initrd_size, initrd);
        if (ret != 0) {
            printf("Failed to load %s\n", initrd);
            goto out;
        }

        uint8_t hash_ev_event_tag[SHA256_DIGEST_LENGTH];
        hash_buf(EVP_sha256(), hash_ev_event_tag, initrd_buf, initrd_size);
        evlog_add(evlog, 9, "EV_EVENT_TAG", hash_ev_event_tag, initrd);

        hash_extend(EVP_sha256(), pcr, hash_ev_event_tag, SHA256_DIGEST_LENGTH);
        free(initrd_buf);
    }

    ret = 0;

out:
    if (wcmdline)
        free(wcmdline);

    return ret;
}