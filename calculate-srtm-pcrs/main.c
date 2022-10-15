/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "libgen.h"

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
#include "config.h"

#define MAX_PCRS 24

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

volatile bool debug_output = false;

static char *
encode_hex(const uint8_t *bin, int length)
{
    size_t len = length * 2 + 1;
    char *hex = calloc(len, 1);
    for (int i = 0; i < length; ++i) {
        // snprintf writes a '0' byte
        snprintf(hex + i * 2, 3, "%.2x", bin[i]);
    }
    return hex;
}

static int
eventlog_add(char **dest, format_t format, const char *name, uint32_t pcr, uint8_t *hash,
             const char *desc)
{
    int ret;
    char *hashstr = encode_hex(hash, SHA256_DIGEST_LENGTH);
    if (!hashstr) {
        printf("Failed to allocate memory\n");
        return -1;
    }

    char s[1024] = { 0 };
    if (format == FORMAT_JSON) {
        ret = snprintf(s, sizeof(s),
                       "{"
                       "\n\t\"type\":\"TPM Verification\","
                       "\n\t\"name\":\"%s\","
                       "\n\t\"pcr\":%d,"
                       "\n\t\"sha256\":\"%s\","
                       "\n\t\"description\":\"%s\""
                       "\n},\n",
                       name, pcr, hashstr, desc);
    } else if (format == FORMAT_TEXT) {
        ret = snprintf(s, sizeof(s),
                       "name: %s"
                       "\n\tpcr: %d"
                       "\n\tsha256: %s"
                       "\n\tdescription: %s\n",
                       name, pcr, hashstr, desc);
    }
    if (!ret) {
        printf("Failed to print eventlog\n");
        ret = -1;
        goto out;
    }

    if (!*dest) {
        size_t size = strlen(s) + 1;
        *dest = (char *)malloc(size);
        if (!*dest) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncpy(*dest, s, size);
    } else {
        size_t size = strlen(*dest) + strlen(s) + 1;
        *dest = (char *)realloc(*dest, size);
        if (!*dest) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncat(*dest, s, strlen(s) + 1);
    }

out:
    free(hashstr);
    return ret;
}

/**
 * Calculates PCR 0
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 * @param ovmf_file The path to the OVMF.fd file that should be used for the calculations
 */
static int
calculate_pcr0(uint8_t *pcr, char **eventlog, format_t format, const char *ovmf_file,
               config_t *config)
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
    eventlog_add(&eventlog[0], format, "EV_S_CRTM_VERSION", 0, hash_ev_s_crtm_version,
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

    config_prepare_peifv(fvmain, config);

    // Measure PEIFV
    uint8_t peifv_hash[SHA256_DIGEST_LENGTH];
    ret = measure_peifv(peifv_hash, fvmain);
    if (ret) {
        printf("Failed to measure PEIFV\n");
        goto out;
    }
    eventlog_add(&eventlog[0], format, "PEIFV", 0, peifv_hash, "OVMF UEFI PEI Firmware Volume");

    // Measure DXEFV
    uint8_t dxefv_hash[SHA256_DIGEST_LENGTH];
    ret = measure_dxefv(dxefv_hash, fvmain);
    if (ret) {
        printf("Failed to measure DXEFV\n");
        goto out;
    }
    eventlog_add(&eventlog[0], format, "DXEFV", 0, dxefv_hash, "OVMF UEFI DXE Firmware Volume");

    // EV_SEPARATOR
    ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        ret = -1;
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    eventlog_add(&eventlog[0], format, "EV_SEPARATOR", 0, hash_ev_separator, "HASH(00000000)");

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
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr1(uint8_t *pcr, char **eventlog, format_t format)
{
    int ret = -1;

    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // EV_EFI_VARIABLE_BOOT
    uint8_t efi_variable_boot[2] = { 0 };
    uint8_t hash_efi_variable_boot[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_variable_boot, (uint8_t *)efi_variable_boot,
             sizeof(efi_variable_boot));
    eventlog_add(&eventlog[1], format, "EV_EFI_VARIABLE_BOOT", 1, hash_efi_variable_boot,
                 "Hash EFI Variable Boot: Hash(0000)");

    // EV_EFI_VARIABLE_BOOT
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
    eventlog_add(
        &eventlog[1], format, "EV_EFI_VARIABLE_BOOT", 1, hash_efi_variable_boot2,
        "HASH(090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400)");

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        goto out;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    eventlog_add(&eventlog[1], format, "EV_SEPARATOR", 1, hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_efi_variable_boot2, SHA256_DIGEST_LENGTH);
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
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 * @param ovmf_file The path to the OVMF.fd file that should be used for the calculations
 */
static int
calculate_pcr2(uint8_t *pcr, char **eventlog, format_t format, char **drivers, size_t num_drivers)
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
        eventlog_add(&eventlog[2], format, "EV_EFI_BOOT_SERVICES_DRIVER", 2, hash_driver,
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
    eventlog_add(&eventlog[2], format, "EV_SEPARATOR", 2, hash_ev_separator, "HASH(00000000)");

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
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr3(uint8_t *pcr, char **eventlog, format_t format)
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
    eventlog_add(&eventlog[3], format, "EV_SEPARATOR", 3, hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 4
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 * @param kernel_file The path of the kernel image (.bzImage) to use for the calculations
 */
static int
calculate_pcr4(uint8_t *pcr, char **eventlog, format_t format, const char *kernel_file,
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
    eventlog_add(&eventlog[4], format, "EV_EFI_BOOT_SERVICES_APPLICATION", 4, hash_kernel,
                 basename((char *)kernel_file));

    // TCG PCClient Firmware Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    // EV_EFI_ACTION "Calling EFI Application from Boot Option"
    char *action_data = "Calling EFI Application from Boot Option";
    uint8_t hash_efi_action[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action, (uint8_t *)action_data, strlen(action_data));
    eventlog_add(&eventlog[4], format, "EV_EFI_ACTION", 4, hash_efi_action,
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
    eventlog_add(&eventlog[4], format, "EV_SEPARATOR", 4, hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_kernel, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_efi_action, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    ret = 0;

out:
    free(kernel_buf);

    return ret;
}

/**
 * Calculates PCR 5
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr5(uint8_t *pcr, char **eventlog, format_t format)
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
    eventlog_add(&eventlog[5], format, "EV_SEPARATOR", 5, hash_ev_separator, "HASH(00000000)");

    // EV_EFI_ACTION "Exit Boot Services Invocation"
    char *efi_action_boot_invocation = "Exit Boot Services Invocation";
    uint8_t hash_efi_action_boot_invocation[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action_boot_invocation, (uint8_t *)efi_action_boot_invocation,
             strlen(efi_action_boot_invocation));
    eventlog_add(&eventlog[5], format, "EV_EFI_ACTION", 5, hash_efi_action_boot_invocation,
                 "HASH('Exit Boot Services Invocation')");

    // EV_EFI_ACTION "Exit Boot Services Returned with Success"
    char *efi_action_boot_exit = "Exit Boot Services Returned with Success";
    uint8_t hash_efi_action_boot_exit[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_efi_action_boot_exit, (uint8_t *)efi_action_boot_exit,
             strlen(efi_action_boot_exit));
    eventlog_add(&eventlog[5], format, "EV_EFI_ACTION", 5, hash_efi_action_boot_exit,
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
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr6(uint8_t *pcr, char **eventlog, format_t format)
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
    eventlog_add(&eventlog[6], format, "EV_SEPARATOR", 6, hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 7
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr7(uint8_t *pcr, char **eventlog, format_t format)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // TODO: Support secure boot

    // GUID 61dfe48b-ca93-d211-aa0d-00e098032b8c
    EFI_GUID var_guid1 = { __builtin_bswap32(0x61dfe48b),
                           __builtin_bswap16(0xca93),
                           __builtin_bswap16(0xd211),
                           { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } };
    // GUID cbb219d7-3a3d-9645-a3bc-dad00e67656f
    EFI_GUID var_guid2 = { __builtin_bswap32(0xcbb219d7),
                           __builtin_bswap16(0x3a3d),
                           __builtin_bswap16(0x9645),
                           { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } };

    // EV_EFI_VARIABLE_DRIVER_CONFIG 'SecureBoot'
    uint8_t hash_secure_boot[SHA256_DIGEST_LENGTH];
    CHAR16 *var_name_secure_boot = u"SecureBoot";
    uint8_t var_data[1] = { 0 };
    uint64_t var_data_len = 1;
    MeasureVariable(hash_secure_boot, var_name_secure_boot, &var_guid1, var_data, var_data_len);
    eventlog_add(&eventlog[7], format, "EV_EFI_VARIABLE_DRIVER_CONFIG", 7, hash_secure_boot,
                 "Variable 'SecureBoot'");

    // EV_EFI_VARIABLE_DRIVER_CONFIG 'PK'
    uint8_t hash_pk[SHA256_DIGEST_LENGTH];
    CHAR16 *var_name_pk = u"PK";
    MeasureVariable(hash_pk, var_name_pk, &var_guid1, NULL, 0);
    eventlog_add(&eventlog[7], format, "EV_EFI_VARIABLE_DRIVER_CONFIG", 7, hash_pk,
                 "Variable 'PK'");

    // EV_EFI_VARIABLE_DRIVER_CONFIG 'KEK'
    uint8_t hash_kek[SHA256_DIGEST_LENGTH];
    CHAR16 *var_name_kek = u"KEK";
    MeasureVariable(hash_kek, var_name_kek, &var_guid1, NULL, 0);
    eventlog_add(&eventlog[7], format, "EV_EFI_VARIABLE_DRIVER_CONFIG", 7, hash_kek,
                 "Variable 'KEK'");

    // EV_EFI_VARIABLE_DRIVER_CONFIG 'DB'
    uint8_t hash_db[SHA256_DIGEST_LENGTH];
    CHAR16 *var_name_db = u"db";
    MeasureVariable(hash_db, var_name_db, &var_guid2, NULL, 0);
    eventlog_add(&eventlog[7], format, "EV_EFI_VARIABLE_DRIVER_CONFIG", 7, hash_db,
                 "Variable 'DB'");

    // EV_EFI_VARIABLE_DRIVER_CONFIG 'DBX'
    uint8_t hash_dbx[SHA256_DIGEST_LENGTH];
    CHAR16 *var_name_dbx = u"dbx";
    MeasureVariable(hash_dbx, var_name_dbx, &var_guid2, NULL, 0);
    eventlog_add(&eventlog[7], format, "EV_EFI_VARIABLE_DRIVER_CONFIG", 7, hash_dbx,
                 "Variable 'DBX'");

    // EV_SEPARATOR
    uint8_t *ev_separator = OPENSSL_hexstr2buf("00000000", NULL);
    if (!ev_separator) {
        printf("Failed to allocate memory for ev separator\n");
        return -1;
    }
    uint8_t hash_ev_separator[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), hash_ev_separator, ev_separator, 4);
    OPENSSL_free(ev_separator);
    eventlog_add(&eventlog[7], format, "EV_SEPARATOR", 7, hash_ev_separator, "HASH(00000000)");

    hash_extend(EVP_sha256(), pcr, hash_secure_boot, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_pk, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_kek, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_db, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_dbx, SHA256_DIGEST_LENGTH);
    hash_extend(EVP_sha256(), pcr, hash_ev_separator, SHA256_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates PCR 8
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr8(uint8_t *pcr, char **eventlog, format_t format)
{
    (void)pcr;
    (void)eventlog;
    (void)format;
    printf("Calculate PCR8 not implemented\n");

    return 0;
}

/**
 * Calculates PCR 9
 *
 * Only applicable if ubuntu kernel is measured into PCR 10 (i.e., if GRUB is used).
 * If no dedicated bootloader is used, see calculation of PCR4 for the kernel
 *
 * @see https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html
 *
 * @param pcr Out buffer containing the final hash of the PCR
 * @param eventlog The event log to record the extend operations in
 * @param format The format of the eventlog
 */
static int
calculate_pcr9(uint8_t *pcr, char **eventlog, format_t format)
{
    memset(pcr, 0x0, SHA256_DIGEST_LENGTH);

    // PCR9 is the second PCR with Static Operating System Measurements
    char *file_list[] = { "/boot/efi/EFI/debian/grub.cfg",
                          "/boot/grub/x86_64-efi/command.lst",
                          "/boot/grub/x86_64-efi/fs.lst",
                          "/boot/grub/x86_64-efi/crypto.lst",
                          "/boot/grub/x86_64-efi/terminal.lst",
                          "/boot/grub/grub.cfg",
                          "/boot/grub/grubenv",
                          "/boot/grub/grubenv",
                          "/boot/grub/fonts/unicode.pf2",
                          "/boot/vmlinuz-5.10.40",
                          "/boot/initrd.img-5.10.40" };

    uint8_t hash[ARRAY_SIZE(file_list)][SHA256_DIGEST_LENGTH];

    for (size_t i = 0; i < ARRAY_SIZE(file_list); i++) {
        int ret = hash_file(EVP_sha256(), hash[i], file_list[i]);
        if (ret) {
            return -1;
        }
        eventlog_add(&eventlog[6], format, "GRUB Measurement", 9, hash[i], file_list[i]);

        hash_extend(EVP_sha256(), pcr, hash[i], SHA256_DIGEST_LENGTH);
    }
    return 0;
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
    printf("\t-p,  --pcrs <num[,num...]>\tPCRs to be calculated\n");
    printf("\t-d,  --debug\t\t\tPrint debug output\n");
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

int
main(int argc, char *argv[])
{
    int ret = -1;
    const char *config_file = NULL;
    const char *kernel = NULL;
    const char *ramdisk = NULL;
    const char *ovmf = NULL;
    bool print_event_log = false;
    char *eventlog[MAX_PCRS] = { 0 };
    bool print_summary = false;
    uint32_t *pcr_nums = NULL;
    size_t len_pcr_nums = 0;
    format_t format = FORMAT_TEXT;
    const char *progname = argv[0];
    char *pcr_str = NULL;
    char **uefi_drivers = NULL;
    size_t num_uefi_drivers = 0;
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
                format = FORMAT_JSON;
            } else if (!strcmp(argv[1], "text")) {
                format = FORMAT_TEXT;
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
        } else if ((!strcmp(argv[0], "-v") || !strcmp(argv[0], "--verbose"))) {
            debug_output = true;
            argv++;
            argc--;
        } else {
            printf("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    if (!config_file &&
        (contains(pcr_nums, len_pcr_nums, 0) || contains(pcr_nums, len_pcr_nums, 4))) {
        printf("Config file must be specified to calculate PCRs 0 and 4\n");
        print_usage(progname);
        goto out;
    }

    if (!kernel && contains(pcr_nums, len_pcr_nums, 4)) {
        printf("Kernel must be specified to calculate PCR4\n");
        print_usage(progname);
        goto out;
    }
    if (!ramdisk) {
        DEBUG("Calculating PCR4 without initrd\n");
    }
    if (!ovmf && (contains(pcr_nums, len_pcr_nums, 0) || contains(pcr_nums, len_pcr_nums, 1) ||
                  contains(pcr_nums, len_pcr_nums, 2))) {
        printf("OVMF must specified for calculating PCRs 0 and 1\n");
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
    }
    DEBUG("\tOVMF: %s\n", ovmf);
    DEBUG("\tEventlog:  %d\n", print_event_log);
    DEBUG("\tSummary:   %d\n", print_summary);
    for (size_t i = 0; i < num_uefi_drivers; i++) {
        DEBUG("\tUEFI driver: %s\n", uefi_drivers[i]);
    }

    uint8_t pcr[MAX_PCRS][SHA256_DIGEST_LENGTH];

    if (contains(pcr_nums, len_pcr_nums, 0)) {
        if (calculate_pcr0(pcr[0], eventlog, format, ovmf, &config)) {
            printf("Failed to calculate event log for PCR 0\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 1)) {
        if (calculate_pcr1(pcr[1], eventlog, format)) {
            printf("Failed to calculate event log for PCR 1\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 2)) {
        if (calculate_pcr2(pcr[2], eventlog, format, uefi_drivers, num_uefi_drivers)) {
            printf("Failed to calculate event log for PCR 2\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 3)) {
        if (calculate_pcr3(pcr[3], eventlog, format)) {
            printf("Failed to calculate event log for PCR 3\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 4)) {
        if (calculate_pcr4(pcr[4], eventlog, format, kernel, &config)) {
            printf("Failed to calculate event log for PCR 4\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 5)) {
        if (calculate_pcr5(pcr[5], eventlog, format)) {
            printf("Failed to calculate event log for PCR 5\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 6)) {
        if (calculate_pcr6(pcr[6], eventlog, format)) {
            printf("Failed to calculate event log for PCR 6\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 7)) {
        if (calculate_pcr7(pcr[7], eventlog, format)) {
            printf("Failed to calculate event log for PCR 7\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 8)) {
        if (calculate_pcr8(pcr[8], eventlog, format)) {
            printf("Failed to calculate event log for PCR 8\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 9)) {
        if (calculate_pcr9(pcr[9], eventlog, format)) {
            printf("Failed to calculate event log for PCR 9\n");
            goto out;
        }
    }

    // Print event log with all extend operations if specified
    if (print_event_log) {
        DEBUG("\nPCR EVENT LOG: \n");
        if (format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < len_pcr_nums; i++) {
            if (!eventlog[pcr_nums[i]]) {
                printf("Failed to print Event Log for PCR %d\n", pcr_nums[i]);
                goto out;
            }
            // Remove last colon on final event log entry if format is json
            if ((format == FORMAT_JSON) && (i == (len_pcr_nums)-1)) {
                eventlog[pcr_nums[i]][strlen(eventlog[pcr_nums[i]]) - 2] = ']';
                eventlog[pcr_nums[i]][strlen(eventlog[pcr_nums[i]]) - 1] = '\0';
            }
            printf("%s", eventlog[pcr_nums[i]]);
        }
        printf("\n");
    }

    // Print final PCRs in specified format
    if (print_summary) {
        DEBUG("\nPCR SUMMARY: \n");
        for (uint32_t i = 0; i < len_pcr_nums; i++) {
            if (format == FORMAT_JSON) {
                printf(
                    "{\n\t\"type\":\"TPM Verification\",\n\t\"name\":\"PCR%d\",\n\t\"pcr\":%d,\n\t\"sha256\":\"",
                    pcr_nums[i], pcr_nums[i]);
                print_data_no_lf(pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
                printf("\"\n\t\"description\":\"PCR%d\"\n}", pcr_nums[i]);
                if (i < len_pcr_nums - 1) {
                    printf(",\n");
                } else {
                    printf("\n");
                }
            } else if (format == FORMAT_TEXT) {
                printf("PCR%d: ", pcr_nums[i]);
                print_data(pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
            } else {
                printf("Unknown output format\n");
                goto out;
            }
        }
    }

    ret = 0;

out:
    if (pcr_nums)
        free(pcr_nums);
    if (pcr_str)
        free(pcr_str);
    for (size_t i = 0; i < MAX_PCRS; i++) {
        if (eventlog[i]) {
            free(eventlog[i]);
        }
    }
    if (uefi_drivers)
        free(uefi_drivers);

    return ret;
}
