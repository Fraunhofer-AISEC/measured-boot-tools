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
#include "Tcg2Dxe.h"
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

volatile bool debug_output = false;

typedef struct {
    uint8_t *acpi_tables;
    ssize_t acpi_tables_size;
    uint8_t *acpi_rsdp;
    ssize_t acpi_rsdp_size;
    uint8_t *table_loader;
    ssize_t table_loader_size;
} rtmr0_qemu_fw_cfg_files_t;

extern EFI_GUID gEfiImageSecurityDatabaseGuid;

/**
 * Calculates the measurement register for the TDX SEAM module (MRSEAM)
 *
 * The MRTD contains the digest of the TDX-module as measured by the SEAM loader
 *
 */
static int
calculate_mrseam(uint8_t *mr, eventlog_t *evlog, const char *tdx_module)
{
    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    uint8_t hash_mrseam[SHA384_DIGEST_LENGTH];
    int ret = hash_file(EVP_sha384(), hash_mrseam, tdx_module);
    if (ret) {
        printf("Failed to measure the TDX-module\n");
        return -1;
    }

    evlog_add(evlog, INDEX_MRSEAM, "TDX-Module", hash_mrseam,
              "SEAMLDR Measurement: TDX-Module");
    memcpy(mr, hash_mrseam, SHA384_DIGEST_LENGTH);

    return 0;
}

/**
 * Calculates the TDX Build-Time Measurement Register (MRTD)
 *
 * The MRTD contains the digest of the OVMF as hashed by the Intel TDX module.
 *
 */
static int
calculate_mrtd(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file)
{
    int ret = -1;

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    uint8_t *ovmf_buf = NULL;
    uint64_t ovmf_size = 0;
    ret = read_file(&ovmf_buf, &ovmf_size, ovmf_file);
    if (ret) {
        goto out;
    }

    uint8_t hash_mrtd[SHA384_DIGEST_LENGTH];
    ret = measure_ovmf(hash_mrtd, ovmf_buf, ovmf_size);
    if (ret) {
        printf("Failed to measure ovmf\n");
        goto out;
    }

    evlog_add(evlog, INDEX_MRTD, "OVMF", hash_mrtd,
              "TDX Module Measurement: Initial TD contents (OVMF)");
    memcpy(mr, hash_mrtd, SHA384_DIGEST_LENGTH);

    ret = 0;

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
static int
calculate_rtmr0(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file,
                rtmr0_qemu_fw_cfg_files_t *cfg)
{
    int ret = -1;
    long len = 0;

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

    // Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
    EFI_STATUS status = MeasureAllSecureVariables(EVP_sha384(), mr, INDEX_RTMR0, evlog);
    if (status != EFI_SUCCESS) {
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

    // EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
    if (cfg->table_loader_size > 0) {
        uint8_t hash_table_loader[SHA384_DIGEST_LENGTH];
        hash_buf(EVP_sha384(), hash_table_loader, cfg->table_loader, cfg->table_loader_size);
        evlog_add(evlog, INDEX_RTMR0, "EV_PLATFORM_CONFIG_FLAGS", hash_table_loader,
                  "etc/table-loader");
        hash_extend(EVP_sha384(), mr, hash_table_loader, SHA384_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
    if (cfg->acpi_rsdp_size > 0) {
        uint8_t hash_acpi_rsdp[SHA384_DIGEST_LENGTH];
        hash_buf(EVP_sha384(), hash_acpi_rsdp, cfg->acpi_rsdp, cfg->acpi_rsdp_size);
        evlog_add(evlog, INDEX_RTMR0, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_rsdp, "etc/acpi/rsdp");
        hash_extend(EVP_sha384(), mr, hash_acpi_rsdp, SHA384_DIGEST_LENGTH);
    }

    // EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
    if (cfg->acpi_tables_size > 0) {
        uint8_t hash_acpi_tables[SHA384_DIGEST_LENGTH];
        hash_buf(EVP_sha384(), hash_acpi_tables, cfg->acpi_tables, cfg->acpi_tables_size);
        evlog_add(evlog, INDEX_RTMR0, "EV_PLATFORM_CONFIG_FLAGS", hash_acpi_tables,
                  "etc/acpi/tables");
        hash_extend(EVP_sha384(), mr, hash_acpi_tables, SHA384_DIGEST_LENGTH);
    }

    // EV_EFI_VARIABLE Boot Order
    len = 2;
    uint8_t efi_variable_boot_order[] = { 0x0, 0x0 };
    uint8_t hash_efi_variable_boot_order[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_variable_boot_order, (uint8_t *)efi_variable_boot_order, len);
    evlog_add(evlog, INDEX_RTMR0, "EV_EFI_VARIABLE", hash_efi_variable_boot_order,
              "VariableName - BootOrder, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
    hash_extend(EVP_sha384(), mr, hash_efi_variable_boot_order, SHA384_DIGEST_LENGTH);

    // EV_EFI_VARIABLE_BOOT Boot0000
    uint8_t *efi_variable_boot0000 = calculate_efi_load_option((size_t *)&len);
    if (!efi_variable_boot0000) {
        printf("failed to calculate efi load option\n");
        goto out;
    }
    uint8_t hash_efi_variable_boot0000[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_variable_boot0000, efi_variable_boot0000, len);
    evlog_add(evlog, INDEX_RTMR0, "EV_EFI_VARIABLE", hash_efi_variable_boot0000,
              "VariableName - Boot0000, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
    hash_extend(EVP_sha384(), mr, hash_efi_variable_boot0000, SHA384_DIGEST_LENGTH);

    // EV_SEPARATOR
    hash_buf(EVP_sha384(), hash_ev_separator, ev_separator, 4);
    evlog_add(evlog, INDEX_RTMR0, "EV_SEPARATOR", hash_ev_separator, "HASH(00000000)");
    hash_extend(EVP_sha384(), mr, hash_ev_separator, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (ovmf_buf)
        free(ovmf_buf);
    if (ev_separator)
        OPENSSL_free(ev_separator);
    if (efi_variable_boot0000)
        free(efi_variable_boot0000);

    return ret;
}

/**
 * Calculates RTMR1
 *
 * RTMR1 contains the Linux kernel PE/COFF image measurement as well as some boot strings.
 *
 */
static int
calculate_rtmr1(uint8_t *mr, eventlog_t *evlog, const char *kernel_file, config_t *config,
                const char *dump_kernel_path)
{
    int ret = -1;

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // Measure kernel
    uint8_t hash_kernel[SHA384_DIGEST_LENGTH] = { 0 };
    uint8_t *kernel_buf = NULL;
    uint64_t kernel_size = 0;

    ret = LoadPeImage(&kernel_buf, &kernel_size, kernel_file);
    if (ret != 0) {
        goto out;
    }

    ret = config_prepare_kernel_pecoff(kernel_buf, kernel_size, config);
    if (ret != 0) {
        printf("Failed to prepare kernel PE/COFF image\n");
        goto out;
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

    // TCG PCClient Firmware Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
    char *action_data0 = EFI_CALLING_EFI_APPLICATION;
    uint8_t hash_efi_action0[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_efi_action0, (uint8_t *)action_data0, strlen(action_data0));
    evlog_add(evlog, INDEX_RTMR1, "EV_EFI_ACTION", hash_efi_action0, action_data0);
    hash_extend(EVP_sha384(), mr, hash_efi_action0, SHA384_DIGEST_LENGTH);

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

    return ret;
}

/**
 * Calculates RTMR2
 *
 * RTMR2 contains the Linux kernel command line.
 *
 */
static int
calculate_rtmr2(uint8_t *mr, eventlog_t *evlog, const char *cmdline_file)
{
    int ret = -1;

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
    DEBUG("Reading cmdline from: %s\n", cmdline_file);

    uint8_t *cmdline_buf;
    size_t cmdline_size = 0;
    ret = read_file(&cmdline_buf, &cmdline_size, cmdline_file);
    if (ret) {
        return -1;
    }
    DEBUG("cmdline size: %ld\n", cmdline_size);

    uint8_t cmdline_buf2[cmdline_size + 1];
    memset(cmdline_buf2, 0x0, sizeof(cmdline_buf2));
    memcpy(cmdline_buf2, cmdline_buf, cmdline_size);
    cmdline_size++;

    size_t cmdline_len = 0;
    char16_t *wcmdline = convert_to_char16((const char *)cmdline_buf2, &cmdline_len);
    if (!wcmdline) {
        printf("Failed to convert to wide character string\n");
        goto out;
    }

    uint8_t hash_ev_event_tag[SHA384_DIGEST_LENGTH];
    hash_buf(EVP_sha384(), hash_ev_event_tag, (uint8_t *)wcmdline, cmdline_len);
    evlog_add(evlog, INDEX_RTMR2, "EV_EVENT_TAG", hash_ev_event_tag, cmdline_file);

    hash_extend(EVP_sha384(), mr, hash_ev_event_tag, SHA384_DIGEST_LENGTH);

    ret = 0;

out:
    if (cmdline_buf) {
        free(cmdline_buf);
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
static int
calculate_rtmr3(uint8_t *mr, eventlog_t *evlog)
{
    (void)evlog;

    int ret = -1;

    memset(mr, 0x0, SHA384_DIGEST_LENGTH);

    ret = 0;

    return ret;
}

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t     --tdxmodule <file>\t\tThe filename of the TDX-module binary\n");
    printf("\t-o,  --ovmf <file>\t\tThe filename of the OVMF.fd file\n");
    printf("\t-k,  --kernel <file>\t\tThe filename of the kernel image\n");
    printf("\t-r,  --ramdisk <file>\t\tThe filename of the initramfs\n");
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-e,  --eventlog\t\t\tPrint detailed eventlog\n");
    printf("\t-s,  --summary\t\t\tPrint final MR values\n");
    printf("\t     --verbose\t\t\tPrint verbose debug output\n");
    printf("\t-c,  --config\t\t\tPath to configuration file\n");
    printf("\t     --cmdline\t\t\tKernel commandline\n");
    printf("\t-a,  --acpirsdp\t\t\tPath to QEMU etc/acpi/rsdp file for RTMR0\n");
    printf("\t-t,  --acpitables\t\tPath to QEMU etc/acpi/tables file for RTMR0\n");
    printf("\t-l,  --tableloader\t\tPath to QEMU etc/table-loader file for RTMR0\n");
    printf("\t     --dumpkernel\t\t\tOptional path to folder to dump the measured kernel\n");
    printf("\n");
}

static bool
last_entry_json(eventlog_t *evlog, size_t index)
{
    if (evlog->format != FORMAT_JSON) {
        return false;
    }
    if (index == MR_LEN - 1) {
        return true;
    }
    for (size_t i = index + 1; i < MR_LEN; i++) {
        if (evlog->log[i]) {
            return false;
        }
    }
    return true;
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
    const char *tdx_module = NULL;
    const char *dump_kernel_path = NULL;
    bool print_event_log = false;
    bool print_summary = false;
    const char *progname = argv[0];
    eventlog_t evlog = { .format = FORMAT_TEXT, .log = { 0 } };
    rtmr0_qemu_fw_cfg_files_t rtmr0_cfg = {
        .acpi_rsdp_size = -1,
        .acpi_tables_size = -1,
        .table_loader_size = -1,
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
        } else if (!strcmp(argv[0], "--tdxmodule") && argc >= 2) {
            tdx_module = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-a") || !strcmp(argv[0], "--acpirsdp")) && argc >= 2) {
            rtmr0_cfg.acpi_rsdp_size = get_file_size(argv[1]);
            if (rtmr0_cfg.acpi_rsdp_size <= 0) {
                printf("Failed to get file size of ACPI RSDP file %s\n", argv[1]);
                goto out;
            }
            rtmr0_cfg.acpi_rsdp = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-t") || !strcmp(argv[0], "--acpitables")) && argc >= 2) {
            rtmr0_cfg.acpi_tables_size = get_file_size(argv[1]);
            if (rtmr0_cfg.acpi_tables_size <= 0) {
                printf("Failed to get file size of ACPI tables file %s\n", argv[1]);
                goto out;
            }
            rtmr0_cfg.acpi_tables = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-l") || !strcmp(argv[0], "--tableloader")) && argc >= 2) {
            rtmr0_cfg.table_loader_size = get_file_size(argv[1]);
            if (rtmr0_cfg.table_loader_size <= 0) {
                printf("Failed to get file size of table loader file %s\n", argv[1]);
                goto out;
            }
            rtmr0_cfg.table_loader = read_file_new(argv[1]);
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
        } else if (!strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "--dumpkernel")) {
            dump_kernel_path = argv[1];
            argv += 2;
            argc -= 2;
        } else {
            printf("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    if (!config_file) {
        printf("Config file must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!kernel) {
        printf("Kernel must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!ovmf) {
        printf("OVMF must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!tdx_module) {
        printf("TDX-Module must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!cmdline) {
        printf("kernel cmdline must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (rtmr0_cfg.acpi_rsdp_size == -1) {
        printf("Config file ACPI RSDP must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (rtmr0_cfg.acpi_tables_size == -1) {
        printf("Config file ACPI tables must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (rtmr0_cfg.table_loader_size == -1) {
        printf("Config file table loader must be specified\n");
        print_usage(progname);
        goto out;
    }

    DEBUG("Calculating TDX measurement registers\n");

    // Load configuration variables
    config_t config = { 0 };
    if (config_file) {
        ret = config_load(&config, config_file);
        if (ret != 0) {
            printf("Failed to load configuration\n");
            goto out;
        }
    }

    DEBUG("Using the following artifacts:\n");
    DEBUG("\tKernel:     %s\n", kernel);
    if (ramdisk) {
        DEBUG("\tInitramfs:  %s\n", ramdisk);
    }
    if (cmdline) {
        DEBUG("\tCmdline:    %s\n", cmdline);
    }
    DEBUG("\tOVMF:       %s\n", ovmf);
    DEBUG("\tTDX-Module: %s\n", tdx_module);
    DEBUG("\tEventlog:   %d\n", print_event_log);
    DEBUG("\tSummary:    %d\n", print_summary);
    if (dump_kernel_path) {
        DEBUG("\nKernel measurement dump path: %s\n", dump_kernel_path);
    }

    uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH];

    if (calculate_mrseam(mrs[INDEX_MRSEAM], &evlog, tdx_module)) {
        printf("Failed to calculate event log for MRSEAM\n");
        goto out;
    }

    if (calculate_mrtd(mrs[INDEX_MRTD], &evlog, ovmf)) {
        printf("Failed to calculate event log for MRTD\n");
        goto out;
    }

    if (calculate_rtmr0(mrs[INDEX_RTMR0], &evlog, ovmf, &rtmr0_cfg)) {
        printf("Failed to calculate event log for RTMR 0\n");
        goto out;
    }

    if (calculate_rtmr1(mrs[INDEX_RTMR1], &evlog, kernel, &config, dump_kernel_path)) {
        printf("Failed to calculate event log for RTMR 1\n");
        goto out;
    }

    if (calculate_rtmr2(mrs[INDEX_RTMR2], &evlog, cmdline)) {
        printf("Failed to calculate event log for RTMR 2\n");
        goto out;
    }

    if (calculate_rtmr3(mrs[INDEX_RTMR3], &evlog)) {
        printf("Failed to calculate event log for RTMR 3\n");
        goto out;
    }

    // Print event log with all extend operations if requested
    if (print_event_log) {
        DEBUG("\nTDX EVENT LOG: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < MR_LEN; i++) {
            if (!evlog.log[i]) {
                DEBUG("No events for MR index %ld\n", i);
                continue;
            }
            // Remove last colon on final event log entry if format is json
            if (last_entry_json(&evlog, i)) {
                evlog.log[i][strlen(evlog.log[i]) - 2] = ']';
                evlog.log[i][strlen(evlog.log[i]) - 1] = '\0';
            }
            printf("%s", evlog.log[i]);
        }
        printf("\n");
    }

    // Print final MRS if requested
    if (print_summary) {
        DEBUG("\nTDX MR SUMMARY: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (uint32_t i = 0; i < MR_LEN; i++) {
            if (evlog.format == FORMAT_JSON) {
                printf(
                    "{\n\t\"type\":\"TDX Reference Value\",\n\t\"subtype\":\"MR Summary\",\n\t\"index\":%d,\n\t\"sha384\":\"", i);
                print_data_no_lf(mrs[i], SHA384_DIGEST_LENGTH, NULL);
                printf("\",\n\t\"description\":\"%s\"\n}", index_to_mr(i));
                if (i < MR_LEN - 1) {
                    printf(",\n");
                }
            } else if (evlog.format == FORMAT_TEXT) {
                printf("Name: %s", index_to_mr(i));
                print_data(mrs[i], SHA384_DIGEST_LENGTH, NULL);
            } else {
                printf("Unknown output format\n");
                goto out;
            }
        }
        if (evlog.format == FORMAT_JSON) {
            printf("]\n");
        }
    }

    ret = 0;

out:
    for (size_t i = 0; i < MR_LEN; i++) {
        if (evlog.log[i]) {
            free(evlog.log[i]);
        }
    }
    if (rtmr0_cfg.acpi_rsdp)
        free(rtmr0_cfg.acpi_rsdp);
    if (rtmr0_cfg.acpi_tables)
        free(rtmr0_cfg.acpi_tables);
    if (rtmr0_cfg.table_loader)
        free(rtmr0_cfg.table_loader);

    return ret;
}
