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

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "td_hob.h"
#include "mrtd.h"
#include "efi_boot.h"
#include "mrs.h"

volatile bool debug_output = false;

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t-m,  --mrs <num[,num...]>\tMeasurement registers to be calculated\n");
    printf("\t     --tdxmodule <file>\t\tThe filename of the TDX-module binary\n");
    printf("\t     --mrseam <hex>\t\tThe MRSEAM hash (alternative to --tdxmodule if hash is supplied externally\n");
    printf("\t-o,  --ovmf <file>\t\tThe filename of the OVMF.fd file\n");
    printf("\t     --mrtd <hex>\t\tThe MRTD hash (alternative to --ovmf if hash is supplied externally)\n");
    printf("\t     --ovmfversion <string>\tThe version of the OVMF image. Default: edk2-stable202502\n");
    printf("\t-k,  --kernel <file>\t\tThe filename of the kernel image\n");
    printf("\t-r,  --ramdisk <file>\t\tThe filename of the initramfs\n");
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-e,  --eventlog\t\t\tPrint detailed eventlog\n");
    printf("\t-s,  --summary\t\t\tPrint final MR values\n");
    printf("\t     --verbose\t\t\tPrint verbose debug output\n");
    printf("\t-c,  --config\t\t\tPath to configuration file\n");
    printf("\t     --cmdline\t\t\tKernel commandline\n");
    printf("\t     --addzeros <num>\t\tAdd <num> trailing zeros to kernel cmdline (default: 1)\n");
    printf("\t-a,  --acpirsdp\t\t\tPath to QEMU etc/acpi/rsdp file for RTMR0\n");
    printf("\t-t,  --acpitables\t\tPath to QEMU etc/acpi/tables file for RTMR0\n");
    printf("\t-l,  --tableloader\t\tPath to QEMU etc/table-loader file for RTMR0\n");
    printf("\t     --bootorder <num>[,<num>,...]\t\tUEFI boot order variable as a comma separated list of integers\n");
    printf("\t     --bootxxxx <file> UEFI Boot#### variable data file (multiple possible)\n");
    printf("\t     --secureboot <file> UEFI secure boot SecureBoot variable data file\n");
    printf("\t     --pk <file> UEFI secure boot Platform Key (PK) variable data file\n");
    printf("\t     --kek <file> UEFI secure boot Key Exchange Key (KEK) variable data file\n");
    printf("\t     --db <file> UEFI secure boot DB variable data file\n");
    printf("\t     --dbx <file> UEFI secure boot DBX variable data file\n");
    printf("\t     --gpt\t\t\tPath to EFI GPT partition table file to be extended into PCR5\n");
    printf("\t-q   --qemuversion\t\tQEMU version (default: 9.2.0)\n");
    printf("\t     --dumpkernel\t\tOptional path to folder to dump the measured kernel\n");
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
    const char *mrtd = NULL;
    const char *tdx_module = NULL;
    const char *mrseam = NULL;
    const char *dump_kernel_path = NULL;
    const char *ovmf_version = "edk2-stable202502";
    const char *secure_boot_path = NULL;
    const char *pk_path = NULL;
    const char *kek_path = NULL;
    const char *db_path = NULL;
    const char *dbx_path = NULL;
    uint16_t *boot_order = NULL;
    size_t len_boot_order = 0;
    char *boot_order_str;
    char **bootxxxx = NULL;
    size_t num_bootxxxx = 0;
    size_t cmdline_trailing_zeros = 1;
    bool print_event_log = false;
    bool print_summary = false;
    uint32_t *mr_nums = NULL;
    size_t len_mr_nums = 0;
    char *mr_str = NULL;
    const char *progname = argv[0];
    eventlog_t evlog = { .format = FORMAT_TEXT, .log = { 0 } };
    acpi_files_t acpi_files = {
        .acpi_rsdp = NULL,
        .acpi_rsdp_size = -1,
        .acpi_tables = NULL,
        .acpi_tables_size = -1,
        .table_loader = NULL,
        .table_loader_size = -1,
    };
    const char *qemu_version = "9.2.0";

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
        } else if (!strcmp(argv[0], "--addzeros") && argc >= 2) {
            long num = (size_t)strtol(argv[1], NULL, 0);
            if (num < 0) {
                printf("trailing zeros value %ld is invalid\n", num);
                return -1;
            }
            cmdline_trailing_zeros = (size_t)num;
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
        } else if (!strcmp(argv[0], "--mrtd") && argc >= 2) {
            mrtd = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--ovmfversion") && argc >= 2) {
            ovmf_version = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-q") || !strcmp(argv[0], "--qemuversion")) && argc >= 2) {
            qemu_version = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--tdxmodule") && argc >= 2) {
            tdx_module = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--mrseam") && argc >= 2) {
            mrseam = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-a") || !strcmp(argv[0], "--acpirsdp")) && argc >= 2) {
            acpi_files.acpi_rsdp_size = get_file_size(argv[1]);
            if (acpi_files.acpi_rsdp_size <= 0) {
                printf("Failed to get file size of ACPI RSDP file %s\n", argv[1]);
                goto out;
            }
            acpi_files.acpi_rsdp = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-t") || !strcmp(argv[0], "--acpitables")) && argc >= 2) {
            acpi_files.acpi_tables_size = get_file_size(argv[1]);
            if (acpi_files.acpi_tables_size <= 0) {
                printf("Failed to get file size of ACPI tables file %s\n", argv[1]);
                goto out;
            }
            acpi_files.acpi_tables = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-l") || !strcmp(argv[0], "--tableloader")) && argc >= 2) {
            acpi_files.table_loader_size = get_file_size(argv[1]);
            if (acpi_files.table_loader_size <= 0) {
                printf("Failed to get file size of table loader file %s\n", argv[1]);
                goto out;
            }
            acpi_files.table_loader = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--bootxxxx") && argc >= 2) {
            bootxxxx = (char **)realloc(bootxxxx, sizeof(char *) * (num_bootxxxx + 1));
            bootxxxx[num_bootxxxx++] = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--secureboot") && argc >= 2) {
            secure_boot_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--pk") && argc >= 2) {
            pk_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--kek") && argc >= 2) {
            kek_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--db") && argc >= 2) {
            db_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--dbx") && argc >= 2) {
            dbx_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--bootorder") && argc >= 2) {
            boot_order_str = (char *)malloc(strlen(argv[1]) + 1);
            if (!boot_order_str) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(boot_order_str, argv[1], strlen(argv[1]) + 1);
            char *pch = strtok(boot_order_str, ",");
            while (pch) {
                boot_order =
                    (uint16_t *)realloc(boot_order, sizeof(uint32_t) * (len_boot_order + 1));
                boot_order[len_boot_order] = (uint16_t)strtol(pch, NULL, 0);
                pch = strtok(NULL, ",");
                len_boot_order++;
            }
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
        } else if ((!strcmp(argv[0], "-m") || !strcmp(argv[0], "--mrs")) && argc >= 2) {
            mr_str = (char *)malloc(strlen(argv[1]) + 1);
            if (!mr_str) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(mr_str, argv[1], strlen(argv[1]) + 1);
            char *pch = strtok(mr_str, ",");
            while (pch) {
                mr_nums = (uint32_t *)realloc(mr_nums, sizeof(uint32_t) * (len_mr_nums + 1));
                mr_nums[len_mr_nums] = (uint32_t)strtol(pch, NULL, 0);
                pch = strtok(NULL, ",");
                len_mr_nums++;
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

    // If no boot order is given, set to default boot order
    if (!boot_order) {
        boot_order = (uint16_t *)calloc(1, sizeof(uint16_t));
        len_boot_order = 1;
    }


    if (!kernel && contains(mr_nums, len_mr_nums, INDEX_RTMR1)) {
        printf("Kernel must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!ovmf && !mrtd && (contains(mr_nums, len_mr_nums, INDEX_MRTD) ||
                  contains(mr_nums, len_mr_nums, INDEX_MRTD))) {
        printf("OVMF or MRTD hash must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!tdx_module && !mrseam && contains(mr_nums, len_mr_nums, INDEX_MRSEAM)) {
        printf("TDX-Module or MRSEAM hash must be specified\n");
        print_usage(progname);
        goto out;
    }
    if (!cmdline && contains(mr_nums, len_mr_nums, INDEX_RTMR2)) {
        printf("kernel cmdline must be specified\n");
        print_usage(progname);
        goto out;
    }

    if (len_mr_nums == 0) {
        printf("No measurement registers specified. Nothing to do\n");
        print_usage(progname);
        goto out;
    }
    for (size_t i = 0; i < len_mr_nums; i++) {
        if (mr_nums[i] >= MR_LEN) {
            printf("Invalid measurement register number %d\n", mr_nums[i]);
            goto out;
        }
    }

    DEBUG("Calculating TDX measurement registers\n");

    DEBUG("Using the following artifacts:\n");
    DEBUG("\tKernel:     %s\n", kernel);
    if (ramdisk) {
        DEBUG("\tInitramfs:  %s\n", ramdisk);
    }
    if (cmdline) {
        DEBUG("\tCmdline:    %s\n", cmdline);
    }
    if (ovmf) {
        DEBUG("\tOVMF:       %s\n", ovmf);
    }
    if (tdx_module) {
        DEBUG("\tTDX-Module: %s\n", tdx_module);
    }
    DEBUG("\tEventlog:   %d\n", print_event_log);
    DEBUG("\tSummary:    %d\n", print_summary);
    if (dump_kernel_path) {
        DEBUG("\nKernel measurement dump path: %s\n", dump_kernel_path);
    }
    if (boot_order) {
        DEBUG("BootOrder: [ ");
        for (size_t i = 0; i < len_boot_order; i++) {
            DEBUG("0x%04x ", boot_order[i]);
        }
        DEBUG("]\n");
    }
    for (size_t i = 0; i < num_bootxxxx; i++) {
        DEBUG("Boot####: %s\n", bootxxxx[i]);
    }
    if (secure_boot_path) {
        DEBUG("SecureBoot path: %s\n", secure_boot_path);
    }
    if (pk_path) {
        DEBUG("PK path: %s\n", pk_path);
    }
    if (kek_path) {
        DEBUG("KEK path: %s\n", kek_path);
    }
    if (db_path) {
        DEBUG("DB path: %s\n", db_path);
    }
    if (dbx_path) {
        DEBUG("DBX path: %s\n", dbx_path);
    }
    DEBUG("OVMF version: %s\n", ovmf_version);
    DEBUG("QEMU version: %s\n", qemu_version);

    uint8_t mrs[MR_LEN][SHA384_DIGEST_LENGTH];

    if (contains(mr_nums, len_mr_nums, INDEX_MRSEAM)) {
        if (calculate_mrseam(mrs[INDEX_MRSEAM], &evlog, tdx_module, mrseam)) {
            printf("Failed to calculate event log for MRSEAM\n");
            goto out;
        }
    }

    if (contains(mr_nums, len_mr_nums, INDEX_MRTD)) {
        if (calculate_mrtd(mrs[INDEX_MRTD], &evlog, ovmf, mrtd, qemu_version)) {
            printf("Failed to calculate event log for MRTD\n");
            goto out;
        }
    }

    if (contains(mr_nums, len_mr_nums, INDEX_RTMR0)) {
        if (calculate_rtmr0(mrs[INDEX_RTMR0], &evlog, ovmf, &acpi_files, ovmf_version,
                            boot_order, len_boot_order, bootxxxx, num_bootxxxx,
                            secure_boot_path, pk_path, kek_path, db_path, dbx_path)) {
            printf("Failed to calculate event log for RTMR 0\n");
            goto out;
        }
    }

    if (contains(mr_nums, len_mr_nums, INDEX_RTMR1)) {
        if (calculate_rtmr1(mrs[INDEX_RTMR1], &evlog, kernel, config_file, dump_kernel_path,
                            ovmf_version)) {
            printf("Failed to calculate event log for RTMR 1\n");
            goto out;
        }
    }

    if (contains(mr_nums, len_mr_nums, INDEX_RTMR2)) {
        if (calculate_rtmr2(mrs[INDEX_RTMR2], &evlog, cmdline, cmdline_trailing_zeros)) {
            printf("Failed to calculate event log for RTMR 2\n");
            goto out;
        }
    }

    if (contains(mr_nums, len_mr_nums, INDEX_RTMR3)) {
        if (calculate_rtmr3(mrs[INDEX_RTMR3], &evlog)) {
            printf("Failed to calculate event log for RTMR 3\n");
            goto out;
        }
    }

    // Print event log with all extend operations if requested
    if (print_event_log) {
        DEBUG("\nTDX EVENT LOG: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < len_mr_nums; i++) {
            if (!evlog.log[mr_nums[i]]) {
                DEBUG("No events for MR index %ld\n", i);
                continue;
            }
            // Remove last colon on final event log entry if format is json
            if (last_entry_json(&evlog, mr_nums[i])) {
                evlog.log[mr_nums[i]][strlen(evlog.log[mr_nums[i]]) - 2] = ']';
                evlog.log[mr_nums[i]][strlen(evlog.log[mr_nums[i]]) - 1] = '\0';
            }
            printf("%s", evlog.log[mr_nums[i]]);
        }
        printf("\n");
    }

    // Print final MRS if requested
    if (print_summary) {
        DEBUG("\nTDX MR SUMMARY: \n");
        if (evlog.format == FORMAT_JSON) {
            printf("[");
        }
        for (uint32_t i = 0; i < len_mr_nums; i++) {
            if (evlog.format == FORMAT_JSON) {
                printf(
                    "{\n\t\"type\":\"TDX Reference Value\",\n\t\"subtype\":\"MR Summary\",\n\t\"index\":%d,\n\t\"sha384\":\"",
                    mr_nums[i]);
                print_data_no_lf(mrs[mr_nums[i]], SHA384_DIGEST_LENGTH, NULL);
                printf("\",\n\t\"description\":\"%s\"\n}", index_to_mr(mr_nums[i]));
                if (i < len_mr_nums - 1) {
                    printf(",\n");
                }
            } else if (evlog.format == FORMAT_TEXT) {
                printf("Name: %s", index_to_mr(mr_nums[i]));
                print_data(mrs[mr_nums[i]], SHA384_DIGEST_LENGTH, NULL);
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
    if (mr_nums)
        free(mr_nums);
    if (mr_str)
        free(mr_str);
    for (size_t i = 0; i < MR_LEN; i++) {
        if (evlog.log[i]) {
            free(evlog.log[i]);
        }
    }
    if (acpi_files.acpi_rsdp)
        free(acpi_files.acpi_rsdp);
    if (acpi_files.acpi_tables)
        free(acpi_files.acpi_tables);
    if (acpi_files.table_loader)
        free(acpi_files.table_loader);

    if (bootxxxx) {
        free(bootxxxx);
    }
    if (boot_order) {
        free(boot_order);
    }

    return ret;
}
