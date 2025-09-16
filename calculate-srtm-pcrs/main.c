/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "common.h"
#include "hash.h"
#include "kernel_config.h"
#include "eventlog.h"
#include "paths.h"
#include "efi_boot.h"
#include "pcrs.h"

#define MAX_PCRS 24

volatile bool debug_output = false;

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s --pcrs <num[,num...]> [options...]\n", progname);
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-e,  --eventlog\t\t\tPrint detailed eventlog\n");
    printf("\t-s,  --summary\t\t\tPrint final PCR values\n");
    printf("\t-a   --aggregate\t\tPrint aggregate PCR value\n");
    printf("\t-p,  --pcrs <num[,num...]>\tPCRs to be calculated\n");
    printf("\t-v   --verbose\t\t\tPrint verbose debug output\n");
    printf("\t-q   --qemu\t\tQEMU VM (appends initrd=initrd to kernel cmdline\n)");
    printf("\t-o,  --ovmf <file>\t\tThe filename of the OVMF.fd file\n");
    printf("\t-c,  --config\t\t\tPath to kernel configuration file\n");
    printf("\t-k,  --kernel <file>\t\tThe filename of direct boot kernel images measured into PCR4\n");
    printf("\t-i,  --initrd <file>\t\tThe filename of the initrd/initramfs\n");
    printf("\t     --driver\t\t\tPath to 3rd party UEFI drivers (multiple --driver possible)\n");
    printf(
        "\t     --bootloader\t\t\tBootloader EFI image to be measured into PCR4 (multiple --bootloader possible)\n");
    printf("\t     --grubcmds\t\t\tPath to GRUB command file file for PCR8\n");
    printf("\t     --cmdline\t\t\tKernel commandline, required for some PCR 9 calculations\n");
    printf("\t     --addzeros <num>\t\tAdd <num> trailing zeros to kernel cmdline (default: 1)\n");
    printf("\t     --stripnewline\t\tStrip potential newline character from the cmdline\n");
    printf("\t     --acpirsdp\t\t\tPath to QEMU etc/acpi/rsdp file for PCR1\n");
    printf("\t     --acpitables\t\tPath to QEMU etc/acpi/tables file for PCR1\n");
    printf("\t     --tableloader\t\tPath to QEMU etc/table-loader file for PCR1\n");
    printf("\t     --tpmlog\t\t\tPath to QEMU etc/tpm/log file for PCR1\n");
    printf("\t     --sbatlevel\t\t\tSBAT level string for measuring DBX authority into PCR7\n");
    printf(
        "\t     --path\t\t\tPath to folder/file to be extended into PCR9, e.g. kernel (multiple --path possible)\n");
    printf("\t     --bootorder <num>[,<num>,...]\t\tUEFI boot order variable as a comma separated list of integers\n");
    printf("\t     --bootxxxx <file> UEFI Boot#### variable data file (multiple possible)\n");
    printf("\t     --secureboot <file> UEFI secure boot SecureBoot variable data file\n");
    printf("\t     --pk <file> UEFI secure boot Platform Key (PK) variable data file\n");
    printf("\t     --kek <file> UEFI secure boot Key Exchange Key (KEK) variable data file\n");
    printf("\t     --db <file> UEFI secure boot DB variable data file\n");
    printf("\t     --dbx <file> UEFI secure boot DBX variable data file\n");
    printf("\t     --gpt\t\t\tPath to EFI GPT partition table file to be extended into PCR5\n");
    printf("\t     --dumppei\t\t\tOptional path to folder to dump the measured PEIFV\n");
    printf("\t     --dumpdxe\t\t\tOptional path to folder to dump the measured DXEFV\n");
    printf("\n");
}

int
main(int argc, char *argv[])
{
    int ret = -1;
    const char *config_file = NULL;
    const char *kernel = NULL;
    const char *initrd = NULL;
    const char *cmdline = NULL;
    const char *ovmf = NULL;
    const char *efi_gpt = NULL;
    const char *grubcmds = NULL;
    const char *sbat_level = NULL;
    const char *dump_pei_path = NULL;
    const char *dump_dxe_path = NULL;
    const char *secure_boot_path = NULL;
    const char *pk_path = NULL;
    const char *kek_path = NULL;
    const char *db_path = NULL;
    const char *dbx_path = NULL;
    bool qemu = false;
    ssize_t cmdline_trailing_zeros = 1;
    bool cmdline_strip_newline = false;
    bool print_event_log = false;
    bool print_summary = false;
    bool print_aggregate = false;
    uint32_t *pcr_nums = NULL;
    size_t len_pcr_nums = 0;
    char *pcr_str = NULL;
    uint16_t *boot_order = NULL;
    size_t len_boot_order = 0;
    char *boot_order_str;
    char **bootxxxx = NULL;
    size_t num_bootxxxx = 0;
    const char *progname = argv[0];
    char **uefi_drivers = NULL;
    size_t num_uefi_drivers = 0;
    char **bootloaders = NULL;
    size_t num_bootloaders = 0;
    char **paths = NULL;
    size_t num_paths = 0;
    eventlog_t evlog = { .format = FORMAT_TEXT, .log = { 0 } };
    acpi_files_t acpi_files = {
        .acpi_rsdp_size = -1, .acpi_tables_size = -1, .table_loader_size = -1, .tpm_log_size = -1
    };

    argv++;
    argc--;

    if (argc < 2) {
        print_usage(progname);
        return -1;
    }

    while (argc > 0) {
        if ((!strcmp(argv[0], "-f") || !strcmp(argv[0], "--format")) && argc >= 2) {
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
        } else if ((!strcmp(argv[0], "-a") || !strcmp(argv[0], "--aggregate"))) {
            print_aggregate = true;
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
        } else if (!strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "-q") || !strcmp(argv[0], "--qemu")) {
            qemu = true;
            argv++;
            argc--;
        } else if ((!strcmp(argv[0], "-o") || !strcmp(argv[0], "--ovmf")) && argc >= 2) {
            ovmf = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-c") || !strcmp(argv[0], "--config")) && argc >= 2) {
            config_file = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-k") || !strcmp(argv[0], "--kernel")) && argc >= 2) {
            kernel = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-r") || !strcmp(argv[0], "--initrd")) && argc >= 2) {
            initrd = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--driver") && argc >= 2) {
            uefi_drivers = (char **)realloc(uefi_drivers, sizeof(char *) * (num_uefi_drivers + 1));
            uefi_drivers[num_uefi_drivers++] = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--bootloader") && argc >= 2) {
            bootloaders = (char **)realloc(bootloaders, sizeof(char *) * (num_bootloaders + 1));
            bootloaders[num_bootloaders++] = argv[1];
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
        } else if (!strcmp(argv[0], "--grubcmds") && argc >= 2) {
            grubcmds = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--sbatlevel") && argc >= 2) {
            sbat_level = argv[1];
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
        } else if (!strcmp(argv[0], "--stripnewline")) {
            cmdline_strip_newline = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "--acpirsdp") && argc >= 2) {
            acpi_files.acpi_rsdp_size = get_file_size(argv[1]);
            if (acpi_files.acpi_rsdp_size < 0) {
                printf("Failed to get file size of ACPI RSDP file %s\n", argv[1]);
                goto out;
            }
            acpi_files.acpi_rsdp = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--acpitables") && argc >= 2) {
            acpi_files.acpi_tables_size = get_file_size(argv[1]);
            if (acpi_files.acpi_tables_size < 0) {
                printf("Failed to get file size of ACPI tables file %s\n", argv[1]);
                goto out;
            }
            acpi_files.acpi_tables = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--tableloader") && argc >= 2) {
            acpi_files.table_loader_size = get_file_size(argv[1]);
            if (acpi_files.table_loader_size < 0) {
                printf("Failed to get file size of table loader file %s\n", argv[1]);
                goto out;
            }
            acpi_files.table_loader = read_file_new(argv[1]);
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--tpmlog") && argc >= 2) {
            acpi_files.tpm_log_size = get_file_size(argv[1]);
            if (acpi_files.tpm_log_size < 0) {
                printf("Failed to get file size of TPM log file %s\n", argv[1]);
                goto out;
            }
            acpi_files.tpm_log = read_file_new(argv[1]);
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
        } else if (!strcmp(argv[0], "--gpt")) {
            efi_gpt = argv[1];
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
        } else if (!strcmp(argv[0], "--dumppei")) {
            dump_pei_path = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--dumpdxe")) {
            dump_dxe_path = argv[1];
            argv += 2;
            argc -= 2;
        } else {
            printf("Invalid option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    // If no boot order is given, set to default boot order
    if (!boot_order) {
        boot_order = (uint16_t *)calloc(1, sizeof(uint16_t));
        len_boot_order = 1;
    }

    for (size_t i = 0; i < len_pcr_nums; i++) {
        if (pcr_nums[i] >= MAX_PCRS) {
            printf("Invalid PCR number %d\n", pcr_nums[i]);
            goto out;
        }
    }

    if (!kernel && !bootloaders && contains(pcr_nums, len_pcr_nums, 4)) {
        printf("Kernel/bootloader must be specified to calculate PCR4\n");
        print_usage(progname);
        goto out;
    }
    if (!ovmf && contains(pcr_nums, len_pcr_nums, 0)) {
        printf("OVMF must specified for calculating PCR0\n");
        print_usage(progname);
        goto out;
    }
    if (!cmdline && contains(pcr_nums, len_pcr_nums, 9)) {
        printf("Kernel cmdline must be specified for calculating PCR9\n");
        print_usage(progname);
        goto out;
    }

    DEBUG("Calculating PCRs [ ");
    for (uint32_t i = 0; i < len_pcr_nums; i++) {
        DEBUG("%d ", pcr_nums[i]);
    }
    DEBUG("] using:\n");
    DEBUG("\tKernel:     %s\n", kernel);
    if (initrd) {
        DEBUG("\tInitramfs:  %s\n", initrd);
    }
    if (cmdline) {
        DEBUG("\tCmdline:    %s\n", cmdline);
    }
    DEBUG("\tQEMU:       %s\n", qemu ? "true" : "false");
    DEBUG("\tOVMF:       %s\n", ovmf);
    DEBUG("\tEventlog:   %d\n", print_event_log);
    DEBUG("\tSummary:    %d\n", print_summary);
    DEBUG("\tAggregate:  %d\n", print_aggregate);
    DEBUG("\tSBAT Level: %s\n", sbat_level);
    for (size_t i = 0; i < num_uefi_drivers; i++) {
        DEBUG("\tUEFI driver: %s\n", uefi_drivers[i]);
    }
    for (size_t i = 0; i < num_bootloaders; i++) {
        DEBUG("\tBootloader: %s\n", bootloaders[i]);
    }
    for (size_t i = 0; i < num_paths; i++) {
        DEBUG("\tPaths: %s\n", paths[i]);
    }
    if (dump_pei_path) {
        DEBUG("\tPEIFV measurement dump path: %s\n", dump_pei_path);
    }
    if (dump_dxe_path) {
        DEBUG("\tDXEFV measurement dump path: %s\n", dump_dxe_path);
    }
    if (boot_order) {
        DEBUG("BootOrder: [");
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

    uint8_t pcr[MAX_PCRS][SHA256_DIGEST_LENGTH];

    if (contains(pcr_nums, len_pcr_nums, 0)) {
        if (calculate_pcr0(pcr[0], &evlog, ovmf, dump_pei_path, dump_dxe_path)) {
            printf("Failed to calculate event log for PCR 0\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 1)) {
        if (calculate_pcr1(pcr[1], &evlog, &acpi_files, boot_order, len_boot_order, bootxxxx,
                           num_bootxxxx)) {
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
        if (calculate_pcr4(pcr[4], &evlog, kernel, config_file, (const char **)bootloaders,
                           num_bootloaders)) {
            printf("Failed to calculate event log for PCR 4\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 5)) {
        if (calculate_pcr5(pcr[5], &evlog, efi_gpt)) {
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
        if (calculate_pcr7(pcr[7], &evlog, sbat_level, secure_boot_path, pk_path, kek_path, db_path,
                           dbx_path)) {
            printf("Failed to calculate event log for PCR 7\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 8)) {
        if (calculate_pcr8(pcr[8], &evlog, grubcmds)) {
            printf("Failed to calculate event log for PCR 8\n");
            goto out;
        }
    }
    if (contains(pcr_nums, len_pcr_nums, 9)) {
        if (calculate_pcr9(pcr[9], &evlog, cmdline, cmdline_trailing_zeros, cmdline_strip_newline, initrd, paths,
                           num_paths, qemu)) {
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
                    "{\n\t\"type\":\"TPM Reference Value\",\n\t\"subtype\":\"PCR Summary\",\n\t\"index\":%d,\n\t\"sha256\":\"",
                    pcr_nums[i]);
                print_data_no_lf(pcr[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
                printf("\",\n\t\"description\":\"PCR%d\"\n}", pcr_nums[i]);
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
    if (bootloaders)
        free(bootloaders);
    if (acpi_files.acpi_rsdp)
        free(acpi_files.acpi_rsdp);
    if (acpi_files.acpi_tables)
        free(acpi_files.acpi_tables);
    if (acpi_files.table_loader)
        free(acpi_files.table_loader);
    if (acpi_files.tpm_log)
        free(acpi_files.tpm_log);
    if (paths) {
        free(paths);
    }
    if (bootxxxx) {
        free(bootxxxx);
    }
    if (boot_order) {
        free(boot_order);
    }

    return ret;
}
