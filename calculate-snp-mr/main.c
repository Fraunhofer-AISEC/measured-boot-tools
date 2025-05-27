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
#include "main.h"
#include "snp.h"

volatile bool debug_output = false;

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t-o,  --ovmf <file>\t\tThe filename of the OVMF.fd file\n");
    printf("\t-k,  --kernel <file>\t\tThe filename of the kernel image\n");
    printf("\t-r,  --initrd <file>\t\tThe filename of the initramfs\n");
    printf("\t     --cmdline\t\t\tKernel commandline\n");
    printf("\t     --vcpus <num>\t\tUse <num> vCPUs (default: 1)\n");
    printf("\t     --vmm-type <type>\t\tVMM type to use (qemu, ec2)\n");
    printf("\t     --verbose\t\t\tPrint verbose debug output\n");
    printf("\n");
}

vmm_type_t
get_vmm_type(const char *s)
{
    if (strcmp(s, "qemu") == 0) {
        return qemu;
    } else if (strcmp(s, "ec2") == 0) {
        return ec2;
    } else {
        return unknown;
    }
}

int
main(int argc, char *argv[])
{
    int ret = -1;
    const char *kernel = NULL;
    const char *initrd = NULL;
    const char *cmdline = NULL;
    const char *ovmf = NULL;
    size_t vcpus = 1;
    vmm_type_t vmm_type = qemu;
    uint8_t mr[SHA384_DIGEST_LENGTH];
    const char *progname = argv[0];

    argv++;
    argc--;

    while (argc > 0) {
        if ((!strcmp(argv[0], "-k") || !strcmp(argv[0], "--kernel")) && argc >= 2) {
            kernel = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--cmdline") && argc >= 2) {
            cmdline = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-r") || !strcmp(argv[0], "--initrd")) && argc >= 2) {
            initrd = argv[1];
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-o") || !strcmp(argv[0], "--ovmf")) && argc >= 2) {
            ovmf = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--vcpus") && argc >= 2) {
            long num = (size_t)strtol(argv[1], NULL, 0);
            if (num <= 0) {
                printf("invalid vcpus value '%ld'\n", num);
                print_usage(progname);
                goto out;
            }
            vcpus = (size_t)num;
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--vmm-type") && argc >= 2) {
            vmm_type = get_vmm_type(argv[1]);
            if (vmm_type == unknown) {
                printf("invalid vmm type: %s\n", argv[1]);
                print_usage(progname);
                goto out;
            }
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else {
            printf("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    if (!ovmf) {
        printf("OVMF must be specified\n");
        print_usage(progname);
        goto out;
    }

    DEBUG("Calculating SNP measurement registers\n");

    DEBUG("Using the following artifacts:\n");
    if (kernel) {
        DEBUG("\tKernel:     %s\n", kernel);
    }
    if (initrd) {
        DEBUG("\tInitramfs:  %s\n", initrd);
    }
    if (cmdline) {
        DEBUG("\tCmdline:    %s\n", cmdline);
    }
    if (ovmf) {
        DEBUG("\tOVMF:       %s\n", ovmf);
    }

    if (calculate_mr(mr, ovmf, kernel, initrd, cmdline, vcpus, vmm_type)) {
        printf("Failed to calculate snp measurement\n");
        goto out;
    }

    printf(
        "[{\n\t\"type\":\"SNP Reference Value\",\n\t\"subtype\":\"SNP Launch Digest\",\n\t\"index\":0,\n\t\"sha384\":\"");
    print_data_no_lf(mr, SHA384_DIGEST_LENGTH, NULL);
    printf("\",\n\t\"description\":\"SNP launch digest for %ld vCPUs\"\n}]\n", vcpus);

    ret = 0;

out:

    return ret;
}
