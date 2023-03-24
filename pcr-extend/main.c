/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uchar.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "common.h"
#include "hash.h"

static void
print_usage(const char *progname)
{
    INFO("\nUsage: %s [options...]", progname);
    INFO("\t-h,  --help\t\tPrint help text");
    INFO("\t-i,  --in <data>[,<data>]\t\
        The numbers of the PCRs to be parsed as a comma separated list without spaces");
    INFO("\n");
}

int
main(int argc, char *argv[])
{
    uint8_t **inputs = NULL;
    size_t *input_lens = NULL;
    size_t num_inputs = 0;
    const char *progname = argv[0];
    int ret = -1;
    argv++;
    argc--;

    while (argc > 0) {
        if (!strcmp(argv[0], "-h") || !strcmp(argv[0], "--help")) {
            print_usage(progname);
            goto out;
        } else if ((!strcmp(argv[0], "-i") || !strcmp(argv[0], "--inputs")) && argc >= 2) {
            char *str = (char *)malloc(strlen(argv[1]) + 1);
            if (!str) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(str, argv[1], strlen(argv[1]) + 1);
            char *pch = strtok(str, ",");
            while (pch) {
                inputs = (uint8_t **)realloc(inputs, sizeof(uint8_t *) * (num_inputs + 1));
                if (!inputs) {
                    printf("Failed to allocate memory\n");
                    goto out;
                }
                input_lens = (size_t *)realloc(input_lens, sizeof(uint32_t) * (num_inputs + 1));
                if (!input_lens) {
                    printf("Failed to allocate memory\n");
                    goto out;
                }
                input_lens[num_inputs] = strlen(pch) / 2;
                inputs[num_inputs] = (uint8_t *)malloc(input_lens[num_inputs]);
                ret = convert_hex_to_bin(pch, strlen(pch), inputs[num_inputs],
                                         input_lens[num_inputs]);
                pch = strtok(NULL, ",");
                num_inputs++;
            }
            argv += 2;
            argc -= 2;
        } else {
            ERROR("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    uint8_t pcr[SHA256_DIGEST_LENGTH] = { 0 };
    for (size_t i = 0; i < num_inputs; i++) {
        print_data(pcr, SHA256_DIGEST_LENGTH, "PCR");
        print_data(inputs[i], input_lens[i], "DATA");
        hash_extend(EVP_sha256(), pcr, inputs[i], input_lens[i]);
    }
    print_data(pcr, SHA256_DIGEST_LENGTH, "PCR");

    ret = 0;

out:
    if (inputs) {
        for (size_t i = 0; i < num_inputs; i++) {
            if (inputs[i]) {
                free(inputs[i]);
            }
        }
        free(inputs);
    }

    return ret;
}