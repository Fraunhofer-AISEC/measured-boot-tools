/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uchar.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "efi_event.h"
#include "tpm2_eventlog.h"
#include "tpm2_alg_util.h"

#include "common.h"
#include "eventcb.h"

#define BIOS_MEASUREMENTS "/sys/kernel/security/tpm0/binary_bios_measurements"

volatile bool debug_output = false;

static int
read_file_chunk(FILE *f, uint8_t *buf, size_t len, size_t *out_len)
{
    ASSERT(f);
    ASSERT(buf);

    size_t chunk_len = 0;
    do {
        chunk_len += fread(&buf[chunk_len], 1, len - chunk_len, f);
    } while (chunk_len < len && !feof(f) && errno == EINTR);

    *out_len += chunk_len;
    if (chunk_len == len)
        return 0;
    return -1;
}

static int
tpm_parse_eventlog(cb_data_t *cb_data, const char *filename)
{
    ASSERT(filename);

    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Failed to open event log file %s\n", filename);
        return -1;
    }

    uint8_t *eventbuf = calloc(1, CHUNK_SIZE);
    ASSERT(eventbuf);

    size_t size = 0;
    int ret;
    while ((ret = read_file_chunk(f, eventbuf + size, CHUNK_SIZE, &size)) == 0) {
        uint8_t *eventbuf_tmp = realloc(eventbuf, size + CHUNK_SIZE);
        ASSERT(eventbuf_tmp);
        eventbuf = eventbuf_tmp;
    }

    tpm2_eventlog_context ctx = {
        .data = cb_data,
        .specid_cb = event_specid_cb,
        .initval_cb = event_initval_cb,
        .event2hdr_cb = event2_header_cb,
        .log_eventhdr_cb = event_header_cb,
        .digest2_cb = event_digest_cb,
        .event2_cb = event_data_cb,
        .eventlog_version = 2,
    };

    if (!parse_eventlog(&ctx, eventbuf, size)) {
        ret = -1;
        printf("Failed to parse event log\n");
        goto out;
    }

    ret = 0;

out:
    if (f) {
        fclose(f);
    }

    if (eventbuf) {
        free(eventbuf);
    }

    return ret;
}

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t-h,  --help\t\tPrint help text\n");
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-p,  --pcrs <nums>\t\tPCRs to be parsed as a comma separated list without spaces\n");
    printf("\t-e,  --eventlog\t\tPrint the eventlog for the specified PCRs\n");
    printf("\t-s,  --summary\t\tPrint the final extended PCR values\n");
    printf("\t-a,  --aggregate\t\tPrint the aggregate PCR value over the selected PCRs\n");
    printf(
        "\t-i,  --in\t\tInput file (default: /sys/kernel/security/tpm0/binary_bios_measurements)\n");
    printf("\t-v,  --verbose\t\t\tPrint verbose debug output\n");
}

int
main(int argc, char *argv[])
{
    bool print_summary = false;
    bool print_eventlog = false;
    bool print_aggregate = false;
    uint32_t *pcr_nums = NULL;
    size_t len_pcr_nums = 0;
    format_t format = FORMAT_TEXT;
    const char *progname = argv[0];
    char *input_file = NULL;
    int ret = -1;
    argv++;
    argc--;

    cb_data_t cb_data = {
        .eventlog = { 0 },
        .format = format,
        .len_pcr_nums = len_pcr_nums,
        .pcr_nums = pcr_nums,
    };
    memset(cb_data.calc_pcrs, 0x0, sizeof(cb_data.calc_pcrs));

    while (argc > 0) {
        if (!strcmp(argv[0], "-h") || !strcmp(argv[0], "--help")) {
            print_usage(progname);
            goto out;
        } else if (!strcmp(argv[0], "-e") || !strcmp(argv[0], "--eventlog")) {
            print_eventlog = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "-s") || !strcmp(argv[0], "--summary")) {
            print_summary = true;
            argv++;
            argc--;
        } else if (!strcmp(argv[0], "-a") || !strcmp(argv[0], "--aggregate")) {
            print_aggregate = true;
            argv++;
            argc--;
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
        } else if ((!strcmp(argv[0], "-p") || !strcmp(argv[0], "--pcrs")) && argc >= 2) {
            char *str = (char *)malloc(strlen(argv[1]) + 1);
            if (!str) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(str, argv[1], strlen(argv[1]) + 1);
            char *pch = strtok(str, ",");
            while (pch) {
                pcr_nums = (uint32_t *)realloc(pcr_nums, sizeof(uint32_t) * (len_pcr_nums + 1));
                pcr_nums[len_pcr_nums] = (uint32_t)strtol(pch, NULL, 0);
                pch = strtok(NULL, ",");
                len_pcr_nums++;
            }
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-i") || !strcmp(argv[0], "--in")) && argc >= 2) {
            input_file = (char *)malloc(strlen(argv[1]) + 1);
            if (!input_file) {
                printf("Failed to allocate memory\n");
                goto out;
            }
            strncpy(input_file, argv[1], strlen(argv[1]) + 1);
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "-v") || !strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else {
            printf("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            goto out;
        }
    }

    if (len_pcr_nums == 0) {
        printf("No PCRs specified, nothing todo\n");
        print_usage(progname);
        goto out;
    }

    cb_data.format = format;
    cb_data.len_pcr_nums = len_pcr_nums;
    cb_data.pcr_nums = pcr_nums;

    if (tpm_parse_eventlog(&cb_data, input_file ? input_file : BIOS_MEASUREMENTS) < 0) {
        printf("Failed to parse eventlog\n");
        goto out;
    }

    if (print_eventlog) {
        if (format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < len_pcr_nums; i++) {
            // Determine if this is the last entry to remove semicolon
            bool last = true;
            for (size_t j = i + 1; j < len_pcr_nums; j++) {
                if (cb_data.eventlog[pcr_nums[j]]) {
                    last = false;
                }
            }
            if (!cb_data.eventlog[pcr_nums[i]]) {
                continue;
            }
            if (last) {
                cb_data.eventlog[pcr_nums[i]][strlen(cb_data.eventlog[pcr_nums[i]]) - 2] = '\n';
                cb_data.eventlog[pcr_nums[i]][strlen(cb_data.eventlog[pcr_nums[i]]) - 1] = '\0';
            }
            printf("%s", cb_data.eventlog[pcr_nums[i]]);
        }
        if (format == FORMAT_JSON) {
            printf("]\n");
        }
    }

    if (print_summary) {
        if (format == FORMAT_JSON) {
            printf("[");
        }
        for (size_t i = 0; i < len_pcr_nums; i++) {
            if (format == FORMAT_JSON) {
                printf(
                    "{\n\t\"type\":\"TPM Reference Value\",\n\t\"subtype\":\"PCR Summary\",\n\t\"pcr\":%d,\n\t\"sha256\":\"",
                    pcr_nums[i]);
                print_data_no_lf(cb_data.calc_pcrs[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
                printf("\",\n\t\"description\":\"PCR%d\"\n}", pcr_nums[i]);
                if (i < len_pcr_nums - 1) {
                    printf(",\n");
                }
            } else if (format == FORMAT_TEXT) {
                printf("PCR%d: ", pcr_nums[i]);
                print_data(cb_data.calc_pcrs[pcr_nums[i]], SHA256_DIGEST_LENGTH, NULL);
            } else {
                printf("Unknown output format\n");
                goto out;
            }
        }
        if (format == FORMAT_JSON) {
            printf("]\n");
        }
    }

    if (print_aggregate) {
        uint8_t aggregate[SHA256_DIGEST_LENGTH] = { 0 };

        EVP_MD_CTX *ctx;
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (uint32_t i = 0; i < len_pcr_nums; i++) {
            EVP_DigestUpdate(ctx, cb_data.calc_pcrs[pcr_nums[i]], SHA256_DIGEST_LENGTH);
        }
        EVP_DigestFinal_ex(ctx, aggregate, NULL);
        EVP_MD_CTX_free(ctx);

        if (format == FORMAT_JSON) {
            printf("{\n\t\"type\":\"TPM PCR Aggregate\",\n\t\"sha256\":\"");
            print_data_no_lf(aggregate, SHA256_DIGEST_LENGTH, NULL);
            printf("\"\n}\n");
        } else if (format == FORMAT_TEXT) {
            printf("PCR Aggregate: ");
            print_data(aggregate, SHA256_DIGEST_LENGTH, NULL);
        } else {
            printf("Unknown output format\n");
            goto out;
        }
    }

    ret = 0;

out:
    if (input_file)
        free(input_file);
    if (pcr_nums)
        free(pcr_nums);
    for (uint32_t i = 0; i < MAX_PCRS; i++)
        if (cb_data.eventlog[i])
            free(cb_data.eventlog[i]);

    return ret;
}