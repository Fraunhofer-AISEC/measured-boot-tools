/*
 * Copyright(c) 2022 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "hash.h"
#include "modsig.h"
#include "ima_measure.h"

#define BINARY_RUNTIME_MEASUREMENTS "/sys/kernel/security/ima/binary_runtime_measurements"

volatile bool debug_output = false;

static uint8_t *
ml_get_ima_list_new(const char *file, size_t *len)
{
    int fd = 0;

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        DEBUG("Could not open file %s", file);
        *len = 0;
        return NULL;
    }

    int ret = 0;
    uint8_t *buf = NULL;
    size_t l = 0;

    // The binary measurement file in /sys is a special file where the file size cannot
    // be determined. Therefore it must be read byte by byte
    while (true) {
        buf = (uint8_t *)realloc(buf, l + 1);
        ret = read(fd, buf + l, 1);

        if (ret == 0) {
            goto out;
        }
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DEBUG("Reading from fd %d: Blocked, retrying...", fd);
                continue;
            }
            free(buf);
            buf = NULL;
            l = 0;
            printf("Failed to read file %s", file);
            goto out;
        }
        l++;
    }

out:
    close(fd);
    *len = l;
    return buf;
}

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t-m,  --measurements <file>\t\tPath to IMA measurements file\n");
    printf("\t     --verbose\t\t\tPrint verbose debug output\n");
    printf("\n");
}

int
main(int argc, char *argv[])
{
    const char *ima_file = BINARY_RUNTIME_MEASUREMENTS;
    const char *progname = argv[0];
    argv++;
    argc--;

    while (argc > 0) {
        if ((!strcmp(argv[0], "-m") || !strcmp(argv[0], "--measurements")) && argc >= 2) {
            ima_file = argv[1];
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "-v") || !strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else {
            printf("Invalid option %s or argument missing\n", argv[0]);
            print_usage(progname);
            return -1;
        }
    }

    DEBUG("Parsing IMA Measurement list");

    size_t size = 0;
    uint8_t *data = ml_get_ima_list_new(ima_file, &size);
    if (!data) {
        printf("Failed to retrieve measurements (if reading from /sys, root is required)\n");
        return -1;
    }

    ima_parse_binary_runtime_measurements(data, size);

    if (data)
        free(data);

    return 0;
}
