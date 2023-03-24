/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"

void
print_data(const uint8_t *buf, size_t len, const char *info)
{
    if (info)
        printf("%s: ", info);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int
convert_hex_to_bin(const char *in, size_t inlen, uint8_t *out, size_t outlen)
{
    ASSERT(inlen >= 2);

    char *pos = (char *)in;
    size_t len = inlen;
    if (strncmp("0X", in, 2) == 0) {
        pos += 2;
        len -= 2;
    }
    if ((len % 2) != 0) {
        return -1;
    }
    if (outlen != (len / 2)) {
        return -2;
    }
    for (size_t i = 0; i < outlen; i++) {
        if ((uint8_t)*pos < 0x30 || (uint8_t)*pos > 0x66 ||
            ((uint8_t)*pos > 0x39 && (uint8_t)*pos < 0x40) ||
            ((uint8_t)*pos > 0x46 && (uint8_t)*pos < 0x61) || (uint8_t) * (pos + 1) < 0x30 ||
            (uint8_t) * (pos + 1) > 0x66 ||
            ((uint8_t) * (pos + 1) > 0x39 && (uint8_t) * (pos + 1) < 0x40) ||
            ((uint8_t) * (pos + 1) > 0x46 && (uint8_t) * (pos + 1) < 0x61)) {
            return -3;
        }
        sscanf(pos, "%2hhx", &out[i]);
        pos += 2;
    }
    return 0;
}