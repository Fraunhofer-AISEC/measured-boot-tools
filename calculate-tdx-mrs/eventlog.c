/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "eventlog.h"
#include "hash.h"

const char *
index_to_mr(uint32_t index)
{
    switch (index) {
    case INDEX_MRTD:
        return "MRTD";
    case INDEX_RTMR0:
        return "RTMR0";
    case INDEX_RTMR1:
        return "RTMR1";
    case INDEX_RTMR2:
        return "RTMR2";
    case INDEX_RTMR3:
        return "RTMR3";
    case INDEX_MRSEAM:
        return "MRSEAM";
    default:
        return "unknown";
    }
}

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

int
evlog_add(eventlog_t *evlog, uint32_t index, const char *name, uint8_t *hash, const char *desc)
{
    int ret;
    char *hashstr = encode_hex(hash, SHA384_DIGEST_LENGTH);
    if (!hashstr) {
        printf("Failed to allocate memory\n");
        return -1;
    }

    char s[1024] = { 0 };
    if (evlog->format == FORMAT_JSON) {
        ret = snprintf(s, sizeof(s),
                       "{"
                       "\n\t\"type\":\"TDX Reference Value\","
                       "\n\t\"subtype\":\"%s\","
                       "\n\t\"index\":%d,"
                       "\n\t\"sha384\":\"%s\","
                       "\n\t\"description\":\"%s: %s\""
                       "\n},\n",
                       name, index, hashstr, index_to_mr(index), desc);
    } else if (evlog->format == FORMAT_TEXT) {
        ret = snprintf(s, sizeof(s),
                       "subtype: %s"
                       "\n\tindex: %d"
                       "\n\tsha384: %s"
                       "\n\tdescription: %s: %s\n",
                       name, index, hashstr, index_to_mr(index), desc);
    }
    if (!ret) {
        printf("Failed to print eventlog\n");
        ret = -1;
        goto out;
    }

    if (!evlog->log[index]) {
        size_t size = strlen(s) + 1;
        evlog->log[index] = (char *)malloc(size);
        if (!evlog->log[index]) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncpy(evlog->log[index], s, size);
    } else {
        size_t size = strlen(evlog->log[index]) + strlen(s) + 1;
        evlog->log[index] = (char *)realloc(evlog->log[index], size);
        if (!evlog->log[index]) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncat(evlog->log[index], s, strlen(s) + 1);
    }

out:
    free(hashstr);
    return ret;
}