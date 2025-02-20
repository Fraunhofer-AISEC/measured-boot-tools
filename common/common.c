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
print_data_no_lf(const uint8_t *buf, size_t len, const char *info)
{
    if (info)
        printf("%s: ", info);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

void
print_data_file(const uint8_t *buf, size_t len, const char *file)
{
    FILE *fp = fopen(file, "w");
    for (size_t i = 0; i < len; i++) {
        // if (i % 16 == 0)
        // 	fprintf(fp,"\n0x%04lX:", i);
        fprintf(fp, "%02X", buf[i]);
    }
    fclose(fp);
}
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

void
print_data_ext(uint8_t *buf, uint32_t len, const char *Label)
{
    uint32_t i;

    printf("%s", Label);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n0x%04x:", i);
        printf(" %02X", buf[i]);
    }
    printf("\n");
}

void
print_data_debug(const uint8_t *buf, size_t len, const char *info)
{
    if (info)
        DEBUG("%s: ", info);
    for (size_t i = 0; i < len; i++) {
        DEBUG("%02X", buf[i]);
    }
    DEBUG("\n");
}

long
get_file_size(const char *filename)
{
    struct stat st = { 0 };
    stat(filename, &st);
    return st.st_size;
}

uint8_t *
read_file_new(const char *filename)
{
    if (access(filename, F_OK) != 0) {
        printf("File %s does not exist\n", filename);
        return NULL;
    }

    struct stat st;
    stat(filename, &st);
    uint64_t file_size = st.st_size;

    DEBUG("File size: %ld\n", file_size);

    uint8_t *buf = (uint8_t *)malloc(sizeof(uint8_t) * file_size);
    if (!buf) {
        printf("Failed to allocate memory\n");
        return NULL;
    }
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Failed to open %s\n", filename);
        return NULL;
    }
    size_t data_read = fread(buf, 1, file_size, f);
    fclose(f);
    if (data_read != (size_t)file_size) {
        printf("ERROR: Failed to read file. Only read: %ld of %ld\n", data_read, file_size);
        return NULL;
    }

    return buf;
}

int
read_file(uint8_t **buf, uint64_t *size, const char *filename)
{
    if (access(filename, F_OK) != 0) {
        printf("File %s does not exist\n", filename);
        return -1;
    }

    struct stat st;
    stat(filename, &st);
    uint64_t file_size = st.st_size;

    DEBUG("File size: %ld\n", file_size);

    *buf = (uint8_t *)malloc(sizeof(uint8_t) * file_size);
    if (!*buf) {
        printf("Failed to allocate memory\n");
        return -1;
    }
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Failed to open %s\n", filename);
        return -1;
    }
    size_t data_read = fread(*buf, 1, file_size, f);
    fclose(f);
    if (data_read != (size_t)file_size) {
        printf("ERROR: Failed to read file. Only read: %ld of %ld\n", data_read, file_size);
        return -1;
    }

    *size = file_size;

    return 0;
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

char *
convert_bin_to_hex(const uint8_t *bin, int length)
{
    // We need two chars per byte plus an additional \0 terminator
    // to convert the buffer to a hex string
    size_t len = length * (size_t)2;
    len = len * sizeof(char);
    len++;
    char *hex = calloc(1, len);
    if (!hex) {
        printf("Failed to allocate memory for bin to hex");
        return NULL;
    }

    for (int i = 0; i < length; ++i) {
        // snprintf additionally writes a '0' byte,
        // to write two actual characters we need a maximum size of three
        snprintf(hex + i * 2, 3, "%.2x", bin[i]);
    }

    return hex;
}