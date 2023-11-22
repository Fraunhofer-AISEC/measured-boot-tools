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

unsigned char *
memdup(const unsigned char *mem, size_t size)
{
    if (!mem) {
        return NULL;
    }
    unsigned char *p = calloc(1, size);
    if (!p) {
        return NULL;
    }
    memcpy(p, mem, size);
    return p;
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