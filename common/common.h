/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <uchar.h>

#define ASSERT(expr)                                                                               \
    if (!(expr)) {                                                                                 \
        printf("%s:%d %s: Assertion %s failed\n", __FILE__, __LINE__, __func__, #expr);            \
        abort();                                                                                   \
    }

#define UNUSED __attribute__((unused))

#define ADD_WITH_OVERFLOW_CHECK(x, y)                                                              \
    __extension__({                                                                                \
        typeof(x) _x = (x);                                                                        \
        typeof(y) _y = (y);                                                                        \
        typeof(x + y) _res;                                                                        \
        if (__builtin_add_overflow(_x, _y, &_res)) {                                               \
            printf("Detected addition integer overflow.");                                         \
            abort();                                                                               \
        }                                                                                          \
        (_res);                                                                                    \
    })

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

extern volatile bool debug_output;

#define print(fmt, ...)                                                                            \
    do {                                                                                           \
        if (debug_output)                                                                          \
            printf(fmt, ##__VA_ARGS__);                                                            \
    } while (0)

#define DEBUG(fmt, ...) print(fmt, ##__VA_ARGS__)

// For tpm2-tools
#define LOG_ERR(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) print(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) print(fmt, ##__VA_ARGS__)

void
print_data(const uint8_t *buf, size_t len, const char *info);

void
print_data_file(const uint8_t *buf, size_t len, const char *file);

void
print_data_ext(uint8_t *buf, uint32_t len, const char *Label);

void
print_data_no_lf(const uint8_t *buf, size_t len, const char *info);

void
print_data_debug(const uint8_t *buf, size_t len, const char *info);

long
get_file_size(const char *filename);

uint8_t *
read_file_new(const char *filename);

int
read_file(uint8_t **buf, uint64_t *size, const char *filename);

int
write_file(const uint8_t *buf, size_t size, const char *filename);

int
convert_hex_to_bin(const char *in, size_t inlen, uint8_t *out, size_t outlen);

char *
convert_bin_to_hex(const uint8_t *bin, int length);

char16_t *
convert_to_char16(const char *in, size_t *out_len);

size_t
char16_strlen(const char16_t *str);

char *
convert_to_char(const char16_t *in, size_t *out_len);