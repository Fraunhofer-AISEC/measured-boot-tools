/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#define ASSERT(expr)                                                                               \
    if (!(expr)) {                                                                                 \
        printf("%s:%d %s: Assertion %s failed\n", __FILE__, __LINE__, __func__, #expr);            \
        abort();                                                                                   \
    }

#define UNUSED __attribute__((unused))

extern volatile bool debug_output;

#define DEBUG(fmt, ...)                                                                            \
    do {                                                                                           \
        if (debug_output)                                                                          \
            printf(fmt, ##__VA_ARGS__);                                                            \
    } while (0)

void
print_data(const uint8_t *buf, size_t len, const char *info);

void
print_data_file(const uint8_t *buf, size_t len, const char *file);

void
print_data_ext(uint8_t *buf, uint32_t len, const char *Label);

void
print_data_no_lf(const uint8_t *buf, size_t len, const char *info);

unsigned char *
memdup(const unsigned char *mem, size_t size);

int
read_file(uint8_t **buf, uint64_t *size, const char *filename);
