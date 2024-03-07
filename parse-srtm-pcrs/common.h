/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>

#define ASSERT(expr)                                                                               \
    if (!(expr)) {                                                                                 \
        printf("%s:%d %s: Assertion %s failed\n", __FILE__, __LINE__, __func__, #expr);            \
        abort();                                                                                   \
    }

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

#define UNUSED(x) (void)x

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

// The debug levels for debug output
#define DBG_NONE (0x0U)
#define DBG_ERR (0x1U)
#define DBG_WARN (0x2U)
#define DBG_INFO (0x4U)
#define DBG_DEBUG (0x8U)
#define DBG_VERB (0x16U)
#define DBG_TRACE (32U)

// Set the desired debug output here (The definitions from above can be OR'ed)
#define DEBUG_LEVEL (DBG_ERR | DBG_WARN | DBG_INFO)

#define print(lvl, fmt, ...)                                                                       \
    do {                                                                                           \
        if (DEBUG_LEVEL & (uint32_t)lvl)                                                           \
            printf(fmt "\n", ##__VA_ARGS__);                                                       \
    } while (0)

#define ERROR(fmt, ...) print(DBG_ERR, "ERROR: " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) print(DBG_WARN, "WARN: " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) print(DBG_INFO, fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...) print(DBG_DEBUG, "DEBUG: " fmt, ##__VA_ARGS__)
#define VERB(fmt, ...) print(DBG_VERB, "VERB: " fmt, ##__VA_ARGS__)
#define TRACE(fmt, ...) print(DBG_TRACE, "TRACE: " fmt, ##__VA_ARGS__)

// For tpm2-tools
#define LOG_ERR(fmt, ...) print(DBG_ERR, "ERROR: " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) print(DBG_WARN, "WARN: " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) print(DBG_INFO, fmt, ##__VA_ARGS__)

void
print_data(const uint8_t *buf, size_t len, const char *info);

void
print_data_no_lf(const uint8_t *buf, size_t len, const char *info);

#endif