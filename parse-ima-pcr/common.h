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

#ifndef COMMON_H_
#define COMMON_H_

#define ASSERT(expr)                                                                               \
    if (!(expr)) {                                                                                 \
        printf("%s:%d %s: Assertion %s failed\n", __FILE__, __LINE__, __func__, #expr);            \
        exit(-1);                                                                                  \
    }

// The debug levels for debug output
#define DBG_NONE (0x0U)
#define DBG_ERR (0x1U)
#define DBG_WARN (0x2U)
#define DBG_INFO (0x4U)
#define DBG_DEBUG (0x8U)
#define DBG_VERB (0x10U)
#define DBG_TRACE (0x20U)

// Set the desired debug output here (The definitions from above can be OR'ed)
#define DEBUG_LEVEL (DBG_ERR | DBG_WARN | DBG_INFO | DBG_VERB | DBG_TRACE)

#define print(lvl, fmt, ...)                                                                       \
    do {                                                                                           \
        if (DEBUG_LEVEL & (uint32_t)lvl)                                                           \
            printf(fmt "\n", ##__VA_ARGS__);                                                       \
    } while (0)

#define ERROR(fmt, ...) print(DBG_ERR, "ERROR: " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) print(DBG_WARN, "WARN: " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) print(DBG_INFO, "INFO: " fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...) print(DBG_DEBUG, "DEBUG: " fmt, ##__VA_ARGS__)
#define VERB(fmt, ...) print(DBG_VERB, "VERB: " fmt, ##__VA_ARGS__)
#define TRACE(fmt, ...) print(DBG_TRACE, "TRACE: " fmt, ##__VA_ARGS__)

unsigned char *
memdup(const unsigned char *mem, size_t size);

#endif