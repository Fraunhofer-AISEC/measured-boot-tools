/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#define MR_LEN 5

#define INDEX_MRTD 0
#define INDEX_RTMR0 1
#define INDEX_RTMR1 2
#define INDEX_RTMR2 3
#define INDEX_RTMR3 4

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    format_t format;
    char *log[MR_LEN];
} eventlog_t;

int
evlog_add(eventlog_t *evlog, uint32_t index, const char *name, uint8_t *hash, const char *desc);

const char *
index_to_mr(uint32_t index);