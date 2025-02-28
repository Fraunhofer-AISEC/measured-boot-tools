/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#define MAX_PCRS 24

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    format_t format;
    char *log[MAX_PCRS];
} eventlog_t;

int
evlog_add(eventlog_t *evlog, uint32_t pcr_index, const char *name, uint8_t *hash, const char *desc);