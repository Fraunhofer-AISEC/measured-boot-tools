/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#define MR_LEN 6

// UEFI Spec 2.10 Section 38.4.1:
// TPM PCR Index | CC Measurement Register Index | TDX-measurement register
//  ------------------------------------------------------------------------
// 0             |   0                           |   MRTD
// 1, 7          |   1                           |   RTMR[0]
// 2~6           |   2                           |   RTMR[1]
// 8~15          |   3                           |   RTMR[2]
#define INDEX_MRTD 0
#define INDEX_RTMR0 1
#define INDEX_RTMR1 2
#define INDEX_RTMR2 3
#define INDEX_RTMR3 4
// Additional reference values, not part of UEFI spec
#define INDEX_MRSEAM 5

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    format_t format;
    char *log[MR_LEN];
} eventlog_t;

int
evlog_add(eventlog_t *evlog, uint32_t index, const char *name, uint8_t *hash, const char *desc);

const char *
index_to_mr(uint32_t index);