/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#define MAX_PCRS 24

/* TCG EFI Platform Specification For TPM Family 1.1 or 1.2 */
#define EV_EFI_EVENT_BASE                0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG    EV_EFI_EVENT_BASE + 0x1
#define EV_EFI_VARIABLE_BOOT             EV_EFI_EVENT_BASE + 0x2
#define EV_EFI_BOOT_SERVICES_APPLICATION EV_EFI_EVENT_BASE + 0x3
#define EV_EFI_BOOT_SERVICES_DRIVER      EV_EFI_EVENT_BASE + 0x4
#define EV_EFI_RUNTIME_SERVICES_DRIVER   EV_EFI_EVENT_BASE + 0x5
#define EV_EFI_GPT_EVENT                 EV_EFI_EVENT_BASE + 0x6
#define EV_EFI_ACTION                    EV_EFI_EVENT_BASE + 0x7
#define EV_EFI_PLATFORM_FIRMWARE_BLOB    EV_EFI_EVENT_BASE + 0x8
#define EV_EFI_HANDOFF_TABLES            EV_EFI_EVENT_BASE + 0x9
#define EV_EFI_VARIABLE_AUTHORITY        EV_EFI_EVENT_BASE + 0xe0

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    format_t format;
    char *log[MAX_PCRS];
} eventlog_t;

int
evlog_add(eventlog_t *evlog, uint32_t pcr_index, const char *name, uint32_t pcr, uint8_t *hash,
             const char *desc);

int
evlog_add_char16(eventlog_t *evlog, uint32_t pcr_index, const char *name, uint32_t pcr, uint8_t *hash, const unsigned short *desc);