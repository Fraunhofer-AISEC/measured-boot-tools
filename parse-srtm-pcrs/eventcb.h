/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef EVENTCB_H_
#define EVENTCB_H_

#define CHUNK_SIZE 16384
#define MAX_PCRS 24

#define SHA256_DIGEST_LENGTH 32

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    char *eventlog[MAX_PCRS];
    format_t format;
    size_t len_pcr_nums;
    uint32_t *pcr_nums;
    uint8_t calc_pcrs[MAX_PCRS][SHA256_DIGEST_LENGTH];
} cb_data_t;

bool
event_specid_cb(TCG_EVENT const *event, void *data);

bool
event_header_cb(TCG_EVENT const *event_hdr, size_t size, void *data);

bool
event2_header_cb(TCG_EVENT_HEADER2 const *eventhdr, size_t size, void *data_in);

bool
event_digest_cb(TCG_DIGEST2 const *digest, size_t size, void *data_in);

bool
event_data_cb(TCG_EVENT2 const *event, UINT32 type, void *data, uint32_t eventlog_version);

#endif
