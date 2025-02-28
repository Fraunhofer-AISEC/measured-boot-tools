/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uchar.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "efi_event.h"
#include "tpm2_eventlog.h"
#include "tpm2_alg_util.h"

#include "common.h"
#include "eventcb.h"
#include "hash.h"

/* converting byte buffer to hex string requires 2x, plus 1 for '\0' */
#define BYTES_TO_HEX_STRING_SIZE(byte_count) ((byte_count)*2 + 1)
#define EVENT_BUF_MAX BYTES_TO_HEX_STRING_SIZE(1024)
#define DIGEST_HEX_STRING_MAX BYTES_TO_HEX_STRING_SIZE(TPM2_MAX_DIGEST_BUFFER)
#define MAX_PCRS 24
#define VAR_DATA_HEX_SIZE(data) BYTES_TO_HEX_STRING_SIZE(data->VariableDataLength)

static int active_pcr;
// TODO better solution
static bool no_action_event_pending = false;

static void
bytes_to_str(uint8_t const *buf, size_t size, char *dest, size_t dest_size);
static void
mystrcat(char **dest, char *src);
static char const *
eventtype_to_string(UINT32 event_type);

static bool
event_uefi_var(void *d, UEFI_VARIABLE_DATA *data, size_t size, UINT32 type,
               uint32_t eventlog_version);
static bool
event_gpt(void *d, UEFI_GPT_DATA *data, size_t size, uint32_t eventlog_version);
static bool
event_ipl(void *data, UINT8 const *description, size_t size);
static bool
event_uefi_platfwblob(void *d, UEFI_PLATFORM_FIRMWARE_BLOB *data);
static bool
event_uefi_image_load(void *d, UEFI_IMAGE_LOAD_EVENT *data, size_t size);
static bool
event_uefi_action(void *data, UINT8 const *action, size_t size);
static bool
event_uefi_post_code(void *data, const TCG_EVENT2 *const event);
static bool
event_gpt(void *d, UEFI_GPT_DATA *data, size_t size, uint32_t eventlog_version);

static bool
contains(uint32_t *pcr_nums, uint32_t len, uint32_t value);

#define ADD_EVLOG(log, pcr_nums, len_pcr_nums, fmt, ...)                                           \
    do {                                                                                           \
        if (contains(pcr_nums, len_pcr_nums, active_pcr)) {                                        \
            char s[1024] = { 0 };                                                                  \
            int n = snprintf(s, sizeof(s), fmt, ##__VA_ARGS__);                                    \
            ASSERT(n > 0);                                                                         \
            mystrcat(&log[active_pcr], s);                                                         \
        }                                                                                          \
    } while (0)

#define ADD_EVLOG_DESCRIPTION(log, pcr_nums, len_pcr_nums, format, fmt, ...)                       \
    do {                                                                                           \
        if (contains(pcr_nums, len_pcr_nums, active_pcr)) {                                        \
            char s[1024] = { 0 };                                                                  \
            int n = 0;                                                                             \
            if (format == FORMAT_JSON) {                                                           \
                n = snprintf(s, sizeof(s), "\t\"description\":\"" fmt "\"\n},\n", ##__VA_ARGS__);  \
            } else {                                                                               \
                n = snprintf(s, sizeof(s), "\tdescription: " fmt "\n", ##__VA_ARGS__);             \
            }                                                                                      \
            ASSERT(n > 0);                                                                         \
            mystrcat(&log[active_pcr], s);                                                         \
        }                                                                                          \
    } while (0)

bool
event_specid_cb(TCG_EVENT const *event, void *data)
{
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    // Event type EV_NO_ACTION is not extended into PCRs
    if (event->eventType == EV_NO_ACTION) {
        return true;
    }

    char hexstr[DIGEST_HEX_STRING_MAX] = {
        0,
    };
    bytes_to_str(event->digest, sizeof(event->digest), hexstr, sizeof(hexstr));

    active_pcr = event->pcrIndex;

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(
            eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
            "{\n\t\"type\":\"TPM Reference Value\",\n\t\"name\":\"%s\",\n\t\"pcr\":%d,\n\t\"sha256\":\"%s\"\n},\n",
            eventtype_to_string(event->eventType), event->pcrIndex, hexstr);
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
                  "name: %s\n\tpcr: %d\n\tsha256: %s\n", eventtype_to_string(event->eventType),
                  event->pcrIndex, hexstr);
    }

    return true;
}

bool
event_initval_cb(void *data, int locality, int pcr)
{
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    //set the static variable for correct appending to the eventlog
    active_pcr = pcr;

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(
            eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
            "{\n\t\"type\":\"TPM Reference Value\",\n\t\"name\":\"TPM_PCR_INIT_VALUE\",\n\t\"pcr\":%d,\n\t\"sha256\":\"000000000000000000000000000000000000000000000000000000000000000%d\"\n},\n",
            pcr, locality);
    } else {
        ADD_EVLOG(
            eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
            "name: %s\n\tpcr: %d\n\tsha256: 000000000000000000000000000000000000000000000000000000000000000%d\n",
            "TPM_PCR_INIT_VALUE", pcr, locality);
    }

    return true;
}

bool
event_header_cb(TCG_EVENT const *event, size_t size, void *data)
{
    (void)size;
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    // Event type EV_NO_ACTION is not extended into PCRs
    if (event->eventType == EV_NO_ACTION) {
        return true;
    }

    char hexstr[DIGEST_HEX_STRING_MAX] = {
        0,
    };
    bytes_to_str(event->digest, sizeof(event->digest), hexstr, sizeof(hexstr));

    active_pcr = event->pcrIndex;

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(
            eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
            "{\n\t\"type\":\"TPM Reference Value\",\n\t\"name\":\"%s\",\n\t\"pcr\":%d,\n\t\"sha256\":\"%s\"\n},\n",
            eventtype_to_string(event->eventType), event->pcrIndex, hexstr);
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
                  "name: %s\n\tpcr: %d\n\tsha256: %s\n", eventtype_to_string(event->eventType),
                  event->pcrIndex, hexstr);
    }

    return true;
}

bool
event2_header_cb(TCG_EVENT_HEADER2 const *eventhdr, size_t size, void *data_in)
{
    (void)size;
    cb_data_t *cb_data = (cb_data_t *)data_in;
    char **eventlog = cb_data->eventlog;

    active_pcr = eventhdr->PCRIndex;

    // Event type EV_NO_ACTION is not extended into PCRs
    if (eventhdr->EventType == EV_NO_ACTION) {
        no_action_event_pending = true;
        return true;
    }

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
                  "{\n\t\"type\":\"TPM Reference Value\",\n\t\"name\":\"%s\",\n\t\"pcr\":%d,\n",
                  eventtype_to_string(eventhdr->EventType), eventhdr->PCRIndex);
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "name: %s\n\tpcr: %d\n",
                  eventtype_to_string(eventhdr->EventType), eventhdr->PCRIndex);
    }

    return true;
}

const char *
get_algo_str(TPM2_ALG_ID id)
{
    switch (id) {
    case TPM2_ALG_SHA1:
        return "sha1";
    case TPM2_ALG_SHA256:
        return "sha256";
    case TPM2_ALG_SHA384:
        return "sha384";
    case TPM2_ALG_SHA512:
        return "sha512";
    default:
        printf("Algorithm ID %u not supported\n", id);
    }
    return "unknown";
}

bool
event_digest_cb(TCG_DIGEST2 const *digest, size_t size, void *data_in)
{
    cb_data_t *cb_data = (cb_data_t *)data_in;
    char **eventlog = cb_data->eventlog;

    // No action event is not extended
    if (no_action_event_pending) {
        no_action_event_pending = false;
        return true;
    }

    const char *algo = get_algo_str(digest->AlgorithmId);

    char hexstr[DIGEST_HEX_STRING_MAX] = {
        0,
    };
    bytes_to_str(digest->Digest, size, hexstr, sizeof(hexstr));
    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "\t\"%s\":\"%s\",\n", algo,
                  hexstr);
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "\t%s: %s\n", algo, hexstr);
    }

    if (active_pcr >= MAX_PCRS) {
        printf("Active PCR %d invalid\n", active_pcr);
        return false;
    }
    if (digest->AlgorithmId == TPM2_ALG_SHA256) {
        hash_extend(EVP_sha256(), cb_data->calc_pcrs[active_pcr], (uint8_t *)digest->Digest,
                    SHA256_DIGEST_LENGTH);
    }

    return true;
}

bool
event_data_cb(TCG_EVENT2 const *event, UINT32 type, void *data, uint32_t eventlog_version)
{
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    if (event->EventSize == 0) {
        return true;
    }

    switch (type) {
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_EFI_VARIABLE_BOOT:
    case EV_EFI_VARIABLE_AUTHORITY:
        return event_uefi_var(data, (UEFI_VARIABLE_DATA *)event->Event, event->EventSize, type,
                              eventlog_version);
    case EV_POST_CODE:
        return event_uefi_post_code(data, event);
    case EV_S_CRTM_CONTENTS:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return event_uefi_platfwblob(data, (UEFI_PLATFORM_FIRMWARE_BLOB *)event->Event);
    case EV_EFI_ACTION:
        return event_uefi_action(data, event->Event, event->EventSize);
    case EV_IPL:
        return event_ipl(data, event->Event, event->EventSize);
    case EV_EFI_BOOT_SERVICES_APPLICATION:
    case EV_EFI_BOOT_SERVICES_DRIVER:
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return event_uefi_image_load(data, (UEFI_IMAGE_LOAD_EVENT *)event->Event, event->EventSize);
    case EV_EFI_GPT_EVENT:
        return event_gpt(data, (UEFI_GPT_DATA *)event->Event, event->EventSize, eventlog_version);
    case EV_NO_ACTION:
        // Event EV_NO_ACTION is not extended
        return true;
    default:
        ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                              "");
        return true;
    }

    return true;
}

static void
bytes_to_str(uint8_t const *buf, size_t size, char *dest, size_t dest_size)
{
    size_t i, j;

    for (i = 0, j = 0; i < size && j < dest_size - 2; ++i, j += 2) {
        sprintf(&dest[j], "%02x", buf[i]);
    }
    dest[j] = '\0';
}

static void
mystrcat(char **dest, char *src)
{
    if (!*dest) {
        size_t size = strlen(src) + 1;
        *dest = (char *)malloc(size);
        ASSERT(*dest);
        strncpy(*dest, src, size);
    } else {
        size_t size = ADD_WITH_OVERFLOW_CHECK(strlen(*dest), strlen(src));
        size = ADD_WITH_OVERFLOW_CHECK(size, 1);
        *dest = (char *)realloc(*dest, size);
        ASSERT(*dest);
        strncat(*dest, src, strlen(src) + 1);
    }
}

static void
guid_unparse_lower(EFI_GUID guid, char guid_buf[37])
{
    snprintf(guid_buf, 37, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1,
             guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
             guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

/*
 * TCG PC Client FPF section 9.2.6
 * The tpm2_eventlog module validates the event structure but nothing within
 * the event data buffer so we must do that here.
 */
static bool
event_uefi_var(void *d, UEFI_VARIABLE_DATA *data, size_t size, UINT32 type,
               uint32_t eventlog_version)
{
    ASSERT(eventlog_version == 2);
    (void)type;
    char uuidstr[37] = { 0 };

    if (size < sizeof(*data)) {
        printf("EventSize is too small\n");
        return false;
    }

    guid_unparse_lower(data->VariableName, uuidstr);

    cb_data_t *cb_data = (cb_data_t *)d;
    char **eventlog = cb_data->eventlog;
    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
                  "\t\"description\":\"Variable %s\"\n},\n", uuidstr);
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums,
                  "\tdescription: Variable %s\n", uuidstr);
    }

    return true;
}

/*
 * TCG PC Client PFP section 9.4.1
 * This event type is extensively used by the Shim and Grub on a wide varities
 * of Linux distributions to measure grub and kernel command line parameters and
 * the loading of grub, kernel, and initrd images.
 */
static bool
event_ipl(void *data, UINT8 const *description, size_t size)
{
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "\t\"description\":\"");
    } else {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "\tdescription: ");
    }

    /* Replace all tabs in description with spaces for valid json output */
    uint8_t *d = (uint8_t *)description;
    while (*d != '\0') {
        if (*d == '\t') {
            *d = ' ';
        }
        d++;
    }

    /* We need to handle when description contains multiple lines. */
    size_t i, j;
    for (i = 0; i < size; i++) {
        for (j = i; j < size; j++) {
            if (description[j] == '\n' || description[j] == '\0') {
                break;
            }
        }
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "%.*s", (int)(j - i),
                  description + i);
        i = j;
    }

    if (cb_data->format == FORMAT_JSON) {
        ADD_EVLOG(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, "\"\n},\n");
    }

    return true;
}

/* TCG PC Client FPF section 9.2.5 */
static bool
event_uefi_platfwblob(void *d, UEFI_PLATFORM_FIRMWARE_BLOB *data)
{
    cb_data_t *cb_data = (cb_data_t *)d;
    char **eventlog = cb_data->eventlog;
    ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                          "BlobBase: 0x%" PRIx64 ";  BlobLength: 0x%" PRIx64, data->BlobBase,
                          data->BlobLength);

    return true;
}

/* TCG PC Client PFP section 9.2.3 */
static bool
event_uefi_image_load(void *d, UEFI_IMAGE_LOAD_EVENT *data, size_t size)
{
    cb_data_t *cb_data = (cb_data_t *)d;
    char **eventlog = cb_data->eventlog;
    size_t devpath_len = (size - sizeof(*data)) * 2 + 1;
    char *buf = calloc(1, devpath_len);
    ASSERT(buf);

    bytes_to_str(data->DevicePath, size - sizeof(*data), buf, devpath_len);

    ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                          "ImageLocationInMemory: 0x%" PRIx64 "; "
                          "ImageLengthInMemory: %" PRIu64 "; "
                          "ImageLinkTimeAddress: 0x%" PRIx64 "; "
                          "LengthOfDevicePath: %" PRIu64 "; "
                          "DevicePath: %s",
                          data->ImageLocationInMemory, data->ImageLengthInMemory,
                          data->ImageLinkTimeAddress, data->LengthOfDevicePath, buf);

    free(buf);
    return true;
}

/* TCG PC Client PFP section 9.4.4 */
static bool
event_uefi_action(void *data, UINT8 const *action, size_t size)
{
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;
    ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                          "%.*s", (int)size, action);

    return true;
}

/*
 * TCG PC Client FPF section 2.3.4.1 and 9.4.1:
 * Usage of the event type EV_POST_CODE:
 * - If a combined event is measured, the event field SHOULD
 * be the string "POST CODE" in all caps. ...
 * - Embedded SMM code and the code that sets it up SHOULD use
 * the string "SMM CODE" in all caps...
 * - BIS code (excluding the BIS Certificate) should use event
 * field string of "BIS CODE" in all caps. ...
 * - ACPI flash data prior to any modifications ... should use
 * event field string of "ACPI DATA" in all caps.
 *
 * Section 9.2.5 also says "...Below is the definition of the
 * UEFI_PLATFORM_FIRMWARE_BLOB structure that the CRTM MUST put
 * into the Event Log entry TCG_PCR_EVENT2.event[1] field for
 * event types EV_POST_CODE, EV_S_CRTM_CONTENTS, and
 * EV_EFI_PLATFORM_FIRMWARE_BLOB."
 */

static bool
event_uefi_post_code(void *data, const TCG_EVENT2 *const event)
{
    const size_t len = event->EventSize;
    cb_data_t *cb_data = (cb_data_t *)data;
    char **eventlog = cb_data->eventlog;

    /* if length is 16, we treat it as EV_EFI_PLATFORM_FIRMWARE_BLOB */
    if (len == 16) {
        const UEFI_PLATFORM_FIRMWARE_BLOB *const blob =
            (const UEFI_PLATFORM_FIRMWARE_BLOB *)event->Event;
        ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                              "BlobBase: 0x%" PRIx64 ";  BlobLength: 0x%" PRIx64, blob->BlobBase,
                              blob->BlobLength);
    } else { // otherwise, we treat it as an ASCII string
        const char *const data = (const char *)event->Event;
        ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                              "%.*s", (int)len, data);
    }
    return true;
}

/* TCG PC Client PFP section 9.2.6 */
static bool
event_gpt(void *d, UEFI_GPT_DATA *data, size_t size, uint32_t eventlog_version)
{
    cb_data_t *cb_data = (cb_data_t *)d;
    char **eventlog = cb_data->eventlog;

    if (size < sizeof(*data)) {
        printf("EventSize(%zu) is too small\n", size);
        return false;
    }

    if (eventlog_version == 2) {
        UEFI_PARTITION_TABLE_HEADER *header = &data->UEFIPartitionHeader;
        char guid[37] = { 0 };

        guid_unparse_lower(header->DiskGUID, guid);

        ADD_EVLOG_DESCRIPTION(eventlog, cb_data->pcr_nums, cb_data->len_pcr_nums, cb_data->format,
                              "Signature: %.*s, "
                              "Revision: 0x%" PRIx32 ", "
                              "HeaderSize: %" PRIu32 ", "
                              "HeaderCRC32: 0x%" PRIx32 ", "
                              "MyLBA: 0x%" PRIx64 ", "
                              "AlternateLBA: 0x%" PRIx64 ", "
                              "FirstUsableLBA: 0x%" PRIx64 ", "
                              "LastUsableLBA: 0x%" PRIx64 ", "
                              "DiskGUID: %s, "
                              "PartitionEntryLBA: 0x%" PRIx64 ", "
                              "NumberOfPartitionEntry: %" PRIu32 ", "
                              "SizeOfPartitionEntry: %" PRIu32 ", "
                              "PartitionEntryArrayCRC32: 0x%" PRIx32 ", "
                              "NumberOfPartitions: %" PRIu64 ",",
                              8, (char *)&header->Signature, /* 8-char ASCII string */
                              header->Revision, header->HeaderSize, header->HeaderCRC32,
                              header->MyLBA, header->AlternateLBA, header->FirstUsableLBA,
                              header->LastUsableLBA, guid, header->PartitionEntryLBA,
                              header->NumberOfPartitionEntries, header->SizeOfPartitionEntry,
                              header->PartitionEntryArrayCRC32, data->NumberOfPartitions);
    }

    return true;
}

static char const *
eventtype_to_string(UINT32 event_type)
{
    switch (event_type) {
    case EV_PREBOOT_CERT:
        return "EV_PREBOOT_CERT";
    case EV_POST_CODE:
        return "EV_POST_CODE";
    case EV_UNUSED:
        return "EV_UNUSED";
    case EV_NO_ACTION:
        return "EV_NO_ACTION";
    case EV_SEPARATOR:
        return "EV_SEPARATOR";
    case EV_ACTION:
        return "EV_ACTION";
    case EV_EVENT_TAG:
        return "EV_EVENT_TAG";
    case EV_S_CRTM_CONTENTS:
        return "EV_S_CRTM_CONTENTS";
    case EV_S_CRTM_VERSION:
        return "EV_S_CRTM_VERSION";
    case EV_CPU_MICROCODE:
        return "EV_CPU_MICROCODE";
    case EV_PLATFORM_CONFIG_FLAGS:
        return "EV_PLATFORM_CONFIG_FLAGS";
    case EV_TABLE_OF_DEVICES:
        return "EV_TABLE_OF_DEVICES";
    case EV_COMPACT_HASH:
        return "EV_COMPACT_HASH";
    case EV_IPL:
        return "EV_IPL";
    case EV_IPL_PARTITION_DATA:
        return "EV_IPL_PARTITION_DATA";
    case EV_NONHOST_CODE:
        return "EV_NONHOST_CODE";
    case EV_NONHOST_CONFIG:
        return "EV_NONHOST_CONFIG";
    case EV_NONHOST_INFO:
        return "EV_NONHOST_INFO";
    case EV_OMIT_BOOT_DEVICE_EVENTS:
        return "EV_OMIT_BOOT_DEVICE_EVENTS";
    case EV_POST_CODE2:
        return "EV_POST_CODE2";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
        return "EV_EFI_VARIABLE_DRIVER_CONFIG";
    case EV_EFI_VARIABLE_BOOT:
        return "EV_EFI_VARIABLE_BOOT";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
        return "EV_EFI_BOOT_SERVICES_APPLICATION";
    case EV_EFI_BOOT_SERVICES_DRIVER:
        return "EV_EFI_BOOT_SERVICES_DRIVER";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return "EV_EFI_RUNTIME_SERVICES_DRIVER";
    case EV_EFI_GPT_EVENT:
        return "EV_EFI_GPT_EVENT";
    case EV_EFI_ACTION:
        return "EV_EFI_ACTION";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case EV_EFI_HANDOFF_TABLES:
        return "EV_EFI_HANDOFF_TABLES";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
        return "EV_EFI_PLATFORM_FIRMWARE_BLOB2";
    case EV_EFI_HANDOFF_TABLES2:
        return "EV_EFI_HANDOFF_TABLES2";
    case EV_EFI_GPT_EVENT2:
        return "EV_EFI_GPT_EVENT2";
    case EV_EFI_HCRTM_EVENT:
        return "EV_EFI_HCRTM_EVENT";
    case EV_EFI_VARIABLE_AUTHORITY:
        return "EV_EFI_VARIABLE_AUTHORITY";
    case EV_EFI_SPDM_FIRMWARE_BLOB:
        return "EV_EFI_SPDM_FIRMWARE_BLOB";
    case EV_EFI_SPDM_FIRMWARE_CONFIG:
        return "EV_EFI_SPDM_FIRMWARE_CONFIG";
    case EV_EFI_SPDM_DEVICE_POLICY:
        return "EV_EFI_SPDM_DEVICE_POLICY";
    case EV_EFI_SPDM_DEVICE_AUTHORITY:
        return "EV_EFI_SPDM_DEVICE_AUTHORITY";
    default:
        return "Unknown event type";
    }
}

static bool
contains(uint32_t *pcr_nums, uint32_t len, uint32_t value)
{
    for (uint32_t i = 0; i < len; i++) {
        if (pcr_nums[i] == value) {
            return true;
        }
    }
    return false;
}
