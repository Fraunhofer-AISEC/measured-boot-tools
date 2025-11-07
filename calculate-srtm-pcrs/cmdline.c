/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <uchar.h>

#include <openssl/evp.h>

#include "common.h"
#include "hash.h"
#include "eventlog.h"


int
calculate_cmdline(uint8_t *pcr, eventlog_t *evlog, const char *cmdline, size_t trailing_zeros,
                            bool strip_newline, const char *initrd, bool qemu, int pcr_num,
                            const char *event_type)
{
    int ret = -1;
    char16_t *wcmdline = NULL;
    uint8_t *cmdline_buf = NULL;
    uint64_t cmdline_size = 0;
    ret = read_file(&cmdline_buf, &cmdline_size, cmdline);
    if (ret != 0 || cmdline_size == 0) {
        printf("Failed to load %s\n", cmdline);
        goto out;
    }

    // Strip trailing newline if specified
    if (strip_newline && cmdline_buf[cmdline_size - 1] == '\n') {
        cmdline_buf[cmdline_size - 1] = '\0';
        cmdline_size--;
    }

    // OvmfPkg/Library/X86QemuLoadImageLib/X86QemuLoadImageLib.c#L570
    // OVMF appends initrd=initrd if initial ramdisk was specified
    if (qemu && initrd) {
        uint64_t old_size = cmdline_size;
        const char *append = " initrd=initrd";
        cmdline_size += strlen(append);
        cmdline_buf = (uint8_t *)realloc(cmdline_buf, cmdline_size);
        memcpy(cmdline_buf + old_size, append, strlen(append));
    }

    char *cmdline_str = (char *)malloc(cmdline_size + 1);
    memset(cmdline_str, 0x0, cmdline_size + 1);
    memcpy(cmdline_str, cmdline_buf, cmdline_size);

    // EV_EVENT_TAG kernel commandline (OVMF uses CHAR16)
    size_t cmdline_len = 0;
    wcmdline = convert_to_char16((const char *)cmdline_buf, cmdline_size, &cmdline_len,
                                    trailing_zeros);
    if (!wcmdline) {
        printf("Failed to convert to wide character string\n");
        ret = -1;
        goto out;
    }

    DEBUG("cmdline file size: %lu\n", cmdline_size);
    DEBUG("cmdline strlen: %lu\n", strlen(cmdline_str));
    DEBUG("cmdline wchar len: %lu\n", cmdline_len);
    print_data_debug((const uint8_t *)wcmdline, cmdline_len, "cmdline");

    uint8_t hash_cmdline[SHA256_DIGEST_LENGTH] = { 0x0 };
    hash_buf(EVP_sha256(), hash_cmdline, (uint8_t *)wcmdline, cmdline_len);
    evlog_add(evlog, pcr_num, event_type, hash_cmdline, (const char *)cmdline_str);

    hash_extend(EVP_sha256(), pcr, hash_cmdline, SHA256_DIGEST_LENGTH);

out:
    if (wcmdline)
        free(wcmdline);
    if (cmdline_buf)
        free(cmdline_buf);
    if (cmdline_str)
        free(cmdline_str);

    return 0;
}