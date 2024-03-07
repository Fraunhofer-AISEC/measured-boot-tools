/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <openssl/evp.h>

#include "common.h"
#include "hash.h"

typedef enum { FORMAT_JSON, FORMAT_TEXT } format_t;

typedef struct {
    format_t format;
    char *template;
    char *strip;
    long pcr;
    char *log;
} eventlog_t;

volatile bool debug_output = false;

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [options...]\n", progname);
    printf("\t-f,  --format <text|json>\tThe output format, can be either 'json' or 'text'\n");
    printf("\t-t,  --tpmpcr [num]\t\tIMA PCR (default: 10\n");
    printf("\t-v,  --verbose\t\t\tPrint verbose debug output\n");
    printf("\t-p,  --path <path>\t\tPath to to IMA binaries (files or folders), multiple -d possible\n");
    printf("\t-s,  --strip <path>\t\tPath prefix to be stripped from paths before hashing\n");
    printf("\t-i,  --imatemplate <template>\tIMA template to calculate entries for (ima-sig, ima-ng)\n");
    printf("\t-b,  --boot_aggregate <digest>\tDigest of the IMA boot_aggregate to be added to eventlog\n");
    printf("\n");
}

static char *
encode_hex(const uint8_t *bin, int length)
{
    size_t len = length * 2 + 1;
    char *hex = calloc(len, 1);
    for (int i = 0; i < length; ++i) {
        // snprintf writes a '0' byte
        snprintf(hex + i * 2, 3, "%.2x", bin[i]);
    }
    return hex;
}

static int
evlog_add(eventlog_t *evlog, char *path, uint8_t *hash, size_t hashlen, bool optional)
{
    int ret;
    char *hashstr = encode_hex(hash, hashlen);
    if (!hashstr) {
        printf("Failed to allocate memory\n");
        return -1;
    }

    char s[1024] = { 0 };
    if (evlog->format == FORMAT_JSON) {
        ret = snprintf(s, sizeof(s),
                       "{"
                       "\n\t\"type\":\"TPM Reference Value\","
                       "\n\t\"name\":\"%s\","
                       "\n\t\"pcr\":%ld,"
                       "\n\t\"sha256\":\"%s\","
                       "\n\t\"description\":\"%s\","
                       "\n\t\"optional\":%s"
                       "\n},\n",
                       basename(path), evlog->pcr, hashstr, path, optional ? "true" : "false");
    } else if (evlog->format == FORMAT_TEXT) {
        ret = snprintf(s, sizeof(s),
                       "name: %s"
                       "\n\tpcr: %ld"
                       "\n\tsha256: %s"
                       "\n\tdescription: %s\n",
                       basename(path), evlog->pcr, hashstr, path);
    }
    if (!ret) {
        printf("Failed to print event log\n");
        ret = -1;
        goto out;
    }

    if (!evlog->log) {
        size_t size = strlen(s) + 1;
        evlog->log = (char *)malloc(size);
        if (!evlog->log) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncpy(evlog->log, s, size);
    } else {
        size_t size = strlen(evlog->log) + strlen(s) + 1;
        evlog->log = (char *)realloc(evlog->log, size);
        if (!evlog->log) {
            printf("Failed to allocate memory\n");
            ret = -1;
            goto out;
        }
        strncat(evlog->log, s, strlen(s) + 1);
    }

out:
    free(hashstr);
    return 0;
}

static char *
concat_path_new(const char *s1, const char *s2)
{
    size_t len = snprintf(NULL, 0, "%s/%s", s1, s2);

    char *s = (char *)malloc(len + 1);
    if (s == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    snprintf(s, len + 1, "%s/%s", s1, s2);

    return s;
}

static char *
strip_prefix_new(char *s, char *prefix) {
    if (!s) {
        return NULL;
    }
    if (prefix && strncmp(s, prefix, strlen(prefix)) == 0) {
        return strdup(s + strlen(prefix));
    }
    return strdup(s);
}

static int
calculate_ima_entry(uint8_t hash[SHA256_DIGEST_LENGTH], char *path, eventlog_t *evlog, bool optional)
{
    const char *hash_algo = "sha256:";
    uint32_t ima_digest_len = strlen("sha256:") + 1 + SHA256_DIGEST_LENGTH;
    uint32_t path_len = strlen(path) + 1;
    uint32_t sig_len = 0x0;
    uint32_t template_len;

    if (!strcmp(evlog->template, "ima-sig")) {
        template_len = sizeof(uint32_t) + // length of hashalgo+hash
                       ima_digest_len +   // length of sha256:\0<digest>
                       sizeof(uint32_t) + // length of binary name
                       path_len +         // length of binary\0
                       sizeof(uint32_t);  // signature length
    } else if (!strcmp(evlog->template, "ima-ng")) {
        template_len = sizeof(uint32_t) + // length of hashalgo+hash
                       ima_digest_len +   // length of sha256:\0<digest>
                       sizeof(uint32_t) + // length of binary name
                       path_len;          // length of binary\0
    } else {
        printf("Template %s not supported\n", evlog->template);
        return -1;
    }
    uint8_t template[template_len];
    uint32_t cursor = 0;

    // Create ima-sig template
    memcpy(template + cursor, &ima_digest_len, sizeof(uint32_t));
    cursor += sizeof(uint32_t);
    memcpy(template + cursor, hash_algo, strlen(hash_algo) + 1);
    cursor += strlen(hash_algo) + 1;
    memcpy(template + cursor, hash, SHA256_DIGEST_LENGTH);
    cursor += SHA256_DIGEST_LENGTH;
    memcpy(template + cursor, &path_len, sizeof(uint32_t));
    cursor += sizeof(uint32_t);
    memcpy(template + cursor, path, strlen(path) + 1);
    if (!strcmp(evlog->template, "ima-sig")) {
        cursor += strlen(path) + 1;
        memcpy(template + cursor, &sig_len, sizeof(uint32_t));
    }

    // Calculate hash of template
    uint8_t template_hash[SHA256_DIGEST_LENGTH];
    hash_buf(EVP_sha256(), template_hash, template, template_len);

    // Write entry
    evlog_add(evlog, path, template_hash, sizeof(template_hash), optional);

    return 0;
}

static int
calculate_ima_entry_path(char *path, eventlog_t *evlog)
{
    int ret = -1;

    DEBUG("Calculating PCR%ld entry for path %s\n", evlog->pcr, path);

    // Calculate hash of file
    uint8_t hash[SHA256_DIGEST_LENGTH];
    ret = hash_file(EVP_sha256(), hash, path);
    if (ret) {
        return -1;
    }

    // Strip binary path of potential prefixes
    char *stripped_path = strip_prefix_new(path, evlog->strip);
    if (!stripped_path) {
        printf("Failed to strip path\n");
        return -1;
    }

    ret = calculate_ima_entry(hash, stripped_path, evlog, true);

    free(stripped_path);

    return ret;
}

static int
calculate_ima_entries_recursively(char *base_path, eventlog_t *evlog)
{
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(base_path);

    if (!dir) {
        return -1;
    }

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            struct stat statbuf;
            snprintf(path, sizeof(path), "%s/%s", base_path, dp->d_name);
            stat(path, &statbuf);

            if (S_ISDIR(statbuf.st_mode)) {
                calculate_ima_entries_recursively(path, evlog);
            } else {
                char *file = concat_path_new(base_path, dp->d_name);
                if (!file) {
                    printf("Failed to calculate path\n");
                    return -1;
                }
                char *realfile = realpath(file, NULL);
                if (!realfile) {
                    DEBUG("WARN: Failed to get real path for %s\n", file);
                    continue;
                }
                int ret = calculate_ima_entry_path(realfile, evlog);
                free(file);
                free(realfile);
                if (ret) {
                    printf("Failed to calculate ima entry\n");
                    return -1;
                }
            }
        }
    }

    closedir(dir);

    return 0;
}

static int
calculate_ima_entries(char **paths, size_t num_paths, eventlog_t *evlog)
{
    int ret = -1;

    for (size_t i = 0; i < num_paths; i++) {
        // Check if path exists
        struct stat path_stat;
        ret = stat(paths[i], &path_stat);
        if (ret) {
            printf("Path %s does not exist\n", paths[i]);
            return -1;
        }

        // Check if path is directory
        if (S_ISDIR(path_stat.st_mode)) {
            DEBUG("Path %s is a directory. Traversing..\n", paths[i]);
            ret = calculate_ima_entries_recursively(paths[i], evlog);
            if (ret) {
                printf("Failed to calculate ima entries recursively\n");
                return -1;
            }
        } else {
            char *path = realpath(paths[i], NULL);
            if (!path) {
                printf("WARN: Failed to get real path for %s\n", paths[i]);
                continue;
            }
            calculate_ima_entry_path(path, evlog);
            free(path);
        }
    }

    ret = 0;

    return ret;
}

int
main(int argc, char *argv[])
{
    int ret = -1;
    const char *progname = argv[0];
    eventlog_t evlog = { .format = FORMAT_JSON, .log = NULL, .template = NULL, .strip = NULL, .pcr = 10 };
    char **paths = NULL;
    size_t num_paths = 0;
    uint8_t *boot_aggregate = NULL;
    long boot_aggregate_len = 0;

    argv++;
    argc--;

    while (argc > 0) {
        if ((!strcmp(argv[0], "-f") || !strcmp(argv[0], "--format")) && argc >= 2) {
            if (!strcmp(argv[1], "json")) {
                evlog.format = FORMAT_JSON;
            } else if (!strcmp(argv[1], "text")) {
                evlog.format = FORMAT_TEXT;
            } else {
                printf("Unknown format '%s'\n", argv[1]);
                print_usage(progname);
                ret = -1;
                goto out;
            }
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-t") || !strcmp(argv[0], "--tpmpcr")) && argc >= 2) {
            char *p;
            evlog.pcr = strtol(argv[1], &p, 10);
            if (errno || p == argv[1] || *p != '\0') {
                printf("-t/--tpm pcrs expects number\n");
                print_usage(progname);
                ret = -1;
                goto out;
            }
            argv += 2;
            argc -= 2;
        } else if (!strcmp(argv[0], "-v") || !strcmp(argv[0], "--verbose")) {
            debug_output = true;
            argv++;
            argc--;
        } else if ((!strcmp(argv[0], "-p") || !strcmp(argv[0], "--path")) && argc >= 2) {
            paths = (char **)realloc(paths, sizeof(char *) * (num_paths + 1));
            paths[num_paths] = argv[1];
            if (paths[num_paths][strlen(paths[num_paths]) - 1] == '/') {
                paths[num_paths][strlen(paths[num_paths]) - 1] = '\0';
            }
            num_paths++;
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-s") || !strcmp(argv[0], "--strip")) && argc >= 2) {
            evlog.strip = (char *)malloc(strlen(argv[1]) + 1);
            if (!evlog.strip) {
                printf("Failed to allocate memory\n");
                ret = -1;
                goto out;
            }
            strncpy(evlog.strip, argv[1], strlen(argv[1]) + 1);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-i") || !strcmp(argv[0], "--imatemplate")) && argc >= 2) {
            evlog.template = (char *)malloc(strlen(argv[1]) + 1);
            if (!evlog.template) {
                printf("Failed to allocate memory\n");
                ret = -1;
                goto out;
            }
            strncpy(evlog.template, argv[1], strlen(argv[1]) + 1);
            argv += 2;
            argc -= 2;
        } else if ((!strcmp(argv[0], "-b") || !strcmp(argv[0], "--boot_aggregate")) && argc >= 2) {
            boot_aggregate = OPENSSL_hexstr2buf(argv[1], &boot_aggregate_len);
            if (!boot_aggregate) {
                printf("Failed to allocate memory for boot_aggregate\n");
                ret = -1;
                goto out;
            }
            argv += 2;
            argc -= 2;
        } else {
            printf("Invalid Option %s or argument missing\n", argv[0]);
            print_usage(progname);
            ret = -1;
            goto out;
        }
    }

    if (!paths && !boot_aggregate) {
        printf("No paths and no boot_aggregate specified. Nothing to do\n");
        print_usage(progname);
        ret = -1;
        goto out;
    }

    if (evlog.template == NULL) {
        evlog.template = strdup("ima-sig");
    }

    DEBUG("Format: %d\n", evlog.format);
    DEBUG("IMA PCR: %ld\n", evlog.pcr);
    DEBUG("Template: %s\n", evlog.template);
    DEBUG("Strip path prefix: %s\n", evlog.strip);
    if (boot_aggregate) {
        print_data_debug(boot_aggregate, boot_aggregate_len, "Boot Aggregate");
    }
    DEBUG("Paths: ");
    for (size_t i = 0; i < num_paths; i++) {
        if (i < (num_paths - 1)) {
            DEBUG("%s, ", paths[i]);
        } else {
            DEBUG("%s\n", paths[i]);
        }
    }

    if (boot_aggregate) {
        if (boot_aggregate_len != SHA256_DIGEST_LENGTH) {
            printf("Only sha256 digests supported\n");
            ret = -1;
            goto out;
        }
        ret = calculate_ima_entry(boot_aggregate, "boot_aggregate", &evlog, false);
        if (ret) {
            printf("Failed to calculate boot_aggregate\n");
            ret = -1;
            goto out;
        }
    }

    ret = calculate_ima_entries(paths, num_paths, &evlog);
    if (ret) {
        printf("Failed to calculate ima entries\n");
        ret = -1;
        goto out;
    }
    if (!evlog.log) {
        printf("Failed to print event log: null\n");
        ret = -1;
        goto out;
    }

    // Create json array
    if (evlog.format == FORMAT_JSON) {
        printf("[");
    }
    // Remove last colon on final event log entry if format is json
    if (evlog.format == FORMAT_JSON) {
        evlog.log[strlen(evlog.log) - 2] = ']';
        evlog.log[strlen(evlog.log) - 1] = '\0';
    }
    printf("%s\n", evlog.log);

out:
    if (evlog.log) {
        free(evlog.log);
    }
    if (evlog.strip) {
        free(evlog.strip);
    }
    if (evlog.template) {
        free(evlog.template);
    }
    if (paths) {
        free(paths);
    }
    if (boot_aggregate) {
        free(boot_aggregate);
    }
    return ret;
}