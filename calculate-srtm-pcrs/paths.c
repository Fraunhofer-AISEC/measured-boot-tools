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

static int
calculate_path(char *path, uint8_t *pcr, eventlog_t *evlog)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int ret = hash_file(EVP_sha256(), hash, path);
    if (ret) {
        return -1;
    }
    evlog_add(evlog, 9, "EV_IPL", hash, path);

    hash_extend(EVP_sha256(), pcr, hash, SHA256_DIGEST_LENGTH);

    return 0;
}

static int
calculate_paths_recursively(char *base_path, uint8_t *pcr, eventlog_t *evlog)
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
                calculate_paths_recursively(path, pcr, evlog);
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
                int ret = calculate_path(realfile, pcr, evlog);
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

int
calculate_paths(uint8_t *pcr, eventlog_t *evlog, char **paths, size_t num_paths)
{
    int ret = -1;

    // Recursively iterate over paths and log and extend all files
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
            ret = calculate_paths_recursively(paths[i], pcr, evlog);
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
            calculate_path(path, pcr, evlog);
            free(path);
        }
    }

    ret = 0;

    return ret;
}