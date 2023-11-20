/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "PiFirmwareVolume.h"
#include "MeasureBootPeCoff.h"
#include "Tcg2Dxe.h"
#include "SecMain.h"

#include "common.h"
#include "config.h"

static char *
trim(char *str)
{
    ASSERT(str);

    char *end;

    while (isspace(*str))
        str++;

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;

    end[1] = '\0';

    return str;
}

static int
set_val(config_t *c, const char *var, const char *val)
{
    if (strcmp(var, "PeCoffTypeOfLoader") == 0) {
        c->kernel_setup_hdr.type_of_loader = (uint8_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffLoadFlags") == 0) {
        c->kernel_setup_hdr.loadflags = (uint8_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffSetupMoveSize") == 0) {
        c->kernel_setup_hdr.setup_move_size = (uint16_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffCode32Start") == 0) {
        c->kernel_setup_hdr.code32_start = (uint32_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffRamdiskImage") == 0) {
        c->kernel_setup_hdr.ramdisk_image = (uint32_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffRamdiskSize") == 0) {
        c->kernel_setup_hdr.ramdisk_size = (uint32_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffBootsectKludge") == 0) {
        c->kernel_setup_hdr.bootsect_kludge = (uint32_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffHeapEndPtr") == 0) {
        c->kernel_setup_hdr.heap_end_ptr = (uint16_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffExtLoaderVer") == 0) {
        c->kernel_setup_hdr.ext_loader_ver = (uint8_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffExtLoaderType") == 0) {
        c->kernel_setup_hdr.ext_loader_type = (uint8_t)strtol(val, NULL, 16);
    } else if (strcmp(var, "PeCoffCmdLinePtr") == 0) {
        c->kernel_setup_hdr.cmd_line_ptr = (uint32_t)strtol(val, NULL, 16);
    } else {
        printf("Config %s unknown\n", var);
        return -1;
    }
    return 0;
}

static void
print_config(config_t *c)
{
    DEBUG("type_of_loader: %x\n", c->kernel_setup_hdr.type_of_loader);
    DEBUG("loadflags: %x\n", c->kernel_setup_hdr.loadflags);
    DEBUG("setup_move_size: %x\n", c->kernel_setup_hdr.setup_move_size);
    DEBUG("code32_start: %x\n", c->kernel_setup_hdr.code32_start);
    DEBUG("ramdisk_image: %x\n", c->kernel_setup_hdr.ramdisk_image);
    DEBUG("ramdisk_size: %x\n", c->kernel_setup_hdr.ramdisk_size);
    DEBUG("bootsect_kludge: %x\n", c->kernel_setup_hdr.bootsect_kludge);
    DEBUG("heap_end_ptr: %x\n", c->kernel_setup_hdr.heap_end_ptr);
    DEBUG("ext_loader_ver: %x\n", c->kernel_setup_hdr.ext_loader_ver);
    DEBUG("ext_loader_type: %x\n", c->kernel_setup_hdr.ext_loader_type);
    DEBUG("cmd_line_ptr: %x\n", c->kernel_setup_hdr.cmd_line_ptr);
    DEBUG("ramdisk_max: %x\n", c->kernel_setup_hdr.ramdisk_max);
}

int
config_load(config_t *config, const char *config_file)
{
    ASSERT(config);
    ASSERT(config_file);

    ssize_t read;
    char *line = NULL;
    size_t len = 0;

    // Read buffer line by line
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        printf("Failed to load config file %s\n", config_file);
        return -1;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        // Separate variable name and value
        char *var = strtok(strdup(line), "=");
        if (!var) {
            continue;
        }
        char *val = strtok(NULL, "=");
        if (!val) {
            free(var);
            continue;
        }

        // strip white spaces and tabs
        char *var_s = trim(var);
        char *val_s = trim(val);

        if (set_val(config, var_s, val_s)) {
            return -1;
        }
        free(var);
    }

    print_config(config);

    fclose(fp);
    if (line)
        free(line);

    return 0;
}

int
config_prepare_kernel_pecoff(uint8_t *buf, uint64_t size, config_t *config)
{
    if (size < sizeof(kernel_setup_hdr_t)) {
        printf("Failed to prepare kernel PE/COFF image: Image too small\n");
        return -1;
    }

    // modify kernel according to values set by the bootloader
    kernel_setup_hdr_t *hdr = (kernel_setup_hdr_t *)buf;

    hdr->type_of_loader = config->kernel_setup_hdr.type_of_loader;
    hdr->loadflags = config->kernel_setup_hdr.loadflags;
    hdr->setup_move_size = config->kernel_setup_hdr.setup_move_size;
    hdr->code32_start = config->kernel_setup_hdr.code32_start;
    hdr->ramdisk_image = config->kernel_setup_hdr.ramdisk_image;
    hdr->ramdisk_size = config->kernel_setup_hdr.ramdisk_size;

    hdr->bootsect_kludge = config->kernel_setup_hdr.bootsect_kludge;
    hdr->heap_end_ptr = config->kernel_setup_hdr.heap_end_ptr;
    hdr->ext_loader_ver = config->kernel_setup_hdr.ext_loader_ver;
    hdr->ext_loader_type = config->kernel_setup_hdr.ext_loader_type;
    hdr->cmd_line_ptr = config->kernel_setup_hdr.cmd_line_ptr;

    return 0;
}