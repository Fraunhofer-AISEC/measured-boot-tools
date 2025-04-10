/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "MeasureBootPeCoff.h"

typedef struct {
    kernel_setup_hdr_t kernel_setup_hdr;
} config_t;

int
config_load(config_t *config, const char *config_file);

int
config_prepare_kernel_pecoff(uint8_t *buf, uint64_t size, config_t *config);