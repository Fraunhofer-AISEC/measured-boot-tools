#pragma once

#include <stdint.h>
#include <stddef.h>

#include "eventlog.h"

#define LOAD_OPTION_ACTIVE (1 << 0)
#define LOAD_OPTION_HIDDEN (1 << 3)
#define LOAD_OPTION_CATEGORY_APP (1 << 8)

uint8_t *
calculate_efi_load_option(size_t *out_len);

int
calculate_efi_boot_vars(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                        uint16_t *boot_order, size_t len_boot_order, char **bootxxxx, size_t num_bootxxxx);