#pragma once

#include <stdint.h>
#include <stddef.h>

#define LOAD_OPTION_ACTIVE (1 << 0)
#define LOAD_OPTION_HIDDEN (1 << 3)
#define LOAD_OPTION_CATEGORY_APP (1 << 8)

uint8_t *
calculate_efi_load_option(size_t *out_len);