#pragma once

#include <stdint.h>
#include <stddef.h>

#include "eventlog.h"

int
calculate_efi_moklist_vars(const EVP_MD *md, uint8_t *mr, uint32_t mr_index, eventlog_t *evlog,
                        char **moklists, size_t num_moklists);