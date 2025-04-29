/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/sha.h>

#include "pcrs.h"
#include "eventlog.h"

int
calculate_acpi_tables(uint8_t *pcr, eventlog_t *evlog, pcr1_config_files_t *cfg);