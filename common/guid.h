/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"

bool
compare_guid(const GUID *g1, const GUID *g2);