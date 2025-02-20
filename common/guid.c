/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"

#include "common.h"

bool
compare_guid(const GUID *g1, const GUID *g2)
{
    if (memcmp(g1->Data4, g2->Data4, sizeof(g1->Data4))) {
        return false;
    }

    return (g1->Data1 == g2->Data1 && g1->Data2 == g2->Data2 && g1->Data3 == g2->Data3);
}