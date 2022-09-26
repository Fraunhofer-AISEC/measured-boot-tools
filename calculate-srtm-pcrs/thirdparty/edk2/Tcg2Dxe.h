/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

int MeasureVariable(
    uint8_t *hash,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  );