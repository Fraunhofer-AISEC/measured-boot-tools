/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "UefiBaseType.h"
#include "UefiTcgPlatform.h"

#include "eventlog.h"

int MeasureVariable(
  IN      const EVP_MD              *md,
  IN      UINT8                     *mr,
  IN      UINT32                    mr_index,
	IN      eventlog_t                *evlog,
  IN      TCG_EVENTTYPE             EventType,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  );

EFI_STATUS
MeasureAllSecureVariables (
  IN  const EVP_MD  *md,
  IN  UINT8         *mr,
  IN  UINT32        mr_index,
  IN  eventlog_t    *evlog
  );

EFI_STATUS
MeasureAllBootVariables (
  IN      const EVP_MD  *md,
  IN      UINT8         *mr,
  IN      UINT32        mr_index,
  IN      eventlog_t    *evlog
  );