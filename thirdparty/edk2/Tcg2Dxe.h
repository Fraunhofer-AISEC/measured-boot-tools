/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

#include "UefiBaseType.h"

#include "eventlog.h"

///
/// Index to a PCR register
///
typedef UINT32 TPM_PCRINDEX;

typedef UINT32        TCG_EVENTTYPE;

int MeasureVariable(
  IN      UINT8                     *pcr,
	IN      eventlog_t                *evlog,
  IN      TPM_PCRINDEX              PCRIndex,
  IN      TCG_EVENTTYPE             EventType,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  );

EFI_STATUS
MeasureAllSecureVariables (
  IN  UINT8       *pcr,
  IN  eventlog_t  *evlog
  );