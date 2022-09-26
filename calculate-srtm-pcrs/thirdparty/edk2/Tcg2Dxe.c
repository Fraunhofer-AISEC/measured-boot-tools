/** @file
  This module implements Tcg2 Protocol.

Copyright (c) 2015 - 2019, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>

Copyright (c) 2022, Fraunhofer AISEC
Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.<BR>

This file was heavily modified to be used within the tpm-pcr-tools. Its only
purpose is now to measure an EFI variable.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "string.h"

#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"

#include <openssl/evp.h>

#include "common.h"
#include "hash.h"

///
/// UEFI_VARIABLE_DATA
///
/// This structure serves as the header for measuring variables. The name of the
/// variable (in Unicode format) should immediately follow, then the variable
/// data.
/// This is defined in TCG PC Client Firmware Profile Spec 00.21
///
#pragma pack (1)
typedef struct tdUEFI_VARIABLE_DATA {
  EFI_GUID                          VariableName;
  UINT64                            UnicodeNameLength;
  UINT64                            VariableDataLength;
  CHAR16                            UnicodeName[1];
  INT8                              VariableData[1];  ///< Driver or platform-specific data
} UEFI_VARIABLE_DATA;
#pragma pack ()

UINTN
EFIAPI
StrLen (
  IN      CONST CHAR16              *String
  )
{
  UINTN                             Length;

  ASSERT (String != NULL);
  ASSERT (((UINTN) String & BIT0) == 0);

  for (Length = 0; *String != L'\0'; String++, Length++) {
      ASSERT (Length < 0xffffffff);
  }
  return Length;
}

int MeasureVariable(
	uint8_t *hash,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  )
{
  UINTN                             VarNameLength;
  UEFI_VARIABLE_DATA                *VarLog;
  UINTN								event_size;

  VarNameLength      = StrLen (VarName);

  event_size = (UINT32)(sizeof (*VarLog) + VarNameLength * sizeof (*VarName) + VarSize
                        - sizeof (VarLog->UnicodeName) - sizeof (VarLog->VariableData));

  VarLog = (UEFI_VARIABLE_DATA *)malloc (event_size);
  if (VarLog == NULL) {
	  printf("Failed to allocate\n");
    return -1;
  }

  VarLog->VariableName       = *VendorGuid;
  VarLog->UnicodeNameLength  = VarNameLength;
  VarLog->VariableDataLength = VarSize;
  memcpy (
     VarLog->UnicodeName,
     VarName,
     VarNameLength * sizeof (*VarName)
     );
  if (VarSize != 0 && VarData != NULL) {
    memcpy (
       (CHAR16 *)VarLog->UnicodeName + VarNameLength,
       VarData,
       VarSize
       );
  }

	sha256(hash, (uint8_t *)VarLog, event_size);

  free (VarLog);
  return 0;
}