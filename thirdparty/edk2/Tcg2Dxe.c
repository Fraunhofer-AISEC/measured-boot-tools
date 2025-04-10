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
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "string.h"

#include "GlobalVariable.h"
#include "ImageAuthentication.h"
#include "ProcessorBind.h"
#include "Base.h"
#include "UefiBaseType.h"
#include "PeImage.h"
#include "PeCoffLib.h"
#include "Tcg2Dxe.h"
#include "UefiTcgPlatform.h"

#include "common.h"
#include "hash.h"
#include "eventlog.h"


EFI_GUID gEfiGlobalVariableGuid = EFI_GLOBAL_VARIABLE;

EFI_GUID gEfiImageSecurityDatabaseGuid = EFI_IMAGE_SECURITY_DATABASE_GUID;

VARIABLE_TYPE  mVariableType[] = {
  { EFI_SECURE_BOOT_MODE_NAME,    &gEfiGlobalVariableGuid        },
  { EFI_PLATFORM_KEY_NAME,        &gEfiGlobalVariableGuid        },
  { EFI_KEY_EXCHANGE_KEY_NAME,    &gEfiGlobalVariableGuid        },
  { EFI_IMAGE_SECURITY_DATABASE,  &gEfiImageSecurityDatabaseGuid },
  { EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid },
};

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
  IN      const EVP_MD              *md,
  IN      UINT8                     *mr,
  IN      UINT32                    mr_index,
	IN      eventlog_t                *evlog,
  IN      TCG_EVENTTYPE             EventType,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  )
{
  UINTN                             VarNameLength;
  UEFI_VARIABLE_DATA                *VarLog;
  UINTN                             event_size;

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

  char VarNameNarrow[VarNameLength+1];
  memset(VarNameNarrow, 0x0, sizeof(VarNameNarrow));
  for (UINTN i = 0; i < VarNameLength; i++) {
    VarNameNarrow[i] = VarName[i] & 0xFF;
  }

  uint8_t hash[EVP_MD_size(md)];
	hash_buf(md, hash, (uint8_t *)VarLog, event_size);

  if (EventType == EV_EFI_VARIABLE_DRIVER_CONFIG) {
    evlog_add(evlog, mr_index, "EV_EFI_VARIABLE_DRIVER_CONFIG", hash, VarNameNarrow);
  } else if (EventType == EV_EFI_VARIABLE_BOOT) {
    evlog_add(evlog, mr_index, "EV_EFI_VARIABLE_BOOT", hash, VarNameNarrow);
  } else if (EventType == EV_EFI_VARIABLE_AUTHORITY) {
    evlog_add(evlog, mr_index, "EV_EFI_VARIABLE_AUTHORITY", hash, VarNameNarrow);
  } else {
    printf("Unsupported event type 0x%x\n", EventType);
  }

  hash_extend(md, mr, hash, EVP_MD_size(md));

  free (VarLog);
  return 0;
}

/**
  Read then Measure and log an EFI variable, and extend the measurement result into a specific PCR.

  @param[in]  PCRIndex          PCR Index.
  @param[in]  EventType         Event type.
  @param[in]   VarName          A Null-terminated string that is the name of the vendor's variable.
  @param[in]   VendorGuid       A unique identifier for the vendor.
  @param[out]  VarSize          The size of the variable data.
  @param[out]  VarData          Pointer to the content of the variable.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
ReadAndMeasureVariable (
  IN      const EVP_MD   *md,
  IN      UINT8          *mr,
  IN      eventlog_t     *evlog,
  IN      UINT32         mr_index,
  IN      TCG_EVENTTYPE  EventType,
  IN      CHAR16         *VarName,
  IN      EFI_GUID       *VendorGuid,
  OUT     UINTN          *VarSize,
  OUT     VOID           **VarData
  )
{
  EFI_STATUS  Status;

  // Here, The function GetVariable2 usually retrieves the variable through the UEFI Runtime Service
  // GetVariable(). Currently, we only support empty VarData
  *VarData = NULL;
  *VarSize = 0;

  Status = MeasureVariable (
             md,
             mr,
             mr_index,
             evlog,
             EventType,
             VarName,
             VendorGuid,
             *VarData,
             *VarSize
             );
  return Status;
}

/**
  Read then Measure and log an EFI Secure variable, and extend the measurement result into PCR[7].

  @param[in]   VarName          A Null-terminated string that is the name of the vendor's variable.
  @param[in]   VendorGuid       A unique identifier for the vendor.
  @param[out]  VarSize          The size of the variable data.
  @param[out]  VarData          Pointer to the content of the variable.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
ReadAndMeasureSecureVariable (
  IN      const EVP_MD  *md,
  IN      UINT8         *mr,
  IN      UINT32        mr_index,
  IN      eventlog_t    *evlog,
  IN      CHAR16        *VarName,
  IN      EFI_GUID      *VendorGuid,
  OUT     UINTN         *VarSize,
  OUT     VOID          **VarData
  )
{
  return ReadAndMeasureVariable (
           md,
           mr,
           evlog,
           mr_index,
           EV_EFI_VARIABLE_DRIVER_CONFIG,
           VarName,
           VendorGuid,
           VarSize,
           VarData
           );
}

/**
  Measure and log all EFI Secure variables, and extend the measurement result into a specific PCR.

  The EFI boot variables are BootOrder and Boot#### variables.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
MeasureAllSecureVariables (
  IN  const EVP_MD  *md,
  IN  UINT8         *mr,
  IN  UINT32        mr_index,
  IN  eventlog_t    *evlog
  )
{
  EFI_STATUS  Status;
  VOID        *Data;
  UINTN       DataSize;
  UINTN       Index;

  Status = EFI_NOT_FOUND;
  for (Index = 0; Index < sizeof (mVariableType)/sizeof (mVariableType[0]); Index++) {
    Status = ReadAndMeasureSecureVariable (
               md,
               mr,
               mr_index,
               evlog,
               mVariableType[Index].VariableName,
               mVariableType[Index].VendorGuid,
               &DataSize,
               &Data
               );
    if (!EFI_ERROR (Status)) {
      if (Data != NULL) {
        free (Data);
      }
    }
  }

  return EFI_SUCCESS;
}