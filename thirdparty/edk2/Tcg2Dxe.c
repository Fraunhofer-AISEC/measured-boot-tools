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

#include "common.h"
#include "hash.h"
#include "eventlog.h"

#define PERF_ID_TCG2_DXE  0x3120

typedef struct {
  CHAR16      *VariableName;
  EFI_GUID    *VendorGuid;
} VARIABLE_TYPE;

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

EFI_GUID gEfiGlobalVariableGuid = EFI_GLOBAL_VARIABLE;

EFI_GUID gEfiImageSecurityDatabaseGuid = EFI_IMAGE_SECURITY_DATABASE_GUID;

VARIABLE_TYPE  mVariableType[] = {
  { EFI_SECURE_BOOT_MODE_NAME,    &gEfiGlobalVariableGuid        },
  { EFI_PLATFORM_KEY_NAME,        &gEfiGlobalVariableGuid        },
  { EFI_KEY_EXCHANGE_KEY_NAME,    &gEfiGlobalVariableGuid        },
  { EFI_IMAGE_SECURITY_DATABASE,  &gEfiImageSecurityDatabaseGuid },
  { EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid },
};

UINTN   mBootAttempts  = 0;
CHAR16  mBootVarName[] = u"BootOrder";

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
  IN      UINT8                     *pcr,
	IN      eventlog_t                *evlog,
  IN      TPM_PCRINDEX              PCRIndex,
  IN      TCG_EVENTTYPE             EventType,
  IN      CHAR16                    *VarName,
  IN      EFI_GUID                  *VendorGuid,
  IN      VOID                      *VarData,
  IN      UINTN                     VarSize
  )
{
  (void)PCRIndex;
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

  uint8_t hash[SHA256_DIGEST_LENGTH];
	sha256(hash, (uint8_t *)VarLog, event_size);

  // TODO replace hardcoded event type
  if (EventType == EV_EFI_VARIABLE_DRIVER_CONFIG) {
    evlog_add(evlog, 7, "EV_EFI_VARIABLE_DRIVER_CONFIG", hash, VarNameNarrow);
  } else {
    printf("Unknown event type 0x%x\n", EventType);
  }

  sha256_extend(pcr, hash);

  free (VarLog);
  return 0;
}

/**
  Returns the status whether get the variable success. The function retrieves
  variable  through the UEFI Runtime Service GetVariable().  The
  returned buffer is allocated using AllocatePool().  The caller is responsible
  for freeing this buffer with FreePool().

  If Name  is NULL, then ASSERT().
  If Guid  is NULL, then ASSERT().
  If Value is NULL, then ASSERT().

  @param[in]  Name  The pointer to a Null-terminated Unicode string.
  @param[in]  Guid  The pointer to an EFI_GUID structure
  @param[out] Value The buffer point saved the variable info.
  @param[out] Size  The buffer size of the variable.

  @return EFI_OUT_OF_RESOURCES      Allocate buffer failed.
  @return EFI_SUCCESS               Find the specified variable.
  @return Others Errors             Return errors from call to gRT->GetVariable.

**/
EFI_STATUS
EFIAPI
GetVariable2 (
  IN CONST CHAR16    *Name,
  IN CONST EFI_GUID  *Guid,
  OUT VOID           **Value,
  OUT UINTN          *Size OPTIONAL
  )
{
  (void)Name;
  (void)Guid;
  (void)Value;
  (void)Size;
  // TODO
  return EFI_UNSUPPORTED;
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
  IN      UINT8          *pcr,
  IN      eventlog_t     *evlog,
  IN      TPM_PCRINDEX   PCRIndex,
  IN      TCG_EVENTTYPE  EventType,
  IN      CHAR16         *VarName,
  IN      EFI_GUID       *VendorGuid,
  OUT     UINTN          *VarSize,
  OUT     VOID           **VarData
  )
{
  EFI_STATUS  Status;

  Status = GetVariable2 (VarName, VendorGuid, VarData, VarSize);
  if (EventType == EV_EFI_VARIABLE_DRIVER_CONFIG) {
    if (EFI_ERROR (Status)) {
      //
      // It is valid case, so we need handle it.
      //
      *VarData = NULL;
      *VarSize = 0;
    }
  } else {
    //
    // if status error, VarData is freed and set NULL by GetVariable2
    //
    if (EFI_ERROR (Status)) {
      return EFI_NOT_FOUND;
    }
  }

  Status = MeasureVariable (
             pcr,
             evlog,
             PCRIndex,
             EventType,
             VarName,
             VendorGuid,
             *VarData,
             *VarSize
             );
  return Status;
}

/**
  Read then Measure and log an EFI boot variable, and extend the measurement result into PCR[1].
according to TCG PC Client PFP spec 0021 Section 2.4.4.2

  @param[in]   VarName          A Null-terminated string that is the name of the vendor's variable.
  @param[in]   VendorGuid       A unique identifier for the vendor.
  @param[out]  VarSize          The size of the variable data.
  @param[out]  VarData          Pointer to the content of the variable.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
ReadAndMeasureBootVariable (
  IN      UINT8       *pcr,
  IN      eventlog_t  *evlog,
  IN      CHAR16    *VarName,
  IN      EFI_GUID  *VendorGuid,
  OUT     UINTN     *VarSize,
  OUT     VOID      **VarData
  )
{
  return ReadAndMeasureVariable (
           pcr,
           evlog,
           1,
           EV_EFI_VARIABLE_BOOT,
           VarName,
           VendorGuid,
           VarSize,
           VarData
           );
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
  IN      UINT8       *pcr,
  IN      eventlog_t  *evlog,
  IN      CHAR16      *VarName,
  IN      EFI_GUID    *VendorGuid,
  OUT     UINTN       *VarSize,
  OUT     VOID        **VarData
  )
{
  return ReadAndMeasureVariable (
           pcr,
           evlog,
           7,
           EV_EFI_VARIABLE_DRIVER_CONFIG,
           VarName,
           VendorGuid,
           VarSize,
           VarData
           );
}

/**
  Measure and log all EFI boot variables, and extend the measurement result into a specific PCR.

  The EFI boot variables are BootOrder and Boot#### variables.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
MeasureAllBootVariables (
  IN      UINT8       *pcr,
  IN      eventlog_t  *evlog
  )
{
  EFI_STATUS  Status;
  UINT16      *BootOrder;
  UINTN       BootCount;
  UINTN       Index;
  VOID        *BootVarData;
  UINTN       Size;

  Status = ReadAndMeasureBootVariable (
             pcr,
             evlog,
             mBootVarName,
             &gEfiGlobalVariableGuid,
             &BootCount,
             (VOID **)&BootOrder
             );
  if ((Status == EFI_NOT_FOUND) || (BootOrder == NULL)) {
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    //
    // BootOrder can't be NULL if status is not EFI_NOT_FOUND
    //
    free (BootOrder);
    return Status;
  }

  BootCount /= sizeof (*BootOrder);
  for (Index = 0; Index < BootCount; Index++) {
    snprintf (mBootVarName, sizeof (mBootVarName), u"Boot%04x", BootOrder[Index]);
    Status = ReadAndMeasureBootVariable (
               pcr,
               evlog,
               mBootVarName,
               &gEfiGlobalVariableGuid,
               &Size,
               &BootVarData
               );
    if (!EFI_ERROR (Status)) {
      free (BootVarData);
    }
  }

  free (BootOrder);
  return EFI_SUCCESS;
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
  IN  UINT8       *pcr,
  IN  eventlog_t  *evlog
  )
{
  EFI_STATUS  Status;
  VOID        *Data;
  UINTN       DataSize;
  UINTN       Index;

  Status = EFI_NOT_FOUND;
  for (Index = 0; Index < sizeof (mVariableType)/sizeof (mVariableType[0]); Index++) {
    Status = ReadAndMeasureSecureVariable (
               pcr,
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

  // TODO not yet implemented
  //
  // Measure DBT if present and not empty
  //
  // Status = GetVariable2 (EFI_IMAGE_SECURITY_DATABASE2, &gEfiImageSecurityDatabaseGuid, &Data, &DataSize);
  // if (!EFI_ERROR (Status)) {
  //   Status = MeasureVariable (
  //              7,
  //              EV_EFI_VARIABLE_DRIVER_CONFIG,
  //              EFI_IMAGE_SECURITY_DATABASE2,
  //              &gEfiImageSecurityDatabaseGuid,
  //              Data,
  //              DataSize
  //              );
  //   FreePool (Data);
  // } else {
  //   DEBUG ((DEBUG_INFO, "Skip measuring variable %s since it's deleted\n", EFI_IMAGE_SECURITY_DATABASE2));
  // }

  return EFI_SUCCESS;
}