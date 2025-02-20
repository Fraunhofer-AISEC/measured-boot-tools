/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

///
/// Describes the format and size of the data inside the HOB.
/// All HOBs must contain this generic HOB header.
///
typedef struct {
  ///
  /// Identifies the HOB data structure type.
  ///
  UINT16    HobType;
  ///
  /// The length in bytes of the HOB.
  ///
  UINT16    HobLength;
  ///
  /// This field must always be set to zero.
  ///
  UINT32    Reserved;
} EFI_HOB_GENERIC_HEADER;

///
/// Allows writers of executable content in the HOB producer phase to
/// maintain and manage HOBs with specific GUID.
///
typedef struct {
  ///
  /// The HOB generic header. Header.HobType = EFI_HOB_TYPE_GUID_EXTENSION.
  ///
  EFI_HOB_GENERIC_HEADER    Header;
  ///
  /// A GUID that defines the contents of this HOB.
  ///
  EFI_GUID                  Name;
  //
  // Guid specific data goes here
  //
} EFI_HOB_GUID_TYPE;

#pragma pack(1)
typedef struct {
  EFI_HOB_GUID_TYPE    GuidHeader;
  UINT16               HostBridgeDevId;

  UINT64               PcdConfidentialComputingGuestAttr;
  BOOLEAN              SevEsIsEnabled;

  UINT32               BootMode;
  BOOLEAN              S3Supported;

  BOOLEAN              SmmSmramRequire;
  BOOLEAN              Q35SmramAtDefaultSmbase;
  UINT16               Q35TsegMbytes;

  UINT64               FirstNonAddress;
  UINT8                PhysMemAddressWidth;
  UINT32               Uc32Base;
  UINT32               Uc32Size;

  BOOLEAN              PcdSetNxForStack;
  UINT64               PcdTdxSharedBitMask;

  UINT64               PcdPciMmio64Base;
  UINT64               PcdPciMmio64Size;
  UINT32               PcdPciMmio32Base;
  UINT32               PcdPciMmio32Size;
  UINT64               PcdPciIoBase;
  UINT64               PcdPciIoSize;

  UINT64               PcdEmuVariableNvStoreReserved;
  UINT32               PcdCpuBootLogicalProcessorNumber;
  UINT32               PcdCpuMaxLogicalProcessorNumber;
  UINT32               DefaultMaxCpuNumber;

  UINT32               S3AcpiReservedMemoryBase;
  UINT32               S3AcpiReservedMemorySize;
} EFI_HOB_PLATFORM_INFO;
#pragma pack()

uint8_t *
extract_lzma_fvmain_new (EFI_FIRMWARE_VOLUME_HEADER  *Fv, size_t *extracted_size);

int
measure_peifv(uint8_t hash[SHA256_DIGEST_LENGTH], uint8_t *fvmain, const char *dump_pei_path);

int
measure_dxefv(uint8_t hash[SHA256_DIGEST_LENGTH], uint8_t *fvmain, const char *dump_dxe_path);