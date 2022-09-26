/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

typedef struct {
    uint64_t efi_qemu_fw_cfg_supported_offset;
    uint64_t efi_qemu_fw_cfg_dma_supported_offset;
    uint64_t efi_address_enc_mask_offset;
    uint64_t efi_feature_control_offset;
    uint64_t efi_platform_info_offset;

    uint8_t efi_qemu_fw_cfg_supported;
    uint8_t efi_qemu_fw_cfg_dma_supported;
    uint64_t efi_address_enc_mask;
    uint64_t efi_feature_control;
    EFI_HOB_PLATFORM_INFO efi_platform_info;
    kernel_setup_hdr_t kernel_setup_hdr;
} config_t;

int
config_load(config_t *config, const char *config_file);

int
config_prepare_peifv(uint8_t *fvmain, config_t *config);

int
config_prepare_kernel_pecoff(uint8_t *buf, uint64_t size, config_t *config);