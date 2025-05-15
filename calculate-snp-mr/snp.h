/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#pragma once

int
calculate_mr(uint8_t *mr, const char *ovmf_file, const char *kernel_file, const char *ramdisk_file,
             const char *cmdline_file, size_t vcpus, vmm_type_t vmm_type);