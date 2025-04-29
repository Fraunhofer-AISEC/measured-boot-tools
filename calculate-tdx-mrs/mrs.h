/* SPDX-License-Identifier: BSD-2-Clause-Patent */

typedef struct {
    uint8_t *acpi_tables;
    ssize_t acpi_tables_size;
    uint8_t *acpi_rsdp;
    ssize_t acpi_rsdp_size;
    uint8_t *table_loader;
    ssize_t table_loader_size;
} rtmr0_qemu_fw_cfg_files_t;

int
calculate_mrseam(uint8_t *mr, eventlog_t *evlog, const char *tdx_module);

int
calculate_mrtd(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file);

int
calculate_rtmr0(uint8_t *mr, eventlog_t *evlog, const char *ovmf_file,
                rtmr0_qemu_fw_cfg_files_t *cfg, const char *ovmf_version);

int
calculate_rtmr1(uint8_t *mr, eventlog_t *evlog, const char *kernel_file, config_t *config,
                const char *dump_kernel_path, const char *ovmf_version);

int
calculate_rtmr2(uint8_t *mr, eventlog_t *evlog, const char *cmdline_file);

int
calculate_rtmr3(uint8_t *mr, eventlog_t *evlog);