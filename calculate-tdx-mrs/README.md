# README

This tool calculates the values of Intel TDX MRTD and RTMR registers based on the OVMF, Linux
kernel, kernel commandline and configuration parameters.

## Prerequisites

```sh
sudo apt install -y build-essential
```

## Build

```sh
make
```

## Install

```sh
sudo make install
```

## Usage

```sh
calculate-tdx-mrs --help
```

### Example Usage

```sh
calculate-tdx-mrs \
    --ovmf OVMF.fd  \
    --kernel linux-amd64-tdx-systemd-debug.bzImage \
    --cmdline linux-amd64-tdx-systemd-debug.cmdline \
    --config configs/calculate-pcrs.cfg \
    --acpirsdp configs/etc-acpi-rsdp \
    --acpitables configs/etc-acpi-tables \
    --tableloader configs/etc-table-loader \
    --eventlog \
    --summary \
    --format json \
```
