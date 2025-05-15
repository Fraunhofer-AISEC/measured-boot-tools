# README

This tool calculates the values of AMD SEV-SNP measurement register based on the OVMF, number of
vCPUs, and optionally the Linux kernel, kernel commandline and initramfs.

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
calculate-snp-mr --help
```

### Example Usage

```sh
calculate-snp-mr \
    --vcpus 2 \
    --vmm-type qemu \
    --ovmf OVMF.fd \
    --kernel linux-amd64-snp.bzImage  \
    --initrd linux-amd64-snp.cpio.zst \
    --cmdline linux-amd64-snp.cmdline \
```