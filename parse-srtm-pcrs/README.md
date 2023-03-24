# README

This tool parses the TPM binary log from containing the boot measurements. By default, it uses
`/sys/kernel/security/tpm0/binary_bios_measurements`  or, if specified, the file given via the
`--in` option.
The tool can format the output as text or as json.

The tool must usually run with root privileges, otherwise the binary bios measurements file
is not available.

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

## Run

```sh
# Usage
parse-srtm-pcrs [-p|--pcrs <num>[,<num>]] [-f|--format text|json] [-i|--in <input-file>] [-h|--help]

# Example
parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json
```
