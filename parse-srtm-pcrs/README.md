# README

This tool parses the binary log from `/sys/kernel/security/tpm0/binary_bios_measurements` containing
the boot measurements. The tool can format the output as text or as json.

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
parse-srtm-pcrs [-p|--pcrs <num>[,<num>]] [-f|--format text|json]

# Example
parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json
```
