# README

This tool simulates TPM PCR digest extensions.

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
pcr-extend [-d|--digests <digest>[,<digest>[,<digest>]]] [-h|--help]

# Example
pcr-extend -d \
    1dd1d4448a042b737b50f0c1763d46c7a9b40d0f0d704f723aff89ef160c54e5,\
    3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba
```
