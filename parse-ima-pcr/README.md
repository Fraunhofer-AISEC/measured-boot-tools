# README

This tool parses the binary log from `/sys/kernel/security/ima/binary_runtime_measurements`
containing the IMA measurements. The tool formats the output as JSON.

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

```h
sudo ./parse-ima-pcr
```
