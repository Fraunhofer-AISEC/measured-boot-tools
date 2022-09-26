# TPM PCR Tools

> :warning: **Note:** These tools are work in progress and not to be used in production!

## Overview

These tools are intended for parsing and calculating the Platform Configuration Registers (PCRs) of
Trusted Platform Modules (TPMs). PCRs are used to record the software running on a platform during
a *Measured Boot*: Starting from an inherently trusted immutable component, each component of the
boot chain measures, i.e., hashes the next component, forming a chain of trust. The measurements
are written to the PCRs, which cannot be reset, but only extended with further hashes.

The information stored in the PCRs can be used for remote attestation, i.e. for the integrity
verification of a platform's software stack. However, in order to perform remote attestation, one
must know the known good values of the software components of a platform. These tools can either
parse the values which have been extended into the PCRs, or calculate those values based on given
software components, such as the UEFI firmware, the kernel, and further components.

Two approaches of a measure boot exist: Static Root of Trust for Measurements (SRTM)
and Dynamic Root of Trust for Measurements (DRTM). SRTM is enabled on most computing platforms and
records all software components starting from the firmware into the static PCRs (0-9). DRTM requires
special processor capabilities (such as Intel TXT) and resets the platform to a known good state
before starting to record values into the dynamic PCRs (17-22). This allows omitting early boot
components such as the firmware and the bootloader.

The tools build upon various other open source projects:
* https://sourceforge.net/projects/tboot/
* https://github.com/tianocore/edk2
* https://github.com/tpm2-software/tpm2-tools

## Tools

**parse-srtm-pcrs** parses the SRTM TPM eventlog from the Linux kernel securityfs
(`/sys/kernel/security/tpm0/binary_bios_measurements`) and can display it in different formats.

**parse-ima-pcrs** parses the Linux kernel's Integrity Measurement Architecture (IMA)
eventlog from the securityfs
(`/sys/kernel/security/integrity/ima/binary_runtime_measurements`) and print the output in different
formats. The IMA can be used to record measurements of kernel modules and user space components.

**calculate-srtm-pcrs** calculates the expected SRTM hashes based on software components, such as
the firmware and the kernel. The tool takes the compiled versions of those software components as
input and offline perfoms the calculations of a measured boot.

## Building the tools

Install dependencies
```sh
sudo apt install build-essential zlib1g-dev libssl-dev
```

Build the tools
```sh
make
```

Install the tools
```sh
sudo make install
```