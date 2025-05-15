# Measured Boot Tools

> :warning: **Note:** These tools are work in progress and not to be used in production!

## Overview

These tools parse or precompute the values of Trusted Platform Module (TPM) Platform
Configuration Registers (PCRs), as well as the measurement registers (MRTD and RTMRs) of
Intel TDX-based platforms and AMD SEV-SNP-based platforms.

The calculation tools can be used to calculate the golden reference values for remote attestation
based on the built UEFI firmware, Linux kernel, kernel commandline and configuration parameters.
The parsing tools can be used to parse the eventlogs of a running system to determine the
state of the system and compare the values to the calculated values.

Further information is provided in the READMEs of the individual tools.

The tools build upon various other open source projects:
* https://sourceforge.net/projects/tboot/
* https://github.com/tianocore/edk2
* https://github.com/tpm2-software/tpm2-tools

## Tools

**calculate-ima-pcr** calculates the expected IMA eventlog based on a list of user space software
components. Note that the order on running systems might differ as the execution of user space
binaries cannot be predicted.

**calculate-snp-mr** calculates the expected hash of the AMD SEV-SNP measurement register based
on the OVMF and optionally kernel, cmdline and initrd. Currently works for QEMU and ec2 instances
and EPYC-v4 CPUs.

**calculate-srtm-pcrs** calculates the expected SRTM PCR eventlog and final PCR values based on
software components, such as the firmware and the kernel. The tool takes the compiled versions of
those software components as input and perfoms/simulates the calculations of a measured boot.

**calculate-tdx-mrs** calculates the expected Intel TDX MRTD and RTMR values based on the
UEFI firmware, Linux kernel, kernel commandline and some configuration parameters.

**parse-srtm-pcrs** parses the SRTM TPM eventlog (PCR0-15) from the Linux kernel securityfs
(`/sys/kernel/security/tpm0/binary_bios_measurements`) and displays it in different formats.

**parse-ima-pcrs** parses the Linux kernel's Integrity Measurement Architecture (IMA)
eventlog from the securityfs
(`/sys/kernel/security/integrity/ima/binary_runtime_measurements`) and prints the output. The IMA
can be used to record measurements of kernel modules and user space components.

**pcr-extend** simply simulates the TPM PCR extend operation on provided input digests.

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