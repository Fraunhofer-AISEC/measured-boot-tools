# README

This tool calculates the values of the SRTM PCRs. It takes the software running on the platform as
input and outputs the PCR summary or the detailed eventlog in a text format or json format.
The tool is work in progress and currently only supports x86 systems started by QEMU with OVMF and a
Linux kernel as PE/COFF image.

- PCR0 UEFI is calculated based on the CRTM and OVMF firmware
- PCR1 UEFI Configuration is calculated using the EFI boot variables
- PCR2 is calculated based on optionally specified 3rd party UEFI drivers
- PCR3 is calculated based on optionally specified 3rd party UEFI driver configurations
- PCR4 UEFI Boot Manager Code is calculated from the kernel PE/COFF image
- PCR5 UEFI Boot Manager Configuration currently only supports event EFI actions being present
- PCR6 Host platform Manufacturer specific, currently supports only EV_SEPARATOR present
- PCR7 Secure Boot Policy, is calculated from the Secure Boot variables, currently supports only secure boot disabled

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
calculate-srtm-pcrs [options...]
	-k,  --kernel <file>		The filename of the kernel image
	-r,  --ramdisk <file>		The filename of the initramfs
	-o,  --ovmf <file>			The filename of the OVMF.fd file
	-d,  --driver <file>        The filename of a used 3rd party UEFI driver (can be multiple)
	-f,  --format <text|json>	The output format, can be either 'json' or 'text'
	-e,  --eventlog			    Print detailed eventlog
	-s,  --summary			    Print final PCR values
	-p,  --pcrs <nums>		    The numbers of the PCRs to be calculated as a comma separated list without spaces
	-v,  --verbose				Verbose debug output
	-c,  --config 				Path to the OVMF / kernel variable configuration file
```

## Example Usage

```sh
./calculate-srtm-pcrs \
	--kernel kernel-linux-amd64-virtio-systemd-debug.bzImage \
	--ramdisk initrd-linux-amd64-virtio-systemd-debug.cpio.zst \
	--ovmf-code OVMF.fd \
	--format json \
	--pcrs 1,3,4,5,6,7 \
	--eventlog \
	--config configs/ovmf-2022-05.cfg
```

## Configuration

The OVMF contains a few global variables, which are initialized and then measured into PCR0 as
part of the PEIFV firmware volume measurement. These values, most importantly the EFI Platform
Info HOB [1] must be set at the correct offset in order to calculate the correct measurement. The
values can and their offset in the image can e.g. be found out through dumping the TPM measurement
during the OVMF build in debug mode.

The kernel image contains a setup header for exchanging values with the bootloader [2]. A part of
these values is "modify" or "write", which means that the bootloader writes these values. As these
values are written before the header is measured as part of the kernel image into PCR4, they must
be set as well.

Therefore, for calculating PCR0 and PCR4, a configuration file path must be specified via the
`-c|--config` command line argument. The configuration file must contain the offsets and the
values (in hex) separated by `=`. Example configurations are provided in `configs/`.

For the configurations, edk2 was built with the following flags:

```sh
build \
-DTPM2_ENABLE=TRUE \
-DSECURE_BOOT_ENABLE=TRUE \
-DFD_SIZE_2MB \
-n "$(nproc)" \
-b RELEASE \
-a X64 \
-t GCC5 \
-p OvmfPkg/OvmfPkgX64.dsc
```

- [1] https://github.com/tianocore/edk2/blob/master/OvmfPkg/PlatformPei/Platform.c#L44
- [2] https://www.kernel.org/doc/html/latest/x86/boot.html?highlight=boot

