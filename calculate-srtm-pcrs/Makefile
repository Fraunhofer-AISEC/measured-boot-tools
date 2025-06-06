CC ?= gcc
DEBUG_BUILD ?= n

LOCAL_CFLAGS := -g -std=gnu99 -ftrapv
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security -Wno-deprecated-declarations

DEFINES :=

ifeq ($(DEBUG_BUILD),y)
    # Requires libasan libasan-static libubsan libubsan-static installed
    LOCAL_CFLAGS += -fsanitize=address -static-libasan -fsanitize=undefined -fsanitize-recover=address
	DEFINES += -DDEBUG_BUILD
endif

LFLAGS := -lcrypto

ISRCS := \
	./ \
	../thirdparty \
	../thirdparty/LzmaCustomDecompressLib \
	../thirdparty/LzmaCustomDecompressLib/Sdk \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C \
	../thirdparty/edk2 \
	../thirdparty/tpm2-tools \
	../thirdparty/tss2 \
	../common

CSRS := \
	main.c \
	eventlog.c \
	paths.c \
	pcrs.c \
	../thirdparty/edk2/MeasureBootPeCoff.c \
	../thirdparty/edk2/SecMain.c \
	../thirdparty/LzmaCustomDecompressLib/LzmaDecompress.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/Bra86.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/LzFind.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/LzmaDec.c \
	../common/common.c \
	../common/efi_boot.c \
	../common/guid.c \
	../common/hash.c \
	../common/kernel_config.c \
	../common/secureboot.c \
	../common/acpi.c \
	../common/gpt.c \

IFLAGS := $(ISRCS:%=-I%)

.PHONY: all
all: calculate-srtm-pcrs

.PHONY: calculate-srtm-pcrs
calculate-srtm-pcrs:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) $(CSRS) $(LFLAGS) -o calculate-srtm-pcrs

.PHONY: install
install:
	install -v -m 0755 ./calculate-srtm-pcrs /usr/bin/

.PHONY: clean
clean:
	$(RM) calculate-srtm-pcrs *.o
