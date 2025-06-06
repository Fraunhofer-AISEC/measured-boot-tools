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
	../thirdparty/LzmaCustomDecompressLib \
	../thirdparty/LzmaCustomDecompressLib/Sdk \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C \
	../thirdparty/edk2 \
	../common \

CSRS := \
	main.c \
	eventlog.c \
	td_hob.c \
	mrtd.c \
	mrs.c \
	../thirdparty/edk2/MeasureBootPeCoff.c \
	../thirdparty/edk2/SecMain.c \
	../thirdparty/LzmaCustomDecompressLib/LzmaDecompress.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/Bra86.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/LzFind.c \
	../thirdparty/LzmaCustomDecompressLib/Sdk/C/LzmaDec.c \
	../common/guid.c \
	../common/common.c \
	../common/hash.c \
	../common/kernel_config.c \
	../common/efi_boot.c \
	../common/secureboot.c \
	../common/acpi.c \
	../common/gpt.c \

IFLAGS := $(ISRCS:%=-I%)

.PHONY: all
all: calculate-tdx-mrs

.PHONY: calculate-tdx-mrs
calculate-tdx-mrs:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) $(CSRS) $(LFLAGS) -o calculate-tdx-mrs

.PHONY: install
install:
	install -v -m 0755 ./calculate-tdx-mrs /usr/bin/

.PHONY: clean
clean:
	$(RM) calculate-tdx-mrs *.o
