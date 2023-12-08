CC ?= gcc
DEBUG_BUILD ?= n

LOCAL_CFLAGS := -g -std=gnu99 -Icommon/ -ftrapv
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security

ifeq ($(DEBUG_BUILD),y)
    LOCAL_CFLAGS += -fsanitize=address -static-libasan -fsanitize=undefined -fsanitize-recover=address
endif

DEFINES :=

INC_DIRS := \
	./ \
	thirdparty/tpm2-tools \
	thirdparty/tss2 \
	thirdparty

LFLAGS := -lcrypto

CSRS := \
	main.c \
	eventcb.c \
	hash.c \
	common.c \
	thirdparty/tpm2-tools/tpm2_openssl.c \
	thirdparty/tpm2-tools/tpm2_eventlog.c \
	thirdparty/tpm2-tools/tpm2_alg_util.c \

IFLAGS := $(INC_DIRS:%=-I%)

.PHONY: all
all: parse-srtm-pcrs

.PHONY: parse-srtm-pcrs
parse-srtm-pcrs:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) -o parse-srtm-pcrs $(CSRS) $(LFLAGS)

.PHONY: install
install:
	install -v -m 0755 ./parse-srtm-pcrs /usr/bin/

.PHONY: clean
clean:
	$(RM) parse-srtm-pcrs *.o
