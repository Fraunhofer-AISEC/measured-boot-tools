CC ?= gcc
DEBUG_BUILD ?= n

LOCAL_CFLAGS := -g -std=gnu99 -Icommon/ -ftrapv
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security

DEFINES :=

ifeq ($(DEBUG_BUILD),y)
    LOCAL_CFLAGS += -fsanitize=address -static-libasan -fsanitize=undefined -fsanitize-recover=address
	DEFINES += -DDEBUG_BUILD
endif

LFLAGS := -lcrypto

ISRCS := \
	./ \
	../common \

CSRS := \
	main.c \
	../common/hash.c \
	../common/common.c \

IFLAGS := $(ISRCS:%=-I%)

.PHONY: all
all: pcr-extend

.PHONY: pcr-extend
pcr-extend:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) $(CSRS) $(LFLAGS) -o pcr-extend

.PHONY: install
install:
	install -v -m 0755 ./pcr-extend /usr/bin/

.PHONY: clean
clean:
	$(RM) pcr-extend *.o
