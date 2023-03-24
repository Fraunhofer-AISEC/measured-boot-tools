CC ?= gcc
DEBUG_BUILD ?= n

LOCAL_CFLAGS := -g -std=gnu99 -Icommon/ -ftrapv
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security

ifeq ($(DEBUG_BUILD),y)
    LOCAL_CFLAGS += -fsanitize=address -static-libasan -fsanitize=undefined -fsanitize-recover=address
endif

DEFINES :=

INC_DIRS :=

LFLAGS := -lcrypto

CSRS := \
	main.c \
	hash.c \
	common.c \

IFLAGS := $(INC_DIRS:%=-I%)

.PHONY: all
all: pcr-extend

.PHONY: pcr-extend
pcr-extend:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) -o pcr-extend $(CSRS) $(LFLAGS)

.PHONY: install
install:
	install -v -m 0755 ./pcr-extend /usr/bin/

.PHONY: clean
clean:
	$(RM) pcr-extend *.o
