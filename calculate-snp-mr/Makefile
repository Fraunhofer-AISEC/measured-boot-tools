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
	../common \

CSRS := \
	main.c \
	snp.c \
	../common/common.c \
	../common/hash.c \

IFLAGS := $(ISRCS:%=-I%)

.PHONY: all
all: calculate-snp-mr

.PHONY: calculate-snp-mr
calculate-snp-mr:
	$(CC) $(DEFINES) $(LOCAL_CFLAGS) $(IFLAGS) $(CSRS) $(LFLAGS) -o calculate-snp-mr

.PHONY: install
install:
	install -v -m 0755 ./calculate-snp-mr /usr/bin/

.PHONY: clean
clean:
	$(RM) calculate-snp-mr *.o
