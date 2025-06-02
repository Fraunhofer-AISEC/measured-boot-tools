#pragma once

#include <stdint.h>
#include <stdio.h>

#include <openssl/sha.h>

int
measure_ovmf(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image_file, uint64_t image_size,
                const char *qemu_version);

int
measure_cfv(uint8_t digest[SHA384_DIGEST_LENGTH], uint8_t *raw_image, uint64_t raw_image_size);