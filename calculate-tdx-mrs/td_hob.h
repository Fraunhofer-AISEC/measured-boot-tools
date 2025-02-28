#pragma once

#include <stdint.h>
#include <stddef.h>

size_t
get_td_hob_size();

int
create_td_hob(uint8_t *dest, size_t dest_len);

void
print_td_hob(uint8_t *data, size_t len);