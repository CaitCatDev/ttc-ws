#pragma once

#include <stdint.h>
#include <stddef.h>

/*endian stuff*/
uint16_t endian_swap16(uint16_t innum);
uint32_t endian_swap32(uint32_t innum);
uint64_t endian_swap64(uint64_t innum);

/*base64 stuff*/
size_t b64_encode_len(size_t lenin);
char *b64_encode(const uint8_t *data, size_t len);
uint8_t *random_array(size_t len);
