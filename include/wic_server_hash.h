/* Copyright (c) 2023 Cameron Harper
 *
 * */

#ifndef WIC_SERVER_HASH_H
#define WIC_SERVER_HASH_H

#include <stdint.h>
#include <stddef.h>

void wic_server_hash(const char *nonce, size_t len, uint8_t *hash);

#endif
