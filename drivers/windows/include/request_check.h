#pragma once

#include <stddef.h>
#include <stdint.h>

/* 1 = reject. Does not look at a disk. */
int dc_request_reject(uint32_t password_len, const char *device);
void dc_wipe_password(uint8_t *password, size_t cap);
