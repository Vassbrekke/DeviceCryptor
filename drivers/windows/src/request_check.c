/*
 * Portable mount-request checks for the Windows filter driver.
 * No disk I/O. The WDK stub wipes the password after this returns.
 */
#include "../include/request_check.h"

#include <string.h>

int dc_request_reject(uint32_t password_len, const char *device) {
    size_t i;
    if (password_len == 0 || password_len > 128 || device == 0 || device[0] == '\0') {
        return 1;
    }
    if (strncmp(device, "\\\\", 2) != 0 && strncmp(device, "/dev/", 5) != 0) {
        return 1;
    }
    for (i = 0; device[i] != '\0'; i++) {
        if (device[i] == '\n') {
            return 1;
        }
        if (device[i] == '.' && device[i + 1] == '.') {
            return 1;
        }
    }
    return 0;
}

void dc_wipe_password(uint8_t *password, size_t cap) {
    if (password == 0 || cap == 0) {
        return;
    }
    memset(password, 0, cap);
}
