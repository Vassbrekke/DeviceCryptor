#include "../include/request_check.h"

#include <stdio.h>

int main(void) {
    uint8_t pw[4] = {1, 2, 3, 4};
    if (!dc_request_reject(0, "\\\\.\\X:")) {
        return 1;
    }
    if (!dc_request_reject(4, "..\\secret")) {
        return 1;
    }
    if (dc_request_reject(4, "\\\\.\\PhysicalDrive0")) {
        return 1;
    }
    dc_wipe_password(pw, sizeof(pw));
    if (pw[0] || pw[1] || pw[2] || pw[3]) {
        return 1;
    }
    return 0;
}
