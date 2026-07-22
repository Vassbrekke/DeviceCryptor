#pragma once

/*
 * BlockIo intercept contracts derived from vendor/VeraCrypt-DCS/DcsInt/DcsInt.h
 * (LGPL-3.0 reference). This header is DeviceCryptor-original wording/layout
 * for the rewrite — not a verbatim copy of DCS sources.
 */

#include <stdint.h>

#define DC_INT_DRIVER_VERSION 1
#define DC_INT_BLOCK_IO_SIGN 0x44434942u /* 'DCIB' */

typedef struct DcCryptInfo DcCryptInfo;

typedef struct DcIntBlockIo {
    uint32_t sign;
    void *controller;   /* EFI_HANDLE */
    void *block_io;     /* EFI_BLOCK_IO_PROTOCOL* */
    void *low_read;     /* EFI_BLOCK_READ */
    void *low_write;    /* EFI_BLOCK_WRITE */
    uint32_t is_reinstalled;
    DcCryptInfo *crypt_info;
    struct DcIntBlockIo *next;
} DcIntBlockIo;

/*
 * Binding lifecycle (EDK2 Driver Binding Protocol):
 *   Supported → Start (install hooks + run PBA) → Stop (restore LowRead/LowWrite)
 * See DcsIntBindingSupported / Start / Stop in vendor/VeraCrypt-DCS/DcsInt.
 */
