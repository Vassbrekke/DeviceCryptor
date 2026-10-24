#pragma once

/*
 * Shared IOCTL definitions for DeviceCryptor Windows filter driver.
 * Numbers are DeviceCryptor-original (do not reuse VeraCrypt CTL codes blindly).
 */

#define DC_DEVICE_TYPE 0x8000

/* FILE_READ_ACCESS | FILE_WRITE_ACCESS. Not FILE_ANY_ACCESS. */
#define IOCTL_DC_MOUNT \
    CTL_CODE(DC_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DC_DISMOUNT \
    CTL_CODE(DC_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DC_GET_STATUS \
    CTL_CODE(DC_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#pragma pack(push, 1)
typedef struct _DC_MOUNT_REQUEST {
    WCHAR ContainerPath[260];
    UCHAR Password[128];
    ULONG PasswordLength;
    LONG Pim;
    BOOLEAN ProtectHidden;
} DC_MOUNT_REQUEST;

typedef struct _DC_STATUS {
    BOOLEAN Mounted;
    ULONGLONG DataLength;
    ULONG SectorSize;
} DC_STATUS;
#pragma pack(pop)
