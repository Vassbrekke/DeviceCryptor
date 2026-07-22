/*
 * Minimal WDK driver scaffold for DeviceCryptor.
 * Compile only with Windows Driver Kit — stub for structure/CI documentation.
 */

#include <ntddk.h>
#include "../include/dc_driver_ioctl.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DcUnload;

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DcUnload;
    /* TODO: create device, symbolic link, register dispatch for IOCTL_DC_* */
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DcUnload(
    PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
}
