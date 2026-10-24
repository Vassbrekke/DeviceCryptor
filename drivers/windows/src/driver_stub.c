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
    /*
     * WDK dispatch must:
     *   - reject a short buffer
     *   - call dc_request_reject on the path and password length
     *   - RtlSecureZeroMemory the password before every return
     * Sector crypto is not linked in this tree. Do not report a volume as mounted.
     */
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
