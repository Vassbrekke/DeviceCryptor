# DeviceCryptor Windows volume filter driver (WDK)

Reference contracts: `vendor/VeraCrypt/src/Driver`  
EFI PBA / BlockIo pre-boot path: **`vendor/VeraCrypt-DCS`** (see `boot/windows-uefi/`)

## Scope

- Volume filter / device filter for mounted containers and system encryption
- IOCTL surface for mount/dismount from `dc` / GUI mount helper
- Sector crypto is not linked into a `.sys` in this tree. The request check rejects a bad path and a bad password length, then the password buffer is wiped.
- Hands off to / coordinates with EFI `DcInt` after PBA for system volumes

## Files

| File | Role |
|------|------|
| `README.md` | This file |
| `include/dc_driver_ioctl.h` | Shared IOCTL codes |
| `src/driver_stub.c` | DRIVER_ENTRY scaffold. Dispatch must call `request_check` and wipe the password |
| `src/request_check.c` | Path and password-length checks. Builds with the host compiler |

The WDK driver is not built or loaded here. `request_check.c` is the part that compiles on Linux.

