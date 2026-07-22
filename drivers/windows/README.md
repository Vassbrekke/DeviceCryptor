# DeviceCryptor Windows volume filter driver (WDK)

Reference contracts: `vendor/VeraCrypt/src/Driver`  
EFI PBA / BlockIo pre-boot path: **`vendor/VeraCrypt-DCS`** (see `boot/windows-uefi/`)

## Scope

- Volume filter / device filter for mounted containers and system encryption
- IOCTL surface for mount/dismount from `dc` / GUI mount helper
- Sector path calls into `dc_crypto` staticlib (AES-256-XTS)
- Hands off to / coordinates with EFI `DcInt` after PBA for system volumes

## Files

| File | Role |
|------|------|
| `README.md` | This file |
| `include/dc_driver_ioctl.h` | Shared IOCTL codes |
| `src/driver_stub.c` | Minimal DRIVER_ENTRY scaffold |

Build with Visual Studio + WDK; not built in Linux CI.

