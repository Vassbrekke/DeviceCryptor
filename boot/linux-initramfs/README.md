# DeviceCryptor Linux initramfs unlock

`local-top-devicecryptor` runs `dc attach` when `DC_SYSTEM_DEVICE` is set. That maps the volume with `cryptsetup` as `/dev/mapper/$DC_MAPPER_NAME` (default `dcroot`). The script was not installed and not booted here.

File-container recovery is in [docs/RECOVERY.md](../../docs/RECOVERY.md). Use `dc rescue` on a live image.

## Files

- `hook-devicecryptor` copies `dc` and `cryptsetup` into an initramfs when that hook is installed
- `local-top-devicecryptor` runs `dc attach` when `DC_SYSTEM_DEVICE` is set

The hook copies `dc` and `cryptsetup` when they are installed on the host. Installing the hook was not done on this machine.
