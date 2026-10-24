# DeviceCryptor Linux initramfs unlock

This is a scaffold. It can check a volume header password. It does not attach a decrypted block device.

Do not set `root=/dev/mapper/dcroot` yet. There is no mapper.

File-container recovery is in [docs/RECOVERY.md](../../docs/RECOVERY.md). Use `dc rescue` on a live image.

## Files

- `hook-devicecryptor` copies `/usr/bin/dc` into an initramfs when that hook is installed
- `local-top-devicecryptor` prompts and runs `dc info` when `DC_SYSTEM_DEVICE` is set

Installing these does not make system encryption work.
