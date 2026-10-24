# Linux block helper

Prefer userspace + `loop` + future `dm-crypt` custom target or `ublk`.

Optional out-of-tree module only if userspace cannot meet latency needs.
This directory holds design notes until a module is required.

## Mount path (current)

1. `dc mount` unlocks headers in userspace (`dc-volume`)
2. Sector R/W via AES-256-XTS in process memory
3. Later: hand master keys to a privileged helper that configures dm/ublk

Do not load `vendor/VeraCrypt` kernel code.

## Helper

`sudo dc attach --device /dev/sda1 --mapper dcroot` prompts for the volume password, unlocks the header, and pipes the master key to `dc helper`. The helper runs `cryptsetup open --type plain` for AES-256-XTS only, and only when the path is a block device and the process is root.

This was not run against a disk. Do not point it at a LUKS device.

- No password and no master key on the command line.
- Mapper name: 1..=64 of `[A-Za-z0-9._-]`.
- Device: absolute `/dev/` path, no `..`, and not a symlink.
