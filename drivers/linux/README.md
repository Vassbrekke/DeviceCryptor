# Linux block helper

Prefer userspace + `loop` + future `dm-crypt` custom target or `ublk`.

Optional out-of-tree module only if userspace cannot meet latency needs.
This directory holds design notes until a module is required.

## Mount path (current)

1. `dc mount` unlocks headers in userspace (`dc-volume`)
2. Sector R/W via AES-256-XTS in process memory
3. Later: hand master keys to a privileged helper that configures dm/ublk

Do not load `vendor/VeraCrypt` kernel code.

## Helper request (not an attach)

`dc attach --device /dev/sda1 --mapper dcroot` only checks the request. It does not call `dmsetup` or `cryptsetup`.

- No password and no master key on the command line or in the request.
- Mapper name: 1..=64 of `[A-Za-z0-9._-]`.
- Device: absolute `/dev/` path, no `..`.
- A valid request is still refused until a privileged helper exists and has been tested.
