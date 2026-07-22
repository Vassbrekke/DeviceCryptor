# Linux block helper

Prefer userspace + `loop` + future `dm-crypt` custom target or `ublk`.

Optional out-of-tree module only if userspace cannot meet latency needs.
This directory holds design notes until a module is required.

## Mount path (current)

1. `dc mount` unlocks headers in userspace (`dc-volume`)
2. Sector R/W via AES-256-XTS in process memory
3. Later: hand master keys to a privileged helper that configures dm/ublk

Do not load `vendor/VeraCrypt` kernel code.
