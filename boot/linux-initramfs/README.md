# DeviceCryptor Linux initramfs unlock

## Install (Debian/Ubuntu initramfs-tools)

1. Install `dc` to `/usr/bin/dc`
2. Copy `hook-devicecryptor` → `/etc/initramfs-tools/hooks/devicecryptor`
3. Copy `local-top-devicecryptor` → `/etc/initramfs-tools/scripts/local-top/devicecryptor`
4. Set kernel cmdline or `/etc/devicecryptor/system.env`:
   - `DC_SYSTEM_DEVICE=/dev/disk/by-uuid/...`
   - `DC_MAPPER_NAME=dcroot`
5. `update-initramfs -u` and configure GRUB/`systemd-boot` root=`/dev/mapper/dcroot`

## Recovery

Boot a rescue ISO with DeviceCryptor, run:

```sh
dc info /dev/sdXN
# then attach decrypted mapping (phase completion)
```

Recovery passphrase / keyfile support mirrors VeraCrypt rescue workflow.
