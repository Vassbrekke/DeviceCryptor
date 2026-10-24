# Recovery

File containers can be recovered today. System-disk mapping cannot. This build does not attach `/dev/mapper` and does not unlock a boot drive.

## Damaged file container

1. Copy the container before you write to it.
2. If you have a header backup from `dc header backup`, check it first:

```bash
dc header check ./volume.hdrbak
dc rescue --check ./volume.hdrbak
```

A good backup starts with `DCHDR01` and holds the primary and hidden header slots (128 KiB). Mode should be `0600`.

3. Confirm the password still opens the header:

```bash
dc info ./volume.dc
```

4. If the header is damaged and the backup checked out:

```bash
dc header restore ./volume.dc ./volume.hdrbak
dc info ./volume.dc
```

Restore writes only the first 128 KiB. It does not rewrite the backup header at the end of the file.

5. Mount with the checkout path. `--live` stays up only while that process is open.

```bash
dc mount ./volume.dc ./mnt
```

`dc rescue` prints these steps. It does not mount anything.

## Rescue ISO

Use any Linux live image that can run this `dc` binary. Copy `dc` onto the image or a USB stick. You do not need the graphical window.

Do not expect a DeviceCryptor rescue ISO in this tree. There is no system-encryption attach, so a rescue disc cannot map an encrypted boot disk yet.

The initramfs scripts under `boot/linux-initramfs/` only check a header password. They print that mapper attach is not done. Do not point GRUB at `/dev/mapper/dcroot` until that attach exists and has been tested.

## What this does not do

- No dm-crypt or ublk helper
- No Windows filter driver
- No EFI pre-boot authenticator
- Select Device and Auto-Mount Devices stay honest: system encryption is not in this build
