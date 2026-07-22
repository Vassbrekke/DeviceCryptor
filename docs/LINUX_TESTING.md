# Linux testing guide (DeviceCryptor)

Linux is the first supported test platform. Windows EFI/driver paths remain scaffolded.

## Build

```bash
cargo build -p dc-cli
# binary: target/debug/dc
```

## One-shot harness

```bash
./scripts/linux-test.sh
```

Covers: create FAT32, keyfiles, mount/write/dismount persistence, wrong password, hidden volumes, unit tests.

## Manual smoke

```bash
./target/debug/dc create ./vol.dc --size 16777216 --password 'secret' --fs fat32
mkdir mnt
./target/debug/dc mount ./vol.dc ./mnt --password 'secret' --id t1
echo hi > ./mnt/hi.txt
./target/debug/dc dismount --id t1 --password 'secret'

mkdir mnt2
./target/debug/dc mount ./vol.dc ./mnt2 --password 'secret' --id t2
cat ./mnt2/hi.txt
./target/debug/dc dismount --id t2 --password 'secret'
```

## Mount backends

| FS | Backend | Privileges |
|----|---------|------------|
| `fat32` (default) | **checkout/checkin** — extracts FAT tree to a directory; `dismount` writes it back | none |
| `ext4` | decrypt to raw + `losetup` + `mount` | root |

Checkout mounts are not live kernel mounts: edit files in the mountpoint directory, then **dismount to sync** into the encrypted container.

## Hidden volumes

```bash
./target/debug/dc create ./h.dc --size 33554432 --password outer --hidden-size 8388608 \
  --hidden-password hidden --fs fat32
./target/debug/dc mount ./h.dc ./outer --password outer --id o
# … write decoy files …
./target/debug/dc dismount --id o --password outer
./target/debug/dc mount ./h.dc ./hid --password hidden --id h
# … write secret files …
./target/debug/dc dismount --id h --password hidden
```

Use `--protect-hidden` + `--hidden-password` when mounting the outer volume to refuse writes that would overwrite the hidden region.

## Keyfiles

```bash
./target/debug/dc create ./k.dc --password p --keyfile ./kf.bin --fs fat32
./target/debug/dc mount ./k.dc ./mnt --password p --keyfile ./kf.bin --id k
```

## Traveler / portable

Copy `target/release/dc` next to your containers — no installer required for checkout mounts.

## Initramfs (system encryption — later)

See `boot/linux-initramfs/`. Header unlock is wired; full dm/ublk attach is next.

## Ext4 (root)

```bash
sudo ./target/debug/dc create ./e.dc --size 67108864 --password p --fs ext4
sudo mkdir /mnt/dc
sudo ./target/debug/dc mount ./e.dc /mnt/dc --password p --fs ext4 --id e
# use /mnt/dc as a normal filesystem
sudo ./target/debug/dc dismount --id e --password p
```
