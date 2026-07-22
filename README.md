# DeviceCryptor

Post-quantum-ready rewrite of VeraCrypt for **Windows** and **Linux**, written in **Rust** (no JavaScript).

- **Defaults:** AES-256-XTS + Argon2id (`DC01` format)
- **Compat:** mount VeraCrypt/TrueCrypt volumes (oracle-tested against `vendor/VeraCrypt`)
- **Windows EFI PBA:** rewrite guided by [`vendor/VeraCrypt-DCS`](https://github.com/veracrypt/VeraCrypt-DCS) (LGPL reference)
- **PQ extras:** ML-KEM-768 key wrap for export
- **UI:** `dc` CLI + `devicecryptor` iced GUI

## Quick start (Linux)

```bash
cargo build -p dc-cli --release
./target/release/dc create ./test.dc --size 16777216 --password 'test-pass' --fs fat32
mkdir mnt
./target/release/dc mount ./test.dc ./mnt --password 'test-pass'
echo hi > ./mnt/hi.txt
./target/release/dc dismount --password 'test-pass'
./scripts/linux-test.sh   # full harness
```

### GUI (full CLI parity)

```bash
cargo build -p dc-gui --release
./target/release/devicecryptor
```

Tabs: **Create**, **Mount**, **Dismount**, **Info**, **Status**, **Favorites**, **Keywrap** — same operations as `dc` (keyfiles, PIM, hidden volumes, wipe, FS type, protect-hidden, ML-KEM wrap).

See [docs/LINUX_TESTING.md](docs/LINUX_TESTING.md).

## Workspace

| Crate | Role |
|-------|------|
| `dc-crypto` | AES-XTS, Argon2id, PBKDF2, ML-KEM |
| `dc-format` | DC01 + VeraCrypt headers |
| `dc-volume` | create/mount/sector I/O, FAT checkout, favorites, hidden volumes |
| `dc-platform` | OS helpers |
| `dc-cli` | `dc` binary |
| `dc-gui` | iced GUI |

See [docs/UPSTREAM_MAP.md](docs/UPSTREAM_MAP.md) (includes **VeraCrypt-DCS** EFI map), [docs/FORMAT.md](docs/FORMAT.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

DeviceCryptor-original code: Apache-2.0 OR MIT. Vendor VeraCrypt / VeraCrypt-DCS retain their own licenses (`NOTICE`).
