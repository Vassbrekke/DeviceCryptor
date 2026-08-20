# DeviceCryptor

Post-quantum-ready rewrite of VeraCrypt for **Windows** and **Linux**, written in **Rust**.

> **v0.2 — Linux file containers are usable for testing.** Still not audited. Do not rely on it for irreplaceable data yet. Bug reports and test results on Linux and Windows are welcome.

- **Defaults:** AES-256-XTS + Argon2id (`DC01` format)
- **Compat:** mount VeraCrypt/TrueCrypt volumes (oracle-tested against `vendor/VeraCrypt`)
- **Windows EFI PBA:** rewrite guided by [`vendor/VeraCrypt-DCS`](https://github.com/veracrypt/VeraCrypt-DCS) (LGPL reference)
- **PQ extras:** ML-KEM-768 key wrap for export
- **UI:** `dc` CLI + `devicecryptor` iced GUI
- **Ops:** password change, header backup/restore, human sizes, silent password prompts

## Quick start (Linux)

```bash
cargo build -p dc-cli --release
./target/release/dc create ./test.dc --size 16M --password 'test-pass' --fs fat32
mkdir mnt
# Mount: password (+ optional --keyfile). Dismount: id only — no password.
./target/release/dc mount ./test.dc ./mnt --password 'test-pass'
echo hi > ./mnt/hi.txt
./target/release/dc dismount
./scripts/linux-test.sh   # full harness
```

### Everyday ops

```bash
# Silent prompt (preferred over --password on shared machines)
./target/release/dc mount ./test.dc ./mnt

# Change password without re-encrypting data
./target/release/dc chpasswd ./test.dc

# Header safety net before experiments
./target/release/dc header backup ./test.dc ./test.hdrbak
./target/release/dc header restore ./test.dc ./test.hdrbak

./target/release/dc status
./target/release/dc info ./test.dc
```

Password tip: omit `--password` to type it silently. Prefer `--password-env` over `--password` (avoids argv leaks).

### GUI (full CLI parity for core tabs)

```bash
cargo build -p dc-gui --release
./target/release/devicecryptor
```

Tabs: **Create**, **Mount**, **Dismount**, **Info**, **Status**, **Favorites**, **Keywrap** — same operations as `dc` (keyfiles, PIM, hidden volumes, wipe, FS type, protect-hidden, ML-KEM wrap).

**Workflow:** mount asks for password (and optional keyfile); **dismount is one click** on Status (or enter mount id on Dismount) — no credentials again.

See [docs/LINUX_TESTING.md](docs/LINUX_TESTING.md), [docs/ROADMAP.md](docs/ROADMAP.md), [CHANGELOG.md](CHANGELOG.md).

## Workspace

| Crate | Role |
|-------|------|
| `dc-crypto` | AES-XTS, Argon2id, PBKDF2, ML-KEM |
| `dc-format` | DC01 + VeraCrypt headers |
| `dc-volume` | create/mount/sector I/O, FAT checkout, favorites, hidden volumes, chpasswd |
| `dc-platform` | OS helpers |
| `dc-cli` | `dc` binary |
| `dc-gui` | iced GUI |

See [docs/UPSTREAM_MAP.md](docs/UPSTREAM_MAP.md) (includes **VeraCrypt-DCS** EFI map), [docs/FORMAT.md](docs/FORMAT.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

DeviceCryptor original code is licensed under the **Apache License 2.0**. Copyright © 2026 [Vassbrekke AS](https://www.vassbrekke.no). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Source: https://github.com/Vassbrekke/DeviceCryptor

Vendor trees under `vendor/` keep their own licenses (VeraCrypt / TrueCrypt terms, VeraCrypt-DCS LGPL-3.0) — see [`NOTICE`](NOTICE). They are reference-only and are not linked into DeviceCryptor release binaries.
