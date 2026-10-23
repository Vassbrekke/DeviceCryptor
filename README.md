# DeviceCryptor

Experimental Rust encrypted-container implementation with AES-256-XTS, Argon2id, and optional ML-KEM-768 key wrap. Linux file containers are the first working path; Windows and system encryption are not ready.

> **v0.2 — experimental.** Not independently audited. Do not use it for irreplaceable data. Bug reports and test results are welcome.

- **Native format:** DC01 — AES-256-XTS + Argon2id + BLAKE3 header MAC
- **Compat:** mount some VeraCrypt/TrueCrypt volumes (AES-XTS path; incomplete cipher/cascade coverage)
- **PQ extras:** ML-KEM-768 wrapping for **key export**, not a post-quantum disk cipher
- **UI:** `dc` CLI + `devicecryptor` classic main window (VeraCrypt layout, not a tabbed shell)
- **Ops:** password change, header backup/restore, human sizes, silent password prompts

This is **not** a VeraCrypt replacement and is **not** “post-quantum-ready.” See [Assurance](#assurance).

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

### GUI (classic main window)

```bash
cargo build -p dc-gui --release
./target/release/devicecryptor
```

The window follows the classic VeraCrypt layout: slot list, Volume field, Select File, Mount, Dismount, Create Volume. Password, creation, header backup/restore, and password change are dialogs — not tabs. ML-KEM key wrap and the Argon2id benchmark sit under **Tools**. Select Device and Auto-Mount Devices are present and say clearly that system/device encryption is not in this build.

See [docs/LINUX_TESTING.md](docs/LINUX_TESTING.md), [docs/ASSURANCE.md](docs/ASSURANCE.md), [docs/ROADMAP.md](docs/ROADMAP.md), [CHANGELOG.md](CHANGELOG.md).

## Workspace

| Crate | Role |
|-------|------|
| `dc-crypto` | AES-XTS, Argon2id, PBKDF2, ML-KEM |
| `dc-format` | DC01 + VeraCrypt headers |
| `dc-volume` | create/mount/sector I/O, FAT checkout, favorites, hidden volumes, chpasswd |
| `dc-platform` | OS helpers |
| `dc-cli` | `dc` binary |
| `dc-gui` | iced GUI |

See [docs/UPSTREAM_MAP.md](docs/UPSTREAM_MAP.md), [docs/FORMAT.md](docs/FORMAT.md) (working spec), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (draft).

## Assurance

DeviceCryptor is a new cryptographic product (unaudited). Primitive crates (`aes`, `argon2`, `ml-kem`, `getrandom`) are used rather than hand-rolled ciphers, but **composition, format, and mount path are not independently reviewed**.

| In tree now | Not yet |
|-------------|---------|
| Unit tests, Linux e2e harness, `cargo audit` in CI | Independent cryptographic review |
| Header libFuzzer target (`fuzz/`) | Differential tests vs known-good AES-XTS / ML-KEM implementations |
| Working DC01 layout notes | Frozen format specification |
| Draft threat model | Side-channel review; corruption/recovery campaign |

Stronger language (“rewrite of VeraCrypt”, “post-quantum-ready”, production use) waits on the gates in [docs/ASSURANCE.md](docs/ASSURANCE.md) and [docs/AUDIT.md](docs/AUDIT.md).

## License

DeviceCryptor original code is licensed under the **Apache License 2.0**. Copyright © 2026 [Vassbrekke AS](https://www.vassbrekke.no). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Source: https://github.com/Vassbrekke/DeviceCryptor

Vendor trees under `vendor/` keep their own licenses (VeraCrypt / TrueCrypt terms, VeraCrypt-DCS LGPL-3.0) — see [`NOTICE`](NOTICE). They are reference-only and are not linked into DeviceCryptor release binaries.
