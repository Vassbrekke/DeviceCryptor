# DeviceCryptor

Experimental Rust encrypted-container tool. Linux file containers work. Windows and system encryption do not.

> **Experimental.** Not independently audited. Do not store irreplaceable data in these volumes. The 0.3 roadmap slice is in this tree. The crate version is still 0.2.0 until a release tag.

- **Native format:** DC01 — AES-256-XTS, Argon2id, BLAKE3 header MAC
- **Compat:** VeraCrypt/TrueCrypt headers on HMAC-SHA-512, HMAC-SHA-256, HMAC-BLAKE2s, HMAC-Whirlpool, HMAC-Streebog, and Argon2id. Disk ciphers: AES-256-XTS, Kuznyechik-XTS, Twofish-XTS, Camellia-256-XTS. Cascades: AES-Twofish, Kuznyechik-Twofish, Kuznyechik-AES, Camellia-Kuznyechik. Serpent, and any cascade that needs it, is not implemented.
- **Key wrap:** ML-KEM-768 wraps an exported key. It is not the disk cipher and is not post-quantum disk encryption.
- **UI:** `dc` CLI and a classic main window (slot list, Volume field, Select File, Mount, Dismount, Create Volume). Not a tabbed shell.
- **Mount:** FAT checkout is the default. Live FAT (`--live`) writes through and stays up only while that process is open.
- **Ops:** password change, header backup/restore, keyfiles, favorites, wipe progress, `dc platforms`

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

Pass `--prf sha512` (or `sha256`, `blake2s`, `whirlpool`, `streebog`, `argon2`) when you know the VeraCrypt header hash. `auto` tries Argon2id first and is slow.

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
./target/release/dc platforms
```

Password tip: omit `--password` to type it silently. Prefer `--password-env` over `--password` (avoids argv leaks).

Live mount stays running until you dismount it:

```bash
./target/release/dc mount ./test.dc ./mnt --live
```

### GUI (classic main window)

```bash
cargo build -p dc-gui --release
./target/release/devicecryptor
```

Password, creation, header backup/restore, and password change are dialogs. ML-KEM key wrap and the Argon2id benchmark sit under **Tools**. Select Device and Auto-Mount Devices stay visible and say that system encryption is not in this build.

See [docs/LINUX_TESTING.md](docs/LINUX_TESTING.md), [docs/ASSURANCE.md](docs/ASSURANCE.md), [docs/ROADMAP.md](docs/ROADMAP.md), [docs/PLATFORMS.md](docs/PLATFORMS.md), [CHANGELOG.md](CHANGELOG.md).

## Workspace

| Crate | Role |
|-------|------|
| `dc-crypto` | AES, Kuznyechik, Twofish, Camellia, Argon2id, PBKDF2, ML-KEM key wrap |
| `dc-format` | DC01 + VeraCrypt headers |
| `dc-volume` | create/mount/sector I/O, FAT checkout, opt-in live FUSE, favorites, hidden volumes, chpasswd |
| `dc-platform` | OS helpers, `dc platforms` |
| `dc-cli` | `dc` binary |
| `dc-gui` | classic window |

See [docs/UPSTREAM_MAP.md](docs/UPSTREAM_MAP.md), [docs/FORMAT.md](docs/FORMAT.md) (working spec), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (draft).

## Assurance

DeviceCryptor is unaudited. Primitive crates are used rather than hand-rolled ciphers. Composition, format, and the mount path are not independently reviewed.

| In tree now | Not yet |
|-------------|---------|
| Vendor volume opens for the ciphers listed above | Serpent and Serpent cascades |
| AES-256-XTS checked against Python `cryptography`; ML-KEM-768 keygen and encapsulation checked against NIST ACVP | Independent cryptographic review |
| Header restore after a flipped header; bad backups rejected | Fuzzing in CI, side-channel review |
| Linux FAT checkout and opt-in live FUSE | System encryption, macOS and Windows mounts |
| `cargo audit` in CI | A clean audit and a frozen DC01 spec |

Stronger language (“rewrite of VeraCrypt”, “post-quantum-ready”, production use) waits on the gates in [docs/ASSURANCE.md](docs/ASSURANCE.md) and [docs/AUDIT.md](docs/AUDIT.md).

## License

DeviceCryptor original code is licensed under the **Apache License 2.0**. Copyright © 2026 [Vassbrekke AS](https://www.vassbrekke.no). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Source: https://github.com/Vassbrekke/DeviceCryptor

Vendor trees under `vendor/` keep their own licenses (VeraCrypt / TrueCrypt terms, VeraCrypt-DCS LGPL-3.0) — see [`NOTICE`](NOTICE). They are reference-only and are not linked into DeviceCryptor release binaries.
