# Roadmap — toward a finished product

Status snapshot for **0.2.x** (Linux file-container path).

## Done (usable product slice)

- [x] DC01 create / open (AES-256-XTS + Argon2id + BLAKE3 header MAC)
- [x] VeraCrypt/TrueCrypt header unlock (compat mount path)
- [x] Linux FAT **checkout/checkin** mount (no root, no FUSE)
- [x] Hidden volumes + protect-hidden on checkout writes
- [x] Keyfiles, favorites, ML-KEM-768 key wrap
- [x] Passwordless dismount via kernel keyring, or a mode-0600 session file if keyctl cannot round-trip
- [x] CLI + iced GUI
- [x] `linux-test.sh` e2e harness + CI
- [x] **v0.2:** silent password prompts, human sizes (`16M`), `chpasswd`, header backup/restore, status polish
- [x] GUI parity for `chpasswd` + header backup/restore (Volumes menu, classic window)
- [x] Progress meter for `--wipe` creates (stderr, every 5%)
- [x] Session key in the user kernel keyring when `keyctl` can round-trip it; file fallback otherwise
- [x] `dc bench` — Argon2id timing helper (`--pim` for the VeraCrypt mapping)
- [x] Install script + `.desktop` launcher + man page (`scripts/install-linux.sh`, `dist/`)
- [x] Keyfile generator (`dc keyfile`, Tools menu)
- [x] Recovery workflow for file containers: `docs/RECOVERY.md`, `dc rescue`, `dc header check`. System-disk mapping and a rescue ISO are not in this build.

## 0.3 (done)

- [x] Vendor oracle: SHA-512, SHA-256, BLAKE2s, and Whirlpool samples unlock (password `test`, AES-XTS) and the first data sector has a boot signature. Hidden SHA-512 volume uses `testhidden`. `test.streebog.hc` unlocks with HMAC-Streebog and Kuznyechik-XTS.
- [x] Optional FUSE live FAT mount (`dc mount --live`, or the Live mount checkbox). Edits write through. Checkout remains the default. The mounting process must stay open.
- [x] VeraCrypt cascades that do not need Serpent: AES-Twofish, Kuznyechik-Twofish, Kuznyechik-AES, and Camellia-Kuznyechik. Each opens a VeraCrypt 1.26.29 HMAC-SHA-512 volume. Serpent and any cascade that includes it stay out: the reviewed `serpent` crate accepts only a 128-bit key, and VeraCrypt uses 256-bit Serpent. No hand-rolled ciphers.
- [x] Argon2id golden volume. VeraCrypt 1.26.29 file `tests/goldens/argon2id-pim1.hc` opens with PIM 1. Header key derivation is 192 bytes; AES-XTS uses the first 64.

## 1.0 gates

Do not use “post-quantum-ready” or “VeraCrypt rewrite” language before these land. Full list: [ASSURANCE.md](ASSURANCE.md).

- [ ] Independent cryptographic review (`docs/AUDIT.md`) — Critical/High fixed. The external side-channel lab is part of this review. Scope is the shipped Linux file-container crates.
- [x] Differential tests vs known-good AES-XTS and ML-KEM-768. AES-256-XTS sector 0 matches Python `cryptography` 50.0.1. ML-KEM-768 keygen and encapsulation match NIST ACVP FIPS203.
- [x] Fuzzing in CI (decrypted header payloads + sector crypto) with a crash policy. The KDF fuzz target stays local-only. See `docs/TESTING.md`.
- [x] Corruption/recovery tests: flipped header fails open, header restore recovers it, truncated containers and bad backups are rejected
- [x] Internal review of KDF wipe, MAC compare, and key wipe. Residuals are in `docs/ASSURANCE.md`. Cipher key schedules stay `zeroize(skip)` because `aes` and `xts-mode` do not implement `Zeroize`.
- [x] Frozen DC01 spec (`docs/FORMAT.md` version 1)
- [x] Threat model signed off against shipped Linux file-container features (`docs/THREAT_MODEL.md`)
- [x] Reproducible release builds + SBOM (`scripts/release-linux.sh`). Same-toolchain hashes are checked. Cross-distro bit-identical builds are not claimed.
- [x] `cargo audit` in CI with no vulnerability ignore list
- [x] Explicit “supported platforms” matrix (distros, kernel, FS backends). See `docs/PLATFORMS.md`. This build: Linux FAT checkout and opt-in live FUSE. No system encryption. macOS and Windows mounts are not implemented.

## Last stage — system encryption

Built, and not run on a disk. This machine has no free device; the disks are LUKS. Do not point this at those disks.

- [x] Privileged mount helper. `sudo dc attach` unlocks a header as root and sends the master key to `dc helper` on a pipe. The helper execs `cryptsetup` plain `aes-xts-plain64` only for a real block device. Cascades stay on the file-container path.
- [x] Linux initramfs unlock calls `dc attach` (`boot/linux-initramfs/`). Not installed and not booted here.
- [x] Windows filter request checks and EFI module logic (`drivers/windows/src/request_check.c`, `boot/windows-uefi/modules.c`). They compile as host programs. There is no signed `.sys` or `.efi`, and nothing was loaded.

## Non-goals (for now)

- Cloud sync / accounts / telemetry
- Shipping vendor VeraCrypt kernel code
- Claiming deniability on SSDs without the same caveats as VeraCrypt
