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

## Near-term (0.3 — still open)

- [x] Vendor oracle: SHA-512, SHA-256, BLAKE2s, and Whirlpool samples unlock (password `test`, AES-XTS) and the first data sector has a boot signature. Hidden SHA-512 volume uses `testhidden`. `test.streebog.hc` unlocks with HMAC-Streebog and Kuznyechik-XTS.
- [x] Optional FUSE live FAT mount (`dc mount --live`, or the Live mount checkbox). Edits write through. Checkout remains the default. The mounting process must stay open.
- [ ] Stronger VeraCrypt cascade/cipher coverage. AES-Twofish opens a VeraCrypt 1.26.29 volume. Other cascades are still absent. Serpent is blocked: the `serpent` crate accepts only a 128-bit key, and VeraCrypt uses 256-bit Serpent. No hand-rolled ciphers.
- [x] Argon2id golden volume. VeraCrypt 1.26.29 file `tests/goldens/argon2id-pim1.hc` opens with PIM 1. Header key derivation is 192 bytes; AES-XTS uses the first 64.

## Mid-term (0.4–0.5 — system encryption prep)

- [ ] Privileged mount helper (dm-crypt/ublk) with clear IPC trust boundary
- [ ] Linux initramfs unlock: full attach path (beyond header unlock scaffold)
- [ ] Recovery workflow docs + rescue ISO notes
- [ ] Windows filter driver + EFI PBA modules (see `boot/windows-uefi/MODULES.md`)

## 1.0 gates

Do not use “post-quantum-ready” or “VeraCrypt rewrite” language before these land. Full list: [ASSURANCE.md](ASSURANCE.md).

- [ ] Independent cryptographic review (`docs/AUDIT.md`) — Critical/High fixed
- [x] Differential tests vs known-good AES-XTS and ML-KEM-768. AES-256-XTS sector 0 matches Python `cryptography` 50.0.1. ML-KEM-768 keygen and encapsulation match NIST ACVP FIPS203.
- [ ] Fuzzing in CI (headers + sector crypto) with a crash policy
- [x] Corruption/recovery tests: flipped header fails open, header restore recovers it, truncated containers and bad backups are rejected
- [ ] Side-channel review of KDF, MAC compare, and key wipe
- [ ] Frozen DC01 spec (`docs/FORMAT.md` versioned)
- [ ] Threat model signed off against shipped features
- [ ] Reproducible release builds + SBOM
- [ ] `cargo audit` clean in release CI
- [x] Explicit “supported platforms” matrix (distros, kernel, FS backends). See `docs/PLATFORMS.md`. This build: Linux FAT checkout and opt-in live FUSE. No system encryption. macOS and Windows mounts are not implemented.

## Non-goals (for now)

- Cloud sync / accounts / telemetry
- Shipping vendor VeraCrypt kernel code
- Claiming deniability on SSDs without the same caveats as VeraCrypt
