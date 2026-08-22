# Roadmap — toward a finished product

Status snapshot for **0.2.x** (Linux file-container path).

## Done (usable product slice)

- [x] DC01 create / open (AES-256-XTS + Argon2id + BLAKE3 header MAC)
- [x] VeraCrypt/TrueCrypt header unlock (compat mount path)
- [x] Linux FAT **checkout/checkin** mount (no root, no FUSE)
- [x] Hidden volumes + protect-hidden on checkout writes
- [x] Keyfiles, favorites, ML-KEM-768 key wrap
- [x] Passwordless dismount via user-private session key file
- [x] CLI + iced GUI
- [x] `linux-test.sh` e2e harness + CI
- [x] **v0.2:** silent password prompts, human sizes (`16M`), `chpasswd`, header backup/restore, status polish

## Near-term (0.3 — product hardening)

- [ ] GUI parity for `chpasswd` + header backup/restore
- [ ] Progress meter for `--wipe` creates
- [ ] Optional FUSE live FAT mount (edit without full checkin on dismount)
- [ ] Session key in kernel keyring / memfd instead of plaintext state file where available
- [ ] `dc bench` — Argon2id timing helper for chosen params
- [ ] Install script + `.desktop` launcher + man page
- [ ] Stronger VeraCrypt cascade/cipher coverage beyond AES-XTS smoke path
- [ ] Expand goldens / oracle tests against vendor VeraCrypt samples

## Mid-term (0.4–0.5 — system encryption prep)

- [ ] Privileged mount helper (dm-crypt/ublk) with clear IPC trust boundary
- [ ] Linux initramfs unlock: full attach path (beyond header unlock scaffold)
- [ ] Recovery workflow docs + rescue ISO notes
- [ ] Windows filter driver + EFI PBA modules (see `boot/windows-uefi/MODULES.md`)

## 1.0 gates

Do not use “post-quantum-ready” or “VeraCrypt rewrite” language before these land. Full list: [ASSURANCE.md](ASSURANCE.md).

- [ ] Independent cryptographic review (`docs/AUDIT.md`) — Critical/High fixed
- [ ] Differential tests vs known-good AES-XTS and ML-KEM-768 implementations
- [ ] Fuzzing in CI (headers + sector crypto) with a crash policy
- [ ] Corruption/recovery tests (truncated/flipped containers, header restore)
- [ ] Side-channel review of KDF, MAC compare, and key wipe
- [ ] Frozen DC01 spec (`docs/FORMAT.md` versioned)
- [ ] Threat model signed off against shipped features
- [ ] Reproducible release builds + SBOM
- [ ] `cargo audit` clean in release CI
- [ ] Explicit “supported platforms” matrix (distros, kernel, FS backends)

## Non-goals (for now)

- Cloud sync / accounts / telemetry
- Shipping vendor VeraCrypt kernel code
- Claiming deniability on SSDs without the same caveats as VeraCrypt
