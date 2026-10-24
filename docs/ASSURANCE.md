# Assurance

DeviceCryptor is an experimental encrypted-container implementation. Using reviewed primitive crates is not the same as a reviewed product. Do not use it for irreplaceable data until the gates below are met.

## Claims we do **not** make (v0.2)

- “Post-quantum-ready” disk encryption — bulk data is AES-256-XTS. ML-KEM-768 is used only for optional **key export** wrapping.
- A VeraCrypt rewrite or replacement — DC01 is a separate format. VeraCrypt/TrueCrypt mount is a **compat** path with incomplete cipher/cascade coverage.
- Production fitness, deniability, or resistance to side channels. The internal note below is not a lab review.

## What exists today

| Layer | What runs | Limits |
|-------|-----------|--------|
| Primitive crates | `aes`/`xts-mode`, `argon2`, `ml-kem`, `blake3`, OS RNG via `getrandom` | Composition and format parsing are ours |
| Unit tests | AES-XTS vs Python `cryptography`; ML-KEM-768 vs NIST ACVP; vendor VeraCrypt samples for SHA-512, SHA-256, BLAKE2s, Whirlpool, and Streebog/Kuznyechik; cascades that do not need Serpent | Serpent and any cascade that includes it |
| Linux e2e | `scripts/linux-test.sh` — create, mount, persist, wrong password, hidden volume, header backup/restore | FAT checkout path; live FUSE is a separate opt-in. `dc attach` was not pointed at a disk |
| Fuzz | `header_payload` and `sector_xts` in CI (no KDF). `header_parse` pays a full KDF and stays local | Bounded run (`-runs=10000`); not a long campaign |
| CI | `fmt`, `clippy -D warnings`, unit tests, linux e2e, fuzz, same-toolchain release hash, `cargo audit` | No vulnerability ignore list |

How to run the current tests: [TESTING.md](TESTING.md).

## Gates before stronger public language

Treat these as required before calling DeviceCryptor a VeraCrypt alternative, “post-quantum-ready,” or suitable for real data:

1. Independent cryptographic review of `dc-crypto`, `dc-format`, key handling, and the Linux mount path ([AUDIT.md](AUDIT.md)). Open. Includes the external side-channel lab.
2. Differential tests against known-good AES-XTS and ML-KEM-768 implementations (not only self-roundtrips). Met.
3. Fuzzing of decrypted header parse and sector encrypt/decrypt in CI, with a crash policy ([TESTING.md](TESTING.md)). Met for the bounded CI job. The password-KDF target stays local.
4. Corruption/recovery tests (truncated files, flipped header bits, backup-slot restore). Met.
5. Side-channel review of KDF, header MAC compare, and key wipe. Internal note below is met. The lab review is still open.
6. Frozen DC01 specification (versioned, with a compatibility policy). Met for version 1.
7. Threat model signed off against the shipped feature set. Met for Linux file containers.

## Internal side-channel note

This is an engineering reading of the code we ship. It is not a lab side-channel review. That lab stays on the open audit in [AUDIT.md](AUDIT.md).

- Argon2id, PBKDF2, and BLAKE3 stay in their crates. Password material and header keys we own are `Zeroizing` or `zeroize`d. The decrypted DC01 payload is wiped after the master key is copied out.
- The DC01 header MAC uses `secure_eq`. VeraCrypt header and key CRC results use the same compare. Which headers are accepted did not change.
- Session master keys are wiped on dismount (`dc-volume`).
- Cipher key schedules in `dc-crypto` are `#[zeroize(skip)]`. `aes` and `xts-mode` do not implement `Zeroize`, so the expanded key lives until the allocation is reused. There is no unsafe wipe.

## Status

In-tree gates for the Linux file-container path are in [ROADMAP.md](ROADMAP.md). External firm engagement, including a side-channel lab, is pending (see [AUDIT.md](AUDIT.md)). DC01 version 1 is frozen in [FORMAT.md](FORMAT.md). The threat model for what ships is [THREAT_MODEL.md](THREAT_MODEL.md).
