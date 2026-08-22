# Assurance

DeviceCryptor is an experimental encrypted-container implementation. Using reviewed primitive crates is not the same as a reviewed product. Do not use it for irreplaceable data until the gates below are met.

## Claims we do **not** make (v0.2)

- “Post-quantum-ready” disk encryption — bulk data is AES-256-XTS. ML-KEM-768 is used only for optional **key export** wrapping.
- A VeraCrypt rewrite or replacement — DC01 is a separate format. VeraCrypt/TrueCrypt mount is a **compat** path with incomplete cipher/cascade coverage.
- Production fitness, deniability, or resistance to side channels.

## What exists today

| Layer | What runs | Limits |
|-------|-----------|--------|
| Primitive crates | `aes`/`xts-mode`, `argon2`, `ml-kem`, `blake3`, OS RNG via `getrandom` | Composition and format parsing are ours |
| Unit tests | AES-XTS roundtrip, Argon2id PIM table vs VeraCrypt constants, DC01 create/open/wrong-password, ML-KEM wrap roundtrip, `chpasswd`/header backup | Roundtrips, not NIST/RFC test vectors for AES-XTS or ML-KEM |
| Linux e2e | `scripts/linux-test.sh` — create, mount, persist, wrong password, hidden volume, header backup/restore | FAT checkout path only; no injected corruption campaign |
| Fuzz | `fuzz/fuzz_targets/header_parse.rs` — DC01 + VeraCrypt header parse with a fixed password | No coverage of sector I/O, KDF, wrap, or mount; not in CI |
| CI | `fmt`, `clippy -D warnings`, unit tests, linux e2e, `cargo audit` | No fuzz job, no golden VeraCrypt volumes in-tree |

How to run the current tests: [TESTING.md](TESTING.md).

## Gates before stronger public language

Treat these as required before calling DeviceCryptor a VeraCrypt alternative, “post-quantum-ready,” or suitable for real data:

1. Independent cryptographic review of `dc-crypto`, `dc-format`, key handling, and the Linux mount path ([AUDIT.md](AUDIT.md)).
2. Differential tests against known-good AES-XTS and ML-KEM-768 implementations (not only self-roundtrips).
3. Continuous fuzzing of header parse **and** sector encrypt/decrypt (with corpus + crash policy).
4. Corruption/recovery tests (truncated files, flipped header bits, backup-slot restore).
5. Side-channel review of KDF, header MAC compare, and key wipe.
6. Frozen DC01 specification (versioned, with a compatibility policy).
7. Threat model signed off against the shipped feature set.

## Status

Internal engineering tests only. External firm engagement: pending (see [AUDIT.md](AUDIT.md)).
