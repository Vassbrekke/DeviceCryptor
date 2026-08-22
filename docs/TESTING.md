# Test and fuzz methodology

This is what we actually run. Gaps are listed in [ASSURANCE.md](ASSURANCE.md).

## Unit tests

```bash
cargo test -p dc-crypto -p dc-format -p dc-volume -p dc-platform -p dc-cli -- --test-threads=1
```

| Crate | Coverage |
|-------|----------|
| `dc-crypto` | AES-256-XTS encrypt/decrypt roundtrip; Argon2id PIM → (time, memory) vs VeraCrypt `get_argon2_params` table; ML-KEM-768 wrap/unwrap roundtrip |
| `dc-format` | DC01 header create/open; wrong password fails closed; password reseal keeps master key |
| `dc-volume` | Session/open smoke; header backup/restore + `chpasswd` |
| `dc-cli` | Size parser |

AES-XTS and ML-KEM tests are **self-consistency** only. They do not compare ciphertext to a second implementation.

Extracted VeraCrypt constants (geometry, PIM, PBKDF2 iteration formula): [TEST_VECTORS.md](TEST_VECTORS.md). Golden `.hc` files are not in the tree yet (`tests/goldens/`).

## Linux end-to-end

```bash
./scripts/linux-test.sh
```

Unprivileged FAT checkout/checkin: create, write, remount, wrong password, hidden volume, header backup, `chpasswd`, restore. Details: [LINUX_TESTING.md](LINUX_TESTING.md).

Not covered: live kernel mounts, crash during checkin, bit-flipped containers, Windows.

## Fuzzing (header parse)

Requires [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and a nightly toolchain.

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run header_parse
```

Target: `fuzz/fuzz_targets/header_parse.rs`. It feeds 512-byte prefixes into `open_dc01_header` and `try_open_veracrypt_header` with a **fixed** password (`b"fuzz"`). Goal: no panic on malformed headers.

Not in CI. No published corpus or crash triage policy yet. Sector I/O, KDF, and ML-KEM wrap are not fuzzed.

Reproduce a crash (when you have one):

```bash
cargo +nightly fuzz run header_parse fuzz/artifacts/header_parse/<crash-id>
```
