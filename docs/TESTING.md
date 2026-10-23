# Test and fuzz methodology

This is what we actually run. Gaps are listed in [ASSURANCE.md](ASSURANCE.md).

## Unit tests

```bash
cargo test -p dc-crypto -p dc-format -p dc-volume -p dc-platform -p dc-cli -- --test-threads=1
```

| Crate | Coverage |
|-------|----------|
| `dc-crypto` | AES-256-XTS roundtrip and a Python `cryptography` sector-0 vector; random sector sizes; Argon2id PIM table; ML-KEM-768 NIST ACVP keygen and encapsulation |
| `dc-format` | DC01 header create/open; wrong password fails closed; password reseal keeps master key |
| `dc-volume` | Session/open smoke; header backup/restore + `chpasswd` |
| `dc-cli` | Size parser |

AES-256-XTS sector 0 is checked against Python `cryptography` 50.0.1. ML-KEM-768 keygen and encapsulation are checked against NIST ACVP FIPS203. Vendor `.hc` samples live under `vendor/VeraCrypt/Tests/` (see `tests/goldens/README.md`).

## Linux end-to-end

```bash
./scripts/linux-test.sh
```

Unprivileged FAT checkout/checkin: create, write, remount, wrong password, hidden volume, header backup, `chpasswd`, restore. Details: [LINUX_TESTING.md](LINUX_TESTING.md).

Not covered: crash during checkin, Windows.

## Fuzzing

Requires [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and a nightly toolchain. Not in CI. No crash triage policy yet.

```bash
cargo +nightly fuzz run sector_xts
```

`sector_xts` encrypts and decrypts aligned slices. It does not derive a password key.

`header_parse` still calls the real header open with password `fuzz`. That pays a full KDF on every input, including Argon2id when the PRF is left on auto. Do not put that target in CI.
