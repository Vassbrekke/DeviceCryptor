# Security Policy

**Status:** v0.2 is experimental and has not had an independent cryptographic review. Do not store irreplaceable data in DeviceCryptor volumes. See [ASSURANCE.md](ASSURANCE.md).

## Reporting

Report vulnerabilities privately to the maintainers. Do not open public issues for
actively exploitable crypto bugs before a fix is available.

## Engineering rules

1. No custom block ciphers, KDFs, or RNGs — use reviewed crates only.
2. Keys and passwords use `zeroize`; prefer locked pages where the OS allows.
3. Constant-time compares for MACs and password verification outcomes that could leak via timing of early exits on MAC only (still fail closed).
4. GUI runs unprivileged; mount/format that needs raw devices uses a helper.
5. `cargo audit` must be clean of known critical advisories in CI before release.
6. System encryption / boot paths require an external audit before 1.0.

## Mount session keys (Linux checkout)

While a volume is mounted, the unlocked master key is needed so **dismount does not
require re-entering the password**.

1. If `keyctl` can store the blob on stdin (`padd`) and read it back, the key lives
   in the user kernel keyring (`devicecryptor-session-<id>`). The on-disk file is
   only an 8-byte marker (`DCSESSKR`), mode `0600`. The key is never passed on argv.
2. Otherwise the full session blob is written to
   `~/.local/state/devicecryptor/<id>.session` (mode `0600`).

Either store is wiped on dismount. A keyring entry also dies at logout if a crash
skips the wipe. Anyone who can read the user keyring or that path while a volume
is mounted can decrypt the container data area — protect the user account the same
way you would any unlocked volume. Mount ids with spaces or path characters skip
the keyring and use the file.

## Password change

`dc chpasswd` re-seals the DC01 header with a new salt and password-derived header
key; the volume master key and ciphertext are unchanged. Always take a
`dc header backup` first if the volume is important. Prefer interactive prompts or
`--password-env` over `--password` / `--new-password` on multi-user hosts (argv is
visible to other processes).

## Cryptography defaults

| Purpose | Algorithm |
|---------|-----------|
| Bulk disk | AES-256-XTS |
| Password KDF (DC01) | Argon2id |
| Header MAC (DC01) | BLAKE3-256 |
| Key export wrap | ML-KEM-768 + HKDF-SHA256 + AES-256-KW-style seal |

## Dependencies

Pin versions in the workspace `Cargo.toml`. Prefer `aes`, `xts-mode`, `argon2`,
`blake3`, `ml-kem`, `zeroize`, `subtle`.
