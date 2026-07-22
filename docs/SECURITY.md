# Security Policy

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
