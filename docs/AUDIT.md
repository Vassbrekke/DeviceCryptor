# External audit checklist (pre-1.0)

**Current status:** no independent cryptographic review. Internal tests only. Do not treat this tree as production crypto.

Scope is the Linux file-container path that ships. Boot unlock, the Windows filter driver, and a privileged mount helper are a later stage. They are not part of this review until that code exists.

## Scope

- [ ] `crates/dc-crypto` (AES-XTS, Argon2id, PBKDF2, ML-KEM wrap, key wipe)
- [ ] `crates/dc-format` (DC01 + VeraCrypt header parsing, MAC and CRC compares)
- [ ] `crates/dc-volume` session keys (user kernel keyring or mode-0600 file) and the Linux FAT mount path
- [ ] Side-channel lab: KDF, header MAC compare, and key wipe. The internal note in [ASSURANCE.md](ASSURANCE.md) is not a substitute.

## Deliverables

- [ ] Written report with severity ratings
- [ ] Reproducible build hashes from `scripts/release-linux.sh` (SHA256 sums + CycloneDX SBOM)
- [ ] All Critical/High findings fixed before a 1.0 tag

## Related assurance work (not a substitute for review)

- Differential tests against known-good AES-XTS / ML-KEM implementations
- Fuzzing methodology: [TESTING.md](TESTING.md)
- Corruption/recovery tests and the internal side-channel note: [ASSURANCE.md](ASSURANCE.md)

## Status

Internal engineering tests only. External firm engagement: pending.
