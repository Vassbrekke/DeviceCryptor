# External audit checklist (pre-1.0)

**Current status:** no independent cryptographic review. Internal tests only. Do not treat v0.2 as production crypto.

## Scope

- [ ] `crates/dc-crypto` (AES-XTS, Argon2id, PBKDF2, ML-KEM wrap)
- [ ] `crates/dc-format` (DC01 + VeraCrypt header parsing)
- [ ] Boot unlock paths (`boot/windows-uefi`, `boot/linux-initramfs`)
- [ ] Windows filter driver key handling
- [ ] Privilege separation GUI ↔ mount helper

## Deliverables

- [ ] Written report with severity ratings
- [ ] Reproducible build hashes (`cargo build --release` + SBOM)
- [ ] All Critical/High findings fixed before 1.0 tag

## Reproducible builds

```bash
cargo build --release -p dc-cli -p dc-gui
cargo tree > sbom-tree.txt
# Prefer cargo-auditable / build-info embedding in release pipeline
```

## Related assurance work (not a substitute for review)

- Differential tests against known-good AES-XTS / ML-KEM implementations
- Fuzzing methodology: [TESTING.md](TESTING.md)
- Corruption/recovery tests and side-channel review: [ASSURANCE.md](ASSURANCE.md)

## Status

Internal engineering tests only. External firm engagement: pending.
