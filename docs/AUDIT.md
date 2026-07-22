# External audit checklist (pre-1.0)

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

## Status

Internal engineering review in progress. External firm engagement: pending.
