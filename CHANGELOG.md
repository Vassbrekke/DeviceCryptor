# Changelog

## Unreleased

### Changed

- Public wording matches assurance: experimental unaudited containers with optional ML-KEM-768 **key wrap**, not a “post-quantum-ready VeraCrypt rewrite”
- Documented test/fuzz methodology and 1.0 assurance gates (`docs/ASSURANCE.md`, `docs/TESTING.md`)

## 0.2.0 — product ops for Linux containers

### Added

- `dc chpasswd` — change DC01 password/keyfiles without re-encrypting volume data
- `dc header backup` / `dc header restore` — primary + hidden header slot safety net
- Human-readable sizes for `--size` / `--hidden-size` (`16M`, `1G`, `512K`, …)
- Silent password prompts via `rpassword` (TTY); confirm on create/chpasswd
- Richer `dc info` / `dc status` output
- Unit + e2e coverage for chpasswd and header backup/restore

### Changed

- Workspace version **0.2.0**
- Default create size CLI default is now `16M` (same 16 MiB as before)
- README + ROADMAP updated for the usable Linux file-container slice

### Security notes

- Prefer omit `--password` or use `--password-env` to avoid argv leakage
- Mount session keys remain in `~/.local/state/devicecryptor/*.session` (mode 0600) while mounted — see `docs/SECURITY.md`

## 0.1.0 — initial public tree

- DC01 format, VeraCrypt compat open, Linux FAT checkout mounts, GUI scaffold, ML-KEM wrap
