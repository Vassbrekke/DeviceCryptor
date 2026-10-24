# Changelog

## Unreleased

### Added

- Classic main window (slot list, Volume field, Select File, Mount / Dismount / Create Volume). Password, creation, header backup/restore, and password change are dialogs. ML-KEM wrap and Argon2id benchmark stay under Tools.
- `dc bench` times DC01 Argon2id defaults; `--pim` times the VeraCrypt PIM mapping
- `dc keyfile` writes a random keyfile (mode 0600)
- `--wipe` prints a stderr progress meter
- Mount session keys prefer the user kernel keyring (`keyctl padd` on stdin) and fall back to the mode-0600 session file
- A wrong DC01 password no longer tries VeraCrypt's 416 MiB Argon2id. That mapping belongs to VeraCrypt headers only.
- `dc attach` checks a system-device helper request and then refuses. It does not call dmsetup or cryptsetup.
- `scripts/install-linux.sh` installs `dc`, `devicecryptor`, a man page, and a desktop launcher

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
