# Upstream Map — VeraCrypt + VeraCrypt-DCS → DeviceCryptor

## Primary volume stack

Pinned reference: [veracrypt/VeraCrypt](https://github.com/veracrypt/VeraCrypt)

| Field | Value |
|-------|-------|
| Path | `vendor/VeraCrypt` |
| Tag | `VeraCrypt_1.26.29` |
| Commit | `d26216c294fdfb090ee856f6195c294176defa1d` |
| Role | Read-only behavioral oracle; **not** linked into release binaries |

## Windows EFI bootloader (system encryption PBA)

Pinned reference: [veracrypt/VeraCrypt-DCS](https://github.com/veracrypt/VeraCrypt-DCS)

| Field | Value |
|-------|-------|
| Path | `vendor/VeraCrypt-DCS` |
| Commit | `ef579bd6005fd38ed7e5ada8f739deb1f6850007` |
| License | LGPL-3.0 (see `vendor/VeraCrypt-DCS/LICENSE`) |
| Role | **Authoritative** EFI PBA / BlockIo intercept design; reference only — rewrite, do not link |

VeraCrypt’s in-tree `src/Boot` remains useful for BIOS/legacy notes; **UEFI Windows system encryption follows DCS**, not a from-scratch redesign.

### DCS module map

| VeraCrypt-DCS path | Role | DeviceCryptor target |
|--------------------|------|----------------------|
| `DcsBoot` | EFI starter (`DcsBoot.efi`) | `boot/windows-uefi/DcBoot/` |
| `DcsInt` | Pre-boot auth + BlockIo R/W interceptor | `boot/windows-uefi/DcInt/` |
| `DcsRe` | Recovery / decrypt tool | `boot/windows-uefi/DcRe/` |
| `DcsCfg` | EFI-shell configuration | `boot/windows-uefi/DcCfg/` |
| `DcsBml` | Boot-menu lock (protect boot order) | `boot/windows-uefi/DcBml/` |
| `DcsInfo` | Platform info generation | `boot/windows-uefi/DcInfo/` |
| `Library/VeraCryptLib` | Password/PIM/auth UI + crypto glue | Port contracts into freestanding C + `dc-crypto` vectors |
| `Library/PasswordLib`, `DcsTpmLib` | Password / TPM hooks | Optional later |
| `SecureBoot/` | Custom-key / SB enrollment notes | `boot/windows-uefi/SIGNING.md` |

### Volume stack map (unchanged)

| VeraCrypt path | DeviceCryptor target | Notes |
|----------------|----------------------|-------|
| `src/Crypto` | `crates/dc-crypto` | Third-party primitive crates; PIM/Argon2 mapping matched to vendor tables |
| `src/Common/Volumes.c`, `Volumes.h` | `crates/dc-format` | Header v5, salt, CRC, `VERA` |
| `src/Common/Pkcs5.c` | `crates/dc-crypto` | PBKDF2 + `get_argon2_params` |
| `src/Volume`, `src/Core`, `src/Mount`, `src/Format` | `crates/dc-volume`, `crates/dc-cli` | Create/mount/dismount |
| `src/Platform` | `crates/dc-platform` | OS abstractions |
| `src/Driver` | `drivers/windows` | Windows filter IOCTLs |
| `src/Boot` | Legacy/BIOS notes only | Prefer DCS for UEFI |
| `src/Main` | `crates/dc-gui` | Feature checklist (iced) |

## License

- `vendor/VeraCrypt` — TrueCrypt License 3.0 (legacy) + Apache-2.0 (VeraCrypt additions)
- `vendor/VeraCrypt-DCS` — **LGPL-3.0**
- DeviceCryptor-original code — Apache-2.0

**Policy:** do not statically link LGPL DCS objects into DeviceCryptor release EFI images. Reimplement module boundaries and on-disk/boot contracts; keep DCS as the oracle. If a future release deliberately incorporates LGPL DCS code, ship corresponding source and LGPL notices.
