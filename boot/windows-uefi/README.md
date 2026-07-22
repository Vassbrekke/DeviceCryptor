# DeviceCryptor Windows UEFI Pre-Boot Authentication

**Primary reference:** [`vendor/VeraCrypt-DCS`](https://github.com/veracrypt/VeraCrypt-DCS)  
(Disk Cryptography Services — VeraCrypt’s EFI bootloader for Windows system encryption, LGPL-3.0)

Secondary notes: `vendor/VeraCrypt/src/Boot` (legacy BIOS / shared boot-area constants).

## DCS boot flow (what we reimplement)

```text
firmware
  → DcBoot.efi          (DcsBoot — starter / chain)
  → DcInt.dcs           (DcsInt — password UI + BlockIo filter)
  → Windows bootmgfw    (after header unlock; sectors decrypted via filter)
```

Supporting tools (DCS names → DeviceCryptor stubs):

| DCS | DeviceCryptor | Purpose |
|-----|---------------|---------|
| `DcsBoot.efi` | `DcBoot/` | Entry / start Windows path |
| `DcsInt.dcs` | `DcInt/` | PBA + `EFI_BLOCK_IO` read/write hook |
| `DcsRe.efi` | `DcRe/` | Recovery decrypt |
| `DcsCfg.dcs` | `DcCfg/` | EFI shell config (`DcsProp`-like) |
| `DcsBml.dcs` | `DcBml/` | Boot-order lock |
| `DcsInfo.dcs` | `DcInfo/` | Platform info |
| `SecureBoot/` | `SIGNING.md` | SB enrollment / Microsoft CA path |

## Crypto constraints in PBA

- Password → **PBKDF2-HMAC-SHA256 / BLAKE2s** (boot-safe KDFs). **Argon2id is not used in pre-boot** (matches VeraCrypt/DCS).
- Header decrypt → AES-256-XTS (and cascades if mounted volume requires them).
- After unlock, `DcInt` installs a BlockIo interceptor (`DCSINT_BLOCK_IO` pattern) so Windows sees plaintext sectors.

## Build

EDK2 package layout mirrors `vendor/VeraCrypt-DCS/DcsPkg.dsc`.  
DeviceCryptor freestanding crypto must match `dc-crypto` / VeraCrypt test vectors — do not link `vendor/VeraCrypt-DCS` into release images (LGPL reference-only policy; see `docs/UPSTREAM_MAP.md`).

## This directory

| Path | Purpose |
|------|---------|
| `README.md` | This file |
| `MODULES.md` | Package checklist vs DCS |
| `pba_stub.c` | Minimal PBA outline |
| `DcInt/block_io_hook.h` | BlockIo intercept contracts from DcsInt |
| `SIGNING.md` | EV + Secure Boot (DCS SecureBoot notes) |
