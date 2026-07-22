# Windows driver / EFI signing pipeline

System encryption is not shippable unsigned on modern Windows + Secure Boot.

## References

- Driver / installer EV signing: same as before
- EFI bootloader Secure Boot: follow **`vendor/VeraCrypt-DCS/SecureBoot/`** and
  VeraCrypt docs — since VeraCrypt **1.26.29**, prefer Microsoft-signed EFI
  bootloaders over replacing platform SB keys (custom-key enrollment can break
  Windows Boot Manager handoff). See DCS `SecureBoot/readme.txt`.

## Required certificates

1. **EV Code Signing** for installers / `dc.exe` / GUI
2. **Windows Hardware Developer Center** attestation or HLK for the filter driver
3. **EFI image signing** compatible with Secure Boot (Microsoft 3rd-party UEFI CA
   where possible; custom DB enrollment only as documented fallback)

## Pipeline sketch

```text
build EDK2 DcBoot + DcInt (Release)
  → sign EFI images for Secure Boot
build WDK driver (Release)
  → Partner Center attestation / WHQL
  → embed in installer with DcBoot/DcInt
  → installer deploys driver + EFI boot entry (DCS-compatible layout)
```

## Local test (test-signing / SB off only)

```powershell
bcdedit /set testsigning on
# NEVER for production users
```

Track EV + SB signing procurement before declaring Phase 3 complete for users.
