# Windows EFI modules vs VeraCrypt-DCS

Pinned: `vendor/VeraCrypt-DCS` @ `ef579bd6005fd38ed7e5ada8f739deb1f6850007`

| Status | DeviceCryptor | Upstream DCS | Notes |
|--------|---------------|--------------|-------|
| logic | `modules.c` | DcBoot, DcInt, DcRe, DcCfg, DcBml, DcInfo | Host-compiled contracts. Not an EDK2 image. |
| scaffold | `pba_stub.c` | `DcsBoot` + `DcsInt` entry | Combined outline |
| scaffold | `DcInt/block_io_hook.h` | `DcsInt/DcsInt.h` | Signature / filter struct |
| docs | `SIGNING.md` | `SecureBoot/` | Prefer MS-signed path (VeraCrypt ≥ 1.26.29) |

Oracle tests: unlock the same system-encrypted disk header that DCS unlocks (password/PIM/keyfile), then verify sector 0 plaintext matches after filter apply.
