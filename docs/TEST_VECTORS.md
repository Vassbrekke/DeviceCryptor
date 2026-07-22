# Extracted test vectors / constants from VeraCrypt_1.26.29

Source: `vendor/VeraCrypt` @ `d26216c294fdfb090ee856f6195c294176defa1d`

## Geometry (`src/Common/Volumes.h`)

| Constant | Value |
|----------|-------|
| `TC_VOLUME_HEADER_SIZE` | 65536 |
| `TC_VOLUME_HEADER_EFFECTIVE_SIZE` | 512 |
| `TC_HIDDEN_VOLUME_HEADER_OFFSET` | 65536 |
| `TC_VOLUME_DATA_OFFSET` | 131072 |
| Magic VERA | `0x56455241` |
| Header version | `0x0005` |

## Argon2id PIM (`src/Common/Pkcs5.c` `get_argon2_params`)

| PIM | time_cost | memory_kib |
|-----|-----------|------------|
| 0 (=12) | 6 | 416×1024 |
| 12 | 6 | 416×1024 |
| 31 | 13 | 1024×1024 |
| 32 | 14 | 1024×1024 |

Formula:
- `m_mib = min(64 + (pim-1)*32, 1024)`; `memory_kib = m_mib * 1024`
- `t = pim<=31 ? 3+floor((pim-1)/3) : 13+(pim-31)`

## PBKDF2-HMAC-SHA512 iterations (non-boot)

| PIM | iterations |
|-----|------------|
| 0 | 500000 |
| n>0 | 15000 + n*1000 |

## DeviceCryptor unit coverage

- `dc-crypto`: PIM table, AES-XTS roundtrip, ML-KEM wrap roundtrip
- `dc-format`: DC01 create/open, wrong password, random VC reject
- `dc-volume`: create/open/sector R/W

Golden VeraCrypt `.hc` files: generate in CI with stock VeraCrypt when available; place under `tests/goldens/` (see README there).
