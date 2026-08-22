# Volume Format Specification

**Working draft.** Layout and field meanings for implementers and tests. Not a frozen on-disk contract until 1.0 (see [ASSURANCE.md](ASSURANCE.md)). Interoperability with other tools is not promised.

## DC01 (DeviceCryptor native — create path)

New volumes use **DC01**. Layout mirrors VeraCrypt geometry so tools can reason about offsets, but on-disk crypto metadata is DeviceCryptor-specific.

### Geometry

| Constant | Value |
|----------|-------|
| Header slot size | 65,536 bytes |
| Effective header | 512 bytes (first 512 of primary slot) |
| Hidden header offset | 65,536 |
| Data area offset | 131,072 (`2 * 65536`) |
| Backup header group | last 131,072 bytes of volume |

### Effective header (512 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 64 | Salt (unencrypted, CSPRNG) |
| 64 | 448 | Encrypted header payload (AES-256-XTS, sector 0) |

### Encrypted payload (after decrypt)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `DC01` (`0x44433031`) |
| 4 | 2 | Format version (`1`) |
| 6 | 2 | Cipher ID (`1` = AES-256-XTS) |
| 8 | 2 | KDF ID (`1` = Argon2id) |
| 10 | 2 | Flags (bit0 = hidden volume host) |
| 12 | 4 | Argon2 time cost |
| 16 | 4 | Argon2 memory KiB |
| 20 | 4 | Argon2 parallelism |
| 24 | 4 | Sector size (512 or 4096) |
| 28 | 8 | Volume data size (bytes) |
| 36 | 8 | Encrypted area start (absolute file offset) |
| 44 | 8 | Encrypted area length |
| 52 | 8 | Hidden volume size (0 if none) |
| 60 | 4 | Reserved |
| 64 | 32 | BLAKE3-256 MAC over bytes 0–63 of payload (with MAC zeroed) |
| 96 | 64 | Master XTS key1 (32) \|\| key2 (32) |
| 160 | 288 | Reserved / future ML-KEM slot metadata |

Header keys: Argon2id(password‖keyfiles, salt) → 64 bytes → XTS key1/key2 for header.

## VeraCrypt / TrueCrypt (compat — mount only)

See `vendor/VeraCrypt/src/Common/Volumes.c` header v5:

- Salt 64 bytes; magic `VERA` (`0x56455241`) after decrypt
- CRC32 of key area and header fields
- Master key area 256 bytes (XTS primary+secondary, room for cascades)
- KDFs: Argon2id (PIM→params per `get_argon2_params`), PBKDF2-HMAC-SHA512/SHA256/etc.

DeviceCryptor **never creates** VeraCrypt-format volumes; it mounts them for migration.
