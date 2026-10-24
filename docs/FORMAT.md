# Volume Format Specification

**Frozen format version 1.** This is the on-disk contract for DC01 volumes this program writes. Interoperability with other tools is not promised. See [ASSURANCE.md](ASSURANCE.md).

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
| 64 | 32 | BLAKE3-256 MAC. Input is payload bytes 0–63, then 32 zero bytes, then payload bytes 96 through the end (master key and reserved). The MAC field itself is not input. |
| 96 | 64 | Master XTS key1 (32) \|\| key2 (32) |
| 160 | 288 | Reserved / future ML-KEM slot metadata |

Header keys: Argon2id(password‖keyfiles, salt) → 64 bytes → XTS key1/key2 for header.

### Compatibility policy

- Writers emit version `1` and set reserved bytes to zero.
- Readers reject any version other than `1`.
- Readers do not interpret reserved bytes. Those bytes are inside the MAC input, so a change fails authentication.
- A later format version uses a new version field. Version 1 volumes keep this layout.
- Offsets, magic `DC01`, cipher id `1`, and KDF id `1` do not change for version 1.

## VeraCrypt / TrueCrypt (compat — mount only)

This section is not part of the frozen DC01 contract.

See `vendor/VeraCrypt/src/Common/Volumes.c` header v5:

- Salt 64 bytes; magic `VERA` (`0x56455241`) after decrypt
- CRC32 of key area and header fields
- Master key area 256 bytes (XTS primary+secondary, room for cascades)
- KDFs: Argon2id (PIM→params per `get_argon2_params`), PBKDF2-HMAC-SHA512/SHA256/etc.

DeviceCryptor **never creates** VeraCrypt-format volumes; it mounts them for migration.
