Golden VeraCrypt samples live in the vendor tree, not copied here:

- `vendor/VeraCrypt/Tests/test.sha512.hc` — password `test`, hidden password `testhidden`, HMAC-SHA-512, AES-XTS
- `vendor/VeraCrypt/Tests/test.sha256.hc` — password `test`, HMAC-SHA-256, AES-XTS
- `vendor/VeraCrypt/Tests/test.blake2s.hc` — password `test`, HMAC-BLAKE2s (hash from the `blake2` crate), AES-XTS
- `vendor/VeraCrypt/Tests/test.whirlpool.hc` — password `test`, HMAC-Whirlpool (hash from the `whirlpool` crate), AES-XTS

`test.streebog.hc` opens with password `test`, HMAC-Streebog, and Kuznyechik-XTS. It is not an AES volume.

`argon2id-pim1.hc` was minted here with VeraCrypt 1.26.29: AES, hash Argon2id, PIM 1, filesystem FAT, quick format, 5 MiB. Password `devicecryptor-argon2`. VeraCrypt rejects a shorter password when the Argon2 PIM is below 12. Header derivation is 192 bytes; the AES-XTS header key is the first 64.

`twofish-sha512.hc` was minted here with VeraCrypt 1.26.29: Twofish, HMAC-SHA-512, PIM 0, password `test`, FAT, 5 MiB.

`camellia-sha512.hc` was minted here with VeraCrypt 1.26.29: Camellia, HMAC-SHA-512, PIM 0, password `test`, FAT, 5 MiB. The cipher is `camellia` 0.1 `Camellia256`. Do not bump that crate to 0.2: it no longer fits `xts-mode` 0.5.

`aes-twofish-sha512.hc` was minted here with VeraCrypt 1.26.29: AES-Twofish, HMAC-SHA-512, PIM 0, password `test`, FAT, 5 MiB. Encrypt order is Twofish-XTS, then AES-XTS. The key is 128 bytes.

`kuznyechik-twofish-sha512.hc`, `kuznyechik-aes-sha512.hc`, and `camellia-kuznyechik-sha512.hc` are the other non-Serpent cascades, same password and HMAC-SHA-512. Serpent cascades are not in this tree.

`aes-twofish-sha256.hc` is AES-Twofish with HMAC-SHA-256. `aes-twofish-blake2s.hc` is HMAC-BLAKE2s. `aes-twofish-whirlpool.hc` is HMAC-Whirlpool. `aes-twofish-streebog.hc` is HMAC-Streebog.

Passwords in the vendor samples are from `vendor/VeraCrypt/Tests/bench.bat`.
