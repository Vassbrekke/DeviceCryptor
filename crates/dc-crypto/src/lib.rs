//! DeviceCryptor crypto: AES-XTS, Argon2id, VeraCrypt-compatible KDFs, ML-KEM wrap.

mod argon2_params;
mod kdf;
mod keywrap;
mod secure;
mod xts;

pub use argon2_params::{argon2_params_for_pim, Argon2Params};
pub use kdf::{
    bench_argon2id, bench_veracrypt_pim, derive_dc01_header_key, derive_header_key_argon2id,
    derive_header_key_pbkdf2_blake2s, derive_header_key_pbkdf2_sha256,
    derive_header_key_pbkdf2_sha512, derive_header_key_pbkdf2_streebog,
    derive_header_key_pbkdf2_whirlpool, keyfiles_pool, pbkdf2_hmac_blake2s, pbkdf2_hmac_streebog,
    pbkdf2_hmac_whirlpool, pbkdf2_iterations, KdfBench, KdfError, PrfId,
};
pub use keywrap::{
    mlkem_decapsulate_key, mlkem_encapsulate_key, mlkem_generate_keypair, KeyWrapError, WrappedKey,
};
pub use secure::{secure_eq, SecureBytes};
pub use xts::{
    Aes256Xts, CamelliaXts, DiskXts, KuznyechikXts, TwofishXts, VolumeCipher, XtsError,
};

pub const SALT_SIZE: usize = 64;
pub const HEADER_XTS_KEY_SIZE: usize = 64; // two AES-256 keys
pub const MASTER_XTS_KEY_SIZE: usize = 64;
pub const SECTOR_SIZE_DEFAULT: usize = 512;

/// Fill `buf` from the OS CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// CRC-32 (ISO 3309 / zlib polynomial) as used by VeraCrypt headers.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
