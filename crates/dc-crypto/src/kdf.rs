use crate::argon2_params::argon2_params_for_pim;
use crate::{HEADER_XTS_KEY_SIZE, SALT_SIZE};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2s256;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512};
use streebog::Streebog512;
use thiserror::Error;
use whirlpool::Whirlpool;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;
type HmacWhirlpool = Hmac<Whirlpool>;
type HmacStreebog = Hmac<Streebog512>;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("invalid salt length")]
    Salt,
    #[error("argon2 params: {0}")]
    Argon2Params(String),
    #[error("argon2 failed")]
    Argon2,
    #[error("pbkdf2 failed")]
    Pbkdf2,
    #[error("output too short")]
    Output,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrfId {
    Sha512 = 1,
    Sha256 = 2,
    Blake2s = 3,
    Whirlpool = 4,
    Streebog = 5,
    Argon2id = 10,
}

/// VeraCrypt PBKDF2 iteration count for non-boot volumes.
pub fn pbkdf2_iterations(prf: PrfId, pim: i32, boot: bool) -> u32 {
    let pim = if pim < 0 { 0 } else { pim };
    match prf {
        PrfId::Sha512 | PrfId::Whirlpool => {
            if pim == 0 {
                500_000
            } else {
                15_000 + (pim as u32) * 1000
            }
        }
        PrfId::Sha256 | PrfId::Blake2s | PrfId::Streebog => {
            if pim == 0 {
                if boot {
                    200_000
                } else {
                    500_000
                }
            } else if boot {
                (pim as u32) * 2048
            } else {
                15_000 + (pim as u32) * 1000
            }
        }
        PrfId::Argon2id => 0,
    }
}

/// Concatenate keyfile bytes (VeraCrypt-style pool contribution is applied by caller;
/// this helper loads raw keyfile contents capped at 1 MiB each).
pub fn keyfiles_pool(keyfiles: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut pool = Zeroizing::new(Vec::new());
    for kf in keyfiles {
        let take = kf.len().min(1024 * 1024);
        pool.extend_from_slice(&kf[..take]);
    }
    pool
}

fn password_with_keyfiles(password: &[u8], keyfiles: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(password.len()));
    out.extend_from_slice(password);
    if !keyfiles.is_empty() {
        let pool = keyfiles_pool(keyfiles);
        out.extend_from_slice(&pool);
    }
    out
}

/// VeraCrypt derives 192 bytes (`ARGON2_HEADER_KEYDATA_SIZE` in Crypto.h).
/// Argon2 mixes the output length into the hash, so a 64-byte derive will not
/// open a VeraCrypt volume. AES-XTS uses the first 64 bytes.
const VERACRYPT_ARGON2_OUT: usize = 192;

pub fn derive_header_key_argon2id(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let p = argon2_params_for_pim(pim);
    let params = Params::new(
        p.memory_kib,
        p.time_cost,
        p.parallelism,
        Some(VERACRYPT_ARGON2_OUT),
    )
    .map_err(|e| KdfError::Argon2Params(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = Zeroizing::new([0u8; VERACRYPT_ARGON2_OUT]);
    argon
        .hash_password_into(&pwd, salt, derived.as_mut())
        .map_err(|_| KdfError::Argon2)?;
    out[..HEADER_XTS_KEY_SIZE].copy_from_slice(&derived[..HEADER_XTS_KEY_SIZE]);
    Ok(())
}

pub fn derive_header_key_pbkdf2_sha512(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let iters = pbkdf2_iterations(PrfId::Sha512, pim, false);
    pbkdf2::<HmacSha512>(&pwd, salt, iters, out).map_err(|_| KdfError::Pbkdf2)?;
    Ok(())
}

/// VeraCrypt PBKDF2-HMAC-SHA256 header key. Same output size as SHA-512 (two AES-256 keys).
pub fn derive_header_key_pbkdf2_sha256(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let iters = pbkdf2_iterations(PrfId::Sha256, pim, false);
    pbkdf2::<HmacSha256>(&pwd, salt, iters, &mut out[..HEADER_XTS_KEY_SIZE])
        .map_err(|_| KdfError::Pbkdf2)?;
    Ok(())
}

/// PBKDF2-HMAC-BLAKE2s. The hash is `blake2::Blake2s256`. HMAC is the RFC 2104 padding
/// VeraCrypt uses in `Pkcs5.c`; the `hmac` crate cannot wrap BLAKE2s (lazy buffer).
pub fn pbkdf2_hmac_blake2s(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if out.is_empty() || iterations == 0 {
        return Err(KdfError::Output);
    }
    const HLEN: usize = 32;
    let mut offset = 0;
    let mut block_index = 1u32;
    while offset < out.len() {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_blake2s(password, &msg);
        let mut acc = u;
        for _ in 1..iterations {
            u = hmac_blake2s(password, &u);
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        let n = (out.len() - offset).min(HLEN);
        out[offset..offset + n].copy_from_slice(&acc[..n]);
        offset += n;
        block_index = block_index.checked_add(1).ok_or(KdfError::Output)?;
        u.zeroize();
        acc.zeroize();
    }
    Ok(())
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Blake2s256::new().chain_update(key).finalize();
        block_key[..32].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let inner = Blake2s256::new()
        .chain_update(ipad)
        .chain_update(data)
        .finalize();
    let outer = Blake2s256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer);
    block_key.zeroize();
    out
}

/// VeraCrypt header key via PBKDF2-HMAC-BLAKE2s. The hash comes from the `blake2` crate, not a local implementation.
pub fn derive_header_key_pbkdf2_blake2s(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let iters = pbkdf2_iterations(PrfId::Blake2s, pim, false);
    pbkdf2_hmac_blake2s(&pwd, salt, iters, &mut out[..HEADER_XTS_KEY_SIZE])
}

/// PBKDF2-HMAC-Whirlpool. The hash is the `whirlpool` crate.
pub fn pbkdf2_hmac_whirlpool(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if out.is_empty() || iterations == 0 {
        return Err(KdfError::Output);
    }
    pbkdf2::<HmacWhirlpool>(password, salt, iterations, out).map_err(|_| KdfError::Pbkdf2)
}

/// VeraCrypt header key via PBKDF2-HMAC-Whirlpool.
pub fn derive_header_key_pbkdf2_whirlpool(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let iters = pbkdf2_iterations(PrfId::Whirlpool, pim, false);
    pbkdf2_hmac_whirlpool(&pwd, salt, iters, &mut out[..HEADER_XTS_KEY_SIZE])
}

/// PBKDF2-HMAC-Streebog-512. The hash is the `streebog` crate.
pub fn pbkdf2_hmac_streebog(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if out.is_empty() || iterations == 0 {
        return Err(KdfError::Output);
    }
    pbkdf2::<HmacStreebog>(password, salt, iterations, out).map_err(|_| KdfError::Pbkdf2)
}

/// VeraCrypt header key via PBKDF2-HMAC-Streebog-512.
pub fn derive_header_key_pbkdf2_streebog(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    pim: i32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let iters = pbkdf2_iterations(PrfId::Streebog, pim, false);
    pbkdf2_hmac_streebog(&pwd, salt, iters, &mut out[..HEADER_XTS_KEY_SIZE])
}

/// DC01 defaults: lower memory for interactive create on constrained CI (still Argon2id).
/// Production mounts should use `derive_header_key_argon2id` with explicit params in header.
pub fn derive_dc01_header_key(
    password: &[u8],
    keyfiles: &[&[u8]],
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() != SALT_SIZE {
        return Err(KdfError::Salt);
    }
    if out.len() < HEADER_XTS_KEY_SIZE {
        return Err(KdfError::Output);
    }
    let pwd = password_with_keyfiles(password, keyfiles);
    let params = Params::new(
        memory_kib,
        time_cost,
        parallelism,
        Some(HEADER_XTS_KEY_SIZE),
    )
    .map_err(|e| KdfError::Argon2Params(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(&pwd, salt, &mut out[..HEADER_XTS_KEY_SIZE])
        .map_err(|_| KdfError::Argon2)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct KdfBench {
    pub label: &'static str,
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
    pub elapsed_ms: u128,
}

/// Time one Argon2id header-key derivation. The derived key is wiped before return.
pub fn bench_argon2id(
    label: &'static str,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<KdfBench, KdfError> {
    let salt = [0xA5u8; SALT_SIZE];
    let mut out = [0u8; HEADER_XTS_KEY_SIZE];
    let started = std::time::Instant::now();
    derive_dc01_header_key(
        b"device-cryptor-bench",
        &[],
        &salt,
        time_cost,
        memory_kib,
        parallelism,
        &mut out,
    )?;
    let elapsed_ms = started.elapsed().as_millis();
    out.zeroize();
    Ok(KdfBench {
        label,
        time_cost,
        memory_kib,
        parallelism,
        elapsed_ms,
    })
}

/// Time VeraCrypt's PIM → Argon2id mapping. PIM 0 means the default PIM 12.
pub fn bench_veracrypt_pim(pim: i32) -> Result<KdfBench, KdfError> {
    let p = argon2_params_for_pim(pim);
    bench_argon2id(
        "veracrypt-argon2id",
        p.time_cost,
        p.memory_kib,
        p.parallelism,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_default_iters() {
        assert_eq!(pbkdf2_iterations(PrfId::Sha512, 0, false), 500_000);
        assert_eq!(pbkdf2_iterations(PrfId::Sha512, 485, false), 500_000);
    }

    #[test]
    fn bench_tiny_argon2_returns_elapsed() {
        let b = bench_argon2id("tiny", 1, 8 * 1024, 1).unwrap();
        assert_eq!(b.time_cost, 1);
        assert_eq!(b.memory_kib, 8 * 1024);
        assert!(b.elapsed_ms < 60_000);
    }

    /// VeraCrypt `Tests.c` PKCS-5 HMAC-BLAKE2s vectors, 5 iterations.
    #[test]
    fn blake2s_matches_veracrypt_pkcs5_vector() {
        let mut short = [0u8; 4];
        pbkdf2_hmac_blake2s(b"password", &[0x12, 0x34, 0x56, 0x78], 5, &mut short).unwrap();
        assert_eq!(short, [0x8d, 0x51, 0xfa, 0x31]);

        let mut long = [0u8; 48];
        pbkdf2_hmac_blake2s(b"password", &[0x12, 0x34, 0x56, 0x78], 5, &mut long).unwrap();
        assert_eq!(
            long,
            [
                0x8d, 0x51, 0xfa, 0x31, 0x46, 0x25, 0x37, 0x67, 0xa3, 0x29, 0x6b, 0x3c, 0x6b, 0xc1,
                0x5d, 0xb2, 0xee, 0xe1, 0x6c, 0x28, 0x00, 0x26, 0xea, 0x08, 0x65, 0x9c, 0x12, 0xf1,
                0x07, 0xde, 0x0d, 0xb9, 0x9b, 0x4f, 0x39, 0xfa, 0xc6, 0x80, 0x26, 0xb1, 0x8f, 0x8e,
                0x48, 0x89, 0x85, 0x2d, 0x24, 0x2d,
            ]
        );
    }

    /// VeraCrypt `Tests.c` PKCS-5 HMAC-Whirlpool vectors, 5 iterations.
    #[test]
    fn whirlpool_matches_veracrypt_pkcs5_vector() {
        let mut short = [0u8; 4];
        pbkdf2_hmac_whirlpool(b"password", &[0x12, 0x34, 0x56, 0x78], 5, &mut short).unwrap();
        assert_eq!(short, [0x50, 0x7c, 0x36, 0x6f]);
    }

    /// VeraCrypt `Tests.c` PKCS-5 HMAC-Streebog vectors, 5 iterations.
    #[test]
    fn streebog_matches_veracrypt_pkcs5_vector() {
        let mut short = [0u8; 4];
        pbkdf2_hmac_streebog(b"password", &[0x12, 0x34, 0x56, 0x78], 5, &mut short).unwrap();
        assert_eq!(short, [0xd0, 0x53, 0xa2, 0x30]);
        let mut long = [0u8; 96];
        pbkdf2_hmac_streebog(b"password", &[0x12, 0x34, 0x56, 0x78], 5, &mut long).unwrap();
        assert_eq!(
            long,
            [
                0xd0, 0x53, 0xa2, 0x30, 0x6f, 0x45, 0x81, 0xeb, 0xbc, 0x06, 0x81, 0xc5, 0xe7, 0x53,
                0xa8, 0x5d, 0xc7, 0xf1, 0x23, 0x33, 0x1e, 0xbe, 0x64, 0x2c, 0x3b, 0x0f, 0x26, 0xd7,
                0x00, 0xe1, 0x95, 0xc9, 0x65, 0x26, 0xb1, 0x85, 0xbe, 0x1e, 0xe2, 0xf4, 0x9b, 0xfc,
                0x6b, 0x14, 0x84, 0xda, 0x24, 0x61, 0xa0, 0x1b, 0x9e, 0x79, 0x5c, 0xee, 0x69, 0x6e,
                0xf9, 0x25, 0xb1, 0x1d, 0xca, 0xa0, 0x31, 0xba, 0x02, 0x6f, 0x9e, 0x99, 0x0f, 0xdb,
                0x25, 0x01, 0x5b, 0xf1, 0xc7, 0x10, 0x19, 0x53, 0x3b, 0x29, 0x3f, 0x18, 0x00, 0xd6,
                0xfc, 0x85, 0x03, 0xdc, 0xf2, 0xe5, 0xe9, 0x5a, 0xb1, 0x1e, 0x61, 0xde,
            ]
        );
    }
}
