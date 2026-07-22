use crate::argon2_params::argon2_params_for_pim;
use crate::{HEADER_XTS_KEY_SIZE, SALT_SIZE};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

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
    Argon2id = 10,
}

/// VeraCrypt PBKDF2 iteration count for non-boot volumes.
pub fn pbkdf2_iterations(prf: PrfId, pim: i32, boot: bool) -> u32 {
    let pim = if pim < 0 { 0 } else { pim };
    match prf {
        PrfId::Sha512 => {
            if pim == 0 {
                500_000
            } else {
                15_000 + (pim as u32) * 1000
            }
        }
        PrfId::Sha256 => {
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
        Some(HEADER_XTS_KEY_SIZE),
    )
    .map_err(|e| KdfError::Argon2Params(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(&pwd, salt, &mut out[..HEADER_XTS_KEY_SIZE])
        .map_err(|_| KdfError::Argon2)?;
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
    pbkdf2::<HmacSha512>(&pwd, salt, iters, &mut out[..HEADER_XTS_KEY_SIZE])
        .map_err(|_| KdfError::Pbkdf2)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_default_iters() {
        assert_eq!(pbkdf2_iterations(PrfId::Sha512, 0, false), 500_000);
        assert_eq!(pbkdf2_iterations(PrfId::Sha512, 485, false), 500_000);
    }
}
