//! ML-KEM-768 key wrap for optional master-key export (DeviceCryptor-only).

use ::kem::{Decapsulate, Encapsulate};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::Aes256Xts;

#[derive(Debug, Error)]
pub enum KeyWrapError {
    #[error("kem failure")]
    Kem,
    #[error("invalid ciphertext")]
    Ciphertext,
    #[error("payload too large or misaligned")]
    Payload,
    #[error("aes-xts: {0}")]
    Xts(#[from] crate::XtsError),
}

#[derive(Clone)]
pub struct WrappedKey {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Encapsulate to an ML-KEM-768 public key and seal `plaintext` with derived AES-256-XTS.
pub fn mlkem_encapsulate_key(
    recipient_ek_bytes: &[u8],
    plaintext: &[u8],
) -> Result<WrappedKey, KeyWrapError> {
    if plaintext.is_empty() || plaintext.len() > 4096 || plaintext.len() % 16 != 0 {
        return Err(KeyWrapError::Payload);
    }
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let ek_arr = Array::try_from(recipient_ek_bytes).map_err(|_| KeyWrapError::Kem)?;
    let ek = Ek::from_bytes(&ek_arr);
    let (ek_ct, shared) = ek.encapsulate(&mut OsRng).map_err(|_| KeyWrapError::Kem)?;
    let hk = Hkdf::<Sha256>::new(None, shared.as_slice());
    let mut xts_key = Zeroizing::new([0u8; 64]);
    hk.expand(b"DeviceCryptor/ML-KEM-wrap/v1", xts_key.as_mut())
        .map_err(|_| KeyWrapError::Kem)?;
    let xts = Aes256Xts::new(xts_key.as_ref())?;
    let mut ct = plaintext.to_vec();
    xts.encrypt_sector(0, &mut ct)?;
    Ok(WrappedKey {
        encapsulated_key: ek_ct.as_slice().to_vec(),
        ciphertext: ct,
    })
}

pub fn mlkem_decapsulate_key(
    dk_bytes: &[u8],
    wrapped: &WrappedKey,
) -> Result<Zeroizing<Vec<u8>>, KeyWrapError> {
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    let dk_arr = Array::try_from(dk_bytes).map_err(|_| KeyWrapError::Kem)?;
    let dk = Dk::from_bytes(&dk_arr);
    let ek_ct = Array::try_from(wrapped.encapsulated_key.as_slice())
        .map_err(|_| KeyWrapError::Ciphertext)?;
    let shared = dk.decapsulate(&ek_ct).map_err(|_| KeyWrapError::Kem)?;
    let hk = Hkdf::<Sha256>::new(None, shared.as_slice());
    let mut xts_key = Zeroizing::new([0u8; 64]);
    hk.expand(b"DeviceCryptor/ML-KEM-wrap/v1", xts_key.as_mut())
        .map_err(|_| KeyWrapError::Kem)?;
    let xts = Aes256Xts::new(xts_key.as_ref())?;
    let mut pt = wrapped.ciphertext.clone();
    if pt.is_empty() || pt.len() % 16 != 0 {
        return Err(KeyWrapError::Ciphertext);
    }
    xts.decrypt_sector(0, &mut pt)?;
    Ok(Zeroizing::new(pt))
}

/// Generate an ML-KEM-768 keypair; returns (encapsulation_key, decapsulation_key) bytes.
pub fn mlkem_generate_keypair() -> Result<(Vec<u8>, Vec<u8>), KeyWrapError> {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    Ok((
        ek.as_bytes().as_slice().to_vec(),
        dk.as_bytes().as_slice().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip() {
        let (ek, dk) = mlkem_generate_keypair().unwrap();
        let msg = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let wrapped = mlkem_encapsulate_key(&ek, msg).unwrap();
        let out = mlkem_decapsulate_key(&dk, &wrapped).unwrap();
        assert_eq!(&out[..], msg);
    }
}
