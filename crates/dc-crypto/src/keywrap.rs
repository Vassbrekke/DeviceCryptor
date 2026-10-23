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

    /// NIST ACVP ML-KEM-768 keyGen FIPS203, tcId 26 (commit 65370b8).
    #[test]
    fn mlkem768_keygen_matches_nist_acvp() {
        use ml_kem::B32;
        use sha2::{Digest, Sha256};

        let d = B32::from(hex32("E34A701C4C87582F42264EE422D3C684D97611F2523EFE0C998AF05056D693DC"));
        let z = B32::from(hex32("A85768F3486BD32A01BF9A8F21EA938E648EAE4E5448C34C3EB88820B159EEDD"));
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        assert_eq!(
            hex::encode(Sha256::digest(ek.as_bytes())),
            "7799c9d8eef172aa78c073514f2f039c240de8c5cb61bca82ba0bc46041ce279"
        );
        assert_eq!(
            hex::encode(Sha256::digest(dk.as_bytes())),
            "104b3444c3de2b81143788d27e17648f45c80f617f906156db2258da96dead40"
        );
    }

    /// NIST ACVP ML-KEM-768 encapsulation, FIPS203 tcId 26.
    #[test]
    fn mlkem768_encap_matches_nist_acvp() {
        use ::kem::Decapsulate;
        use ml_kem::{B32, EncapsulateDeterministic};

        let case: serde_json::Value =
            serde_json::from_str(include_str!("../tests/mlkem768-acvp-encap.json")).unwrap();
        let ek_bytes = hex::decode(case["ek"].as_str().unwrap()).unwrap();
        let dk_bytes = hex::decode(case["dk"].as_str().unwrap()).unwrap();
        let m_bytes = hex::decode(case["m"].as_str().unwrap()).unwrap();
        let c_bytes = hex::decode(case["c"].as_str().unwrap()).unwrap();
        let k_bytes = hex::decode(case["k"].as_str().unwrap()).unwrap();

        type Ek = <MlKem768 as KemCore>::EncapsulationKey;
        type Dk = <MlKem768 as KemCore>::DecapsulationKey;
        let ek = Ek::from_bytes(&ml_kem::array::Array::try_from(ek_bytes.as_slice()).unwrap());
        let dk = Dk::from_bytes(&ml_kem::array::Array::try_from(dk_bytes.as_slice()).unwrap());
        let m_arr: [u8; 32] = m_bytes.as_slice().try_into().unwrap();
        let m = B32::from(m_arr);
        let (ct, shared) = ek.encapsulate_deterministic(&m).unwrap();
        assert_eq!(ct.as_slice(), c_bytes.as_slice());
        assert_eq!(shared.as_slice(), k_bytes.as_slice());
        let opened = dk.decapsulate(&ct).unwrap();
        assert_eq!(opened.as_slice(), k_bytes.as_slice());
    }

    fn hex32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        bytes.try_into().unwrap()
    }
}
