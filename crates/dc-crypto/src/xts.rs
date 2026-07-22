use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use thiserror::Error;
use xts_mode::{get_tweak_default, Xts128};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Error)]
pub enum XtsError {
    #[error("invalid key length")]
    Key,
    #[error("buffer length must be a multiple of 16")]
    Alignment,
}

/// AES-256-XTS for volume data and headers.
#[derive(ZeroizeOnDrop)]
pub struct Aes256Xts {
    #[zeroize(skip)]
    cipher: Xts128<Aes256>,
}

impl Aes256Xts {
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.len() != 64 {
            return Err(XtsError::Key);
        }
        let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..64]));
        Ok(Self {
            cipher: Xts128::new(cipher_1, cipher_2),
        })
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        let tweak = get_tweak_default(sector as u128);
        self.cipher.encrypt_sector(buf, tweak);
        Ok(())
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        let tweak = get_tweak_default(sector as u128);
        self.cipher.decrypt_sector(buf, tweak);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fill_random;

    #[test]
    fn roundtrip_sector() {
        let mut key = [0u8; 64];
        fill_random(&mut key).unwrap();
        let xts = Aes256Xts::new(&key).unwrap();
        let mut buf = [0u8; 512];
        fill_random(&mut buf).unwrap();
        let orig = buf;
        xts.encrypt_sector(7, &mut buf).unwrap();
        assert_ne!(buf, orig);
        xts.decrypt_sector(7, &mut buf).unwrap();
        assert_eq!(buf, orig);
    }
}
