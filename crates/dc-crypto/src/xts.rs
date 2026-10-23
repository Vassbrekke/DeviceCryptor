use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use kuznyechik::Kuznyechik;
use thiserror::Error;
use twofish::Twofish;
use camellia::Camellia256;
use xts_mode::{get_tweak_default, Xts128};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeCipher {
    Aes256,
    Kuznyechik,
    Twofish,
    Camellia,
    /// VeraCrypt AES-Twofish. Encrypt order is Twofish, then AES.
    AesTwofish,
}

impl VolumeCipher {
    pub fn label(self) -> &'static str {
        match self {
            Self::Aes256 => "AES-256-XTS",
            Self::Kuznyechik => "Kuznyechik-XTS",
            Self::Twofish => "Twofish-XTS",
            Self::Camellia => "Camellia-256-XTS",
            Self::AesTwofish => "AES-Twofish-XTS",
        }
    }

    /// Bytes of XTS key material this cipher reads from a derived or master key.
    pub fn xts_key_len(self) -> usize {
        match self {
            Self::AesTwofish => 128,
            _ => 64,
        }
    }
}

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

/// Kuznyechik-XTS. The block cipher is the `kuznyechik` crate.
#[derive(ZeroizeOnDrop)]
pub struct KuznyechikXts {
    #[zeroize(skip)]
    cipher: Xts128<Kuznyechik>,
}

impl KuznyechikXts {
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.len() != 64 {
            return Err(XtsError::Key);
        }
        let cipher_1 = Kuznyechik::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Kuznyechik::new(GenericArray::from_slice(&key[32..64]));
        Ok(Self {
            cipher: Xts128::new(cipher_1, cipher_2),
        })
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .encrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .decrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }
}

/// Twofish-XTS. The block cipher is the `twofish` crate.
#[derive(ZeroizeOnDrop)]
pub struct TwofishXts {
    #[zeroize(skip)]
    cipher: Xts128<Twofish>,
}

impl TwofishXts {
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.len() != 64 {
            return Err(XtsError::Key);
        }
        let cipher_1 = Twofish::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Twofish::new(GenericArray::from_slice(&key[32..64]));
        Ok(Self {
            cipher: Xts128::new(cipher_1, cipher_2),
        })
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .encrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .decrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }
}

/// Camellia-256-XTS. The block cipher is `Camellia256` from the `camellia` crate.
#[derive(ZeroizeOnDrop)]
pub struct CamelliaXts {
    #[zeroize(skip)]
    cipher: Xts128<Camellia256>,
}

impl CamelliaXts {
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.len() != 64 {
            return Err(XtsError::Key);
        }
        let cipher_1 = Camellia256::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Camellia256::new(GenericArray::from_slice(&key[32..64]));
        Ok(Self {
            cipher: Xts128::new(cipher_1, cipher_2),
        })
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .encrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() % 16 != 0 || buf.is_empty() {
            return Err(XtsError::Alignment);
        }
        self.cipher
            .decrypt_sector(buf, get_tweak_default(sector as u128));
        Ok(())
    }
}

/// VeraCrypt AES-Twofish cascade.
/// Key layout: Twofish primary, AES primary, Twofish tweak, AES tweak (32 bytes each).
/// Encrypt applies Twofish-XTS, then AES-XTS. Decrypt is the reverse.
#[derive(ZeroizeOnDrop)]
pub struct AesTwofishXts {
    #[zeroize(skip)]
    twofish: TwofishXts,
    #[zeroize(skip)]
    aes: Aes256Xts,
}

impl AesTwofishXts {
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.len() < 128 {
            return Err(XtsError::Key);
        }
        let mut twofish_key = [0u8; 64];
        twofish_key[..32].copy_from_slice(&key[..32]);
        twofish_key[32..].copy_from_slice(&key[64..96]);
        let mut aes_key = [0u8; 64];
        aes_key[..32].copy_from_slice(&key[32..64]);
        aes_key[32..].copy_from_slice(&key[96..128]);
        let out = Self {
            twofish: TwofishXts::new(&twofish_key)?,
            aes: Aes256Xts::new(&aes_key)?,
        };
        twofish_key.zeroize();
        aes_key.zeroize();
        Ok(out)
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        self.twofish.encrypt_sector(sector, buf)?;
        self.aes.encrypt_sector(sector, buf)
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        self.aes.decrypt_sector(sector, buf)?;
        self.twofish.decrypt_sector(sector, buf)
    }
}

/// Disk cipher selected after the header decrypts.
/// The boxed ciphers zeroize themselves on drop.
pub enum DiskXts {
    Aes(Box<Aes256Xts>),
    Kuznyechik(Box<KuznyechikXts>),
    Twofish(Box<TwofishXts>),
    Camellia(Box<CamelliaXts>),
    AesTwofish(Box<AesTwofishXts>),
}

impl DiskXts {
    pub fn open(cipher: VolumeCipher, key: &[u8]) -> Result<Self, XtsError> {
        match cipher {
            VolumeCipher::Aes256 => Ok(Self::Aes(Box::new(Aes256Xts::new(key)?))),
            VolumeCipher::Kuznyechik => Ok(Self::Kuznyechik(Box::new(KuznyechikXts::new(key)?))),
            VolumeCipher::Twofish => Ok(Self::Twofish(Box::new(TwofishXts::new(key)?))),
            VolumeCipher::Camellia => Ok(Self::Camellia(Box::new(CamelliaXts::new(key)?))),
            VolumeCipher::AesTwofish => Ok(Self::AesTwofish(Box::new(AesTwofishXts::new(key)?))),
        }
    }

    pub fn encrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        match self {
            Self::Aes(c) => c.encrypt_sector(sector, buf),
            Self::Kuznyechik(c) => c.encrypt_sector(sector, buf),
            Self::Twofish(c) => c.encrypt_sector(sector, buf),
            Self::Camellia(c) => c.encrypt_sector(sector, buf),
            Self::AesTwofish(c) => c.encrypt_sector(sector, buf),
        }
    }

    pub fn decrypt_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), XtsError> {
        match self {
            Self::Aes(c) => c.decrypt_sector(sector, buf),
            Self::Kuznyechik(c) => c.decrypt_sector(sector, buf),
            Self::Twofish(c) => c.decrypt_sector(sector, buf),
            Self::Camellia(c) => c.decrypt_sector(sector, buf),
            Self::AesTwofish(c) => c.decrypt_sector(sector, buf),
        }
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

    #[test]
    fn random_sectors_roundtrip() {
        let mut key = [0u8; 64];
        fill_random(&mut key).unwrap();
        let xts = Aes256Xts::new(&key).unwrap();
        for sector in [0u64, 1, 7, 0x1_0000] {
            for len in [16usize, 32, 512] {
                let mut buf = vec![0u8; len];
                fill_random(&mut buf).unwrap();
                let orig = buf.clone();
                xts.encrypt_sector(sector, &mut buf).unwrap();
                assert_ne!(buf, orig);
                xts.decrypt_sector(sector, &mut buf).unwrap();
                assert_eq!(buf, orig);
            }
        }
        assert!(xts.encrypt_sector(0, &mut [0u8; 15]).is_err());
        assert!(xts.decrypt_sector(0, &mut []).is_err());
    }

    #[test]
    fn cipher_labels() {
        assert_eq!(VolumeCipher::Aes256.label(), "AES-256-XTS");
        assert_eq!(VolumeCipher::Kuznyechik.label(), "Kuznyechik-XTS");
        assert_eq!(VolumeCipher::Twofish.label(), "Twofish-XTS");
        assert_eq!(VolumeCipher::Camellia.label(), "Camellia-256-XTS");
        assert_eq!(VolumeCipher::AesTwofish.label(), "AES-Twofish-XTS");
    }

    /// AES-256-XTS sector 0 against Python `cryptography` 50.0.1.
    /// Key is bytes 0..63. Tweak is 16 zero bytes. Plaintext is 32 bytes.
    #[test]
    fn aes256_xts_matches_cryptography_sector0() {
        let key: Vec<u8> = (0u8..64).collect();
        let xts = Aes256Xts::new(&key).unwrap();
        let mut buf = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9".to_vec();
        xts.encrypt_sector(0, &mut buf).unwrap();
        assert_eq!(
            buf,
            hex_bytes("da31736e73e34eb6ca5fa00391e69c9b3facd5c3e2c42d55e4e1946b3ebcd1b3")
        );
    }

    /// GOST R 34.12-2015 / RFC 7801 Kuznyechik block vector.
    #[test]
    fn kuznyechik_matches_gost_vector() {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        let key = hex_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let plain = hex_bytes("1122334455667700ffeeddccbbaa9988");
        let cipher = kuznyechik::Kuznyechik::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block.as_slice(),
            &hex_bytes("7f679d90bebc24305a468d42b9d4edcd")[..]
        );
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
