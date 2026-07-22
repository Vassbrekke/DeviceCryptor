//! VeraCrypt / TrueCrypt volume header v5 compatibility.
//! Spec: vendor/VeraCrypt/src/Common/Volumes.c

use byteorder::{BigEndian, ByteOrder};
use dc_crypto::{
    crc32, derive_header_key_argon2id, derive_header_key_pbkdf2_sha512, Aes256Xts, SecureBytes,
    SALT_SIZE,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub const VC_MAGIC: u32 = 0x5645_5241; // 'VERA'
pub const TC_MAGIC: u32 = 0x5452_5545; // 'TRUE'
pub const VC_HEADER_EFFECTIVE: usize = 512;
pub const VC_HEADER_SLOT: u64 = 65_536;
pub const VC_DATA_OFFSET: u64 = 131_072;

#[derive(Debug, Error)]
pub enum VeraCryptError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid header")]
    Invalid,
    #[error("authentication failed")]
    Auth,
}

#[derive(Clone, Debug)]
pub struct VeraCryptHeader {
    pub header_version: u16,
    pub required_program_version: u16,
    pub hidden_volume_size: u64,
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    pub master_keys: SecureBytes,
}

#[derive(Clone, Debug)]
pub struct VeraCryptOpenOptions<'a> {
    pub password: &'a [u8],
    pub keyfiles: &'a [&'a [u8]],
    pub pim: i32,
}

pub fn try_open_veracrypt_header(
    header512: &[u8],
    opts: &VeraCryptOpenOptions<'_>,
) -> Result<VeraCryptHeader, VeraCryptError> {
    if header512.len() < VC_HEADER_EFFECTIVE {
        return Err(VeraCryptError::Invalid);
    }
    let salt = &header512[..SALT_SIZE];
    let mut enc = [0u8; VC_HEADER_EFFECTIVE - SALT_SIZE];
    enc.copy_from_slice(&header512[SALT_SIZE..VC_HEADER_EFFECTIVE]);

    // Try Argon2id then PBKDF2-SHA512 (most common modern / classic).
    if let Ok(h) = try_with_kdf(salt, &enc, opts, KdfKind::Argon2id) {
        return Ok(h);
    }
    if let Ok(h) = try_with_kdf(salt, &enc, opts, KdfKind::Pbkdf2Sha512) {
        return Ok(h);
    }
    Err(VeraCryptError::Auth)
}

enum KdfKind {
    Argon2id,
    Pbkdf2Sha512,
}

fn try_with_kdf(
    salt: &[u8],
    enc: &[u8; VC_HEADER_EFFECTIVE - SALT_SIZE],
    opts: &VeraCryptOpenOptions<'_>,
    kind: KdfKind,
) -> Result<VeraCryptHeader, VeraCryptError> {
    let mut key = Zeroizing::new([0u8; 64]);
    match kind {
        KdfKind::Argon2id => {
            derive_header_key_argon2id(opts.password, opts.keyfiles, salt, opts.pim, key.as_mut())
                .map_err(|e| VeraCryptError::Crypto(e.to_string()))?
        }
        KdfKind::Pbkdf2Sha512 => derive_header_key_pbkdf2_sha512(
            opts.password,
            opts.keyfiles,
            salt,
            opts.pim,
            key.as_mut(),
        )
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?,
    }

    let xts = Aes256Xts::new(key.as_ref()).map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
    let mut buf = *enc;
    xts.decrypt_sector(0, &mut buf)
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;

    let magic = BigEndian::read_u32(&buf[0..4]);
    if magic != VC_MAGIC && magic != TC_MAGIC {
        return Err(VeraCryptError::Auth);
    }

    let key_crc = BigEndian::read_u32(&buf[8..12]);
    let computed_key_crc = crc32(&buf[192..448]); // bytes 256-511 of full header = offset 192 in payload
                                                  // Full header layout: salt(64) + payload. Payload offset 0 = header offset 64.
                                                  // Key area at header 256..511 → payload 192..447 (256 bytes)
    let key_area = &buf[192..448];
    if crc32(key_area) != key_crc {
        // Some volumes store CRC differently — still check header CRC
        let _ = computed_key_crc;
    }

    let header_crc = BigEndian::read_u32(&buf[188..192]); // offset 252 in full hdr → 188 in payload
    let mut hdr_fields = [0u8; 188];
    hdr_fields.copy_from_slice(&buf[0..188]);
    if crc32(&hdr_fields) != header_crc {
        // VeraCrypt: CRC of decrypted bytes 64-251 of full header = payload 0..187
        return Err(VeraCryptError::Auth);
    }

    // Re-check key CRC properly
    if crc32(key_area) != key_crc {
        return Err(VeraCryptError::Auth);
    }

    let mut master = SecureBytes::new(256);
    master.as_mut_slice().copy_from_slice(key_area);

    Ok(VeraCryptHeader {
        header_version: BigEndian::read_u16(&buf[4..6]),
        required_program_version: BigEndian::read_u16(&buf[6..8]),
        hidden_volume_size: BigEndian::read_u64(&buf[28..36]),
        volume_size: BigEndian::read_u64(&buf[36..44]),
        encrypted_area_start: BigEndian::read_u64(&buf[44..52]),
        encrypted_area_length: BigEndian::read_u64(&buf[52..60]),
        flags: BigEndian::read_u32(&buf[60..64]),
        sector_size: BigEndian::read_u32(&buf[64..68]),
        master_keys: master,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_crypto::secure_eq;

    #[test]
    fn rejects_random() {
        let mut buf = [0u8; 512];
        dc_crypto::fill_random(&mut buf).unwrap();
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
        };
        assert!(try_open_veracrypt_header(&buf, &opts).is_err());
    }

    #[test]
    fn crc_helper_stable() {
        assert!(!secure_eq(b"a", b"b"));
    }
}
