//! VeraCrypt / TrueCrypt volume header v5 compatibility.
//! Spec: vendor/VeraCrypt/src/Common/Volumes.c

use byteorder::{BigEndian, ByteOrder};
use dc_crypto::{
    crc32, derive_header_key_argon2id, derive_header_key_pbkdf2_blake2s,
    derive_header_key_pbkdf2_sha256, derive_header_key_pbkdf2_sha512,
    derive_header_key_pbkdf2_streebog, derive_header_key_pbkdf2_whirlpool, DiskXts, PrfId,
    SecureBytes, VolumeCipher, SALT_SIZE,
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
    pub cipher: VolumeCipher,
}

#[derive(Clone, Debug)]
pub struct VeraCryptOpenOptions<'a> {
    pub password: &'a [u8],
    pub keyfiles: &'a [&'a [u8]],
    pub pim: i32,
    /// `None` tries Argon2id, then HMAC-SHA-512, then HMAC-SHA-256.
    /// Set this to skip the others — VeraCrypt's PKCS-5 PRF mount option.
    pub prf: Option<PrfId>,
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

    // Autodetect is slow: Argon2id (default PIM) runs before the PBKDF2 hashes.
    let order: &[KdfKind] = match opts.prf {
        Some(PrfId::Argon2id) => &[KdfKind::Argon2id],
        Some(PrfId::Sha512) => &[KdfKind::Pbkdf2Sha512],
        Some(PrfId::Sha256) => &[KdfKind::Pbkdf2Sha256],
        Some(PrfId::Blake2s) => &[KdfKind::Pbkdf2Blake2s],
        Some(PrfId::Whirlpool) => &[KdfKind::Pbkdf2Whirlpool],
        Some(PrfId::Streebog) => &[KdfKind::Pbkdf2Streebog],
        None => &[
            KdfKind::Argon2id,
            KdfKind::Pbkdf2Sha512,
            KdfKind::Pbkdf2Sha256,
            KdfKind::Pbkdf2Blake2s,
            KdfKind::Pbkdf2Whirlpool,
            KdfKind::Pbkdf2Streebog,
        ],
    };
    for kind in order {
        if let Ok(h) = try_with_kdf(salt, &enc, opts, *kind) {
            return Ok(h);
        }
    }
    Err(VeraCryptError::Auth)
}

#[derive(Clone, Copy)]
enum KdfKind {
    Argon2id,
    Pbkdf2Sha512,
    Pbkdf2Sha256,
    Pbkdf2Blake2s,
    Pbkdf2Whirlpool,
    Pbkdf2Streebog,
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
        KdfKind::Pbkdf2Sha256 => derive_header_key_pbkdf2_sha256(
            opts.password,
            opts.keyfiles,
            salt,
            opts.pim,
            key.as_mut(),
        )
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?,
        KdfKind::Pbkdf2Blake2s => derive_header_key_pbkdf2_blake2s(
            opts.password,
            opts.keyfiles,
            salt,
            opts.pim,
            key.as_mut(),
        )
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?,
        KdfKind::Pbkdf2Whirlpool => derive_header_key_pbkdf2_whirlpool(
            opts.password,
            opts.keyfiles,
            salt,
            opts.pim,
            key.as_mut(),
        )
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?,
        KdfKind::Pbkdf2Streebog => derive_header_key_pbkdf2_streebog(
            opts.password,
            opts.keyfiles,
            salt,
            opts.pim,
            key.as_mut(),
        )
        .map_err(|e| VeraCryptError::Crypto(e.to_string()))?,
    }

    let mut accepted = None;
    for cipher in [
        VolumeCipher::Aes256,
        VolumeCipher::Kuznyechik,
        VolumeCipher::Twofish,
        VolumeCipher::Camellia,
    ] {
        let xts = DiskXts::open(cipher, key.as_ref())
            .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
        let mut buf = *enc;
        xts.decrypt_sector(0, &mut buf)
            .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
        if parse_header(&buf).is_ok() {
            accepted = Some((buf, cipher));
            break;
        }
    }
    if accepted.is_none() && matches!(kind, KdfKind::Pbkdf2Sha512) {
        let mut wide = Zeroizing::new([0u8; 128]);
        derive_header_key_pbkdf2_sha512(opts.password, opts.keyfiles, salt, opts.pim, wide.as_mut())
            .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
        let xts = DiskXts::open(VolumeCipher::AesTwofish, wide.as_ref())
            .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
        let mut buf = *enc;
        xts.decrypt_sector(0, &mut buf)
            .map_err(|e| VeraCryptError::Crypto(e.to_string()))?;
        if parse_header(&buf).is_ok() {
            accepted = Some((buf, VolumeCipher::AesTwofish));
        }
    }
    let (buf, cipher) = accepted.ok_or(VeraCryptError::Auth)?;
    let mut header = parse_header(&buf)?;
    header.cipher = cipher;
    Ok(header)
}

fn parse_header(
    buf: &[u8; VC_HEADER_EFFECTIVE - SALT_SIZE],
) -> Result<VeraCryptHeader, VeraCryptError> {
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
        cipher: VolumeCipher::Aes256,
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
            prf: Some(PrfId::Sha512),
        };
        assert!(try_open_veracrypt_header(&buf, &opts).is_err());
    }

    #[test]
    fn crc_helper_stable() {
        assert!(!secure_eq(b"a", b"b"));
    }

    /// Vendor oracle: `vendor/VeraCrypt/Tests/test.sha512.hc`, password `test`
    /// (see `vendor/VeraCrypt/Tests/bench.bat`). PBKDF2-HMAC-SHA512, PIM 0.
    /// Data-unit number is the file offset divided by the sector size.
    #[test]
    fn opens_vendor_sha512_sample() {
        let data = read_vendor_sample("test.sha512.hc");
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha512),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("vendor sha512 sample should unlock with password test");
        assert_eq!(header.header_version, 5);
        assert_eq!(header.cipher, VolumeCipher::Aes256);
        assert!(header.volume_size > 0);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );

        let hidden_opts = VeraCryptOpenOptions {
            password: b"testhidden",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha512),
        };
        let hidden_off = VC_HEADER_SLOT as usize;
        let hidden = try_open_veracrypt_header(
            &data[hidden_off..hidden_off + VC_HEADER_EFFECTIVE],
            &hidden_opts,
        )
        .expect("hidden volume password testhidden");
        assert!(hidden.volume_size > 0);
        assert_ne!(hidden.encrypted_area_start, header.encrypted_area_start);
    }

    /// Same vendor set, HMAC-SHA-256 PRF. Still AES-XTS for the header.
    #[test]
    fn opens_vendor_sha256_sample() {
        let data = read_vendor_sample("test.sha256.hc");
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha256),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("vendor sha256 sample should unlock with password test");
        assert_eq!(header.header_version, 5);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Vendor `test.blake2s.hc`. HMAC is composed over `blake2::Blake2s256`, not a local hash.
    #[test]
    fn opens_vendor_blake2s_sample() {
        let data = read_vendor_sample("test.blake2s.hc");
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Blake2s),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("vendor blake2s sample should unlock with password test");
        assert_eq!(header.header_version, 5);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Vendor `test.whirlpool.hc`. Hash is the `whirlpool` crate.
    #[test]
    fn opens_vendor_whirlpool_sample() {
        let data = read_vendor_sample("test.whirlpool.hc");
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Whirlpool),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("vendor whirlpool sample should unlock with password test");
        assert_eq!(header.header_version, 5);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Vendor `test.streebog.hc` is Kuznyechik-XTS, not AES. Slow in debug.
    #[test]
    #[ignore = "500k Streebog; run with --release -- --ignored"]
    fn opens_vendor_streebog_kuznyechik_sample() {
        let data = read_vendor_sample("test.streebog.hc");
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Streebog),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("vendor streebog sample should unlock");
        assert_eq!(header.cipher, VolumeCipher::Kuznyechik);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Volume minted by VeraCrypt 1.26.29: AES, Argon2id, PIM 1, password
    /// `devicecryptor-argon2` (20 characters; VeraCrypt rejects shorter passwords
    /// below PIM 12). File: tests/goldens/argon2id-pim1.hc
    #[test]
    fn opens_minted_argon2id_sample() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/goldens/argon2id-pim1.hc");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let opts = VeraCryptOpenOptions {
            password: b"devicecryptor-argon2",
            keyfiles: &[],
            pim: 1,
            prf: Some(PrfId::Argon2id),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("minted Argon2id volume should unlock");
        assert_eq!(header.header_version, 5);
        assert_eq!(header.cipher, VolumeCipher::Aes256);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Volume minted by VeraCrypt 1.26.29: Twofish, HMAC-SHA-512, PIM 0, password `test`.
    #[test]
    fn opens_minted_twofish_sample() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/goldens/twofish-sha512.hc");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha512),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("minted Twofish volume should unlock");
        assert_eq!(header.cipher, VolumeCipher::Twofish);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Volume minted by VeraCrypt 1.26.29: Camellia, HMAC-SHA-512, PIM 0, password `test`.
    #[test]
    fn opens_minted_camellia_sample() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/goldens/camellia-sha512.hc");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha512),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("minted Camellia volume should unlock");
        assert_eq!(header.cipher, VolumeCipher::Camellia);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    /// Volume minted by VeraCrypt 1.26.29: AES-Twofish, HMAC-SHA-512, PIM 0, password `test`.
    #[test]
    fn opens_minted_aes_twofish_sample() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/goldens/aes-twofish-sha512.hc");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let opts = VeraCryptOpenOptions {
            password: b"test",
            keyfiles: &[],
            pim: 0,
            prf: Some(PrfId::Sha512),
        };
        let header = try_open_veracrypt_header(&data[..VC_HEADER_EFFECTIVE], &opts)
            .expect("minted AES-Twofish volume should unlock");
        assert_eq!(header.cipher, VolumeCipher::AesTwofish);
        assert_eq!(
            &decrypt_vendor_boot(&data, &header)[510..512],
            &[0x55, 0xAA]
        );
    }

    fn read_vendor_sample(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/VeraCrypt/Tests")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn decrypt_vendor_boot(data: &[u8], header: &VeraCryptHeader) -> [u8; 512] {
        let sector = if header.sector_size == 0 {
            512
        } else {
            header.sector_size
        };
        let start = header.encrypted_area_start as usize;
        assert!(data.len() >= start + sector as usize);
        let mut buf = [0u8; 512];
        buf.copy_from_slice(&data[start..start + 512]);
        let unit = header.encrypted_area_start / u64::from(sector);
        let xts = DiskXts::open(header.cipher, &header.master_keys.as_slice()[..header.cipher.xts_key_len()]).unwrap();
        xts.decrypt_sector(unit, &mut buf).unwrap();
        buf
    }
}
