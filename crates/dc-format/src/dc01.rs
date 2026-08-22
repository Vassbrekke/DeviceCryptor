use blake3::Hasher;
use byteorder::{ByteOrder, LittleEndian};
use dc_crypto::{
    derive_dc01_header_key, fill_random, secure_eq, Aes256Xts, SecureBytes, SALT_SIZE,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub const DC01_MAGIC: u32 = 0x4443_3031; // 'DC01' big-endian ascii as u32 BE
pub const DC01_VERSION: u16 = 1;
pub const DC01_EFFECTIVE: usize = 512;

#[derive(Debug, Error)]
pub enum Dc01Error {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid header")]
    Invalid,
    #[error("wrong password or corrupted header")]
    Auth,
}

#[derive(Clone, Debug)]
pub struct Dc01Header {
    pub cipher_id: u16,
    pub kdf_id: u16,
    pub flags: u16,
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
    pub sector_size: u32,
    pub volume_data_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub hidden_volume_size: u64,
    pub master_key: SecureBytes,
}

#[derive(Clone, Debug)]
pub struct Dc01OpenOptions<'a> {
    pub password: &'a [u8],
    pub keyfiles: &'a [&'a [u8]],
}

/// Default interactive Argon2id params for new DC01 volumes (documented; stored in header).
pub const DC01_DEFAULT_TIME: u32 = 3;
pub const DC01_DEFAULT_MEM_KIB: u32 = 64 * 1024; // 64 MiB
pub const DC01_DEFAULT_PARALLELISM: u32 = 4;

pub fn create_dc01_header(
    opts: &Dc01OpenOptions<'_>,
    volume_data_size: u64,
    sector_size: u32,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<(Vec<u8>, SecureBytes), Dc01Error> {
    create_dc01_header_at(
        opts,
        volume_data_size,
        crate::DATA_OFFSET,
        volume_data_size,
        0,
        0,
        sector_size,
        time_cost,
        memory_kib,
        parallelism,
    )
}

/// Create a header with explicit encrypted-area placement (used for hidden volumes).
#[allow(clippy::too_many_arguments)]
pub fn create_dc01_header_at(
    opts: &Dc01OpenOptions<'_>,
    volume_data_size: u64,
    encrypted_area_start: u64,
    encrypted_area_length: u64,
    hidden_volume_size: u64,
    flags: u16,
    sector_size: u32,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<(Vec<u8>, SecureBytes), Dc01Error> {
    let mut salt = [0u8; SALT_SIZE];
    fill_random(&mut salt).map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let mut master = SecureBytes::new(64);
    fill_random(master.as_mut_slice()).map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let mut payload = [0u8; DC01_EFFECTIVE - SALT_SIZE];
    payload[0..4].copy_from_slice(b"DC01");
    LittleEndian::write_u16(&mut payload[4..6], DC01_VERSION);
    LittleEndian::write_u16(&mut payload[6..8], 1); // AES-256-XTS
    LittleEndian::write_u16(&mut payload[8..10], 1); // Argon2id
    LittleEndian::write_u16(&mut payload[10..12], flags);
    LittleEndian::write_u32(&mut payload[12..16], time_cost);
    LittleEndian::write_u32(&mut payload[16..20], memory_kib);
    LittleEndian::write_u32(&mut payload[20..24], parallelism);
    LittleEndian::write_u32(&mut payload[24..28], sector_size);
    LittleEndian::write_u64(&mut payload[28..36], volume_data_size);
    LittleEndian::write_u64(&mut payload[36..44], encrypted_area_start);
    LittleEndian::write_u64(&mut payload[44..52], encrypted_area_length);
    LittleEndian::write_u64(&mut payload[52..60], hidden_volume_size);

    // MAC placeholder then master keys
    payload[64..96].fill(0);
    payload[96..160].copy_from_slice(master.as_slice());

    let mac = {
        let mut h = Hasher::new();
        h.update(&payload[0..64]);
        h.update(&[0u8; 32]); // mac region zeroed in MAC input
        h.update(&payload[96..]);
        h.finalize()
    };
    payload[64..96].copy_from_slice(mac.as_bytes());

    let mut header_key = Zeroizing::new([0u8; 64]);
    derive_dc01_header_key(
        opts.password,
        opts.keyfiles,
        &salt,
        time_cost,
        memory_kib,
        parallelism,
        header_key.as_mut(),
    )
    .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let xts = Aes256Xts::new(header_key.as_ref()).map_err(|e| Dc01Error::Crypto(e.to_string()))?;
    xts.encrypt_sector(0, &mut payload)
        .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let mut header = vec![0u8; DC01_EFFECTIVE];
    header[..SALT_SIZE].copy_from_slice(&salt);
    header[SALT_SIZE..].copy_from_slice(&payload);
    Ok((header, master))
}

/// Re-seal a DC01 header keeping the existing master key (password change / re-key).
///
/// Geometry and Argon2 params are taken from `opened`. A fresh salt is generated.
pub fn seal_dc01_header_with_master(
    opts: &Dc01OpenOptions<'_>,
    opened: &Dc01Header,
) -> Result<Vec<u8>, Dc01Error> {
    if opened.master_key.len() != 64 {
        return Err(Dc01Error::Invalid);
    }
    let mut salt = [0u8; SALT_SIZE];
    fill_random(&mut salt).map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let mut payload = [0u8; DC01_EFFECTIVE - SALT_SIZE];
    payload[0..4].copy_from_slice(b"DC01");
    LittleEndian::write_u16(&mut payload[4..6], DC01_VERSION);
    LittleEndian::write_u16(&mut payload[6..8], opened.cipher_id);
    LittleEndian::write_u16(&mut payload[8..10], opened.kdf_id);
    LittleEndian::write_u16(&mut payload[10..12], opened.flags);
    LittleEndian::write_u32(&mut payload[12..16], opened.time_cost);
    LittleEndian::write_u32(&mut payload[16..20], opened.memory_kib);
    LittleEndian::write_u32(&mut payload[20..24], opened.parallelism);
    LittleEndian::write_u32(&mut payload[24..28], opened.sector_size);
    LittleEndian::write_u64(&mut payload[28..36], opened.volume_data_size);
    LittleEndian::write_u64(&mut payload[36..44], opened.encrypted_area_start);
    LittleEndian::write_u64(&mut payload[44..52], opened.encrypted_area_length);
    LittleEndian::write_u64(&mut payload[52..60], opened.hidden_volume_size);

    payload[64..96].fill(0);
    payload[96..160].copy_from_slice(opened.master_key.as_slice());

    let mac = {
        let mut h = Hasher::new();
        h.update(&payload[0..64]);
        h.update(&[0u8; 32]);
        h.update(&payload[96..]);
        h.finalize()
    };
    payload[64..96].copy_from_slice(mac.as_bytes());

    let mut header_key = Zeroizing::new([0u8; 64]);
    derive_dc01_header_key(
        opts.password,
        opts.keyfiles,
        &salt,
        opened.time_cost,
        opened.memory_kib,
        opened.parallelism,
        header_key.as_mut(),
    )
    .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let xts = Aes256Xts::new(header_key.as_ref()).map_err(|e| Dc01Error::Crypto(e.to_string()))?;
    xts.encrypt_sector(0, &mut payload)
        .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let mut header = vec![0u8; DC01_EFFECTIVE];
    header[..SALT_SIZE].copy_from_slice(&salt);
    header[SALT_SIZE..].copy_from_slice(&payload);
    Ok(header)
}

pub fn open_dc01_header(
    header512: &[u8],
    opts: &Dc01OpenOptions<'_>,
) -> Result<Dc01Header, Dc01Error> {
    if header512.len() < DC01_EFFECTIVE {
        return Err(Dc01Error::Invalid);
    }
    let salt = &header512[..SALT_SIZE];
    let mut payload = [0u8; DC01_EFFECTIVE - SALT_SIZE];
    payload.copy_from_slice(&header512[SALT_SIZE..DC01_EFFECTIVE]);

    // Peek Argon2 params require decrypt — try with params embedded after decrypt.
    // We must derive with candidate params. DC01 stores params inside ciphertext, so
    // try default params first, then common VeraCrypt-mapped defaults.
    let candidates: &[(u32, u32, u32)] = &[
        (
            DC01_DEFAULT_TIME,
            DC01_DEFAULT_MEM_KIB,
            DC01_DEFAULT_PARALLELISM,
        ),
        (3, 64 * 1024, 1),
        (6, 416 * 1024, 1), // VeraCrypt PIM 12
    ];

    for &(time_cost, memory_kib, parallelism) in candidates {
        if let Ok(h) = try_decrypt(salt, &payload, opts, time_cost, memory_kib, parallelism) {
            return Ok(h);
        }
    }
    Err(Dc01Error::Auth)
}

fn try_decrypt(
    salt: &[u8],
    payload_enc: &[u8; DC01_EFFECTIVE - SALT_SIZE],
    opts: &Dc01OpenOptions<'_>,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<Dc01Header, Dc01Error> {
    let mut header_key = Zeroizing::new([0u8; 64]);
    derive_dc01_header_key(
        opts.password,
        opts.keyfiles,
        salt,
        time_cost,
        memory_kib,
        parallelism,
        header_key.as_mut(),
    )
    .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    let xts = Aes256Xts::new(header_key.as_ref()).map_err(|e| Dc01Error::Crypto(e.to_string()))?;
    let mut payload = *payload_enc;
    xts.decrypt_sector(0, &mut payload)
        .map_err(|e| Dc01Error::Crypto(e.to_string()))?;

    if &payload[0..4] != b"DC01" {
        return Err(Dc01Error::Auth);
    }
    let version = LittleEndian::read_u16(&payload[4..6]);
    if version != DC01_VERSION {
        return Err(Dc01Error::Invalid);
    }

    let stored_time = LittleEndian::read_u32(&payload[12..16]);
    let stored_mem = LittleEndian::read_u32(&payload[16..20]);
    let stored_par = LittleEndian::read_u32(&payload[20..24]);
    if stored_time != time_cost || stored_mem != memory_kib || stored_par != parallelism {
        // Wrong candidate params succeeded magic by chance — reject
        return Err(Dc01Error::Auth);
    }

    let mut mac_region = [0u8; 32];
    mac_region.copy_from_slice(&payload[64..96]);
    payload[64..96].fill(0);
    let mut h = Hasher::new();
    h.update(&payload[0..64]);
    h.update(&[0u8; 32]);
    h.update(&payload[96..]);
    let mac = h.finalize();
    if !secure_eq(mac.as_bytes(), &mac_region) {
        return Err(Dc01Error::Auth);
    }

    let mut master = SecureBytes::new(64);
    master.as_mut_slice().copy_from_slice(&payload[96..160]);

    Ok(Dc01Header {
        cipher_id: LittleEndian::read_u16(&payload[6..8]),
        kdf_id: LittleEndian::read_u16(&payload[8..10]),
        flags: LittleEndian::read_u16(&payload[10..12]),
        time_cost: stored_time,
        memory_kib: stored_mem,
        parallelism: stored_par,
        sector_size: LittleEndian::read_u32(&payload[24..28]),
        volume_data_size: LittleEndian::read_u64(&payload[28..36]),
        encrypted_area_start: LittleEndian::read_u64(&payload[36..44]),
        encrypted_area_length: LittleEndian::read_u64(&payload[44..52]),
        hidden_volume_size: LittleEndian::read_u64(&payload[52..60]),
        master_key: master,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_open_roundtrip() {
        let opts = Dc01OpenOptions {
            password: b"correct horse battery staple",
            keyfiles: &[],
        };
        let (hdr, master) = create_dc01_header(
            &opts,
            1024 * 1024,
            512,
            DC01_DEFAULT_TIME,
            DC01_DEFAULT_MEM_KIB,
            DC01_DEFAULT_PARALLELISM,
        )
        .unwrap();
        let opened = open_dc01_header(&hdr, &opts).unwrap();
        assert_eq!(opened.master_key.as_slice(), master.as_slice());
        assert_eq!(opened.volume_data_size, 1024 * 1024);
    }

    #[test]
    fn wrong_password_fails() {
        let opts = Dc01OpenOptions {
            password: b"secret",
            keyfiles: &[],
        };
        let (hdr, _) = create_dc01_header(
            &opts,
            65536,
            512,
            DC01_DEFAULT_TIME,
            DC01_DEFAULT_MEM_KIB,
            DC01_DEFAULT_PARALLELISM,
        )
        .unwrap();
        let bad = Dc01OpenOptions {
            password: b"wrong",
            keyfiles: &[],
        };
        assert!(open_dc01_header(&hdr, &bad).is_err());
    }

    #[test]
    fn seal_with_master_changes_password() {
        let old = Dc01OpenOptions {
            password: b"old-pass-phrase",
            keyfiles: &[],
        };
        let (hdr, master) = create_dc01_header(
            &old,
            1024 * 1024,
            512,
            DC01_DEFAULT_TIME,
            DC01_DEFAULT_MEM_KIB,
            DC01_DEFAULT_PARALLELISM,
        )
        .unwrap();
        let opened = open_dc01_header(&hdr, &old).unwrap();
        assert_eq!(opened.master_key.as_slice(), master.as_slice());

        let new = Dc01OpenOptions {
            password: b"new-pass-phrase",
            keyfiles: &[],
        };
        let resealed = seal_dc01_header_with_master(&new, &opened).unwrap();
        assert!(open_dc01_header(&resealed, &old).is_err());
        let again = open_dc01_header(&resealed, &new).unwrap();
        assert_eq!(again.master_key.as_slice(), master.as_slice());
        assert_eq!(again.volume_data_size, 1024 * 1024);
    }
}
