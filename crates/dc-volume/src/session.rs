use std::fs::{File, OpenOptions as FsOpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use dc_crypto::{fill_random, Aes256Xts, DiskXts, SecureBytes, VolumeCipher};
use dc_format::dc01::{
    create_dc01_header, create_dc01_header_at, open_dc01_header, Dc01OpenOptions,
    DC01_DEFAULT_MEM_KIB, DC01_DEFAULT_PARALLELISM, DC01_DEFAULT_TIME,
};
use dc_format::veracrypt::{try_open_veracrypt_header, VeraCryptOpenOptions};
use dc_format::{DATA_OFFSET, HEADER_SLOT_SIZE, HIDDEN_HEADER_OFFSET};
use zeroize::Zeroize;

use crate::VolumeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeKind {
    Dc01,
    VeraCrypt,
}

#[derive(Clone, Debug)]
pub struct CreateOptions<'a> {
    pub password: &'a [u8],
    pub keyfiles: &'a [&'a [u8]],
    /// Total container size in bytes (including headers).
    pub size: u64,
    pub sector_size: u32,
    pub hidden_size: Option<u64>,
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
    /// Sparse create (fast); still writes headers and randomizes header slots.
    pub sparse: bool,
}

impl Default for CreateOptions<'_> {
    fn default() -> Self {
        Self {
            password: b"",
            keyfiles: &[],
            size: 4 * 1024 * 1024,
            sector_size: 512,
            hidden_size: None,
            time_cost: DC01_DEFAULT_TIME,
            memory_kib: DC01_DEFAULT_MEM_KIB,
            parallelism: DC01_DEFAULT_PARALLELISM,
            sparse: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenOptions<'a> {
    pub password: &'a [u8],
    pub keyfiles: &'a [&'a [u8]],
    pub pim: i32,
    /// VeraCrypt PKCS-5 PRF. `None` tries Argon2id, HMAC-SHA-512, then HMAC-SHA-256.
    pub prf: Option<dc_crypto::PrfId>,
    pub protect_hidden: bool,
    pub hidden_password: Option<&'a [u8]>,
}

pub struct MountedVolume {
    pub path: PathBuf,
    pub kind: VolumeKind,
    pub sector_size: u32,
    pub data_offset: u64,
    pub data_length: u64,
    pub is_hidden: bool,
    /// Outer volume's hidden region size when protect_hidden is active.
    pub hidden_protect_size: u64,
    pub cipher: VolumeCipher,
    /// Password hash that opened this volume. DC01 is always Argon2id.
    pub kdf: &'static str,
    pub(crate) file: File,
    xts: DiskXts,
    #[allow(dead_code)]
    master: SecureBytes,
}

impl MountedVolume {
    pub fn sync(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    /// XTS data-unit number for a sector inside the decrypted data area.
    ///
    /// VeraCrypt uses the host-file sector (`offset / sector_size`). DC01 uses
    /// the sector index within the data area, which is how these volumes are written.
    fn data_unit(&self, data_sector: u64) -> u64 {
        match self.kind {
            VolumeKind::VeraCrypt => {
                self.data_offset / u64::from(self.sector_size.max(1)) + data_sector
            }
            VolumeKind::Dc01 => data_sector,
        }
    }
}

impl Drop for MountedVolume {
    fn drop(&mut self) {
        // Zeroize handled by SecureBytes / Aes256Xts Drop
        let _ = self.file.sync_all();
    }
}

pub fn create_container(path: &Path, opts: &CreateOptions<'_>) -> Result<(), VolumeError> {
    create_container_with_progress(path, opts, &mut |_, _| {})
}

/// Create a container, reporting wipe progress as `(bytes_written, total_size)`.
///
/// Sparse creates report a single `(size, size)` tick. Random wipes report after each chunk.
pub fn create_container_with_progress(
    path: &Path,
    opts: &CreateOptions<'_>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(), VolumeError> {
    if opts.size < DATA_OFFSET + opts.sector_size as u64 + HEADER_SLOT_SIZE * 2 {
        return Err(VolumeError::Invalid("size too small"));
    }
    if opts.password.is_empty() {
        return Err(VolumeError::Invalid("password required"));
    }

    let data_size = opts.size - DATA_OFFSET - HEADER_SLOT_SIZE * 2;
    let dc_opts = Dc01OpenOptions {
        password: opts.password,
        keyfiles: opts.keyfiles,
    };
    let (header, _master) = create_dc01_header(
        &dc_opts,
        data_size,
        opts.sector_size,
        opts.time_cost,
        opts.memory_kib,
        opts.parallelism,
    )
    .map_err(|e| VolumeError::Format(e.to_string()))?;

    let mut file = FsOpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    if opts.sparse {
        file.seek(SeekFrom::Start(opts.size.saturating_sub(1)))?;
        file.write_all(&[0])?;
        file.seek(SeekFrom::Start(0))?;
        progress(opts.size, opts.size);
    } else {
        let mut chunk = vec![0u8; 1024 * 1024];
        let mut written = 0u64;
        while written < opts.size {
            fill_random(&mut chunk).map_err(|e| VolumeError::Crypto(e.to_string()))?;
            let n = ((opts.size - written) as usize).min(chunk.len());
            file.write_all(&chunk[..n])?;
            written += n as u64;
            progress(written, opts.size);
        }
        file.seek(SeekFrom::Start(0))?;
    }

    // Primary header slot
    let mut slot = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut slot).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    slot[..header.len()].copy_from_slice(&header);
    file.write_all(&slot)?;

    // Hidden header slot
    let mut hidden_slot = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut hidden_slot).map_err(|e| VolumeError::Crypto(e.to_string()))?;

    if let Some(hidden_size) = opts.hidden_size {
        if hidden_size >= data_size {
            return Err(VolumeError::Invalid("hidden volume too large"));
        }
        let (hh, _) = create_dc01_header(
            &dc_opts,
            hidden_size,
            opts.sector_size,
            opts.time_cost,
            opts.memory_kib,
            opts.parallelism,
        )
        .map_err(|e| VolumeError::Format(e.to_string()))?;
        // Note: real hidden volumes use a different password; caller should pass via API later.
        // For parity scaffold we embed a second header with same password (tests use distinct flow).
        hidden_slot[..hh.len()].copy_from_slice(&hh);
        let _ = HIDDEN_HEADER_OFFSET;
    }
    file.write_all(&hidden_slot)?;

    // Backup headers at end
    let backup_off = opts.size - HEADER_SLOT_SIZE * 2;
    file.seek(SeekFrom::Start(backup_off))?;
    let mut b1 = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut b1).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    b1[..header.len()].copy_from_slice(&header);
    file.write_all(&b1)?;
    let mut b2 = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut b2).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    file.write_all(&b2)?;
    file.sync_all()?;
    Ok(())
}

/// Create outer + hidden with distinct passwords (proper hidden volume).
pub fn create_container_with_hidden(
    path: &Path,
    outer: &CreateOptions<'_>,
    hidden_password: &[u8],
    hidden_size: u64,
) -> Result<(), VolumeError> {
    create_container_with_hidden_progress(path, outer, hidden_password, hidden_size, &mut |_, _| {})
}

/// Same as [`create_container_with_hidden`], forwarding wipe progress from the outer create.
pub fn create_container_with_hidden_progress(
    path: &Path,
    outer: &CreateOptions<'_>,
    hidden_password: &[u8],
    hidden_size: u64,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(), VolumeError> {
    create_container_with_progress(path, outer, progress)?;
    let data_size = outer.size - DATA_OFFSET - HEADER_SLOT_SIZE * 2;
    if hidden_size == 0 || hidden_size >= data_size {
        return Err(VolumeError::Invalid("hidden volume too large"));
    }
    // Hidden data occupies the end of the outer data area (VeraCrypt-compatible geometry).
    let enc_start = DATA_OFFSET + (data_size - hidden_size);
    let dc_opts = Dc01OpenOptions {
        password: hidden_password,
        keyfiles: outer.keyfiles,
    };
    let (hh, _) = create_dc01_header_at(
        &dc_opts,
        hidden_size,
        enc_start,
        hidden_size,
        hidden_size,
        1, // flag: hidden
        outer.sector_size,
        outer.time_cost,
        outer.memory_kib,
        outer.parallelism,
    )
    .map_err(|e| VolumeError::Format(e.to_string()))?;

    let mut file = FsOpenOptions::new().write(true).read(true).open(path)?;
    file.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;
    let mut hidden_slot = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut hidden_slot).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    hidden_slot[..hh.len()].copy_from_slice(&hh);
    file.write_all(&hidden_slot)?;
    file.sync_all()?;
    Ok(())
}

pub fn open_container(path: &Path, opts: &OpenOptions<'_>) -> Result<MountedVolume, VolumeError> {
    let mut file = FsOpenOptions::new().read(true).write(true).open(path)?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header)?;

    let dc_opts = Dc01OpenOptions {
        password: opts.password,
        keyfiles: opts.keyfiles,
    };

    if let Ok(h) = open_dc01_header(&header, &dc_opts) {
        let xts = DiskXts::Aes(Box::new(
            Aes256Xts::new(h.master_key.as_slice())
                .map_err(|e| VolumeError::Crypto(e.to_string()))?,
        ));
        return Ok(MountedVolume {
            path: path.to_path_buf(),
            kind: VolumeKind::Dc01,
            sector_size: h.sector_size,
            data_offset: h.encrypted_area_start,
            data_length: h.encrypted_area_length,
            is_hidden: (h.flags & 1) != 0,
            hidden_protect_size: 0,
            cipher: VolumeCipher::Aes256,
            kdf: "Argon2id",
            file,
            xts,
            master: h.master_key,
        });
    }

    let vc_opts = VeraCryptOpenOptions {
        password: opts.password,
        keyfiles: opts.keyfiles,
        pim: opts.pim,
        prf: opts.prf,
    };
    if let Ok(h) = try_open_veracrypt_header(&header, &vc_opts) {
        let n = h.cipher.xts_key_len();
        let key = &h.master_keys.as_slice()[..n.min(h.master_keys.len())];
        let mut key_bytes = SecureBytes::new(n);
        key_bytes.as_mut_slice().copy_from_slice(key);
        let xts = DiskXts::open(h.cipher, key_bytes.as_slice())
            .map_err(|e| VolumeError::Crypto(e.to_string()))?;
        let sector = if h.sector_size == 0 {
            512
        } else {
            h.sector_size
        };
        return Ok(MountedVolume {
            path: path.to_path_buf(),
            kind: VolumeKind::VeraCrypt,
            sector_size: sector,
            data_offset: if h.encrypted_area_start != 0 {
                h.encrypted_area_start
            } else {
                VC_DATA_OFFSET_FALLBACK
            },
            data_length: if h.encrypted_area_length != 0 {
                h.encrypted_area_length
            } else {
                h.volume_size
            },
            is_hidden: h.hidden_volume_size != 0,
            hidden_protect_size: 0,
            cipher: h.cipher,
            kdf: h.prf.label(),
            file,
            xts,
            master: key_bytes,
        });
    }

    // Hidden VeraCrypt header sits at 64 KiB. The outer header does not name it.
    file.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;
    if file.read_exact(&mut header).is_ok() {
        if let Ok(h) = try_open_veracrypt_header(&header, &vc_opts) {
            let n = h.cipher.xts_key_len();
            let key = &h.master_keys.as_slice()[..n.min(h.master_keys.len())];
            let mut key_bytes = SecureBytes::new(n);
            key_bytes.as_mut_slice().copy_from_slice(key);
            let xts = DiskXts::open(h.cipher, key_bytes.as_slice())
                .map_err(|e| VolumeError::Crypto(e.to_string()))?;
            let sector = if h.sector_size == 0 {
                512
            } else {
                h.sector_size
            };
            return Ok(MountedVolume {
                path: path.to_path_buf(),
                kind: VolumeKind::VeraCrypt,
                sector_size: sector,
                data_offset: if h.encrypted_area_start != 0 {
                    h.encrypted_area_start
                } else {
                    VC_DATA_OFFSET_FALLBACK
                },
                data_length: if h.encrypted_area_length != 0 {
                    h.encrypted_area_length
                } else {
                    h.volume_size
                },
                is_hidden: true,
                hidden_protect_size: 0,
                cipher: h.cipher,
                kdf: h.prf.label(),
                file,
                xts,
                master: key_bytes,
            });
        }
    }

    // Hidden DC01 header (distinct password)
    if let Ok(vol) = try_open_at(path, HIDDEN_HEADER_OFFSET, opts, true) {
        return Ok(vol);
    }

    let _ = opts.protect_hidden;
    let _ = opts.hidden_password;
    Err(VolumeError::Auth)
}

const VC_DATA_OFFSET_FALLBACK: u64 = 131_072;

fn try_open_at(
    path: &Path,
    offset: u64,
    opts: &OpenOptions<'_>,
    is_hidden: bool,
) -> Result<MountedVolume, VolumeError> {
    let mut file = FsOpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header)?;
    let dc_opts = Dc01OpenOptions {
        password: opts.password,
        keyfiles: opts.keyfiles,
    };
    let h = open_dc01_header(&header, &dc_opts).map_err(|_| VolumeError::Auth)?;
    let xts = DiskXts::Aes(Box::new(
        Aes256Xts::new(h.master_key.as_slice()).map_err(|e| VolumeError::Crypto(e.to_string()))?,
    ));
    Ok(MountedVolume {
        path: path.to_path_buf(),
        kind: VolumeKind::Dc01,
        sector_size: h.sector_size,
        data_offset: h.encrypted_area_start,
        data_length: h.encrypted_area_length,
        is_hidden,
        hidden_protect_size: 0,
        cipher: VolumeCipher::Aes256,
        kdf: "Argon2id",
        file,
        xts,
        master: h.master_key,
    })
}

pub fn read_sectors(
    vol: &mut MountedVolume,
    start_sector: u64,
    buf: &mut [u8],
) -> Result<(), VolumeError> {
    let ss = vol.sector_size as u64;
    if buf.len() as u64 % ss != 0 {
        return Err(VolumeError::Invalid("buffer not sector-aligned"));
    }
    let offset = vol.data_offset + start_sector * ss;
    vol.file.seek(SeekFrom::Start(offset))?;
    vol.file.read_exact(buf)?;
    let sectors = buf.len() as u64 / ss;
    for i in 0..sectors {
        let start = (i as usize) * vol.sector_size as usize;
        let end = start + vol.sector_size as usize;
        vol.xts
            .decrypt_sector(vol.data_unit(start_sector + i), &mut buf[start..end])
            .map_err(|e| VolumeError::Crypto(e.to_string()))?;
    }
    Ok(())
}

pub fn write_sectors(
    vol: &mut MountedVolume,
    start_sector: u64,
    buf: &[u8],
) -> Result<(), VolumeError> {
    let ss = vol.sector_size as u64;
    if buf.len() as u64 % ss != 0 {
        return Err(VolumeError::Invalid("buffer not sector-aligned"));
    }
    let mut tmp = buf.to_vec();
    let sectors = tmp.len() as u64 / ss;
    for i in 0..sectors {
        let start = (i as usize) * vol.sector_size as usize;
        let end = start + vol.sector_size as usize;
        vol.xts
            .encrypt_sector(vol.data_unit(start_sector + i), &mut tmp[start..end])
            .map_err(|e| VolumeError::Crypto(e.to_string()))?;
    }
    let offset = vol.data_offset + start_sector * ss;
    vol.file.seek(SeekFrom::Start(offset))?;
    vol.file.write_all(&tmp)?;
    tmp.zeroize();
    Ok(())
}

pub fn dismount_session(vol: MountedVolume) {
    drop(vol);
}

/// Re-open a container using a previously unlocked master key (no password).
/// Used for passwordless dismount/checkin after mount cached the session key.
pub fn open_with_master_key(
    path: &Path,
    master_key: &[u8],
    kind: VolumeKind,
    sector_size: u32,
    data_offset: u64,
    data_length: u64,
    is_hidden: bool,
) -> Result<MountedVolume, VolumeError> {
    if master_key.len() != 64 {
        return Err(VolumeError::Invalid("master key must be 64 bytes"));
    }
    if sector_size == 0 || sector_size % 16 != 0 {
        return Err(VolumeError::Invalid("invalid sector size"));
    }
    let file = FsOpenOptions::new().read(true).write(true).open(path)?;
    let xts = DiskXts::Aes(Box::new(
        Aes256Xts::new(master_key).map_err(|e| VolumeError::Crypto(e.to_string()))?,
    ));
    Ok(MountedVolume {
        path: path.to_path_buf(),
        kind,
        sector_size,
        data_offset,
        data_length,
        is_hidden,
        hidden_protect_size: 0,
        cipher: VolumeCipher::Aes256,
        kdf: "unknown",
        file,
        xts,
        master: SecureBytes::from_slice(master_key),
    })
}

impl MountedVolume {
    /// Master key material for AES-256-XTS (64 bytes). Session cache only.
    pub(crate) fn master_key_bytes(&self) -> &[u8] {
        self.master.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn create_open_write_read() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        let opts = CreateOptions {
            password: b"test-password-ok",
            size: 2 * 1024 * 1024,
            sparse: true,
            ..CreateOptions::default()
        };
        create_container(&path, &opts).unwrap();
        let mut vol = open_container(
            &path,
            &OpenOptions {
                password: b"test-password-ok",
                keyfiles: &[],
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .unwrap();
        let mut sector = vec![0u8; 512];
        sector[0..4].copy_from_slice(b"DC!!");
        write_sectors(&mut vol, 0, &sector).unwrap();
        let mut out = vec![0u8; 512];
        read_sectors(&mut vol, 0, &mut out).unwrap();
        assert_eq!(&out[0..4], b"DC!!");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wipe_reports_progress_to_total() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wipe.dc");
        let size = 2 * 1024 * 1024;
        let opts = CreateOptions {
            password: b"test-password-ok",
            size,
            sparse: false,
            ..CreateOptions::default()
        };
        let mut ticks = 0u32;
        let mut last = 0u64;
        create_container_with_progress(&path, &opts, &mut |done, total| {
            ticks += 1;
            last = done;
            assert_eq!(total, size);
            assert!(done <= total);
        })
        .unwrap();
        assert!(ticks >= 2);
        assert_eq!(last, size);
    }

    #[test]
    fn vendor_sha512_volume_boot_sector() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/VeraCrypt/Tests/test.sha512.hc");
        let mut vol = open_container(
            &path,
            &OpenOptions {
                password: b"test",
                keyfiles: &[],
                pim: 0,
                prf: Some(dc_crypto::PrfId::Sha512),
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .unwrap();
        assert!(matches!(vol.kind, VolumeKind::VeraCrypt));
        assert!(!vol.is_hidden);
        let mut sector = vec![0u8; vol.sector_size as usize];
        read_sectors(&mut vol, 0, &mut sector).unwrap();
        assert_eq!(&sector[510..512], &[0x55, 0xAA]);

        let mut hidden = open_container(
            &path,
            &OpenOptions {
                password: b"testhidden",
                keyfiles: &[],
                pim: 0,
                prf: Some(dc_crypto::PrfId::Sha512),
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .unwrap();
        assert!(hidden.is_hidden);
        let mut hsector = vec![0u8; hidden.sector_size as usize];
        read_sectors(&mut hidden, 0, &mut hsector).unwrap();
        assert_eq!(&hsector[510..512], &[0x55, 0xAA]);
    }
}
