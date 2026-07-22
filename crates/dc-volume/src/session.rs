use std::fs::{File, OpenOptions as FsOpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use dc_crypto::{fill_random, Aes256Xts, SecureBytes};
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
    pub(crate) file: File,
    xts: Aes256Xts,
    #[allow(dead_code)]
    master: SecureBytes,
}

impl MountedVolume {
    pub fn sync(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

impl Drop for MountedVolume {
    fn drop(&mut self) {
        // Zeroize handled by SecureBytes / Aes256Xts Drop
        let _ = self.file.sync_all();
    }
}

pub fn create_container(path: &Path, opts: &CreateOptions<'_>) -> Result<(), VolumeError> {
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
    } else {
        let mut chunk = vec![0u8; 1024 * 1024];
        let mut written = 0u64;
        while written < opts.size {
            fill_random(&mut chunk).map_err(|e| VolumeError::Crypto(e.to_string()))?;
            let n = ((opts.size - written) as usize).min(chunk.len());
            file.write_all(&chunk[..n])?;
            written += n as u64;
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
    create_container(path, outer)?;
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
        let xts = Aes256Xts::new(h.master_key.as_slice())
            .map_err(|e| VolumeError::Crypto(e.to_string()))?;
        return Ok(MountedVolume {
            path: path.to_path_buf(),
            kind: VolumeKind::Dc01,
            sector_size: h.sector_size,
            data_offset: h.encrypted_area_start,
            data_length: h.encrypted_area_length,
            is_hidden: false,
            hidden_protect_size: 0,
            file,
            xts,
            master: h.master_key,
        });
    }

    let vc_opts = VeraCryptOpenOptions {
        password: opts.password,
        keyfiles: opts.keyfiles,
        pim: opts.pim,
    };
    if let Ok(h) = try_open_veracrypt_header(&header, &vc_opts) {
        let key = &h.master_keys.as_slice()[..64.min(h.master_keys.len())];
        let mut key64 = SecureBytes::new(64);
        key64.as_mut_slice().copy_from_slice(key);
        let xts =
            Aes256Xts::new(key64.as_slice()).map_err(|e| VolumeError::Crypto(e.to_string()))?;
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
            file,
            xts,
            master: key64,
        });
    }

    // Hidden volume header (distinct password)
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
    let xts =
        Aes256Xts::new(h.master_key.as_slice()).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    Ok(MountedVolume {
        path: path.to_path_buf(),
        kind: VolumeKind::Dc01,
        sector_size: h.sector_size,
        data_offset: h.encrypted_area_start,
        data_length: h.encrypted_area_length,
        is_hidden,
        hidden_protect_size: 0,
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
            .decrypt_sector(start_sector + i, &mut buf[start..end])
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
            .encrypt_sector(start_sector + i, &mut tmp[start..end])
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
}
