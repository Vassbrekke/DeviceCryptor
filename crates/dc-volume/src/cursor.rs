//! Seekable byte view of an unlocked volume's data area (for FAT / formatting).

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use crate::session::{read_sectors, write_sectors, MountedVolume};
use crate::VolumeError;

/// Sector-backed Read/Write/Seek over a `MountedVolume`.
pub struct VolumeCursor {
    vol: Arc<Mutex<MountedVolume>>,
    pos: u64,
    /// If set, refuse writes that would overwrite the hidden volume region
    /// (outer volume mount with protect-hidden). Hidden data sits at the *end*
    /// of the outer data area: `[data_length - hidden_size, data_length)`.
    protect_hidden_size: Option<u64>,
}

impl VolumeCursor {
    pub fn new(vol: Arc<Mutex<MountedVolume>>) -> Self {
        Self {
            vol,
            pos: 0,
            protect_hidden_size: None,
        }
    }

    pub fn with_hidden_protection(mut self, hidden_size: u64) -> Self {
        self.protect_hidden_size = Some(hidden_size);
        self
    }

    fn data_length(&self) -> u64 {
        self.vol.lock().unwrap().data_length
    }

    fn check_hidden_protect(&self, offset: u64, len: u64) -> io::Result<()> {
        if let Some(hs) = self.protect_hidden_size {
            if hs == 0 {
                return Ok(());
            }
            let data_len = self.data_length();
            let hidden_start = data_len.saturating_sub(hs);
            let end = offset.saturating_add(len);
            if end > hidden_start {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "write would damage hidden volume",
                ));
            }
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut vol = self.vol.lock().unwrap();
        let ss = vol.sector_size as u64;
        let data_len = vol.data_length;
        if offset >= data_len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(data_len - offset) as usize;
        let start_sector = offset / ss;
        let end_off = offset + want as u64;
        let end_sector = end_off.div_ceil(ss);
        let n_sectors = (end_sector - start_sector) as usize;
        let mut tmp = vec![0u8; n_sectors * vol.sector_size as usize];
        read_sectors(&mut vol, start_sector, &mut tmp).map_err(vol_err)?;
        let skip = (offset % ss) as usize;
        buf[..want].copy_from_slice(&tmp[skip..skip + want]);
        Ok(want)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.check_hidden_protect(offset, buf.len() as u64)?;
        let mut vol = self.vol.lock().unwrap();
        let ss = vol.sector_size as u64;
        let data_len = vol.data_length;
        if offset >= data_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "write past end of volume",
            ));
        }
        let want = (buf.len() as u64).min(data_len - offset) as usize;
        let start_sector = offset / ss;
        let end_off = offset + want as u64;
        let end_sector = end_off.div_ceil(ss);
        let n_sectors = (end_sector - start_sector) as usize;
        let mut tmp = vec![0u8; n_sectors * vol.sector_size as usize];
        read_sectors(&mut vol, start_sector, &mut tmp).map_err(vol_err)?;
        let skip = (offset % ss) as usize;
        tmp[skip..skip + want].copy_from_slice(&buf[..want]);
        write_sectors(&mut vol, start_sector, &tmp).map_err(vol_err)?;
        Ok(want)
    }
}

fn vol_err(e: VolumeError) -> io::Error {
    io::Error::other(e.to_string())
}

impl Read for VolumeCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for VolumeCursor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.write_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut vol = self.vol.lock().unwrap();
        vol.sync()
    }
}

impl Seek for VolumeCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data_length();
        let next = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => len as i64 + p,
            SeekFrom::Current(p) => self.pos as i64 + p,
        };
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

/// Format the unlocked volume as FAT32 (in-place via sector I/O).
pub fn format_fat32(vol: Arc<Mutex<MountedVolume>>) -> Result<(), VolumeError> {
    let cursor = VolumeCursor::new(vol);
    // fatfs formats via MkfsOptions
    fatfs::format_volume(
        cursor,
        fatfs::FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat32)
            .volume_label(*b"DEVICECRYPT"),
    )
    .map_err(|e| VolumeError::Format(e.to_string()))?;
    Ok(())
}
