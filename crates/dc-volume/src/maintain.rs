//! Password change and header backup/restore for DC01 volumes.

use std::fs::{self, OpenOptions as FsOpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use dc_crypto::fill_random;
use dc_format::dc01::{open_dc01_header, seal_dc01_header_with_master, Dc01OpenOptions};
use dc_format::{DATA_OFFSET, HEADER_SLOT_SIZE, HIDDEN_HEADER_OFFSET};

use crate::session::OpenOptions;
use crate::VolumeError;

/// Magic for DeviceCryptor header backup files (version 1).
const HDR_BACKUP_MAGIC: &[u8; 8] = b"DCHDR01\0";
/// Bytes covered: primary header slot + hidden header slot.
const HDR_BACKUP_BODY: u64 = HEADER_SLOT_SIZE * 2;

/// Change the password (and optional keyfiles) on a DC01 volume without re-encrypting data.
///
/// Master key and volume geometry are preserved. Primary or hidden header is updated
/// depending on which password unlocks the volume. Matching backup header slot is updated.
pub fn change_password(
    path: &Path,
    current: &OpenOptions<'_>,
    new_password: &[u8],
    new_keyfiles: &[&[u8]],
) -> Result<(), VolumeError> {
    if new_password.is_empty() {
        return Err(VolumeError::Invalid("new password required"));
    }

    let mut file = FsOpenOptions::new().read(true).write(true).open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < DATA_OFFSET + HEADER_SLOT_SIZE * 2 {
        return Err(VolumeError::Invalid("container too small"));
    }

    let cur = Dc01OpenOptions {
        password: current.password,
        keyfiles: current.keyfiles,
    };

    // Try primary header, then hidden.
    let (header_off, backup_off, opened) = {
        let mut hdr = [0u8; 512];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut hdr)?;
        if let Ok(h) = open_dc01_header(&hdr, &cur) {
            let backup = file_len - HEADER_SLOT_SIZE * 2;
            (0u64, backup, h)
        } else {
            file.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;
            file.read_exact(&mut hdr)?;
            let h = open_dc01_header(&hdr, &cur).map_err(|_| VolumeError::Auth)?;
            let backup = file_len - HEADER_SLOT_SIZE;
            (HIDDEN_HEADER_OFFSET, backup, h)
        }
    };

    let new_opts = Dc01OpenOptions {
        password: new_password,
        keyfiles: new_keyfiles,
    };
    let sealed = seal_dc01_header_with_master(&new_opts, &opened)
        .map_err(|e| VolumeError::Format(e.to_string()))?;

    write_header_slot(&mut file, header_off, &sealed)?;
    write_header_slot(&mut file, backup_off, &sealed)?;
    file.sync_all()?;
    Ok(())
}

fn write_header_slot(
    file: &mut std::fs::File,
    offset: u64,
    header512: &[u8],
) -> Result<(), VolumeError> {
    if header512.len() != 512 {
        return Err(VolumeError::Invalid("header must be 512 bytes"));
    }
    let mut slot = vec![0u8; HEADER_SLOT_SIZE as usize];
    fill_random(&mut slot).map_err(|e| VolumeError::Crypto(e.to_string()))?;
    slot[..512].copy_from_slice(header512);
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&slot)?;
    Ok(())
}

/// Backup primary + hidden header slots (first 128 KiB) to `dest`.
///
/// Does not include volume data. Useful before password changes or risky experiments.
pub fn backup_headers(container: &Path, dest: &Path) -> Result<(), VolumeError> {
    let mut src = FsOpenOptions::new().read(true).open(container)?;
    let len = src.metadata()?.len();
    if len < HDR_BACKUP_BODY {
        return Err(VolumeError::Invalid(
            "container too small for header backup",
        ));
    }
    let mut body = vec![0u8; HDR_BACKUP_BODY as usize];
    src.seek(SeekFrom::Start(0))?;
    src.read_exact(&mut body)?;

    let mut out = Vec::with_capacity(8 + 8 + body.len());
    out.extend_from_slice(HDR_BACKUP_MAGIC);
    out.extend_from_slice(&HDR_BACKUP_BODY.to_le_bytes());
    out.extend_from_slice(&body);
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(dest, out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Check a header backup file without writing to a container.
pub fn inspect_header_backup(backup_file: &Path) -> Result<u64, VolumeError> {
    let data = fs::read(backup_file)?;
    if data.len() < 16 || &data[..8] != HDR_BACKUP_MAGIC {
        return Err(VolumeError::Format(
            "not a DeviceCryptor header backup".into(),
        ));
    }
    let body_len = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if body_len != HDR_BACKUP_BODY || data.len() != 16 + body_len as usize {
        return Err(VolumeError::Format(
            "corrupt or unsupported header backup".into(),
        ));
    }
    Ok(body_len)
}

/// Restore primary + hidden header slots from a `backup_headers` file.
///
/// Only touches the first 128 KiB of the container. Does not rewrite backup headers
/// at the end of the file (run `dc chpasswd` or a full repair path for those).
pub fn restore_headers(container: &Path, backup_file: &Path) -> Result<(), VolumeError> {
    let data = fs::read(backup_file)?;
    if data.len() < 16 || &data[..8] != HDR_BACKUP_MAGIC {
        return Err(VolumeError::Format(
            "not a DeviceCryptor header backup".into(),
        ));
    }
    let body_len = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if body_len != HDR_BACKUP_BODY || data.len() != 16 + body_len as usize {
        return Err(VolumeError::Format(
            "corrupt or unsupported header backup".into(),
        ));
    }
    let body = &data[16..];

    let mut file = FsOpenOptions::new()
        .read(true)
        .write(true)
        .open(container)?;
    let len = file.metadata()?.len();
    if len < HDR_BACKUP_BODY {
        return Err(VolumeError::Invalid("container too small"));
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn inspect_rejects_a_short_file_and_accepts_magic() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.hdrbak");
        std::fs::write(&bad, b"nope").unwrap();
        assert!(inspect_header_backup(&bad).is_err());

        let good = dir.path().join("good.hdrbak");
        let mut f = std::fs::File::create(&good).unwrap();
        f.write_all(b"DCHDR01\0").unwrap();
        f.write_all(&HDR_BACKUP_BODY.to_le_bytes()).unwrap();
        f.write_all(&vec![0u8; HDR_BACKUP_BODY as usize]).unwrap();
        assert_eq!(inspect_header_backup(&good).unwrap(), HDR_BACKUP_BODY);
    }

    use crate::session::{create_container, open_container, CreateOptions, OpenOptions};
    use tempfile::NamedTempFile;

    #[test]
    fn chpasswd_and_header_backup_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);

        create_container(
            &path,
            &CreateOptions {
                password: b"alpha-pass",
                size: 2 * 1024 * 1024,
                sparse: true,
                ..CreateOptions::default()
            },
        )
        .unwrap();

        let bak = path.with_extension("hdrbak");
        backup_headers(&path, &bak).unwrap();

        change_password(
            &path,
            &OpenOptions {
                password: b"alpha-pass",
                keyfiles: &[],
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
            b"beta-pass",
            &[],
        )
        .unwrap();

        assert!(open_container(
            &path,
            &OpenOptions {
                password: b"alpha-pass",
                keyfiles: &[],
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .is_err());

        open_container(
            &path,
            &OpenOptions {
                password: b"beta-pass",
                keyfiles: &[],
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .unwrap();

        // Restore old headers → old password works again
        restore_headers(&path, &bak).unwrap();
        open_container(
            &path,
            &OpenOptions {
                password: b"alpha-pass",
                keyfiles: &[],
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
        )
        .unwrap();

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak);
    }

    fn opts(password: &'static [u8]) -> OpenOptions<'static> {
        OpenOptions {
            password,
            keyfiles: &[],
            pim: 0,
            prf: None,
            protect_hidden: false,
            hidden_password: None,
        }
    }

    #[test]
    fn flipped_header_fails_until_restore() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        create_container(
            &path,
            &CreateOptions {
                password: b"alpha-pass",
                size: 2 * 1024 * 1024,
                sparse: true,
                ..CreateOptions::default()
            },
        )
        .unwrap();
        let bak = path.with_extension("hdrbak");
        backup_headers(&path, &bak).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[80] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        assert!(open_container(&path, &opts(b"alpha-pass")).is_err());

        restore_headers(&path, &bak).unwrap();
        open_container(&path, &opts(b"alpha-pass")).unwrap();

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak);
    }

    #[test]
    fn truncated_container_and_bad_backup_are_rejected() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        create_container(
            &path,
            &CreateOptions {
                password: b"alpha-pass",
                size: 2 * 1024 * 1024,
                sparse: true,
                ..CreateOptions::default()
            },
        )
        .unwrap();
        let bak = path.with_extension("hdrbak");
        backup_headers(&path, &bak).unwrap();

        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(100).unwrap();
        assert!(open_container(&path, &opts(b"alpha-pass")).is_err());
        assert!(backup_headers(&path, &bak).is_err());

        fs::write(&bak, b"not-a-backup").unwrap();
        assert!(restore_headers(&path, &bak).is_err());

        let mut short = b"DCHDR01\0".to_vec();
        short.extend_from_slice(&16u64.to_le_bytes());
        short.extend_from_slice(&[0u8; 8]);
        fs::write(&bak, short).unwrap();
        assert!(restore_headers(&path, &bak).is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak);
    }
}
