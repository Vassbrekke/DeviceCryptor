//! Checkout/checkin mount: extract FAT32 tree to a directory; write back on dismount.
//! Works without FUSE or root — primary Linux testing path.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use fatfs::{FileSystem, FsOptions};
use serde::{Deserialize, Serialize};

use crate::cursor::{format_fat32, VolumeCursor};
use crate::fstype::FsType;
use crate::session::{open_container, read_sectors, MountedVolume, OpenOptions};
use crate::VolumeError;
use dc_platform::{default_mount_state_dir, ensure_parent_dir, is_elevated};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountState {
    pub id: String,
    pub container: PathBuf,
    pub mountpoint: PathBuf,
    pub backend: String,
    pub loop_dev: Option<String>,
    pub raw_path: Option<PathBuf>,
    pub pid: u32,
    pub fs: String,
    pub protect_hidden: u64,
}

fn state_path(id: &str) -> Result<PathBuf, VolumeError> {
    let dir = default_mount_state_dir().map_err(|e| VolumeError::Platform(e.to_string()))?;
    ensure_parent_dir(&dir.join("x")).map_err(|e| VolumeError::Platform(e.to_string()))?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{id}.json")))
}

pub fn load_mount_state(id: &str) -> Result<Option<MountState>, VolumeError> {
    let p = state_path(id)?;
    if !p.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(p)?;
    Ok(Some(
        serde_json::from_str(&data).map_err(|e| VolumeError::Format(e.to_string()))?,
    ))
}

fn save_mount_state(st: &MountState) -> Result<(), VolumeError> {
    let p = state_path(&st.id)?;
    let data = serde_json::to_string_pretty(st).map_err(|e| VolumeError::Format(e.to_string()))?;
    fs::write(p, data)?;
    Ok(())
}

fn remove_mount_state(id: &str) -> Result<(), VolumeError> {
    let p = state_path(id)?;
    if p.exists() {
        fs::remove_file(p)?;
    }
    Ok(())
}

pub fn format_volume(vol: Arc<Mutex<MountedVolume>>, fs: FsType) -> Result<(), VolumeError> {
    match fs {
        FsType::None => Ok(()),
        FsType::Fat32 => format_fat32(vol),
        FsType::Ext4 => format_ext4_via_temp(vol),
    }
}

fn format_ext4_via_temp(vol: Arc<Mutex<MountedVolume>>) -> Result<(), VolumeError> {
    let data_len = vol.lock().unwrap().data_length;
    let dir = default_mount_state_dir().map_err(|e| VolumeError::Platform(e.to_string()))?;
    fs::create_dir_all(&dir)?;
    let raw = dir.join(format!("fmt-{}.img", std::process::id()));
    {
        let f = File::create(&raw)?;
        f.set_len(data_len)?;
    }
    let status = Command::new("mkfs.ext4")
        .args(["-F", "-q"])
        .arg(&raw)
        .status()
        .map_err(|e| VolumeError::Platform(format!("mkfs.ext4: {e}")))?;
    if !status.success() {
        let _ = fs::remove_file(&raw);
        return Err(VolumeError::Platform("mkfs.ext4 failed".into()));
    }
    let mut src = File::open(&raw)?;
    let mut cursor = VolumeCursor::new(Arc::clone(&vol));
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        cursor.write_all(&buf[..n])?;
    }
    cursor.flush()?;
    let _ = fs::remove_file(&raw);
    Ok(())
}

pub fn export_raw_image(
    vol: Arc<Mutex<MountedVolume>>,
    raw_path: &Path,
) -> Result<(), VolumeError> {
    let data_len = vol.lock().unwrap().data_length;
    {
        let f = File::create(raw_path)?;
        f.set_len(data_len)?;
    }
    let mut dst = File::options().write(true).open(raw_path)?;
    let mut cursor = VolumeCursor::new(vol);
    cursor.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut left = data_len;
    while left > 0 {
        let n = (buf.len() as u64).min(left) as usize;
        cursor.read_exact(&mut buf[..n])?;
        dst.write_all(&buf[..n])?;
        left -= n as u64;
    }
    dst.sync_all()?;
    Ok(())
}

pub fn import_raw_image(
    vol: Arc<Mutex<MountedVolume>>,
    raw_path: &Path,
) -> Result<(), VolumeError> {
    let mut src = File::open(raw_path)?;
    let mut cursor = VolumeCursor::new(vol);
    cursor.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        cursor.write_all(&buf[..n])?;
    }
    cursor.flush()?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct LinuxMountOptions<'a> {
    pub id: &'a str,
    pub mountpoint: &'a Path,
    pub open: OpenOptions<'a>,
    pub fs_hint: FsType,
}

fn resolve_hidden_protect(container: &Path, opts: &OpenOptions<'_>) -> u64 {
    if !opts.protect_hidden {
        return 0;
    }
    let Some(hp) = opts.hidden_password else {
        return 0;
    };
    open_container(
        container,
        &OpenOptions {
            password: hp,
            keyfiles: opts.keyfiles,
            pim: opts.pim,
            protect_hidden: false,
            hidden_password: None,
        },
    )
    .map(|h| h.data_length)
    .unwrap_or(0)
}

fn is_fat_volume(vol: &mut MountedVolume) -> bool {
    let mut sector = vec![0u8; vol.sector_size as usize];
    if read_sectors(vol, 0, &mut sector).is_err() {
        return false;
    }
    sector.len() >= 512 && sector[510] == 0x55 && sector[511] == 0xAA
}

/// Mount for Linux testing (checkout/checkin for FAT; loop for ext4 when root).
pub fn linux_mount(
    container: &Path,
    opts: &LinuxMountOptions<'_>,
) -> Result<MountState, VolumeError> {
    if opts.mountpoint.exists() {
        let meta = fs::metadata(opts.mountpoint)?;
        if meta.is_dir() {
            let empty = fs::read_dir(opts.mountpoint)?.next().is_none();
            if !empty {
                return Err(VolumeError::Invalid(
                    "mountpoint must be an empty directory",
                ));
            }
        } else {
            return Err(VolumeError::Invalid(
                "mountpoint exists and is not a directory",
            ));
        }
    } else {
        fs::create_dir_all(opts.mountpoint)?;
    }

    let protect = resolve_hidden_protect(container, &opts.open);
    let mut vol = open_container(container, &opts.open)?;
    vol.hidden_protect_size = protect;
    let is_fat = is_fat_volume(&mut vol);
    let vol = Arc::new(Mutex::new(vol));

    let fs = match opts.fs_hint {
        FsType::Fat32 => FsType::Fat32,
        FsType::Ext4 => FsType::Ext4,
        FsType::None if is_fat => FsType::Fat32,
        FsType::None => FsType::Ext4,
    };

    match fs {
        FsType::Fat32 => mount_fat_checkout(container, vol, opts, protect),
        FsType::Ext4 | FsType::None => mount_loop(container, vol, opts, fs),
    }
}

fn mount_fat_checkout(
    container: &Path,
    vol: Arc<Mutex<MountedVolume>>,
    opts: &LinuxMountOptions<'_>,
    protect: u64,
) -> Result<MountState, VolumeError> {
    extract_fat_tree(Arc::clone(&vol), opts.mountpoint, protect)?;
    // Marker so users know this is a DeviceCryptor checkout mount
    fs::write(
        opts.mountpoint.join(".devicecryptor-mount"),
        b"backend=fat-checkout\n",
    )?;
    let st = MountState {
        id: opts.id.to_string(),
        container: container.to_path_buf(),
        mountpoint: opts.mountpoint.to_path_buf(),
        backend: "fat-checkout".into(),
        loop_dev: None,
        raw_path: None,
        pid: std::process::id(),
        fs: "fat32".into(),
        protect_hidden: protect,
    };
    save_mount_state(&st)?;
    Ok(st)
}

fn extract_fat_tree(
    vol: Arc<Mutex<MountedVolume>>,
    dest: &Path,
    protect: u64,
) -> Result<(), VolumeError> {
    let cursor = {
        let c = VolumeCursor::new(vol);
        if protect > 0 {
            c.with_hidden_protection(protect)
        } else {
            c
        }
    };
    let fs = FileSystem::new(cursor, FsOptions::new())
        .map_err(|e| VolumeError::Format(e.to_string()))?;
    extract_dir(&fs.root_dir(), dest)?;
    Ok(())
}

fn extract_dir<IO: Read + Write + Seek>(
    dir: &fatfs::Dir<IO>,
    dest: &Path,
) -> Result<(), VolumeError> {
    fs::create_dir_all(dest)?;
    for entry in dir.iter() {
        let entry = entry.map_err(|e| VolumeError::Format(e.to_string()))?;
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let out = dest.join(&name);
        if entry.is_dir() {
            let sub = entry.to_dir();
            extract_dir(&sub, &out)?;
        } else {
            let mut file = entry.to_file();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(VolumeError::Io)?;
            fs::write(out, buf)?;
        }
    }
    Ok(())
}

fn import_fat_tree(
    vol: Arc<Mutex<MountedVolume>>,
    src: &Path,
    protect: u64,
) -> Result<(), VolumeError> {
    // Reformat then copy host tree into FAT (simple, reliable for testing).
    format_fat32(Arc::clone(&vol))?;
    let cursor = {
        let c = VolumeCursor::new(vol);
        if protect > 0 {
            c.with_hidden_protection(protect)
        } else {
            c
        }
    };
    let fs = FileSystem::new(cursor, FsOptions::new())
        .map_err(|e| VolumeError::Format(e.to_string()))?;
    import_dir(&fs.root_dir(), src)?;
    Ok(())
}

fn import_dir<IO: Read + Write + Seek>(
    dir: &fatfs::Dir<IO>,
    src: &Path,
) -> Result<(), VolumeError> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue; // skip .devicecryptor-mount and dotfiles
        }
        let path = entry.path();
        if path.is_dir() {
            let sub = dir
                .create_dir(&name_str)
                .map_err(|e| VolumeError::Format(e.to_string()))?;
            import_dir(&sub, &path)?;
        } else {
            let data = fs::read(&path)?;
            let mut f = dir
                .create_file(&name_str)
                .map_err(|e| VolumeError::Format(e.to_string()))?;
            f.write_all(&data).map_err(VolumeError::Io)?;
            f.flush().map_err(VolumeError::Io)?;
        }
    }
    Ok(())
}

fn mount_loop(
    container: &Path,
    vol: Arc<Mutex<MountedVolume>>,
    opts: &LinuxMountOptions<'_>,
    fs: FsType,
) -> Result<MountState, VolumeError> {
    if !is_elevated() {
        return Err(VolumeError::Platform(
            "ext4/loop mount requires root; create with --fs fat32 for unprivileged checkout mounts"
                .into(),
        ));
    }
    let dir = default_mount_state_dir().map_err(|e| VolumeError::Platform(e.to_string()))?;
    fs::create_dir_all(&dir)?;
    let raw = dir.join(format!("{}.raw", opts.id));
    export_raw_image(Arc::clone(&vol), &raw)?;
    drop(vol);

    let out = Command::new("losetup")
        .args(["--find", "--show"])
        .arg(&raw)
        .output()
        .map_err(|e| VolumeError::Platform(format!("losetup: {e}")))?;
    if !out.status.success() {
        return Err(VolumeError::Platform(format!(
            "losetup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let loop_dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let fstype = match fs {
        FsType::Ext4 => "ext4",
        FsType::Fat32 => "vfat",
        FsType::None => "auto",
    };
    let status = Command::new("mount")
        .args(["-t", fstype])
        .arg(&loop_dev)
        .arg(opts.mountpoint)
        .status()
        .map_err(|e| VolumeError::Platform(format!("mount: {e}")))?;
    if !status.success() {
        let _ = Command::new("losetup").args(["-d", &loop_dev]).status();
        let _ = fs::remove_file(&raw);
        return Err(VolumeError::Platform("mount failed".into()));
    }

    let st = MountState {
        id: opts.id.to_string(),
        container: container.to_path_buf(),
        mountpoint: opts.mountpoint.to_path_buf(),
        backend: "loop".into(),
        loop_dev: Some(loop_dev),
        raw_path: Some(raw),
        pid: std::process::id(),
        fs: fstype.into(),
        protect_hidden: 0,
    };
    save_mount_state(&st)?;
    Ok(st)
}

pub fn linux_dismount(id: &str, open_for_sync: OpenOptions<'_>) -> Result<(), VolumeError> {
    let st = load_mount_state(id)?.ok_or(VolumeError::Invalid("not mounted"))?;
    match st.backend.as_str() {
        "fat-checkout" => {
            let _ = fs::remove_file(st.mountpoint.join(".devicecryptor-mount"));
            let vol = open_container(&st.container, &open_for_sync)?;
            let mut vol = vol;
            vol.hidden_protect_size = st.protect_hidden;
            let vol = Arc::new(Mutex::new(vol));
            import_fat_tree(vol, &st.mountpoint, st.protect_hidden)?;
            // Clean checkout dir contents (leave directory)
            for entry in fs::read_dir(&st.mountpoint)? {
                let entry = entry?;
                let p = entry.path();
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(p)?;
                } else {
                    fs::remove_file(p)?;
                }
            }
        }
        "loop" => {
            let _ = Command::new("umount").arg(&st.mountpoint).status();
            if let Some(ref loop_dev) = st.loop_dev {
                let _ = Command::new("losetup").args(["-d", loop_dev]).status();
            }
            if let Some(raw) = st.raw_path.as_ref() {
                let vol = open_container(&st.container, &open_for_sync)?;
                let vol = Arc::new(Mutex::new(vol));
                import_raw_image(vol, raw)?;
                let _ = fs::remove_file(raw);
            }
        }
        _ => {}
    }
    remove_mount_state(id)?;
    Ok(())
}
