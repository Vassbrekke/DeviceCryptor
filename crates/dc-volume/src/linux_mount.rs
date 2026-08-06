//! Checkout/checkin mount: extract FAT32 tree to a directory; write back on dismount.
//! Works without FUSE or root — primary Linux testing path.
//!
//! **Standard workflow (VeraCrypt-like):**
//! - **Mount** requires password and optional keyfile(s).
//! - **Dismount** needs only the mount id — credentials are not re-prompted.
//!
//! While mounted, the unlocked master key is held in a user-private session file
//! (`~/.local/state/devicecryptor/<id>.session`, mode 0600) so checkin can re-open
//! the container without the password. The session file is wiped on dismount.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use fatfs::{FileSystem, FsOptions};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cursor::{format_fat32, VolumeCursor};
use crate::fstype::FsType;
use crate::session::{
    open_container, open_with_master_key, read_sectors, MountedVolume, OpenOptions, VolumeKind,
};
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

const SESSION_MAGIC: &[u8; 8] = b"DCSESS01";
const SESSION_KIND_DC01: u8 = 0;
const SESSION_KIND_VC: u8 = 1;

fn state_dir() -> Result<PathBuf, VolumeError> {
    let dir = default_mount_state_dir().map_err(|e| VolumeError::Platform(e.to_string()))?;
    ensure_parent_dir(&dir.join("x")).map_err(|e| VolumeError::Platform(e.to_string()))?;
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn state_path(id: &str) -> Result<PathBuf, VolumeError> {
    Ok(state_dir()?.join(format!("{id}.json")))
}

fn session_path(id: &str) -> Result<PathBuf, VolumeError> {
    Ok(state_dir()?.join(format!("{id}.session")))
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

/// List all active mount states (non-secret metadata only).
pub fn list_mount_states() -> Result<Vec<MountState>, VolumeError> {
    let dir = state_dir()?;
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let data = fs::read_to_string(&p)?;
        if let Ok(st) = serde_json::from_str::<MountState>(&data) {
            out.push(st);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
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

/// Persist unlocked master key for passwordless dismount (mode 0600).
fn save_session_key(id: &str, vol: &MountedVolume) -> Result<(), VolumeError> {
    let key = vol.master_key_bytes();
    if key.len() != 64 {
        return Err(VolumeError::Invalid("master key must be 64 bytes"));
    }
    let p = session_path(id)?;
    let kind = match vol.kind {
        VolumeKind::Dc01 => SESSION_KIND_DC01,
        VolumeKind::VeraCrypt => SESSION_KIND_VC,
    };
    let mut blob = Vec::with_capacity(8 + 1 + 1 + 4 + 8 + 8 + 64);
    blob.extend_from_slice(SESSION_MAGIC);
    blob.push(kind);
    blob.push(if vol.is_hidden { 1 } else { 0 });
    blob.extend_from_slice(&vol.sector_size.to_le_bytes());
    blob.extend_from_slice(&vol.data_offset.to_le_bytes());
    blob.extend_from_slice(&vol.data_length.to_le_bytes());
    blob.extend_from_slice(key);

    write_private_file(&p, &blob)?;
    blob.zeroize();
    Ok(())
}

struct SessionMaterial {
    kind: VolumeKind,
    is_hidden: bool,
    sector_size: u32,
    data_offset: u64,
    data_length: u64,
    master: Vec<u8>,
}

impl Drop for SessionMaterial {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

fn load_session_key(id: &str) -> Result<SessionMaterial, VolumeError> {
    let p = session_path(id)?;
    if !p.exists() {
        return Err(VolumeError::Invalid(
            "mount session key missing — remount the volume (dismount does not need a password after a fresh mount)",
        ));
    }
    let mut data = fs::read(&p)?;
    const MIN: usize = 8 + 1 + 1 + 4 + 8 + 8 + 64;
    if data.len() < MIN || &data[..8] != SESSION_MAGIC {
        data.zeroize();
        return Err(VolumeError::Format("corrupt mount session file".into()));
    }
    let kind = match data[8] {
        SESSION_KIND_DC01 => VolumeKind::Dc01,
        SESSION_KIND_VC => VolumeKind::VeraCrypt,
        _ => {
            data.zeroize();
            return Err(VolumeError::Format("unknown session volume kind".into()));
        }
    };
    let is_hidden = data[9] != 0;
    let sector_size = u32::from_le_bytes(data[10..14].try_into().unwrap());
    let data_offset = u64::from_le_bytes(data[14..22].try_into().unwrap());
    let data_length = u64::from_le_bytes(data[22..30].try_into().unwrap());
    let master = data[30..94].to_vec();
    data.zeroize();
    Ok(SessionMaterial {
        kind,
        is_hidden,
        sector_size,
        data_offset,
        data_length,
        master,
    })
}

fn wipe_session_key(id: &str) -> Result<(), VolumeError> {
    let p = session_path(id)?;
    if p.exists() {
        // Overwrite then remove so key material is not left in free space casually.
        if let Ok(meta) = fs::metadata(&p) {
            let len = meta.len() as usize;
            let zeros = vec![0u8; len.max(128)];
            let _ = write_private_file(&p, &zeros);
        }
        let _ = fs::remove_file(&p);
    }
    Ok(())
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), VolumeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

fn open_from_session(container: &Path, id: &str) -> Result<MountedVolume, VolumeError> {
    let mut sess = load_session_key(id)?;
    let vol = open_with_master_key(
        container,
        &sess.master,
        sess.kind,
        sess.sector_size,
        sess.data_offset,
        sess.data_length,
        sess.is_hidden,
    );
    sess.master.zeroize();
    vol
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
    {
        let guard = vol.lock().unwrap();
        save_session_key(opts.id, &guard)?;
    }
    if let Err(e) = extract_fat_tree(Arc::clone(&vol), opts.mountpoint, protect) {
        let _ = wipe_session_key(opts.id);
        return Err(e);
    }
    // Marker so users know this is a DeviceCryptor checkout mount
    if let Err(e) = fs::write(
        opts.mountpoint.join(".devicecryptor-mount"),
        b"backend=fat-checkout\n",
    ) {
        let _ = wipe_session_key(opts.id);
        return Err(VolumeError::Io(e));
    }
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
    if let Err(e) = save_mount_state(&st) {
        let _ = wipe_session_key(opts.id);
        return Err(e);
    }
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
    {
        let guard = vol.lock().unwrap();
        save_session_key(opts.id, &guard)?;
    }
    let dir = state_dir()?;
    let raw = dir.join(format!("{}.raw", opts.id));
    export_raw_image(Arc::clone(&vol), &raw)?;
    drop(vol);

    let out = Command::new("losetup")
        .args(["--find", "--show"])
        .arg(&raw)
        .output()
        .map_err(|e| VolumeError::Platform(format!("losetup: {e}")))?;
    if !out.status.success() {
        let _ = wipe_session_key(opts.id);
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
        let _ = wipe_session_key(opts.id);
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

/// Dismount by mount id only — no password or keyfile.
///
/// Uses the session key saved at mount time to sync checkout/loop backends
/// back into the encrypted container, then wipes the session material.
pub fn linux_dismount(id: &str) -> Result<(), VolumeError> {
    let st = load_mount_state(id)?.ok_or(VolumeError::Invalid("not mounted"))?;
    match st.backend.as_str() {
        "fat-checkout" => {
            let _ = fs::remove_file(st.mountpoint.join(".devicecryptor-mount"));
            let mut vol = open_from_session(&st.container, id)?;
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
                let vol = open_from_session(&st.container, id)?;
                let vol = Arc::new(Mutex::new(vol));
                import_raw_image(vol, raw)?;
                let _ = fs::remove_file(raw);
            }
        }
        _ => {}
    }
    wipe_session_key(id)?;
    remove_mount_state(id)?;
    Ok(())
}
