//! Volume lifecycle: create, unlock, sector I/O, favorites, Linux mount, keyfiles.

mod cursor;
mod favorites;
mod fstype;
#[cfg(target_os = "linux")]
mod linux_mount;
mod session;

pub use cursor::{format_fat32, VolumeCursor};
pub use favorites::{add_favorite, list_favorites, remove_favorite, Favorite};
pub use fstype::FsType;
pub use session::{
    create_container, create_container_with_hidden, dismount_session, open_container,
    open_with_master_key, read_sectors, write_sectors, CreateOptions, MountedVolume, OpenOptions,
    VolumeKind,
};

#[cfg(target_os = "linux")]
pub use linux_mount::{
    format_volume, linux_dismount, linux_mount, list_mount_states, load_mount_state,
    LinuxMountOptions, MountState,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("format: {0}")]
    Format(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("auth failed")]
    Auth,
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
    #[error("platform: {0}")]
    Platform(String),
}
