//! Shared filesystem type for create/mount.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsType {
    Fat32,
    Ext4,
    None,
}

impl FsType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fat" | "fat32" | "vfat" => Some(Self::Fat32),
            "ext4" => Some(Self::Ext4),
            "none" | "" | "auto" => Some(Self::None),
            _ => None,
        }
    }
}
