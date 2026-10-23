//! Platform helpers: privileges, path checks, optional loop hints.

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Message(String),
}

/// True if process appears to have admin/root privileges.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Conservative: treat as non-elevated unless later WinAPI check is added.
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub fn ensure_parent_dir(path: &Path) -> Result<(), PlatformError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Favorites store path (~/.config/devicecryptor/favorites.json or %APPDATA%).
pub fn favorites_path() -> Result<PathBuf, PlatformError> {
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| PlatformError::Message("HOME not set".into()))?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("devicecryptor")
            .join("favorites.json"))
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA")
            .ok_or_else(|| PlatformError::Message("APPDATA not set".into()))?;
        Ok(PathBuf::from(base)
            .join("DeviceCryptor")
            .join("favorites.json"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(PlatformError::Unsupported("favorites path"))
    }
}

/// Suggest a mount point directory for unlocked volume metadata (not a block mount).
pub fn default_mount_state_dir() -> Result<PathBuf, PlatformError> {
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| PlatformError::Message("HOME not set".into()))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("devicecryptor"))
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| PlatformError::Message("LOCALAPPDATA not set".into()))?;
        Ok(PathBuf::from(base).join("DeviceCryptor").join("state"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(PlatformError::Unsupported("mount state"))
    }
}

/// What this build can do. Not a distro certification.
pub fn platform_report() -> Vec<&'static str> {
    #[cfg(target_os = "linux")]
    {
        vec![
            "os: linux",
            "container-create: yes",
            "mount-fat-checkout: yes",
            "mount-fat-fuse: yes",
            "mount-ext4-loop: root-only",
            "system-encryption: no",
            "macos-mount: no",
            "windows-mount: no",
        ]
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![
            "os: other",
            "container-create: yes",
            "mount-fat-checkout: no",
            "mount-fat-fuse: no",
            "mount-ext4-loop: no",
            "system-encryption: no",
            "macos-mount: no",
            "windows-mount: no",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::platform_report;

    #[test]
    fn report_refuses_system_encryption() {
        let lines = platform_report();
        assert!(lines.contains(&"system-encryption: no"));
        #[cfg(target_os = "linux")]
        assert!(lines.contains(&"mount-fat-checkout: yes"));
        #[cfg(target_os = "linux")]
        assert!(lines.contains(&"mount-fat-fuse: yes"));
    }
}
