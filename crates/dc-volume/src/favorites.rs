use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::VolumeError;
use dc_platform::{ensure_parent_dir, favorites_path};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Favorite {
    pub path: PathBuf,
    pub label: String,
    pub automount: bool,
}

pub fn list_favorites() -> Result<Vec<Favorite>, VolumeError> {
    let path = favorites_path().map_err(|e| VolumeError::Platform(e.to_string()))?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path)?;
    let list: Vec<Favorite> =
        serde_json::from_str(&data).map_err(|e| VolumeError::Format(e.to_string()))?;
    Ok(list)
}

pub fn add_favorite(fav: Favorite) -> Result<(), VolumeError> {
    let path = favorites_path().map_err(|e| VolumeError::Platform(e.to_string()))?;
    ensure_parent_dir(&path).map_err(|e| VolumeError::Platform(e.to_string()))?;
    let mut list = list_favorites()?;
    list.retain(|f| f.path != fav.path);
    list.push(fav);
    let data =
        serde_json::to_string_pretty(&list).map_err(|e| VolumeError::Format(e.to_string()))?;
    std::fs::write(path, data)?;
    Ok(())
}

pub fn remove_favorite(container: &Path) -> Result<(), VolumeError> {
    let path = favorites_path().map_err(|e| VolumeError::Platform(e.to_string()))?;
    let mut list = list_favorites()?;
    list.retain(|f| f.path != container);
    if path.exists() {
        let data =
            serde_json::to_string_pretty(&list).map_err(|e| VolumeError::Format(e.to_string()))?;
        std::fs::write(path, data)?;
    }
    Ok(())
}
