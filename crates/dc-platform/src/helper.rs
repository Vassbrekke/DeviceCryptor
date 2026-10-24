//! Root dm-crypt helper.
//!
//! `dc attach` unlocks a header, then sends one frame to `dc helper` on a pipe.
//! The frame holds the master key, never the password, and never uses argv.
//! `dc helper` is the only path that execs cryptsetup. It does so only as root,
//! and only after `lstat` shows a real block device.

use std::fs::symlink_metadata;
use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::{Zeroize, Zeroizing};

use crate::{is_elevated, validate_helper_request, PlatformError};

const FRAME_MAGIC: &[u8; 4] = b"DCH1";
const FRAME_MAX: usize = 1024;

/// AES-256-XTS plain mapping. Cascades are not handed to the kernel.
pub struct DmPlainRequest {
    pub device: String,
    pub mapper: String,
    pub sector_size: u32,
    pub data_offset: u64,
    pub data_length: u64,
    /// cryptsetup `--skip`. 0 for DC01 (IV restarts at the data area).
    /// Equal to `data_offset / 512` for VeraCrypt (IV is the host sector).
    pub iv_skip_512: u64,
    pub key: Zeroizing<Vec<u8>>,
}

pub fn cryptsetup_argv(req: &DmPlainRequest) -> Result<Vec<String>, PlatformError> {
    check_fields(req)?;
    let offset = req.data_offset / 512;
    let size = req.data_length / 512;
    Ok(vec![
        "--batch-mode".into(),
        "open".into(),
        "--type".into(),
        "plain".into(),
        "--cipher".into(),
        "aes-xts-plain64".into(),
        "--key-size".into(),
        "512".into(),
        "--key-file=-".into(),
        "--offset".into(),
        offset.to_string(),
        "--skip".into(),
        req.iv_skip_512.to_string(),
        "--size".into(),
        size.to_string(),
        "--sector-size".into(),
        "512".into(),
        "--".into(),
        req.device.clone(),
        req.mapper.clone(),
    ])
}

fn check_fields(req: &DmPlainRequest) -> Result<(), PlatformError> {
    validate_helper_request(&req.device, &req.mapper)?;
    if req.device.len() <= 5 || req.device.ends_with('/') {
        return Err(PlatformError::Message(
            "device must be a /dev node, not /dev itself".into(),
        ));
    }
    if req.sector_size != 512 {
        return Err(PlatformError::Message(
            "dm helper accepts 512-byte sectors only".into(),
        ));
    }
    if req.key.len() != 64 {
        return Err(PlatformError::Message(
            "dm helper accepts a 64-byte AES-256-XTS key only".into(),
        ));
    }
    if req.data_offset < 512 || req.data_offset % 512 != 0 {
        return Err(PlatformError::Message(
            "data offset must be a positive multiple of 512".into(),
        ));
    }
    if req.data_length < 512 || req.data_length % 512 != 0 {
        return Err(PlatformError::Message(
            "data length must be a positive multiple of 512".into(),
        ));
    }
    let absolute = req.data_offset / 512;
    if req.iv_skip_512 != 0 && req.iv_skip_512 != absolute {
        return Err(PlatformError::Message(
            "IV skip must be 0 (DC01) or the data offset in 512-byte sectors (VeraCrypt)".into(),
        ));
    }
    Ok(())
}

pub fn encode_frame(req: &DmPlainRequest) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    check_fields(req)?;
    let dev = req.device.as_bytes();
    let map = req.mapper.as_bytes();
    if dev.len() > 255 || map.len() > 64 {
        return Err(PlatformError::Message(
            "device or mapper is too long".into(),
        ));
    }
    let mut body = Vec::with_capacity(48 + dev.len() + map.len() + req.key.len());
    body.extend_from_slice(FRAME_MAGIC);
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&req.sector_size.to_le_bytes());
    body.extend_from_slice(&req.data_offset.to_le_bytes());
    body.extend_from_slice(&req.data_length.to_le_bytes());
    body.extend_from_slice(&req.iv_skip_512.to_le_bytes());
    body.push(dev.len() as u8);
    body.push(map.len() as u8);
    body.push(req.key.len() as u8);
    body.extend_from_slice(dev);
    body.extend_from_slice(map);
    body.extend_from_slice(&req.key);
    if body.len() > FRAME_MAX {
        body.zeroize();
        return Err(PlatformError::Message("helper frame is too large".into()));
    }
    Ok(Zeroizing::new(body))
}

pub fn decode_frame(buf: &[u8]) -> Result<DmPlainRequest, PlatformError> {
    if buf.len() < 4 + 2 + 4 + 8 + 8 + 8 + 3 || buf.len() > FRAME_MAX {
        return Err(PlatformError::Message(
            "helper frame has a bad length".into(),
        ));
    }
    if &buf[0..4] != FRAME_MAGIC {
        return Err(PlatformError::Message(
            "helper frame has a bad magic".into(),
        ));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != 1 {
        return Err(PlatformError::Message(
            "helper frame version is not 1".into(),
        ));
    }
    let sector_size = u32::from_le_bytes(buf[6..10].try_into().unwrap());
    let data_offset = u64::from_le_bytes(buf[10..18].try_into().unwrap());
    let data_length = u64::from_le_bytes(buf[18..26].try_into().unwrap());
    let iv_skip_512 = u64::from_le_bytes(buf[26..34].try_into().unwrap());
    let dev_len = buf[34] as usize;
    let map_len = buf[35] as usize;
    let key_len = buf[36] as usize;
    let rest = &buf[37..];
    if rest.len() != dev_len + map_len + key_len {
        return Err(PlatformError::Message("helper frame is truncated".into()));
    }
    let device = std::str::from_utf8(&rest[..dev_len])
        .map_err(|_| PlatformError::Message("device path is not utf-8".into()))?
        .to_string();
    let mapper = std::str::from_utf8(&rest[dev_len..dev_len + map_len])
        .map_err(|_| PlatformError::Message("mapper name is not utf-8".into()))?
        .to_string();
    let mut key = rest[dev_len + map_len..].to_vec();
    let req = DmPlainRequest {
        device,
        mapper,
        sector_size,
        data_offset,
        data_length,
        iv_skip_512,
        key: Zeroizing::new(std::mem::take(&mut key)),
    };
    check_fields(&req)?;
    Ok(req)
}

/// Exec cryptsetup. Returns before that if the path is not a block device or the process is not root.
pub fn apply_dm_plain(req: &DmPlainRequest) -> Result<(), PlatformError> {
    let args = cryptsetup_argv(req)?;
    if !is_block_device(&req.device)? {
        return Err(PlatformError::Message(
            "device must be a block device, not a symlink".into(),
        ));
    }
    if !is_elevated() {
        return Err(PlatformError::Message("dm helper must be root".into()));
    }
    let mut child = Command::new("cryptsetup")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PlatformError::Message(format!("cryptsetup: {e}")))?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| PlatformError::Message("cryptsetup stdin".into()))?;
    input
        .write_all(req.key.as_slice())
        .map_err(|e| PlatformError::Message(format!("cryptsetup stdin: {e}")))?;
    drop(input);
    let output = child
        .wait_with_output()
        .map_err(|e| PlatformError::Message(format!("cryptsetup: {e}")))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let err = err.trim();
        return Err(PlatformError::Message(format!("cryptsetup failed: {err}")));
    }
    Ok(())
}

fn is_block_device(path: &str) -> Result<bool, PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let meta = symlink_metadata(path)?;
        let kind = meta.file_type();
        Ok(!kind.is_symlink() && kind.is_block_device())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(PlatformError::Unsupported("block devices"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(iv: u64) -> DmPlainRequest {
        DmPlainRequest {
            device: "/dev/sdz9".into(),
            mapper: "dcroot".into(),
            sector_size: 512,
            data_offset: 131_072,
            data_length: 1024 * 1024,
            iv_skip_512: iv,
            key: Zeroizing::new(vec![7u8; 64]),
        }
    }

    #[test]
    fn frame_roundtrip_hides_the_key_from_argv() {
        let req = sample(0);
        let frame = encode_frame(&req).unwrap();
        let args = cryptsetup_argv(&req).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("--key-file=-"));
        assert!(joined.contains("--skip 0"));
        assert!(joined.contains("--offset 256"));
        assert_eq!(args[args.len() - 2], "/dev/sdz9");
        assert_eq!(args[args.len() - 1], "dcroot");
        assert!(!joined.contains('\u{7}'));
        let back = decode_frame(&frame).unwrap();
        assert_eq!(back.key.as_slice(), req.key.as_slice());
        assert_eq!(back.iv_skip_512, 0);
    }

    #[test]
    fn veracrypt_iv_skip_matches_the_host_sector() {
        let req = sample(131_072 / 512);
        let args = cryptsetup_argv(&req).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("--skip 256"));
    }

    #[test]
    fn rejects_a_short_key_a_bad_iv_and_a_dotdot_device() {
        let mut req = sample(0);
        req.key = Zeroizing::new(vec![1u8; 32]);
        assert!(encode_frame(&req).is_err());
        let mut req = sample(3);
        assert!(cryptsetup_argv(&req).is_err());
        req = sample(0);
        req.device = "/dev/../etc/passwd".into();
        assert!(cryptsetup_argv(&req).is_err());
    }

    #[test]
    fn apply_refuses_a_char_device_before_cryptsetup() {
        let mut req = sample(0);
        req.device = "/dev/null".into();
        let err = apply_dm_plain(&req).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("block device"), "{msg}");
    }
}
