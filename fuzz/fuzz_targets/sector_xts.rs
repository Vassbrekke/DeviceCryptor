#![no_main]
use dc_crypto::Aes256Xts;
use libfuzzer_sys::fuzz_target;

// Sector encrypt/decrypt only. No password KDF.
fuzz_target!(|data: &[u8]| {
    if data.len() < 80 {
        return;
    }
    let mut key = [0u8; 64];
    key.copy_from_slice(&data[..64]);
    let Ok(xts) = Aes256Xts::new(&key) else {
        return;
    };
    let sector = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let body = &data[72..];
    let n = body.len() - (body.len() % 16);
    if n == 0 {
        let mut bad = body.to_vec();
        let _ = xts.encrypt_sector(sector, &mut bad);
        return;
    }
    let mut buf = body[..n].to_vec();
    let orig = buf.clone();
    if xts.encrypt_sector(sector, &mut buf).is_err() {
        return;
    }
    if xts.decrypt_sector(sector, &mut buf).is_err() {
        return;
    }
    assert_eq!(buf, orig);
});
