#![no_main]
use dc_crypto::SALT_SIZE;
use dc_format::dc01::{parse_dc01_payload, DC01_EFFECTIVE};
use dc_format::veracrypt::{parse_header, VC_HEADER_EFFECTIVE};
use libfuzzer_sys::fuzz_target;

// Decrypted header bytes only. No password KDF.
fuzz_target!(|data: &[u8]| {
    if data.len() >= DC01_EFFECTIVE - SALT_SIZE + 12 {
        let mut payload = [0u8; DC01_EFFECTIVE - SALT_SIZE];
        payload.copy_from_slice(&data[..DC01_EFFECTIVE - SALT_SIZE]);
        let rest = &data[DC01_EFFECTIVE - SALT_SIZE..];
        let time = u32::from_le_bytes(rest[0..4].try_into().unwrap());
        let mem = u32::from_le_bytes(rest[4..8].try_into().unwrap());
        let par = u32::from_le_bytes(rest[8..12].try_into().unwrap());
        let _ = parse_dc01_payload(&payload, time, mem, par);
    }
    if data.len() >= VC_HEADER_EFFECTIVE - SALT_SIZE {
        let mut payload = [0u8; VC_HEADER_EFFECTIVE - SALT_SIZE];
        payload.copy_from_slice(&data[..VC_HEADER_EFFECTIVE - SALT_SIZE]);
        let _ = parse_header(&payload);
    }
});
