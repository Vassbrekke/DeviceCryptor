#![no_main]
use dc_format::dc01::{open_dc01_header, Dc01OpenOptions};
use dc_format::veracrypt::{try_open_veracrypt_header, VeraCryptOpenOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }
    let header = &data[..512];
    let pw = b"fuzz";
    let _ = open_dc01_header(
        header,
        &Dc01OpenOptions {
            password: pw,
            keyfiles: &[],
        },
    );
    let _ = try_open_veracrypt_header(
        header,
        &VeraCryptOpenOptions {
            password: pw,
            keyfiles: &[],
            pim: 0,
            prf: None,
        },
    );
});
