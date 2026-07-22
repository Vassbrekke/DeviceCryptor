//! Volume header formats: DC01 (native) and VeraCrypt v5 (compat).

pub mod dc01;
pub mod veracrypt;

pub use dc01::{
    create_dc01_header, create_dc01_header_at, open_dc01_header, Dc01Header, Dc01OpenOptions,
    DC01_MAGIC, DC01_VERSION,
};
pub use veracrypt::{
    try_open_veracrypt_header, VeraCryptHeader, VeraCryptOpenOptions, VC_DATA_OFFSET,
    VC_HEADER_EFFECTIVE, VC_HEADER_SLOT, VC_MAGIC,
};

pub const HEADER_SLOT_SIZE: u64 = 65_536;
pub const HIDDEN_HEADER_OFFSET: u64 = 65_536;
pub const DATA_OFFSET: u64 = 131_072;
