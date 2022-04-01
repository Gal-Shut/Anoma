use bech32::Variant;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Error decoding from Bech32m: {0}")]
    DecodeBech32(bech32::Error),
    #[error("Error decoding from base32: {0}")]
    DecodeBase32(bech32::Error),
    #[error("Unexpected Bech32m human-readable part {0}, expected {1}")]
    UnexpectedBech32Prefix(String, String),
    #[error("Unexpected Bech32m variant {0:?}, expected {VARIANT:?}")]
    UnexpectedBech32Variant(bech32::Variant),
    #[error("Invalid inner encoding")]
    InvalidInnerEncoding(std::io::Error),
}

/// Result of a function that may fail
pub type DecodeResult<T> = std::result::Result<T, DecodeError>;

/// We're using "Bech32m" variant
pub const VARIANT: bech32::Variant = Variant::Bech32m;
