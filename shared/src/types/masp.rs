//! MASP types

use std::fmt::Display;
use std::str::FromStr;

use bech32::{FromBase32, ToBase32};

use crate::bech32m;

/// human-readable part of Bech32m encoded address
// TODO use "a" for live network
const FULL_VIEWING_KEY_HRP: &str = "fvktest";
const PAYMENT_ADDRESS_HRP: &str = "patest";

pub struct FullViewingKey(masp_primitives::keys::FullViewingKey);

pub struct PaymentAddress(masp_primitives::primitives::PaymentAddress);

impl Display for FullViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0.to_bytes();
        let encoded = bech32::encode(
            FULL_VIEWING_KEY_HRP,
            bytes.to_base32(),
            bech32m::VARIANT,
        )
        .unwrap_or_else(|_| {
            panic!(
                "The human-readable part {} should never cause a failure",
                FULL_VIEWING_KEY_HRP
            )
        });
        writeln!(f, "{encoded}")
    }
}

impl FromStr for FullViewingKey {
    type Err = bech32m::DecodeError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        use bech32m::DecodeError;
        let (prefix, hash_base32, variant) =
            bech32::decode(string).map_err(DecodeError::DecodeBech32)?;
        if prefix != FULL_VIEWING_KEY_HRP {
            return Err(DecodeError::UnexpectedBech32Prefix(
                prefix,
                FULL_VIEWING_KEY_HRP.into(),
            ));
        }
        match variant {
            bech32m::VARIANT => {}
            _ => return Err(DecodeError::UnexpectedBech32Variant(variant)),
        }
        let bytes: Vec<u8> = FromBase32::from_base32(&hash_base32)
            .map_err(DecodeError::DecodeBase32)?;
        masp_primitives::keys::FullViewingKey::read(&mut &bytes[..])
            .map_err(DecodeError::InvalidInnerEncoding)
            .map(Self)
    }
}

impl From<FullViewingKey> for masp_primitives::keys::FullViewingKey {
    fn from(key: FullViewingKey) -> Self {
        key.0
    }
}

impl From<masp_primitives::keys::FullViewingKey> for FullViewingKey {
    fn from(key: masp_primitives::keys::FullViewingKey) -> Self {
        Self(key)
    }
}

impl From<PaymentAddress> for masp_primitives::primitives::PaymentAddress {
    fn from(addr: PaymentAddress) -> Self {
        addr.0
    }
}

impl From<masp_primitives::primitives::PaymentAddress> for PaymentAddress {
    fn from(addr: masp_primitives::primitives::PaymentAddress) -> Self {
        Self(addr)
    }
}
