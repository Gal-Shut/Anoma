//! Ed25519 keys and related functionality

use std::convert::TryInto;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Write};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek::SignatureError;
use ed25519_dalek::{ExpandedSecretKey, Signer, Verifier};
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::proto::Tx;
use crate::types::address::{self, Address};
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::key::sigscheme::{SigScheme, TryFromRef, IntoRef, SignedTxData};

const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Ed25519 public key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(ed25519_dalek::PublicKey);

/// Ed25519 secret key
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey(ed25519_dalek::SecretKey);

/// Ed25519 keypair
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Keypair {
    /// Secret key
    pub secret: SecretKey,
    /// Public key
    pub public: PublicKey,
}

/// Ed25519 signature
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature(ed25519_dalek::Signature);

/// Ed25519 public key hash
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct PublicKeyHash(pub(crate) String);

const PKH_HASH_LEN: usize = address::HASH_LEN;
const PK_STORAGE_KEY: &str = "ed25519_pk";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VerifySigError {
    #[error("Signature verification failed: {0}")]
    SigError(SignatureError),
    #[error("Signature verification failed to encode the data: {0}")]
    EncodingError(std::io::Error),
    #[error("Transaction doesn't have any data with a signature.")]
    MissingData,
}

impl IntoRef<[u8]> for Keypair {
    /// Convert this keypair to bytes.
    fn into_ref<'a>(&self, bytes: &'a mut [u8]) -> &'a mut [u8] {
        bytes[..ed25519_dalek::SECRET_KEY_LENGTH]
            .copy_from_slice(self.secret.0.as_bytes());
        bytes[ed25519_dalek::SECRET_KEY_LENGTH..]
            .copy_from_slice(self.public.0.as_bytes());
        bytes
    }
}

impl TryFromRef<[u8]> for Keypair {
    type Error = SignatureError;
    /// Construct a `Keypair` from the bytes of a `PublicKey` and `SecretKey`.
    /// Wrapper for [`ed25519_dalek::Keypair::from_bytes`].
    fn try_from_ref(bytes: &[u8]) -> Result<Keypair, SignatureError> {
        let keypair = ed25519_dalek::Keypair::from_bytes(bytes)?;
        Ok(keypair.into())
    }
}

impl PublicKey {
    /// Construct a PublicKey from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        let pk = ed25519_dalek::PublicKey::from_bytes(bytes)?;
        Ok(pk.into())
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 public key: {}", e),
                )
            })?;
        ed25519_dalek::PublicKey::from_bytes(&bytes)
            .map(PublicKey)
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 public key: {}", e),
                )
            })
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the key to bytes first..
        let vec = self.0.as_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec
            .try_to_vec()
            .expect("Public key bytes encoding shouldn't fail");
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 secret key: {}", e),
                )
            })?;
        ed25519_dalek::SecretKey::from_bytes(&bytes)
            .map(SecretKey)
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 secret key: {}", e),
                )
            })
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the key to bytes first..
        let vec = self.0.as_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec
            .try_to_vec()
            .expect("Secret key bytes encoding shouldn't fail");
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 signature: {}", e),
                )
            })?;
        // convert them to an expected size array
        let bytes: [u8; SIGNATURE_LEN] = bytes[..].try_into().map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding ed25519 signature: {}", e),
            )
        })?;
        let sig = ed25519_dalek::ed25519::signature::Signature::from_bytes(
            &bytes[..SIGNATURE_LEN],
        )
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Error creating ed25509 signature from bytes: {}", err),
            )
        })?;
        Ok(Signature(sig))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the signature to bytes first..
        let vec = self.0.to_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec
            .try_to_vec()
            .expect("Signature bytes encoding shouldn't fail");
        writer.write_all(&bytes)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.try_to_vec()
            .expect("Encoding public key shouldn't fail")
            .hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.try_to_vec()
            .expect("Encoding public key shouldn't fail")
            .partial_cmp(
                &other
                    .try_to_vec()
                    .expect("Encoding public key shouldn't fail"),
            )
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.try_to_vec()
            .expect("Encoding public key shouldn't fail")
            .cmp(
                &other
                    .try_to_vec()
                    .expect("Encoding public key shouldn't fail"),
            )
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vec = self
            .try_to_vec()
            .expect("Encoding public key shouldn't fail");
        write!(f, "{}", hex::encode(&vec))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParsePublicKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParsePublicKeyError {
    #[error("Invalid public key hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid public key encoding: {0}")]
    InvalidEncoding(std::io::Error),
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vec = self
            .try_to_vec()
            .expect("Encoding secret key shouldn't fail");
        write!(f, "{}", hex::encode(&vec))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParseSecretKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseSecretKeyError {
    #[error("Invalid secret key hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid secret key encoding: {0}")]
    InvalidEncoding(std::io::Error),
}

impl Display for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vec = self.try_to_vec().expect("Encoding keypair shouldn't fail");
        write!(f, "{}", hex::encode(&vec))
    }
}

impl FromStr for Keypair {
    type Err = ParseKeypairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParseKeypairError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseKeypairError::InvalidEncoding)
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseKeypairError {
    #[error("Invalid keypair hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid keypair encoding: {0}")]
    InvalidEncoding(std::io::Error),
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.try_to_vec()
            .expect("Encoding signature for hash shouldn't fail")
            .hash(state);
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.try_to_vec()
            .expect("Encoding signature shouldn't fail")
            .partial_cmp(
                &other
                    .try_to_vec()
                    .expect("Encoding signature shouldn't fail"),
            )
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(pk: ed25519_dalek::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PublicKey> for ed25519_dalek::PublicKey {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl PublicKeyHash {
    fn from_public_key(pk: &PublicKey) -> Self {
        let pk_bytes =
            pk.try_to_vec().expect("Public key encoding shouldn't fail");
        let mut hasher = Sha256::new();
        hasher.update(pk_bytes);
        // hex of the first 40 chars of the hash
        Self(format!(
            "{:.width$X}",
            hasher.finalize(),
            width = PKH_HASH_LEN
        ))
    }
}

impl From<PublicKeyHash> for String {
    fn from(pkh: PublicKeyHash) -> Self {
        pkh.0
    }
}

impl Display for PublicKeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PublicKeyHash {
    type Err = PkhFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PKH_HASH_LEN {
            return Err(Self::Err::UnexpectedLen(s.len()));
        }
        Ok(Self(s.to_owned()))
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum PkhFromStringError {
    #[error("Wrong PKH len. Expected {PKH_HASH_LEN}, got {0}")]
    UnexpectedLen(usize),
}

impl From<PublicKey> for PublicKeyHash {
    fn from(pk: PublicKey) -> Self {
        Self::from_public_key(&pk)
    }
}

impl From<&PublicKey> for PublicKeyHash {
    fn from(pk: &PublicKey) -> Self {
        Self::from_public_key(pk)
    }
}

impl From<ed25519_dalek::SecretKey> for SecretKey {
    fn from(sk: ed25519_dalek::SecretKey) -> Self {
        Self(sk)
    }
}

impl From<SecretKey> for ed25519_dalek::SecretKey {
    fn from(sk: SecretKey) -> Self {
        sk.0
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Self(sig)
    }
}

impl From<Signature> for ed25519_dalek::Signature {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl From<ed25519_dalek::Keypair> for Keypair {
    fn from(keypair: ed25519_dalek::Keypair) -> Self {
        Self {
            secret: keypair.secret.into(),
            public: keypair.public.into(),
        }
    }
}

impl From<Keypair> for ed25519_dalek::Keypair {
    fn from(keypair: Keypair) -> Self {
        Self {
            secret: keypair.secret.into(),
            public: keypair.public.into(),
        }
    }
}

impl Signer<Signature> for Keypair {
    /// Sign a message with this keypair's secret key.
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        let expanded: ExpandedSecretKey = (&self.secret.0).into();
        Ok(expanded.sign(message, &self.public.0).into())
    }
}

impl Verifier<Signature> for Keypair {
    /// Verify a signature on a message with this keypair's public key.
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        self.public.0.verify(message, &signature.0)
    }
}

impl Verifier<Signature> for PublicKey {
    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        self.0.verify(message, &signature.0)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ed25519_dalek::ed25519::signature::Signature for Signature {
    fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, ed25519_dalek::ed25519::signature::Error> {
        let sig: ed25519_dalek::Signature = bytes.try_into()?;
        Ok(sig.into())
    }
}

/// An implementation of the Ed25519 signature scheme
#[derive(Debug, Clone)]
pub struct Ed25519Scheme;

impl SigScheme for Ed25519Scheme {
    type Signature = Signature;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Keypair = Keypair;
    type VerifyError = VerifySigError;

    const KEYPAIR_LENGTH:usize = ed25519_dalek::KEYPAIR_LENGTH;

    fn pk_key(owner: &Address) -> Key {
        Key::from(owner.to_db_key())
            .push(&PK_STORAGE_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    fn is_pk_key(key: &Key) -> Option<&Address> {
        match &key.segments[..] {
            [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
                if key == PK_STORAGE_KEY =>
            {
                Some(owner)
            }
            _ => None,
        }
    }

    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + RngCore,
    {
        ed25519_dalek::Keypair::generate(csprng).into()
    }

    fn sign(keypair: &Keypair, data: impl AsRef<[u8]>) -> Self::Signature {
        keypair.sign(data.as_ref())
    }

    fn verify_signature<T: BorshSerialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        let bytes = data.try_to_vec().map_err(VerifySigError::EncodingError)?;
        pk.0.verify_strict(&bytes, &sig.0)
            .map_err(VerifySigError::SigError)
    }

    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        pk.0.verify_strict(data, &sig.0)
            .map_err(VerifySigError::SigError)
    }

    fn sign_tx(keypair: &Keypair, tx: Tx) -> Tx {
        let to_sign = tx.to_bytes();
        let sig = Self::sign(keypair, &to_sign);
        let signed = SignedTxData::<Self> { data: tx.data, sig }
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail");
        Tx {
            code: tx.code,
            data: Some(signed),
            timestamp: tx.timestamp,
        }
    }

    fn verify_tx_sig(
        pk: &Self::PublicKey,
        tx: &Tx,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        // Try to get the transaction data from decoded `SignedTxData`
        let tx_data = tx.data.clone().ok_or(VerifySigError::MissingData)?;
        let signed_tx_data = SignedTxData::<Self>::try_from_slice(&tx_data[..])
            .expect("Decoding transaction data shouldn't fail");
        let data = signed_tx_data.data;
        let tx = Tx {
            code: tx.code.clone(),
            data,
            timestamp: tx.timestamp,
        };
        let signed_data = tx.to_bytes();
       Self:: verify_signature_raw(pk, &signed_data, sig)
    }
}

/// Run `cargo test gen_keypair -- --nocapture` to generate a keypair.
#[cfg(test)]
#[test]
fn gen_keypair() {
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    let mut rng: ThreadRng = thread_rng();
    let keypair = Ed25519Scheme::generate(&mut rng);
    println!("keypair {:?}", keypair.into_ref(&mut [0; Ed25519Scheme::KEYPAIR_LENGTH]));
}

/// Helpers for testing with keys.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;
    use rand::prelude::{StdRng, ThreadRng};
    use rand::{thread_rng, SeedableRng};

    use super::*;

    /// A keypair for tests
    pub fn keypair_1() -> Keypair {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            33, 82, 91, 186, 100, 168, 220, 158, 185, 140, 63, 172, 3, 88, 52,
            113, 94, 30, 213, 84, 175, 184, 235, 169, 70, 175, 36, 252, 45,
            190, 138, 79, 210, 187, 198, 90, 69, 83, 156, 77, 199, 63, 208, 63,
            137, 102, 22, 229, 110, 195, 38, 174, 142, 127, 157, 224, 139, 212,
            239, 204, 58, 80, 108, 184,
        ];
        ed25519_dalek::Keypair::from_bytes(&bytes).unwrap().into()
    }

    /// A keypair for tests
    pub fn keypair_2() -> Keypair {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            27, 238, 157, 32, 131, 242, 184, 142, 146, 189, 24, 249, 68, 165,
            205, 71, 213, 158, 25, 253, 52, 217, 87, 52, 171, 225, 110, 131,
            238, 58, 94, 56, 218, 133, 189, 80, 14, 157, 68, 124, 151, 37, 127,
            173, 117, 91, 248, 234, 34, 13, 77, 148, 10, 75, 30, 191, 172, 85,
            175, 8, 36, 233, 18, 203,
        ];
        ed25519_dalek::Keypair::from_bytes(&bytes).unwrap().into()
    }

    /// Generate an arbitrary [`Keypair`].
    pub fn arb_keypair() -> impl Strategy<Value = Keypair> {
        any::<[u8; 32]>().prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            ed25519_dalek::Keypair::generate(&mut rng).into()
        })
    }

    /// Generate a new random [`Keypair`].
    pub fn gen_keypair() -> Keypair {
        let mut rng: ThreadRng = thread_rng();
        Ed25519Scheme::generate(&mut rng)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Run `cargo test gen_keypair -- --nocapture` to generate a
    /// new keypair.
    #[test]
    fn gen_keypair() {
        let keypair = testing::gen_keypair();
        let public_key: PublicKey = keypair.public;
        let secret_key: SecretKey = keypair.secret;
        println!("Public key: {}", public_key);
        println!("Secret key: {}", secret_key);
    }
}
