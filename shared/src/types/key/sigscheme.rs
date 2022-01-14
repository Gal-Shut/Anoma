//! Ed25519 keys and related functionality

use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek::SignatureError;
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::storage::Key;

/// A value-to-value conversion that consumes the input value.

pub trait IntoRef<T> where T: ?Sized {
    /// Performs the conversion.
    fn into_ref<'a>(&self, slc: &'a mut T) -> &'a mut T;
}

/// Simple and safe type conversions that may fail in a controlled
/// way under some circumstances.

pub trait TryFromRef<T> : Sized where T: ?Sized {
    /// The type returned in the event of a conversion error.
    type Error;
    /// Performs the conversion.
    fn try_from_ref(value: &T) -> Result<Self, Self::Error>;
}

/// Represents a digital signature scheme. More precisely this trait captures
/// the concepts of public keys, private keys, and signatures as well as
/// the algorithms over these concepts to generate keys, sign messages, and
/// verify signatures.

pub trait SigScheme {
    /// Represents the signature for this scheme
    type Signature : Hash + PartialOrd + AsRef<[u8]> + ed25519_dalek::ed25519::signature::Signature;
    /// Represents the public key for this scheme
    type PublicKey : BorshSerialize + BorshDeserialize + Ord + Display +
        FromStr + PartialOrd + Hash;
    /// Represents the secret key for this scheme
    type SecretKey : BorshSerialize + BorshDeserialize + Display + FromStr;
    /// Represents the keypair for this scheme
    type Keypair : Display + FromStr + IntoRef<[u8]> + TryFromRef<[u8]>;
    /// Represents an error in signature verification
    type VerifyError;
    /// The length of Keypairs in bytes
    const KEYPAIR_LENGTH: usize;
    /// Obtain a storage key for user's public key.
    fn pk_key(owner: &Address) -> Key;
    /// Check if the given storage key is a public key. If it is, returns the owner.
    fn is_pk_key(key: &Key) -> Option<&Address>;
    /// Generate an ed25519 keypair.
    /// Wrapper for [`ed25519_dalek::Keypair::generate`].
    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R) -> Self::Keypair
    where R: CryptoRng + RngCore;
    /// Sign the data with a key.
    fn sign(keypair: &Self::Keypair, data: impl AsRef<[u8]>) -> Self::Signature;
    /// Check that the public key matches the signature on the given data.
    fn verify_signature<T: BorshSerialize + BorshDeserialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), Self::VerifyError>;
    /// Check that the public key matches the signature on the given raw data.
    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), Self::VerifyError>;
    /// Sign a transaction using [`SignedTxData`].
    fn sign_tx(keypair: &Self::Keypair, tx: Tx) -> Tx;
    /// Verify that the transaction has been signed by the secret key
    /// counterpart of the given public key.
    fn verify_tx_sig(
        pk: &Self::PublicKey,
        tx: &Tx,
        sig: &Self::Signature,
    ) -> Result<(), Self::VerifyError>;
}

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which is can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedTxData<S: SigScheme> {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: S::Signature,
}

/// A generic signed data wrapper for Borsh encode-able data.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Signed<S: SigScheme, T: BorshSerialize + BorshDeserialize> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sig: S::Signature,
}

impl<S, T> PartialEq for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.sig == other.sig
    }
}

impl<S, T> Eq for Signed<S, T> where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + Eq + PartialEq
{
}

impl<S, T> Hash for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.sig.hash(state);
    }
}

impl<S, T> PartialOrd for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<S, T> Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize,
{
    /// Initialize a new signed data.
    pub fn new(keypair: &S::Keypair, data: T) -> Self {
        let to_sign = data
            .try_to_vec()
            .expect("Encoding data for signing shouldn't fail");
        let sig = S::sign(keypair, &to_sign);
        Self { data, sig }
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(&self, pk: &S::PublicKey) -> Result<(), S::VerifyError> {
        let bytes = self
            .data
            .try_to_vec()
            .expect("Encoding data for verifying signature shouldn't fail");
        S::verify_signature_raw(pk, &bytes, &self.sig)
    }
}

