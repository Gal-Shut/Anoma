//! The merkle tree in the storage

use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ics23::{CommitmentProof, ProofSpec};
use prost::Message;
use sha2::{Digest, Sha256};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::error::Error as SmtError;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};
#[cfg(not(feature = "ABCI"))]
use tendermint::merkle::proof::{Proof, ProofOp};
#[cfg(feature = "ABCI")]
use tendermint_stable::merkle::proof::{Proof, ProofOp};
use thiserror::Error;

use crate::bytes::ByteBuf;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{DbKeySeg, Error as StorageError, Key};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key: {0}")]
    InvalidKey(StorageError),
    #[error("Empty Key: {0}")]
    EmptyKey(String),
    #[error("SMT error: {0}")]
    Smt(SmtError),
    #[error("Invalid store type: {0}")]
    StoreType(String),
}

/// Result for functions that may fail
type Result<T> = std::result::Result<T, Error>;

/// Store types for the merkle tree
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum StoreType {
    /// Base tree, which has roots of the subtrees
    Base,
    /// For Account and other data
    Account,
    /// For IBC-related data
    Ibc,
    /// For PoS-related data
    PoS,
}

impl StoreType {
    /// Get an iterator for the base tree and subtrees
    pub fn iter() -> std::slice::Iter<'static, Self> {
        static SUB_TREE_TYPES: [StoreType; 4] = [
            StoreType::Base,
            StoreType::Account,
            StoreType::PoS,
            StoreType::Ibc,
        ];
        SUB_TREE_TYPES.iter()
    }

    fn sub_key(key: &Key) -> Result<(Self, Key)> {
        if key.is_empty() {
            return Err(Error::EmptyKey("the key is empty".to_owned()));
        }
        match key.segments.get(0) {
            Some(DbKeySeg::AddressSeg(Address::Internal(internal))) => {
                match internal {
                    InternalAddress::PoS | InternalAddress::PosSlashPool => {
                        Ok((StoreType::PoS, key.sub_key()?))
                    }
                    InternalAddress::Ibc => {
                        Ok((StoreType::Ibc, key.sub_key()?))
                    }
                    // use the same key for Parameters
                    _ => Ok((StoreType::Account, key.clone())),
                }
            }
            // use the same key for Account
            _ => Ok((StoreType::Account, key.clone())),
        }
    }
}

impl FromStr for StoreType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "base" => Ok(StoreType::Base),
            "account" => Ok(StoreType::Account),
            "ibc" => Ok(StoreType::Ibc),
            "pos" => Ok(StoreType::PoS),
            _ => Err(Error::StoreType(s.to_string())),
        }
    }
}

impl fmt::Display for StoreType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreType::Base => write!(f, "base"),
            StoreType::Account => write!(f, "account"),
            StoreType::Ibc => write!(f, "ibc"),
            StoreType::PoS => write!(f, "pos"),
        }
    }
}

/// Merkle tree storage
#[derive(Default)]
pub struct MerkleTree<H: StorageHasher + Default> {
    base: SparseMerkleTree<H, H256, DefaultStore<H256>>,
    account: SparseMerkleTree<H, H256, DefaultStore<H256>>,
    ibc: SparseMerkleTree<H, H256, DefaultStore<H256>>,
    pos: SparseMerkleTree<H, H256, DefaultStore<H256>>,
}

impl<H: StorageHasher + Default> core::fmt::Debug for MerkleTree<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_hash = format!("{}", ByteBuf(self.base.root().as_slice()));
        f.debug_struct("MerkleTree")
            .field("root_hash", &root_hash)
            .finish()
    }
}

impl<H: StorageHasher + Default> MerkleTree<H> {
    /// Restore the tree from the stores
    pub fn new(stores: MerkleTreeStoresRead) -> Self {
        let base = SparseMerkleTree::new(stores.base.0, stores.base.1);
        let account = SparseMerkleTree::new(stores.account.0, stores.account.1);
        let ibc = SparseMerkleTree::new(stores.ibc.0, stores.ibc.1);
        let pos = SparseMerkleTree::new(stores.pos.0, stores.pos.1);

        Self {
            base,
            account,
            ibc,
            pos,
        }
    }

    fn tree(
        &self,
        store_type: &StoreType,
    ) -> &SparseMerkleTree<H, H256, DefaultStore<H256>> {
        match store_type {
            StoreType::Base => &self.base,
            StoreType::Account => &self.account,
            StoreType::Ibc => &self.ibc,
            StoreType::PoS => &self.pos,
        }
    }

    fn update_tree(
        &mut self,
        store_type: &StoreType,
        key: H256,
        value: H256,
    ) -> Result<()> {
        let tree = match store_type {
            StoreType::Account => &mut self.account,
            StoreType::Ibc => &mut self.ibc,
            StoreType::PoS => &mut self.pos,
            // base tree should not be directly updated
            StoreType::Base => unreachable!(),
        };
        let sub_root = tree.update(key, value).map_err(Error::Smt)?;

        // update the base tree with the updated sub root without hashing
        if *store_type != StoreType::Base {
            let base_key = H::hash(&store_type.to_string());
            self.base.update(base_key, *sub_root)?;
        }
        Ok(())
    }

    /// Check if the key exists in the tree
    pub fn has_key(&self, key: &Key) -> Result<bool> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self.tree(&store_type);
        let value = subtree.get(&H::hash(sub_key.to_string()))?;
        Ok(!value.is_zero())
    }

    /// Update the tree with the given key and value
    pub fn update(&mut self, key: &Key, value: impl AsRef<[u8]>) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        self.update_tree(
            &store_type,
            H::hash(sub_key.to_string()),
            H::hash(value),
        )
    }

    /// Delete the value corresponding to the given key
    pub fn delete(&mut self, key: &Key) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        self.update_tree(
            &store_type,
            H::hash(sub_key.to_string()),
            H256::zero(),
        )
    }

    /// Get the root
    pub fn root(&self) -> MerkleRoot {
        (*self.base.root()).into()
    }

    /// Get the stores of the base and sub trees
    pub fn stores(&self) -> MerkleTreeStoresWrite {
        MerkleTreeStoresWrite {
            base: (self.base.root(), self.base.store()),
            account: (self.account.root(), self.account.store()),
            ibc: (self.ibc.root(), self.ibc.store()),
            pos: (self.pos.root(), self.pos.store()),
        }
    }

    /// Get the existence proof
    pub fn get_existence_proof(&self, key: &Key) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self.tree(&store_type);

        // Get a proof of the sub tree
        let hashed_sub_key = H::hash(&sub_key.to_string());
        let sub_proof = subtree.membership_proof(&hashed_sub_key)?;
        self.get_proof(key, sub_proof)
    }

    /// Get the non-existence proof
    pub fn get_non_existence_proof(&self, key: &Key) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self.tree(&store_type);

        // Get a proof of the sub tree
        let hashed_sub_key = H::hash(&sub_key.to_string());
        let sub_proof = subtree.non_membership_proof(&hashed_sub_key)?;
        self.get_proof(key, sub_proof)
    }

    /// Get the Tendermint proof with the base proof
    fn get_proof(
        &self,
        key: &Key,
        sub_proof: CommitmentProof,
    ) -> Result<Proof> {
        let mut data = vec![];
        sub_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let sub_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: key.to_string().as_bytes().to_vec(),
            data,
        };

        // Get a membership proof of the base tree because the sub root should
        // exist
        let (store_type, _) = StoreType::sub_key(key)?;
        let base_key = store_type.to_string();
        let base_proof = self.base.membership_proof(&H::hash(&base_key))?;

        let mut data = vec![];
        base_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let base_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: key.to_string().as_bytes().to_vec(),
            data,
        };

        // Set ProofOps from leaf to root
        Ok(Proof {
            ops: vec![sub_proof_op, base_proof_op],
        })
    }

    /// Get the proof specs
    pub fn proof_specs(&self) -> Vec<ProofSpec> {
        let spec = sparse_merkle_tree::proof_ics23::get_spec(H::hash_op());
        let sub_tree_spec = spec.clone();
        let base_tree_spec = spec;
        vec![sub_tree_spec, base_tree_spec]
    }
}

/// The root hash of the merkle tree as bytes
pub struct MerkleRoot(pub Vec<u8>);

impl From<H256> for MerkleRoot {
    fn from(root: H256) -> Self {
        Self(root.as_slice().to_vec())
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ByteBuf(&self.0))
    }
}

/// The root and store pairs to restore the trees
#[derive(Default)]
pub struct MerkleTreeStoresRead {
    base: (H256, DefaultStore<H256>),
    account: (H256, DefaultStore<H256>),
    ibc: (H256, DefaultStore<H256>),
    pos: (H256, DefaultStore<H256>),
}

impl MerkleTreeStoresRead {
    /// Set the root of the given store type
    pub fn set_root(&mut self, store_type: &StoreType, root: H256) {
        match store_type {
            StoreType::Base => self.base.0 = root,
            StoreType::Account => self.account.0 = root,
            StoreType::Ibc => self.ibc.0 = root,
            StoreType::PoS => self.pos.0 = root,
        }
    }

    /// Set the store of the given store type
    pub fn set_store(
        &mut self,
        store_type: &StoreType,
        store: DefaultStore<H256>,
    ) {
        match store_type {
            StoreType::Base => self.base.1 = store,
            StoreType::Account => self.account.1 = store,
            StoreType::Ibc => self.ibc.1 = store,
            StoreType::PoS => self.pos.1 = store,
        }
    }
}

/// The root and store pairs to be persistent
pub struct MerkleTreeStoresWrite<'a> {
    base: (&'a H256, &'a DefaultStore<H256>),
    account: (&'a H256, &'a DefaultStore<H256>),
    ibc: (&'a H256, &'a DefaultStore<H256>),
    pos: (&'a H256, &'a DefaultStore<H256>),
}

impl<'a> MerkleTreeStoresWrite<'a> {
    /// Get the root of the given store type
    pub fn root(&self, store_type: &StoreType) -> &H256 {
        match store_type {
            StoreType::Base => self.base.0,
            StoreType::Account => self.account.0,
            StoreType::Ibc => self.ibc.0,
            StoreType::PoS => self.pos.0,
        }
    }

    /// Get the store of the given store type
    pub fn store(&self, store_type: &StoreType) -> &DefaultStore<H256> {
        match store_type {
            StoreType::Base => self.base.1,
            StoreType::Account => self.account.1,
            StoreType::Ibc => self.ibc.1,
            StoreType::PoS => self.pos.1,
        }
    }
}

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: Hasher + Default {
    /// Hash the value to store
    fn hash(value: impl AsRef<[u8]>) -> H256;
}

/// The storage hasher used for the merkle tree.
#[derive(Default)]
pub struct Sha256Hasher(sparse_merkle_tree::sha256::Sha256Hasher);

impl Hasher for Sha256Hasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.write_h256(h)
    }

    fn finish(self) -> H256 {
        self.0.finish()
    }

    fn hash_op() -> ics23::HashOp {
        sparse_merkle_tree::sha256::Sha256Hasher::hash_op()
    }
}

impl StorageHasher for Sha256Hasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(value.as_ref());
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .expect("Sha256 output conversion to fixed array shouldn't fail");
        bytes.into()
    }
}

impl fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hasher")
    }
}

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Error::InvalidKey(error)
    }
}

impl From<SmtError> for Error {
    fn from(error: SmtError) -> Self {
        Error::Smt(error)
    }
}

#[cfg(test)]
mod test {
    use ics23::commitment_proof::Proof as Ics23Proof;

    use super::*;
    use crate::types::storage::KeySeg;

    #[test]
    fn test_crud_value() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();
        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        assert!(!tree.has_key(&ibc_key).unwrap());
        assert!(!tree.has_key(&pos_key).unwrap());

        // update IBC tree
        tree.update(&ibc_key, [1u8; 8]).unwrap();
        assert!(tree.has_key(&ibc_key).unwrap());
        assert!(!tree.has_key(&pos_key).unwrap());
        // update another tree
        tree.update(&pos_key, [2u8; 8]).unwrap();
        assert!(tree.has_key(&pos_key).unwrap());

        // delete a value on IBC tree
        tree.delete(&ibc_key).unwrap();
        assert!(!tree.has_key(&ibc_key).unwrap());
        assert!(tree.has_key(&pos_key).unwrap());
    }

    #[test]
    fn test_restore_tree() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        tree.update(&ibc_key, [1u8; 8]).unwrap();
        tree.update(&pos_key, [2u8; 8]).unwrap();

        let stores_write = tree.stores();
        let mut stores_read = MerkleTreeStoresRead::default();
        for st in StoreType::iter() {
            stores_read.set_root(st, *stores_write.root(st));
            stores_read.set_store(st, stores_write.store(st).clone());
        }
        let restored_tree = MerkleTree::<Sha256Hasher>::new(stores_read);
        assert!(restored_tree.has_key(&ibc_key).unwrap());
        assert!(restored_tree.has_key(&pos_key).unwrap());
    }

    #[test]
    fn test_proof() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        let ibc_val = [1u8; 8].to_vec();
        tree.update(&ibc_key, ibc_val.clone()).unwrap();
        let pos_val = [2u8; 8].to_vec();
        tree.update(&pos_key, pos_val).unwrap();

        let specs = tree.proof_specs();
        let proof = tree.get_existence_proof(&ibc_key).unwrap();
        let (store_type, sub_key) = StoreType::sub_key(&ibc_key).unwrap();
        let paths = vec![sub_key.to_string(), store_type.to_string()];
        let mut sub_root = ibc_val.clone();
        let mut value = ibc_val;
        // First, the sub proof is verified. Next the base proof is verified
        // with the sub root
        for ((p, spec), key) in
            proof.ops.iter().zip(specs.iter()).zip(paths.iter())
        {
            let commitment_proof = CommitmentProof::decode(&*p.data).unwrap();
            let existence_proof = match commitment_proof.clone().proof.unwrap()
            {
                Ics23Proof::Exist(ep) => ep,
                _ => unreachable!(),
            };
            sub_root =
                ics23::calculate_existence_root(&existence_proof).unwrap();
            assert!(ics23::verify_membership(
                &commitment_proof,
                spec,
                &sub_root,
                key.as_bytes(),
                &value,
            ));
            // for the verification of the base tree
            value = sub_root.clone();
        }
        // Check the base root
        assert_eq!(sub_root, tree.root().0);
    }

    #[test]
    fn test_non_existence_proof() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();
        let pos_key2 = key_prefix.push(&"test2".to_string()).unwrap();

        let ibc_val = [1u8; 8].to_vec();
        tree.update(&ibc_key, ibc_val).unwrap();
        let pos_val = [2u8; 8].to_vec();
        tree.update(&pos_key, pos_val).unwrap();
        let pos_val2 = [3u8; 8].to_vec();
        // to prevent the subtree from being empty after deletion
        tree.update(&pos_key2, pos_val2).unwrap();

        // Delete the pos key and verify non-existence proof for it
        tree.delete(&pos_key).unwrap();

        let specs = tree.proof_specs();
        let nep = tree.get_non_existence_proof(&pos_key).unwrap();
        let subtree_nep = nep.ops.get(0).unwrap();
        let nep_commitment_proof =
            CommitmentProof::decode(&*subtree_nep.data).unwrap();
        let non_existence_proof =
            match nep_commitment_proof.clone().proof.unwrap() {
                Ics23Proof::Nonexist(nep) => nep,
                _ => unreachable!(),
            };
        let subtree_root = if let Some(left) = &non_existence_proof.left {
            ics23::calculate_existence_root(left).unwrap()
        } else if let Some(right) = &non_existence_proof.right {
            ics23::calculate_existence_root(right).unwrap()
        } else {
            unreachable!()
        };
        let (store_type, sub_key) = StoreType::sub_key(&pos_key).unwrap();

        let subtree_spec = specs.get(0).unwrap();
        let nep_verification_res = ics23::verify_non_membership(
            &nep_commitment_proof,
            subtree_spec,
            &subtree_root,
            sub_key.to_string().as_bytes(),
        );
        assert!(nep_verification_res);

        let basetree_ep = nep.ops.get(1).unwrap();
        let basetree_ep_commitment_proof =
            CommitmentProof::decode(&*basetree_ep.data).unwrap();
        let basetree_ics23_ep =
            match basetree_ep_commitment_proof.clone().proof.unwrap() {
                Ics23Proof::Exist(ep) => ep,
                _ => unreachable!(),
            };
        let basetree_root =
            ics23::calculate_existence_root(&basetree_ics23_ep).unwrap();
        let basetree_verification_res = ics23::verify_membership(
            &basetree_ep_commitment_proof,
            specs.get(1).unwrap(),
            &basetree_root,
            store_type.to_string().as_bytes(),
            &subtree_root,
        );
        assert!(basetree_verification_res);
    }
}
