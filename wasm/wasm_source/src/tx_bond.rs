//! A tx for a PoS bond that stakes tokens via a self-bond or delegation.

use anoma_tx_prelude::proof_of_stake::bond_tokens;
use anoma_tx_prelude::*;

#[transaction]
fn apply_tx(tx_data: Vec<u8>) {
    let signed = SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    let bond =
        transaction::pos::Bond::try_from_slice(&signed.data.unwrap()[..])
            .unwrap();

    if let Err(err) =
        bond_tokens(bond.source.as_ref(), &bond.validator, bond.amount)
    {
        debug_log!("Bond failed with: {}", err);
        panic!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use anoma::proto::Tx;
    use anoma_tests::tx::*;
    use anoma_tx_prelude::storage::Epoch;
    use anoma_vp_prelude::proof_of_stake::{anoma_proof_of_stake::PosBase, PosParams};

    /// 1. valid self-bond
    #[test]
    fn test_valid_self_bond() {
        // The environment must be initialized first
        let mut tx_env = TestTxEnv::default();
        
        // Initialize PoS storage
        let pos_params = PosParams::default();
        let epoch = Epoch::default();
            tx_env.storage
                .init_genesis(
                    &pos_params,
                    [].into_iter(),
                    epoch,
                )
                .unwrap();

        tx_host_env::set(tx_env);

        let validator = address::testing::established_address_1();
        let amount = token::Amount::whole(1);

        let bond = transaction::pos::Bond { validator, amount, source: None };
        // TODO: do this after rebase on #927 after it's fixed
        // let mut tx = env.tx.clone();
        let mut tx = Tx::new(vec![], Some(bond.try_to_vec().unwrap()));
        let key = key::testing::keypair_1();
        let tx = tx.sign(&key);
        let bond_bytes = tx.data.unwrap();

        apply_tx(bond_bytes);
    }

    // 2. valid delegation
    // 3. invalid self-bond
    //    - given `validator` address is not actually validator
    //    - insufficient balance
    // 4. invalid delegation
    //    - given `validator` address is not actually validator
    //    - insufficient balance
    //    - `source` address doesn't exist
    //    - `source` address is validator account that is equal to `validator` address
    //    - `source` address is validator account other than `validator` address
}