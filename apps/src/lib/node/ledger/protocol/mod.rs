//! The ledger's protocol

use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;

use anoma_shared::ledger::gas::{self, BlockGasMeter, VpGasMeter, VpsGas};
use anoma_shared::ledger::ibc::{self, Ibc};
use anoma_shared::ledger::native_vp::{self, NativeVp};
use anoma_shared::ledger::parameters::{self, ParametersVp};
use anoma_shared::ledger::pos::{self, PoS};
use anoma_shared::ledger::storage::write_log::WriteLog;
use anoma_shared::proto::{self, Tx};
use anoma_shared::types::address::{Address, InternalAddress};
use anoma_shared::types::storage::Key;
use anoma_shared::vm::{self, wasm};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::node::ledger::storage::PersistentStorage;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(anoma_shared::ledger::storage::Error),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(proto::Error),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::run::Error),
    #[error("Gas error: {0}")]
    GasError(gas::Error),
    #[error("Error executing VP for addresses: {0:?}")]
    VpRunnerError(vm::wasm::run::Error),
    #[error("The address {0} doesn't exist")]
    MissingAddress(Address),
    #[error("IBC native VP: {0}")]
    IbcNativeVpError(ibc::Error),
    #[error("PoS native VP: {0}")]
    PosNativeVpError(pos::Error),
    #[error("Parameters native VP: {0}")]
    ParametersNativeVpError(parameters::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Transaction application result
#[derive(Clone, Debug)]
pub struct TxResult {
    pub gas_used: u64,
    pub changed_keys: HashSet<Key>,
    pub vps_result: VpsResult,
}

impl TxResult {
    pub fn is_accepted(&self) -> bool {
        self.vps_result.rejected_vps.is_empty()
    }
}

/// Result of checking a transaction with validity predicates
#[derive(Clone, Debug)]
pub struct VpsResult {
    pub accepted_vps: HashSet<Address>,
    pub rejected_vps: HashSet<Address>,
    pub gas_used: VpsGas,
    pub errors: Vec<(Address, String)>,
}

impl Default for VpsResult {
    fn default() -> Self {
        Self {
            accepted_vps: HashSet::default(),
            rejected_vps: HashSet::default(),
            gas_used: VpsGas::default(),
            errors: Vec::default(),
        }
    }
}

/// Apply a given transaction
pub fn apply_tx(
    tx_bytes: &[u8],
    block_gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    storage: &PersistentStorage,
) -> Result<TxResult> {
    block_gas_meter
        .add_base_transaction_fee(tx_bytes.len())
        .map_err(Error::GasError)?;

    let tx = Tx::try_from(tx_bytes).map_err(Error::TxDecodingError)?;

    let verifiers = execute_tx(&tx, storage, block_gas_meter, write_log)?;

    let vps_result =
        check_vps(&tx, storage, block_gas_meter, write_log, &verifiers)?;

    let gas_used = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError)?;
    let changed_keys = write_log.get_keys();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
    })
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
fn execute_tx(
    tx: &Tx,
    storage: &PersistentStorage,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
) -> Result<HashSet<Address>> {
    let tx_code = tx.code.clone();
    gas_meter
        .add_compiling_fee(tx_code.len())
        .map_err(Error::GasError)?;
    let tx_data = tx.data.clone().unwrap_or_default();
    wasm::run::tx(storage, write_log, gas_meter, tx_code, tx_data)
        .map_err(Error::TxRunnerError)
}

/// A validity predicate
enum Vp<'a> {
    Wasm(Vec<u8>),
    Native(&'a InternalAddress),
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps(
    tx: &Tx,
    storage: &PersistentStorage,
    gas_meter: &mut BlockGasMeter,
    write_log: &WriteLog,
    verifiers_from_tx: &HashSet<Address>,
) -> Result<VpsResult> {
    let verifiers = write_log.verifiers_changed_keys(verifiers_from_tx);

    // collect the VPs for the verifiers
    let verifiers: Vec<(Address, HashSet<Key>, Vp)> = verifiers
        .iter()
        .map(|(addr, keys)| {
            let vp = match addr {
                Address::Internal(addr) => Vp::Native(&addr),
                Address::Established(_) | Address::Implicit(_) => {
                    let (vp, gas) = storage
                        .validity_predicate(&addr)
                        .map_err(Error::StorageError)?;
                    gas_meter.add(gas).map_err(Error::GasError)?;
                    let vp =
                        vp.ok_or_else(|| Error::MissingAddress(addr.clone()))?;

                    gas_meter
                        .add_compiling_fee(vp.len())
                        .map_err(Error::GasError)?;
                    Vp::Wasm(vp)
                }
            };

            Ok((addr.clone(), keys.clone(), vp))
        })
        .collect::<std::result::Result<_, _>>()?;

    let initial_gas = gas_meter.get_current_transaction_gas();

    let vps_result =
        execute_vps(verifiers, tx, storage, write_log, initial_gas)?;
    tracing::debug!("Total VPs gas cost {:?}", vps_result.gas_used);

    gas_meter
        .add_vps_gas(&vps_result.gas_used)
        .map_err(Error::GasError)?;

    Ok(vps_result)
}

/// Execute verifiers' validity predicates
fn execute_vps(
    verifiers: Vec<(Address, HashSet<Key>, Vp)>,
    tx: &Tx,
    storage: &PersistentStorage,
    write_log: &WriteLog,
    initial_gas: u64,
) -> Result<VpsResult> {
    let verifiers_addr = verifiers
        .iter()
        .map(|(addr, _, _)| addr)
        .cloned()
        .collect::<HashSet<_>>();

    verifiers
        .par_iter()
        .try_fold(VpsResult::default, |mut result, (addr, keys, vp)| {
            let mut gas_meter = VpGasMeter::new(initial_gas);
            let accept = match &vp {
                Vp::Wasm(vp) => execute_wasm_vp(
                    tx,
                    storage,
                    write_log,
                    &verifiers_addr,
                    &mut gas_meter,
                    (addr, keys, vp),
                ),
                Vp::Native(internal_addr) => {
                    let ctx =
                        native_vp::Ctx::new(storage, write_log, tx, gas_meter);
                    let tx_data = match tx.data.as_ref() {
                        Some(data) => &data[..],
                        None => &[],
                    };

                    let accepted: Result<bool> = match internal_addr {
                        InternalAddress::PoS => {
                            let pos = PoS { ctx };
                            pos.validate_tx(tx_data, keys, &verifiers_addr)
                                .map_err(Error::PosNativeVpError)
                        }
                        InternalAddress::Ibc => {
                            let ibc = Ibc { ctx };
                            ibc.validate_tx(tx_data, keys, &verifiers_addr)
                                .map_err(Error::IbcNativeVpError)
                        }
                        InternalAddress::Parameters => {
                            let parameters = ParametersVp { ctx };
                            parameters
                                .validate_tx(tx_data, keys, &verifiers_addr)
                                .map_err(Error::ParametersNativeVpError)
                        }
                    };

                    accepted
                }
            };

            // Returning error from here will short-circuit the VP parallel
            // execution. It's important that we only short-circuit gas
            // errors to get deterministic gas costs
            match accept {
                Ok(accepted) => {
                    if !accepted {
                        result.rejected_vps.insert(addr.clone());
                        Ok(result)
                    } else {
                        result.accepted_vps.insert(addr.clone());
                        Ok(result)
                    }
                }
                Err(err) => match err {
                    Error::GasError(_) => Err(err),
                    _ => {
                        result.rejected_vps.insert(addr.clone());
                        result.errors.push((addr.clone(), err.to_string()));
                        Ok(result)
                    }
                },
            }
        })
        .try_reduce(VpsResult::default, |a, b| {
            merge_vp_results(a, b, initial_gas)
        })
}

/// Merge VP results from parallel runs
fn merge_vp_results(
    a: VpsResult,
    mut b: VpsResult,
    initial_gas: u64,
) -> Result<VpsResult> {
    let accepted_vps = a.accepted_vps.union(&b.accepted_vps).cloned().collect();
    let rejected_vps = a.rejected_vps.union(&b.rejected_vps).cloned().collect();
    let mut errors = a.errors;
    errors.append(&mut b.errors);
    let mut gas_used = a.gas_used;

    // Returning error from here will short-circuit the VP parallel execution.
    // It's important that we only short-circuit gas errors to get deterministic
    // gas costs

    gas_used
        .merge(&mut b.gas_used, initial_gas)
        .map_err(Error::GasError)?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
    })
}

/// Execute a WASM validity predicates
#[allow(clippy::too_many_arguments)]
fn execute_wasm_vp(
    tx: &Tx,
    storage: &PersistentStorage,
    write_log: &WriteLog,
    verifiers: &HashSet<Address>,
    vp_gas_meter: &mut VpGasMeter,
    (addr, keys, vp): (&Address, &HashSet<Key>, &[u8]),
) -> Result<bool> {
    wasm::run::vp(
        vp,
        tx,
        addr,
        storage,
        write_log,
        vp_gas_meter,
        keys,
        verifiers,
    )
    .map_err(Error::VpRunnerError)
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction is {}. Gas used: {};{} VPs result: {}",
            if self.is_accepted() {
                "valid"
            } else {
                "invalid"
            },
            self.gas_used,
            iterable_to_string("Changed keys", self.changed_keys.iter()),
            self.vps_result,
        )
    }
}

impl fmt::Display for VpsResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            iterable_to_string("Accepted", self.accepted_vps.iter()),
            iterable_to_string("Rejected", self.rejected_vps.iter()),
            iterable_to_string(
                "Errors",
                self.errors
                    .iter()
                    .map(|(addr, err)| format!("{} in {}", err, addr))
            ),
        )
    }
}

fn iterable_to_string<T: fmt::Display>(
    label: &str,
    iter: impl Iterator<Item = T>,
) -> String {
    let mut iter = iter.peekable();
    if iter.peek().is_none() {
        "".into()
    } else {
        format!(
            " {}: {};",
            label,
            iter.map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}