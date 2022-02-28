use std::env;
use std::str::FromStr;

use anoma::ledger::gas::BlockGasMeter;
use anoma::ledger::storage::testing::TestStorage;
use anoma::ledger::storage::write_log::WriteLog;
use anoma::vm::wasm::{self, run};
use borsh::BorshSerialize;

fn main() {
    let args: Vec<_> = env::args().collect();
    let iters = args
        .get(1)
        .map(|raw| usize::from_str(raw).expect("Invalid number"))
        .unwrap_or(100);

    let storage = TestStorage::default();
    let mut write_log = WriteLog::default();

    // This code will allocate memory of the given size
    let tx_code = include_bytes!("../../wasm_for_tests/tx_memory_limit.wasm");

    // borsh-encoded usize
    let tx_data = 2_usize.pow(23).try_to_vec().unwrap();
    let (mut vp_cache, _) = wasm::compilation_cache::common::testing::cache();
    let (mut tx_cache, _) = wasm::compilation_cache::common::testing::cache();

    for i in 0..iters {
        let mut gas_meter = BlockGasMeter::default();
        println!("Iter {}", i);
        let result = run::tx(
            &storage,
            &mut write_log,
            &mut gas_meter,
            tx_code.clone(),
            tx_data.clone(),
            &mut vp_cache,
            &mut tx_cache,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);
    }
}
