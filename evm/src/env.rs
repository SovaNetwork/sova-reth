//! EVM transaction environment - using Optimism transaction types only

use alloy_primitives::Address;
use reth_ethereum::evm::revm::context::TxEnv;
use sova_chainspec::L1_BLOCK_CONTRACT_ADDRESS;

// Use OpTransaction<TxEnv> as the transaction environment
pub type SovaTxEnv = op_revm::OpTransaction<TxEnv>;

pub fn sova_l1block_address() -> Address {
    L1_BLOCK_CONTRACT_ADDRESS
}
