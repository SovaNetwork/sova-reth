//! EVM transaction environment - using Optimism transaction types only

use reth_ethereum::evm::revm::context::TxEnv;

// Use OpTransaction<TxEnv> as the transaction environment
pub type CustomTxEnv = op_revm::OpTransaction<TxEnv>;
