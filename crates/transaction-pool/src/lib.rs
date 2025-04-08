mod txpool;

use reth_transaction_pool::{CoinbaseTipOrdering, EthTransactionValidator, Pool, TransactionValidationTaskExecutor};
pub use txpool::SovaPooledTransaction;

/// Type alias for default ethereum transaction pool
pub type SovaTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<Client, SovaPooledTransaction>>,
    CoinbaseTipOrdering<SovaPooledTransaction>,
    S,
>;