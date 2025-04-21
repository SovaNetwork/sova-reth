mod validator;

use reth_optimism_node::txpool::OpPooledTransaction;
use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};
pub use validator::SovaTransactionValidator;

/// Type alias for default optimism transaction pool
pub type SovaTransactionPool<Client, S, T = OpPooledTransaction> = Pool<
    TransactionValidationTaskExecutor<SovaTransactionValidator<Client, T>>,
    CoinbaseTipOrdering<T>,
    S,
>;
