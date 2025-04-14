use reth_rpc_eth_api::{helpers::{EthSigner, EthTransactions, LoadTransaction, SpawnBlocking}, FullEthApiTypes, RpcNodeCoreExt};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_storage_api::{BlockReader, BlockReaderIdExt, ProviderTx, TransactionsProvider};
use reth_transaction_pool::{TransactionOrigin, TransactionPool};
use revm_primitives::{Bytes, B256};
use reth_rpc_eth_api::FromEthApiError;
use reth_transaction_pool::PoolTransaction;
use reth_rpc_eth_api::RpcNodeCore;

use super::{SovaEthApi, SovaNodeCore};

// Implement EthTransactions for SovaEthApi<N>
impl<N> EthTransactions for SovaEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: SovaNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.inner.eth_api.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        let recovered = recover_raw_transaction(&tx)?;

        // broadcast raw transaction to subscribers if there is any.
        self.inner.eth_api.broadcast_raw_transaction(tx);

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let hash = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
    }
}

impl<N> LoadTransaction for SovaEthApi<N>
where
    Self: SpawnBlocking + FullEthApiTypes + RpcNodeCoreExt,
    N: SovaNodeCore<Provider: TransactionsProvider, Pool: TransactionPool>,
    Self::Pool: TransactionPool,
{
}