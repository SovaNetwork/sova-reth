//! Loads and formats OP receipt RPC response.

use alloy_consensus::transaction::TransactionMeta;
use op_revm::L1BlockInfo;
use reth_chainspec::ChainSpecProvider;
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::{OpReceipt, OpTransactionSigned};
use reth_optimism_rpc::OpReceiptBuilder;
use reth_rpc_eth_api::{helpers::LoadReceipt, FromEthApiError, RpcReceipt};
use reth_rpc_eth_types::EthApiError;
use reth_storage_api::{ReceiptProvider, TransactionsProvider};

use super::SovaEthApi;

impl<N> LoadReceipt for SovaEthApi<N>
where
    Self: Send + Sync,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = OpChainSpec>>,
    Self::Provider: TransactionsProvider<Transaction = OpTransactionSigned>
        + ReceiptProvider<Receipt = OpReceipt>,
{
    async fn build_transaction_receipt(
        &self,
        tx: OpTransactionSigned,
        meta: TransactionMeta,
        receipt: OpReceipt,
    ) -> Result<RpcReceipt<Self::NetworkTypes>, Self::Error> {
        let (_, receipts) = self
            .inner
            .eth_api
            .cache()
            .get_block_and_receipts(meta.block_hash)
            .await
            .map_err(Self::Error::from_eth_err)?
            .ok_or(Self::Error::from_eth_err(EthApiError::HeaderNotFound(
                meta.block_hash.into(),
            )))?;

        // let mut l1_block_info =
        //     reth_optimism_evm::extract_l1_info(block.body()).map_err(OpEthApiError::from)?;

        let mut l1_block_info = L1BlockInfo::default();


        let mut receipt = OpReceiptBuilder::new(
            &self.inner.eth_api.provider().chain_spec(),
            &tx,
            meta,
            &receipt,
            &receipts,
            &mut l1_block_info,
        )?
        .build();

        // TODO(powvt): Cleanup the receipt builder to remove or modify all Optimism L1 block fields
        receipt.l1_block_info.l1_gas_used = Some(0);

        Ok(receipt)
    }
}
