use alloy_consensus::Header;
use alloy_evm::block::{BlockExecutionError, BlockExecutorFactory};
use alloy_op_evm::OpBlockExecutionCtx;
use reth_ethereum::{
    evm::primitives::execute::{BlockAssembler, BlockAssemblerInput},
    primitives::Receipt,
};
use reth_op::{node::OpBlockAssembler, DepositReceipt};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use std::sync::Arc;

// SlotLockManager DI imports
use slot_lock_manager::{SentinelClientImpl, SlotLockManager, SlotLockManagerConfig};
use sova_chainspec::L1_BLOCK_CONTRACT_ADDRESS;

pub fn build_slot_lock_manager() -> eyre::Result<Arc<SlotLockManager>> {
    let sentinel_url =
        std::env::var("SENTINEL_URL").unwrap_or_else(|_| "http://localhost:50051".to_string());
    let cfg = SlotLockManagerConfig::builder()
        .sentinel_url(sentinel_url.clone())
        .excluded_address(L1_BLOCK_CONTRACT_ADDRESS)
        .build();
    let sentinel = Arc::new(SentinelClientImpl::new(sentinel_url));
    Ok(Arc::new(SlotLockManager::new(cfg, sentinel)))
}

#[derive(Clone, Debug)]
pub struct SovaBlockAssembler {
    block_assembler: OpBlockAssembler<OpChainSpec>,
}

impl SovaBlockAssembler {
    pub const fn new(chain_spec: Arc<OpChainSpec>) -> Self {
        Self {
            block_assembler: OpBlockAssembler::new(chain_spec),
        }
    }
}

impl<F> BlockAssembler<F> for SovaBlockAssembler
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = OpBlockExecutionCtx,
        Transaction = reth_op::OpTransactionSigned,
        Receipt: Receipt + DepositReceipt,
    >,
{
    type Block = <OpPrimitives as NodePrimitives>::Block;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F, Header>,
    ) -> Result<Self::Block, BlockExecutionError> {
        Ok(self
            .block_assembler
            .assemble_block(input)?
            .map_header(From::from))
    }
}
