use std::sync::Arc;

use alloy_consensus::Header;
use alloy_evm::block::{BlockExecutionError, BlockExecutorFactory};
use alloy_op_evm::OpBlockExecutionCtx;

use reth_ethereum::{
    evm::primitives::execute::{BlockAssembler, BlockAssemblerInput},
    primitives::Receipt,
};
use reth_op::DepositReceipt;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::OpBlockAssembler;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;

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
