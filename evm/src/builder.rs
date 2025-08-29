use alloy_op_hardforks::OpHardforks;

use reth_ethereum::node::api::FullNodeTypes;
use reth_node_builder::{components::ExecutorBuilder, BuilderContext, NodeTypes};
use reth_optimism_evm::OpRethReceiptBuilder;
use reth_optimism_primitives::OpPrimitives;

use crate::SovaEvmConfig;

/// A Sova EVM and executor builder.
#[derive(Debug, Copy, Clone, Default)]
#[non_exhaustive]
pub struct SovaExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SovaExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: OpHardforks, Primitives = OpPrimitives>>,
{
    type EVM = SovaEvmConfig<
        <Node::Types as NodeTypes>::ChainSpec,
        <Node::Types as NodeTypes>::Primitives,
    >;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let evm_config = SovaEvmConfig::new(ctx.chain_spec(), OpRethReceiptBuilder::default());

        Ok(evm_config)
    }
}
