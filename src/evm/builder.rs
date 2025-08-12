use crate::evm::SovaEvmConfig;
use reth_ethereum::node::api::FullNodeTypes;
use reth_node_builder::{components::ExecutorBuilder, BuilderContext, NodeTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::OpPrimitives;
use std::{future, future::Future};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CustomExecutorBuilder;

impl<Node: FullNodeTypes> ExecutorBuilder<Node> for CustomExecutorBuilder
where
    Node::Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
{
    type EVM = SovaEvmConfig;

    fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> impl Future<Output = eyre::Result<Self::EVM>> + Send {
        future::ready(Ok(SovaEvmConfig::new(ctx.chain_spec())))
    }
}
