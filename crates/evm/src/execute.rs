use reth::builder::{components::ExecutorBuilder, BuilderContext};
use reth_chainspec::ChainSpec;
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_ethereum::{BasicBlockExecutorProvider, EthExecutionStrategyFactory};
use reth_primitives::EthPrimitives;

use sova_cli::SovaConfig;

use crate::MyEvmConfig;

#[derive(Clone)]
pub struct MyExecutorBuilder {
    config: SovaConfig,
}

impl MyExecutorBuilder {
    pub fn new(config: &SovaConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = MyEvmConfig;
    type Executor = BasicBlockExecutorProvider<EthExecutionStrategyFactory<Self::EVM>>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
        Ok((
            evm_config.clone(),
            BasicBlockExecutorProvider::new(EthExecutionStrategyFactory::new(
                ctx.chain_spec(),
                evm_config,
            )),
        ))
    }
}
