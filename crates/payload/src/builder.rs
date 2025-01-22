use reth_node_ethereum::node::EthereumPayloadBuilder;

use sova_cli::SovaConfig;

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyPayloadBuilder {
    pub inner: EthereumPayloadBuilder,
    pub config: SovaConfig,
}

impl MyPayloadBuilder {
    pub fn new(config: &SovaConfig) -> Self {
        Self {
            inner: EthereumPayloadBuilder::default(),
            config: config.clone(),
        }
    }
}

// impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for MyPayloadBuilder
// where
//     Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
//     Node: FullNodeTypes<Types = Types>,
//     Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
//         + Unpin
//         + 'static,
//     Types::Engine: PayloadTypes<
//         BuiltPayload = EthBuiltPayload,
//         PayloadAttributes = PayloadAttributes,
//         PayloadBuilderAttributes = EthPayloadBuilderAttributes,
//     >,
// {
//     async fn spawn_payload_service(
//         self,
//         ctx: &BuilderContext<Node>,
//         pool: Pool,
//     ) -> eyre::Result<reth::payload::PayloadBuilderHandle<Types::Engine>> {
//         let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
//         self.inner.spawn(evm_config, ctx, pool)
//     }
// }
