use reth::{
    api::{FullNodeTypes, NodeTypes, NodeTypesWithEngine, PayloadTypes},
    builder::{
        components::{ComponentsBuilder, ExecutorBuilder, PayloadServiceBuilder},
        BuilderContext, Node, NodeAdapter, NodeComponentsBuilder,
    },
    chainspec::ChainSpec,
    payload::{EthBuiltPayload, EthPayloadBuilderAttributes},
    primitives::{EthPrimitives, TransactionSigned},
    providers::EthStorage,
    rpc::types::engine::PayloadAttributes,
    transaction_pool::{PoolTransaction, TransactionPool},
};
use reth_node_ethereum::{
    node::{
        EthereumAddOns, EthereumConsensusBuilder, EthereumNetworkBuilder, EthereumPayloadBuilder,
        EthereumPoolBuilder,
    },
    BasicBlockExecutorProvider, EthEngineTypes,
};
use reth_trie_db::MerklePatriciaTrie;

use sova_cli::SovaConfig;
use sova_evm::{MyEvmConfig, MyExecutionStrategyFactory};

use crate::SovaArgs;

/// Type configuration for a regular Sova node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaNode {
    /// Additional Sova args
    pub args: SovaArgs,
}

impl SovaNode {
    /// Creates a new instance of the Sova node type.
    pub fn new(args: SovaArgs) -> Self {
        Self { args }
    }

    /// Returns the components for the given [`SovaArgs`].
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        MyPayloadBuilder,
        EthereumNetworkBuilder,
        MyExecutorBuilder,
        EthereumConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<
                Engine = EthEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = EthPrimitives,
            >,
        >,
    {
        let btc_network: bitcoin::Network = self.args.btc_network.clone().into();

        let sova_config: SovaConfig = SovaConfig::new(
            &btc_network,
            &self.args.network_url,
            &self.args.btc_rpc_username,
            &self.args.btc_rpc_password,
            &self.args.network_signing_url,
            &self.args.network_utxo_url,
            &self.args.btc_tx_queue_url,
        );
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .payload(MyPayloadBuilder::new(&sova_config))
            .network(EthereumNetworkBuilder::default())
            .executor(MyExecutorBuilder::new(&sova_config))
            .consensus(EthereumConsensusBuilder::default())
    }
}

impl NodeTypes for SovaNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = EthStorage;
}

impl NodeTypesWithEngine for SovaNode {
    type Engine = EthEngineTypes;
}

impl<N> Node<N> for SovaNode
where
    N: FullNodeTypes<
        Types: NodeTypesWithEngine<
            Engine = EthEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = EthPrimitives,
            Storage = EthStorage,
        >,
    >,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        MyPayloadBuilder,
        EthereumNetworkBuilder,
        MyExecutorBuilder,
        EthereumConsensusBuilder,
    >;

    type AddOns = EthereumAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}

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

impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for MyPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = PayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<reth::payload::PayloadBuilderHandle<Types::Engine>> {
        let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
        self.inner.spawn(evm_config, ctx, pool)
    }
}

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
    type Executor = BasicBlockExecutorProvider<MyExecutionStrategyFactory>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
        Ok((
            evm_config.clone(),
            BasicBlockExecutorProvider::new(MyExecutionStrategyFactory {
                chain_spec: ctx.chain_spec(),
                evm_config,
            }),
        ))
    }
}
