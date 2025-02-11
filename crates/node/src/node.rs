use std::sync::Arc;

use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_chainspec::ChainSpec;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthEngineTypes, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{execute::BasicBlockExecutorProvider, ConfigureEvmFor};
use reth_node_api::TxTy;
use reth_node_builder::{
    components::{ComponentsBuilder, ExecutorBuilder, PayloadServiceBuilder},
    node::{FullNodeTypes, NodeTypes, NodeTypesWithEngine},
    BuilderContext, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig, PayloadTypes,
};
use reth_node_ethereum::{
    node::{EthereumAddOns, EthereumConsensusBuilder, EthereumNetworkBuilder, EthereumPoolBuilder},
    payload::EthereumPayloadBuilder,
};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_primitives::EthPrimitives;
use reth_provider::{CanonStateSubscriptions, EthStorage};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;

use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, MyEvmConfig, MyExecutionStrategyFactory, WithInspector};

use crate::SovaArgs;

/// Type configuration for a regular Sova node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaNode {
    /// Additional Sova args
    pub args: SovaArgs,
    /// Bitcoin client wrapper
    pub bitcoin_client: Arc<BitcoinClient>,
    /// Node configuration
    pub sova_config: SovaConfig,
}

impl SovaNode {
    /// Creates a new instance of the Sova node type.
    pub fn new(args: SovaArgs) -> Result<Self, bitcoincore_rpc::Error> {
        let btc_config: BitcoinConfig = BitcoinConfig::new(
            args.btc_network.clone().into(),
            &args.network_url,
            &args.btc_rpc_username,
            &args.btc_rpc_password,
        );

        let sova_config = SovaConfig::new(
            btc_config,
            &args.network_signing_url,
            &args.network_utxo_url,
            &args.btc_tx_queue_url,
            &args.sentinel_url,
        );

        let bitcoin_client = BitcoinClient::new(&sova_config.bitcoin_config)?;

        Ok(Self {
            args,
            bitcoin_client: Arc::new(bitcoin_client),
            sova_config,
        })
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
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .payload(MyPayloadBuilder::new(
                &self.sova_config,
                self.bitcoin_client.clone(),
            ))
            .network(EthereumNetworkBuilder::default())
            .executor(MyExecutorBuilder::new(
                &self.sova_config,
                self.bitcoin_client.clone(),
            ))
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

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyPayloadBuilder {
    pub inner: EthereumPayloadBuilder,
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
}

impl MyPayloadBuilder {
    pub fn new(config: &SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            inner: EthereumPayloadBuilder::default(),
            config: config.clone(),
            bitcoin_client,
        }
    }

    /// A helper method initializing [`PayloadBuilderService`] with the given EVM config.
    pub fn spawn<Types, Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<Types::Engine>>
    where
        Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
        Node: FullNodeTypes<Types = Types>,
        Evm: ConfigureEvmFor<Types::Primitives> + WithInspector,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Types::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        let conf = ctx.payload_builder_config();
        let payload_builder = sova_payload::MyPayloadBuilder::new(
            evm_config,
            EthereumBuilderConfig::new(conf.extra_data_bytes()).with_gas_limit(conf.gas_limit()),
        );

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor()
            .spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}

impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for MyPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = EthPayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<Types::Engine>> {
        let evm_config = MyEvmConfig::new(
            &self.config,
            ctx.chain_spec(),
            self.bitcoin_client.clone(),
            ctx.task_executor().clone(),
        )
        .map_err(|e| {
            eyre::eyre!(
                "PayloadServiceBuilder::spawn_payload_service: Failed to create EVM config: {}",
                e
            )
        })?;

        self.spawn(evm_config, ctx, pool)
    }
}

#[derive(Clone)]
pub struct MyExecutorBuilder {
    config: SovaConfig,
    bitcoin_client: Arc<BitcoinClient>,
}

impl MyExecutorBuilder {
    pub fn new(config: &SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config: config.clone(),
            bitcoin_client,
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
        let evm_config = MyEvmConfig::new(
            &self.config,
            ctx.chain_spec(),
            self.bitcoin_client.clone(),
            ctx.task_executor().clone(),
        )
        .map_err(|e| {
            eyre::eyre!(
                "ExecutorBuilder::build_evm: Failed to create EVM config: {}",
                e
            )
        })?;

        Ok((
            evm_config.clone(),
            BasicBlockExecutorProvider::new(MyExecutionStrategyFactory {
                chain_spec: ctx.chain_spec(),
                evm_config,
            }),
        ))
    }
}
