use std::sync::Arc;

use op_alloy_consensus::OpPooledTransaction;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor};
use reth_network::{NetworkHandle, PeersInfo};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeAddOns, NodeTypes, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder, NetworkBuilder,
        PayloadBuilderBuilder,
    },
    node::FullNodeTypes,
    rpc::{
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, RethRpcAddOns, RpcAddOns,
        RpcHandle,
    },
    BuilderContext, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::{
    node::{OpConsensusBuilder, OpPoolBuilder},
    txpool::OpPooledTx,
    OpEngineTypes, OpNetworkPrimitives, OpNextBlockEnvAttributes,
};
use reth_optimism_payload_builder::builder::OpPayloadTransactions;
use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
use reth_optimism_rpc::OpEthApiError;
use reth_provider::{providers::ProviderFactoryBuilder, EthStorage};
use reth_rpc_eth_types::error::FromEvmError;
use reth_tracing::tracing::info;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;

use revm_context::TxEnv;
use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, MyEvmConfig, SovaBlockExecutorProvider};
use sova_rpc::{SovaEthApi, SovaEthApiBuilder};

use crate::{engine::SovaEngineValidator, rpc::SovaEngineApiBuilder, SovaArgs};

/// Storage implementation for Sova
pub type SovaStorage = EthStorage<OpTransactionSigned>;

/// Custom AddOns for Sova
#[derive(Debug)]
pub struct SovaAddOns<N>
where
    N: FullNodeComponents,
    SovaEthApiBuilder: EthApiBuilder<N>,
{
    pub inner: RpcAddOns<
        N,
        SovaEthApiBuilder,
        SovaEngineValidatorBuilder,
        SovaEngineApiBuilder<SovaEngineValidatorBuilder>,
    >,
}

impl<N> Default for SovaAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<Primitives = OpPrimitives>>,
    SovaEthApiBuilder: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self::builder().build()
    }
}

impl<N> SovaAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<Primitives = OpPrimitives>>,
    SovaEthApiBuilder: EthApiBuilder<N>,
{
    /// Build a [`SovaAddOns`] using [`SovaAddOnsBuilder`].
    pub fn builder() -> SovaAddOnsBuilder {
        SovaAddOnsBuilder::default()
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaAddOnsBuilder;

impl SovaAddOnsBuilder {
    /// Builds an instance of [`OpAddOns`].
    pub fn build<N>(self) -> SovaAddOns<N>
    where
        N: FullNodeComponents<Types: NodeTypes<Primitives = OpPrimitives>>,
        SovaEthApiBuilder: EthApiBuilder<N>,
    {
        // NOTE: In optimism this is where the sequencer is injected as an AddOn.
        // Block producers on Sova commit to a specific BTC block context.

        SovaAddOns {
            inner: RpcAddOns::new(
                SovaEthApiBuilder::default(),
                Default::default(),
                Default::default(),
            ),
        }
    }
}

impl<N> NodeAddOns<N> for SovaAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
            Storage = SovaStorage,
            Payload = OpEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = OpNextBlockEnvAttributes>,
    >,
    OpEthApiError: FromEvmError<N::Evm>,
    <N::Pool as TransactionPool>::Transaction: OpPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = op_revm::OpTransaction<TxEnv>>,
{
    type Handle = RpcHandle<N, SovaEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        // No-op - no flashbots, no optimism sequencer
        self.inner.launch_add_ons_with(ctx, |_, _, _| Ok(())).await
    }
}

impl<N> RethRpcAddOns<N> for SovaAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
            Storage = SovaStorage,
            Payload = OpEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = OpNextBlockEnvAttributes>,
    >,
    OpEthApiError: FromEvmError<N::Evm>,
    <<N as FullNodeComponents>::Pool as TransactionPool>::Transaction: OpPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = op_revm::OpTransaction<TxEnv>>,
{
    type EthApi = SovaEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<N> for SovaAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
            Payload = OpEngineTypes,
        >,
    >,
    SovaEthApiBuilder: EthApiBuilder<N>,
{
    type Validator = SovaEngineValidator;

    async fn engine_validator(&self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        SovaEngineValidatorBuilder::default().build(ctx).await
    }
}

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
        OpPoolBuilder,
        BasicPayloadServiceBuilder<MyPayloadBuilder>,
        SovaNetworkBuilder,
        MyExecutorBuilder,
        OpConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                Payload = OpEngineTypes,
                ChainSpec = OpChainSpec,
                Primitives = OpPrimitives,
                Storage = SovaStorage,
            >,
        >,
    {
        let pool_builder =
            OpPoolBuilder::default().with_enable_tx_conditional(self.args.enable_tx_conditional);

        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(pool_builder)
            .payload(BasicPayloadServiceBuilder::new(MyPayloadBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            )))
            .network(SovaNetworkBuilder::default())
            .executor(MyExecutorBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            ))
            .consensus(OpConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl<N> Node<N> for SovaNode
where
    N: FullNodeTypes<
        Types: NodeTypes<
            Payload = OpEngineTypes,
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
            Storage = SovaStorage,
        >,
    >,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        OpPoolBuilder,
        BasicPayloadServiceBuilder<MyPayloadBuilder>,
        SovaNetworkBuilder,
        MyExecutorBuilder,
        OpConsensusBuilder,
    >;

    type AddOns = SovaAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        SovaAddOns::default()
    }
}

impl NodeTypes for SovaNode {
    type Primitives = OpPrimitives;
    type ChainSpec = OpChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = SovaStorage;
    type Payload = OpEngineTypes;
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyPayloadBuilder<Txs = ()> {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
}

impl MyPayloadBuilder {
    pub fn new(config: SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config,
            bitcoin_client,
            best_transactions: (),
        }
    }
}

impl<Txs> MyPayloadBuilder<Txs> {
    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(self, best_transactions: T) -> MyPayloadBuilder<T> {
        let Self {
            config,
            bitcoin_client,
            ..
        } = self;
        MyPayloadBuilder {
            config,
            bitcoin_client,
            best_transactions,
        }
    }

    /// A helper method to initialize [`sova_payload::MyPayloadBuilder`] with the
    /// given EVM config.
    pub fn build<Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<sova_payload::MyPayloadBuilder<Pool, Node::Provider, Evm, Txs>>
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                Payload = OpEngineTypes,
                ChainSpec = OpChainSpec,
                Primitives = OpPrimitives,
            >,
        >,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Txs: OpPayloadTransactions<Pool::Transaction>,
    {
        let payload_builder = sova_payload::MyPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new().with_gas_limit(ctx.payload_builder_config().gas_limit()),
        )
        .with_transactions(self.best_transactions.clone());

        Ok(payload_builder)
    }
}

impl<Node, Pool, Txs> PayloadBuilderBuilder<Node, Pool> for MyPayloadBuilder<Txs>
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = OpEngineTypes,
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Txs: OpPayloadTransactions<Pool::Transaction>,
    <Pool as TransactionPool>::Transaction: OpPooledTx,
{
    type PayloadBuilder = sova_payload::MyPayloadBuilder<Pool, Node::Provider, MyEvmConfig, Txs>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::PayloadBuilder> {
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

        self.build(evm_config, ctx, pool)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MyExecutorBuilder {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
}

impl MyExecutorBuilder {
    pub fn new(config: SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config: config.clone(),
            bitcoin_client,
        }
    }
}

impl<Types, Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = MyEvmConfig;
    type Executor = SovaBlockExecutorProvider<MyEvmConfig>;

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
            SovaBlockExecutorProvider::new(evm_config),
        ))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SovaNetworkBuilder;

impl<Node, Pool> NetworkBuilder<Node, Pool> for SovaNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>>,
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TxTy<Node::Types>,
                Pooled = OpPooledTransaction,
            >,
        > + Unpin
        + 'static,
{
    type Primitives = OpNetworkPrimitives;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<NetworkHandle<Self::Primitives>> {
        let network = ctx.network_builder().await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

/// Builder for [`SovaEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for SovaEngineValidatorBuilder
where
    Types: NodeTypes<ChainSpec = OpChainSpec, Payload = OpEngineTypes, Primitives = OpPrimitives>,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = SovaEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SovaEngineValidator::new(ctx.config.chain.clone()))
    }
}
