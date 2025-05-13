use std::sync::Arc;

use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, NodeAddOns, NodeTypes, PrimitivesTy, TxTy,
};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder,
        PayloadBuilderBuilder,
    },
    node::FullNodeTypes,
    rpc::{
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, RethRpcAddOns, RpcAddOns,
        RpcHandle,
    },
    BuilderContext, Node, NodeAdapter, NodeComponentsBuilder,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::{
    node::{OpConsensusBuilder, OpNetworkBuilder, OpPoolBuilder},
    txpool::OpPooledTx,
    OpEngineTypes, OpNextBlockEnvAttributes,
};
use reth_optimism_payload_builder::{
    builder::OpPayloadTransactions,
    config::{OpBuilderConfig, OpDAConfig},
};
use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
use reth_optimism_rpc::OpEthApiError;

use reth_provider::{providers::ProviderFactoryBuilder, EthStorage};
use reth_rpc_eth_types::error::FromEvmError;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;

use revm_context::TxEnv;
use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, MyEvmConfig, SovaBlockExecutorProvider};
use sova_rpc::{SovaEthApi, SovaEthApiBuilder};

use crate::{engine::SovaEngineValidator, rpc::SovaEngineApiBuilder, SovaArgs};

/// Storage implementation for Sova
pub type SovaStorage = EthStorage<OpTransactionSigned>;

/// Type configuration for a regular Sova node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaNode {
    /// Additional Sova args with Op Rollup Args
    pub args: SovaArgs,
    /// Bitcoin client wrapper
    pub bitcoin_client: Arc<BitcoinClient>,
    /// Node configuration
    pub sova_config: SovaConfig,
    /// Data availability configuration for the OP builder.
    ///
    /// Used to throttle the size of the data availability payloads (configured by the batcher via
    /// the `miner_` api).
    ///
    /// By default no throttling is applied.
    pub da_config: OpDAConfig,
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
            args.sentinel_confirmation_threshold,
            args.sequencer_mode,
        );

        let bitcoin_client = BitcoinClient::new(
            &sova_config.bitcoin_config,
            sova_config.sentinel_confirmation_threshold,
        )?;

        Ok(Self {
            args,
            bitcoin_client: Arc::new(bitcoin_client),
            sova_config,
            da_config: OpDAConfig::default(),
        })
    }

    /// Configure the data availability configuration for the builder.
    pub fn with_da_config(mut self, da_config: OpDAConfig) -> Self {
        self.da_config = da_config;
        self
    }

    /// Returns the components for the given [`SovaArgs`].
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        OpPoolBuilder,
        BasicPayloadServiceBuilder<SovaPayloadBuilder>,
        OpNetworkBuilder,
        SovaExecutorBuilder,
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
        let SovaArgs {
            disable_txpool_gossip,
            compute_pending_block,
            discovery_v4,
            ..
        } = self.args;

        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(
                OpPoolBuilder::default()
                    .with_enable_tx_conditional(self.args.enable_tx_conditional)
                    .with_supervisor(
                        self.args.supervisor_http.clone(),
                        self.args.supervisor_safety_level,
                    ),
            )
            .payload(BasicPayloadServiceBuilder::new(
                SovaPayloadBuilder::new(
                    self.sova_config.clone(),
                    Arc::clone(&self.bitcoin_client),
                    compute_pending_block,
                )
                .with_da_config(self.da_config.clone()),
            ))
            .network(OpNetworkBuilder {
                disable_txpool_gossip,
                disable_discovery_v4: !discovery_v4,
            })
            .executor(SovaExecutorBuilder::new(
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
        BasicPayloadServiceBuilder<SovaPayloadBuilder>,
        OpNetworkBuilder,
        SovaExecutorBuilder,
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
    /// Builds an instance of [`SovaAddOns`].
    pub fn build<N>(self) -> SovaAddOns<N>
    where
        N: FullNodeComponents<Types: NodeTypes<Primitives = OpPrimitives>>,
        SovaEthApiBuilder: EthApiBuilder<N>,
    {
        // NOTE: In optimism this is where the sequencer is injected as an AddOn.
        // Block producers on Sova commit to a specific BTC block context.

        SovaAddOns {
            inner: RpcAddOns::new(SovaEthApiBuilder, Default::default(), Default::default()),
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

/// A Sova payload builder service
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaPayloadBuilder<Txs = ()> {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
    /// By default the pending block equals the latest block
    /// to save resources and not leak txs from the tx-pool,
    /// this flag enables computing of the pending block
    /// from the tx-pool instead.
    ///
    /// If `compute_pending_block` is not enabled, the payload builder
    /// will use the payload attributes from the latest block. Note
    /// that this flag is not yet functional.
    pub compute_pending_block: bool,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
    /// This data availability configuration specifies constraints for the payload builder
    /// when assembling payloads
    pub da_config: OpDAConfig,
}

impl SovaPayloadBuilder {
    /// Create a new instance with the given `compute_pending_block` flag and data availability config.
    pub fn new(
        config: SovaConfig,
        bitcoin_client: Arc<BitcoinClient>,
        compute_pending_block: bool,
    ) -> Self {
        Self {
            config,
            bitcoin_client,
            compute_pending_block,
            best_transactions: (),
            da_config: OpDAConfig::default(),
        }
    }

    /// Configure the data availability configuration for the OP payload builder.
    pub fn with_da_config(mut self, da_config: OpDAConfig) -> Self {
        self.da_config = da_config;
        self
    }
}

impl<Txs> SovaPayloadBuilder<Txs> {
    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(self, best_transactions: T) -> SovaPayloadBuilder<T> {
        let Self {
            config,
            bitcoin_client,
            compute_pending_block,
            da_config,
            ..
        } = self;
        SovaPayloadBuilder {
            config,
            bitcoin_client,
            compute_pending_block,
            best_transactions,
            da_config,
        }
    }

    /// A helper method to initialize [`sova_payload::SovaPayloadBuilder`] with the
    /// given EVM config.
    pub fn build<Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<sova_payload::SovaPayloadBuilder<Pool, Node::Provider, Evm, Txs>>
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
        Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>>,
        Txs: OpPayloadTransactions<Pool::Transaction>,
    {
        let payload_builder = sova_payload::SovaPayloadBuilder::with_builder_config(
            pool,
            ctx.provider().clone(),
            evm_config,
            OpBuilderConfig {
                da_config: self.da_config.clone(),
            },
        )
        .with_sova_integration(self.config.clone(), self.bitcoin_client.clone())
        .with_transactions(self.best_transactions.clone())
        .set_compute_pending_block(self.compute_pending_block);
        Ok(payload_builder)
    }
}

impl<Node, Pool, Txs> PayloadBuilderBuilder<Node, Pool> for SovaPayloadBuilder<Txs>
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
    type PayloadBuilder = sova_payload::SovaPayloadBuilder<Pool, Node::Provider, MyEvmConfig, Txs>;

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

/// A type that knows how to build the Sova EVM.
///
/// The Sova EVM is customized such that there are new precompiles and a
/// custom inspector which is used for enforcing transaction finality on Bitcoin.
#[derive(Debug, Default, Clone)]
pub struct SovaExecutorBuilder {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
}

impl SovaExecutorBuilder {
    pub fn new(config: SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config: config.clone(),
            bitcoin_client,
        }
    }
}

impl<Types, Node> ExecutorBuilder<Node> for SovaExecutorBuilder
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
            SovaBlockExecutorProvider::new(evm_config, self.bitcoin_client),
        ))
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
