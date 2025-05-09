use std::sync::Arc;

use op_alloy_consensus::{interop::SafetyLevel, OpPooledTransaction};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor};
use reth_network::{NetworkHandle, PeersInfo};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, NodeAddOns, NodePrimitives, NodeTypes, TxTy,
};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder, PayloadBuilderBuilder, PoolBuilder, PoolBuilderConfigOverrides,
    },
    node::FullNodeTypes,
    rpc::{
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, RethRpcAddOns, RpcAddOns,
        RpcHandle,
    },
    BuilderContext, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::{
    txpool::{
        conditional::MaybeConditionalTransaction, interop::MaybeInteropTransaction,
        supervisor::DEFAULT_SUPERVISOR_URL, OpPooledTx,
    },
    OpEngineTypes, OpNetworkPrimitives, OpNextBlockEnvAttributes,
};
use reth_optimism_payload_builder::builder::OpPayloadTransactions;
use reth_optimism_primitives::{DepositReceipt, OpPrimitives, OpTransactionSigned};
use reth_optimism_rpc::OpEthApiError;
use reth_optimism_txpool::supervisor::SupervisorClient;
use reth_provider::CanonStateSubscriptions;
use reth_provider::{providers::ProviderFactoryBuilder, EthStorage};
use reth_rpc_eth_types::error::FromEvmError;
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, CoinbaseTipOrdering, EthPoolTransaction, PoolTransaction,
    TransactionPool, TransactionValidationTaskExecutor,
};
use reth_trie_db::MerklePatriciaTrie;

use revm_context::TxEnv;
use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, MyEvmConfig, SovaBlockExecutorProvider};
use sova_rpc::{SovaEthApi, SovaEthApiBuilder};
use sova_txpool::{SovaTransactionPool, SovaTransactionValidator};

use crate::{engine::SovaEngineValidator, rpc::SovaEngineApiBuilder, SovaArgs};

/// Storage implementation for Sova
pub type SovaStorage = EthStorage<OpTransactionSigned>;

/// Type configuration for a regular Sova node.
#[derive(Debug, Clone)]
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
        })
    }

    /// Returns the components for the given [`SovaArgs`].
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        SovaPoolBuilder,
        BasicPayloadServiceBuilder<SovaPayloadBuilder>,
        SovaNetworkBuilder,
        SovaExecutorBuilder,
        SovaConsensusBuilder,
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
            SovaPoolBuilder::default().with_enable_tx_conditional(self.args.enable_tx_conditional);

        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(pool_builder)
            .payload(BasicPayloadServiceBuilder::new(SovaPayloadBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            )))
            .network(SovaNetworkBuilder)
            .executor(SovaExecutorBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            ))
            .consensus(SovaConsensusBuilder::default())
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
        SovaPoolBuilder,
        BasicPayloadServiceBuilder<SovaPayloadBuilder>,
        SovaNetworkBuilder,
        SovaExecutorBuilder,
        SovaConsensusBuilder,
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

/// A Sova transaction pool. This pool is closely associated with the
/// Optimism design except the L1Block validations are modified to validate
/// Bitcoin L1Block data.
#[derive(Debug, Clone)]
pub struct SovaPoolBuilder<T = reth_optimism_txpool::OpPooledTransaction> {
    /// Enforced overrides that are applied to the pool config.
    pub pool_config_overrides: PoolBuilderConfigOverrides,
    /// Enable transaction conditionals.
    pub enable_tx_conditional: bool,
    /// Supervisor client url
    pub supervisor_http: String,
    /// Supervisor safety level
    pub supervisor_safety_level: SafetyLevel,
    /// Marker for the pooled transaction type.
    _pd: core::marker::PhantomData<T>,
}

impl<T> Default for SovaPoolBuilder<T> {
    fn default() -> Self {
        Self {
            pool_config_overrides: Default::default(),
            enable_tx_conditional: false,
            supervisor_http: DEFAULT_SUPERVISOR_URL.to_string(),
            supervisor_safety_level: SafetyLevel::CrossUnsafe,
            _pd: Default::default(),
        }
    }
}

impl<T> SovaPoolBuilder<T> {
    /// Sets the `enable_tx_conditional` flag on the pool builder.
    pub fn with_enable_tx_conditional(mut self, enable_tx_conditional: bool) -> Self {
        self.enable_tx_conditional = enable_tx_conditional;
        self
    }

    /// Sets the [`PoolBuilderConfigOverrides`] on the pool builder.
    pub fn with_pool_config_overrides(
        mut self,
        pool_config_overrides: PoolBuilderConfigOverrides,
    ) -> Self {
        self.pool_config_overrides = pool_config_overrides;
        self
    }

    /// Sets the supervisor client
    pub fn with_supervisor(
        mut self,
        supervisor_client: String,
        supervisor_safety_level: SafetyLevel,
    ) -> Self {
        self.supervisor_http = supervisor_client;
        self.supervisor_safety_level = supervisor_safety_level;
        self
    }
}

impl<Node, T> PoolBuilder<Node> for SovaPoolBuilder<T>
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: OpHardforks>>,
    T: EthPoolTransaction<Consensus = TxTy<Node::Types>>
        + MaybeConditionalTransaction
        + MaybeInteropTransaction,
{
    type Pool = SovaTransactionPool<Node::Provider, DiskFileBlobStore, T>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let Self {
            pool_config_overrides,
            ..
        } = self;
        let data_dir = ctx.config().datadir();
        let blob_store = DiskFileBlobStore::open(data_dir.blobstore(), Default::default())?;
        // supervisor used for interop
        if ctx
            .chain_spec()
            .is_interop_active_at_timestamp(ctx.head().timestamp)
            && self.supervisor_http == DEFAULT_SUPERVISOR_URL
        {
            info!(target: "reth::cli",
                url=%DEFAULT_SUPERVISOR_URL,
                "Default supervisor url is used, consider changing --rollup.supervisor-http."
            );
        }
        let supervisor_client =
            SupervisorClient::new(self.supervisor_http.clone(), self.supervisor_safety_level).await;

        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .no_eip4844()
            .with_head_timestamp(ctx.head().timestamp)
            .kzg_settings(ctx.kzg_settings()?)
            .with_additional_tasks(
                pool_config_overrides
                    .additional_validation_tasks
                    .unwrap_or_else(|| ctx.config().txpool.additional_validation_tasks),
            )
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone())
            .map(|validator| {
                SovaTransactionValidator::new(validator)
                    // In --dev mode we can't require gas fees because we're unable to decode
                    // the L1 block info
                    .require_l1_data_gas_fee(!ctx.config().dev.dev)
                    .with_supervisor(supervisor_client.clone())
            });

        let transaction_pool = reth_transaction_pool::Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store,
            pool_config_overrides.apply(ctx.pool_config()),
        );
        info!(target: "reth::cli", "Transaction pool initialized");

        // spawn txpool maintenance tasks
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            if !ctx.config().txpool.disable_transactions_backup {
                // Use configured backup path or default to data dir
                let transactions_path = ctx
                    .config()
                    .txpool
                    .transactions_backup_path
                    .clone()
                    .unwrap_or_else(|| data_dir.txpool_transactions());

                let transactions_backup_config =
                    reth_transaction_pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(transactions_path);

                ctx.task_executor()
                    .spawn_critical_with_graceful_shutdown_signal(
                        "local transactions backup task",
                        |shutdown| {
                            reth_transaction_pool::maintain::backup_local_transactions_task(
                                shutdown,
                                pool.clone(),
                                transactions_backup_config,
                            )
                        },
                    );
            }

            // spawn the main maintenance task
            ctx.task_executor().spawn_critical(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool.clone(),
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_transaction_pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: pool.config().max_queued_lifetime,
                        no_local_exemptions: transaction_pool
                            .config()
                            .local_transactions_config
                            .no_exemptions,
                        ..Default::default()
                    },
                ),
            );
            debug!(target: "reth::cli", "Spawned txpool maintenance task");

            // spawn the Op txpool maintenance task
            let chain_events = ctx.provider().canonical_state_stream();
            ctx.task_executor().spawn_critical(
                "Op txpool interop maintenance task",
                reth_optimism_txpool::maintain::maintain_transaction_pool_interop_future(
                    pool.clone(),
                    chain_events,
                    supervisor_client,
                ),
            );
            debug!(target: "reth::cli", "Spawned Op interop txpool maintenance task");

            if self.enable_tx_conditional {
                // spawn the Op txpool maintenance task
                let chain_events = ctx.provider().canonical_state_stream();
                ctx.task_executor().spawn_critical(
                    "Op txpool conditional maintenance task",
                    reth_optimism_txpool::maintain::maintain_transaction_pool_conditional_future(
                        pool,
                        chain_events,
                    ),
                );
                debug!(target: "reth::cli", "Spawned Op conditional txpool maintenance task");
            }
        }

        Ok(transaction_pool)
    }
}

/// A Sova payload builder service
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SovaPayloadBuilder<Txs = ()> {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
}

impl SovaPayloadBuilder {
    pub fn new(config: SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config,
            bitcoin_client,
            best_transactions: (),
        }
    }
}

impl<Txs> SovaPayloadBuilder<Txs> {
    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(self, best_transactions: T) -> SovaPayloadBuilder<T> {
        let Self {
            config,
            bitcoin_client,
            ..
        } = self;
        SovaPayloadBuilder {
            config,
            bitcoin_client,
            best_transactions,
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
        Txs: OpPayloadTransactions<Pool::Transaction>,
    {
        let payload_builder = sova_payload::SovaPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new().with_gas_limit(ctx.payload_builder_config().gas_limit()),
            self.bitcoin_client.clone(),
            self.config,
        )
        .with_transactions(self.best_transactions.clone());

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
#[derive(Debug, Clone)]
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

/// A type that knows how to build the Sova network.
/// Similar to the Ethereum network builder, this builder spawns
/// an Ethereum p2p tx pool and p2p eth request handler.
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

/// A basic Sova consensus builder which uses unmodified
/// Ethereum style consensus to choose the canonical chain.
/// The EthBeaconConsensus consensus engine does basic checks
/// as outlined in the Ethereum execution specs.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for SovaConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: OpHardforks,
            Primitives: NodePrimitives<Receipt: DepositReceipt>,
        >,
    >,
{
    type Consensus = Arc<EthBeaconConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
    }
}
