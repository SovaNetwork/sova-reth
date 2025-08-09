use std::sync::Arc;

use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeComponents, NodeTypes, PayloadTypes, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder, PayloadBuilderBuilder,
    },
    node::FullNodeTypes,
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::{
    node::{OpAddOns, OpAddOnsBuilder, OpConsensusBuilder, OpNetworkBuilder, OpPoolBuilder},
    txpool::OpPooledTx,
    OpEngineTypes,
};
use reth_optimism_payload_builder::{
    builder::OpPayloadTransactions,
    config::{OpBuilderConfig, OpDAConfig},
};
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_optimism_primitives::OpPrimitives;

use reth_provider::providers::ProviderFactoryBuilder;
use reth_optimism_storage::OpStorage;
use reth_tracing::tracing::{error, info};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;

use sova_sentinel_client::SlotLockClient;

use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, SovaEvmConfig};

use crate::SovaArgs;

/// Storage implementation for Sova
pub type SovaStorage = OpStorage;

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
    pub async fn new(args: SovaArgs) -> Result<Self, Box<dyn std::error::Error>> {
        let btc_config: BitcoinConfig = BitcoinConfig::new(
            args.btc_network.clone().into(),
            &args.btc_network_url,
            &args.btc_rpc_username,
            &args.btc_rpc_password,
        );

        let sova_config = SovaConfig::new(
            btc_config,
            &args.network_utxos_url,
            &args.sentinel_url,
            args.sentinel_confirmation_threshold,
            args.sequencer.is_some(),
        );

        let bitcoin_client = BitcoinClient::new(
            &sova_config.bitcoin_config,
            sova_config.sentinel_confirmation_threshold,
        )
        .map_err(|e| format!("Failed to create Bitcoin client: {e}"))?;

        // Perform health checks
        Self::health_check_bitcoin(&bitcoin_client)?;
        Self::health_check_sentinel(&args.sentinel_url).await?;

        Ok(Self {
            args,
            bitcoin_client: Arc::new(bitcoin_client),
            sova_config,
            da_config: OpDAConfig::default(),
        })
    }

    /// Health check for Bitcoin service
    fn health_check_bitcoin(
        bitcoin_client: &BitcoinClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Performing Bitcoin service health check...");

        match bitcoin_client.get_current_block_info() {
            Ok(block_info) => {
                info!(
                    "Bitcoin service is healthy. Current block height: {}",
                    block_info.current_block_height
                );
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Bitcoin service health check failed: {e}");
                error!("{}", error_msg);
                Err(error_msg.into())
            }
        }
    }

    /// Health check for Sentinel service - performs both connection and basic RPC test
    async fn health_check_sentinel(sentinel_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Performing Sentinel service health check...");

        match SlotLockClient::connect(sentinel_url.to_string()).await {
            Ok(mut client) => {
                // Test the connection with a simple batch_get_slot_status call with empty slots
                // This verifies that the service is not just reachable but actually functional
                match client.batch_get_slot_status(0, 0, vec![]).await {
                    Ok(_) => {
                        info!(
                            "Sentinel service is healthy and functional at {}",
                            sentinel_url
                        );
                        Ok(())
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Sentinel service RPC test failed at {sentinel_url}: {e}");
                        error!("{}", error_msg);
                        Err(error_msg.into())
                    }
                }
            }
            Err(e) => {
                let error_msg = format!("Sentinel service health check failed: Unable to connect to {sentinel_url}: {e}");
                error!("{}", error_msg);
                Err(error_msg.into())
            }
        }
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
            .executor(SovaExecutorBuilder::new(self.sova_config.clone(), Arc::clone(&self.bitcoin_client)))
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
            .consensus(OpConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
    
    /// Returns a builder for the add-ons
    pub fn add_ons_builder(&self) -> OpAddOnsBuilder<op_alloy_network::Optimism> {
        OpAddOnsBuilder::default()
            .with_sequencer(self.args.sequencer.clone())
            .with_da_config(self.da_config.clone())
            .with_enable_tx_conditional(self.args.enable_tx_conditional)
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

    type AddOns =
        OpAddOns<
            NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
            reth_optimism_rpc::OpEthApiBuilder,
            reth_optimism_node::OpEngineValidatorBuilder,
            reth_optimism_node::OpEngineApiBuilder<reth_optimism_node::OpEngineValidatorBuilder>,
        >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        self.add_ons_builder().build()
    }
}

impl<N> DebugNode<N> for SovaNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block<op_alloy_consensus::OpTxEnvelope>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_node_api::BlockTy<Self> {
        let alloy_rpc_types_eth::Block {
            header,
            transactions,
            ..
        } = rpc_block;
        reth_optimism_primitives::OpBlock {
            header: header.inner,
            body: reth_optimism_primitives::OpBlockBody {
                transactions: transactions.into_transactions().collect(),
                ..Default::default()
            },
        }
    }

    fn local_payload_attributes_builder(
        chain_spec: &<Self as NodeTypes>::ChainSpec,
    ) -> impl reth_node_api::PayloadAttributesBuilder<<<Self as NodeTypes>::Payload as PayloadTypes>::PayloadAttributes> {
        reth_engine_local::LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

impl NodeTypes for SovaNode {
    type Primitives = OpPrimitives;
    type ChainSpec = OpChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = SovaStorage;
    type Payload = OpEngineTypes;
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

impl<Node, Pool, Txs> PayloadBuilderBuilder<Node, Pool, SovaEvmConfig> for SovaPayloadBuilder<Txs>
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
    type PayloadBuilder = sova_payload::SovaPayloadBuilder<Pool, Node::Provider, SovaEvmConfig, Txs>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: SovaEvmConfig,
    ) -> eyre::Result<Self::PayloadBuilder> {
        self.build(evm_config, ctx, pool)
    }
}

/// A type that knows how to build the Sova EVM.
///
/// The Sova EVM is customized such that there are Bitcoin precompiles as well as
/// a custom inspector which is used for enforcing transaction finality on Bitcoin.
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
    type EVM = SovaEvmConfig;
    // Executor type removed in v1.6.0 - functionality moved to EVM type

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        // Create SentinelClient for the worker
        let sentinel_url = std::env::var("SOVA_SENTINEL_URL")
            .unwrap_or_else(|_| "http://[::1]:50051".to_string());
        let confirmation_threshold = std::env::var("SOVA_SENTINEL_CONFIRMATION_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);
        let sentinel_client = sova_evm::SentinelClient::new(sentinel_url, confirmation_threshold);
        
        // Create SentinelWorker with bounded capacity
        let sentinel_worker = Arc::new(sova_evm::SentinelWorker::start(sentinel_client, 1000)
            .map_err(|e| eyre::eyre!("Failed to start sentinel worker: {}", e))?);
        
        info!("SOVA: Started sentinel worker for Bitcoin L2 slot locking");
        
        // Create the Sova EVM configuration that implements BlockExecutorFactory
        let evm_config = SovaEvmConfig::new(
            ctx.chain_spec().clone(),
            self.bitcoin_client.clone(),
            sentinel_worker
        );

        // In v1.6.0, we only return the EVM config which implements BlockExecutorFactory
        Ok(evm_config)
    }
}
