use std::sync::Arc;

use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder, PayloadBuilderBuilder,
    },
    node::FullNodeTypes,
    rpc::Identity,
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder,
};
use reth_node_api::{PayloadAttributesBuilder, PayloadTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::{
    node::{OpAddOns, OpConsensusBuilder, OpNetworkBuilder, OpPoolBuilder},
    txpool::OpPooledTx,
    OpEngineTypes, OpNextBlockEnvAttributes,
};
use reth_optimism_payload_builder::{
    config::{OpBuilderConfig, OpDAConfig}, 
    OpPayloadBuilder,
};
use reth_optimism_primitives::{OpPrimitives};

use reth_provider::{providers::ProviderFactoryBuilder};
use reth_tracing::tracing::{error, info};
use reth_trie_db::MerklePatriciaTrie;

use sova_sentinel_client::SlotLockClient;

use sova_cli::{BitcoinConfig, SovaConfig};
use sova_evm::{BitcoinClient, MyEvmConfig};

use crate::SovaArgs;

/// Storage implementation for Sova
pub type SovaStorage = reth_optimism_storage::OpStorage;


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

        let sova_payload_builder = SovaPayloadBuilder::new(
            compute_pending_block,
            self.da_config.clone()
        );
        
        let payload_service = BasicPayloadServiceBuilder::new(sova_payload_builder);

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
            .executor(SovaExecutorBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            ))
            .payload(payload_service)
            .network(OpNetworkBuilder {
                disable_txpool_gossip,
                disable_discovery_v4: !discovery_v4,
            })
            .consensus(OpConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }

    /// Returns a builder for [`OpAddOns`] with the sova configuration
    pub fn add_ons_builder<NetworkT>(&self) -> reth_optimism_node::OpAddOnsBuilder<NetworkT> {
        reth_optimism_node::OpAddOnsBuilder::default()
            .with_sequencer(self.args.sequencer.clone())
            .with_sequencer_headers(Vec::new())  // SovaArgs doesn't have sequencer_headers
            .with_da_config(self.da_config.clone())
            .with_enable_tx_conditional(self.args.enable_tx_conditional)
            .with_min_suggested_priority_fee(0)
            .with_historical_rpc(None)  // SovaArgs doesn't have historical_rpc
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

    type AddOns = OpAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
        reth_optimism_rpc::OpEthApiBuilder,
        reth_optimism_node::OpEngineValidatorBuilder,
        reth_optimism_node::OpEngineApiBuilder<reth_optimism_node::OpEngineValidatorBuilder>,
        Identity,
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
        _chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<<Self as NodeTypes>::Payload as PayloadTypes>::PayloadAttributes> {
        reth_engine_local::LocalPayloadAttributesBuilder::new(Arc::new(_chain_spec.clone()))
    }
}

impl NodeTypes for SovaNode {
    type Primitives = OpPrimitives;
    type ChainSpec = OpChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = SovaStorage;
    type Payload = OpEngineTypes;
}

/// Sova payload builder that wraps OpPayloadBuilder with slot lock enforcement
#[derive(Debug, Clone)]
pub struct SovaPayloadBuilder {
    pub compute_pending_block: bool,
    pub da_config: OpDAConfig,
}

impl SovaPayloadBuilder {
    pub fn new(compute_pending_block: bool, da_config: OpDAConfig) -> Self {
        Self {
            compute_pending_block,
            da_config,
        }
    }
}

impl<Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for SovaPayloadBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
            Storage = SovaStorage,
            Payload = OpEngineTypes,
        >,
    >,
    Pool: reth_transaction_pool::TransactionPool<Transaction: OpPooledTx<Consensus = reth_optimism_primitives::OpTransactionSigned>> + Unpin + 'static,
    Evm: reth_evm::ConfigureEvm<Primitives = OpPrimitives, NextBlockEnvCtx = OpNextBlockEnvAttributes> + 'static,
{
    type PayloadBuilder = OpPayloadBuilder<Pool, Node::Provider, Evm, ()>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let payload_builder = OpPayloadBuilder::with_builder_config(
            pool,
            ctx.provider().clone(),
            evm_config,
            OpBuilderConfig {
                da_config: self.da_config,
            },
        )
        .set_compute_pending_block(self.compute_pending_block)
        .with_transactions(());

        Ok(payload_builder)
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
    type EVM = MyEvmConfig;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        let evm_config =
            MyEvmConfig::new(&self.config, ctx.chain_spec(), ctx.task_executor().clone()).map_err(
                |e| {
                    eyre::eyre!(
                        "ExecutorBuilder::build_evm: Failed to create EVM config: {}",
                        e
                    )
                },
            )?;

        Ok(evm_config)
    }
}
