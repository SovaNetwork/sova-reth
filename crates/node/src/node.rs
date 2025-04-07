use std::sync::Arc;

use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_chainspec::ChainSpec;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor, NextBlockEnvAttributes};
use reth_node_api::{FullNodeComponents, NodeAddOns, NodeTypes};
use reth_node_builder::{
    components::{ComponentsBuilder, ExecutorBuilder, PayloadServiceBuilder}, node::FullNodeTypes, rpc::{BasicEngineApiBuilder, EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, EthApiCtx, RethRpcAddOns, RpcAddOns, RpcHandle}, BuilderContext, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig
};
use reth_node_ethereum::node::{
    EthereumAddOns, EthereumConsensusBuilder, EthereumNetworkBuilder, EthereumPoolBuilder,
};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_primitives::TransactionSigned;
use reth_provider::{CanonStateSubscriptions, EthStorage};
use reth_rpc::{eth::core::EthApiFor, ValidationApi};
use reth_rpc_api::{eth::FullEthApiServer, servers::BlockSubmissionValidationApiServer};
use reth_rpc_builder::{config::RethRpcServerConfig, RethRpcModule};
use reth_rpc_eth_types::{error::FromEvmError, EthApiError};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;

use revm::context::TxEnv;
use sova_cli::{BitcoinConfig, SovaConfig};
use sova_engine_primitives::SovaEngineTypes;
use sova_evm::{BitcoinClient, MyEvmConfig, SovaBlockExecutorProvider};
use sova_primitives::{tx::SovaTransaction, SovaPrimitives};

use crate::{engine::SovaEngineValidator, SovaArgs};

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
        EthereumPoolBuilder,
        MyPayloadBuilder,
        EthereumNetworkBuilder,
        MyExecutorBuilder,
        EthereumConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                Payload = SovaEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SovaPrimitives,
                Storage = EthStorage,
            >,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .payload(MyPayloadBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            ))
            .network(EthereumNetworkBuilder::default())
            .executor(MyExecutorBuilder::new(
                self.sova_config.clone(),
                Arc::clone(&self.bitcoin_client),
            ))
            .consensus(EthereumConsensusBuilder::default())
    }
}

impl NodeTypes for SovaNode {
    type Primitives = SovaPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = EthStorage;
    type Payload = SovaEngineTypes;
}

impl<N> Node<N> for SovaNode
where
    N: FullNodeTypes<
        Types: NodeTypes<
            Payload = SovaEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SovaPrimitives,
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

    type AddOns =
        SovaAddOns<NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        SovaAddOns::default()
    }
}

#[derive(Debug)]
pub struct SovaAddOns<N>
where
    N: FullNodeComponents,
{
    inner: RpcAddOns<
        N,
        SovaEthApiBuilder,
        SovaEngineValidatorBuilder,
        BasicEngineApiBuilder<SovaEngineValidatorBuilder>,
    >,
}

impl<N: FullNodeComponents> Default for SovaAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<Primitives = SovaPrimitives>>,
    SovaEthApiBuilder: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self { inner: Default::default() }
    }
}

impl<N> NodeAddOns<N> for SovaAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = SovaPrimitives,
            Storage = EthStorage,
            Payload = SovaEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SovaEthApiError: FromEvmError<N::Evm>,
    <N::Pool as TransactionPool>::Transaction: SovaPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type Handle = RpcHandle<N, SovaEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        let validation_api = ValidationApi::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.block_executor().clone(),
            ctx.config.rpc.flashbots_config(),
            Box::new(ctx.node.task_executor().clone()),
            Arc::new(SovaEngineValidator::new(ctx.config.chain.clone())),
        );

        self.inner
            .launch_add_ons_with(ctx, move |modules, _, _| {
                modules.merge_if_module_configured(
                    RethRpcModule::Flashbots,
                    validation_api.into_rpc(),
                )?;

                Ok(())
            })
            .await
    }
}

impl<N> RethRpcAddOns<N> for SovaAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = SovaPrimitives,
            Storage = EthStorage,
            Payload = SovaEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SovaEthApiError: FromEvmError<N::Evm>,
    <<N as FullNodeComponents>::Pool as TransactionPool>::Transaction: SovaPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = SovaTransaction<TxEnv>>,
{
    type EthApi = SovaEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.rpc_add_ons.hooks_mut()
    }
}

#[derive(Debug, Default, Clone)]
pub struct SovaEthApiBuilder;

impl<N> EthApiBuilder<N> for SovaEthApiBuilder
where
    N: FullNodeComponents,
    EthApiFor<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type EthApi = EthApiFor<N>;

    fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> Self::EthApi {
        reth_rpc::EthApiBuilder::new(
            ctx.components.provider().clone(),
            ctx.components.pool().clone(),
            ctx.components.network().clone(),
            ctx.components.evm_config().clone(),
        )
        .eth_cache(ctx.cache)
        .task_spawner(ctx.components.task_executor().clone())
        .gas_cap(ctx.config.rpc_gas_cap.into())
        .max_simulate_blocks(ctx.config.rpc_max_simulate_blocks)
        .eth_proof_window(ctx.config.eth_proof_window)
        .fee_history_cache_config(ctx.config.fee_history_cache)
        .proof_permits(ctx.config.proof_permits)
        .build()
    }
}

/// Builder for [`SovaEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SovaEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for SovaEngineValidatorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Payload = SovaEngineTypes, Primitives = SovaPrimitives>,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = SovaEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SovaEngineValidator::new(ctx.config.chain.clone()))
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyPayloadBuilder {
    pub config: SovaConfig,
    pub bitcoin_client: Arc<BitcoinClient>,
}

impl MyPayloadBuilder {
    pub fn new(config: SovaConfig, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            config,
            bitcoin_client,
        }
    }
}

impl<Node, Pool> PayloadServiceBuilder<Node, Pool> for MyPayloadBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = SovaEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SovaPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
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

        let conf = ctx.payload_builder_config();
        let payload_builder = sova_payload::MyPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new().with_gas_limit(conf.gas_limit()),
        );

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
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
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SovaPrimitives>,
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
