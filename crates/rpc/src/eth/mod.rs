mod block;
mod call;
mod pending_block;
mod receipt;
mod transaction;

use op_alloy_network::Optimism;
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::OpEthApiError;

use std::{fmt, sync::Arc};

use alloy_primitives::U256;
use reth_chain_state::CanonStateSubscriptions;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_network_api::NetworkInfo;
use reth_node_builder::{
    rpc::{EthApiBuilder, EthApiCtx},
    ConfigureEvm, FullNodeComponents, NodePrimitives,
};
use reth_rpc::eth::{core::EthApiInner, DevSigner, EthApiTypes, FullEthApiServer, RpcNodeCore};
use reth_rpc_eth_api::{
    helpers::{
        AddDevSigners, EthApiSpec, EthFees, EthSigner, EthState, LoadBlock, LoadFee, LoadState,
        SpawnBlocking, Trace,
    },
    FromEvmError, RpcNodeCoreExt,
};
use reth_rpc_eth_types::{EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_storage_api::{
    BlockNumReader, BlockReader, BlockReaderIdExt, ProviderBlock, ProviderHeader, ProviderReceipt,
    ProviderTx, StageCheckpointReader, StateProviderFactory,
};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use reth_transaction_pool::TransactionPool;

/// Adapter for [`EthApiInner`], which holds all the data required to serve core `eth_` API.
pub type EthApiNodeBackend<N> = EthApiInner<
    <N as RpcNodeCore>::Provider,
    <N as RpcNodeCore>::Pool,
    <N as RpcNodeCore>::Network,
    <N as RpcNodeCore>::Evm,
>;

/// A helper trait with requirements for [`RpcNodeCore`] to be used in [`SovaEthApi`].
pub trait SovaNodeCore: RpcNodeCore<Provider: BlockReader> {}
impl<T> SovaNodeCore for T where T: RpcNodeCore<Provider: BlockReader> {}

/// Sova-Reth `Eth` API implementation.
///
/// This type provides the functionality for handling `eth_` related requests.
///
/// This wraps a default `Eth` implementation, and provides additional functionality where the
/// optimism spec deviates from the default (ethereum) spec, e.g. transaction forwarding to the
/// sequencer, receipts, additional RPC fields for transaction receipts.
///
/// This type implements the [`FullEthApi`](reth_rpc_eth_api::helpers::FullEthApi) by implemented
/// all the `Eth` helper traits and prerequisite traits.
#[derive(Clone)]
pub struct SovaEthApi<N: SovaNodeCore> {
    /// Gateway to node's core components.
    pub inner: Arc<SovaEthApiInner<N>>,
}

impl<N> SovaEthApi<N>
where
    N: SovaNodeCore<
        Provider: BlockReaderIdExt
                      + ChainSpecProvider
                      + CanonStateSubscriptions<Primitives = OpPrimitives>
                      + Clone
                      + 'static,
    >,
{
    /// Returns a reference to the [`EthApiNodeBackend`].
    pub fn eth_api(&self) -> &EthApiNodeBackend<N> {
        self.inner.eth_api()
    }

    /// Build a [`SovaEthApi`] using [`SovaEthApiBuilder`].
    pub const fn builder() -> SovaEthApiBuilder {
        SovaEthApiBuilder::new()
    }
}

impl<N> EthApiTypes for SovaEthApi<N>
where
    Self: Send + Sync,
    N: SovaNodeCore,
{
    type Error = OpEthApiError;
    type NetworkTypes = Optimism;
    type TransactionCompat = Self;

    fn tx_resp_builder(&self) -> &Self::TransactionCompat {
        self
    }
}

impl<N> RpcNodeCore for SovaEthApi<N>
where
    N: SovaNodeCore,
{
    type Primitives = OpPrimitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = <N as RpcNodeCore>::Evm;
    type Network = <N as RpcNodeCore>::Network;
    type PayloadBuilder = ();

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.eth_api.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.eth_api.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.eth_api.network()
    }

    #[inline]
    fn payload_builder(&self) -> &Self::PayloadBuilder {
        &()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.eth_api.provider()
    }
}

impl<N> RpcNodeCoreExt for SovaEthApi<N>
where
    N: SovaNodeCore,
{
    #[inline]
    fn cache(&self) -> &EthStateCache<ProviderBlock<N::Provider>, ProviderReceipt<N::Provider>> {
        self.inner.eth_api.cache()
    }
}

impl<N> EthApiSpec for SovaEthApi<N>
where
    N: SovaNodeCore<
        Provider: ChainSpecProvider<ChainSpec: EthereumHardforks>
                      + BlockNumReader
                      + StageCheckpointReader,
        Network: NetworkInfo,
    >,
{
    type Transaction = ProviderTx<Self::Provider>;

    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.eth_api.starting_block()
    }

    #[inline]
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.inner.eth_api.signers()
    }
}

impl<N> SpawnBlocking for SovaEthApi<N>
where
    Self: Send + Sync + Clone + 'static,
    N: SovaNodeCore,
{
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.inner.eth_api.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.eth_api.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.eth_api.blocking_task_guard()
    }
}

impl<N> LoadFee for SovaEthApi<N>
where
    Self: LoadBlock<Provider = N::Provider>,
    N: SovaNodeCore<
        Provider: BlockReaderIdExt
                      + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
    >,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.eth_api.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache {
        self.inner.eth_api.fee_history_cache()
    }
}

impl<N> LoadState for SovaEthApi<N> where
    N: SovaNodeCore<
        Provider: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>,
        Pool: TransactionPool,
    >
{
}

impl<N> EthState for SovaEthApi<N>
where
    Self: LoadState + SpawnBlocking,
    N: SovaNodeCore,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_api.eth_proof_window()
    }
}

impl<N> EthFees for SovaEthApi<N>
where
    Self: LoadFee,
    N: SovaNodeCore,
{
}

impl<N> Trace for SovaEthApi<N>
where
    Self: RpcNodeCore<Provider: BlockReader>
        + LoadState<
            Evm: ConfigureEvm<
                Primitives: NodePrimitives<
                    BlockHeader = ProviderHeader<Self::Provider>,
                    SignedTx = ProviderTx<Self::Provider>,
                >,
            >,
            Error: FromEvmError<Self::Evm>,
        >,
    N: SovaNodeCore,
{
}

impl<N> AddDevSigners for SovaEthApi<N>
where
    N: SovaNodeCore,
{
    fn with_dev_accounts(&self) {
        *self.inner.eth_api.signers().write() = DevSigner::random_signers(20)
    }
}

impl<N: SovaNodeCore> fmt::Debug for SovaEthApi<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SovaEthApi").finish_non_exhaustive()
    }
}

/// Container type `SovaEthApi`
#[allow(missing_debug_implementations)]
pub struct SovaEthApiInner<N: SovaNodeCore> {
    /// Gateway to node's core components.
    pub eth_api: EthApiNodeBackend<N>,
}

impl<N: SovaNodeCore> SovaEthApiInner<N> {
    /// Returns a reference to the [`EthApiNodeBackend`].
    const fn eth_api(&self) -> &EthApiNodeBackend<N> {
        &self.eth_api
    }
}

/// Builds [`SovaEthApi`] for Sova.
#[derive(Debug, Default)]
pub struct SovaEthApiBuilder;

impl SovaEthApiBuilder {
    /// Creates a new [`SovaEthApiBuilder`].
    pub const fn new() -> Self {
        Self
    }
}

impl<N> EthApiBuilder<N> for SovaEthApiBuilder
where
    N: FullNodeComponents,
    SovaEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type EthApi = SovaEthApi<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let eth_api = reth_rpc::EthApiBuilder::new(
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
        .gas_oracle_config(ctx.config.gas_oracle)
        .build_inner();

        Ok(SovaEthApi {
            inner: Arc::new(SovaEthApiInner { eth_api }),
        })
    }
}
