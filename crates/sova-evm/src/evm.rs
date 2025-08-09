use std::sync::Arc;

use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    precompiles::PrecompilesMap,
    Database, Evm, EvmFactory,
};
use reth_evm::EvmEnv;
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor, OpEvm, OpEvmFactory};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpRethReceiptBuilder};
use reth_op::OpReceipt;
use reth_optimism_primitives::OpTransactionSigned;
use reth_evm::{InspectorFor, ConfigureEvm};
use revm::database::State;
use op_revm::{OpSpecId, OpContext, OpHaltReason};
use revm::context_interface::result::EVMError;
use revm_context::TxEnv;
use alloy_consensus::{Header, Block};
use reth_primitives::{SealedBlock, SealedHeader};
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_evm::{OpBlockAssembler, OpNextBlockEnvAttributes};
use reth_tracing::tracing::debug;

use crate::{BitcoinClient, SentinelWorker, SovaBlockExecutor, precompiles::SovaPrecompiles, state_hook::SharedSovaStateHook};

/// Sova EVM configuration that integrates Bitcoin L2 functionality
/// with the Optimism execution model using Reth v1.6.0 patterns.
#[derive(Debug, Clone)]
pub struct SovaEvmConfig {
    /// Base Optimism EVM configuration that we delegate to
    inner: OpEvmConfig,
    /// Bitcoin client for precompile operations and L1 validation
    bitcoin_client: Arc<BitcoinClient>,
    /// Our custom EVM factory with Bitcoin precompiles
    evm_factory: SovaEvmFactory,
    /// State hook for capturing storage writes during execution
    state_hook: SharedSovaStateHook,
    /// Sentinel worker for slot lock coordination
    sentinel_worker: Arc<SentinelWorker>,
}

impl SovaEvmConfig {
    /// Creates a new Sova EVM configuration.
    pub fn new(chain_spec: Arc<OpChainSpec>, bitcoin_client: Arc<BitcoinClient>, sentinel_worker: Arc<SentinelWorker>) -> Self {
        let inner = OpEvmConfig::new(chain_spec, OpRethReceiptBuilder::default());
        
        // Create SovaEvmFactory with Bitcoin precompiles integrated
        let evm_factory = SovaEvmFactory::new(
            inner.evm_factory().clone(), 
            Arc::clone(&bitcoin_client),
            Arc::clone(&sentinel_worker)
        );
        
        // Create shared state hook for capturing storage writes
        let state_hook = SharedSovaStateHook::new();
        
        Self {
            inner,
            bitcoin_client,
            evm_factory,
            state_hook,
            sentinel_worker,
        }
    }

    /// Gets a reference to the state hook for accessing captured writes
    pub fn state_hook(&self) -> &SharedSovaStateHook {
        &self.state_hook
    }

    /// Returns the inner Optimism EVM config.
    pub fn inner(&self) -> &OpEvmConfig {
        &self.inner
    }
}

/// Implementation of BlockExecutorFactory for Sova
/// This is the key trait that Reth v1.6.0 uses to create custom executors
impl BlockExecutorFactory for SovaEvmConfig {
    type EvmFactory = SovaEvmFactory;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: OpEvm<&'a mut State<DB>, I, PrecompilesMap>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        // Create the underlying Optimism executor
        let op_executor = OpBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec().clone(),
            *self.inner.executor_factory.receipt_builder(),
        );

        // Wrap it in our Sova executor that adds slot locking functionality
        // TODO: Extract actual block number from context or database - using 0 for now
        let current_block_number = 0u64; // Placeholder - should be extracted from execution context
        SovaBlockExecutor::new(op_executor, Arc::clone(&self.bitcoin_client), Arc::clone(&self.sentinel_worker), current_block_number)
    }
}

/// Sova EVM Factory that creates EVMs with Bitcoin precompiles
#[derive(Debug, Clone)]
pub struct SovaEvmFactory {
    /// Base Optimism EVM factory
    inner: OpEvmFactory,
    /// Bitcoin precompiles
    precompiles: SovaPrecompiles,
}

impl SovaEvmFactory {
    pub fn new(inner: OpEvmFactory, bitcoin_client: Arc<BitcoinClient>, sentinel_worker: Arc<SentinelWorker>) -> Self {
        Self {
            inner,
            precompiles: SovaPrecompiles::new(bitcoin_client, sentinel_worker),
        }
    }
}

impl EvmFactory for SovaEvmFactory {
    type Evm<DB: Database, I: revm::Inspector<OpContext<DB>>> = OpEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = op_revm::OpTransaction<TxEnv>;
    type Error<DBError: std::error::Error + Send + Sync + 'static> = EVMError<DBError, op_revm::OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        env: alloy_evm::EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, revm::inspector::NoOpInspector> {
        use revm::Context;
        use op_revm::{precompiles::OpPrecompiles, DefaultOp, OpBuilder};
        use revm::inspector::NoOpInspector;
        
        let spec_id = env.cfg_env.spec;
        
        // Start with base OP precompiles
        let base_precompiles = OpPrecompiles::new_with_spec(spec_id);
        let mut precompiles_map = PrecompilesMap::from_static(base_precompiles.precompiles());
        
        // Add our Bitcoin precompiles
        SovaPrecompiles::add_to_precompiles_map(&mut precompiles_map, self.precompiles.bitcoin_client.clone(), self.precompiles.sentinel_worker.clone());
        
        // Build the OpEvm using the proper constructor
        let op_evm_inner = Context::op()
            .with_db(db)
            .with_block(env.block_env)
            .with_cfg(env.cfg_env)
            .build_op_with_inspector(NoOpInspector {})
            .with_precompiles(precompiles_map);
        
        let op_evm = OpEvm::new(op_evm_inner, false);
        
        debug!("SOVA: Created EVM with Bitcoin precompiles integrated");
        op_evm
    }

    fn create_evm_with_inspector<DB: Database, I: revm::Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        env: alloy_evm::EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        use revm::Context;
        use op_revm::{precompiles::OpPrecompiles, DefaultOp, OpBuilder};
        
        let spec_id = env.cfg_env.spec;
        
        // Start with base OP precompiles
        let base_precompiles = OpPrecompiles::new_with_spec(spec_id);
        let mut precompiles_map = PrecompilesMap::from_static(base_precompiles.precompiles());
        
        // Add our Bitcoin precompiles
        SovaPrecompiles::add_to_precompiles_map(&mut precompiles_map, self.precompiles.bitcoin_client.clone(), self.precompiles.sentinel_worker.clone());
        
        // Build the OpEvm using the proper constructor
        let op_evm_inner = Context::op()
            .with_db(db)
            .with_block(env.block_env)
            .with_cfg(env.cfg_env)
            .build_op_with_inspector(inspector)
            .with_precompiles(precompiles_map);
        
        let op_evm = OpEvm::new(op_evm_inner, true);
        
        debug!("SOVA: Created EVM with inspector and Bitcoin precompiles integrated");
        op_evm
    }
}

/// Implementation of ConfigureEvm for SovaEvmConfig
/// This delegates most functionality to the inner OpEvmConfig while adding Bitcoin L2 capabilities
impl ConfigureEvm for SovaEvmConfig {
    type Primitives = OpPrimitives;
    type Error = <OpEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = OpNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = OpBlockAssembler<OpChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<OpSpecId> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &OpNextBlockEnvAttributes,
    ) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block(
        &self,
        block: &SealedBlock<Block<OpTransactionSigned>>,
    ) -> OpBlockExecutionCtx {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> OpBlockExecutionCtx {
        self.inner.context_for_next_block(parent, attributes)
    }
}

/// Legacy trait for backwards compatibility during migration
pub trait WithInspector {
    // This trait is no longer needed in v1.6.0 since we don't use inspector hooks
    // Keeping it for now to avoid compilation errors during migration
}