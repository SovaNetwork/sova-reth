mod constants;
mod execute;
mod inspector;
mod precompiles;

use constants::BTC_PRECOMPILE_ADDRESS;
use execute::MyBlockExecutor;
pub use execute::MyExecutionStrategyFactory;
use inspector::SovaInspector;
pub use inspector::{AccessedStorage, BroadcastResult, SlotProvider, StorageChange, WithInspector};
pub use precompiles::BitcoinClient;
use precompiles::{BitcoinRpcPrecompile, StatefulPrecompile};

use std::{error::Error, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_primitives::Bytes;
use alloy_evm::{EvmFactory, eth::EthEvmContext};

use reth_chainspec::ChainSpec;
use reth_evm::{block::{BlockExecutorFactory, BlockExecutorFor}, env::EvmEnv, eth::EthBlockExecutionCtx, ConfigureEvm, Database, InspectorFor};
use reth_node_api::NextBlockEnvAttributes;
use reth_primitives::{Receipt, SealedBlock, TransactionSigned};
use reth_revm::{
    context::{Cfg, Context, TxEnv}, context_interface::result::{EVMError, HaltReason}, handler::{EthPrecompiles, PrecompileProvider}, inspector::{Inspector, NoOpInspector}, interpreter::{interpreter::EthInterpreter, Gas, InstructionResult, InterpreterResult}, primitives::{hardfork::SpecId, Address as RevmAddress}, MainBuilder, MainContext, State
};
use reth_tasks::TaskExecutor;
use reth_evm_ethereum::{EthEvm, EthEvmConfig};

use sova_cli::SovaConfig;

// Custom precompiles that include Bitcoin precompile
#[derive(Clone)]
pub struct CustomPrecompiles {
    // Standard Ethereum precompiles
    standard: EthPrecompiles,
    // Our Bitcoin precompile
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl CustomPrecompiles {
    fn new(bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>) -> Self {
        Self {
            standard: EthPrecompiles::default(),
            bitcoin_rpc_precompile,
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for CustomPrecompiles
where
    CTX: reth_revm::context_interface::ContextTr,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) {
        // Set spec on the standard precompiles
        PrecompileProvider::<CTX>::set_spec(&mut self.standard, spec);
    }

    fn run(
        &mut self,
        context: &mut CTX,
        address: &RevmAddress,
        bytes: &Bytes,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        // Handle Bitcoin precompile
        if *address == BTC_PRECOMPILE_ADDRESS {
            let precompile = self.bitcoin_rpc_precompile.read();
            
            // Use EvmEnv from reth_evm
            let env = reth_evm::EvmEnv::default();
            
            // Call Bitcoin precompile using the StatefulPrecompile trait
            match StatefulPrecompile::call(&*precompile, bytes, 0, &env) {
                Ok(result) => {
                    // Convert to InterpreterResult
                    Ok(Some(InterpreterResult {
                        result: InstructionResult::Return,
                        output: result.bytes,
                        gas: Gas::new(result.gas_used),
                    }))
                }
                Err(err) => Err(format!("Bitcoin precompile error: {:?}", err)),
            }
        } else {
            // Delegate to standard precompiles
            self.standard.run(context, address, bytes, gas_limit)
        }
    }

    fn contains(&self, address: &RevmAddress) -> bool {
        *address == BTC_PRECOMPILE_ADDRESS || self.standard.contains(address)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = RevmAddress>> {
        // Add Bitcoin precompile address to warm addresses from standard precompiles
        let standard_addresses = self.standard.warm_addresses();
        
        // Chain our Bitcoin precompile address onto the standard warm addresses
        Box::new(standard_addresses.chain(std::iter::once(BTC_PRECOMPILE_ADDRESS)))
    }
}

#[derive(Clone)]
pub struct MyEvmFactory {
    /// Bitcoin precompile execution logic
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    /// Engine inspector used to track bitcoin precompile execution for double spends
    inspector: Arc<RwLock<SovaInspector>>,
}

impl MyEvmFactory {
    pub fn new(
        config: &SovaConfig,
        bitcoin_client: Arc<BitcoinClient>,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn Error>> {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(
            bitcoin_client.clone(),
            config.bitcoin_config.network,
            config.network_signing_url.clone(),
            config.network_utxo_url.clone(),
        )?;

        let inspector = SovaInspector::new(
            BTC_PRECOMPILE_ADDRESS,
            vec![BTC_PRECOMPILE_ADDRESS],
            config.sentinel_url.clone(),
            task_executor,
            bitcoin_client,
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        Ok(Self {
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
            inspector: Arc::new(RwLock::new(inspector)),
        })
    }
}

impl EvmFactory for MyEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        EthEvm<DB, I, CustomPrecompiles>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(CustomPrecompiles::new(self.bitcoin_rpc_precompile.clone()));

        EthEvm::new(evm, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        EthEvm::new(
            self.create_evm(db, input).into_inner().with_inspector(inspector), 
            true
        )
    }
}

#[derive(Clone)]
pub struct MyEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// Custom EVM factory
    factory: MyEvmFactory,
}

impl MyEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<ChainSpec>,
        bitcoin_client: Arc<BitcoinClient>,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn Error>> {
        let factory = MyEvmFactory::new(config, bitcoin_client, task_executor)?;
        
        Ok(Self {
            inner: EthEvmConfig::new(chain_spec),
            factory
        })
    }
}

impl BlockExecutorFactory for MyEvmConfig {
    type EvmFactory = MyEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;

    fn evm_factory(&self) -> &MyEvmFactory {
        &self.factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<&'a mut State<DB>, I, CustomPrecompiles>,
        ctx: EthBlockExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        MyBlockExecutor::new(
            evm, 
            ctx,
            self.inner.chain_spec(),
            self.inner.executor_factory.receipt_builder(),
            self
        )
    }
}

// ConfigureEvm implementation delegates to inner
impl ConfigureEvm for MyEvmConfig {
    type Primitives = <reth_evm_ethereum::EthEvmConfig<MyEvmFactory> as ConfigureEvm>::Primitives;
    type Error = <reth_evm_ethereum::EthEvmConfig<MyEvmFactory> as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <reth_evm_ethereum::EthEvmConfig<MyEvmFactory> as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = <reth_evm_ethereum::EthEvmConfig<MyEvmFactory> as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<SpecId> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv<SpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock,
    ) -> <Self::BlockExecutorFactory as alloy_evm::block::BlockExecutorFactory>::ExecutionCtx<'a> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &reth_primitives::SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> <Self::BlockExecutorFactory as alloy_evm::block::BlockExecutorFactory>::ExecutionCtx<'_> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl WithInspector for MyEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.factory.inspector
    }
}
