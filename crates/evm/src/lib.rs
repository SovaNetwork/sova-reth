mod constants;
mod execute;
mod inspector;
mod precompiles;

use constants::BTC_PRECOMPILE_ADDRESS;
pub use execute::MyBlockExecutor;
use inspector::SovaInspector;
pub use inspector::{AccessedStorage, BroadcastResult, SlotProvider, StorageChange, WithInspector};
pub use precompiles::BitcoinClient;
use precompiles::BitcoinRpcPrecompile;

use std::{error::Error, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{EthBlockExecutionCtx, EthEvmContext},
    EthEvm, EvmFactory,
};
use alloy_primitives::{Address, Bytes};

use reth_chainspec::ChainSpec;
use reth_evm::{env::EvmEnv, ConfigureEvm, InspectorFor, NextBlockEnvAttributes};
use reth_evm_ethereum::EthBlockAssembler;
use reth_node_ethereum::EthEvmConfig;
use reth_primitives::{Receipt, SealedBlock, SealedHeader, TransactionSigned};
use reth_revm::{
    context::{Cfg, Context, TxEnv},
    context_interface::{
        result::{EVMError, HaltReason},
        ContextTr,
    },
    handler::{EthPrecompiles, PrecompileProvider},
    inspector::{Inspector, NoOpInspector},
    interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
    primitives::hardfork::SpecId,
    Database, MainBuilder, MainContext, State,
};
use reth_tasks::TaskExecutor;

use sova_cli::SovaConfig;

// Custom precompiles that include Bitcoin precompile
#[derive(Clone)]
pub struct CustomPrecompiles {
    /// Standard Ethereum precompiles
    pub standard: EthPrecompiles,
    /// Bitcoin RPC precompile
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl CustomPrecompiles {
    pub fn new(bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>) -> Self {
        Self {
            standard: EthPrecompiles::default(),
            bitcoin_rpc_precompile,
        }
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for CustomPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        // Explicitly call the PrecompileProvider implementation for EthPrecompiles
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.standard, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        if *address == BTC_PRECOMPILE_ADDRESS {
            // Handle Bitcoin precompile
            let precompile = self.bitcoin_rpc_precompile.write();

            let mut result = InterpreterResult {
                result: InstructionResult::Return,
                gas: Gas::new(gas_limit),
                output: Bytes::new(),
            };
            // Call the Bitcoin precompile implementation
            match precompile.run(&inputs.input) {
                Ok(output) => {
                    let underflow = result.gas.record_cost(output.gas_used);
                    assert!(underflow, "Gas underflow is not possible");
                    result.result = InstructionResult::Return;
                    result.output = output.bytes;
                }
                Err(PrecompileError::Fatal(e)) => return Err(e),
                Err(e) => {
                    result.result = if e.is_oog() {
                        InstructionResult::PrecompileOOG
                    } else {
                        InstructionResult::PrecompileError
                    };
                }
            }

            Ok(Some(result))
        } else {
            // Delegate to standard precompiles
            self.standard
                .run(context, address, inputs, is_static, gas_limit)
        }
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        // Combine standard precompiles with Bitcoin precompile address
        Box::new(
            self.standard
                .warm_addresses()
                .chain(std::iter::once(BTC_PRECOMPILE_ADDRESS)),
        )
    }

    fn contains(&self, address: &Address) -> bool {
        *address == BTC_PRECOMPILE_ADDRESS || self.standard.contains(address)
    }
}

#[derive(Clone, Debug)]
pub struct MyEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// EVM Factory
    evm_factory: MyEvmFactory,
    /// Bitcoin precompile execution logic
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    /// Engine inspector used to track bitcoin precompile execution for double spends
    inspector: Arc<RwLock<SovaInspector>>,
}

impl MyEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<ChainSpec>,
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
            inner: EthEvmConfig::new(chain_spec),
            evm_factory: MyEvmFactory::default(),
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
            inspector: Arc::new(RwLock::new(inspector)),
        })
    }
}

impl BlockExecutorFactory for MyEvmConfig {
    type EvmFactory = MyEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<&'a mut State<DB>, I, CustomPrecompiles>,
        ctx: EthBlockExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + Inspector<EthEvmContext<&'a mut State<DB>>> + 'a,
        <DB as Database>::Error: Send + Sync + 'static,
    {
        MyBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec(),
            self.inner.executor_factory.receipt_builder(),
        )
    }
}

impl ConfigureEvm for MyEvmConfig {
    type Primitives = <EthEvmConfig as ConfigureEvm>::Primitives;
    type Error = <EthEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <EthEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

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

    fn context_for_block<'a>(&self, block: &'a SealedBlock) -> EthBlockExecutionCtx<'a> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl WithInspector for MyEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.inspector
    }
}

/// Custom EVM configuration
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MyEvmFactory {
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl Default for MyEvmFactory {
    fn default() -> Self {
        Self {
            bitcoin_rpc_precompile: Arc::new(RwLock::new(BitcoinRpcPrecompile::default())),
        }
    }
}

impl MyEvmFactory {
    /// Create a new factory with the given Bitcoin precompile
    pub fn new(bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>) -> Self {
        Self {
            bitcoin_rpc_precompile,
        }
    }
}

impl EvmFactory for MyEvmFactory {
    type Evm<DB, I>
        = EthEvm<DB, I, CustomPrecompiles>
    where
        DB: Database,
        I: Inspector<Self::Context<DB>>,
        <DB as Database>::Error: Send + Sync + 'static;

    type Context<DB>
        = EthEvmContext<DB>
    where
        DB: Database,
        <DB as Database>::Error: Send + Sync + 'static;

    type Tx = TxEnv;
    type Error<DBError: Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, NoOpInspector>
    where
        <DB as Database>::Error: Send + Sync + 'static,
    {
        let custom_precompiles = CustomPrecompiles::new(self.bitcoin_rpc_precompile.clone());

        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(custom_precompiles);

        EthEvm::new(evm, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I>
    where
        <DB as Database>::Error: Send + Sync + 'static,
    {
        EthEvm::new(
            self.create_evm(db, input)
                .into_inner()
                .with_inspector(inspector),
            true,
        )
    }
}
