mod constants;
mod evm;
mod execute;
mod inspector;
mod precompiles;
mod sova_revm;

use constants::BTC_PRECOMPILE_ADDRESS;
pub use constants::{L1_BLOCK_CONTRACT_ADDRESS, L1_BLOCK_CONTRACT_CALLER};
use evm::{SovaEvm, SovaEvmFactory};
pub use execute::{MyBlockExecutor, SovaBlockExecutorProvider};
use inspector::SovaInspector;
pub use inspector::{AccessedStorage, BroadcastResult, SlotProvider, StorageChange, WithInspector};
pub use precompiles::BitcoinClient;
use precompiles::BitcoinRpcPrecompile;

use std::{error::Error, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::{Block, Header};
use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    EvmEnv,
};
use alloy_op_evm::OpBlockExecutionCtx;
use alloy_primitives::{Address, Bytes};

use reth_evm::{ConfigureEvm, InspectorFor};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpBlockAssembler, OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_primitives::{OpPrimitives, OpReceipt, OpTransactionSigned};
use reth_primitives::{SealedBlock, SealedHeader};
use reth_revm::{
    context::Cfg,
    context_interface::ContextTr,
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
    Database, State,
};
use reth_tasks::TaskExecutor;

use op_revm::OpSpecId;

use sova_cli::SovaConfig;

// Custom precompiles that include Bitcoin precompile
#[derive(Clone, Default)]
pub struct CustomPrecompiles {
    /// Standard Ethereum precompiles (prague)
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
    /// Wrapper around optimism configuration
    inner: OpEvmConfig,
    /// EVM Factory
    evm_factory: SovaEvmFactory,
    /// Engine inspector used to track bitcoin precompile execution for double spends
    inspector: Arc<RwLock<SovaInspector>>,
}

impl MyEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<OpChainSpec>,
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
            vec![BTC_PRECOMPILE_ADDRESS, L1_BLOCK_CONTRACT_ADDRESS],
            config.sentinel_url.clone(),
            task_executor,
            bitcoin_client,
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        let bitcoin_precompile = Arc::new(RwLock::new(bitcoin_precompile));
        Ok(Self {
            inner: OpEvmConfig::optimism(chain_spec),
            evm_factory: SovaEvmFactory::new(bitcoin_precompile),
            inspector: Arc::new(RwLock::new(inspector)),
        })
    }

    /// Returns the chain spec associated with this configuration
    pub const fn chain_spec(&self) -> &Arc<OpChainSpec> {
        self.inner.chain_spec()
    }
}

impl BlockExecutorFactory for MyEvmConfig {
    type EvmFactory = SovaEvmFactory;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: SovaEvm<&'a mut State<DB>, I, CustomPrecompiles>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
        <DB as Database>::Error: Send + Sync + 'static,
    {
        MyBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec().clone(),
            *self.inner.executor_factory.receipt_builder(),
        )
    }
}

impl ConfigureEvm for MyEvmConfig {
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

impl WithInspector for MyEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.inspector
    }
}
