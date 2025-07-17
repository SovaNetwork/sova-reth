mod evm;
mod execute;
mod inspector;
mod precompiles;
mod sova_revm;

use alloy_evm::Database as Alloy_Database;
use evm::{SovaEvm, SovaEvmFactory};
use inspector::SovaInspector;
pub use inspector::{AccessedStorage, BroadcastResult, SlotProvider, StorageChange, WithInspector};
use once_cell::race::OnceBox;
pub use precompiles::{BitcoinClient, BitcoinRpcPrecompile, SovaL1BlockInfo};
use reth_errors::BlockExecutionError;
use revm::{handler::EthPrecompiles, precompile::Precompiles, primitives::hardfork::SpecId};

use std::{error::Error, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::{Block, Header};
use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    EvmEnv,
};
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor};

use reth_evm::{execute::Executor, precompiles::PrecompilesMap, ConfigureEvm, InspectorFor};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpBlockAssembler, OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_primitives::{OpPrimitives, OpReceipt, OpTransactionSigned};
use reth_primitives::{SealedBlock, SealedHeader};
use reth_revm::{Database, State};
use reth_tasks::TaskExecutor;

use op_revm::{
    precompiles::{fjord, granite, isthmus},
    OpSpecId,
};

use sova_chainspec::{
    BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS, DECODE_TRANSACTION_ADDRESS,
    L1_BLOCK_CONTRACT_ADDRESS, PRECOMPILE_ADDRESSES, VAULT_SPEND_ADDRESS,
};
use sova_cli::SovaConfig;

use crate::execute::SovaBlockExecutor;
use crate::precompiles::{
    SOVA_BITCOIN_PRECOMPILE_BROADCAST_TRANSACTION,
    SOVA_BITCOIN_PRECOMPILE_CONVERT_ADDRESS, SOVA_BITCOIN_PRECOMPILE_DECODE_TRANSACTION,
    SOVA_BITCOIN_PRECOMPILE_VAULT_SPEND,
};

// Custom precompiles that include Bitcoin precompile
#[derive(Clone, Default)]
pub struct SovaPrecompiles {
    pub inner: EthPrecompiles,
    pub spec: OpSpecId,
}

impl SovaPrecompiles {
    pub fn new() -> Self {
        Self::new_with_spec(OpSpecId::ISTHMUS)
    }

    #[inline]
    pub fn new_with_spec(spec: OpSpecId) -> Self {
        let global_precompiles = match spec {
            spec @ (OpSpecId::BEDROCK
            | OpSpecId::REGOLITH
            | OpSpecId::CANYON
            | OpSpecId::ECOTONE) => Precompiles::new(spec.into_eth_spec().into()),
            OpSpecId::FJORD => fjord(),
            OpSpecId::GRANITE | OpSpecId::HOLOCENE => granite(),
            OpSpecId::ISTHMUS | OpSpecId::INTEROP | OpSpecId::OSAKA => isthmus(),
        };

        static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
        let precompiles = INSTANCE.get_or_init(|| {
            let mut precompiles = global_precompiles.clone();
            precompiles.extend([
                SOVA_BITCOIN_PRECOMPILE_BROADCAST_TRANSACTION,
                SOVA_BITCOIN_PRECOMPILE_DECODE_TRANSACTION,
                SOVA_BITCOIN_PRECOMPILE_CONVERT_ADDRESS,
                SOVA_BITCOIN_PRECOMPILE_VAULT_SPEND,
            ]);
            Box::new(precompiles)
        });

        Self {
            inner: EthPrecompiles {
                precompiles,
                spec: SpecId::default(),
            },
            spec,
        }
    }

    #[inline]
    pub fn precompiles(self) -> PrecompilesMap {
        PrecompilesMap::from_static(self.inner.precompiles)
    }
}

// impl<CTX> PrecompileProvider<CTX> for SovaPrecompiles
// where
//     CTX: ContextTr<Cfg: Cfg<Spec = OpSpecId>>,
// {
//     type Output = InterpreterResult;

//     #[inline]
//     fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
//         *self = Self::new_with_spec(spec);
//         true
//     }

//     fn run(
//         &mut self,
//         context: &mut CTX,
//         address: &Address,
//         inputs: &InputsImpl,
//         is_static: bool,
//         gas_limit: u64,
//     ) -> Result<Option<Self::Output>, String> {
//         let inputs = InputsImpl {
//             target_address: inputs.target_address,
//             caller_address: inputs.caller_address,
//             input: if *address == BTC_PRECOMPILE_ADDRESS {
//                 let input =
//                     BitcoinRpcPrecompileInput::new(inputs.input.clone(), inputs.caller_address);
//                 alloy_rlp::encode(input).to_vec().into()
//             } else {
//                 inputs.input.clone()
//             },
//             call_value: inputs.call_value,
//         };
//         self.inner
//             .run(context, address, &inputs, is_static, gas_limit)
//     }

//     fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
//         // Combine standard precompiles with Bitcoin precompile address
//         self.inner.warm_addresses()
//     }

//     fn contains(&self, address: &Address) -> bool {
//         self.inner.contains(address)
//     }
// }

#[derive(Clone, Debug)]
pub struct SovaEvmConfig {
    /// Wrapper around optimism configuration
    inner: OpEvmConfig,
    /// EVM Factory
    evm_factory: SovaEvmFactory,
    /// Engine inspector used to track bitcoin precompile execution for double spends
    inspector: Arc<RwLock<SovaInspector>>,
}

impl SovaEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<OpChainSpec>,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn Error>> {
        let inspector = SovaInspector::new(
            PRECOMPILE_ADDRESSES,
            vec![
                BROADCAST_TRANSACTION_ADDRESS,
                DECODE_TRANSACTION_ADDRESS,
                CONVERT_ADDRESS_ADDRESS,
                VAULT_SPEND_ADDRESS,
                L1_BLOCK_CONTRACT_ADDRESS,
            ],
            config.sentinel_url.clone(),
            task_executor,
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        Ok(Self {
            inner: OpEvmConfig::optimism(chain_spec),
            evm_factory: SovaEvmFactory::new(),
            inspector: Arc::new(RwLock::new(inspector)),
        })
    }

    /// Returns the chain spec associated with this configuration
    pub const fn chain_spec(&self) -> &Arc<OpChainSpec> {
        self.inner.chain_spec()
    }
}

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
        evm: SovaEvm<&'a mut State<DB>, I, PrecompilesMap>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
        <DB as Database>::Error: Send + Sync + 'static,
    {
        OpBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec().clone(),
            *self.inner.executor_factory.receipt_builder(),
        )
    }
}

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

    fn executor<DB: Alloy_Database>(
        &self,
        db: DB,
    ) -> impl Executor<DB, Primitives = Self::Primitives, Error = BlockExecutionError> {
        SovaBlockExecutor::new(self, db)
    }

    fn batch_executor<DB: Alloy_Database>(
        &self,
        db: DB,
    ) -> impl Executor<DB, Primitives = Self::Primitives, Error = BlockExecutionError> {
        SovaBlockExecutor::new(self, db)
    }
}

impl WithInspector for SovaEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.inspector
    }
}

impl WithInspector for &SovaEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.inspector
    }
}
