use core::fmt::Debug;

use alloy_evm::{precompiles::PrecompilesMap, Database, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, Bytes};
use core::ops::{Deref, DerefMut};
use op_revm::{OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError};
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::result::{EVMError, ResultAndState},
    handler::{instructions::EthInstructions, PrecompileProvider},
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
};

use crate::revm::default::DefaultSova;
use crate::{inspector::SovaInspector, revm::builder::SovaBuilder};
use crate::{sova_revm::SovaRevmEvm, SovaPrecompiles};

/// Sova EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`SovaRevmEvm`](sova_revm::SovaRevmEvm) type.
#[allow(missing_debug_implementations)] // missing revm::OpContext Debug impl
pub struct SovaEvm<DB: Database, I = SovaInspector, P = SovaPrecompiles> {
    inner: SovaRevmEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
    inspect: bool,
}

impl<DB: Database, I, P> SovaEvm<DB, I, P> {
    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &OpContext<DB> {
        &self.inner.0.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut OpContext<DB> {
        &mut self.inner.0.ctx
    }
}

impl<DB: Database, I, P> SovaEvm<DB, I, P> {
    /// Creates a new Sova EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] of the given
    /// [`SovaRevmEvm`](sova_revm::SovaRevmEvm) should be invoked on [`Evm::transact`].
    pub const fn new(
        evm: SovaRevmEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
        inspect: bool,
    ) -> Self {
        Self {
            inner: evm,
            inspect,
        }
    }
}

impl<DB: Database, I, P> Deref for SovaEvm<DB, I, P> {
    type Target = OpContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, P> DerefMut for SovaEvm<DB, I, P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, P> Evm for SovaEvm<DB, I, P>
where
    DB: Database,
    I: Inspector<OpContext<DB>>,
    P: PrecompileProvider<OpContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = OpTransaction<TxEnv>;
    type Error = EVMError<DB::Error, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = P;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context {
            block: block_env,
            cfg: cfg_env,
            journaled_state,
            ..
        } = self.inner.0.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.0.ctx.journaled_state.database,
            &self.inner.0.inspector,
            &self.inner.0.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.0.ctx.journaled_state.database,
            &mut self.inner.0.inspector,
            &mut self.inner.0.precompiles,
        )
    }
}

/// Factory producing [`SovaEvm`]s.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SovaEvmFactory;

impl EvmFactory for SovaEvmFactory {
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = SovaEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = OpTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let spec_id = input.cfg_env.spec;
        SovaEvm {
            inner: Context::sova()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_sova_with_inspector(NoOpInspector {})
                .with_precompiles(PrecompilesMap::from_static(SovaPrecompiles::satoshi(
                    spec_id,
                ))),
            inspect: false,
        }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec_id = input.cfg_env.spec;
        SovaEvm {
            inner: Context::sova()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_sova_with_inspector(inspector)
                .with_precompiles(PrecompilesMap::from_static(SovaPrecompiles::satoshi(
                    spec_id,
                ))),
            inspect: true,
        }
    }
}
