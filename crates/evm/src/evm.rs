use alloy_evm::{Database, Evm, EvmEnv};
use alloy_primitives::{Address, Bytes, U256};
use core::ops::{Deref, DerefMut};
use op_revm::{OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::{EVMError, ResultAndState},
    handler::{instructions::EthInstructions, PrecompileProvider},
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    ExecuteEvm, InspectEvm, Inspector,
};

use crate::CustomPrecompiles;

/// Sova EVM implementation.
///
/// This is a wrapper type around the OpEVM with custom Bitcoin precompiles.
#[expect(missing_debug_implementations)]
pub struct SovaEvm<DB: Database, I, P = CustomPrecompiles> {
    inner: op_revm::OpEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
    inspect: bool,
}

impl<DB: Database, I, P> SovaEvm<DB, I, P> {
    /// Creates a new Sova EVM instance.
    ///
    /// The `inspect` argument determines whether the configured Inspector should be invoked
    /// on transaction execution.
    pub const fn new(
        evm: op_revm::OpEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
        inspect: bool,
    ) -> Self {
        Self {
            inner: evm,
            inspect,
        }
    }

    /// Consumes self and returns the inner EVM instance.
    pub fn into_inner(
        self,
    ) -> op_revm::OpEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P> {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &OpContext<DB> {
        &self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut OpContext<DB> {
        &mut self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM inspector.
    pub fn inspector_mut(&mut self) -> &mut I {
        &mut self.inner.0.data.inspector
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

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.set_tx(tx);
            self.inner.inspect_replay()
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
        // Similar implementation as EthEvm but with OpTransaction
        let tx = OpTransaction {
            base: TxEnv {
                caller,
                kind: alloy_primitives::TxKind::Call(contract),
                nonce: 0,
                gas_limit: 30_000_000,
                value: U256::ZERO,
                data,
                gas_price: 0,
                chain_id: None,
                gas_priority_fee: None,
                access_list: Default::default(),
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                tx_type: 0,
                authorization_list: Default::default(),
            },
            enveloped_tx: Some(Bytes::default()),
            deposit: Default::default(),
        };

        let mut gas_limit = tx.base.gas_limit;
        let mut basefee = 0;
        let mut disable_nonce_check = true;

        // ensure the block gas limit is >= the tx
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // disable the base fee check for this call by setting the base fee to zero
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // disable the nonce check
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        let mut res = self.transact(tx);

        // swap back to the previous gas limit
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // swap back to the previous base fee
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // swap back to the previous nonce check flag
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        // Clean up the state to only include the contract's changes
        if let Ok(res) = &mut res {
            res.state.retain(|addr, _| *addr == contract);
        }

        res
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        &mut self.journaled_state.database
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let context = self.inner.0.data.ctx;
        let BlockEnv { .. } = context.block;
        let CfgEnv { .. } = context.cfg;

        (
            context.journaled_state.database,
            EvmEnv {
                block_env: context.block,
                cfg_env: context.cfg,
            },
        )
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }
}
