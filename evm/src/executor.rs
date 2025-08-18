use crate::{
    alloy::{SovaEvm, SovaEvmFactory},
    SovaEvmConfig, SovaTxEnv,
};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, CommitChanges, ExecutableTx, OnStateHook,
    },
    Database, Evm,
};
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor};
use eyre::Result;
use reth_ethereum::evm::primitives::InspectorFor;
use reth_op::node::OpRethReceiptBuilder;
use reth_op::OpReceipt;
use reth_op::OpTransactionSigned;
use reth_optimism_chainspec::OpChainSpec;
use revm::{context::result::ExecutionResult, database::State};
use std::sync::Arc;

pub struct SovaBlockExecutor<Evm> {
    inner: OpBlockExecutor<Evm, OpRethReceiptBuilder, Arc<OpChainSpec>>,
}

impl<'db, DB, E> BlockExecutor for SovaBlockExecutor<E>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = SovaTxEnv>,
{
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    /// This method has been modified to execute the transaction twice.
    ///
    /// The first execution is to collect any reverted slots using the state changes and the slot-lock-manager.
    ///
    /// If there are any slots that need to be reverted due to a Bitcoin transaction not being finalized in
    /// Bitcoin mainnet these database changes are applied prior to the second execution.
    ///
    /// The second execution of the tx (after the reverts have been applied to db) determines the final
    /// ExecutionResult for that tx. It is possible for the tx to fail the first execution, reverts get
    /// applied to db and succeed on the second execution.
    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // TODO1: Execute transaction to collect state changes
        // TODO1: process state changes using `SlotLockManager::check_precompile_call()`

        // TODO2: Apply state reversion using `evm.db_mut()` if there is any reverted slots returned from check_precompile_call

        // TODO3: Execute tx again with the applied state changes
        self.inner.execute_transaction_with_commit_condition(tx, f)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<OpReceipt>), BlockExecutionError> {
        self.inner.finish()

        // TODO4: call SlotLockManager::update_sentinel_locks() so that everything in the finalized broadcast cache (lock_data)
        // gets added to the sentinel database for future tracking
    }

    fn set_state_hook(&mut self, _hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(_hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

impl BlockExecutorFactory for SovaEvmConfig {
    type EvmFactory = SovaEvmFactory;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.sova_evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: SovaEvm<&'a mut State<DB>, I>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        SovaBlockExecutor {
            inner: OpBlockExecutor::new(
                evm,
                ctx,
                self.inner.chain_spec().clone(),
                *self.inner.executor_factory.receipt_builder(),
            ),
        }
    }
}
