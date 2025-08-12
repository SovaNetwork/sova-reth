use crate::{
    alloy::{SovaEvm, SovaEvmFactory},
    SovaEvmConfig, SovaTxEnv,
};
use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, CommitChanges, ExecutableTx, OnStateHook,
    },
    Database, Evm,
};
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor};
use alloy_primitives::{Address, U256};
use eyre::Result;
use reth_ethereum::evm::primitives::InspectorFor;
use reth_op::node::OpRethReceiptBuilder;
use reth_op::OpReceipt;
use reth_op::OpTransactionSigned;
use reth_optimism_chainspec::OpChainSpec;
use revm::{context::result::ExecutionResult, database::State};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct SovaBlockExecutor<Evm> {
    inner: OpBlockExecutor<Evm, OpRethReceiptBuilder, Arc<OpChainSpec>>,
    revert_plan: BTreeMap<(Address, U256), U256>, // (addr, slot) -> prev
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
        if !self.revert_plan.is_empty() {
            let _evm = self.evm_mut();
            // TODO: get a mutable DB handle from `evm` and do set_storage writes:
            for ((addr, slot), prev) in std::mem::take(&mut self.revert_plan) {
                // _evm.db_mut().set_storage(addr, slot, prev);
                tracing::debug!("Would revert storage at {addr:?}:{slot:?} to {prev:?}");
            }
        }
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // TODO: Add SlotLockManager check here (async challenge)
        // 1. Extract OpTransactionSigned from ExecutableTx
        // 2. Call simulate_tx_capture to get StorageCache
        // 3. Read L1 block info using DbStorageReader
        // 4. Build SlotLockRequest and call slot_lock_mgr.check_precompile_call().await
        // 5. Handle SlotLockDecision::RevertWithSlotData by updating revert_plan
        // 6. Return error for SlotLockDecision::Revert

        // Execute through the inner OpBlockExecutor
        self.inner.execute_transaction_with_commit_condition(
            Recovered::new_unchecked(tx.tx(), *tx.signer()),
            f,
        )
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<OpReceipt>), BlockExecutionError> {
        self.inner.finish()
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
            revert_plan: BTreeMap::new(),
        }
    }
}
