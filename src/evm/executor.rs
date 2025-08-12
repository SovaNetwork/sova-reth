use crate::evm::{
    alloy::{CustomEvm, CustomEvmFactory},
    CustomTxEnv, SovaEvmConfig,
};
use alloy_consensus::transaction::{Recovered, Transaction};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, CommitChanges, ExecutableTx, OnStateHook,
    },
    Database, Evm,
};
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor};
use reth_ethereum::evm::primitives::InspectorFor;
use reth_op::node::OpRethReceiptBuilder;
use reth_op::OpReceipt;
use reth_op::OpTransactionSigned;
use reth_optimism_chainspec::OpChainSpec;
use revm::{context::result::ExecutionResult, database::State};
use std::sync::Arc;

pub struct CustomBlockExecutor<Evm> {
    inner: OpBlockExecutor<Evm, OpRethReceiptBuilder, Arc<OpChainSpec>>,
}

impl<'db, DB, E> BlockExecutor for CustomBlockExecutor<E>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = CustomTxEnv>,
{
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // Log if this is a Bitcoin precompile transaction
        if let Some(to) = tx.tx().to() {
            if matches!(
                to,
                crate::chainspec::BROADCAST_TRANSACTION_ADDRESS
                    | crate::chainspec::DECODE_TRANSACTION_ADDRESS
                    | crate::chainspec::CONVERT_ADDRESS_ADDRESS
                    | crate::chainspec::VAULT_SPEND_ADDRESS
            ) {
                tracing::debug!("Executing transaction to Bitcoin precompile at {}", to);
            }
        }

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
    type EvmFactory = CustomEvmFactory;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.custom_evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: CustomEvm<&'a mut State<DB>, I>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        CustomBlockExecutor {
            inner: OpBlockExecutor::new(
                evm,
                ctx,
                self.inner.chain_spec().clone(),
                *self.inner.executor_factory.receipt_builder(),
            ),
        }
    }
}
