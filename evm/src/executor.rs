use crate::{
    alloy::{SovaEvm, SovaEvmFactory},
    canyon::ensure_create2_deployer,
    SovaEvmConfig,
};
use alloy_primitives::U256;
use slot_lock_manager::SlotLockManager;
use sova_chainspec::L1_BLOCK_CONTRACT_ADDRESS;
extern crate alloc;
use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use alloy_consensus::{Eip658Value, Header, Transaction, TxReceipt};
use alloy_eips::{Encodable2718, Typed2718};
use alloy_evm::{
    block::{
        state_changes::{balance_increment_state, post_block_balance_increments},
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, BlockValidationError, CommitChanges, ExecutableTx, OnStateHook,
        StateChangePostBlockSource, StateChangeSource, SystemCaller,
    },
    eth::receipt_builder::ReceiptBuilderCtx,
    Database, Evm, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_op_evm::{block::receipt_builder::OpReceiptBuilder, OpBlockExecutionCtx};
use alloy_op_hardforks::OpHardforks;
use eyre::Result;
use op_alloy_consensus::OpDepositReceipt;
use op_revm::transaction::deposit::DEPOSIT_TRANSACTION_TYPE;
use reth_ethereum::evm::primitives::InspectorFor;
use reth_op::OpReceipt;
use reth_op::OpTransactionSigned;
use revm::{
    context::result::{ExecutionResult, ResultAndState},
    database::State,
    DatabaseCommit,
};
use slot_lock_manager::{BlockContext, TransactionContext};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

/// Block executor for Sova.
///
/// Modeled after: https://github.com/alloy-rs/evm/blob/main/crates/op-evm/src/block/mod.rs
#[derive(Debug)]
pub struct SovaBlockExecutor<Evm, R: OpReceiptBuilder, Spec> {
    /// Spec.
    spec: Spec,
    /// Receipt builder.
    receipt_builder: R,

    /// Context for block execution.
    ctx: OpBlockExecutionCtx,
    /// The EVM used by executor.
    evm: Evm,
    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by executed transactions.
    gas_used: u64,
    /// Whether Regolith hardfork is active.
    is_regolith: bool,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
    /// Slot lock manager for Bitcoin finality checking.
    slot_lock_manager: Arc<SlotLockManager>,
}

impl<E, R, Spec> SovaBlockExecutor<E, R, Spec>
where
    E: Evm,
    R: OpReceiptBuilder,
    Spec: OpHardforks + Clone,
{
    /// Creates a new [`SovaBlockExecutor`].
    pub fn new(
        evm: E,
        ctx: OpBlockExecutionCtx,
        spec: Spec,
        receipt_builder: R,
        slot_lock_manager: Arc<SlotLockManager>,
    ) -> Self {
        Self {
            is_regolith: spec
                .is_regolith_active_at_timestamp(evm.block().timestamp.saturating_to()),
            evm,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
            receipts: Vec::new(),
            gas_used: 0,
            ctx,
            slot_lock_manager,
        }
    }
}

impl<'db, DB, E, R, Spec> SovaBlockExecutor<E, R, Spec>
where
    DB: Database + 'db,
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    R: OpReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: OpHardforks,
{
    /// Read BTC height from L1Block contract storage
    fn get_btc_height_from_l1block(&mut self) -> Result<u64, BlockExecutionError> {
        // For genesis block (block 0), return BTC height 0 without contract access
        let current_block_number = self.evm.block().number.saturating_to::<u64>();
        if current_block_number <= 1 {
            return Ok(0);
        }

        // Read storage directly from the database using the Database trait's storage() method
        let height_value = self
            .evm
            .db_mut()
            .database
            .storage(L1_BLOCK_CONTRACT_ADDRESS, U256::ZERO)
            .map_err(BlockExecutionError::other)?;

        Ok(height_value.saturating_to::<u64>())
    }
}

impl<'db, DB, E, R, Spec> BlockExecutor for SovaBlockExecutor<E, R, Spec>
where
    DB: Database + 'db,
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    R: OpReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: OpHardforks,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self
            .spec
            .is_spurious_dragon_active_at_block(self.evm.block().number.saturating_to());
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        self.system_caller
            .apply_blockhashes_contract_call(self.ctx.parent_hash, &mut self.evm)?;
        self.system_caller
            .apply_beacon_root_contract_call(self.ctx.parent_beacon_block_root, &mut self.evm)?;

        // Ensure that the create2deployer is force-deployed at the canyon transition. Optimism
        // blocks will always have at least a single transaction in them (the L1 info transaction),
        // so we can safely assume that this will always be triggered upon the transition and that
        // the above check for empty blocks will never be hit on OP chains.
        ensure_create2_deployer(
            &self.spec,
            self.evm.block().timestamp.saturating_to(),
            self.evm.db_mut(),
        )
        .map_err(BlockExecutionError::other)?;

        Ok(())
    }

    /// This method has been modified to execute the transaction twice.
    ///
    /// Pass A: Execute transaction on scratch state to feed storage changes to the slot-lock-manager.
    /// The manager queries the Sentinel and fills its revert cache with any slots that need correction.
    ///
    /// Apply corrections: Get pending reverts from manager and apply them to the real DB.
    /// This materializes corrective state (reverted slots, locks) before the second execution.
    ///
    /// Pass B: Execute transaction normally on the corrected DB. Transactions that should revert
    /// will now naturally fail due to the applied corrections, without needing runtime hooks.
    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        let is_deposit = tx.tx().ty() == DEPOSIT_TRANSACTION_TYPE;

        // The sum of the transaction's gas limit, Tg, and the gas utilized in this block prior,
        // must be no greater than the block's gasLimit.
        let block_available_gas = self.evm.block().gas_limit - self.gas_used;
        if tx.tx().gas_limit() > block_available_gas && (self.is_regolith || !is_deposit) {
            return Err(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: tx.tx().gas_limit(),
                    block_available_gas,
                }
                .into(),
            );
        }

        // Cache the depositor account prior to the state transition for the deposit nonce.
        //
        // Note that this *only* needs to be done post-regolith hardfork, as deposit nonces
        // were not introduced in Bedrock. In addition, regular transactions don't have deposit
        // nonces, so we don't need to touch the DB for those.
        let depositor = (self.is_regolith && is_deposit)
            .then(|| {
                self.evm
                    .db_mut()
                    .load_cache_account(*tx.signer())
                    .map(|acc| acc.account_info().unwrap_or_default())
            })
            .transpose()
            .map_err(BlockExecutionError::other)?;

        let hash = tx.tx().trie_hash();

        // Save the current bundle state before any execution
        let pre_execution_bundle = self.evm.db_mut().take_bundle();

        // Pass A: Execute transaction to collect state changes for the slot-lock-manager
        let ResultAndState {
            result: first_result,
            state: first_state,
        } = self
            .evm
            .transact(tx)
            .map_err(move |err| BlockExecutionError::evm(err, hash))?;

        info!(
            "first_state has {} accounts with changes",
            first_state.len()
        );

        // Create context for SlotLockManager
        let transaction_context = TransactionContext {
            operation_id: Uuid::new_v4(),
            caller: *tx.signer(),
            target: tx.tx().to().unwrap_or_default(),
        };

        let block_context = BlockContext {
            number: self.evm.block().number.saturating_to::<u64>(),
            btc_block_height: self.get_btc_height_from_l1block()?,
        };

        // Feed the EVM state to slot-lock-manager (queries Sentinel and fills revert cache)
        let _slot_response = self
            .slot_lock_manager
            .check_evm_state(&first_state, transaction_context, block_context, None)
            .map_err(BlockExecutionError::other)?;

        // Restore pre-execution bundle state (discard Pass A results)
        self.evm.db_mut().bundle_state = pre_execution_bundle;

        // Apply corrections: Get pending reverts from manager and apply to real DB
        let pending_reverts = self.slot_lock_manager.get_pending_reverts();
        for revert in &pending_reverts {
            // Load the account into cache if not present
            let account = self
                .evm
                .db_mut()
                .load_cache_account(revert.address)
                .map_err(BlockExecutionError::other)?;

            // Update storage if account exists
            if let Some(ref mut plain_account) = account.account {
                let storage_key = U256::from_be_bytes(revert.slot.to_be_bytes::<32>());
                let revert_value = U256::from_be_bytes(revert.revert_to.to_be_bytes::<32>());
                plain_account.storage.insert(storage_key, revert_value);
            }

            // Mark account as changed
            account.status = account.status.on_changed(false);
        }

        // Determine final execution result
        let (final_result, final_state) = if pending_reverts.is_empty() {
            // No corrections needed, use Pass A result
            (first_result, first_state)
        } else {
            // Pass B: Re-execute transaction on corrected DB
            let ResultAndState { result, state } = self
                .evm
                .transact(tx)
                .map_err(move |err| BlockExecutionError::evm(err, hash))?;
            (result, state)
        };

        // Check if we should commit the result
        if !f(&final_result).should_commit() {
            return Ok(None);
        }

        self.system_caller.on_state(
            StateChangeSource::Transaction(self.receipts.len()),
            &final_state,
        );

        let gas_used = final_result.gas_used();

        // append gas used
        self.gas_used += gas_used;

        // Build receipt
        self.receipts.push(
            match self.receipt_builder.build_receipt(ReceiptBuilderCtx {
                tx: tx.tx(),
                result: final_result,
                cumulative_gas_used: self.gas_used,
                evm: &self.evm,
                state: &final_state,
            }) {
                Ok(receipt) => receipt,
                Err(ctx) => {
                    let receipt = alloy_consensus::Receipt {
                        // Success flag was added in `EIP-658: Embedding transaction status code
                        // in receipts`.
                        status: Eip658Value::Eip658(ctx.result.is_success()),
                        cumulative_gas_used: self.gas_used,
                        logs: ctx.result.into_logs(),
                    };

                    self.receipt_builder
                        .build_deposit_receipt(OpDepositReceipt {
                            inner: receipt,
                            deposit_nonce: depositor.map(|account| account.nonce),
                            // The deposit receipt version was introduced in Canyon to indicate an
                            // update to how receipt hashes should be computed
                            // when set. The state transition process ensures
                            // this is only set for post-Canyon deposit
                            // transactions.
                            deposit_receipt_version: (is_deposit
                                && self.spec.is_canyon_active_at_timestamp(
                                    self.evm.block().timestamp.saturating_to(),
                                ))
                            .then_some(1),
                        })
                }
            },
        );

        // ONLY commit the final state here
        self.evm.db_mut().commit(final_state);

        Ok(Some(gas_used))
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        let balance_increments =
            post_block_balance_increments::<Header>(&self.spec, self.evm.block(), &[], None);

        // increment balances
        self.evm
            .db_mut()
            .increment_balances(balance_increments.clone())
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;

        // call state hook with changes due to balance increments.
        self.system_caller.try_on_state_with(|| {
            balance_increment_state(&balance_increments, self.evm.db_mut()).map(|state| {
                (
                    StateChangeSource::PostBlock(StateChangePostBlockSource::BalanceIncrements),
                    Cow::Owned(state),
                )
            })
        })?;

        let gas_used = self
            .receipts
            .last()
            .map(|r| r.cumulative_gas_used())
            .unwrap_or_default();

        // Update sentinel locks for finalized transactions
        self.slot_lock_manager
            .update_sentinel_locks_sync(self.evm.block().number.saturating_to())
            .map_err(BlockExecutionError::other)?;

        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests: Default::default(),
                gas_used,
            },
        ))
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.evm
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
        let slot_lock_manager =
            crate::assembler::build_slot_lock_manager().expect("Failed to build slot lock manager");

        SovaBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec().clone(),
            self.inner.executor_factory.receipt_builder(),
            slot_lock_manager,
        )
    }
}
