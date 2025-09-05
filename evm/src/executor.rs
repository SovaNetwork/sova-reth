use crate::inspector::{InspectorHandle, SovaInspector};
use crate::MaybeSovaInspector;
use crate::{alloy::SovaEvmFactory, canyon::ensure_create2_deployer};

extern crate alloc;

use std::env;

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
    Database, Evm, EvmEnv, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_op_evm::{
    block::{receipt_builder::OpReceiptBuilder},
    OpBlockExecutionCtx,
};
use alloy_op_hardforks::{OpChainHardforks, OpHardforks};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address,
};
use eyre::Result;
use op_alloy_consensus::OpDepositReceipt;
use op_revm::{transaction::deposit::DEPOSIT_TRANSACTION_TYPE, OpSpecId};
use reth_evm::block::InternalBlockExecutionError;
use reth_optimism_evm::OpRethReceiptBuilder;
use reth_tasks::TaskExecutor;
use revm::context::result::ResultAndState;
use revm::state::EvmStorageSlot;
use revm::{
    context::{result::ExecutionResult, CfgEnv},
    database::State,
    inspector::NoOpInspector,
    DatabaseCommit, Inspector,
};
use sova_chainspec::{BITCOIN_PRECOMPILE_ADDRESSES, SOVA_L1_BLOCK_CONTRACT_ADDRESS};
use tracing::debug;

/// Block executor for Sova.
///
/// Modeled after: https://github.com/alloy-rs/evm/blob/main/crates/op-evm/src/block/mod.rs
#[derive(Debug)]
pub struct SovaBlockExecutor<E: alloy_evm::Evm, R: OpReceiptBuilder, Spec, EvmF = SovaEvmFactory> {
    /// Spec.
    spec: Spec,
    /// Receipt builder.
    receipt_builder: R,

    /// Context for block execution.
    ctx: OpBlockExecutionCtx,
    /// The EVM used by executor.
    evm: E,
    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by executed transactions.
    gas_used: u64,
    /// Whether Regolith hardfork is active.
    is_regolith: bool,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
    /// The per-block env snapshot (cfg_env + block_env)
    evm_env: EvmEnv<<E as alloy_evm::Evm>::Spec>,
    /// The EVM factory for reference
    evm_factory: EvmF,
    /// Inspector handle for optional Sova inspector
    inspector: InspectorHandle,
    /// Sentinel URL for SovaInspector construction
    sentinel_url: String,
    /// Task executor for SovaInspector construction
    task_executor: TaskExecutor,
}

/// Configuration for Sova inspector components
pub struct SovaInspectorConfig {
    pub sentinel_url: String,
    pub task_executor: TaskExecutor,
}

impl<E, R, Spec, EvmF> SovaBlockExecutor<E, R, Spec, EvmF>
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
        evm_env: EvmEnv<<E as alloy_evm::Evm>::Spec>,
        evm_factory: EvmF,
        inspector_config: SovaInspectorConfig,
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
            evm_env,
            evm_factory,
            inspector: InspectorHandle::none(),
            sentinel_url: inspector_config.sentinel_url,
            task_executor: inspector_config.task_executor,
        }
    }
}

impl<'db, DB, E, R, Spec, EvmF> BlockExecutor for SovaBlockExecutor<E, R, Spec, EvmF>
where
    DB: Database + 'db,
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    R: OpReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: OpHardforks,
    EvmF: EvmFactory<
        Spec = <E as Evm>::Spec,
        Tx = <E as Evm>::Tx,
        HaltReason = <E as Evm>::HaltReason,
    >,
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

        // Install SovaInspector for this block:
        let sova = SovaInspector::new(
            BITCOIN_PRECOMPILE_ADDRESSES,
            [SOVA_L1_BLOCK_CONTRACT_ADDRESS].to_vec(),
            self.sentinel_url.clone(),
            self.task_executor.clone(),
        )
        .map_err(BlockExecutionError::other)?;

        self.inspector = InspectorHandle::new(sova);

        Ok(())
    }

    /// This method has been modified to execute the transaction twice.
    ///
    /// Execution 1: Execute transaction on scratch state to feed storage changes to the slot-lock-manager.
    /// The manager queries the Sentinel and fills its revert cache with any slots that need correction.
    ///
    /// Apply corrections: Get pending reverts from manager and apply them to the real DB.
    /// This materializes corrective state (reverted slots, locks) before the second execution.
    ///
    /// Execution 2: Execute transaction normally on the corrected DB. Transactions that should revert
    /// will now naturally fail due to the applied corrections, without needing runtime hooks.
    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        let is_deposit = tx.tx().ty() == DEPOSIT_TRANSACTION_TYPE;

        // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
        // must be no greater than the block’s gasLimit.
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

        let tx_hash = tx.tx().trie_hash();

        // ---- Simulation Phase (Pass #1) ----
        // Snapshot pre-execution bundle so we can discard the simulation effects cleanly.
        let pre_execution_bundle = self.evm.db_mut().take_bundle();

        // Run the TX once to populate the inspector's revert cache
        let pending_reverts: Vec<(Address, reth_revm::db::states::TransitionAccount)> = {
            let mut per_tx_insp = MaybeSovaInspector::empty(NoOpInspector);
            per_tx_insp.sova = Some(
                SovaInspector::new(
                    BITCOIN_PRECOMPILE_ADDRESSES,
                    [SOVA_L1_BLOCK_CONTRACT_ADDRESS].to_vec(),
                    self.sentinel_url.clone(),
                    self.task_executor.clone(),
                )
                .map_err(BlockExecutionError::other)?,
            );

            let mut evm_sim = self.evm_factory.create_evm_with_inspector(
                self.evm.db_mut(),
                self.evm_env.clone(),
                per_tx_insp,
            );
            evm_sim.enable_inspector();

            evm_sim
                .transact(&tx)
                .map_err(|err| BlockExecutionError::evm(err, tx_hash))?;

            let (_, insp, _) = evm_sim.components_mut();
            if let Some(sova) = insp.sova_mut() {
                sova.take_slot_revert_cache()
            } else {
                return Err(BlockExecutionError::msg(
                    "execute_transaction_with_commit_condition::error: sova inspector field should always be set during simulation"
                ));
            }
        };

        // ---- Revert Application Phase ----
        // Discard simulation writes and apply the inspector's pending reverts.
        self.evm.db_mut().bundle_state = pre_execution_bundle;

        if !pending_reverts.is_empty() {
            for (address, transition) in &pending_reverts {
                for (slot, slot_data) in &transition.storage {
                    let original_value = slot_data.previous_or_original_value;
                    let revert_value = slot_data.present_value;

                    debug!(
                        "Reverting slot {:?} from {:?} to {:?}",
                        slot, original_value, revert_value
                    );

                    // Load account and convert it to revm account
                    let cache_acc =
                        self.evm
                            .db_mut()
                            .load_cache_account(*address)
                            .map_err(|err| {
                                BlockExecutionError::Internal(InternalBlockExecutionError::msg(err))
                            })?;

                    // Convert cache account to revm account and add storage slot
                    let acc_info = cache_acc.account_info().unwrap_or_default();
                    let mut revm_acc: revm::state::Account = acc_info.into();

                    // Create storage slot with the revert value (assuming transaction_id 0)
                    let storage_slot = EvmStorageSlot::new_changed(original_value, revert_value, 0);
                    revm_acc.storage.insert(*slot, storage_slot);
                    revm_acc.mark_touch();

                    // Commit the change
                    let mut changes: HashMap<Address, revm::state::Account> = HashMap::new();
                    changes.insert(*address, revm_acc);
                    self.evm.db_mut().commit(changes);
                }
            }
        }

        // ---- Final Execution Phase (Pass #2) ----
        // Re-execute transaction on corrected DB and update receipts/state as usual.

        // Build a fresh, per-tx inspector for the canonical pass (so it can record lock_data).
        let mut per_tx_insp2 = MaybeSovaInspector::empty(NoOpInspector);
        per_tx_insp2.sova = Some(
            SovaInspector::new(
                BITCOIN_PRECOMPILE_ADDRESSES,
                [SOVA_L1_BLOCK_CONTRACT_ADDRESS].to_vec(),
                self.sentinel_url.clone(),
                self.task_executor.clone(),
            )
            .map_err(BlockExecutionError::other)?,
        );

        // Create an EVM bound to our DB snapshot + the new per-tx inspector.
        let (result, state) = {
            let mut evm_tx = self.evm_factory.create_evm_with_inspector(
                self.evm.db_mut(),
                self.evm_env.clone(),
                per_tx_insp2,
            );
            evm_tx.enable_inspector();

            let ResultAndState { result, state } = evm_tx
                .transact(&tx)
                .map_err(|err| BlockExecutionError::evm(err, tx_hash))?;

            // Pull the per-tx SovaInspector out and merge its lock_data back into the block-level handle
            let (_, insp, _) = evm_tx.components_mut();
            if let Some(mut sova_ptx) = core::mem::take(&mut insp.sova) {
                // merge so `finish()` sees everything in lock_data via self.inspector
                self.inspector.append_lock_data_from(&mut sova_ptx);
            }

            (result, state)
        };

        if !f(&result).should_commit() {
            return Ok(None);
        }

        self.system_caller
            .on_state(StateChangeSource::Transaction(self.receipts.len()), &state);

        let gas_used = result.gas_used();

        // append gas used
        self.gas_used += gas_used;

        self.receipts.push(
            match self.receipt_builder.build_receipt(ReceiptBuilderCtx {
                tx: tx.tx(),
                result,
                cumulative_gas_used: self.gas_used,
                evm: &self.evm,
                state: &state,
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

        self.evm.db_mut().commit(state);

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
        self.inspector
            .update_sentinel_locks(self.evm_env.block_env.number.saturating_to())
            .map_err(|e| {
                BlockExecutionError::Internal(reth_evm::block::InternalBlockExecutionError::msg(
                    e.to_string(),
                ))
            })?;

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

/// Ethereum block executor factory.
#[derive(Debug, Clone)]
pub struct SovaBlockExecutorFactory<
    R = OpRethReceiptBuilder,
    Spec = OpChainHardforks,
    EvmFactory = SovaEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
    /// Sentinel URL for SovaInspector construction
    sentinel_url: String,
    /// Task executor for SovaInspector construction
    task_executor: TaskExecutor,
}

impl<R, Spec, EvmFactory> SovaBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`SovaBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`OpReceiptBuilder`].
    pub fn new(
        receipt_builder: R,
        spec: Spec,
        evm_factory: EvmFactory,
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Self {
        Self {
            receipt_builder,
            spec,
            evm_factory,
            sentinel_url,
            task_executor,
        }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Exposes the EVM factory.
    pub const fn evm_factory(&self) -> &EvmFactory {
        &self.evm_factory
    }

    /// Exposes the sentinel URL.
    pub const fn sentinel_url(&self) -> &String {
        &self.sentinel_url
    }

    /// Exposes the task executor.
    pub const fn task_executor(&self) -> &TaskExecutor {
        &self.task_executor
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for SovaBlockExecutorFactory<R, Spec, EvmF>
where
    R: OpReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: OpHardforks,
    EvmF: EvmFactory<
            Spec = OpSpecId,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
        > + Clone,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <EvmF as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<<EvmF as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        // Create EvmEnv from block information; its Spec MUST match E::Spec
        let evm_env: EvmEnv<<EvmF as EvmFactory>::Spec> = EvmEnv {
            cfg_env: CfgEnv::default(),
            block_env: evm.block().clone(),
        };

        SovaBlockExecutor::new(
            evm,
            ctx,
            &self.spec,
            &self.receipt_builder,
            evm_env,
            self.evm_factory.clone(),
            SovaInspectorConfig {
                sentinel_url: self.sentinel_url.clone(),
                task_executor: self.task_executor.clone(),
            },
        )
    }
}

impl<R, Spec, EvmFactory> Default for SovaBlockExecutorFactory<R, Spec, EvmFactory>
where
    R: Default,
    Spec: Default,
    EvmFactory: Default,
{
    fn default() -> Self {
        Self {
            receipt_builder: R::default(),
            spec: Spec::default(),
            evm_factory: EvmFactory::default(),
            sentinel_url: env::var("SOVA_SENTINEL_URL").unwrap_or_default(),
            task_executor: TaskExecutor::current(),
        }
    }
}
