extern crate alloc;

use alloc::{borrow::Cow, boxed::Box, vec::Vec};

use alloy_consensus::{BlockHeader, Eip658Value, Header, Transaction, TxReceipt};
use alloy_eips::{
    eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS, eip7685::Requests, Encodable2718, Typed2718,
};
use alloy_evm::block::ExecutableTx;

use alloy_op_evm::{block::receipt_builder::OpReceiptBuilder, OpBlockExecutionCtx};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, Bytes,
};
use op_alloy_consensus::OpDepositReceipt;
use op_revm::transaction::deposit::DEPOSIT_TRANSACTION_TYPE;
use reth_errors::{BlockValidationError, RethError};
use reth_evm::{
    block::{
        BlockExecutor, InternalBlockExecutionError, StateChangePostBlockSource, StateChangeSource,
        SystemCaller,
    },
    eth::{
        eip6110::{self, accumulate_deposits_from_receipts},
        receipt_builder::ReceiptBuilderCtx,
    },
    execute::{BlockExecutionError, BlockExecutorProvider, Executor},
    state_change::{balance_increment_state, post_block_balance_increments},
    ConfigureEvm, Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded, OnStateHook,
};
use reth_node_api::NodePrimitives;
use reth_optimism_forks::OpHardforks;
use reth_primitives::{Log, RecoveredBlock};
use reth_provider::BlockExecutionResult;
use reth_revm::{
    context::result::ExecutionResult,
    db::{states::bundle_state::BundleRetention, State},
    state::Account,
    DatabaseCommit,
};
use reth_tracing::tracing::info;
use revm::context::result::ResultAndState;

use crate::WithInspector;

/// A Sova block executor provider that can create executors using a strategy factory.
#[derive(Clone, Debug)]
pub struct SovaBlockExecutorProvider<F> {
    strategy_factory: F,
}

impl<F> SovaBlockExecutorProvider<F> {
    /// Creates a new `SovaBlockExecutorProvider` with the given strategy factory.
    pub const fn new(strategy_factory: F) -> Self {
        Self { strategy_factory }
    }
}

impl<F> BlockExecutorProvider for SovaBlockExecutorProvider<F>
where
    F: ConfigureEvm + 'static + WithInspector,
{
    type Primitives = F::Primitives;

    type Executor<DB: Database> = SovaBlockExecutor<F, DB>;

    fn executor<DB>(&self, db: DB) -> Self::Executor<DB>
    where
        DB: Database,
    {
        SovaBlockExecutor::new(self.strategy_factory.clone(), db)
    }
}

/// A generic block executor that uses a [`BlockExecutor`] to
/// execute blocks.
#[allow(missing_debug_implementations, dead_code)]
pub struct SovaBlockExecutor<F, DB> {
    /// Block execution strategy.
    pub(crate) strategy_factory: F,
    /// Database.
    pub(crate) db: State<DB>,
}

impl<F, DB: Database> SovaBlockExecutor<F, DB> {
    /// Creates a new `SovaBlockExecutor` with the given strategy.
    pub fn new(strategy_factory: F, db: DB) -> Self {
        let db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .without_state_clear()
            .build();
        Self {
            strategy_factory,
            db,
        }
    }
}

impl<F, DB> Executor<DB> for SovaBlockExecutor<F, DB>
where
    F: ConfigureEvm + WithInspector,
    DB: Database,
{
    type Primitives = F::Primitives;
    type Error = BlockExecutionError;

    fn execute_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        info!("execution flow: starting");

        // === SIMULATION PHASE ===
        // Capture revert information
        let revert_cache = {
            // Get inspector for simulation phase
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // Set up simulation environment
            let evm_env = self.strategy_factory.evm_env(block.header());
            let mut evm = self
                .strategy_factory
                .evm_factory()
                .create_evm_with_inspector(&mut self.db, evm_env, &mut *inspector);

            // Run transactions in simulation mode
            for tx in block.transactions_recovered() {
                let _ = evm.transact(tx); // Ignore results, just want to capture reverts
            }

            // We must drop evm first to release the mutable borrow on inspector
            drop(evm);

            // Now we can safely access inspector fields
            let cache = inspector.slot_revert_cache.clone();

            // Explicitly drop inspector and lock
            drop(inspector);

            cache
        };

        // === REVERT APPLICATION PHASE ===
        // Apply any reverts collected during simulation
        if !revert_cache.is_empty() {
            for (address, transition) in &revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;

                    // Handle the account
                    let acc = self.db.load_cache_account(*address).map_err(|err| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::msg(err))
                    })?;

                    if let Some(a) = acc.account.as_mut() {
                        a.storage.insert(*slot, prev_value);
                    }

                    // Convert to revm account
                    let mut revm_acc: Account = acc
                        .account_info()
                        .ok_or(BlockExecutionError::other(RethError::msg(
                            "failed to convert account to revm account",
                        )))?
                        .into();

                    revm_acc.mark_touch();

                    // Commit the change
                    let mut changes: HashMap<Address, Account> = HashMap::new();
                    changes.insert(*address, revm_acc);
                    self.db.commit(changes);
                }
            }
        }

        // === MAIN EXECUTION PHASE ===
        // Execute with state hook and get result
        let result = {
            // Get fresh inspector
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // Set up environment
            let evm_env = self.strategy_factory.evm_env(block.header());
            let evm = self.strategy_factory.evm_with_env_and_inspector(
                &mut self.db,
                evm_env,
                &mut *inspector,
            );

            // Create executor with state hook
            let ctx = self.strategy_factory.context_for_block(block);
            let mut strategy = self.strategy_factory.create_executor(evm, ctx);

            // Execute all transactions
            strategy.apply_pre_execution_changes()?;
            for tx in block.transactions_recovered() {
                strategy.execute_transaction(tx)?;
            }

            // This method consumes strategy, so it will be dropped automatically
            let result = strategy.apply_post_execution_changes()?;

            // Only drop remaining resources
            drop(inspector);

            result
        };

        // === UPDATE SENTINEL LOCKS ===
        {
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // locks are to be applied to the next block
            let locked_block_num: u64 = block.number() + 1;

            // handle locking of storage slots for any btc broadcasts in this block
            inspector
                .update_sentinel_locks(locked_block_num)
                .map_err(|err| {
                    InternalBlockExecutionError::msg(format!(
                        "Execution error: Failed to update sentinel locks: {}",
                        err
                    ))
                })?;
        }

        self.db.merge_transitions(BundleRetention::Reverts);

        Ok(result)
    }

    fn execute_one_with_state_hook<H>(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
        state_hook: H,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    where
        H: OnStateHook + 'static,
    {
        info!("execution flow: starting");

        // === SIMULATION PHASE ===
        // Capture revert information
        let revert_cache = {
            // Get inspector for simulation phase
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // Set up simulation environment
            let evm_env = self.strategy_factory.evm_env(block.header());
            let mut evm = self
                .strategy_factory
                .evm_factory()
                .create_evm_with_inspector(&mut self.db, evm_env, &mut *inspector);

            // Run transactions in simulation mode
            for tx in block.transactions_recovered() {
                let _ = evm.transact(tx); // Ignore results, just want to capture reverts
            }

            // We must drop evm first to release the mutable borrow on inspector
            drop(evm);

            // Now we can safely access inspector fields
            let cache = inspector.slot_revert_cache.clone();

            // Explicitly drop inspector and lock
            drop(inspector);

            cache
        };

        // === REVERT APPLICATION PHASE ===
        // Apply any reverts collected during simulation
        if !revert_cache.is_empty() {
            for (address, transition) in &revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;

                    // Handle the account
                    let acc = self.db.load_cache_account(*address).map_err(|err| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::msg(err))
                    })?;

                    if let Some(a) = acc.account.as_mut() {
                        a.storage.insert(*slot, prev_value);
                    }

                    // Convert to revm account
                    let mut revm_acc: Account = acc
                        .account_info()
                        .ok_or(BlockExecutionError::other(RethError::msg(
                            "failed to convert account to revm account",
                        )))?
                        .into();

                    revm_acc.mark_touch();

                    // Commit the change
                    let mut changes: HashMap<Address, Account> = HashMap::new();
                    changes.insert(*address, revm_acc);
                    self.db.commit(changes);
                }
            }
        }

        // === MAIN EXECUTION PHASE ===
        // Execute with state hook and get result
        let result = {
            // Get fresh inspector
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // Set up environment
            let evm_env = self.strategy_factory.evm_env(block.header());
            let evm = self.strategy_factory.evm_with_env_and_inspector(
                &mut self.db,
                evm_env,
                &mut *inspector,
            );

            // Create executor with state hook
            let ctx = self.strategy_factory.context_for_block(block);
            let mut strategy = self
                .strategy_factory
                .create_executor(evm, ctx)
                .with_state_hook(Some(Box::new(state_hook)));

            // Execute all transactions
            strategy.apply_pre_execution_changes()?;
            for tx in block.transactions_recovered() {
                strategy.execute_transaction(tx)?;
            }

            // This method consumes strategy, so it will be dropped automatically
            let result = strategy.apply_post_execution_changes()?;

            // Only drop remaining resources
            drop(inspector);

            result
        };

        // *** UPDATE SENTINEL LOCKS ***
        {
            let inspector_lock = self.strategy_factory.with_inspector();
            let mut inspector = inspector_lock.write();

            // locks are to be applied to the next block
            let locked_block_num: u64 = block.number() + 1;

            // handle locking of storage slots for any btc broadcasts in this block
            inspector
                .update_sentinel_locks(locked_block_num)
                .map_err(|err| {
                    InternalBlockExecutionError::msg(format!(
                        "Execution error: Failed to update sentinel locks: {}",
                        err
                    ))
                })?;
        }

        self.db.merge_transitions(BundleRetention::Reverts);

        Ok(result)
    }

    fn into_state(self) -> State<DB> {
        self.db
    }

    fn size_hint(&self) -> usize {
        self.db.bundle_state.size_hint()
    }
}

/// Block executor for Optimism.
#[derive(Debug)]
pub struct MyBlockExecutor<Evm, R: OpReceiptBuilder, Spec> {
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
}

impl<E, R, Spec> MyBlockExecutor<E, R, Spec>
where
    E: Evm,
    R: OpReceiptBuilder,
    Spec: OpHardforks + Clone,
{
    /// Creates a new [`OpBlockExecutor`].
    pub fn new(evm: E, ctx: OpBlockExecutionCtx, spec: Spec, receipt_builder: R) -> Self {
        Self {
            is_regolith: spec.is_regolith_active_at_timestamp(evm.block().timestamp),
            evm,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
            receipts: Vec::new(),
            gas_used: 0,
            ctx,
        }
    }
}

impl<E, R, Spec> MyBlockExecutor<E, R, Spec>
where
    R: OpReceiptBuilder,
{
    /// Find deposit logs in a list of receipts, and return the concatenated
    /// deposit request bytestring.
    ///
    /// The address of the deposit contract is taken from the chain spec, and
    /// defaults to [`MAINNET_DEPOSIT_CONTRACT_ADDRESS`] if not specified in
    /// the chain spec.
    pub fn parse_deposits_from_receipts<'a, I, Receipt>(
        receipts: I,
    ) -> Result<Bytes, BlockValidationError>
    where
        I: IntoIterator<Item = &'a Receipt>,
        Receipt: TxReceipt<Log = Log> + 'a,
    {
        let mut out = Vec::new();
        accumulate_deposits_from_receipts(MAINNET_DEPOSIT_CONTRACT_ADDRESS, receipts, &mut out)?;
        Ok(out.into())
    }
}

impl<'db, DB, E, R, Spec> BlockExecutor for MyBlockExecutor<E, R, Spec>
where
    DB: Database + 'db,
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    R: OpReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: OpHardforks,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self
            .spec
            .is_spurious_dragon_active_at_block(self.evm.block().number);
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        self.system_caller
            .apply_blockhashes_contract_call(self.ctx.parent_hash, &mut self.evm)?;
        self.system_caller
            .apply_beacon_root_contract_call(self.ctx.parent_beacon_block_root, &mut self.evm)?;

        Ok(())
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
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

        let hash = tx.tx().trie_hash();

        // Execute transaction.
        let result_and_state = self
            .evm
            .transact(tx)
            .map_err(move |err| BlockExecutionError::evm(err, hash))?;

        self.system_caller.on_state(
            StateChangeSource::Transaction(self.receipts.len()),
            &result_and_state.state,
        );
        let ResultAndState { result, state } = result_and_state;

        f(&result);

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
                                && self
                                    .spec
                                    .is_canyon_active_at_timestamp(self.evm.block().timestamp))
                            .then_some(1),
                        })
                }
            },
        );

        self.evm.db_mut().commit(state);

        Ok(gas_used)
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        let requests = if self
            .spec
            .is_prague_active_at_timestamp(self.evm.block().timestamp)
        {
            // Collect all EIP-6110 deposits
            let deposit_requests =
                MyBlockExecutor::<E, R, Spec>::parse_deposits_from_receipts(&self.receipts)?;

            let mut requests = Requests::default();

            if !deposit_requests.is_empty() {
                requests.push_request_with_type(eip6110::DEPOSIT_REQUEST_TYPE, deposit_requests);
            }

            requests.extend(
                self.system_caller
                    .apply_post_execution_changes(&mut self.evm)?,
            );
            requests
        } else {
            Requests::default()
        };

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
        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests,
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
