extern crate alloc;

use alloc::{borrow::Cow, boxed::Box, vec::Vec};

use alloy_consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::{eip7685::Requests, Encodable2718};
use alloy_evm::block::ExecutableTx;

use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address,
};
use reth_chainspec::EthereumHardfork;
use reth_errors::RethError;
use reth_evm::{
    block::{
        BlockExecutor, InternalBlockExecutionError, StateChangePostBlockSource, StateChangeSource,
        SystemCaller,
    },
    eth::{
        dao_fork, eip6110,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
        spec::EthExecutorSpec,
        EthBlockExecutionCtx,
    },
    execute::{BlockExecutionError, BlockExecutorProvider, BlockValidationError, Executor},
    state_change::{balance_increment_state, post_block_balance_increments},
    ConfigureEvm, Database, Evm, EvmFactory, FromRecoveredTx, OnStateHook,
};
use reth_node_api::NodePrimitives;
use reth_primitives::{Log, RecoveredBlock};
use reth_provider::BlockExecutionResult;
use reth_revm::{
    context::result::{ExecutionResult, ResultAndState},
    db::{states::bundle_state::BundleRetention, State, TransitionAccount},
    state::Account,
    DatabaseCommit,
};

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
        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let evm_env = self.strategy_factory.evm_env(block.header());
        let evm = self.strategy_factory.evm_with_env_and_inspector(
            &mut self.db,
            evm_env,
            &mut *inspector,
        );
        let ctx = self.strategy_factory.context_for_block(block);
        let mut strategy = self.strategy_factory.create_executor(evm, ctx);

        // let strategy = self.strategy_factory.executor_for_block(&mut self.db, block);

        strategy.apply_pre_execution_changes()?;

        drop(strategy);
        drop(inspector);

        // *** SIMULATION PHASE ***

        // Get evm_env
        let evm_env = self.strategy_factory.evm_env(block.header());

        // Get inspector
        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let mut evm = self
            .strategy_factory
            .evm_factory()
            .create_evm_with_inspector(&mut self.db, evm_env, &mut *inspector);

        for tx in block.transactions_recovered() {
            match evm.transact(tx) {
                Ok(_result) => {
                    // Explicitly NOT committing state changes here
                    // We're only using this simulation to capture reverts in the inspector
                }
                Err(_err) => {
                    // we dont really care about the error here, we just want to capture the revert
                }
            };
        }

        drop(evm);

        let revert_cache: Vec<(Address, TransitionAccount)> = inspector.slot_revert_cache.clone();

        // apply mask to the database
        if !revert_cache.is_empty() {
            for (address, transition) in &revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;

                    // Load account from state
                    let acc = self.db.load_cache_account(*address).map_err(|err| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::msg(err))
                    })?;

                    // Set slot in account to previous value
                    if let Some(a) = acc.account.as_mut() {
                        a.storage.insert(*slot, prev_value);
                    }

                    // Convert to revm account, mark as modified and commit it to state
                    let mut revm_acc: Account = acc
                        .account_info()
                        .ok_or(BlockExecutionError::other(RethError::msg(
                            "failed to convert account to revm account",
                        )))?
                        .into();

                    revm_acc.mark_touch();

                    let mut changes: HashMap<Address, Account> = HashMap::new();
                    changes.insert(*address, revm_acc);

                    // commit to account slot changes to state
                    self.db.commit(changes);
                }
            }
        }

        drop(inspector);

        // *** EXECUTION PHASE ***

        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let evm_env = self.strategy_factory.evm_env(block.header());
        let evm = self.strategy_factory.evm_with_env_and_inspector(
            &mut self.db,
            evm_env,
            &mut *inspector,
        );
        let ctx = self.strategy_factory.context_for_block(block);
        let mut strategy = self.strategy_factory.create_executor(evm, ctx);

        for tx in block.transactions_recovered() {
            strategy.execute_transaction(tx)?;
        }
        let result = strategy.apply_post_execution_changes()?;

        drop(inspector);

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

        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let evm_env = self.strategy_factory.evm_env(block.header());
        let evm = self.strategy_factory.evm_with_env_and_inspector(
            &mut self.db,
            evm_env,
            &mut *inspector,
        );
        let ctx = self.strategy_factory.context_for_block(block);
        let mut strategy = self.strategy_factory.create_executor(evm, ctx)
            .with_state_hook(Some(Box::new(state_hook)));

        // let mut strategy = self
        //     .strategy_factory
        //     .executor_for_block(&mut self.db, block)
        //     .with_state_hook(Some(Box::new(state_hook)));

        strategy.apply_pre_execution_changes()?;

        drop(strategy);
        drop(inspector);

        // *** SIMULATION PHASE ***

        // Get evm_env
        let evm_env = self.strategy_factory.evm_env(block.header());

        // Get inspector
        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let mut evm = self
            .strategy_factory
            .evm_factory()
            .create_evm_with_inspector(&mut self.db, evm_env, &mut *inspector);

        for tx in block.transactions_recovered() {
            match evm.transact(tx) {
                Ok(_result) => {
                    // Explicitly NOT committing state changes here
                    // We're only using this simulation to capture reverts in the inspector
                }
                Err(_err) => {
                    // we dont really care about the error here, we just want to capture the revert
                }
            };
        }

        drop(evm);

        let revert_cache: Vec<(Address, TransitionAccount)> = inspector.slot_revert_cache.clone();

        // apply mask to the database
        if !revert_cache.is_empty() {
            for (address, transition) in &revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;

                    // Load account from state
                    let acc = self.db.load_cache_account(*address).map_err(|err| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::msg(err))
                    })?;

                    // Set slot in account to previous value
                    if let Some(a) = acc.account.as_mut() {
                        a.storage.insert(*slot, prev_value);
                    }

                    // Convert to revm account, mark as modified and commit it to state
                    let mut revm_acc: Account = acc
                        .account_info()
                        .ok_or(BlockExecutionError::other(RethError::msg(
                            "failed to convert account to revm account",
                        )))?
                        .into();

                    revm_acc.mark_touch();

                    let mut changes: HashMap<Address, Account> = HashMap::new();
                    changes.insert(*address, revm_acc);

                    // commit to account slot changes to state
                    self.db.commit(changes);
                }
            }
        }

        drop(inspector);

        // *** EXECUTION PHASE ***

        let inspector_lock = self.strategy_factory.with_inspector();
        let mut inspector = inspector_lock.write();

        let evm_env = self.strategy_factory.evm_env(block.header());
        let evm = self.strategy_factory.evm_with_env_and_inspector(
            &mut self.db,
            evm_env,
            &mut *inspector,
        );
        let ctx = self.strategy_factory.context_for_block(block);
        let mut strategy = self.strategy_factory.create_executor(evm, ctx);

        for tx in block.transactions_recovered() {
            strategy.execute_transaction(tx)?;
        }
        let result = strategy.apply_post_execution_changes()?;

        drop(inspector);

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

/// Block executor for Sova.
/// NOTE: There is a lot of duplicate code in the impl since the `EthBlockExecutor` params are private
#[derive(Debug)]
pub struct MyBlockExecutor<'a, Evm, Spec, R: ReceiptBuilder> {
    /// Reference to the specification object.
    spec: Spec,

    /// Context for block execution.
    pub ctx: EthBlockExecutionCtx<'a>,
    /// Inner EVM.
    evm: Evm,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
    /// Receipt builder.
    receipt_builder: R,

    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by transactions in this block.
    gas_used: u64,
}

impl<'a, Evm, Spec, R> MyBlockExecutor<'a, Evm, Spec, R>
where
    Spec: Clone,
    R: ReceiptBuilder,
{
    pub fn new(evm: Evm, ctx: EthBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self {
        Self {
            evm,
            ctx,
            receipts: Vec::new(),
            gas_used: 0,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
        }
    }
}

impl<'db, DB, E, Spec, R> BlockExecutor for MyBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx: FromRecoveredTx<R::Transaction>>,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
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
        // The sum of the transaction's gas limit, Tg, and the gas utilized in this block prior,
        // must be no greater than the block's gasLimit.
        let block_available_gas = self.evm.block().gas_limit - self.gas_used;

        if tx.tx().gas_limit() > block_available_gas {
            return Err(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: tx.tx().gas_limit(),
                    block_available_gas,
                }
                .into(),
            );
        }

        // Execute transaction.
        let result_and_state = self
            .evm
            .transact(tx)
            .map_err(|err| BlockExecutionError::evm(err, tx.tx().trie_hash()))?;
        self.system_caller.on_state(
            StateChangeSource::Transaction(self.receipts.len()),
            &result_and_state.state,
        );
        let ResultAndState { result, state } = result_and_state;

        f(&result);

        let gas_used = result.gas_used();

        // append gas used
        self.gas_used += gas_used;

        // Push transaction changeset and calculate header bloom filter for receipt.
        self.receipts
            .push(self.receipt_builder.build_receipt(ReceiptBuilderCtx {
                tx: tx.tx(),
                evm: &self.evm,
                result,
                state: &state,
                cumulative_gas_used: self.gas_used,
            }));

        // Commit the state changes.
        self.evm.db_mut().commit(state);

        Ok(gas_used)
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        let requests = if self
            .spec
            .is_prague_active_at_timestamp(self.evm.block().timestamp)
        {
            // Collect all EIP-6110 deposits
            let deposit_requests =
                eip6110::parse_deposits_from_receipts(&self.spec, &self.receipts)?;

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

        let mut balance_increments = post_block_balance_increments(
            &self.spec,
            self.evm.block(),
            self.ctx.ommers,
            self.ctx.withdrawals.as_deref(),
        );

        // Irregular state change at Ethereum DAO hardfork
        if self
            .spec
            .ethereum_fork_activation(EthereumHardfork::Dao)
            .transitions_at_block(self.evm.block().number)
        {
            // drain balances from hardcoded addresses.
            let drained_balance: u128 = self
                .evm
                .db_mut()
                .drain_balances(dao_fork::DAO_HARDFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();

            // return balance to DAO beneficiary.
            *balance_increments
                .entry(dao_fork::DAO_HARDFORK_BENEFICIARY)
                .or_default() += drained_balance;
        }
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

        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests,
                gas_used: self.gas_used,
            },
        ))
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }
}
