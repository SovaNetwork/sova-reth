extern crate alloc;

use std::sync::Arc;

use alloc::{boxed::Box, vec::Vec};

use alloy_consensus::BlockHeader;
use alloy_evm::block::ExecutableTx;

use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address,
};
use reth_chainspec::ChainSpec;
use reth_errors::RethError;
use reth_evm::{
    block::{BlockExecutor, InternalBlockExecutionError},
    eth::EthBlockExecutor,
    execute::{BlockExecutionError, BlockExecutorProvider, Executor},
    ConfigureEvm, Database, Evm, EvmFactory, OnStateHook,
};
use reth_evm_ethereum::RethReceiptBuilder;
use reth_node_api::NodePrimitives;
use reth_primitives::{Receipt, RecoveredBlock, TransactionSigned};
use reth_provider::BlockExecutionResult;
use reth_revm::{
    context::{result::ExecutionResult, TxEnv},
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
        let mut strategy = self
            .strategy_factory
            .create_executor(evm, ctx)
            .with_state_hook(Some(Box::new(state_hook)));

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

/// Block executor for Sova.
/// NOTE: There is a lot of duplicate code in the impl since the `EthBlockExecutor` params are private
#[derive(Debug)]
pub struct MyBlockExecutor<'a, Evm> {
    /// Inner Ethereum execution strategy.
    pub inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec>, &'a RethReceiptBuilder>,
}

impl<'db, DB, E> BlockExecutor for MyBlockExecutor<'_, E>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = TxEnv>,
{
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        self.inner.execute_transaction_with_result_closure(tx, f)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
}
