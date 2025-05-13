extern crate alloc;

use std::sync::Arc;

use alloc::boxed::Box;

use alloy_consensus::{BlockHeader, Transaction};

use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, B256, U256,
};

use reth_errors::RethError;
use reth_evm::{
    block::{BlockExecutor, InternalBlockExecutionError},
    execute::{BlockExecutionError, BlockExecutorProvider, Executor},
    ConfigureEvm, Database, Evm, EvmFactory, OnStateHook,
};
use reth_node_api::{BlockBody, NodePrimitives};
use reth_primitives::RecoveredBlock;
use reth_provider::BlockExecutionResult;
use reth_revm::{
    db::{states::bundle_state::BundleRetention, State},
    state::Account,
    DatabaseCommit,
};
use reth_tracing::tracing::{debug, info, warn};

use crate::{BitcoinClient, WithInspector, L1_BLOCK_SATOSHI_SELECTOR};

/// A Sova block executor provider that can create executors using a strategy factory.
#[derive(Clone, Debug)]
pub struct SovaBlockExecutorProvider<F> {
    strategy_factory: F,
    bitcoin_client: Arc<BitcoinClient>,
}

impl<F> SovaBlockExecutorProvider<F> {
    /// Creates a new `SovaBlockExecutorProvider` with the given strategy factory.
    pub const fn new(strategy_factory: F, bitcoin_client: Arc<BitcoinClient>) -> Self {
        Self {
            strategy_factory,
            bitcoin_client,
        }
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
        SovaBlockExecutor::new(
            self.strategy_factory.clone(),
            db,
            self.bitcoin_client.clone(),
        )
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
    /// Bitcoin client for validating block data.
    pub(crate) bitcoin_client: Arc<BitcoinClient>,
}

impl<F, DB: Database> SovaBlockExecutor<F, DB> {
    /// Creates a new `SovaBlockExecutor` with the given strategy.
    pub fn new(strategy_factory: F, db: DB, bitcoin_client: Arc<BitcoinClient>) -> Self {
        let db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .without_state_clear()
            .build();
        Self {
            strategy_factory,
            db,
            bitcoin_client,
        }
    }
}

impl<F, DB> SovaBlockExecutor<F, DB>
where
    F: ConfigureEvm + WithInspector,
    DB: Database,
{
    fn verify_l1block_transaction(
        &self,
        block: &RecoveredBlock<<<F as ConfigureEvm>::Primitives as NodePrimitives>::Block>,
    ) -> Result<(), BlockExecutionError> {
        for (idx, tx) in block.body().transactions().iter().enumerate() {
            info!("idx {}: tx: {:?}", idx, tx);
        }

        // Validate the SECOND transaction (index 1) for BTC data
        //
        // TODO(powvt): Make this resilient to more than one sequencer tx
        match block.body().transactions().get(1) {
            Some(tx) => {
                // Extract the input data from the first transaction
                let input = tx.input();

                // Check if input data is sufficient
                if input.len() < 4 {
                    debug!("L1Block transaction input data too short");
                    return Err(BlockExecutionError::other(RethError::msg(
                        "L1Block transaction input data too short",
                    )));
                }

                if block.number() == 0 {
                    // Skip validation for genesis block
                    debug!(target: "execution", "Genesis block - skipping Bitcoin block validation");
                    Ok(())
                } else if input[0..4] == L1_BLOCK_SATOSHI_SELECTOR {
                    // TODO(powvt): improve validations of BTC data

                    if input.len() < 68 {
                        // 4 bytes selector + 32 bytes blockHeight + 32 bytes blockHash
                        return Err(BlockExecutionError::other(RethError::msg(
                            "L1Block transaction data insufficient length",
                        )));
                    }

                    // Extract block height from 32 bytes after selector
                    let block_height = U256::try_from_be_slice(&input[4..36]).ok_or_else(|| {
                        BlockExecutionError::other(RethError::msg(
                            "Failed to parse Bitcoin block height",
                        ))
                    })?;

                    // Extract block hash from next 32 bytes
                    let tx_block_hash = B256::from_slice(&input[36..68]);

                    // TODO(powvt): Parse setBitcoinBlockDataCompact format from L1Block contract

                    // Validate the Bitcoin block hash
                    match self
                        .bitcoin_client
                        .validate_block_hash(block_height.to::<u64>(), tx_block_hash)
                    {
                        Ok(true) => {
                            debug!(
                                target: "execution",
                                "Verified L1Block transaction: Bitcoin height={}, hash={:?}",
                                block_height.to::<u64>(),
                                tx_block_hash
                            );
                            Ok(())
                        }
                        Ok(false) => {
                            warn!("Bitcoin block hash validation failed: Expected hash {:?} does not match actual hash for block at height {}", tx_block_hash, block_height.to::<u64>() - 6);
                            return Err(BlockExecutionError::other(RethError::msg(format!(
                                "Bitcoin block hash validation failed: Expected hash {:?} does not match actual hash for block at height {}",
                                tx_block_hash, block_height.to::<u64>() - 6
                            ))));
                        }
                        Err(err) => {
                            warn!("Failed to validate Bitcoin block hash: {}", err);
                            return Err(BlockExecutionError::other(RethError::msg(format!(
                                "Failed to validate Bitcoin block hash: {}",
                                err
                            ))));
                        }
                    }
                } else {
                    warn!(
                        "Function selector not recognized, received {:?}",
                        &input[0..4]
                    );
                    Err(BlockExecutionError::other(RethError::msg(
                        "Function selector not recognized",
                    )))
                }
            }
            None => {
                warn!("Block body transactions are empty");
                Err(BlockExecutionError::other(RethError::msg(
                    "Block body transactions are empty",
                )))
            }
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

        // === L1Block VERIFICATION ===
        self.verify_l1block_transaction(block)?;

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

        // === L1Block VERIFICATION ===
        self.verify_l1block_transaction(block)?;

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

    fn into_state(self) -> State<DB> {
        self.db
    }

    fn size_hint(&self) -> usize {
        self.db.bundle_state.size_hint()
    }
}
