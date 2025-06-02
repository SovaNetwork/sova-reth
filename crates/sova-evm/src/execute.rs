extern crate alloc;

use std::{borrow::Cow, sync::Arc};

use alloc::boxed::Box;

use alloy_consensus::{BlockHeader, Eip658Value, Header, Transaction, TxReceipt};

use alloy_eips::{Encodable2718, Typed2718 as _};
use alloy_op_evm::{block::receipt_builder::OpReceiptBuilder, OpBlockExecutionCtx};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, B256, U256,
};

use op_alloy_consensus::OpDepositReceipt;
use op_revm::transaction::deposit::DEPOSIT_TRANSACTION_TYPE;
use reth_errors::{BlockValidationError, RethError};
use reth_evm::{
    block::{
        BlockExecutor, ExecutableTx, InternalBlockExecutionError, StateChangePostBlockSource,
        StateChangeSource, SystemCaller,
    },
    eth::receipt_builder::ReceiptBuilderCtx,
    execute::{BlockExecutionError, Executor},
    state_change::{balance_increment_state, post_block_balance_increments},
    ConfigureEvm, Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded, OnStateHook,
};
use reth_node_api::{BlockBody, NodePrimitives};
use reth_optimism_forks::OpHardforks;
use reth_primitives::RecoveredBlock;
use reth_provider::BlockExecutionResult;
use reth_revm::{
    db::{states::bundle_state::BundleRetention, State},
    state::Account,
    DatabaseCommit,
};
use reth_tracing::tracing::{debug, info, warn};

use revm::context::{result::ResultAndState, Block as _};
use sova_chainspec::L1_BLOCK_SATOSHI_SELECTOR;

use crate::{BitcoinClient, WithInspector};

/// A generic block executor that uses a [`BlockExecutor`] to
/// execute blocks.
#[allow(missing_debug_implementations, dead_code)]
pub struct OldSovaBlockExecutor<F, DB> {
    /// Block execution strategy.
    pub(crate) strategy_factory: F,
    /// Database.
    pub(crate) db: State<DB>,
    /// Bitcoin client for validating block data.
    pub(crate) bitcoin_client: Arc<BitcoinClient>,
}

impl<F, DB: Database> OldSovaBlockExecutor<F, DB> {
    // Creates a new `OldSovaBlockExecutor` with the given strategy.
    // pub fn new(strategy_factory: F, db: DB, bitcoin_client: Arc<BitcoinClient>) -> Self {
    //     let db = State::builder()
    //         .with_database(db)
    //         .with_bundle_update()
    //         .without_state_clear()
    //         .build();
    //     Self {
    //         strategy_factory,
    //         db,
    //         bitcoin_client,
    //     }
    // }
}

impl<F, DB> OldSovaBlockExecutor<F, DB>
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

impl<F, DB> Executor<DB> for OldSovaBlockExecutor<F, DB>
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

/// Block executor for Optimism.
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
    /// Bitcoin client for validating block data.
    _bitcoin_client: Arc<BitcoinClient>,
}

impl<E, R, Spec> SovaBlockExecutor<E, R, Spec>
where
    E: Evm,
    R: OpReceiptBuilder,
    Spec: OpHardforks + Clone,
{
    /// Creates a new [`OpBlockExecutor`].
    pub fn new(
        evm: E,
        ctx: OpBlockExecutionCtx,
        spec: Spec,
        receipt_builder: R,
        bitcoin_client: Arc<BitcoinClient>,
    ) -> Self {
        Self {
            is_regolith: spec.is_regolith_active_at_timestamp(evm.block().timestamp),
            evm,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
            receipts: Vec::new(),
            gas_used: 0,
            ctx,
            _bitcoin_client: bitcoin_client,
        }
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
            .is_spurious_dragon_active_at_block(self.evm.block().number);
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        self.system_caller
            .apply_blockhashes_contract_call(self.ctx.parent_hash, &mut self.evm)?;
        self.system_caller
            .apply_beacon_root_contract_call(self.ctx.parent_beacon_block_root, &mut self.evm)?;

        // Ensure that the create2deployer is force-deployed at the canyon transition. Optimism
        // blocks will always have at least a single transaction in them (the L1 info transaction),
        // so we can safely assume that this will always be triggered upon the transition and that
        // the above check for empty blocks will never be hit on OP chains.
        // TODO(deb): do we need to ensure this?
        // ensure_create2_deployer(&self.spec, self.evm.block().timestamp, self.evm.db_mut())
        //     .map_err(BlockExecutionError::other)?;

        Ok(())
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&revm::context::result::ExecutionResult<<Self::Evm as Evm>::HaltReason>),
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

    /// Executes all transactions in a block, applying pre and post execution changes.
    fn execute_block(
        mut self,
        transactions: impl IntoIterator<Item = impl ExecutableTx<Self>>,
    ) -> Result<BlockExecutionResult<Self::Receipt>, BlockExecutionError>
    where
        Self: Sized,
    {
        let mut transactions_list = Vec::new();
        for tx in transactions {
            transactions_list.push(tx);
        }

        // self.custom_pre_block_execution(transactions_list.clone())?;

        self.apply_pre_execution_changes()?;

        for tx in transactions_list {
            self.execute_transaction(tx.clone())?;
        }

        self.apply_post_execution_changes()
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
    fn _verify_l1block_transaction(
        &self,
        transactions: impl IntoIterator<Item = impl ExecutableTx<Self>>,
    ) -> Result<(), BlockExecutionError> {
        // for (idx, tx) in block.body().transactions().iter().enumerate() {
        //     info!("idx {}: tx: {:?}", idx, tx);
        // }

        let transactions: Vec<_> = transactions.into_iter().collect();

        // Validate the SECOND transaction (index 1) for BTC data
        //
        // TODO(powvt): Make this resilient to more than one sequencer tx
        match transactions.get(1) {
            Some(tx) => {
                // Extract the input data from the first transaction
                let input = tx.tx().input();

                // Check if input data is sufficient
                if input.len() < 4 {
                    debug!("L1Block transaction input data too short");
                    return Err(BlockExecutionError::other(RethError::msg(
                        "L1Block transaction input data too short",
                    )));
                }

                if self.evm().block().number() == 0 {
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
                        ._bitcoin_client
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
