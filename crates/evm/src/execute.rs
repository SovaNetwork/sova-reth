use std::{fmt::Display, sync::Arc};

use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::{eip6110, eip7685::Requests};

use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address,
};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_consensus::ConsensusError;
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::{
    execute::{
        balance_increment_state, BlockExecutionError, BlockExecutionStrategy,
        BlockExecutionStrategyFactory, BlockValidationError, ExecuteOutput,
        InternalBlockExecutionError,
    },
    state_change::post_block_balance_increments,
    system_calls::{OnStateHook, SystemCaller},
    ConfigureEvm, Evm, TxEnvOverrides,
};
use reth_node_api::BlockBody;
use reth_primitives::{EthPrimitives, Receipt, RecoveredBlock};
use reth_primitives_traits::transaction::signed::SignedTransaction;
use reth_provider::ProviderError;
use reth_revm::{
    db::State,
    primitives::{Account, ResultAndState},
    Database, DatabaseCommit, TransitionAccount,
};

use crate::{inspector::WithInspector, MyEvmConfig};

pub struct MyExecutionStrategy<DB, EvmConfig>
where
    EvmConfig: Clone,
{
    /// The chainspec
    chain_spec: Arc<ChainSpec>,
    /// How to create an EVM
    evm_config: EvmConfig,
    /// Optional overrides for the transactions environment.
    tx_env_overrides: Option<Box<dyn TxEnvOverrides>>,
    /// Current state for block execution
    state: State<DB>,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<EvmConfig, ChainSpec>,
}

impl<DB, EvmConfig> MyExecutionStrategy<DB, EvmConfig>
where
    EvmConfig: Clone,
{
    pub fn new(state: State<DB>, chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        let system_caller = SystemCaller::new(evm_config.clone(), chain_spec.clone());
        Self {
            state,
            chain_spec,
            evm_config,
            system_caller,
            tx_env_overrides: None,
        }
    }
}

impl<DB, EvmConfig> BlockExecutionStrategy for MyExecutionStrategy<DB, EvmConfig>
where
    DB: Database<Error: Into<ProviderError> + Display>,
    EvmConfig: ConfigureEvm<
            Header = alloy_consensus::Header,
            Transaction = reth_primitives::TransactionSigned,
        > + WithInspector,
{
    type DB = DB;
    type Error = BlockExecutionError;
    type Primitives = EthPrimitives;

    fn init(&mut self, tx_env_overrides: Box<dyn TxEnvOverrides>) {
        self.tx_env_overrides = Some(tx_env_overrides);
    }

    fn apply_pre_execution_changes(
        &mut self,
        block: &RecoveredBlock<reth_primitives::Block>,
    ) -> Result<(), Self::Error> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag =
            (*self.chain_spec).is_spurious_dragon_active_at_block(block.number());
        self.state.set_state_clear_flag(state_clear_flag);

        let mut evm = self
            .evm_config
            .evm_for_block(&mut self.state, block.header());

        self.system_caller
            .apply_pre_execution_changes(block.header(), &mut evm)?;

        Ok(())
    }

    fn execute_transactions(
        &mut self,
        block: &RecoveredBlock<reth_primitives::Block>,
    ) -> Result<ExecuteOutput<Receipt>, Self::Error> {
        // Prepare EVM configuration
        let cfg_and_block_env = self.evm_config.cfg_and_block_env(block.header());

        // *** SIMULATION PHASE ***

        // Get inspector in inner scope
        let inspector_lock = self.evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // Create EVM in inner scope
        let mut evm = self.evm_config.evm_with_env_and_inspector(
            &mut self.state,
            cfg_and_block_env.clone(),
            &mut *inspector,
        );

        // Simulate transaction execution
        for (sender, transaction) in block.transactions_with_sender() {
            let mut tx_env = self.evm_config.tx_env(transaction, *sender);

            if let Some(tx_env_overrides) = &mut self.tx_env_overrides {
                tx_env_overrides.apply(&mut tx_env);
            }

            let _ = evm.transact(tx_env).map_err(move |err| {
                let new_err = err.map_db_err(|e| e.into());
                BlockValidationError::EVM {
                    hash: transaction.recalculate_hash(),
                    error: Box::new(new_err),
                }
            })?;
        }

        drop(evm);

        let revert_cache: Vec<(Address, TransitionAccount)> = inspector.slot_revert_cache.clone();

        // apply mask to the database
        for (address, transition) in &revert_cache {
            for (slot, slot_data) in &transition.storage {
                let prev_value = slot_data.previous_or_original_value;

                // Load account from state
                let acc = self.state.load_cache_account(*address).map_err(|e| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::msg(e))
                })?;

                // Set slot in account to previous value
                if let Some(a) = acc.account.as_mut() {
                    a.storage.insert(*slot, prev_value);
                }

                // Convert to revm account, mark as modified and commit it to state
                let mut revm_acc: Account = acc
                    .account_info()
                    .ok_or(BlockExecutionError::Internal(
                        InternalBlockExecutionError::msg("failed to get account info"),
                    ))?
                    .into();

                revm_acc.mark_touch();

                let mut changes: HashMap<Address, Account> = HashMap::new();
                changes.insert(*address, revm_acc);

                // commit to account slot changes to state
                self.state.commit(changes);
            }
        }

        drop(inspector);

        // *** EXECUTION PHASE ***

        // Get inspector
        let inspector_lock = self.evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // Create EVM
        let mut evm = self.evm_config.evm_with_env_and_inspector(
            &mut self.state,
            cfg_and_block_env,
            &mut *inspector,
        );

        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body().transaction_count());

        for (sender, transaction) in block.transactions_with_sender() {
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.gas_limit() - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas {
                return Err(
                    BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                        transaction_gas_limit: transaction.gas_limit(),
                        block_available_gas,
                    }
                    .into(),
                );
            }

            let mut tx_env = self.evm_config.tx_env(transaction, *sender);

            if let Some(tx_env_overrides) = &mut self.tx_env_overrides {
                tx_env_overrides.apply(&mut tx_env);
            }

            // Execute transaction.
            let result_and_state = evm.transact(tx_env).map_err(move |err| {
                let new_err = err.map_db_err(|e| e.into());
                // Ensure hash is calculated for error log, if not already done
                BlockValidationError::EVM {
                    hash: transaction.recalculate_hash(),
                    error: Box::new(new_err),
                }
            })?;
            self.system_caller.on_state(&result_and_state.state);
            let ResultAndState { result, state } = result_and_state;
            evm.db_mut().commit(state);

            // append gas used
            cumulative_gas_used += result.gas_used();

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(
                #[allow(clippy::needless_update)] // side-effect of optimism fields
                Receipt {
                    tx_type: transaction.tx_type(),
                    // Success flag was added in `EIP-658: Embedding transaction status code in
                    // receipts`.
                    success: result.is_success(),
                    cumulative_gas_used,
                    // convert to reth log
                    logs: result.into_logs(),
                    ..Default::default()
                },
            );
        }

        Ok(ExecuteOutput {
            receipts,
            gas_used: cumulative_gas_used,
        })
    }

    fn apply_post_execution_changes(
        &mut self,
        block: &RecoveredBlock<reth_primitives::Block>,
        receipts: &[Receipt],
    ) -> Result<Requests, Self::Error> {
        let mut evm = self
            .evm_config
            .evm_for_block(&mut self.state, block.header());

        let requests = if self
            .chain_spec
            .is_prague_active_at_timestamp(block.timestamp)
        {
            // Collect all EIP-6110 deposits
            let deposit_requests = reth_evm_ethereum::eip6110::parse_deposits_from_receipts(
                &self.chain_spec,
                receipts,
            )?;

            let mut requests = Requests::default();

            if !deposit_requests.is_empty() {
                requests.push_request_with_type(eip6110::DEPOSIT_REQUEST_TYPE, deposit_requests);
            }

            requests.extend(self.system_caller.apply_post_execution_changes(&mut evm)?);
            requests
        } else {
            Requests::default()
        };
        drop(evm);

        let balance_increments = post_block_balance_increments(&self.chain_spec, block);

        // NOTE(powvt): This is a special case for the Ethereum DAO hardfork. Sova does not inherit this history.
        // // Irregular state change at Ethereum DAO hardfork
        // if self.chain_spec.fork(EthereumHardfork::Dao).transitions_at_block(block.number()) {
        //     // drain balances from hardcoded addresses.
        //     let drained_balance: u128 = self
        //         .state
        //         .drain_balances(DAO_HARDFORK_ACCOUNTS)
        //         .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
        //         .into_iter()
        //         .sum();

        //     // return balance to DAO beneficiary.
        //     *balance_increments.entry(DAO_HARDFORK_BENEFICIARY).or_default() += drained_balance;
        // }

        // increment balances
        self.state
            .increment_balances(balance_increments.clone())
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;
        // call state hook with changes due to balance increments.
        let balance_state = balance_increment_state(&balance_increments, &mut self.state)?;
        self.system_caller.on_state(&balance_state);

        {
            let inspector_lock = self.evm_config.with_inspector();
            let mut inspector = inspector_lock.write();

            // handle locking of storage slots for any btc broadcasts in this block
            inspector
                .update_sentinel_locks(block.number())
                .map_err(|err| {
                    InternalBlockExecutionError::msg(format!(
                        "Failed to update sentinel locks: {}",
                        err
                    ))
                })?;
        }

        Ok(requests)
    }

    fn state_ref(&self) -> &State<DB> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut State<DB> {
        &mut self.state
    }

    fn with_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<reth_primitives::Block>,
        receipts: &[Receipt],
        requests: &Requests,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(block, &self.chain_spec.clone(), receipts, requests)
    }
}

#[derive(Debug, Clone)]
pub struct MyExecutionStrategyFactory<EvmConfig = MyEvmConfig> {
    /// Describes the properties of the chain
    pub chain_spec: Arc<ChainSpec>,
    /// Config for EVM that includes Bitcoin precompile setup
    pub evm_config: EvmConfig,
}

impl<EvmConfig> MyExecutionStrategyFactory<EvmConfig> {
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self {
            chain_spec,
            evm_config,
        }
    }
}

impl<EvmConfig> BlockExecutionStrategyFactory for MyExecutionStrategyFactory<EvmConfig>
where
    EvmConfig: Clone
        + Unpin
        + Sync
        + Send
        + 'static
        + ConfigureEvm<
            Header = alloy_consensus::Header,
            Transaction = reth_primitives::TransactionSigned,
        >
        + WithInspector,
{
    type Primitives = EthPrimitives;
    type Strategy<DB: Database<Error: Into<ProviderError> + Display>> =
        MyExecutionStrategy<DB, EvmConfig>;

    fn create_strategy<DB>(&self, db: DB) -> Self::Strategy<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        let state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .without_state_clear()
            .build();

        MyExecutionStrategy::new(state, self.chain_spec.clone(), self.evm_config.clone())
    }
}
