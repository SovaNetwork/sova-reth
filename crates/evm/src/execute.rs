use std::{fmt::Display, sync::Arc};

use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::eip7685::Requests;

use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_evm::{
    execute::{
        BlockExecutionError, BlockExecutionStrategy, BlockExecutionStrategyFactory,
        BlockValidationError, ExecuteOutput,
    },
    system_calls::SystemCaller,
    ConfigureEvm, Evm, TxEnvOverrides,
};
use reth_node_api::BlockBody;
use reth_primitives::{EthPrimitives, Receipt, RecoveredBlock};
use reth_primitives_traits::transaction::signed::SignedTransaction;
use reth_provider::ProviderError;
use reth_revm::{db::State, primitives::ResultAndState, Database, DatabaseCommit};

use crate::MyEvmConfig;

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
            tx_env_overrides: None,
            system_caller,
        }
    }
}

impl<DB, EvmConfig> BlockExecutionStrategy for MyExecutionStrategy<DB, EvmConfig>
where
    DB: Database<Error: Into<ProviderError> + Display>,
    EvmConfig: ConfigureEvm<
        Header = alloy_consensus::Header,
        Transaction = reth_primitives::TransactionSigned,
    >,
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
        // Set state clear flag if the block is after the Spurious Dragon hardfork
        let state_clear_flag = self
            .chain_spec
            .is_spurious_dragon_active_at_block(block.number);
        self.state.set_state_clear_flag(state_clear_flag);

        Ok(())
    }

    fn execute_transactions(
        &mut self,
        block: &RecoveredBlock<reth_primitives::Block>,
    ) -> Result<ExecuteOutput<Receipt>, Self::Error> {
        let cfg_and_block_env = self.evm_config.cfg_and_block_env(block.header());
        let mut evm = self
            .evm_config
            .evm_with_env(&mut self.state, cfg_and_block_env);

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
        _block: &RecoveredBlock<reth_primitives::Block>,
        _receipts: &[Receipt],
    ) -> Result<Requests, Self::Error> {
        Ok(Requests::default())
    }

    fn state_ref(&self) -> &State<DB> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut State<DB> {
        &mut self.state
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
        >,
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
