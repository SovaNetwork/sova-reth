/// Note - Database utilization:
/// Inspector - checks if slots are locked (READ)
/// Strategy - locks slots after successful txs (WRITE)
/// Factory - shares the same storage instance between components

use std::{collections::{BTreeSet, HashMap}, convert::Infallible, fmt::Display, sync::Arc};

use parking_lot::RwLock;

use reth::{
    builder::{components::ExecutorBuilder, BuilderContext}, providers::ProviderError, revm::{
        handler::register::EvmHandler, inspector_handle_register, precompile::PrecompileSpecId, primitives::{BlockEnv, CfgEnvWithHandlerCfg, Env, EnvWithHandlerCfg, Precompile, TxEnv}, ContextPrecompile, ContextPrecompiles, Database, DatabaseCommit, Evm, EvmBuilder, GetInspector, State
    }
};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_evm::execute::{
        BlockExecutionError, BlockExecutionStrategy, BlockExecutionStrategyFactory,
        BlockValidationError, ExecuteOutput,
    };
use reth_evm_ethereum::EthEvmConfig;
use reth_node_ethereum::BasicBlockExecutorProvider;
use reth_primitives::{BlockWithSenders, EthPrimitives, Receipt, TransactionSigned};
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv, FullNodeTypes, NextBlockEnvAttributes, NodeTypes};

use alloy_primitives::{Address, Bytes, StorageKey, B256, U256};
use alloy_consensus::{Header, Transaction};
use alloy_eips::eip7685::Requests;
use reth_revm::primitives::ResultAndState;
use reth_tracing::tracing::info;

use crate::{config::CorsaConfig, modules::btc_storage::{BitcoinStorageInspector, StorageSlotAddress, UnconfirmedBtcStorageDb}};
use super::{bitcoin_precompile::BitcoinRpcPrecompile, constants::BITCOIN_PRECOMPILE_ADDRESS};

#[derive(Debug)]
struct StorageLockedError(String);

impl std::fmt::Display for StorageLockedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StorageLockedError {}

#[derive(Clone)]
pub struct BitcoinEvmConfig {
    /// Wrapper around mainnet configuration
    pub inner: EthEvmConfig,
    /// Bitcoin RPC precompile
    pub bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    /// Storage database for tracking locked slots
    pub storage_db: Arc<RwLock<UnconfirmedBtcStorageDb>>,
}

impl BitcoinEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    pub fn set_precompiles<EXT, DB>(
        handler: &mut EvmHandler<EXT, DB>,
        bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    ) where
        DB: Database,
    {
        let spec_id = handler.cfg.spec_id;
        let mut loaded_precompiles: ContextPrecompiles<DB> =
            ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));

        loaded_precompiles.to_mut().insert(
            BITCOIN_PRECOMPILE_ADDRESS,
            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                BitcoinRpcPrecompile::clone(&bitcoin_rpc_precompile.read()),
            ))),
        );

        handler.pre_execution.load_precompiles = Arc::new(move || loaded_precompiles.clone());
    }
}

impl ConfigureEvmEnv for BitcoinEvmConfig {
    type Header = Header;
    type Transaction = TransactionSigned;

    type Error = Infallible;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        self.inner.fill_tx_env(tx_env, transaction, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        self.inner.fill_tx_env_system_contract_call(env, caller, contract, data);
    }

    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        header: &Self::Header,
        total_difficulty: U256,
    ) {
        self.inner.fill_cfg_env(cfg_env, header, total_difficulty);
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> Result<(CfgEnvWithHandlerCfg, BlockEnv), Self::Error> {
        self.inner.next_cfg_and_block_env(parent, attributes)
    }
}

impl ConfigureEvm for BitcoinEvmConfig {
    type DefaultExternalContext<'a> = BitcoinStorageInspector;

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        let inspector = BitcoinStorageInspector::new(
            BITCOIN_PRECOMPILE_ADDRESS,
            vec![BITCOIN_PRECOMPILE_ADDRESS],
            self.storage_db.clone(),
        );
        
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .append_handler_register_box(Box::new(move |handler| {
                BitcoinEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .append_handler_register_box(Box::new(move |handler| {
                BitcoinEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {
        BitcoinStorageInspector::new(
            BITCOIN_PRECOMPILE_ADDRESS,
            vec![BITCOIN_PRECOMPILE_ADDRESS],
            self.storage_db.clone(),
        )
    }
}

pub struct BitcoinExecutionStrategy<DB>
where
    DB: Database<Error: Into<ProviderError> + Display>,
{
    /// The chainspec
    chain_spec: Arc<ChainSpec>,
    /// How to create an EVM
    evm_config: BitcoinEvmConfig,
    /// Current state for block execution
    state: State<DB>,
    /// flagged btc slots storage
    storage_db: Arc<RwLock<UnconfirmedBtcStorageDb>>,
    /// custom inspector
    inspector: BitcoinStorageInspector,
}

impl<DB> BitcoinExecutionStrategy<DB>
where
    DB: Database<Error: Into<ProviderError> + Display>,
{
    fn evm_env_for_block(
        &self,
        header: &alloy_consensus::Header,
        total_difficulty: U256,
    ) -> EnvWithHandlerCfg {
        let (cfg, block_env) = self.evm_config.cfg_and_block_env(header, total_difficulty);
        EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, Default::default())
    }

    fn handle_bitcoin_storage(
        &self,
        tx_hash: B256,
        storage_accesses: HashMap<Address, BTreeSet<StorageKey>>,
        bitcoin_called: bool,
    ) -> Result<(), BlockExecutionError> {
        if !bitcoin_called || storage_accesses.is_empty() {
            return Ok(());
        }

        let mut storage_db = self.storage_db.write();
        
        // First collect all slots that need to be locked
        let slots_to_lock: Vec<StorageSlotAddress> = storage_accesses
            .iter()
            .flat_map(|(address, slots)| {
                slots.iter().map(|slot| StorageSlotAddress::new(*address, *slot))
            })
            .collect();

        // If no conflicts found, lock all slots
        info!("Locking {} slots for tx {:?}", slots_to_lock.len(), tx_hash);
        for slot in slots_to_lock {
            storage_db.lock_slot(slot, tx_hash);
        }

        Ok(())
    }
}

impl<DB> BlockExecutionStrategy for BitcoinExecutionStrategy<DB>
where
    DB: Database<Error: Into<ProviderError> + Display>,
{
    type DB = DB;
    type Error = BlockExecutionError;
    type Primitives = EthPrimitives;

    fn apply_pre_execution_changes(
        &mut self,
        block: &BlockWithSenders,
        _total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork
        let state_clear_flag = self.chain_spec.is_spurious_dragon_active_at_block(block.number);
        self.state.set_state_clear_flag(state_clear_flag);

        Ok(())
    }

    /// If a specfic tramsaction interacts with the precompile address, the btc transaction data is added to the lock.
    ///
    /// The precompile itself checks if there is a lock on that BTC data. If there is it reverts the precompile execution.
    ///
    /// The indexer is the only thing that can unlock BTC data.
    fn execute_transactions(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<ExecuteOutput<Receipt>, Self::Error> {
        let env = self.evm_env_for_block(&block.header, total_difficulty);
        let mut evm = self.evm_config.evm_with_env_and_inspector(&mut self.state, env.clone(), &mut self.inspector);
        info!("Executing transactions evm created");
        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body.transactions.len());

        for (sender, transaction) in block.transactions_with_sender() {
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }

            self.evm_config.fill_tx_env(evm.tx_mut(), transaction, *sender);
            
            // Execute the transaction, run the inspector, and get results
            let result_and_state = evm.transact().map_err(|err| {
                let new_err = err.map_db_err(|e| e.into());
                // Ensure hash is calculated for error log, if not already done
                BlockValidationError::EVM {
                    hash: transaction.recalculate_hash(),
                    error: Box::new(new_err),
                }
            })?;
            // Extract storage access information
            let storage_accesses = evm.context.external.accessed_storage.clone();
            let broadcast_precompile_called = evm.context.external.broadcast_precompile_called;
            info!("Transaction state - broadcast_called: {}, storage_accesses: {:?}", 
                broadcast_precompile_called, 
                storage_accesses
            );
            
            // Clear the inspector state for the next transaction
            evm.context.external.accessed_storage.clear();
            evm.context.external.broadcast_precompile_called = false;

            // Process Bitcoin storage if needed
            if broadcast_precompile_called {
                let tx_hash = transaction.hash();
                // Release mutable borrow of EVM to handle storage
                drop(evm);
                self.handle_bitcoin_storage(tx_hash, storage_accesses, true)?;
                // Recreate EVM with same environment
                evm = self.evm_config.evm_with_env_and_inspector(
                    &mut self.state, 
                    env.clone(),
                    &mut self.inspector
                );
            }

            // TODO(powvt): how can `self.system_caller` be implemented? See the optimism execute.rs file
            // self.system_caller.on_state(&result_and_state.state);
            let ResultAndState { result, state } = result_and_state;

            evm.db_mut().commit(state);

            // append gas used
            cumulative_gas_used += result.gas_used();
            
            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Receipt {
                tx_type: transaction.tx_type(),
                    // Success flag was added in `EIP-658: Embedding transaction status code in
                    // receipts`.
                    success: result.is_success(),
                    cumulative_gas_used,
                    // convert to reth log
                    logs: result.into_logs(),
                    ..Default::default()
            });
        }

        Ok(ExecuteOutput { receipts, gas_used: cumulative_gas_used })
    }

    fn apply_post_execution_changes(
        &mut self,
        _block: &BlockWithSenders,
        _total_difficulty: U256,
        _receipts: &[Receipt],
    ) -> Result<Requests, BlockExecutionError> {
        Ok(Requests::default())
    }

    fn state_ref(&self) -> &State<DB> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut State<DB> {
        &mut self.state
    }
}

#[derive(Clone)]
pub struct BitcoinExecutionStrategyFactory {
    /// Describes the properties of the chain
    chain_spec: Arc<ChainSpec>,
    /// Config for EVM that includes Bitcoin precompile setup
    evm_config: BitcoinEvmConfig,
    /// Shared storage database for tracking locked slots across transactions
    storage_db: Arc<RwLock<UnconfirmedBtcStorageDb>>,
}

impl BlockExecutionStrategyFactory for BitcoinExecutionStrategyFactory {
    type Primitives = EthPrimitives;
    type Strategy<DB: Database<Error: Into<ProviderError> + Display>> = BitcoinExecutionStrategy<DB>;

    fn create_strategy<DB>(&self, db: DB) -> Self::Strategy<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        let state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .without_state_clear()
            .build();

        BitcoinExecutionStrategy {
            state,
            chain_spec: self.chain_spec.clone(),
            evm_config: self.evm_config.clone(),
            storage_db: self.storage_db.clone(),
            inspector: BitcoinStorageInspector::new(
                BITCOIN_PRECOMPILE_ADDRESS,
                vec![BITCOIN_PRECOMPILE_ADDRESS],
                self.storage_db.clone(),
            ),
        }
    }
}

#[derive(Clone)]
pub struct CorsaExecutorBuilder {
    config: CorsaConfig,
    storage_db: Option<Arc<RwLock<UnconfirmedBtcStorageDb>>>,
}

impl CorsaExecutorBuilder {
    pub fn new(config: CorsaConfig) -> Self {
        Self { 
            config,
            storage_db: None,
        }
    }
}

impl<Node> ExecutorBuilder<Node> for CorsaExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = BitcoinEvmConfig;
    type Executor = BasicBlockExecutorProvider<BitcoinExecutionStrategyFactory>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        // Create or use existing storage DB
        let storage_db = self.storage_db.unwrap_or_else(|| 
            Arc::new(RwLock::new(UnconfirmedBtcStorageDb::new()))
        );
        
        let evm_config = BitcoinEvmConfig {
            inner: EthEvmConfig::new(ctx.chain_spec()),
            bitcoin_rpc_precompile: Arc::new(RwLock::new(BitcoinRpcPrecompile::new(
                self.config.bitcoin.as_ref(),
                self.config.network_signing_url.clone(),
                self.config.network_utxo_url.clone(),
                self.config.btc_tx_queue_url.clone(),
            ).expect("Failed to create Bitcoin RPC precompile"))),
            storage_db: storage_db.clone(),
        };
        
        let strategy_factory = BitcoinExecutionStrategyFactory {
            chain_spec: ctx.chain_spec(),
            evm_config: evm_config.clone(),
            storage_db,
        };
        
        let executor = BasicBlockExecutorProvider::new(strategy_factory);

        Ok((evm_config, executor))
    }
}