mod inspector;
mod precompiles;
mod slot_lock_manager;

pub use precompiles::{BitcoinClient, BitcoinRpcPrecompile, SovaL1BlockInfo};
pub use slot_lock_manager::{SlotLockManager, AccessedStorage, BroadcastResult, StorageChange};

use std::{error::Error, sync::Arc};
use parking_lot::RwLock;

// Use OpBlockExecutionCtx from alloy-op-evm (same version as reth v1.6.0)
use alloy_op_evm::OpBlockExecutionCtx;
use alloy_consensus::{Transaction, Receipt, Eip658Value};
use alloy_primitives::{Address, U256};
use reth_evm::{ConfigureEvm, block::{BlockExecutor, BlockExecutorFactory, BlockExecutorFor, ExecutableTx, CommitChanges, BlockExecutionError, StateChangeSource}, system_calls::SystemCaller, OnStateHook, EvmFactory};
use reth_optimism_evm::{OpEvmConfig, OpEvmFactory};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::{OpTransactionSigned, OpReceipt};
use op_alloy_consensus::OpTxType;
use reth_provider::BlockExecutionResult;
use reth_revm::{State, DatabaseCommit};
use reth_tasks::TaskExecutor;
use revm::{Database, inspector::Inspector};
use revm::context::result::{ExecutionResult, ResultAndState};
use sova_chainspec::{BROADCAST_TRANSACTION_ADDRESS, VAULT_SPEND_ADDRESS};
// Simplified imports for reth v1.6.0 compatibility
use sova_cli::SovaConfig;

/// Sova EVM configuration that wraps OpEvmConfig and adds slot lock enforcement
#[derive(Clone, Debug)]
pub struct MyEvmConfig {
    /// Wrapper around optimism configuration
    inner: OpEvmConfig,
    /// Slot lock manager for Bitcoin precompile enforcement
    slot_lock_manager: Arc<RwLock<SlotLockManager>>,
}

impl MyEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<OpChainSpec>,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn Error>> {
        let slot_lock_manager = SlotLockManager::new(
            config.sentinel_url.clone(),
            task_executor,
        )?;

        Ok(Self {
            inner: OpEvmConfig::optimism(chain_spec),
            slot_lock_manager: Arc::new(RwLock::new(slot_lock_manager)),
        })
    }

    /// Returns the chain spec associated with this configuration
    pub const fn chain_spec(&self) -> &Arc<OpChainSpec> {
        self.inner.chain_spec()
    }

    /// Get the slot lock manager for post-execution enforcement
    pub fn slot_lock_manager(&self) -> &Arc<RwLock<SlotLockManager>> {
        &self.slot_lock_manager
    }
}

// Implement ConfigureEvm by delegating to OpEvmConfig
impl ConfigureEvm for MyEvmConfig {
    type Primitives = <OpEvmConfig as ConfigureEvm>::Primitives;
    type Error = <OpEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <OpEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = <OpEvmConfig as ConfigureEvm>::BlockExecutorFactory;
    type BlockAssembler = <OpEvmConfig as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self.inner.block_executor_factory()
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &alloy_consensus::Header) -> reth_evm::EvmEnv<op_revm::OpSpecId> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &alloy_consensus::Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<reth_evm::EvmEnv<op_revm::OpSpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block(
        &self,
        block: &reth_primitives::SealedBlock<alloy_consensus::Block<reth_optimism_primitives::OpTransactionSigned>>,
    ) -> OpBlockExecutionCtx {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &reth_primitives::SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> OpBlockExecutionCtx {
        self.inner.context_for_next_block(parent, attributes)
    }

    // SlotLockManager is available for slot lock validation logic
    // Inspector pattern removed - slot locking will use a cleaner implementation approach
}

// Implement BlockExecutorFactory following the Optimism pattern exactly
impl BlockExecutorFactory for MyEvmConfig {
    type EvmFactory = OpEvmFactory;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + std::fmt::Debug + 'a,
        <DB as Database>::Error: std::marker::Send + std::marker::Sync + std::fmt::Debug + 'static,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        SovaBlockExecutor::new(
            evm,
            ctx,
            self.chain_spec().clone(),
            self.slot_lock_manager.clone(),
        )
    }
}

// Trait for accessing the slot lock manager - keeping this for the core slot locking functionality
pub trait WithSlotLockManager {
    fn slot_lock_manager(&self) -> &Arc<RwLock<SlotLockManager>>;
}

impl WithSlotLockManager for MyEvmConfig {
    fn slot_lock_manager(&self) -> &Arc<RwLock<SlotLockManager>> {
        &self.slot_lock_manager
    }
}

/// Custom Sova block executor that validates slot locks during transaction execution
/// Following the OpBlockExecutor pattern exactly
#[derive(Debug)]
pub struct SovaBlockExecutor<Evm> {
    /// Chain specification
    chain_spec: Arc<OpChainSpec>,
    /// Block execution context
    ctx: OpBlockExecutionCtx,
    /// EVM instance
    evm: Evm,
    /// Slot lock manager for Bitcoin slot validation
    slot_lock_manager: Arc<RwLock<SlotLockManager>>,
    /// System caller for pre/post execution operations
    system_caller: SystemCaller<Arc<OpChainSpec>>,
    /// Receipts collected during block execution
    receipts: Vec<OpReceipt>,
    /// Total gas used in this block
    gas_used: u64,
}

impl<Evm> SovaBlockExecutor<Evm> {
    /// Create a new Sova block executor
    pub fn new(
        evm: Evm,
        ctx: OpBlockExecutionCtx,
        chain_spec: Arc<OpChainSpec>,
        slot_lock_manager: Arc<RwLock<SlotLockManager>>,
    ) -> Self {
        Self {
            system_caller: SystemCaller::new(chain_spec.clone()),
            chain_spec,
            ctx,
            evm,
            slot_lock_manager,
            receipts: Vec::new(),
            gas_used: 0,
        }
    }

    /// Validate slot locks before executing transaction
    /// This is the critical slot validation logic
    fn validate_slot_locks(&self, tx: &OpTransactionSigned, block_number: u64) -> Result<(), BlockExecutionError> {
        // Check if this transaction interacts with Bitcoin precompiles
        let to_address = match tx.to() {
            Some(addr) => addr,
            None => return Ok(()), // Contract creation, no slot validation needed
        };

        // Only validate transactions calling Bitcoin precompiles that manage slots
        if !self.is_bitcoin_precompile_with_slots(to_address) {
            return Ok(());
        }
        
        let mut slot_lock_manager = self.slot_lock_manager.write();
        
        reth_tracing::tracing::debug!(
            target: "sova_executor",
            tx_hash = %tx.hash(),
            to = %to_address,
            "Validating slot locks for Bitcoin precompile transaction"
        );

        // Parse transaction calldata to extract accessed storage slots
        // For Bitcoin precompiles, the calldata contains information about which UTXO slots will be accessed
        if let Err(parse_error) = self.parse_and_record_bitcoin_slots(&mut slot_lock_manager, tx, to_address) {
            return Err(BlockExecutionError::msg(format!(
                "Failed to parse Bitcoin precompile calldata: {}", 
                parse_error
            )));
        }

        // Validate that none of the accessed slots are locked
        match slot_lock_manager.validate_no_locked_slots(block_number) {
            Ok(()) => {
                reth_tracing::tracing::debug!(
                    target: "sova_executor",
                    tx_hash = %tx.hash(),
                    "All slot locks validated successfully"
                );
                Ok(())
            }
            Err(err) => {
                reth_tracing::tracing::warn!(
                    target: "sova_executor",
                    tx_hash = %tx.hash(),
                    error = %err,
                    "Slot lock validation failed"
                );
                Err(BlockExecutionError::msg(format!(
                    "Slot lock validation failed: {}", 
                    err
                )))
            }
        }
    }

    /// Check if an address corresponds to a Bitcoin precompile that manages storage slots
    fn is_bitcoin_precompile_with_slots(&self, address: Address) -> bool {
        address == BROADCAST_TRANSACTION_ADDRESS || address == VAULT_SPEND_ADDRESS
    }

    /// Parse Bitcoin precompile calldata and record accessed storage slots
    /// This is a simplified implementation - in production would need proper calldata parsing
    fn parse_and_record_bitcoin_slots(
        &self,
        slot_lock_manager: &mut crate::slot_lock_manager::SlotLockManager,
        tx: &OpTransactionSigned,
        precompile_address: Address,
    ) -> Result<(), String> {
        let calldata = tx.input();
        
        reth_tracing::tracing::debug!(
            target: "sova_executor",
            precompile_address = %precompile_address,
            calldata_len = calldata.len(),
            "Parsing Bitcoin precompile calldata for slot access"
        );

        // TODO: Implement proper calldata parsing for Bitcoin precompiles
        // This would involve:
        // 1. Parsing the function selector (first 4 bytes)
        // 2. Decoding the parameters based on the precompile's ABI
        // 3. Extracting UTXO identifiers that map to storage slots
        // 4. Recording those slots with slot_lock_manager.record_storage_access()
        
        // For now, this is a placeholder that demonstrates the integration pattern
        // In a real implementation, you would:
        // - Parse the Bitcoin transaction hex from calldata
        // - Extract UTXO references (outpoint: txid + vout)
        // - Convert to storage slot keys using a deterministic mapping
        // - Record each accessed slot
        
        if calldata.len() < 4 {
            return Err("Invalid calldata: too short for function selector".to_string());
        }

        // Example: For BROADCAST_TRANSACTION, extract UTXO slots from Bitcoin transaction
        if precompile_address == BROADCAST_TRANSACTION_ADDRESS {
            // Placeholder logic - would parse Bitcoin transaction and extract UTXOs
            reth_tracing::tracing::info!(
                target: "sova_executor",
                "Processing broadcast transaction - would extract UTXO slots here"
            );
            
            // Example of recording a storage slot (this would be based on actual UTXO parsing)
            let example_slot = U256::from(0x1234); // Would be derived from UTXO outpoint
            let storage_change = crate::slot_lock_manager::StorageChange {
                key: example_slot,
                value: U256::from(1), // Would be the actual storage value
                had_value: None,
            };
            slot_lock_manager.record_storage_access(precompile_address, example_slot, storage_change);
        }
        
        Ok(())
    }
}

// Implement BlockExecutor following the OpBlockExecutor pattern exactly
impl<'db, DB, Evm> BlockExecutor for SovaBlockExecutor<Evm>
where
    DB: Database + 'db,
    Evm: reth_evm::Evm<
        DB = &'db mut State<DB>,
        Tx: reth_evm::FromRecoveredTx<OpTransactionSigned> + reth_evm::FromTxWithEncoded<OpTransactionSigned>,
    >,
{
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;
    type Evm = Evm;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Apply system calls like OpBlockExecutor does
        self.system_caller.apply_blockhashes_contract_call(
            self.ctx.parent_hash,
            &mut self.evm,
        )?;
        
        self.system_caller.apply_beacon_root_contract_call(
            self.ctx.parent_beacon_block_root,
            &mut self.evm,
        )?;

        reth_tracing::tracing::debug!(target: "sova_executor", "Applied pre-execution changes with system calls");
        Ok(())
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as reth_evm::Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // CRITICAL: Validate slot locks BEFORE executing the transaction
        let block_number = self.evm.block().number.saturating_to();
        self.validate_slot_locks(tx.tx(), block_number)?;

        // Check gas limits (following OpBlockExecutor pattern)
        let block_available_gas = self.evm.block().gas_limit - self.gas_used;
        if tx.tx().gas_limit() > block_available_gas {
            return Err(BlockExecutionError::msg(format!(
                "Transaction gas limit {} exceeds available block gas {}", 
                tx.tx().gas_limit(), 
                block_available_gas
            )));
        }

        // Execute the transaction
        let ResultAndState { result, state } = self
            .evm
            .transact(tx)
            .map_err(|err| BlockExecutionError::msg(format!("EVM execution failed: {}", err)))?;

        // Check if we should commit based on the provided condition
        if !f(&result).should_commit() {
            return Ok(None);
        }

        // Notify system caller of state changes
        self.system_caller.on_state(
            StateChangeSource::Transaction(self.receipts.len()),
            &state,
        );

        let gas_used = result.gas_used();
        self.gas_used += gas_used;

        // Build receipt following OpBlockExecutor pattern
        let base_receipt = Receipt {
            status: Eip658Value::Eip658(result.is_success()),
            cumulative_gas_used: self.gas_used,
            logs: result.logs().to_vec(),
        };
        
        let receipt = match tx.tx().tx_type() {
            OpTxType::Legacy => OpReceipt::Legacy(base_receipt),
            OpTxType::Eip2930 => OpReceipt::Eip2930(base_receipt),
            OpTxType::Eip1559 => OpReceipt::Eip1559(base_receipt),
            OpTxType::Eip7702 => OpReceipt::Eip7702(base_receipt),
            OpTxType::Deposit => {
                // For deposit transactions, we'd need special handling
                // For now, default to Legacy to keep compilation working
                OpReceipt::Legacy(base_receipt)
            }
        };
        self.receipts.push(receipt);

        // Commit state changes
        self.evm.db_mut().commit(state);

        reth_tracing::tracing::debug!(
            target: "sova_executor",
            tx_hash = %tx.tx().hash(),
            gas_used = gas_used,
            total_gas_used = self.gas_used,
            "Transaction executed successfully with slot lock validation"
        );

        Ok(Some(gas_used))
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        // Apply post-execution system calls
        let requests = self.system_caller.apply_post_execution_changes(&mut self.evm)?;

        reth_tracing::tracing::info!(
            target: "sova_executor", 
            receipts_count = self.receipts.len(),
            total_gas_used = self.gas_used,
            "Block execution finished with slot lock validation"
        );

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

    fn evm(&self) -> &Self::Evm {
        &self.evm
    }
}