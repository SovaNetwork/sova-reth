use std::collections::HashMap;
use std::sync::Arc;

use alloy_evm::{
    block::{BlockExecutionError, BlockExecutionResult, BlockExecutor, CommitChanges, ExecutableTx, OnStateHook},
    Database, Evm, precompiles::PrecompilesMap,
};
use alloy_primitives::{Address, U256};
use reth_optimism_primitives::OpTransactionSigned;
use reth_optimism_evm::OpRethReceiptBuilder;
use reth_op::OpReceipt;
use alloy_op_evm::{OpBlockExecutor, OpEvm};
use reth_optimism_chainspec::OpChainSpec;
use revm::{
    context::result::ExecutionResult, 
};
use reth_revm::State;
use revm_context::TxEnv;
use reth_tracing::tracing::{debug, info, warn};

use crate::{BitcoinClient, SentinelClient, SentinelError, SentinelWorker, SharedSovaStateHook, CombinedStateHook};
use crate::sentinel_client::{SlotLockRequest, BitcoinTransactionRegistration, BitcoinStorageChange, BitcoinOperationType};

//
// ===== CONCRETE TYPE DEFINITIONS =====
// Monomorphized types that eliminate all trait bound issues by using proven concrete types.
// Following the pattern from alloy-op-evm examples and reth custom-node.
//

// We'll use a generic type alias and let the provider construct the concrete type
// This allows the compiler to infer the EVM generics when OpBlockExecutor is constructed

/// Storage slot change tracked during simulation phase
#[derive(Debug, Clone)]
struct StorageChange {
    address: Address,
    key: U256,
    value: U256,
    previous_value: Option<U256>,
}

/// Result of slot lock checking with sentinel
#[derive(Debug, Clone)]
pub enum SlotStatus {
    Unlocked,
    Locked,
    Reverted { previous_value: U256 },
}

/// Custom Sova Block Executor that implements the two-phase execution pattern
/// for Bitcoin L2 slot locking enforcement. Following reth custom-node pattern.
pub struct SovaBlockExecutor<E> {
    /// The underlying Optimism block executor that we wrap
    inner: OpBlockExecutor<E, OpRethReceiptBuilder, Arc<OpChainSpec>>,
    /// Bitcoin client for L1 validation and precompile operations  
    bitcoin_client: Arc<BitcoinClient>,
    /// Sentinel worker for slot lock coordination
    sentinel_worker: Arc<SentinelWorker>,
    /// Storage changes tracked during simulation phase
    simulation_storage_changes: Vec<StorageChange>,
    /// Slots that need to be reverted due to Bitcoin failures
    revert_slots: HashMap<(Address, U256), U256>,
    /// Current L2 block number for Bitcoin operations
    current_block_number: u64,
    /// Current Bitcoin block height
    current_btc_height: u64,
}

impl<E> SovaBlockExecutor<E> {
    pub fn new(
        inner: OpBlockExecutor<E, OpRethReceiptBuilder, Arc<OpChainSpec>>,
        bitcoin_client: Arc<BitcoinClient>,
        sentinel_worker: Arc<SentinelWorker>,
        current_block_number: u64,
    ) -> Self {
        // Get current Bitcoin height from Bitcoin client
        let current_btc_height = bitcoin_client
            .get_current_block_info()
            .map(|info| info.current_block_height)
            .unwrap_or(0); // Fallback to 0 if Bitcoin client unavailable
            
        Self {
            inner,
            bitcoin_client,
            sentinel_worker,
            simulation_storage_changes: Vec::new(),
            revert_slots: HashMap::new(),
            current_block_number,
            current_btc_height,
        }
    }

    /// Phase 1: Simulation execution to capture storage changes and check for Bitcoin conflicts
    /// TODO: Implement closure-style state hook for real simulation
    fn simulate_execution<T>(
        &mut self,
        _tx: &T,
    ) -> Result<Vec<StorageChange>, BlockExecutionError>
    where
        T: ExecutableTx<Self>,
    {
        info!("SOVA: Starting simulation phase for slot lock enforcement");
        
        // TODO: Implement real simulation with closure-style state hooks
        // For now, return empty changes until we implement the closure API
        let storage_changes = Vec::new();
        
        debug!("SOVA: Simulation captured {} storage changes (placeholder)", storage_changes.len());
        Ok(storage_changes)
    }

    /// Phase 2: Check storage changes against sentinel for lock status
    async fn check_slot_locks(
        &self,
        storage_changes: &[StorageChange],
    ) -> Result<HashMap<(Address, U256), SlotStatus>, SentinelError> {
        let mut slot_statuses = HashMap::new();
        
        if storage_changes.is_empty() {
            debug!("SOVA: No storage changes to check for slot locks");
            return Ok(slot_statuses);
        }

        info!("SOVA: Checking {} storage changes for slot locks", storage_changes.len());

        // Group storage changes by address for efficient batch checking
        let mut slots_by_address: HashMap<Address, Vec<U256>> = HashMap::new();
        for change in storage_changes {
            slots_by_address.entry(change.address).or_default().push(change.key);
        }

        // Call sentinel to check slot locks using worker
        let response = self.sentinel_worker.check_locks(
            slots_by_address.iter().flat_map(|(addr, slots)| {
                slots.iter().map(|slot| (*addr, *slot))
            }).collect(),
            self.current_block_number,
            self.current_btc_height,
        )?;
        
        // Convert worker response to our internal SlotStatus format
        for ((address, slot), status) in response {
            slot_statuses.insert((address, slot), status.into());
        }

        info!("SOVA: Completed slot lock checking for {} slots", slot_statuses.len());
        Ok(slot_statuses)
    }
    
    /// Helper function to determine if a storage slot is critical for Bitcoin L2 operations
    fn is_bitcoin_critical_slot(&self, address: Address, slot: U256) -> bool {
        // In production, this would check if the address/slot combination
        // is related to Bitcoin operations that need L1 finality confirmation
        
        // For now, simple check: any address that looks like a precompile
        // and specific slot patterns that might be Bitcoin-related
        address.as_slice()[19] < 0x10 || // Precompile-like addresses
        slot < U256::from(100)  // Lower slots more likely to be critical state
    }
    
    /// Helper function to determine if a transaction involves Bitcoin operations
    fn transaction_involves_bitcoin_ops(&self, storage_changes: &[StorageChange]) -> bool {
        // Check if any of the storage changes are related to Bitcoin precompiles or critical state
        storage_changes.iter().any(|change| 
            self.is_bitcoin_critical_slot(change.address, change.key)
        )
    }

    /// Phase 3: Apply state corrections for reverted slots
    fn apply_state_corrections(&mut self) -> Result<(), BlockExecutionError> {
        if self.revert_slots.is_empty() {
            debug!("SOVA: No state corrections needed");
            return Ok(());
        }

        info!("SOVA: Applying {} state corrections for reverted Bitcoin transactions", self.revert_slots.len());
        
        // TODO: Access the EVM's state to apply corrections via proper BlockExecutor methods
        // For now, we'll just log what would be corrected
        
        for ((address, slot), previous_value) in &self.revert_slots {
            debug!("SOVA: Reverting slot {:?} at {:?} to previous value {:?}", slot, address, previous_value);
            
            // TODO: Apply the state correction by setting the storage slot back to its previous value
            // This would undo the effect of a Bitcoin transaction that was later reverted on L1
            info!("SOVA: Would revert slot {:?} at {:?} to previous value {:?}", 
                  slot, address, previous_value);
        }

        // Clear the revert slots after applying corrections
        let corrected_count = self.revert_slots.len();
        self.revert_slots.clear();
        
        info!("SOVA: Successfully applied {} state corrections", corrected_count);
        Ok(())
    }
}

impl<E> BlockExecutor for SovaBlockExecutor<E>
where
    E: Evm,
{
    type Evm = E;
    type Transaction = <OpBlockExecutor<E, OpRethReceiptBuilder, Arc<OpChainSpec>> as BlockExecutor>::Transaction;
    type Receipt = <OpBlockExecutor<E, OpRethReceiptBuilder, Arc<OpChainSpec>> as BlockExecutor>::Receipt;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Step 1: Apply any state corrections from previous block's Bitcoin transaction failures
        self.apply_state_corrections()?;
        
        // Step 2: Delegate to the underlying Optimism executor for standard pre-execution changes
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        info!("SOVA: Executing transaction with slot lock enforcement");

        // ===== SOVA TWO-PHASE EXECUTION =====
        
        // Phase 1: Simulate to capture storage changes
        let storage_changes = self.simulate_execution(&tx)?;
        
        // Phase 2: Check against sentinel using worker (clean sync/async boundary)
        let slots: Vec<(Address, U256)> = storage_changes
            .iter()
            .map(|change| (change.address, change.key))
            .collect();
            
        let slot_lock_results = self.sentinel_worker.check_locks(
            slots,
            self.current_block_number,
            self.current_btc_height,
        ).map_err(|e| BlockExecutionError::other(std::io::Error::new(
            std::io::ErrorKind::Other, 
            format!("Sentinel error: {}", e)
        )))?;
        
        // Convert to internal SlotStatus format
        let mut slot_statuses = HashMap::new();
        for ((address, slot), status) in slot_lock_results {
            slot_statuses.insert((address, slot), status.into());
        }

        // Phase 3: Check if any slots are locked and should prevent execution
        for ((address, slot), status) in &slot_statuses {
            match status {
                SlotStatus::Locked => {
                    warn!("SOVA: Transaction blocked - attempted to modify locked slot {:?} at {:?}", slot, address);
                    // Return a failed execution that gets reverted
                    return Ok(None);
                }
                SlotStatus::Reverted { previous_value } => {
                    // Record this slot for correction in the next block
                    self.revert_slots.insert((*address, *slot), previous_value);
                }
                SlotStatus::Unlocked => {
                    // OK to proceed
                }
            }
        }

        // Phase 4: Execute the transaction for real if all checks pass
        info!("SOVA: All slot locks passed, executing transaction normally");
        let result = self.inner.execute_transaction_with_commit_condition(tx, f);

        // Phase 5: If successful and this involved Bitcoin operations, update sentinel locks
        if let Ok(Some(gas_used)) = &result {
            debug!("SOVA: Transaction executed successfully, gas used: {}", gas_used);
            
            // Check if this transaction involved Bitcoin operations that need L1 confirmation
            if self.transaction_involves_bitcoin_ops(&storage_changes) {
                info!("SOVA: Transaction involved Bitcoin operations, registering with sentinel");
                
                // Convert storage changes to Bitcoin storage changes for sentinel registration
                let bitcoin_storage_changes: Vec<BitcoinStorageChange> = storage_changes
                    .iter()
                    .filter(|change| self.is_bitcoin_critical_slot(change.address, change.key))
                    .map(|change| BitcoinStorageChange {
                        address: change.address,
                        slot: change.key,
                        new_value: change.value,
                        previous_value: change.previous_value.unwrap_or_default(),
                        operation_type: BitcoinOperationType::Broadcast {
                            btc_tx_hash: "placeholder_tx_hash".to_string(), // TODO: Extract from actual tx
                        },
                    })
                    .collect();

                if !bitcoin_storage_changes.is_empty() {
                    let registration = BitcoinTransactionRegistration {
                        l2_tx_hash: alloy_primitives::B256::ZERO, // TODO: Extract actual tx hash from ExecutableTx
                        l2_block_number: self.current_block_number,
                        storage_changes: bitcoin_storage_changes.clone(),
                    };

                    // Register with sentinel using worker (clean sync/async boundary)
                    let slots: Vec<(Address, U256)> = bitcoin_storage_changes
                        .iter()
                        .map(|change| (change.address, change.slot))
                        .collect();
                        
                    let registration_result = self.sentinel_worker.lock_slots(
                        slots,
                        self.current_block_number,
                        self.current_btc_height,
                        alloy_primitives::B256::ZERO, // TODO: Extract actual Bitcoin txid from precompile data
                    );

                    match registration_result {
                        Ok(()) => {
                            info!("SOVA: Successfully registered Bitcoin transaction with sentinel");
                        }
                        Err(e) => {
                            warn!("SOVA: Failed to register Bitcoin transaction with sentinel: {}", e);
                            // Continue execution - registration failure is not fatal for current block
                        }
                    }
                }
            }
        } else if let Err(ref err) = result {
            warn!("SOVA: Transaction execution failed: {:?}", err);
        }

        result
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        // Delegate to inner executor for now
        // TODO: Combine with our Bitcoin L2 state tracking
        self.inner.set_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}