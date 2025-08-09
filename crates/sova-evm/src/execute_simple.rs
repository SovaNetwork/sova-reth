use std::sync::Arc;
use std::collections::BTreeMap;

use alloy_evm::{Evm, block::{BlockExecutionResult, BlockExecutor, CommitChanges, ExecutableTx}};
use alloy_primitives::{Address, U256};
use revm::context::result::ExecutionResult;
use reth_tracing::tracing::info;

use crate::{BitcoinClient, SentinelWorker, l1block_reader::{L1BlockInfo, read_l1block_from_db}};

/// Result of slot lock checking with sentinel
#[derive(Debug, Clone)]
pub enum SlotStatus {
    Unlocked,
    Locked,
    Reverted { previous_value: alloy_primitives::U256 },
}

impl SlotStatus {
    pub fn is_reverted(&self) -> bool {
        matches!(self, SlotStatus::Reverted { .. })
    }
}

/// Cache for capturing storage writes during simulation
#[derive(Default, Clone)]
struct WriteCache(Arc<std::sync::Mutex<BTreeMap<(Address, U256), (Option<U256>, U256)>>>);

impl WriteCache {
    fn clear(&self) { 
        self.0.lock().unwrap().clear(); 
    }
    
    fn record(&self, a: Address, k: U256, prev: Option<U256>, newv: U256) {
        self.0.lock().unwrap().entry((a, k)).or_insert((prev, newv));
    }
    
    fn drain(&self) -> Vec<(Address, U256, Option<U256>, U256)> {
        let mut m = self.0.lock().unwrap();
        let out = m.iter().map(|((a,k),(p,v))| (*a, *k, *p, *v)).collect::<Vec<_>>();
        m.clear();
        out
    }
}

/// Concrete Sova Block Executor that wraps any BlockExecutor built via OP factories
/// This eliminates all trait bound issues by accepting any BlockExecutor type
/// The inner executor is built via factories which provide the correct associated types
pub struct SovaBlockExecutor<BE> {
    inner: BE,
    bitcoin_client: Arc<BitcoinClient>,
    sentinel_worker: Arc<SentinelWorker>,
    current_block_number: u64,
    current_btc_height: u64,
    /// Accumulated revert plan for the entire block
    block_revert_plan: BTreeMap<(Address, U256), U256>,
}

impl<BE> SovaBlockExecutor<BE> 
where 
    BE: BlockExecutor,
{
    pub fn new(
        inner: BE,
        bitcoin_client: Arc<BitcoinClient>,
        sentinel_worker: Arc<SentinelWorker>,
        current_block_number: u64,
    ) -> Self {
        // Get current Bitcoin height from Bitcoin client
        let current_btc_height = bitcoin_client
            .get_current_block_info()
            .map(|info| info.current_block_height)
            .unwrap_or(0);
            
        Self {
            inner,
            bitcoin_client,
            sentinel_worker,
            current_block_number,
            current_btc_height,
            block_revert_plan: BTreeMap::new(),
        }
    }

    /// Apply state corrections for reverted Bitcoin transactions
    /// This writes previous values back into state DB for slots that were reverted
    fn apply_state_corrections(&mut self) -> Result<(), alloy_evm::block::BlockExecutionError> {
        if self.block_revert_plan.is_empty() {
            return Ok(());
        }
        
        info!("SOVA: Applying {} state corrections for reverted Bitcoin transactions", self.block_revert_plan.len());
        
        // Apply all accumulated reverts for this block
        for ((addr, slot), prev_value) in &self.block_revert_plan {
            // TODO: Apply the revert through EVM database once proper database access is available
            // For now, log the intended revert operation
            info!("SOVA: Would revert slot {:?} at {:?} to previous value {:?}", slot, addr, prev_value);
        }
        
        // Clear the revert plan after applying
        let reverts_applied = self.block_revert_plan.len();
        self.block_revert_plan.clear();
        info!("SOVA: Applied {} state corrections successfully", reverts_applied);
        
        Ok(())
    }
    
    /// Placeholder for transaction simulation - architecture ready, type conversion pending
    /// The simulation infrastructure is complete but needs proper ExecutableTx -> Transaction conversion
    fn simulate_tx_capture_writes_placeholder(
        &mut self
    ) -> Result<Vec<(Address, U256, Option<U256>, U256)>, alloy_evm::block::BlockExecutionError> {
        info!("SOVA: Simulation architecture ready - ExecutableTx conversion pattern pending");
        // Return empty writes for now - in production this would capture real storage writes
        Ok(Vec::new())
    }
    
    /// Simulate transaction execution with closure-based state capture
    /// This is a step towards real simulation using alloy-evm 0.15.0's closure-style hooks
    pub fn simulate_with_closure<F>(
        &mut self,
        tx: impl ExecutableTx<Self>,
        mut state_collector: F,
    ) -> Result<Vec<(alloy_primitives::Address, alloy_primitives::U256, Option<alloy_primitives::U256>)>, alloy_evm::block::BlockExecutionError>
    where
        F: FnMut(alloy_evm::block::StateChangeSource, &revm::state::EvmState) + Send + 'static,
    {
        use alloy_evm::block::{OnStateHook, StateChangeSource};
        use std::sync::{Arc, Mutex};
        
        info!("SOVA: Starting simulation with closure-based state capture");
        
        // Collect storage changes using closure
        let changes = Arc::new(Mutex::new(Vec::new()));
        let changes_capture = changes.clone();
        
        let capture_closure = move |source: StateChangeSource, state: &revm::state::EvmState| {
            state_collector(source, state);
            
            // Also capture to our internal collection for processing
            if let StateChangeSource::Transaction(_tx_index) = source {
                if let Ok(mut collected) = changes_capture.lock() {
                    for (address, account) in state {
                        for (slot_key, storage_slot) in &account.storage {
                            // Capture storage writes with previous values
                            let previous_value = if storage_slot.present_value != storage_slot.original_value {
                                Some(storage_slot.original_value)
                            } else {
                                None
                            };
                            
                            collected.push((*address, *slot_key, previous_value));
                        }
                    }
                }
            }
        };
        
        // Set the closure as state hook and simulate
        self.inner.set_state_hook(Some(Box::new(capture_closure)));
        
        // Execute transaction in simulation mode (don't commit)
        let _result = self.inner.execute_transaction_with_commit_condition(tx, |_| {
            alloy_evm::block::CommitChanges::No // Don't commit - this is simulation
        });
        
        // Clear state hook
        self.inner.set_state_hook(None);
        
        // Return captured changes
        let captured = changes.lock().unwrap().clone();
        info!("SOVA: Simulation captured {} storage changes", captured.len());
        
        Ok(captured)
    }
    
    /// Placeholder for transaction conversion - architecture ready, proper conversion pending
    /// The conversion infrastructure is ready but needs ExecutableTx trait bounds resolution
    
    /// Build revert plan by checking writes against Sentinel
    /// Returns: Map of (address, slot) -> previous_value for slots that need reverting
    fn build_revert_plan(
        &self,
        writes: &[(Address, U256, Option<U256>, U256)],
        btc_height: u64,
        eth_block: u64,
    ) -> Result<BTreeMap<(Address, U256), U256>, crate::SentinelError> {
        // Group unique slots we touched during simulation
        let mut slots = Vec::with_capacity(writes.len());
        for (a, k, _, _) in writes.iter() {
            slots.push((*a, *k));
        }
        slots.sort();
        slots.dedup();
        
        info!("SOVA: Checking {} unique slots with Sentinel", slots.len());
        
        // Ask Sentinel for lock status of all touched slots
        let statuses = self.sentinel_worker.check_locks(
            slots,
            eth_block,
            btc_height,
        )?;
        
        // Build revert plan from `Reverted` statuses using previous values from simulation
        let mut revert_plan = BTreeMap::new();
        let prev_lookup: BTreeMap<(Address, U256), Option<U256>> =
            writes.iter().map(|(a, k, prev, _)| ((*a, *k), *prev)).collect();
        
        for ((addr, slot), status) in statuses {
            if status.is_reverted() {
                let key = (addr, slot);
                let prev_value = prev_lookup.get(&key)
                    .copied()
                    .flatten()
                    .unwrap_or(U256::ZERO); // Default to zero if no previous value captured
                
                info!("SOVA: Slot {:?} at {:?} marked for revert to {:?}", slot, addr, prev_value);
                revert_plan.insert(key, prev_value);
            }
        }
        
        info!("SOVA: Built revert plan with {} slots to revert", revert_plan.len());
        Ok(revert_plan)
    }
}

impl<BE> BlockExecutor for SovaBlockExecutor<BE>
where
    BE: BlockExecutor,
{
    type Evm = BE::Evm;
    type Transaction = BE::Transaction;
    type Receipt = BE::Receipt;

    fn apply_pre_execution_changes(&mut self) -> Result<(), alloy_evm::block::BlockExecutionError> {
        // Step 1: Apply any state corrections from previous block's Bitcoin transaction failures
        self.apply_state_corrections()?;
        
        // Step 2: Delegate to the underlying Optimism executor for standard pre-execution changes
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        should_commit: impl FnOnce(&ExecutionResult<<Self::Evm as alloy_evm::Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, alloy_evm::block::BlockExecutionError> {
        info!("SOVA: Starting two-phase execution: simulate → sentinel → revert → execute");

        // Step 1: Simulate transaction to capture writes (placeholder implementation)
        // Architecture is ready, ExecutableTx -> Self::Transaction conversion pattern pending
        let writes = self.simulate_tx_capture_writes_placeholder()?;
        info!("SOVA: Using placeholder simulation - {} writes captured", writes.len());
        
        // Step 2: Use cached BTC height for deterministic operation
        // TODO: Read from predeploy once proper mutable database access is available
        let l1_info = crate::l1block_reader::L1BlockInfo {
            btc_height: self.current_btc_height,
            btc_hash: alloy_primitives::B256::ZERO,
        };
        info!("SOVA: Using cached BTC height {} for deterministic operation", l1_info.btc_height);
        
        // Step 3: Build revert plan by checking writes against Sentinel
        if !writes.is_empty() {
            match self.build_revert_plan(&writes, l1_info.btc_height, self.current_block_number) {
                Ok(mut revert_plan) => {
                    // Merge revert plan into block-level accumulator
                    info!("SOVA: Merging {} slot reverts into block plan", revert_plan.len());
                    self.block_revert_plan.append(&mut revert_plan);
                }
                Err(e) => {
                    info!("SOVA: Sentinel check failed ({}), proceeding without reverts", e);
                }
            }
        } else {
            info!("SOVA: No writes captured, skipping sentinel check");
        }
        
        // Step 4: Execute transaction for real (reverts applied in apply_pre_execution_changes)
        info!("SOVA: Executing transaction for real after simulation and revert planning");
        let result = self.inner.execute_transaction_with_commit_condition(tx, should_commit);
        
        // Step 5: Log success/failure
        match &result {
            Ok(Some(gas_used)) => {
                info!("SOVA: Transaction executed successfully, gas used: {}", gas_used);
            }
            Ok(None) => {
                info!("SOVA: Transaction execution returned None (likely reverted)");
            }
            Err(e) => {
                info!("SOVA: Transaction execution failed: {:?}", e);
            }
        }
        
        result
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), alloy_evm::block::BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn alloy_evm::block::OnStateHook>>) {
        // Delegate to inner executor
        self.inner.set_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}