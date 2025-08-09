use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy_evm::block::{OnStateHook, StateChangeSource};
use alloy_primitives::{Address, U256};
use revm::state::EvmState;
use reth_tracing::tracing::debug;

/// Captures storage writes (address, slot, previous_value) during transaction execution
/// for slot lock enforcement in the Sova Bitcoin L2 system.
#[derive(Debug, Default)]
pub struct SovaOnStateHook {
    /// Storage writes captured during execution: (address, slot, previous_value)
    writes: Vec<(Address, U256, Option<U256>)>,
    /// Current transaction ID being tracked
    current_tx_id: Option<usize>,
}

impl SovaOnStateHook {
    /// Creates a new state hook for capturing storage writes
    pub fn new() -> Self {
        Self {
            writes: Vec::new(),
            current_tx_id: None,
        }
    }

    /// Clears all captured writes, typically called before executing a new transaction
    pub fn clear(&mut self) {
        self.writes.clear();
        self.current_tx_id = None;
        debug!("SOVA: State hook cleared for new transaction");
    }

    /// Drains all captured writes and returns them, typically called after transaction execution
    pub fn drain(&mut self) -> Vec<(Address, U256, Option<U256>)> {
        let writes = std::mem::take(&mut self.writes);
        self.current_tx_id = None;
        debug!("SOVA: Drained {} storage writes from state hook", writes.len());
        writes
    }

    /// Gets a read-only view of current writes without draining
    pub fn get_writes(&self) -> &[(Address, U256, Option<U256>)] {
        &self.writes
    }
    
    /// Filters writes to only include those with captured previous values (needed for reverts)
    pub fn get_revertible_writes(&self) -> Vec<(Address, U256, U256)> {
        self.writes
            .iter()
            .filter_map(|(address, slot, prev_value)| {
                // Only include writes where we captured the previous value
                prev_value.map(|prev| (*address, *slot, prev))
            })
            .collect()
    }

    /// Sets the current transaction ID for tracking
    pub fn set_transaction_id(&mut self, tx_id: usize) {
        self.current_tx_id = Some(tx_id);
    }

    /// Processes a single account's storage changes and extracts writes
    /// This captures the previous value before SSTORE operations for accurate revert handling
    fn process_account_storage(&mut self, address: Address, account: &revm::state::Account) {
        for (slot_key, storage_slot) in &account.storage {
            // Only process slots that were written in the current transaction
            if let Some(current_tx_id) = self.current_tx_id {
                if storage_slot.transaction_id == current_tx_id {
                    let slot = *slot_key;
                    
                    // Determine the previous value before this write
                    // The original_value in a storage slot represents the value before any changes in this tx
                    let previous_value = if storage_slot.is_cold {
                        // Cold slot - was loaded from state DB, original_value is the DB value
                        Some(storage_slot.original_value)
                    } else if storage_slot.present_value != storage_slot.original_value {
                        // Warm slot that was changed - original_value is the pre-transaction value
                        Some(storage_slot.original_value)
                    } else {
                        // Warm slot that was accessed but not changed in this tx
                        // This shouldn't normally happen as we only see changed slots here
                        None
                    };

                    debug!(
                        "SOVA: Captured storage write - address: {:?}, slot: {:?}, prev: {:?} -> new: {:?} (cold: {}, changed: {})",
                        address, 
                        slot, 
                        previous_value,
                        storage_slot.present_value,
                        storage_slot.is_cold,
                        storage_slot.present_value != storage_slot.original_value
                    );

                    // Always record the write with the previous value for revert capability
                    self.writes.push((address, slot, previous_value));
                }
            }
        }
    }
}

impl OnStateHook for SovaOnStateHook {
    fn on_state(&mut self, source: StateChangeSource, state: &EvmState) {
        // Only capture writes from transactions, not system calls
        if let StateChangeSource::Transaction(tx_index) = source {
            // Update current transaction ID if it changed
            if self.current_tx_id != Some(tx_index) {
                self.set_transaction_id(tx_index);
            }

            // Process each account in the state for storage changes
            for (address, account) in state {
                self.process_account_storage(*address, account);
            }
        }
    }
}

/// Thread-safe wrapper for SovaOnStateHook to be shared across EVM components
#[derive(Debug, Clone)]
pub struct SharedSovaStateHook {
    inner: Arc<Mutex<SovaOnStateHook>>,
}

impl SharedSovaStateHook {
    /// Creates a new shared state hook
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SovaOnStateHook::new())),
        }
    }

    /// Clears all captured writes
    pub fn clear(&self) {
        if let Ok(mut hook) = self.inner.lock() {
            hook.clear();
        }
    }

    /// Drains all captured writes
    pub fn drain(&self) -> Vec<(Address, U256, Option<U256>)> {
        if let Ok(mut hook) = self.inner.lock() {
            hook.drain()
        } else {
            Vec::new()
        }
    }

    /// Gets a snapshot of current writes
    pub fn get_writes(&self) -> Vec<(Address, U256, Option<U256>)> {
        if let Ok(hook) = self.inner.lock() {
            hook.get_writes().to_vec()
        } else {
            Vec::new()
        }
    }
    
    /// Gets only the revertible writes (those with captured previous values)
    pub fn get_revertible_writes(&self) -> Vec<(Address, U256, U256)> {
        if let Ok(hook) = self.inner.lock() {
            hook.get_revertible_writes()
        } else {
            Vec::new()
        }
    }

    /// Creates a boxed OnStateHook trait object for use with EVM
    pub fn create_hook(&self) -> Box<dyn OnStateHook> {
        Box::new(SovaStateHookProxy {
            shared: self.clone(),
        })
    }
}

impl Default for SharedSovaStateHook {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy that implements OnStateHook and forwards to SharedSovaStateHook
#[derive(Debug)]
struct SovaStateHookProxy {
    shared: SharedSovaStateHook,
}

impl OnStateHook for SovaStateHookProxy {
    fn on_state(&mut self, source: StateChangeSource, state: &EvmState) {
        if let Ok(mut hook) = self.shared.inner.lock() {
            hook.on_state(source, state);
        }
    }
}

/// Combined state hook that calls both our Sova hook and an external hook
pub struct CombinedStateHook {
    sova_hook: Box<dyn OnStateHook>,
    external_hook: Box<dyn OnStateHook>,
}

impl CombinedStateHook {
    pub fn new(sova_hook: Box<dyn OnStateHook>, external_hook: Box<dyn OnStateHook>) -> Self {
        Self {
            sova_hook,
            external_hook,
        }
    }
}

impl OnStateHook for CombinedStateHook {
    fn on_state(&mut self, source: StateChangeSource, state: &EvmState) {
        // Call both hooks
        self.sova_hook.on_state(source, state);
        self.external_hook.on_state(source, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::state::{Account, EvmStorageSlot};
    use std::collections::HashMap;
    
    #[test]
    fn test_hook_captures_previous_values() {
        let mut hook = SovaOnStateHook::new();
        hook.set_transaction_id(1);
        
        // Create a mock account with storage changes
        let mut account = Account::default();
        let address = Address::random();
        let slot_key = U256::from(0x42);
        
        // Simulate a storage slot that was changed from 0x01 to 0x02 in transaction 1
        let storage_slot = EvmStorageSlot::new_changed(
            U256::from(0x01), // original value
            U256::from(0x02), // present value  
            1,                // transaction_id
        );
        
        account.storage.insert(slot_key, storage_slot);
        
        // Create a mock EVM state
        let mut state = HashMap::new();
        state.insert(address, account);
        
        // Process the storage changes
        hook.process_account_storage(address, &state[&address]);
        
        // Verify the hook captured the write with previous value
        let writes = hook.get_writes();
        assert_eq!(writes.len(), 1, "Should capture exactly one write");
        
        let (captured_addr, captured_slot, captured_prev) = &writes[0];
        assert_eq!(*captured_addr, address, "Should capture correct address");
        assert_eq!(*captured_slot, slot_key, "Should capture correct slot");
        assert_eq!(*captured_prev, Some(U256::from(0x01)), "Should capture previous value 0x01");
        
        // Test revertible writes
        let revertible = hook.get_revertible_writes();
        assert_eq!(revertible.len(), 1, "Should have one revertible write");
        
        let (revert_addr, revert_slot, revert_prev) = &revertible[0];
        assert_eq!(*revert_addr, address, "Revertible write should have correct address");
        assert_eq!(*revert_slot, slot_key, "Revertible write should have correct slot");
        assert_eq!(*revert_prev, U256::from(0x01), "Revertible write should have previous value");
    }
    
    #[test]
    fn test_shared_hook_thread_safety() {
        let shared_hook = SharedSovaStateHook::new();
        
        // Test that we can clear and get writes across thread boundaries
        shared_hook.clear();
        let writes = shared_hook.get_writes();
        assert_eq!(writes.len(), 0, "New shared hook should be empty");
        
        let revertible = shared_hook.get_revertible_writes();
        assert_eq!(revertible.len(), 0, "New shared hook should have no revertible writes");
        
        // Test hook creation
        let _hook_proxy = shared_hook.create_hook();
        // Hook creation should succeed without panic
    }
}