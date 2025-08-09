use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use alloy_primitives::{Address, U256, B256};
use crossbeam_channel::{bounded, Receiver, Sender};
use reth_tracing::tracing::{debug, info, warn, error};

use crate::sentinel_client::{SentinelClient, SentinelError, SlotLockStatus};

/// Request types for the sentinel worker
#[derive(Debug)]
pub enum SentinelReq {
    /// Check if storage slots are locked
    CheckLocks {
        /// Slots to check: (address, slot)
        slots: Vec<(Address, U256)>,
        /// Current L2 block number
        eth_block: u64,
        /// Current Bitcoin block height
        btc_block: u64,
        /// Response channel
        resp: crossbeam_channel::Sender<Result<Vec<((Address, U256), SlotLockStatus)>, SentinelError>>,
    },
    /// Lock storage slots for a Bitcoin transaction
    LockSlots {
        /// Slots to lock: (address, slot)
        slots: Vec<(Address, U256)>,
        /// L2 block number
        eth_block: u64,
        /// Bitcoin block height
        btc_block: u64,
        /// Bitcoin transaction ID
        txid: B256,
        /// Response channel
        resp: crossbeam_channel::Sender<Result<(), SentinelError>>,
    },
}

/// Single background worker for all sentinel operations
/// Maintains one async runtime and processes requests via channels
pub struct SentinelWorker {
    /// Request sender
    tx: Sender<SentinelReq>,
    /// Worker thread handle
    _handle: thread::JoinHandle<()>,
}

impl SentinelWorker {
    /// Start the sentinel worker with a dedicated async runtime
    pub fn start(client: SentinelClient, capacity: usize) -> Result<Self, SentinelError> {
        let (tx, rx) = bounded::<SentinelReq>(capacity);
        
        info!("SOVA: Starting sentinel worker with capacity {}", capacity);
        
        let handle = thread::Builder::new()
            .name("sova-sentinel-worker".to_string())
            .spawn(move || {
                Self::run_worker(client, rx);
            })
            .map_err(|e| SentinelError::Connection(format!("Failed to spawn sentinel worker: {}", e)))?;
        
        Ok(Self {
            tx,
            _handle: handle,
        })
    }
    
    /// Main worker loop - runs in dedicated thread with async runtime
    fn run_worker(client: SentinelClient, rx: Receiver<SentinelReq>) {
        // Create dedicated async runtime for this worker
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .thread_name("sova-sentinel-runtime")
            .build()
        {
            Ok(rt) => {
                info!("SOVA: Sentinel worker async runtime started");
                rt
            }
            Err(e) => {
                error!("SOVA: Failed to create sentinel worker runtime: {}", e);
                return;
            }
        };
        
        // Spawn the main async task
        rt.block_on(async {
            let mut pending_requests = 0usize;
            let mut completed_requests = 0usize;
            
            info!("SOVA: Sentinel worker async task started");
            
            loop {
                match rx.recv() {
                    Ok(req) => {
                        pending_requests += 1;
                        debug!("SOVA: Processing sentinel request {} (pending: {})", 
                               completed_requests + 1, pending_requests);
                        
                        match req {
                            SentinelReq::CheckLocks { slots, eth_block, btc_block, resp } => {
                                Self::handle_check_locks(&client, slots, eth_block, btc_block, resp).await;
                            }
                            SentinelReq::LockSlots { slots, eth_block, btc_block, txid, resp } => {
                                Self::handle_lock_slots(&client, slots, eth_block, btc_block, txid, resp).await;
                            }
                        }
                        
                        pending_requests -= 1;
                        completed_requests += 1;
                    }
                    Err(_) => {
                        info!("SOVA: Sentinel worker shutting down (channel closed)");
                        break;
                    }
                }
            }
            
            info!("SOVA: Sentinel worker processed {} total requests", completed_requests);
        });
    }
    
    /// Handle slot lock checking
    async fn handle_check_locks(
        client: &SentinelClient,
        slots: Vec<(Address, U256)>,
        eth_block: u64,
        btc_block: u64,
        resp: crossbeam_channel::Sender<Result<Vec<((Address, U256), SlotLockStatus)>, SentinelError>>,
    ) {
        debug!("SOVA: Checking {} slots for locks at L2 block {}, BTC block {}", 
               slots.len(), eth_block, btc_block);
        
        // Group slots by address for efficient batch checking
        let mut slots_by_address: HashMap<Address, Vec<U256>> = HashMap::new();
        for (address, slot) in &slots {
            slots_by_address.entry(*address).or_default().push(*slot);
        }
        
        // Create slot lock request
        let request = crate::sentinel_client::SlotLockRequest {
            block_number: eth_block,
            block_hash: B256::ZERO, // TODO: Get actual block hash
            slots_by_address,
        };
        
        // Call sentinel service
        let result = match client.check_slot_locks(request).await {
            Ok(response) => {
                debug!("SOVA: Received slot lock response for {} slots", response.slot_statuses.len());
                Ok(response.slot_statuses.into_iter().collect())
            }
            Err(e) => {
                warn!("SOVA: Slot lock check failed: {}", e);
                Err(e)
            }
        };
        
        // Send response back
        if let Err(_) = resp.send(result) {
            warn!("SOVA: Failed to send slot check response - receiver dropped");
        }
    }
    
    /// Handle slot locking
    async fn handle_lock_slots(
        client: &SentinelClient,
        slots: Vec<(Address, U256)>,
        eth_block: u64,
        btc_block: u64,
        txid: B256,
        resp: crossbeam_channel::Sender<Result<(), SentinelError>>,
    ) {
        debug!("SOVA: Locking {} slots for Bitcoin tx {} at L2 block {}, BTC block {}", 
               slots.len(), txid, eth_block, btc_block);
        
        // Convert to storage changes for registration
        let storage_changes: Vec<crate::sentinel_client::BitcoinStorageChange> = slots.clone()
            .into_iter()
            .map(|(address, slot)| crate::sentinel_client::BitcoinStorageChange {
                address,
                slot,
                new_value: U256::ZERO, // TODO: Get actual new value
                previous_value: U256::ZERO, // TODO: Get actual previous value
                operation_type: crate::sentinel_client::BitcoinOperationType::Broadcast {
                    btc_tx_hash: format!("{:?}", txid),
                },
            })
            .collect();
        
        // Create registration request
        let registration = crate::sentinel_client::BitcoinTransactionRegistration {
            l2_tx_hash: B256::ZERO, // TODO: Get actual L2 tx hash
            l2_block_number: eth_block,
            storage_changes,
        };
        
        // Register with sentinel
        let result = match client.register_bitcoin_transaction(registration).await {
            Ok(()) => {
                debug!("SOVA: Successfully locked {} slots for Bitcoin tx {}", 
                       slots.len(), txid);
                Ok(())
            }
            Err(e) => {
                warn!("SOVA: Failed to lock slots for Bitcoin tx {}: {}", txid, e);
                Err(e)
            }
        };
        
        // Send response back
        if let Err(_) = resp.send(result) {
            warn!("SOVA: Failed to send lock response - receiver dropped");
        }
    }
    
    /// Check if storage slots are locked (blocking call from sync context)
    pub fn check_locks(
        &self, 
        slots: Vec<(Address, U256)>, 
        eth_block: u64, 
        btc_block: u64
    ) -> Result<Vec<((Address, U256), SlotLockStatus)>, SentinelError> {
        debug!("SOVA: Sync check_locks called for {} slots", slots.len());
        
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        
        let req = SentinelReq::CheckLocks {
            slots,
            eth_block,
            btc_block,
            resp: resp_tx,
        };
        
        // Send request
        self.tx.send(req)
            .map_err(|_| SentinelError::Connection("Sentinel worker disconnected".into()))?;
        
        // Block on response
        resp_rx.recv()
            .map_err(|_| SentinelError::Connection("Sentinel worker response channel closed".into()))?
    }
    
    /// Lock storage slots for a Bitcoin transaction (blocking call from sync context)  
    pub fn lock_slots(
        &self,
        slots: Vec<(Address, U256)>,
        eth_block: u64,
        btc_block: u64,
        txid: B256,
    ) -> Result<(), SentinelError> {
        debug!("SOVA: Sync lock_slots called for {} slots, txid {}", slots.len(), txid);
        
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        
        let req = SentinelReq::LockSlots {
            slots,
            eth_block,
            btc_block,
            txid,
            resp: resp_tx,
        };
        
        // Send request
        self.tx.send(req)
            .map_err(|_| SentinelError::Connection("Sentinel worker disconnected".into()))?;
        
        // Block on response
        resp_rx.recv()
            .map_err(|_| SentinelError::Connection("Sentinel worker response channel closed".into()))?
    }
    
    /// Get worker queue depth for monitoring
    pub fn queue_depth(&self) -> usize {
        self.tx.len()
    }
    
    /// Check if worker is still alive
    pub fn is_alive(&self) -> bool {
        !self.tx.is_full() // Rough heuristic - if channel is not full, worker is likely processing
    }
}

impl std::fmt::Debug for SentinelWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SentinelWorker")
            .field("queue_depth", &self.queue_depth())
            .field("is_alive", &self.is_alive())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_worker_creation() {
        // Test that worker can be created (but not started without proper sentinel client)
        let client = SentinelClient::new("http://localhost:50051".to_string(), 6);
        let result = SentinelWorker::start(client, 100);
        
        // Should succeed in creating the worker structure
        assert!(result.is_ok(), "Worker creation failed: {:?}", result.err());
        
        let worker = result.unwrap();
        assert!(worker.queue_depth() == 0, "New worker should have empty queue");
        
        // Give worker thread a moment to initialize
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Worker thread should be running
        assert!(worker.is_alive(), "Worker should be alive after creation");
    }
}