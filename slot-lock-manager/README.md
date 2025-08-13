# SlotLockManager

A standalone slot lock manager service for Bitcoin L2 rollup finality tracking and enforcement. This service provides a clean and reusable component for managing Bitcoin finality guarantees in EVM state transitions.

## Overview

The SlotLockManager enforces "slot locks" - a mechanism that tracks EVM storage slot changes and ensures Bitcoin finality before allowing state modifications. It provides:

- **Slot Lock Enforcement**: Prevents state modifications when Bitcoin finality hasn't been reached
- **Slot Reversion**: Reverts EVM slots to previous values when Bitcoin transactions fail
- **Sentinel Integration**: Communicates with the sentinel service for lock status

## Key Components

### SlotLockManager
The main service that:
- Processes EVM storage access patterns
- Enforces slot locks before any Bitcoin precompile calls which are tied to a Bitcoin transaction
- Manages slot reverts when Bitcoin finality isn't reached
- Interfaces with the sentinel service for lock status

### StorageCache
Tracks storage slot changes:
- Records storage accesses during transaction execution
- Maintains history of slot values for tracking in the sentinel
- Manages broadcast transaction data for locking

### SentinelClient
Interfaces with the sentinel service:
- Checks slot lock status before transactions
- Update slot locks after a block has been processed

## Two-Phase Broadcast Flow

For Bitcoin broadcast precompiles, the SlotLockManager uses a two-phase approach:

1. **Phase 1 - Pre-execution**: Call `check_precompile_call()` to validate storage accesses and check locks
2. **Phase 2 - Post-execution**: Call `finalize_broadcast()` with the actual Bitcoin txid after successful precompile execution

This ensures that:
- Storage accesses are validated before Bitcoin transaction broadcast
- The actual Bitcoin txid is captured for future slot locking operations
- Failed broadcasts don't leave orphaned lock data

## Usage

```rust
use slot_lock_manager::{SlotLockManager, SlotLockManagerConfig, SentinelClientImpl};
use std::sync::Arc;

// Configure the manager using builder pattern
let config = SlotLockManagerConfig::builder()
    .sentinel_url("http://localhost:50051")
    .excluded_address(L1_BLOCK_CONTRACT_ADDRESS)
    .build();

// Create sentinel client
let sentinel_client = Arc::new(SentinelClientImpl::new(config.sentinel_url.clone()));

// Create the manager
let manager = SlotLockManager::new(config, sentinel_client);

// PHASE 1: Check if a broadcast transaction should be allowed
let request = SlotLockRequest {
    transaction_context: TransactionContext { /* ... */ },
    block_context: BlockContext { /* ... */ },
    precompile_call: Some(PrecompileCall { 
        method: BitcoinPrecompileMethod::BroadcastTransaction,
        /* ... */
    }),
    storage_accesses: vec![/* ... */],
};

let response = manager.check_precompile_call(request).await?;
match response.decision {
    SlotLockDecision::Allow => {
        // Transaction can proceed - execute the precompile
        let txid = execute_broadcast_precompile(input)?;
        
        // PHASE 2: Finalize with actual Bitcoin txid  
        manager.finalize_broadcast(txid, btc_block_height);
    }
    SlotLockDecision::Revert { reason } => {
        // Transaction should be reverted
    }
    SlotLockDecision::RevertWithSlotData { slots } => {
        // Transaction should be reverted with slot data restoration
    }
}
```

### Configuration Options

The SlotLockManager supports flexible configuration through a builder pattern:

```rust
let config = SlotLockManagerConfig::builder()
    .sentinel_url("http://localhost:50051")                    // Sentinel service endpoint
    .excluded_address(L1_BLOCK_CONTRACT_ADDRESS)               // Single excluded address
    .excluded_addresses(vec![addr1, addr2])                    // Multiple excluded addresses
    .bitcoin_precompile_addresses([addr1, addr2, addr3, addr4]) // Custom precompile addresses
    .build();
```

**Builder Methods:**
- `.sentinel_url(url)` - Sets the sentinel service URL (default: `http://localhost:50051`)
- `.excluded_address(address)` - Adds a single address to exclude from slot tracking
- `.excluded_addresses(addresses)` - Adds multiple addresses to exclude from slot tracking  
- `.bitcoin_precompile_addresses(addresses)` - Sets custom Bitcoin precompile addresses (default: standard precompile addresses)

## Testing

Run the test suite:

```bash
cargo test
```

The tests include mock implementations for sentinel client testing and basic functionality verification.