# SlotLockManager

A standalone slot lock manager service for Bitcoin L2 rollup finality tracking and enforcement. This service provides a clean and reusable component for managing Bitcoin finality guarantees in EVM state transitions.

## Overview

The SlotLockManager enforces "slot locks" - a mechanism that tracks EVM storage slot changes and ensures Bitcoin finality before allowing state modifications. It provides:

- **Slot Lock Enforcement**: Prevents state modifications when Bitcoin finality hasn't been reached
- **Slot Reversion**: Reverts EVM slots to previous values when Bitcoin transactions fail
- **Sentinel Integration**: Communicates with the [Sova Sentinel](https://github.com/SovaNetwork/sova-sentinel) which serves as a lock status database which can read from a Bitcoin Node for up to date slot statuses

## Key Components

### SlotLockManager
A helper service to sova-reth that:
- Processes EVM storage access per tx
- Enforces slot locks on all L2 transactions which are tied to Bitcoin transactions
- Interfaces with the sentinel service for lock status

### StorageCache
Tracks storage slot changes:
- Records storage accesses during transaction execution
- Maintains history of slot values for tracking in the sentinel
- Manages Bitcoin tx broadcast data for locking

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
