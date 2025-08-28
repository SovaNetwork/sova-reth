//! Bitcoin precompile constants for Sova network
//!
//! This module defines the constants used for Bitcoin-specific precompiles
//! in the Sova network, including addresses, gas costs, and other configuration.

/// Convert existing chainspec addresses to precompile IDs
/// These IDs correspond to the actual addresses defined in constants.rs:
/// - BROADCAST_TRANSACTION_ADDRESS: 0x999
/// - DECODE_TRANSACTION_ADDRESS: 0x998  
/// - CONVERT_ADDRESS_ADDRESS: 0x997
/// - VAULT_SPEND_ADDRESS: 0x996
pub const BROADCAST_TRANSACTION_PRECOMPILE_ID: u64 = 0x999;
pub const DECODE_TRANSACTION_PRECOMPILE_ID: u64 = 0x998;
pub const CONVERT_ADDRESS_PRECOMPILE_ID: u64 = 0x997;
pub const VAULT_SPEND_PRECOMPILE_ID: u64 = 0x996;

/// Gas constants for Bitcoin precompiles
/// These are base gas costs for each Bitcoin operation
pub const BITCOIN_BROADCAST_BASE_GAS: u64 = 21000;
pub const BITCOIN_DECODE_BASE_GAS: u64 = 3000;
pub const BITCOIN_CONVERT_BASE_GAS: u64 = 21000;
pub const BITCOIN_VAULT_SPEND_BASE_GAS: u64 = 50000;
