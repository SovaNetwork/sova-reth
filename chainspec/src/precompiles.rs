//! Bitcoin precompile constants for Sova network
//!
//! This module defines the constants used for Bitcoin-specific precompiles
//! in the Sova network, including addresses, gas costs, and other configuration.

use crate::{
    BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS, DECODE_TRANSACTION_ADDRESS,
    VAULT_SPEND_ADDRESS,
};
use alloy_primitives::Address;

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
pub const BITCOIN_CONVERT_BASE_GAS: u64 = 2100;
pub const BITCOIN_VAULT_SPEND_BASE_GAS: u64 = 50000;

/// Utility function to convert Address to u64 for precompile addressing
pub fn address_to_u64(addr: Address) -> u64 {
    // Extract the last 8 bytes of the address as u64
    let bytes = addr.0;
    u64::from_be_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ])
}
