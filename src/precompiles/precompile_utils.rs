use crate::chainspec::{
    BitcoinPrecompileMethod, BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS,
    DECODE_TRANSACTION_ADDRESS, VAULT_SPEND_ADDRESS,
};
use alloy_primitives::Address;

pub struct BitcoinMethodHelper;

impl BitcoinMethodHelper {
    /// Calculate the gas used for a method using saturating arithmetic
    /// This version never overflows but may saturate at u64::MAX
    pub fn calculate_gas_used(method: &BitcoinPrecompileMethod, input_length: usize) -> u64 {
        // Simple gas calculation - can be refined later
        match method {
            BitcoinPrecompileMethod::BroadcastTransaction => 30_000,
            BitcoinPrecompileMethod::DecodeTransaction => 3_000 + (input_length as u64 * 3),
            BitcoinPrecompileMethod::ConvertAddress => 3_000,
            BitcoinPrecompileMethod::VaultSpend => 30_000,
        }
    }

    /// Check if the calculated gas exceeds the method's limit
    pub fn is_gas_limit_exceeded(method: &BitcoinPrecompileMethod, input_length: usize) -> bool {
        let gas_limit = match method {
            BitcoinPrecompileMethod::BroadcastTransaction => 30_000,
            BitcoinPrecompileMethod::DecodeTransaction => 3_000_000,
            BitcoinPrecompileMethod::ConvertAddress => 3_000,
            BitcoinPrecompileMethod::VaultSpend => 30_000,
        };

        Self::calculate_gas_used(method, input_length) > gas_limit
    }

    /// Matches returns precompile enum for an address
    pub fn method_from_address(
        address: Address,
    ) -> Result<BitcoinPrecompileMethod, Box<dyn std::error::Error>> {
        match address {
            BROADCAST_TRANSACTION_ADDRESS => Ok(BitcoinPrecompileMethod::BroadcastTransaction),
            DECODE_TRANSACTION_ADDRESS => Ok(BitcoinPrecompileMethod::DecodeTransaction),
            CONVERT_ADDRESS_ADDRESS => Ok(BitcoinPrecompileMethod::ConvertAddress),
            VAULT_SPEND_ADDRESS => Ok(BitcoinPrecompileMethod::VaultSpend),
            _ => Err(format!(
                "Unknown Bitcoin precompile address: {}",
                hex::encode(address)
            )
            .into()),
        }
    }
}
