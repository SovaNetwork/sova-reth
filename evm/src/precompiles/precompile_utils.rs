use sova_chainspec::{BitcoinPrecompileMethod};

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
}
