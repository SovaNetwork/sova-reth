use alloy_primitives::Address;
use sova_chainspec::{
    BitcoinPrecompileMethod, BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS,
    DECODE_TRANSACTION_ADDRESS, VAULT_SPEND_ADDRESS,
};

/// Gas configuration for each Bitcoin method
#[derive(Debug, Clone, Copy)]
struct GasConfig {
    /// Maximum gas allowed for this method
    limit: u64,
    /// Base gas cost (without input considerations)
    base_cost: u64,
    /// Additional gas cost per input byte (0 if not dependent on input size)
    cost_per_byte: u64,
}

pub struct BitcoinMethodHelper;

impl BitcoinMethodHelper {
    /// Get the gas configuration for this method
    fn gas_config(method: &BitcoinPrecompileMethod) -> GasConfig {
        match method {
            BitcoinPrecompileMethod::BroadcastTransaction => GasConfig {
                limit: 30_000,
                base_cost: 30_000,
                cost_per_byte: 0,
            },
            BitcoinPrecompileMethod::DecodeTransaction => GasConfig {
                limit: 3_000_000,
                base_cost: 3_000,
                cost_per_byte: 3,
            },
            BitcoinPrecompileMethod::ConvertAddress => GasConfig {
                limit: 3_000,
                base_cost: 3_000,
                cost_per_byte: 0,
            },
            BitcoinPrecompileMethod::VaultSpend => GasConfig {
                limit: 30_000,
                base_cost: 30_000,
                cost_per_byte: 0,
            },
        }
    }

    /// Gets the gas limit for the method
    pub fn gas_limit(method: &BitcoinPrecompileMethod) -> u64 {
        Self::gas_config(method).limit
    }

    /// Calculate the gas used for a method, accounting for input size where relevant
    pub fn calculate_gas_used(method: &BitcoinPrecompileMethod, input_length: usize) -> u64 {
        let config = Self::gas_config(method);
        config.base_cost + (input_length as u64 * config.cost_per_byte)
    }

    /// Check if the calculated gas exceeds the method's limit
    pub fn is_gas_limit_exceeded(method: &BitcoinPrecompileMethod, input_length: usize) -> bool {
        Self::calculate_gas_used(method, input_length) > Self::gas_limit(method)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_calculation() {
        // Test BroadcastTransaction (fixed gas)
        let method = BitcoinPrecompileMethod::BroadcastTransaction;
        assert_eq!(BitcoinMethodHelper::calculate_gas_used(&method, 0), 30_000);
        assert_eq!(
            BitcoinMethodHelper::calculate_gas_used(&method, 1000),
            30_000
        );

        // Test DecodeTransaction (variable gas)
        let method = BitcoinPrecompileMethod::DecodeTransaction;
        assert_eq!(BitcoinMethodHelper::calculate_gas_used(&method, 0), 3_000);
        assert_eq!(
            BitcoinMethodHelper::calculate_gas_used(&method, 1000),
            3_000 + 3_000
        );

        // Test gas limit check
        let method = BitcoinPrecompileMethod::DecodeTransaction;
        assert!(!BitcoinMethodHelper::is_gas_limit_exceeded(&method, 1000)); // 3_000 + 3_000 < 150_000
        assert!(BitcoinMethodHelper::is_gas_limit_exceeded(
            &method, 1_000_000
        )); // 3_000 + 3_000_000 > 3_000_000
    }
}
