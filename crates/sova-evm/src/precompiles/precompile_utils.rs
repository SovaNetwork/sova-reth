use alloy_primitives::Bytes;
use std::fmt;

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

/// Represents all available Bitcoin precompile methods with their associated selectors and gas parameters
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BitcoinMethod {
    /// Broadcasts a Bitcoin transaction
    /// Selector: 0x00000001
    BroadcastTransactionAndLock,

    /// Decodes a raw Bitcoin transaction
    /// Selector: 0x00000002
    DecodeTransaction,

    /// Converts Ethereum address to Bitcoin address
    /// Selector: 0x00000003
    ConvertAddress,

    /// Creates, signs, and broadcasts a Bitcoin transaction from a specified signer
    /// Selector: 0x00000004
    VaultSpend,

    /// Performs all lock-checks for touched slots BEFORE the CheckLocks method is called
    /// Selector: 0x00000005
    CheckLocks,
}

impl BitcoinMethod {
    /// Minimum input length required for method selection (selector size)
    pub const SELECTOR_SIZE: usize = 4;

    /// Get the gas configuration for this method
    fn gas_config(&self) -> GasConfig {
        match self {
            Self::BroadcastTransactionAndLock => GasConfig {
                limit: 30_000,
                base_cost: 30_000,
                cost_per_byte: 0,
            },
            Self::DecodeTransaction => GasConfig {
                limit: 3_000_000,
                base_cost: 3_000,
                cost_per_byte: 3,
            },
            Self::ConvertAddress => GasConfig {
                limit: 3_000,
                base_cost: 3_000,
                cost_per_byte: 0,
            },
            Self::VaultSpend => GasConfig {
                limit: 30_000,
                base_cost: 30_000,
                cost_per_byte: 0,
            },
            Self::CheckLocks => GasConfig {
                limit: 10_000,
                base_cost: 10_000,
                cost_per_byte: 0,
            },
        }
    }

    /// Gets the gas limit for the method
    pub fn gas_limit(&self) -> u64 {
        self.gas_config().limit
    }

    /// Calculate the gas used for a method, accounting for input size where relevant
    pub fn calculate_gas_used(&self, input_length: usize) -> u64 {
        let config = self.gas_config();
        config.base_cost + (input_length as u64 * config.cost_per_byte)
    }

    /// Check if the calculated gas exceeds the method's limit
    pub fn is_gas_limit_exceeded(&self, input_length: usize) -> bool {
        self.calculate_gas_used(input_length) > self.gas_limit()
    }

    /// Try to parse a method from a selector byte array
    pub fn from_selector(selector: [u8; 4]) -> Result<Self, MethodError> {
        let selector_value = u32::from_be_bytes(selector);
        match selector_value {
            0x00000001 => Ok(Self::BroadcastTransactionAndLock),
            0x00000002 => Ok(Self::DecodeTransaction),
            0x00000003 => Ok(Self::ConvertAddress),
            0x00000004 => Ok(Self::VaultSpend),
            0x00000005 => Ok(Self::CheckLocks),
            _ => Err(MethodError::UnknownSelector(selector_value)),
        }
    }
}

/// Error type for method parsing failures
#[derive(Clone, PartialEq)]
pub enum MethodError {
    /// Input was too short to contain a method selector
    InputTooShort,
    /// Method selector was not recognized (includes the unrecognized selector)
    UnknownSelector(u32),
}

impl fmt::Display for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooShort => write!(f, "Input too short for method selector"),
            Self::UnknownSelector(selector) => {
                write!(f, "Unknown method selector: 0x{:08x}", selector)
            }
        }
    }
}

impl fmt::Debug for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for MethodError {}

impl TryFrom<&[u8]> for BitcoinMethod {
    type Error = MethodError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() < Self::SELECTOR_SIZE {
            return Err(MethodError::InputTooShort);
        }

        let mut selector = [0u8; 4];
        selector.copy_from_slice(&input[0..4]);
        Self::from_selector(selector)
    }
}

impl TryFrom<&Bytes> for BitcoinMethod {
    type Error = MethodError;

    fn try_from(input: &Bytes) -> Result<Self, Self::Error> {
        Self::try_from(&input[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_method() {
        // Test all valid method selectors - map raw bytes to expected enum variants
        let test_cases = [
            (
                [0x00, 0x00, 0x00, 0x01],
                BitcoinMethod::BroadcastTransactionAndLock,
            ),
            ([0x00, 0x00, 0x00, 0x02], BitcoinMethod::DecodeTransaction),
            ([0x00, 0x00, 0x00, 0x03], BitcoinMethod::ConvertAddress),
            ([0x00, 0x00, 0x00, 0x04], BitcoinMethod::VaultSpend),
            ([0x00, 0x00, 0x00, 0x05], BitcoinMethod::CheckLocks),
        ];

        // Test parsing from byte arrays to method variants
        for (selector, expected_method) in test_cases {
            // Create input with extra byte to ensure it handles additional data correctly
            let mut input = Vec::from(selector);
            input.push(0xff);

            // Parse using the TryFrom implementation
            let method = BitcoinMethod::try_from(&input[..]).unwrap();
            assert_eq!(method, expected_method);
        }

        // Test parsing using from_selector directly
        for (selector, expected_method) in test_cases {
            let method = BitcoinMethod::from_selector(selector).unwrap();
            assert_eq!(method, expected_method);
        }

        // Additional tests to verify the round-trip works as expected
        for (selector_bytes, _) in test_cases {
            // Test that we get the right method
            let method = BitcoinMethod::from_selector(selector_bytes).unwrap();

            // Check method variant directly
            match method {
                BitcoinMethod::BroadcastTransactionAndLock
                    if selector_bytes == [0x00, 0x00, 0x00, 0x01] => {}
                BitcoinMethod::DecodeTransaction if selector_bytes == [0x00, 0x00, 0x00, 0x02] => {}
                BitcoinMethod::ConvertAddress if selector_bytes == [0x00, 0x00, 0x00, 0x03] => {}
                BitcoinMethod::VaultSpend if selector_bytes == [0x00, 0x00, 0x00, 0x04] => {}
                BitcoinMethod::CheckLocks if selector_bytes == [0x00, 0x00, 0x00, 0x05] => {}
                _ => panic!(
                    "Unexpected method variant for selector {:?}",
                    selector_bytes
                ),
            }
        }
    }

    #[test]
    fn test_gas_calculation() {
        // Test BroadcastTransactionAndLock (fixed gas)
        let method = BitcoinMethod::BroadcastTransactionAndLock;
        assert_eq!(method.calculate_gas_used(0), 30_000);
        assert_eq!(method.calculate_gas_used(1000), 30_000);

        // Test DecodeTransaction (variable gas)
        let method = BitcoinMethod::DecodeTransaction;
        assert_eq!(method.calculate_gas_used(0), 3_000);
        assert_eq!(method.calculate_gas_used(1000), 3_000 + 3_000);

        // Test gas limit check
        let method = BitcoinMethod::DecodeTransaction;
        assert!(!method.is_gas_limit_exceeded(1000)); // 3_000 + 3_000 < 150_000
        assert!(method.is_gas_limit_exceeded(1_000_000)); // 3_000 + 3_000_000 > 3_000_000
    }

    #[test]
    fn test_invalid_input() {
        // Test input too short
        let input = [0x00, 0x00, 0x00];
        let result = BitcoinMethod::try_from(&input[..]);
        assert!(matches!(result, Err(MethodError::InputTooShort)));

        // Test unknown selector
        let input = [0xff, 0xff, 0xff, 0xff];
        let result = BitcoinMethod::try_from(&input[..]);
        match result {
            Err(MethodError::UnknownSelector(selector)) => assert_eq!(selector, 0xffffffff),
            _ => panic!("Expected UnknownSelector error"),
        }
    }
}
