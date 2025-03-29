use std::fmt;

use alloy_primitives::Bytes;

/// Represents all available Bitcoin precompile methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BitcoinMethod {
    /// Broadcasts a Bitcoin transaction
    BroadcastTransaction,
    /// Decodes a raw Bitcoin transaction
    DecodeTransaction,
    /// Checks Bitcoin transaction signature
    CheckSignature,
    /// Converts Ethereum address to Bitcoin address
    ConvertAddress,
    /// Creates and signs a Bitcoin transaction
    CreateAndSignTransaction,
}

impl BitcoinMethod {
    /// Gets the gas limit for the method
    pub fn gas_limit(&self) -> u64 {
        match self {
            BitcoinMethod::BroadcastTransaction => 100_000,
            BitcoinMethod::DecodeTransaction => 150_000,
            BitcoinMethod::CheckSignature => 100_000,
            BitcoinMethod::ConvertAddress => 3_000,
            BitcoinMethod::CreateAndSignTransaction => 25_000,
        }
    }
}

/// Error type for method parsing failures
#[derive(Clone, PartialEq)]
pub enum MethodError {
    /// Input was too short to contain a method selector
    InputTooShort,
    /// Method selector was not recognized
    UnknownSelector,
}

impl fmt::Display for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MethodError::InputTooShort => write!(f, "Input too short for method selector"),
            MethodError::UnknownSelector => write!(f, "Unknown method selector"),
        }
    }
}

impl fmt::Debug for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for MethodError {}

impl TryFrom<&Bytes> for BitcoinMethod {
    type Error = MethodError;

    fn try_from(input: &Bytes) -> Result<Self, Self::Error> {
        if input.len() < 4 {
            return Err(MethodError::InputTooShort);
        }

        let selector = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        match selector {
            0x00000001 => Ok(BitcoinMethod::BroadcastTransaction),
            0x00000002 => Ok(BitcoinMethod::DecodeTransaction),
            0x00000003 => Ok(BitcoinMethod::CheckSignature),
            0x00000004 => Ok(BitcoinMethod::ConvertAddress),
            0x00000005 => Ok(BitcoinMethod::CreateAndSignTransaction),
            _ => Err(MethodError::UnknownSelector),
        }
    }
}

impl TryFrom<&[u8]> for BitcoinMethod {
    type Error = MethodError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() < 4 {
            return Err(MethodError::InputTooShort);
        }

        let selector = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        match selector {
            0x00000001 => Ok(BitcoinMethod::BroadcastTransaction),
            0x00000002 => Ok(BitcoinMethod::DecodeTransaction),
            0x00000003 => Ok(BitcoinMethod::CheckSignature),
            0x00000004 => Ok(BitcoinMethod::ConvertAddress),
            0x00000005 => Ok(BitcoinMethod::CreateAndSignTransaction),
            _ => Err(MethodError::UnknownSelector),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_method() {
        let input = [0x00, 0x00, 0x00, 0x01, 0xff]; // BroadcastTransaction
        assert_eq!(
            BitcoinMethod::try_from(&input[..]).unwrap(),
            BitcoinMethod::BroadcastTransaction
        );
    }

    #[test]
    fn test_invalid_input() {
        let input = [0x00, 0x00, 0x00]; // Too short
        assert!(matches!(
            BitcoinMethod::try_from(&input[..]),
            Err(MethodError::InputTooShort)
        ));

        let input = [0xff, 0xff, 0xff, 0xff]; // Unknown selector
        assert!(matches!(
            BitcoinMethod::try_from(&input[..]),
            Err(MethodError::UnknownSelector)
        ));
    }
}
