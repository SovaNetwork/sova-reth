//! Contains the transaction type identifier for Sova.

extern crate alloc;

use alloy_consensus::Typed2718;
use alloy_eips::eip2718::Eip2718Error;
use alloy_primitives::{U8, U64};
use alloy_rlp::{BufMut, Decodable, Encodable};
use derive_more::Display;

/// Identifier for an Sova L1Block transaction
pub const L1_BLOCK_TX_TYPE_ID: u8 = 126; // 0x7E

/// Sova `TransactionType` flags as specified in EIPs [2718], [1559],
/// [2930], [4844], as well as the [bitcoin context (L1Block) transaction spec]
///
/// [2718]: https://eips.ethereum.org/EIPS/eip-2718
/// [1559]: https://eips.ethereum.org/EIPS/eip-1559
/// [2930]: https://eips.ethereum.org/EIPS/eip-2930
/// [4844]: https://eips.ethereum.org/EIPS/eip-4844
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, Default, PartialEq, PartialOrd, Ord, Hash, Display)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(into = "U8", try_from = "U64")]
pub enum SovaTxType {
    /// Legacy transaction type.
    #[default]
    #[display("legacy")]
    Legacy = 0,
    /// EIP-2930 transaction type.
    #[display("eip2930")]
    Eip2930 = 1,
    /// EIP-1559 transaction type.
    #[display("eip1559")]
    Eip1559 = 2,
    /// EIP-4844 transaction type.
    #[display("eip4844")]
    Eip4844 = 3,
    /// EIP-7702 transaction type.
    #[display("eip7702")]
    Eip7702 = 4,
    /// Sova Bitcoin context transaction type.
    #[display("l1block")]
    L1Block = 126,
}

impl SovaTxType {
    /// List of all variants.
    pub const ALL: [Self; 6] =
        [Self::Legacy, Self::Eip2930, Self::Eip1559, Self::Eip4844, Self::Eip7702, Self::L1Block];
}

impl From<SovaTxType> for U8 {
    fn from(tx_type: SovaTxType) -> Self {
        Self::from(u8::from(tx_type))
    }
}

impl From<SovaTxType> for u8 {
    fn from(v: SovaTxType) -> Self {
        v as Self
    }
}

impl TryFrom<u8> for SovaTxType {
    type Error = Eip2718Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Legacy,
            1 => Self::Eip2930,
            2 => Self::Eip1559,
            3 => Self::Eip4844,
            4 => Self::Eip7702,
            126 => Self::L1Block,
            _ => return Err(Eip2718Error::UnexpectedType(value)),
        })
    }
}

impl TryFrom<u64> for SovaTxType {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let err = || "invalid tx type";
        let value: u8 = value.try_into().map_err(|_| err())?;
        Self::try_from(value).map_err(|_| err())
    }
}

impl TryFrom<U64> for SovaTxType {
    type Error = &'static str;

    fn try_from(value: U64) -> Result<Self, Self::Error> {
        value.to::<u64>().try_into()
    }
}

impl TryFrom<usize> for SovaTxType {
    type Error = String;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::Eip2930),
            2 => Ok(Self::Eip1559),
            3 => Ok(Self::Eip4844),
            4 => Ok(Self::Eip7702),
            126 => Ok(Self::L1Block),
            _ => Err(format!("Unknown transaction type: {}", value)),
        }
    }
}

impl PartialEq<u8> for SovaTxType {
    fn eq(&self, other: &u8) -> bool {
        (*self as u8) == *other
    }
}

impl PartialEq<SovaTxType> for u8 {
    fn eq(&self, other: &SovaTxType) -> bool {
        *self == *other as Self
    }
}

impl Encodable for SovaTxType {
    fn encode(&self, out: &mut dyn BufMut) {
        (*self as u8).encode(out);
    }

    fn length(&self) -> usize {
        1
    }
}

impl Decodable for SovaTxType {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let ty = u8::decode(buf)?;

        Self::try_from(ty).map_err(|_| alloy_rlp::Error::Custom("invalid transaction type"))
    }
}

impl Typed2718 for SovaTxType {
    fn ty(&self) -> u8 {
        (*self).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn test_all_tx_types() {
        assert_eq!(SovaTxType::ALL.len(), 5);
        let all = vec![
            SovaTxType::Legacy,
            SovaTxType::Eip2930,
            SovaTxType::Eip1559,
            SovaTxType::Eip4844,
            SovaTxType::Eip7702,
            SovaTxType::L1Block,
        ];
        assert_eq!(SovaTxType::ALL.to_vec(), all);
    }

    #[test]
    fn tx_type_roundtrip() {
        for &tx_type in &SovaTxType::ALL {
            let mut buf = Vec::new();
            tx_type.encode(&mut buf);
            let decoded = SovaTxType::decode(&mut &buf[..]).unwrap();
            assert_eq!(tx_type, decoded);
        }
    }
}
