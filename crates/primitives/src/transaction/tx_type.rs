use alloy_consensus::Typed2718;
use alloy_eips::eip2718::Eip2718Error;
use alloy_primitives::{U64, U8};
use alloy_rlp::{BufMut, Decodable, Encodable};
use derive_more::Display;

/// Identifier for a Sova deposit transaction (same as Optimism's deposit type)
pub const DEPOSIT_TX_TYPE_ID: u8 = 126; // 0x7E (same as Optimism's DEPOSIT_TX_TYPE_ID)

/// Sova `TransactionType` flags
#[repr(u8)]
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    Default,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    serde::Serialize,
    serde::Deserialize,
)]
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
    /// Deposit transaction type.
    #[display("deposit")]
    Deposit = 126, // Using the same type ID as Optimism's deposit
}

impl SovaTxType {
    /// List of all variants.
    pub const ALL: [Self; 6] = [
        Self::Legacy,
        Self::Eip2930,
        Self::Eip1559,
        Self::Eip4844,
        Self::Eip7702,
        Self::Deposit,
    ];

    /// Returns whether this transaction type is legacy.
    #[inline]
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// Returns whether this transaction type is EIP-2930.
    #[inline]
    pub const fn is_eip2930(&self) -> bool {
        matches!(self, Self::Eip2930)
    }

    /// Returns whether this transaction type is EIP-1559.
    #[inline]
    pub const fn is_eip1559(&self) -> bool {
        matches!(self, Self::Eip1559)
    }

    /// Returns whether this transaction type is EIP-4844.
    #[inline]
    pub const fn is_eip4844(&self) -> bool {
        matches!(self, Self::Eip4844)
    }

    /// Returns whether this transaction type is EIP-7702.
    #[inline]
    pub const fn is_eip7702(&self) -> bool {
        matches!(self, Self::Eip7702)
    }

    /// Returns whether this transaction type is a deposit.
    #[inline]
    pub const fn is_deposit(&self) -> bool {
        matches!(self, Self::Deposit)
    }
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
            126 => Self::Deposit,
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
