use alloc::vec::Vec;
use alloy_consensus::{
    Eip2718EncodableReceipt, Eip658Value, Receipt, ReceiptWithBloom, RlpDecodableReceipt,
    RlpEncodableReceipt, TxReceipt, Typed2718,
};
use alloy_primitives::{Bloom, Log};
use alloy_rlp::{BufMut, Decodable, Header};
use op_alloy_consensus::OpDepositReceipt;
use reth_primitives_traits::InMemorySize;
use crate::tx_type::SovaTxType;

/// Typed Sova transaction receipt.
/// Receipt containing result of transaction execution.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SovaReceipt {
    /// Legacy receipt
    Legacy(Receipt),
    /// EIP-2930 receipt
    Eip2930(Receipt),
    /// EIP-1559 receipt
    Eip1559(Receipt),
    /// EIP-4844 receipt
    Eip4844(Receipt),
    /// EIP-7702 receipt
    Eip7702(Receipt),
    /// Deposit receipt
    Deposit(OpDepositReceipt),
}

impl SovaReceipt {
    /// Returns [`SovaTxType`] of the receipt.
    pub const fn tx_type(&self) -> SovaTxType {
        match self {
            Self::Legacy(_) => SovaTxType::Legacy,
            Self::Eip2930(_) => SovaTxType::Eip2930,
            Self::Eip1559(_) => SovaTxType::Eip1559,
            Self::Eip4844(_) => SovaTxType::Eip4844,
            Self::Eip7702(_) => SovaTxType::Eip7702,
            Self::Deposit(_) => SovaTxType::Deposit,
        }
    }

    /// Returns inner [`Receipt`],
    pub const fn as_receipt(&self) -> &Receipt {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip4844(receipt) |
            Self::Eip7702(receipt) => receipt,
            Self::Deposit(receipt) => &receipt.inner,
        }
    }

    /// Returns a mutable reference to the inner [`Receipt`],
    pub const fn as_receipt_mut(&mut self) -> &mut Receipt {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip4844(receipt) |
            Self::Eip7702(receipt) => receipt,
            Self::Deposit(receipt) => &mut receipt.inner,
        }
    }

    /// Returns length of RLP-encoded receipt fields with the given [`Bloom`] without an RLP header.
    pub fn rlp_encoded_fields_length(&self, bloom: &Bloom) -> usize {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip4844(receipt) |
            Self::Eip7702(receipt) => receipt.rlp_encoded_fields_length_with_bloom(bloom),
            Self::Deposit(receipt) => receipt.rlp_encoded_fields_length_with_bloom(bloom),
        }
    }

    /// RLP-encodes receipt fields with the given [`Bloom`] without an RLP header.
    pub fn rlp_encode_fields(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip4844(receipt) |
            Self::Eip7702(receipt) => receipt.rlp_encode_fields_with_bloom(bloom, out),
            Self::Deposit(receipt) => receipt.rlp_encode_fields_with_bloom(bloom, out),
        }
    }

    /// Returns RLP header for inner encoding.
    pub fn rlp_header_inner(&self, bloom: &Bloom) -> Header {
        Header { list: true, payload_length: self.rlp_encoded_fields_length(bloom) }
    }

    /// RLP-decodes the receipt from the provided buffer. This does not expect a type byte or
    /// network header.
    pub fn rlp_decode_inner(
        buf: &mut &[u8],
        tx_type: SovaTxType,
    ) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        match tx_type {
            SovaTxType::Legacy => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Legacy(receipt), logs_bloom })
            }
            SovaTxType::Eip2930 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip2930(receipt), logs_bloom })
            }
            SovaTxType::Eip1559 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip1559(receipt), logs_bloom })
            }
            SovaTxType::Eip4844 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip4844(receipt), logs_bloom })
            }
            SovaTxType::Eip7702 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip7702(receipt), logs_bloom })
            }
            SovaTxType::Deposit => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Deposit(receipt), logs_bloom })
            }
        }
    }
}

impl Eip2718EncodableReceipt for SovaReceipt {
    fn eip2718_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        !self.tx_type().is_legacy() as usize + self.rlp_header_inner(bloom).length_with_payload()
    }

    fn eip2718_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        if !self.tx_type().is_legacy() {
            out.put_u8(self.tx_type() as u8);
        }
        self.rlp_header_inner(bloom).encode(out);
        self.rlp_encode_fields(bloom, out);
    }
}

impl RlpEncodableReceipt for SovaReceipt {
    fn rlp_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        let mut len = self.eip2718_encoded_length_with_bloom(bloom);
        if !self.tx_type().is_legacy() {
            len += Header {
                list: false,
                payload_length: self.eip2718_encoded_length_with_bloom(bloom),
            }
            .length();
        }

        len
    }

    fn rlp_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        if !self.tx_type().is_legacy() {
            Header { list: false, payload_length: self.eip2718_encoded_length_with_bloom(bloom) }
                .encode(out);
        }
        self.eip2718_encode_with_bloom(bloom, out);
    }
}

impl RlpDecodableReceipt for SovaReceipt {
    fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let header_buf = &mut &**buf;
        let header = Header::decode(header_buf)?;

        // Legacy receipt, reuse initial buffer without advancing
        if header.list {
            return Self::rlp_decode_inner(buf, SovaTxType::Legacy)
        }

        // Otherwise, advance the buffer and try decoding type flag followed by receipt
        *buf = *header_buf;

        let remaining = buf.len();
        let tx_type = SovaTxType::decode(buf)?;
        let this = Self::rlp_decode_inner(buf, tx_type)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }
}

impl TxReceipt for SovaReceipt {
    type Log = Log;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().status_or_post_state()
    }

    fn status(&self) -> bool {
        self.as_receipt().status()
    }

    fn bloom(&self) -> Bloom {
        self.as_receipt().bloom()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used()
    }

    fn logs(&self) -> &[Log] {
        self.as_receipt().logs()
    }
}

impl Typed2718 for SovaReceipt {
    fn ty(&self) -> u8 {
        self.tx_type().into()
    }
}

impl InMemorySize for SovaReceipt {
    fn size(&self) -> usize {
        self.as_receipt().size()
    }
}

impl reth_primitives_traits::Receipt for SovaReceipt {}

/// Trait for deposit receipt.
pub trait DepositReceipt: reth_primitives_traits::Receipt {
    /// Returns deposit receipt if it is a deposit transaction.
    ///
    /// # Returns
    /// An `Option<&mut OpDepositReceipt>` for accessing deposit-specific fields.
    fn as_deposit_receipt_mut(&mut self) -> Option<&mut OpDepositReceipt>;
}

impl DepositReceipt for SovaReceipt {
    fn as_deposit_receipt_mut(&mut self) -> Option<&mut OpDepositReceipt> {
        match self {
            Self::Deposit(receipt) => Some(receipt),
            _ => None,
        }
    }
}

#[cfg(feature = "reth-codec")]
mod compact {
    use super::*;
    use alloc::borrow::Cow;
    use reth_codecs::Compact;

    #[derive(reth_codecs::CompactZstd)]
    #[reth_zstd(
        compressor = reth_zstd_compressors::RECEIPT_COMPRESSOR,
        decompressor = reth_zstd_compressors::RECEIPT_DECOMPRESSOR
    )]
    struct CompactSovaReceipt<'a> {
        tx_type: SovaTxType,
        success: bool,
        cumulative_gas_used: u64,
        #[expect(clippy::owned_cow)]
        logs: Cow<'a, Vec<Log>>,
        deposit_nonce: Option<u64>,
        deposit_receipt_version: Option<u64>,
    }

    impl<'a> From<&'a SovaReceipt> for CompactSovaReceipt<'a> {
        fn from(receipt: &'a SovaReceipt) -> Self {
            Self {
                tx_type: receipt.tx_type(),
                success: receipt.status(),
                cumulative_gas_used: receipt.cumulative_gas_used(),
                logs: Cow::Borrowed(&receipt.as_receipt().logs),
                deposit_nonce: if let SovaReceipt::Deposit(receipt) = receipt {
                    receipt.deposit_nonce
                } else {
                    None
                },
                deposit_receipt_version: if let SovaReceipt::Deposit(receipt) = receipt {
                    receipt.deposit_receipt_version
                } else {
                    None
                },
            }
        }
    }

    impl From<CompactSovaReceipt<'_>> for SovaReceipt {
        fn from(receipt: CompactSovaReceipt<'_>) -> Self {
            let CompactSovaReceipt {
                tx_type,
                success,
                cumulative_gas_used,
                logs,
                deposit_nonce,
                deposit_receipt_version,
            } = receipt;

            let inner = Receipt { 
                status: success.into(), 
                cumulative_gas_used, 
                logs: logs.into_owned() 
            };

            match tx_type {
                SovaTxType::Legacy => Self::Legacy(inner),
                SovaTxType::Eip2930 => Self::Eip2930(inner),
                SovaTxType::Eip1559 => Self::Eip1559(inner),
                SovaTxType::Eip4844 => Self::Eip4844(inner),
                SovaTxType::Eip7702 => Self::Eip7702(inner),
                SovaTxType::Deposit => Self::Deposit(OpDepositReceipt {
                    inner,
                    deposit_nonce,
                    deposit_receipt_version,
                }),
            }
        }
    }

    impl Compact for SovaReceipt {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: bytes::BufMut + AsMut<[u8]>,
        {
            CompactSovaReceipt::from(self).to_compact(buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            let (receipt, buf) = CompactSovaReceipt::from_compact(buf, len);
            (receipt.into(), buf)
        }
    }
}