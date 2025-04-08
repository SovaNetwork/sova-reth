//! L1Block Transaction type.

extern crate alloc;

use alloc::vec::Vec;
use alloy_consensus::{Sealable, Transaction, Typed2718};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
};
use alloy_primitives::{
    keccak256, Address, Bytes, ChainId, PrimitiveSignature as Signature, TxHash, TxKind, B256, U256,
};
use alloy_rlp::{
    Buf, BufMut, Decodable, Encodable, Error as DecodeError, Header, EMPTY_STRING_CODE,
};
use core::mem;

use crate::SovaTxType;

/// L1Block transactions, also known as bitcoin context transactions are initiated by block builder,
/// and added as the first transaction in a Sova block.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct TxL1Block {
    /// Hash that uniquely identifies the source of the deposit.
    pub source_hash: B256,
    /// The address of the sender account.
    pub from: Address,
    /// The address of the recipient account, or the null (zero-length) address if the deposited
    /// transaction is a contract creation.
    pub to: TxKind,
    /// The ETH value to mint on L2.
    pub mint: Option<u128>,
    ///  The ETH value to send to the recipient account.
    pub value: U256,
    /// The gas limit for the L2 transaction.
    pub gas_limit: u64,
    /// Field indicating if this transaction is exempt from the L2 gas limit.
    pub is_system_transaction: bool,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some).
    pub input: Bytes,
}

impl TxL1Block {
    /// Decodes the inner [TxL1Block] fields from RLP bytes.
    ///
    /// NOTE: This assumes a RLP header has already been decoded, and _just_ decodes the following
    /// RLP fields in the following order:
    ///
    /// - `source_hash`
    /// - `from`
    /// - `to`
    /// - `mint`
    /// - `value`
    /// - `gas_limit`
    /// - `is_system_transaction`
    /// - `input`
    pub fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            source_hash: Decodable::decode(buf)?,
            from: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            mint: if *buf.first().ok_or(DecodeError::InputTooShort)? == EMPTY_STRING_CODE {
                buf.advance(1);
                None
            } else {
                Some(Decodable::decode(buf)?)
            },
            value: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            is_system_transaction: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
        })
    }

    /// Decodes the transaction from RLP bytes.
    pub fn rlp_decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let this = Self::rlp_decode_fields(buf)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }

    /// Outputs the length of the transaction's fields, without a RLP header or length of the
    /// eip155 fields.
    pub(crate) fn rlp_encoded_fields_length(&self) -> usize {
        self.source_hash.length()
            + self.from.length()
            + self.to.length()
            + self.mint.map_or(1, |mint| mint.length())
            + self.value.length()
            + self.gas_limit.length()
            + self.is_system_transaction.length()
            + self.input.0.length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header.
    /// <https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/deposits.md#the-deposited-transaction-type>
    pub(crate) fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.source_hash.encode(out);
        self.from.encode(out);
        self.to.encode(out);
        if let Some(mint) = self.mint {
            mint.encode(out);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
        self.value.encode(out);
        self.gas_limit.encode(out);
        self.is_system_transaction.encode(out);
        self.input.encode(out);
    }

    /// Calculates a heuristic for the in-memory size of the [TxL1Block] transaction.
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<B256>() + // source_hash
        mem::size_of::<Address>() + // from
        self.to.size() + // to
        mem::size_of::<Option<u128>>() + // mint
        mem::size_of::<U256>() + // value
        mem::size_of::<u128>() + // gas_limit
        mem::size_of::<bool>() + // is_system_transaction
        self.input.len() // input
    }

    /// Get the transaction type
    pub(crate) const fn tx_type(&self) -> SovaTxType {
        SovaTxType::L1Block
    }

    /// Create an rlp header for the transaction.
    fn rlp_header(&self) -> Header {
        Header {
            list: true,
            payload_length: self.rlp_encoded_fields_length(),
        }
    }

    /// RLP encodes the transaction.
    pub fn rlp_encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        self.rlp_encode_fields(out);
    }

    /// Get the length of the transaction when RLP encoded.
    pub fn rlp_encoded_length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }

    /// Get the length of the transaction when EIP-2718 encoded. This is the
    /// 1 byte type flag + the length of the RLP encoded transaction.
    pub fn eip2718_encoded_length(&self) -> usize {
        self.rlp_encoded_length() + 1
    }

    fn network_header(&self) -> Header {
        Header {
            list: false,
            payload_length: self.eip2718_encoded_length(),
        }
    }

    /// Get the length of the transaction when network encoded. This is the
    /// EIP-2718 encoded length with an outer RLP header.
    pub fn network_encoded_length(&self) -> usize {
        self.network_header().length_with_payload()
    }

    /// Network encode the transaction with the given signature.
    pub fn network_encode(&self, out: &mut dyn BufMut) {
        self.network_header().encode(out);
        self.encode_2718(out);
    }

    /// Calculate the transaction hash.
    pub fn tx_hash(&self) -> TxHash {
        let mut buf = Vec::with_capacity(self.eip2718_encoded_length());
        self.encode_2718(&mut buf);
        keccak256(&buf)
    }

    /// Returns the signature for the optimism deposit transactions, which don't include a
    /// signature.
    pub const fn signature() -> Signature {
        Signature::new(U256::ZERO, U256::ZERO, false)
    }
}

impl Typed2718 for TxL1Block {
    fn ty(&self) -> u8 {
        SovaTxType::L1Block as u8
    }
}

impl Transaction for TxL1Block {
    fn chain_id(&self) -> Option<ChainId> {
        None
    }

    fn nonce(&self) -> u64 {
        0u64
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        0
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        0
    }

    fn effective_gas_price(&self, _: Option<u64>) -> u128 {
        0
    }

    fn is_dynamic_fee(&self) -> bool {
        false
    }

    fn kind(&self) -> TxKind {
        self.to
    }

    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn input(&self) -> &Bytes {
        &self.input
    }

    fn access_list(&self) -> Option<&AccessList> {
        None
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

impl Encodable2718 for TxL1Block {
    fn type_flag(&self) -> Option<u8> {
        Some(SovaTxType::L1Block as u8)
    }

    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(self.tx_type() as u8);
        self.rlp_encode(out);
    }
}

impl Decodable2718 for TxL1Block {
    fn typed_decode(ty: u8, data: &mut &[u8]) -> Eip2718Result<Self> {
        let ty: SovaTxType = ty
            .try_into()
            .map_err(|_| Eip2718Error::UnexpectedType(ty))?;
        if ty != SovaTxType::L1Block as u8 {
            return Err(Eip2718Error::UnexpectedType(ty as u8));
        }
        let tx = Self::decode(data)?;
        Ok(tx)
    }

    fn fallback_decode(data: &mut &[u8]) -> Eip2718Result<Self> {
        let tx = Self::decode(data)?;
        Ok(tx)
    }
}

impl Encodable for TxL1Block {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: true,
            payload_length: self.rlp_encoded_fields_length(),
        }
        .encode(out);
        self.rlp_encode_fields(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_encoded_fields_length();
        Header {
            list: true,
            payload_length,
        }
        .length()
            + payload_length
    }
}

impl Decodable for TxL1Block {
    fn decode(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(data)
    }
}

impl Sealable for TxL1Block {
    fn hash_slow(&self) -> B256 {
        self.tx_hash()
    }
}

/// A trait representing a deposit transaction with specific attributes.
pub trait BitcoinContextTransaction: Transaction {
    /// Returns the hash that uniquely identifies the source of the deposit.
    ///
    /// # Returns
    /// An `Option<B256>` containing the source hash if available.
    fn source_hash(&self) -> Option<B256>;

    /// Returns the optional mint value of the deposit transaction.
    ///
    /// # Returns
    /// An `Option<u128>` representing the ETH value to mint on L2, if any.
    fn mint(&self) -> Option<u128>;

    /// Indicates whether the transaction is exempt from the L2 gas limit.
    ///
    /// # Returns
    /// A `bool` indicating if the transaction is a system transaction.
    fn is_system_transaction(&self) -> bool;
}

impl BitcoinContextTransaction for TxL1Block {
    #[inline]
    fn source_hash(&self) -> Option<B256> {
        Some(self.source_hash)
    }

    #[inline]
    fn mint(&self) -> Option<u128> {
        self.mint
    }

    #[inline]
    fn is_system_transaction(&self) -> bool {
        self.is_system_transaction
    }
}

/// Deposit transactions don't have a signature, however, we include an empty signature in the
/// response for better compatibility.
///
/// This function can be used as `serialize_with` serde attribute for the [`TxDeposit`] and will
/// flatten [`TxDeposit::signature`] into response.
pub fn serde_deposit_tx_rpc<T: serde::Serialize, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct SerdeHelper<'a, T> {
        #[serde(flatten)]
        value: &'a T,
        #[serde(flatten)]
        signature: Signature,
    }

    SerdeHelper {
        value,
        signature: TxL1Block::signature(),
    }
    .serialize(serializer)
}

/// Bincode-compatible [`TxL1Block`] serde implementation.
pub(super) mod serde_bincode_compat {
    extern crate alloc;

    use alloc::borrow::Cow;
    use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::TxDeposit`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use op_alloy_consensus::{TxDeposit, serde_bincode_compat};
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data {
    ///     #[serde_as(as = "serde_bincode_compat::TxDeposit")]
    ///     transaction: TxDeposit,
    /// }
    /// ```
    #[derive(Debug, Serialize, Deserialize)]
    pub struct TxL1Block<'a> {
        source_hash: B256,
        from: Address,
        #[serde(default)]
        to: TxKind,
        #[serde(default)]
        mint: Option<u128>,
        value: U256,
        gas_limit: u64,
        is_system_transaction: bool,
        input: Cow<'a, Bytes>,
    }

    impl<'a> From<&'a super::TxL1Block> for TxL1Block<'a> {
        fn from(value: &'a super::TxL1Block) -> Self {
            Self {
                source_hash: value.source_hash,
                from: value.from,
                to: value.to,
                mint: value.mint,
                value: value.value,
                gas_limit: value.gas_limit,
                is_system_transaction: value.is_system_transaction,
                input: Cow::Borrowed(&value.input),
            }
        }
    }

    impl<'a> From<TxL1Block<'a>> for super::TxL1Block {
        fn from(value: TxL1Block<'a>) -> Self {
            Self {
                source_hash: value.source_hash,
                from: value.from,
                to: value.to,
                mint: value.mint,
                value: value.value,
                gas_limit: value.gas_limit,
                is_system_transaction: value.is_system_transaction,
                input: value.input.into_owned(),
            }
        }
    }

    impl SerializeAs<super::TxL1Block> for TxL1Block<'_> {
        fn serialize_as<S>(source: &super::TxL1Block, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            TxL1Block::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::TxL1Block> for TxL1Block<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::TxL1Block, D::Error>
        where
            D: Deserializer<'de>,
        {
            TxL1Block::deserialize(deserializer).map(Into::into)
        }
    }
}

impl reth_codecs::Compact for TxL1Block {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let start = buf.as_mut().len();

        // Encode each field
        self.source_hash.to_compact(buf);
        self.from.to_compact(buf);
        self.to.to_compact(buf);

        // Handle Option<u128> for mint
        if let Some(mint) = self.mint {
            // 1 bit flag indicating mint is present
            buf.put_u8(1);
            // Encode mint value
            mint.to_compact(buf);
        } else {
            // 0 bit flag indicating mint is absent
            buf.put_u8(0);
        }

        self.value.to_compact(buf);
        self.gas_limit.to_compact(buf);

        // Encode boolean
        buf.put_u8(self.is_system_transaction as u8);

        // Encode input bytes
        self.input.to_compact(buf);

        buf.as_mut().len() - start
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let mut remaining = buf;

        // Decode each field
        let (source_hash, updated) = B256::from_compact(remaining, remaining.len());
        remaining = updated;

        let (from, updated) = Address::from_compact(remaining, remaining.len());
        remaining = updated;

        let (to, updated) = TxKind::from_compact(remaining, remaining.len());
        remaining = updated;

        // Decode Option<u128> for mint
        let has_mint = remaining[0] != 0;
        remaining = &remaining[1..]; // Advance past the flag byte

        let (mint, updated) = if has_mint {
            let (mint_value, updated) = u128::from_compact(remaining, remaining.len());
            (Some(mint_value), updated)
        } else {
            (None, remaining)
        };
        remaining = updated;

        let (value, updated) = U256::from_compact(remaining, remaining.len());
        remaining = updated;

        let (gas_limit, updated) = u64::from_compact(remaining, remaining.len());
        remaining = updated;

        // Decode boolean
        let is_system_transaction = remaining[0] != 0;
        remaining = &remaining[1..]; // Advance past the boolean byte

        // Decode input bytes
        let (input, updated) = Bytes::from_compact(remaining, remaining.len());
        remaining = updated;

        (
            Self {
                source_hash,
                from,
                to,
                mint,
                value,
                gas_limit,
                is_system_transaction,
                input,
            },
            remaining,
        )
    }
}
