use alloy_consensus::{
    transaction::RlpEcdsaEncodableTx, SignableTransaction, Signed, Transaction, TxEip1559,
    TxEip2930, TxEip4844, TxEip7702, TxLegacy, Typed2718,
};
use alloy_eips::{eip2930::AccessList, Encodable2718};
use alloy_primitives::{
    bytes::BufMut, Address, Bytes, ChainId, PrimitiveSignature as Signature, TxHash, TxKind, B256,
};
use reth_primitives_traits::InMemorySize;

use super::{envelope::SovaTxEnvelope, l1_block::TxL1Block, tx_type::SovaTxType};

/// The TypedTransaction enum represents all Ethereum transaction request types, modified for Sova
///
/// Its variants correspond to specific allowed transactions:
/// 1. Legacy (pre-EIP2718) [`TxLegacy`]
/// 2. EIP2930 (state access lists) [`TxEip2930`]
/// 3. EIP1559 [`TxEip1559`]
/// 4. L1Block [`TxL1Block`]
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SovaTypedTransaction {
    /// Legacy transaction
    Legacy(TxLegacy),
    /// EIP-2930 transaction
    Eip2930(TxEip2930),
    /// EIP-1559 transaction
    Eip1559(TxEip1559),
    /// EIP-4844 transaction
    Eip4844(TxEip4844),
    /// EIP-7702 transaction
    Eip7702(TxEip7702),
    /// Sova L1Block transaction
    L1Block(TxL1Block),
}

impl From<TxLegacy> for SovaTypedTransaction {
    fn from(tx: TxLegacy) -> Self {
        Self::Legacy(tx)
    }
}

impl From<TxEip2930> for SovaTypedTransaction {
    fn from(tx: TxEip2930) -> Self {
        Self::Eip2930(tx)
    }
}

impl From<TxEip1559> for SovaTypedTransaction {
    fn from(tx: TxEip1559) -> Self {
        Self::Eip1559(tx)
    }
}

impl From<TxEip4844> for SovaTypedTransaction {
    fn from(tx: TxEip4844) -> Self {
        Self::Eip4844(tx)
    }
}

impl From<TxEip7702> for SovaTypedTransaction {
    fn from(tx: TxEip7702) -> Self {
        Self::Eip7702(tx)
    }
}

impl From<TxL1Block> for SovaTypedTransaction {
    fn from(tx: TxL1Block) -> Self {
        Self::L1Block(tx)
    }
}

impl From<SovaTxEnvelope> for SovaTypedTransaction {
    fn from(envelope: SovaTxEnvelope) -> Self {
        match envelope {
            SovaTxEnvelope::Legacy(tx) => Self::Legacy(tx.strip_signature()),
            SovaTxEnvelope::Eip2930(tx) => Self::Eip2930(tx.strip_signature()),
            SovaTxEnvelope::Eip1559(tx) => Self::Eip1559(tx.strip_signature()),
            SovaTxEnvelope::Eip4844(tx) => Self::Eip4844(tx.strip_signature()),
            SovaTxEnvelope::Eip7702(tx) => Self::Eip7702(tx.strip_signature()),
            SovaTxEnvelope::L1Block(tx) => Self::L1Block(tx.into_inner()),
        }
    }
}

impl SovaTypedTransaction {
    /// Return the [`SovaTxType`] of the inner txn.
    pub const fn tx_type(&self) -> SovaTxType {
        match self {
            Self::Legacy(_) => SovaTxType::Legacy,
            Self::Eip2930(_) => SovaTxType::Eip2930,
            Self::Eip1559(_) => SovaTxType::Eip1559,
            Self::Eip4844(_) => SovaTxType::Eip4844,
            Self::Eip7702(_) => SovaTxType::Eip7702,
            Self::L1Block(_) => SovaTxType::L1Block,
        }
    }

    /// Calculates the signing hash for the transaction.
    ///
    /// Returns `None` if the tx is a L1Block transaction.
    pub fn checked_signature_hash(&self) -> Option<B256> {
        match self {
            Self::Legacy(tx) => Some(tx.signature_hash()),
            Self::Eip2930(tx) => Some(tx.signature_hash()),
            Self::Eip1559(tx) => Some(tx.signature_hash()),
            Self::Eip4844(tx) => Some(tx.signature_hash()),
            Self::Eip7702(tx) => Some(tx.signature_hash()),
            Self::L1Block(_) => None,
        }
    }

    /// Return the inner legacy transaction if it exists.
    pub const fn legacy(&self) -> Option<&TxLegacy> {
        match self {
            Self::Legacy(tx) => Some(tx),
            _ => None,
        }
    }

    /// Return the inner EIP-2930 transaction if it exists.
    pub const fn eip2930(&self) -> Option<&TxEip2930> {
        match self {
            Self::Eip2930(tx) => Some(tx),
            _ => None,
        }
    }

    /// Return the inner EIP-1559 transaction if it exists.
    pub const fn eip1559(&self) -> Option<&TxEip1559> {
        match self {
            Self::Eip1559(tx) => Some(tx),
            _ => None,
        }
    }

    /// Return the inner L1Block transaction if it exists.
    pub const fn l1_block(&self) -> Option<&TxL1Block> {
        match self {
            Self::L1Block(tx) => Some(tx),
            _ => None,
        }
    }

    /// Returns `true` if transaction is L1Block transaction.
    pub const fn is_deposit(&self) -> bool {
        matches!(self, Self::L1Block(_))
    }

    /// Calculate the transaction hash for the given signature.
    ///
    /// Note: Returns the regular tx hash if this is a L1Block variant
    pub fn tx_hash(&self, signature: &Signature) -> TxHash {
        match self {
            Self::Legacy(tx) => tx.tx_hash(signature),
            Self::Eip2930(tx) => tx.tx_hash(signature),
            Self::Eip1559(tx) => tx.tx_hash(signature),
            Self::Eip4844(tx) => tx.tx_hash(signature),
            Self::Eip7702(tx) => tx.tx_hash(signature),
            Self::L1Block(tx) => tx.tx_hash(),
        }
    }
}

impl Typed2718 for SovaTypedTransaction {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy(_) => SovaTxType::Legacy as u8,
            Self::Eip2930(_) => SovaTxType::Eip2930 as u8,
            Self::Eip1559(_) => SovaTxType::Eip1559 as u8,
            Self::Eip4844(_) => SovaTxType::Eip4844 as u8,
            Self::Eip7702(_) => SovaTxType::Eip7702 as u8,
            Self::L1Block(_) => SovaTxType::L1Block as u8,
        }
    }
}

impl Transaction for SovaTypedTransaction {
    fn chain_id(&self) -> Option<alloy_primitives::ChainId> {
        match self {
            Self::Legacy(tx) => tx.chain_id(),
            Self::Eip2930(tx) => tx.chain_id(),
            Self::Eip1559(tx) => tx.chain_id(),
            Self::Eip4844(tx) => tx.chain_id(),
            Self::Eip7702(tx) => tx.chain_id(),
            Self::L1Block(tx) => tx.chain_id(),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.nonce(),
            Self::Eip2930(tx) => tx.nonce(),
            Self::Eip1559(tx) => tx.nonce(),
            Self::Eip4844(tx) => tx.nonce(),
            Self::Eip7702(tx) => tx.nonce(),
            Self::L1Block(tx) => tx.nonce(),
        }
    }

    fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.gas_limit(),
            Self::Eip2930(tx) => tx.gas_limit(),
            Self::Eip1559(tx) => tx.gas_limit(),
            Self::Eip4844(tx) => tx.gas_limit(),
            Self::Eip7702(tx) => tx.gas_limit(),
            Self::L1Block(tx) => tx.gas_limit(),
        }
    }

    fn gas_price(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.gas_price(),
            Self::Eip2930(tx) => tx.gas_price(),
            Self::Eip1559(tx) => tx.gas_price(),
            Self::Eip4844(tx) => tx.gas_price(),
            Self::Eip7702(tx) => tx.gas_price(),
            Self::L1Block(tx) => tx.gas_price(),
        }
    }

    fn max_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.max_fee_per_gas(),
            Self::Eip2930(tx) => tx.max_fee_per_gas(),
            Self::Eip1559(tx) => tx.max_fee_per_gas(),
            Self::Eip4844(tx) => tx.max_fee_per_gas(),
            Self::Eip7702(tx) => tx.max_fee_per_gas(),
            Self::L1Block(tx) => tx.max_fee_per_gas(),
        }
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.max_priority_fee_per_gas(),
            Self::Eip2930(tx) => tx.max_priority_fee_per_gas(),
            Self::Eip1559(tx) => tx.max_priority_fee_per_gas(),
            Self::Eip4844(tx) => tx.max_priority_fee_per_gas(),
            Self::Eip7702(tx) => tx.max_priority_fee_per_gas(),
            Self::L1Block(tx) => tx.max_priority_fee_per_gas(),
        }
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.max_fee_per_blob_gas(),
            Self::Eip2930(tx) => tx.max_fee_per_blob_gas(),
            Self::Eip1559(tx) => tx.max_fee_per_blob_gas(),
            Self::Eip4844(tx) => tx.max_fee_per_blob_gas(),
            Self::Eip7702(tx) => tx.max_fee_per_blob_gas(),
            Self::L1Block(tx) => tx.max_fee_per_blob_gas(),
        }
    }

    fn priority_fee_or_price(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.priority_fee_or_price(),
            Self::Eip2930(tx) => tx.priority_fee_or_price(),
            Self::Eip1559(tx) => tx.priority_fee_or_price(),
            Self::Eip4844(tx) => tx.priority_fee_or_price(),
            Self::Eip7702(tx) => tx.priority_fee_or_price(),
            Self::L1Block(tx) => tx.priority_fee_or_price(),
        }
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match self {
            Self::Legacy(tx) => tx.effective_gas_price(base_fee),
            Self::Eip2930(tx) => tx.effective_gas_price(base_fee),
            Self::Eip1559(tx) => tx.effective_gas_price(base_fee),
            Self::Eip4844(tx) => tx.effective_gas_price(base_fee),
            Self::Eip7702(tx) => tx.effective_gas_price(base_fee),
            Self::L1Block(tx) => tx.effective_gas_price(base_fee),
        }
    }

    fn is_dynamic_fee(&self) -> bool {
        match self {
            Self::Legacy(tx) => tx.is_dynamic_fee(),
            Self::Eip2930(tx) => tx.is_dynamic_fee(),
            Self::Eip1559(tx) => tx.is_dynamic_fee(),
            Self::Eip4844(tx) => tx.is_dynamic_fee(),
            Self::Eip7702(tx) => tx.is_dynamic_fee(),
            Self::L1Block(tx) => tx.is_dynamic_fee(),
        }
    }

    fn kind(&self) -> TxKind {
        match self {
            Self::Legacy(tx) => tx.kind(),
            Self::Eip2930(tx) => tx.kind(),
            Self::Eip1559(tx) => tx.kind(),
            Self::Eip4844(tx) => tx.kind(),
            Self::Eip7702(tx) => tx.kind(),
            Self::L1Block(tx) => tx.kind(),
        }
    }

    fn is_create(&self) -> bool {
        match self {
            Self::Legacy(tx) => tx.is_create(),
            Self::Eip2930(tx) => tx.is_create(),
            Self::Eip1559(tx) => tx.is_create(),
            Self::Eip4844(tx) => tx.is_create(),
            Self::Eip7702(tx) => tx.is_create(),
            Self::L1Block(tx) => tx.is_create(),
        }
    }

    fn to(&self) -> Option<Address> {
        match self {
            Self::Legacy(tx) => tx.to(),
            Self::Eip2930(tx) => tx.to(),
            Self::Eip1559(tx) => tx.to(),
            Self::Eip4844(tx) => tx.to(),
            Self::Eip7702(tx) => tx.to(),
            Self::L1Block(tx) => tx.to(),
        }
    }

    fn value(&self) -> alloy_primitives::U256 {
        match self {
            Self::Legacy(tx) => tx.value(),
            Self::Eip2930(tx) => tx.value(),
            Self::Eip1559(tx) => tx.value(),
            Self::Eip4844(tx) => tx.value(),
            Self::Eip7702(tx) => tx.value(),
            Self::L1Block(tx) => tx.value(),
        }
    }

    fn input(&self) -> &Bytes {
        match self {
            Self::Legacy(tx) => tx.input(),
            Self::Eip2930(tx) => tx.input(),
            Self::Eip1559(tx) => tx.input(),
            Self::Eip4844(tx) => tx.input(),
            Self::Eip7702(tx) => tx.input(),
            Self::L1Block(tx) => tx.input(),
        }
    }

    fn access_list(&self) -> Option<&AccessList> {
        match self {
            Self::Legacy(tx) => tx.access_list(),
            Self::Eip2930(tx) => tx.access_list(),
            Self::Eip1559(tx) => tx.access_list(),
            Self::Eip4844(tx) => tx.access_list(),
            Self::Eip7702(tx) => tx.access_list(),
            Self::L1Block(tx) => tx.access_list(),
        }
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        match self {
            Self::Legacy(tx) => tx.blob_versioned_hashes(),
            Self::Eip2930(tx) => tx.blob_versioned_hashes(),
            Self::Eip1559(tx) => tx.blob_versioned_hashes(),
            Self::Eip4844(tx) => tx.blob_versioned_hashes(),
            Self::Eip7702(tx) => tx.blob_versioned_hashes(),
            Self::L1Block(tx) => tx.blob_versioned_hashes(),
        }
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        match self {
            Self::Legacy(tx) => tx.authorization_list(),
            Self::Eip2930(tx) => tx.authorization_list(),
            Self::Eip1559(tx) => tx.authorization_list(),
            Self::Eip4844(tx) => tx.authorization_list(),
            Self::Eip7702(tx) => tx.authorization_list(),
            Self::L1Block(tx) => tx.authorization_list(),
        }
    }
}

impl RlpEcdsaEncodableTx for SovaTypedTransaction {
    fn rlp_encoded_fields_length(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.rlp_encoded_fields_length(),
            Self::Eip2930(tx) => tx.rlp_encoded_fields_length(),
            Self::Eip1559(tx) => tx.rlp_encoded_fields_length(),
            Self::Eip4844(tx) => tx.rlp_encoded_fields_length(),
            Self::Eip7702(tx) => tx.rlp_encoded_fields_length(),
            Self::L1Block(tx) => tx.rlp_encoded_fields_length(),
        }
    }

    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Legacy(tx) => tx.rlp_encode_fields(out),
            Self::Eip2930(tx) => tx.rlp_encode_fields(out),
            Self::Eip1559(tx) => tx.rlp_encode_fields(out),
            Self::Eip4844(tx) => tx.rlp_encode_fields(out),
            Self::Eip7702(tx) => tx.rlp_encode_fields(out),
            Self::L1Block(tx) => tx.rlp_encode_fields(out),
        }
    }

    fn eip2718_encode_with_type(&self, signature: &Signature, _ty: u8, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx) => tx.eip2718_encode_with_type(signature, tx.ty(), out),
            Self::Eip2930(tx) => tx.eip2718_encode_with_type(signature, tx.ty(), out),
            Self::Eip1559(tx) => tx.eip2718_encode_with_type(signature, tx.ty(), out),
            Self::Eip4844(tx) => tx.eip2718_encode_with_type(signature, tx.ty(), out),
            Self::Eip7702(tx) => tx.eip2718_encode_with_type(signature, tx.ty(), out),
            Self::L1Block(tx) => tx.encode_2718(out),
        }
    }

    fn eip2718_encode(&self, signature: &Signature, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx) => tx.eip2718_encode(signature, out),
            Self::Eip2930(tx) => tx.eip2718_encode(signature, out),
            Self::Eip1559(tx) => tx.eip2718_encode(signature, out),
            Self::Eip4844(tx) => tx.eip2718_encode(signature, out),
            Self::Eip7702(tx) => tx.eip2718_encode(signature, out),
            Self::L1Block(tx) => tx.encode_2718(out),
        }
    }

    fn network_encode_with_type(&self, signature: &Signature, _ty: u8, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx) => tx.network_encode_with_type(signature, tx.ty(), out),
            Self::Eip2930(tx) => tx.network_encode_with_type(signature, tx.ty(), out),
            Self::Eip1559(tx) => tx.network_encode_with_type(signature, tx.ty(), out),
            Self::Eip4844(tx) => tx.network_encode_with_type(signature, tx.ty(), out),
            Self::Eip7702(tx) => tx.network_encode_with_type(signature, tx.ty(), out),
            Self::L1Block(tx) => tx.network_encode(out),
        }
    }

    fn network_encode(&self, signature: &Signature, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx) => tx.network_encode(signature, out),
            Self::Eip2930(tx) => tx.network_encode(signature, out),
            Self::Eip1559(tx) => tx.network_encode(signature, out),
            Self::Eip4844(tx) => tx.network_encode(signature, out),
            Self::Eip7702(tx) => tx.network_encode(signature, out),
            Self::L1Block(tx) => tx.network_encode(out),
        }
    }

    fn tx_hash_with_type(&self, signature: &Signature, _ty: u8) -> TxHash {
        match self {
            Self::Legacy(tx) => tx.tx_hash_with_type(signature, tx.ty()),
            Self::Eip2930(tx) => tx.tx_hash_with_type(signature, tx.ty()),
            Self::Eip1559(tx) => tx.tx_hash_with_type(signature, tx.ty()),
            Self::Eip4844(tx) => tx.tx_hash_with_type(signature, tx.ty()),
            Self::Eip7702(tx) => tx.tx_hash_with_type(signature, tx.ty()),
            Self::L1Block(tx) => tx.tx_hash(),
        }
    }

    fn tx_hash(&self, signature: &Signature) -> TxHash {
        match self {
            Self::Legacy(tx) => tx.tx_hash(signature),
            Self::Eip2930(tx) => tx.tx_hash(signature),
            Self::Eip1559(tx) => tx.tx_hash(signature),
            Self::Eip4844(tx) => tx.tx_hash(signature),
            Self::Eip7702(tx) => tx.tx_hash(signature),
            Self::L1Block(tx) => tx.tx_hash(),
        }
    }
}

impl SignableTransaction<Signature> for SovaTypedTransaction {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        match self {
            Self::Legacy(tx) => tx.set_chain_id(chain_id),
            Self::Eip2930(tx) => tx.set_chain_id(chain_id),
            Self::Eip1559(tx) => tx.set_chain_id(chain_id),
            Self::Eip4844(tx) => tx.set_chain_id(chain_id),
            Self::Eip7702(tx) => tx.set_chain_id(chain_id),
            Self::L1Block(_) => {}
        }
    }

    fn encode_for_signing(&self, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx) => tx.encode_for_signing(out),
            Self::Eip2930(tx) => tx.encode_for_signing(out),
            Self::Eip1559(tx) => tx.encode_for_signing(out),
            Self::Eip4844(tx) => tx.encode_for_signing(out),
            Self::Eip7702(tx) => tx.encode_for_signing(out),
            Self::L1Block(_) => {}
        }
    }

    fn payload_len_for_signature(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.payload_len_for_signature(),
            Self::Eip2930(tx) => tx.payload_len_for_signature(),
            Self::Eip1559(tx) => tx.payload_len_for_signature(),
            Self::Eip4844(tx) => tx.payload_len_for_signature(),
            Self::Eip7702(tx) => tx.payload_len_for_signature(),
            Self::L1Block(_) => 0,
        }
    }

    fn into_signed(self, signature: Signature) -> Signed<Self, Signature>
    where
        Self: Sized,
    {
        let hash = self.tx_hash(&signature);
        Signed::new_unchecked(self, signature, hash)
    }
}

impl InMemorySize for SovaTypedTransaction {
    fn size(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.size(),
            Self::Eip2930(tx) => tx.size(),
            Self::Eip1559(tx) => tx.size(),
            Self::Eip4844(tx) => tx.size(),
            Self::Eip7702(tx) => tx.size(),
            Self::L1Block(tx) => tx.size(),
        }
    }
}

/// Compact encoding for `SovaTransactionSigned`
/// NOTE: This code deviates from the original `reth` implementation. This implementation
/// has been simplified and removes the need for an additional sova_codecs module.
impl reth_codecs::Compact for SovaTypedTransaction {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        match self {
            Self::Legacy(tx) => tx.to_compact(buf),
            Self::Eip2930(tx) => tx.to_compact(buf),
            Self::Eip1559(tx) => tx.to_compact(buf),
            Self::Eip4844(tx) => tx.to_compact(buf),
            Self::Eip7702(tx) => tx.to_compact(buf),
            Self::L1Block(tx) => tx.to_compact(buf),
        }
    }

    fn from_compact(buf: &[u8], tx_type: usize) -> (Self, &[u8]) {
        match tx_type
            .try_into()
            .map_err(|_| format!("Unknown transaction type: {}", tx_type))
            .unwrap()
        {
            SovaTxType::Legacy => {
                let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                (Self::Legacy(tx), buf)
            }
            SovaTxType::Eip2930 => {
                let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                (Self::Eip2930(tx), buf)
            }
            SovaTxType::Eip1559 => {
                let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                (Self::Eip1559(tx), buf)
            }
            SovaTxType::Eip4844 => {
                let (tx, buf) = TxEip4844::from_compact(buf, buf.len());
                (Self::Eip4844(tx), buf)
            }
            SovaTxType::Eip7702 => {
                let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                (Self::Eip7702(tx), buf)
            }
            SovaTxType::L1Block => {
                let (tx, buf) = TxL1Block::from_compact(buf, buf.len());
                (Self::L1Block(tx), buf)
            }
        }
    }
}
