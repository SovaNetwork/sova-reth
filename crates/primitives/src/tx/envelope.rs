extern crate alloc;

use alloy_consensus::{
    transaction::RlpEcdsaDecodableTx, Sealable, Sealed, Signed, Transaction, TxEip1559, TxEip2930,
    TxEip4844, TxEip4844Variant, TxEip7702, TxEnvelope, TxLegacy, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rlp::{Decodable, Encodable};

use super::{l1_block::TxL1Block, tx_type::SovaTxType, typed::SovaTypedTransaction};

/// The Ethereum [EIP-2718] Transaction Envelope, modified for Sova.
///
/// # Note:
///
/// This enum distinguishes between tagged and untagged legacy transactions, as
/// the in-protocol merkle tree may commit to EITHER 0-prefixed or raw.
/// Therefore we must ensure that encoding returns the precise byte-array that
/// was decoded, preserving the presence or absence of the `TransactionType`
/// flag.
///
/// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SovaTxEnvelope {
    /// An untagged [`TxLegacy`].
    Legacy(Signed<TxLegacy>),
    /// A [`TxEip2930`] tagged with type 1.
    Eip2930(Signed<TxEip2930>),
    /// A [`TxEip1559`] tagged with type 2.
    Eip1559(Signed<TxEip1559>),
    /// A [`TxEip4844`] tagged with type 3.
    Eip4844(Signed<TxEip4844>),
    /// A [`TxEip7702`] tagged with type 4.
    Eip7702(Signed<TxEip7702>),
    /// A [`TxL1Block`] tagged with type 0x7E.
    L1Block(Sealed<TxL1Block>),
}

impl AsRef<Self> for SovaTxEnvelope {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl From<Signed<TxLegacy>> for SovaTxEnvelope {
    fn from(v: Signed<TxLegacy>) -> Self {
        Self::Legacy(v)
    }
}

impl From<Signed<TxEip2930>> for SovaTxEnvelope {
    fn from(v: Signed<TxEip2930>) -> Self {
        Self::Eip2930(v)
    }
}

impl From<Signed<TxEip1559>> for SovaTxEnvelope {
    fn from(v: Signed<TxEip1559>) -> Self {
        Self::Eip1559(v)
    }
}

impl From<Signed<TxEip4844>> for SovaTxEnvelope {
    fn from(v: Signed<TxEip4844>) -> Self {
        Self::Eip4844(v)
    }
}

impl From<Signed<TxEip4844Variant>> for SovaTxEnvelope {
    fn from(v: Signed<TxEip4844Variant>) -> Self {
        let (tx_variant, sig, hash) = v.into_parts();
        match tx_variant {
            TxEip4844Variant::TxEip4844(tx) => Self::Eip4844(Signed::new_unchecked(tx, sig, hash)),
            TxEip4844Variant::TxEip4844WithSidecar(tx_with_sidecar) => {
                Self::Eip4844(Signed::new_unchecked(tx_with_sidecar.tx, sig, hash))
            }
        }
    }
}

impl From<Signed<TxEip7702>> for SovaTxEnvelope {
    fn from(v: Signed<TxEip7702>) -> Self {
        Self::Eip7702(v)
    }
}

impl From<TxL1Block> for SovaTxEnvelope {
    fn from(v: TxL1Block) -> Self {
        v.seal_slow().into()
    }
}

impl From<Signed<SovaTypedTransaction>> for SovaTxEnvelope {
    fn from(value: Signed<SovaTypedTransaction>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        match tx {
            SovaTypedTransaction::Legacy(tx_legacy) => {
                let tx = Signed::new_unchecked(tx_legacy, sig, hash);
                Self::Legacy(tx)
            }
            SovaTypedTransaction::Eip2930(tx_eip2930) => {
                let tx = Signed::new_unchecked(tx_eip2930, sig, hash);
                Self::Eip2930(tx)
            }
            SovaTypedTransaction::Eip1559(tx_eip1559) => {
                let tx = Signed::new_unchecked(tx_eip1559, sig, hash);
                Self::Eip1559(tx)
            }
            SovaTypedTransaction::Eip4844(tx_eip4844) => {
                let tx = Signed::new_unchecked(tx_eip4844, sig, hash);
                Self::Eip4844(tx)
            }
            SovaTypedTransaction::Eip7702(tx_eip7702) => {
                let tx = Signed::new_unchecked(tx_eip7702, sig, hash);
                Self::Eip7702(tx)
            }
            SovaTypedTransaction::L1Block(tx) => Self::L1Block(Sealed::new_unchecked(tx, hash)),
        }
    }
}

impl From<Sealed<TxL1Block>> for SovaTxEnvelope {
    fn from(v: Sealed<TxL1Block>) -> Self {
        Self::L1Block(v)
    }
}

impl TryFrom<TxEnvelope> for SovaTxEnvelope {
    type Error = TxEnvelope;

    fn try_from(value: TxEnvelope) -> Result<Self, Self::Error> {
        Self::try_from_eth_envelope(value)
    }
}

impl TryFrom<SovaTxEnvelope> for TxEnvelope {
    type Error = SovaTxEnvelope;

    fn try_from(value: SovaTxEnvelope) -> Result<Self, Self::Error> {
        value.try_into_eth_envelope()
    }
}

impl Typed2718 for SovaTxEnvelope {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy(tx) => tx.tx().ty(),
            Self::Eip2930(tx) => tx.tx().ty(),
            Self::Eip1559(tx) => tx.tx().ty(),
            Self::Eip4844(tx) => tx.tx().ty(),
            Self::Eip7702(tx) => tx.tx().ty(),
            Self::L1Block(tx) => tx.ty(),
        }
    }
}

impl Transaction for SovaTxEnvelope {
    fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Legacy(tx) => tx.tx().chain_id(),
            Self::Eip2930(tx) => tx.tx().chain_id(),
            Self::Eip1559(tx) => tx.tx().chain_id(),
            Self::Eip4844(tx) => tx.tx().chain_id(),
            Self::Eip7702(tx) => tx.tx().chain_id(),
            Self::L1Block(tx) => tx.chain_id(),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.tx().nonce(),
            Self::Eip2930(tx) => tx.tx().nonce(),
            Self::Eip1559(tx) => tx.tx().nonce(),
            Self::Eip4844(tx) => tx.tx().nonce(),
            Self::Eip7702(tx) => tx.tx().nonce(),
            Self::L1Block(tx) => tx.nonce(),
        }
    }

    fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.tx().gas_limit(),
            Self::Eip2930(tx) => tx.tx().gas_limit(),
            Self::Eip1559(tx) => tx.tx().gas_limit(),
            Self::Eip4844(tx) => tx.tx().gas_limit(),
            Self::Eip7702(tx) => tx.tx().gas_limit(),
            Self::L1Block(tx) => tx.gas_limit(),
        }
    }

    fn gas_price(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.tx().gas_price(),
            Self::Eip2930(tx) => tx.tx().gas_price(),
            Self::Eip1559(tx) => tx.tx().gas_price(),
            Self::Eip4844(tx) => tx.tx().gas_price(),
            Self::Eip7702(tx) => tx.tx().gas_price(),
            Self::L1Block(tx) => tx.gas_price(),
        }
    }

    fn max_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.tx().max_fee_per_gas(),
            Self::Eip2930(tx) => tx.tx().max_fee_per_gas(),
            Self::Eip1559(tx) => tx.tx().max_fee_per_gas(),
            Self::Eip4844(tx) => tx.tx().max_fee_per_gas(),
            Self::Eip7702(tx) => tx.tx().max_fee_per_gas(),
            Self::L1Block(tx) => tx.max_fee_per_gas(),
        }
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.tx().max_priority_fee_per_gas(),
            Self::Eip2930(tx) => tx.tx().max_priority_fee_per_gas(),
            Self::Eip1559(tx) => tx.tx().max_priority_fee_per_gas(),
            Self::Eip4844(tx) => tx.tx().max_priority_fee_per_gas(),
            Self::Eip7702(tx) => tx.tx().max_priority_fee_per_gas(),
            Self::L1Block(tx) => tx.max_priority_fee_per_gas(),
        }
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        match self {
            Self::Legacy(tx) => tx.tx().max_fee_per_blob_gas(),
            Self::Eip2930(tx) => tx.tx().max_fee_per_blob_gas(),
            Self::Eip1559(tx) => tx.tx().max_fee_per_blob_gas(),
            Self::Eip4844(tx) => tx.tx().max_fee_per_blob_gas(),
            Self::Eip7702(tx) => tx.tx().max_fee_per_blob_gas(),
            Self::L1Block(tx) => tx.max_fee_per_blob_gas(),
        }
    }

    fn priority_fee_or_price(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.tx().priority_fee_or_price(),
            Self::Eip2930(tx) => tx.tx().priority_fee_or_price(),
            Self::Eip1559(tx) => tx.tx().priority_fee_or_price(),
            Self::Eip4844(tx) => tx.tx().priority_fee_or_price(),
            Self::Eip7702(tx) => tx.tx().priority_fee_or_price(),
            Self::L1Block(tx) => tx.priority_fee_or_price(),
        }
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match self {
            Self::Legacy(tx) => tx.tx().effective_gas_price(base_fee),
            Self::Eip2930(tx) => tx.tx().effective_gas_price(base_fee),
            Self::Eip1559(tx) => tx.tx().effective_gas_price(base_fee),
            Self::Eip4844(tx) => tx.tx().effective_gas_price(base_fee),
            Self::Eip7702(tx) => tx.tx().effective_gas_price(base_fee),
            Self::L1Block(tx) => tx.effective_gas_price(base_fee),
        }
    }

    fn is_dynamic_fee(&self) -> bool {
        match self {
            Self::Legacy(tx) => tx.tx().is_dynamic_fee(),
            Self::Eip2930(tx) => tx.tx().is_dynamic_fee(),
            Self::Eip1559(tx) => tx.tx().is_dynamic_fee(),
            Self::Eip4844(tx) => tx.tx().is_dynamic_fee(),
            Self::Eip7702(tx) => tx.tx().is_dynamic_fee(),
            Self::L1Block(tx) => tx.is_dynamic_fee(),
        }
    }

    fn kind(&self) -> TxKind {
        match self {
            Self::Legacy(tx) => tx.tx().kind(),
            Self::Eip2930(tx) => tx.tx().kind(),
            Self::Eip1559(tx) => tx.tx().kind(),
            Self::Eip4844(tx) => tx.tx().kind(),
            Self::Eip7702(tx) => tx.tx().kind(),
            Self::L1Block(tx) => tx.kind(),
        }
    }

    fn is_create(&self) -> bool {
        match self {
            Self::Legacy(tx) => tx.tx().is_create(),
            Self::Eip2930(tx) => tx.tx().is_create(),
            Self::Eip1559(tx) => tx.tx().is_create(),
            Self::Eip4844(tx) => tx.tx().is_create(),
            Self::Eip7702(tx) => tx.tx().is_create(),
            Self::L1Block(tx) => tx.is_create(),
        }
    }

    fn to(&self) -> Option<Address> {
        match self {
            Self::Legacy(tx) => tx.tx().to(),
            Self::Eip2930(tx) => tx.tx().to(),
            Self::Eip1559(tx) => tx.tx().to(),
            Self::Eip4844(tx) => tx.tx().to(),
            Self::Eip7702(tx) => tx.tx().to(),
            Self::L1Block(tx) => tx.to(),
        }
    }

    fn value(&self) -> U256 {
        match self {
            Self::Legacy(tx) => tx.tx().value(),
            Self::Eip2930(tx) => tx.tx().value(),
            Self::Eip1559(tx) => tx.tx().value(),
            Self::Eip4844(tx) => tx.tx().value(),
            Self::Eip7702(tx) => tx.tx().value(),
            Self::L1Block(tx) => tx.value(),
        }
    }

    fn input(&self) -> &Bytes {
        match self {
            Self::Legacy(tx) => tx.tx().input(),
            Self::Eip2930(tx) => tx.tx().input(),
            Self::Eip1559(tx) => tx.tx().input(),
            Self::Eip4844(tx) => tx.tx().input(),
            Self::Eip7702(tx) => tx.tx().input(),
            Self::L1Block(tx) => tx.input(),
        }
    }

    fn access_list(&self) -> Option<&AccessList> {
        match self {
            Self::Legacy(tx) => tx.tx().access_list(),
            Self::Eip2930(tx) => tx.tx().access_list(),
            Self::Eip1559(tx) => tx.tx().access_list(),
            Self::Eip4844(tx) => tx.tx().access_list(),
            Self::Eip7702(tx) => tx.tx().access_list(),
            Self::L1Block(tx) => tx.access_list(),
        }
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        match self {
            Self::Legacy(tx) => tx.tx().blob_versioned_hashes(),
            Self::Eip2930(tx) => tx.tx().blob_versioned_hashes(),
            Self::Eip1559(tx) => tx.tx().blob_versioned_hashes(),
            Self::Eip4844(tx) => tx.tx().blob_versioned_hashes(),
            Self::Eip7702(tx) => tx.tx().blob_versioned_hashes(),
            Self::L1Block(tx) => tx.blob_versioned_hashes(),
        }
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        match self {
            Self::Legacy(tx) => tx.tx().authorization_list(),
            Self::Eip2930(tx) => tx.tx().authorization_list(),
            Self::Eip1559(tx) => tx.tx().authorization_list(),
            Self::Eip4844(tx) => tx.tx().authorization_list(),
            Self::Eip7702(tx) => tx.tx().authorization_list(),
            Self::L1Block(tx) => tx.authorization_list(),
        }
    }
}

impl SovaTxEnvelope {
    /// Returns true if the transaction is a legacy transaction.
    #[inline]
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    /// Returns true if the transaction is an EIP-2930 transaction.
    #[inline]
    pub const fn is_eip2930(&self) -> bool {
        matches!(self, Self::Eip2930(_))
    }

    /// Returns true if the transaction is an EIP-1559 transaction.
    #[inline]
    pub const fn is_eip1559(&self) -> bool {
        matches!(self, Self::Eip1559(_))
    }

    /// Returns true if the transaction is an EIP-4844 transaction.
    #[inline]
    pub const fn is_eip4844(&self) -> bool {
        matches!(self, Self::Eip4844(_))
    }

    /// Returns true if the transaction is a system transaction.
    #[inline]
    pub const fn is_system_transaction(&self) -> bool {
        match self {
            Self::L1Block(tx) => tx.inner().is_system_transaction,
            _ => false,
        }
    }

    /// Attempts to convert the optimism variant into an ethereum [`TxEnvelope`].
    ///
    /// Returns the envelope as error if it is a variant unsupported on ethereum: [`TxL1Block`]
    pub fn try_into_eth_envelope(self) -> Result<TxEnvelope, Self> {
        match self {
            Self::Legacy(tx) => Ok(tx.into()),
            Self::Eip2930(tx) => Ok(tx.into()),
            Self::Eip1559(tx) => Ok(tx.into()),
            Self::Eip4844(tx) => Ok(tx.into()),
            Self::Eip7702(tx) => Ok(tx.into()),
            tx @ Self::L1Block(_) => Err(tx),
        }
    }

    /// Attempts to convert an ethereum [`TxEnvelope`] into the optimism variant.
    ///
    /// Returns the given envelope as error if [`SovaTxEnvelope`] doesn't support the variant
    /// (EIP-4844)
    pub fn try_from_eth_envelope(tx: TxEnvelope) -> Result<Self, TxEnvelope> {
        match tx {
            TxEnvelope::Legacy(tx) => Ok(tx.into()),
            TxEnvelope::Eip2930(tx) => Ok(tx.into()),
            TxEnvelope::Eip1559(tx) => Ok(tx.into()),
            TxEnvelope::Eip4844(tx) => Ok(tx.into()),
            TxEnvelope::Eip7702(tx) => Ok(tx.into()),
        }
    }

    /// Returns true if the transaction is a deposit transaction.
    #[inline]
    pub const fn is_deposit(&self) -> bool {
        matches!(self, Self::L1Block(_))
    }

    /// Returns the [`TxLegacy`] variant if the transaction is a legacy transaction.
    pub const fn as_legacy(&self) -> Option<&Signed<TxLegacy>> {
        match self {
            Self::Legacy(tx) => Some(tx),
            _ => None,
        }
    }

    /// Returns the [`TxEip2930`] variant if the transaction is an EIP-2930 transaction.
    pub const fn as_eip2930(&self) -> Option<&Signed<TxEip2930>> {
        match self {
            Self::Eip2930(tx) => Some(tx),
            _ => None,
        }
    }

    /// Returns the [`TxEip1559`] variant if the transaction is an EIP-1559 transaction.
    pub const fn as_eip1559(&self) -> Option<&Signed<TxEip1559>> {
        match self {
            Self::Eip1559(tx) => Some(tx),
            _ => None,
        }
    }

    /// Returns the [`TxEip4844`] variant if the transaction is an EIP-4844 transaction.
    pub const fn as_eip4844(&self) -> Option<&Signed<TxEip4844>> {
        match self {
            Self::Eip4844(tx) => Some(tx),
            _ => None,
        }
    }

    pub const fn as_l1_block(&self) -> Option<&Sealed<TxL1Block>> {
        match self {
            Self::L1Block(tx) => Some(tx),
            _ => None,
        }
    }

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

    /// Returns the inner transaction hash.
    pub fn tx_hash(&self) -> B256 {
        match self {
            Self::Legacy(tx) => *tx.hash(),
            Self::Eip1559(tx) => *tx.hash(),
            Self::Eip2930(tx) => *tx.hash(),
            Self::Eip4844(tx) => *tx.hash(),
            Self::Eip7702(tx) => *tx.hash(),
            Self::L1Block(tx) => tx.tx_hash(),
        }
    }

    /// Return the length of the inner txn, including type byte length
    pub fn eip2718_encoded_length(&self) -> usize {
        match self {
            Self::Legacy(t) => t.eip2718_encoded_length(),
            Self::Eip2930(t) => t.eip2718_encoded_length(),
            Self::Eip1559(t) => t.eip2718_encoded_length(),
            Self::Eip4844(t) => t.eip2718_encoded_length(),
            Self::Eip7702(t) => t.eip2718_encoded_length(),
            Self::L1Block(t) => t.eip2718_encoded_length(),
        }
    }
}

impl Encodable for SovaTxEnvelope {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.network_encode(out)
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for SovaTxEnvelope {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::network_decode(buf)?)
    }
}

impl Decodable2718 for SovaTxEnvelope {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        match ty
            .try_into()
            .map_err(|_| Eip2718Error::UnexpectedType(ty))?
        {
            SovaTxType::Eip2930 => Ok(Self::Eip2930(TxEip2930::rlp_decode_signed(buf)?)),
            SovaTxType::Eip1559 => Ok(Self::Eip1559(TxEip1559::rlp_decode_signed(buf)?)),
            SovaTxType::Eip4844 => Ok(Self::Eip4844(TxEip4844::rlp_decode_signed(buf)?)),
            SovaTxType::Eip7702 => Ok(Self::Eip7702(TxEip7702::rlp_decode_signed(buf)?)),
            SovaTxType::L1Block => Ok(Self::L1Block(TxL1Block::decode(buf)?.seal_slow())),
            SovaTxType::Legacy => Err(alloy_rlp::Error::Custom(
                "type-0 eip2718 transactions are not supported",
            )
            .into()),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        Ok(Self::Legacy(TxLegacy::rlp_decode_signed(buf)?))
    }
}

impl Encodable2718 for SovaTxEnvelope {
    fn type_flag(&self) -> Option<u8> {
        match self {
            Self::Legacy(_) => None,
            Self::Eip2930(_) => Some(SovaTxType::Eip2930 as u8),
            Self::Eip1559(_) => Some(SovaTxType::Eip1559 as u8),
            Self::Eip4844(_) => Some(SovaTxType::Eip4844 as u8),
            Self::Eip7702(_) => Some(SovaTxType::Eip7702 as u8),
            Self::L1Block(_) => Some(SovaTxType::L1Block as u8),
        }
    }

    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            // Legacy transactions have no difference between network and 2718
            Self::Legacy(tx) => tx.eip2718_encode(out),
            Self::Eip2930(tx) => {
                tx.eip2718_encode(out);
            }
            Self::Eip1559(tx) => {
                tx.eip2718_encode(out);
            }
            Self::Eip4844(tx) => {
                tx.eip2718_encode(out);
            }
            Self::Eip7702(tx) => {
                tx.eip2718_encode(out);
            }
            Self::L1Block(tx) => {
                tx.encode_2718(out);
            }
        }
    }

    fn trie_hash(&self) -> B256 {
        match self {
            Self::Legacy(tx) => *tx.hash(),
            Self::Eip1559(tx) => *tx.hash(),
            Self::Eip2930(tx) => *tx.hash(),
            Self::Eip4844(tx) => *tx.hash(),
            Self::Eip7702(tx) => *tx.hash(),
            Self::L1Block(tx) => tx.seal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_consensus::SignableTransaction;
    use alloy_primitives::{hex, Address, Bytes, PrimitiveSignature, TxKind, B256, U256};

    #[test]
    fn test_tx_gas_limit() {
        let tx = TxL1Block {
            gas_limit: 1,
            ..Default::default()
        };
        let tx_envelope = SovaTxEnvelope::L1Block(tx.seal_slow());
        assert_eq!(tx_envelope.gas_limit(), 1);
    }

    #[test]
    fn test_deposit() {
        let tx = TxL1Block {
            is_system_transaction: true,
            ..Default::default()
        };
        let tx_envelope = SovaTxEnvelope::L1Block(tx.seal_slow());
        assert!(tx_envelope.is_deposit());

        let tx = TxEip1559::default();
        let sig = PrimitiveSignature::test_signature();
        let tx_envelope = SovaTxEnvelope::Eip1559(tx.into_signed(sig));
        assert!(!tx_envelope.is_system_transaction());
    }

    #[test]
    fn test_system_transaction() {
        let mut tx = TxL1Block {
            is_system_transaction: true,
            ..Default::default()
        };
        let tx_envelope = SovaTxEnvelope::L1Block(tx.clone().seal_slow());
        assert!(tx_envelope.is_system_transaction());

        tx.is_system_transaction = false;
        let tx_envelope = SovaTxEnvelope::L1Block(tx.seal_slow());
        assert!(!tx_envelope.is_system_transaction());
    }

    #[test]
    fn test_encode_decode_deposit() {
        let tx = TxL1Block {
            source_hash: B256::left_padding_from(&[0xde, 0xad]),
            from: Address::left_padding_from(&[0xbe, 0xef]),
            mint: Some(1),
            gas_limit: 2,
            to: TxKind::Call(Address::left_padding_from(&[3])),
            value: U256::from(4_u64),
            input: Bytes::from(vec![5]),
            is_system_transaction: false,
        };
        let tx_envelope = SovaTxEnvelope::L1Block(tx.seal_slow());
        let encoded = tx_envelope.encoded_2718();
        let decoded = SovaTxEnvelope::decode_2718(&mut encoded.as_ref()).unwrap();
        assert_eq!(encoded.len(), tx_envelope.encode_2718_len());
        assert_eq!(decoded, tx_envelope);
    }

    #[test]
    fn eip2718_deposit_decode() {
        // <https://basescan.org/tx/0xc468b38a20375922828c8126912740105125143b9856936085474b2590bbca91>
        let b = hex!(
            "7ef8f8a0417d134467f4737fcdf2475f0ecdd2a0ed6d87ecffc888ba9f60ee7e3b8ac26a94deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b8a4440a5e20000008dd00101c1200000000000000040000000066c352bb000000000139c4f500000000000000000000000000000000000000000000000000000000c0cff1460000000000000000000000000000000000000000000000000000000000000001d4c88f4065ac9671e8b1329b90773e89b5ddff9cf8675b2b5e9c1b28320609930000000000000000000000005050f69a9786f081509234f1a7f4684b5e5b76c9"
        );

        let tx = SovaTxEnvelope::decode_2718(&mut b[..].as_ref()).unwrap();
        let deposit = tx.as_l1_block().unwrap();
        assert!(deposit.mint.is_none());
    }

    #[test]
    fn eip1559_decode() {
        let tx = TxEip1559 {
            chain_id: 1u64,
            nonce: 2,
            max_fee_per_gas: 3,
            max_priority_fee_per_gas: 4,
            gas_limit: 5,
            to: Address::left_padding_from(&[6]).into(),
            value: U256::from(7_u64),
            input: vec![8].into(),
            access_list: Default::default(),
        };
        let sig = PrimitiveSignature::test_signature();
        let tx_signed = tx.into_signed(sig);
        let envelope: SovaTxEnvelope = tx_signed.into();
        let encoded = envelope.encoded_2718();
        let mut slice = encoded.as_slice();
        let decoded = SovaTxEnvelope::decode_2718(&mut slice).unwrap();
        assert!(matches!(decoded, SovaTxEnvelope::Eip1559(_)));
    }
}
