use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
    Sealed, SignableTransaction, Signed, Transaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702,
    TxLegacy, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxHash, TxKind, Uint, B256};
use alloy_rlp::Header;
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
#[cfg(any(test, feature = "reth-codec"))]
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::signed::RecoveryError,
    InMemorySize, SignedTransaction,
};

use super::{deposit::SovaTxDeposit, envelope::SovaTxEnvelope, tx_type::SovaTxType, typed::SovaTypedTransaction};

/// Signed transaction.
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(rlp))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Eq)]
pub struct SovaTransactionSigned {
    /// Transaction hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: OnceLock<TxHash>,
    /// The transaction signature values
    signature: Signature,
    /// Raw transaction info
    transaction: SovaTypedTransaction,
}

impl Deref for SovaTransactionSigned {
    type Target = SovaTypedTransaction;
    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl SovaTransactionSigned {
    /// Creates a new signed transaction from the given transaction, signature and hash.
    pub fn new(transaction: SovaTypedTransaction, signature: Signature, hash: B256) -> Self {
        Self {
            hash: hash.into(),
            signature,
            transaction,
        }
    }

    #[cfg(test)]
    fn input_mut(&mut self) -> &mut Bytes {
        match &mut self.transaction {
            SovaTypedTransaction::Legacy(tx) => &mut tx.input,
            SovaTypedTransaction::Eip2930(tx) => &mut tx.input,
            SovaTypedTransaction::Eip1559(tx) => &mut tx.input,
            SovaTypedTransaction::Eip4844(tx) => &mut tx.input,
            SovaTypedTransaction::Eip7702(tx) => &mut tx.input,
            SovaTypedTransaction::Deposit(tx) => &mut tx.input,
        }
    }

    /// Consumes the type and returns the transaction.
    #[inline]
    pub fn into_transaction(self) -> SovaTypedTransaction {
        self.transaction
    }

    /// Returns the transaction.
    #[inline]
    pub const fn transaction(&self) -> &SovaTypedTransaction {
        &self.transaction
    }

    /// Splits the `SovaTransactionSigned` into its transaction and signature.
    pub fn split(self) -> (SovaTypedTransaction, Signature) {
        (self.transaction, self.signature)
    }

    /// Creates a new signed transaction from the given transaction and signature without the hash.
    ///
    /// Note: this only calculates the hash on the first [`SovaTransactionSigned::hash`] call.
    pub fn new_unhashed(transaction: SovaTypedTransaction, signature: Signature) -> Self {
        Self {
            hash: Default::default(),
            signature,
            transaction,
        }
    }

    /// Returns whether this transaction is a deposit.
    pub const fn is_deposit(&self) -> bool {
        matches!(self.transaction, SovaTypedTransaction::Deposit(_))
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (SovaTypedTransaction, Signature, B256) {
        let hash = *self.hash.get_or_init(|| self.recalculate_hash());
        (self.transaction, self.signature, hash)
    }
}

impl SignedTransaction for SovaTransactionSigned {
    fn tx_hash(&self) -> &TxHash {
        self.hash.get_or_init(|| self.recalculate_hash())
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        if let SovaTypedTransaction::Deposit(SovaTxDeposit { from, .. }) = self.transaction {
            return Ok(from);
        }

        let Self {
            transaction,
            signature,
            ..
        } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer(signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        if let SovaTypedTransaction::Deposit(SovaTxDeposit { from, .. }) = &self.transaction {
            return Ok(*from);
        }

        let Self {
            transaction,
            signature,
            ..
        } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer_unchecked(signature, signature_hash)
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        match &self.transaction {
            // Deposit transaction does not have a signature. Directly return the
            // `from` address.
            SovaTypedTransaction::Deposit(tx) => return Ok(tx.from),
            SovaTypedTransaction::Legacy(tx) => tx.encode_for_signing(buf),
            SovaTypedTransaction::Eip2930(tx) => tx.encode_for_signing(buf),
            SovaTypedTransaction::Eip1559(tx) => tx.encode_for_signing(buf),
            SovaTypedTransaction::Eip4844(tx) => tx.encode_for_signing(buf),
            SovaTypedTransaction::Eip7702(tx) => tx.encode_for_signing(buf),
        };
        recover_signer_unchecked(&self.signature, keccak256(buf))
    }

    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }
}

macro_rules! impl_from_signed {
    ($($tx:ident),*) => {
        $(
            impl From<Signed<$tx>> for SovaTransactionSigned {
                fn from(value: Signed<$tx>) -> Self {
                    let(tx,sig,hash) = value.into_parts();
                    Self::new(tx.into(), sig, hash)
                }
            }
        )*
    };
}

impl_from_signed!(
    TxLegacy,
    TxEip2930,
    TxEip1559,
    TxEip4844,
    TxEip7702,
    SovaTypedTransaction
);

impl From<SovaTxEnvelope> for SovaTransactionSigned {
    fn from(value: SovaTxEnvelope) -> Self {
        match value {
            SovaTxEnvelope::Legacy(tx) => tx.into(),
            SovaTxEnvelope::Eip2930(tx) => tx.into(),
            SovaTxEnvelope::Eip1559(tx) => tx.into(),
            SovaTxEnvelope::Eip4844(tx) => tx.into(),
            SovaTxEnvelope::Eip7702(tx) => tx.into(),
            SovaTxEnvelope::Deposit(tx) => tx.into(),
        }
    }
}

impl From<Sealed<SovaTxDeposit>> for SovaTransactionSigned {
    fn from(value: Sealed<SovaTxDeposit>) -> Self {
        let (tx, hash) = value.into_parts();
        Self::new(
            SovaTypedTransaction::Deposit(tx),
            SovaTxDeposit::signature(),
            hash,
        )
    }
}

impl InMemorySize for SovaTransactionSigned {
    #[inline]
    fn size(&self) -> usize {
        mem::size_of::<TxHash>() + self.transaction.size() + mem::size_of::<Signature>()
    }
}

impl alloy_rlp::Encodable for SovaTransactionSigned {
    fn encode(&self, out: &mut dyn alloy_rlp::bytes::BufMut) {
        self.network_encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = self.encode_2718_len();
        if !self.is_legacy() {
            payload_length += Header {
                list: false,
                payload_length,
            }
            .length();
        }

        payload_length
    }
}

impl alloy_rlp::Decodable for SovaTransactionSigned {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::network_decode(buf).map_err(Into::into)
    }
}

impl Encodable2718 for SovaTransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        if Typed2718::is_legacy(self) {
            None
        } else {
            Some(self.ty())
        }
    }

    fn encode_2718_len(&self) -> usize {
        match &self.transaction {
            SovaTypedTransaction::Legacy(legacy_tx) => {
                legacy_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Eip4844(blob_tx) => {
                blob_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Deposit(deposit_tx) => deposit_tx.eip2718_encoded_length(),
        }
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        let Self {
            transaction,
            signature,
            ..
        } = self;

        match &transaction {
            SovaTypedTransaction::Legacy(legacy_tx) => legacy_tx.eip2718_encode(signature, out),
            SovaTypedTransaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip4844(blob_tx) => blob_tx.eip2718_encode(signature, out),
            SovaTypedTransaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Deposit(deposit_tx) => deposit_tx.encode_2718(out),
        }
    }
}

impl Decodable2718 for SovaTransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        match ty
            .try_into()
            .map_err(|_| Eip2718Error::UnexpectedType(ty))?
        {
            SovaTxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
            SovaTxType::Eip2930 => {
                let (tx, signature, hash) = TxEip2930::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SovaTypedTransaction::Eip2930(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            SovaTxType::Eip1559 => {
                let (tx, signature, hash) = TxEip1559::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SovaTypedTransaction::Eip1559(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            SovaTxType::Eip4844 => {
                let (tx, signature, hash) = TxEip4844::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SovaTypedTransaction::Eip4844(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            SovaTxType::Eip7702 => {
                let (tx, signature, hash) = TxEip7702::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SovaTypedTransaction::Eip7702(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            SovaTxType::Deposit => Ok(Self::new_unhashed(
                SovaTypedTransaction::Deposit(SovaTxDeposit::rlp_decode(buf)?),
                SovaTxDeposit::signature(),
            )),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        let (transaction, signature) = TxLegacy::rlp_decode_with_signature(buf)?;
        let signed_tx = Self::new_unhashed(SovaTypedTransaction::Legacy(transaction), signature);

        Ok(signed_tx)
    }
}

impl Transaction for SovaTransactionSigned {
    fn chain_id(&self) -> Option<u64> {
        self.deref().chain_id()
    }

    fn nonce(&self) -> u64 {
        self.deref().nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.deref().gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.deref().gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.deref().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.deref().max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.deref().max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.deref().priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.deref().effective_gas_price(base_fee)
    }

    fn effective_tip_per_gas(&self, base_fee: u64) -> Option<u128> {
        self.deref().effective_tip_per_gas(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.deref().is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.deref().kind()
    }

    fn is_create(&self) -> bool {
        self.deref().is_create()
    }

    fn value(&self) -> Uint<256, 4> {
        self.deref().value()
    }

    fn input(&self) -> &Bytes {
        self.deref().input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.deref().access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.deref().blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.deref().authorization_list()
    }
}

impl Typed2718 for SovaTransactionSigned {
    fn ty(&self) -> u8 {
        self.deref().ty()
    }
}

impl PartialEq for SovaTransactionSigned {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
            && self.transaction == other.transaction
            && self.tx_hash() == other.tx_hash()
    }
}

impl Hash for SovaTransactionSigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature.hash(state);
        self.transaction.hash(state);
    }
}

/// Calculates the signing hash for the transaction.
fn signature_hash(tx: &SovaTypedTransaction) -> B256 {
    match tx {
        SovaTypedTransaction::Legacy(tx) => tx.signature_hash(),
        SovaTypedTransaction::Eip2930(tx) => tx.signature_hash(),
        SovaTypedTransaction::Eip1559(tx) => tx.signature_hash(),
        SovaTypedTransaction::Eip4844(tx) => tx.signature_hash(),
        SovaTypedTransaction::Eip7702(tx) => tx.signature_hash(),
        SovaTypedTransaction::Deposit(_) => B256::ZERO, // Deposit transactions don't have a signature hash
    }
}

#[cfg(feature = "serde")]
mod serde_from {
    //! Support for tagged and untagged transaction deserialization.
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    #[serde(untagged)]
    pub(crate) enum MaybeTaggedTypedTransaction {
        Tagged(TaggedTypedTransaction),
        Untagged(TxLegacy),
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "type")]
    pub(crate) enum TaggedTypedTransaction {
        /// Legacy transaction
        #[serde(rename = "0x00", alias = "0x0")]
        Legacy(TxLegacy),
        /// EIP-2930 transaction
        #[serde(rename = "0x01", alias = "0x1")]
        Eip2930(TxEip2930),
        /// EIP-1559 transaction
        #[serde(rename = "0x02", alias = "0x2")]
        Eip1559(TxEip1559),
        /// EIP-4844 transaction
        #[serde(rename = "0x03", alias = "0x3")]
        Eip4844(TxEip4844),
        /// EIP-7702 transaction
        #[serde(rename = "0x04", alias = "0x4")]
        Eip7702(TxEip7702),
        /// Deposit transaction
        #[serde(
            rename = "0x7e",
            alias = "0x7E",
            serialize_with = "op_alloy_consensus::serde_deposit_tx_rpc"
        )]
        Deposit(SovaTxDeposit),
    }

    impl From<MaybeTaggedTypedTransaction> for SovaTypedTransaction {
        fn from(value: MaybeTaggedTypedTransaction) -> Self {
            match value {
                MaybeTaggedTypedTransaction::Tagged(tagged) => tagged.into(),
                MaybeTaggedTypedTransaction::Untagged(tx) => Self::Legacy(tx),
            }
        }
    }

    impl From<TaggedTypedTransaction> for SovaTypedTransaction {
        fn from(value: TaggedTypedTransaction) -> Self {
            match value {
                TaggedTypedTransaction::Legacy(tx) => Self::Legacy(tx),
                TaggedTypedTransaction::Eip2930(tx) => Self::Eip2930(tx),
                TaggedTypedTransaction::Eip1559(tx) => Self::Eip1559(tx),
                TaggedTypedTransaction::Eip4844(tx) => Self::Eip4844(tx),
                TaggedTypedTransaction::Eip7702(tx) => Self::Eip7702(tx),
                TaggedTypedTransaction::Deposit(tx) => Self::Deposit(tx),
            }
        }
    }

    impl From<SovaTypedTransaction> for TaggedTypedTransaction {
        fn from(value: SovaTypedTransaction) -> Self {
            match value {
                SovaTypedTransaction::Legacy(tx) => Self::Legacy(tx),
                SovaTypedTransaction::Eip2930(tx) => Self::Eip2930(tx),
                SovaTypedTransaction::Eip1559(tx) => Self::Eip1559(tx),
                SovaTypedTransaction::Eip4844(tx) => Self::Eip4844(tx),
                SovaTypedTransaction::Eip7702(tx) => Self::Eip7702(tx),
                SovaTypedTransaction::Deposit(tx) => Self::Deposit(tx),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex_literal::hex};

    #[test]
    fn test_deposit_transaction() {
        let from_addr = address!("0x1111111111111111111111111111111111111111");
        let to_addr = address!("0x2222222222222222222222222222222222222222");

        let tx = SovaTxDeposit {
            source_hash: B256::random(),
            from: from_addr,
            to: TxKind::Call(to_addr),
            mint: Some(1000),
            value: 5000.into(),
            gas_limit: 21000,
            is_system_transaction: false,
            input: Bytes::default(),
        };

        let signed_tx = SovaTransactionSigned::new_unhashed(
            SovaTypedTransaction::Deposit(tx.clone()),
            SovaTxDeposit::signature(),
        );

        assert!(signed_tx.is_deposit());
        assert_eq!(signed_tx.recover_signer().unwrap(), from_addr);
    }
}
