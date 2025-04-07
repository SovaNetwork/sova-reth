//! A signed Sova transaction.

extern crate alloc;

use alloc::vec::Vec;
use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx}, Sealed, SignableTransaction, Signed, Transaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy, Typed2718
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{
    keccak256, Address, Bytes, PrimitiveSignature as Signature, TxHash, TxKind, Uint, B256,
};
use alloy_rlp::Header;
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::{error::TransactionConversionError, signed::RecoveryError},
    InMemorySize, SignedTransaction,
};
use reth_revm::context::TxEnv;

use crate::SovaTxType;

use super::{envelope::SovaTxEnvelope, l1_block::TxL1Block, pooled::SovaPooledTransaction, typed::SovaTypedTransaction, DepositTransactionParts, SovaTransaction};

/// Signed transaction.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Debug, Clone, Eq, derive_more::AsRef, derive_more::Deref)]
pub struct SovaTransactionSigned {
    /// Transaction hash
    #[serde(skip)]
    hash: OnceLock<TxHash>,
    /// The transaction signature values
    signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    transaction: SovaTypedTransaction,
}

impl SovaTransactionSigned {
    /// Creates a new signed transaction from the given transaction, signature and hash.
    pub fn new(transaction: SovaTypedTransaction, signature: Signature, hash: B256) -> Self {
        Self { hash: hash.into(), signature, transaction }
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
        Self { hash: Default::default(), signature, transaction }
    }

    /// Returns whether this transaction is a deposit.
    pub const fn is_l1_block(&self) -> bool {
        matches!(self.transaction, SovaTypedTransaction::L1Block(_))
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (SovaTypedTransaction, Signature, B256) {
        let hash = *self.hash.get_or_init(|| self.recalculate_hash());
        (self.transaction, self.signature, hash)
    }

    /// Returns the [`TxEip4844`] if the transaction is an EIP-4844 transaction.
    pub const fn as_eip4844(&self) -> Option<&TxEip4844> {
        match &self.transaction {
            SovaTypedTransaction::Eip4844(tx) => Some(tx),
            _ => None,
        }
    }
}

impl SignedTransaction for SovaTransactionSigned {
    fn tx_hash(&self) -> &TxHash {
        self.hash.get_or_init(|| self.recalculate_hash())
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        if let SovaTypedTransaction::L1Block(TxL1Block { from, .. }) = self.transaction {
            return Ok(from)
        }

        let Self { transaction, signature, .. } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer(signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        if let SovaTypedTransaction::L1Block(TxL1Block { from, .. }) = &self.transaction {
            return Ok(*from)
        }

        let Self { transaction, signature, .. } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer_unchecked(signature, signature_hash)
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        match &self.transaction {
            // Optimism's Deposit transaction does not have a signature. Directly return the
            // `from` address.
            SovaTypedTransaction::L1Block(tx) => return Ok(tx.from),
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

impl_from_signed!(TxLegacy, TxEip2930, TxEip1559, TxEip4844, TxEip7702, SovaTypedTransaction);

impl From<SovaTxEnvelope> for SovaTransactionSigned {
    fn from(value: SovaTxEnvelope) -> Self {
        match value {
            SovaTxEnvelope::Legacy(tx) => tx.into(),
            SovaTxEnvelope::Eip2930(tx) => tx.into(),
            SovaTxEnvelope::Eip1559(tx) => tx.into(),
            SovaTxEnvelope::Eip4844(tx) => tx.into(),
            SovaTxEnvelope::Eip7702(tx) => tx.into(),
            SovaTxEnvelope::L1Block(tx) => tx.into(),
        }
    }
}

impl From<SovaTransactionSigned> for SovaTxEnvelope {
    fn from(value: SovaTransactionSigned) -> Self {
        let (tx, signature, hash) = value.into_parts();
        match tx {
            SovaTypedTransaction::Legacy(tx) => Signed::new_unchecked(tx, signature, hash).into(),
            SovaTypedTransaction::Eip2930(tx) => Signed::new_unchecked(tx, signature, hash).into(),
            SovaTypedTransaction::Eip1559(tx) => Signed::new_unchecked(tx, signature, hash).into(),
            SovaTypedTransaction::Eip4844(tx) => Signed::new_unchecked(tx, signature, hash).into(),
            SovaTypedTransaction::L1Block(tx) => Sealed::new_unchecked(tx, hash).into(),
            SovaTypedTransaction::Eip7702(tx) => Signed::new_unchecked(tx, signature, hash).into(),
        }
    }
}

impl From<SovaTransactionSigned> for Signed<SovaTypedTransaction> {
    fn from(value: SovaTransactionSigned) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new_unchecked(tx, sig, hash)
    }
}

impl From<Sealed<TxL1Block>> for SovaTransactionSigned {
    fn from(value: Sealed<TxL1Block>) -> Self {
        let (tx, hash) = value.into_parts();
        Self::new(SovaTypedTransaction::L1Block(tx), TxL1Block::signature(), hash)
    }
}

/// A trait that represents an optimism transaction, mainly used to indicate whether or not the
/// transaction is a deposit transaction.
pub trait SovaTransactionTr {
    /// Whether or not the transaction is a L1 Bitcoin block context transaction.
    fn is_l1_block(&self) -> bool;
}

impl SovaTransactionTr for SovaTransactionSigned {
    fn is_l1_block(&self) -> bool {
        self.is_l1_block()
    }
}

impl FromRecoveredTx<SovaTransactionSigned> for SovaTransaction<TxEnv> {
    fn from_recovered_tx(tx: &SovaTransactionSigned, sender: Address) -> Self {
        let envelope = tx.encoded_2718();

        let base = match &tx.transaction {
            SovaTypedTransaction::Legacy(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                gas_priority_fee: None,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: tx.chain_id,
                nonce: tx.nonce,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 0,
                caller: sender,
            },
            SovaTypedTransaction::Eip2930(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                gas_priority_fee: None,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 1,
                caller: sender,
            },
            SovaTypedTransaction::Eip1559(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 2,
                caller: sender,
            },
            SovaTypedTransaction::Eip4844(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                kind: TxKind::Call(tx.to),
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: tx.blob_versioned_hashes.clone(),
                max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
                authorization_list: Default::default(),
                tx_type: 3,
                caller: sender,
            },
            SovaTypedTransaction::Eip7702(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                kind: TxKind::Call(tx.to),
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: tx.authorization_list.clone(),
                tx_type: 4,
                caller: sender,
            },
            SovaTypedTransaction::L1Block(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: 0,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: None,
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                gas_priority_fee: Default::default(),
                tx_type: 126,
                caller: sender,
            },
        };

        Self {
            base,
            enveloped_tx: Some(envelope.into()),
            deposit: if let SovaTypedTransaction::L1Block(tx) = &tx.transaction {
                DepositTransactionParts {
                    is_system_transaction: tx.is_system_transaction,
                    source_hash: tx.source_hash,
                    // For consistency with op-geth, we always return `0x0` for mint if it is
                    // missing This is because op-geth does not distinguish
                    // between null and 0, because this value is decoded from RLP where null is
                    // represented as 0
                    mint: Some(tx.mint.unwrap_or_default()),
                }
            } else {
                Default::default()
            },
        }
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
            payload_length += Header { list: false, payload_length }.length();
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
            SovaTypedTransaction::Eip4844(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encoded_length(&self.signature)
            }
            SovaTypedTransaction::L1Block(deposit_tx) => deposit_tx.eip2718_encoded_length(),
        }
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        let Self { transaction, signature, .. } = self;

        match &transaction {
            SovaTypedTransaction::Legacy(legacy_tx) => {
                // do nothing w/ with_header
                legacy_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip4844(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encode(signature, out)
            }
            SovaTypedTransaction::Eip7702(set_code_tx) => set_code_tx.eip2718_encode(signature, out),
            SovaTypedTransaction::L1Block(deposit_tx) => deposit_tx.encode_2718(out),
        }
    }
}

impl Decodable2718 for SovaTransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        match ty.try_into().map_err(|_| Eip2718Error::UnexpectedType(ty))? {
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
            SovaTxType::L1Block => Ok(Self::new_unhashed(
                SovaTypedTransaction::L1Block(TxL1Block::rlp_decode(buf)?),
                TxL1Block::signature(),
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
        self.signature == other.signature &&
            self.transaction == other.transaction &&
            self.tx_hash() == other.tx_hash()
    }
}

impl Hash for SovaTransactionSigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature.hash(state);
        self.transaction.hash(state);
    }
}

/// Compact encoding for `SovaTransactionSigned`
/// NOTE: This code deviates from the original `reth` implementation. This implementation
/// has been simplified and removes the need for an additional sova_codecs module.
impl reth_codecs::Compact for SovaTransactionSigned {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        // Store the starting position of the buffer
        let start = buf.as_mut().len();
        
        // Write a placeholder for the bitflags
        buf.put_u8(0);
        
        // Compact-encode the signature and get the signature bit
        let sig_bit = self.signature.to_compact(buf) as u8;
        
        // Compact-encode the transaction and get the transaction type bits
        let tx_bits = match &self.transaction {
            SovaTypedTransaction::Legacy(tx) => {
                tx.to_compact(buf);
                SovaTxType::Legacy as u8
            },
            SovaTypedTransaction::Eip2930(tx) => {
                tx.to_compact(buf);
                SovaTxType::Eip2930 as u8
            },
            SovaTypedTransaction::Eip1559(tx) => {
                tx.to_compact(buf);
                SovaTxType::Eip1559 as u8
            },
            SovaTypedTransaction::Eip4844(tx) => {
                tx.to_compact(buf);
                SovaTxType::Eip4844 as u8
            },
            SovaTypedTransaction::Eip7702(tx) => {
                tx.to_compact(buf);
                SovaTxType::Eip7702 as u8
            },
            SovaTypedTransaction::L1Block(tx) => {
                tx.to_compact(buf);
                SovaTxType::L1Block as u8
            },
        };
        
        // Update the bitflags byte with actual values
        // Format: [SignatureBit(1bit) | TransactionTypeBits(3bits)]
        buf.as_mut()[start] = sig_bit | (tx_bits << 1);
        
        // Return the number of bytes written
        buf.as_mut().len() - start
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {       
        let mut remaining = buf;
        
        // Read the bitflags byte
        let bitflags = remaining[0] as usize;
        remaining = &remaining[1..];
        
        // Extract the signature bit and decode the signature
        let sig_bit = bitflags & 1;
        let (signature, updated) = Signature::from_compact(remaining, sig_bit);
        remaining = updated;
        
        // Extract the transaction type bits
        let tx_type_bits = (bitflags >> 1) & 0b111;
        
        // Convert to SovaTxType
        let tx_type = match SovaTxType::try_from(tx_type_bits) {
            Ok(ty) => ty,
            Err(err) => panic!("{}", err), // Or handle more gracefully
        };
        
        // Decode the appropriate transaction type
        let (transaction, remaining) = match tx_type {
            SovaTxType::Legacy => {
                let (tx, updated) = TxLegacy::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::Legacy(tx), updated)
            },
            SovaTxType::Eip2930 => {
                let (tx, updated) = TxEip2930::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::Eip2930(tx), updated)
            },
            SovaTxType::Eip1559 => {
                let (tx, updated) = TxEip1559::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::Eip1559(tx), updated)
            },
            SovaTxType::Eip4844 => {
                let (tx, updated) = TxEip4844::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::Eip4844(tx), updated)
            },
            SovaTxType::Eip7702 => {
                let (tx, updated) = TxEip7702::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::Eip7702(tx), updated)
            },
            SovaTxType::L1Block => {
                let (tx, updated) = TxL1Block::from_compact(remaining, remaining.len());
                (SovaTypedTransaction::L1Block(tx), updated)
            },
        };
        
        // Return the constructed transaction and the remaining buffer
        (Self { 
            hash: Default::default(), 
            signature, 
            transaction 
        }, remaining)
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
        SovaTypedTransaction::L1Block(_) => B256::ZERO,
    }
}

/// Returns `true` if transaction is deposit transaction.
pub const fn is_l1_block(tx: &SovaTypedTransaction) -> bool {
    matches!(tx, SovaTypedTransaction::L1Block(_))
}

impl From<SovaPooledTransaction> for SovaTransactionSigned {
    fn from(value: SovaPooledTransaction) -> Self {
        match value {
            SovaPooledTransaction::Legacy(tx) => tx.into(),
            SovaPooledTransaction::Eip2930(tx) => tx.into(),
            SovaPooledTransaction::Eip1559(tx) => tx.into(),
            SovaPooledTransaction::Eip4844(tx) => tx.into(),
            SovaPooledTransaction::Eip7702(tx) => tx.into(),
        }
    }
}

impl TryFrom<SovaTransactionSigned> for SovaPooledTransaction {
    type Error = TransactionConversionError;

    fn try_from(value: SovaTransactionSigned) -> Result<Self, Self::Error> {
        let hash = *value.tx_hash();
        let SovaTransactionSigned { hash: _, signature, transaction } = value;

        match transaction {
            SovaTypedTransaction::Legacy(tx) => {
                Ok(Self::Legacy(Signed::new_unchecked(tx, signature, hash)))
            }
            SovaTypedTransaction::Eip2930(tx) => {
                Ok(Self::Eip2930(Signed::new_unchecked(tx, signature, hash)))
            }
            SovaTypedTransaction::Eip1559(tx) => {
                Ok(Self::Eip1559(Signed::new_unchecked(tx, signature, hash)))
            }
            SovaTypedTransaction::Eip4844(tx) => {
                Ok(Self::Eip4844(Signed::new_unchecked(tx, signature, hash)))
            }
            SovaTypedTransaction::Eip7702(tx) => {
                Ok(Self::Eip7702(Signed::new_unchecked(tx, signature, hash)))
            }
            SovaTypedTransaction::L1Block(_) => Err(TransactionConversionError::UnsupportedForP2P),
        }
    }
}

pub mod serde_bincode_compat {
    extern crate alloc;

    use alloc::borrow::Cow;
    use alloy_consensus::{transaction::serde_bincode_compat::{
        TxEip1559, TxEip2930, TxEip7702, TxLegacy,
    }, TxEip4844};
    use alloy_primitives::{PrimitiveSignature as Signature, TxHash};
    use reth_primitives_traits::{serde_bincode_compat::SerdeBincodeCompat, SignedTransaction};
    use serde::{Deserialize, Serialize};

    use crate::tx::l1_block::serde_bincode_compat;

    /// Bincode-compatible [`super::SovaTypedTransaction`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(missing_docs)]
    enum SovaTypedTransaction<'a> {
        Legacy(TxLegacy<'a>),
        Eip2930(TxEip2930<'a>),
        Eip1559(TxEip1559<'a>),
        Eip4844(Cow<'a, TxEip4844>),
        Eip7702(TxEip7702<'a>),
        L1Block(serde_bincode_compat::TxL1Block<'a>),
    }

    impl<'a> From<&'a super::SovaTypedTransaction> for SovaTypedTransaction<'a> {
        fn from(value: &'a super::SovaTypedTransaction) -> Self {
            match value {
                super::SovaTypedTransaction::Legacy(tx) => Self::Legacy(TxLegacy::from(tx)),
                super::SovaTypedTransaction::Eip2930(tx) => Self::Eip2930(TxEip2930::from(tx)),
                super::SovaTypedTransaction::Eip1559(tx) => Self::Eip1559(TxEip1559::from(tx)),
                super::SovaTypedTransaction::Eip4844(tx) => Self::Eip4844(Cow::Borrowed(tx)),
                super::SovaTypedTransaction::Eip7702(tx) => Self::Eip7702(TxEip7702::from(tx)),
                super::SovaTypedTransaction::L1Block(tx) => {
                    Self::L1Block(serde_bincode_compat::TxL1Block::from(tx))
                }
            }
        }
    }

    impl<'a> From<SovaTypedTransaction<'a>> for super::SovaTypedTransaction {
        fn from(value: SovaTypedTransaction<'a>) -> Self {
            match value {
                SovaTypedTransaction::Legacy(tx) => Self::Legacy(tx.into()),
                SovaTypedTransaction::Eip2930(tx) => Self::Eip2930(tx.into()),
                SovaTypedTransaction::Eip1559(tx) => Self::Eip1559(tx.into()),
                SovaTypedTransaction::Eip4844(tx) => Self::Eip4844(tx.into_owned()),
                SovaTypedTransaction::Eip7702(tx) => Self::Eip7702(tx.into()),
                SovaTypedTransaction::L1Block(tx) => Self::L1Block(tx.into()),
            }
        }
    }

    /// Bincode-compatible [`super::OpTransactionSigned`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SovaTransactionSigned<'a> {
        hash: TxHash,
        signature: Signature,
        transaction: SovaTypedTransaction<'a>,
    }

    impl<'a> From<&'a super::SovaTransactionSigned> for SovaTransactionSigned<'a> {
        fn from(value: &'a super::SovaTransactionSigned) -> Self {
            Self {
                hash: *value.tx_hash(),
                signature: value.signature,
                transaction: SovaTypedTransaction::from(&value.transaction),
            }
        }
    }

    impl<'a> From<SovaTransactionSigned<'a>> for super::SovaTransactionSigned {
        fn from(value: SovaTransactionSigned<'a>) -> Self {
            Self {
                hash: value.hash.into(),
                signature: value.signature,
                transaction: value.transaction.into(),
            }
        }
    }

    impl SerdeBincodeCompat for super::SovaTransactionSigned {
        type BincodeRepr<'a> = SovaTransactionSigned<'a>;

        fn as_repr(&self) -> Self::BincodeRepr<'_> {
            self.into()
        }

        fn from_repr(repr: Self::BincodeRepr<'_>) -> Self {
            repr.into()
        }
    }
}