use std::{fmt::Debug, sync::Arc};

use alloy_consensus::{transaction::PooledTransaction, Signed, Typed2718};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2930::AccessList,
    eip4844::{
        env_settings::KzgSettings, BlobTransactionSidecar,
        BlobTransactionValidationError,
    },
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, Bytes, TxHash, TxKind, B256, U256};
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_primitives_traits::{
    transaction::error::TransactionConversionError, InMemorySize, Recovered,
    SignedTransaction,
};
use reth_transaction_pool::{EthBlobTransactionSidecar, EthPoolTransaction, PoolTransaction};

/// The default [`PoolTransaction`] for the [Pool](crate::Pool) for Sova.
///
/// This type is essentially a wrapper around [`Recovered`] with additional
/// fields derived from the transaction that are frequently used by the pools for ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovaPooledTransaction<T = TransactionSigned> {
    /// `EcRecovered` transaction, the consensus format.
    pub transaction: Recovered<T>,

    /// For EIP-1559 transactions: `max_fee_per_gas * gas_limit + tx_value`.
    /// For legacy transactions: `gas_price * gas_limit + tx_value`.
    /// For EIP-4844 blob transactions: `max_fee_per_gas * gas_limit + tx_value +
    /// max_blob_fee_per_gas * blob_gas_used`.
    pub cost: U256,

    /// This is the RLP length of the transaction, computed when the transaction is added to the
    /// pool.
    pub encoded_length: usize,

    /// The blob side car for this transaction
    pub blob_sidecar: EthBlobTransactionSidecar,
}

impl<T: SignedTransaction> SovaPooledTransaction<T> {
    /// Create new instance of [Self].
    ///
    /// Caution: In case of blob transactions, this does marks the blob sidecar as
    /// [`EthBlobTransactionSidecar::Missing`]
    pub fn new(transaction: Recovered<T>, encoded_length: usize) -> Self {
        let mut blob_sidecar = EthBlobTransactionSidecar::None;

        let gas_cost = U256::from(transaction.max_fee_per_gas())
            .saturating_mul(U256::from(transaction.gas_limit()));

        let mut cost = gas_cost.saturating_add(transaction.value());

        if let (Some(blob_gas_used), Some(max_fee_per_blob_gas)) =
            (transaction.blob_gas_used(), transaction.max_fee_per_blob_gas())
        {
            // Add max blob cost using saturating math to avoid overflow
            cost = cost.saturating_add(U256::from(
                max_fee_per_blob_gas.saturating_mul(blob_gas_used as u128),
            ));

            // because the blob sidecar is not included in this transaction variant, mark it as
            // missing
            blob_sidecar = EthBlobTransactionSidecar::Missing;
        }

        Self { transaction, cost, encoded_length, blob_sidecar }
    }

    /// Return the reference to the underlying transaction.
    pub const fn transaction(&self) -> &Recovered<T> {
        &self.transaction
    }
}

impl PoolTransaction for SovaPooledTransaction {
    type TryFromConsensusError = TransactionConversionError;

    type Consensus = TransactionSigned;

    type Pooled = PooledTransaction;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.transaction().clone()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.transaction
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_length = tx.encode_2718_len();
        let (tx, signer) = tx.into_parts();
        match tx {
            PooledTransaction::Eip4844(tx) => {
                // include the blob sidecar
                let (tx, sig, hash) = tx.into_parts();
                let (tx, blob) = tx.into_parts();
                let tx = Signed::new_unchecked(tx, sig, hash);
                let tx = TransactionSigned::from(tx);
                let tx = Recovered::new_unchecked(tx, signer);
                let mut pooled = Self::new(tx, encoded_length);
                pooled.blob_sidecar = EthBlobTransactionSidecar::Present(blob);
                pooled
            }
            tx => {
                // no blob sidecar
                let tx = Recovered::new_unchecked(tx.into(), signer);
                Self::new(tx, encoded_length)
            }
        }
    }

    /// Returns hash of the transaction.
    fn hash(&self) -> &TxHash {
        self.transaction.tx_hash()
    }

    /// Returns the Sender of the transaction.
    fn sender(&self) -> Address {
        self.transaction.signer()
    }

    /// Returns a reference to the Sender of the transaction.
    fn sender_ref(&self) -> &Address {
        self.transaction.signer_ref()
    }

    /// Returns the cost that this transaction is allowed to consume:
    ///
    /// For EIP-1559 transactions: `max_fee_per_gas * gas_limit + tx_value`.
    /// For legacy transactions: `gas_price * gas_limit + tx_value`.
    /// For EIP-4844 blob transactions: `max_fee_per_gas * gas_limit + tx_value +
    /// max_blob_fee_per_gas * blob_gas_used`.
    fn cost(&self) -> &U256 {
        &self.cost
    }

    /// Returns the length of the rlp encoded object
    fn encoded_length(&self) -> usize {
        self.encoded_length
    }
}

impl<T: Typed2718> Typed2718 for SovaPooledTransaction<T> {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl<T: InMemorySize> InMemorySize for SovaPooledTransaction<T> {
    fn size(&self) -> usize {
        self.transaction.size()
    }
}

impl<T: alloy_consensus::Transaction> alloy_consensus::Transaction for SovaPooledTransaction<T> {
    fn chain_id(&self) -> Option<alloy_primitives::ChainId> {
        self.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.transaction.kind()
    }

    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }

    fn value(&self) -> U256 {
        self.transaction.value()
    }

    fn input(&self) -> &Bytes {
        self.transaction.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl EthPoolTransaction for SovaPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        if self.is_eip4844() {
            std::mem::replace(&mut self.blob_sidecar, EthBlobTransactionSidecar::Missing)
        } else {
            EthBlobTransactionSidecar::None
        }
    }

    fn try_into_pooled_eip4844(
        self,
        sidecar: Arc<BlobTransactionSidecar>,
    ) -> Option<Recovered<Self::Pooled>> {
        let (signed_transaction, signer) = self.into_consensus().into_parts();
        let pooled_transaction =
            signed_transaction.try_into_pooled_eip4844(Arc::unwrap_or_clone(sidecar)).ok()?;

        Some(Recovered::new_unchecked(pooled_transaction, signer))
    }

    fn try_from_eip4844(
        tx: Recovered<Self::Consensus>,
        sidecar: BlobTransactionSidecar,
    ) -> Option<Self> {
        let (tx, signer) = tx.into_parts();
        tx.try_into_pooled_eip4844(sidecar)
            .ok()
            .map(|tx| tx.with_signer(signer))
            .map(Self::from_pooled)
    }

    fn validate_blob(
        &self,
        sidecar: &BlobTransactionSidecar,
        settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        match self.transaction.transaction() {
            Transaction::Eip4844(tx) => tx.validate_blob(sidecar, settings),
            _ => Err(BlobTransactionValidationError::NotBlobTransaction(self.ty())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy};
    use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
    use alloy_primitives::PrimitiveSignature as Signature;
    use reth_ethereum_primitives::{Transaction, TransactionSigned};
    use reth_transaction_pool::GetPooledTransactionLimit;

    #[test]
    fn test_eth_pooled_transaction_new_legacy() {
        // Create a legacy transaction with specific parameters
        let tx = Transaction::Legacy(TxLegacy {
            gas_price: 10,
            gas_limit: 1000,
            value: U256::from(100),
            ..Default::default()
        });
        let signature = Signature::test_signature();
        let signed_tx = TransactionSigned::new_unhashed(tx, signature);
        let transaction = Recovered::new_unchecked(signed_tx, Default::default());
        let pooled_tx = SovaPooledTransaction::new(transaction.clone(), 200);

        // Check that the pooled transaction is created correctly
        assert_eq!(pooled_tx.transaction, transaction);
        assert_eq!(pooled_tx.encoded_length, 200);
        assert_eq!(pooled_tx.blob_sidecar, EthBlobTransactionSidecar::None);
        assert_eq!(pooled_tx.cost, U256::from(100) + U256::from(10 * 1000));
    }

    #[test]
    fn test_eth_pooled_transaction_new_eip2930() {
        // Create an EIP-2930 transaction with specific parameters
        let tx = Transaction::Eip2930(TxEip2930 {
            gas_price: 10,
            gas_limit: 1000,
            value: U256::from(100),
            ..Default::default()
        });
        let signature = Signature::test_signature();
        let signed_tx = TransactionSigned::new_unhashed(tx, signature);
        let transaction = Recovered::new_unchecked(signed_tx, Default::default());
        let pooled_tx = SovaPooledTransaction::new(transaction.clone(), 200);

        // Check that the pooled transaction is created correctly
        assert_eq!(pooled_tx.transaction, transaction);
        assert_eq!(pooled_tx.encoded_length, 200);
        assert_eq!(pooled_tx.blob_sidecar, EthBlobTransactionSidecar::None);
        assert_eq!(pooled_tx.cost, U256::from(100) + U256::from(10 * 1000));
    }

    #[test]
    fn test_eth_pooled_transaction_new_eip1559() {
        // Create an EIP-1559 transaction with specific parameters
        let tx = Transaction::Eip1559(TxEip1559 {
            max_fee_per_gas: 10,
            gas_limit: 1000,
            value: U256::from(100),
            ..Default::default()
        });
        let signature = Signature::test_signature();
        let signed_tx = TransactionSigned::new_unhashed(tx, signature);
        let transaction = Recovered::new_unchecked(signed_tx, Default::default());
        let pooled_tx = SovaPooledTransaction::new(transaction.clone(), 200);

        // Check that the pooled transaction is created correctly
        assert_eq!(pooled_tx.transaction, transaction);
        assert_eq!(pooled_tx.encoded_length, 200);
        assert_eq!(pooled_tx.blob_sidecar, EthBlobTransactionSidecar::None);
        assert_eq!(pooled_tx.cost, U256::from(100) + U256::from(10 * 1000));
    }

    #[test]
    fn test_eth_pooled_transaction_new_eip4844() {
        // Create an EIP-4844 transaction with specific parameters
        let tx = Transaction::Eip4844(TxEip4844 {
            max_fee_per_gas: 10,
            gas_limit: 1000,
            value: U256::from(100),
            max_fee_per_blob_gas: 5,
            blob_versioned_hashes: vec![B256::default()],
            ..Default::default()
        });
        let signature = Signature::test_signature();
        let signed_tx = TransactionSigned::new_unhashed(tx, signature);
        let transaction = Recovered::new_unchecked(signed_tx, Default::default());
        let pooled_tx = SovaPooledTransaction::new(transaction.clone(), 300);

        // Check that the pooled transaction is created correctly
        assert_eq!(pooled_tx.transaction, transaction);
        assert_eq!(pooled_tx.encoded_length, 300);
        assert_eq!(pooled_tx.blob_sidecar, EthBlobTransactionSidecar::Missing);
        let expected_cost =
            U256::from(100) + U256::from(10 * 1000) + U256::from(5 * DATA_GAS_PER_BLOB);
        assert_eq!(pooled_tx.cost, expected_cost);
    }

    #[test]
    fn test_eth_pooled_transaction_new_eip7702() {
        // Init an EIP-7702 transaction with specific parameters
        let tx = Transaction::Eip7702(TxEip7702 {
            max_fee_per_gas: 10,
            gas_limit: 1000,
            value: U256::from(100),
            ..Default::default()
        });
        let signature = Signature::test_signature();
        let signed_tx = TransactionSigned::new_unhashed(tx, signature);
        let transaction = Recovered::new_unchecked(signed_tx, Default::default());
        let pooled_tx = SovaPooledTransaction::new(transaction.clone(), 200);

        // Check that the pooled transaction is created correctly
        assert_eq!(pooled_tx.transaction, transaction);
        assert_eq!(pooled_tx.encoded_length, 200);
        assert_eq!(pooled_tx.blob_sidecar, EthBlobTransactionSidecar::None);
        assert_eq!(pooled_tx.cost, U256::from(100) + U256::from(10 * 1000));
    }

    #[test]
    fn test_pooled_transaction_limit() {
        // No limit should never exceed
        let limit_none = GetPooledTransactionLimit::None;
        // Any size should return false
        assert!(!limit_none.exceeds(1000));

        // Size limit of 2MB (2 * 1024 * 1024 bytes)
        let size_limit_2mb = GetPooledTransactionLimit::ResponseSizeSoftLimit(2 * 1024 * 1024);

        // Test with size below the limit
        // 1MB is below 2MB, should return false
        assert!(!size_limit_2mb.exceeds(1024 * 1024));

        // Test with size exactly at the limit
        // 2MB equals the limit, should return false
        assert!(!size_limit_2mb.exceeds(2 * 1024 * 1024));

        // Test with size exceeding the limit
        // 3MB is above the 2MB limit, should return true
        assert!(size_limit_2mb.exceeds(3 * 1024 * 1024));
    }
}
