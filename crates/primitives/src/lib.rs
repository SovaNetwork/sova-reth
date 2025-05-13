mod transaction;

pub use transaction::SovaReceipt;
pub use transaction::SovaTransactionSigned;

pub type SovaBlock = alloy_consensus::Block<SovaTransactionSigned>;

pub type SovaBlockBody = <SovaBlock as reth_primitives_traits::Block>::Body;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SovaPrimitives;

impl reth_primitives_traits::NodePrimitives for SovaPrimitives {
    type Block = SovaBlock;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = SovaBlockBody;
    type SignedTx = SovaTransactionSigned;
    type Receipt = SovaReceipt;
}

/// Bincode-compatible serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    pub use super::receipt::serde_bincode_compat::*;
    pub use op_alloy_consensus::serde_bincode_compat::*;
}
