pub mod tx;
pub use tx::{signed::SovaTransactionSigned, tx_type::SovaTxType};

pub use reth_ethereum_primitives::serde_bincode_compat::*;
use reth_primitives_traits::NodePrimitives;

/// Type alias for the ethereum block
pub type SovaBlock = alloy_consensus::Block<SovaTransactionSigned>;

/// Type alias for the ethereum blockbody
pub type SovaBlockBody = alloy_consensus::BlockBody<SovaTransactionSigned>;

/// Helper struct that specifies the ethereum
/// [`NodePrimitives`](reth_primitives_traits::NodePrimitives) types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[derive(serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct SovaPrimitives;

impl NodePrimitives for SovaPrimitives {
    type Block = SovaBlock;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = SovaBlockBody;
    type SignedTx = SovaTransactionSigned;
    type Receipt = reth_ethereum_primitives::Receipt;
}