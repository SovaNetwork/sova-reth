//! Contains types required for building a payload.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use alloy_eips::{eip4844::BlobTransactionSidecar, eip7685::Requests};
use alloy_primitives::U256;
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadFieldV2, ExecutionPayloadV1, ExecutionPayloadV3, PayloadId,
};
use sova_primitives::{Block, SovaPrimitives};
use reth_payload_primitives::BuiltPayload;
use reth_primitives_traits::SealedBlock;

/// Contains the built payload.
///
/// According to the [engine API specification](https://github.com/ethereum/execution-apis/blob/main/src/engine/README.md) the execution layer should build the initial version of the payload with an empty transaction set and then keep update it in order to maximize the revenue.
/// Therefore, the empty-block here is always available and full-block will be set/updated
/// afterward.
#[derive(Debug, Clone)]
pub struct SovaBuiltPayload {
    /// Identifier of the payload
    pub(crate) id: PayloadId,
    /// The built block
    pub(crate) block: Arc<SealedBlock<Block>>,
    /// The fees of the block
    pub(crate) fees: U256,
    /// The blobs, proofs, and commitments in the block. If the block is pre-cancun, this will be
    /// empty.
    pub(crate) sidecars: Vec<BlobTransactionSidecar>,
    /// The requests of the payload
    pub(crate) requests: Option<Requests>,
}

// === impl BuiltPayload ===

impl SovaBuiltPayload {
    /// Initializes the payload with the given initial block
    ///
    /// Caution: This does not set any [`BlobTransactionSidecar`].
    pub const fn new(
        id: PayloadId,
        block: Arc<SealedBlock<Block>>,
        fees: U256,
        requests: Option<Requests>,
    ) -> Self {
        Self { id, block, fees, sidecars: Vec::new(), requests }
    }

    /// Returns the identifier of the payload.
    pub const fn id(&self) -> PayloadId {
        self.id
    }

    /// Returns the built block(sealed)
    pub fn block(&self) -> &SealedBlock<Block> {
        &self.block
    }

    /// Fees of the block
    pub const fn fees(&self) -> U256 {
        self.fees
    }

    /// Returns the blob sidecars.
    pub fn sidecars(&self) -> &[BlobTransactionSidecar] {
        &self.sidecars
    }

    /// Adds sidecars to the payload.
    pub fn extend_sidecars(&mut self, sidecars: impl IntoIterator<Item = BlobTransactionSidecar>) {
        self.sidecars.extend(sidecars)
    }

    /// Same as [`Self::extend_sidecars`] but returns the type again.
    pub fn with_sidecars(
        mut self,
        sidecars: impl IntoIterator<Item = BlobTransactionSidecar>,
    ) -> Self {
        self.extend_sidecars(sidecars);
        self
    }
}

impl BuiltPayload for SovaBuiltPayload {
    type Primitives = SovaPrimitives;

    fn block(&self) -> &SealedBlock<Block> {
        &self.block
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

// V1 engine_getPayloadV1 response
impl From<SovaBuiltPayload> for ExecutionPayloadV1 {
    fn from(value: SovaBuiltPayload) -> Self {
        Self::from_block_unchecked(
            value.block().hash(),
            &Arc::unwrap_or_clone(value.block).into_block(),
        )
    }
}

// V2 engine_getPayloadV2 response
impl From<SovaBuiltPayload> for ExecutionPayloadEnvelopeV2 {
    fn from(value: SovaBuiltPayload) -> Self {
        let SovaBuiltPayload { block, fees, .. } = value;

        Self {
            block_value: fees,
            execution_payload: ExecutionPayloadFieldV2::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
        }
    }
}

impl From<SovaBuiltPayload> for ExecutionPayloadEnvelopeV3 {
    fn from(value: SovaBuiltPayload) -> Self {
        let SovaBuiltPayload { block, fees, sidecars, .. } = value;

        Self {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            // From the engine API spec:
            //
            // > Client software **MAY** use any heuristics to decide whether to set
            // `shouldOverrideBuilder` flag or not. If client software does not implement any
            // heuristic this flag **SHOULD** be set to `false`.
            //
            // Spec:
            // <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification-2>
            should_override_builder: false,
            blobs_bundle: sidecars.into(),
        }
    }
}

impl From<SovaBuiltPayload> for ExecutionPayloadEnvelopeV4 {
    fn from(value: SovaBuiltPayload) -> Self {
        Self {
            execution_requests: value.requests.clone().unwrap_or_default(),
            envelope_inner: value.into(),
        }
    }
}