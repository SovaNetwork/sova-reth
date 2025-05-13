//! Validates execution payload wrt Ethereum consensus rules and Execution Engine API version.

use std::sync::Arc;

use alloy_consensus::Block;
use alloy_rpc_types_engine::PayloadError;
use op_alloy_rpc_types_engine::{OpExecutionData, OpPayloadError};
use reth_chainspec::EthereumHardforks;
use reth_engine_primitives::{EngineValidator, PayloadValidator};
use reth_node_api::{BuiltPayload, NodePrimitives, PayloadTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::{OpBuiltPayload, OpPayloadAttributes, OpPayloadBuilderAttributes};
use reth_optimism_primitives::{OpBlock, OpPrimitives};
use reth_payload_primitives::{
    validate_version_specific_fields, EngineApiMessageVersion, EngineObjectValidationError,
    NewPayloadError, PayloadOrAttributes,
};
use reth_payload_validator::{cancun, prague, shanghai};
use reth_primitives_traits::{Block as _, RecoveredBlock, SealedBlock, SignedTransaction};

/// The types used in the Sova consensus engine
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SovaEngineTypes;

impl PayloadTypes for SovaEngineTypes {
    // Using standard Ethereum types for compatibility with Eth CL clients
    type ExecutionData = ExecutionData;
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = EthPayloadAttributes;
    type PayloadBuilderAttributes = EthPayloadBuilderAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        // Convert from Sova block type to standard Ethereum payload
        // This ensures compatibility with Ethereum consensus clients
        ExecutionData::from_block_unchecked(block.hash(), &block.into_block())
    }
}

impl EngineTypes for SovaEngineTypes {
    // Use standard Ethereum payload envelopes for compatibility with consensus clients
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

/// Validator for the ethereum engine API.
#[derive(Debug, Clone)]
pub struct SovaEngineValidator {
    inner: SovaExecutionPayloadValidator<OpChainSpec>,
}

impl SovaEngineValidator {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<OpChainSpec>) -> Self {
        Self {
            inner: SovaExecutionPayloadValidator::new(chain_spec),
        }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &OpChainSpec {
        self.inner.chain_spec()
    }
}

impl PayloadValidator for SovaEngineValidator {
    type Block = OpBlock;
    type ExecutionData = OpExecutionData;

    fn ensure_well_formed_payload(
        &self,
        payload: OpExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = self
            .inner
            .ensure_well_formed_payload(payload)
            .map_err(NewPayloadError::other)?;
        sealed_block
            .try_recover()
            .map_err(|e| NewPayloadError::Other(e.into()))
    }
}

impl<Types> EngineValidator<Types> for SovaEngineValidator
where
    Types: PayloadTypes<PayloadAttributes = OpPayloadAttributes, ExecutionData = OpExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Self::ExecutionData, OpPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        // payload_or_attrs
        //     .execution_requests()
        //     .map(|requests| validate_execution_requests(requests))
        //     .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &OpPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Self::ExecutionData, OpPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// Execution payload validator.
#[derive(Clone, Debug)]
pub struct SovaExecutionPayloadValidator<OpChainSpec> {
    /// Chain spec to validate against.
    chain_spec: Arc<OpChainSpec>,
}

impl<OpChainSpec> SovaExecutionPayloadValidator<OpChainSpec> {
    /// Create a new validator.
    pub const fn new(chain_spec: Arc<OpChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    pub const fn chain_spec(&self) -> &Arc<OpChainSpec> {
        &self.chain_spec
    }
}

impl<OpChainSpec: OpHardforks> SovaExecutionPayloadValidator<OpChainSpec> {
    /// Returns true if the Cancun hardfork is active at the given timestamp.
    #[inline]
    fn is_cancun_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.chain_spec().is_cancun_active_at_timestamp(timestamp)
    }

    /// Returns true if the Shanghai hardfork is active at the given timestamp.
    #[inline]
    fn is_shanghai_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.chain_spec().is_shanghai_active_at_timestamp(timestamp)
    }

    /// Returns true if the Prague hardfork is active at the given timestamp.
    #[inline]
    fn is_prague_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.chain_spec().is_prague_active_at_timestamp(timestamp)
    }

    /// Ensures that the given payload does not violate any consensus rules that concern the block's
    /// layout, like:
    ///    - missing or invalid base fee
    ///    - invalid extra data
    ///    - invalid transactions
    ///    - incorrect hash
    ///    - the versioned hashes passed with the payload do not exactly match transaction versioned
    ///      hashes
    ///    - the block does not contain blob transactions if it is pre-cancun
    ///
    /// The checks are done in the order that conforms with the engine-API specification.
    ///
    /// This is intended to be invoked after receiving the payload from the CLI.
    /// The additional [`MaybeCancunPayloadFields`](alloy_rpc_types_engine::MaybeCancunPayloadFields) are not part of the payload, but are additional fields in the `engine_newPayloadV3` RPC call, See also <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#engine_newpayloadv3>
    ///
    /// If the cancun fields are provided this also validates that the versioned hashes in the block
    /// match the versioned hashes passed in the
    /// [`CancunPayloadFields`](alloy_rpc_types_engine::CancunPayloadFields), if the cancun payload
    /// fields are provided. If the payload fields are not provided, but versioned hashes exist
    /// in the block, this is considered an error: [`PayloadError::InvalidVersionedHashes`].
    ///
    /// This validates versioned hashes according to the Engine API Cancun spec:
    /// <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification>
    pub fn ensure_well_formed_payload<T: SignedTransaction>(
        &self,
        payload: OpExecutionData,
    ) -> Result<SealedBlock<Block<T>>, OpPayloadError> {
        let OpExecutionData { payload, sidecar } = payload;

        let expected_hash = payload.block_hash();

        // First parse the block
        let sealed_block = payload.try_into_block_with_sidecar(&sidecar)?.seal_slow();

        // Ensure the hash included in the payload matches the block hash
        if expected_hash != sealed_block.hash() {
            return Err(OpPayloadError::from(PayloadError::BlockHash {
                execution: sealed_block.hash(),
                consensus: expected_hash,
            }));
        }

        shanghai::ensure_well_formed_fields(
            sealed_block.body(),
            self.is_shanghai_active_at_timestamp(sealed_block.timestamp),
        )?;

        cancun::ensure_well_formed_fields(
            &sealed_block,
            sidecar.canyon(),
            self.is_cancun_active_at_timestamp(sealed_block.timestamp),
        )?;

        prague::ensure_well_formed_fields(
            sealed_block.body(),
            sidecar.isthmus(),
            self.is_prague_active_at_timestamp(sealed_block.timestamp),
        )?;

        Ok(sealed_block)
    }
}
