//! Sova specific engine API types and impls.

mod payload;
use std::sync::Arc;

pub use payload::{SovaBuiltPayload, SovaPayloadBuilderAttributes};

extern crate alloc;

use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload};
pub use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes,
};
use reth::{
    api::{FullNodeComponents, NodeTypes},
    builder::rpc::EngineValidatorBuilder,
};
use reth_chainspec::ChainSpec;
use reth_engine_primitives::EngineTypes;
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, SealedBlock};
use sova_primitives::{SovaBlock, SovaPrimitives};

/// The types used in the default mainnet sova beacon consensus engine.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SovaEngineTypes<T: PayloadTypes = SovaPayloadTypes> {
    _marker: core::marker::PhantomData<T>,
}

impl<
        T: PayloadTypes<
            ExecutionData = ExecutionData,
            BuiltPayload: BuiltPayload<Primitives: NodePrimitives<Block = SovaBlock>>,
        >,
    > PayloadTypes for SovaEngineTypes<T>
{
    type ExecutionData = T::ExecutionData;
    type BuiltPayload = T::BuiltPayload;
    type PayloadAttributes = T::PayloadAttributes;
    type PayloadBuilderAttributes = T::PayloadBuilderAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        ExecutionData { payload, sidecar }
    }
}

impl<T: PayloadTypes<ExecutionData = ExecutionData>> EngineTypes for SovaEngineTypes<T>
where
    T::BuiltPayload: BuiltPayload<Primitives: NodePrimitives<Block = SovaBlock>>
        + TryInto<ExecutionPayloadV1>
        + TryInto<ExecutionPayloadEnvelopeV2>
        + TryInto<ExecutionPayloadEnvelopeV3>
        + TryInto<ExecutionPayloadEnvelopeV4>,
{
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

/// A default payload type for [`SovaEngineTypes`]
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SovaPayloadTypes<N: NodePrimitives = SovaPrimitives>(core::marker::PhantomData<N>);

impl<N: NodePrimitives> PayloadTypes for SovaPayloadTypes<N>
where
    SovaBuiltPayload<N>: BuiltPayload<Primitives: NodePrimitives<Block = SovaBlock>>,
{
    type ExecutionData = ExecutionData;
    type BuiltPayload = SovaBuiltPayload<N>;
    type PayloadAttributes = EthPayloadAttributes;
    type PayloadBuilderAttributes = SovaPayloadBuilderAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        ExecutionData { payload, sidecar }
    }
}
