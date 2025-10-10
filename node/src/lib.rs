use op_alloy_network::Optimism;
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_ethereum::node::api::{FullNodeComponents, FullNodeTypes, NodeTypes};
use reth_node_builder::{
    components::{BasicPayloadServiceBuilder, ComponentsBuilder},
    DebugNode, Node, NodeAdapter, NodeComponentsBuilder,
};
use reth_op::{
    node::{
        node::{OpConsensusBuilder, OpNetworkBuilder, OpPayloadBuilder, OpPoolBuilder},
        OpAddOns, OpEngineApiBuilder, OpEngineValidatorBuilder, OpFullNodeTypes, OpNode,
        OpNodeTypes,
    },
    rpc::OpEthApiBuilder,
};
use reth_optimism_primitives::OpPrimitives;
use reth_payload_primitives::{PayloadAttributesBuilder, PayloadTypes};
use sova_chainspec::SovaChainSpec;
use sova_evm::SovaExecutorBuilder;
use std::sync::Arc;

pub mod args;
pub mod cli;

pub use args::SovaArgs;
pub use cli::Cli;

#[derive(Debug, Clone, Default)]
pub struct SovaNode {
    inner: OpNode,
}

impl NodeTypes for SovaNode {
    type Primitives = OpPrimitives;
    type ChainSpec = SovaChainSpec;
    type Storage = <OpNode as NodeTypes>::Storage;
    type Payload = <OpNode as NodeTypes>::Payload;
}

impl<N> Node<N> for SovaNode
where
    N: FullNodeTypes<Types: OpFullNodeTypes + OpNodeTypes>,
    N::Types: NodeTypes<ChainSpec = SovaChainSpec, Primitives = OpPrimitives>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        OpPoolBuilder,
        BasicPayloadServiceBuilder<OpPayloadBuilder>,
        OpNetworkBuilder,
        SovaExecutorBuilder,
        OpConsensusBuilder,
    >;

    type AddOns = OpAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
        OpEthApiBuilder<Optimism>,
        OpEngineValidatorBuilder,
        OpEngineApiBuilder<OpEngineValidatorBuilder>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(OpPoolBuilder::default())
            .executor(SovaExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(OpPayloadBuilder::new(
                false,
            )))
            .network(OpNetworkBuilder::new(false, false))
            .consensus(OpConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        self.inner.add_ons_builder().build()
    }
}

impl<N> DebugNode<N> for SovaNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block<op_alloy_consensus::OpTxEnvelope>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_node_api::BlockTy<Self> {
        rpc_block.into_consensus()
    }

    fn local_payload_attributes_builder(
        chain_spec: &<Self as NodeTypes>::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<<Self as NodeTypes>::Payload as PayloadTypes>::PayloadAttributes>
    {
        LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}
