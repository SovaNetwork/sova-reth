use reth_ethereum::node::api::FullNodeTypes;
use reth_node_builder::{components::ExecutorBuilder, BuilderContext, NodeTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::OpPrimitives;
use std::{future, future::Future};

use crate::{build_slot_lock_manager, SovaEvmConfig};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SovaExecutorBuilder;

impl<Node: FullNodeTypes> ExecutorBuilder<Node> for SovaExecutorBuilder
where
    Node::Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
{
    type EVM = SovaEvmConfig;

    fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> impl Future<Output = eyre::Result<Self::EVM>> + Send {
        // TODO: Handle SlotLockManager creation error properly
        let slot_lock_mgr = build_slot_lock_manager().unwrap_or_else(|_| {
            tracing::warn!("Failed to build SlotLockManager, using stub");
            std::sync::Arc::new(slot_lock_manager::SlotLockManager::new(
                slot_lock_manager::SlotLockManagerConfig::default(),
                std::sync::Arc::new(slot_lock_manager::SentinelClientImpl::new(String::new())),
            ))
        });
        future::ready(Ok(SovaEvmConfig::new(ctx.chain_spec(), slot_lock_mgr)))
    }
}
