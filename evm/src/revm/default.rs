use op_revm::{L1BlockInfo, OpContext, OpSpecId, OpTransaction};
use reth_revm::db::EmptyDB;
use revm::{context::CfgEnv, Context, MainContext};

/// Trait that allows for a default context to be created.
pub trait DefaultSova {
    /// Create a default context.
    fn sova() -> OpContext<EmptyDB>;
}

impl DefaultSova for OpContext<EmptyDB> {
    fn sova() -> Self {
        Context::mainnet()
            .with_tx(OpTransaction::default())
            .with_cfg(CfgEnv::new_with_spec(OpSpecId::BEDROCK))
            .with_chain(L1BlockInfo::default())
    }
}
