use op_revm::{L1BlockInfo, OpSpecId, OpTransaction};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    database_interface::EmptyDB,
    Context, Journal, MainContext,
};

/// Type alias for the default context type of the SovaEvm.
pub type SovaContext<DB> =
    Context<BlockEnv, OpTransaction<TxEnv>, CfgEnv<OpSpecId>, DB, Journal<DB>, L1BlockInfo>;

/// Trait that allows for a default context to be created.
pub trait DefaultSova {
    /// Create a default context.
    fn sova() -> SovaContext<EmptyDB>;
}

impl DefaultSova for SovaContext<EmptyDB> {
    fn sova() -> Self {
        Context::mainnet()
            .with_tx(OpTransaction::default())
            .with_cfg(CfgEnv::new_with_spec(OpSpecId::BEDROCK))
            .with_chain(L1BlockInfo::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{sova_revm::builder::SovaBuilder, SovaPrecompiles};
    use revm::{
        inspector::{InspectEvm, NoOpInspector},
        ExecuteEvm,
    };

    #[test]
    fn default_run_sova() {
        let ctx = Context::sova();
        // convert to optimism context
        let mut evm = ctx
            .build_sova_op_with_inspector(NoOpInspector {})
            .with_precompiles(SovaPrecompiles::default().precompiles());
        // execute
        let _ = evm.replay();
        // inspect
        let _ = evm.inspect_one_tx(OpTransaction::default());
    }
}
