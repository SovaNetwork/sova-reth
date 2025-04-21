use op_revm::{transaction::OpTxTr, L1BlockInfo, OpSpecId};
use revm::{
    context::{Cfg, JournalOutput, JournalTr},
    context_interface::Block,
    Context, Database, Inspector,
};

use crate::CustomPrecompiles;

use super::evm::SovaEvm;

/// Trait that allows for Sova EVM to be built from a context.
pub trait SovaBuilder: Sized {
    /// Type of the context.
    type Context;

    /// Build the Sova EVM with custom inspector and custom precompiles.
    fn build_sova_op_with_inspector<INSP: Inspector<Self::Context>>(
        self,
        inspector: INSP,
        precompiles: CustomPrecompiles,
    ) -> SovaEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, JOURNAL> SovaBuilder for Context<BLOCK, TX, CFG, DB, JOURNAL, L1BlockInfo>
where
    BLOCK: Block,
    TX: OpTxTr,
    CFG: Cfg<Spec = OpSpecId>,
    DB: Database,
    JOURNAL: JournalTr<Database = DB, FinalOutput = JournalOutput>,
{
    type Context = Self;

    fn build_sova_op_with_inspector<INSP>(
        self,
        inspector: INSP,
        precompiles: CustomPrecompiles,
    ) -> SovaEvm<Self::Context, INSP> {
        SovaEvm::new(self, inspector).with_precompiles(precompiles)
    }
}
