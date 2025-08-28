//! Optimism builder trait [`OpBuilder`] used to build [`OpEvm`].
use op_revm::{transaction::OpTxTr, L1BlockInfo, OpSpecId};
use revm::{
    context::Cfg,
    context_interface::{Block, JournalTr},
    handler::instructions::EthInstructions,
    interpreter::interpreter::EthInterpreter,
    state::EvmState,
    Context, Database,
};

use crate::{sova_revm::SovaRevmEvm, SovaPrecompiles};

/// Type alias for default SovaEvm
pub type DefaultSovaRevmEvm<CTX, INSP = ()> =
    SovaRevmEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, SovaPrecompiles>;

/// Trait that allows for optimism SovaEvm to be built
pub trait SovaBuilder: Sized {
    /// Type of the context.
    type Context;

    /// Build the sova.
    ///
    /// This method is kept to match the API from revm/op-revm crate:
    /// https://github.com/bluealloy/revm/blob/main/crates/op-revm/src/api/builder.rs
    #[allow(dead_code)]
    fn build_sova(self) -> DefaultSovaRevmEvm<Self::Context>;

    /// Build the sova with an inspector.
    fn build_sova_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultSovaRevmEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, JOURNAL> SovaBuilder for Context<BLOCK, TX, CFG, DB, JOURNAL, L1BlockInfo>
where
    BLOCK: Block,
    TX: OpTxTr,
    CFG: Cfg<Spec = OpSpecId>,
    DB: Database,
    JOURNAL: JournalTr<Database = DB, State = EvmState>,
{
    type Context = Self;

    #[allow(dead_code)]
    fn build_sova(self) -> DefaultSovaRevmEvm<Self::Context> {
        SovaRevmEvm::new(self, ())
    }

    fn build_sova_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultSovaRevmEvm<Self::Context, INSP> {
        SovaRevmEvm::new(self, inspector)
    }
}
