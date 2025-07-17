use revm::{
    context::{ContextSetters, ContextTr, Evm, FrameStack},
    handler::{
        evm::{ContextDbError, FrameInitResult},
        instructions::{EthInstructions, InstructionProvider},
        EthFrame, EvmTr, FrameInitOrResult, FrameTr, PrecompileProvider,
    },
    inspector::{InspectorEvmTr, JournalExt},
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    Inspector,
};

use crate::SovaPrecompiles;

/// Sova EVM implementation.
///
/// This is a wrapper type around the `revm` EVM with custom Bitcoin precompiles.
pub struct SovaEvm<CTX, INSP, I = EthInstructions<EthInterpreter, CTX>, P = SovaPrecompiles>(
    pub Evm<CTX, INSP, I, P, EthFrame<EthInterpreter>>,
);

impl<CTX: ContextTr, INSP>
    SovaEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, SovaPrecompiles>
{
    pub fn new(ctx: CTX, inspector: INSP) -> Self {
        Self(Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles: SovaPrecompiles::default(),
            frame_stack: FrameStack::new(),
        })
    }
}

impl<CTX, INSP, I, P> SovaEvm<CTX, INSP, I, P> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> SovaEvm<CTX, OINSP, I, P> {
        SovaEvm(self.0.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles<OP>(self, precompiles: OP) -> SovaEvm<CTX, INSP, I, OP> {
        SovaEvm(self.0.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> INSP {
        self.0.into_inspector()
    }
}

impl<CTX, INSP, I, P> InspectorEvmTr for SovaEvm<CTX, INSP, I, P>
where
    CTX: ContextTr<Journal: JournalExt> + ContextSetters,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
    INSP: Inspector<CTX, I::InterpreterTypes>,
{
    type Inspector = INSP;

    fn inspector(&mut self) -> &mut Self::Inspector {
        &mut self.0.inspector
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        (&mut self.0.ctx, &mut self.0.inspector)
    }

    fn ctx_inspector_frame(
        &mut self,
    ) -> (&mut Self::Context, &mut Self::Inspector, &mut Self::Frame) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
        )
    }

    fn ctx_inspector_frame_instructions(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Inspector,
        &mut Self::Frame,
        &mut Self::Instructions,
    ) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
            &mut self.0.instruction,
        )
    }
}

impl<CTX, INSP, I, P> EvmTr for SovaEvm<CTX, INSP, I, P>
where
    CTX: ContextTr,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Context = CTX;
    type Instructions = I;
    type Precompiles = P;
    type Frame = EthFrame<EthInterpreter>;

    #[inline]
    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.0.frame_stack
    }

    /// Initializes the frame for the given frame input. Frame is pushed to the frame stack.
    #[inline]
    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<FrameInitResult<'_, Self::Frame>, ContextDbError<CTX>> {
        let is_first_init = self.0.frame_stack.index().is_none();
        let new_frame = if is_first_init {
            self.0.frame_stack.start_init()
        } else {
            self.0.frame_stack.get_next()
        };

        let ctx = &mut self.0.ctx;
        let precompiles = &mut self.0.precompiles;
        let res = Self::Frame::init_with_context(new_frame, ctx, precompiles, frame_input)?;

        Ok(res.map_frame(|token| {
            if is_first_init {
                self.0.frame_stack.end_init(token);
            } else {
                self.0.frame_stack.push(token);
            }
            self.0.frame_stack.get()
        }))
    }

    /// Run the frame from the top of the stack. Returns the frame init or result.
    #[inline]
    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextDbError<CTX>> {
        let frame = self.0.frame_stack.get();
        let context = &mut self.0.ctx;
        let instructions = &mut self.0.instruction;

        let action = frame
            .interpreter
            .run_plain(instructions.instruction_table(), context);

        frame.process_next_action(context, action).inspect(|i| {
            if i.is_result() {
                frame.set_finished(true);
            }
        })
    }

    /// Returns the result of the frame to the caller. Frame is popped from the frame stack.
    #[inline]
    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextDbError<Self::Context>> {
        if self.0.frame_stack.get().is_finished() {
            self.0.frame_stack.pop();
        }
        if self.0.frame_stack.index().is_none() {
            return Ok(Some(result));
        }
        self.0
            .frame_stack
            .get()
            .return_result::<_, ContextDbError<Self::Context>>(&mut self.0.ctx, result)?;
        Ok(None)
    }

    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        &self.0.ctx
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        (&mut self.0.ctx, &mut self.0.instruction)
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        (&mut self.0.ctx, &mut self.0.precompiles)
    }
}
