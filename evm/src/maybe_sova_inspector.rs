use reth_revm::inspector::JournalExt;
use revm::context_interface::ContextTr;
use revm::inspector::NoOpInspector;
use revm::interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter};
use revm::primitives::{Log, B256};
use revm::Inspector;

// Import your SovaInspector (adjust path if needed)
use crate::inspector::SovaInspector;

/// Composite inspector that always invokes SovaInspector (if present)
/// and also forwards to a user-provided inspector (NoOpInspector).
#[derive(Debug)]
pub struct MaybeSovaInspector<U = NoOpInspector> {
    pub sova: Option<SovaInspector>,
    pub user: U,
}

impl<U> MaybeSovaInspector<U> {
    /// Create a new MaybeSovaInspector with no SovaInspector, only the user inspector
    pub fn empty(user: U) -> Self {
        Self { sova: None, user }
    }

    /// Create a new MaybeSovaInspector with both SovaInspector and user inspector
    pub fn with_sova(user: U, sova: SovaInspector) -> Self {
        Self {
            sova: Some(sova),
            user,
        }
    }

    /// Optional convenience to prep per-tx state on the Sova side
    pub fn prepare_for_tx(&mut self, _tx_hash: B256) {
        // Currently no per-tx preparation needed
        // This is a placeholder for future use if needed
    }

    /// Get a reference to the embedded SovaInspector if present
    pub fn sova(&self) -> Option<&SovaInspector> {
        self.sova.as_ref()
    }

    /// Get a mutable reference to the embedded SovaInspector if present
    pub fn sova_mut(&mut self) -> Option<&mut SovaInspector> {
        self.sova.as_mut()
    }
}

impl<CTX, U> Inspector<CTX> for MaybeSovaInspector<U>
where
    CTX: ContextTr<Journal: JournalExt>,
    U: Inspector<CTX>,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        if let Some(ref mut sova) = self.sova {
            sova.initialize_interp(interp, context);
        }
        self.user.initialize_interp(interp, context);
    }

    fn step(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        if let Some(ref mut sova) = self.sova {
            sova.step(interp, context);
        }
        self.user.step(interp, context);
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        if let Some(ref mut sova) = self.sova {
            sova.step_end(interp, context);
        }
        self.user.step_end(interp, context);
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // First let SovaInspector handle the call
        if let Some(ref mut sova) = self.sova {
            if let Some(outcome) = sova.call(context, inputs) {
                return Some(outcome);
            }
        }

        // If SovaInspector didn't return an outcome, let the user inspector handle it
        self.user.call(context, inputs)
    }

    fn call_end(&mut self, context: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        if let Some(ref mut sova) = self.sova {
            sova.call_end(context, inputs, outcome);
        }
        self.user.call_end(context, inputs, outcome);
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        // First let SovaInspector handle the create
        if let Some(ref mut sova) = self.sova {
            if let Some(outcome) = sova.create(context, inputs) {
                return Some(outcome);
            }
        }

        // If SovaInspector didn't return an outcome, let the user inspector handle it
        self.user.create(context, inputs)
    }

    fn create_end(
        &mut self,
        context: &mut CTX,
        inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(ref mut sova) = self.sova {
            sova.create_end(context, inputs, outcome);
        }
        self.user.create_end(context, inputs, outcome);
    }

    fn log(&mut self, interp: &mut Interpreter, context: &mut CTX, log: Log) {
        if let Some(ref mut sova) = self.sova {
            sova.log(interp, context, log.clone());
        }
        self.user.log(interp, context, log);
    }
}
