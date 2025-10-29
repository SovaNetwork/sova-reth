mod abi;
mod address_deriver;
mod bitcoin_precompile;
mod btc_client;
mod precompile_utils;

use std::borrow::Cow;

pub use bitcoin_precompile::BitcoinRpcPrecompile;
pub use precompile_utils::BitcoinMethodHelper;

use once_cell::race::OnceBox;

use op_revm::{precompiles::OpPrecompiles, OpSpecId};
use revm_precompile::{
    u64_to_address, Precompile, PrecompileId, PrecompileOutput, PrecompileResult, Precompiles,
};

use revm::{
    context::{Cfg, ContextTr},
    handler::PrecompileProvider,
    interpreter::{InputsImpl, InterpreterResult},
};
use sova_chainspec::{
    BROADCAST_TRANSACTION_PRECOMPILE_ID, CONVERT_ADDRESS_PRECOMPILE_ID,
    DECODE_TRANSACTION_PRECOMPILE_ID, SOVA_BTC_CONTRACT_ADDRESS,
};

use crate::SovaSpecId;

/// Bitcoin transaction broadcast precompile
pub fn bitcoin_broadcast_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
    // Caller validation is handled by SovaInspector before this function is called
    match BitcoinRpcPrecompile::run_broadcast_transaction(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(output.gas_used, output.bytes)),
        Err(e) => Err(e),
    }
}

/// Bitcoin transaction decode precompile
pub fn bitcoin_decode_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
    match BitcoinRpcPrecompile::run_decode_transaction(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(output.gas_used, output.bytes)),
        Err(e) => Err(e),
    }
}

/// Bitcoin address conversion precompile (pre-Beta)
pub fn bitcoin_convert_address(input: &[u8], gas_limit: u64) -> PrecompileResult {
    match BitcoinRpcPrecompile::run_convert_address(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(output.gas_used, output.bytes)),
        Err(e) => Err(e),
    }
}

/// Bitcoin address conversion precompile (Beta - uses Beta XPUB)
pub fn bitcoin_convert_address_beta(input: &[u8], gas_limit: u64) -> PrecompileResult {
    match BitcoinRpcPrecompile::run_convert_address_beta(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(output.gas_used, output.bytes)),
        Err(e) => Err(e),
    }
}

/// Precompile constants for Bitcoin precompiles
pub const BITCOIN_BROADCAST: Precompile = Precompile::new(
    PrecompileId::Custom(Cow::Borrowed("bitcoin_broadcast")),
    u64_to_address(BROADCAST_TRANSACTION_PRECOMPILE_ID),
    bitcoin_broadcast_transaction,
);

pub const BITCOIN_DECODE: Precompile = Precompile::new(
    PrecompileId::Custom(Cow::Borrowed("bitcoin_decode")),
    u64_to_address(DECODE_TRANSACTION_PRECOMPILE_ID),
    bitcoin_decode_transaction,
);

/// Bitcoin address conversion precompile (pre-Beta)
pub const BITCOIN_CONVERT: Precompile = Precompile::new(
    PrecompileId::Custom(Cow::Borrowed("bitcoin_convert")),
    u64_to_address(CONVERT_ADDRESS_PRECOMPILE_ID),
    bitcoin_convert_address,
);

/// Bitcoin address conversion precompile (Beta - uses Beta XPUB)
pub const BITCOIN_CONVERT_BETA: Precompile = Precompile::new(
    PrecompileId::Custom(Cow::Borrowed("bitcoin_convert_beta")),
    u64_to_address(CONVERT_ADDRESS_PRECOMPILE_ID),
    bitcoin_convert_address_beta,
);

/// SovaPrecompiles - extends OpPrecompiles with Bitcoin functionality
#[derive(Debug, Clone)]
pub struct SovaPrecompiles {
    /// Inner precompile provider based on OpPrecompiles.
    inner: OpPrecompiles,
    /// Spec id of the precompile provider.
    spec: SovaSpecId,
}

impl SovaPrecompiles {
    /// Create a new precompile provider with the given SovaSpecId.
    #[inline]
    pub fn new_with_spec(spec: SovaSpecId) -> Self {
        Self {
            inner: OpPrecompiles::new_with_spec(spec.op_spec()),
            spec,
        }
    }

    /// Getter for the Beta hardfork status.
    #[inline]
    pub fn is_beta_active(&self) -> bool {
        self.spec.is_beta_active()
    }

    /// Getter for the spec.
    #[inline]
    pub fn spec(&self) -> SovaSpecId {
        self.spec
    }

    /// Precompiles getter.
    #[inline]
    pub fn precompiles(&self) -> &'static Precompiles {
        self.inner.precompiles()
    }

    /// Returns precompiles for Satoshi hardfork.
    ///
    /// If Beta hardfork is active, uses BITCOIN_CONVERT_BETA which uses the Beta XPUB.
    /// Otherwise, uses BITCOIN_CONVERT which uses the standard mainnet XPUB.
    pub fn satoshi(spec: SovaSpecId) -> &'static Precompiles {
        if spec.is_beta_active() {
            Self::satoshi_beta(spec.op_spec())
        } else {
            Self::satoshi_pre_beta(spec.op_spec())
        }
    }

    /// Returns precompiles for Satoshi hardfork pre-Beta (uses standard mainnet XPUB)
    fn satoshi_pre_beta(op_spec: OpSpecId) -> &'static Precompiles {
        static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
        INSTANCE.get_or_init(|| {
            let mut all_precompiles = OpPrecompiles::new_with_spec(op_spec).precompiles().clone();

            // Extend with Bitcoin precompiles for Satoshi fork (pre-Beta)
            all_precompiles.extend([BITCOIN_BROADCAST, BITCOIN_CONVERT, BITCOIN_DECODE]);

            Box::new(all_precompiles)
        })
    }

    /// Returns precompiles for Satoshi hardfork post-Beta (uses Beta mainnet XPUB)
    fn satoshi_beta(op_spec: OpSpecId) -> &'static Precompiles {
        static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
        INSTANCE.get_or_init(|| {
            let mut all_precompiles = OpPrecompiles::new_with_spec(op_spec).precompiles().clone();

            // Extend with Bitcoin precompiles for Satoshi fork (Beta)
            // Use BITCOIN_CONVERT_BETA instead of BITCOIN_CONVERT
            all_precompiles.extend([BITCOIN_BROADCAST, BITCOIN_CONVERT_BETA, BITCOIN_DECODE]);

            Box::new(all_precompiles)
        })
    }
}

impl Default for SovaPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(SovaSpecId::default())
    }
}

// Implementation of PrecompileProvider trait for SovaPrecompiles
impl<CTX> PrecompileProvider<CTX> for SovaPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = OpSpecId>>,
{
    type Output = InterpreterResult;

    #[inline]
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        // We need to convert OpSpecId to SovaSpecId, but we don't have block context here
        // For now, preserve existing Beta status when spec changes
        let sova_spec = SovaSpecId::new(spec, self.spec.is_beta_active());

        if sova_spec == self.spec {
            return false;
        }
        *self = Self::new_with_spec(sova_spec);
        true
    }

    #[inline]
    fn run(
        &mut self,
        context: &mut CTX,
        address: &alloy_primitives::Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        // Extract caller address from inputs
        let caller = inputs.caller_address;

        // Handle Bitcoin precompiles with caller validation
        match *address {
            sova_chainspec::BROADCAST_TRANSACTION_ADDRESS => {
                // Only the native bitcoin wrapper contract can call this method
                if caller != SOVA_BTC_CONTRACT_ADDRESS {
                    Err(
                        "Unauthorized caller. Only SovaBTC contract may call broadcast precompile."
                            .to_string(),
                    )
                } else {
                    self.inner
                        .run(context, address, inputs, is_static, gas_limit)
                }
            }
            _ => {
                // Not a whitelisted Bitcoin precompile address
                self.inner
                    .run(context, address, inputs, is_static, gas_limit)
            }
        }
    }

    #[inline]
    fn warm_addresses(&self) -> Box<impl Iterator<Item = alloy_primitives::Address>> {
        <OpPrecompiles as PrecompileProvider<CTX>>::warm_addresses(&self.inner)
    }

    #[inline]
    fn contains(&self, address: &alloy_primitives::Address) -> bool {
        <OpPrecompiles as PrecompileProvider<CTX>>::contains(&self.inner, address)
    }
}
