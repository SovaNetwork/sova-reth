use std::error::Error;
use std::sync::Arc;

use crate::chainspec::{
    BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS, DECODE_TRANSACTION_ADDRESS,
    VAULT_SPEND_ADDRESS,
};
use crate::evm::CustomTxEnv;
use crate::precompiles::BitcoinRpcPrecompile;
use alloy_evm::{
    precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap},
    Database, Evm, EvmEnv, EvmFactory,
};
use alloy_op_evm::{OpEvm, OpEvmFactory};
use alloy_primitives::{Address, Bytes};
use op_revm::{OpContext, OpHaltReason, OpSpecId, OpTransactionError};
use reth_ethereum::evm::revm::{
    context::{result::ResultAndState, BlockEnv},
    handler::PrecompileProvider,
    interpreter::InterpreterResult,
    Inspector,
};

use revm::{context_interface::result::EVMError, inspector::NoOpInspector};

pub struct CustomEvm<DB: Database, I, P = PrecompilesMap> {
    inner: OpEvm<DB, I, P>,
}

impl<DB: Database, I, P> CustomEvm<DB, I, P> {
    pub fn new(op: OpEvm<DB, I, P>) -> Self {
        Self { inner: op }
    }
}

impl<DB, I, P> Evm for CustomEvm<DB, I, P>
where
    DB: Database,
    I: Inspector<OpContext<DB>>,
    P: PrecompileProvider<OpContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = CustomTxEnv;
    type Error = EVMError<DB::Error, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = P;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled)
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        self.inner.components_mut()
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct CustomEvmFactory(pub OpEvmFactory);

impl CustomEvmFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EvmFactory for CustomEvmFactory {
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = CustomEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = CustomTxEnv;
    type Error<DBError: Error + Send + Sync + 'static> = EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let mut op_evm = self.0.create_evm(db, input);

        // Build one shared instance from env just once.
        let btc = Arc::new(BitcoinRpcPrecompile::from_env());

        let (_, _, precompiles) = op_evm.components_mut();
        precompiles.ensure_dynamic_precompiles();

        // Install stateful closures for each Sova precompile
        precompiles.apply_precompile(&BROADCAST_TRANSACTION_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.broadcast_btc_tx(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&DECODE_TRANSACTION_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.decode_raw_transaction(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&CONVERT_ADDRESS_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.convert_address(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&VAULT_SPEND_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.network_spend(pi.data, &pi.caller, pi.gas),
            ))
        });

        CustomEvm::new(op_evm)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut op_evm = self.0.create_evm_with_inspector(db, input, inspector);

        // Build one shared instance from env just once.
        let btc = Arc::new(BitcoinRpcPrecompile::from_env());

        let (_, _, precompiles) = op_evm.components_mut();
        precompiles.ensure_dynamic_precompiles();

        // Install stateful closures for each Sova precompile
        precompiles.apply_precompile(&BROADCAST_TRANSACTION_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.broadcast_btc_tx(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&DECODE_TRANSACTION_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.decode_raw_transaction(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&CONVERT_ADDRESS_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.convert_address(pi.data, pi.gas),
            ))
        });

        precompiles.apply_precompile(&VAULT_SPEND_ADDRESS, |_| {
            let btc = btc.clone();
            Some(DynPrecompile::new_stateful(
                move |pi: PrecompileInput<'_>| btc.network_spend(pi.data, &pi.caller, pi.gas),
            ))
        });

        CustomEvm::new(op_evm)
    }
}
