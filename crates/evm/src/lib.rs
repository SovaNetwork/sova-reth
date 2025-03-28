mod constants;
mod execute;
mod inspector;
mod precompiles;

use constants::BTC_PRECOMPILE_ADDRESS;
pub use execute::MyExecutionStrategyFactory;
use inspector::SovaInspector;
pub use inspector::{AccessedStorage, BroadcastResult, SlotProvider, StorageChange, WithInspector};
pub use precompiles::BitcoinClient;
use precompiles::BitcoinRpcPrecompile;

use std::{convert::Infallible, error::Error, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes};

use reth_chainspec::ChainSpec;
use reth_evm::{env::EvmEnv, ConfigureEvm};
use reth_node_api::{ConfigureEvmEnv, NextBlockEnvAttributes};
use reth_node_ethereum::EthEvmConfig;
use reth_primitives::TransactionSigned;
use reth_revm::{
    handler::register::EvmHandler, inspector_handle_register, precompile::PrecompileSpecId, primitives::{CfgEnvWithHandlerCfg, Env, Precompile, TxEnv}, ContextPrecompile, ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector
};
use reth_tasks::TaskExecutor;

use sova_cli::SovaConfig;

#[derive(Clone)]
pub struct MyEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// Bitcoin precompile execution logic
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    /// Engine inspector used to track bitcoin precompile execution for double spends
    inspector: Arc<RwLock<SovaInspector>>,
}

impl MyEvmConfig {
    pub fn new(
        config: &SovaConfig,
        chain_spec: Arc<ChainSpec>,
        bitcoin_client: Arc<BitcoinClient>,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn Error>> {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(
            bitcoin_client.clone(),
            config.bitcoin_config.network,
            config.network_signing_url.clone(),
            config.network_utxo_url.clone(),
        )?;

        let inspector = SovaInspector::new(
            BTC_PRECOMPILE_ADDRESS,
            vec![BTC_PRECOMPILE_ADDRESS],
            config.sentinel_url.clone(),
            task_executor,
            bitcoin_client,
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        Ok(Self {
            inner: EthEvmConfig::new(chain_spec),
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
            inspector: Arc::new(RwLock::new(inspector)),
        })
    }

    pub fn set_precompiles<EXT, DB>(
        handler: &mut EvmHandler<EXT, DB>,
        bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    ) where
        DB: Database,
    {
        let spec_id = handler.cfg.spec_id;
        let mut loaded_precompiles: ContextPrecompiles<DB> =
            ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));

        loaded_precompiles.to_mut().insert(
            BTC_PRECOMPILE_ADDRESS,
            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                BitcoinRpcPrecompile::clone(&bitcoin_rpc_precompile.read()),
            ))),
        );

        handler.pre_execution.load_precompiles = Arc::new(move || loaded_precompiles.clone());
    }
}

impl ConfigureEvmEnv for MyEvmConfig {
    type Header = Header;
    type Transaction = TransactionSigned;

    type Error = Infallible;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        self.inner.fill_tx_env(tx_env, transaction, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        self.inner.fill_tx_env_system_contract_call(env, caller, contract, data);
    }

    fn fill_cfg_env(&self, cfg_env: &mut CfgEnvWithHandlerCfg, header: &Self::Header) {
        self.inner.fill_cfg_env(cfg_env, header);
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        self.inner.next_cfg_and_block_env(parent, attributes)
    }
}

impl ConfigureEvm for MyEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            // add BTC precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {}
}

impl WithInspector for MyEvmConfig {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>> {
        &self.inspector
    }
}
