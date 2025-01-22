mod abi;
mod client;
mod constants;
mod execute;
mod inspector;
mod precompiles;

use crate::precompiles::BitcoinRpcPrecompile;
pub use abi::*;
pub use client::*;
pub use constants::*;
pub use execute::*;
pub use inspector::*;

use std::{convert::Infallible, sync::Arc};

use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_primitives::Address;

use reth::revm::{
    handler::register::EvmHandler,
    inspector_handle_register,
    precompile::PrecompileSpecId,
    primitives::{CfgEnvWithHandlerCfg, Precompile, TxEnv},
    ContextPrecompile, ContextPrecompiles, Database, EvmBuilder, GetInspector,
};
use reth_chainspec::ChainSpec;
use reth_evm::{env::EvmEnv, ConfigureEvm};
use reth_node_api::{ConfigureEvmEnv, NextBlockEnvAttributes};
use reth_node_ethereum::{evm::EthEvm, EthEvmConfig};
use reth_primitives::TransactionSigned;

use sova_cli::SovaConfig;

#[derive(Debug, Clone)]
pub struct MyEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// Bitcoin RPC precompile Arc<RwLock<>> is used here since precompiles
    /// needs to be shared across multiple EVM instances
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl MyEvmConfig {
    pub fn new(config: &SovaConfig, chain_spec: Arc<ChainSpec>) -> Self {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(
            config.bitcoin.as_ref(),
            config.network_signing_url.clone(),
            config.network_utxo_url.clone(),
            config.btc_tx_queue_url.clone(),
        )
        .expect("Failed to create Bitcoin RPC precompile");
        Self {
            inner: EthEvmConfig::new(chain_spec),
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
        }
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
            BITCOIN_PRECOMPILE_ADDRESS,
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
    type Evm<'a, DB: Database + 'a, I: 'a> = EthEvm<'a, I, DB>;

    fn evm_with_env<DB: Database>(&self, db: DB, evm_env: EvmEnv) -> Self::Evm<'_, DB, ()> {
        let _ = StorageInspector::new(
            BITCOIN_PRECOMPILE_ADDRESS,
            vec![BITCOIN_PRECOMPILE_ADDRESS],
        );

        EvmBuilder::default()
            .with_db(db)
            //.with_external_context(inspector)
            .with_cfg_env_with_handler_cfg(evm_env.cfg_env_with_handler_cfg)
            .with_block_env(evm_env.block_env)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .build()
            .into()
    }

    fn evm_with_env_and_inspector<DB, I>(
        &self,
        db: DB,
        evm_env: EvmEnv,
        inspector: I,
    ) -> Self::Evm<'_, DB, I>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .with_cfg_env_with_handler_cfg(evm_env.cfg_env_with_handler_cfg)
            .with_block_env(evm_env.block_env)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
            .into()
    }
}
