use std::{path::Path, sync::Arc};

use alloy_primitives::{Address, StorageKey};
use parking_lot::RwLock;
use reth_chainspec::ChainSpec;
use reth_db::{open_db,DatabaseEnv};
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_ethereum::EthereumNode;
use reth_provider::{providers::StaticFileProvider, DatabaseProviderRW, ProviderFactory};
use reth_revm::{interpreter::{opcode, Interpreter}, EvmContext, Inspector};

use super::{storage_cache::StorageCache, table::{StorageLockKey, StorageLockTable}};

pub struct SovaInspector {
    /// accessed storage cache
    cache: StorageCache,
    /// client for calling external storage service
    db_provider: DatabaseProviderRW<Arc<DatabaseEnv>, NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        // let db_env = std::env::var("./data").unwrap();
        let db_path = Path::new("./data");
        let db = match open_db(db_path.join("db").as_path(), Default::default()) {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to open db: {}", e);
            }
        };

        let static_file_provider = match StaticFileProvider::read_only(db_path.join("static_files"), true) {
            Ok(provider) => provider,
            Err(e) => {
                panic!("Failed to create static file provider: {}", e);
            }
        };

        let factory = ProviderFactory::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
            db.into(),
            chain_spec,
            static_file_provider,
        );

        let db_provider = match factory.provider_rw() {
            Ok(provider) => provider,
            Err(e) => {
                panic!("Failed to create provider: {}", e);
            }
        };

        Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            db_provider,
        }
    }
}

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        // optimistically cache storage accesses for if there is a btc tx broadcast
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);
                self.cache.insert_accessed_storage(address, key);

                // test db
                let _ = self.db_provider.0.tx_ref().new_cursor::<StorageLockTable>();
            }
        }
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}