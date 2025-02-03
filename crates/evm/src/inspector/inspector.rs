use std::{path::{Path, PathBuf}, sync::Arc};

use alloy_primitives::{Address, StorageKey};
use parking_lot::RwLock;
use reth_chainspec::ChainSpec;
use reth_db::{mdbx::{tx::Tx, RW}, open_db, DatabaseEnv, cursor::DbCursorRW};
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_ethereum::EthereumNode;
use reth_provider::{providers::StaticFileProvider, DatabaseProvider, DatabaseProviderFactory, ProviderFactory};
use reth_revm::{interpreter::{opcode, CallInputs, CallOutcome, Interpreter}, EvmContext, Inspector};
use reth_tracing::tracing::info;

use super::{storage_cache::StorageCache, table::{StorageLockKey, StorageLockTable}};

pub struct SovaInspector {
    /// accessed storage cache
    cache: StorageCache,
    // /// client for calling external storage service
    // db_provider: DatabaseProvider<Tx<RW>, NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        // let db_path = std::env::var("RETH_DB_PATH").map_err(|e| format!("Failed to get RETH_DB_PATH: {}", e)).unwrap();
        // let path = Path::new(&db_path).join("db");
        // info!("path exists: {:?}", path.exists());
        // let db = match open_db(path.as_path(), Default::default()) {
        //     Ok(db) => db,
        //     Err(e) => {
        //         panic!("Failed to open db: {}", e);
        //     }
        // };

        // let static_file_provider = match StaticFileProvider::read_only(path.join("static_files"), true) {
        //     Ok(provider) => provider,
        //     Err(e) => {
        //         panic!("Failed to create static file provider: {}", e);
        //     }
        // };

        // let factory = ProviderFactory::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
        //     db.into(),
        //     chain_spec,
        //     static_file_provider,
        // );

        // let db_provider = match factory.database_provider_rw() {
        //     Ok(provider) => provider,
        //     Err(e) => {
        //         panic!("Failed to create provider: {}", e);
        //     }
        // };

        Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            // db_provider,
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

                // // test db
                // let mut cursor = match self.db_provider.tx_mut().new_cursor::<StorageLockTable>() {
                //     Ok(cursor) => cursor,
                //     Err(e) => {
                //         panic!("Failed to create cursor: {}", e);
                //     }
                // };

                // let value: u64 = 0x1234567890;
                // match cursor.upsert(StorageLockKey {address, slot: key}, &value) {
                //     Ok(_) => {
                //         info!("upsert success");
                //     }
                //     Err(e) => {
                //         panic!("Failed to upsert: {}", e);
                //     }
                // }
            }
        }
    }

    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let db = if let Ok(db_path) = std::env::var("RETH_DB_PATH") {
            let path = Path::new(&db_path).join("db");
            match reth_db::open_db(&path.as_path(), Default::default()) {
                Ok(db) => Some(Arc::new(db)),
                Err(e) => {
                    info!("Failed to open database at {:?}: {}", path, e);
                    None
                }
            }
        } else {
            info!("RETH_DB_PATH environment variable not set");
            None
        };

        // create a new database provider with the db...

        // write to custom table usng the db provider

        None
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}