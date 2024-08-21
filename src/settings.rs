use std::path::PathBuf;
use std::io;

use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub network: Network,
    pub network_url: String,
    pub bitcoin_rpc_username: String,
    pub bitcoin_rpc_password: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: Network::Regtest,
            network_url: "http://127.0.0.1".to_string(),
            bitcoin_rpc_username: "user".to_string(),
            bitcoin_rpc_password: "password".to_string(),
        }
    }
}

impl Settings {
    pub(crate) fn from_toml_file(path: &PathBuf) -> Result<Self, io::Error> {
        let toml = std::fs::read_to_string(path)?;
        toml::from_str(&toml).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}