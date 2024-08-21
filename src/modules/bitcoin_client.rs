use bitcoincore_rpc::{Auth, Client};
use bitcoin::Network;
use crate::settings::Settings;

pub fn create_rpc_client(settings: &Settings) -> Client {
    let port = match settings.network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Regtest => 18443,
        Network::Signet => 38332,
        _ => {
            unreachable!("unsupported network")
        }
    };

    // TODO: allow for other authentication
    let auth = Auth::UserPass(
        settings.bitcoin_rpc_username.clone(),
        settings.bitcoin_rpc_password.clone(),
    );
    // let auth = bitcoincore_rpc::Auth::CookieFile("/Users/alex/Library/Application Support/Bitcoin/regtest/.cookie".to_string().parse().unwrap());

    let url = format!("{}:{port}", settings.network_url);

    Client::new(&url, auth.clone()).unwrap()
}