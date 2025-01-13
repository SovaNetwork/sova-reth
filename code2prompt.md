# Table of Contents
- src/config.rs
- src/main.rs
- src/cli.rs
- src/modules/bitcoin_precompile.rs
- src/modules/mod.rs
- src/modules/abi_decoding.rs
- src/modules/abi_encoding.rs
- src/modules/bitcoin_client.rs

## File: src/config.rs

- Extension: .rs
- Language: rust
- Size: 2458 bytes
- Created: 2025-01-12 12:15:35
- Modified: 2025-01-12 12:15:35

### Code

```rust
use std::sync::Arc;

use reth::primitives::Genesis;
use reth_chainspec::ChainSpec;

use bitcoin::Network;

#[derive(Clone)]
pub struct BitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
}

#[derive(Clone)]
pub struct CorsaConfig {
    pub bitcoin: Arc<BitcoinConfig>,
    pub network_signing_url: String,
    pub network_utxo_url: String,
    pub btc_tx_queue_url: String,
}

impl CorsaConfig {
    pub fn new(args: &crate::cli::Args) -> Self {
        let bitcoin_config = BitcoinConfig {
            network: args.btc_network,
            network_url: args.network_url.clone(),
            rpc_username: args.btc_rpc_username.clone(),
            rpc_password: args.btc_rpc_password.clone(),
        };

        CorsaConfig {
            bitcoin: Arc::new(bitcoin_config),
            network_signing_url: args.network_signing_url.clone(),
            network_utxo_url: args.network_utxo_url.clone(),
            btc_tx_queue_url: args.btc_tx_queue_url.clone(),
        }
    }
}

/// Genesis data for the testnet
pub fn custom_chain() -> Arc<ChainSpec> {
    let custom_genesis = r#"
    {
        "nonce": "0x42",
        "timestamp": "0x0",
        "extraData": "0x5343",
        "gasLimit": "0x1388",
        "difficulty": "0x400000000",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {
            "0x1a0Fe90f5Bf076533b2B74a21b3AaDf225CdDfF7": {
                "balance": "0x52b7d2dcc80cd2e4000000"
            }
        },
        "number": "0x0",
        "gasUsed": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "config": {
            "ethash": {},
            "chainId": 120893,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "terminalTotalDifficulty": 0,
            "terminalTotalDifficultyPassed": true,
            "shanghaiTime": 0,
            "cancunTime": 0
        }
    }
    "#;
    let genesis: Genesis = serde_json::from_str(custom_genesis).unwrap();
    Arc::new(genesis.into())
}

```

## File: src/main.rs

- Extension: .rs
- Language: rust
- Size: 6437 bytes
- Created: 2025-01-12 12:15:35
- Modified: 2025-01-12 12:15:35

### Code

```rust
use std::sync::Arc;

use clap::Parser;
use parking_lot::RwLock;

use reth::{
    builder::{components::ExecutorBuilder, BuilderContext, NodeBuilder},
    primitives::{address, revm_primitives::Env, Bytes},
    revm::{
        handler::register::EvmHandler,
        inspector_handle_register,
        precompile::{Precompile, PrecompileSpecId},
        ContextPrecompile, ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector,
    },
    tasks::TaskManager,
};
use reth_chainspec::{ChainSpec, Head};
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv, FullNodeTypes};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{node::EthereumAddOns, EthExecutorProvider, EthereumNode};
use reth_primitives::{
    revm_primitives::{AnalysisKind, CfgEnvWithHandlerCfg, TxEnv},
    Address, Header, TransactionSigned, U256,
};
use reth_tracing::{tracing::info, RethTracer, Tracer};

mod cli;
mod config;
mod modules;

use cli::Args;
use config::{custom_chain, CorsaConfig};
use modules::bitcoin_precompile::BitcoinRpcPrecompile;

#[derive(Clone)]
pub struct MyEvmConfig {
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl MyEvmConfig {
    pub fn new(config: &CorsaConfig) -> Self {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(
            config.bitcoin.as_ref(),
            config.network_signing_url.clone(),
            config.network_utxo_url.clone(),
            config.btc_tx_queue_url.clone(),
        )
        .expect("Failed to create Bitcoin RPC precompile");
        Self {
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
            address!("0000000000000000000000000000000000000999"),
            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                BitcoinRpcPrecompile::clone(&bitcoin_rpc_precompile.read()),
            ))),
        );

        handler.pre_execution.load_precompiles = Arc::new(move || loaded_precompiles.clone());
    }
}

impl ConfigureEvmEnv for MyEvmConfig {
    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        let spec_id = reth_evm_ethereum::revm_spec(
            chain_spec,
            &Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;

        cfg_env.handler_cfg.spec_id = spec_id;
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        EthEvmConfig::default().fill_tx_env(tx_env, transaction, sender)
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        EthEvmConfig::default().fill_tx_env_system_contract_call(env, caller, contract, data)
    }
}

impl ConfigureEvm for MyEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            // add additional precompiles
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

#[derive(Clone)]
pub struct MyExecutorBuilder {
    config: CorsaConfig,
}

impl MyExecutorBuilder {
    pub fn new(config: CorsaConfig) -> Self {
        Self { config }
    }
}

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes,
{
    type EVM = MyEvmConfig;
    type Executor = EthExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.config);
        Ok((
            evm_config.clone(),
            EthExecutorProvider::new(ctx.chain_spec(), evm_config),
        ))
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    let args = Args::parse();
    let app_config = CorsaConfig::new(&args);

    let node_config = NodeConfig::test()
        .dev() // enable dev chain features, REMOVE THIS IN PRODUCTION
        .with_rpc(RpcServerArgs {
            http: true,
            http_addr: "0.0.0.0".parse().expect("Invalid IP address"), // listen on all available network interfaces
            http_port: 8545,
            ..RpcServerArgs::default()
        })
        .with_chain(custom_chain());

    let handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .with_types::<EthereumNode>()
        .with_components(
            EthereumNode::components().executor(MyExecutorBuilder::new(app_config.clone())),
        )
        .with_add_ons::<EthereumAddOns>()
        .launch()
        .await
        .unwrap();

    info!("Corsa EVM node started");

    handle.node_exit_future.await
}

```

## File: src/cli.rs

- Extension: .rs
- Language: rust
- Size: 1572 bytes
- Created: 2024-12-23 08:34:52
- Modified: 2024-12-23 08:34:52

### Code

```rust
use clap::Parser;

use bitcoin::Network;

/// Our custom cli args extension that adds flags to configure the bitcoin rpc client
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// CLI flag to indicate the bitcoin network the bitcoin rpc client will connect to
    #[arg(long, value_parser = parse_network, default_value = "regtest")]
    pub btc_network: Network,

    // CLI flag to indicate the bitcoin rpc url
    #[arg(long, default_value = "http://127.0.0.1")]
    pub network_url: String,

    /// CLI flag to indicate the bitcoin rpc username
    #[arg(long, default_value = "user")]
    pub btc_rpc_username: String,

    /// CLI flag to indicate the bitcoin rpc password
    #[arg(long, default_value = "password")]
    pub btc_rpc_password: String,

    /// CLI flag to indicate the network signing service url
    #[arg(long, default_value = "http://127.0.0.1:5555")]
    pub network_signing_url: String,

    /// CLI flag to indicate the network UTXO database url
    #[arg(long, default_value = "http://127.0.0.1:5557")]
    pub network_utxo_url: String,

    /// CLI flag to indicate the bitcoin transaction queue url
    #[arg(long, default_value = "http://127.0.0.1:5558")]
    pub btc_tx_queue_url: String,
}

fn parse_network(s: &str) -> Result<Network, &'static str> {
    match s {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "mainnet" => Ok(Network::Bitcoin),
        _ => Err("Invalid network. Use 'regtest', 'testnet', 'signet' or 'mainnet'"),
    }
}

```

## File: src/modules/bitcoin_precompile.rs

- Extension: .rs
- Language: rust
- Size: 13458 bytes
- Created: 2025-01-12 12:15:35
- Modified: 2025-01-12 12:15:35

### Code

```rust
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use reqwest::blocking::Client as ReqwestClient;

use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{
    Bytes as RethBytes, Env, PrecompileError, PrecompileErrors, PrecompileResult,
    StatefulPrecompile,
};
use reth_tracing::tracing::{error, info};

use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, OutPoint, TxOut};

use crate::config::BitcoinConfig;

use super::{
    abi_decoding::{decode_input, DecodedInput},
    abi_encoding::abi_encode_tx_data,
    bitcoin_client::BitcoinClientWrapper,
};

#[derive(Deserialize)]
#[allow(dead_code)]
struct UtxoSelectionResponse {
    block_height: i32,
    address: String,
    target_amount: i64,
    selected_utxos: Vec<UtxoUpdate>,
    total_amount: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UtxoUpdate {
    id: String,
    address: String,
    public_key: Option<String>,
    txid: String,
    vout: i32,
    amount: i64,
    script_pub_key: String,
    script_type: String,
    created_at: String,
    block_height: i32,
    spent_txid: Option<String>,
    spent_at: Option<String>,
    spent_block: Option<i32>,
}

#[derive(Serialize)]
struct SignTxInputData {
    txid: String,
    vout: u32,
    amount: u64,
}

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<BitcoinClientWrapper>,
    network: Network,
    http_client: Arc<ReqwestClient>,
    network_signing_url: String,
    network_utxo_url: String,
    btc_tx_queue_url: String,
}

impl BitcoinRpcPrecompile {
    pub fn new(
        config: &BitcoinConfig,
        network_signing_url: String,
        network_utxo_url: String,
        btc_tx_queue_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        let http_client = ReqwestClient::new();

        Ok(Self {
            bitcoin_client: Arc::new(client),
            network: config.network,
            http_client: Arc::new(http_client),
            network_signing_url,
            network_utxo_url,
            btc_tx_queue_url,
        })
    }

    fn make_http_request<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        endpoint: &str,
        method: reqwest::Method,
        payload: Option<&T>,
    ) -> Result<R, PrecompileErrors> {
        let url = format!("{}/{}", base_url, endpoint);
        let mut request = self.http_client.request(method.clone(), &url);

        if let Some(data) = payload {
            request = match method {
                reqwest::Method::GET => request.query(data),
                _ => request.json(data),
            };
        }

        request
            .send()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "HTTP request failed: {}",
                    e
                )))
            })?
            .json()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Failed to parse response: {}",
                    e
                )))
            })
    }

    fn call_enclave<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileErrors> {
        self.make_http_request(
            &self.network_signing_url,
            endpoint,
            reqwest::Method::POST,
            Some(payload),
        )
    }

    fn call_utxo_selection<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileErrors> {
        self.make_http_request(
            &self.network_utxo_url,
            endpoint,
            reqwest::Method::GET,
            Some(payload),
        )
    }

    fn call_btc_tx_queue(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (10_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        // Deserialize to verify transaction format
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        // Get txid for return value
        let txid = tx.txid();

        // Queue transaction for broadcasting
        let broadcast_request = serde_json::json!({
            "raw_tx": hex::encode(input)
        });

        // Queue transaction for broadcasting
        // TODO (@powvt): handle what about when the broadcast fails in the queue?
        match self.make_http_request::<_, serde_json::Value>(
            &self.btc_tx_queue_url,
            "broadcast",
            reqwest::Method::POST,
            Some(&broadcast_request),
        ) {
            Ok(_) => {
                info!(
                    "Successfully queued transaction for broadcast, txid: {}",
                    txid
                );
            }
            Err(e) => {
                error!("Failed to broadcast transaction: {}", e);
                // Continue execution despite error
            }
        }

        // Convert txid to bytes and return
        let mut txid_bytes: [u8; 32] = txid.to_raw_hash().to_byte_array();
        txid_bytes.reverse();

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(txid_bytes.to_vec()),
        ))
    }

    /// TODO (@powvt): manually decode tx data, dont use node for this
    fn decode_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (4_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        let data = self
            .bitcoin_client
            .decode_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(
                    "Decode raw transaction bitcoin rpc call failed",
                ))
            })?;

        let encoded_data: AlloyBytes = abi_encode_tx_data(&data, &self.network).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to encode transaction data: {:?}",
                e
            )))
        })?;

        // Convert AlloyBytes to RethBytes by creating a new RethBytes from the underlying Vec<u8>
        let reth_bytes = RethBytes::from(encoded_data.to_vec());
        Ok(PrecompileOutput::new(gas_used, reth_bytes))
    }

    fn check_signature(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (6_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        // Closure to fetch previous transaction output (TxOut) for each input
        let mut spent = |outpoint: &OutPoint| -> Option<TxOut> {
            match self
                .bitcoin_client
                .get_raw_transaction(&outpoint.txid, None)
            {
                Ok(prev_tx) => prev_tx
                    .output
                    .get(outpoint.vout as usize)
                    .map(|output| TxOut {
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                    }),
                Err(_) => None,
            }
        };

        // Verify the transaction. For each input, check if unlocking script is valid based on the corresponding TxOut.
        tx.verify(&mut spent).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "Transaction verification failed: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            reth::primitives::Bytes::from(vec![1]),
        ))
    }

    fn derive_btc_address(
        &self,
        ethereum_address_trimmed: &str,
    ) -> Result<String, PrecompileErrors> {
        let enclave_request = serde_json::json!({
            "ethereum_address": ethereum_address_trimmed
        });

        let response: serde_json::Value = self.call_enclave("derive_address", &enclave_request)?;

        response["address"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                PrecompileErrors::Error(PrecompileError::Other(
                    "Failed to extract Bitcoin address from response".to_string(),
                ))
            })
    }

    fn convert_address(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 3_000_u64;

        // Convert input to a hex string and remove '0x' if present
        let ethereum_address_hex = hex::encode(input);
        let ethereum_address_trimmed = ethereum_address_hex.trim_start_matches("0x");

        let bitcoin_address = self.derive_btc_address(ethereum_address_trimmed)?;

        Ok(PrecompileOutput::new(
            gas_used,
            reth::primitives::Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    fn create_and_sign_raw_transaction(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 25_000_u64;

        let decoded_input: DecodedInput = decode_input(input)?;

        // Get bitcoin address for the signer
        let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;

        let endpoint = format!(
            "select-utxos/block/{}/address/{}/amount/{}",
            decoded_input.block_height, bitcoin_address, decoded_input.amount
        );

        // Call the UTXO selection service
        let selected_utxos: UtxoSelectionResponse = self.call_utxo_selection(&endpoint, &())?;

        let inputs: Vec<SignTxInputData> = selected_utxos
            .selected_utxos
            .into_iter()
            .map(|utxo| SignTxInputData {
                txid: utxo.txid,
                vout: utxo.vout as u32,
                amount: utxo.amount as u64,
            })
            .collect();

        // Calculate total input amount
        let total_input: u64 = inputs.iter().map(|input| input.amount).sum();

        let fee = 1000000; // TODO: Add dynamic fee estimation

        let mut outputs = vec![serde_json::json!({
            "address": decoded_input.destination,
            "amount": decoded_input.amount,
        })];

        // Add change output if necessary
        if total_input > decoded_input.amount + fee {
            let change_amount = total_input - decoded_input.amount - fee;
            let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;
            outputs.push(serde_json::json!({
                "address": bitcoin_address,
                "amount": change_amount,
            }));
        }

        let sign_request = serde_json::json!({
            "ethereum_address": decoded_input.signer,
            "inputs": inputs,
            "outputs": outputs,
        });

        let sign_response: serde_json::Value =
            self.call_enclave("sign_transaction", &sign_request)?;

        let signed_tx_hex = sign_response["signed_tx"].as_str().ok_or_else(|| {
            PrecompileErrors::Error(PrecompileError::other("Missing signed_tx in response"))
        })?;

        info!("Signed transaction: {}", signed_tx_hex);

        let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to decode signed transaction into hex: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(signed_tx_bytes),
        ))
    }
}

impl StatefulPrecompile for BitcoinRpcPrecompile {
    fn call(
        &self,
        input: &reth::primitives::Bytes,
        _gas_price: u64,
        _env: &Env,
    ) -> PrecompileResult {
        if input.len() < 4 {
            return Err(PrecompileErrors::Error(PrecompileError::other(
                "Input too short for method selector",
            )));
        }

        // Parse the first 4 bytes as a u32 method selector
        let method_selector = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        match method_selector {
            0x00000001 => self.call_btc_tx_queue(&input[4..], 100_000),
            0x00000002 => self.decode_raw_transaction(&input[4..], 150_000),
            0x00000003 => self.check_signature(&input[4..], 100_000),
            0x00000004 => self.convert_address(&input[4..]),
            0x00000005 => self.create_and_sign_raw_transaction(input),
            _ => Err(PrecompileErrors::Error(PrecompileError::other(
                "Unsupported Bitcoin RPC method",
            ))),
        }
    }
}

```

## File: src/modules/mod.rs

- Extension: .rs
- Language: rust
- Size: 96 bytes
- Created: 2025-01-12 12:15:22
- Modified: 2025-01-12 12:15:22

### Code

```rust
pub mod abi_decoding;
pub mod abi_encoding;
pub mod bitcoin_client;
pub mod bitcoin_precompile;

```

## File: src/modules/abi_decoding.rs

- Extension: .rs
- Language: rust
- Size: 2750 bytes
- Created: 2025-01-12 12:15:35
- Modified: 2025-01-12 12:15:35

### Code

```rust
use alloy_dyn_abi::{DynSolType, DynSolValue};
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors};

pub struct DecodedInput {
    #[allow(dead_code)]
    pub method_selector: Vec<u8>,
    pub signer: String,
    pub amount: u64,
    pub block_height: u64,
    pub destination: String,
}

pub fn decode_input(input: &[u8]) -> Result<DecodedInput, PrecompileErrors> {
    let input_type = DynSolType::Tuple(vec![
        DynSolType::FixedBytes(4), // method selector
        DynSolType::Address,       // signer address
        DynSolType::Uint(64),      // amount
        DynSolType::Uint(64),      // block_height
        DynSolType::String,        // destination
    ]);

    let decoded = input_type.abi_decode(input).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "Failed to decode input: {:?}",
            e
        )))
    })?;

    if let DynSolValue::Tuple(values) = decoded {
        Ok(DecodedInput {
            method_selector: extract_fixed_bytes(&values[0], 4)?,
            signer: extract_address(&values[1])?,
            amount: extract_uint(&values[2])?,
            block_height: extract_uint(&values[3])?,
            destination: extract_string(&values[4])?,
        })
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid input structure",
        )))
    }
}

fn extract_fixed_bytes(value: &DynSolValue, size: usize) -> Result<Vec<u8>, PrecompileErrors> {
    if let DynSolValue::FixedBytes(bytes, s) = value {
        if *s == size {
            Ok(bytes.as_slice().to_vec())
        } else {
            Err(PrecompileErrors::Error(PrecompileError::other(
                "Invalid fixed bytes size",
            )))
        }
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid fixed bytes",
        )))
    }
}

fn extract_address(value: &DynSolValue) -> Result<String, PrecompileErrors> {
    if let DynSolValue::Address(addr) = value {
        Ok(format!("{:?}", addr).trim_start_matches("0x").to_string())
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid address",
        )))
    }
}

fn extract_uint(value: &DynSolValue) -> Result<u64, PrecompileErrors> {
    if let DynSolValue::Uint(amount, _) = value {
        Ok(amount.to::<u64>())
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid uint",
        )))
    }
}

fn extract_string(value: &DynSolValue) -> Result<String, PrecompileErrors> {
    if let DynSolValue::String(s) = value {
        Ok(s.clone())
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid string",
        )))
    }
}

```

## File: src/modules/abi_encoding.rs

- Extension: .rs
- Language: rust
- Size: 3483 bytes
- Created: 2025-01-12 12:15:35
- Modified: 2025-01-12 12:15:35

### Code

```rust
use reth_primitives::revm_primitives::PrecompileError;

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};

use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::{
    GetRawTransactionResultVin, GetRawTransactionResultVout,
};
use bitcoincore_rpc::json::DecodeRawTransactionResult;

sol! {
    struct Output {
        string addr;
        uint256 value;
        bytes script;
    }

    struct Input {
        bytes32 prev_tx_hash;
        uint256 output_index;
        bytes script_sig;
        bytes[] witness;
    }

    struct BitcoinTx {
        bytes32 txid;
        Output[] outputs;
        Input[] inputs;
        uint256 locktime;
    }
}

fn encode_output(
    output: &GetRawTransactionResultVout,
    network: &Network,
) -> Result<Output, PrecompileError> {
    let addr = match &output.script_pub_key.address {
        Some(addr_unchecked) => addr_unchecked
            .clone()
            .require_network(*network)
            .map(|checked_addr| checked_addr.to_string())
            .unwrap_or_else(|_| "Invalid network".to_string()),
        None => Address::ZERO.to_string(),
    };

    if addr == Address::ZERO.to_string() || addr == "Invalid network" {
        return Err(PrecompileError::other("Invalid vout address"));
    }

    Ok(Output {
        addr,
        value: U256::from(output.value.to_sat()),
        script: output.script_pub_key.hex.clone().into(),
    })
}

fn encode_input(input: &GetRawTransactionResultVin) -> Result<Input, PrecompileError> {
    let prev_tx_hash = input
        .txid
        .ok_or_else(|| PrecompileError::other("Missing vin txid"))?;

    // Reverse the byte order of the prev transaction hash
    // Bitcoin uses little-endian byte order for transaction hashes
    let reversed_prev_tx_hash: [u8; 32] = {
        let mut reversed = prev_tx_hash.to_byte_array(); // results in big endian by default
        reversed.reverse(); // reverse -> little endian
        reversed
    };

    let output_index = input
        .vout
        .ok_or_else(|| PrecompileError::other("Missing vout"))?;

    let script_sig_hex = match &input.script_sig {
        Some(script) => Bytes::from(script.hex.clone()),
        None => Bytes::new(),
    };

    let txin_witness: Vec<Bytes> = input
        .txinwitness
        .as_ref()
        .map(|w| w.iter().map(|item| Bytes::from(item.clone())).collect())
        .unwrap_or_default();

    Ok(Input {
        prev_tx_hash: FixedBytes::from(reversed_prev_tx_hash),
        output_index: U256::from(output_index),
        script_sig: script_sig_hex,
        witness: txin_witness,
    })
}

pub fn abi_encode_tx_data(
    tx_data: &DecodeRawTransactionResult,
    network: &Network,
) -> Result<Bytes, PrecompileError> {
    let txid = Vec::from_hex(&tx_data.txid.to_string())
        .map_err(|e| PrecompileError::Other(format!("Failed to decode txid: {:?}", e)))?;

    let outputs = tx_data
        .vout
        .iter()
        .map(|output| encode_output(output, network))
        .collect::<Result<Vec<_>, _>>()?;

    let inputs = tx_data
        .vin
        .iter()
        .map(encode_input)
        .collect::<Result<Vec<_>, _>>()?;

    let data = BitcoinTx {
        txid: FixedBytes::from_slice(&txid),
        outputs,
        inputs,
        locktime: U256::from(tx_data.locktime),
    };

    Ok(Bytes::from(data.abi_encode()))
}

```

## File: src/modules/bitcoin_client.rs

- Extension: .rs
- Language: rust
- Size: 1300 bytes
- Created: 2024-12-23 08:34:52
- Modified: 2024-12-23 08:34:52

### Code

```rust
use bitcoin::{BlockHash, Transaction, Txid};
use bitcoincore_rpc::{json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use crate::config::BitcoinConfig;

pub struct BitcoinClientWrapper {
    client: Client,
}

impl BitcoinClientWrapper {
    pub fn new(config: &BitcoinConfig) -> Result<Self, bitcoincore_rpc::Error> {
        let port = match config.network {
            bitcoin::Network::Bitcoin => 8332,
            bitcoin::Network::Testnet => 18332,
            bitcoin::Network::Regtest => 18443,
            bitcoin::Network::Signet => 38332,
            _ => unreachable!("unsupported network id"),
        };

        let auth = Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone());

        let url = format!("{}:{}", config.network_url, port);
        let client = Client::new(&url, auth)?;
        Ok(Self { client })
    }

    pub fn decode_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<DecodeRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.decode_raw_transaction(tx, None)
    }

    pub fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<Transaction, bitcoincore_rpc::Error> {
        self.client.get_raw_transaction(txid, block_hash)
    }
}

```

