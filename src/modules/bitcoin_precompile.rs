use std::sync::Arc;

use hex::FromHex;
use parking_lot::RwLock;

use reqwest::blocking::Client as ReqwestClient;

use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{
    Bytes as RethBytes, Env, PrecompileError, PrecompileErrors, PrecompileResult,
    StatefulPrecompile,
};

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, OutPoint, TxOut};

use crate::config::BitcoinConfig;

use super::{abi_encoding::abi_encode_tx_data, bitcoin_client::BitcoinClientWrapper};

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<RwLock<BitcoinClientWrapper>>,
    network: Network,
    enclave_client: Arc<ReqwestClient>,
    enclave_client_url: String,
}

impl BitcoinRpcPrecompile {
    pub fn new(
        config: &BitcoinConfig,
        enclave_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        let enclave_client = ReqwestClient::new();

        Ok(Self {
            bitcoin_client: Arc::new(RwLock::new(client)),
            network: config.network,
            enclave_client: Arc::new(enclave_client),
            enclave_client_url: enclave_url,
        })
    }

    fn send_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (10_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        let txid = self
            .bitcoin_client
            .read()
            .send_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(
                    "Send raw transaction bitcoin rpc call failed",
                ))
            })?;

        // Convert the Txid to raw bytes and reverse the byte order
        let mut txid_bytes: [u8; 32] = txid.to_raw_hash().to_byte_array();
        txid_bytes.reverse();

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(txid_bytes.to_vec()),
        ))
    }

    fn get_block_count(&self) -> PrecompileResult {
        let gas_used: u64 = 2_000_u64;

        let block_count = self.bitcoin_client.read().get_block_count().map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other("Failed to get block count"))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            reth::primitives::Bytes::from(block_count.to_be_bytes().to_vec()),
        ))
    }

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
            .read()
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
                .read()
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
        // Prepare the payload for the enclave RPC call
        let enclave_request = serde_json::json!({
            "ethereum_address": ethereum_address_trimmed
        });

        let url = format!("{}/derive_address", self.enclave_client_url);

        // Call the enclave RPC
        let response = self
            .enclave_client
            .post(url)
            .json(&enclave_request)
            .send()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Enclave RPC call failed: {:?}",
                    e
                )))
            })?;

        // Parse the response
        let status: serde_json::Value = response.json().map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to parse response: {:?}",
                e
            )))
        })?;

        // Check if the response contains an error
        let bitcoin_address = status["address"].as_str().ok_or_else(|| {
            PrecompileErrors::Error(PrecompileError::Other(
                "Failed to extract Bitcoin address from response".to_string(),
            ))
        })?;

        Ok(bitcoin_address.to_string())
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

    fn create_and_sign_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (5_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        // Define the types for our structured input
        let input_type = DynSolType::Tuple(vec![
            DynSolType::FixedBytes(4),
            DynSolType::Address,
            DynSolType::Uint(64),
            DynSolType::String,
            DynSolType::Array(Box::new(DynSolType::Tuple(vec![
                DynSolType::FixedBytes(32),
                DynSolType::Uint(32),
                DynSolType::Uint(64),
            ]))),
        ]);

        let decoded_input = input_type.abi_decode(input).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "Failed to decode input: {:?}",
                e
            )))
        })?;

        if let DynSolValue::Tuple(values) = decoded_input {
            let _method_selector = if let DynSolValue::FixedBytes(selector, 4) = &values[0] {
                selector
            } else {
                return Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid method selector",
                )));
            };

            let signer = if let DynSolValue::Address(addr) = &values[1] {
                addr
            } else {
                return Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid signer address",
                )));
            };

            let amount = if let DynSolValue::Uint(amount, _) = &values[2] {
                amount.to::<u64>()
            } else {
                return Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid amount",
                )));
            };

            let destination = if let DynSolValue::String(dest) = &values[3] {
                dest
            } else {
                return Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid destination address",
                )));
            };

            let utxos = if let DynSolValue::Array(utxo_array) = &values[4] {
                utxo_array
                    .iter()
                    .map(|utxo| {
                        if let DynSolValue::Tuple(utxo_values) = utxo {
                            let txid =
                                if let DynSolValue::FixedBytes(txid_bytes, 32) = &utxo_values[0] {
                                    hex::encode(txid_bytes)
                                } else {
                                    return Err(PrecompileErrors::Error(PrecompileError::other(
                                        "Invalid UTXO txid",
                                    )));
                                };

                            let vout = if let DynSolValue::Uint(vout, _) = &utxo_values[1] {
                                vout.to::<u32>()
                            } else {
                                return Err(PrecompileErrors::Error(PrecompileError::other(
                                    "Invalid UTXO vout",
                                )));
                            };

                            let utxo_amount = if let DynSolValue::Uint(amount, _) = &utxo_values[2]
                            {
                                amount.to::<u64>()
                            } else {
                                return Err(PrecompileErrors::Error(PrecompileError::other(
                                    "Invalid UTXO amount",
                                )));
                            };

                            Ok(serde_json::json!({
                                "txid": txid,
                                "vout": vout,
                                "amount": utxo_amount,
                            }))
                        } else {
                            Err(PrecompileErrors::Error(PrecompileError::other(
                                "Invalid UTXO structure",
                            )))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                return Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid UTXO array",
                )));
            };

            // Calculate total input amount
            let total_input: u64 = utxos
                .iter()
                .map(|utxo| utxo["amount"].as_u64().ok_or_else(
                    || PrecompileErrors::Error(PrecompileError::other("UTXO to spend is missing the amount field")),
                ))
                .collect::<Result<Vec<_>, _>>()? // bubble up errors
                .iter()
                .sum();

            // Prepare outputs
            let mut outputs = vec![serde_json::json!({
                "address": destination,
                "amount": amount,
            })];

            // bitcoin fees are hardcoded 0.01 BTC
            // TODO(powvt): Add dynamic fee estimation
            let fee = 1000000;

            // Calculate and add change output if necessary
            if total_input > amount + fee {
                let change_amount = total_input - amount - fee;

                // Convert Ethereum address to trimmed hex string
                let ethereum_address_hex = format!("{:?}", signer);
                let ethereum_address_trimmed = ethereum_address_hex.trim_start_matches("0x");

                // Derive Bitcoin address for change output
                let bitcoin_address =
                    self.derive_btc_address(ethereum_address_trimmed)
                        .map_err(|e| {
                            PrecompileErrors::Error(PrecompileError::other(format!(
                                "Failed to derive Bitcoin address: {:?}",
                                e
                            )))
                        })?;

                outputs.push(serde_json::json!({
                    "address": bitcoin_address,
                    "amount": change_amount,
                }));
            }

            // Prepare the request for the enclave service
            let sign_request = serde_json::json!({
                "ethereum_address": format!("{:?}", signer).trim_start_matches("0x"),
                "inputs": utxos,
                "outputs": outputs,
            });

            // Call the enclave service to sign the transaction
            let url = format!("{}/sign_transaction", self.enclave_client_url);
            let response = self
                .enclave_client
                .post(&url)
                .json(&sign_request)
                .send()
                .map_err(|e| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "Failed to call enclave service: {:?}",
                        e
                    )))
                })?;

            let sign_response: serde_json::Value = response.json().map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Failed to parse enclave response: {:?}",
                    e
                )))
            })?;

            // Extract and validate signed transaction hex
            let signed_tx_hex = sign_response["signed_tx"].as_str().ok_or_else(|| {
                PrecompileErrors::Error(PrecompileError::other("Missing signed_tx in response"))
            })?;

            let signed_tx_bytes = Vec::from_hex(signed_tx_hex).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Failed to decode hex: {:?}",
                    e
                )))
            })?;

            Ok(PrecompileOutput::new(
                gas_used,
                RethBytes::from(signed_tx_bytes),
            ))
        } else {
            Err(PrecompileErrors::Error(PrecompileError::other(
                "Invalid input structure",
            )))
        }
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
            0x00000000 => self.send_raw_transaction(&input[4..], 100_000),
            0x00000001 => self.get_block_count(),
            0x00000002 => self.decode_raw_transaction(&input[4..], 150_000),
            0x00000003 => self.check_signature(&input[4..], 100_000),
            0x00000004 => self.convert_address(&input[4..]),
            0x00000005 => self.create_and_sign_raw_transaction(&input, 250_000),
            _ => Err(PrecompileErrors::Error(PrecompileError::other(
                "Unsupported Bitcoin RPC method",
            ))),
        }
    }
}
