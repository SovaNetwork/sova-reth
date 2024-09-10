use reth::primitives::Bytes;

use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::json::DecodeRawTransactionResult;
use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::ScriptPubkeyType;
use bitcoincore_rpc::bitcoincore_rpc_json::{GetRawTransactionResultVin, GetRawTransactionResultVout};

use alloy_sol_types::{sol, SolValue};
use alloy_primitives::{FixedBytes, U256};

/////////////
/// NOTES ///
/////////////
/// - Need to fix the script type encoding -> output_script_type
/// - Need to fix the addr.clone().require_network(Network::Regtest line
/// - Need to fix the script_sig line


#[derive(Debug)]
pub enum EncodingError {
    DecodingBtcTxError(String),
}

sol! {
    struct Output {
        string addr;
        uint256 value;
        bytes script;
    }

    struct Input {
        string addr;
        bytes32 prev_tx_hash;
        uint256 output_index;
        uint256 output_script_type;
        bytes script_sig;
    }

    struct BitcoinTx {
        bytes32 txid;
        Output[] outputs;
        Input[] inputs;
        uint256 locktime;
    }
}

fn script_type(script_type: &ScriptPubkeyType) -> U256 {
    match script_type {
        ScriptPubkeyType::PubkeyHash => U256::from(0), // P2PKH
        ScriptPubkeyType::ScriptHash => U256::from(1), // P2SH
        ScriptPubkeyType::Witness_v0_KeyHash | ScriptPubkeyType::Witness_v0_ScriptHash => U256::from(2), // P2WPKH or P2WSH
        _ => U256::from(0), // Default to P2PKH
    }
}

fn encode_output(output: &GetRawTransactionResultVout) -> Result<Output, EncodingError> {
    let addr = output.script_pub_key.address
        .as_ref()
        .map(|addr| {
            addr.clone().require_network(Network::Regtest)
                .map(|checked_addr| checked_addr.to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    Ok(Output {
        addr,
        value: U256::from(output.value.to_sat()),
        script: output.script_pub_key.hex.clone().into(),
    })
}

fn encode_input(input: &GetRawTransactionResultVin) -> Result<Input, EncodingError> {
    let prev_tx_hash = input.txid
        .ok_or_else(|| EncodingError::DecodingBtcTxError("Missing txid".to_string()))?
        .to_byte_array();

    Ok(Input {
        addr: "0x0000000000000000000000000000000000000000".into(),
        prev_tx_hash: FixedBytes::from(prev_tx_hash),
        output_index: U256::from(input.vout.unwrap_or_default()),
        output_script_type: U256::from(2),
        script_sig: input.txinwitness.as_ref()
            .map(|w| w.concat())
            .unwrap_or_else(|| input.script_sig.as_ref().map(|s| s.hex.clone()).unwrap_or_default())
            .into(),
    })
}

pub fn encode_tx_data(tx_data: &DecodeRawTransactionResult) -> Result<Bytes, EncodingError> {
    let txid = Vec::from_hex(&tx_data.txid.to_string())
        .map_err(|e| EncodingError::DecodingBtcTxError(e.to_string()))?;

    let outputs = tx_data.vout.iter()
        .map(encode_output)
        .collect::<Result<Vec<_>, _>>()?;

    let inputs = tx_data.vin.iter()
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