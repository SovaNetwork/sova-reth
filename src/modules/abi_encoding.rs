use reth_primitives::revm_primitives::PrecompileError;

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};

use bitcoin::hashes::Hash;
use bitcoin::{Network, Script};
use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::{
    GetRawTransactionResultVin, GetRawTransactionResultVout,
};
use bitcoincore_rpc::json::DecodeRawTransactionResult;

sol! {
    enum ScriptType {
        P2PKH,
        P2SH,
        P2WPKH,
        P2WSH
    }

    struct Output {
        string addr;
        uint256 value;
        bytes script;
    }

    struct Input {
        bytes32 prev_tx_hash;
        uint256 output_index;
        ScriptType output_script_type;
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

fn determine_vin_script_type(
    input: &GetRawTransactionResultVin,
) -> Result<ScriptType, PrecompileError> {
    if let Some(script_sig) = &input.script_sig {
        let script = Script::from_bytes(&script_sig.hex);
        if script.is_p2pkh() {
            Ok(ScriptType::P2PKH)
        } else if script.is_p2sh() {
            if input.txinwitness.is_some() && !input.txinwitness.as_ref().unwrap().is_empty() {
                Ok(ScriptType::P2WSH) // P2SH-wrapped segwit
            } else {
                Ok(ScriptType::P2SH) // Native P2SH
            }
        } else {
            Err(PrecompileError::other("Unknown script type"))
        }
    } else if input.txinwitness.is_some() && !input.txinwitness.as_ref().unwrap().is_empty() {
        if input.txinwitness.as_ref().unwrap().len() == 2 {
            Ok(ScriptType::P2WPKH) // Native segwit P2WPKH
        } else {
            Ok(ScriptType::P2WSH) // Native segwit P2WSH
        }
    } else {
        Err(PrecompileError::other("Unable to determine script type"))
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

    let script_type = determine_vin_script_type(input)?;

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
        output_script_type: script_type,
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
