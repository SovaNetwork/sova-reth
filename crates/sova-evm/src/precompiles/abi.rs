use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};

use reth_revm::precompile::PrecompileError;

use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::{
    GetRawTransactionResultVin, GetRawTransactionResultVout,
};
use bitcoincore_rpc::json::DecodeRawTransactionResult;

// Decoding

pub struct DecodedInput {
    #[allow(dead_code)]
    pub caller: String,
    pub amount: u64,
    pub btc_gas_limit: u64,
    pub block_height: u64,
    pub destination: String,
}

pub fn decode_input(input: &[u8]) -> Result<DecodedInput, PrecompileError> {
    let input_type = DynSolType::Tuple(vec![
        DynSolType::Address,  // caller address
        DynSolType::Uint(64), // amount
        DynSolType::Uint(64), // btcGasLimit
        DynSolType::Uint(64), // block_height
        DynSolType::String,   // destination
    ]);

    let decoded = input_type
        .abi_decode_params(input)
        .map_err(|e| PrecompileError::other(format!("Failed to decode input: {e:?}")))?;

    if let DynSolValue::Tuple(values) = decoded {
        Ok(DecodedInput {
            caller: extract_address(&values[0])?,
            amount: extract_uint(&values[1])?,
            btc_gas_limit: extract_uint(&values[2])?,
            block_height: extract_uint(&values[3])?,
            destination: extract_string(&values[4])?,
        })
    } else {
        Err(PrecompileError::other("Invalid input structure"))
    }
}

fn extract_address(value: &DynSolValue) -> Result<String, PrecompileError> {
    if let DynSolValue::Address(addr) = value {
        Ok(format!("{addr:?}").trim_start_matches("0x").to_string())
    } else {
        Err(PrecompileError::other("Invalid address"))
    }
}

fn extract_uint(value: &DynSolValue) -> Result<u64, PrecompileError> {
    if let DynSolValue::Uint(amount, _) = value {
        Ok(amount.to::<u64>())
    } else {
        Err(PrecompileError::other("Invalid uint"))
    }
}

fn extract_string(value: &DynSolValue) -> Result<String, PrecompileError> {
    if let DynSolValue::String(s) = value {
        Ok(s.clone())
    } else {
        Err(PrecompileError::other("Invalid string"))
    }
}

// Encoding

sol! {
    struct Output {
        string addr;
        uint256 value;
        bytes script;
    }

    struct Input {
        bytes32 prev_tx_hash;
        uint32 output_index;
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
        output_index,
        script_sig: script_sig_hex,
        witness: txin_witness,
    })
}

pub fn abi_encode_tx_data(
    tx_data: &DecodeRawTransactionResult,
    network: &Network,
) -> Result<Bytes, PrecompileError> {
    let txid = Vec::from_hex(&tx_data.txid.to_string())
        .map_err(|e| PrecompileError::Other(format!("Failed to decode txid: {e:?}")))?;

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
