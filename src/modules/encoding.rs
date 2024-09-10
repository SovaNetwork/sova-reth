use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::json::DecodeRawTransactionResult;
use ethabi::{encode, Token};
use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::ScriptPubkeyType;
use bitcoincore_rpc::bitcoincore_rpc_json::{GetRawTransactionResultVin, GetRawTransactionResultVout};
use reth::primitives::Bytes;
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors};

#[derive(Debug)]
pub enum EncodingError {
    DecodingError(String),
    EncodingError(String),
}

fn script_type(script_type: &ScriptPubkeyType) -> Token {
    match script_type {
        ScriptPubkeyType::PubkeyHash => Token::Uint(ethabi::Uint::from(0)), // P2PKH
        ScriptPubkeyType::ScriptHash => Token::Uint(ethabi::Uint::from(1)), // P2SH
        ScriptPubkeyType::Witness_v0_KeyHash | ScriptPubkeyType::Witness_v0_ScriptHash => Token::Uint(ethabi::Uint::from(2)), // P2WPKH or P2WSH
        _ => Token::Uint(ethabi::Uint::from(0)), // Default to P2PKH
    }
}

fn encode_output(output: &GetRawTransactionResultVout) -> Result<Token, EncodingError> {
    let addr = Token::String(
        output.script_pub_key.address
                .as_ref()
                .map(|addr| {
                    addr.clone().require_network(Network::Regtest)
                        .map(|checked_addr| checked_addr.to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default()
    );
    let value = Token::Uint(ethabi::Uint::from(output.value.to_sat()));
    let script = Token::Bytes(output.script_pub_key.hex.clone());

    Ok(Token::Tuple(vec![addr, value, script]))
}

fn encode_input(input: &GetRawTransactionResultVin) -> Result<Token, EncodingError> {
    let addr = Token::String("0x0000000000000000000000000000000000000000".to_string());
    let prev_tx_hash = Token::FixedBytes(Vec::from(input.txid
        .ok_or_else(|| PrecompileErrors::Error(PrecompileError::other("Missing txid")))
        .unwrap()
        .to_byte_array()
        .into_iter()
        .rev()
        .collect::<Vec<u8>>()
    ));
    let output_index = Token::Uint(ethabi::Uint::from(input.vout.unwrap_or_default()));
    let output_script_type = Token::Uint(ethabi::Uint::from(2));
    let script_sig = Token::Bytes(input.txinwitness.as_ref()
        .map(|w| w.concat())
        .unwrap_or_else(|| input.script_sig.as_ref().map(|s| s.hex.clone()).unwrap_or_default())
        .into()
    );

    Ok(Token::Tuple(vec![addr, prev_tx_hash, output_index, output_script_type, script_sig]))
}

pub fn encode_tx_data(tx_data: &DecodeRawTransactionResult) -> Result<Bytes, EncodingError> {
    let txid = Token::FixedBytes(Vec::from_hex(&tx_data.txid.to_string()).map_err(|e| EncodingError::DecodingError(e.to_string()))?);
    
    let outputs = Token::Array(
        tx_data.vout.iter()
            .map(encode_output)
            .collect::<Result<Vec<_>, _>>()?
    );

    let inputs = Token::Array(
        tx_data.vin.iter()
            .map(encode_input)
            .collect::<Result<Vec<_>, _>>()?
    );
    
    let locktime = Token::Uint(ethabi::Uint::from(tx_data.locktime));

    let encoded = encode(&[
        Token::Tuple(vec![txid, outputs, inputs, locktime])
    ]);

    Ok(Bytes::from(encoded))
}
