use alloy_dyn_abi::{DynSolType, DynSolValue};
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors};

pub struct DecodedInput {
    #[allow(dead_code)]
    pub method_selector: Vec<u8>,
    pub signer: String,
    pub amount: u64,
    pub destination: String,
    pub utxos: Vec<DynSolValue>,
}

pub fn decode_input(input: &[u8]) -> Result<DecodedInput, PrecompileErrors> {
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
            destination: extract_string(&values[3])?,
            utxos: extract_array(&values[4])?,
        })
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid input structure",
        )))
    }
}

pub fn parse_utxos(utxos: &[DynSolValue]) -> Result<Vec<serde_json::Value>, PrecompileErrors> {
    utxos
        .iter()
        .map(|utxo| {
            if let DynSolValue::Tuple(utxo_values) = utxo {
                Ok(serde_json::json!({
                    "txid": hex::encode(extract_fixed_bytes(&utxo_values[0], 32)?),
                    "vout": extract_uint(&utxo_values[1])?,
                    "amount": extract_uint(&utxo_values[2])?,
                }))
            } else {
                Err(PrecompileErrors::Error(PrecompileError::other(
                    "Invalid UTXO structure",
                )))
            }
        })
        .collect()
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

fn extract_array(value: &DynSolValue) -> Result<Vec<DynSolValue>, PrecompileErrors> {
    if let DynSolValue::Array(arr) = value {
        Ok(arr.clone())
    } else {
        Err(PrecompileErrors::Error(PrecompileError::other(
            "Invalid array",
        )))
    }
}
