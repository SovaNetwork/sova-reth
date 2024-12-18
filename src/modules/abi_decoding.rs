use alloy_dyn_abi::{DynSolType, DynSolValue};
use reth::revm::precompile::{PrecompileError, PrecompileErrors};

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
