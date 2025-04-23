//! Optimism-specific implementation and utilities for the executor

use alloy_consensus::Transaction;
use alloy_primitives::{hex, U256};
use op_revm::L1BlockInfo;
use reth_execution_errors::BlockExecutionError;
use reth_optimism_forks::OpHardforks;
use reth_primitives_traits::BlockBody;

/// The function selector of the "setBitcoinBlockData" function in the `L1Block` contract.
const L1_BLOCK_SATOSHI_SELECTOR: [u8; 4] = hex!("b0b42b30");

/// Extracts the [`L1BlockInfo`] from the L2 block. The L1 info transaction is always the first
/// transaction in the L2 block.
///
/// Returns an error if the L1 info transaction is not found, if the block is empty.
pub fn extract_l1_info<B: BlockBody>(body: &B) -> Result<L1BlockInfo, OpBlockExecutionError> {
    let l1_info_tx = body
        .transactions()
        .first()
        .ok_or(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::MissingTransaction))?;
    extract_l1_info_from_tx(l1_info_tx)
}

/// Extracts the [`L1BlockInfo`] from the L1 info transaction (first transaction) in the L2
/// block.
///
/// Returns an error if the calldata is shorter than 4 bytes.
pub fn extract_l1_info_from_tx<T: Transaction>(
    tx: &T,
) -> Result<L1BlockInfo, OpBlockExecutionError> {
    let l1_info_tx_data = tx.input();
    if l1_info_tx_data.len() < 4 {
        return Err(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::InvalidCalldata));
    }

    parse_l1_info(l1_info_tx_data)
}

/// Parses the input of the first transaction in the L2 block, into [`L1BlockInfo`].
///
/// Returns an error if data is incorrect length.
///
/// Caution this expects that the input is the calldata of the [`L1BlockInfo`] transaction (first
/// transaction) in the L2 block.
///
/// # Panics
/// If the input is shorter than 4 bytes.
pub fn parse_l1_info(input: &[u8]) -> Result<L1BlockInfo, OpBlockExecutionError> {
    // Parse the L1 info transaction into an L1BlockInfo struct, depending on the function selector.
    // There is currently 1 variants:
    // - Satoshi
    if input[0..4] == L1_BLOCK_SATOSHI_SELECTOR {
        parse_l1_info_tx_satoshi(input[4..].as_ref())
    } else {
        return Err(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::UnexpectedCalldataLength))
    }
}

pub fn parse_l1_info_tx_satoshi(data: &[u8]) -> Result<L1BlockInfo, OpBlockExecutionError> {
    if data.len() != 172 {
        return Err(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::UnexpectedCalldataLength));
    }

    // https://github.com/ethereum-optimism/op-geth/blob/60038121c7571a59875ff9ed7679c48c9f73405d/core/types/rollup_cost.go#L317-L328
    //
    // data layout assumed for Ecotone:
    // offset type varname
    // 0     <selector>
    // 4     uint32 _basefeeScalar (start offset in this scope)
    // 8     uint32 _blobBaseFeeScalar
    // 12    uint64 _sequenceNumber,
    // 20    uint64 _timestamp,
    // 28    uint64 _l1BlockNumber
    // 36    uint256 _basefee,
    // 68    uint256 _blobBaseFee,
    // 100   bytes32 _hash,
    // 132   bytes32 _batcherHash,
    // 164   uint32 _operatorFeeScalar
    // 168   uint64 _operatorFeeConstant

    let l1_base_fee_scalar = U256::try_from_be_slice(&data[..4])
        .ok_or(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::BaseFeeScalarConversion))?;
    let l1_blob_base_fee_scalar = U256::try_from_be_slice(&data[4..8]).ok_or({
        OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::BlobBaseFeeScalarConversion)
    })?;
    let l1_base_fee = U256::try_from_be_slice(&data[32..64])
        .ok_or(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::BaseFeeConversion))?;
    let l1_blob_base_fee = U256::try_from_be_slice(&data[64..96])
        .ok_or(OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::BlobBaseFeeConversion))?;
    let operator_fee_scalar = U256::try_from_be_slice(&data[160..164]).ok_or({
        OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::OperatorFeeScalarConversion)
    })?;
    let operator_fee_constant = U256::try_from_be_slice(&data[164..172]).ok_or({
        OpBlockExecutionError::L1BlockInfo(L1BlockInfoError::OperatorFeeConstantConversion)
    })?;

    let mut l1block = L1BlockInfo::default();
    l1block.l1_base_fee = l1_base_fee;
    l1block.l1_base_fee_scalar = l1_base_fee_scalar;
    l1block.l1_blob_base_fee = Some(l1_blob_base_fee);
    l1block.l1_blob_base_fee_scalar = Some(l1_blob_base_fee_scalar);
    l1block.operator_fee_scalar = Some(operator_fee_scalar);
    l1block.operator_fee_constant = Some(operator_fee_constant);

    Ok(l1block)
}

/// An extension trait for [`L1BlockInfo`] that allows us to calculate the L1 cost of a transaction
/// based off of the chain spec's activated hardfork.
pub trait RethL1BlockInfo {
    /// Forwards an L1 transaction calculation to revm and returns the gas cost.
    ///
    /// ### Takes
    /// - `chain_spec`: The chain spec for the node.
    /// - `timestamp`: The timestamp of the current block.
    /// - `input`: The calldata of the transaction.
    /// - `is_deposit`: Whether or not the transaction is a deposit.
    fn l1_tx_data_fee(
        &mut self,
        chain_spec: impl OpHardforks,
        timestamp: u64,
        input: &[u8],
        is_deposit: bool,
    ) -> Result<U256, BlockExecutionError>;

    /// Computes the data gas cost for an L2 transaction.
    ///
    /// ### Takes
    /// - `chain_spec`: The chain spec for the node.
    /// - `timestamp`: The timestamp of the current block.
    /// - `input`: The calldata of the transaction.
    fn l1_data_gas(
        &self,
        chain_spec: impl OpHardforks,
        timestamp: u64,
        input: &[u8],
    ) -> Result<U256, BlockExecutionError>;
}

impl RethL1BlockInfo for L1BlockInfo {
    fn l1_tx_data_fee(
        &mut self,
        chain_spec: impl OpHardforks,
        timestamp: u64,
        input: &[u8],
        is_deposit: bool,
    ) -> Result<U256, BlockExecutionError> {
        if is_deposit {
            return Ok(U256::ZERO);
        }

        let spec_id = revm_spec_by_timestamp_after_bedrock(&chain_spec, timestamp);
        Ok(self.calculate_tx_l1_cost(input, spec_id))
    }

    fn l1_data_gas(
        &self,
        chain_spec: impl OpHardforks,
        timestamp: u64,
        input: &[u8],
    ) -> Result<U256, BlockExecutionError> {
        let spec_id = revm_spec_by_timestamp_after_bedrock(&chain_spec, timestamp);
        Ok(self.data_gas(input, spec_id))
    }
}