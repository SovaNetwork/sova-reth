use alloy_primitives::{address, Address, U256};

pub const BTC_PRECOMPILE_ADDRESS: Address = address!("0000000000000000000000000000000000000999");

pub const L1_BLOCK_CONTRACT_ADDRESS: Address =
    address!("0x2100000000000000000000000000000000000015"); // TODO rm duplicate in chainspec
pub const L1_BLOCK_CONTRACT_CALLER: Address =
    address!("0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");
pub const L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT: U256 = U256::ZERO;
