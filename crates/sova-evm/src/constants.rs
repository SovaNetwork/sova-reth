use alloy_primitives::{address, Address};

pub const BTC_PRECOMPILE_ADDRESS: Address = address!("0000000000000000000000000000000000000999");

pub const L1_BLOCK_CONTRACT_ADDRESS: Address =
    address!("0x4200000000000000000000000000000000000015"); // TODO rm duplicate in chainspec
pub const L1_BLOCK_CONTRACT_CALLER: Address =
    address!("0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");
