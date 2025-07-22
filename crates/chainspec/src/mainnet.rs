use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
};

use alloy_genesis::Genesis;
use alloy_primitives::{address, b256, Bytes, U256};

use reth_chainspec::Chain;
use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};

use crate::constants::sova_forks;

/// Sova main chain specification.
pub static SOVA: LazyLock<Arc<OpChainSpec>> = LazyLock::new(|| {
    let genesis = Genesis::default()
        .with_nonce(0x01d83d)
        .with_timestamp(0x673e4f9b)
        .with_extra_data(Bytes::from_str("0x4853").unwrap())
        .with_gas_limit(0x1c9c380)
        .with_difficulty(U256::from(1))
        .with_mix_hash(b256!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))
        .with_coinbase(address!("0000000000000000000000000000000000000000"));

    let spec: OpChainSpec = OpChainSpecBuilder::default()
        .chain(Chain::from_id(120893))
        .genesis(genesis)
        .with_forks(sova_forks())
        .build();

    spec.into()
});
