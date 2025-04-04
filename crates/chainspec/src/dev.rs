use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
};

use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{address, b256, Address, Bytes, U256};

use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, DepositContract};
use reth_revm::primitives::hex;

use crate::constants::{deposit_contract_storage, DEPOSIT_CONTRACT_ADDRESS, DEPOSIT_CONTRACT_CODE};

/// Sova dev devnet specification.
pub static DEV: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let deposit_contract_storage = deposit_contract_storage();

    let genesis = Genesis::default()
        .with_nonce(0x01d83d)
        .with_timestamp(0x673e4f9b)
        .with_extra_data(Bytes::from_str("0x4853").unwrap())
        .with_gas_limit(0x1c9c380)
        .with_difficulty(U256::from(1))
        .with_mix_hash(b256!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))
        .with_coinbase(address!("0000000000000000000000000000000000000000"))
        .extend_accounts(vec![
            // first dev account in anvil
            // pk: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
            (
                Address::from(hex!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")),
                GenesisAccount::default().with_balance(U256::from(10).pow(U256::from(18))),
            ),
            // PoS deposit contract
            (
                Address::from_str(DEPOSIT_CONTRACT_ADDRESS).unwrap(),
                GenesisAccount::default()
                    .with_code(Some(Bytes::from_str(DEPOSIT_CONTRACT_CODE).unwrap()))
                    .with_storage(Some(deposit_contract_storage))
                    .with_balance(U256::from(0)),
            ),
        ]);

    let mut spec: ChainSpec = ChainSpecBuilder::default()
        .chain(Chain::from_id(120893))
        .genesis(genesis)
        .cancun_activated()
        .build();

    spec.deposit_contract = Some(DepositContract::new(
        Address::from_str(DEPOSIT_CONTRACT_ADDRESS).unwrap(),
        0,
        b256!("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
    ));

    spec.into()
});
