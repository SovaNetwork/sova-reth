use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
};

use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{address, b256, Address, Bytes, U256};

use reth_chainspec::{BaseFeeParams, BaseFeeParamsKind, Chain, ChainSpec};
use reth_optimism_chainspec::{make_op_genesis_header, OpChainSpec};
use reth_primitives_traits::SealedHeader;
use reth_revm::primitives::hex;

use super::constants::{
    sova_btc_contract_storage, sova_devnet_forks, sova_l1_block_contract_storage,
    L1_BLOCK_CONTRACT_CODE, SOVA_BTC_CONTRACT_ADDRESS, SOVA_BTC_CONTRACT_CODE,
    SOVA_L1_BLOCK_CONTRACT_ADDRESS,
};

/// Sova testnet derivation xpub
pub const SOVA_TESTNET_DERIVATION_XPUB: &str = "tpubDBDW1EWi7SNXqzpbci5DUc9HuXhx3cUPZ1wyjgxWmDTpwNQR9ijpEb9VomyDEoH7rAZiGmC9f2yQFfqDn5z4H54NavPGK8yuTLJC8JZzTv9";

/// Sova dev devnet specification.
pub static DEV: LazyLock<Arc<OpChainSpec>> = LazyLock::new(|| {
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
        .with_base_fee(Some(0x3b9aca00u128)) // 1 gwei
        .extend_accounts(vec![
            // first dev account in anvil
            // pk: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
            (
                Address::from(hex!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")),
                GenesisAccount::default().with_balance(U256::from(10).pow(U256::from(18))),
            ),
            // Sova L1Block contract
            (
                SOVA_L1_BLOCK_CONTRACT_ADDRESS,
                GenesisAccount::default()
                    .with_code(Some(Bytes::from_str(L1_BLOCK_CONTRACT_CODE).unwrap()))
                    .with_storage(Some(sova_l1_block_contract_storage())),
            ),
            // SovaBTC contract
            (
                SOVA_BTC_CONTRACT_ADDRESS,
                GenesisAccount::default()
                    .with_code(Some(Bytes::from_str(SOVA_BTC_CONTRACT_CODE).unwrap()))
                    .with_storage(Some(sova_btc_contract_storage()))
                    .with_balance(U256::from(0)),
            ),
        ]);

    let hardforks = sova_devnet_forks();
    let genesis_header = SealedHeader::seal_slow(make_op_genesis_header(&genesis, &hardforks));

    OpChainSpec {
        inner: ChainSpec {
            chain: Chain::from_id(120893),
            genesis_header,
            genesis,
            paris_block_and_final_difficulty: Some((0, U256::from(0))),
            hardforks,
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            ..Default::default()
        },
    }
    .into()
});
