use alloy_primitives::{address, b256, Address};
use reth_chainspec::DepositContract;

pub(crate) const MAINNET_DEPOSIT_CONTRACT_ADDR: Address =
    address!("4242424242424242424242424242424242424242");

pub(crate) const MAINNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    MAINNET_DEPOSIT_CONTRACT_ADDR, // specified in genesis json
    0,                             // pre-deployed at genesis
    b256!("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);
