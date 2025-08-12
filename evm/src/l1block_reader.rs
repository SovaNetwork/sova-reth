use alloy_primitives::{Address, B256, U256};
use eyre::Result;

pub struct L1BlockInfo {
    pub btc_height: u64,
    pub btc_hash: B256,
}

// These slots must match your SovaL1Block.sol layout
const SLOT_BTC_HEIGHT: U256 = U256::from_limbs([0, 0, 0, 0]);
const SLOT_BTC_HASH: U256 = U256::from_limbs([1, 0, 0, 0]);

pub trait StorageReader {
    fn storage(&self, addr: Address, slot: U256) -> Result<U256>;
}

pub fn read_l1block_from_db(db: &dyn StorageReader, addr: Address) -> Result<L1BlockInfo> {
    let h = db.storage(addr, SLOT_BTC_HEIGHT)?;
    let hh = db.storage(addr, SLOT_BTC_HASH)?;
    Ok(L1BlockInfo {
        btc_height: h.as_limbs()[0] as u64,
        btc_hash: B256::from(hh.to_be_bytes()),
    })
}
