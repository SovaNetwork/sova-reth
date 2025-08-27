use super::sova_trait::{Inspector, SlotRevert};
use crate::inspector::SovaInspector;
use alloy_primitives::{Address, B256, U256};

#[derive(Default, Debug)]
pub struct InspectorHandle {
    inner: Option<Box<dyn Inspector>>,
}

impl InspectorHandle {
    pub fn new<I: Inspector + 'static>(inspector: I) -> Self {
        Self {
            inner: Some(Box::new(inspector)),
        }
    }

    pub fn none() -> Self {
        Self { inner: None }
    }

    // 🔧 Run a closure with &mut SovaInspector if present
    fn with_sova_mut<R>(&mut self, f: impl FnOnce(&mut SovaInspector) -> R) -> Option<R> {
        let i = self.inner.as_mut()?;
        let sova = i.as_any_mut().downcast_mut::<SovaInspector>()?;
        Some(f(sova))
    }

    // Merge lock_data from another SovaInspector (collected during Pass #2)
    pub fn append_lock_data_from(&mut self, other: &mut SovaInspector) {
        let _ = self.with_sova_mut(|s| {
            s.cache.lock_data.extend(other.cache.lock_data.drain());
        });
    }

    // --- passthrough hook helpers ---
    pub fn on_block_start(&mut self) {
        if let Some(i) = self.inner.as_mut() {
            i.on_block_start();
        }
    }
    pub fn on_block_end(&mut self) {
        if let Some(i) = self.inner.as_mut() {
            i.on_block_end();
        }
    }
    pub fn on_tx_start(&mut self, tx_hash: B256) {
        if let Some(i) = self.inner.as_mut() {
            i.on_tx_start(tx_hash);
        }
    }
    pub fn on_tx_end(&mut self, tx_hash: B256) {
        if let Some(i) = self.inner.as_mut() {
            i.on_tx_end(tx_hash);
        }
    }
    pub fn on_sstore(&mut self, addr: Address, slot: U256, prev: U256, newv: U256) {
        if let Some(i) = self.inner.as_mut() {
            i.on_sstore(addr, slot, prev, newv);
        }
    }
    pub fn on_broadcast_end(&mut self, txid: [u8; 32], btc_block: u64) {
        if let Some(i) = self.inner.as_mut() {
            i.on_broadcast_end(txid, btc_block);
        }
    }
    pub fn take_slot_reverts(&mut self) -> Vec<(Address, SlotRevert)> {
        if let Some(i) = self.inner.as_mut() {
            i.take_slot_reverts()
        } else {
            Vec::new()
        }
    }

    pub fn update_sentinel_locks(
        &mut self,
        block_number: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // only acts if the inner inspector is SovaInspector
        if let Some(Ok(())) = self.with_sova_mut(|s| s.update_sentinel_locks(block_number)) {
            return Ok(());
        }
        Ok(())
    }
}
