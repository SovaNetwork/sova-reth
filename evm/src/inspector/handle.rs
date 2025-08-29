use crate::inspector::SovaInspector;

use super::sova_trait::Inspector;

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

    // Run a closure with &mut SovaInspector if present
    fn with_sova_mut<R>(&mut self, f: impl FnOnce(&mut SovaInspector) -> R) -> Option<R> {
        let i = self.inner.as_mut()?;
        let sova = i.as_any_mut().downcast_mut::<SovaInspector>()?;
        Some(f(sova))
    }

    // Merge lock_data from another SovaInspector (collected during execution Pass #2)
    pub fn append_lock_data_from(&mut self, other: &mut SovaInspector) {
        let _ = self.with_sova_mut(|s| {
            s.cache.lock_data.extend(other.cache.lock_data.drain());
        });
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
