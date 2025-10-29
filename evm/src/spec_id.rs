//! Contains the `[SovaSpecId]` type and its implementation.

use op_revm::OpSpecId;

/// Sova spec id that wraps OpSpecId and adds Sova-specific hardfork information.
///
/// This allows us to track whether the Beta hardfork is active, which affects
/// Bitcoin address derivation (chooses between SOVA_MAINNET_DERIVATION_XPUB and
/// SOVA_MAINNET_DERIVATION_XPUB_BETA).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SovaSpecId {
    /// The underlying OP Stack spec ID
    pub op_spec: OpSpecId,
    /// Whether the Beta hardfork is active (block >= 1280000)
    pub is_beta_active: bool,
}

impl SovaSpecId {
    /// Create a new SovaSpecId with the given OpSpecId and Beta status.
    pub const fn new(op_spec: OpSpecId, is_beta_active: bool) -> Self {
        Self {
            op_spec,
            is_beta_active,
        }
    }

    /// Create a SovaSpecId from OpSpecId with Beta inactive.
    pub const fn from_op_spec(op_spec: OpSpecId) -> Self {
        Self::new(op_spec, false)
    }

    /// Create a SovaSpecId with Beta active.
    pub const fn with_beta(op_spec: OpSpecId) -> Self {
        Self::new(op_spec, true)
    }

    /// Get the underlying OpSpecId.
    pub const fn op_spec(&self) -> OpSpecId {
        self.op_spec
    }

    /// Check if Beta hardfork is active.
    pub const fn is_beta_active(&self) -> bool {
        self.is_beta_active
    }
}

impl Default for SovaSpecId {
    fn default() -> Self {
        Self::from_op_spec(OpSpecId::default())
    }
}

impl From<OpSpecId> for SovaSpecId {
    fn from(op_spec: OpSpecId) -> Self {
        Self::from_op_spec(op_spec)
    }
}

impl From<SovaSpecId> for OpSpecId {
    fn from(spec: SovaSpecId) -> Self {
        spec.op_spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sova_spec_id_creation() {
        let spec = SovaSpecId::new(OpSpecId::BEDROCK, false);
        assert_eq!(spec.op_spec(), OpSpecId::BEDROCK);
        assert!(!spec.is_beta_active());

        let spec_beta = SovaSpecId::with_beta(OpSpecId::ISTHMUS);
        assert_eq!(spec_beta.op_spec(), OpSpecId::ISTHMUS);
        assert!(spec_beta.is_beta_active());
    }

    #[test]
    fn test_from_op_spec() {
        let spec: SovaSpecId = OpSpecId::BEDROCK.into();
        assert_eq!(spec.op_spec(), OpSpecId::BEDROCK);
        assert!(!spec.is_beta_active());
    }

    #[test]
    fn test_into_op_spec() {
        let spec = SovaSpecId::with_beta(OpSpecId::ISTHMUS);
        let op_spec: OpSpecId = spec.into();
        assert_eq!(op_spec, OpSpecId::ISTHMUS);
    }

    #[test]
    fn test_default() {
        let spec = SovaSpecId::default();
        assert_eq!(spec.op_spec(), OpSpecId::default());
        assert!(!spec.is_beta_active());
    }
}
