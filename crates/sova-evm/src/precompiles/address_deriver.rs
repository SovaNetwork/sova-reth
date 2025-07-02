use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, PublicKey};

use reth_revm::precompile::PrecompileError;
use reth_tracing::tracing::warn;

use sova_chainspec::SOVA_ADDR_CONVERT_DOMAIN_TAG;

/// Client-side Bitcoin address deriver using extended public key derivation
/// This allows deterministic Bitcoin address conversion without calling the enclave
#[derive(Clone, Debug)]
pub struct SovaAddressDeriver {
    /// Extended public key derived from m/44'/0' - safe to share publicly
    ethereum_xpub: Xpub,
    /// Bitcoin network for address generation
    network: Network,
    /// Secp256k1 context for public key operations (verification only)
    secp: Secp256k1<bitcoin::secp256k1::VerifyOnly>,
}

impl SovaAddressDeriver {
    /// Initialize with the network's Ethereum derivation extended public key
    /// This xpub is derived from m/44'/0' and is safe to share publicly
    pub fn new(ethereum_xpub: Xpub, network: Network) -> Self {
        Self {
            ethereum_xpub,
            network,
            secp: Secp256k1::verification_only(),
        }
    }

    /// Convert Ethereum address to BIP32 derivation path using hash-based approach
    /// This eliminates collisions while ensuring all child numbers are non-hardened
    ///
    /// Collision resistance: SHA256 provides 2^128 security against birthday attacks,
    /// which is more than sufficient for the 2^160 Ethereum address space
    fn evm_address_to_derivation_path(evm_address: &[u8; 20]) -> DerivationPath {
        // Hash the Ethereum address to get uniform distribution and avoid collisions
        let mut engine = sha256::Hash::engine();
        engine.input(SOVA_ADDR_CONVERT_DOMAIN_TAG);
        engine.input(evm_address);
        let hash = sha256::Hash::from_engine(engine);
        let hash_bytes = hash.to_byte_array();

        // Split 32-byte hash into chunks for BIP32 derivation path
        //
        // Entropy analysis:
        // - Input: 256 bits (SHA256 hash of Ethereum address)
        // - Output: 7-level derivation path using 217 bits (7 × 31 bits)
        // - Entropy utilization: 217/256 = 85% (39 bits unused)
        // - Birthday paradox: √(2^217) = 2^(217/2) = 2^108.5
        // - Security: ~2^108 operations needed to find collision
        //
        // Design analysis:
        // - 7 levels chosen for reasonable path depth vs entropy trade-off
        // - 31 bits per level (0x7FFFFFFF mask) ensures non-hardened derivation
        // - Remaining 39 bits provide no additional security benefit given 2^160 Ethereum address space
        // - Could use all 8 chunks (248 bits) but depth/simplicity trade-off favors current approach
        let mut chunks = Vec::new();

        for i in 0..7 {
            let chunk_start = i * 4;
            let chunk_bytes = &hash_bytes[chunk_start..chunk_start + 4];

            // Convert 4 bytes to u32 and mask to ensure non-hardened
            // BIP32 rules say child numbers gte 2^31 (0x80000000) are hardened
            // Masking with 0x7FFFFFFF ensures value is always < 2^31
            let value = u32::from_be_bytes([
                chunk_bytes[0],
                chunk_bytes[1],
                chunk_bytes[2],
                chunk_bytes[3],
            ]) & 0x7FFFFFFF;

            chunks.push(ChildNumber::from(value));
        }

        DerivationPath::from(chunks)
    }

    /// Derive Bitcoin address from Ethereum address using public key derivation
    pub fn derive_bitcoin_address(
        &self,
        evm_address: &[u8; 20],
    ) -> Result<Address, PrecompileError> {
        // Get the derivation path for this Ethereum address
        let path = Self::evm_address_to_derivation_path(evm_address);

        // Derive the child public key using the path
        let child_xpub = self
            .ethereum_xpub
            .derive_pub(&self.secp, &path)
            .map_err(|e| {
                warn!("Failed to derive child public key: {}", e);
                PrecompileError::Other(format!("Failed to derive child public key: {}", e))
            })?;

        // Convert to Bitcoin address (P2WPKH)
        let public_key = PublicKey::new(child_xpub.public_key);
        let address = Address::p2wpkh(&public_key, self.network).map_err(|e| {
            warn!("Failed to create P2WPKH address: {}", e);
            PrecompileError::Other(format!("Failed to create P2WPKH address: {}", e))
        })?;

        Ok(address)
    }
}
