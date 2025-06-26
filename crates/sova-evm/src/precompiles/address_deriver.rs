use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::{Address, Network, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::hashes::{sha256, Hash};

use reth_revm::precompile::PrecompileError;

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
    fn evm_address_to_derivation_path(evm_address: &[u8; 20]) -> DerivationPath {
        // Hash the Ethereum address to get uniform distribution and avoid collisions
        let hash = sha256::Hash::hash(evm_address);
        let hash_bytes = hash.to_byte_array();
        
        // Split 32-byte hash into 8 chunks of 4 bytes each
        // Use only the first 7 chunks (28 bytes) to stay within reasonable path depth
        let mut chunks = Vec::new();
        
        for i in 0..7 {
            let chunk_start = i * 4;
            let chunk_bytes = &hash_bytes[chunk_start..chunk_start + 4];
            
            // Convert 4 bytes to u32 and mask to ensure non-hardened
            // BIP32 rules state child numbers gte 2^31 (0x80000000) are hardened
            // Masking with 0x7FFFFFFF ensures value is always < 2^31
            let value = u32::from_be_bytes([
                chunk_bytes[0],
                chunk_bytes[1], 
                chunk_bytes[2],
                chunk_bytes[3]
            ]) & 0x7FFFFFFF; // Clear most significant bit to ensure non-hardened
            
            chunks.push(ChildNumber::from(value));
        }
        
        DerivationPath::from(chunks)
    }

    /// Derive Bitcoin address from Ethereum address using public key derivation only
    /// This is cryptographically secure and collision-free
    pub fn derive_bitcoin_address(&self, evm_address: &[u8; 20]) -> Result<Address, PrecompileError> {
        // Get the derivation path for this Ethereum address
        let path = Self::evm_address_to_derivation_path(evm_address);
        
        // Derive the child public key using the path
        let child_xpub = self.ethereum_xpub.derive_pub(&self.secp, &path)
            .map_err(|e| PrecompileError::Other(format!("Failed to derive child public key: {}", e)))?;
        
        // Convert to Bitcoin address (P2WPKH)
        let public_key = PublicKey::new(child_xpub.public_key);
        let address = Address::p2wpkh(&public_key, self.network)
            .map_err(|e| PrecompileError::Other(format!("Failed to create P2WPKH address: {}", e)))?;
        
        Ok(address)
    }

    /// Helper function to convert hex string to bytes (for Ethereum addresses)
    pub fn eth_addr_to_bytes(eth_addr: &str) -> Result<[u8; 20], PrecompileError> {
        let eth_addr = eth_addr.strip_prefix("0x").unwrap_or(eth_addr);
        let bytes = hex::decode(eth_addr)
            .map_err(|e| PrecompileError::Other(format!("Invalid hex in Ethereum address: {}", e)))?;
        
        if bytes.len() != 20 {
            return Err(PrecompileError::Other(format!(
                "Ethereum address must be 20 bytes, got {}", 
                bytes.len()
            )));
        }
        
        let mut array = [0u8; 20];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}