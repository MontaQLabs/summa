//! Client-side utilities for Summa
//!
//! This module provides convenient functions for clients (wallets, dApps)
//! to interact with Summa-enabled contracts.
//!
//! NOTE: Some functions here require `std` feature for randomness.

use crate::ciphertext::Ciphertext;
use crate::curve::Scalar;
use crate::keys::{KeyPair, PublicKey};
use crate::range_proof::{RangeProof, TransferProof};
use crate::FheError;

/// A wallet for managing encrypted balances
pub struct ConfidentialWallet {
    keypair: KeyPair,
}

impl ConfidentialWallet {
    /// Create a new wallet from a seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        ConfidentialWallet {
            keypair: KeyPair::from_seed(seed),
        }
    }

    /// Get the public key (share this with the contract)
    pub fn public_key(&self) -> &PublicKey {
        &self.keypair.public
    }

    /// Get the public key as bytes for contract registration
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.public.to_bytes()
    }

    /// Encrypt an amount for deposit or transfer
    ///
    /// # Arguments
    /// * `amount` - The amount to encrypt
    /// * `randomness_seed` - Seed for deterministic randomness (use fresh random in production!)
    pub fn encrypt_amount(&self, amount: u64, randomness_seed: &[u8; 32]) -> Result<Ciphertext, FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        self.keypair.public.encrypt(amount, &randomness)
    }

    /// Encrypt an amount for sending to another public key
    pub fn encrypt_for(&self, amount: u64, recipient: &PublicKey, randomness_seed: &[u8; 32]) -> Result<Ciphertext, FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        recipient.encrypt(amount, &randomness)
    }

    /// Decrypt a ciphertext (e.g., your balance)
    ///
    /// NOTE: This only works for small values (up to ~1 million by default)
    /// due to discrete log computation
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64, FheError> {
        self.keypair.decrypt(ciphertext)
    }

    /// Create a transfer proof
    ///
    /// # Arguments
    /// * `transfer_amount` - Amount to transfer
    /// * `current_balance` - Your current (decrypted) balance
    /// * `randomness_seed` - Seed for proof randomness
    pub fn create_transfer_proof(
        &self,
        transfer_amount: u64,
        current_balance: u64,
        transfer_randomness: &[u8; 32],
        new_balance_randomness: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<TransferData, TransferError> {
        if transfer_amount > current_balance {
            return Err(TransferError::InsufficientBalance);
        }

        let new_balance = current_balance - transfer_amount;

        // Create randomness scalars
        let transfer_rand = Scalar::random_with_seed(transfer_randomness);
        let balance_rand = Scalar::random_with_seed(new_balance_randomness);

        // Encrypt the transfer amount
        let encrypted_amount = self.keypair.public.encrypt(transfer_amount, &transfer_rand)
            .map_err(|_| TransferError::EncryptionFailed)?;

        // Encrypt the new balance (for proof)
        let encrypted_new_balance = self.keypair.public.encrypt(new_balance, &balance_rand)
            .map_err(|_| TransferError::EncryptionFailed)?;

        // Create the transfer proof
        let proof = TransferProof::create(
            transfer_amount,
            current_balance,
            &transfer_rand,
            &balance_rand,
            &self.keypair.public,
            proof_seed,
        ).map_err(|_| TransferError::ProofCreationFailed)?;

        Ok(TransferData {
            encrypted_amount,
            encrypted_new_balance,
            proof,
        })
    }

    /// Create a simple range proof for an amount
    pub fn create_range_proof(
        &self,
        value: u64,
        randomness_seed: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<(Ciphertext, RangeProof), FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        let ciphertext = self.keypair.public.encrypt(value, &randomness)?;

        let proof = RangeProof::create(
            value,
            &randomness,
            &self.keypair.public,
            64,
            proof_seed,
        ).map_err(|_| FheError::RangeProofFailed)?;

        Ok((ciphertext, proof))
    }
}

/// Data needed for a confidential transfer
pub struct TransferData {
    /// The encrypted transfer amount
    pub encrypted_amount: Ciphertext,
    /// The encrypted new balance (for verification)
    pub encrypted_new_balance: Ciphertext,
    /// The proof that the transfer is valid
    pub proof: TransferProof,
}

impl TransferData {
    /// Encode for sending to the contract
    pub fn encode_for_contract(&self) -> alloc::vec::Vec<u8> {
        use parity_scale_codec::Encode;

        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&self.encrypted_amount.to_bytes());
        let proof_bytes = self.proof.encode();
        data.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&proof_bytes);
        data
    }
}

/// Errors that can occur during transfer preparation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// Not enough balance for transfer
    InsufficientBalance,
    /// Failed to encrypt the amount
    EncryptionFailed,
    /// Failed to create the proof
    ProofCreationFailed,
}

/// Helper to build contract calldata
pub struct CalldataBuilder {
    data: alloc::vec::Vec<u8>,
}

impl CalldataBuilder {
    /// Create a new builder with a function selector
    pub fn new(selector: [u8; 4]) -> Self {
        CalldataBuilder {
            data: selector.to_vec(),
        }
    }

    /// Add an address (20 bytes)
    pub fn add_address(mut self, address: &[u8; 20]) -> Self {
        self.data.extend_from_slice(address);
        self
    }

    /// Add a ciphertext (64 bytes)
    pub fn add_ciphertext(mut self, ct: &Ciphertext) -> Self {
        self.data.extend_from_slice(&ct.to_bytes());
        self
    }

    /// Add raw bytes with length prefix
    pub fn add_bytes(mut self, bytes: &[u8]) -> Self {
        self.data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.data.extend_from_slice(bytes);
        self
    }

    /// Add a 32-byte value
    pub fn add_bytes32(mut self, value: &[u8; 32]) -> Self {
        self.data.extend_from_slice(value);
        self
    }

    /// Build the final calldata
    pub fn build(self) -> alloc::vec::Vec<u8> {
        self.data
    }
}

// Contract function selectors (matching the contract)
pub mod selectors {
    //! Function selectors for the Confidential Asset contract

    /// registerPublicKey(bytes32)
    pub const REGISTER_PUBKEY: [u8; 4] = [0x12, 0x34, 0xab, 0xcd];

    /// transfer(address,bytes,bytes)
    pub const TRANSFER: [u8; 4] = [0x56, 0x78, 0xef, 0xab];

    /// deposit(bytes)
    pub const DEPOSIT: [u8; 4] = [0x9a, 0xbc, 0x01, 0x23];

    /// getEncryptedBalance(address)
    pub const GET_BALANCE: [u8; 4] = [0xde, 0xf4, 0x56, 0x78];

    /// mint(address,bytes)
    pub const MINT: [u8; 4] = [0xaa, 0xbb, 0x11, 0x22];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_encrypt_decrypt() {
        let wallet = ConfidentialWallet::from_seed(&[42u8; 32]);

        let amount = 12345u64;
        let ct = wallet.encrypt_amount(amount, &[1u8; 32]).unwrap();
        let decrypted = wallet.decrypt(&ct).unwrap();

        assert_eq!(amount, decrypted);
    }

    #[test]
    fn test_calldata_builder() {
        let wallet = ConfidentialWallet::from_seed(&[42u8; 32]);
        let pubkey_bytes = wallet.public_key_bytes();

        let calldata = CalldataBuilder::new(selectors::REGISTER_PUBKEY)
            .add_bytes32(&pubkey_bytes)
            .build();

        assert_eq!(calldata.len(), 4 + 32); // selector + pubkey
        assert_eq!(&calldata[..4], &selectors::REGISTER_PUBKEY);
    }

    #[test]
    fn test_transfer_data_creation() {
        let wallet = ConfidentialWallet::from_seed(&[42u8; 32]);

        let result = wallet.create_transfer_proof(
            100,    // transfer amount
            1000,   // current balance
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        assert!(result.is_ok());
        let transfer_data = result.unwrap();

        // Verify the encrypted amount decrypts correctly
        let decrypted = wallet.decrypt(&transfer_data.encrypted_amount).unwrap();
        assert_eq!(decrypted, 100);
    }
}

