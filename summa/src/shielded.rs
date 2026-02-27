//! Shielded pool primitives for Summa







use parity_scale_codec::{Decode, Encode};
use crate::ciphertext::Ciphertext;
use crate::curve::{Scalar, simple_hash};
use crate::keys::PublicKey;
use crate::FheError;

/// A confidential note in the shielded pool
#[derive(Clone, Debug, Encode, Decode)]
pub struct Note {
    /// The encrypted value of the note
    pub ciphertext: Ciphertext,
    /// The nullifier to prevent double-spending
    pub nullifier: [u8; 32],
}

impl Note {
    /// Create a new note from a value and randomness
    pub fn create(
        value: u64,
        randomness: &Scalar,
        public_key: &PublicKey,
        nullifier_seed: &[u8; 32],
    ) -> Result<Self, FheError> {
        let ciphertext = public_key.encrypt(value, randomness)?;
        
        // Compute nullifier: H(randomness, public_key)
        // This ensures the nullifier is deterministic given the note's secrets
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&randomness.to_bytes());
        let pk_bytes = public_key.to_bytes();
        let nullifier = simple_hash(&[&seed, &pk_bytes, nullifier_seed]);
        
        Ok(Note {
            ciphertext,
            nullifier,
        })
    }
}
