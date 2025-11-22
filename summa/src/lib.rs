//! # Summa - Homomorphic Encryption for Polkadot PVM
//!
//! A "Somewhat" Homomorphic Encryption (SHE) library using Twisted ElGamal
//! on the JubJub curve, optimized for RISC-V/PVM execution.
//!
//! ## Features
//! - **Additively Homomorphic**: `Encrypt(A) + Encrypt(B) = Encrypt(A + B)`
//! - **Scalar Multiplication**: `Encrypt(A) * k = Encrypt(A * k)`
//! - **Range Proofs**: Verify encrypted values are within bounds (no underflow!)
//! - **no_std Compatible**: Runs on PVM/RISC-V
//!
//! ## Example
//! ```ignore
//! use summa::{KeyPair, Ciphertext};
//!
//! // Client-side: Encrypt a deposit
//! let keypair = KeyPair::generate();
//! let encrypted_deposit = keypair.encrypt(1000u64);
//!
//! // On-chain: Add to balance (contract never sees plaintext!)
//! let new_balance = old_balance.add_encrypted(&encrypted_deposit);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod ciphertext;
mod curve;
mod keys;
mod range_proof;
pub mod client;

pub use ciphertext::Ciphertext;
pub use curve::{CompressedPoint, CurvePoint, Scalar};
pub use keys::{KeyPair, PublicKey, SecretKey};
pub use range_proof::{RangeProof, RangeProofError, TransferProof};
pub use client::{ConfidentialWallet, CalldataBuilder, TransferData, TransferError};

/// Re-export codec for downstream users
pub use parity_scale_codec::{Decode, Encode};

/// The bit-width for range proofs (values must be in [0, 2^RANGE_BITS))
pub const RANGE_BITS: u32 = 64;

/// Library error types
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum FheError {
    /// Failed to deserialize a curve point
    InvalidPoint,
    /// Failed to deserialize a scalar
    InvalidScalar,
    /// Range proof verification failed
    RangeProofFailed,
    /// Generic cryptographic error
    CryptoError,
}

