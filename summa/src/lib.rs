#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Summa - Homomorphic Encryption for Polkadot PVM
//!
//! Internal module version of the Summa library, embedded inside the
//! contract crate so we can reuse the existing build configuration.

#[cfg(not(test))]
extern crate alloc;

#[cfg(test)]
extern crate std as alloc;

mod ciphertext;
pub mod curve;
mod dleq;
mod keys;
mod range_proof;
mod shielded;
mod veil;
pub mod client;

pub use ciphertext::Ciphertext;
pub use curve::{CompressedPoint, CurvePoint, Scalar};
pub use dleq::DleqProof;
pub use keys::{KeyPair, PublicKey, SecretKey};
pub use range_proof::{EqualityProof, RangeProof, RangeProofError, TransferProof, AffineUpdateProof};
pub use shielded::Note;
pub use veil::{EnrollmentNullifier, ApplicationNullifier};
pub use client::{CalldataBuilder, ConfidentialWallet, TransferData, TransferError, SplitTransferData};

pub use parity_scale_codec::{Decode, Encode};

/// The bit-width for range proofs (values must be in \[0, 2^RANGE_BITS))
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

#[cfg(test)]
mod tests;
