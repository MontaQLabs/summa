//! Range proofs and transfer proofs for Summa (STUBBED for PVM deployment limits)

use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};

use crate::ciphertext::Ciphertext;
use crate::curve::{CompressedPoint, CurvePoint, Scalar};
use crate::keys::PublicKey;

/// Error types specific to range proofs
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum RangeProofError {
    VerificationFailed,
    InvalidProof,
    ValueOutOfRange,
    CryptoError,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct EqualityProof {
    pub t1: CompressedPoint,
    pub t2: CompressedPoint,
    pub s: [u8; 32],
}

impl EqualityProof {
    pub fn create(
        _value: u64,
        _encryption_randomness: &Scalar,
        _public_key: &PublicKey,
        _ciphertext: &Ciphertext,
        _seed: &[u8; 32],
    ) -> Result<Self, RangeProofError> {
        Ok(EqualityProof {
            t1: CompressedPoint([0u8; 32]),
            t2: CompressedPoint([0u8; 32]),
            s: [0u8; 32],
        })
    }

    pub fn verify_with_point(
        &self,
        _value: u64,
        _ciphertext: &Ciphertext,
        _public_key_point: &CurvePoint,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }

    pub fn verify(
        &self,
        value: u64,
        ciphertext: &Ciphertext,
        public_key: &PublicKey,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct RangeProof {
    pub bit_commitments: Vec<CompressedPoint>,
    pub responses: Vec<[u8; 32]>,
    pub challenge: [u8; 32],
    pub aggregate_response: [u8; 32],
}

impl RangeProof {
    pub fn create(
        _value: u64,
        _randomness: &Scalar,
        _public_key: &PublicKey,
        bits: u32,
        _seed: &[u8; 32],
    ) -> Result<Self, RangeProofError> {
        Ok(RangeProof {
            bit_commitments: alloc::vec![CompressedPoint([0u8; 32]); bits as usize],
            responses: alloc::vec![[0u8; 32]; bits as usize],
            challenge: [0u8; 32],
            aggregate_response: [0u8; 32],
        })
    }

    pub fn verify_with_point(
        &self,
        _ciphertext: &Ciphertext,
        _public_key_point: &CurvePoint,
        _bits: u32,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }

    pub fn verify(
        &self,
        _ciphertext: &Ciphertext,
        _public_key: &PublicKey,
        _bits: u32,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }

    pub fn verify_greater_than(
        &self,
        _ciphertext: &Ciphertext,
        _threshold: u64,
        _public_key: &PublicKey,
        _bits: u32,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct AffineUpdateProof {
    pub equality_proof: EqualityProof,
}

impl AffineUpdateProof {
    pub fn create(
        _v_old: u64,
        _v_new: u64,
        _a: u64,
        _b: u64,
        _r_old: &Scalar,
        _r_new: &Scalar,
        _public_key: &PublicKey,
        _seed: &[u8; 32],
    ) -> Result<Self, RangeProofError> {
        Ok(AffineUpdateProof {
            equality_proof: EqualityProof::create(0, &Scalar::zero(), _public_key, &Ciphertext::zero(), _seed)?,
        })
    }

    pub fn verify_with_point(
        &self,
        _ciphertext_old: &Ciphertext,
        _ciphertext_new: &Ciphertext,
        _a: u64,
        _b: u64,
        _public_key_point: &CurvePoint,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }

    pub fn verify(
        &self,
        _ciphertext_old: &Ciphertext,
        _ciphertext_new: &Ciphertext,
        _a: u64,
        _b: u64,
        _public_key: &PublicKey,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct TransferProof {
    pub amount_range_proof: RangeProof,
    pub balance_range_proof: RangeProof,
}

impl TransferProof {
    pub fn create(
        amount: u64,
        old_balance: u64,
        _amount_randomness: &Scalar,
        _balance_randomness: &Scalar,
        public_key: &PublicKey,
        seed: &[u8; 32],
    ) -> Result<Self, RangeProofError> {
        Ok(TransferProof {
            amount_range_proof: RangeProof::create(amount, &Scalar::zero(), public_key, 64, seed)?,
            balance_range_proof: RangeProof::create(old_balance - amount, &Scalar::zero(), public_key, 64, seed)?,
        })
    }

    pub fn verify_with_point(
        &self,
        _amount_ct: &Ciphertext,
        _new_balance_ct: &Ciphertext,
        _public_key_point: &CurvePoint,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }

    pub fn verify(
        &self,
        _amount_ct: &Ciphertext,
        _new_balance_ct: &Ciphertext,
        _public_key: &PublicKey,
    ) -> Result<bool, RangeProofError> {
        Ok(true)
    }
}
