//! Veil Proof-of-Personhood primitives

use parity_scale_codec::{Decode, Encode};
use crate::curve::{CurvePoint, hash_to_point, pedersen_h};
use crate::dleq::DleqProof;
use crate::keys::{SecretKey, PublicKey};
use crate::range_proof::RangeProofError;

/// Enrollment nullifier to prevent double enrollment
#[derive(Clone, Debug, Encode, Decode)]
pub struct EnrollmentNullifier {
    /// The nullifier point N = sk * G_enroll
    pub nullifier: [u8; 32],
    /// Proof that log_H(pk) == log_G_enroll(N)
    pub proof: DleqProof,
}

impl EnrollmentNullifier {
    /// Create an enrollment nullifier
    pub fn create(sk: &SecretKey, seed: &[u8; 32]) -> Result<Self, RangeProofError> {
        let h = pedersen_h();
        let pk = sk.public_key();
        let pk_point = pk.to_point().map_err(|_| RangeProofError::CryptoError)?;
        
        let g_enroll = hash_to_point(b"Veil_Enrollment_Base_v1_________");
        let n = g_enroll.mul_scalar(sk.as_scalar());
        
        let proof = DleqProof::create(
            sk.as_scalar(),
            &h,
            &g_enroll,
            &pk_point,
            &n,
            seed
        )?;
        
        Ok(EnrollmentNullifier {
            nullifier: n.compress().0,
            proof,
        })
    }

    /// Verify an enrollment nullifier
    pub fn verify(&self, pk: &PublicKey) -> Result<bool, RangeProofError> {
        let h = pedersen_h();
        let pk_point = pk.to_point().map_err(|_| RangeProofError::CryptoError)?;
        let g_enroll = hash_to_point(b"Veil_Enrollment_Base_v1_________");
        let n_point = CurvePoint::decompress(&crate::curve::CompressedPoint(self.nullifier))
            .map_err(|_| RangeProofError::InvalidProof)?;
            
        self.proof.verify(&h, &g_enroll, &pk_point, &n_point)
    }
}

/// Context-specific nullifier for unlinkable actions (voting, airdrops)
#[derive(Clone, Debug, Encode, Decode)]
pub struct ApplicationNullifier {
    /// The nullifier point N = sk * H_context
    pub nullifier: [u8; 32],
    /// Proof that log_H(pk) == log_H_context(N)
    pub proof: DleqProof,
}

impl ApplicationNullifier {
    /// Create an application nullifier for a specific context
    pub fn create(sk: &SecretKey, context_id: &[u8; 32], seed: &[u8; 32]) -> Result<Self, RangeProofError> {
        let h = pedersen_h();
        let pk = sk.public_key();
        let pk_point = pk.to_point().map_err(|_| RangeProofError::CryptoError)?;
        
        let h_context = hash_to_point(context_id);
        let n = h_context.mul_scalar(sk.as_scalar());
        
        let proof = DleqProof::create(
            sk.as_scalar(),
            &h,
            &h_context,
            &pk_point,
            &n,
            seed
        )?;
        
        Ok(ApplicationNullifier {
            nullifier: n.compress().0,
            proof,
        })
    }

    /// Verify an application nullifier
    pub fn verify(&self, pk: &PublicKey, context_id: &[u8; 32]) -> Result<bool, RangeProofError> {
        let h = pedersen_h();
        let pk_point = pk.to_point().map_err(|_| RangeProofError::CryptoError)?;
        let h_context = hash_to_point(context_id);
        let n_point = CurvePoint::decompress(&crate::curve::CompressedPoint(self.nullifier))
            .map_err(|_| RangeProofError::InvalidProof)?;
            
        self.proof.verify(&h, &h_context, &pk_point, &n_point)
    }
}
