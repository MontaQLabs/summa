//! Discrete Log Equality (DLEQ) proof
//!
//! Proves that log_G1(P1) == log_G2(P2) without revealing the secret log.
//! This is used for ownership proofs and contextual nullifiers.

use parity_scale_codec::{Decode, Encode};
use crate::curve::{CurvePoint, Scalar, simple_hash};
use crate::range_proof::RangeProofError;

/// A Discrete Log Equality (DLEQ) proof.
/// Proves that log_G1(P1) == log_G2(P2).
#[derive(Clone, Debug, Encode, Decode)]
pub struct DleqProof {
    /// Commitment T1 = k * G1
    pub t1: [u8; 32],
    /// Commitment T2 = k * G2
    pub t2: [u8; 32],
    /// Response s = k + c * sk
    pub s: [u8; 32],
}

impl DleqProof {
    /// Create a DLEQ proof
    pub fn create(
        sk: &Scalar,
        g1: &CurvePoint,
        g2: &CurvePoint,
        p1: &CurvePoint,
        p2: &CurvePoint,
        seed: &[u8; 32],
    ) -> Result<Self, RangeProofError> {
        let k = Scalar::random_with_seed(seed);
        
        let t1 = g1.mul_scalar(&k).compress();
        let t2 = g2.mul_scalar(&k).compress();
        
        // Challenge c = Hash(G1, G2, P1, P2, T1, T2)
        let challenge_bytes = simple_hash(&[
            &g1.compress().0,
            &g2.compress().0,
            &p1.compress().0,
            &p2.compress().0,
            &t1.0,
            &t2.0,
        ]);
        let c = Scalar::from_hash_output(&challenge_bytes);
        
        // s = k + c * sk
        let s = k.add(&c.mul(sk));
        
        Ok(DleqProof {
            t1: t1.0,
            t2: t2.0,
            s: s.to_bytes(),
        })
    }

    /// Verify a DLEQ proof
    pub fn verify(
        &self,
        g1: &CurvePoint,
        g2: &CurvePoint,
        p1: &CurvePoint,
        p2: &CurvePoint,
    ) -> Result<bool, RangeProofError> {
        let t1 = CurvePoint::decompress(&crate::curve::CompressedPoint(self.t1))
            .map_err(|_| RangeProofError::InvalidProof)?;
        let t2 = CurvePoint::decompress(&crate::curve::CompressedPoint(self.t2))
            .map_err(|_| RangeProofError::InvalidProof)?;
        let s = Scalar::from_bytes(&self.s).map_err(|_| RangeProofError::InvalidProof)?;
        
        // Recompute challenge
        let challenge_bytes = simple_hash(&[
            &g1.compress().0,
            &g2.compress().0,
            &p1.compress().0,
            &p2.compress().0,
            &self.t1,
            &self.t2,
        ]);
        let c = Scalar::from_hash_output(&challenge_bytes);
        
        // Check s * G1 == T1 + c * P1
        let lhs1 = g1.mul_scalar(&s);
        let rhs1 = t1.add(&p1.mul_scalar(&c));
        
        if lhs1 != rhs1 {
            return Ok(false);
        }
        
        // Check s * G2 == T2 + c * P2
        let lhs2 = g2.mul_scalar(&s);
        let rhs2 = t2.add(&p2.mul_scalar(&c));
        
        if lhs2 != rhs2 {
            return Ok(false);
        }
        
        Ok(true)
    }
}
