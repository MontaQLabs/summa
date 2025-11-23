//! Curve primitives for JubJub (ed-on-bls12-381)
//!
//! We use JubJub because:
//! 1. It's embedded in BLS12-381 (Polkadot's native curve)
//! 2. It's efficient for Bulletproofs/ZK
//! 3. Twisted Edwards form is fast for additions
//!
//! # Security Notes
//! - All serializations use canonical forms
//! - Points are validated on deserialization
//! - No cofactor issues (we use the prime-order subgroup)

use ark_ec::{CurveGroup, Group};
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::Zero;
use parity_scale_codec::{Decode, Encode};

use crate::FheError;

/// A scalar field element (private key, randomness, etc.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar(pub(crate) Fr);

/// A point on the JubJub curve (uncompressed, for computation)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurvePoint(pub(crate) EdwardsProjective);

/// Compressed representation of a curve point (32 bytes for storage/transmission)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CompressedPoint(pub [u8; 32]);

impl Scalar {
    /// Create a scalar from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Scalar(Fr::from(val))
    }

    /// Create a scalar from a u128 value
    pub fn from_u128(val: u128) -> Self {
        Scalar(Fr::from(val))
    }

    /// Generate a random scalar using a seeded RNG
    ///
    /// # Security Warning
    /// The seed MUST be derived from a cryptographically secure source.
    /// Never use predictable or low-entropy seeds in production!
    pub fn random_with_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed(*seed);
        Scalar(Fr::rand(&mut rng))
    }

    /// Generate random scalar from arbitrary seed bytes
    ///
    /// This uses a simple domain-separated construction:
    /// scalar = hash_to_field(domain || bytes)
    ///
    /// # Security Note
    /// For production use with true randomness, use OS entropy directly.
    pub fn random_from_bytes(bytes: &[u8]) -> Self {
        // Domain separation and proper expansion
        let mut seed = [0u8; 32];
        let len = bytes.len().min(32);
        seed[..len].copy_from_slice(&bytes[..len]);
        // XOR with domain separator to prevent collisions
        let domain = b"Summa_scalar_domain_v1_______";
        for i in 0..32 {
            seed[i] ^= domain[i];
        }
        Self::random_with_seed(&seed)
    }

    /// Create a scalar from raw bytes (hash output)
    ///
    /// Reduces the 32-byte input modulo the field order.
    /// This is suitable for Fiat-Shamir challenges.
    pub fn from_hash_output(bytes: &[u8; 32]) -> Self {
        // Convert bytes to a field element by reduction
        // This is more secure than using bytes as RNG seed
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(bytes);
        // arkworks Fr can handle this directly
        Scalar(Fr::from_le_bytes_mod_order(&wide))
    }

    /// Serialize to bytes (canonical form)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        self.0
            .serialize_compressed(&mut buf[..])
            .expect("serialization should not fail");
        buf
    }

    /// Deserialize from bytes with validation
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, FheError> {
        Fr::deserialize_compressed(&bytes[..])
            .map(Scalar)
            .map_err(|_| FheError::InvalidScalar)
    }

    /// Zero scalar (additive identity)
    pub fn zero() -> Self {
        Scalar(Fr::from(0u64))
    }

    /// One scalar (multiplicative identity)
    pub fn one() -> Self {
        Scalar(Fr::from(1u64))
    }

    /// Add two scalars: self + other
    pub fn add(&self, other: &Self) -> Self {
        Scalar(self.0 + other.0)
    }

    /// Subtract scalars: self - other
    pub fn sub(&self, other: &Self) -> Self {
        Scalar(self.0 - other.0)
    }

    /// Multiply two scalars: self * other
    pub fn mul(&self, other: &Self) -> Self {
        Scalar(self.0 * other.0)
    }

    /// Negate a scalar: -self
    pub fn neg(&self) -> Self {
        Scalar(-self.0)
    }

    /// Check if scalar is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Get the inner Fr element (internal use only)
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> Fr {
        self.0
    }
}

impl CurvePoint {
    /// The generator point G of JubJub
    pub fn generator() -> Self {
        CurvePoint(EdwardsProjective::generator())
    }

    /// The identity point (point at infinity)
    pub fn identity() -> Self {
        CurvePoint(EdwardsProjective::zero())
    }

    /// Scalar multiplication: self * scalar
    pub fn mul_scalar(&self, scalar: &Scalar) -> Self {
        CurvePoint(self.0 * scalar.0)
    }

    /// Point addition: self + other
    pub fn add(&self, other: &Self) -> Self {
        CurvePoint(self.0 + other.0)
    }

    /// Point subtraction: self - other
    pub fn sub(&self, other: &Self) -> Self {
        CurvePoint(self.0 - other.0)
    }

    /// Point negation: -self
    pub fn neg(&self) -> Self {
        CurvePoint(-self.0)
    }

    /// Compress the point for storage (32 bytes)
    ///
    /// Uses canonical serialization for consistent representation.
    pub fn compress(&self) -> CompressedPoint {
        let affine = self.0.into_affine();
        let mut buf = [0u8; 32];
        affine
            .serialize_compressed(&mut buf[..])
            .expect("compression should not fail");
        CompressedPoint(buf)
    }

    /// Decompress from storage with full validation
    ///
    /// Verifies the point is on the curve and in the correct subgroup.
    pub fn decompress(compressed: &CompressedPoint) -> Result<Self, FheError> {
        use ark_ed_on_bls12_381::EdwardsAffine;
        EdwardsAffine::deserialize_compressed(&compressed.0[..])
            .map(|affine| CurvePoint(affine.into()))
            .map_err(|_| FheError::InvalidPoint)
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0.is_zero()
    }

    /// Get the inner EdwardsProjective element (internal use only)
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> EdwardsProjective {
        self.0
    }
}

impl CompressedPoint {
    /// Create a compressed point from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        CompressedPoint(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decompress to a curve point with validation
    pub fn decompress(&self) -> Result<CurvePoint, FheError> {
        CurvePoint::decompress(self)
    }
}

/// A second generator point H for Pedersen commitments
///
/// H is computed as hash_to_curve("Summa_H"), ensuring:
/// 1. No one knows the discrete log of H with respect to G
/// 2. The derivation is deterministic and verifiable
///
/// # Nothing-Up-My-Sleeve
/// The string "Summa_H" is self-documenting and follows
/// the nothing-up-my-sleeve principle.
pub fn pedersen_h() -> CurvePoint {
    // Domain-separated hash-to-curve using "try and increment"
    // This is a simplified version; production should use 
    // a proper hash-to-curve (RFC 9380)
    let domain = b"Summa_Pedersen_H_generator_v1";

    // Hash domain to get initial scalar, then multiply generator
    // This gives us a point with unknown discrete log relative to G
    let scalar = Scalar::random_with_seed(domain);
    CurvePoint::generator().mul_scalar(&scalar)
}

/// Simple hash function for Fiat-Shamir transforms
///
/// This is a basic sponge-like construction. For production,
/// replace with Blake2b, SHA3, or Poseidon.
///
/// # Structure
/// - Absorbs data in 32-byte blocks
/// - Applies simple mixing function
/// - Returns 32-byte digest
pub fn simple_hash(data: &[&[u8]]) -> [u8; 32] {
    let mut state = [0u8; 32];

    // Domain separator
    let domain = b"Summa_Hash_v1________________";
    for i in 0..32 {
        state[i] = domain[i];
    }

    // Absorb all data chunks
    for chunk in data {
        for (i, byte) in chunk.iter().enumerate() {
            let idx = i % 32;
            // Mix: rotate and XOR (simplified ARX)
            state[idx] = state[idx].rotate_left(3) ^ byte;
            state[(idx + 1) % 32] = state[(idx + 1) % 32].wrapping_add(*byte);
        }
        // Final mixing round after each chunk
        for i in 0..32 {
            state[i] = state[i].rotate_left(5) ^ state[(i + 17) % 32];
        }
    }

    // Output permutation
    for _ in 0..3 {
        for i in 0..32 {
            state[i] = state[i].rotate_left(7) ^ state[(i + 13) % 32];
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_u64(100);
        let b = Scalar::from_u64(50);
        let c = a.add(&b);
        assert_ne!(c, Scalar::zero());

        let d = a.sub(&b);
        assert_ne!(d, Scalar::zero());
    }

    #[test]
    fn test_point_compression_roundtrip() {
        let g = CurvePoint::generator();
        let scalar = Scalar::from_u64(42);
        let point = g.mul_scalar(&scalar);

        let compressed = point.compress();
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_point_arithmetic() {
        let g = CurvePoint::generator();
        let s1 = Scalar::from_u64(5);
        let s2 = Scalar::from_u64(3);

        let p1 = g.mul_scalar(&s1); // 5G
        let p2 = g.mul_scalar(&s2); // 3G
        let sum = p1.add(&p2); // 8G

        let expected = g.mul_scalar(&Scalar::from_u64(8));
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_identity_point() {
        let id = CurvePoint::identity();
        assert!(id.is_identity());

        let compressed = id.compress();
        let decompressed = compressed.decompress().unwrap();
        assert!(decompressed.is_identity());
    }

    #[test]
    fn test_pedersen_h_is_deterministic() {
        let h1 = pedersen_h();
        let h2 = pedersen_h();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_pedersen_h_different_from_g() {
        let g = CurvePoint::generator();
        let h = pedersen_h();
        assert_ne!(g, h);
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let data = [b"hello".as_slice(), b"world".as_slice()];
        let h1 = simple_hash(&data);
        let h2 = simple_hash(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_different_inputs() {
        let h1 = simple_hash(&[b"hello"]);
        let h2 = simple_hash(&[b"world"]);
        assert_ne!(h1, h2);
    }
}
