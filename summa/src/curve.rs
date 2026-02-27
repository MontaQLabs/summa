//! Curve primitives for JubJub (ed-on-bls12-381)







use ark_ec::{CurveGroup, Group};
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::Zero;
use blake2::{Blake2s256, Digest};
use parity_scale_codec::{Decode, Encode};

use crate::FheError;

/// A scalar field element (private key, randomness, etc.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar(pub(crate) Fr);

/// A point on the JubJub curve (uncompressed, for computation)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurvePoint(pub(crate) EdwardsProjective);

/// Compressed representation of a curve point (32 bytes for storage/transmission)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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
    pub fn random_from_bytes(bytes: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        let len = bytes.len().min(32);
        seed[..len].copy_from_slice(&bytes[..len]);
        let domain = b"Summa_scalar_domain_v1_fixed_32_";
        for i in 0..32 {
            seed[i] ^= domain[i];
        }
        Self::random_with_seed(&seed)
    }

    /// Create a scalar from raw bytes (hash output)
    pub fn from_hash_output(bytes: &[u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(bytes);
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
}

use once_cell::race::OnceBox;
use alloc::boxed::Box;

static G_CACHE: OnceBox<CurvePoint> = OnceBox::new();
static H_CACHE: OnceBox<CurvePoint> = OnceBox::new();

impl CurvePoint {
    /// The generator point G of JubJub
    pub fn generator() -> Self {
        G_CACHE.get_or_init(|| {
            Box::new(CurvePoint(EdwardsProjective::generator()))
        }).clone()
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
    pub fn compress(&self) -> CompressedPoint {
        let affine = self.0.into_affine();
        let mut buf = [0u8; 32];
        affine
            .serialize_compressed(&mut buf[..])
            .expect("compression should not fail");
        CompressedPoint(buf)
    }

    /// Decompress from storage with full validation
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
pub fn pedersen_h() -> CurvePoint {
    H_CACHE.get_or_init(|| {
        let h_bytes = [
            0x4e, 0x7c, 0xdf, 0xaa, 0xff, 0xcc, 0x0e, 0x8d, 0xd8, 0xd4, 0x15, 0xda, 0x55, 0x36, 0xdb,
            0x50, 0xd6, 0x0d, 0xaa, 0xbb, 0x95, 0x24, 0x38, 0x65, 0xc1, 0xe6, 0x5b, 0x98, 0xc6, 0xd8,
            0x4f, 0x19,
        ];
        Box::new(CurvePoint::decompress(&CompressedPoint(h_bytes)).unwrap())
    }).clone()
}

/// Fiat–Shamir hash using BLAKE2s-256 with domain separation.
pub fn simple_hash(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"Summa_FiatShamir_v1");
    for c in chunks {
        hasher.update(&(*c).len().to_le_bytes());
        hasher.update(c);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Simple hash-to-point for context-specific base points.
/// In production, use a more rigorous MapToCurve algorithm.
pub fn hash_to_point(context: &[u8; 32]) -> CurvePoint {
    // Ensure we don't use G or H by mixing in a domain
    let domain = b"Summa_Contextual_Base_v1________";
    let mut mixed = [0u8; 32];
    for i in 0..32 {
        mixed[i] = context[i] ^ domain[i];
    }
    let mixed_scalar = Scalar::from_hash_output(&mixed);
    CurvePoint::generator().mul_scalar(&mixed_scalar)
}

