//! Key management for Twisted ElGamal encryption







use parity_scale_codec::{Decode, Encode};

use crate::ciphertext::Ciphertext;
use crate::curve::{CompressedPoint, CurvePoint, Scalar};
use crate::FheError;

/// A secret key (scalar on JubJub)
#[derive(Clone)]
pub struct SecretKey(Scalar);

/// A public key (point on JubJub)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicKey(CompressedPoint);

/// A key pair containing both secret and public keys
pub struct KeyPair {
    /// The secret key (keep this private!)
    pub secret: SecretKey,
    /// The public key (share this freely)
    pub public: PublicKey,
}

impl SecretKey {
    /// Create a secret key from a 32-byte seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey(Scalar::random_with_seed(seed))
    }

    /// Serialize the secret key
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize a secret key
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, FheError> {
        Scalar::from_bytes(bytes).map(SecretKey)
    }

    /// Access the underlying scalar
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Derive the public key from this secret key
    pub fn public_key(&self) -> PublicKey {
        let h = crate::curve::pedersen_h();
        let point = h.mul_scalar(&self.0);
        PublicKey(point.compress())
    }

    /// Decrypt a ciphertext (STUBBED for PVM deployment)
    pub fn decrypt(&self, _ciphertext: &Ciphertext) -> Result<u64, FheError> {
        Ok(0)
    }

    fn discrete_log(_target: &CurvePoint) -> Result<u64, FheError> {
        Ok(0)
    }
}

impl PublicKey {
    /// Create from a compressed point
    pub fn from_compressed(point: CompressedPoint) -> Self {
        PublicKey(point)
    }

    /// Get the compressed point
    pub fn as_compressed(&self) -> &CompressedPoint {
        &self.0
    }

    /// Decompress to a curve point
    pub fn to_point(&self) -> Result<CurvePoint, FheError> {
        self.0.decompress()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0 .0
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(CompressedPoint(bytes))
    }

    /// Encrypt a value under this public key
    pub fn encrypt(&self, value: u64, randomness: &Scalar) -> Result<Ciphertext, FheError> {
        let g = CurvePoint::generator();
        let h = crate::curve::pedersen_h();
        let y = self.to_point()?;

        let c1 = h.mul_scalar(randomness);

        let m_g = g.mul_scalar(&Scalar::from_u64(value));
        let r_y = y.mul_scalar(randomness);
        let c2 = m_g.add(&r_y);

        Ok(Ciphertext {
            c1: c1.compress(),
            c2: c2.compress(),
        })
    }

    /// Encrypt with a deterministic seed (useful for reproducible tests)
    pub fn encrypt_with_seed(&self, value: u64, seed: &[u8; 32]) -> Result<Ciphertext, FheError> {
        let randomness = Scalar::random_with_seed(seed);
        self.encrypt(value, &randomness)
    }
}

impl KeyPair {
    /// Generate a new key pair from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = SecretKey::from_seed(seed);
        let public = secret.public_key();
        KeyPair { secret, public }
    }

    /// Encrypt a value
    pub fn encrypt(&self, value: u64, randomness: &Scalar) -> Result<Ciphertext, FheError> {
        self.public.encrypt(value, randomness)
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64, FheError> {
        self.secret.decrypt(ciphertext)
    }
}

