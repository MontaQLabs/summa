//! Key management for Twisted ElGamal encryption
//!
//! In Twisted ElGamal:
//! - Secret key: scalar `x`
//! - Public key: point `Y = x * G`
//!
//! The "twist" is that we encode small messages in the exponent,
//! allowing efficient discrete log recovery for small values.

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

    /// Get the underlying scalar (for advanced use)
    #[allow(dead_code)]
    pub(crate) fn scalar(&self) -> &Scalar {
        &self.0
    }

    /// Serialize the secret key
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize a secret key
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, FheError> {
        Scalar::from_bytes(bytes).map(SecretKey)
    }

    /// Derive the public key from this secret key
    pub fn public_key(&self) -> PublicKey {
        let point = CurvePoint::generator().mul_scalar(&self.0);
        PublicKey(point.compress())
    }

    /// Decrypt a ciphertext
    ///
    /// For Twisted ElGamal with message in exponent:
    /// - C1 = r * G
    /// - C2 = m * G + r * Y
    ///
    /// To decrypt: C2 - x * C1 = m * G
    /// Then solve discrete log to recover m (only works for small m!)
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64, FheError> {
        let c1 = ciphertext.c1.decompress()?;
        let c2 = ciphertext.c2.decompress()?;

        // Compute m * G = C2 - x * C1
        let x_c1 = c1.mul_scalar(&self.0);
        let m_g = c2.sub(&x_c1);

        // Baby-step giant-step to recover m
        // For production, use a precomputed table
        Self::discrete_log(&m_g)
    }

    /// Brute-force discrete log for small values (up to 2^20 for now)
    /// In production, use baby-step giant-step with precomputed tables
    fn discrete_log(target: &CurvePoint) -> Result<u64, FheError> {
        if target.is_identity() {
            return Ok(0);
        }

        let g = CurvePoint::generator();
        let mut current = g.clone();

        // Linear search for small values (fine for demo, use BSGS in production)
        // This supports values up to ~1 million
        const MAX_VALUE: u64 = 1 << 20;

        for i in 1..=MAX_VALUE {
            if current == *target {
                return Ok(i);
            }
            current = current.add(&g);
        }

        // Value too large or negative (which shouldn't happen with range proofs)
        Err(FheError::CryptoError)
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
    ///
    /// Twisted ElGamal encryption:
    /// - Pick random `r`
    /// - C1 = r * G
    /// - C2 = m * G + r * Y  (where Y is the public key)
    pub fn encrypt(&self, value: u64, randomness: &Scalar) -> Result<Ciphertext, FheError> {
        let g = CurvePoint::generator();
        let y = self.to_point()?;

        // C1 = r * G
        let c1 = g.mul_scalar(randomness);

        // C2 = m * G + r * Y
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let value = 1000u64;
        let rand_seed = [1u8; 32];
        let ciphertext = keypair
            .public
            .encrypt_with_seed(value, &rand_seed)
            .unwrap();

        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_encrypt_zero() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let rand_seed = [2u8; 32];
        let ciphertext = keypair.public.encrypt_with_seed(0, &rand_seed).unwrap();

        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(0, decrypted);
    }

    #[test]
    fn test_public_key_serialization() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let bytes = keypair.public.to_bytes();
        let restored = PublicKey::from_bytes(bytes);

        assert_eq!(keypair.public, restored);
    }
}

