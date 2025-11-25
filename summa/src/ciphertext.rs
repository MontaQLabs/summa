//! Ciphertext type with homomorphic operations
//!
//! This is the core data structure that contracts manipulate.
//! The magic: you can add/multiply ciphertexts without decrypting!

use parity_scale_codec::{Decode, Encode};

use crate::curve::{CompressedPoint, CurvePoint, Scalar};
use crate::FheError;

/// An encrypted value (Twisted ElGamal ciphertext)
///
/// Structure: (C1, C2) where:
/// - C1 = r * G (ephemeral key)
/// - C2 = m * G + r * Y (encrypted message with public key Y)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Ciphertext {
    /// First component: r * G
    pub c1: CompressedPoint,
    /// Second component: m * G + r * Y
    pub c2: CompressedPoint,
}

impl Ciphertext {
    /// Create a ciphertext from compressed points
    pub fn new(c1: CompressedPoint, c2: CompressedPoint) -> Self {
        Ciphertext { c1, c2 }
    }

    /// Create a ciphertext encrypting zero (identity elements)
    /// Useful for initializing balances
    pub fn zero() -> Self {
        // Zero ciphertext: both components are identity point
        // This represents Encrypt(0) with r=0
        let identity = CurvePoint::identity().compress();
        Ciphertext {
            c1: identity.clone(),
            c2: identity,
        }
    }

    /// Homomorphic Addition: Encrypt(A) + Encrypt(B) = Encrypt(A + B)
    ///
    /// This is THE killer feature. The contract adds encrypted balances
    /// without ever knowing the actual values!
    ///
    /// Math:
    /// - (C1_a + C1_b, C2_a + C2_b)
    /// - = ((r_a + r_b) * G, (m_a + m_b) * G + (r_a + r_b) * Y)
    /// - = Encrypt(m_a + m_b) with randomness (r_a + r_b)
    pub fn add_encrypted(&self, other: &Ciphertext) -> Result<Ciphertext, FheError> {
        let c1_a = self.c1.decompress()?;
        let c1_b = other.c1.decompress()?;
        let c2_a = self.c2.decompress()?;
        let c2_b = other.c2.decompress()?;

        let new_c1 = c1_a.add(&c1_b);
        let new_c2 = c2_a.add(&c2_b);

        Ok(Ciphertext {
            c1: new_c1.compress(),
            c2: new_c2.compress(),
        })
    }

    /// Homomorphic Subtraction: Encrypt(A) - Encrypt(B) = Encrypt(A - B)
    ///
    /// Used for transfers: sender_balance -= amount
    pub fn sub_encrypted(&self, other: &Ciphertext) -> Result<Ciphertext, FheError> {
        let c1_a = self.c1.decompress()?;
        let c1_b = other.c1.decompress()?;
        let c2_a = self.c2.decompress()?;
        let c2_b = other.c2.decompress()?;

        let new_c1 = c1_a.sub(&c1_b);
        let new_c2 = c2_a.sub(&c2_b);

        Ok(Ciphertext {
            c1: new_c1.compress(),
            c2: new_c2.compress(),
        })
    }

    /// Scalar Multiplication: Encrypt(A) * k = Encrypt(A * k)
    ///
    /// Useful for: interest calculation, fee multiplication, etc.
    /// Example: balance.mul_scalar(105) / 100 = 5% increase
    pub fn mul_scalar(&self, scalar: u64) -> Result<Ciphertext, FheError> {
        let c1 = self.c1.decompress()?;
        let c2 = self.c2.decompress()?;

        let s = Scalar::from_u64(scalar);

        let new_c1 = c1.mul_scalar(&s);
        let new_c2 = c2.mul_scalar(&s);

        Ok(Ciphertext {
            c1: new_c1.compress(),
            c2: new_c2.compress(),
        })
    }

    /// Scalar Multiplication with a Scalar type
    pub fn mul_scalar_field(&self, scalar: &Scalar) -> Result<Ciphertext, FheError> {
        let c1 = self.c1.decompress()?;
        let c2 = self.c2.decompress()?;

        let new_c1 = c1.mul_scalar(scalar);
        let new_c2 = c2.mul_scalar(scalar);

        Ok(Ciphertext {
            c1: new_c1.compress(),
            c2: new_c2.compress(),
        })
    }

    /// Negate: -Encrypt(A) = Encrypt(-A)
    ///
    /// Useful for creating "negative" amounts (though with range proofs,
    /// you'd prove the original is positive, then negate)
    pub fn neg(&self) -> Result<Ciphertext, FheError> {
        let c1 = self.c1.decompress()?;
        let c2 = self.c2.decompress()?;

        Ok(Ciphertext {
            c1: c1.neg().compress(),
            c2: c2.neg().compress(),
        })
    }

    /// Serialize to bytes (64 bytes total)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.c1.0);
        result[32..].copy_from_slice(&self.c2.0);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut c1_bytes = [0u8; 32];
        let mut c2_bytes = [0u8; 32];
        c1_bytes.copy_from_slice(&bytes[..32]);
        c2_bytes.copy_from_slice(&bytes[32..]);
        Ciphertext {
            c1: CompressedPoint(c1_bytes),
            c2: CompressedPoint(c2_bytes),
        }
    }

    /// Re-randomize a ciphertext (changes appearance without changing value)
    ///
    /// This is important for privacy: if you receive a payment and then
    /// send it, re-randomization prevents linking the transactions.
    ///
    /// Math: Add Encrypt(0) with fresh randomness r':
    /// - new_c1 = c1 + r' * G
    /// - new_c2 = c2 + r' * Y
    pub fn rerandomize(
        &self,
        public_key: &crate::PublicKey,
        randomness: &Scalar,
    ) -> Result<Ciphertext, FheError> {
        let c1 = self.c1.decompress()?;
        let c2 = self.c2.decompress()?;
        let y = public_key.to_point()?;
        let g = CurvePoint::generator();

        // Add fresh randomness
        let r_g = g.mul_scalar(randomness);
        let r_y = y.mul_scalar(randomness);

        let new_c1 = c1.add(&r_g);
        let new_c2 = c2.add(&r_y);

        Ok(Ciphertext {
            c1: new_c1.compress(),
            c2: new_c2.compress(),
        })
    }
}

/// Batch operations for efficiency
impl Ciphertext {
    /// Add multiple ciphertexts together
    pub fn sum(ciphertexts: &[Ciphertext]) -> Result<Ciphertext, FheError> {
        if ciphertexts.is_empty() {
            return Ok(Ciphertext::zero());
        }

        let mut result = ciphertexts[0].clone();
        for ct in &ciphertexts[1..] {
            result = result.add_encrypted(ct)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_homomorphic_addition() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        // Encrypt two values
        let ct_a = keypair.public.encrypt_with_seed(100, &[1u8; 32]).unwrap();
        let ct_b = keypair.public.encrypt_with_seed(50, &[2u8; 32]).unwrap();

        // Add them homomorphically
        let ct_sum = ct_a.add_encrypted(&ct_b).unwrap();

        // Decrypt and verify
        let decrypted = keypair.decrypt(&ct_sum).unwrap();
        assert_eq!(150, decrypted);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let ct_a = keypair.public.encrypt_with_seed(100, &[1u8; 32]).unwrap();
        let ct_b = keypair.public.encrypt_with_seed(30, &[2u8; 32]).unwrap();

        let ct_diff = ct_a.sub_encrypted(&ct_b).unwrap();

        let decrypted = keypair.decrypt(&ct_diff).unwrap();
        assert_eq!(70, decrypted);
    }

    #[test]
    fn test_scalar_multiplication() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let ct = keypair.public.encrypt_with_seed(100, &[1u8; 32]).unwrap();
        let ct_scaled = ct.mul_scalar(5).unwrap();

        let decrypted = keypair.decrypt(&ct_scaled).unwrap();
        assert_eq!(500, decrypted);
    }

    #[test]
    fn test_zero_ciphertext() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let ct = keypair.public.encrypt_with_seed(100, &[1u8; 32]).unwrap();
        let zero = Ciphertext::zero();

        let sum = ct.add_encrypted(&zero).unwrap();

        // Note: The result won't equal ct directly because zero ciphertext
        // has a different structure, but decryption should match
        let decrypted = keypair.decrypt(&sum).unwrap();
        assert_eq!(100, decrypted);
    }

    #[test]
    fn test_serialization() {
        let seed = [42u8; 32];
        let keypair = KeyPair::from_seed(&seed);

        let ct = keypair.public.encrypt_with_seed(42, &[1u8; 32]).unwrap();
        let bytes = ct.to_bytes();
        let restored = Ciphertext::from_bytes(&bytes);

        assert_eq!(ct, restored);
    }
}


