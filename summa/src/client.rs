//! Client-side utilities for Summa







use crate::ciphertext::Ciphertext;
use crate::curve::Scalar;
use crate::keys::{KeyPair, PublicKey};
use crate::range_proof::{EqualityProof, RangeProof, TransferProof, AffineUpdateProof};
use crate::shielded::Note;
use crate::FheError;

/// A wallet for managing encrypted balances
pub struct ConfidentialWallet {
    keypair: KeyPair,
}

impl ConfidentialWallet {
    /// Create a new wallet from a seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        ConfidentialWallet {
            keypair: KeyPair::from_seed(seed),
        }
    }

    /// Get the public key (share this with the contract)
    pub fn public_key(&self) -> &PublicKey {
        &self.keypair.public
    }

    /// Get the public key as bytes for contract registration
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.public.to_bytes()
    }

    /// Encrypt an amount for deposit or transfer
    pub fn encrypt_amount(
        &self,
        amount: u64,
        randomness_seed: &[u8; 32],
    ) -> Result<Ciphertext, FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        self.keypair.public.encrypt(amount, &randomness)
    }

    /// Encrypt an amount for sending to another public key
    pub fn encrypt_for(
        &self,
        amount: u64,
        recipient: &PublicKey,
        randomness_seed: &[u8; 32],
    ) -> Result<Ciphertext, FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        recipient.encrypt(amount, &randomness)
    }

    /// Decrypt a ciphertext (e.g., your balance)
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64, FheError> {
        self.keypair.decrypt(ciphertext)
    }

    /// Create a transfer proof
    pub fn create_transfer_proof(
        &self,
        transfer_amount: u64,
        current_balance: u64,
        transfer_randomness: &[u8; 32],
        new_balance_randomness: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<TransferData, TransferError> {
        if transfer_amount > current_balance {
            return Err(TransferError::InsufficientBalance);
        }

        let new_balance = current_balance - transfer_amount;

        let transfer_rand = Scalar::random_with_seed(transfer_randomness);
        let balance_rand = Scalar::random_with_seed(new_balance_randomness);

        let encrypted_amount = self
            .keypair
            .public
            .encrypt(transfer_amount, &transfer_rand)
            .map_err(|_| TransferError::EncryptionFailed)?;

        let encrypted_new_balance = self
            .keypair
            .public
            .encrypt(new_balance, &balance_rand)
            .map_err(|_| TransferError::EncryptionFailed)?;

        let proof = TransferProof::create(
            transfer_amount,
            current_balance,
            &transfer_rand,
            &balance_rand,
            &self.keypair.public,
            proof_seed,
        )
        .map_err(|_| TransferError::ProofCreationFailed)?;

        Ok(TransferData {
            encrypted_amount,
            encrypted_new_balance,
            proof,
        })
    }

    /// Create split transfers (multi-recipient)
    pub fn create_split_transfers(
        &self,
        legs: &[(u64, [u8; 20], [u8; 32])], // (amount, recipient, seed)
        current_balance: u64,
    ) -> Result<SplitTransferData, TransferError> {
        let mut total_amount = 0u64;
        for (amount, _, _) in legs {
            total_amount = total_amount.checked_add(*amount).ok_or(TransferError::InsufficientBalance)?;
        }

        if total_amount > current_balance {
            return Err(TransferError::InsufficientBalance);
        }

        let mut results = alloc::vec::Vec::new();
        let mut running_balance = current_balance;

        for (amount, recipient, seed) in legs {
            let mut leg_seed = *seed;
            leg_seed[0] ^= 0xff;

            let transfer_rand = Scalar::random_with_seed(seed);
            
            // For split transfers, the next leg's proof must be against the balance AFTER this leg
            let new_balance = running_balance - amount;
            let balance_rand = Scalar::random_with_seed(&leg_seed);

            let encrypted_amount = self
                .keypair
                .public
                .encrypt(*amount, &transfer_rand)
                .map_err(|_| TransferError::EncryptionFailed)?;

            let proof = TransferProof::create(
                *amount,
                running_balance,
                &transfer_rand,
                &balance_rand,
                &self.keypair.public,
                seed,
            )
            .map_err(|_| TransferError::ProofCreationFailed)?;

            results.push(SplitTransferLeg {
                recipient: *recipient,
                encrypted_amount,
                proof,
            });

            running_balance = new_balance;
        }

        Ok(SplitTransferData { legs: results })
    }

    /// Mint a note from balance
    pub fn mint_note_from_balance(
        &self,
        value: u64,
        current_balance: u64,
        randomness_seed: &[u8; 32],
        nullifier_seed: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<(Note, TransferProof), TransferError> {
        if value > current_balance {
            return Err(TransferError::InsufficientBalance);
        }

        let randomness = Scalar::random_with_seed(randomness_seed);
        let note = Note::create(value, &randomness, &self.keypair.public, nullifier_seed)
            .map_err(|_| TransferError::EncryptionFailed)?;

        // Proof that note.ciphertext subtracts correctly from balance
        let balance_rand = Scalar::random_with_seed(proof_seed);
        let proof = TransferProof::create(
            value,
            current_balance,
            &randomness,
            &balance_rand,
            &self.keypair.public,
            proof_seed,
        )
        .map_err(|_| TransferError::ProofCreationFailed)?;

        Ok((note, proof))
    }

    /// Create an affine update proof
    pub fn apply_affine_with_proof(
        &self,
        v_old: u64,
        a: u64,
        b: u64,
        r_old: &Scalar,
        r_new_seed: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<(Ciphertext, AffineUpdateProof), FheError> {
        let v_new = a.wrapping_mul(v_old).wrapping_add(b);
        let r_new = Scalar::random_with_seed(r_new_seed);
        let ciphertext_new = self.keypair.public.encrypt(v_new, &r_new)?;

        let proof = AffineUpdateProof::create(
            v_old,
            v_new,
            a,
            b,
            r_old,
            &r_new,
            &self.keypair.public,
            proof_seed,
        ).map_err(|_| FheError::RangeProofFailed)?;

        Ok((ciphertext_new, proof))
    }

    /// Create a simple range proof for an amount
    pub fn create_range_proof(
        &self,
        value: u64,
        randomness_seed: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<(Ciphertext, RangeProof), FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        let ciphertext = self.keypair.public.encrypt(value, &randomness)?;

        let proof = RangeProof::create(
            value,
            &randomness,
            &self.keypair.public,
            64,
            proof_seed,
        )
        .map_err(|_| FheError::RangeProofFailed)?;

        Ok((ciphertext, proof))
    }

    /// Create a deposit ciphertext together with an equality proof that
    /// `ciphertext` encrypts the public `value`.
    pub fn create_deposit_proof(
        &self,
        value: u64,
        randomness_seed: &[u8; 32],
        proof_seed: &[u8; 32],
    ) -> Result<(Ciphertext, EqualityProof), FheError> {
        let randomness = Scalar::random_with_seed(randomness_seed);
        let ciphertext = self.keypair.public.encrypt(value, &randomness)?;

        let proof = EqualityProof::create(
            value,
            &randomness,
            &self.keypair.public,
            &ciphertext,
            proof_seed,
        )
        .map_err(|_| FheError::RangeProofFailed)?;

        Ok((ciphertext, proof))
    }
}

/// Data needed for a confidential transfer
pub struct TransferData {
    /// The encrypted transfer amount
    pub encrypted_amount: Ciphertext,
    /// The encrypted new balance (for verification)
    pub encrypted_new_balance: Ciphertext,
    /// The proof that the transfer is valid
    pub proof: TransferProof,
}

/// A single leg of a split transfer
pub struct SplitTransferLeg {
    /// Recipient address
    pub recipient: [u8; 20],
    /// The encrypted amount for this recipient
    pub encrypted_amount: Ciphertext,
    /// The proof that the sender had enough balance for this leg
    pub proof: TransferProof,
}

/// Data needed for a split confidential transfer
pub struct SplitTransferData {
    /// The legs of the split transfer
    pub legs: alloc::vec::Vec<SplitTransferLeg>,
}

impl SplitTransferData {
    /// Encode for sending to the contract
    pub fn encode_for_contract(&self) -> alloc::vec::Vec<u8> {
        use parity_scale_codec::Encode;

        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&(self.legs.len() as u32).to_be_bytes());
        for leg in &self.legs {
            data.extend_from_slice(&leg.recipient);
            data.extend_from_slice(&leg.encrypted_amount.to_bytes());
            let proof_bytes = leg.proof.encode();
            data.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(&proof_bytes);
        }
        data
    }
}

impl TransferData {
    /// Encode for sending to the contract
    pub fn encode_for_contract(&self) -> alloc::vec::Vec<u8> {
        use parity_scale_codec::Encode;

        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&self.encrypted_amount.to_bytes());
        let proof_bytes = self.proof.encode();
        data.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&proof_bytes);
        data
    }
}

/// Errors that can occur during transfer preparation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// Not enough balance for transfer
    InsufficientBalance,
    /// Failed to encrypt the amount
    EncryptionFailed,
    /// Failed to create the proof
    ProofCreationFailed,
}

/// Helper to build contract calldata
pub struct CalldataBuilder {
    data: alloc::vec::Vec<u8>,
}

impl CalldataBuilder {
    /// Create a new builder with a function selector
    pub fn new(selector: [u8; 4]) -> Self {
        CalldataBuilder {
            data: selector.to_vec(),
        }
    }

    /// Add an address (20 bytes)
    pub fn add_address(mut self, address: &[u8; 20]) -> Self {
        self.data.extend_from_slice(address);
        self
    }

    /// Add a ciphertext (64 bytes)
    pub fn add_ciphertext(mut self, ct: &Ciphertext) -> Self {
        self.data.extend_from_slice(&ct.to_bytes());
        self
    }

    /// Add raw bytes with length prefix
    pub fn add_bytes(mut self, bytes: &[u8]) -> Self {
        self.data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.data.extend_from_slice(bytes);
        self
    }

    /// Add a 32-byte value
    pub fn add_bytes32(mut self, value: &[u8; 32]) -> Self {
        self.data.extend_from_slice(value);
        self
    }

    /// Build the final calldata
    pub fn build(self) -> alloc::vec::Vec<u8> {
        self.data
    }
}

/// Contract function selectors (matching the contract)
pub mod selectors {
    /// registerPublicKey(bytes32)
    pub const REGISTER_PUBKEY: [u8; 4] = [0x12, 0x34, 0xab, 0xcd];

    /// transfer(address,bytes,bytes)
    pub const TRANSFER: [u8; 4] = [0x56, 0x78, 0xef, 0xab];

    /// deposit(bytes)
    pub const DEPOSIT: [u8; 4] = [0x9a, 0xbc, 0x01, 0x23];

    /// getEncryptedBalance(address)
    pub const GET_BALANCE: [u8; 4] = [0xde, 0xf4, 0x56, 0x78];

    /// mint(address,bytes)
    pub const MINT: [u8; 4] = [0xaa, 0xbb, 0x11, 0x22];

    /// totalSupply()
    pub const TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
}

