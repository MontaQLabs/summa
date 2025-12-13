# Summa Technical Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Cryptographic Foundations](#cryptographic-foundations)
3. [Library Components](#library-components)
4. [Smart Contract Design](#smart-contract-design)
5. [Security Analysis](#security-analysis)
6. [Performance Characteristics](#performance-characteristics)
7. [API Reference](#api-reference)
8. [Deployment Guide](#deployment-guide)
9. [Known Limitations](#known-limitations)
10. [Future Improvements](#future-improvements)

---

## Architecture Overview

Summa is a **Somewhat Homomorphic Encryption (SHE)** library designed for the Polkadot Virtual Machine (PVM). It enables privacy-preserving smart contracts where computations can be performed on encrypted data without decryption.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT SIDE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐     │
│  │  Key Generation │    │    Encryption    │    │   Proof Creation   │     │
│  │                 │    │                  │    │                    │     │
│  │  seed → (sk,pk) │    │  (value,pk,r)    │    │  (value,balance)   │     │
│  │                 │    │      ↓           │    │        ↓           │     │
│  │                 │    │  Ciphertext      │    │   TransferProof    │     │
│  └─────────────────┘    └──────────────────┘    └────────────────────┘     │
│                                                                             │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                         Transaction (calldata)
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            POLKADOT PVM                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Confidential Asset Contract                      │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                    │    │
│  │   Storage:                                                         │    │
│  │   ┌─────────────────────────────────────────────────────────────┐ │    │
│  │   │  balances[addr] → Ciphertext (encrypted balance)            │ │    │
│  │   │  pubkeys[addr]  → PublicKey (for encryption)                │ │    │
│  │   │  owner          → Address (admin)                           │ │    │
│  │   │  totalSupply    → Ciphertext (encrypted)                    │ │    │
│  │   └─────────────────────────────────────────────────────────────┘ │    │
│  │                                                                    │    │
│  │   Operations (all on encrypted data):                              │    │
│  │   ┌─────────────────────────────────────────────────────────────┐ │    │
│  │   │  • add_encrypted(ct1, ct2) → ct3                            │ │    │
│  │   │  • sub_encrypted(ct1, ct2) → ct3                            │ │    │
│  │   │  • verify_range_proof(proof, ct) → bool                     │ │    │
│  │   └─────────────────────────────────────────────────────────────┘ │    │
│  │                                                                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Registration**: User generates keypair, registers public key on-chain
2. **Encryption**: User encrypts values client-side using their public key
3. **Transaction**: Encrypted values + proofs sent to contract
4. **Computation**: Contract performs homomorphic operations on ciphertexts
5. **Verification**: Contract verifies range proofs (no negative amounts)
6. **Storage**: Updated encrypted balances stored on-chain
7. **Decryption**: Only the key holder can decrypt their balance

---

## Cryptographic Foundations

### Elliptic Curve: JubJub (ed-on-bls12-381)

Summa uses the **JubJub curve**, a twisted Edwards curve embedded in BLS12-381.

**Curve Parameters:**
```
- Field: Fq where q is the scalar field of BLS12-381
- Order: r = 6554484396890773809930967563523245729705921265872317281365359162392183254199
- Cofactor: 8 (we work in the prime-order subgroup)
- Generator: Standard JubJub generator G
```

**Why JubJub?**
1. **Native to Polkadot**: BLS12-381 is Polkadot's signature curve
2. **ZK-Friendly**: Efficient for SNARKs/Bulletproofs
3. **Twisted Edwards**: Fast point addition (unified formulas)
4. **Embedded Curve**: Can be verified inside BLS12-381 circuits

### Twisted ElGamal Encryption

Standard ElGamal encrypts messages as curve points. **Twisted ElGamal** encodes the message in the exponent, enabling efficient discrete log recovery for small values.

**Key Generation:**
```
sk = random scalar in Zr
pk = sk * G
```

**Encryption:**
```
Input: message m, randomness r
C1 = r * G
C2 = m * G + r * pk

Ciphertext = (C1, C2)
```

**Decryption:**
```
m * G = C2 - sk * C1
m = discrete_log(m * G)  // Only efficient for small m
```

**Homomorphic Properties:**
```
Addition:
  Enc(a) + Enc(b) = (C1_a + C1_b, C2_a + C2_b) = Enc(a + b)

Scalar Multiplication:
  k * Enc(a) = (k * C1, k * C2) = Enc(k * a)
```

### Pedersen Commitments

Used in range proofs to commit to values without revealing them.

```
Commit(v, r) = v * G + r * H

where:
- G is the generator
- H is a second generator with unknown discrete log relative to G
- v is the value
- r is the blinding factor
```

**Binding Property**: Cannot find (v', r') ≠ (v, r) with same commitment
**Hiding Property**: Commitment reveals nothing about v

### Range Proofs

Prove a value is in [0, 2^n) without revealing it.

**Approach (Simplified Bulletproofs):**

1. **Bit Decomposition**: Express value as bits: v = Σ(2^i * b_i)
2. **Bit Commitments**: Commit to each bit: C_i = b_i * G + r_i * H
3. **Bit Proofs**: Prove each commitment is to 0 or 1
4. **Aggregation**: Prove commitments sum to the ciphertext value

**Fiat-Shamir Transform:**
```
challenge = Hash(G, H, commitments, public_data)
```

This converts the interactive Sigma protocol to non-interactive.

---

## Library Components

### Module Structure

```
summa/
├── src/
│   ├── lib.rs          # Main exports, FheError
│   ├── curve.rs        # Scalar, CurvePoint, CompressedPoint
│   ├── keys.rs         # SecretKey, PublicKey, KeyPair
│   ├── ciphertext.rs   # Ciphertext, homomorphic ops
│   ├── range_proof.rs  # RangeProof, TransferProof
│   └── client.rs       # ConfidentialWallet, CalldataBuilder
```

### `curve.rs` - Elliptic Curve Primitives

```rust
/// Field scalar (256-bit integer mod r)
pub struct Scalar(Fr);

impl Scalar {
    fn from_u64(val: u64) -> Self;
    fn random_with_seed(seed: &[u8; 32]) -> Self;
    fn from_hash_output(bytes: &[u8; 32]) -> Self;  // Fiat-Shamir
    fn add(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
}

/// Curve point (projective coordinates)
pub struct CurvePoint(EdwardsProjective);

impl CurvePoint {
    fn generator() -> Self;           // G
    fn identity() -> Self;            // Point at infinity
    fn mul_scalar(&self, s: &Scalar) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn compress(&self) -> CompressedPoint;  // 32 bytes
}

/// Compressed point (32 bytes)
pub struct CompressedPoint([u8; 32]);

/// Second generator for Pedersen commitments
fn pedersen_h() -> CurvePoint;

/// Simple hash for Fiat-Shamir (replace with Blake2/Poseidon in production)
fn simple_hash(data: &[&[u8]]) -> [u8; 32];
```

### `keys.rs` - Key Management

```rust
pub struct SecretKey(Scalar);
pub struct PublicKey(CompressedPoint);
pub struct KeyPair { secret: SecretKey, public: PublicKey }

impl SecretKey {
    fn from_seed(seed: &[u8; 32]) -> Self;
    fn public_key(&self) -> PublicKey;
    fn decrypt(&self, ct: &Ciphertext) -> Result<u64, FheError>;
}

impl PublicKey {
    fn encrypt(&self, value: u64, randomness: &Scalar) -> Ciphertext;
}
```

**Discrete Log Recovery:**

The `decrypt` function must solve: given m*G, find m.

```rust
fn discrete_log(target: &CurvePoint) -> Result<u64, FheError> {
    // Linear search (demo) - O(n)
    // Production: Baby-step Giant-step - O(√n)
    const MAX_VALUE: u64 = 1 << 20;  // ~1 million
    
    let g = CurvePoint::generator();
    let mut current = g.clone();
    
    for i in 1..=MAX_VALUE {
        if current == *target {
            return Ok(i);
        }
        current = current.add(&g);
    }
    Err(FheError::CryptoError)
}
```

### `ciphertext.rs` - Encrypted Values

```rust
#[derive(Encode, Decode)]
pub struct Ciphertext {
    pub c1: CompressedPoint,  // r * G
    pub c2: CompressedPoint,  // m * G + r * pk
}

impl Ciphertext {
    /// Homomorphic addition
    fn add_encrypted(&self, other: &Ciphertext) -> Result<Ciphertext, FheError>;
    
    /// Homomorphic subtraction
    fn sub_encrypted(&self, other: &Ciphertext) -> Result<Ciphertext, FheError>;
    
    /// Scalar multiplication
    fn mul_scalar(&self, k: u64) -> Result<Ciphertext, FheError>;
    
    /// Re-randomize (for unlinkability)
    fn rerandomize(&self, pk: &PublicKey, r: &Scalar) -> Result<Ciphertext, FheError>;
    
    /// Zero ciphertext (identity for addition)
    fn zero() -> Self;
    
    /// Serialization (64 bytes)
    fn to_bytes(&self) -> [u8; 64];
    fn from_bytes(bytes: &[u8; 64]) -> Self;
}
```

### `range_proof.rs` - Zero-Knowledge Proofs

```rust
#[derive(Encode, Decode)]
pub struct RangeProof {
    bit_commitments: Vec<CompressedPoint>,  // 64 commitments
    responses: Vec<[u8; 32]>,               // 64 responses
    challenge: [u8; 32],                     // Fiat-Shamir challenge
    aggregate_response: [u8; 32],            // Links to ciphertext
}

impl RangeProof {
    /// Create proof (client-side)
    fn create(
        value: u64,
        encryption_randomness: &Scalar,
        public_key: &PublicKey,
        bits: u32,
        seed: &[u8; 32],
    ) -> Result<Self, RangeProofError>;
    
    /// Verify proof (on-chain)
    fn verify(
        &self,
        ciphertext: &Ciphertext,
        public_key: &PublicKey,
        bits: u32,
    ) -> Result<bool, RangeProofError>;
}

/// Combined proof for transfers
pub struct TransferProof {
    amount_range_proof: RangeProof,    // Amount ≥ 0
    balance_range_proof: RangeProof,   // New balance ≥ 0
}
```

---

## Smart Contract Design

### Storage Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Storage Keys                                   │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Balance Key:    [0xba1a2ce0][........][20-byte address]              │
│                  ↑ prefix    ↑ padding  ↑ account                     │
│                                                                        │
│  PubKey Key:     [0x9b3f7a21][........][20-byte address]              │
│                                                                        │
│  Total Supply:   [0xff...ff00...00746f74616c5f7370]                   │
│                  Fixed 32-byte key                                     │
│                                                                        │
│  Owner:          [0xaa...aa00...006f776e65725f5f5f]                   │
│                  Fixed 32-byte key                                     │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Function Selectors

| Function | Selector | Access |
|----------|----------|--------|
| `registerPublicKey(bytes32)` | `0x1234abcd` | Anyone |
| `transfer(address,bytes,bytes)` | `0x5678efab` | Anyone |
| `deposit(bytes)` | `0x9abc0123` | Anyone |
| `getEncryptedBalance(address)` | `0xdef45678` | View |
| `mint(address,bytes)` | `0xaabb1122` | Owner |
| `transferOwnership(address)` | `0xf2fde38b` | Owner |
| `owner()` | `0x8da5cb5b` | View |

### Calldata Formats

**Register Public Key:**
```
[selector: 4][pubkey: 32]
Total: 36 bytes
```

**Mint:**
```
[selector: 4][recipient: 20][ciphertext: 64]
Total: 88 bytes
```

**Transfer:**
```
[selector: 4][recipient: 20][ciphertext: 64][proof_len: 4][proof: var]
Minimum: 92 + proof_len bytes
```

**Get Balance:**
```
[selector: 4][account: 20]
Total: 24 bytes
```

### Transfer Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Transfer Execution                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Parse calldata                                                          │
│     ├── Extract recipient address                                           │
│     ├── Extract encrypted amount (64 bytes)                                 │
│     └── Extract transfer proof                                              │
│                                                                             │
│  2. Validate sender                                                         │
│     ├── Check sender has registered public key                              │
│     └── Load sender's encrypted balance                                     │
│                                                                             │
│  3. Validate recipient                                                      │
│     ├── Check recipient has registered public key                           │
│     └── Prevent self-transfer                                               │
│                                                                             │
│  4. Homomorphic computation                                                 │
│     ├── new_sender_bal = sender_bal.sub_encrypted(amount)                   │
│     └── new_receiver_bal = receiver_bal.add_encrypted(amount)               │
│                                                                             │
│  5. Verify range proof [CRITICAL]                                           │
│     ├── Verify amount ≥ 0                                                   │
│     └── Verify new_sender_bal ≥ 0                                           │
│                                                                             │
│  6. Update storage                                                          │
│     ├── Store new_sender_bal                                                │
│     └── Store new_receiver_bal                                              │
│                                                                             │
│  7. Return success                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Analysis

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Balance underflow** | Range proofs verify new_balance ≥ 0 |
| **Negative transfers** | Range proofs verify amount ≥ 0 |
| **Key extraction** | Discrete log is computationally hard |
| **Replay attacks** | PVM provides nonce/tx ordering |
| **Malicious minting** | Owner-only access control |
| **Front-running** | N/A (privacy doesn't prevent) |
| **Balance linking** | Re-randomization available |

### Cryptographic Assumptions

1. **ECDLP Hardness**: No efficient algorithm exists to compute discrete logarithms on JubJub
2. **Random Oracle Model**: Fiat-Shamir hash behaves as a random oracle
3. **Trusted Setup**: None required (discrete-log based)

### Known Attack Vectors

**1. Timing Attacks on Decryption**
```
Risk: Linear discrete log search has value-dependent timing
Mitigation: Use constant-time BSGS algorithm
Status: TODO for production
```

**2. Malleability**
```
Risk: Ciphertext can be modified (add Enc(0))
Mitigation: Sign transactions, verify proof linkage
Status: Partially mitigated by range proofs
```

**3. Insufficient Range Bits**
```
Risk: If bits < 64, values can overflow
Mitigation: Always use 64-bit range proofs
Status: Enforced in code
```

### Audit Checklist

- [ ] Formal verification of homomorphic properties
- [ ] Timing analysis of cryptographic operations
- [ ] Fuzzing of SCALE encoding/decoding
- [ ] Review of Fiat-Shamir transcript
- [ ] Storage key collision analysis
- [ ] Gas/weight limit analysis

---

## Performance Characteristics

### Size Analysis

| Component | Size (bytes) |
|-----------|--------------|
| Public Key | 32 |
| Ciphertext | 64 |
| Range Proof (64-bit) | ~4,160 |
| Transfer Proof | ~8,320 |
| Contract Binary | ~48,000 |

### Computational Costs

| Operation | Approx. Gas | Notes |
|-----------|-------------|-------|
| Point addition | ~1,000 | On-curve |
| Scalar multiplication | ~50,000 | Variable base |
| Point decompression | ~5,000 | Validation |
| SCALE decode | ~100/byte | |
| Range proof verify | ~3,200,000 | 64 bits |

### Bottlenecks

1. **Discrete Log Recovery**: O(√n) with BSGS for n-bit values
2. **Range Proof Size**: Linear in bit-width (64 × 64 bytes)
3. **Storage Reads**: Each balance lookup costs I/O

---

## API Reference

### CLI Tool Usage

```bash
# Generate keypair
gen-ciphertext keygen --seed 0x<32_bytes>

# Encrypt value
gen-ciphertext encrypt --value 1000 --seed 0x<32_bytes>

# Decrypt ciphertext
gen-ciphertext decrypt <hex_ciphertext> --seed 0x<32_bytes>

# Generate calldata
gen-ciphertext calldata register --seed 0x<32_bytes>
gen-ciphertext calldata mint --to 0x<address> --amount 1000 --seed 0x<32_bytes>
gen-ciphertext calldata balance --to 0x<address>

# Verify ciphertext
gen-ciphertext verify <hex_ciphertext>
```

### Library Usage (Rust)

```rust
use summa::{ConfidentialWallet, Ciphertext, TransferProof};

// Create wallet from seed
let wallet = ConfidentialWallet::from_seed(&seed);

// Get public key for registration
let pubkey = wallet.public_key_bytes();

// Encrypt a value
let ciphertext = wallet.encrypt_amount(1000, &randomness)?;

// Decrypt a balance
let balance = wallet.decrypt(&encrypted_balance)?;

// Create transfer proof
let transfer_data = wallet.create_transfer_proof(
    transfer_amount,
    current_balance,
    &transfer_randomness,
    &balance_randomness,
    &proof_seed,
)?;
```

### Contract Interaction (cast)

```bash
# Register public key
cast send $CONTRACT "0x1234abcd<pubkey>" --private-key $KEY

# Mint tokens
cast send $CONTRACT "0xaabb1122<address><ciphertext>" --private-key $KEY

# Get balance
cast call $CONTRACT "0xdef45678<address>"

# Transfer (with proof)
cast send $CONTRACT "0x5678efab<to><ciphertext><proof_len><proof>" --private-key $KEY
```

---

## Deployment Guide

### Prerequisites

1. **Rust** 1.84+ with `riscv64` target
2. **polkatool** 0.26 for linking
3. **cast** (Foundry) for deployment
4. **Funded account** on target network

### Build Process

```bash
# Install dependencies
cargo install polkatool@0.26

# Build library and contracts
make all

# Output: confidential-asset.polkavm
```

### Deployment

```bash
# Set environment
export PRIVATE_KEY=0x<your_key>
export ETH_RPC_URL=https://testnet-passet-hub-eth-rpc.polkadot.io

# Deploy
./deploy.sh --network testnet

# Or manually
cast send --private-key $PRIVATE_KEY --create "0x$(xxd -p -c 99999 confidential-asset.polkavm)"
```

### Post-Deployment

1. Note the contract address from deployment output
2. Register your public key
3. Test with small mint amounts
4. Verify balance retrieval and decryption

---

## Known Limitations

### Current Implementation

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Linear discrete log | Slow decryption for large values | Use values < 1M |
| Simple hash function | Not cryptographically ideal | Use Blake2b in production |
| No batch verification | Inefficient for multiple proofs | TODO |
| Fixed heap size | 64KB limit | Adjust constant if needed |
| Simplified range proofs | Not fully sound | Implement full Bulletproofs |

### PVM Constraints

- **Basic block size**: Complex operations split across functions
- **No floating point**: All arithmetic is integer-based
- **Memory limits**: Heap constrained to 64KB
- **No precompiles**: All crypto in pure Rust

---

## Future Improvements

### Short Term

1. **Blake2b Hash**: Replace simple_hash with proper hash function
2. **BSGS Decryption**: Constant-time discrete log with precomputed tables
3. **Batch Verification**: Verify multiple proofs efficiently
4. **Event Emission**: Add transfer events for indexing

### Medium Term

1. **Full Bulletproofs**: Complete inner-product argument
2. **Poseidon Hash**: ZK-friendly hash for circuits
3. **Withdrawal Proofs**: Convert private to public balances
4. **Multi-asset Support**: Multiple token types per contract

### Long Term

1. **Recursive Proofs**: Aggregate multiple transfers
2. **Hardware Acceleration**: PVM precompiles for EC ops
3. **Privacy Pools**: Anonymity sets for transfers
4. **Cross-chain Bridges**: Private transfers across parachains

---

## References

1. **Twisted ElGamal**: Peng, Kun, and Feng Bao. "An efficient range proof scheme."
2. **Bulletproofs**: Bünz et al. "Bulletproofs: Short Proofs for Confidential Transactions."
3. **JubJub**: Zcash protocol specification, JubJub curve.
4. **Polkadot PVM**: Polkadot SDK documentation.

---

## License

MIT License - See LICENSE file for details.

## Authors

Built with Summa for the Polkadot ecosystem.

---

*Last updated: December 2024*


