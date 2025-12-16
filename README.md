# Summa

**Privacy-Preserving Smart Contracts on Polkadot PVM**

Summa is a Somewhat Homomorphic Encryption (SHE) library that enables confidential computation on the Polkadot Virtual Machine. Smart contracts can perform arithmetic on encrypted data without ever seeing the plaintext values.

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│   Encrypt(100) + Encrypt(50) = Encrypt(150)                       │
│                                                                    │
│   The contract computes the sum without knowing either value.      │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Live Demo

**Try it now on Passet Hub Testnet:**

| Contract | Address |
|----------|---------|
| Confidential Asset | `0x68d64d2b645ff6da083ef35a90f3b3931ea20b29` |

```bash
# Setup
export ETH_RPC_URL="https://testnet-passet-hub-eth-rpc.polkadot.io"
export CONTRACT="0x68d64d2b645ff6da083ef35a90f3b3931ea20b29"

# Query an encrypted balance
cast call $CONTRACT "0xdef45678c4B24396670D89CB02d525E3F8fa979839c19503"
```

See [DEPLOYED.md](DEPLOYED.md) for full deployment details and example calls.

---

## How It Works

### Twisted ElGamal Encryption

Summa uses Twisted ElGamal on the JubJub curve. The "twist" encodes messages in the exponent, enabling:

- **Additive Homomorphism**: `Enc(a) + Enc(b) = Enc(a + b)`
- **Scalar Multiplication**: `k × Enc(a) = Enc(k × a)`

```
Encryption:
    C₁ = r × G
    C₂ = m × G + r × Y    (Y = public key)

Homomorphic Add:
    (C₁ₐ + C₁ᵦ, C₂ₐ + C₂ᵦ) = Enc(a + b)
```

### Zero-Knowledge Range Proofs

Without range proofs, an attacker could send `Enc(-1000)` and underflow their balance. Summa includes Bulletproofs-style range proofs that verify `0 ≤ value < 2⁶⁴` without revealing the value.

---

## Use Cases

### 1. Confidential Assets (Private ERC-20)

The flagship demo contract. Token balances are encrypted - only the holder can decrypt their balance.

```rust
// On-chain: Contract adds encrypted balances
let new_balance = old_balance.add_encrypted(&deposit)?;

// Off-chain: Only you can decrypt
let balance = wallet.decrypt(&encrypted_balance)?;
```

**Tested on Passet Hub:**
- Minted encrypted tokens ✓
- Homomorphic balance updates ✓
- Client-side decryption ✓

### 2. Confidential Treasury

DAOs can manage payroll privately. Individual salaries are hidden, but total treasury spend is auditable.

### 3. Sealed-Bid Voting

Submit `Enc(votes)` during voting period. Sum homomorphically. Decrypt only after deadline. Prevents herd behavior.

### 4. Dark Pool Settlement

Combine with off-chain ZK proofs for order matching. Summa handles encrypted balance updates on-chain.

---

## Quick Start

### Prerequisites

```bash
# Rust 1.84+
rustup update stable

# RISC-V target for PVM
rustup target add riscv64gc-unknown-none-elf

# Polkatool for linking
cargo install polkatool@0.26

# Foundry for deployment
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

### Build

```bash
git clone https://github.com/MontaQLabs/summa
cd summa
make all
```

### Deploy

```bash
export PRIVATE_KEY=0x<your_key>
./deploy.sh --network testnet
```

### Interact

```bash
# Generate a keypair
cargo run -p gen-ciphertext keygen

# Encrypt a value
cargo run -p gen-ciphertext encrypt --value 1000 --seed 0x<your_seed>

# Decrypt a ciphertext
cargo run -p gen-ciphertext decrypt <hex_ciphertext> --seed 0x<your_seed>

# Generate contract calldata
cargo run -p gen-ciphertext calldata mint --to 0x<address> --amount 1000 --seed 0x<your_seed>
```

---

## Project Structure

```
summa/
├── summa/                        # Core cryptographic library
│   ├── src/
│   │   ├── curve.rs             # JubJub elliptic curve primitives
│   │   ├── keys.rs              # Key generation, encryption, decryption
│   │   ├── ciphertext.rs        # Homomorphic operations
│   │   ├── range_proof.rs       # Zero-knowledge range proofs
│   │   └── client.rs            # Wallet and calldata utilities
│   └── README.md
├── contracts/
│   └── confidential-asset/       # Private token contract (PVM)
├── tools/
│   └── gen-ciphertext/           # CLI for encryption/decryption
├── docs/
│   ├── TECHNICAL.md             # Detailed technical documentation
│   └── paper.tex                # Academic paper (LaTeX)
├── DEPLOYED.md                   # Live deployment addresses
├── deploy.sh                     # Multi-network deployment script
└── Makefile
```

---

## API Reference

### Library (Rust)

```rust
use summa::{ConfidentialWallet, Ciphertext};

// Create wallet from 32-byte seed
let wallet = ConfidentialWallet::from_seed(&seed);

// Get public key (share this for receiving)
let pubkey = wallet.public_key_bytes();

// Encrypt a value
let ct = wallet.encrypt_amount(1000, &randomness)?;

// Decrypt (client-side only)
let value = wallet.decrypt(&ct)?;

// Homomorphic operations (works on-chain!)
let sum = ct1.add_encrypted(&ct2)?;
let diff = ct1.sub_encrypted(&ct2)?;
let scaled = ct.mul_scalar(5)?;
```

### Contract Functions

| Function | Selector | Description |
|----------|----------|-------------|
| `registerPublicKey(bytes32)` | `0x1234abcd` | Register encryption key |
| `mint(address,bytes)` | `0xaabb1122` | Mint tokens (owner only) |
| `transfer(address,bytes,bytes)` | `0x5678efab` | Transfer with range proof |
| `getEncryptedBalance(address)` | `0xdef45678` | Get encrypted balance |
| `owner()` | `0x8da5cb5b` | Get contract owner |
| `transferOwnership(address)` | `0xf2fde38b` | Transfer ownership |

---

## Performance

| Operation | Gas (approx.) | Time |
|-----------|---------------|------|
| Encryption (client) | N/A | ~2ms |
| Homomorphic Add | ~20,000 | ~0.05ms |
| Scalar Multiply | ~50,000 | ~0.12ms |
| Range Proof Verify | ~500,000 | ~12ms |
| Decryption (client) | N/A | ~50ms |

Contract size: ~48KB

---

## Security Considerations

**Cryptographic Assumptions:**
- Discrete Log Problem on JubJub is hard
- Fiat-Shamir heuristic (random oracle model)

**What's Protected:**
- Individual balances (encrypted)
- Transfer amounts (encrypted + range proved)

**What's Public:**
- Transaction graph (who transacts with whom)
- Total supply
- Contract state structure

**Production Checklist:**
- [ ] Replace simple hash with Blake2b/Poseidon
- [ ] Implement Baby-Step Giant-Step for constant-time decryption
- [ ] External security audit
- [ ] Formal verification of range proofs

---

## Documentation

- **[Technical Documentation](docs/TECHNICAL.md)** - Deep dive into cryptography and architecture
- **[Academic Paper](docs/paper.tex)** - LaTeX paper with formal definitions

---

## Contributing

Contributions welcome! Please read our contributing guidelines.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Built for Polkadot 🔴</b>
  <br>
  <i>Enabling confidential computation on public blockchains</i>
</p>
