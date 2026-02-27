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

### Advanced Cryptographic Primitives

- **DLEQ Proofs**: Proves that two elliptic curve points share the same discrete log. Used for nullifier verification.
- **Shielded Notes**: Support for UTXO-style private transfers using nullifiers to prevent double-spending.

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

### 2. Shielded Transfers (UTXO Mode)

Move from account-based to note-based privacy. Spend notes anonymously by revealing nullifiers.



### 4. Sealed-Bid Voting

Submit `Enc(votes)` during voting period. Sum homomorphically. Decrypt only after deadline. Prevents herd behavior.

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
│   │   ├── dleq.rs              # DLEQ proofs for nullifiers
│   │   ├── shielded.rs          # Note/UTXO primitives
│   │   ├── veil.rs              # Proof of Personhood primitives
│   │   └── client.rs            # Wallet and calldata utilities
│   └── README.md
├── contracts/
│   └── confidential-asset/       # Private token contract (PVM)
│       ├── src/main.rs          # Contract logic with new features
│       └── Summa.sol            # Solidity router for EVM integration
├── tools/
│   └── gen-ciphertext/           # CLI for encryption/decryption
├── docs/
│   ├── TECHNICAL.md             # Detailed technical documentation
│   ├── benchmark.md             # Performance benchmarks
├── DEPLOYED.md                   # Live deployment addresses
├── deploy.sh                     # Multi-network deployment script
└── Makefile
```

---

## Performance

Detailed benchmarks are available in [docs/benchmark.md](docs/benchmark.md).

| Operation | Gas (approx.) | Time |
|-----------|---------------|------|
| Encryption (client) | N/A | ~2ms |
| Homomorphic Add | ~20,000 | ~0.05ms |
| Range Proof Verify | ~500,000 | ~12ms |

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Built for Polkadot 🔴</b>
  <br>
  <i>Enabling confidential computation on public blockchains</i>
</p>
