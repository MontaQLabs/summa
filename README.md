# 🔐 Summa - Homomorphic Encryption for Polkadot

[![Rust](https://img.shields.io/badge/rust-1.84%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Network](https://img.shields.io/badge/network-Polkadot%20PVM-E6007A.svg)](https://polkadot.network)

**Privacy-preserving smart contracts for Polkadot.** Compute on encrypted data without decryption.

## ✨ Features

- **🔒 Private Balances** - Token balances stored as encrypted ciphertexts
- **➕ Homomorphic Operations** - Add/subtract encrypted values on-chain
- **📜 Zero-Knowledge Proofs** - Prevent underflow without revealing amounts
- **⚡ PVM Optimized** - Built for Polkadot's RISC-V virtual machine

## 🚀 Quick Start

```bash
# Build
make all

# Deploy
export PRIVATE_KEY=0x...
./deploy.sh --network testnet

# Interact
cargo run -p gen-ciphertext keygen
```

## 📦 Project Structure

```
summa/
├── summa/                    # Core cryptographic library
├── contracts/
│   └── confidential-asset/   # Private token contract
├── tools/
│   └── gen-ciphertext/       # CLI encryption tool
├── docs/
│   └── TECHNICAL.md          # Technical documentation
└── deploy.sh                 # Deployment script
```

## 📖 Documentation

See [docs/TECHNICAL.md](docs/TECHNICAL.md) for detailed technical documentation.

## 📜 License

MIT License
