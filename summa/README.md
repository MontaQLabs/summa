# Summa - Homomorphic Encryption for Polkadot

A `no_std` compatible library for privacy-preserving computations on Polkadot PVM.

## Features

- Twisted ElGamal encryption on JubJub curve
- Homomorphic addition and scalar multiplication
- Zero-knowledge range proofs
- SCALE codec integration

## Usage

```rust
use summa::{ConfidentialWallet, Ciphertext};

let wallet = ConfidentialWallet::from_seed(&seed);
let ct = wallet.encrypt_amount(1000, &randomness)?;
let sum = ct1.add_encrypted(&ct2)?;
```

## License

MIT
