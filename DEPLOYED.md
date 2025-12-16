# Summa - Live Deployment

## Passet Hub Testnet

### Confidential Asset Contract

```
Address:  0x68d64d2b645ff6da083ef35a90f3b3931ea20b29
TX Hash:  0xe2e904634af789b699176e086946b0d85dc0c302e00ebd83aeb0c448542a5c97
Block:    0x275a47
Network:  Passet Hub Testnet
```

### Debug FHE Contract

```
Address:  0xc5f4dfe7102817c710c4ff05f89f0257dc0edfd5
```

---

## Network Configuration

```bash
export ETH_RPC_URL="https://testnet-passet-hub-eth-rpc.polkadot.io"
```

**Faucet:** https://contracts.polkadot.io/connect-to-asset-hub

---

## Test Wallet (Testnet Only!)

```
Address:     0xc4B24396670D89CB02d525E3F8fa979839c19503
Private Key: 0x9885855a16430396b5043367822299c74e712b149e2c35a05595246c3d70bbf8
FHE Seed:    [42u8; 32] (hex: 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a)
```

⚠️ **This is a TESTNET wallet for demo purposes. Do not use for real funds.**

---

## Function Selectors

| Function | Selector | Description |
|----------|----------|-------------|
| `registerPublicKey(bytes32)` | `0x1234abcd` | Register your FHE public key |
| `transfer(address,bytes,bytes)` | `0x5678efab` | Transfer encrypted tokens |
| `deposit(bytes)` | `0x9abc0123` | Deposit & encrypt tokens |
| `getEncryptedBalance(address)` | `0xdef45678` | Get encrypted balance |
| `mint(address,bytes)` | `0xaabb1122` | Mint tokens (owner only) |
| `owner()` | `0x8da5cb5b` | Get contract owner |
| `transferOwnership(address)` | `0xf2fde38b` | Transfer ownership |

---

## Try It Now

### Setup

```bash
export ETH_RPC_URL="https://testnet-passet-hub-eth-rpc.polkadot.io"
export PRIV_KEY="0x9885855a16430396b5043367822299c74e712b149e2c35a05595246c3d70bbf8"
export CONTRACT="0x68d64d2b645ff6da083ef35a90f3b3931ea20b29"
```

### 1. Check Existing Balance

```bash
# Query encrypted balance for test address
cast call $CONTRACT "0xdef45678c4B24396670D89CB02d525E3F8fa979839c19503"

# Returns ~64 bytes of encrypted balance data
```

### 2. Decrypt Balance Locally

```bash
# Using the CLI tool
cargo run -p gen-ciphertext decrypt "<hex_from_above>" --seed 0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a

# Output: ✅ Decrypted value: 1000
```

### 3. Register Your Public Key

```bash
# Generate keypair (or use test seed)
cargo run -p gen-ciphertext keygen

# Register with contract
cast send --private-key $PRIV_KEY $CONTRACT "0x1234abcd<your_32_byte_pubkey>"
```

### 4. Mint Tokens (Owner Only)

```bash
# Generate calldata
cargo run -p gen-ciphertext calldata mint \
    --to 0xc4B24396670D89CB02d525E3F8fa979839c19503 \
    --amount 500 \
    --seed 0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a

# Send transaction
cast send --private-key $PRIV_KEY $CONTRACT "<calldata_from_above>"
```

### 5. Verify Homomorphic Addition

```bash
# Get new balance (should be previous + 500)
NEW_BAL=$(cast call $CONTRACT "0xdef45678c4B24396670D89CB02d525E3F8fa979839c19503")

# Decrypt
cargo run -p gen-ciphertext decrypt "$NEW_BAL" --seed 0x2a2a...

# Output: ✅ Decrypted value: 1500
```

---

## Verified Test Results

The following operations were tested on Passet Hub:

| Test | Result |
|------|--------|
| Contract deployment | ✅ 48KB deployed successfully |
| Register public key | ✅ Stored on-chain |
| Mint 1000 tokens | ✅ Homomorphic add worked |
| Mint 100 more tokens | ✅ Balance updated to 1100 |
| Query encrypted balance | ✅ Returns valid ciphertext |
| Client-side decryption | ✅ Correctly recovers value |
| Homomorphic addition on-chain | ✅ Verified via debug contract |

---

## Contract Source

The deployed contract source is in `contracts/confidential-asset/src/main.rs`.

Key features:
- Owner-based access control
- Homomorphic balance updates
- Range proof verification (for transfers)
- SCALE-encoded storage

