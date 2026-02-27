# Summa & Veil Live Testing Results (Paseo Asset Hub)

This document records the results of live on-chain tests performed on the deployed contracts.

## Network Information
- **Network:** Paseo Asset Hub (Testnet)
- **Rust Core Address:** `0x010394c0cf86d31c54e2a95730b4102e77950bcb`
- **SummaRouter Address:** `0x98b0a96d9655065e09887c549b7591e287d5e5d5`
- **Wallet Address:** `0xE56369f022053dFa10AcB7b2142f929cABD5bFA7`
- **RPC URL:** `https://eth-rpc-testnet.polkadot.io/`

## Test Execution Log

### 1. Register Public Key
Registers the JubJub public key for the test wallet.
- **Action:** `SummaRouter.registerPublicKey(bytes32)`
- **JubJub PK:** `0x202446d8343b73e8757f4eb48491cd9effc7e3aefabc8a3c77775496efb8dd0a`
- **Transaction Hash:** `0xda0515d0abe18caca2ba66ba033deb4fa853207e786aa2b8335bb38fcc71804d`
- **Gas Used:** 989
- **Status:** Success

### 2. Confidential Deposit
Deposits PAS tokens into the confidential balance.
- **Action:** `SummaRouter.depositEncrypted(bytes, bytes)`
- **Amount:** 100 PAS
- **Transaction Hash:** `0x89476fa77a5568c519afae86811a5ab0a38166357f9a18de09312986f21e78da`
- **Gas Used:** 2,612
- **Status:** Success

### 3. Veil: Application Nullifier Verification
Verifies a contextual nullifier for a specific action (e.g., voting).
- **Action:** `SummaRouter.isUniquePerson(uint64, bytes32, bytes)`
- **Context ID:** 170 (0xaa)
- **Nullifier:** `0x37a5876129a1688cf2dadaf94962664e9c64ec0e047371f7b8018750e978cf33`
- **Transaction Hash:** `0x40d5ab2f8254b1789f575cca7c2b5df63b6512c0aeaaf5639c4c8b25c3e46ef7`
- **Gas Used:** 1,964
- **Status:** Success

### 4. Confidential Transfer
Transfers value between two registered accounts.
- **Action:** `SummaRouter.confidentialTransfer(address, bytes, bytes)`
- **Amount:** 50 PAS (encrypted)
- **Status:** Pending Execution
