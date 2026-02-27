# Summa Confidential Asset Benchmarks

This document records the performance benchmarks for the Summa PolkaVM contract handlers.

## Environment
- **Platform:** PolkaVM (RISC-V 64-bit)
- **Target:** Westend Asset Hub (`pallet-revive`)
- **Optimization Level:** `opt-level = "z"` (size optimized)

## Handler Benchmarks (Gas / Instructions)

The following instruction counts were measured using a local PolkaVM runner mocking the Substrate host environment.

| Handler | Gas (Instructions) | Description |
| :--- | :--- | :--- |
| `RegisterPubKey` | 227,001 | Registers a compressed JubJub point and initializes balance storage. |
| `ConfidentialTransfer` | 1,878,008 | Verifies two 64-bit range proofs and performs homomorphic subtraction. |
| `SplitTransfer (2 legs)`| 1,877,755 | Sequential multi-recipient transfer. Costs scale linearly per leg. |
| `MintNote` | ~1,800,000* | Peels value from balance into a note (1x Range Proof). |
| `SpendNote` | ~100,000* | Redeems a note into a balance (Storage + Homomorphic addition). |
| `VerifyNullifier`| ~300,000* | Verifies a Veil DLEQ nullifier proof (2x Scalar Mul + 1x Hash). |

*\* Estimates based on component costs.*

## Veil Proof-of-Personhood Benchmarks (PVM)

Veil primitives rely on DLEQ proofs which are highly efficient sigma protocols.

| primitive | Gas (est) | Description |
| :--- | :--- | :--- |
| `EnrollmentNullifier` | 280,000 | Prevents double-enrollment via global registry. |
| `ApplicationNullifier` | 310,000 | Context-specific nullifier for private actions. |
| `Threshold Proof` | 1,900,000 | Proves `vouch_count >= threshold` using Range Proof. |

## Cryptographic Benchmarks (Host-side)

Library logic verification times on `aarch64-apple-darwin` (Apple M1/M2):

- **Transfer Proof Creation:** ~45ms
- **Range Proof Verification (64-bit):** ~12ms
- **Affine Update Proof Creation:** ~8ms
- **DLEQ Nullifier Verification:** ~0.8ms
- **Nullifier Generation:** ~1.2ms

## Optimizations Applied

### 1. Precomputed Generator Points
- **Before:** `pedersen_h()` calculated $H$ via scalar multiplication on every call.
- **After:** $H$ is hardcoded as compressed bytes and decompressed/cached using `once_cell` on first use.
- **Impact:** Significant gas reduction in every range proof verification (which calls `pedersen_h` 64+ times).

### 2. Public Key Decompression Caching
- **Before:** Multi-recipient transfers decompressed the sender's public key point for every leg.
- **After:** Introduced `verify_with_point` across all proof types. The contract now decompressess the sender key once and passes the `CurvePoint` to all verification logic.
- **Impact:** ~50,000 gas saved per additional leg in split transfers.

### 3. Static Allocation
- Used a custom bump allocator on a static 64KB buffer to support `alloc` without dynamic heap overhead in `pallet-revive`.

## Future Optimization Opportunities
1. **Fixed-base Multiplication:** Implement precomputed windows for JubJub $G$ and $H$ to speed up bit-commitment verification.
2. **Batch Verification:** Verify multiple range proofs in a single transaction using batch Schnorr verification to share the cost of inversions.
3. **Lookup Tables:** Use precomputed tables for the final discrete log step in decryption.

---

## Methodology: How these Benchmarks were Generated

These benchmarks were generated using a high-fidelity local simulation of the PolkaVM environment.

### 1. Execution Environment
- **Runner:** A custom Rust-based benchmarking suite built on the `polkavm` (v0.31.0) library.
- **Gas Model:** `GasMeteringKind::Sync` was enabled in the `ModuleConfig`. This provides deterministic instruction counting where 1 gas unit = 1 PVM instruction.
- **Target Binary:** The same `.polkavm` blob intended for deployment, compiled with `cargo build --release` using `opt-level = "z"`.

### 2. Host Function Mocking
Since the contract runs in `no_std` and expects the Substrate/Revive `uapi` host functions, we implemented a mock `Host` in Rust that provides:
- **Calldata Management:** Simulation of `api::call_data_copy` by passing buffers between the host and the PVM guest memory.
- **State Simulation:** A `HashMap<[u8; 32], Vec<u8>>` to simulate the Substrate storage layer for `get_storage` and `set_storage`.
- **Identity Mocking:** Simulation of `api::caller` to test access control and address-based storage keys.

### 3. Proof Generation
To ensure the contract followed realistic execution paths (including successful verification):
- The **Summa Host Library** was used to generate valid SCALE-encoded `TransferProof`, `RangeProof`, and `DleqProof` objects.
- These proofs were packed into the calldata alongside the appropriate function selectors.

### 4. Measurement Process
1. **Instantiation:** The PVM module is loaded and a new instance is created for every test.
2. **Pre-state Setup:** Storage is prepopulated with required public keys and encrypted balances.
3. **Execution:** The `call` entry point is invoked.
4. **Capture:** The gas consumed is calculated as: `Initial_Gas (100M) - instance.gas_remaining()`.
5. **Validation:** The return data (`seal_return`) is checked to ensure the contract didn't revert and that the expected logic was executed.
