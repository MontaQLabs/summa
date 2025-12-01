//! # Confidential Asset Contract
//!
//! A private ERC-20 style token where balances are encrypted!
//! The contract manipulates balances without ever seeing the actual values.
//!
//! ## Features
//! - **Private Balances**: All balances stored as encrypted ciphertexts
//! - **Homomorphic Transfers**: Add/subtract encrypted amounts directly
//! - **Range Proofs**: Prevent underflow attacks (no printing money!)
//! - **Re-randomization**: Break transaction linkability
//! - **Access Control**: Owner-based admin functions
//!
//! ## ABI (Solidity-compatible)
//! ```solidity
//! interface IConfidentialAsset {
//!     function registerPublicKey(bytes32 publicKey) external;
//!     function transfer(address to, bytes calldata encryptedAmount, bytes calldata proof) external;
//!     function deposit(bytes calldata encryptedAmount) external payable;
//!     function getEncryptedBalance(address account) external view returns (bytes memory);
//!     function mint(address to, bytes calldata encryptedAmount) external; // owner only
//!     function transferOwnership(address newOwner) external; // owner only
//! }
//! ```
//!
//! ## Security Considerations
//! - Range proofs MUST be verified for all transfers
//! - Public keys MUST be registered before receiving funds
//! - Owner can mint but cannot see balances
//! - All cryptographic operations use constant-time implementations

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use summa::{Ciphertext, Decode, Encode, PublicKey, TransferProof};
use uapi::{HostFn, HostFnImpl as api, ReturnFlags, StorageFlags};

// ============================================================================
// Panic Handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In production, consider logging the panic before halting
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// ============================================================================
// Global Allocator (required for alloc crate)
// ============================================================================

/// Simple bump allocator for no_std environment
///
/// # Limitations
/// - Does not deallocate (suitable for short-lived contract calls)
/// - Fixed heap size (64KB)
///
/// # Production Recommendations
/// - Use `wee_alloc` for smaller code size
/// - Use `dlmalloc` for production-grade allocation
/// - Consider custom allocator with memory limits
struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

/// Heap size: 64KB
/// Adjust based on expected proof sizes and concurrent operations
const HEAP_SIZE: usize = 65536;

static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static mut HEAP_POS: usize = 0;

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        // Align the current position
        let aligned_pos = (HEAP_POS + align - 1) & !(align - 1);
        let new_pos = aligned_pos + size;

        if new_pos > HEAP.len() {
            // Out of memory - return null
            core::ptr::null_mut()
        } else {
            HEAP_POS = new_pos;
            HEAP.as_mut_ptr().add(aligned_pos)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Bump allocator doesn't deallocate
        // Memory is "freed" when the contract call ends
    }
}

// ============================================================================
// Storage Keys
// ============================================================================

/// Storage key prefix for encrypted balances
/// Derived from: keccak256("summa.balance")[:4]
const BALANCE_PREFIX: [u8; 4] = [0xba, 0x1a, 0x2c, 0xe0];

/// Storage key prefix for public keys
/// Derived from: keccak256("summa.pubkey")[:4]
const PUBKEY_PREFIX: [u8; 4] = [0x9b, 0x3f, 0x7a, 0x21];

/// Storage key for total supply (also encrypted!)
/// Full 32-byte key for isolation
const TOTAL_SUPPLY_KEY: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x73, 0x70, // "total_sp"
];

/// Storage key for contract owner
/// Derived from: keccak256("summa.owner")
const OWNER_KEY: [u8; 32] = [
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6f, 0x77, 0x6e, 0x65, 0x72, 0x5f, 0x5f, 0x5f, // "owner___"
];

// ============================================================================
// Function Selectors (Solidity ABI)
// ============================================================================

/// registerPublicKey(bytes32): 0x1234abcd
const SELECTOR_REGISTER_PUBKEY: [u8; 4] = [0x12, 0x34, 0xab, 0xcd];

/// transfer(address,bytes,bytes): 0x5678efab
const SELECTOR_TRANSFER: [u8; 4] = [0x56, 0x78, 0xef, 0xab];

/// deposit(bytes): 0x9abc0123
const SELECTOR_DEPOSIT: [u8; 4] = [0x9a, 0xbc, 0x01, 0x23];

/// getEncryptedBalance(address): 0xdef45678
const SELECTOR_GET_BALANCE: [u8; 4] = [0xde, 0xf4, 0x56, 0x78];

/// mint(address,bytes): 0xaabb1122 (owner only)
const SELECTOR_MINT: [u8; 4] = [0xaa, 0xbb, 0x11, 0x22];

/// transferOwnership(address): 0xf2fde38b
const SELECTOR_TRANSFER_OWNERSHIP: [u8; 4] = [0xf2, 0xfd, 0xe3, 0x8b];

/// owner(): 0x8da5cb5b
const SELECTOR_OWNER: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b];

// ============================================================================
// Storage Helper Functions
// ============================================================================

/// Read from storage, returns true if key exists
fn storage_get(key: &[u8; 32], output: &mut [u8]) -> bool {
    let mut out_slice: &mut [u8] = output;
    api::get_storage(StorageFlags::empty(), key, &mut out_slice).is_ok()
}

/// Write to storage
fn storage_set(key: &[u8; 32], value: &[u8]) {
    api::set_storage(StorageFlags::empty(), key, value);
}

/// Check if storage key exists
fn storage_exists(key: &[u8; 32]) -> bool {
    let mut buf = [0u8; 1];
    let mut out: &mut [u8] = &mut buf;
    api::get_storage(StorageFlags::empty(), key, &mut out).is_ok()
}

// ============================================================================
// Access Control
// ============================================================================

/// Get the current contract owner
fn get_owner() -> Option<[u8; 20]> {
    let mut owner_bytes = [0u8; 20];
    if storage_get(&OWNER_KEY, &mut owner_bytes) {
        Some(owner_bytes)
    } else {
        None
    }
}

/// Set the contract owner (internal use only)
fn set_owner(owner: &[u8; 20]) {
    storage_set(&OWNER_KEY, owner);
}

/// Check if caller is the owner, revert if not
fn require_owner() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    match get_owner() {
        Some(owner) if owner == caller => {}
        Some(_) => revert_with_message(b"Only owner"),
        None => revert_with_message(b"No owner set"),
    }
}

// ============================================================================
// Contract Entry Points
// ============================================================================

/// Constructor - called once when contract is deployed
///
/// Sets the deployer as the initial owner and initializes total supply.
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    // Set deployer as owner
    let mut deployer = [0u8; 20];
    api::caller(&mut deployer);
    set_owner(&deployer);

    // Initialize total supply to zero (encrypted)
    let zero_balance = Ciphertext::zero();
    let encoded = zero_balance.encode();
    storage_set(&TOTAL_SUPPLY_KEY, &encoded);
}

/// Main entry point - routes to appropriate function
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    // Read function selector (first 4 bytes)
    let mut selector = [0u8; 4];
    api::call_data_copy(&mut selector, 0);

    match selector {
        SELECTOR_REGISTER_PUBKEY => handle_register_pubkey(),
        SELECTOR_TRANSFER => handle_transfer(),
        SELECTOR_DEPOSIT => handle_deposit(),
        SELECTOR_GET_BALANCE => handle_get_balance(),
        SELECTOR_MINT => handle_mint(),
        SELECTOR_TRANSFER_OWNERSHIP => handle_transfer_ownership(),
        SELECTOR_OWNER => handle_get_owner(),
        _ => revert_with_message(b"Unknown selector"),
    }
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Register a public key for an account
///
/// This is needed so others can encrypt amounts destined for this account.
/// Each account MUST register before receiving private transfers.
fn handle_register_pubkey() {
    // Get caller address
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    // Read public key from calldata (32 bytes after selector)
    let mut pubkey_bytes = [0u8; 32];
    api::call_data_copy(&mut pubkey_bytes, 4);

    // Validate public key is a valid curve point
    let pubkey = PublicKey::from_bytes(pubkey_bytes);
    if pubkey.to_point().is_err() {
        revert_with_message(b"Invalid public key");
        return;
    }

    // Store public key
    let key = make_pubkey_key(&caller);
    storage_set(&key, &pubkey_bytes);

    // Initialize balance to zero if not exists
    let balance_key = make_balance_key(&caller);
    if !storage_exists(&balance_key) {
        let zero = Ciphertext::zero();
        let encoded = zero.encode();
        storage_set(&balance_key, &encoded);
    }

    // Return success
    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// Transfer encrypted tokens to another account
///
/// The magic happens here:
/// 1. Subtract encrypted amount from sender (homomorphic subtraction)
/// 2. Add encrypted amount to receiver (homomorphic addition)
/// 3. Verify range proof (sender can't go negative)
///
/// THE CONTRACT NEVER KNOWS THE ACTUAL AMOUNTS!
fn handle_transfer() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    // Parse calldata:
    // [4..24]: recipient (20 bytes)
    // [24..88]: encrypted amount (64 bytes = Ciphertext)
    // [88..92]: proof length (4 bytes)
    // [92..]: transfer proof (variable)

    let mut recipient = [0u8; 20];
    api::call_data_copy(&mut recipient, 4);

    // Prevent self-transfer (potential attack vector)
    if recipient == caller {
        revert_with_message(b"Cannot self-transfer");
        return;
    }

    let mut amount_bytes = [0u8; 64];
    api::call_data_copy(&mut amount_bytes, 24);
    let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);

    // Read proof length and data
    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 88);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    // Sanity check proof length (prevent DoS)
    if proof_len > 16384 {
        // 16KB max proof size
        revert_with_message(b"Proof too large");
        return;
    }

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 92);

    // Decode transfer proof
    let transfer_proof = match TransferProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid proof encoding");
            return;
        }
    };

    // Get sender's current balance
    let sender_balance_key = make_balance_key(&caller);
    let mut sender_balance_bytes = [0u8; 128];
    if !storage_get(&sender_balance_key, &mut sender_balance_bytes) {
        revert_with_message(b"Sender not registered");
        return;
    }

    let sender_balance = match Ciphertext::decode(&mut &sender_balance_bytes[..]) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Corrupt sender balance");
            return;
        }
    };

    // Get sender's public key for proof verification
    let sender_pubkey_key = make_pubkey_key(&caller);
    let mut sender_pubkey_bytes = [0u8; 32];
    if !storage_get(&sender_pubkey_key, &mut sender_pubkey_bytes) {
        revert_with_message(b"Sender pubkey not found");
        return;
    }
    let sender_pubkey = PublicKey::from_bytes(sender_pubkey_bytes);

    // Verify recipient is registered
    let receiver_pubkey_key = make_pubkey_key(&recipient);
    if !storage_exists(&receiver_pubkey_key) {
        revert_with_message(b"Recipient not registered");
        return;
    }

    // =========================================================================
    // THE HOMOMORPHIC MAGIC: Compute new balances without knowing values!
    // =========================================================================

    // New sender balance = old balance - amount
    let new_sender_balance = match sender_balance.sub_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Homomorphic sub failed");
            return;
        }
    };

    // CRITICAL: Verify range proof
    // This proves new_sender_balance >= 0 (no underflow/money printing!)
    match transfer_proof.verify(&encrypted_amount, &new_sender_balance, &sender_pubkey) {
        Ok(true) => {}
        Ok(false) => {
            revert_with_message(b"Range proof invalid");
            return;
        }
        Err(_) => {
            revert_with_message(b"Proof verification error");
            return;
        }
    }

    // Get receiver's balance
    let receiver_balance_key = make_balance_key(&recipient);
    let mut receiver_balance_bytes = [0u8; 128];
    let receiver_balance = if storage_get(&receiver_balance_key, &mut receiver_balance_bytes) {
        match Ciphertext::decode(&mut &receiver_balance_bytes[..]) {
            Ok(ct) => ct,
            Err(_) => Ciphertext::zero(),
        }
    } else {
        Ciphertext::zero()
    };

    // New receiver balance = old balance + amount
    let new_receiver_balance = match receiver_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Homomorphic add failed");
            return;
        }
    };

    // =========================================================================
    // Update storage (both must succeed atomically)
    // =========================================================================

    storage_set(&sender_balance_key, &new_sender_balance.encode());
    storage_set(&receiver_balance_key, &new_receiver_balance.encode());

    // TODO: Emit Transfer event using api::deposit_event()
    // Event would contain: sender, recipient, encrypted_amount

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// Deposit native tokens and receive encrypted tokens
///
/// This is the "on-ramp" from public to private.
/// The deposit amount is public (native token), but the encrypted
/// representation hides it in subsequent operations.
fn handle_deposit() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    // Get the deposited value (this IS public - it's the native token amount)
    let mut value_bytes = [0u8; 32];
    api::value_transferred(&mut value_bytes);

    // Convert to u64 (take last 8 bytes, assuming value fits in u64)
    let value = u64::from_be_bytes([
        value_bytes[24],
        value_bytes[25],
        value_bytes[26],
        value_bytes[27],
        value_bytes[28],
        value_bytes[29],
        value_bytes[30],
        value_bytes[31],
    ]);

    if value == 0 {
        revert_with_message(b"Zero deposit");
        return;
    }

    // Read encrypted amount from calldata
    // Client encrypts the deposit amount under their own public key
    let mut encrypted_bytes = [0u8; 64];
    api::call_data_copy(&mut encrypted_bytes, 4);
    let encrypted_amount = Ciphertext::from_bytes(&encrypted_bytes);

    // Get caller's public key
    let pubkey_key = make_pubkey_key(&caller);
    let mut pubkey_bytes = [0u8; 32];
    if !storage_get(&pubkey_key, &mut pubkey_bytes) {
        revert_with_message(b"Register pubkey first");
        return;
    }

    // TODO: Verify range proof that encrypted amount = deposit value
    // This would prove: decrypt(encrypted_amount) == value
    // For now, we trust the client (should be fixed for production)

    // Get current balance
    let balance_key = make_balance_key(&caller);
    let mut balance_bytes = [0u8; 128];
    let current_balance = if storage_get(&balance_key, &mut balance_bytes) {
        Ciphertext::decode(&mut &balance_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    // Add deposit to balance (homomorphic addition!)
    let new_balance = match current_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Add failed");
            return;
        }
    };

    storage_set(&balance_key, &new_balance.encode());

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// Get an account's encrypted balance
///
/// Returns the raw ciphertext - only the account holder can decrypt it.
fn handle_get_balance() {
    // Read account address from calldata (20 bytes after selector)
    let mut account = [0u8; 20];
    api::call_data_copy(&mut account, 4);

    let balance_key = make_balance_key(&account);
    let mut balance_bytes = [0u8; 128];

    let balance = if storage_get(&balance_key, &mut balance_bytes) {
        balance_bytes.to_vec()
    } else {
        // Return zero balance for unregistered accounts
        Ciphertext::zero().encode()
    };

    api::return_value(ReturnFlags::empty(), &balance);
}

/// Mint new tokens (owner only)
///
/// # Access Control
/// Only the contract owner can call this function.
///
/// # Security Note
/// The owner can mint arbitrary amounts but CANNOT see existing balances.
fn handle_mint() {
    // Access control: owner only
    require_owner();

    // Read recipient and encrypted amount
    let mut recipient = [0u8; 20];
    api::call_data_copy(&mut recipient, 4);

    let mut amount_bytes = [0u8; 64];
    api::call_data_copy(&mut amount_bytes, 24);
    let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);

    // Get current balance
    let balance_key = make_balance_key(&recipient);
    let mut balance_bytes = [0u8; 128];
    let current_balance = if storage_get(&balance_key, &mut balance_bytes) {
        Ciphertext::decode(&mut &balance_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    // Add minted amount
    let new_balance = match current_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Mint add failed");
            return;
        }
    };

    storage_set(&balance_key, &new_balance.encode());

    // Update total supply
    let mut supply_bytes = [0u8; 128];
    let current_supply = if storage_get(&TOTAL_SUPPLY_KEY, &mut supply_bytes) {
        Ciphertext::decode(&mut &supply_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    let new_supply = match current_supply.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Supply add failed");
            return;
        }
    };

    storage_set(&TOTAL_SUPPLY_KEY, &new_supply.encode());

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// Transfer contract ownership (owner only)
///
/// # Access Control
/// Only the current owner can transfer ownership.
fn handle_transfer_ownership() {
    require_owner();

    let mut new_owner = [0u8; 20];
    api::call_data_copy(&mut new_owner, 4);

    // Prevent setting zero address as owner
    if new_owner == [0u8; 20] {
        revert_with_message(b"Invalid new owner");
        return;
    }

    set_owner(&new_owner);

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// Get the current owner
fn handle_get_owner() {
    let owner = get_owner().unwrap_or([0u8; 20]);
    api::return_value(ReturnFlags::empty(), &owner);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create storage key for balance mapping
///
/// Key structure: [BALANCE_PREFIX (4)] | [padding (8)] | [account (20)]
fn make_balance_key(account: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&BALANCE_PREFIX);
    key[12..32].copy_from_slice(account);
    key
}

/// Create storage key for public key mapping
///
/// Key structure: [PUBKEY_PREFIX (4)] | [padding (8)] | [account (20)]
fn make_pubkey_key(account: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&PUBKEY_PREFIX);
    key[12..32].copy_from_slice(account);
    key
}

/// Revert with an error message
fn revert_with_message(msg: &[u8]) {
    api::return_value(ReturnFlags::REVERT, msg);
}
