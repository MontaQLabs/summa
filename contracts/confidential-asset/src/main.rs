//! Confidential Asset contract using embedded Summa FHE library.
#![no_main]
#![no_std]

extern crate alloc;

use uapi::{HostFn, HostFnImpl as api, ReturnFlags, StorageFlags};
use summa::{Ciphertext, Decode, Encode, EqualityProof, PublicKey, TransferProof, AffineUpdateProof, EnrollmentNullifier, ApplicationNullifier, RangeProof};

// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// Simple bump allocator for no_std
struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

const HEAP_SIZE: usize = 65536;
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static mut HEAP_POS: usize = 0;

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        let aligned_pos = (unsafe { HEAP_POS } + align - 1) & !(align - 1);
        let new_pos = aligned_pos + size;

        if new_pos > HEAP_SIZE {
            core::ptr::null_mut()
        } else {
            unsafe { HEAP_POS = new_pos };
            (core::ptr::addr_of_mut!(HEAP) as *mut u8).add(aligned_pos)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // bump allocator: no deallocation
    }
}

// Storage keys
const BALANCE_PREFIX: [u8; 4] = [0xba, 0x1a, 0x2c, 0xe0];
const PUBKEY_PREFIX: [u8; 4] = [0x9b, 0x3f, 0x7a, 0x21];
const NOTE_PREFIX: [u8; 4] = [0x6e, 0x6f, 0x74, 0x65]; // "note"
const NULLIFIER_PREFIX: [u8; 4] = [0x6e, 0x75, 0x6c, 0x6c]; // "null"
const TOTAL_SUPPLY_KEY: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f,
    0x73, 0x70,
];
const OWNER_KEY: [u8; 32] = [
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x5f,
    0x5f, 0x5f,
];

// Function selectors
const SELECTOR_REGISTER_PUBKEY: [u8; 4] = [0x12, 0x34, 0xab, 0xcd];
const SELECTOR_TRANSFER: [u8; 4] = [0x56, 0x78, 0xef, 0xab];
const SELECTOR_DEPOSIT: [u8; 4] = [0x9a, 0xbc, 0x01, 0x23];
const SELECTOR_GET_BALANCE: [u8; 4] = [0xde, 0xf4, 0x56, 0x78];
const SELECTOR_MINT: [u8; 4] = [0xaa, 0xbb, 0x11, 0x22];
const SELECTOR_TRANSFER_OWNERSHIP: [u8; 4] = [0xf2, 0xfd, 0xe3, 0x8b];
const SELECTOR_OWNER: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b];
// totalSupply(): 0x18160ddd (ERC-20 standard)
const SELECTOR_TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];

const SELECTOR_TRANSFER_SPLIT: [u8; 4] = [0x77, 0x88, 0x99, 0xaa];
const SELECTOR_MINT_NOTE: [u8; 4] = [0xbb, 0xcc, 0xdd, 0xee];
const SELECTOR_SPEND_NOTE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const SELECTOR_APPLY_AFFINE: [u8; 4] = [0x55, 0x66, 0x77, 0x88];

// Veil PoP Primitives
const SELECTOR_VERIFY_ENROLLMENT: [u8; 4] = [0x33, 0x44, 0x55, 0x66];
const SELECTOR_VERIFY_APPLICATION: [u8; 4] = [0x77, 0x88, 0xaa, 0xbb];
const SELECTOR_VERIFY_THRESHOLD: [u8; 4] = [0xcc, 0xdd, 0xee, 0xff];

fn storage_get(key: &[u8; 32], output: &mut [u8]) -> bool {
    let mut out_slice: &mut [u8] = output;
    api::get_storage(StorageFlags::empty(), key, &mut out_slice).is_ok()
}

fn storage_set(key: &[u8; 32], value: &[u8]) {
    api::set_storage(StorageFlags::empty(), key, value);
}

fn storage_exists(key: &[u8; 32]) -> bool {
    let mut buf = [0u8; 1];
    let mut out: &mut [u8] = &mut buf;
    api::get_storage(StorageFlags::empty(), key, &mut out).is_ok()
}

fn get_owner() -> Option<[u8; 20]> {
    let mut owner_bytes = [0u8; 20];
    if storage_get(&OWNER_KEY, &mut owner_bytes) {
        Some(owner_bytes)
    } else {
        None
    }
}

fn set_owner(owner: &[u8; 20]) {
    storage_set(&OWNER_KEY, owner);
}

fn require_owner() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    match get_owner() {
        Some(owner) if owner == caller => {}
        Some(_) => revert_with_message(b"Only owner"),
        None => revert_with_message(b"No owner set"),
    }
}

#[unsafe(no_mangle)]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    let mut deployer = [0u8; 20];
    api::caller(&mut deployer);
    set_owner(&deployer);

    let zero_balance = Ciphertext::zero();
    let encoded = zero_balance.encode();
    storage_set(&TOTAL_SUPPLY_KEY, &encoded);
}

#[unsafe(no_mangle)]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
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
        SELECTOR_TOTAL_SUPPLY => handle_total_supply(),
        SELECTOR_TRANSFER_SPLIT => handle_transfer_split(),
        SELECTOR_MINT_NOTE => handle_mint_note(),
        SELECTOR_SPEND_NOTE => handle_spend_note(),
        SELECTOR_APPLY_AFFINE => handle_apply_affine(),
        SELECTOR_VERIFY_ENROLLMENT => handle_verify_enrollment(),
        SELECTOR_VERIFY_APPLICATION => handle_verify_application(),
        SELECTOR_VERIFY_THRESHOLD => handle_verify_threshold(),
        _ => revert_with_message(b"Unknown selector"),
    }
}

fn handle_register_pubkey() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut pubkey_bytes = [0u8; 32];
    api::call_data_copy(&mut pubkey_bytes, 4);

    let pubkey = PublicKey::from_bytes(pubkey_bytes);
    if pubkey.to_point().is_err() {
        revert_with_message(b"Invalid public key");
        return;
    }

    let key = make_pubkey_key(&caller);
    storage_set(&key, &pubkey_bytes);

    let balance_key = make_balance_key(&caller);
    if !storage_exists(&balance_key) {
        let zero = Ciphertext::zero();
        let encoded = zero.encode();
        storage_set(&balance_key, &encoded);
    }

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_transfer() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut recipient = [0u8; 20];
    api::call_data_copy(&mut recipient, 4);

    if recipient == caller {
        revert_with_message(b"Cannot self-transfer");
        return;
    }

    let mut amount_bytes = [0u8; 64];
    api::call_data_copy(&mut amount_bytes, 24);
    let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);

    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 88);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    if proof_len > 16384 {
        revert_with_message(b"Proof too large");
        return;
    }

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 92);

    let transfer_proof = match TransferProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid proof encoding");
            return;
        }
    };

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

    let sender_pubkey_key = make_pubkey_key(&caller);
    let mut sender_pubkey_bytes = [0u8; 32];
    if !storage_get(&sender_pubkey_key, &mut sender_pubkey_bytes) {
        revert_with_message(b"Sender pubkey not found");
        return;
    }
    let sender_pubkey = PublicKey::from_bytes(sender_pubkey_bytes);

    let receiver_pubkey_key = make_pubkey_key(&recipient);
    if !storage_exists(&receiver_pubkey_key) {
        revert_with_message(b"Recipient not registered");
        return;
    }

    let new_sender_balance = match sender_balance.sub_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Homomorphic sub failed");
            return;
        }
    };

    match transfer_proof.verify(&encrypted_amount, &new_sender_balance, &sender_pubkey) {
        Ok(true) => {}
        _ => {
            revert_with_message(b"Range proof invalid");
            return;
        }
    }

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

    let new_receiver_balance = match receiver_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Homomorphic add failed");
            return;
        }
    };

    storage_set(&sender_balance_key, &new_sender_balance.encode());
    storage_set(&receiver_balance_key, &new_receiver_balance.encode());

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_deposit() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut value_bytes = [0u8; 32];
    api::value_transferred(&mut value_bytes);

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

    // Calldata layout:
    // [4..68]: encrypted amount (64 bytes)
    // [68..72]: equality proof length (u32, big-endian)
    // [72..]: SCALE-encoded EqualityProof
    let mut encrypted_bytes = [0u8; 64];
    api::call_data_copy(&mut encrypted_bytes, 4);
    let encrypted_amount = Ciphertext::from_bytes(&encrypted_bytes);

    // Read equality proof length
    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 68);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    if proof_len > 4096 {
        // Sanity cap: equality proof should be small
        revert_with_message(b"Equality proof too large");
        return;
    }

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 72);

    let equality_proof = match EqualityProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid equality proof encoding");
            return;
        }
    };

    let pubkey_key = make_pubkey_key(&caller);
    let mut pubkey_bytes = [0u8; 32];
    if !storage_get(&pubkey_key, &mut pubkey_bytes) {
        revert_with_message(b"Register pubkey first");
        return;
    }
    let pubkey = PublicKey::from_bytes(pubkey_bytes);

    // Verify equality proof: encrypted_amount encodes `value`
    match equality_proof.verify(value, &encrypted_amount, &pubkey) {
        Ok(true) => {}
        Ok(false) => {
            revert_with_message(b"Equality proof invalid");
            return;
        }
        Err(_) => {
            revert_with_message(b"Equality proof error");
            return;
        }
    }

    let balance_key = make_balance_key(&caller);
    let mut balance_bytes = [0u8; 128];
    let current_balance = if storage_get(&balance_key, &mut balance_bytes) {
        Ciphertext::decode(&mut &balance_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    let new_balance = match current_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Add failed");
            return;
        }
    };

    storage_set(&balance_key, &new_balance.encode());

    // Update encrypted total supply as well (deposit mints into the shielded pool)
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

fn handle_get_balance() {
    let mut account = [0u8; 20];
    api::call_data_copy(&mut account, 4);

    let balance_key = make_balance_key(&account);
    let mut balance_bytes = [0u8; 128];

    let balance = if storage_get(&balance_key, &mut balance_bytes) {
        balance_bytes.to_vec()
    } else {
        Ciphertext::zero().encode()
    };

    api::return_value(ReturnFlags::empty(), &balance);
}

fn handle_mint() {
    require_owner();

    let mut recipient = [0u8; 20];
    api::call_data_copy(&mut recipient, 4);

    let mut amount_bytes = [0u8; 64];
    api::call_data_copy(&mut amount_bytes, 24);
    let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);

    let balance_key = make_balance_key(&recipient);
    let mut balance_bytes = [0u8; 128];
    let current_balance = if storage_get(&balance_key, &mut balance_bytes) {
        Ciphertext::decode(&mut &balance_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    let new_balance = match current_balance.add_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Mint add failed");
            return;
        }
    };

    storage_set(&balance_key, &new_balance.encode());

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

fn handle_transfer_ownership() {
    require_owner();

    let mut new_owner = [0u8; 20];
    api::call_data_copy(&mut new_owner, 4);

    if new_owner == [0u8; 20] {
        revert_with_message(b"Invalid new owner");
        return;
    }

    set_owner(&new_owner);

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_get_owner() {
    let owner = get_owner().unwrap_or([0u8; 20]);
    api::return_value(ReturnFlags::empty(), &owner);
}

fn handle_total_supply() {
    let mut supply_bytes = [0u8; 128];
    let supply = if storage_get(&TOTAL_SUPPLY_KEY, &mut supply_bytes) {
        supply_bytes.to_vec()
    } else {
        Ciphertext::zero().encode()
    };
    api::return_value(ReturnFlags::empty(), &supply);
}

fn handle_transfer_split() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let sender_balance_key = make_balance_key(&caller);
    let mut sender_balance_bytes = [0u8; 128];
    if !storage_get(&sender_balance_key, &mut sender_balance_bytes) {
        revert_with_message(b"Sender not registered");
        return;
    }
    let mut sender_balance = match Ciphertext::decode(&mut &sender_balance_bytes[..]) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Corrupt balance");
            return;
        }
    };

    let sender_pubkey_key = make_pubkey_key(&caller);
    let mut sender_pubkey_bytes = [0u8; 32];
    if !storage_get(&sender_pubkey_key, &mut sender_pubkey_bytes) {
        revert_with_message(b"Sender pubkey not found");
        return;
    }
    let sender_pubkey = PublicKey::from_bytes(sender_pubkey_bytes);
    let sender_pubkey_point = match sender_pubkey.to_point() {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid sender pubkey");
            return;
        }
    };

    let mut num_legs_bytes = [0u8; 4];
    api::call_data_copy(&mut num_legs_bytes, 4);
    let num_legs = u32::from_be_bytes(num_legs_bytes) as usize;

    let mut offset = 8usize;
    for _ in 0..num_legs {
        let mut recipient = [0u8; 20];
        api::call_data_copy(&mut recipient, offset as u32);
        offset += 20;

        let mut amount_bytes = [0u8; 64];
        api::call_data_copy(&mut amount_bytes, offset as u32);
        let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);
        offset += 64;

        let mut proof_len_bytes = [0u8; 4];
        api::call_data_copy(&mut proof_len_bytes, offset as u32);
        let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;
        offset += 4;

        let mut proof_data = alloc::vec![0u8; proof_len];
        api::call_data_copy(&mut proof_data, offset as u32);
        offset += proof_len;

        let transfer_proof = match TransferProof::decode(&mut &proof_data[..]) {
            Ok(p) => p,
            Err(_) => {
                revert_with_message(b"Invalid proof");
                return;
            }
        };

        // Update sender balance sequentially
        let next_sender_balance = match sender_balance.sub_encrypted(&encrypted_amount) {
            Ok(ct) => ct,
            Err(_) => {
                revert_with_message(b"Sub failed");
                return;
            }
        };

        // Verify proof for this leg using decompressed key
        match transfer_proof.verify_with_point(&encrypted_amount, &next_sender_balance, &sender_pubkey_point) {
            Ok(true) => {}
            _ => {
                revert_with_message(b"Leg proof invalid");
                return;
            }
        }

        // Update recipient balance
        let receiver_balance_key = make_balance_key(&recipient);
        let mut rb_bytes = [0u8; 128];
        let rb = if storage_get(&receiver_balance_key, &mut rb_bytes) {
            Ciphertext::decode(&mut &rb_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
        } else {
            Ciphertext::zero()
        };
        let next_rb = rb.add_encrypted(&encrypted_amount).unwrap();
        storage_set(&receiver_balance_key, &next_rb.encode());

        sender_balance = next_sender_balance;
    }

    storage_set(&sender_balance_key, &sender_balance.encode());
    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_mint_note() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut nullifier = [0u8; 32];
    api::call_data_copy(&mut nullifier, 4);

    let mut amount_bytes = [0u8; 64];
    api::call_data_copy(&mut amount_bytes, 36);
    let encrypted_amount = Ciphertext::from_bytes(&amount_bytes);

    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 100);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 104);

    let transfer_proof = match TransferProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid proof");
            return;
        }
    };

    let sender_balance_key = make_balance_key(&caller);
    let mut sb_bytes = [0u8; 128];
    if !storage_get(&sender_balance_key, &mut sb_bytes) {
        revert_with_message(b"Sender not found");
        return;
    }
    let sb = match Ciphertext::decode(&mut &sb_bytes[..]) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Corrupt balance");
            return;
        }
    };

    let sender_pubkey_key = make_pubkey_key(&caller);
    let mut spk_bytes = [0u8; 32];
    if !storage_get(&sender_pubkey_key, &mut spk_bytes) {
        revert_with_message(b"Pubkey not found");
        return;
    }
    let spk = PublicKey::from_bytes(spk_bytes);

    let next_sb = match sb.sub_encrypted(&encrypted_amount) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Sub failed");
            return;
        }
    };
    
    match transfer_proof.verify(&encrypted_amount, &next_sb, &spk) {
        Ok(true) => {}
        _ => {
            revert_with_message(b"Mint proof invalid");
            return;
        }
    }

    storage_set(&sender_balance_key, &next_sb.encode());
    
    // Store the note
    let note_key = make_note_key(&nullifier);
    storage_set(&note_key, &encrypted_amount.encode());

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_spend_note() {
    let mut nullifier = [0u8; 32];
    api::call_data_copy(&mut nullifier, 4);

    let mut recipient = [0u8; 20];
    api::call_data_copy(&mut recipient, 36);

    let null_key = make_nullifier_key(&nullifier);
    if storage_exists(&null_key) {
        revert_with_message(b"Already spent");
        return;
    }

    let note_key = make_note_key(&nullifier);
    let mut note_bytes = [0u8; 128];
    if !storage_get(&note_key, &mut note_bytes) {
        revert_with_message(b"Note not found");
        return;
    }
    let encrypted_amount = match Ciphertext::decode(&mut &note_bytes[..]) {
        Ok(ct) => ct,
        Err(_) => {
            revert_with_message(b"Corrupt note");
            return;
        }
    };

    let receiver_balance_key = make_balance_key(&recipient);
    let mut rb_bytes = [0u8; 128];
    let rb = if storage_get(&receiver_balance_key, &mut rb_bytes) {
        Ciphertext::decode(&mut &rb_bytes[..]).unwrap_or_else(|_| Ciphertext::zero())
    } else {
        Ciphertext::zero()
    };

    let next_rb = rb.add_encrypted(&encrypted_amount).unwrap();
    storage_set(&receiver_balance_key, &next_rb.encode());
    storage_set(&null_key, &[1u8]);

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_apply_affine() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut ct_old_bytes = [0u8; 64];
    api::call_data_copy(&mut ct_old_bytes, 4);
    let ct_old = Ciphertext::from_bytes(&ct_old_bytes);

    let mut ct_new_bytes = [0u8; 64];
    api::call_data_copy(&mut ct_new_bytes, 68);
    let ct_new = Ciphertext::from_bytes(&ct_new_bytes);

    let mut a_bytes = [0u8; 8];
    api::call_data_copy(&mut a_bytes, 132);
    let a = u64::from_be_bytes(a_bytes);

    let mut b_bytes = [0u8; 8];
    api::call_data_copy(&mut b_bytes, 140);
    let b = u64::from_be_bytes(b_bytes);

    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 148);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 152);

    let proof = match AffineUpdateProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid proof");
            return;
        }
    };

    // Verify the balance matches what the user claims to update
    let balance_key = make_balance_key(&caller);
    let mut actual_balance_bytes = [0u8; 128];
    if !storage_get(&balance_key, &mut actual_balance_bytes) {
        revert_with_message(b"Balance not found");
        return;
    }
    if actual_balance_bytes[..64] != ct_old_bytes {
         revert_with_message(b"Mismatch old balance");
         return;
    }

    let pubkey_key = make_pubkey_key(&caller);
    let mut spk_bytes = [0u8; 32];
    if !storage_get(&pubkey_key, &mut spk_bytes) {
        revert_with_message(b"Pubkey not found");
        return;
    }
    let spk = PublicKey::from_bytes(spk_bytes);

    match proof.verify(&ct_old, &ct_new, a, b, &spk) {
        Ok(true) => {}
        _ => {
            revert_with_message(b"Affine proof invalid");
            return;
        }
    }

    storage_set(&balance_key, &ct_new.encode());
    api::return_value(ReturnFlags::empty(), &[1u8]);
}

fn handle_verify_enrollment() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let pubkey_key = make_pubkey_key(&caller);
    let mut spk_bytes = [0u8; 32];
    if !storage_get(&pubkey_key, &mut spk_bytes) {
        revert_with_message(b"Pubkey not found");
        return;
    }
    let spk = PublicKey::from_bytes(spk_bytes);

    let data_size = api::call_data_size() as usize;
    if data_size <= 4 {
        revert_with_message(b"Missing proof data");
        return;
    }
    let proof_len = data_size - 4;
    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 4);
    
    let enroll = match EnrollmentNullifier::decode(&mut &proof_data[..]) {
        Ok(e) => e,
        Err(_) => {
            revert_with_message(b"Invalid proof encoding");
            return;
        }
    };

    match enroll.verify(&spk) {
        Ok(true) => api::return_value(ReturnFlags::empty(), &[1u8]),
        _ => revert_with_message(b"Enrollment proof invalid"),
    }
}

fn handle_verify_application() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let pubkey_key = make_pubkey_key(&caller);
    let mut spk_bytes = [0u8; 32];
    if !storage_get(&pubkey_key, &mut spk_bytes) {
        revert_with_message(b"Pubkey not found");
        return;
    }
    let spk = PublicKey::from_bytes(spk_bytes);

    let mut context_id = [0u8; 32];
    api::call_data_copy(&mut context_id, 4);

    let data_size = api::call_data_size() as usize;
    if data_size <= 36 {
        revert_with_message(b"Missing proof data");
        return;
    }
    let proof_len = data_size - 36;
    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 36);
    
    let app = match ApplicationNullifier::decode(&mut &proof_data[..]) {
        Ok(a) => a,
        Err(_) => {
            revert_with_message(b"Invalid proof encoding");
            return;
        }
    };

    match app.verify(&spk, &context_id) {
        Ok(true) => api::return_value(ReturnFlags::empty(), &[1u8]),
        _ => revert_with_message(b"Application proof invalid"),
    }
}

fn handle_verify_threshold() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut threshold_bytes = [0u8; 8];
    api::call_data_copy(&mut threshold_bytes, 4);
    let threshold = u64::from_be_bytes(threshold_bytes);

    let mut proof_len_bytes = [0u8; 4];
    api::call_data_copy(&mut proof_len_bytes, 12);
    let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

    let mut proof_data = alloc::vec![0u8; proof_len];
    api::call_data_copy(&mut proof_data, 16);

    let proof = match RangeProof::decode(&mut &proof_data[..]) {
        Ok(p) => p,
        Err(_) => {
            revert_with_message(b"Invalid proof encoding");
            return;
        }
    };

    let balance_key = make_balance_key(&caller);
    let mut balance_bytes = [0u8; 128];
    if !storage_get(&balance_key, &mut balance_bytes) {
        revert_with_message(b"Balance not found");
        return;
    }
    let balance_ct = Ciphertext::decode(&mut &balance_bytes[..]).unwrap();

    let pubkey_key = make_pubkey_key(&caller);
    let mut spk_bytes = [0u8; 32];
    storage_get(&pubkey_key, &mut spk_bytes);
    let spk = PublicKey::from_bytes(spk_bytes);

    match proof.verify_greater_than(&balance_ct, threshold, &spk, 64) {
        Ok(true) => api::return_value(ReturnFlags::empty(), &[1u8]),
        _ => revert_with_message(b"Threshold proof invalid"),
    }
}

fn make_balance_key(account: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&BALANCE_PREFIX);
    key[12..32].copy_from_slice(account);
    key
}

fn make_pubkey_key(account: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&PUBKEY_PREFIX);
    key[12..32].copy_from_slice(account);
    key
}

fn make_note_key(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&NOTE_PREFIX);
    key[4..].copy_from_slice(&nullifier[4..]);
    key
}

fn make_nullifier_key(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&NULLIFIER_PREFIX);
    key[4..].copy_from_slice(&nullifier[4..]);
    key
}

fn revert_with_message(msg: &[u8]) {
    api::return_value(ReturnFlags::REVERT, msg);
}


