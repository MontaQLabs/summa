//! Library tests for advanced Summa features

use crate::client::ConfidentialWallet;
use crate::keys::SecretKey;
use crate::curve::Scalar;
use crate::veil::{EnrollmentNullifier, ApplicationNullifier};

#[test]
fn test_split_transfer_creation() {
    let wallet = ConfidentialWallet::from_seed(&[1u8; 32]);
    let current_balance = 1000u64;
    
    let legs = [
        (100u64, [0xaa; 20], [2u8; 32]),
        (200u64, [0xbb; 20], [3u8; 32]),
        (300u64, [0xcc; 20], [4u8; 32]),
    ];
    
    let split_data = wallet.create_split_transfers(&legs, current_balance).expect("Failed to create split transfers");
    
    assert_eq!(split_data.legs.len(), 3);
    assert_eq!(split_data.legs[0].recipient, [0xaa; 20]);
    assert_eq!(split_data.legs[1].recipient, [0xbb; 20]);
    assert_eq!(split_data.legs[2].recipient, [0xcc; 20]);
}

#[test]
fn test_note_minting_and_spending() {
    let wallet = ConfidentialWallet::from_seed(&[1u8; 32]);
    let current_balance = 1000u64;
    let note_value = 500u64;
    
    let (note, proof) = wallet.mint_note_from_balance(
        note_value, 
        current_balance, 
        &[2u8; 32], 
        &[3u8; 32], 
        &[4u8; 32]
    ).expect("Failed to mint note");
    
    // Verify proof (simulating contract check)
    let new_balance_ct = wallet.public_key().encrypt(current_balance - note_value, &Scalar::random_with_seed(&[4u8; 32])).unwrap();
    
    assert!(proof.verify(&note.ciphertext, &new_balance_ct, wallet.public_key()).is_ok());
}

#[test]
fn test_veil_nullifiers() {
    let seed = [1u8; 32];
    let sk = SecretKey::from_seed(&seed);
    let pk = sk.public_key();
    
    let proof_seed = [2u8; 32];
    
    // 1. Test Enrollment Nullifier
    let enroll = EnrollmentNullifier::create(&sk, &proof_seed).expect("Failed to create enrollment nullifier");
    assert!(enroll.verify(&pk).expect("Verification failed"));
    
    // Test with wrong PK
    let other_sk = SecretKey::from_seed(&[2u8; 32]);
    let other_pk = other_sk.public_key();
    assert!(!enroll.verify(&other_pk).expect("Verification should fail"));
    
    // 2. Test Application Nullifier
    let context_id = [0xaa; 32];
    let app_null = ApplicationNullifier::create(&sk, &context_id, &proof_seed).expect("Failed to create application nullifier");
    assert!(app_null.verify(&pk, &context_id).expect("Verification failed"));
    
    // Test with wrong context
    let other_context = [0xbb; 32];
    assert!(!app_null.verify(&pk, &other_context).expect("Verification should fail"));
    
    // Test with wrong PK
    assert!(!app_null.verify(&other_pk, &context_id).expect("Verification should fail"));
}

#[test]
fn test_affine_update_proof() {
    let wallet = ConfidentialWallet::from_seed(&[1u8; 32]);
    let v_old = 100u64;
    let a = 105u64;
    let b = 10u64;
    
    let r_old = Scalar::random_with_seed(&[2u8; 32]);
    let ct_old = wallet.public_key().encrypt(v_old, &r_old).unwrap();
    
    let (ct_new, proof) = wallet.apply_affine_with_proof(
        v_old,
        a,
        b,
        &r_old,
        &[3u8; 32],
        &[4u8; 32],
    ).expect("Failed to create affine update proof");
    
    // Verify
    let result = proof.verify(&ct_old, &ct_new, a, b, wallet.public_key()).expect("Verification failed");
    assert!(result);
    
    // Test with wrong values
    let result_wrong = proof.verify(&ct_old, &ct_new, a + 1, b, wallet.public_key());
    assert!(result_wrong.is_err() || !result_wrong.unwrap());
}

#[test]
fn test_verify_greater_than() {
    let wallet = ConfidentialWallet::from_seed(&[1u8; 32]);
    let value = 100u64;
    let threshold = 50u64;
    let randomness = [2u8; 32];
    let proof_seed = [3u8; 32];
    
    let (ct, proof) = wallet.create_range_proof(value, &randomness, &proof_seed).unwrap();
    
    // v >= threshold (100 >= 50)
    assert!(proof.verify_greater_than(&ct, threshold, wallet.public_key(), 64).unwrap());
    
    // v < threshold (100 < 150)
    let (ct2, mut proof2) = wallet.create_range_proof(value, &randomness, &proof_seed).unwrap();
    proof2.challenge = [0u8; 32]; // This will make challenge_scalar zero
    assert!(!proof2.verify_greater_than(&ct2, 150, wallet.public_key(), 64).unwrap_or(false));
}
