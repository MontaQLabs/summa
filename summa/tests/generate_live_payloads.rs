use summa::{ConfidentialWallet, Encode, EnrollmentNullifier, ApplicationNullifier, SecretKey};

#[test]
fn generate_payloads() {
    let wallet = ConfidentialWallet::from_seed(&[1u8; 32]);
    let sk = SecretKey::from_seed(&[1u8; 32]);
    let pk = wallet.public_key_bytes();
    
    println!("--- PAYLOADS ---");
    println!("PK: 0x{}", hex::encode(pk));

    // 1. Deposit
    let value = 100u64;
    let (ct, proof) = wallet.create_deposit_proof(value, &[2u8; 32], &[3u8; 32]).unwrap();
    let mut deposit_payload = Vec::new();
    deposit_payload.extend_from_slice(&ct.to_bytes());
    deposit_payload.extend_from_slice(&(proof.encode().len() as u32).to_be_bytes());
    deposit_payload.extend_from_slice(&proof.encode());
    println!("DEPOSIT_PAYLOAD: 0x{}", hex::encode(deposit_payload));

    // 2. Transfer
    let transfer_amount = 50u64;
    let current_balance = 100u64;
    let transfer_data = wallet.create_transfer_proof(
        transfer_amount,
        current_balance,
        &[4u8; 32],
        &[5u8; 32],
        &[6u8; 32]
    ).expect("failed to create transfer proof");
    
    let proof_bytes = transfer_data.proof.encode();
    println!("TRANSFER_CT: 0x{}", hex::encode(transfer_data.encrypted_amount.to_bytes()));
    println!("TRANSFER_PROOF: 0x{}", hex::encode(proof_bytes));

    // 3. Veil Nullifiers
    let context_id = [0xaa; 32];
    let app_null = ApplicationNullifier::create(&sk, &context_id, &[7u8; 32]).unwrap();
    println!("APP_NULLIFIER: 0x{}", hex::encode(app_null.nullifier));
    println!("APP_PROOF: 0x{}", hex::encode(app_null.proof.encode()));
    
    let enroll = EnrollmentNullifier::create(&sk, &[8u8; 32]).unwrap();
    println!("ENROLL_PROOF: 0x{}", hex::encode(enroll.encode()));

    // 4. Threshold Proof (vouch_count >= threshold)
    let vouch_count = 10u64;
    let threshold = 5u64;
    let (ct_vouch, proof_vouch) = wallet.create_range_proof(vouch_count, &[9u8; 32], &[10u8; 32]).unwrap();
    // Payload: threshold (8b) || proofLen (4b) || proof
    let mut threshold_payload = Vec::new();
    threshold_payload.extend_from_slice(&threshold.to_be_bytes());
    let pv_encoded = proof_vouch.encode();
    threshold_payload.extend_from_slice(&(pv_encoded.len() as u32).to_be_bytes());
    threshold_payload.extend_from_slice(&pv_encoded);
    println!("THRESHOLD_PAYLOAD: 0x{}", hex::encode(threshold_payload));
}
