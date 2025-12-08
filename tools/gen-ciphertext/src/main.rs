//! Summa CLI Tool - Generate and manage encrypted data
//!
//! This tool provides utilities for:
//! - Generating keypairs
//! - Encrypting values
//! - Decrypting ciphertexts
//! - Building contract calldata
//!
//! # Security Warning
//! This tool is for testing/development. In production:
//! - Use hardware wallets for key management
//! - Never expose seeds or private keys
//! - Use secure entropy sources

use summa::{
    Ciphertext, CompressedPoint, ConfidentialWallet, CurvePoint, Decode, Encode, Scalar,
};
use std::env;
use std::io::{self, Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => print_help(),
        "version" | "--version" | "-V" => println!("summa-cli v{}", VERSION),
        "keygen" => cmd_keygen(&args[2..]),
        "encrypt" => cmd_encrypt(&args[2..]),
        "decrypt" => cmd_decrypt(&args[2..]),
        "calldata" => cmd_calldata(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "test-zero" => cmd_test_zero(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Run 'gen-ciphertext help' for usage");
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        r#"
Summa CLI Tool v{}

USAGE:
    gen-ciphertext <COMMAND> [OPTIONS]

COMMANDS:
    keygen              Generate a new keypair
    encrypt             Encrypt a value
    decrypt             Decrypt a ciphertext
    calldata            Generate contract calldata
    verify              Verify a ciphertext
    test-zero           Test Ciphertext::zero() functionality
    help                Show this help message
    version             Show version

EXAMPLES:
    # Generate a new keypair (prompts for seed or generates random)
    gen-ciphertext keygen

    # Generate keypair from hex seed
    gen-ciphertext keygen --seed 0x0123456789...

    # Encrypt a value (100 tokens)
    gen-ciphertext encrypt --value 100 --seed <hex_seed>

    # Decrypt a ciphertext
    gen-ciphertext decrypt <hex_ciphertext> --seed <hex_seed>

    # Generate calldata for minting
    gen-ciphertext calldata mint --to <address> --amount 1000 --seed <hex_seed>

SECURITY:
    - Seeds should be 32 bytes of cryptographically secure randomness
    - Never share your seed or private key
    - In production, use hardware wallets

"#,
        VERSION
    );
}

/// Generate a new keypair
fn cmd_keygen(args: &[String]) {
    let seed = parse_seed_arg(args);

    let wallet = ConfidentialWallet::from_seed(&seed);
    let pubkey = wallet.public_key_bytes();

    println!("=== Summa Keypair ===\n");
    println!("Public Key (32 bytes, share this):");
    println!("  {}\n", hex::encode(pubkey));
    println!("Seed (32 bytes, KEEP SECRET!):");
    println!("  {}\n", hex::encode(seed));

    // Show derived address (keccak256(pubkey)[12:])
    let address = derive_address(&pubkey);
    println!("Derived Address:");
    println!("  0x{}\n", hex::encode(address));
}

/// Encrypt a value
fn cmd_encrypt(args: &[String]) {
    let seed = parse_seed_arg(args);
    let value = parse_value_arg(args);
    let rand_seed = parse_rand_seed_arg(args);

    let wallet = ConfidentialWallet::from_seed(&seed);
    let ct = wallet
        .encrypt_amount(value, &rand_seed)
        .expect("Encryption failed");

    println!("=== Encrypted Value ===\n");
    println!("Value: {}", value);
    println!("\nCiphertext (64 bytes):");
    println!("  {}\n", hex::encode(ct.to_bytes()));
    println!("C1 (32 bytes): {}", hex::encode(&ct.c1.0));
    println!("C2 (32 bytes): {}", hex::encode(&ct.c2.0));
}

/// Decrypt a ciphertext
fn cmd_decrypt(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gen-ciphertext decrypt <hex_ciphertext> --seed <hex_seed>");
        std::process::exit(1);
    }

    let hex_data = &args[0];
    let seed = parse_seed_arg(&args[1..]);

    let wallet = ConfidentialWallet::from_seed(&seed);
    let hex_clean = hex_data.strip_prefix("0x").unwrap_or(hex_data);

    let bytes = match hex::decode(hex_clean) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to decode hex: {}", e);
            std::process::exit(1);
        }
    };

    println!("=== Decrypting Ciphertext ===\n");
    println!("Input length: {} bytes", bytes.len());

    // Try SCALE decoding first
    if let Ok(ct) = Ciphertext::decode(&mut &bytes[..]) {
        println!("Format: SCALE-encoded\n");
        println!("C1: {}", hex::encode(&ct.c1.0));
        println!("C2: {}", hex::encode(&ct.c2.0));

        match wallet.decrypt(&ct) {
            Ok(value) => println!("\n✅ Decrypted value: {}", value),
            Err(e) => println!("\n❌ Decryption failed: {:?}", e),
        }
        return;
    }

    // Try raw 64-byte format
    if bytes.len() >= 64 {
        let mut ct_bytes = [0u8; 64];
        ct_bytes.copy_from_slice(&bytes[..64]);
        let ct = Ciphertext::from_bytes(&ct_bytes);

        println!("Format: Raw 64-byte\n");
        println!("C1: {}", hex::encode(&ct.c1.0));
        println!("C2: {}", hex::encode(&ct.c2.0));

        match wallet.decrypt(&ct) {
            Ok(value) => println!("\n✅ Decrypted value: {}", value),
            Err(e) => println!("\n❌ Decryption failed: {:?}", e),
        }
    } else {
        eprintln!("Invalid ciphertext format (need at least 64 bytes)");
        std::process::exit(1);
    }
}

/// Generate contract calldata
fn cmd_calldata(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gen-ciphertext calldata <action> [options]");
        eprintln!("Actions: register, mint, transfer, balance");
        std::process::exit(1);
    }

    match args[0].as_str() {
        "register" => {
            let seed = parse_seed_arg(&args[1..]);
            let wallet = ConfidentialWallet::from_seed(&seed);
            let pubkey = wallet.public_key_bytes();

            println!("=== Register Public Key Calldata ===\n");
            println!("Selector: 0x1234abcd");
            println!("Public Key: {}", hex::encode(pubkey));
            println!("\nFull calldata:");
            println!("0x1234abcd{}", hex::encode(pubkey));
        }
        "mint" => {
            let seed = parse_seed_arg(&args[1..]);
            let address = parse_address_arg(&args[1..]);
            let value = parse_value_arg(&args[1..]);
            let rand_seed = parse_rand_seed_arg(&args[1..]);

            let wallet = ConfidentialWallet::from_seed(&seed);
            let ct = wallet
                .encrypt_amount(value, &rand_seed)
                .expect("Encryption failed");

            println!("=== Mint Calldata ===\n");
            println!("Selector: 0xaabb1122");
            println!("Recipient: {}", hex::encode(&address));
            println!("Amount: {} (encrypted)", value);
            println!("\nFull calldata:");
            println!("0xaabb1122{}{}", hex::encode(&address), hex::encode(ct.to_bytes()));
        }
        "transfer" => {
            let seed = parse_seed_arg(&args[1..]);
            let address = parse_address_arg(&args[1..]);
            let value = parse_value_arg(&args[1..]);
            let rand_seed = parse_rand_seed_arg(&args[1..]);

            let wallet = ConfidentialWallet::from_seed(&seed);
            let ct = wallet
                .encrypt_amount(value, &rand_seed)
                .expect("Encryption failed");

            println!("=== Transfer Calldata ===\n");
            println!("Selector: 0x5678efab");
            println!("Recipient: {}", hex::encode(&address));
            println!("Amount: {} (encrypted)", value);
            println!("\nFull calldata (without proof):");
            println!("0x5678efab{}{}", hex::encode(&address), hex::encode(ct.to_bytes()));
            println!("\n⚠️  Note: Full transfer requires a range proof appended");
        }
        "balance" => {
            let address = parse_address_arg(&args[1..]);

            println!("=== Get Balance Calldata ===\n");
            println!("Selector: 0xdef45678");
            println!("Account: {}", hex::encode(&address));
            println!("\nFull calldata:");
            println!("0xdef45678{}", hex::encode(&address));
        }
        _ => {
            eprintln!("Unknown calldata action: {}", args[0]);
            std::process::exit(1);
        }
    }
}

/// Verify a ciphertext
fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gen-ciphertext verify <hex_ciphertext>");
        std::process::exit(1);
    }

    let hex_data = &args[0];
    let hex_clean = hex_data.strip_prefix("0x").unwrap_or(hex_data);

    let bytes = match hex::decode(hex_clean) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to decode hex: {}", e);
            std::process::exit(1);
        }
    };

    println!("=== Verifying Ciphertext ===\n");
    println!("Input length: {} bytes", bytes.len());

    // Try to parse and validate the points
    if bytes.len() >= 64 {
        let mut c1_bytes = [0u8; 32];
        let mut c2_bytes = [0u8; 32];
        c1_bytes.copy_from_slice(&bytes[..32]);
        c2_bytes.copy_from_slice(&bytes[32..64]);

        let c1 = CompressedPoint::from_bytes(c1_bytes);
        let c2 = CompressedPoint::from_bytes(c2_bytes);

        println!("\nC1 (32 bytes): {}", hex::encode(&c1.0));
        print!("  Validity: ");
        match c1.decompress() {
            Ok(p) => {
                if p.is_identity() {
                    println!("✅ Valid (identity point)");
                } else {
                    println!("✅ Valid curve point");
                }
            }
            Err(_) => println!("❌ Invalid point!"),
        }

        println!("\nC2 (32 bytes): {}", hex::encode(&c2.0));
        print!("  Validity: ");
        match c2.decompress() {
            Ok(p) => {
                if p.is_identity() {
                    println!("✅ Valid (identity point)");
                } else {
                    println!("✅ Valid curve point");
                }
            }
            Err(_) => println!("❌ Invalid point!"),
        }
    } else {
        eprintln!("Need at least 64 bytes for a ciphertext");
    }
}

/// Test Ciphertext::zero() functionality
fn cmd_test_zero() {
    println!("=== Testing Ciphertext::zero() ===\n");

    // Test identity point
    let identity = CurvePoint::identity();
    let compressed = identity.compress();
    println!("Identity point compressed: {}", hex::encode(&compressed.0));

    match compressed.decompress() {
        Ok(point) => {
            println!("Decompression: SUCCESS");
            println!("Is identity: {}", point.is_identity());
        }
        Err(e) => {
            println!("Decompression: FAILED - {:?}", e);
        }
    }

    println!("\n--- Ciphertext::zero() ---");
    let zero_ct = Ciphertext::zero();
    println!("C1: {}", hex::encode(&zero_ct.c1.0));
    println!("C2: {}", hex::encode(&zero_ct.c2.0));
    println!("SCALE encoded: {}", hex::encode(zero_ct.encode()));

    // Test with a fresh random seed
    let seed = generate_random_seed();
    let wallet = ConfidentialWallet::from_seed(&seed);
    let ct_100 = wallet
        .encrypt_amount(100, &[1u8; 32])
        .expect("encryption failed");

    println!("\n--- Testing zero + encrypted(100) ---");
    match zero_ct.add_encrypted(&ct_100) {
        Ok(result) => {
            println!("Addition: SUCCESS");
            println!("Result: {}", hex::encode(result.to_bytes()));
            match wallet.decrypt(&result) {
                Ok(v) => println!("Decrypts to: {}", v),
                Err(e) => println!("Decrypt failed: {:?}", e),
            }
        }
        Err(e) => {
            println!("Addition: FAILED - {:?}", e);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_seed_arg(args: &[String]) -> [u8; 32] {
    for i in 0..args.len() {
        if args[i] == "--seed" && i + 1 < args.len() {
            let hex = args[i + 1].strip_prefix("0x").unwrap_or(&args[i + 1]);
            let bytes = hex::decode(hex).expect("Invalid hex seed");
            if bytes.len() != 32 {
                eprintln!("Seed must be exactly 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return seed;
        }
    }

    // No seed provided - prompt or generate
    eprint!("No --seed provided. Generate random? [Y/n]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if input.trim().to_lowercase() == "n" {
        eprint!("Enter seed (64 hex chars): ");
        io::stdout().flush().unwrap();
        input.clear();
        io::stdin().read_line(&mut input).unwrap();
        let hex = input.trim().strip_prefix("0x").unwrap_or(input.trim());
        let bytes = hex::decode(hex).expect("Invalid hex seed");
        if bytes.len() != 32 {
            eprintln!("Seed must be exactly 32 bytes (64 hex chars)");
            std::process::exit(1);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    } else {
        generate_random_seed()
    }
}

fn parse_value_arg(args: &[String]) -> u64 {
    for i in 0..args.len() {
        if (args[i] == "--value" || args[i] == "--amount") && i + 1 < args.len() {
            return args[i + 1].parse().expect("Invalid value");
        }
    }
    eprintln!("Missing --value or --amount argument");
    std::process::exit(1);
}

fn parse_address_arg(args: &[String]) -> [u8; 20] {
    for i in 0..args.len() {
        if args[i] == "--to" && i + 1 < args.len() {
            let hex = args[i + 1].strip_prefix("0x").unwrap_or(&args[i + 1]);
            let bytes = hex::decode(hex).expect("Invalid hex address");
            if bytes.len() != 20 {
                eprintln!("Address must be exactly 20 bytes (40 hex chars)");
                std::process::exit(1);
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&bytes);
            return addr;
        }
    }
    eprintln!("Missing --to <address> argument");
    std::process::exit(1);
}

fn parse_rand_seed_arg(args: &[String]) -> [u8; 32] {
    for i in 0..args.len() {
        if args[i] == "--randomness" && i + 1 < args.len() {
            let hex = args[i + 1].strip_prefix("0x").unwrap_or(&args[i + 1]);
            let bytes = hex::decode(hex).expect("Invalid hex randomness");
            if bytes.len() != 32 {
                eprintln!("Randomness must be exactly 32 bytes");
                std::process::exit(1);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return seed;
        }
    }
    // Generate random if not specified
    generate_random_seed()
}

fn generate_random_seed() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut seed = [0u8; 32];
    
    // Mix multiple entropy sources
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    seed[0..16].copy_from_slice(&time.to_le_bytes());
    
    // Add some process-specific entropy
    let hasher = RandomState::new().build_hasher();
    let hash = hasher.finish();
    seed[16..24].copy_from_slice(&hash.to_le_bytes());
    
    // Add more mixing
    let pid = std::process::id();
    seed[24..28].copy_from_slice(&pid.to_le_bytes());
    
    // Final mix using simple hash
    for i in 0..32 {
        seed[i] = seed[i].wrapping_add(seed[(i + 17) % 32].rotate_left(3));
    }
    
    eprintln!("Generated random seed: {}", hex::encode(&seed));
    seed
}

fn derive_address(pubkey: &[u8; 32]) -> [u8; 20] {
    // Simplified address derivation (not keccak256, just for demo)
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&pubkey[12..32]);
    addr
}
