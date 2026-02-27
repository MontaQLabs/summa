use summa::{curve::pedersen_h, Encode};

#[test]
fn print_h_point() {
    let h = pedersen_h();
    let compressed = h.compress();
    println!("PEDERSEN_H_BYTES: {:02x?}", compressed.0);
}
