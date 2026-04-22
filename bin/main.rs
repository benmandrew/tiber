use tiber::{decrypt, encrypt, key::Key128, util};

fn main() {
    // let mut state = [0u8; 16];
    let mut state: [u8; 16] = "bruhbruhbruhbruh"
        .as_bytes()
        .try_into()
        .expect("Input must be 16 bytes");
    util::print_as_text(&state);
    util::print_hex_array(&state);
    let key = Key128::new([0u8; 16]); // Replace with actual key
    encrypt::encrypt(&mut state, &key);
    util::print_hex_array(&state);
    decrypt::decrypt(&mut state, &key);
    util::print_hex_array(&state);
}
