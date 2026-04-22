use tiber::{decrypt, encrypt, key::Key128, print_hex_array};

fn main() {
    let input = b"Hello, world!";
    let mut state = [0u8; 16];
    state[..input.len()].copy_from_slice(input);
    print_hex_array(&state);
    let key = Key128::new([0u8; 16]); // Replace with actual key
    encrypt::encrypt(&mut state, &key.round_keys);
    print_hex_array(&state);
    decrypt::decrypt(&mut state, &key.round_keys);
    print_hex_array(&state);
}
