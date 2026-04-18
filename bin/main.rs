use tiber::{print_hex_array, encrypt, decrypt};

fn main() {
    let input = b"Hello, world!";
    let mut state = [0u8; 16];
    state[..input.len()].copy_from_slice(input);
    print_hex_array(&state);
    let round_keys: [[u8; 16]; 11] = [[0; 16]; 11]; // Replace with actual round keys
    encrypt::encrypt(&mut state, &round_keys);
    print_hex_array(&state);
    decrypt::decrypt(&mut state, &round_keys);
    print_hex_array(&state);
}
