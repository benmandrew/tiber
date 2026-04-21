//! AES implementation and utilities for encryption and decryption.
#![deny(missing_docs)]

pub mod decrypt;
pub mod encrypt;
pub mod key;
pub mod sbox;

/// Prints a 16-byte array as hex values.
pub fn print_hex_array(arr: &[u8; 16]) {
    for byte in arr.iter() {
        print!("{:02x} ", byte);
    }
    println!();
}
