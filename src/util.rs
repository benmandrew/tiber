//! Utility functions for AES implementation.

/// Prints a 16-byte array as hex values.
pub fn print_hex_array(arr: &[u8; 16]) {
    for byte in arr.iter() {
        print!("{:02x} ", byte);
    }
    println!();
}

/// Prints a 16-byte array as ASCII characters.
pub fn print_as_text(arr: &[u8; 16]) {
    for byte in arr.iter() {
        print!("{}", *byte as char);
    }
    println!();
}
