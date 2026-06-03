#![no_main]
use libfuzzer_sys::fuzz_target;
use tiber::{cbc, key::Key128};

// Input layout: [0..16] key | [16..32] IV | [32..] plaintext blocks
// Only full 16-byte blocks past the IV are used; trailing bytes are ignored.
fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return; // need key + IV + at least one full block
    }
    let key = Key128::new(data[..16].try_into().unwrap());
    let iv: [u8; 16] = data[16..32].try_into().unwrap();
    let mut blocks: Vec<[u8; 16]> = data[32..]
        .chunks_exact(16)
        .map(|c| c.try_into().unwrap())
        .collect();
    let original = blocks.clone();
    cbc::encrypt_blocks(&mut blocks, &key, &iv);
    cbc::decrypt_blocks(&mut blocks, &key, &iv);
    assert_eq!(blocks, original);
});
