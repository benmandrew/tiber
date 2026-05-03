#![no_main]
use libfuzzer_sys::fuzz_target;
use tiber::{decrypt, encrypt, key::Key128};

fuzz_target!(|data: [u8; 32]| {
    let key = Key128::new(data[..16].try_into().unwrap());
    let mut block: [u8; 16] = data[16..].try_into().unwrap();
    let original = block;
    encrypt::encrypt(&mut block, &key);
    decrypt::decrypt(&mut block, &key);
    assert_eq!(block, original);
});
