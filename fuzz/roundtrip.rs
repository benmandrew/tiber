use afl::fuzz;
use tiber::{decrypt, encrypt, key::Key128};

fn main() {
    fuzz!(|data: &[u8]| {
        if data.len() < 16 {
            return;
        }
        let key = Key128::new(data[..16].try_into().unwrap());
        let mut block = [b' '; 16];
        let n = (data.len() - 16).min(16);
        block[..n].copy_from_slice(&data[16..16 + n]);
        let original = block;
        encrypt::encrypt(&mut block, &key);
        decrypt::decrypt(&mut block, &key);
        assert_eq!(block, original);
    });
}
