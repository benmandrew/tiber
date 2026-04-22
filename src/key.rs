//! AES key routines
use crate::sbox;

macro_rules! define_aes_key_type {
    ($name:ident, $key_size:expr, $n_keywords:expr, $n_round_keys:expr) => {
        /// Macro to define AES Key types with compile-time checked round key size and methods.
        pub struct $name {
            /// Original cipher key.
            pub key: [u8; $key_size],
            /// Expanded round keys derived from the cipher key.
            pub round_keys: [u32; 4 * $n_round_keys],
        }
        impl $name {
            /// Creates a new AES key instance and performs key expansion to generate round keys.
            pub fn new(key: [u8; $key_size]) -> Self {
                let round_keys = Self::expand_key(&key);
                Self { key, round_keys }
            }
            fn expand_key(key: &[u8; $key_size]) -> [u32; 4 * $n_round_keys] {
                let mut w = [0u32; 4 * $n_round_keys];
                for i in 0..$n_keywords {
                    w[i] = u32::from_be_bytes([
                        key[i * 4],
                        key[i * 4 + 1],
                        key[i * 4 + 2],
                        key[i * 4 + 3],
                    ]);
                }
                for i in $n_keywords..4 * $n_round_keys {
                    let mut tmp = w[i - 1];
                    if i % $n_keywords == 0 {
                        tmp = sub_word(rot_word(tmp)) ^ ROUND_CONSTANTS[i / $n_keywords - 1];
                    } else if $n_keywords > 6 && i % $n_keywords == 4 {
                        tmp = sub_word(tmp);
                    }
                    w[i] = w[i - $n_keywords] ^ tmp;
                }
                w
            }
        }
    };
}

define_aes_key_type!(Key128, 16, 4, 11);
define_aes_key_type!(Key192, 24, 6, 13);
define_aes_key_type!(Key256, 32, 8, 15);

/// Round constants used in the key expansion process. These are derived from
/// powers of 2 in the finite field GF(2^8).
static ROUND_CONSTANTS: [u32; 10] = [
    0x01 << 24,
    0x02 << 24,
    0x04 << 24,
    0x08 << 24,
    0x10 << 24,
    0x20 << 24,
    0x40 << 24,
    0x80 << 24,
    0x1b << 24,
    0x36 << 24,
];

/// Rotates a 4-byte word left by one byte. For example, 0x01020304 becomes 0x02030401.
fn rot_word(word: u32) -> u32 {
    let top_byte = word >> 24;
    (word << 8) | top_byte
}

/// Applies the S-box to each byte of the word.
fn sub_word(word: u32) -> u32 {
    let b0 = sbox::S_BOX[((word >> 24) & 0xff) as usize] as u32;
    let b1 = sbox::S_BOX[((word >> 16) & 0xff) as usize] as u32;
    let b2 = sbox::S_BOX[((word >> 8) & 0xff) as usize] as u32;
    let b3 = sbox::S_BOX[(word & 0xff) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot_word() {
        // 0x01020304 -> 0x02030401
        assert_eq!(rot_word(0x01020304), 0x02030401);
        // 0x00000000 -> 0x00000000
        assert_eq!(rot_word(0x00000000), 0x00000000);
        // 0xaabbccdd -> 0xbbccddaa
        assert_eq!(rot_word(0xaabbccdd), 0xbbccddaa);
    }

    #[test]
    fn test_sub_word() {
        // For a word of all zeros, should be S_BOX[0] in all bytes
        let s = sbox::S_BOX[0] as u32;
        let expected = (s << 24) | (s << 16) | (s << 8) | s;
        assert_eq!(sub_word(0x00000000), expected);

        // For a word of all 0xff, should be S_BOX[255] in all bytes
        let s = sbox::S_BOX[255] as u32;
        let expected = (s << 24) | (s << 16) | (s << 8) | s;
        assert_eq!(sub_word(0xffffffff), expected);

        // For a word with distinct bytes: 0x01020304
        let expected = ((sbox::S_BOX[0x04] as u32) << 24)
            | ((sbox::S_BOX[0x03] as u32) << 16)
            | ((sbox::S_BOX[0x02] as u32) << 8)
            | (sbox::S_BOX[0x01] as u32);
        assert_eq!(sub_word(0x04030201), expected);
    }

    #[test]
    fn test_expand_key_128bit_zero() {
        // 128-bit zero key
        let key = Key128::new([0u8; 16]);
        let expanded = &key.round_keys;
        let expected_hex = "
            00000000 00000000 00000000 00000000
            62636363 62636363 62636363 62636363
            9b9898c9 f9fbfbaa 9b9898c9 f9fbfbaa
            90973450 696ccffa f2f45733 0b0fac99
            ee06da7b 876a1581 759e42b2 7e91ee2b
            7f2e2b88 f8443e09 8dda7cbb f34b9290
            ec614b85 1425758c 99ff0937 6ab49ba7
            21751787 3550620b acaf6b3c c61bf09b
            0ef90333 3ba96138 97060a04 511dfa9f
            b1d4d8e2 8a7db9da 1d7bb3de 4c664941
            b4ef5bcb 3e92e211 23e951cf 6f8f188e
        "
        .replace('\n', "")
        .replace(' ', "");
        let expected: Vec<u32> = expected_hex
            .as_bytes()
            .chunks(8)
            .map(|chunk| {
                let s = std::str::from_utf8(chunk).unwrap();
                u32::from_str_radix(s, 16).unwrap()
            })
            .collect();
        assert_eq!(
            expanded.len(),
            expected.len(),
            "Expanded key length mismatch"
        );
        for (i, (a, b)) in expanded.iter().zip(expected.iter()).enumerate() {
            assert_eq!(a, b, "Word {}: 0x{:08x} != 0x{:08x}", i, a, b);
        }
    }
}
