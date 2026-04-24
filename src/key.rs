//! AES key types and key expansion logic.
//!
//! This module defines the `AesKey` trait, which is implemented by the
//! `Key128`, `Key192`, and `Key256` structs representing AES-128, AES-192, and
//! AES-256 keys respectively. Each key type includes methods for key expansion
//! to generate round keys used in the encryption and decryption processes.
//!
//! - [Wikipedia](https://en.wikipedia.org/wiki/AES_key_schedule)
use crate::sbox;

/// Trait for AES key types (Key128, Key192, Key256)
pub trait AesKey {
    /// Returns the number of round keys, which determines the number of rounds in AES.
    fn n_round_keys(&self) -> usize;
    /// Retrieves the round key for a specific round. Each round key consists of four words from the expanded key schedule.
    fn get_round_key(&self, round: usize) -> [[u8; 4]; 4];
}

impl AesKey for Key128 {
    fn n_round_keys(&self) -> usize {
        self.n_round_keys
    }
    fn get_round_key(&self, round: usize) -> [[u8; 4]; 4] {
        self.get_round_key(round)
    }
}

impl AesKey for Key192 {
    fn n_round_keys(&self) -> usize {
        self.n_round_keys
    }
    fn get_round_key(&self, round: usize) -> [[u8; 4]; 4] {
        self.get_round_key(round)
    }
}

impl AesKey for Key256 {
    fn n_round_keys(&self) -> usize {
        self.n_round_keys
    }
    fn get_round_key(&self, round: usize) -> [[u8; 4]; 4] {
        self.get_round_key(round)
    }
}

macro_rules! define_aes_key_type {
    ($name:ident, $key_size:expr, $n_keywords:expr, $n_round_keys:expr) => {
        #[doc = "AES Key type with compile-time checked round key size and methods."]
        #[doc = "\n- Key size (bytes): `"]
        #[doc = stringify!($key_size)]
        #[doc = "`\n- Key size (32-bit words): `"]
        #[doc = stringify!($n_keywords)]
        #[doc = "`\n- Round keys: `"]
        #[doc = stringify!($n_round_keys)]
        #[doc = "`"]
        pub struct $name {
            /// Original cipher key.
            pub key: [u8; $key_size],
            /// Expanded round keys derived from the cipher key.
            pub round_keys: [[u8; 4]; 4 * $n_round_keys],
            /// Number of round keys, which determines the number of rounds in AES.
            pub n_round_keys: usize,
        }
        impl $name {
            /// Creates a new AES key instance and performs key expansion to generate round keys.
            pub fn new(key: [u8; $key_size]) -> Self {
                let round_keys = Self::expand_key(&key);
                Self {
                    key,
                    round_keys,
                    n_round_keys: $n_round_keys,
                }
            }
            fn expand_key(key: &[u8; $key_size]) -> [[u8; 4]; 4 * $n_round_keys] {
                let mut w = [[0u8; 4]; 4 * $n_round_keys];
                for i in 0..$n_keywords {
                    w[i] = [key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]];
                }
                for i in $n_keywords..4 * $n_round_keys {
                    let mut tmp = w[i - 1];
                    if i % $n_keywords == 0 {
                        tmp = xor_words(
                            sub_word(rot_word(tmp)),
                            ROUND_CONSTANTS[i / $n_keywords - 1],
                        );
                    } else if $n_keywords > 6 && i % $n_keywords == 4 {
                        tmp = sub_word(tmp);
                    }
                    w[i] = xor_words(w[i - $n_keywords], tmp);
                }
                w
            }
            /// Retrieves the round key for a specific round. Each round key
            /// consists of four words from the expanded key schedule.
            pub fn get_round_key(&self, round: usize) -> [[u8; 4]; 4] {
                let start = round * 4;
                [
                    self.round_keys[start],
                    self.round_keys[start + 1],
                    self.round_keys[start + 2],
                    self.round_keys[start + 3],
                ]
            }
        }
    };
}

define_aes_key_type!(Key128, 16, 4, 11);
define_aes_key_type!(Key192, 24, 6, 13);
define_aes_key_type!(Key256, 32, 8, 15);

/// Round constants used in the key expansion process. These are derived from
/// powers of 2 in the finite field GF(2^8).
static ROUND_CONSTANTS: [[u8; 4]; 10] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
];

fn xor_words(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// Rotates a 4-byte word left by one byte. For example, 0x01020304 becomes 0x02030401.
fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

/// Applies the S-box to each byte of the word.
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    let b0 = sbox::S_BOX[word[0] as usize];
    let b1 = sbox::S_BOX[word[1] as usize];
    let b2 = sbox::S_BOX[word[2] as usize];
    let b3 = sbox::S_BOX[word[3] as usize];
    [b0, b1, b2, b3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot_word() {
        // 0x01020304 -> 0x02030401
        assert_eq!(rot_word([0x01, 0x02, 0x03, 0x04]), [0x02, 0x03, 0x04, 0x01]);
        // 0x00000000 -> 0x00000000
        assert_eq!(rot_word([0x00, 0x00, 0x00, 0x00]), [0x00, 0x00, 0x00, 0x00]);
        // 0xaabbccdd -> 0xbbccddaa
        assert_eq!(rot_word([0xaa, 0xbb, 0xcc, 0xdd]), [0xbb, 0xcc, 0xdd, 0xaa]);
    }

    #[test]
    fn test_sub_word() {
        // For a word of all zeros, should be S_BOX[0] in all bytes
        let s = sbox::S_BOX[0];
        assert_eq!(sub_word([0x00, 0x00, 0x00, 0x00]), [s, s, s, s]);
        // For a word of all 0xff, should be S_BOX[255] in all bytes
        let s = sbox::S_BOX[255];
        assert_eq!(sub_word([0xff, 0xff, 0xff, 0xff]), [s, s, s, s]);
        // For a word with distinct bytes: 0x01020304
        assert_eq!(
            sub_word([0x04, 0x03, 0x02, 0x01]),
            [
                sbox::S_BOX[0x04],
                sbox::S_BOX[0x03],
                sbox::S_BOX[0x02],
                sbox::S_BOX[0x01]
            ]
        );
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
        .replace(['\n', ' '], "");
        let expected: Vec<[u8; 4]> = expected_hex
            .as_bytes()
            .chunks(8)
            .map(|chunk| {
                let s = std::str::from_utf8(chunk).unwrap();
                let u32_val = u32::from_str_radix(s, 16).unwrap();
                [
                    (u32_val >> 24) as u8,
                    (u32_val >> 16) as u8,
                    (u32_val >> 8) as u8,
                    u32_val as u8,
                ]
            })
            .collect();
        assert_eq!(
            expanded.len(),
            expected.len(),
            "Expanded key length mismatch"
        );
        for (i, (a, b)) in expanded.iter().zip(expected.iter()).enumerate() {
            assert_eq!(a, b, "Word {}", i);
        }
    }
}
