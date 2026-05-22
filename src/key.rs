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

    fn parse_hex_words(s: &str) -> Vec<[u8; 4]> {
        s.replace(['\n', ' '], "")
            .as_bytes()
            .chunks(8)
            .map(|chunk| {
                let s = std::str::from_utf8(chunk).unwrap();
                let u = u32::from_str_radix(s, 16).unwrap();
                [(u >> 24) as u8, (u >> 16) as u8, (u >> 8) as u8, u as u8]
            })
            .collect()
    }

    fn assert_round_keys_eq(actual: &[[u8; 4]], expected: &[[u8; 4]]) {
        assert_eq!(actual.len(), expected.len(), "word count mismatch");
        for (i, (a, b)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(a, b, "word {i}");
        }
    }

    #[test]
    fn test_expand_key_128bit_zero() {
        // NIST FIPS 197, Appendix A.1
        let key = Key128::new([0u8; 16]);
        assert_round_keys_eq(
            &key.round_keys,
            &parse_hex_words(
                "00000000 00000000 00000000 00000000
                 62636363 62636363 62636363 62636363
                 9b9898c9 f9fbfbaa 9b9898c9 f9fbfbaa
                 90973450 696ccffa f2f45733 0b0fac99
                 ee06da7b 876a1581 759e42b2 7e91ee2b
                 7f2e2b88 f8443e09 8dda7cbb f34b9290
                 ec614b85 1425758c 99ff0937 6ab49ba7
                 21751787 3550620b acaf6b3c c61bf09b
                 0ef90333 3ba96138 97060a04 511dfa9f
                 b1d4d8e2 8a7db9da 1d7bb3de 4c664941
                 b4ef5bcb 3e92e211 23e951cf 6f8f188e",
            ),
        );
    }

    #[test]
    fn test_expand_key_192bit_nist() {
        // NIST FIPS 197, Appendix A.2
        let key = Key192::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ]);
        assert_round_keys_eq(
            &key.round_keys,
            &parse_hex_words(
                "00010203 04050607 08090a0b 0c0d0e0f
                 10111213 14151617 5846f2f9 5c43f4fe
                 544afef5 5847f0fa 4856e2e9 5c43f4fe
                 40f949b3 1cbabd4d 48f043b8 10b7b342
                 58e151ab 04a2a555 7effb541 6245080c
                 2ab54bb4 3a02f8f6 62e3a95d 66410c08
                 f5018572 97448d7e bdf1c6ca 87f33e3c
                 e5109761 83519b69 34157c9e a351f1e0
                 1ea0372a 99530916 7c439e77 ff12051e
                 dd7e0e88 7e2fff68 608fc842 f9dcc154
                 859f5f23 7a8d5a3d c0c02952 beefd63a
                 de601e78 27bcdf2c a223800f d8aeda32
                 a4970a33 1a78dc09 c418c271 e3a41d5d",
            ),
        );
    }

    #[test]
    fn test_expand_key_256bit_nist() {
        // NIST FIPS 197, Appendix A.3
        let key = Key256::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        assert_round_keys_eq(
            &key.round_keys,
            &parse_hex_words(
                "00010203 04050607 08090a0b 0c0d0e0f
                 10111213 14151617 18191a1b 1c1d1e1f
                 a573c29f a176c498 a97fce93 a572c09c
                 1651a8cd 0244beda 1a5da4c1 0640bade
                 ae87dff0 0ff11b68 a68ed5fb 03fc1567
                 6de1f148 6fa54f92 75f8eb53 73b8518d
                 c656827f c9a79917 6f294cec 6cd5598b
                 3de23a75 524775e7 27bf9eb4 5407cf39
                 0bdc905f c27b0948 ad5245a4 c1871c2f
                 45f5a660 17b2d387 300d4d33 640a820a
                 7ccff71c beb4fe54 13e6bbf0 d261a7df
                 f01afafe e7a82979 d7a5644a b3afe640
                 2541fe71 9bf50025 8813bbd5 5a721c0a
                 4e5a6699 a9f24fe0 7e572baa cdf8cdea
                 24fc79cc bf0979e9 371ac23c 6d68de36",
            ),
        );
    }
}
