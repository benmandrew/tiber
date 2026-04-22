//! AES key routines
use crate::sbox;

/// AES key structure and key expansion routines.
pub struct Key<const KEY_SIZE: usize, const N_KEYWORDS: usize, const N_ROUND_KEYS: usize> {
    /// The raw key bytes.
    pub key: [u8; KEY_SIZE],

    pub round_keys: [u32; 4 * N_ROUND_KEYS],
}

/// Type alias for 128-bit AES keys.
pub type Key128 = Key<16, 4, 11>;
/// Type alias for 192-bit AES keys.
pub type Key192 = Key<24, 6, 13>;
/// Type alias for 256-bit AES keys.
pub type Key256 = Key<32, 8, 15>;

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

/// Expands the cipher key into a key schedule.
fn expand_key<const KEY_SIZE: usize, const N_KEYWORDS: usize, const N_ROUND_KEYS: usize>(
    key: &Key<KEY_SIZE, N_KEYWORDS, N_ROUND_KEYS>,
) -> Vec<u32> {
    let mut w: Vec<u32> = Vec::with_capacity(4 * N_ROUND_KEYS);
    for i in 0..N_KEYWORDS {
        w.push(u32::from_be_bytes([
            key.key[i * 4],
            key.key[i * 4 + 1],
            key.key[i * 4 + 2],
            key.key[i * 4 + 3],
        ]));
    }
    for i in N_KEYWORDS..4 * N_ROUND_KEYS {
        let mut tmp = w[i - 1];
        if i % N_KEYWORDS == 0 {
            tmp = sub_word(rot_word(tmp)) ^ ROUND_CONSTANTS[i / N_KEYWORDS - 1];
        } else if N_KEYWORDS > 6 && i % N_KEYWORDS == 4 {
            tmp = sub_word(tmp);
        }
        w.push(w[i - N_KEYWORDS] ^ tmp);
    }
    w
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
        let key_bytes = [0u8; 16];
        let mut key_words = Vec::with_capacity(4);
        for chunk in key_bytes.chunks(4) {
            key_words.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let key = Key128 { key: key_bytes };
        let expanded = expand_key(&key);
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
