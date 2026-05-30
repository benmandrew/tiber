//! Cipher Block Chaining (CBC) mode of operation for AES.
//!
//! CBC XORs each plaintext block with the previous ciphertext block before
//! encryption, breaking the pattern-preserving weakness of ECB mode.
//!
//! - **Encryption** must be sequential: block *i* depends on the ciphertext of
//!   block *i-1*.
//! - **Decryption** is parallelisable: every ciphertext block can be AES-decrypted
//!   independently (all are known upfront), after which the XOR with the previous
//!   ciphertext block is applied sequentially.
//!
//! - [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
use crate::key::AesKey;
use crate::{decrypt, encrypt};
use rayon::prelude::*;

/// Encrypt `blocks` in-place using AES-CBC with the given `iv`.
///
/// Each block is XOR'd with the previous ciphertext block (or `iv` for the
/// first block) and then AES-encrypted. Processing is sequential due to the
/// data dependency.
pub fn encrypt_blocks<K: AesKey>(blocks: &mut [[u8; 16]], key: &K, iv: &[u8; 16]) {
    let mut prev = *iv;
    for block in blocks.iter_mut() {
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        encrypt::encrypt(block, key);
        prev = *block;
    }
}

/// Decrypt `blocks` in-place using AES-CBC with the given `iv`.
///
/// AES decryption of each block is independent and runs in parallel. The XOR
/// with the previous ciphertext block is then applied sequentially.
pub fn decrypt_blocks<K: AesKey + Sync>(blocks: &mut [[u8; 16]], key: &K, iv: &[u8; 16]) {
    let ciphertext: Vec<[u8; 16]> = blocks.to_vec();
    blocks.par_iter_mut().for_each(|block| {
        decrypt::decrypt(block, key);
    });
    for (i, block) in blocks.iter_mut().enumerate() {
        let prev = if i == 0 { iv } else { &ciphertext[i - 1] };
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key128;

    fn key_and_iv() -> (Key128, [u8; 16]) {
        let key = Key128::new([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        (key, iv)
    }

    // NIST SP 800-38A, Section F.2.1 — AES-128-CBC
    #[test]
    fn test_nist_sp_800_38a_encrypt() {
        let (key, iv) = key_and_iv();
        let mut blocks = [
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
            [
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51,
            ],
            [
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a,
                0x52, 0xef,
            ],
            [
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c,
                0x37, 0x10,
            ],
        ];
        encrypt_blocks(&mut blocks, &key, &iv);
        assert_eq!(
            blocks,
            [
                [
                    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
                    0xe9, 0x19, 0x7d
                ],
                [
                    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91,
                    0x76, 0x78, 0xb2
                ],
                [
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22,
                    0x22, 0x95, 0x16
                ],
                [
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75,
                    0x86, 0xe1, 0xa7
                ],
            ]
        );
    }

    #[test]
    fn test_nist_sp_800_38a_decrypt() {
        let (key, iv) = key_and_iv();
        let mut blocks = [
            [
                0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
                0x19, 0x7d,
            ],
            [
                0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
                0x78, 0xb2,
            ],
            [
                0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22,
                0x95, 0x16,
            ],
            [
                0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86,
                0xe1, 0xa7,
            ],
        ];
        decrypt_blocks(&mut blocks, &key, &iv);
        assert_eq!(
            blocks,
            [
                [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a
                ],
                [
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                    0xaf, 0x8e, 0x51
                ],
                [
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                    0x0a, 0x52, 0xef
                ],
                [
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                    0x6c, 0x37, 0x10
                ],
            ]
        );
    }

    #[test]
    fn test_roundtrip_single_block() {
        let (key, iv) = key_and_iv();
        let original = [[
            0xdeu8, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ]];
        let mut blocks = original;
        encrypt_blocks(&mut blocks, &key, &iv);
        assert_ne!(blocks, original);
        decrypt_blocks(&mut blocks, &key, &iv);
        assert_eq!(blocks, original);
    }

    #[test]
    fn test_roundtrip_multiple_blocks() {
        let (key, iv) = key_and_iv();
        let original = [
            [0u8; 16],
            [0xffu8; 16],
            [
                0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                0x54, 0x32, 0x10,
            ],
        ];
        let mut blocks = original;
        encrypt_blocks(&mut blocks, &key, &iv);
        assert_ne!(blocks, original);
        decrypt_blocks(&mut blocks, &key, &iv);
        assert_eq!(blocks, original);
    }

    #[test]
    fn test_identical_plaintext_blocks_produce_different_ciphertext() {
        let (key, iv) = key_and_iv();
        let mut blocks = [[0x42u8; 16]; 3];
        encrypt_blocks(&mut blocks, &key, &iv);
        // All three plaintext blocks are identical but ciphertext must differ
        assert_ne!(blocks[0], blocks[1]);
        assert_ne!(blocks[1], blocks[2]);
    }
}
