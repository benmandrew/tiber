//! Convert plaintext to ciphertext using AES encryption steps.
//!
//! This module implements the core AES encryption steps: [`sub_bytes`], [`shift_rows`],
//! [`mix_columns`], and [`add_round_key`]. It also provides the [`encrypt`] function
//! which performs the full encryption process using a given key.
use crate::key::AesKey;
use crate::sbox;

/// In the [`sub_bytes`] step, each byte *a<sub>i,j</sub>* in the state array is replaced with
/// a *S(a<sub>i,j</sub>)* using an 8-bit substitution box.
///
/// Before round 0, the state array is simply the plaintext/input. This
/// operation provides the non-linearity in the cipher. The S-box used is
/// derived from the multiplicative inverse over *GF(2<sup>8</sup>)*, known to have good
/// non-linearity properties. To avoid attacks based on simple algebraic
/// properties, the S-box is constructed by combining the inverse function with
/// an invertible affine transformation. The S-box is also chosen to avoid any
/// fixed points (and so is a derangement), i.e., *S(a<sub>i,j</sub>)* ≠ *a<sub>i,j</sub>*, and also any
/// opposite fixed points, i.e., *S(a<sub>i,j</sub>)* ⊕ *a<sub>i,j</sub>* ≠ FF<sub>16</sub>. While performing the
/// decryption, the `inv_sub_bytes` step (the inverse of `sub_bytes`) is used, which
/// requires first taking the inverse of the affine transformation and then
/// finding the multiplicative inverse.
///
/// - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step)
pub fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = sbox::S_BOX[*byte as usize];
    }
}

/// The `shift_rows` step operates on the rows of the state; it cyclically
/// shifts the bytes in each row by a certain offset.
///
/// For AES, the first row is left unchanged. Each byte of the second row is
/// shifted one to the left. Similarly, the third and fourth rows are shifted
/// by offsets of two and three respectively. In this way, each column of the
/// output state of the `shift_rows` step is composed of bytes from each column
/// of the input state. The importance of this step is to avoid the columns
/// being encrypted independently, in which case AES would degenerate into four
/// independent block ciphers.
///
/// - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step)
pub fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}

/// In the MixColumns step, the four bytes of each column of the state are
/// combined using an invertible linear transformation.
///
/// The MixColumns function takes four bytes as input and outputs four bytes,
/// where each input byte affects all four output bytes. Together with
/// [`shift_rows`], `mix_columns` provides diffusion in the cipher. During this
/// operation, each column is transformed using a fixed matrix. Matrix
/// multiplication is composed of multiplication and addition of the entries.
/// Entries are bytes treated as coefficients of polynomial of order
/// *x<sup>7</sup>*. Addition is simply XOR. Multiplication is modulo
/// irreducible polynomial
/// *x<sup>8</sup> + x<sup>4</sup> + x<sup>3</sup> + x + 1*. If processed bit
/// by bit, then, after shifting, a conditional XOR with *1B<sub>16</sub>*
/// should be performed if the shifted value is larger than *FF<sub>16</sub>*
/// (overflow must be corrected by subtraction of generating polynomial). These
/// are special cases of the usual multiplication in *GF(2<sup>8</sup>)*.
///
/// - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step)
pub fn mix_columns(state: &mut [u8; 16]) {
    // AES MixColumns transformation
    fn xtime(x: u8) -> u8 {
        (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
    }
    for c in 0..4 {
        let i = c * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];
        state[i] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
        state[i + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
        state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
        state[i + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// In the `add_round_key` step, the subkey is combined with the state.
///
/// For each round, a subkey is derived from the main key using Rijndael's key
/// schedule; each subkey is the same size as the state. The subkey is added
/// by combining of the state with the corresponding byte of the subkey using
/// bitwise XOR.
///
/// - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey_Step)
pub fn add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]; 4]) {
    for i in 0..16 {
        state[i] ^= round_key[i / 4][i % 4];
    }
}

/// End-to-end encryption of plaintext to ciphertext.
///
/// The `encrypt` function takes a 16-byte plaintext and a key, and produces a
/// 16-byte ciphertext. The key is expanded into round keys using the key
/// schedule, and the encryption process consists of an initial [`add_round_key`]
/// step, followed by a number of rounds (depending on the key size) of
/// [`sub_bytes`], [`shift_rows`], [`mix_columns`], and [`add_round_key`].
///
/// - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm)
pub fn encrypt<K: AesKey>(state: &mut [u8; 16], key: &K) {
    add_round_key(state, &key.get_round_key(0));
    for round in 1..key.n_round_keys() - 1 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &key.get_round_key(round));
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &key.get_round_key(key.n_round_keys() - 1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::S_BOX;

    #[test]
    fn test_sub_bytes_identity() {
        // S_BOX[0] = 0x63, S_BOX[255] = 0x16
        let mut state = [0u8; 16];
        sub_bytes(&mut state);
        assert_eq!(state, [S_BOX[0]; 16]);

        let mut state = [255u8; 16];
        sub_bytes(&mut state);
        assert_eq!(state, [S_BOX[255]; 16]);
    }

    #[test]
    fn test_sub_bytes_varied() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected: [u8; 16] = [
            S_BOX[0], S_BOX[1], S_BOX[2], S_BOX[3], S_BOX[4], S_BOX[5], S_BOX[6], S_BOX[7],
            S_BOX[8], S_BOX[9], S_BOX[10], S_BOX[11], S_BOX[12], S_BOX[13], S_BOX[14], S_BOX[15],
        ];
        sub_bytes(&mut state);
        assert_eq!(state, expected);
    }

    #[test]
    fn test_shift_rows_identity() {
        let mut state = [0u8; 16];
        shift_rows(&mut state);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_shift_rows_patterned() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        shift_rows(&mut state);
        let expected = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        assert_eq!(state, expected);
    }

    #[test]
    fn test_mix_columns_identity() {
        let mut state = [0u8; 16];
        mix_columns(&mut state);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_mix_columns_patterned() {
        let mut state = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let before = state;
        mix_columns(&mut state);
        assert_ne!(state, before);
    }

    #[test]
    fn test_add_round_key_identity() {
        let mut state = [0u8; 16];
        let round_key = [[0u8; 4]; 4];
        add_round_key(&mut state, &round_key);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_add_round_key_patterned() {
        let mut state = [1u8; 16];
        let round_key = [[2u8; 4]; 4];
        add_round_key(&mut state, &round_key);
        assert_eq!(state, [3u8; 16]);
    }
}
