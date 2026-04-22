//! AES decryption routines.
use crate::key::Key128;
use crate::sbox;

/// Applies the inverse S-box to each byte of the state.
pub fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = sbox::INV_S_BOX[*byte as usize];
    }
}

/// [`inv_shift_rows`] is the inverse of the [`shift_rows`](crate::encrypt::shift_rows) function.
pub fn inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[1] = temp[13];
    state[2] = temp[10];
    state[3] = temp[7];
    state[4] = temp[4];
    state[5] = temp[1];
    state[6] = temp[14];
    state[7] = temp[11];
    state[8] = temp[8];
    state[9] = temp[5];
    state[10] = temp[2];
    state[11] = temp[15];
    state[12] = temp[12];
    state[13] = temp[9];
    state[14] = temp[6];
    state[15] = temp[3];
}

/// Multiplies two bytes in the finite field GF(2^8) using the irreducible
/// polynomial x^8 + x^4 + x^3 + x + 1.
fn mul(x: u8, y: u8) -> u8 {
    let mut r = 0u8;
    let mut a = x;
    let mut b = y;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    r
}

/// [`inv_mix_columns`] is the inverse of the [`mix_columns`](crate::encrypt::mix_columns) function.
pub fn inv_mix_columns(state: &mut [u8; 16]) {
    let temp = *state;
    for c in 0..4 {
        let s0 = temp[c * 4];
        let s1 = temp[c * 4 + 1];
        let s2 = temp[c * 4 + 2];
        let s3 = temp[c * 4 + 3];
        state[c * 4] = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09);
        state[c * 4 + 1] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d);
        state[c * 4 + 2] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b);
        state[c * 4 + 3] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e);
    }
}

/// Transformation of the state in which a round key is combined with the
/// state by applying the bitwise XOR operation. Each round key consists of
/// four words from the key schedule.
pub fn inv_add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]; 4]) {
    for i in 0..16 {
        state[i] ^= round_key[i / 4][i % 4];
    }
}

/// AES decryption routine.
pub fn decrypt(state: &mut [u8; 16], key: &Key128) {
    inv_add_round_key(state, &key.get_round_key(key.n_round_keys - 1));
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for round in (1..key.n_round_keys - 1).rev() {
        inv_add_round_key(state, &key.get_round_key(round));
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    inv_add_round_key(state, &key.get_round_key(0));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::INV_S_BOX;

    #[test]
    fn test_inv_sub_bytes_identity() {
        let mut state = [0u8; 16];
        inv_sub_bytes(&mut state);
        assert_eq!(state, [INV_S_BOX[0]; 16]);

        let mut state = [255u8; 16];
        inv_sub_bytes(&mut state);
        assert_eq!(state, [INV_S_BOX[255]; 16]);
    }

    #[test]
    fn test_inv_sub_bytes_varied() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected: [u8; 16] = [
            INV_S_BOX[0],
            INV_S_BOX[1],
            INV_S_BOX[2],
            INV_S_BOX[3],
            INV_S_BOX[4],
            INV_S_BOX[5],
            INV_S_BOX[6],
            INV_S_BOX[7],
            INV_S_BOX[8],
            INV_S_BOX[9],
            INV_S_BOX[10],
            INV_S_BOX[11],
            INV_S_BOX[12],
            INV_S_BOX[13],
            INV_S_BOX[14],
            INV_S_BOX[15],
        ];
        inv_sub_bytes(&mut state);
        assert_eq!(state, expected);
    }

    #[test]
    fn test_inv_shift_rows_identity() {
        let mut state = [0u8; 16];
        inv_shift_rows(&mut state);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_inv_shift_rows_patterned() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        inv_shift_rows(&mut state);
        let expected = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
        assert_eq!(state, expected);
    }

    #[test]
    fn test_inv_mix_columns_identity() {
        let mut state = [0u8; 16];
        inv_mix_columns(&mut state);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_inv_mix_columns_patterned() {
        let mut state = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let before = state;
        inv_mix_columns(&mut state);
        assert_ne!(state, before);
    }

    #[test]
    fn test_inv_add_round_key_identity() {
        let mut state = [0u8; 16];
        let round_key = [[0u8; 4]; 4];
        inv_add_round_key(&mut state, &round_key);
        assert_eq!(state, [0u8; 16]);
    }

    #[test]
    fn test_inv_add_round_key_patterned() {
        let mut state = [1u8; 16];
        let round_key = [[2u8; 4]; 4];
        inv_add_round_key(&mut state, &round_key);
        assert_eq!(state, [3u8; 16]);
    }
}
