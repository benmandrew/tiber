//! AES encryption routines.
use crate::key::Key128;
use crate::sbox;

/// Applies the S-box to each byte of the state.
pub fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = sbox::S_BOX[*byte as usize];
    }
}

/// Invertible, non-linear transformation of the state in which a substitution
/// table, called an S-box, is applied independently to each byte in the state.
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

/// Transformation of the state that multiplies each of the four columns of
/// the state by a single fixed matrix.
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

/// Transformation of the state in which a round key is combined with the
/// state by applying the bitwise XOR operation. Each round key consists of
/// four words from the key schedule.
pub fn add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]; 4]) {
    for i in 0..16 {
        state[i] ^= round_key[i / 4][i % 4];
    }
}

/// AES encryption routine.
pub fn encrypt(state: &mut [u8; 16], key: &Key128) {
    add_round_key(state, &key.get_round_key(0));
    for round in 1..key.n_round_keys - 1 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &key.get_round_key(round));
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &key.get_round_key(key.n_round_keys - 1));
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
