use crate::sbox;

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = sbox::INV_S_BOX[state[i] as usize];
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let temp = state.clone();
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

fn inv_mix_columns(state: &mut [u8; 16]) {
    let temp = state.clone();
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

fn inv_add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

pub fn decrypt(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    inv_add_round_key(state, &round_keys[10]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for round in (1..10).rev() {
        inv_add_round_key(state, &round_keys[round]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    inv_add_round_key(state, &round_keys[0]);
}
