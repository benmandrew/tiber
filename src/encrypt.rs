use crate::sbox;

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = sbox::S_BOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
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

fn mix_columns(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0] ^ temp[4] ^ temp[8] ^ temp[12];
    state[1] = temp[1] ^ temp[5] ^ temp[9] ^ temp[13];
    state[2] = temp[2] ^ temp[6] ^ temp[10] ^ temp[14];
    state[3] = temp[3] ^ temp[7] ^ temp[11] ^ temp[15];
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

pub fn encrypt(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    add_round_key(state, &round_keys[0]);
    for round_key in round_keys.iter().skip(1) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[10]);
}
