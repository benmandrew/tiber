use tiber::{decrypt, encrypt, key::Key128};
use wasm_bindgen::prelude::*;

/// Returns a Vec<[u8; 16]> (as JsValue) of the state after each round of AES encryption.
#[wasm_bindgen]
pub fn encrypt_rounds(plaintext: &[u8], key: &[u8]) -> JsValue {
    let mut state = [0u8; 16];
    state[..plaintext.len()].copy_from_slice(plaintext);
    let key = Key128::new(key.try_into().expect("Key must be 16 bytes"));
    let mut rounds = vec![];
    // Initial AddRoundKey
    let round0 = key.get_round_key(0);
    encrypt::add_round_key(&mut state, &round0);
    rounds.push(state);
    // 9 main rounds
    for round in 1..10 {
        encrypt::sub_bytes(&mut state);
        encrypt::shift_rows(&mut state);
        encrypt::mix_columns(&mut state);
        let round_key = key.get_round_key(round);
        encrypt::add_round_key(&mut state, &round_key);
        rounds.push(state);
    }
    // Final round (no mix_columns)
    encrypt::sub_bytes(&mut state);
    encrypt::shift_rows(&mut state);
    let round_key = key.get_round_key(10);
    encrypt::add_round_key(&mut state, &round_key);
    rounds.push(state);
    serde_wasm_bindgen::to_value(&rounds).unwrap()
}

/// Returns a Vec<[u8; 16]> (as JsValue) of the state after each round of AES decryption.
#[wasm_bindgen]
pub fn decrypt_rounds(ciphertext: &[u8], key: &[u8]) -> JsValue {
    let mut state = [0u8; 16];
    state[..ciphertext.len()].copy_from_slice(ciphertext);
    let key = Key128::new(key.try_into().expect("Key must be 16 bytes"));
    let mut rounds = vec![];
    // Initial AddRoundKey (last round key)
    let round10 = key.get_round_key(10);
    decrypt::inv_add_round_key(&mut state, &round10);
    rounds.push(state);
    // 9 main rounds
    for round in (1..10).rev() {
        decrypt::inv_shift_rows(&mut state);
        decrypt::inv_sub_bytes(&mut state);
        let round_key = key.get_round_key(round);
        decrypt::inv_add_round_key(&mut state, &round_key);
        decrypt::inv_mix_columns(&mut state);
        rounds.push(state);
    }
    // Final round (no inv_mix_columns)
    decrypt::inv_shift_rows(&mut state);
    decrypt::inv_sub_bytes(&mut state);
    let round_key = key.get_round_key(0);
    decrypt::inv_add_round_key(&mut state, &round_key);
    rounds.push(state);
    serde_wasm_bindgen::to_value(&rounds).unwrap()
}
