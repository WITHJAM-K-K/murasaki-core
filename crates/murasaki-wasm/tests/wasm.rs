#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use murasaki_wasm::{
    decrypt_chunk_wasm, encrypt_chunk_wasm, generate_master_key_wasm, generate_recovery_seed_wasm,
    recover_master_key_wasm, unwrap_key_wasm, wrap_key_wasm,
};

#[wasm_bindgen_test]
fn test_generate_master_key_returns_32_bytes() {
    let key = generate_master_key_wasm().unwrap();
    assert_eq!(key.len(), 32);
}

#[wasm_bindgen_test]
fn test_generate_master_key_is_random() {
    let key1 = generate_master_key_wasm().unwrap();
    let key2 = generate_master_key_wasm().unwrap();
    assert_ne!(key1, key2);
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_chunk_roundtrip() {
    let file_key = generate_master_key_wasm().unwrap();
    let plaintext = b"hello wasm world".to_vec();
    let ciphertext = encrypt_chunk_wasm(&plaintext, &file_key).unwrap();
    let decrypted = decrypt_chunk_wasm(&ciphertext, &file_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn test_encrypt_chunk_nonce_is_random() {
    let file_key = generate_master_key_wasm().unwrap();
    let plaintext = b"same plaintext".to_vec();
    let ct1 = encrypt_chunk_wasm(&plaintext, &file_key).unwrap();
    let ct2 = encrypt_chunk_wasm(&plaintext, &file_key).unwrap();
    assert_ne!(ct1, ct2);
}

#[wasm_bindgen_test]
fn test_decrypt_with_wrong_key_throws() {
    let key1 = generate_master_key_wasm().unwrap();
    let key2 = generate_master_key_wasm().unwrap();
    let ciphertext = encrypt_chunk_wasm(b"secret", &key1).unwrap();
    let result = decrypt_chunk_wasm(&ciphertext, &key2);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_wrap_unwrap_key_roundtrip() {
    let master_key = generate_master_key_wasm().unwrap();
    let password_key = generate_master_key_wasm().unwrap(); // 32バイトならOK
    let wrapped = wrap_key_wasm(&master_key, &password_key).unwrap();
    let unwrapped = unwrap_key_wasm(&wrapped, &password_key).unwrap();
    assert_eq!(unwrapped, master_key);
}

#[wasm_bindgen_test]
fn test_recovery_seed_roundtrip() {
    let master_key = generate_master_key_wasm().unwrap();
    let mnemonic = generate_recovery_seed_wasm(&master_key).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    let recovered = recover_master_key_wasm(&mnemonic).unwrap();
    assert_eq!(recovered, master_key);
}

#[wasm_bindgen_test]
fn test_invalid_mnemonic_throws() {
    let result = recover_master_key_wasm("invalid mnemonic phrase");
    assert!(result.is_err());
}
