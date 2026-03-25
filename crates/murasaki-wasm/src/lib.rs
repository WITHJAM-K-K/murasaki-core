use murasaki_crypto::{
    decrypt_chunk, derive_password_key, encrypt_chunk, generate_master_key, generate_recovery_seed,
    recover_master_key, unwrap_key, wrap_key, Argon2Params, FileKey, MasterKey, PasswordKey,
    RecoverySeed, WrappedKey,
};
use wasm_bindgen::prelude::*;

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// 32バイトのmaster keyをランダム生成する
#[wasm_bindgen]
pub fn generate_master_key_wasm() -> Result<Vec<u8>, JsValue> {
    let key = generate_master_key().map_err(to_js_err)?;
    Ok(key.as_bytes().to_vec())
}

/// パスワードからpassword keyを導出する
/// params: [m_cost(4B LE), t_cost(4B LE), p_cost(4B LE), salt(32B)] = 44バイト
#[wasm_bindgen]
pub fn derive_password_key_wasm(password: &[u8], params: &[u8]) -> Result<Vec<u8>, JsValue> {
    if params.len() != 44 {
        return Err(JsValue::from_str("paramsは44バイト必要です"));
    }
    let m_cost = u32::from_le_bytes(params[0..4].try_into().unwrap());
    let t_cost = u32::from_le_bytes(params[4..8].try_into().unwrap());
    let p_cost = u32::from_le_bytes(params[8..12].try_into().unwrap());
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&params[12..44]);

    let argon_params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
        salt,
    };
    let key = derive_password_key(password, &argon_params).map_err(to_js_err)?;
    Ok(key.as_bytes().to_vec())
}

/// master keyをpassword keyでラップする
/// master_key: 32バイト, password_key: 32バイト → nonce||ciphertext||tag
#[wasm_bindgen]
pub fn wrap_key_wasm(master_key: &[u8], password_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mk = bytes_to_master_key(master_key)?;
    let pk = bytes_to_password_key(password_key)?;
    let wrapped = wrap_key(&mk, &pk).map_err(to_js_err)?;
    Ok(wrapped.0)
}

/// ラップ済みmaster keyをアンラップする
#[wasm_bindgen]
pub fn unwrap_key_wasm(wrapped: &[u8], password_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pk = bytes_to_password_key(password_key)?;
    let wk = WrappedKey(wrapped.to_vec());
    let mk = unwrap_key(&wk, &pk).map_err(to_js_err)?;
    Ok(mk.as_bytes().to_vec())
}

/// チャンクを暗号化する: nonce(12B)||ciphertext||tag(16B)
#[wasm_bindgen]
pub fn encrypt_chunk_wasm(plaintext: &[u8], file_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let fk = bytes_to_file_key(file_key)?;
    encrypt_chunk(plaintext, &fk).map_err(to_js_err)
}

/// チャンクを復号する
#[wasm_bindgen]
pub fn decrypt_chunk_wasm(ciphertext: &[u8], file_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let fk = bytes_to_file_key(file_key)?;
    decrypt_chunk(ciphertext, &fk).map_err(to_js_err)
}

/// Manifestを暗号化する（チャンクと同じ対称暗号）
#[wasm_bindgen]
pub fn encrypt_manifest_wasm(plaintext: &[u8], file_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    encrypt_chunk_wasm(plaintext, file_key)
}

/// Manifestを復号する
#[wasm_bindgen]
pub fn decrypt_manifest_wasm(ciphertext: &[u8], file_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    decrypt_chunk_wasm(ciphertext, file_key)
}

/// master keyから24ワードのrecovery seedを生成する
#[wasm_bindgen]
pub fn generate_recovery_seed_wasm(master_key: &[u8]) -> Result<String, JsValue> {
    let mk = bytes_to_master_key(master_key)?;
    let seed = generate_recovery_seed(&mk).map_err(to_js_err)?;
    Ok(seed.as_str().to_string())
}

/// mnemonicからmaster keyを復元する
#[wasm_bindgen]
pub fn recover_master_key_wasm(mnemonic: &str) -> Result<Vec<u8>, JsValue> {
    let seed = RecoverySeed::from_phrase(mnemonic).map_err(to_js_err)?;
    let mk = recover_master_key(&seed).map_err(to_js_err)?;
    Ok(mk.as_bytes().to_vec())
}

// --- ヘルパー ---

fn bytes_to_master_key(bytes: &[u8]) -> Result<MasterKey, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("master keyは32バイト必要です"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(MasterKey::new(arr))
}

fn bytes_to_password_key(bytes: &[u8]) -> Result<PasswordKey, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("password keyは32バイト必要です"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(PasswordKey(zeroize::Zeroizing::new(arr)))
}

fn bytes_to_file_key(bytes: &[u8]) -> Result<FileKey, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("file keyは32バイト必要です"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(FileKey::new(arr))
}
