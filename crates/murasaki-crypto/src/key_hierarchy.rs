use crate::error::CryptoError;
use crate::hkdf_derive::MasterKey;
use crate::kdf::PasswordKey;
use crate::symmetric::FileKey;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;

pub struct WrappedKey(pub Vec<u8>); // nonce(12) || ciphertext || tag(16)

impl WrappedKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// OsRng から 32 バイトの master key を生成する
pub fn generate_master_key() -> Result<MasterKey, CryptoError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(bytes.as_mut());
    Ok(MasterKey::new(*bytes))
}

/// OsRng から 32 バイトの file key を生成する
pub fn generate_file_key() -> Result<FileKey, CryptoError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(bytes.as_mut());
    Ok(FileKey::new(*bytes))
}

/// master key を password key で AES-256-GCM ラップする
pub fn wrap_key(
    master_key: &MasterKey,
    password_key: &PasswordKey,
) -> Result<WrappedKey, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(password_key.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, master_key.as_bytes().as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(WrappedKey(output))
}

/// ラップ済み master key をアンラップする
pub fn unwrap_key(
    wrapped: &WrappedKey,
    password_key: &PasswordKey,
) -> Result<MasterKey, CryptoError> {
    let data = wrapped.as_bytes();
    if data.len() < NONCE_SIZE {
        return Err(CryptoError::UnwrapFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(password_key.as_bytes())
        .map_err(|_| CryptoError::UnwrapFailed)?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::UnwrapFailed)?;

    if plaintext.len() != 32 {
        return Err(CryptoError::UnwrapFailed);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plaintext);
    Ok(MasterKey::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_password_key, Argon2Params};

    fn test_password_key() -> PasswordKey {
        let params = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            salt: [0x33u8; 32],
        };
        derive_password_key(b"test-password", &params).unwrap()
    }

    #[test]
    fn generate_master_key_returns_32_bytes() {
        let key = generate_master_key().unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_master_key_is_unique() {
        let key1 = generate_master_key().unwrap();
        let key2 = generate_master_key().unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn generate_file_key_is_unique() {
        let key1 = generate_file_key().unwrap();
        let key2 = generate_file_key().unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let master_key = generate_master_key().unwrap();
        let password_key = test_password_key();
        let original_bytes = *master_key.as_bytes();

        let wrapped = wrap_key(&master_key, &password_key).unwrap();
        let recovered = unwrap_key(&wrapped, &password_key).unwrap();

        assert_eq!(recovered.as_bytes(), &original_bytes);
    }

    #[test]
    fn unwrap_with_wrong_key_returns_error() {
        let master_key = generate_master_key().unwrap();
        let password_key = test_password_key();
        let wrong_key = PasswordKey(zeroize::Zeroizing::new([0x99u8; 32]));

        let wrapped = wrap_key(&master_key, &password_key).unwrap();
        let result = unwrap_key(&wrapped, &wrong_key);

        assert!(matches!(result, Err(CryptoError::UnwrapFailed)));
    }
}
