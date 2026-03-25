use crate::error::CryptoError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;

pub struct FileKey(pub(crate) Zeroizing<[u8; 32]>);

impl FileKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 暗号化: nonce(12B) || ciphertext || tag(16B) 形式で返す
pub fn encrypt_chunk(plaintext: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// 復号: nonce(12B) || ciphertext || tag(16B) 形式を受け取り plaintext を返す
pub fn decrypt_chunk(data: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::DecryptionFailed)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FileKey {
        FileKey::new([0x42u8; 32])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello murasaki";
        let ciphertext = encrypt_chunk(plaintext, &key).unwrap();
        let decrypted = decrypt_chunk(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ciphertext_has_nonce_prefix() {
        let key = test_key();
        let plaintext = b"test data";
        let ciphertext = encrypt_chunk(plaintext, &key).unwrap();
        // nonce(12) + ciphertext + tag(16) = 最低28バイト以上
        assert!(ciphertext.len() >= 12 + plaintext.len() + 16);
    }

    #[test]
    fn nonce_is_unique_per_call() {
        let key = test_key();
        let plaintext = b"same plaintext";
        let ct1 = encrypt_chunk(plaintext, &key).unwrap();
        let ct2 = encrypt_chunk(plaintext, &key).unwrap();
        // 同じ平文でも nonce が異なるため暗号文は異なる
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_key_returns_error() {
        let key1 = test_key();
        let key2 = FileKey::new([0x99u8; 32]);
        let plaintext = b"secret";
        let ciphertext = encrypt_chunk(plaintext, &key1).unwrap();
        let result = decrypt_chunk(&ciphertext, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_returns_error() {
        let key = test_key();
        let plaintext = b"integrity check";
        let mut ciphertext = encrypt_chunk(plaintext, &key).unwrap();
        // 暗号文を改ざん
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        let result = decrypt_chunk(&ciphertext, &key);
        assert!(result.is_err());
    }
}
