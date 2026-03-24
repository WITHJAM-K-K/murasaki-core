use crate::{
    decrypt_chunk, derive_password_key, encrypt_chunk, generate_file_key, generate_master_key,
    generate_recovery_seed, recover_master_key, unwrap_key, wrap_key, Argon2Params, CryptoError,
    FileKey, MasterKey, PasswordKey, RecoverySeed, WrappedKey,
};
use crate::hash::hash_chunk;

/// 暗号プリミティブ・鍵階層管理の統合サービストレイト
///
/// このtraitを実装することで、暗号実装をモック等に差し替えることができる。
/// デフォルト実装は各自由関数に委譲する。
pub trait CryptoService {
    fn generate_master_key(&self) -> Result<MasterKey, CryptoError>;
    fn generate_file_key(&self) -> Result<FileKey, CryptoError>;
    fn derive_password_key(&self, password: &[u8], params: &Argon2Params) -> Result<PasswordKey, CryptoError>;
    fn wrap_key(&self, master_key: &MasterKey, password_key: &PasswordKey) -> Result<WrappedKey, CryptoError>;
    fn unwrap_key(&self, wrapped: &WrappedKey, password_key: &PasswordKey) -> Result<MasterKey, CryptoError>;
    fn encrypt_chunk(&self, plaintext: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError>;
    fn decrypt_chunk(&self, ciphertext: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError>;
    fn generate_recovery_seed(&self, master_key: &MasterKey) -> Result<RecoverySeed, CryptoError>;
    fn recover_master_key(&self, seed: &RecoverySeed) -> Result<MasterKey, CryptoError>;
    fn hash_chunk(&self, data: &[u8]) -> [u8; 32];
}

/// デフォルトの暗号実装（各自由関数に委譲）
pub struct DefaultCryptoService;

impl CryptoService for DefaultCryptoService {
    fn generate_master_key(&self) -> Result<MasterKey, CryptoError> {
        generate_master_key()
    }

    fn generate_file_key(&self) -> Result<FileKey, CryptoError> {
        generate_file_key()
    }

    fn derive_password_key(&self, password: &[u8], params: &Argon2Params) -> Result<PasswordKey, CryptoError> {
        derive_password_key(password, params)
    }

    fn wrap_key(&self, master_key: &MasterKey, password_key: &PasswordKey) -> Result<WrappedKey, CryptoError> {
        wrap_key(master_key, password_key)
    }

    fn unwrap_key(&self, wrapped: &WrappedKey, password_key: &PasswordKey) -> Result<MasterKey, CryptoError> {
        unwrap_key(wrapped, password_key)
    }

    fn encrypt_chunk(&self, plaintext: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError> {
        encrypt_chunk(plaintext, key)
    }

    fn decrypt_chunk(&self, ciphertext: &[u8], key: &FileKey) -> Result<Vec<u8>, CryptoError> {
        decrypt_chunk(ciphertext, key)
    }

    fn generate_recovery_seed(&self, master_key: &MasterKey) -> Result<RecoverySeed, CryptoError> {
        generate_recovery_seed(master_key)
    }

    fn recover_master_key(&self, seed: &RecoverySeed) -> Result<MasterKey, CryptoError> {
        recover_master_key(seed)
    }

    fn hash_chunk(&self, data: &[u8]) -> [u8; 32] {
        hash_chunk(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_crypto_service_generate_master_key() {
        let svc = DefaultCryptoService;
        let k1 = svc.generate_master_key().unwrap();
        let k2 = svc.generate_master_key().unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn default_crypto_service_encrypt_decrypt_roundtrip() {
        let svc = DefaultCryptoService;
        let key = svc.generate_file_key().unwrap();
        let plaintext = b"hello trait";
        let ct = svc.encrypt_chunk(plaintext, &key).unwrap();
        let pt = svc.decrypt_chunk(&ct, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn default_crypto_service_hash_chunk_is_deterministic() {
        let svc = DefaultCryptoService;
        let data = b"some data";
        assert_eq!(svc.hash_chunk(data), svc.hash_chunk(data));
    }
}
