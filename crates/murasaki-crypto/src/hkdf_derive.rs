use crate::error::CryptoError;
use crate::symmetric::FileKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const FILE_KEY_INFO: &[u8] = b"murasaki-file-key-v1";
const SHARE_KEY_INFO: &[u8] = b"murasaki-share-key-v1";

pub struct MasterKey(pub(crate) Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct ShareKey(pub(crate) Zeroizing<[u8; 32]>);

impl ShareKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// master key から file key を導出する
pub fn derive_file_key(master_key: &MasterKey, context: &[u8]) -> Result<FileKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(context), master_key.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(FILE_KEY_INFO, okm.as_mut())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(FileKey::new(*okm))
}

/// master key から share key を導出する
pub fn derive_share_key(master_key: &MasterKey, context: &[u8]) -> Result<ShareKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(context), master_key.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(SHARE_KEY_INFO, okm.as_mut())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(ShareKey(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> MasterKey {
        MasterKey::new([0xAAu8; 32])
    }

    #[test]
    fn derive_file_key_is_deterministic() {
        let master = test_master_key();
        let context = b"file-entry-id-001";
        let key1 = derive_file_key(&master, context).unwrap();
        let key2 = derive_file_key(&master, context).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_share_key_is_deterministic() {
        let master = test_master_key();
        let context = b"share-id-001";
        let key1 = derive_share_key(&master, context).unwrap();
        let key2 = derive_share_key(&master, context).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn file_key_and_share_key_differ() {
        let master = test_master_key();
        let context = b"same-context";
        let file_key = derive_file_key(&master, context).unwrap();
        let share_key = derive_share_key(&master, context).unwrap();
        // 同じコンテキストでも info が異なるので鍵は異なる
        assert_ne!(file_key.as_bytes(), share_key.as_bytes());
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let master = test_master_key();
        let key1 = derive_file_key(&master, b"context-1").unwrap();
        let key2 = derive_file_key(&master, b"context-2").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
