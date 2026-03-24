use murasaki_crypto::error::CryptoError;
use murasaki_format::error::FormatError;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("ストレージ操作に失敗しました: {0}")]
    OperationFailed(String),
    #[error("オブジェクトが見つかりません")]
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault のアンロックに失敗しました")]
    UnlockFailed,
    #[error("Vault がロックされています")]
    VaultLocked,
    #[error("オブジェクトの整合性検証に失敗しました")]
    IntegrityCheckFailed,
    #[error("ストレージエラー: {0}")]
    Storage(#[from] StorageError),
    #[error("暗号エラー: {0}")]
    Crypto(#[from] CryptoError),
    #[error("フォーマットエラー: {0}")]
    Format(#[from] FormatError),
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("無効なリカバリーシードです")]
    InvalidRecoverySeed,
    #[error("暗号エラー: {0}")]
    Crypto(#[from] CryptoError),
}
