#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("暗号化に失敗しました")]
    EncryptionFailed,
    #[error("復号に失敗しました: 鍵が無効か、データが破損しています")]
    DecryptionFailed,
    #[error("鍵のアンラップに失敗しました")]
    UnwrapFailed,
    #[error("無効なリカバリーシードです")]
    InvalidRecoverySeed,
    #[error("乱数生成に失敗しました")]
    RngError,
}
