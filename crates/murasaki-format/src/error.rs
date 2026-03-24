#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("バージョンが一致しません: expected={expected}, found={found}")]
    VersionMismatch { expected: u8, found: u8 },
    #[error("フォーマットのパースに失敗しました: {0}")]
    ParseError(String),
}
