use crate::chunk::{merge, split, Chunk};
use crate::error::FormatError;

/// ファイルを固定サイズチャンクに分割・再結合するトレイト
pub trait ChunkSplitter {
    fn split(&self, data: &[u8]) -> Vec<Chunk>;
    fn merge(&self, chunks: &[Chunk]) -> Result<Vec<u8>, FormatError>;
}

/// デフォルトの4MBチャンク分割実装
pub struct DefaultChunkSplitter;

impl ChunkSplitter for DefaultChunkSplitter {
    fn split(&self, data: &[u8]) -> Vec<Chunk> {
        split(data)
    }

    fn merge(&self, chunks: &[Chunk]) -> Result<Vec<u8>, FormatError> {
        merge(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_splitter_roundtrip() {
        let splitter = DefaultChunkSplitter;
        let data: Vec<u8> = (0..100).collect();
        let chunks = splitter.split(&data);
        let merged = splitter.merge(&chunks).unwrap();
        assert_eq!(merged, data);
    }
}
