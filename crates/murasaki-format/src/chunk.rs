use crate::error::FormatError;
use murasaki_crypto::hash_chunk;

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB 不変条件

/// チャンクデータ（4MB固定サイズ + メタデータ）
pub struct Chunk {
    pub index: u32,
    pub data: Box<[u8; CHUNK_SIZE]>, // 常に4MB（パディング済み）
    pub original_size: usize,        // 実際のデータサイズ
    pub hash: [u8; 32],              // SHA-256（パディング前のデータ）
}

impl Chunk {
    fn new(index: u32, src: &[u8]) -> Self {
        assert!(src.len() <= CHUNK_SIZE);
        let hash = hash_chunk(src);
        // スタックオーバーフローを避けるためヒープ上に確保
        let mut data: Box<[u8; CHUNK_SIZE]> = vec![0u8; CHUNK_SIZE]
            .into_boxed_slice()
            .try_into()
            .expect("CHUNK_SIZE should match");
        data[..src.len()].copy_from_slice(src);
        Chunk {
            index,
            data,
            original_size: src.len(),
            hash,
        }
    }
}

/// ファイルデータを4MB固定チャンクに分割する
pub fn split(data: &[u8]) -> Vec<Chunk> {
    if data.is_empty() {
        return vec![Chunk::new(0, &[])];
    }
    data.chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| Chunk::new(i as u32, chunk))
        .collect()
}

/// チャンク列からファイルデータを再構成する
pub fn merge(chunks: &[Chunk]) -> Result<Vec<u8>, FormatError> {
    // インデックス順にソート済みであることを確認
    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.index as usize != i {
            return Err(FormatError::ParseError(format!(
                "チャンクのインデックスが不正です: expected={i}, found={}",
                chunk.index
            )));
        }
    }

    let mut result = Vec::new();
    for chunk in chunks {
        result.extend_from_slice(&chunk.data[..chunk.original_size]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_empty_produces_one_chunk() {
        let chunks = split(&[]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].original_size, 0);
    }

    #[test]
    fn split_small_data_produces_one_chunk() {
        let data = b"hello world";
        let chunks = split(data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].original_size, data.len());
        assert_eq!(chunks[0].data.len(), CHUNK_SIZE);
    }

    #[test]
    fn split_merge_roundtrip_small() {
        let data: Vec<u8> = (0..100).collect();
        let chunks = split(&data);
        let merged = merge(&chunks).unwrap();
        assert_eq!(merged, data);
    }

    #[test]
    fn split_merge_roundtrip_multi_chunk() {
        // 4MB + 1 バイトのデータ → 2チャンク
        let data: Vec<u8> = vec![0xAAu8; CHUNK_SIZE + 1];
        let chunks = split(&data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].original_size, CHUNK_SIZE);
        assert_eq!(chunks[1].original_size, 1);
        let merged = merge(&chunks).unwrap();
        assert_eq!(merged, data);
    }

    #[test]
    fn chunk_data_is_always_chunk_size() {
        let data: Vec<u8> = vec![0x55u8; 1000];
        let chunks = split(&data);
        for chunk in &chunks {
            assert_eq!(chunk.data.len(), CHUNK_SIZE);
        }
    }

    #[test]
    fn chunk_hash_matches_original_data() {
        let data = b"test data for hashing";
        let chunks = split(data);
        let expected_hash = hash_chunk(data);
        assert_eq!(chunks[0].hash, expected_hash);
    }
}
