use sha2::{Digest, Sha256};

/// データのSHA-256ハッシュを計算する
pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chunk_is_deterministic() {
        let data = b"test data";
        assert_eq!(hash_chunk(data), hash_chunk(data));
    }

    #[test]
    fn hash_chunk_differs_for_different_data() {
        assert_ne!(hash_chunk(b"foo"), hash_chunk(b"bar"));
    }

    #[test]
    fn hash_chunk_returns_32_bytes() {
        let result = hash_chunk(b"any data");
        assert_eq!(result.len(), 32);
    }
}
