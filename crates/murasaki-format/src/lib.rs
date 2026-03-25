pub mod chunk;
pub mod codec;
pub mod error;
pub mod splitter;
pub mod types;

pub use codec::{
    decode_vault_manifest, decode_vault_object, decode_vault_share, encode_vault_manifest,
    encode_vault_object, encode_vault_share,
};
pub use error::FormatError;
pub use splitter::{ChunkSplitter, DefaultChunkSplitter};
pub use types::{
    ChunkHash, FileEntryId, ManifestRef, ObjectId, ShareId, UuidBytes, VaultId, VaultManifest,
    VaultObject, VaultShare,
};

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_vault_object() -> VaultObject {
        VaultObject {
            version: 1,
            object_id: Uuid::new_v4().into(),
            file_entry_id: Uuid::new_v4().into(),
            chunk_index: 0,
            ciphertext: vec![1, 2, 3, 4, 5],
            hash: [0xABu8; 32],
        }
    }

    fn sample_vault_manifest() -> VaultManifest {
        VaultManifest {
            version: 1,
            file_entry_id: Uuid::new_v4().into(),
            ciphertext: vec![10, 20, 30],
        }
    }

    fn sample_vault_share() -> VaultShare {
        VaultShare {
            version: 1,
            share_id: Uuid::new_v4().into(),
            encrypted_file_key: vec![7, 8, 9],
            manifest_ref: Uuid::new_v4().into(),
        }
    }

    #[test]
    fn vobj_encode_decode_roundtrip() {
        let original = sample_vault_object();
        let bytes = encode_vault_object(&original).unwrap();
        let decoded = decode_vault_object(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vman_encode_decode_roundtrip() {
        let original = sample_vault_manifest();
        let bytes = encode_vault_manifest(&original).unwrap();
        let decoded = decode_vault_manifest(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vshr_encode_decode_roundtrip() {
        let original = sample_vault_share();
        let bytes = encode_vault_share(&original).unwrap();
        let decoded = decode_vault_share(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vobj_version_mismatch_returns_error() {
        let mut obj = sample_vault_object();
        obj.version = 2; // 不正なバージョン
        let result = encode_vault_object(&obj);
        assert!(matches!(
            result,
            Err(FormatError::VersionMismatch {
                expected: 1,
                found: 2
            })
        ));
    }

    #[test]
    fn vobj_decode_corrupted_data_returns_error() {
        let corrupted = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = decode_vault_object(&corrupted);
        assert!(matches!(result, Err(FormatError::ParseError(_))));
    }

    #[test]
    fn vman_version_mismatch_returns_error() {
        let mut manifest = sample_vault_manifest();
        manifest.version = 99;
        let result = encode_vault_manifest(&manifest);
        assert!(matches!(
            result,
            Err(FormatError::VersionMismatch {
                expected: 1,
                found: 99
            })
        ));
    }

    #[test]
    fn vshr_version_mismatch_returns_error() {
        let mut share = sample_vault_share();
        share.version = 0;
        let result = encode_vault_share(&share);
        assert!(matches!(
            result,
            Err(FormatError::VersionMismatch {
                expected: 1,
                found: 0
            })
        ));
    }
}
