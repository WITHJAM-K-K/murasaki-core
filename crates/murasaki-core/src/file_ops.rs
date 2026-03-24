use crate::error::{StorageError, VaultError};
use crate::storage::StorageAdapter;
use crate::vault::{FileEntry, VaultSession};
use murasaki_crypto::{decrypt_chunk, derive_file_key, encrypt_chunk};
use murasaki_format::{
    codec::{decode_vault_manifest, decode_vault_object, encode_vault_manifest, encode_vault_object},
    types::{ChunkHash, FileEntryId, ManifestRef, ObjectId, VaultManifest, VaultObject},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// 復号化されたManifestの内容
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestContent {
    pub file_entry_id: FileEntryId,
    pub filename: String,
    pub mime: String,
    pub original_size: u64,
    pub chunk_list: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub object_id: ObjectId,
    pub chunk_index: u32,
    pub hash: ChunkHash,
}

pub struct FileService<'a, S: StorageAdapter> {
    storage: &'a S,
    session: &'a VaultSession,
}

impl<'a, S: StorageAdapter> FileService<'a, S> {
    pub fn new(session: &'a VaultSession, storage: &'a S) -> Self {
        Self { storage, session }
    }

    /// file_entry_id をコンテキストとして master key から file key を導出する
    fn derive_key_for(&self, file_entry_id: &FileEntryId) -> Result<murasaki_crypto::FileKey, VaultError> {
        Ok(derive_file_key(&self.session.master_key, &file_entry_id.0)?)
    }

    /// ファイルを暗号化して保存する
    pub fn encrypt_file(
        &self,
        data: &[u8],
        name: &str,
        mime: &str,
    ) -> Result<FileEntryId, VaultError> {
        let file_entry_id: FileEntryId = Uuid::new_v4().into();
        let file_key = self.derive_key_for(&file_entry_id)?;

        // チャンクに分割して暗号化
        let chunk_size = 4 * 1024 * 1024;
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(chunk_size).collect()
        };

        let mut chunk_refs = Vec::new();
        let mut object_ids = Vec::new();

        for (index, chunk_data) in chunks.iter().enumerate() {
            let hash = sha256(chunk_data);
            let ciphertext = encrypt_chunk(chunk_data, &file_key)?;
            let object_id: ObjectId = Uuid::new_v4().into();

            let vault_object = VaultObject {
                version: 1,
                object_id,
                file_entry_id,
                chunk_index: index as u32,
                ciphertext,
                hash,
            };
            let encoded = encode_vault_object(&vault_object)?;
            self.storage.put_object(&object_id, &encoded)?;

            chunk_refs.push(ChunkRef {
                object_id,
                chunk_index: index as u32,
                hash,
            });
            object_ids.push(object_id);
        }

        // Manifestを暗号化して保存
        let manifest_ref: ManifestRef = Uuid::new_v4().into();
        let manifest_content = ManifestContent {
            file_entry_id,
            filename: name.to_string(),
            mime: mime.to_string(),
            original_size: data.len() as u64,
            chunk_list: chunk_refs,
        };
        let manifest_json = serde_json::to_vec(&manifest_content)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;
        let encrypted_manifest = encrypt_chunk(&manifest_json, &file_key)?;
        let vault_manifest = VaultManifest {
            version: 1,
            file_entry_id,
            ciphertext: encrypted_manifest,
        };
        let encoded_manifest = encode_vault_manifest(&vault_manifest)?;
        self.storage.put_manifest(&manifest_ref, &encoded_manifest)?;

        // FileEntryを保存（manifest_refへのポインタ）
        let file_entry = FileEntry {
            file_entry_id,
            display_name: name.to_string(),
            mime: mime.to_string(),
            original_size: data.len() as u64,
            manifest_ref,
        };
        let file_entry_json = serde_json::to_vec(&file_entry)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;
        let entry_key = file_entry_id;
        self.storage.put_manifest(&entry_key, &file_entry_json)?;

        Ok(file_entry_id)
    }

    /// ファイルを復号して返す
    pub fn decrypt_file(&self, file_entry_id: &FileEntryId) -> Result<Vec<u8>, VaultError> {
        let file_entry_json = self.storage.get_manifest(file_entry_id)?;
        let file_entry: FileEntry = serde_json::from_slice(&file_entry_json)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;

        let file_key = self.derive_key_for(file_entry_id)?;

        let manifest_data = self.storage.get_manifest(&file_entry.manifest_ref)?;
        let vault_manifest = decode_vault_manifest(&manifest_data)?;

        let manifest_json = decrypt_chunk(&vault_manifest.ciphertext, &file_key)?;
        let manifest: ManifestContent = serde_json::from_slice(&manifest_json)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;

        let mut chunk_data_list: Vec<(u32, Vec<u8>)> = Vec::new();
        for chunk_ref in &manifest.chunk_list {
            let object_data = self.storage.get_object(&chunk_ref.object_id)?;
            let vault_object = decode_vault_object(&object_data)?;

            let decrypted = decrypt_chunk(&vault_object.ciphertext, &file_key)?;

            // 整合性検証（復号後のデータのハッシュを確認）
            let actual_hash = sha256(&decrypted);
            if actual_hash != chunk_ref.hash {
                return Err(VaultError::IntegrityCheckFailed);
            }

            chunk_data_list.push((chunk_ref.chunk_index, decrypted));
        }

        // インデックス順にソート
        chunk_data_list.sort_by_key(|(idx, _)| *idx);

        let mut result = Vec::new();
        for (_, data) in chunk_data_list {
            result.extend_from_slice(&data);
        }
        Ok(result)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorageAdapter;
    use crate::vault::VaultSession;
    use murasaki_crypto::MasterKey;

    fn test_session() -> (InMemoryStorageAdapter, VaultSession) {
        let storage = InMemoryStorageAdapter::new();
        let session = VaultSession {
            vault_id: Uuid::new_v4().into(),
            master_key: MasterKey::new([0xDDu8; 32]),
        };
        (storage, session)
    }

    #[test]
    fn encrypt_decrypt_file_roundtrip() {
        let (storage, session) = test_session();
        let service = FileService::new(&session, &storage);

        let data = b"Hello, murasaki!".to_vec();
        let file_entry_id = service.encrypt_file(&data, "hello.txt", "text/plain").unwrap();
        let recovered = service.decrypt_file(&file_entry_id).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn encrypt_decrypt_multi_chunk_roundtrip() {
        let (storage, session) = test_session();
        let service = FileService::new(&session, &storage);

        // 1025バイト（チャンクサイズ1KBとして複数チャンクになるよう小さな値でテスト）
        let data: Vec<u8> = (0..255u8).cycle().take(1025).collect();
        let file_entry_id = service
            .encrypt_file(&data, "test.bin", "application/octet-stream")
            .unwrap();
        let recovered = service.decrypt_file(&file_entry_id).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn integrity_check_fails_on_tampered_object() {
        let (storage, session) = test_session();
        let service = FileService::new(&session, &storage);

        let data = b"tamper test".to_vec();
        let file_entry_id = service.encrypt_file(&data, "test.txt", "text/plain").unwrap();

        // オブジェクトリストを取得して最初のオブジェクトを改ざん
        let objects = storage.list_objects().unwrap();
        if let Some(obj_id) = objects.first() {
            // 改ざんされたデータを書き込む
            storage.put_object(obj_id, b"corrupted data that is invalid").unwrap();
        }

        let result = service.decrypt_file(&file_entry_id);
        assert!(result.is_err());
    }
}
