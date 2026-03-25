use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct UuidBytes(pub [u8; 16]);

impl From<Uuid> for UuidBytes {
    fn from(uuid: Uuid) -> Self {
        UuidBytes(*uuid.as_bytes())
    }
}

impl From<UuidBytes> for Uuid {
    fn from(b: UuidBytes) -> Self {
        Uuid::from_bytes(b.0)
    }
}

pub type VaultId = UuidBytes;
pub type ObjectId = UuidBytes;
pub type FileEntryId = UuidBytes;
pub type ManifestRef = UuidBytes;
pub type ShareId = UuidBytes;
pub type ChunkHash = [u8; 32];

/// VOBJ v1: 暗号化チャンクオブジェクト
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultObject {
    pub version: u8,
    pub object_id: ObjectId,
    pub file_entry_id: FileEntryId,
    pub chunk_index: u32,
    pub ciphertext: Vec<u8>, // nonce || ciphertext || tag
    pub hash: ChunkHash,
}

/// VMAN v1: 暗号化Manifest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultManifest {
    pub version: u8,
    pub file_entry_id: FileEntryId,
    pub ciphertext: Vec<u8>, // 暗号化 JSON
}

/// VSHR v1: 共有パッケージ
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultShare {
    pub version: u8,
    pub share_id: ShareId,
    pub encrypted_file_key: Vec<u8>,
    pub manifest_ref: ManifestRef,
}
