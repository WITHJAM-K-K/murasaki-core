use crate::error::{StorageError, VaultError};
use crate::storage::StorageAdapter;
use murasaki_crypto::{
    derive_password_key, generate_master_key, generate_recovery_seed,
    unwrap_key, wrap_key, Argon2Params, MasterKey, RecoverySeed, WrappedKey,
};
use murasaki_format::types::{FileEntryId, ManifestRef, UuidBytes, VaultId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub vault_id: VaultId,
    pub wrapped_master_key: Vec<u8>,
    pub argon_params: StoredArgon2Params,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredArgon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 32],
}

impl From<&StoredArgon2Params> for Argon2Params {
    fn from(p: &StoredArgon2Params) -> Self {
        Argon2Params {
            m_cost: p.m_cost,
            t_cost: p.t_cost,
            p_cost: p.p_cost,
            salt: p.salt,
        }
    }
}

pub struct VaultSession {
    pub vault_id: VaultId,
    pub master_key: MasterKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub file_entry_id: FileEntryId,
    pub display_name: String,
    pub mime: String,
    pub original_size: u64,
    pub manifest_ref: ManifestRef,
}

pub struct VaultManager<S: StorageAdapter> {
    storage: S,
}

const VAULT_METADATA_KEY: &str = "vault_metadata";

impl<S: StorageAdapter> VaultManager<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub async fn create_vault(
        &self,
        password: &[u8],
    ) -> Result<(VaultMetadata, RecoverySeed), VaultError> {
        let argon_params = default_argon2_params_with_random_salt();
        let master_key = generate_master_key()?;
        let password_key = derive_password_key(password, &(&argon_params).into())?;
        let wrapped = wrap_key(&master_key, &password_key)?;
        let recovery_seed = generate_recovery_seed(&master_key)?;

        let metadata = VaultMetadata {
            vault_id: Uuid::new_v4().into(),
            wrapped_master_key: wrapped.0,
            argon_params,
        };
        let serialized = serde_json::to_vec(&metadata)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;
        let meta_id = string_to_uuid_bytes(VAULT_METADATA_KEY);
        self.storage.put_manifest(&meta_id, &serialized).await?;

        Ok((metadata, recovery_seed))
    }

    pub async fn unlock(&self, password: &[u8]) -> Result<VaultSession, VaultError> {
        let meta_id = string_to_uuid_bytes(VAULT_METADATA_KEY);
        let data = self.storage.get_manifest(&meta_id).await?;
        let metadata: VaultMetadata = serde_json::from_slice(&data)
            .map_err(|e| VaultError::Storage(StorageError::OperationFailed(e.to_string())))?;

        let argon_params: Argon2Params = (&metadata.argon_params).into();
        let password_key = derive_password_key(password, &argon_params)
            .map_err(|_| VaultError::UnlockFailed)?;
        let wrapped = WrappedKey(metadata.wrapped_master_key);
        let master_key =
            unwrap_key(&wrapped, &password_key).map_err(|_| VaultError::UnlockFailed)?;

        Ok(VaultSession {
            vault_id: metadata.vault_id,
            master_key,
        })
    }
}

fn default_argon2_params_with_random_salt() -> StoredArgon2Params {
    let salt_key = generate_master_key().unwrap_or_else(|_| MasterKey::new([0u8; 32]));
    StoredArgon2Params {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 1,
        salt: *salt_key.as_bytes(),
    }
}

fn string_to_uuid_bytes(s: &str) -> UuidBytes {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&result[..16]);
    UuidBytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorageAdapter;

    #[tokio::test]
    async fn create_vault_returns_metadata_and_seed() {
        let storage = InMemoryStorageAdapter::new();
        let vault = VaultManager::new(storage);
        let (metadata, seed) = vault.create_vault(b"my-password").await.unwrap();
        assert!(!metadata.wrapped_master_key.is_empty());
        assert_eq!(seed.as_str().split_whitespace().count(), 24);
    }

    #[tokio::test]
    async fn unlock_with_correct_password_returns_session() {
        let storage = InMemoryStorageAdapter::new();
        let vault = VaultManager::new(storage);
        vault.create_vault(b"my-password").await.unwrap();
        let session = vault.unlock(b"my-password").await.unwrap();
        assert!(!session.master_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn unlock_with_wrong_password_returns_error() {
        let storage = InMemoryStorageAdapter::new();
        let vault = VaultManager::new(storage);
        vault.create_vault(b"my-password").await.unwrap();
        let result = vault.unlock(b"wrong-password").await;
        assert!(matches!(result, Err(VaultError::UnlockFailed)));
    }
}
