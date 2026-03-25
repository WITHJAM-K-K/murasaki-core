use crate::error::StorageError;
use async_trait::async_trait;
use murasaki_format::types::{ManifestRef, ObjectId};
use std::collections::HashMap;
use std::sync::Mutex;

#[async_trait]
pub trait StorageAdapter: Send + Sync {
    async fn put_object(&self, id: &ObjectId, data: &[u8]) -> Result<(), StorageError>;
    async fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>, StorageError>;
    async fn delete_object(&self, id: &ObjectId) -> Result<(), StorageError>;
    async fn list_objects(&self) -> Result<Vec<ObjectId>, StorageError>;
    async fn put_manifest(&self, id: &ManifestRef, data: &[u8]) -> Result<(), StorageError>;
    async fn get_manifest(&self, id: &ManifestRef) -> Result<Vec<u8>, StorageError>;
    async fn delete_manifest(&self, id: &ManifestRef) -> Result<(), StorageError>;
}

/// テスト用インメモリStorageAdapter
pub struct InMemoryStorageAdapter {
    objects: Mutex<HashMap<[u8; 16], Vec<u8>>>,
    manifests: Mutex<HashMap<[u8; 16], Vec<u8>>>,
}

impl InMemoryStorageAdapter {
    pub fn new() -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorageAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageAdapter for InMemoryStorageAdapter {
    async fn put_object(&self, id: &ObjectId, data: &[u8]) -> Result<(), StorageError> {
        self.objects.lock().unwrap().insert(id.0, data.to_vec());
        Ok(())
    }

    async fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>, StorageError> {
        self.objects
            .lock()
            .unwrap()
            .get(&id.0)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn delete_object(&self, id: &ObjectId) -> Result<(), StorageError> {
        self.objects.lock().unwrap().remove(&id.0);
        Ok(())
    }

    async fn list_objects(&self) -> Result<Vec<ObjectId>, StorageError> {
        let ids = self
            .objects
            .lock()
            .unwrap()
            .keys()
            .map(|k| murasaki_format::types::UuidBytes(*k))
            .collect();
        Ok(ids)
    }

    async fn put_manifest(&self, id: &ManifestRef, data: &[u8]) -> Result<(), StorageError> {
        self.manifests.lock().unwrap().insert(id.0, data.to_vec());
        Ok(())
    }

    async fn get_manifest(&self, id: &ManifestRef) -> Result<Vec<u8>, StorageError> {
        self.manifests
            .lock()
            .unwrap()
            .get(&id.0)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn delete_manifest(&self, id: &ManifestRef) -> Result<(), StorageError> {
        self.manifests.lock().unwrap().remove(&id.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_object_id() -> ObjectId {
        Uuid::new_v4().into()
    }

    fn test_manifest_ref() -> ManifestRef {
        Uuid::new_v4().into()
    }

    #[tokio::test]
    async fn put_and_get_object() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        store.put_object(&id, b"data").await.unwrap();
        let result = store.get_object(&id).await.unwrap();
        assert_eq!(result, b"data");
    }

    #[tokio::test]
    async fn get_nonexistent_object_returns_not_found() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        let result = store.get_object(&id).await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn delete_object() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        store.put_object(&id, b"data").await.unwrap();
        store.delete_object(&id).await.unwrap();
        assert!(matches!(
            store.get_object(&id).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn list_objects() {
        let store = InMemoryStorageAdapter::new();
        let id1 = test_object_id();
        let id2 = test_object_id();
        store.put_object(&id1, b"a").await.unwrap();
        store.put_object(&id2, b"b").await.unwrap();
        let list = store.list_objects().await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn put_and_get_manifest() {
        let store = InMemoryStorageAdapter::new();
        let id = test_manifest_ref();
        store.put_manifest(&id, b"manifest-data").await.unwrap();
        let result = store.get_manifest(&id).await.unwrap();
        assert_eq!(result, b"manifest-data");
    }
}
