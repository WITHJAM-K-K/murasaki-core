use crate::error::StorageError;
use murasaki_format::types::{ManifestRef, ObjectId};
use std::collections::HashMap;
use std::sync::Mutex;

pub trait StorageAdapter {
    fn put_object(&self, id: &ObjectId, data: &[u8]) -> Result<(), StorageError>;
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>, StorageError>;
    fn delete_object(&self, id: &ObjectId) -> Result<(), StorageError>;
    fn list_objects(&self) -> Result<Vec<ObjectId>, StorageError>;
    fn put_manifest(&self, id: &ManifestRef, data: &[u8]) -> Result<(), StorageError>;
    fn get_manifest(&self, id: &ManifestRef) -> Result<Vec<u8>, StorageError>;
    fn delete_manifest(&self, id: &ManifestRef) -> Result<(), StorageError>;
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

impl StorageAdapter for InMemoryStorageAdapter {
    fn put_object(&self, id: &ObjectId, data: &[u8]) -> Result<(), StorageError> {
        self.objects.lock().unwrap().insert(id.0, data.to_vec());
        Ok(())
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>, StorageError> {
        self.objects
            .lock()
            .unwrap()
            .get(&id.0)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn delete_object(&self, id: &ObjectId) -> Result<(), StorageError> {
        self.objects.lock().unwrap().remove(&id.0);
        Ok(())
    }

    fn list_objects(&self) -> Result<Vec<ObjectId>, StorageError> {
        let ids = self
            .objects
            .lock()
            .unwrap()
            .keys()
            .map(|k| murasaki_format::types::UuidBytes(*k))
            .collect();
        Ok(ids)
    }

    fn put_manifest(&self, id: &ManifestRef, data: &[u8]) -> Result<(), StorageError> {
        self.manifests.lock().unwrap().insert(id.0, data.to_vec());
        Ok(())
    }

    fn get_manifest(&self, id: &ManifestRef) -> Result<Vec<u8>, StorageError> {
        self.manifests
            .lock()
            .unwrap()
            .get(&id.0)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn delete_manifest(&self, id: &ManifestRef) -> Result<(), StorageError> {
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

    #[test]
    fn put_and_get_object() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        store.put_object(&id, b"data").unwrap();
        let result = store.get_object(&id).unwrap();
        assert_eq!(result, b"data");
    }

    #[test]
    fn get_nonexistent_object_returns_not_found() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        let result = store.get_object(&id);
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn delete_object() {
        let store = InMemoryStorageAdapter::new();
        let id = test_object_id();
        store.put_object(&id, b"data").unwrap();
        store.delete_object(&id).unwrap();
        assert!(matches!(store.get_object(&id), Err(StorageError::NotFound)));
    }

    #[test]
    fn list_objects() {
        let store = InMemoryStorageAdapter::new();
        let id1 = test_object_id();
        let id2 = test_object_id();
        store.put_object(&id1, b"a").unwrap();
        store.put_object(&id2, b"b").unwrap();
        let list = store.list_objects().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn put_and_get_manifest() {
        let store = InMemoryStorageAdapter::new();
        let id = test_manifest_ref();
        store.put_manifest(&id, b"manifest-data").unwrap();
        let result = store.get_manifest(&id).unwrap();
        assert_eq!(result, b"manifest-data");
    }
}
