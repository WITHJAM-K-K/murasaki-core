use murasaki_core::{
    file_ops::FileService,
    recovery::{DefaultRecoveryService, RecoveryService},
    storage::InMemoryStorageAdapter,
    vault::VaultManager,
};
use murasaki_crypto::{generate_master_key, generate_recovery_seed};

/// ファイル暗号化 → 保存 → 復号のラウンドトリップ
#[test]
fn file_encrypt_decrypt_lifecycle() {
    let vault_mgr = VaultManager::new(InMemoryStorageAdapter::new());
    vault_mgr.create_vault(b"lifecycle-pass").unwrap();
    let session = vault_mgr.unlock(b"lifecycle-pass").unwrap();

    let file_storage = InMemoryStorageAdapter::new();
    let service = FileService::new(&session, &file_storage);

    let original_data = b"Hello, zero-knowledge world!".to_vec();
    let file_entry_id = service
        .encrypt_file(&original_data, "test.txt", "text/plain")
        .unwrap();
    let recovered = service.decrypt_file(&file_entry_id).unwrap();
    assert_eq!(recovered, original_data);
}

/// Vault 作成 → アンロック → ファイル操作 → 不正パスワードでアンロック失敗
#[test]
fn vault_create_lock_unlock_file_ops() {
    let vault_mgr = VaultManager::new(InMemoryStorageAdapter::new());

    let (_, _recovery_seed) = vault_mgr.create_vault(b"secure-password").unwrap();

    let session = vault_mgr.unlock(b"secure-password").unwrap();

    let file_storage = InMemoryStorageAdapter::new();
    let service = FileService::new(&session, &file_storage);
    let data = b"confidential content".to_vec();
    let file_id = service.encrypt_file(&data, "secret.txt", "text/plain").unwrap();
    let decrypted = service.decrypt_file(&file_id).unwrap();
    assert_eq!(decrypted, data);

    let result = vault_mgr.unlock(b"wrong-password");
    assert!(result.is_err());
}

/// recovery seed 生成 → master key 復元
#[test]
fn recovery_seed_generate_and_restore() {
    let master_key = generate_master_key().unwrap();
    let original_bytes = *master_key.as_bytes();

    let seed = generate_recovery_seed(&master_key).unwrap();
    let mnemonic = seed.as_str().to_string();

    assert_eq!(mnemonic.split_whitespace().count(), 24);

    let svc = DefaultRecoveryService;
    let recovered = svc.recover(&mnemonic).unwrap();
    assert_eq!(recovered.as_bytes(), &original_bytes);
}

/// 不正な recovery seed はエラーを返す
#[test]
fn invalid_recovery_seed_returns_error() {
    let svc = DefaultRecoveryService;
    let result = svc.recover("abandon abandon abandon");
    assert!(result.is_err());
}
