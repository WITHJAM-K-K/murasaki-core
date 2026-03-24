# Architecture

murasaki-core is a Rust workspace that provides the cryptographic core for murasaki — a zero-knowledge encryption layer over cloud storage. All encryption and decryption happen exclusively on the client side.

## Workspace Structure

```
murasaki-core/
├── crates/
│   ├── murasaki-crypto/   # Cryptographic primitives
│   ├── murasaki-format/   # Binary format definitions
│   ├── murasaki-core/     # Vault business logic
│   └── murasaki-wasm/     # WebAssembly bindings
└── Cargo.toml             # Workspace root
```

## Layered Architecture

The workspace follows a strict layered architecture. Dependencies flow in one direction only — upper layers depend on lower layers, never the reverse.

```
┌─────────────────────────────────┐
│         murasaki-wasm           │  WebAssembly bridge (JS/TS consumers)
├─────────────────────────────────┤
│         murasaki-core           │  Vault logic, file operations, recovery
├──────────────┬──────────────────┤
│ murasaki-    │  murasaki-       │  Independent: no cross-dependency
│ crypto       │  format          │
└──────────────┴──────────────────┘
```

**Dependency rules:**
- `murasaki-crypto` and `murasaki-format` are independent of each other
- `murasaki-core` depends on both `murasaki-crypto` and `murasaki-format`
- `murasaki-wasm` depends on `murasaki-crypto` and `murasaki-core` only

## Crate Responsibilities

### `murasaki-crypto`

Provides all cryptographic primitives. No business logic lives here.

| Module | Responsibility |
|--------|---------------|
| `symmetric` | AES-256-GCM encrypt/decrypt (`encrypt_chunk`, `decrypt_chunk`) |
| `kdf` | Argon2id password key derivation (`derive_password_key`) |
| `hkdf_derive` | HKDF-SHA-256 key derivation (`derive_file_key`, `derive_share_key`) |
| `key_hierarchy` | Master key / file key generation and wrapping |
| `recovery` | BIP-39 24-word mnemonic generation and restoration |
| `hash` | SHA-256 chunk integrity hashing (`hash_chunk`) |
| `service` | `CryptoService` trait — injectable abstraction over all primitives |

**Key types** (all sensitive types use `Zeroizing<T>` for memory erasure on drop):

```
MasterKey(Zeroizing<[u8; 32]>)
PasswordKey(Zeroizing<[u8; 32]>)
FileKey(Zeroizing<[u8; 32]>)
WrappedKey(Vec<u8>)          // nonce(12) ‖ ciphertext ‖ tag(16)
RecoverySeed { mnemonic: Zeroizing<String> }
```

### `murasaki-format`

Defines the binary wire format for all objects stored to the cloud. No cryptographic logic here.

**Binary objects:**

| Format | Struct | Description |
|--------|--------|-------------|
| VOBJ v1 | `VaultObject` | One encrypted file chunk |
| VMAN v1 | `VaultManifest` | Encrypted file metadata + chunk list |
| VSHR v1 | `VaultShare` | Encrypted file key for sharing |

All formats carry a version byte as their first field. Unknown versions return `FormatError::VersionMismatch`. Serialization uses `bincode` v2.

**Chunk model:**

Files are split into fixed 4 MB chunks (`CHUNK_SIZE = 4 * 1024 * 1024`). The final chunk is zero-padded to 4 MB. Each chunk carries its SHA-256 hash of the original (pre-padding) data, used for integrity verification on decrypt.

```
split(data: &[u8]) -> Vec<Chunk>
merge(chunks: &[Chunk]) -> Result<Vec<u8>, FormatError>
```

The `ChunkSplitter` trait allows alternative implementations for testing.

### `murasaki-core`

Contains all Vault business logic. Depends on both `murasaki-crypto` and `murasaki-format`.

**Key components:**

#### `StorageAdapter` (trait)

Port interface for pluggable cloud storage backends. Implemented by consumers (e.g., a Google Drive adapter in `murasaki-extension`).

```rust
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
```

`InMemoryStorageAdapter` is provided for testing.

#### `VaultManager<S: StorageAdapter>`

Manages the Vault lifecycle.

```
create_vault(password) → (VaultMetadata, RecoverySeed)
unlock(password)        → VaultSession
```

`VaultSession` holds the decrypted `MasterKey` in memory only — it is never written to storage. The storage layer persists only `wrappedMasterKey` (the master key encrypted under the password key).

#### `FileService<'a, S>`

Handles file encryption and decryption within an active `VaultSession`.

```
encrypt_file(data, name, mime) → FileEntryId
decrypt_file(file_entry_id)    → Vec<u8>
```

Internally: derives a per-file key from the master key via HKDF, splits the file into 4 MB chunks, encrypts each chunk, stores them as `VaultObject` (VOBJ), then encrypts the manifest (VMAN) and stores it.

#### `RecoveryService` (trait)

```rust
pub trait RecoveryService {
    fn recover(&self, mnemonic: &str) -> Result<MasterKey, RecoveryError>;
}
```

`DefaultRecoveryService` restores a master key from a BIP-39 24-word mnemonic.

### `murasaki-wasm`

Thin wasm-bindgen wrapper over `murasaki-crypto`. Does not expose `VaultManager` or `FileService` — those are orchestrated by the consuming application (e.g., `murasaki-extension`) on the JS side.

All exported functions take/return `Uint8Array` or `String`. Rust errors are converted to `JsValue` and thrown as JavaScript exceptions.

Build: `wasm-pack build --target bundler`

## Data Flow: File Encryption

```
Client
  │  encrypt_file(data, "report.pdf", "application/pdf")
  ▼
FileService
  ├─ derive_file_key(master_key, file_entry_id)  ← HKDF-SHA-256
  ├─ for each 4 MB chunk:
  │    ├─ hash_chunk(chunk_data)                  ← SHA-256
  │    ├─ encrypt_chunk(chunk_data, file_key)     ← AES-256-GCM
  │    └─ put_object(VaultObject { ciphertext, hash })
  ├─ build ManifestContent { filename, mime, chunk_list }
  ├─ encrypt_chunk(manifest_json, file_key)       ← AES-256-GCM
  └─ put_manifest(VaultManifest { ciphertext })
  │
  ▼
StorageAdapter  →  Cloud Storage
```

## Data Flow: Vault Unlock

```
Client
  │  unlock(password: &[u8])
  ▼
VaultManager
  ├─ get_manifest(VAULT_METADATA_KEY)
  ├─ derive_password_key(password, argon_params)  ← Argon2id
  ├─ unwrap_key(wrapped_master_key, password_key) ← AES-256-GCM
  └─ VaultSession { vault_id, master_key }        ← in memory only
```

## Error Handling

Each crate defines its own typed error enum via `thiserror`. Upper layers wrap lower-layer errors:

```
CryptoError
FormatError
StorageError
VaultError  ←  wraps CryptoError, FormatError, StorageError
RecoveryError  ←  wraps CryptoError
```

WASM layer converts any error to `JsValue::from_str(&e.to_string())`.

---

# アーキテクチャ

murasaki-core は murasaki のための暗号コアを提供する Rust ワークスペースです。murasaki はクラウドストレージ上のゼロ知識暗号化レイヤーです。すべての暗号化・復号はクライアント側でのみ行われます。

## ワークスペース構成

```
murasaki-core/
├── crates/
│   ├── murasaki-crypto/   # Cryptographic primitives
│   ├── murasaki-format/   # Binary format definitions
│   ├── murasaki-core/     # Vault business logic
│   └── murasaki-wasm/     # WebAssembly bindings
└── Cargo.toml             # Workspace root
```

## レイヤードアーキテクチャ

ワークスペースは厳格なレイヤードアーキテクチャに従います。依存関係は一方向にのみ流れ、上位レイヤーが下位レイヤーに依存し、その逆はありません。

```
┌─────────────────────────────────┐
│         murasaki-wasm           │  WebAssembly bridge (JS/TS consumers)
├─────────────────────────────────┤
│         murasaki-core           │  Vault logic, file operations, recovery
├──────────────┬──────────────────┤
│ murasaki-    │  murasaki-       │  Independent: no cross-dependency
│ crypto       │  format          │
└──────────────┴──────────────────┘
```

**依存関係ルール:**
- `murasaki-crypto` と `murasaki-format` は互いに独立している
- `murasaki-core` は `murasaki-crypto` と `murasaki-format` の両方に依存する
- `murasaki-wasm` は `murasaki-crypto` と `murasaki-core` にのみ依存する

## クレートの責務

### `murasaki-crypto`

すべての暗号プリミティブを提供します。ビジネスロジックはここには含まれません。

| Module | Responsibility |
|--------|---------------|
| `symmetric` | AES-256-GCM encrypt/decrypt (`encrypt_chunk`, `decrypt_chunk`) |
| `kdf` | Argon2id password key derivation (`derive_password_key`) |
| `hkdf_derive` | HKDF-SHA-256 key derivation (`derive_file_key`, `derive_share_key`) |
| `key_hierarchy` | Master key / file key generation and wrapping |
| `recovery` | BIP-39 24-word mnemonic generation and restoration |
| `hash` | SHA-256 chunk integrity hashing (`hash_chunk`) |
| `service` | `CryptoService` trait — injectable abstraction over all primitives |

**主要な型**（すべての機密型はドロップ時のメモリ消去のために `Zeroizing<T>` を使用）:

```
MasterKey(Zeroizing<[u8; 32]>)
PasswordKey(Zeroizing<[u8; 32]>)
FileKey(Zeroizing<[u8; 32]>)
WrappedKey(Vec<u8>)          // nonce(12) ‖ ciphertext ‖ tag(16)
RecoverySeed { mnemonic: Zeroizing<String> }
```

### `murasaki-format`

クラウドに保存されるすべてのオブジェクトのバイナリワイヤーフォーマットを定義します。暗号ロジックはここには含まれません。

**バイナリオブジェクト:**

| Format | Struct | Description |
|--------|--------|-------------|
| VOBJ v1 | `VaultObject` | One encrypted file chunk |
| VMAN v1 | `VaultManifest` | Encrypted file metadata + chunk list |
| VSHR v1 | `VaultShare` | Encrypted file key for sharing |

すべてのフォーマットは最初のフィールドとしてバージョンバイトを持ちます。不明なバージョンは `FormatError::VersionMismatch` を返します。シリアライズには `bincode` v2 を使用します。

**チャンクモデル:**

ファイルは固定 4 MB チャンク（`CHUNK_SIZE = 4 * 1024 * 1024`）に分割されます。最後のチャンクは 4 MB までゼロパディングされます。各チャンクは元の（パディング前の）データの SHA-256 ハッシュを保持し、復号時の整合性検証に使用されます。

```
split(data: &[u8]) -> Vec<Chunk>
merge(chunks: &[Chunk]) -> Result<Vec<u8>, FormatError>
```

`ChunkSplitter` トレイトにより、テスト用の代替実装が可能です。

### `murasaki-core`

すべての Vault ビジネスロジックを含みます。`murasaki-crypto` と `murasaki-format` の両方に依存します。

**主要コンポーネント:**

#### `StorageAdapter` (trait)

プラガブルなクラウドストレージバックエンドのためのポートインターフェースです。コンシューマ側で実装されます（例: `murasaki-extension` の Google Drive アダプタ）。

```rust
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
```

テスト用に `InMemoryStorageAdapter` が提供されています。

#### `VaultManager<S: StorageAdapter>`

Vault のライフサイクルを管理します。

```
create_vault(password) → (VaultMetadata, RecoverySeed)
unlock(password)        → VaultSession
```

`VaultSession` は復号された `MasterKey` をメモリ上にのみ保持し、ストレージには書き込まれません。ストレージレイヤーは `wrappedMasterKey`（パスワードキーで暗号化されたマスターキー）のみを永続化します。

#### `FileService<'a, S>`

アクティブな `VaultSession` 内でファイルの暗号化と復号を処理します。

```
encrypt_file(data, name, mime) → FileEntryId
decrypt_file(file_entry_id)    → Vec<u8>
```

内部処理: HKDF を通じてマスターキーからファイルごとのキーを導出し、ファイルを 4 MB チャンクに分割し、各チャンクを暗号化して `VaultObject`（VOBJ）として保存し、その後マニフェスト（VMAN）を暗号化して保存します。

#### `RecoveryService` (trait)

```rust
pub trait RecoveryService {
    fn recover(&self, mnemonic: &str) -> Result<MasterKey, RecoveryError>;
}
```

`DefaultRecoveryService` は BIP-39 の 24 単語ニーモニックからマスターキーを復元します。

### `murasaki-wasm`

`murasaki-crypto` に対する薄い wasm-bindgen ラッパーです。`VaultManager` や `FileService` は公開せず、それらはコンシューマアプリケーション（例: `murasaki-extension`）の JS 側でオーケストレーションされます。

すべてのエクスポート関数は `Uint8Array` または `String` を受け取り/返します。Rust のエラーは `JsValue` に変換され、JavaScript 例外としてスローされます。

ビルド: `wasm-pack build --target bundler`

## データフロー: ファイル暗号化

```
Client
  │  encrypt_file(data, "report.pdf", "application/pdf")
  ▼
FileService
  ├─ derive_file_key(master_key, file_entry_id)  ← HKDF-SHA-256
  ├─ for each 4 MB chunk:
  │    ├─ hash_chunk(chunk_data)                  ← SHA-256
  │    ├─ encrypt_chunk(chunk_data, file_key)     ← AES-256-GCM
  │    └─ put_object(VaultObject { ciphertext, hash })
  ├─ build ManifestContent { filename, mime, chunk_list }
  ├─ encrypt_chunk(manifest_json, file_key)       ← AES-256-GCM
  └─ put_manifest(VaultManifest { ciphertext })
  │
  ▼
StorageAdapter  →  Cloud Storage
```

## データフロー: Vault アンロック

```
Client
  │  unlock(password: &[u8])
  ▼
VaultManager
  ├─ get_manifest(VAULT_METADATA_KEY)
  ├─ derive_password_key(password, argon_params)  ← Argon2id
  ├─ unwrap_key(wrapped_master_key, password_key) ← AES-256-GCM
  └─ VaultSession { vault_id, master_key }        ← in memory only
```

## エラーハンドリング

各クレートは `thiserror` を使って独自の型付きエラー列挙型を定義します。上位レイヤーは下位レイヤーのエラーをラップします:

```
CryptoError
FormatError
StorageError
VaultError  ←  wraps CryptoError, FormatError, StorageError
RecoveryError  ←  wraps CryptoError
```

WASM レイヤーはすべてのエラーを `JsValue::from_str(&e.to_string())` に変換します。
