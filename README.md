# murasaki-core

<!-- TODO: uncomment once published
[![Crates.io](https://img.shields.io/crates/v/murasaki-core.svg)](https://crates.io/crates/murasaki-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
-->

## Overview

Rust core library for **murasaki**, a zero-knowledge cloud encryption vault.

- All encryption happens **exclusively on the client side** — the cloud provider never sees file contents, file names, or directory structure.
- Serves as the cryptographic foundation for **murasaki-extension**, a Chrome Extension that brings zero-knowledge encryption to Google Drive.

## Crates

| Crate | Description |
|-------|-------------|
| `murasaki-crypto` | Cryptographic primitives — AES-256-GCM, Argon2id, HKDF, BIP-39 mnemonic |
| `murasaki-format` | Binary formats — VOBJ, VMAN, VSHR containers and chunk processing |
| `murasaki-core` | Vault logic — creation, unlock, file encryption/decryption, recovery |
| `murasaki-wasm` | JavaScript/TypeScript bindings via wasm-bindgen |

## Quick Start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
murasaki-core = { path = "crates/murasaki-core" }
tokio = { version = "1", features = ["full"] }
```

Create a vault, unlock it, encrypt a file, and decrypt it back:

```rust
use murasaki_core::{
    storage::InMemoryStorageAdapter,
    vault::VaultManager,
    file_ops::FileService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = InMemoryStorageAdapter::new();
    let vault = VaultManager::new(storage);

    // Create a vault (returns a BIP-39 recovery seed)
    let (_, recovery_seed) = vault.create_vault(b"my-password").await?;
    println!("Recovery seed: {}", recovery_seed.as_str());

    // Unlock the vault
    let session = vault.unlock(b"my-password").await?;

    // Encrypt a file
    let file_storage = InMemoryStorageAdapter::new();
    let svc = FileService::new(&session, &file_storage);
    let id = svc.encrypt_file(b"hello, world", "hello.txt", "text/plain").await?;

    // Decrypt the file
    let data = svc.decrypt_file(&id).await?;
    assert_eq!(data, b"hello, world");
    Ok(())
}
```

## Security Guarantees

- **Zero-knowledge architecture** — The cloud provider cannot access plaintext data, file names, or directory structures. All cryptographic operations run on the client.
- **Nonce uniqueness** — Every encryption operation generates a fresh random nonce; nonce reuse is structurally prevented.
- **No plaintext master key storage** — The master key is always wrapped (encrypted) at rest; it is never persisted in plaintext.
- **Mandatory manifest encryption** — Vault manifests (file metadata, tree structure) are always encrypted before storage; no metadata is stored in the clear.
- **Memory zeroization** — Sensitive key material is zeroized on drop using `zeroize`, minimizing exposure in memory.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Crate structure, data flows, component responsibilities
- [Security Design](docs/SECURITY.md) — Cryptographic design, key hierarchy, invariants, threat model

## License

MIT

---

# murasaki-core（日本語）

## 概要

**murasaki** のゼロ知識クラウド暗号保管庫のための Rust コアライブラリ。

- 暗号化はすべて**クライアント側のみ**で実行される。クラウド事業者はファイル内容・ファイル名・ディレクトリ構造を一切参照できない。
- Chrome Extension である **murasaki-extension** の暗号基盤として機能し、Google Drive 上でのゼロ知識暗号化を実現する。

## クレート一覧

| クレート | 説明 |
|---------|------|
| `murasaki-crypto` | 暗号プリミティブ — AES-256-GCM / Argon2id / HKDF / BIP-39 ニーモニック |
| `murasaki-format` | バイナリフォーマット — VOBJ / VMAN / VSHR コンテナとチャンク処理 |
| `murasaki-core` | Vault ロジック — 作成・アンロック・ファイル暗号化・復号・リカバリ |
| `murasaki-wasm` | wasm-bindgen による JavaScript/TypeScript バインディング |

## クイックスタート

`Cargo.toml` に依存関係を追加する:

```toml
[dependencies]
murasaki-core = { path = "crates/murasaki-core" }
tokio = { version = "1", features = ["full"] }
```

Vault を作成し、アンロックして、ファイルを暗号化・復号する:

```rust
use murasaki_core::{
    storage::InMemoryStorageAdapter,
    vault::VaultManager,
    file_ops::FileService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = InMemoryStorageAdapter::new();
    let vault = VaultManager::new(storage);

    // Vault を作成する（BIP-39 リカバリシードが返される）
    let (_, recovery_seed) = vault.create_vault(b"my-password").await?;
    println!("Recovery seed: {}", recovery_seed.as_str());

    // Vault をアンロックする
    let session = vault.unlock(b"my-password").await?;

    // ファイルを暗号化する
    let file_storage = InMemoryStorageAdapter::new();
    let svc = FileService::new(&session, &file_storage);
    let id = svc.encrypt_file(b"hello, world", "hello.txt", "text/plain").await?;

    // ファイルを復号する
    let data = svc.decrypt_file(&id).await?;
    assert_eq!(data, b"hello, world");
    Ok(())
}
```

## セキュリティ保証

- **ゼロ知識アーキテクチャ** — クラウド事業者は平文データ・ファイル名・ディレクトリ構造にアクセスできない。すべての暗号処理はクライアント上で実行される。
- **ノンス一意性** — 暗号化操作ごとに新鮮なランダムノンスを生成する。ノンスの再利用は構造的に防止されている。
- **master key の平文保存禁止** — master key は常にラップ（暗号化）された状態で保存され、平文で永続化されることはない。
- **Manifest の暗号化必須** — Vault マニフェスト（ファイルメタデータ・ツリー構造）は常に暗号化してから保存される。平文でメタデータが保存されることはない。
- **メモリゼロクリア** — 機密鍵素材は `zeroize` を使ってドロップ時にゼロクリアされ、メモリ上の露出を最小化する。

## ドキュメント

- [アーキテクチャ](docs/ARCHITECTURE.md) — クレート構成・データフロー・コンポーネント責務
- [セキュリティ設計](docs/SECURITY.md) — 暗号設計・鍵階層・不変条件・脅威モデル

## ライセンス

MIT
