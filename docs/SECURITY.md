# Security Design

This document describes the cryptographic design, security invariants, and threat model of murasaki-core.

## Threat Model

| Adversary | Capability | murasaki's defense |
|-----------|-----------|-------------------|
| Cloud provider | Full read access to stored objects | All content is AES-256-GCM encrypted client-side before upload |
| Network observer | TLS traffic interception | Client-side encryption provides a second layer beyond TLS |
| Compromised password | Guessing/bruteforce | Argon2id with configurable cost parameters |
| Memory inspection | Access to process memory | `Zeroizing<T>` erases sensitive keys on drop |
| Tampered ciphertext | Bit-flip or substitution | AES-GCM authentication tag rejects modified ciphertext |
| Metadata inference | Object size analysis | Fixed 4 MB chunks prevent size-based file identification |

**Out of scope for murasaki-core:**
- Client application integrity (handled by `murasaki-extension` build signing)
- Key management UI (consumer responsibility)
- Rate-limiting against brute-force unlock attempts (consumer responsibility)

---

## Cryptographic Primitives

### Symmetric Encryption — AES-256-GCM

Used for: chunk encryption, manifest encryption, key wrapping.

Library: [`aes-gcm`](https://crates.io/crates/aes-gcm) 0.10.3 (RustCrypto, NCC Group audited)

**Ciphertext format:**

```
[ nonce (12 bytes) ][ ciphertext ][ GCM tag (16 bytes) ]
```

- Nonce is generated from `OsRng` on every encryption call. Nonce reuse is architecturally impossible because no nonce is ever stored or reused.
- Authentication tag verification is performed atomically before any plaintext is returned. Partial plaintext is never returned on failure.

### Password Key Derivation — Argon2id

Used for: deriving `PasswordKey` from the user's passphrase.

Library: [`argon2`](https://crates.io/crates/argon2) 0.5 (RustCrypto)

Default parameters:

```
m_cost = 65536   (64 MB memory)
t_cost = 3       (3 iterations)
p_cost = 1       (single thread)
salt   = 32 bytes from OsRng (unique per vault, stored as VaultMetadata)
```

The salt is stored alongside the `wrappedMasterKey`. The same password + same params always produces the same `PasswordKey` (deterministic), enabling unlock without storing the key itself.

### Key Derivation — HKDF-SHA-256

Used for: deriving `FileKey` and `ShareKey` from the `MasterKey`.

Library: [`hkdf`](https://crates.io/crates/hkdf) 0.12.4 + [`sha2`](https://crates.io/crates/sha2) 0.10.9 (RustCrypto)

```
FileKey  = HKDF-SHA-256(ikm: master_key, info: file_entry_id_bytes)
ShareKey = HKDF-SHA-256(ikm: master_key, info: share_id_bytes)
```

Each file gets a unique derived key — compromise of one file key does not expose any other file or the master key.

### Integrity Hashing — SHA-256

Used for: per-chunk integrity verification.

Each chunk's SHA-256 hash is computed over the **pre-padding plaintext** and stored in the `VaultObject`. On decryption, the hash of the recovered plaintext is verified against the stored value. A mismatch returns `VaultError::IntegrityCheckFailed`.

Note: AES-GCM already provides authenticated encryption (AEAD). The SHA-256 hash provides an additional application-level integrity check that survives independent of the encryption layer.

### Recovery Seed — BIP-39

Used for: out-of-band master key backup.

Library: [`tiny-bip39`](https://crates.io/crates/tiny-bip39) 2.0.0

The master key (32 bytes of entropy) is encoded as a BIP-39 24-word mnemonic. Recovery restores the exact master key from the mnemonic. The `RecoverySeed` type wraps the mnemonic in `Zeroizing<String>` so it is erased from memory when dropped.

A lost recovery seed means the master key is unrecoverable if the password is also lost.

---

## Key Hierarchy

```
User passphrase
    │
    │  Argon2id (+ per-vault salt)
    ▼
PasswordKey (32 bytes)
    │
    │  AES-256-GCM wrap
    ▼
wrappedMasterKey  ──── stored in cloud (VaultMetadata)
    │
    │  AES-256-GCM unwrap (on unlock)
    ▼
MasterKey (32 bytes)  ──── memory only, never persisted
    │
    ├─── HKDF(file_entry_id)  →  FileKey (per file)
    │        │
    │        │  AES-256-GCM
    │        ▼
    │    Encrypted chunks (VOBJ) + Encrypted manifest (VMAN)
    │
    └─── BIP-39 encoding  →  RecoverySeed (24 words)
```

**Invariants:**
- `MasterKey` is never written to any persistent storage.
- `wrappedMasterKey` stored in the cloud is ciphertext only — its plaintext can only be recovered by someone who knows the password or the recovery seed.
- `FileKey` is derived deterministically and never stored — it is re-derived from `MasterKey` on each unlock/decrypt.

---

## Security Invariants

The following invariants are enforced by the library and must not be violated by consumers.

### 1. Nonce non-reuse

Every `encrypt_chunk` / `wrap_key` call generates a fresh 12-byte nonce from `OsRng`. There is no API to supply an external nonce. AES-GCM with a repeated nonce under the same key leaks the key; this invariant makes nonce reuse structurally impossible.

### 2. No plaintext master key persistence

`MasterKey` is a newtype over `Zeroizing<[u8; 32]>`. Only `wrappedMasterKey` (AES-GCM ciphertext) is passed to `StorageAdapter`. `VaultManager` never calls `put_object` or `put_manifest` with raw key material.

### 3. Manifest always encrypted

`VaultManifest.ciphertext` contains the encrypted file metadata (name, MIME type, size, creation timestamp, chunk list). It is encrypted with the same AES-256-GCM scheme as chunks. The cloud provider cannot read file metadata.

### 4. Fixed chunk size

`CHUNK_SIZE = 4 * 1024 * 1024` (4 MB) is a compile-time constant. All chunks — including the last one — are padded to exactly 4 MB before encryption. This prevents size-based inference of file content or boundaries.

### 5. No partial plaintext on decryption failure

AES-GCM decryption either succeeds completely or returns an error. The underlying `aes-gcm` crate does not expose partial plaintext. `murasaki-crypto` propagates `CryptoError::DecryptionFailed` immediately.

### 6. Memory erasure

All sensitive types (`MasterKey`, `PasswordKey`, `FileKey`, `RecoverySeed`) implement `Drop` via `Zeroizing<T>`, which overwrites the memory with zeros before deallocation. This limits the window of exposure in case of a memory dump.

---

## Zero-Knowledge Property

murasaki is zero-knowledge with respect to the cloud storage provider. A provider with full read access to the stored objects observes only:

- Opaque binary blobs of fixed size (4 MB + 28 bytes overhead each)
- UUIDs as object identifiers
- No file names, MIME types, sizes, creation dates, or directory structure

This is achieved by:
1. Encrypting file content chunk-by-chunk before upload
2. Storing all file metadata in the encrypted `VaultManifest`, never in plaintext
3. Deriving object identifiers from UUIDs (not from file names or paths)

---

## Cryptographic Library Provenance

All cryptographic dependencies are from the [RustCrypto](https://github.com/RustCrypto) project, which maintains a coordinated set of pure-Rust cryptographic implementations.

| Library | Version | Algorithm | Audit status |
|---------|---------|-----------|--------------|
| `aes-gcm` | 0.10.3 | AES-256-GCM | NCC Group (2023) |
| `argon2` | 0.5 | Argon2id | RustCrypto project |
| `hkdf` | 0.12.4 | HKDF-SHA-256 | RustCrypto project |
| `sha2` | 0.10.9 | SHA-256 | RustCrypto project |
| `tiny-bip39` | 2.0.0 | BIP-39 | — |
| `zeroize` | 1.x | Memory erasure | RustCrypto project |

No custom cryptographic implementations are used. All algorithms are standard and well-specified.

---

## Known Limitations

- **Single client assumption (Phase 1):** `VaultSession` holds the `MasterKey` in memory for the duration of the session. Concurrent multi-client access to the same vault is not supported and may result in race conditions on the storage layer.
- **No forward secrecy:** Compromise of the master key exposes all past and future file keys (they are derived from it). Key rotation is not yet implemented.
- **Recovery seed is a single point of failure:** Loss of both the password and the recovery seed results in permanent data loss. There is no secondary recovery mechanism.

---

# セキュリティ設計

このドキュメントでは、murasaki-core の暗号設計、セキュリティ不変条件、および脅威モデルについて説明する。

## 脅威モデル

| Adversary | Capability | murasaki's defense |
|-----------|-----------|-------------------|
| Cloud provider | Full read access to stored objects | All content is AES-256-GCM encrypted client-side before upload |
| Network observer | TLS traffic interception | Client-side encryption provides a second layer beyond TLS |
| Compromised password | Guessing/bruteforce | Argon2id with configurable cost parameters |
| Memory inspection | Access to process memory | `Zeroizing<T>` erases sensitive keys on drop |
| Tampered ciphertext | Bit-flip or substitution | AES-GCM authentication tag rejects modified ciphertext |
| Metadata inference | Object size analysis | Fixed 4 MB chunks prevent size-based file identification |

**murasaki-core のスコープ外:**
- クライアントアプリケーションの完全性（`murasaki-extension` のビルド署名で対応）
- 鍵管理 UI（利用者側の責任）
- ブルートフォースアンロック試行に対するレート制限（利用者側の責任）

---

## 暗号プリミティブ

### 共通鍵暗号 — AES-256-GCM

用途: チャンク暗号化、マニフェスト暗号化、鍵ラッピング。

ライブラリ: [`aes-gcm`](https://crates.io/crates/aes-gcm) 0.10.3（RustCrypto、NCC Group 監査済み）

**暗号文フォーマット:**

```
[ nonce (12 bytes) ][ ciphertext ][ GCM tag (16 bytes) ]
```

- ノンスは暗号化呼び出しごとに `OsRng` から生成される。ノンスは保存も再利用もされないため、ノンスの再利用はアーキテクチャ上不可能である。
- 認証タグの検証は、平文が返される前にアトミックに実行される。失敗時に部分的な平文が返されることはない。

### パスワード鍵導出 — Argon2id

用途: ユーザーのパスフレーズから `PasswordKey` を導出する。

ライブラリ: [`argon2`](https://crates.io/crates/argon2) 0.5（RustCrypto）

デフォルトパラメータ:

```
m_cost = 65536   (64 MB memory)
t_cost = 3       (3 iterations)
p_cost = 1       (single thread)
salt   = 32 bytes from OsRng (unique per vault, stored as VaultMetadata)
```

ソルトは `wrappedMasterKey` と共に保存される。同じパスワードと同じパラメータからは常に同じ `PasswordKey` が生成される（決定論的）ため、鍵自体を保存せずにアンロックが可能となる。

### 鍵導出 — HKDF-SHA-256

用途: `MasterKey` から `FileKey` および `ShareKey` を導出する。

ライブラリ: [`hkdf`](https://crates.io/crates/hkdf) 0.12.4 + [`sha2`](https://crates.io/crates/sha2) 0.10.9（RustCrypto）

```
FileKey  = HKDF-SHA-256(ikm: master_key, info: file_entry_id_bytes)
ShareKey = HKDF-SHA-256(ikm: master_key, info: share_id_bytes)
```

各ファイルは固有の導出鍵を持つ。1つのファイル鍵が漏洩しても、他のファイルやマスター鍵が露出することはない。

### 完全性ハッシュ — SHA-256

用途: チャンク単位の完全性検証。

各チャンクの SHA-256 ハッシュは**パディング前の平文**に対して計算され、`VaultObject` に保存される。復号時には、復元された平文のハッシュが保存された値と照合される。不一致の場合は `VaultError::IntegrityCheckFailed` が返される。

注: AES-GCM はすでに認証付き暗号化（AEAD）を提供している。SHA-256 ハッシュは、暗号化レイヤーとは独立して機能する追加のアプリケーションレベルの完全性チェックを提供する。

### リカバリシード — BIP-39

用途: 帯域外でのマスター鍵バックアップ。

ライブラリ: [`tiny-bip39`](https://crates.io/crates/tiny-bip39) 2.0.0

マスター鍵（32バイトのエントロピー）は BIP-39 の24単語ニーモニックとしてエンコードされる。リカバリ時にはニーモニックから正確なマスター鍵が復元される。`RecoverySeed` 型はニーモニックを `Zeroizing<String>` でラップしており、ドロップ時にメモリから消去される。

リカバリシードを紛失した場合、パスワードも失われていればマスター鍵は復元不可能となる。

---

## 鍵階層

```
User passphrase
    │
    │  Argon2id (+ per-vault salt)
    ▼
PasswordKey (32 bytes)
    │
    │  AES-256-GCM wrap
    ▼
wrappedMasterKey  ──── stored in cloud (VaultMetadata)
    │
    │  AES-256-GCM unwrap (on unlock)
    ▼
MasterKey (32 bytes)  ──── memory only, never persisted
    │
    ├─── HKDF(file_entry_id)  →  FileKey (per file)
    │        │
    │        │  AES-256-GCM
    │        ▼
    │    Encrypted chunks (VOBJ) + Encrypted manifest (VMAN)
    │
    └─── BIP-39 encoding  →  RecoverySeed (24 words)
```

**不変条件:**
- `MasterKey` は永続ストレージに書き込まれることはない。
- クラウドに保存される `wrappedMasterKey` は暗号文のみであり、その平文はパスワードまたはリカバリシードを知る者のみが復元できる。
- `FileKey` は決定論的に導出され、保存されることはない。アンロック/復号のたびに `MasterKey` から再導出される。

---

## セキュリティ不変条件

以下の不変条件はライブラリによって強制されており、利用者はこれに違反してはならない。

### 1. ノンスの非再利用

すべての `encrypt_chunk` / `wrap_key` 呼び出しは `OsRng` から新しい12バイトのノンスを生成する。外部ノンスを供給する API は存在しない。同一鍵でノンスが繰り返されると AES-GCM は鍵を漏洩させるが、この不変条件によりノンスの再利用は構造的に不可能である。

### 2. 平文マスター鍵の非永続化

`MasterKey` は `Zeroizing<[u8; 32]>` のニュータイプである。`StorageAdapter` に渡されるのは `wrappedMasterKey`（AES-GCM 暗号文）のみである。`VaultManager` が生の鍵素材を引数として `put_object` や `put_manifest` を呼び出すことはない。

### 3. マニフェストは常に暗号化

`VaultManifest.ciphertext` には暗号化されたファイルメタデータ（名前、MIME タイプ、サイズ、作成タイムスタンプ、チャンクリスト）が含まれる。チャンクと同じ AES-256-GCM スキームで暗号化される。クラウドプロバイダーはファイルメタデータを読み取ることができない。

### 4. 固定チャンクサイズ

`CHUNK_SIZE = 4 * 1024 * 1024`（4 MB）はコンパイル時定数である。最後のチャンクを含むすべてのチャンクは、暗号化前に正確に 4 MB にパディングされる。これにより、サイズに基づくファイル内容や境界の推測を防止する。

### 5. 復号失敗時に部分的な平文を返さない

AES-GCM の復号は完全に成功するか、エラーを返すかのいずれかである。基盤となる `aes-gcm` クレートは部分的な平文を公開しない。`murasaki-crypto` は `CryptoError::DecryptionFailed` を即座に伝播する。

### 6. メモリ消去

すべての機密型（`MasterKey`、`PasswordKey`、`FileKey`、`RecoverySeed`）は `Zeroizing<T>` を介して `Drop` を実装しており、メモリ解放前にゼロで上書きする。これにより、メモリダンプが発生した場合の露出ウィンドウを制限する。

---

## ゼロ知識特性

murasaki はクラウドストレージプロバイダーに対してゼロ知識である。保存されたオブジェクトへの完全な読み取りアクセスを持つプロバイダーが観察できるのは以下のみである:

- 固定サイズの不透明なバイナリブロブ（各 4 MB + 28 バイトのオーバーヘッド）
- オブジェクト識別子としての UUID
- ファイル名、MIME タイプ、サイズ、作成日、ディレクトリ構造は一切なし

これは以下によって実現される:
1. アップロード前にファイル内容をチャンク単位で暗号化
2. すべてのファイルメタデータを暗号化された `VaultManifest` に保存し、平文では保存しない
3. オブジェクト識別子を UUID から導出する（ファイル名やパスからではない）

---

## 暗号ライブラリの出所

すべての暗号依存関係は [RustCrypto](https://github.com/RustCrypto) プロジェクトに由来し、同プロジェクトは協調的な純 Rust 暗号実装群を維持している。

| Library | Version | Algorithm | Audit status |
|---------|---------|-----------|--------------|
| `aes-gcm` | 0.10.3 | AES-256-GCM | NCC Group (2023) |
| `argon2` | 0.5 | Argon2id | RustCrypto project |
| `hkdf` | 0.12.4 | HKDF-SHA-256 | RustCrypto project |
| `sha2` | 0.10.9 | SHA-256 | RustCrypto project |
| `tiny-bip39` | 2.0.0 | BIP-39 | — |
| `zeroize` | 1.x | Memory erasure | RustCrypto project |

カスタム暗号実装は使用していない。すべてのアルゴリズムは標準的かつ十分に仕様化されたものである。

---

## 既知の制限事項

- **シングルクライアント前提（Phase 1）:** `VaultSession` はセッション期間中 `MasterKey` をメモリに保持する。同一 Vault への並行マルチクライアントアクセスはサポートされておらず、ストレージレイヤーで競合状態が発生する可能性がある。
- **前方秘匿性なし:** マスター鍵が漏洩すると、すべての過去および将来のファイル鍵が露出する（それらはマスター鍵から導出されるため）。鍵ローテーションは未実装である。
- **リカバリシードが単一障害点:** パスワードとリカバリシードの両方を紛失すると、永久的なデータ損失となる。二次的な復旧メカニズムは存在しない。
