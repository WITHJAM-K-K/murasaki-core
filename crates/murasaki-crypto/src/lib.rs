pub mod error;
pub mod hash;
pub mod hkdf_derive;
pub mod kdf;
pub mod key_hierarchy;
pub mod recovery;
pub mod service;
pub mod symmetric;

pub use error::CryptoError;
pub use hash::hash_chunk;
pub use hkdf_derive::{derive_file_key, derive_share_key, MasterKey, ShareKey};
pub use kdf::{derive_password_key, Argon2Params, PasswordKey};
pub use key_hierarchy::{generate_file_key, generate_master_key, unwrap_key, wrap_key, WrappedKey};
pub use recovery::{generate_recovery_seed, recover_master_key, RecoverySeed};
pub use service::{CryptoService, DefaultCryptoService};
pub use symmetric::{decrypt_chunk, encrypt_chunk, FileKey};
