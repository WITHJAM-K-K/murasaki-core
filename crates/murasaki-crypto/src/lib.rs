pub mod error;
pub mod hash;
pub mod symmetric;
pub mod kdf;
pub mod hkdf_derive;
pub mod key_hierarchy;
pub mod recovery;

pub use hash::hash_chunk;
pub use symmetric::{encrypt_chunk, decrypt_chunk, FileKey};
pub use kdf::{derive_password_key, PasswordKey, Argon2Params};
pub use hkdf_derive::{derive_file_key, derive_share_key, MasterKey, ShareKey};
pub use key_hierarchy::{generate_master_key, generate_file_key, wrap_key, unwrap_key, WrappedKey};
pub use recovery::{generate_recovery_seed, recover_master_key, RecoverySeed};
pub use error::CryptoError;
