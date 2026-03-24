use crate::error::CryptoError;
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroizing;

pub struct PasswordKey(pub Zeroizing<[u8; 32]>);

impl PasswordKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 32],
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64MB
            t_cost: 3,
            p_cost: 1,
            salt: [0u8; 32],
        }
    }
}

pub fn derive_password_key(password: &[u8], params: &Argon2Params) -> Result<PasswordKey, CryptoError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, &params.salt, output.as_mut())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(PasswordKey(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> Argon2Params {
        Argon2Params {
            m_cost: 8,    // テスト用に最小値
            t_cost: 1,
            p_cost: 1,
            salt: [0x11u8; 32],
        }
    }

    #[test]
    fn derive_password_key_is_deterministic() {
        let params = test_params();
        let key1 = derive_password_key(b"password", &params).unwrap();
        let key2 = derive_password_key(b"password", &params).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let params = test_params();
        let key1 = derive_password_key(b"password1", &params).unwrap();
        let key2 = derive_password_key(b"password2", &params).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let params1 = test_params();
        let mut params2 = test_params();
        params2.salt = [0x22u8; 32];
        let key1 = derive_password_key(b"password", &params1).unwrap();
        let key2 = derive_password_key(b"password", &params2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
