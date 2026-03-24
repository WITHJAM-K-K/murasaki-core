use crate::error::CryptoError;
use crate::hkdf_derive::MasterKey;
use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

pub struct RecoverySeed {
    mnemonic: Zeroizing<String>,
}

impl RecoverySeed {
    pub fn as_str(&self) -> &str {
        &self.mnemonic
    }

    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        // BIP-39 フレーズとして有効か検証
        Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| CryptoError::InvalidRecoverySeed)?;
        Ok(RecoverySeed {
            mnemonic: Zeroizing::new(phrase.to_string()),
        })
    }
}

/// master key のエントロピーから 24-word BIP-39 mnemonic を生成する
pub fn generate_recovery_seed(master_key: &MasterKey) -> Result<RecoverySeed, CryptoError> {
    // MasterKey は 32 バイト = 256 ビット → Words24
    let mnemonic = Mnemonic::from_entropy(master_key.as_bytes(), Language::English)
        .map_err(|_| CryptoError::InvalidRecoverySeed)?;
    Ok(RecoverySeed {
        mnemonic: Zeroizing::new(mnemonic.phrase().to_string()),
    })
}

/// mnemonic から master key を復元する
pub fn recover_master_key(seed: &RecoverySeed) -> Result<MasterKey, CryptoError> {
    let mnemonic = Mnemonic::from_phrase(seed.as_str(), Language::English)
        .map_err(|_| CryptoError::InvalidRecoverySeed)?;
    let entropy = mnemonic.entropy();
    if entropy.len() != 32 {
        return Err(CryptoError::InvalidRecoverySeed);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(entropy);
    Ok(MasterKey::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_hierarchy::generate_master_key;

    #[test]
    fn generate_and_recover_roundtrip() {
        let master_key = generate_master_key().unwrap();
        let original = *master_key.as_bytes();
        let seed = generate_recovery_seed(&master_key).unwrap();
        let recovered = recover_master_key(&seed).unwrap();
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn seed_has_24_words() {
        let master_key = generate_master_key().unwrap();
        let seed = generate_recovery_seed(&master_key).unwrap();
        let word_count = seed.as_str().split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn invalid_mnemonic_returns_error() {
        let bad_seed = RecoverySeed {
            mnemonic: Zeroizing::new("invalid mnemonic phrase that is not valid".to_string()),
        };
        let result = recover_master_key(&bad_seed);
        assert!(matches!(result, Err(CryptoError::InvalidRecoverySeed)));
    }
}
