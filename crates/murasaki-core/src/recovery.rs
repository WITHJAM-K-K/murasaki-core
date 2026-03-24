use crate::error::RecoveryError;
use murasaki_crypto::{recover_master_key, MasterKey, RecoverySeed};

pub struct RecoveryService;

impl RecoveryService {
    /// recovery seed（mnemonic）から master key を復元する
    pub fn recover(mnemonic: &str) -> Result<MasterKey, RecoveryError> {
        let seed = RecoverySeed::from_phrase(mnemonic)
            .map_err(|_| RecoveryError::InvalidRecoverySeed)?;
        Ok(recover_master_key(&seed)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murasaki_crypto::{generate_master_key, generate_recovery_seed};

    #[test]
    fn recover_from_valid_mnemonic() {
        let master_key = generate_master_key().unwrap();
        let original = *master_key.as_bytes();
        let seed = generate_recovery_seed(&master_key).unwrap();
        let recovered = RecoveryService::recover(seed.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn invalid_mnemonic_returns_error() {
        let result = RecoveryService::recover("this is not a valid bip39 mnemonic phrase at all");
        assert!(matches!(result, Err(RecoveryError::InvalidRecoverySeed)));
    }
}
