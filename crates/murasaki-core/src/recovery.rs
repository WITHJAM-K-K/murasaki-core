use crate::error::RecoveryError;
use murasaki_crypto::{recover_master_key, MasterKey, RecoverySeed};

/// recovery seed からmaster keyを復元するトレイト
pub trait RecoveryService {
    fn recover(&self, mnemonic: &str) -> Result<MasterKey, RecoveryError>;
}

/// デフォルトのBIP-39 mnemonic実装
pub struct DefaultRecoveryService;

impl RecoveryService for DefaultRecoveryService {
    fn recover(&self, mnemonic: &str) -> Result<MasterKey, RecoveryError> {
        let seed =
            RecoverySeed::from_phrase(mnemonic).map_err(|_| RecoveryError::InvalidRecoverySeed)?;
        Ok(recover_master_key(&seed)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murasaki_crypto::{generate_master_key, generate_recovery_seed};

    #[test]
    fn recover_from_valid_mnemonic() {
        let svc = DefaultRecoveryService;
        let master_key = generate_master_key().unwrap();
        let original = *master_key.as_bytes();
        let seed = generate_recovery_seed(&master_key).unwrap();
        let recovered = svc.recover(seed.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn invalid_mnemonic_returns_error() {
        let svc = DefaultRecoveryService;
        let result = svc.recover("this is not a valid bip39 mnemonic phrase at all");
        assert!(matches!(result, Err(RecoveryError::InvalidRecoverySeed)));
    }
}
