use crate::error::FormatError;
use bincode::{config, Decode, Encode};
use serde::{Deserialize, Serialize};

const VOBJ_VERSION: u8 = 1;
const VMAN_VERSION: u8 = 1;
const VSHR_VERSION: u8 = 1;

pub fn encode<T>(value: &T) -> Result<Vec<u8>, FormatError>
where
    T: Serialize + Encode,
{
    bincode::encode_to_vec(value, config::standard())
        .map_err(|e| FormatError::ParseError(e.to_string()))
}

pub fn decode<T>(bytes: &[u8]) -> Result<T, FormatError>
where
    T: for<'de> Deserialize<'de> + Decode<()>,
{
    let (value, _) = bincode::decode_from_slice(bytes, config::standard())
        .map_err(|e| FormatError::ParseError(e.to_string()))?;
    Ok(value)
}

pub fn encode_vault_object(obj: &crate::types::VaultObject) -> Result<Vec<u8>, FormatError> {
    if obj.version != VOBJ_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VOBJ_VERSION,
            found: obj.version,
        });
    }
    encode(obj)
}

pub fn decode_vault_object(bytes: &[u8]) -> Result<crate::types::VaultObject, FormatError> {
    let obj: crate::types::VaultObject = decode(bytes)?;
    if obj.version != VOBJ_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VOBJ_VERSION,
            found: obj.version,
        });
    }
    Ok(obj)
}

pub fn encode_vault_manifest(manifest: &crate::types::VaultManifest) -> Result<Vec<u8>, FormatError> {
    if manifest.version != VMAN_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VMAN_VERSION,
            found: manifest.version,
        });
    }
    encode(manifest)
}

pub fn decode_vault_manifest(bytes: &[u8]) -> Result<crate::types::VaultManifest, FormatError> {
    let obj: crate::types::VaultManifest = decode(bytes)?;
    if obj.version != VMAN_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VMAN_VERSION,
            found: obj.version,
        });
    }
    Ok(obj)
}

pub fn encode_vault_share(share: &crate::types::VaultShare) -> Result<Vec<u8>, FormatError> {
    if share.version != VSHR_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VSHR_VERSION,
            found: share.version,
        });
    }
    encode(share)
}

pub fn decode_vault_share(bytes: &[u8]) -> Result<crate::types::VaultShare, FormatError> {
    let obj: crate::types::VaultShare = decode(bytes)?;
    if obj.version != VSHR_VERSION {
        return Err(FormatError::VersionMismatch {
            expected: VSHR_VERSION,
            found: obj.version,
        });
    }
    Ok(obj)
}
