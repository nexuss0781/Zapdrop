use crate::settings::{atomic_write_json, SettingsStore};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};
use uuid::Uuid;

const IDENTITY_VERSION: u32 = 1;
#[cfg(any(target_os = "windows", target_os = "macos"))]
const KEYRING_SERVICE: &str = "com.nexuss.zapdrop";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentity {
    pub version: u32,
    pub device_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub key_storage: String,
}

impl DeviceIdentity {
    pub fn load_or_create(store: &SettingsStore) -> io::Result<Self> {
        store.ensure_root()?;
        if store.identity_path().exists() {
            let bytes = fs::read(store.identity_path())?;
            let identity: Self = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid identity: {error}"),
                )
            })?;
            if identity.version == IDENTITY_VERSION && !identity.device_id.is_empty() {
                if read_secret(store, &identity).is_ok() {
                    return Ok(identity);
                }
            }
        }
        Self::create(store)
    }

    fn create(store: &SettingsStore) -> io::Result<Self> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_b64 = BASE64.encode(public_key);
        let device_id = Uuid::new_v4().to_string();
        let fingerprint = fingerprint(&public_key);
        let secret = BASE64.encode(signing_key.to_bytes());

        let key_storage = if save_keyring_secret(&device_id, secret.as_bytes()) {
            "osKeyring".to_string()
        } else {
            write_locked_secret(&store.private_key_path(), secret.as_bytes())?;
            "protectedFileFallback".to_string()
        };

        let identity = Self {
            version: IDENTITY_VERSION,
            device_id,
            public_key: public_key_b64,
            fingerprint,
            key_storage,
        };
        atomic_write_json(&store.identity_path(), &identity)?;
        Ok(identity)
    }

    pub fn signing_key(&self, store: &SettingsStore) -> io::Result<SigningKey> {
        let encoded = read_secret(store, self)?;
        let decoded = BASE64.decode(encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid private key encoding: {error}"),
            )
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private key must contain 32 bytes",
            )
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn reset(store: &SettingsStore) -> io::Result<Self> {
        if let Ok(identity) = self::load_identity_file(store) {
            let _ = delete_keyring_secret(&identity.device_id);
        }
        let _ = fs::remove_file(store.identity_path());
        let _ = fs::remove_file(store.private_key_path());
        Self::create(store)
    }
}

fn load_identity_file(store: &SettingsStore) -> io::Result<DeviceIdentity> {
    let bytes = fs::read(store.identity_path())?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    digest
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn read_secret(store: &SettingsStore, identity: &DeviceIdentity) -> io::Result<Vec<u8>> {
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let _ = identity;
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    if identity.key_storage == "osKeyring" {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &identity.device_id) {
            if let Ok(secret) = entry.get_secret() {
                return Ok(secret);
            }
        }
    }
    fs::read(store.private_key_path())
}

fn save_keyring_secret(device_id: &str, secret: &[u8]) -> bool {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        return keyring::Entry::new(KEYRING_SERVICE, device_id)
            .and_then(|entry| entry.set_secret(secret))
            .is_ok();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (device_id, secret);
        false
    }
}

fn delete_keyring_secret(device_id: &str) -> bool {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        return keyring::Entry::new(KEYRING_SERVICE, device_id)
            .and_then(|entry| entry.delete_credential())
            .is_ok();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = device_id;
        false
    }
}

fn write_locked_secret(path: &Path, secret: &[u8]) -> io::Result<()> {
    fs::write(path, secret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DeviceIdentity;
    use crate::settings::SettingsStore;
    use std::fs;

    #[test]
    fn creates_and_reloads_stable_identity() {
        let root = std::env::temp_dir().join(format!("zapdrop-identity-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(root.clone());
        let first = DeviceIdentity::load_or_create(&store).expect("create identity");
        let second = DeviceIdentity::load_or_create(&store).expect("reload identity");
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.public_key, second.public_key);
        assert!(!first.fingerprint.is_empty());
        fs::remove_dir_all(root).expect("remove test data");
    }
}
