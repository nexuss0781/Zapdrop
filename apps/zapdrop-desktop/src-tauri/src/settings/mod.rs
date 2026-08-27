use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const SETTINGS_VERSION: u32 = 2;

fn default_always_ask_before_receive() -> bool {
    true
}

fn default_conflict_policy() -> String {
    "rename".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub version: u32,
    pub device_name: String,
    pub receive_directory: String,
    pub selected_interface: Option<String>,
    pub advertise_on_startup: bool,
    #[serde(default = "default_always_ask_before_receive")]
    pub always_ask_before_receive: bool,
    #[serde(default = "default_conflict_policy")]
    pub default_conflict_policy: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        let device_name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .ok()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "This PC".to_string());
        let receive_directory = directories::UserDirs::new()
            .and_then(|dirs| dirs.download_dir().map(Path::to_path_buf))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .join("Zapdrop")
            .to_string_lossy()
            .to_string();

        Self {
            version: SETTINGS_VERSION,
            device_name: normalize_device_name(&device_name),
            receive_directory,
            selected_interface: None,
            advertise_on_startup: true,
            always_ask_before_receive: true,
            default_conflict_policy: default_conflict_policy(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    root: PathBuf,
}

impl SettingsStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn settings_path(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    pub fn identity_path(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.root.join("identity.key")
    }

    pub fn ensure_root(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)
    }

    pub fn load(&self) -> io::Result<AppSettings> {
        self.ensure_root()?;
        if !self.settings_path().exists() {
            let settings = AppSettings::default();
            self.save(&settings)?;
            return Ok(settings);
        }

        let bytes = fs::read(self.settings_path())?;
        let mut settings: AppSettings = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid settings: {error}"),
            )
        })?;
        settings.version = SETTINGS_VERSION;
        settings.device_name = normalize_device_name(&settings.device_name);
        Ok(settings)
    }

    pub fn save(&self, settings: &AppSettings) -> io::Result<()> {
        self.ensure_root()?;
        let mut normalized = settings.clone();
        normalized.version = SETTINGS_VERSION;
        normalized.device_name = normalize_device_name(&normalized.device_name);
        atomic_write_json(&self.settings_path(), &normalized)
    }
}

pub fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("com", "Nexuss", "Zapdrop")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".zapdrop")
        })
}

pub fn normalize_device_name(value: &str) -> String {
    let trimmed = value.trim();
    let safe: String = trimmed
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect();
    if safe.trim().is_empty() {
        "This PC".to_string()
    } else {
        safe.trim().to_string()
    }
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::{normalize_device_name, AppSettings, SettingsStore};
    use std::fs;

    #[test]
    fn normalizes_empty_and_control_names() {
        assert_eq!(normalize_device_name("\n\t"), "This PC");
        assert_eq!(normalize_device_name(" Desk\u{0000} PC "), "Desk PC");
        assert!(normalize_device_name(&"x".repeat(100)).len() <= 64);
    }

    #[test]
    fn loads_legacy_settings_with_receive_defaults() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-legacy-settings-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(root.clone());
        store.ensure_root().unwrap();
        fs::write(
            store.settings_path(),
            r#"{"version":1,"deviceName":"Legacy PC","receiveDirectory":"/tmp/zapdrop","selectedInterface":null,"advertiseOnStartup":true}"#,
        )
        .unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.always_ask_before_receive);
        assert_eq!(loaded.default_conflict_policy, "rename");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persists_settings_atomically() {
        let root = std::env::temp_dir().join(format!("zapdrop-settings-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(root.clone());
        let mut settings = AppSettings::default();
        settings.device_name = "Test PC".to_string();
        store.save(&settings).expect("save settings");
        assert_eq!(store.load().expect("load settings").device_name, "Test PC");
        fs::remove_dir_all(root).expect("remove test data");
    }
}
