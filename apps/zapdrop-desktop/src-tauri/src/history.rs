use crate::settings::{atomic_write_json, SettingsStore};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io,
    sync::{Arc, Mutex},
};

const MAX_HISTORY_ENTRIES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferHistoryEntry {
    pub id: String,
    pub transfer_id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub direction: String,
    pub peer_id: String,
    pub peer_name: String,
    pub status: String,
    pub source_names: Vec<String>,
    pub items: usize,
    pub total_bytes: u64,
    pub bytes_done: u64,
    pub conflict_policy: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    path: std::path::PathBuf,
    entries: Arc<Mutex<Vec<TransferHistoryEntry>>>,
}

impl HistoryStore {
    pub fn load(settings: &SettingsStore) -> io::Result<Self> {
        settings.ensure_root()?;
        let path = settings.root().join("transfer-history.json");
        let mut entries = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice::<Vec<TransferHistoryEntry>>(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid transfer history: {error}"),
                )
            })?
        } else {
            Vec::new()
        };
        entries.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        entries.truncate(MAX_HISTORY_ENTRIES);
        Ok(Self {
            path,
            entries: Arc::new(Mutex::new(entries)),
        })
    }

    pub fn list(&self) -> Vec<TransferHistoryEntry> {
        self.entries.lock().expect("history store poisoned").clone()
    }

    pub fn record(&self, mut entry: TransferHistoryEntry) -> io::Result<()> {
        let mut entries = self.entries.lock().expect("history store poisoned");
        if let Some(existing) = entries.iter_mut().find(|existing| existing.id == entry.id) {
            *existing = entry;
        } else {
            entry.started_at = entry.started_at.max(1);
            entries.push(entry);
        }
        entries.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        entries.truncate(MAX_HISTORY_ENTRIES);
        atomic_write_json(&self.path, &*entries)
    }

    pub fn clear(&self) -> io::Result<()> {
        let mut entries = self.entries.lock().expect("history store poisoned");
        entries.clear();
        atomic_write_json(&self.path, &*entries)
    }
}

#[cfg(test)]
pub fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{epoch_seconds, HistoryStore, TransferHistoryEntry};
    use crate::settings::SettingsStore;
    use std::fs;

    #[test]
    fn persists_updates_and_clears_history() {
        let root = std::env::temp_dir().join(format!("zapdrop-history-{}", uuid::Uuid::new_v4()));
        let settings = SettingsStore::new(root.clone());
        let store = HistoryStore::load(&settings).unwrap();
        store
            .record(TransferHistoryEntry {
                id: "h1".into(),
                transfer_id: "t1".into(),
                parent_id: None,
                direction: "send".into(),
                peer_id: "p1".into(),
                peer_name: "Desk".into(),
                status: "completed".into(),
                source_names: vec!["file.txt".into()],
                items: 1,
                total_bytes: 5,
                bytes_done: 5,
                conflict_policy: "rename".into(),
                started_at: epoch_seconds(),
                finished_at: Some(epoch_seconds()),
                error: None,
            })
            .unwrap();
        assert_eq!(HistoryStore::load(&settings).unwrap().list().len(), 1);
        store.clear().unwrap();
        assert!(store.list().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
