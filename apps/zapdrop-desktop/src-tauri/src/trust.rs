use crate::{
    pairing::PairingOutcome,
    settings::{atomic_write_json, SettingsStore},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPeer {
    pub version: u32,
    pub peer_id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub endpoint: String,
}

#[derive(Debug, Clone)]
pub struct TrustedPeerStore {
    path: std::path::PathBuf,
    peers: Arc<Mutex<Vec<TrustedPeer>>>,
}

impl TrustedPeer {
    pub fn from_pairing(outcome: &PairingOutcome) -> Self {
        let now = epoch_seconds();
        Self {
            version: 1,
            peer_id: outcome.peer_id.clone(),
            name: outcome.name.clone(),
            public_key: outcome.public_key.clone(),
            fingerprint: outcome.fingerprint.clone(),
            first_seen: now,
            last_seen: now,
            endpoint: outcome.endpoint.clone(),
        }
    }
}

impl TrustedPeerStore {
    pub fn load(store: &SettingsStore) -> io::Result<Self> {
        store.ensure_root()?;
        let path = store.root().join("trusted-peers.json");
        let peers = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice::<Vec<TrustedPeer>>(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid trusted peers: {error}"),
                )
            })?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            peers: Arc::new(Mutex::new(peers)),
        })
    }

    pub fn list(&self) -> Vec<TrustedPeer> {
        self.peers.lock().expect("trusted peers poisoned").clone()
    }

    pub fn find_by_id(&self, peer_id: &str) -> Option<TrustedPeer> {
        self.peers
            .lock()
            .expect("trusted peers poisoned")
            .iter()
            .find(|peer| peer.peer_id == peer_id)
            .cloned()
    }

    pub fn matches_exact(
        &self,
        peer_id: &str,
        public_key: Option<&str>,
        fingerprint: Option<&str>,
    ) -> bool {
        let Some(public_key) = public_key else {
            return false;
        };
        let Some(fingerprint) = fingerprint else {
            return false;
        };
        self.peers
            .lock()
            .expect("trusted peers poisoned")
            .iter()
            .any(|peer| {
                peer.peer_id == peer_id
                    && peer.public_key == public_key
                    && peer.fingerprint == fingerprint
            })
    }

    pub fn contains(&self, peer_id: &str, fingerprint: Option<&str>) -> bool {
        self.peers
            .lock()
            .expect("trusted peers poisoned")
            .iter()
            .any(|peer| {
                peer.peer_id == peer_id
                    && fingerprint
                        .map(|value| value == peer.fingerprint)
                        .unwrap_or(false)
            })
    }

    pub fn upsert(&self, peer: TrustedPeer) -> io::Result<()> {
        let mut peers = self.peers.lock().expect("trusted peers poisoned");
        if let Some(existing) = peers
            .iter_mut()
            .find(|existing| existing.peer_id == peer.peer_id)
        {
            if existing.public_key != peer.public_key || existing.fingerprint != peer.fingerprint {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "trusted peer key changed; revoke and pair again explicitly",
                ));
            }
            existing.name = peer.name;
            existing.last_seen = peer.last_seen;
            existing.endpoint = peer.endpoint;
        } else if peers.iter().any(|existing| {
            existing.fingerprint == peer.fingerprint || existing.public_key == peer.public_key
        }) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "public key or fingerprint is already bound to another trusted peer",
            ));
        } else {
            peers.push(peer);
        }
        atomic_write_json(&self.path, &*peers)
    }

    pub fn remove(&self, peer_id: &str) -> io::Result<bool> {
        let mut peers = self.peers.lock().expect("trusted peers poisoned");
        let before = peers.len();
        peers.retain(|peer| peer.peer_id != peer_id);
        if peers.len() != before {
            atomic_write_json(&self.path, &*peers)?;
            return Ok(true);
        }
        Ok(false)
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{TrustedPeer, TrustedPeerStore};
    use crate::settings::SettingsStore;
    use std::fs;

    #[test]
    fn persists_updates_and_revokes_trusted_peer() {
        let root = std::env::temp_dir().join(format!("zapdrop-trust-{}", uuid::Uuid::new_v4()));
        let settings = SettingsStore::new(root.clone());
        let trust = TrustedPeerStore::load(&settings).expect("load trust store");
        trust
            .upsert(TrustedPeer {
                version: 1,
                peer_id: "peer-1".into(),
                name: "Studio PC".into(),
                public_key: "public-key".into(),
                fingerprint: "aa:bb".into(),
                first_seen: 1,
                last_seen: 2,
                endpoint: "192.168.1.20:53317".into(),
            })
            .expect("save peer");
        let reloaded = TrustedPeerStore::load(&settings).expect("reload trust store");
        assert!(reloaded.contains("peer-1", Some("aa:bb")));
        assert!(reloaded.matches_exact("peer-1", Some("public-key"), Some("aa:bb"),));
        assert!(!reloaded.matches_exact("peer-1", Some("attacker-key"), Some("aa:bb"),));
        reloaded
            .upsert(TrustedPeer {
                version: 1,
                peer_id: "peer-1".into(),
                name: "Studio PC".into(),
                public_key: "public-key".into(),
                fingerprint: "aa:bb".into(),
                first_seen: 1,
                last_seen: 3,
                endpoint: "192.168.1.21:53317".into(),
            })
            .expect("update peer");
        assert_eq!(reloaded.list()[0].endpoint, "192.168.1.21:53317");
        assert!(reloaded
            .upsert(TrustedPeer {
                version: 1,
                peer_id: "peer-1".into(),
                name: "Attacker".into(),
                public_key: "new-key".into(),
                fingerprint: "cc:dd".into(),
                first_seen: 1,
                last_seen: 4,
                endpoint: "192.168.1.99:53317".into(),
            })
            .is_err());
        assert!(reloaded.remove("peer-1").expect("remove peer"));
        assert!(!reloaded.contains("peer-1", Some("aa:bb")));
        fs::remove_dir_all(root).expect("remove test data");
    }
}
