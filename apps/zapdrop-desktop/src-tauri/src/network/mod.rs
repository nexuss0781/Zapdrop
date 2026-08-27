use crate::{
    discovery::{DiscoveryService, NetworkDiagnostics, PeerRecord},
    identity::DeviceIdentity,
    settings::{default_data_dir, AppSettings, SettingsStore},
};
use std::{collections::HashMap, io};
use tauri::AppHandle;

pub struct RuntimeState {
    pub store: SettingsStore,
    pub settings: AppSettings,
    pub identity: DeviceIdentity,
    pub discovery: Option<DiscoveryService>,
    pub discovery_error: Option<String>,
    pub manual_peers: HashMap<String, PeerRecord>,
}

impl RuntimeState {
    pub fn boot(app: AppHandle) -> io::Result<Self> {
        let store = SettingsStore::new(default_data_dir());
        let settings = store.load()?;
        let identity = DeviceIdentity::load_or_create(&store)?;
        let (discovery, discovery_error) = if settings.advertise_on_startup {
            match DiscoveryService::start(
                app.clone(),
                &identity.device_id,
                &settings.device_name,
                &identity.fingerprint,
            ) {
                Ok(service) => (Some(service), None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, Some("Discovery is disabled in Settings".to_string()))
        };
        Ok(Self {
            store,
            settings,
            identity,
            discovery,
            discovery_error,
            manual_peers: HashMap::new(),
        })
    }

    pub fn restart_discovery(&mut self, app: &AppHandle) {
        self.stop_discovery();
        if !self.settings.advertise_on_startup {
            self.discovery_error = Some("Discovery is disabled in Settings".to_string());
            return;
        }
        match DiscoveryService::start(
            app.clone(),
            &self.identity.device_id,
            &self.settings.device_name,
            &self.identity.fingerprint,
        ) {
            Ok(service) => {
                self.discovery = Some(service);
                self.discovery_error = None;
            }
            Err(error) => {
                self.discovery = None;
                self.discovery_error = Some(error.to_string());
            }
        }
    }

    pub fn stop_discovery(&mut self) {
        if let Some(mut discovery) = self.discovery.take() {
            discovery.stop();
        }
    }

    pub fn peers(&self) -> Vec<PeerRecord> {
        let mut peers = self.manual_peers.values().cloned().collect::<Vec<_>>();
        if let Some(discovery) = &self.discovery {
            peers.extend(discovery.registry.list());
        }
        peers.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        peers
    }

    pub fn diagnostics(&self) -> NetworkDiagnostics {
        self.discovery
            .as_ref()
            .map(DiscoveryService::diagnostics)
            .unwrap_or_else(|| NetworkDiagnostics {
                local_ip: "Unavailable".to_string(),
                listening_port: 0,
                service_type: crate::discovery::SERVICE_TYPE.to_string(),
                mdns_available: false,
                manual_fallback_available: true,
                interface_note: self
                    .discovery_error
                    .clone()
                    .unwrap_or_else(|| "Discovery is not running".to_string()),
            })
    }
}

impl Drop for RuntimeState {
    fn drop(&mut self) {
        self.stop_discovery();
    }
}
