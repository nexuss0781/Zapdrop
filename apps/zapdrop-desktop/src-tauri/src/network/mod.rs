use crate::{
    discovery::{DiscoveryService, NetworkDiagnostics, PeerRecord},
    history::HistoryStore,
    identity::DeviceIdentity,
    pairing::{PairingCoordinator, PairingOutcome, PairingRequestView},
    settings::{default_data_dir, AppSettings, SettingsStore},
    transfer::{ReceiveOfferCoordinator, TransferManager, TransferRequest, TransferServerContext},
    trust::{TrustedPeer, TrustedPeerStore},
};
use std::{collections::HashMap, io};
use tauri::AppHandle;

pub struct RuntimeState {
    pub store: SettingsStore,
    pub settings: AppSettings,
    pub identity: DeviceIdentity,
    pub discovery: Option<DiscoveryService>,
    pub pairing: Option<PairingCoordinator>,
    pub trust: TrustedPeerStore,
    pub transfer: TransferManager,
    pub history: HistoryStore,
    pub offers: ReceiveOfferCoordinator,
    pub discovery_error: Option<String>,
    pub pairing_error: Option<String>,
    pub manual_peers: HashMap<String, PeerRecord>,
}

impl RuntimeState {
    pub fn boot(app: AppHandle) -> io::Result<Self> {
        let store = SettingsStore::new(default_data_dir());
        let settings = store.load()?;
        let identity = DeviceIdentity::load_or_create(&store)?;
        let trust = TrustedPeerStore::load(&store)?;
        let history = HistoryStore::load(&store)?;
        let mut runtime = Self {
            store,
            settings,
            identity,
            discovery: None,
            pairing: None,
            trust,
            transfer: TransferManager::new(history.clone()),
            history,
            offers: ReceiveOfferCoordinator::new(),
            discovery_error: None,
            pairing_error: None,
            manual_peers: HashMap::new(),
        };
        runtime.restart_discovery(&app);
        Ok(runtime)
    }

    pub fn restart_discovery(&mut self, app: &AppHandle) {
        self.stop_pairing();
        self.stop_discovery();
        self.discovery_error = None;
        self.pairing_error = None;
        if !self.settings.advertise_on_startup {
            self.discovery_error = Some("Discovery is disabled in Settings".to_string());
            self.pairing_error = Some("Pairing listener is disabled in Settings".to_string());
            return;
        }
        match DiscoveryService::start(
            app.clone(),
            &self.identity.device_id,
            &self.settings.device_name,
            &self.identity.fingerprint,
            &self.identity.public_key,
        ) {
            Ok(service) => {
                let pairing = service.pairing_listener().and_then(|listener| {
                    PairingCoordinator::start(
                        listener,
                        app.clone(),
                        Some(self.transfer_context(app)),
                    )
                });
                match pairing {
                    Ok(pairing) => self.pairing = Some(pairing),
                    Err(error) => self.pairing_error = Some(error.to_string()),
                }
                self.discovery = Some(service);
            }
            Err(error) => {
                self.discovery = None;
                self.discovery_error = Some(error.to_string());
                self.pairing_error =
                    Some("Pairing listener unavailable without a local endpoint".to_string());
            }
        }
    }

    pub fn transfer_context(&self, app: &AppHandle) -> TransferServerContext {
        TransferServerContext {
            app: Some(app.clone()),
            identity: self.identity.clone(),
            store: self.store.clone(),
            trust: self.trust.clone(),
            device_name: self.settings.device_name.clone(),
            receive_directory: self.settings.receive_directory.clone(),
            cancelled: self.transfer.cancelled.clone(),
            history: self.history.clone(),
            offers: self.offers.clone(),
            always_ask_before_receive: self.settings.always_ask_before_receive,
            default_conflict_policy: self.settings.default_conflict_policy.clone(),
        }
    }

    pub fn start_transfer(&self, app: &AppHandle, request: TransferRequest) -> io::Result<String> {
        self.transfer.start_parallel(
            app.clone(),
            self.identity.clone(),
            self.store.clone(),
            self.settings.device_name.clone(),
            self.peers(),
            request,
        )
    }

    pub fn cancel_transfer(&self, transfer_id: &str) {
        self.transfer.cancel(transfer_id);
    }

    pub fn stop_pairing(&mut self) {
        if let Some(mut pairing) = self.pairing.take() {
            pairing.stop();
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
        for peer in &mut peers {
            peer.trusted = self.trust.contains(&peer.id, peer.fingerprint.as_deref());
            if peer.trusted && peer.status == "online" {
                peer.status = "trusted".to_string();
            }
        }
        peers.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        peers
    }

    pub fn pending_transfers(&self) -> Vec<crate::transfer::IncomingTransferOffer> {
        self.offers.list(&self.settings.receive_directory)
    }

    pub fn pending_pairings(&self) -> Vec<PairingRequestView> {
        self.pairing
            .as_ref()
            .map(PairingCoordinator::pending)
            .unwrap_or_default()
    }

    pub fn trusted_peers(&self) -> Vec<TrustedPeer> {
        self.trust.list()
    }

    pub fn diagnostics(&self) -> NetworkDiagnostics {
        let mut diagnostics = self
            .discovery
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
            });
        if let Some(error) = &self.pairing_error {
            diagnostics.interface_note = format!("{}; {}", diagnostics.interface_note, error);
        }
        diagnostics
    }

    pub fn pairing_port(&self) -> u16 {
        self.pairing
            .as_ref()
            .map(|pairing| pairing.port)
            .or_else(|| {
                self.discovery
                    .as_ref()
                    .map(|discovery| discovery.diagnostics().listening_port)
            })
            .unwrap_or(0)
    }

    pub fn pair_outbound(&self, peer_id: &str) -> io::Result<PairingOutcome> {
        let peer = self
            .peers()
            .into_iter()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "peer is no longer available")
            })?;
        let outcome = crate::pairing::request_pairing(
            &peer.endpoint,
            peer.fingerprint.as_deref(),
            peer.public_key.as_deref(),
            &self.identity,
            &self.store,
            &self.settings.device_name,
        )?;
        Ok(outcome)
    }
}

impl Drop for RuntimeState {
    fn drop(&mut self) {
        self.stop_pairing();
        self.stop_discovery();
    }
}
