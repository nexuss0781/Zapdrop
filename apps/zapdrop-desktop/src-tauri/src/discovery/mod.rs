use mdns_sd::{ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter};

pub const SERVICE_TYPE: &str = "_zapdrop._tcp.local.";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerRecord {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: Option<String>,
    pub endpoint: String,
    pub port: u16,
    pub status: String,
    pub discovered_via: String,
    pub last_seen: u64,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiagnostics {
    pub local_ip: String,
    pub listening_port: u16,
    pub service_type: String,
    pub mdns_available: bool,
    pub manual_fallback_available: bool,
    pub interface_note: String,
}

#[derive(Debug, Clone)]
pub struct PeerRegistry {
    peers: Arc<Mutex<HashMap<String, PeerRecord>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn list(&self) -> Vec<PeerRecord> {
        let mut peers: Vec<_> = self
            .peers
            .lock()
            .expect("peer registry poisoned")
            .values()
            .cloned()
            .collect();
        peers.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        peers
    }

    pub fn upsert(&self, peer: PeerRecord) {
        self.peers
            .lock()
            .expect("peer registry poisoned")
            .insert(peer.id.clone(), peer);
    }

    pub fn mark_removed(&self, fullname: &str) -> Option<PeerRecord> {
        let id = self
            .peers
            .lock()
            .expect("peer registry poisoned")
            .iter()
            .find(|(_, peer)| peer.endpoint == fullname)
            .map(|(id, _)| id.clone());
        id.and_then(|id| {
            self.peers
                .lock()
                .expect("peer registry poisoned")
                .remove(&id)
        })
    }
}

pub struct DiscoveryService {
    mdns: Arc<ServiceDaemon>,
    stop: Arc<AtomicBool>,
    listener: Option<std::net::TcpListener>,
    worker: Option<JoinHandle<()>>,
    diagnostics: NetworkDiagnostics,
    pub registry: PeerRegistry,
}

impl DiscoveryService {
    pub fn start(
        app: AppHandle,
        device_id: &str,
        device_name: &str,
        fingerprint: &str,
    ) -> io::Result<Self> {
        let local_ip = choose_local_ip()?;
        let listener = std::net::TcpListener::bind(SocketAddr::new(local_ip, 0))?;
        let port = listener.local_addr()?.port();
        let mdns = Arc::new(
            ServiceDaemon::new()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?,
        );
        let registry = PeerRegistry::new();
        let instance_name = service_instance_name(device_name, device_id);
        let hostname = format!("zapdrop-{}.local.", &device_id[..8.min(device_id.len())]);
        let properties = vec![
            ("v", "1".to_string()),
            ("id", device_id.to_string()),
            ("name", device_name.to_string()),
            ("platform", std::env::consts::OS.to_string()),
            ("fingerprint", fingerprint.to_string()),
            (
                "caps",
                "folders,multi-recipient,manual-endpoint".to_string(),
            ),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            local_ip.to_string(),
            port,
            &properties[..],
        )
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        mdns.register(service)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        let receiver = mdns
            .browse(SERVICE_TYPE)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_registry = registry.clone();
        let worker_app = app.clone();
        let own_id = device_id.to_string();
        let worker = thread::Builder::new()
            .name("zapdrop-mdns".to_string())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(Duration::from_millis(750)) {
                        Ok(ServiceEvent::ServiceResolved(resolved)) => {
                            if let Some(peer) = peer_from_resolved(&resolved, &own_id) {
                                worker_registry.upsert(peer.clone());
                                let _ = worker_app.emit("peer-updated", peer);
                            }
                        }
                        Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                            if let Some(peer) = worker_registry.mark_removed(&fullname) {
                                let _ = worker_app.emit("peer-removed", peer);
                            }
                        }
                        Ok(_) => {}
                        Err(_) if worker_stop.load(Ordering::Relaxed) => break,
                        Err(_) => {}
                    }
                }
            })
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;

        Ok(Self {
            mdns,
            stop,
            listener: Some(listener),
            worker: Some(worker),
            diagnostics: NetworkDiagnostics {
                local_ip: local_ip.to_string(),
                listening_port: port,
                service_type: SERVICE_TYPE.to_string(),
                mdns_available: true,
                manual_fallback_available: true,
                interface_note: "Advertising on the selected private/local interface".to_string(),
            },
            registry,
        })
    }

    pub fn diagnostics(&self) -> NetworkDiagnostics {
        self.diagnostics.clone()
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.mdns.shutdown();
        let _ = self.listener.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn choose_local_ip() -> io::Result<IpAddr> {
    let ip = local_ip_address::local_ip()
        .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error.to_string()))?;
    if is_local_network_ip(ip) {
        Ok(ip)
    } else {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no private/local network interface found",
        ))
    }
}

pub fn is_local_network_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

pub fn parse_manual_endpoint(value: &str) -> io::Result<SocketAddr> {
    let endpoint = value.trim().parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint must be ip:port: {error}"),
        )
    })?;
    if !is_local_network_ip(endpoint.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "endpoint must be on a private or local network",
        ));
    }
    Ok(endpoint)
}

pub fn manual_peer(endpoint: &str) -> io::Result<PeerRecord> {
    let socket = parse_manual_endpoint(endpoint)?;
    let now = epoch_seconds();
    Ok(PeerRecord {
        id: format!("manual-{}", endpoint.replace([':', '[', ']'], "-")),
        name: format!("Manual peer {}", endpoint),
        platform: "unknown".to_string(),
        fingerprint: None,
        endpoint: endpoint.to_string(),
        port: socket.port(),
        status: "manual".to_string(),
        discovered_via: "manual".to_string(),
        last_seen: now,
        trusted: false,
    })
}

fn peer_from_resolved(resolved: &mdns_sd::ResolvedService, own_id: &str) -> Option<PeerRecord> {
    let id = resolved.get_property_val_str("id")?.to_string();
    if id.is_empty() || id == own_id || !resolved.is_valid() {
        return None;
    }
    let address = resolved.addresses.iter().find_map(|scoped| {
        let ip = match scoped {
            ScopedIp::V4(value) => IpAddr::V4(*value.addr()),
            ScopedIp::V6(value) => IpAddr::V6(*value.addr()),
            _ => return None,
        };
        is_local_network_ip(ip).then_some(ip)
    })?;
    let name = resolved
        .get_property_val_str("name")
        .unwrap_or("Nearby PC")
        .to_string();
    let platform = resolved
        .get_property_val_str("platform")
        .unwrap_or("unknown")
        .to_string();
    let fingerprint = resolved
        .get_property_val_str("fingerprint")
        .map(ToString::to_string);
    Some(PeerRecord {
        id,
        name,
        platform,
        fingerprint,
        endpoint: SocketAddr::new(address, resolved.port).to_string(),
        port: resolved.port,
        status: "online".to_string(),
        discovered_via: "mdns".to_string(),
        last_seen: epoch_seconds(),
        trusted: false,
    })
}

fn service_instance_name(device_name: &str, device_id: &str) -> String {
    let cleaned: String = device_name
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
        })
        .collect();
    let label = if cleaned.is_empty() {
        "Zapdrop-PC"
    } else {
        cleaned.as_str()
    };
    format!(
        "{}-{}",
        &label[..label.len().min(40)],
        &device_id[..8.min(device_id.len())]
    )
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{is_local_network_ip, parse_manual_endpoint};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn accepts_private_manual_endpoints() {
        let endpoint = parse_manual_endpoint("192.168.1.20:53317").expect("private endpoint");
        assert_eq!(endpoint.port(), 53317);
        assert!(is_local_network_ip(endpoint.ip()));
    }

    #[test]
    fn rejects_public_manual_endpoints() {
        assert!(parse_manual_endpoint("8.8.8.8:53").is_err());
        assert!(!is_local_network_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
