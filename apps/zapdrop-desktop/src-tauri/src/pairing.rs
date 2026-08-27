use crate::{
    identity::DeviceIdentity,
    settings::SettingsStore,
    transfer::{self, TransferServerContext},
    trust::TrustedPeer,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

const PROTOCOL_VERSION: u32 = 1;
const REQUEST_KIND: &str = "zapdrop_pair_request";
const RESPONSE_KIND: &str = "zapdrop_pair_response";
const MAX_LINE_BYTES: usize = 64 * 1024;
const CLOCK_SKEW_SECONDS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub kind: String,
    pub version: u32,
    pub request_id: String,
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub public_key: String,
    pub fingerprint: String,
    pub nonce: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingResponse {
    pub kind: String,
    pub version: u32,
    pub request_id: String,
    pub status: String,
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub public_key: String,
    pub fingerprint: String,
    pub reason: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequestView {
    pub request_id: String,
    pub peer_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub fingerprint: String,
    pub endpoint: String,
    pub received_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOutcome {
    pub request_id: String,
    pub status: String,
    pub peer_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub fingerprint: String,
    pub endpoint: String,
    pub reason: Option<String>,
}

impl PairingOutcome {
    pub fn accepted(peer: &TrustedPeer) -> Self {
        Self {
            request_id: String::new(),
            status: "accepted".to_string(),
            peer_id: peer.peer_id.clone(),
            name: peer.name.clone(),
            platform: "unknown".to_string(),
            public_key: peer.public_key.clone(),
            fingerprint: peer.fingerprint.clone(),
            endpoint: peer.endpoint.clone(),
            reason: None,
        }
    }
}

struct PendingPairing {
    request: PairingRequest,
    endpoint: String,
    stream: TcpStream,
}

#[derive(Clone)]
struct PairingContext {
    app: AppHandle,
    transfer: Option<TransferServerContext>,
}

pub struct PairingCoordinator {
    pending: Arc<Mutex<HashMap<String, PendingPairing>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    pub port: u16,
}

impl PairingCoordinator {
    pub fn start(
        listener: TcpListener,
        app: AppHandle,
        transfer: Option<TransferServerContext>,
    ) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_pending = Arc::clone(&pending);
        let worker_stop = Arc::clone(&stop);
        let context = PairingContext { app, transfer };
        let worker = thread::Builder::new()
            .name("zapdrop-pairing-listener".to_string())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, address)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(12)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(12)));
                            let pending = Arc::clone(&worker_pending);
                            let context = context.clone();
                            thread::spawn(move || {
                                let first: serde_json::Value = match read_json_line(&stream) {
                                    Ok(value) => value,
                                    Err(error) => { let _ = write_json_line(&stream, &serde_json::json!({"kind":"zapdrop_protocol_error","error":error.to_string()})); return; }
                                };
                                if transfer::is_transfer_hello(&first) {
                                    if let Some(transfer) = context.transfer.clone() {
                                        transfer::handle_incoming(stream, address, first, transfer);
                                    } else {
                                        let _ = write_json_line(&stream, &serde_json::json!({"kind":"zapdrop_transfer_error","status":"failed","reason":"transfer service is unavailable"}));
                                    }
                                } else {
                                    handle_incoming(stream, address, first, pending, context);
                                }
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(100))
                        }
                        Err(_) => thread::sleep(Duration::from_millis(250)),
                    }
                }
            })
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        Ok(Self {
            pending,
            stop,
            worker: Some(worker),
            port,
        })
    }

    pub fn pending(&self) -> Vec<PairingRequestView> {
        self.pending
            .lock()
            .expect("pending pairings poisoned")
            .values()
            .map(|pending| PairingRequestView {
                request_id: pending.request.request_id.clone(),
                peer_id: pending.request.device_id.clone(),
                name: pending.request.device_name.clone(),
                platform: pending.request.platform.clone(),
                public_key: pending.request.public_key.clone(),
                fingerprint: pending.request.fingerprint.clone(),
                endpoint: pending.endpoint.clone(),
                received_at: pending.request.timestamp,
            })
            .collect()
    }

    pub fn accept(
        &self,
        request_id: &str,
        identity: &DeviceIdentity,
        store: &SettingsStore,
        device_name: &str,
    ) -> io::Result<TrustedPeer> {
        let pending = self
            .pending
            .lock()
            .expect("pending pairings poisoned")
            .remove(request_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "pairing request expired"))?;
        let trusted = trusted_peer(&pending.request, pending.endpoint.clone());
        let response = signed_response(
            identity,
            store,
            device_name,
            &pending.request,
            "accepted",
            None,
        )?;
        write_json_line(&pending.stream, &response)?;
        Ok(trusted)
    }

    pub fn reject(
        &self,
        request_id: &str,
        identity: &DeviceIdentity,
        store: &SettingsStore,
        device_name: &str,
        reason: String,
    ) -> io::Result<()> {
        let pending = self
            .pending
            .lock()
            .expect("pending pairings poisoned")
            .remove(request_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "pairing request expired"))?;
        let response = signed_response(
            identity,
            store,
            device_name,
            &pending.request,
            "rejected",
            Some(reason),
        )?;
        write_json_line(&pending.stream, &response)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.pending
            .lock()
            .expect("pending pairings poisoned")
            .clear();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for PairingCoordinator {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn request_pairing(
    endpoint: &str,
    expected_fingerprint: Option<&str>,
    expected_public_key: Option<&str>,
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
) -> io::Result<PairingOutcome> {
    let address: SocketAddr = endpoint.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid pairing endpoint: {error}"),
        )
    })?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let request = signed_request(identity, store, device_name)?;
    write_json_line(&stream, &request)?;
    let response: PairingResponse = read_json_line(&stream)?;
    validate_response(
        &response,
        &request,
        expected_fingerprint,
        expected_public_key,
    )?;
    Ok(PairingOutcome {
        request_id: response.request_id,
        status: response.status,
        peer_id: response.device_id,
        name: response.device_name,
        platform: response.platform,
        public_key: response.public_key,
        fingerprint: response.fingerprint,
        endpoint: endpoint.to_string(),
        reason: response.reason,
    })
}

fn handle_incoming(
    mut stream: TcpStream,
    address: SocketAddr,
    first: serde_json::Value,
    pending: Arc<Mutex<HashMap<String, PendingPairing>>>,
    context: PairingContext,
) {
    let request: PairingRequest = match serde_json::from_value(first)
        .map_err(invalid_data)
        .and_then(|request| validate_request(&request).map(|()| request))
    {
        Ok(request) => request,
        Err(error) => {
            let _ = stream.write_all(format!("pairing error: {error}\n").as_bytes());
            return;
        }
    };
    let request_view = PairingRequestView {
        request_id: request.request_id.clone(),
        peer_id: request.device_id.clone(),
        name: request.device_name.clone(),
        platform: request.platform.clone(),
        public_key: request.public_key.clone(),
        fingerprint: request.fingerprint.clone(),
        endpoint: address.to_string(),
        received_at: request.timestamp,
    };
    pending.lock().expect("pending pairings poisoned").insert(
        request.request_id.clone(),
        PendingPairing {
            request,
            endpoint: address.to_string(),
            stream,
        },
    );
    let _ = context.app.emit("pairing-request", request_view);
}

fn signed_request(
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
) -> io::Result<PairingRequest> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut request = PairingRequest {
        kind: REQUEST_KIND.to_string(),
        version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        device_id: identity.device_id.clone(),
        device_name: device_name.to_string(),
        platform: std::env::consts::OS.to_string(),
        public_key: identity.public_key.clone(),
        fingerprint: identity.fingerprint.clone(),
        nonce: BASE64.encode(nonce),
        timestamp: epoch_seconds(),
        signature: String::new(),
    };
    let key = identity.signing_key(store)?;
    request.signature = BASE64.encode(key.sign(signing_payload(&request).as_bytes()).to_bytes());
    Ok(request)
}

fn signed_response(
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
    request: &PairingRequest,
    status: &str,
    reason: Option<String>,
) -> io::Result<PairingResponse> {
    let mut response = PairingResponse {
        kind: RESPONSE_KIND.to_string(),
        version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        status: status.to_string(),
        device_id: identity.device_id.clone(),
        device_name: device_name.to_string(),
        platform: std::env::consts::OS.to_string(),
        public_key: identity.public_key.clone(),
        fingerprint: identity.fingerprint.clone(),
        reason,
        signature: String::new(),
    };
    let key = identity.signing_key(store)?;
    response.signature = BASE64.encode(key.sign(response_payload(&response).as_bytes()).to_bytes());
    Ok(response)
}

fn validate_request(request: &PairingRequest) -> io::Result<()> {
    if request.kind != REQUEST_KIND
        || request.version != PROTOCOL_VERSION
        || request.request_id.is_empty()
        || request.device_id.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported pairing request",
        ));
    }
    validate_timestamp(request.timestamp)?;
    verify_public_key_and_signature(
        &request.public_key,
        &request.fingerprint,
        &request.signature,
        signing_payload(request).as_bytes(),
    )
}

fn validate_response(
    response: &PairingResponse,
    request: &PairingRequest,
    expected_fingerprint: Option<&str>,
    expected_public_key: Option<&str>,
) -> io::Result<()> {
    if response.kind != RESPONSE_KIND
        || response.version != PROTOCOL_VERSION
        || response.request_id != request.request_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported pairing response",
        ));
    }
    if let Some(expected) = expected_fingerprint {
        if expected != response.fingerprint {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "response fingerprint does not match discovery",
            ));
        }
    }
    if let Some(expected) = expected_public_key {
        if expected != response.public_key {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "response public key does not match discovery",
            ));
        }
    }
    verify_public_key_and_signature(
        &response.public_key,
        &response.fingerprint,
        &response.signature,
        response_payload(response).as_bytes(),
    )
}

fn verify_public_key_and_signature(
    public_key: &str,
    expected_fingerprint: &str,
    signature: &str,
    payload: &[u8],
) -> io::Result<()> {
    let public_bytes: [u8; 32] = BASE64
        .decode(public_key)
        .map_err(invalid_data)?
        .try_into()
        .map_err(|_| invalid_data("public key must contain 32 bytes"))?;
    if public_key_fingerprint(&public_bytes) != expected_fingerprint {
        return Err(invalid_data("public key fingerprint mismatch"));
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|error| invalid_data(error.to_string()))?;
    let signature_bytes = BASE64.decode(signature).map_err(invalid_data)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|error| invalid_data(error.to_string()))?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
}

fn signing_payload(request: &PairingRequest) -> String {
    format!(
        "zapdrop-pair-request-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        request.kind,
        request.version,
        request.request_id,
        request.device_id,
        request.device_name,
        request.platform,
        request.public_key,
        request.fingerprint,
        request.nonce,
        request.timestamp
    )
}

fn response_payload(response: &PairingResponse) -> String {
    format!(
        "zapdrop-pair-response-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        response.kind,
        response.version,
        response.request_id,
        response.status,
        response.device_id,
        response.device_name,
        response.platform,
        response.public_key,
        response.fingerprint
    )
}

fn trusted_peer(request: &PairingRequest, endpoint: String) -> TrustedPeer {
    let now = epoch_seconds();
    TrustedPeer {
        version: 1,
        peer_id: request.device_id.clone(),
        name: request.device_name.clone(),
        public_key: request.public_key.clone(),
        fingerprint: request.fingerprint.clone(),
        endpoint,
        first_seen: now,
        last_seen: now,
    }
}

fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    digest
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn validate_timestamp(timestamp: u64) -> io::Result<()> {
    let now = epoch_seconds();
    if timestamp.abs_diff(now) > CLOCK_SKEW_SECONDS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pairing request expired",
        ));
    }
    Ok(())
}

pub(crate) fn write_json_line<T: Serialize>(stream: &TcpStream, value: &T) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut bytes = serde_json::to_vec(value).map_err(invalid_data)?;
    bytes.push(b'\n');
    writer.write_all(&bytes)
}

pub(crate) fn read_json_line<T: for<'de> Deserialize<'de>>(stream: &TcpStream) -> io::Result<T> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(invalid_data("pairing frame too large"));
    }
    serde_json::from_slice(line.trim_ascii()).map_err(invalid_data)
}

fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        public_key_fingerprint, response_payload, signed_request, validate_request, PairingResponse,
    };
    use crate::{identity::DeviceIdentity, settings::SettingsStore};
    use std::fs;

    #[test]
    fn signed_request_has_verifiable_identity_material() {
        let root = std::env::temp_dir().join(format!("zapdrop-pairing-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(root.clone());
        let identity = DeviceIdentity::load_or_create(&store).expect("identity");
        let request = signed_request(&identity, &store, "Test PC").expect("request");
        assert_eq!(request.fingerprint, identity.fingerprint);
        validate_request(&request).expect("request verifies");
        fs::remove_dir_all(root).expect("remove test data");
    }

    #[test]
    fn response_payload_excludes_signature() {
        let response = PairingResponse {
            kind: "zapdrop_pair_response".into(),
            version: 1,
            request_id: "r".into(),
            status: "rejected".into(),
            device_id: "d".into(),
            device_name: "PC".into(),
            platform: "linux".into(),
            public_key: "p".into(),
            fingerprint: "f".into(),
            reason: Some("no".into()),
            signature: "different".into(),
        };
        assert_eq!(
            response_payload(&response),
            response_payload(&PairingResponse {
                signature: "other".into(),
                ..response.clone()
            })
        );
        assert_eq!(public_key_fingerprint(&[0u8; 32]).len(), 35);
    }
}
