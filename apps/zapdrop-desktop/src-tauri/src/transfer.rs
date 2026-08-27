use crate::{
    discovery::PeerRecord,
    history::{HistoryStore, TransferHistoryEntry},
    identity::DeviceIdentity,
    pairing::{read_json_line, write_json_line},
    settings::SettingsStore,
    trust::TrustedPeerStore,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpStream},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

const TRANSFER_VERSION: u32 = 1;
const HELLO_KIND: &str = "zapdrop_transfer_hello";
const MANIFEST_KIND: &str = "zapdrop_transfer_manifest";
const READY_KIND: &str = "zapdrop_transfer_ready";
const CHUNK_KIND: &str = "zapdrop_transfer_chunk";
const COMPLETE_KIND: &str = "zapdrop_transfer_complete";
const CANCEL_KIND: &str = "zapdrop_transfer_cancelled";
const CHUNK_SIZE: usize = 1024 * 1024;
const HELLO_ACCEPTED_KIND: &str = "zapdrop_transfer_hello_ok";
const MAX_PARALLEL_RECIPIENTS: usize = 8;
const OFFER_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSource {
    pub path: String,
    pub relative_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    pub transfer_id: Option<String>,
    pub peer_ids: Vec<String>,
    pub sources: Vec<TransferSource>,
    pub conflict_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestItem {
    pub item_id: String,
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub transfer_id: String,
    pub peer_id: String,
    pub peer_name: String,
    pub direction: String,
    pub status: String,
    pub current_path: Option<String>,
    pub bytes_done: u64,
    pub total_bytes: u64,
    pub items_done: usize,
    pub total_items: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferHello {
    kind: String,
    version: u32,
    transfer_id: String,
    sender_id: String,
    sender_name: String,
    public_key: String,
    fingerprint: String,
    nonce: String,
    timestamp: u64,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferManifest {
    kind: String,
    version: u32,
    transfer_id: String,
    items: Vec<ManifestItem>,
    total_bytes: u64,
    conflict_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferReady {
    kind: String,
    version: u32,
    transfer_id: String,
    offsets: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferChunk {
    kind: String,
    version: u32,
    transfer_id: String,
    item_id: String,
    relative_path: String,
    offset: u64,
    length: u32,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferControl {
    kind: String,
    version: u32,
    transfer_id: String,
    status: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingTransferOffer {
    pub transfer_id: String,
    pub peer_id: String,
    pub peer_name: String,
    pub items: Vec<ManifestItem>,
    pub total_bytes: u64,
    pub conflict_policy: String,
    pub default_receive_directory: String,
    pub conflicts: Vec<String>,
    pub received_at: u64,
}

struct PendingTransferOffer {
    stream: TcpStream,
    manifest: TransferManifest,
    peer_id: String,
    peer_name: String,
    received_at: u64,
}

#[derive(Clone)]
pub struct ReceiveOfferCoordinator {
    pending: Arc<Mutex<HashMap<String, PendingTransferOffer>>>,
}

impl ReceiveOfferCoordinator {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn list(&self, default_directory: &str) -> Vec<IncomingTransferOffer> {
        self.purge_expired();
        self.pending
            .lock()
            .expect("pending transfer offers poisoned")
            .values()
            .map(|offer| IncomingTransferOffer {
                transfer_id: offer.manifest.transfer_id.clone(),
                peer_id: offer.peer_id.clone(),
                peer_name: offer.peer_name.clone(),
                items: offer.manifest.items.clone(),
                total_bytes: offer.manifest.total_bytes,
                conflict_policy: offer.manifest.conflict_policy.clone(),
                default_receive_directory: default_directory.to_string(),
                conflicts: existing_conflicts(default_directory, &offer.manifest),
                received_at: offer.received_at,
            })
            .collect()
    }

    fn purge_expired(&self) {
        let cutoff = epoch_seconds().saturating_sub(OFFER_TIMEOUT_SECS);
        self.pending
            .lock()
            .expect("pending transfer offers poisoned")
            .retain(|_, offer| offer.received_at >= cutoff);
    }

    fn insert(&self, offer: PendingTransferOffer) {
        self.purge_expired();
        self.pending
            .lock()
            .expect("pending transfer offers poisoned")
            .insert(offer.manifest.transfer_id.clone(), offer);
    }

    pub fn accept(
        &self,
        transfer_id: &str,
        policy: String,
        destination: Option<String>,
        context: TransferServerContext,
    ) -> io::Result<()> {
        let policy = normalize_conflict_policy(&policy)?;
        let destination = destination.unwrap_or_else(|| context.receive_directory.clone());
        let root = safe_root(&destination)?;
        let pending = self
            .pending
            .lock()
            .expect("pending transfer offers poisoned")
            .remove(transfer_id)
            .ok_or_else(|| invalid("incoming transfer offer expired"))?;
        let mut offsets = HashMap::new();
        for item in &pending.manifest.items {
            offsets.insert(
                item.item_id.clone(),
                partial_offset(&root, &pending.manifest.transfer_id, item),
            );
        }
        write_json_line(
            &pending.stream,
            &TransferReady {
                kind: READY_KIND.to_string(),
                version: TRANSFER_VERSION,
                transfer_id: pending.manifest.transfer_id.clone(),
                offsets,
            },
        )?;
        let mut manifest = pending.manifest;
        manifest.conflict_policy = policy;
        let reader = BufReader::new(pending.stream.try_clone()?);
        let started_at = epoch_seconds();
        let source_names = manifest
            .items
            .iter()
            .map(|item| item.relative_path.clone())
            .collect::<Vec<_>>();
        let _ = context.history.record(TransferHistoryEntry {
            id: format!("{}:{}", manifest.transfer_id, pending.peer_id),
            transfer_id: manifest.transfer_id.clone(),
            direction: "receive".to_string(),
            peer_id: pending.peer_id.clone(),
            peer_name: pending.peer_name.clone(),
            status: "started".to_string(),
            source_names: source_names.clone(),
            items: manifest.items.len(),
            total_bytes: manifest.total_bytes,
            bytes_done: 0,
            conflict_policy: manifest.conflict_policy.clone(),
            started_at,
            finished_at: None,
            error: None,
        });
        emit_progress(
            context.app.as_ref(),
            &manifest.transfer_id,
            &pending.peer_id,
            &pending.peer_name,
            "receive",
            "started",
            None,
            0,
            manifest.total_bytes,
            0,
            manifest.items.len(),
            None,
        );
        thread::Builder::new()
            .name(format!("zapdrop-receive-{}", manifest.transfer_id))
            .spawn(move || {
                let result = receive_items(
                    reader,
                    &root,
                    &manifest,
                    &context,
                    &pending.peer_id,
                    &pending.peer_name,
                );
                finish_received_transfer(
                    &pending.stream,
                    &context,
                    &manifest,
                    &pending.peer_id,
                    &pending.peer_name,
                    source_names,
                    started_at,
                    result,
                );
            })
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        Ok(())
    }

    pub fn reject(&self, transfer_id: &str, reason: String) -> io::Result<()> {
        let pending = self
            .pending
            .lock()
            .expect("pending transfer offers poisoned")
            .remove(transfer_id)
            .ok_or_else(|| invalid("incoming transfer offer expired"))?;
        write_json_line(
            &pending.stream,
            &TransferControl {
                kind: "zapdrop_transfer_rejected".to_string(),
                version: TRANSFER_VERSION,
                transfer_id: transfer_id.to_string(),
                status: "rejected".to_string(),
                reason: Some(reason),
            },
        )
    }
}

#[derive(Clone)]
pub struct TransferServerContext {
    pub app: Option<AppHandle>,
    pub identity: DeviceIdentity,
    pub store: SettingsStore,
    pub trust: TrustedPeerStore,
    pub device_name: String,
    pub receive_directory: String,
    pub cancelled: Arc<Mutex<HashSet<String>>>,
    pub history: HistoryStore,
    pub offers: ReceiveOfferCoordinator,
    pub always_ask_before_receive: bool,
    pub default_conflict_policy: String,
}

#[derive(Clone)]
pub struct TransferManager {
    pub cancelled: Arc<Mutex<HashSet<String>>>,
    active: Arc<Mutex<HashMap<String, usize>>>,
    history: HistoryStore,
}

impl TransferManager {
    pub fn new(history: HistoryStore) -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(HashSet::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            history,
        }
    }

    pub fn cancel(&self, transfer_id: &str) {
        self.cancelled
            .lock()
            .expect("cancel set poisoned")
            .insert(transfer_id.to_string());
    }

    pub fn is_cancelled(&self, transfer_id: &str) -> bool {
        self.cancelled
            .lock()
            .expect("cancel set poisoned")
            .contains(transfer_id)
    }

    fn finish(&self, transfer_id: &str) {
        let mut active = self.active.lock().expect("active transfer set poisoned");
        if let Some(count) = active.get_mut(transfer_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(transfer_id);
                self.cancelled
                    .lock()
                    .expect("cancel set poisoned")
                    .remove(transfer_id);
            }
        }
    }

    pub fn start_parallel(
        &self,
        app: AppHandle,
        identity: DeviceIdentity,
        store: SettingsStore,
        device_name: String,
        peers: Vec<PeerRecord>,
        request: TransferRequest,
    ) -> io::Result<String> {
        if request.sources.is_empty() {
            return Err(invalid("at least one source is required"));
        }
        if request.peer_ids.is_empty() {
            return Err(invalid("at least one trusted peer is required"));
        }
        let manifest = build_manifest(&request.sources)?;
        if manifest.is_empty() {
            return Err(invalid("sources contain no transferable files"));
        }
        let total_bytes = manifest.iter().map(|item| item.size).sum::<u64>();
        let transfer_id = request
            .transfer_id
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let selected = peers
            .into_iter()
            .filter(|peer| request.peer_ids.iter().any(|id| id == &peer.id))
            .collect::<Vec<_>>();
        if selected.len() != request.peer_ids.len() {
            return Err(invalid("one or more peers are unavailable"));
        }
        if selected.len() > MAX_PARALLEL_RECIPIENTS {
            return Err(invalid(format!(
                "a transfer can target at most {MAX_PARALLEL_RECIPIENTS} recipients at once"
            )));
        }
        for peer in &selected {
            if !peer.trusted {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer {} is not trusted", peer.name),
                ));
            }
        }
        let manager = self.clone();
        self.active
            .lock()
            .expect("active transfer set poisoned")
            .insert(transfer_id.clone(), selected.len());
        let item_count = manifest.len();
        for peer in selected {
            let started_at = epoch_seconds();
            let source_names = request
                .sources
                .iter()
                .map(|source| {
                    source.relative_path.clone().unwrap_or_else(|| {
                        source
                            .path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&source.path)
                            .to_string()
                    })
                })
                .collect::<Vec<_>>();
            let history = self.history.clone();
            let app = app.clone();
            let identity = identity.clone();
            let store = store.clone();
            let device_name = device_name.clone();
            let sources = request.sources.clone();
            let policy = request
                .conflict_policy
                .clone()
                .unwrap_or_else(|| "rename".to_string());
            let transfer_id = transfer_id.clone();
            let manager = manager.clone();
            let _ = history.record(TransferHistoryEntry {
                id: format!("{}:{}", transfer_id, peer.id),
                transfer_id: transfer_id.clone(),
                direction: "send".to_string(),
                peer_id: peer.id.clone(),
                peer_name: peer.name.clone(),
                status: "started".to_string(),
                source_names: source_names.clone(),
                items: item_count,
                total_bytes,
                bytes_done: 0,
                conflict_policy: policy.clone(),
                started_at,
                finished_at: None,
                error: None,
            });
            thread::Builder::new()
                .name(format!("zapdrop-transfer-{}", peer.id))
                .spawn(move || {
                    let result = send_to_peer(
                        Some(&app),
                        &identity,
                        &store,
                        &device_name,
                        &peer,
                        &sources,
                        &policy,
                        &transfer_id,
                        total_bytes,
                        &manager,
                    );
                    let progress = match result {
                        Ok(()) => TransferProgress {
                            transfer_id: transfer_id.clone(),
                            peer_id: peer.id.clone(),
                            peer_name: peer.name.clone(),
                            direction: "send".to_string(),
                            status: "completed".to_string(),
                            current_path: None,
                            bytes_done: total_bytes,
                            total_bytes,
                            items_done: item_count,
                            total_items: item_count,
                            error: None,
                        },
                        Err(error) => TransferProgress {
                            transfer_id: transfer_id.clone(),
                            peer_id: peer.id.clone(),
                            peer_name: peer.name.clone(),
                            direction: "send".to_string(),
                            status: if manager.is_cancelled(&transfer_id) {
                                "cancelled"
                            } else {
                                "failed"
                            }
                            .to_string(),
                            current_path: None,
                            bytes_done: 0,
                            total_bytes,
                            items_done: 0,
                            total_items: item_count,
                            error: Some(error.to_string()),
                        },
                    };
                    let _ = history.record(history_entry(
                        &progress,
                        source_names.clone(),
                        &policy,
                        started_at,
                    ));
                    let event = if progress.status == "completed" {
                        "transfer-complete"
                    } else if progress.status == "cancelled" {
                        "transfer-cancelled"
                    } else {
                        "transfer-failed"
                    };
                    let _ = app.emit(event, progress);
                    manager.finish(&transfer_id);
                })
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        }
        Ok(transfer_id)
    }
}

pub fn is_transfer_hello(value: &serde_json::Value) -> bool {
    value.get("kind").and_then(|value| value.as_str()) == Some(HELLO_KIND)
}

pub fn handle_incoming(
    stream: TcpStream,
    address: SocketAddr,
    first: serde_json::Value,
    context: TransferServerContext,
) {
    let hello: TransferHello = match serde_json::from_value(first).map_err(invalid) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let peer_id = hello.sender_id.clone();
    let peer_name = hello.sender_name.clone();
    if let Err(error) = validate_hello(&hello) {
        let _ = write_error(&stream, &error.to_string());
        return;
    }
    let trusted = context.trust.list().into_iter().find(|peer| {
        peer.peer_id == hello.sender_id
            && peer.fingerprint == hello.fingerprint
            && peer.public_key == hello.public_key
    });
    if trusted.is_none() {
        let _ = write_error(&stream, "sender is not trusted");
        return;
    }
    if write_json_line(
        &stream,
        &TransferControl {
            kind: HELLO_ACCEPTED_KIND.to_string(),
            version: TRANSFER_VERSION,
            transfer_id: hello.transfer_id.clone(),
            status: "ready".to_string(),
            reason: None,
        },
    )
    .is_err()
    {
        return;
    }
    let mut reader = match stream.try_clone() {
        Ok(clone) => BufReader::new(clone),
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let manifest: TransferManifest = match read_json_line_from_reader(&mut reader) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    if let Err(error) = validate_manifest(&manifest, &hello.transfer_id) {
        let _ = write_error(&stream, &error.to_string());
        return;
    }
    let received_at = epoch_seconds();
    let offer = IncomingTransferOffer {
        transfer_id: manifest.transfer_id.clone(),
        peer_id: peer_id.clone(),
        peer_name: peer_name.clone(),
        items: manifest.items.clone(),
        total_bytes: manifest.total_bytes,
        conflict_policy: manifest.conflict_policy.clone(),
        default_receive_directory: context.receive_directory.clone(),
        conflicts: existing_conflicts(&context.receive_directory, &manifest),
        received_at,
    };
    let transfer_id = manifest.transfer_id.clone();
    context.offers.insert(PendingTransferOffer {
        stream,
        manifest,
        peer_id,
        peer_name,
        received_at,
    });
    if let Some(app) = context.app.as_ref() {
        let _ = app.emit("incoming-transfer-offer", offer);
    }
    if !context.always_ask_before_receive {
        let _ = context.offers.accept(
            &transfer_id,
            context.default_conflict_policy.clone(),
            None,
            context.clone(),
        );
    }
    let _ = address;
}

fn send_to_peer(
    app: Option<&AppHandle>,
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
    peer: &PeerRecord,
    sources: &[TransferSource],
    policy: &str,
    transfer_id: &str,
    total_bytes: u64,
    manager: &TransferManager,
) -> io::Result<()> {
    let address: SocketAddr = peer.endpoint.parse().map_err(invalid)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
    stream.set_read_timeout(Some(Duration::from_secs(OFFER_TIMEOUT_SECS + 30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let hello = signed_hello(identity, store, device_name, transfer_id)?;
    write_json_line(&stream, &hello)?;
    let hello_ack: TransferControl = read_json_line(&stream)?;
    if hello_ack.kind != HELLO_ACCEPTED_KIND
        || hello_ack.transfer_id != transfer_id
        || hello_ack.status != "ready"
    {
        return Err(invalid(hello_ack.reason.unwrap_or_else(|| {
            "receiver rejected transfer session".to_string()
        })));
    }
    let manifest = build_manifest(sources)?;
    write_json_line(
        &stream,
        &TransferManifest {
            kind: MANIFEST_KIND.to_string(),
            version: TRANSFER_VERSION,
            transfer_id: transfer_id.to_string(),
            total_bytes,
            items: manifest.clone(),
            conflict_policy: policy.to_string(),
        },
    )?;
    let ready_value: serde_json::Value = read_json_line(&stream)?;
    if ready_value.get("kind").and_then(|value| value.as_str()) != Some(READY_KIND) {
        let control: TransferControl = serde_json::from_value(ready_value).map_err(invalid)?;
        return Err(invalid(control.reason.unwrap_or_else(|| {
            "receiver did not accept the transfer".to_string()
        })));
    }
    let ready: TransferReady = serde_json::from_value(ready_value).map_err(invalid)?;
    if ready.transfer_id != transfer_id {
        return Err(invalid("transfer ready response mismatch"));
    }
    let mut done = 0u64;
    for item in &manifest {
        let offset = *ready.offsets.get(&item.item_id).unwrap_or(&0);
        let source = source_for_item(sources, item)?;
        let mut file = File::open(&source)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut current = offset;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        while current < item.size {
            if manager.is_cancelled(transfer_id) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "transfer cancelled",
                ));
            }
            let read = file.read(&mut buffer)?;
            if read == 0 {
                return Err(invalid("source ended before manifest size"));
            }
            let chunk = TransferChunk {
                kind: CHUNK_KIND.to_string(),
                version: TRANSFER_VERSION,
                transfer_id: transfer_id.to_string(),
                item_id: item.item_id.clone(),
                relative_path: item.relative_path.clone(),
                offset: current,
                length: read as u32,
                sha256: digest_bytes(&buffer[..read]),
            };
            write_json_line(&stream, &chunk)?;
            stream.write_all(&buffer[..read])?;
            current += read as u64;
            done += read as u64;
            emit_progress(
                app,
                transfer_id,
                &peer.id,
                &peer.name,
                "send",
                "transferring",
                Some(item.relative_path.clone()),
                done,
                total_bytes,
                0,
                manifest.len(),
                None,
            );
        }
    }
    let control: TransferControl = read_json_line(&stream)?;
    if control.status != "completed" {
        return Err(invalid(control.reason.unwrap_or_else(|| {
            "receiver did not complete transfer".to_string()
        })));
    }
    Ok(())
}

fn receive_items(
    mut reader: BufReader<TcpStream>,
    root: &Path,
    manifest: &TransferManifest,
    context: &TransferServerContext,
    peer_id: &str,
    peer_name: &str,
) -> io::Result<u64> {
    let mut total_done = 0u64;
    let mut completed = 0usize;
    for item in &manifest.items {
        if context
            .cancelled
            .lock()
            .expect("cancel set poisoned")
            .contains(&manifest.transfer_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "transfer cancelled",
            ));
        }
        let mut offset = partial_offset(root, &manifest.transfer_id, item);
        while offset < item.size {
            let chunk: TransferChunk = read_json_line_from_reader(&mut reader)?;
            if chunk.kind != CHUNK_KIND
                || chunk.transfer_id != manifest.transfer_id
                || chunk.item_id != item.item_id
                || chunk.offset != offset
                || chunk.length as u64 > item.size - offset
            {
                return Err(invalid("invalid transfer chunk header"));
            }
            let mut data = vec![0u8; chunk.length as usize];
            reader.read_exact(&mut data)?;
            if digest_bytes(&data) != chunk.sha256 {
                return Err(invalid("transfer chunk checksum mismatch"));
            }
            let partial = partial_path(root, &manifest.transfer_id, item);
            if let Some(parent) = partial.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(&partial)?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&data)?;
            file.flush()?;
            offset += data.len() as u64;
            total_done += data.len() as u64;
            emit_progress(
                context.app.as_ref(),
                &manifest.transfer_id,
                peer_id,
                peer_name,
                "receive",
                "transferring",
                Some(item.relative_path.clone()),
                total_done,
                manifest.total_bytes,
                completed,
                manifest.items.len(),
                None,
            );
        }
        let partial = partial_path(root, &manifest.transfer_id, item);
        if digest_file(&partial)? != item.sha256 {
            return Err(invalid("received file checksum mismatch"));
        }
        if item.kind == "file" {
            if let Some(destination) =
                destination_path(root, &item.relative_path, &manifest.conflict_policy)?
            {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(&partial, destination)?;
            } else {
                fs::remove_file(&partial)?;
            }
        }

        completed += 1;
        emit_progress(
            context.app.as_ref(),
            &manifest.transfer_id,
            peer_id,
            peer_name,
            "receive",
            "transferring",
            Some(item.relative_path.clone()),
            total_done,
            manifest.total_bytes,
            completed,
            manifest.items.len(),
            None,
        );
    }
    let _ = fs::remove_dir_all(root.join(".zapdrop-partial").join(&manifest.transfer_id));
    Ok(total_done)
}

fn finish_received_transfer(
    stream: &TcpStream,
    context: &TransferServerContext,
    manifest: &TransferManifest,
    peer_id: &str,
    peer_name: &str,
    source_names: Vec<String>,
    started_at: u64,
    result: io::Result<u64>,
) {
    let (status, bytes_done, items_done, error) = match result {
        Ok(bytes) => ("completed", bytes, manifest.items.len(), None),
        Err(error) => {
            let status = if context
                .cancelled
                .lock()
                .expect("cancel set poisoned")
                .contains(&manifest.transfer_id)
            {
                "cancelled"
            } else {
                "failed"
            };
            (status, 0, 0, Some(error.to_string()))
        }
    };
    let progress = TransferProgress {
        transfer_id: manifest.transfer_id.clone(),
        peer_id: peer_id.to_string(),
        peer_name: peer_name.to_string(),
        direction: "receive".to_string(),
        status: status.to_string(),
        current_path: None,
        bytes_done,
        total_bytes: manifest.total_bytes,
        items_done,
        total_items: manifest.items.len(),
        error: error.clone(),
    };
    let _ = context.history.record(history_entry(
        &progress,
        source_names,
        &manifest.conflict_policy,
        started_at,
    ));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let _ = write_json_line(
        stream,
        &TransferControl {
            kind: if status == "completed" {
                COMPLETE_KIND
            } else if status == "cancelled" {
                CANCEL_KIND
            } else {
                "zapdrop_transfer_error"
            }
            .to_string(),
            version: TRANSFER_VERSION,
            transfer_id: manifest.transfer_id.clone(),
            status: status.to_string(),
            reason: error.clone(),
        },
    );
    let event = if status == "completed" {
        "transfer-complete"
    } else if status == "cancelled" {
        "transfer-cancelled"
    } else {
        "transfer-failed"
    };
    if let Some(app) = context.app.as_ref() {
        let _ = app.emit(event, progress);
    }
}

fn normalize_conflict_policy(policy: &str) -> io::Result<String> {
    if matches!(policy, "rename" | "overwrite" | "skip") {
        Ok(policy.to_string())
    } else {
        Err(invalid("unknown conflict policy"))
    }
}

fn existing_conflicts(directory: &str, manifest: &TransferManifest) -> Vec<String> {
    let Ok(root) = safe_root(directory) else {
        return Vec::new();
    };
    manifest
        .items
        .iter()
        .filter(|item| root.join(&item.relative_path).exists())
        .map(|item| item.relative_path.clone())
        .collect()
}

fn signed_hello(
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
    transfer_id: &str,
) -> io::Result<TransferHello> {
    let mut hello = TransferHello {
        kind: HELLO_KIND.to_string(),
        version: TRANSFER_VERSION,
        transfer_id: transfer_id.to_string(),
        sender_id: identity.device_id.clone(),
        sender_name: device_name.to_string(),
        public_key: identity.public_key.clone(),
        fingerprint: identity.fingerprint.clone(),
        nonce: BASE64.encode(Uuid::new_v4().as_bytes()),
        timestamp: epoch_seconds(),
        signature: String::new(),
    };
    let key = identity.signing_key(store)?;
    hello.signature = BASE64
        .encode(ed25519_dalek::Signer::sign(&key, hello_payload(&hello).as_bytes()).to_bytes());
    Ok(hello)
}

fn validate_hello(hello: &TransferHello) -> io::Result<()> {
    if hello.kind != HELLO_KIND
        || hello.version != TRANSFER_VERSION
        || hello.transfer_id.is_empty()
        || hello.sender_id.is_empty()
    {
        return Err(invalid("unsupported transfer hello"));
    }
    if epoch_seconds().abs_diff(hello.timestamp) > 300 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transfer hello expired",
        ));
    }
    let public: [u8; 32] = BASE64
        .decode(&hello.public_key)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| invalid("invalid transfer public key"))?;
    if fingerprint(&public) != hello.fingerprint {
        return Err(invalid("transfer fingerprint mismatch"));
    }
    let signature =
        ed25519_dalek::Signature::from_slice(&BASE64.decode(&hello.signature).map_err(invalid)?)
            .map_err(invalid)?;
    VerifyingKey::from_bytes(&public)
        .map_err(invalid)?
        .verify(hello_payload(hello).as_bytes(), &signature)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
}

fn hello_payload(hello: &TransferHello) -> String {
    format!(
        "zapdrop-transfer-hello-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        hello.kind,
        hello.version,
        hello.transfer_id,
        hello.sender_id,
        hello.sender_name,
        hello.public_key,
        hello.fingerprint,
        hello.nonce,
        hello.timestamp,
        ""
    )
}

fn validate_manifest(manifest: &TransferManifest, transfer_id: &str) -> io::Result<()> {
    if manifest.kind != MANIFEST_KIND
        || manifest.version != TRANSFER_VERSION
        || manifest.transfer_id != transfer_id
        || manifest.items.is_empty()
    {
        return Err(invalid("invalid transfer manifest"));
    }
    normalize_conflict_policy(&manifest.conflict_policy)?;
    if manifest.items.len() > 100_000 {
        return Err(invalid("transfer contains too many items"));
    }
    let mut item_ids = HashSet::new();
    let mut paths = HashSet::new();
    let sum = manifest.items.iter().try_fold(0u64, |sum, item| {
        validate_relative_path(&item.relative_path)?;
        if !item_ids.insert(item.item_id.as_str()) || !paths.insert(item.relative_path.as_str()) {
            return Err(invalid(
                "manifest contains duplicate item identifiers or paths",
            ));
        }
        if item.kind != "file" {
            return Err(invalid("only regular files are supported in Phase 4"));
        }
        sum.checked_add(item.size)
            .ok_or_else(|| invalid("transfer size overflow"))
    })?;
    if sum != manifest.total_bytes {
        return Err(invalid("manifest total size mismatch"));
    }
    Ok(())
}

fn build_manifest(sources: &[TransferSource]) -> io::Result<Vec<ManifestItem>> {
    let mut items = Vec::new();
    for source in sources {
        let path = PathBuf::from(&source.path);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("source not found: {}", source.path),
            ));
        }
        collect_files(
            &path,
            source.relative_path.clone().unwrap_or_else(|| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            }),
            &mut items,
        )?;
    }
    Ok(items)
}
fn collect_files(path: &Path, relative: String, items: &mut Vec<ManifestItem>) -> io::Result<()> {
    validate_relative_path(&relative)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("symbolic links are not allowed"));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            collect_files(&entry.path(), format!("{relative}/{name}"), items)?;
        }
    } else if metadata.is_file() {
        items.push(ManifestItem {
            item_id: stable_item_id(&relative),
            relative_path: relative,
            kind: "file".to_string(),
            size: metadata.len(),
            sha256: digest_file(path)?,
        });
    } else {
        return Err(invalid("source is not a regular file or directory"));
    }
    Ok(())
}
fn source_for_item(sources: &[TransferSource], item: &ManifestItem) -> io::Result<PathBuf> {
    for source in sources {
        let path = PathBuf::from(&source.path);
        let root = source.relative_path.clone().unwrap_or_else(|| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });
        if item.relative_path == root {
            return Ok(path);
        }
        if item.relative_path.starts_with(&(root.clone() + "/")) {
            let remainder =
                item.relative_path[root.len() + 1..].replace('/', std::path::MAIN_SEPARATOR_STR);
            return Ok(path.join(remainder));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "manifest source mapping missing",
    ))
}

pub fn validate_relative_path(value: &str) -> io::Result<()> {
    if value.is_empty() || value.contains('\0') || Path::new(value).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path must be relative",
        ));
    }
    if value == ".zapdrop-partial"
        || value.starts_with(".zapdrop-partial/")
        || value.starts_with(".zapdrop-partial\\")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reserved transfer state path is not allowed",
        ));
    }
    for component in Path::new(value).components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "path traversal is not allowed",
                ))
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }
    Ok(())
}
pub fn safe_root(value: &str) -> io::Result<PathBuf> {
    let expanded = if value == "~" {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("home directory unavailable"))?
    } else if let Some(rest) = value.strip_prefix("~/") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("home directory unavailable"))?
            .join(rest)
    } else {
        PathBuf::from(value)
    };
    fs::create_dir_all(&expanded)?;
    Ok(fs::canonicalize(expanded)?)
}
fn destination_path(root: &Path, relative: &str, policy: &str) -> io::Result<Option<PathBuf>> {
    validate_relative_path(relative)?;
    let candidate = root.join(relative);
    if let Some(parent) = candidate.parent() {
        fs::create_dir_all(parent)?;
        let canonical_parent = fs::canonicalize(parent)?;
        if !canonical_parent.starts_with(root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination escapes receive directory",
            ));
        }
    }
    if fs::symlink_metadata(&candidate)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination symlink is not allowed",
        ));
    }
    if candidate.exists() {
        match policy {
            "skip" => return Ok(None),

            "overwrite" => {}
            "rename" => {
                let stem = candidate.file_stem().unwrap_or_default().to_string_lossy();
                let ext = candidate
                    .extension()
                    .map(|value| format!(".{}", value.to_string_lossy()))
                    .unwrap_or_default();
                for index in 1..10_000 {
                    let alt = candidate.with_file_name(format!("{stem} ({index}){ext}"));
                    if !alt.exists() {
                        return Ok(Some(alt));
                    }
                }
                return Err(invalid("could not find conflict-free destination"));
            }
            _ => return Err(invalid("unknown conflict policy")),
        }
    }
    Ok(Some(candidate))
}
fn partial_path(root: &Path, transfer_id: &str, item: &ManifestItem) -> PathBuf {
    root.join(".zapdrop-partial")
        .join(transfer_id)
        .join(format!("{}.part", item.item_id))
}
fn partial_offset(root: &Path, transfer_id: &str, item: &ManifestItem) -> u64 {
    fs::metadata(partial_path(root, transfer_id, item))
        .map(|meta| meta.len().min(item.size))
        .unwrap_or(0)
}
fn stable_item_id(relative_path: &str) -> String {
    format!(
        "item-{}",
        format_digest(Sha256::digest(relative_path.as_bytes()).as_slice())
    )
}

fn digest_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format_digest(hasher.finalize().as_slice()))
}
fn digest_bytes(bytes: &[u8]) -> String {
    format_digest(Sha256::digest(bytes).as_slice())
}
fn format_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn fingerprint(public_key: &[u8; 32]) -> String {
    Sha256::digest(public_key)
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn emit_progress(
    app: Option<&AppHandle>,
    transfer_id: &str,
    peer_id: &str,
    peer_name: &str,
    direction: &str,
    status: &str,
    current_path: Option<String>,
    bytes_done: u64,
    total_bytes: u64,
    items_done: usize,
    total_items: usize,
    error: Option<String>,
) {
    let Some(app) = app else {
        return;
    };
    let _ = app.emit(
        "transfer-progress",
        TransferProgress {
            transfer_id: transfer_id.to_string(),
            peer_id: peer_id.to_string(),
            peer_name: peer_name.to_string(),
            direction: direction.to_string(),
            status: status.to_string(),
            current_path,
            bytes_done,
            total_bytes,
            items_done,
            total_items,
            error,
        },
    );
}
fn history_entry(
    progress: &TransferProgress,
    source_names: Vec<String>,
    policy: &str,
    started_at: u64,
) -> TransferHistoryEntry {
    TransferHistoryEntry {
        id: format!("{}:{}", progress.transfer_id, progress.peer_id),
        transfer_id: progress.transfer_id.clone(),
        direction: progress.direction.clone(),
        peer_id: progress.peer_id.clone(),
        peer_name: progress.peer_name.clone(),
        status: progress.status.clone(),
        source_names,
        items: progress.total_items,
        total_bytes: progress.total_bytes,
        bytes_done: progress.bytes_done,
        conflict_policy: policy.to_string(),
        started_at,
        finished_at: Some(epoch_seconds()),
        error: progress.error.clone(),
    }
}

fn read_json_line_from_reader<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
) -> io::Result<T> {
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    if line.len() > 64 * 1024 {
        return Err(invalid("transfer frame too large"));
    }
    serde_json::from_slice(line.trim_ascii()).map_err(invalid)
}

fn write_error(stream: &TcpStream, reason: &str) -> io::Result<()> {
    write_json_line(
        stream,
        &TransferControl {
            kind: "zapdrop_transfer_error".to_string(),
            version: TRANSFER_VERSION,
            transfer_id: String::new(),
            status: "failed".to_string(),
            reason: Some(reason.to_string()),
        },
    )
}
fn invalid(error: impl ToString) -> io::Error {
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
    use super::*;
    use crate::{
        history::HistoryStore,
        identity::DeviceIdentity,
        settings::SettingsStore,
        trust::{TrustedPeer, TrustedPeerStore},
    };
    use std::{
        fs,
        net::TcpListener,
        path::PathBuf,
        sync::{Arc, Barrier, Mutex},
        thread,
    };
    #[test]
    fn rejects_traversal() {
        assert!(validate_relative_path("../escape.txt").is_err());
        assert!(validate_relative_path("/absolute.txt").is_err());
    }
    #[test]
    fn resolves_conflict_by_renaming() {
        let root = std::env::temp_dir().join(format!("zapdrop-transfer-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file.txt");
        fs::write(&path, b"existing").unwrap();
        let renamed = destination_path(&root, "file.txt", "rename")
            .unwrap()
            .unwrap();
        assert_eq!(
            renamed.file_name().unwrap().to_string_lossy(),
            "file (1).txt"
        );
        assert!(destination_path(&root, "file.txt", "skip")
            .unwrap()
            .is_none());
        assert!(destination_path(&root, "file.txt", "invalid").is_err());
        fs::remove_dir_all(PathBuf::from(root)).unwrap();
    }

    #[test]
    fn bidirectional_concurrent_loopback_transfer() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-bidirectional-{}", uuid::Uuid::new_v4()));
        let data_a = root.join("peer-a-data");
        let data_b = root.join("peer-b-data");
        let source_a = root.join("from-a.txt");
        let source_b = root.join("from-b.txt");
        let receive_a = root.join("peer-a-received");
        let receive_b = root.join("peer-b-received");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source_a, b"hello from peer A\n").unwrap();
        fs::write(&source_b, b"hello from peer B\n").unwrap();

        let store_a = SettingsStore::new(data_a);
        let store_b = SettingsStore::new(data_b);
        let identity_a = DeviceIdentity::load_or_create(&store_a).unwrap();
        let identity_b = DeviceIdentity::load_or_create(&store_b).unwrap();
        let trust_a = TrustedPeerStore::load(&store_a).unwrap();
        let trust_b = TrustedPeerStore::load(&store_b).unwrap();
        trust_a
            .upsert(TrustedPeer {
                version: 1,
                peer_id: identity_b.device_id.clone(),
                name: "Peer B".to_string(),
                public_key: identity_b.public_key.clone(),
                fingerprint: identity_b.fingerprint.clone(),
                first_seen: 1,
                last_seen: 1,
                endpoint: "127.0.0.1:0".to_string(),
            })
            .unwrap();
        trust_b
            .upsert(TrustedPeer {
                version: 1,
                peer_id: identity_a.device_id.clone(),
                name: "Peer A".to_string(),
                public_key: identity_a.public_key.clone(),
                fingerprint: identity_a.fingerprint.clone(),
                first_seen: 1,
                last_seen: 1,
                endpoint: "127.0.0.1:0".to_string(),
            })
            .unwrap();

        let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint_a = listener_a.local_addr().unwrap();
        let endpoint_b = listener_b.local_addr().unwrap();
        let context_a = test_context(
            identity_a.clone(),
            store_a.clone(),
            trust_a,
            receive_a.clone(),
            "Peer A",
        );
        let context_b = test_context(
            identity_b.clone(),
            store_b.clone(),
            trust_b,
            receive_b.clone(),
            "Peer B",
        );
        let receiver_a = thread::spawn(move || {
            let (stream, address) = listener_a.accept().unwrap();
            let first: serde_json::Value = read_json_line(&stream).unwrap();
            handle_incoming(stream, address, first, context_a);
        });
        let receiver_b = thread::spawn(move || {
            let (stream, address) = listener_b.accept().unwrap();
            let first: serde_json::Value = read_json_line(&stream).unwrap();
            handle_incoming(stream, address, first, context_b);
        });
        let peer_a = PeerRecord {
            id: identity_a.device_id.clone(),
            name: "Peer A".to_string(),
            platform: "windows".to_string(),
            fingerprint: Some(identity_a.fingerprint.clone()),
            public_key: Some(identity_a.public_key.clone()),
            endpoint: endpoint_a.to_string(),
            port: endpoint_a.port(),
            status: "trusted".to_string(),
            discovered_via: "loopback-test".to_string(),
            last_seen: epoch_seconds(),
            trusted: true,
        };
        let peer_b = PeerRecord {
            id: identity_b.device_id.clone(),
            name: "Peer B".to_string(),
            platform: "windows".to_string(),
            fingerprint: Some(identity_b.fingerprint.clone()),
            public_key: Some(identity_b.public_key.clone()),
            endpoint: endpoint_b.to_string(),
            port: endpoint_b.port(),
            status: "trusted".to_string(),
            discovered_via: "loopback-test".to_string(),
            last_seen: epoch_seconds(),
            trusted: true,
        };
        let barrier = Arc::new(Barrier::new(2));
        let manager_a = TransferManager::new(HistoryStore::load(&store_a).unwrap());
        let manager_b = TransferManager::new(HistoryStore::load(&store_b).unwrap());
        let source_a_path = source_a.to_string_lossy().to_string();
        let source_b_path = source_b.to_string_lossy().to_string();
        let barrier_a = Arc::clone(&barrier);
        let sender_a = thread::spawn(move || {
            barrier_a.wait();
            send_to_peer(
                None,
                &identity_a,
                &store_a,
                "Peer A",
                &peer_b,
                &[TransferSource {
                    path: source_a_path,
                    relative_path: Some("from-a.txt".to_string()),
                }],
                "rename",
                "transfer-a-to-b",
                18,
                &manager_a,
            )
        });
        let barrier_b = Arc::clone(&barrier);
        let sender_b = thread::spawn(move || {
            barrier_b.wait();
            send_to_peer(
                None,
                &identity_b,
                &store_b,
                "Peer B",
                &peer_a,
                &[TransferSource {
                    path: source_b_path,
                    relative_path: Some("from-b.txt".to_string()),
                }],
                "rename",
                "transfer-b-to-a",
                18,
                &manager_b,
            )
        });
        sender_a.join().unwrap().unwrap();
        sender_b.join().unwrap().unwrap();
        receiver_a.join().unwrap();
        receiver_b.join().unwrap();
        assert_eq!(
            fs::read(receive_a.join("from-b.txt")).unwrap(),
            b"hello from peer B\n"
        );
        assert_eq!(
            fs::read(receive_b.join("from-a.txt")).unwrap(),
            b"hello from peer A\n"
        );
        assert!(
            HistoryStore::load(&SettingsStore::new(root.join("peer-a-data")))
                .unwrap()
                .list()
                .iter()
                .any(|entry| entry.transfer_id == "transfer-b-to-a" && entry.status == "completed")
        );
        assert!(
            HistoryStore::load(&SettingsStore::new(root.join("peer-b-data")))
                .unwrap()
                .list()
                .iter()
                .any(|entry| entry.transfer_id == "transfer-a-to-b" && entry.status == "completed")
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn test_context(
        identity: DeviceIdentity,
        store: SettingsStore,
        trust: TrustedPeerStore,
        receive_directory: PathBuf,
        device_name: &str,
    ) -> TransferServerContext {
        let history = HistoryStore::load(&store).unwrap();
        TransferServerContext {
            app: None,
            identity,
            store,
            trust,
            device_name: device_name.to_string(),
            receive_directory: receive_directory.to_string_lossy().to_string(),
            cancelled: Arc::new(Mutex::new(HashSet::new())),
            history,
            offers: ReceiveOfferCoordinator::new(),
            always_ask_before_receive: false,
            default_conflict_policy: "rename".to_string(),
        }
    }
}
