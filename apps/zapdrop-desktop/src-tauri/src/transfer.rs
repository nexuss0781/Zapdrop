use crate::{
    discovery::PeerRecord,
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

#[derive(Clone)]
pub struct TransferServerContext {
    pub app: AppHandle,
    pub identity: DeviceIdentity,
    pub store: SettingsStore,
    pub trust: TrustedPeerStore,
    pub device_name: String,
    pub receive_directory: String,
    pub cancelled: Arc<Mutex<HashSet<String>>>,
}

#[derive(Clone)]
pub struct TransferManager {
    pub cancelled: Arc<Mutex<HashSet<String>>>,
    active: Arc<Mutex<HashMap<String, usize>>>,
}

impl TransferManager {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(HashSet::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
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
            thread::Builder::new()
                .name(format!("zapdrop-transfer-{}", peer.id))
                .spawn(move || {
                    let result = send_to_peer(
                        &app,
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
    let root = match safe_root(&context.receive_directory) {
        Ok(root) => root,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let mut offsets = HashMap::new();
    for item in &manifest.items {
        offsets.insert(
            item.item_id.clone(),
            partial_offset(&root, &manifest.transfer_id, item),
        );
    }
    if write_json_line(
        &stream,
        &TransferReady {
            kind: READY_KIND.to_string(),
            version: TRANSFER_VERSION,
            transfer_id: manifest.transfer_id.clone(),
            offsets,
        },
    )
    .is_err()
    {
        return;
    }
    emit_progress(
        &context.app,
        &manifest.transfer_id,
        &peer_id,
        &peer_name,
        "receive",
        "started",
        None,
        0,
        manifest.total_bytes,
        0,
        manifest.items.len(),
        None,
    );
    let result = receive_items(&mut reader, &root, &manifest, &context);
    match result {
        Ok(bytes) => {
            let _ = write_json_line(
                &stream,
                &TransferControl {
                    kind: COMPLETE_KIND.to_string(),
                    version: TRANSFER_VERSION,
                    transfer_id: manifest.transfer_id.clone(),
                    status: "completed".to_string(),
                    reason: None,
                },
            );
            emit_progress(
                &context.app,
                &manifest.transfer_id,
                &peer_id,
                &peer_name,
                "receive",
                "completed",
                None,
                bytes,
                manifest.total_bytes,
                manifest.items.len(),
                manifest.items.len(),
                None,
            );
        }
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
            let _ = write_json_line(
                &stream,
                &TransferControl {
                    kind: if status == "cancelled" {
                        CANCEL_KIND
                    } else {
                        "zapdrop_transfer_error"
                    }
                    .to_string(),
                    version: TRANSFER_VERSION,
                    transfer_id: manifest.transfer_id.clone(),
                    status: status.to_string(),
                    reason: Some(error.to_string()),
                },
            );
            emit_progress(
                &context.app,
                &manifest.transfer_id,
                &peer_id,
                &peer_name,
                "receive",
                status,
                None,
                0,
                manifest.total_bytes,
                0,
                manifest.items.len(),
                Some(error.to_string()),
            );
        }
    }
    let _ = address;
}

fn send_to_peer(
    app: &AppHandle,
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
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
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
    let ready: TransferReady = read_json_line(&stream)?;
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
    reader: &mut BufReader<TcpStream>,
    root: &Path,
    manifest: &TransferManifest,
    context: &TransferServerContext,
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
            let chunk: TransferChunk = read_json_line_from_reader(reader)?;
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
                &context.app,
                &manifest.transfer_id,
                &context.identity.device_id,
                &context.device_name,
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
            &context.app,
            &manifest.transfer_id,
            &context.identity.device_id,
            &context.device_name,
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
    app: &AppHandle,
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
    use super::{destination_path, validate_relative_path};
    use std::{fs, path::PathBuf};
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
}
