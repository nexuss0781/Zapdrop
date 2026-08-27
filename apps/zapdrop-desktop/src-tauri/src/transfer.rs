#[cfg(feature = "swarm-v2")]
use crate::secure::{
    establish_channel, open_piece, seal_piece, ChannelRole, EncryptedFrame, JobKey, SecureHandshake,
};
#[cfg(feature = "swarm-v2")]
use crate::swarm::{
    ChunkProfile, DistributionMode, EncryptedPieceHeader, SwarmJob, SWARM_PROTOCOL_VERSION,
};
use crate::{
    discovery::PeerRecord,
    history::{HistoryStore, TransferHistoryEntry},
    identity::DeviceIdentity,
    pairing::{read_json_line, write_json_line},
    scheduler::{SwarmScheduler, SwarmSchedulerOptions},
    settings::SettingsStore,
    trust::TrustedPeerStore,
};
#[cfg(feature = "swarm-v2")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
#[cfg(feature = "swarm-v2")]
use ed25519_dalek::{Signature, Signer};
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
const MAX_PENDING_TRANSFER_OFFERS: usize = 32;
#[cfg(feature = "swarm-v2")]
const V2_JOB_AAD: &[u8] = b"zapdrop/swarm/v2/direct-job";
#[cfg(feature = "swarm-v2")]
const V2_PIECE_AAD: &[u8] = b"zapdrop/swarm/v2/direct-piece";
#[cfg(feature = "swarm-v2")]
const V2_COMPLETE_AAD: &[u8] = b"zapdrop/swarm/v2/direct-complete";
#[cfg(feature = "swarm-v2")]
const V2_DIRECT_OFFER_KIND: &str = "zapdrop_swarm_direct_offer";
#[cfg(feature = "swarm-v2")]
const V2_DIRECT_DECISION_KIND: &str = "zapdrop_swarm_direct_decision";
#[cfg(feature = "swarm-v2")]
const V2_DIRECT_READY_KIND: &str = "zapdrop_swarm_direct_ready";
#[cfg(feature = "swarm-v2")]
const V2_DIRECT_PIECE_KIND: &str = "zapdrop_swarm_direct_piece";
#[cfg(feature = "swarm-v2")]
const V2_DIRECT_COMPLETE_KIND: &str = "zapdrop_swarm_direct_complete";
#[cfg(feature = "swarm-v2")]
const MAX_V2_DIRECT_ITEMS: usize = 100_000;
#[cfg(feature = "swarm-v2")]
const MAX_V2_DIRECT_TOTAL_BYTES: u64 = 1 << 50;
#[cfg(feature = "swarm-v2")]
const MAX_V2_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectOffer {
    kind: String,
    version: u32,
    job: SwarmJob,
    items: Vec<ManifestItem>,
    total_bytes: u64,
    conflict_policy: String,
    key_envelope: Option<crate::secure::JobKeyEnvelope>,
}

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectKeyProvision {
    kind: String,
    version: u32,
    job_id: String,
    key_envelope: crate::secure::JobKeyEnvelope,
}

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectDecision {
    kind: String,
    version: u32,
    job_id: String,
    accepted: bool,
    destination: Option<String>,
    conflict_policy: String,
    reason: Option<String>,
}

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectReady {
    kind: String,
    version: u32,
    job_id: String,
    offsets: HashMap<String, u64>,
    #[serde(default)]
    missing_ranges: HashMap<String, Vec<crate::snapshot::ByteRange>>,
}

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectPiece {
    kind: String,
    version: u32,
    header: EncryptedPieceHeader,
    ciphertext: String,
}

#[cfg(feature = "swarm-v2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2DirectCompletion {
    kind: String,
    version: u32,
    job_id: String,
    status: String,
    total_bytes: u64,
    digest: String,
    reason: Option<String>,
}

#[cfg(feature = "swarm-v2")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V2JobUnsigned<'a> {
    kind: &'a str,
    version: u32,
    job_id: &'a str,
    sender_id: &'a str,
    sender_public_key: &'a str,
    sender_fingerprint: &'a str,
    snapshot_root: &'a str,
    recipient_ids: &'a [String],
    distribution_mode: DistributionMode,
    chunk_profile: &'a ChunkProfile,
    content_key_id: &'a str,
    created_at: u64,
    expires_at: u64,
}

#[cfg(feature = "swarm-v2")]
fn v2_job_signing_bytes(job: &SwarmJob) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&V2JobUnsigned {
        kind: &job.kind,
        version: job.version,
        job_id: &job.job_id,
        sender_id: &job.sender_id,
        sender_public_key: &job.sender_public_key,
        sender_fingerprint: &job.sender_fingerprint,
        snapshot_root: &job.snapshot_root,
        recipient_ids: &job.recipient_ids,
        distribution_mode: job.distribution_mode,
        chunk_profile: &job.chunk_profile,
        content_key_id: &job.content_key_id,
        created_at: job.created_at,
        expires_at: job.expires_at,
    })
    .map_err(invalid)
}

#[cfg(feature = "swarm-v2")]
fn sign_v2_job(job: &mut SwarmJob, signing_key: &ed25519_dalek::SigningKey) -> io::Result<()> {
    let bytes = v2_job_signing_bytes(job)?;
    job.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn verify_v2_job(job: &SwarmJob, verifying_key: &VerifyingKey) -> io::Result<()> {
    job.validate_at(v2_epoch_seconds()).map_err(invalid)?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(&job.signature).map_err(invalid)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| invalid("invalid v2 job signature length"))?;
    verifying_key
        .verify(
            &v2_job_signing_bytes(job)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| invalid("v2 job signature verification failed"))
}

#[cfg(feature = "swarm-v2")]
fn v2_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(feature = "swarm-v2")]
fn v2_switch_enabled(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE")
    )
}

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
    #[serde(default)]
    pub scheduler: Option<SwarmSchedulerOptions>,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentTransferProgress {
    pub transfer_id: String,
    pub status: String,
    pub recipients_total: usize,
    pub recipients_done: usize,
    pub recipients_completed: usize,
    pub recipients_failed: usize,
    pub recipients_cancelled: usize,
    pub bytes_done: u64,
    pub total_bytes: u64,
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

#[cfg(feature = "swarm-v2")]
struct PendingV2TransferOffer {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    channel: crate::secure::SecureChannel,
    offer: V2DirectOffer,
    peer_id: String,
    peer_name: String,
    peer_key: VerifyingKey,
    received_at: u64,
}

#[derive(Clone)]
pub struct ReceiveOfferCoordinator {
    pending: Arc<Mutex<HashMap<String, PendingTransferOffer>>>,
    #[cfg(feature = "swarm-v2")]
    pending_v2: Arc<Mutex<HashMap<String, PendingV2TransferOffer>>>,
}

impl ReceiveOfferCoordinator {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "swarm-v2")]
            pending_v2: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn list(&self, default_directory: &str) -> Vec<IncomingTransferOffer> {
        self.purge_expired();
        let mut offers = self
            .pending
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
            .collect::<Vec<_>>();
        #[cfg(feature = "swarm-v2")]
        offers.extend(
            self.pending_v2
                .lock()
                .expect("pending v2 transfer offers poisoned")
                .values()
                .map(|offer| IncomingTransferOffer {
                    transfer_id: offer.offer.job.job_id.clone(),
                    peer_id: offer.peer_id.clone(),
                    peer_name: offer.peer_name.clone(),
                    items: offer.offer.items.clone(),
                    total_bytes: offer.offer.total_bytes,
                    conflict_policy: offer.offer.conflict_policy.clone(),
                    default_receive_directory: default_directory.to_string(),
                    conflicts: existing_v2_conflicts(default_directory, &offer.offer),
                    received_at: offer.received_at,
                }),
        );
        offers
    }

    fn purge_expired(&self) {
        let cutoff = epoch_seconds().saturating_sub(OFFER_TIMEOUT_SECS);
        self.pending
            .lock()
            .expect("pending transfer offers poisoned")
            .retain(|_, offer| offer.received_at >= cutoff);
        #[cfg(feature = "swarm-v2")]
        self.pending_v2
            .lock()
            .expect("pending v2 transfer offers poisoned")
            .retain(|_, offer| offer.received_at >= cutoff);
    }

    fn insert(&self, offer: PendingTransferOffer) -> io::Result<()> {
        self.purge_expired();
        let mut pending = self
            .pending
            .lock()
            .expect("pending transfer offers poisoned");
        if pending.contains_key(&offer.manifest.transfer_id) {
            return Err(invalid("duplicate transfer offer"));
        }
        if pending.len() >= MAX_PENDING_TRANSFER_OFFERS {
            return Err(invalid("too many pending transfer offers"));
        }
        pending.insert(offer.manifest.transfer_id.clone(), offer);
        Ok(())
    }

    #[cfg(feature = "swarm-v2")]
    fn insert_v2(&self, offer: PendingV2TransferOffer) -> io::Result<()> {
        self.purge_expired();
        let mut pending = self
            .pending_v2
            .lock()
            .expect("pending v2 transfer offers poisoned");
        if pending.contains_key(&offer.offer.job.job_id) {
            return Err(invalid("duplicate v2 transfer offer"));
        }
        if pending.len() >= MAX_PENDING_TRANSFER_OFFERS {
            return Err(invalid("too many pending v2 transfer offers"));
        }
        pending.insert(offer.offer.job.job_id.clone(), offer);
        Ok(())
    }

    pub fn accept(
        &self,
        transfer_id: &str,
        policy: String,
        destination: Option<String>,
        context: TransferServerContext,
    ) -> io::Result<()> {
        #[cfg(feature = "swarm-v2")]
        if self
            .pending_v2
            .lock()
            .expect("pending v2 transfer offers poisoned")
            .contains_key(transfer_id)
        {
            return self.accept_v2(transfer_id, policy, destination, context);
        }
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
            parent_id: None,
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

    #[cfg(feature = "swarm-v2")]
    fn accept_v2(
        &self,
        transfer_id: &str,
        policy: String,
        destination: Option<String>,
        context: TransferServerContext,
    ) -> io::Result<()> {
        let policy = normalize_conflict_policy(&policy)?;
        let destination = destination.unwrap_or_else(|| context.receive_directory.clone());
        let destination_root = safe_root(&destination)?;
        let pending = self
            .pending_v2
            .lock()
            .expect("pending v2 transfer offers poisoned")
            .remove(transfer_id)
            .ok_or_else(|| invalid("incoming transfer offer expired"))?;
        let decision = V2DirectDecision {
            kind: V2_DIRECT_DECISION_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: pending.offer.job.job_id.clone(),
            accepted: true,
            destination: Some(destination_root.to_string_lossy().to_string()),
            conflict_policy: policy.clone(),
            reason: None,
        };
        let mut channel = pending.channel;
        write_v2_frame(
            &pending.stream,
            &seal_v2_json(&mut channel, &decision, V2_JOB_AAD)?,
        )?;
        let mut receive_context = context;
        receive_context.receive_directory = destination_root.to_string_lossy().to_string();
        receive_context.default_conflict_policy = policy;
        let stream = pending.stream;
        let mut reader = pending.reader;
        let offer = pending.offer;
        let peer_id = pending.peer_id;
        let peer_name = pending.peer_name;
        let peer_key = pending.peer_key;
        thread::Builder::new()
            .name(format!("zapdrop-v2-receive-{transfer_id}"))
            .spawn(move || {
                let _ = receive_v2_direct(
                    &stream,
                    &mut reader,
                    &mut channel,
                    offer,
                    &receive_context,
                    &peer_id,
                    &peer_name,
                    &peer_key,
                    true,
                );
            })
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        Ok(())
    }

    pub fn reject(&self, transfer_id: &str, reason: String) -> io::Result<()> {
        #[cfg(feature = "swarm-v2")]
        if !self
            .pending
            .lock()
            .expect("pending transfer offers poisoned")
            .contains_key(transfer_id)
        {
            let pending = self
                .pending_v2
                .lock()
                .expect("pending v2 transfer offers poisoned")
                .remove(transfer_id)
                .ok_or_else(|| invalid("incoming transfer offer expired"))?;
            let mut channel = pending.channel;
            let decision = V2DirectDecision {
                kind: V2_DIRECT_DECISION_KIND.to_string(),
                version: SWARM_PROTOCOL_VERSION,
                job_id: transfer_id.to_string(),
                accepted: false,
                destination: None,
                conflict_policy: "rename".to_string(),
                reason: Some(reason),
            };
            return write_v2_frame(
                &pending.stream,
                &seal_v2_json(&mut channel, &decision, V2_JOB_AAD)?,
            );
        }
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

    pub fn cancel_recipient(&self, transfer_id: &str, peer_id: &str) {
        self.cancelled
            .lock()
            .expect("cancel set poisoned")
            .insert(format!("{transfer_id}:{peer_id}"));
    }

    pub fn clear_recipient_cancel(&self, transfer_id: &str, peer_id: &str) {
        self.cancelled
            .lock()
            .expect("cancel set poisoned")
            .remove(&format!("{transfer_id}:{peer_id}"));
    }

    pub fn is_cancelled(&self, transfer_id: &str) -> bool {
        self.cancelled
            .lock()
            .expect("cancel set poisoned")
            .contains(transfer_id)
    }

    pub fn is_cancelled_for(&self, transfer_id: &str, peer_id: &str) -> bool {
        self.is_cancelled(transfer_id)
            || self
                .cancelled
                .lock()
                .expect("cancel set poisoned")
                .contains(&format!("{transfer_id}:{peer_id}"))
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
        let scheduler_options =
            request
                .scheduler
                .clone()
                .unwrap_or_else(|| SwarmSchedulerOptions {
                    max_parallel_recipients: selected.len(),
                    queue_limit: selected.len(),
                    bandwidth_bytes_per_second: 0,
                    max_retries: 0,
                });
        let scheduler = SwarmScheduler::new(scheduler_options)?;
        let manager = self.clone();
        self.active
            .lock()
            .expect("active transfer set poisoned")
            .insert(transfer_id.clone(), selected.len());
        let item_count = manifest.len();
        let parent_source_names = request
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
        let _ = self.history.record(TransferHistoryEntry {
            id: transfer_id.clone(),
            transfer_id: transfer_id.clone(),
            parent_id: None,
            direction: "send".to_string(),
            peer_id: "swarm".to_string(),
            peer_name: "Swarm job".to_string(),
            status: "started".to_string(),
            source_names: parent_source_names,
            items: item_count,
            total_bytes,
            bytes_done: 0,
            conflict_policy: request
                .conflict_policy
                .clone()
                .unwrap_or_else(|| "rename".to_string()),
            started_at: epoch_seconds(),
            finished_at: None,
            error: None,
        });
        let expected_children = selected.len();
        let _ = app.emit(
            "transfer-parent-progress",
            ParentTransferProgress {
                transfer_id: transfer_id.clone(),
                status: "queued".to_string(),
                recipients_total: expected_children,
                recipients_done: 0,
                recipients_completed: 0,
                recipients_failed: 0,
                recipients_cancelled: 0,
                bytes_done: 0,
                total_bytes,
            },
        );
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
            let expected_children = expected_children;
            let scheduler = scheduler.clone();
            let _ = history.record(TransferHistoryEntry {
                id: format!("{}:{}", transfer_id, peer.id),
                transfer_id: transfer_id.clone(),
                parent_id: Some(transfer_id.clone()),
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
                    emit_progress(
                        Some(&app),
                        &transfer_id,
                        &peer.id,
                        &peer.name,
                        "send",
                        "queued",
                        None,
                        0,
                        total_bytes,
                        0,
                        item_count,
                        None,
                    );
                    let result = scheduler.acquire(&peer.id).and_then(|_permit| {
                        let mut result = Err(invalid("transfer did not run"));
                        for attempt in 0..=scheduler.options().max_retries {
                            if manager.is_cancelled_for(&transfer_id, &peer.id) {
                                result = Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "transfer cancelled",
                                ));
                                break;
                            }
                            result = send_to_peer(
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
                                Some(scheduler.as_ref()),
                            );
                            if result.is_ok()
                                || attempt == scheduler.options().max_retries
                                || manager.is_cancelled_for(&transfer_id, &peer.id)
                                || !result
                                    .as_ref()
                                    .err()
                                    .is_some_and(is_retryable_transfer_error)
                            {
                                break;
                            }
                            let reason = result
                                .as_ref()
                                .err()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "transient transfer failure".to_string());
                            emit_progress(
                                Some(&app),
                                &transfer_id,
                                &peer.id,
                                &peer.name,
                                "send",
                                "retrying",
                                None,
                                0,
                                total_bytes,
                                0,
                                item_count,
                                Some(format!(
                                    "retry {} of {}: {reason}",
                                    attempt + 1,
                                    scheduler.options().max_retries
                                )),
                            );
                            thread::sleep(Duration::from_millis(100 * u64::from(attempt + 1)));
                        }
                        result
                    });
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
                            status: if manager.is_cancelled_for(&transfer_id, &peer.id) {
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
                        Some(transfer_id.clone()),
                    ));
                    reconcile_parent_history(
                        &history,
                        &transfer_id,
                        expected_children,
                        source_names.clone(),
                        item_count,
                        total_bytes,
                        &policy,
                    );
                    emit_parent_progress(
                        Some(&app),
                        &history,
                        &transfer_id,
                        expected_children,
                        total_bytes,
                    );
                    let event = if progress.status == "completed" {
                        "transfer-complete"
                    } else if progress.status == "cancelled" {
                        "transfer-cancelled"
                    } else {
                        "transfer-failed"
                    };
                    let _ = app.emit(event, progress);
                    manager.clear_recipient_cancel(&transfer_id, &peer.id);
                    manager.finish(&transfer_id);
                })
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        }
        Ok(transfer_id)
    }
}

pub fn is_secure_hello(value: &serde_json::Value) -> bool {
    value.get("kind").and_then(|value| value.as_str()) == Some("zapdrop_secure_hello")
}

pub fn is_transfer_hello(value: &serde_json::Value) -> bool {
    value.get("kind").and_then(|value| value.as_str()) == Some(HELLO_KIND)
}

#[cfg(feature = "swarm-v2")]
pub fn handle_secure_incoming(
    stream: TcpStream,
    first: serde_json::Value,
    context: TransferServerContext,
) {
    let hello: SecureHandshake = match serde_json::from_value(first).map_err(invalid) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let trusted = context
        .trust
        .list()
        .into_iter()
        .find(|peer| peer.peer_id == hello.device_id && peer.fingerprint == hello.fingerprint);
    let Some(trusted) = trusted else {
        let _ = write_error(&stream, "secure sender is not trusted");
        return;
    };
    let public_key_bytes = match BASE64.decode(&trusted.public_key).map_err(invalid) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let public_key_bytes: [u8; 32] = match public_key_bytes.try_into() {
        Ok(value) => value,
        Err(_) => {
            let _ = write_error(&stream, "trusted public key has invalid length");
            return;
        }
    };
    let peer_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &format!("invalid trusted public key: {error}"));
            return;
        }
    };
    let signing_key = match context.identity.signing_key(&context.store) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &format!("could not load device identity: {error}"));
            return;
        }
    };
    let (response, ephemeral) = match SecureHandshake::create(
        &signing_key,
        hello.session_id.clone(),
        context.identity.device_id.clone(),
        context.identity.fingerprint.clone(),
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    if write_json_line(&stream, &response).is_err() {
        return;
    }
    let mut channel = match establish_channel(
        &ephemeral,
        &response,
        &hello,
        &peer_key,
        &trusted.peer_id,
        &trusted.fingerprint,
        ChannelRole::Responder,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    let proof = match channel.seal(b"zapdrop-v2-secure-ready", b"secure-handshake-confirmation") {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    if write_json_line(&stream, &proof).is_err() {
        return;
    }
    let mut reader = match stream.try_clone() {
        Ok(clone) => BufReader::new(clone),
        Err(_) => return,
    };
    let frame: EncryptedFrame = match read_v2_frame(&mut reader) {
        Ok(value) => value,
        Err(_) => return,
    };
    let offer: V2DirectOffer = match open_v2_json(&mut channel, &frame, V2_JOB_AAD) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_error(&stream, &error.to_string());
            return;
        }
    };
    if let Err(error) = validate_v2_direct_offer(&offer, &context, &trusted.peer_id, &peer_key) {
        let _ = write_error(&stream, &error.to_string());
        return;
    }
    let received_at = epoch_seconds();
    let transfer_id = offer.job.job_id.clone();
    let incoming = IncomingTransferOffer {
        transfer_id: transfer_id.clone(),
        peer_id: trusted.peer_id.clone(),
        peer_name: trusted.name.clone(),
        items: offer.items.clone(),
        total_bytes: offer.total_bytes,
        conflict_policy: offer.conflict_policy.clone(),
        default_receive_directory: context.receive_directory.clone(),
        conflicts: existing_v2_conflicts(&context.receive_directory, &offer),
        received_at,
    };
    if context
        .offers
        .insert_v2(PendingV2TransferOffer {
            stream,
            reader,
            channel,
            offer,
            peer_id: trusted.peer_id.clone(),
            peer_name: trusted.name.clone(),
            peer_key,
            received_at,
        })
        .is_err()
    {
        return;
    }
    if let Some(app) = context.app.as_ref() {
        let _ = app.emit("incoming-transfer-offer", incoming);
    }
    if !context.always_ask_before_receive {
        let _ = context.offers.accept(
            &transfer_id,
            context.default_conflict_policy.clone(),
            None,
            context.clone(),
        );
    }
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
    if context
        .offers
        .insert(PendingTransferOffer {
            stream,
            manifest,
            peer_id,
            peer_name,
            received_at,
        })
        .is_err()
    {
        return;
    }
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

#[cfg(feature = "swarm-v2")]
fn seal_v2_json<T: Serialize>(
    channel: &mut crate::secure::SecureChannel,
    value: &T,
    aad: &[u8],
) -> io::Result<EncryptedFrame> {
    let bytes = serde_json::to_vec(value).map_err(invalid)?;
    channel.seal(&bytes, aad).map_err(invalid)
}

#[cfg(feature = "swarm-v2")]
fn open_v2_json<T: for<'de> Deserialize<'de>>(
    channel: &mut crate::secure::SecureChannel,
    frame: &EncryptedFrame,
    aad: &[u8],
) -> io::Result<T> {
    let bytes = channel.open(frame, aad).map_err(invalid)?;
    serde_json::from_slice(&bytes).map_err(invalid)
}

#[cfg(feature = "swarm-v2")]
fn v2_public_key(identity: &DeviceIdentity) -> io::Result<String> {
    let bytes = BASE64.decode(&identity.public_key).map_err(invalid)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(feature = "swarm-v2")]
fn create_v2_job(
    identity: &DeviceIdentity,
    transfer_id: &str,
    recipient_id: &str,
    items: &[ManifestItem],
    signing_key: &ed25519_dalek::SigningKey,
) -> io::Result<(SwarmJob, JobKey)> {
    let created_at = v2_epoch_seconds();
    let profile = ChunkProfile {
        profile_id: "fixed-4m-sha256-aead".to_string(),
        piece_size: crate::swarm::DEFAULT_PIECE_SIZE,
        max_in_flight_pieces: 8,
        hash: "sha256".to_string(),
        aead: "x25519-hkdf-sha256-chacha20poly1305".to_string(),
    };
    let snapshot_root = v2_snapshot_root(items)?;
    let mut job = SwarmJob {
        kind: "zapdrop_swarm_job".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job_id: transfer_id.to_string(),
        sender_id: identity.device_id.clone(),
        sender_public_key: v2_public_key(identity)?,
        sender_fingerprint: identity.fingerprint.clone(),
        snapshot_root,
        recipient_ids: vec![recipient_id.to_string()],
        distribution_mode: DistributionMode::Direct,
        chunk_profile: profile,
        content_key_id: format!("key-{transfer_id}"),
        created_at,
        expires_at: created_at.saturating_add(2 * 60 * 60),
        signature: String::new(),
    };
    sign_v2_job(&mut job, signing_key)?;
    job.validate_at(created_at).map_err(invalid)?;
    Ok((job, JobKey::generate()))
}

#[cfg(feature = "swarm-v2")]
fn send_v2_direct(
    app: Option<&AppHandle>,
    manager: Option<&TransferManager>,
    scheduler: Option<&SwarmScheduler>,
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
    peer: &PeerRecord,
    sources: &[TransferSource],
    policy: &str,
    transfer_id: &str,
) -> io::Result<()> {
    let address: SocketAddr = peer.endpoint.parse().map_err(invalid)?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
    stream.set_read_timeout(Some(Duration::from_secs(OFFER_TIMEOUT_SECS + 30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let signing_key = identity.signing_key(store)?;
    let (hello, ephemeral) = SecureHandshake::create(
        &signing_key,
        transfer_id.to_string(),
        identity.device_id.clone(),
        identity.fingerprint.clone(),
    )
    .map_err(invalid)?;
    write_json_line(&stream, &hello)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let peer_hello: SecureHandshake = read_json_line_from_reader(&mut reader)?;
    let encoded_public_key = peer
        .public_key
        .as_deref()
        .ok_or_else(|| invalid("peer public key is unavailable"))?;
    let public_key_bytes = BASE64.decode(encoded_public_key).map_err(invalid)?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| invalid("peer public key has invalid length"))?;
    let peer_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(invalid)?;
    let mut channel = establish_channel(
        &ephemeral,
        &hello,
        &peer_hello,
        &peer_key,
        &peer.id,
        peer.fingerprint.as_deref().unwrap_or_default(),
        ChannelRole::Initiator,
    )
    .map_err(invalid)?;
    let proof: EncryptedFrame = read_json_line_from_reader(&mut reader)?;
    let proof_bytes = channel
        .open(&proof, b"secure-handshake-confirmation")
        .map_err(invalid)?;
    if proof_bytes != b"zapdrop-v2-secure-ready" {
        return Err(invalid("secure handshake proof mismatch"));
    }
    let profile = ChunkProfile {
        profile_id: "fixed-4m-sha256-aead".to_string(),
        piece_size: crate::swarm::DEFAULT_PIECE_SIZE,
        max_in_flight_pieces: 8,
        hash: "sha256".to_string(),
        aead: "x25519-hkdf-sha256-chacha20poly1305".to_string(),
    };
    let manifest = build_v2_manifest(sources, &profile)?;
    verify_v2_sources_unchanged(sources, &manifest)?;
    let total_bytes = manifest.iter().try_fold(0u64, |total, item| {
        total
            .checked_add(item.size)
            .ok_or_else(|| invalid("v2 manifest size overflow"))
    })?;
    let (job, job_key) = create_v2_job(identity, transfer_id, &peer.id, &manifest, &signing_key)?;
    let offer = V2DirectOffer {
        kind: V2_DIRECT_OFFER_KIND.to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job: job.clone(),
        items: manifest.clone(),
        total_bytes,
        conflict_policy: policy.to_string(),
        key_envelope: None,
    };
    write_v2_frame(&stream, &seal_v2_json(&mut channel, &offer, V2_JOB_AAD)?)?;
    let decision_frame: EncryptedFrame = read_v2_frame(&mut reader)?;
    let decision: V2DirectDecision = open_v2_json(&mut channel, &decision_frame, V2_JOB_AAD)?;
    if !decision.accepted || decision.job_id != job.job_id {
        return Err(invalid(
            decision
                .reason
                .unwrap_or_else(|| "receiver rejected v2 direct job".to_string()),
        ));
    }
    let key_envelope = channel
        .wrap_job_key(&job, &peer.id, &job.content_key_id, &job_key)
        .map_err(invalid)?;
    let key_provision = V2DirectKeyProvision {
        kind: "zapdrop_swarm_direct_key".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job_id: job.job_id.clone(),
        key_envelope,
    };
    write_v2_frame(
        &stream,
        &seal_v2_json(&mut channel, &key_provision, V2_JOB_AAD)?,
    )?;
    let ready_frame: EncryptedFrame = read_v2_frame(&mut reader)?;
    let ready: V2DirectReady = open_v2_json(&mut channel, &ready_frame, V2_JOB_AAD)?;
    if ready.kind != V2_DIRECT_READY_KIND
        || ready.version != SWARM_PROTOCOL_VERSION
        || ready.job_id != job.job_id
    {
        return Err(invalid("invalid v2 direct ready frame"));
    }
    let piece_size = job.chunk_profile.piece_size as usize;
    let mut sent_bytes = 0u64;
    for item in &manifest {
        sent_bytes = sent_bytes.saturating_add(
            if let Some(ranges) = ready.missing_ranges.get(&item.item_id) {
                item.size
                    .saturating_sub(ranges.iter().map(|range| range.length).sum())
            } else {
                *ready.offsets.get(&item.item_id).unwrap_or(&0)
            },
        );
        let source = source_for_item(sources, item)?;
        let mut file = File::open(source)?;
        let offset = *ready.offsets.get(&item.item_id).unwrap_or(&0);
        if offset > item.size || offset % job.chunk_profile.piece_size != 0 {
            return Err(invalid("receiver supplied an invalid v2 resume offset"));
        }
        let ranges = ready
            .missing_ranges
            .get(&item.item_id)
            .cloned()
            .unwrap_or_else(|| {
                if offset < item.size {
                    vec![crate::snapshot::ByteRange {
                        offset,
                        length: item.size - offset,
                    }]
                } else {
                    Vec::new()
                }
            });
        validate_v2_missing_ranges(&ranges, item.size, job.chunk_profile.piece_size)?;
        let mut buffer = vec![0u8; piece_size];
        for range in ranges {
            let mut current = range.offset;
            let end = range.offset + range.length;
            file.seek(SeekFrom::Start(current))?;
            let mut index = current / job.chunk_profile.piece_size;
            while current < end {
                if manager.is_some_and(|manager| manager.is_cancelled_for(transfer_id, &peer.id)) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "v2 transfer cancelled",
                    ));
                }
                let target = (end - current).min(piece_size as u64) as usize;
                let read = file.read(&mut buffer[..target])?;
                if read == 0 {
                    return Err(invalid("source ended before v2 manifest range"));
                }
                let piece_id = format!("piece-{}-{index}", item.item_id);
                let (header, ciphertext) = seal_piece(
                    &job_key,
                    &job.job_id,
                    &job.snapshot_root,
                    &piece_id,
                    &item.item_id,
                    index,
                    current,
                    &buffer[..read],
                )
                .map_err(invalid)?;
                let piece = V2DirectPiece {
                    kind: V2_DIRECT_PIECE_KIND.to_string(),
                    version: SWARM_PROTOCOL_VERSION,
                    header,
                    ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
                };
                if let Some(scheduler) = scheduler {
                    scheduler.throttle(read);
                }
                write_v2_frame(&stream, &seal_v2_json(&mut channel, &piece, V2_PIECE_AAD)?)?;
                current += read as u64;
                index += 1;
                sent_bytes += read as u64;
                emit_progress(
                    app,
                    transfer_id,
                    &peer.id,
                    &peer.name,
                    "send",
                    "transferring",
                    Some(item.relative_path.clone()),
                    sent_bytes,
                    total_bytes,
                    0,
                    manifest.len(),
                    None,
                );
            }
        }
    }
    let completion_frame: EncryptedFrame = read_v2_frame(&mut reader)?;
    let completion: V2DirectCompletion =
        open_v2_json(&mut channel, &completion_frame, V2_COMPLETE_AAD)?;
    if completion.kind != V2_DIRECT_COMPLETE_KIND
        || completion.version != SWARM_PROTOCOL_VERSION
        || completion.job_id != job.job_id
        || completion.status != "completed"
        || completion.total_bytes != total_bytes
        || completion.digest != job.snapshot_root
    {
        return Err(invalid(completion.reason.unwrap_or_else(|| {
            "v2 direct transfer completion proof failed".to_string()
        })));
    }
    let _ = device_name;
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn receive_v2_direct(
    stream: &TcpStream,
    reader: &mut BufReader<TcpStream>,
    channel: &mut crate::secure::SecureChannel,
    offer: V2DirectOffer,
    context: &TransferServerContext,
    peer_id: &str,
    peer_name: &str,
    peer_key: &VerifyingKey,
    decision_already_sent: bool,
) -> io::Result<()> {
    let transfer_id = offer.job.job_id.clone();
    let source_names = offer
        .items
        .iter()
        .map(|item| item.relative_path.clone())
        .collect::<Vec<_>>();
    let total_bytes = offer.total_bytes;
    let total_items = offer.items.len();
    let policy = offer.conflict_policy.clone();
    let started_at = epoch_seconds();
    let _ = context.history.record(TransferHistoryEntry {
        id: format!("{transfer_id}:{peer_id}"),
        transfer_id: transfer_id.clone(),
        parent_id: None,
        direction: "receive".to_string(),
        peer_id: peer_id.to_string(),
        peer_name: peer_name.to_string(),
        status: "started".to_string(),
        source_names: source_names.clone(),
        items: total_items,
        total_bytes,
        bytes_done: 0,
        conflict_policy: policy.clone(),
        started_at,
        finished_at: None,
        error: None,
    });
    emit_progress(
        context.app.as_ref(),
        &transfer_id,
        peer_id,
        peer_name,
        "receive",
        "started",
        None,
        0,
        total_bytes,
        0,
        total_items,
        None,
    );
    let result = receive_v2_direct_inner(
        stream,
        reader,
        channel,
        offer,
        context,
        peer_id,
        peer_name,
        peer_key,
        decision_already_sent,
    );
    let (status, error) = match &result {
        Ok(()) => ("completed", None),
        Err(error) => ("failed", Some(error.to_string())),
    };
    let progress = TransferProgress {
        transfer_id: transfer_id.clone(),
        peer_id: peer_id.to_string(),
        peer_name: peer_name.to_string(),
        direction: "receive".to_string(),
        status: status.to_string(),
        current_path: None,
        bytes_done: if result.is_ok() { total_bytes } else { 0 },
        total_bytes,
        items_done: if result.is_ok() { total_items } else { 0 },
        total_items,
        error: error.clone(),
    };
    let _ = context.history.record(history_entry(
        &progress,
        source_names,
        &policy,
        started_at,
        None,
    ));
    let event = match status {
        "completed" => "transfer-complete",
        _ => "transfer-failed",
    };
    if let Some(app) = context.app.as_ref() {
        let _ = app.emit(event, progress);
    }
    result
}

#[cfg(feature = "swarm-v2")]
fn validate_v2_direct_offer(
    offer: &V2DirectOffer,
    context: &TransferServerContext,
    peer_id: &str,
    peer_key: &VerifyingKey,
) -> io::Result<()> {
    if offer.kind != V2_DIRECT_OFFER_KIND || offer.version != SWARM_PROTOCOL_VERSION {
        return Err(invalid("invalid v2 direct offer"));
    }
    verify_v2_job(&offer.job, peer_key)?;
    if offer.job.sender_id != peer_id
        || offer.job.sender_public_key != URL_SAFE_NO_PAD.encode(peer_key.to_bytes())
        || offer.job.sender_fingerprint != fingerprint(&peer_key.to_bytes())
        || offer.job.distribution_mode != DistributionMode::Direct
        || offer.job.chunk_profile.profile_id != "fixed-4m-sha256-aead"
        || offer.job.chunk_profile.piece_size != crate::swarm::DEFAULT_PIECE_SIZE
        || offer.job.chunk_profile.aead != "x25519-hkdf-sha256-chacha20poly1305"
        || !offer.job.authorizes(&context.identity.device_id)
        || offer.items.is_empty()
        || offer.items.len() > MAX_V2_DIRECT_ITEMS
        || offer.total_bytes > MAX_V2_DIRECT_TOTAL_BYTES
        || offer.key_envelope.is_some()
    {
        return Err(invalid("v2 direct job authorization or manifest mismatch"));
    }
    validate_v2_component("jobId", &offer.job.job_id)?;
    if context.history.list().iter().any(|entry| {
        entry.transfer_id == offer.job.job_id
            && entry.peer_id == peer_id
            && entry.status == "completed"
    }) {
        return Err(invalid("v2 job has already completed"));
    }
    normalize_conflict_policy(&offer.conflict_policy)?;
    let mut item_ids = HashSet::with_capacity(offer.items.len());
    let mut paths = HashSet::with_capacity(offer.items.len());
    let total_bytes = offer.items.iter().try_fold(0u64, |total, item| {
        validate_v2_component("itemId", &item.item_id)?;
        validate_relative_path(&item.relative_path)?;
        if item.kind != "file" {
            return Err(invalid("v2 direct jobs support regular files only"));
        }
        if !item_ids.insert(item.item_id.as_str()) || !paths.insert(item.relative_path.as_str()) {
            return Err(invalid(
                "v2 direct manifest contains duplicate IDs or paths",
            ));
        }
        if !is_sha256_hex(&item.sha256) {
            return Err(invalid("v2 direct manifest contains an invalid digest"));
        }
        total
            .checked_add(item.size)
            .ok_or_else(|| invalid("v2 direct size overflow"))
    })?;
    if total_bytes != offer.total_bytes
        || v2_snapshot_root(&offer.items)? != offer.job.snapshot_root
    {
        return Err(invalid("v2 direct snapshot root or total mismatch"));
    }
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn validate_v2_component(field: &str, value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > crate::swarm::MAX_SWARM_ID_BYTES
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(|character| character.is_control())
    {
        return Err(invalid(format!("invalid v2 {field}")));
    }
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(feature = "swarm-v2")]
fn v2_snapshot_root(items: &[ManifestItem]) -> io::Result<String> {
    let mut canonical = items.to_vec();
    canonical.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then_with(|| left.item_id.cmp(&right.item_id))
    });
    let bytes = serde_json::to_vec(&canonical).map_err(invalid)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

#[cfg(feature = "swarm-v2")]
fn v2_partial_path(root: &Path, job_id: &str, item_id: &str) -> io::Result<PathBuf> {
    let partial_root = root.join(".zapdrop-partial");
    reject_symlink(&partial_root)?;
    fs::create_dir_all(&partial_root)?;
    let job_root = partial_root.join(format!("job-{}", digest_bytes(job_id.as_bytes())));
    reject_symlink(&job_root)?;
    fs::create_dir_all(&job_root)?;
    if !fs::canonicalize(&job_root)?.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "v2 partial directory escapes receive root",
        ));
    }
    Ok(job_root.join(format!("item-{}.part", digest_bytes(item_id.as_bytes()))))
}

#[cfg(feature = "swarm-v2")]
fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symlinked transfer staging path is not allowed",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "swarm-v2")]
fn receive_v2_direct_inner(
    stream: &TcpStream,
    reader: &mut BufReader<TcpStream>,
    channel: &mut crate::secure::SecureChannel,
    offer: V2DirectOffer,
    context: &TransferServerContext,
    peer_id: &str,
    peer_name: &str,
    peer_key: &VerifyingKey,
    decision_already_sent: bool,
) -> io::Result<()> {
    validate_v2_direct_offer(&offer, context, peer_id, peer_key)?;
    let policy = normalize_conflict_policy(&context.default_conflict_policy)?;
    let destination = safe_root(&context.receive_directory)?;
    crate::snapshot::disk_space_preflight(&destination, offer.total_bytes, None)?;
    if !decision_already_sent {
        let decision = V2DirectDecision {
            kind: V2_DIRECT_DECISION_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: offer.job.job_id.clone(),
            accepted: true,
            destination: Some(destination.to_string_lossy().to_string()),
            conflict_policy: policy.clone(),
            reason: None,
        };
        write_v2_frame(stream, &seal_v2_json(channel, &decision, V2_JOB_AAD)?)?;
    }
    let key_frame: EncryptedFrame = read_v2_frame(reader)?;
    let key_provision: V2DirectKeyProvision = open_v2_json(channel, &key_frame, V2_JOB_AAD)?;
    if key_provision.kind != "zapdrop_swarm_direct_key"
        || key_provision.version != SWARM_PROTOCOL_VERSION
        || key_provision.job_id != offer.job.job_id
    {
        return Err(invalid("invalid v2 job-key provision"));
    }
    let job_key = channel
        .unwrap_job_key(
            &key_provision.key_envelope,
            &offer.job,
            &context.identity.device_id,
        )
        .map_err(invalid)?;
    let journal_file = crate::snapshot::journal_path(&destination, &offer.job.job_id);
    let mut journal = match crate::snapshot::TransferJournal::load(&journal_file) {
        Ok(existing)
            if existing.job_id == offer.job.job_id
                && existing.snapshot_root == offer.job.snapshot_root =>
        {
            existing
        }
        Ok(_) => crate::snapshot::TransferJournal::new(
            offer.job.job_id.clone(),
            offer.job.snapshot_root.clone(),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::snapshot::TransferJournal::new(
                offer.job.job_id.clone(),
                offer.job.snapshot_root.clone(),
            )
        }
        Err(error) => return Err(error),
    };
    journal.save_atomic(&journal_file)?;
    let mut offsets = HashMap::new();
    let mut total_done = 0u64;
    for item in &offer.items {
        let partial = v2_partial_path(&destination, &offer.job.job_id, &item.item_id)?;
        reject_symlink(&partial)?;
        let partial_offset = fs::metadata(&partial)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let journal_offset = journal.contiguous_offset(&item.item_id, item.size);
        let mut offset = partial_offset;
        if partial_offset != 0 && journal_offset == 0 {
            let _ = fs::remove_file(&partial);
            offset = 0;
        }
        if journal_offset != 0 && journal_offset != partial_offset && partial_offset != item.size {
            let _ = fs::remove_file(&partial);
            offset = 0;
        }
        if offset > item.size || offset % offer.job.chunk_profile.piece_size != 0 {
            let _ = fs::remove_file(&partial);
            offset = 0;
        }
        offsets.insert(item.item_id.clone(), offset);
        total_done = total_done.saturating_add(journal.verified_bytes(&item.item_id, item.size));
    }
    let mut missing_ranges = HashMap::new();
    for item in &offer.items {
        let item_missing =
            journal.missing_ranges(&item.item_id, item.size, offer.job.chunk_profile.piece_size)?;
        if !item_missing.is_empty() {
            missing_ranges.insert(item.item_id.clone(), item_missing);
        }
    }
    let ready = V2DirectReady {
        kind: V2_DIRECT_READY_KIND.to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job_id: offer.job.job_id.clone(),
        offsets,
        missing_ranges,
    };
    write_v2_frame(stream, &seal_v2_json(channel, &ready, V2_JOB_AAD)?)?;
    let mut completed = 0usize;
    for item in &offer.items {
        let partial = v2_partial_path(&destination, &offer.job.job_id, &item.item_id)?;
        reject_symlink(&partial)?;
        let ranges =
            journal.missing_ranges(&item.item_id, item.size, offer.job.chunk_profile.piece_size)?;
        validate_v2_missing_ranges(&ranges, item.size, offer.job.chunk_profile.piece_size)?;
        for range in ranges {
            let mut offset = range.offset;
            let range_end = range.offset + range.length;
            let mut index = offset / offer.job.chunk_profile.piece_size;
            while offset < range_end {
                if context
                    .cancelled
                    .lock()
                    .expect("cancel set poisoned")
                    .contains(&offer.job.job_id)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "v2 transfer cancelled",
                    ));
                }
                let frame: EncryptedFrame = read_v2_frame(reader)?;
                let piece: V2DirectPiece = open_v2_json(channel, &frame, V2_PIECE_AAD)?;
                if piece.kind != V2_DIRECT_PIECE_KIND || piece.version != SWARM_PROTOCOL_VERSION {
                    return Err(invalid("invalid v2 direct piece frame"));
                }
                piece
                    .header
                    .validate_against(&offer.job.chunk_profile)
                    .map_err(invalid)?;
                if piece.header.job_id != offer.job.job_id
                    || piece.header.object_id != item.item_id
                    || piece.header.index != index
                    || piece.header.offset != offset
                    || piece.header.plaintext_length > range_end.saturating_sub(offset)
                {
                    return Err(invalid("v2 direct piece does not match manifest offset"));
                }
                let ciphertext = URL_SAFE_NO_PAD.decode(&piece.ciphertext).map_err(invalid)?;
                let plaintext = open_piece(
                    &job_key,
                    &offer.job.snapshot_root,
                    &piece.header,
                    &ciphertext,
                )
                .map_err(invalid)?;
                if plaintext.len() as u64 != piece.header.plaintext_length {
                    return Err(invalid("v2 direct piece plaintext length mismatch"));
                }
                reject_symlink(&partial)?;
                if let Some(parent) = partial.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut file = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(&partial)?;
                file.set_len(item.size)?;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&plaintext)?;
                file.flush()?;
                journal.mark_verified(
                    &item.item_id,
                    &item.sha256,
                    &item.relative_path,
                    crate::snapshot::ByteRange {
                        offset,
                        length: plaintext.len() as u64,
                    },
                )?;
                journal.save_atomic(&journal_file)?;
                offset += plaintext.len() as u64;
                index += 1;
                total_done += plaintext.len() as u64;
                emit_progress(
                    context.app.as_ref(),
                    &offer.job.job_id,
                    peer_id,
                    peer_name,
                    "receive",
                    "transferring",
                    Some(item.relative_path.clone()),
                    total_done,
                    offer.total_bytes,
                    completed,
                    offer.items.len(),
                    None,
                );
            }
        }
        if digest_file(&partial)? != item.sha256 {
            return Err(invalid("v2 direct file digest mismatch"));
        }
        if let Some(final_path) = destination_path(&destination, &item.relative_path, &policy)? {
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent)?;
            }
            reject_symlink(&final_path)?;
            fs::rename(&partial, &final_path)?;
        }
        journal.mark_complete(&item.item_id, &item.sha256, &item.relative_path);
        journal.save_atomic(&journal_file)?;
        completed += 1;
        emit_progress(
            context.app.as_ref(),
            &offer.job.job_id,
            peer_id,
            peer_name,
            "receive",
            "transferring",
            Some(item.relative_path.clone()),
            total_done,
            offer.total_bytes,
            completed,
            offer.items.len(),
            None,
        );
    }
    let completion = V2DirectCompletion {
        kind: V2_DIRECT_COMPLETE_KIND.to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job_id: offer.job.job_id,
        status: "completed".to_string(),
        total_bytes: total_done,
        digest: offer.job.snapshot_root,
        reason: None,
    };
    write_v2_frame(
        stream,
        &seal_v2_json(channel, &completion, V2_COMPLETE_AAD)?,
    )?;
    let _ = (context, peer_name);
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn send_v2_secure_probe(
    identity: &DeviceIdentity,
    store: &SettingsStore,
    device_name: &str,
    peer: &PeerRecord,
    session_id: &str,
) -> io::Result<()> {
    let address: SocketAddr = peer.endpoint.parse().map_err(invalid)?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(12)))?;
    let signing_key = identity.signing_key(store)?;
    let (hello, ephemeral) = SecureHandshake::create(
        &signing_key,
        session_id.to_string(),
        identity.device_id.clone(),
        identity.fingerprint.clone(),
    )
    .map_err(invalid)?;
    write_json_line(&stream, &hello)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let peer_hello: SecureHandshake = read_json_line_from_reader(&mut reader)?;
    let encoded_public_key = peer
        .public_key
        .as_deref()
        .ok_or_else(|| invalid("peer public key is unavailable"))?;
    let public_key_bytes = BASE64.decode(encoded_public_key).map_err(invalid)?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| invalid("peer public key has invalid length"))?;
    let peer_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(invalid)?;
    let mut channel = establish_channel(
        &ephemeral,
        &hello,
        &peer_hello,
        &peer_key,
        &peer.id,
        peer.fingerprint.as_deref().unwrap_or_default(),
        ChannelRole::Initiator,
    )
    .map_err(invalid)?;
    let proof: EncryptedFrame = read_json_line_from_reader(&mut reader)?;
    let plaintext = channel
        .open(&proof, b"secure-handshake-confirmation")
        .map_err(invalid)?;
    if plaintext != b"zapdrop-v2-secure-ready" {
        return Err(invalid("secure handshake proof mismatch"));
    }
    let _ = device_name;
    Ok(())
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
    scheduler: Option<&SwarmScheduler>,
) -> io::Result<()> {
    #[cfg(feature = "swarm-v2")]
    if v2_switch_enabled("ZAPDROP_SWARM_V2_DIRECT") {
        return send_v2_direct(
            app,
            Some(manager),
            scheduler,
            identity,
            store,
            device_name,
            peer,
            sources,
            policy,
            transfer_id,
        );
    }
    #[cfg(feature = "swarm-v2")]
    if v2_switch_enabled("ZAPDROP_SWARM_V2_PROBE") {
        return send_v2_secure_probe(identity, store, device_name, peer, transfer_id);
    }
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
            if manager.is_cancelled_for(transfer_id, &peer.id) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "transfer cancelled",
                ));
            }
            let read = file.read(&mut buffer)?;
            if read == 0 {
                return Err(invalid("source ended before manifest size"));
            }
            if let Some(scheduler) = scheduler {
                scheduler.throttle(read);
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
        None,
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

#[cfg(feature = "swarm-v2")]
fn existing_v2_conflicts(directory: &str, offer: &V2DirectOffer) -> Vec<String> {
    let Ok(root) = safe_root(directory) else {
        return Vec::new();
    };
    offer
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

#[cfg(feature = "swarm-v2")]
fn build_v2_manifest(
    sources: &[TransferSource],
    profile: &ChunkProfile,
) -> io::Result<Vec<ManifestItem>> {
    let snapshot_sources = sources
        .iter()
        .map(|source| {
            let path = PathBuf::from(&source.path);
            let relative_path = source.relative_path.clone().unwrap_or_else(|| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });
            crate::snapshot::SnapshotSource {
                path,
                relative_path,
            }
        })
        .collect::<Vec<_>>();
    let snapshot = crate::snapshot::build_snapshot(
        &snapshot_sources,
        &crate::snapshot::SnapshotOptions {
            chunk_profile: profile.clone(),
            page_bytes: crate::snapshot::DEFAULT_SNAPSHOT_PAGE_BYTES,
        },
    )?;
    let mut items = snapshot
        .files
        .into_iter()
        .map(|file| ManifestItem {
            item_id: stable_item_id(&file.relative_path),
            relative_path: file.relative_path,
            kind: "file".to_string(),
            size: file.size,
            sha256: file.sha256,
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(items)
}

#[cfg(feature = "swarm-v2")]
fn validate_v2_missing_ranges(
    ranges: &[crate::snapshot::ByteRange],
    total_bytes: u64,
    piece_size: u64,
) -> io::Result<()> {
    if piece_size == 0 {
        return Err(invalid("v2 piece size cannot be zero"));
    }
    let mut end = 0u64;
    for range in ranges {
        if range.length == 0
            || range.offset < end
            || range.offset % piece_size != 0
            || range.length > piece_size
            || range.offset.checked_add(range.length).is_none()
            || range.offset + range.length > total_bytes
        {
            return Err(invalid("invalid v2 missing range"));
        }
        end = range.offset + range.length;
    }
    Ok(())
}

#[cfg(feature = "swarm-v2")]
fn verify_v2_sources_unchanged(
    sources: &[TransferSource],
    manifest: &[ManifestItem],
) -> io::Result<()> {
    for item in manifest {
        let source = source_for_item(sources, item)?;
        let generation = crate::snapshot::capture_source_generation(&source)?;
        if generation.size != item.size || generation.sha256 != item.sha256 {
            return Err(invalid(format!(
                "source changed since v2 snapshot creation: {}",
                item.relative_path
            )));
        }
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
    items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
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
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || Path::new(value).is_absolute()
    {
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
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination symlink is not allowed",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
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
    digest_file_prefix(path, u64::MAX)
}

fn digest_file_prefix(path: &Path, limit: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut remaining = limit;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
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
fn is_retryable_transfer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
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
fn emit_parent_progress(
    app: Option<&AppHandle>,
    history: &HistoryStore,
    transfer_id: &str,
    expected_children: usize,
    total_bytes: u64,
) {
    let children = history
        .list()
        .into_iter()
        .filter(|entry| entry.parent_id.as_deref() == Some(transfer_id))
        .collect::<Vec<_>>();
    let completed = children
        .iter()
        .filter(|entry| entry.status == "completed")
        .count();
    let failed = children
        .iter()
        .filter(|entry| entry.status == "failed")
        .count();
    let cancelled = children
        .iter()
        .filter(|entry| entry.status == "cancelled")
        .count();
    let done = completed + failed + cancelled;
    let status = if done < expected_children {
        "transferring"
    } else if completed == expected_children {
        "completed"
    } else if completed > 0 {
        "partial"
    } else if cancelled == expected_children {
        "cancelled"
    } else {
        "failed"
    };
    let payload = ParentTransferProgress {
        transfer_id: transfer_id.to_string(),
        status: status.to_string(),
        recipients_total: expected_children,
        recipients_done: done,
        recipients_completed: completed,
        recipients_failed: failed,
        recipients_cancelled: cancelled,
        bytes_done: children.iter().map(|entry| entry.bytes_done).sum(),
        total_bytes,
    };
    if let Some(app) = app {
        let _ = app.emit("transfer-parent-progress", payload);
    }
}

fn reconcile_parent_history(
    history: &HistoryStore,
    parent_id: &str,
    expected_children: usize,
    source_names: Vec<String>,
    items: usize,
    total_bytes: u64,
    policy: &str,
) {
    let children = history
        .list()
        .into_iter()
        .filter(|entry| entry.parent_id.as_deref() == Some(parent_id))
        .collect::<Vec<_>>();
    if children.len() < expected_children {
        return;
    }
    let completed = children
        .iter()
        .filter(|entry| entry.status == "completed")
        .count();
    let cancelled = children
        .iter()
        .filter(|entry| entry.status == "cancelled")
        .count();
    let status = if completed == expected_children {
        "completed"
    } else if completed > 0 {
        "partial"
    } else if cancelled == expected_children {
        "cancelled"
    } else {
        "failed"
    };
    let error = if status == "partial" || status == "failed" {
        Some(format!(
            "{completed}/{expected_children} recipient sessions completed"
        ))
    } else {
        None
    };
    let _ = history.record(TransferHistoryEntry {
        id: parent_id.to_string(),
        transfer_id: parent_id.to_string(),
        parent_id: None,
        direction: "send".to_string(),
        peer_id: "swarm".to_string(),
        peer_name: "Swarm job".to_string(),
        status: status.to_string(),
        source_names,
        items,
        total_bytes,
        bytes_done: children.iter().map(|entry| entry.bytes_done).sum(),
        conflict_policy: policy.to_string(),
        started_at: children
            .iter()
            .map(|entry| entry.started_at)
            .min()
            .unwrap_or_else(epoch_seconds),
        finished_at: Some(epoch_seconds()),
        error,
    });
}

fn history_entry(
    progress: &TransferProgress,
    source_names: Vec<String>,
    policy: &str,
    started_at: u64,
    parent_id: Option<String>,
) -> TransferHistoryEntry {
    TransferHistoryEntry {
        id: format!("{}:{}", progress.transfer_id, progress.peer_id),
        transfer_id: progress.transfer_id.clone(),
        parent_id,
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
    read_json_line_limited(reader, 64 * 1024)
}

fn read_json_line_limited<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> io::Result<T> {
    let mut line = Vec::with_capacity(max_bytes.min(8 * 1024));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "transfer frame ended before newline",
                ));
            }
            return Err(invalid("transfer frame ended before newline"));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(consumed) > max_bytes {
            return Err(invalid("transfer frame too large"));
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            return serde_json::from_slice(line.trim_ascii()).map_err(invalid);
        }
    }
}

#[cfg(feature = "swarm-v2")]
fn write_v2_frame<T: Serialize>(stream: &TcpStream, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(invalid)?;
    if payload.is_empty() || payload.len() > MAX_V2_FRAME_BYTES {
        return Err(invalid("v2 frame exceeds protocol limit"));
    }
    let length = u32::try_from(payload.len()).map_err(|_| invalid("v2 frame length overflow"))?;
    let mut writer = stream.try_clone()?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)
}

#[cfg(feature = "swarm-v2")]
fn read_v2_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl BufRead) -> io::Result<T> {
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_V2_FRAME_BYTES {
        return Err(invalid("v2 frame exceeds protocol limit"));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(invalid)
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
        io::Cursor,
        net::TcpListener,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
    };
    #[test]
    fn retries_only_transient_network_errors() {
        assert!(is_retryable_transfer_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert!(is_retryable_transfer_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset",
        )));
        assert!(!is_retryable_transfer_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied",
        )));
        assert!(!is_retryable_transfer_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid",
        )));
    }

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
    fn local_three_recipient_parent_harness() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-fanout-harness-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let settings = SettingsStore::new(root.clone());
        let history = HistoryStore::load(&settings).unwrap();
        let manager = TransferManager::new(history.clone());
        let parent_id = "local-fanout-harness";
        let total_bytes = 300;
        let peers = ["peer-1", "peer-2", "peer-3"];
        history
            .record(TransferHistoryEntry {
                id: parent_id.to_string(),
                transfer_id: parent_id.to_string(),
                parent_id: None,
                direction: "send".to_string(),
                peer_id: "swarm".to_string(),
                peer_name: "Swarm job".to_string(),
                status: "started".to_string(),
                source_names: vec!["fixture.bin".to_string()],
                items: 1,
                total_bytes,
                bytes_done: 0,
                conflict_policy: "rename".to_string(),
                started_at: 1,
                finished_at: None,
                error: None,
            })
            .unwrap();
        manager
            .active
            .lock()
            .unwrap()
            .insert(parent_id.to_string(), peers.len());
        manager.cancel_recipient(parent_id, "peer-3");
        let scheduler = SwarmScheduler::new(SwarmSchedulerOptions {
            max_parallel_recipients: 1,
            queue_limit: 2,
            ..Default::default()
        })
        .unwrap();
        let barrier = Arc::new(Barrier::new(peers.len()));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for peer_id in peers {
            let history = history.clone();
            let manager = manager.clone();
            let scheduler = scheduler.clone();
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let permit = scheduler.acquire(peer_id).unwrap();
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(2));
                let cancelled = manager.is_cancelled_for(parent_id, peer_id);
                let (status, bytes_done, error) = if cancelled {
                    ("cancelled", 0, Some("recipient cancelled".to_string()))
                } else if peer_id == "peer-2" {
                    ("failed", 0, Some("simulated recipient failure".to_string()))
                } else {
                    ("completed", 100, None)
                };
                history
                    .record(TransferHistoryEntry {
                        id: format!("{parent_id}:{peer_id}"),
                        transfer_id: parent_id.to_string(),
                        parent_id: Some(parent_id.to_string()),
                        direction: "send".to_string(),
                        peer_id: peer_id.to_string(),
                        peer_name: peer_id.to_string(),
                        status: status.to_string(),
                        source_names: vec!["fixture.bin".to_string()],
                        items: 1,
                        total_bytes: 100,
                        bytes_done,
                        conflict_policy: "rename".to_string(),
                        started_at: 1,
                        finished_at: Some(2),
                        error,
                    })
                    .unwrap();
                reconcile_parent_history(
                    &history,
                    parent_id,
                    3,
                    vec!["fixture.bin".to_string()],
                    1,
                    total_bytes,
                    "rename",
                );
                active.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
                manager.clear_recipient_cancel(parent_id, peer_id);
                manager.finish(parent_id);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let entries = history.list();
        let parent = entries.iter().find(|entry| entry.id == parent_id).unwrap();
        assert_eq!(parent.status, "partial");
        assert_eq!(parent.bytes_done, 100);
        assert_eq!(parent.total_bytes, total_bytes);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.parent_id.as_deref() == Some(parent_id))
                .count(),
            3
        );
        assert!(peak.load(Ordering::SeqCst) <= 1);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(!manager.active.lock().unwrap().contains_key(parent_id));
        fs::remove_dir_all(root).unwrap();
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
                None,
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
                None,
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

    #[cfg(feature = "swarm-v2")]
    #[test]
    fn secure_v2_direct_file_transfer_roundtrip() {
        let root = std::env::temp_dir().join(format!("zapdrop-direct-v2-{}", uuid::Uuid::new_v4()));
        let server_data = root.join("server-data");
        let client_data = root.join("client-data");
        let source = root.join("source.txt");
        let received = root.join("received");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, b"encrypted v2 direct transfer\n").unwrap();
        let server_store = SettingsStore::new(server_data);
        let client_store = SettingsStore::new(client_data);
        let server_identity = DeviceIdentity::load_or_create(&server_store).unwrap();
        let client_identity = DeviceIdentity::load_or_create(&client_store).unwrap();
        let server_trust = TrustedPeerStore::load(&server_store).unwrap();
        server_trust
            .upsert(TrustedPeer {
                version: 1,
                peer_id: client_identity.device_id.clone(),
                name: "Secure Client".to_string(),
                public_key: client_identity.public_key.clone(),
                fingerprint: client_identity.fingerprint.clone(),
                first_seen: 1,
                last_seen: 1,
                endpoint: "127.0.0.1:0".to_string(),
            })
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let mut context = test_context(
            server_identity.clone(),
            server_store.clone(),
            server_trust,
            received.clone(),
            "Secure Server",
        );
        context.always_ask_before_receive = true;
        let approval_offers = context.offers.clone();
        let approval_context = context.clone();
        let server = thread::spawn(move || {
            let (stream, address) = listener.accept().unwrap();
            let first: serde_json::Value = read_json_line(&stream).unwrap();
            assert!(is_secure_hello(&first));
            let _ = address;
            handle_secure_incoming(stream, first, context);
        });
        let peer = PeerRecord {
            id: server_identity.device_id.clone(),
            name: "Secure Server".to_string(),
            platform: "windows".to_string(),
            fingerprint: Some(server_identity.fingerprint.clone()),
            public_key: Some(server_identity.public_key.clone()),
            endpoint: endpoint.to_string(),
            port: endpoint.port(),
            status: "trusted".to_string(),
            discovered_via: "secure-v2-direct-test".to_string(),
            last_seen: epoch_seconds(),
            trusted: true,
        };
        let sender = thread::spawn({
            let client_identity = client_identity.clone();
            let client_store = client_store.clone();
            let peer = peer.clone();
            let source = source.clone();
            move || {
                send_v2_direct(
                    None,
                    None,
                    None,
                    &client_identity,
                    &client_store,
                    "Secure Client",
                    &peer,
                    &[TransferSource {
                        path: source.to_string_lossy().to_string(),
                        relative_path: Some("source.txt".to_string()),
                    }],
                    "rename",
                    "secure-direct-file",
                )
            }
        });
        for _ in 0..20 {
            if approval_offers
                .list(&received.to_string_lossy())
                .iter()
                .any(|offer| offer.transfer_id == "secure-direct-file")
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        approval_offers
            .accept(
                "secure-direct-file",
                "rename".to_string(),
                None,
                approval_context,
            )
            .unwrap();
        sender.join().unwrap().unwrap();
        server.join().unwrap();
        assert_eq!(
            fs::read(received.join("source.txt")).unwrap(),
            b"encrypted v2 direct transfer\n"
        );
        assert!(
            HistoryStore::load(&SettingsStore::new(root.join("server-data")))
                .unwrap()
                .list()
                .iter()
                .any(|entry| {
                    entry.transfer_id == "secure-direct-file"
                        && entry.direction == "receive"
                        && entry.status == "completed"
                })
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "swarm-v2")]
    #[test]
    fn secure_v2_offer_rejects_preapproval_key_envelope() {
        let root = std::env::temp_dir().join(format!("zapdrop-v2-offer-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let sender_store = SettingsStore::new(root.join("sender-data"));
        let receiver_store = SettingsStore::new(root.join("receiver-data"));
        let sender = DeviceIdentity::load_or_create(&sender_store).unwrap();
        let receiver = DeviceIdentity::load_or_create(&receiver_store).unwrap();
        let signing_key = sender.signing_key(&sender_store).unwrap();
        let item = ManifestItem {
            item_id: "item-1".to_string(),
            relative_path: "file.txt".to_string(),
            kind: "file".to_string(),
            size: 1,
            sha256: digest_bytes(b"x"),
        };
        let (job, job_key) = create_v2_job(
            &sender,
            "offer-with-key",
            &receiver.device_id,
            std::slice::from_ref(&item),
            &signing_key,
        )
        .unwrap();
        let channel_key = JobKey::generate();
        let envelope = crate::secure::provision_job_key(
            &job,
            &receiver.device_id,
            &job.content_key_id,
            &job_key,
            &channel_key,
        )
        .unwrap();
        let offer = V2DirectOffer {
            kind: V2_DIRECT_OFFER_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job,
            items: vec![item],
            total_bytes: 1,
            conflict_policy: "rename".to_string(),
            key_envelope: Some(envelope),
        };
        let receiver_context = test_context(
            receiver.clone(),
            receiver_store,
            TrustedPeerStore::load(&SettingsStore::new(root.join("receiver-data"))).unwrap(),
            root.join("received"),
            "Receiver",
        );
        let sender_key = VerifyingKey::from_bytes(
            &BASE64
                .decode(&sender.public_key)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(validate_v2_direct_offer(
            &offer,
            &receiver_context,
            &sender.device_id,
            &sender_key
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "swarm-v2")]
    #[test]
    fn secure_v2_offer_rejects_unsafe_metadata_and_snapshot_mismatch() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-v2-validation-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let sender_store = SettingsStore::new(root.join("sender-data"));
        let receiver_store = SettingsStore::new(root.join("receiver-data"));
        let sender = DeviceIdentity::load_or_create(&sender_store).unwrap();
        let receiver = DeviceIdentity::load_or_create(&receiver_store).unwrap();
        let signing_key = sender.signing_key(&sender_store).unwrap();
        let item = ManifestItem {
            item_id: "item-1".to_string(),
            relative_path: "file.txt".to_string(),
            kind: "file".to_string(),
            size: 1,
            sha256: digest_bytes(b"x"),
        };
        let (job, _) = create_v2_job(
            &sender,
            "validation-job",
            &receiver.device_id,
            std::slice::from_ref(&item),
            &signing_key,
        )
        .unwrap();
        let receiver_context = test_context(
            receiver.clone(),
            receiver_store,
            TrustedPeerStore::load(&SettingsStore::new(root.join("receiver-data"))).unwrap(),
            root.join("received"),
            "Receiver",
        );
        let sender_key = VerifyingKey::from_bytes(
            &BASE64
                .decode(&sender.public_key)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let mut unsafe_offer = V2DirectOffer {
            kind: V2_DIRECT_OFFER_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job: job.clone(),
            items: vec![item.clone()],
            total_bytes: 1,
            conflict_policy: "rename".to_string(),
            key_envelope: None,
        };
        unsafe_offer.job.job_id = "../escape".to_string();
        sign_v2_job(&mut unsafe_offer.job, &signing_key).unwrap();
        assert!(validate_v2_direct_offer(
            &unsafe_offer,
            &receiver_context,
            &sender.device_id,
            &sender_key
        )
        .is_err());

        let mut mismatched_offer = V2DirectOffer {
            kind: V2_DIRECT_OFFER_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job,
            items: vec![item.clone()],
            total_bytes: 1,
            conflict_policy: "rename".to_string(),
            key_envelope: None,
        };
        mismatched_offer.job.snapshot_root =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        sign_v2_job(&mut mismatched_offer.job, &signing_key).unwrap();
        assert!(validate_v2_direct_offer(
            &mismatched_offer,
            &receiver_context,
            &sender.device_id,
            &sender_key
        )
        .is_err());

        let mut duplicate_offer = mismatched_offer;
        duplicate_offer.job.snapshot_root =
            v2_snapshot_root(&[item.clone(), item.clone()]).unwrap();
        duplicate_offer.items = vec![item.clone(), item];
        duplicate_offer.total_bytes = 2;
        sign_v2_job(&mut duplicate_offer.job, &signing_key).unwrap();
        assert!(validate_v2_direct_offer(
            &duplicate_offer,
            &receiver_context,
            &sender.device_id,
            &sender_key
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "swarm-v2")]
    #[test]
    fn secure_v2_frame_rejects_oversized_length_before_allocation() {
        let mut reader = std::io::BufReader::new(Cursor::new(u32::MAX.to_be_bytes().to_vec()));
        assert!(read_v2_frame::<serde_json::Value>(&mut reader).is_err());
    }

    #[cfg(feature = "swarm-v2")]
    #[test]
    fn secure_v2_listener_probe_roundtrip() {
        let root = std::env::temp_dir().join(format!("zapdrop-secure-v2-{}", uuid::Uuid::new_v4()));
        let server_data = root.join("server-data");
        let client_data = root.join("client-data");
        fs::create_dir_all(&root).unwrap();
        let server_store = SettingsStore::new(server_data);
        let client_store = SettingsStore::new(client_data);
        let server_identity = DeviceIdentity::load_or_create(&server_store).unwrap();
        let client_identity = DeviceIdentity::load_or_create(&client_store).unwrap();
        let server_trust = TrustedPeerStore::load(&server_store).unwrap();
        server_trust
            .upsert(TrustedPeer {
                version: 1,
                peer_id: client_identity.device_id.clone(),
                name: "Secure Client".to_string(),
                public_key: client_identity.public_key.clone(),
                fingerprint: client_identity.fingerprint.clone(),
                first_seen: 1,
                last_seen: 1,
                endpoint: "127.0.0.1:0".to_string(),
            })
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let context = test_context(
            server_identity.clone(),
            server_store.clone(),
            server_trust,
            root.join("server-received"),
            "Secure Server",
        );
        let server = thread::spawn(move || {
            let (stream, _address) = listener.accept().unwrap();
            let first: serde_json::Value = read_json_line(&stream).unwrap();
            assert!(is_secure_hello(&first));
            handle_secure_incoming(stream, first, context);
        });
        let peer = PeerRecord {
            id: server_identity.device_id.clone(),
            name: "Secure Server".to_string(),
            platform: "windows".to_string(),
            fingerprint: Some(server_identity.fingerprint.clone()),
            public_key: Some(server_identity.public_key.clone()),
            endpoint: endpoint.to_string(),
            port: endpoint.port(),
            status: "trusted".to_string(),
            discovered_via: "secure-v2-test".to_string(),
            last_seen: epoch_seconds(),
            trusted: true,
        };
        send_v2_secure_probe(
            &client_identity,
            &client_store,
            "Secure Client",
            &peer,
            "secure-session-v2",
        )
        .unwrap();
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parent_history_reconciles_partial_success() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-parent-history-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = HistoryStore::load(&SettingsStore::new(root.clone())).unwrap();
        store
            .record(TransferHistoryEntry {
                id: "parent-job".to_string(),
                transfer_id: "parent-job".to_string(),
                parent_id: None,
                direction: "send".to_string(),
                peer_id: "swarm".to_string(),
                peer_name: "Swarm job".to_string(),
                status: "started".to_string(),
                source_names: vec!["folder".to_string()],
                items: 1,
                total_bytes: 10,
                bytes_done: 0,
                conflict_policy: "rename".to_string(),
                started_at: 1,
                finished_at: None,
                error: None,
            })
            .unwrap();
        for (peer, status, bytes) in [("peer-a", "completed", 10), ("peer-b", "failed", 0)] {
            store
                .record(TransferHistoryEntry {
                    id: format!("parent-job:{peer}"),
                    transfer_id: "parent-job".to_string(),
                    parent_id: Some("parent-job".to_string()),
                    direction: "send".to_string(),
                    peer_id: peer.to_string(),
                    peer_name: peer.to_string(),
                    status: status.to_string(),
                    source_names: vec!["folder".to_string()],
                    items: 1,
                    total_bytes: 10,
                    bytes_done: bytes,
                    conflict_policy: "rename".to_string(),
                    started_at: 1,
                    finished_at: Some(2),
                    error: None,
                })
                .unwrap();
        }
        reconcile_parent_history(
            &store,
            "parent-job",
            2,
            vec!["folder".to_string()],
            1,
            10,
            "rename",
        );
        let parent = store
            .list()
            .into_iter()
            .find(|entry| entry.id == "parent-job")
            .unwrap();
        assert_eq!(parent.status, "partial");
        assert_eq!(parent.bytes_done, 10);
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
