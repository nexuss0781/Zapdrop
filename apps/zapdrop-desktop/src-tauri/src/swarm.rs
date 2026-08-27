use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const SWARM_PROTOCOL_VERSION: u32 = 2;
pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_SWARM_ID_BYTES: usize = 128;
pub const MAX_SWARM_RECIPIENTS: usize = 256;
pub const MAX_SWARM_OBJECTS: u64 = 10_000_000;
pub const MAX_INDEX_PAGE_BYTES: u64 = 1024 * 1024;
pub const MIN_PIECE_SIZE: u64 = 256 * 1024;
pub const DEFAULT_PIECE_SIZE: u64 = 4 * 1024 * 1024;
pub const MAX_PIECE_SIZE: u64 = 16 * 1024 * 1024;
pub const MAX_JOB_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
pub const AEAD_NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SwarmValidationError {
    #[error("{0} has an invalid value")]
    InvalidValue(String),
    #[error("{0} is required")]
    Required(String),
    #[error("{0} exceeds the protocol limit")]
    Limit(String),
    #[error("{0} is duplicated")]
    Duplicate(String),
    #[error("{0} is not authorized for this job")]
    Unauthorized(String),
    #[error("{0} is not ordered canonically")]
    NonCanonical(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DistributionMode {
    Direct,
    Queued,
    Tree,
    Mesh,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityOperation {
    ReadPiece,
    ForwardPiece,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChunkProfile {
    pub profile_id: String,
    pub piece_size: u64,
    pub max_in_flight_pieces: u32,
    pub hash: String,
    pub aead: String,
}

impl Default for ChunkProfile {
    fn default() -> Self {
        Self {
            profile_id: "fixed-4m-sha256-aead".to_string(),
            piece_size: DEFAULT_PIECE_SIZE,
            max_in_flight_pieces: 8,
            hash: "sha256".to_string(),
            aead: "reserved-phase6".to_string(),
        }
    }
}

impl ChunkProfile {
    pub fn validate(&self) -> Result<(), SwarmValidationError> {
        validate_token("profileId", &self.profile_id)?;
        if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&self.piece_size) {
            return Err(SwarmValidationError::Limit("pieceSize".to_string()));
        }
        if !self.piece_size.is_multiple_of(1024) {
            return Err(SwarmValidationError::InvalidValue(
                "pieceSize must be a multiple of 1024".to_string(),
            ));
        }
        if !(1..=64).contains(&self.max_in_flight_pieces) {
            return Err(SwarmValidationError::Limit("maxInFlightPieces".to_string()));
        }
        if self.hash != "sha256" {
            return Err(SwarmValidationError::InvalidValue(
                "only sha256 is supported by the initial profile".to_string(),
            ));
        }
        validate_token("aead", &self.aead)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmJob {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub sender_id: String,
    pub sender_public_key: String,
    pub sender_fingerprint: String,
    pub snapshot_root: String,
    pub recipient_ids: Vec<String>,
    pub distribution_mode: DistributionMode,
    pub chunk_profile: ChunkProfile,
    pub content_key_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl SwarmJob {
    pub fn validate_at(&self, now: u64) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_swarm_job" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("jobId", &self.job_id)?;
        validate_token("senderId", &self.sender_id)?;
        validate_public_key(&self.sender_public_key)?;
        validate_token("senderFingerprint", &self.sender_fingerprint)?;
        validate_token("snapshotRoot", &self.snapshot_root)?;
        validate_token("contentKeyId", &self.content_key_id)?;
        validate_encoded_bytes("signature", &self.signature, None)?;
        if self.recipient_ids.is_empty() {
            return Err(SwarmValidationError::Required("recipientIds".to_string()));
        }
        if self.recipient_ids.len() > MAX_SWARM_RECIPIENTS {
            return Err(SwarmValidationError::Limit("recipientIds".to_string()));
        }
        let mut recipients = HashSet::with_capacity(self.recipient_ids.len());
        for recipient in &self.recipient_ids {
            validate_token("recipientId", recipient)?;
            if !recipients.insert(recipient) {
                return Err(SwarmValidationError::Duplicate("recipientId".to_string()));
            }
        }
        self.chunk_profile.validate()?;
        if self.created_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(SwarmValidationError::InvalidValue(
                "createdAt is in the future".to_string(),
            ));
        }
        if self.expires_at <= self.created_at {
            return Err(SwarmValidationError::InvalidValue(
                "expiresAt must be after createdAt".to_string(),
            ));
        }
        if self.expires_at - self.created_at > MAX_JOB_TTL_SECS {
            return Err(SwarmValidationError::Limit("job lifetime".to_string()));
        }
        if self.expires_at <= now {
            return Err(SwarmValidationError::InvalidValue(
                "job has expired".to_string(),
            ));
        }
        Ok(())
    }

    pub fn authorizes(&self, recipient_id: &str) -> bool {
        self.recipient_ids.iter().any(|value| value == recipient_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRoot {
    pub kind: String,
    pub version: u32,
    pub root_id: String,
    pub node_count: u64,
    pub total_bytes: u64,
    pub total_files: u64,
    pub chunk_profile_id: String,
    pub created_at: u64,
    pub signature: String,
}

impl SnapshotRoot {
    pub fn validate(&self, profile: &ChunkProfile) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_snapshot_root" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("rootId", &self.root_id)?;
        if self.node_count > MAX_SWARM_OBJECTS || self.total_files > MAX_SWARM_OBJECTS {
            return Err(SwarmValidationError::Limit(
                "snapshot object count".to_string(),
            ));
        }
        if self.chunk_profile_id != profile.profile_id {
            return Err(SwarmValidationError::InvalidValue(
                "chunkProfileId does not match the job profile".to_string(),
            ));
        }
        validate_encoded_bytes("signature", &self.signature, None)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: ObjectKind,
    pub size: u64,
    pub object_id: String,
}

impl DirectoryEntry {
    pub fn validate(&self) -> Result<(), SwarmValidationError> {
        validate_path_component(&self.name)?;
        validate_token("objectId", &self.object_id)?;
        if self.kind == ObjectKind::Directory && self.size != 0 {
            return Err(SwarmValidationError::InvalidValue(
                "directory size must be zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryNode {
    pub kind: String,
    pub version: u32,
    pub object_id: String,
    pub entries: Vec<DirectoryEntry>,
}

impl DirectoryNode {
    pub fn validate(&self) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_directory_node" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("objectId", &self.object_id)?;
        if self.entries.len() as u64 > MAX_SWARM_OBJECTS {
            return Err(SwarmValidationError::Limit("directory entries".to_string()));
        }
        let mut previous: Option<&str> = None;
        let mut names = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if !names.insert(entry.name.as_str()) {
                return Err(SwarmValidationError::Duplicate(
                    "directory entry name".to_string(),
                ));
            }
            if let Some(previous) = previous {
                if previous >= entry.name.as_str() {
                    return Err(SwarmValidationError::NonCanonical(
                        "directory entries".to_string(),
                    ));
                }
            }
            previous = Some(&entry.name);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileObject {
    pub kind: String,
    pub version: u32,
    pub object_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub piece_count: u64,
    pub piece_index_page: String,
}

impl FileObject {
    pub fn validate(&self, profile: &ChunkProfile) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_file_object" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("objectId", &self.object_id)?;
        validate_relative_path(&self.relative_path)?;
        validate_sha256(&self.sha256)?;
        let expected = self.size.div_ceil(profile.piece_size);
        if self.piece_count != expected {
            return Err(SwarmValidationError::InvalidValue(
                "pieceCount does not match size and chunk profile".to_string(),
            ));
        }
        if self.piece_count > MAX_SWARM_OBJECTS {
            return Err(SwarmValidationError::Limit("pieceCount".to_string()));
        }
        if self.piece_index_page.len() as u64 > MAX_INDEX_PAGE_BYTES {
            return Err(SwarmValidationError::Limit("pieceIndexPage".to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PieceDescriptor {
    pub piece_id: String,
    pub object_id: String,
    pub index: u64,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

impl PieceDescriptor {
    pub fn validate_against(
        &self,
        profile: &ChunkProfile,
        file_size: u64,
    ) -> Result<(), SwarmValidationError> {
        validate_token("pieceId", &self.piece_id)?;
        validate_token("objectId", &self.object_id)?;
        validate_sha256(&self.sha256)?;
        if self.length == 0 || self.length > profile.piece_size {
            return Err(SwarmValidationError::InvalidValue(
                "piece length".to_string(),
            ));
        }
        if self.offset > file_size || self.length > file_size.saturating_sub(self.offset) {
            return Err(SwarmValidationError::InvalidValue(
                "piece range".to_string(),
            ));
        }
        if self.index > MAX_SWARM_OBJECTS {
            return Err(SwarmValidationError::Limit("piece index".to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPieceHeader {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub piece_id: String,
    pub object_id: String,
    pub index: u64,
    pub offset: u64,
    pub plaintext_length: u64,
    pub ciphertext_length: u64,
    pub nonce: String,
    pub ciphertext_sha256: String,
    pub tag: String,
}

impl EncryptedPieceHeader {
    pub fn validate_against(&self, profile: &ChunkProfile) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_encrypted_piece" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("jobId", &self.job_id)?;
        validate_token("pieceId", &self.piece_id)?;
        validate_token("objectId", &self.object_id)?;
        if self.plaintext_length == 0 || self.plaintext_length > profile.piece_size {
            return Err(SwarmValidationError::InvalidValue(
                "plaintextLength".to_string(),
            ));
        }
        if self.ciphertext_length < self.plaintext_length
            || self.ciphertext_length > self.plaintext_length + 64
        {
            return Err(SwarmValidationError::InvalidValue(
                "ciphertextLength".to_string(),
            ));
        }
        validate_encoded_bytes("nonce", &self.nonce, Some(AEAD_NONCE_BYTES))?;
        validate_sha256(&self.ciphertext_sha256)?;
        validate_encoded_bytes("tag", &self.tag, Some(AEAD_TAG_BYTES))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecipientCapability {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub recipient_id: String,
    pub snapshot_root: String,
    pub allowed_object_ids: Vec<String>,
    pub operations: Vec<CapabilityOperation>,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: String,
}

impl RecipientCapability {
    pub fn validate_for(
        &self,
        job: &SwarmJob,
        recipient_id: &str,
        now: u64,
    ) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_recipient_capability" {
            return Err(SwarmValidationError::InvalidValue("kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        if self.job_id != job.job_id {
            return Err(SwarmValidationError::InvalidValue(
                "capability jobId".to_string(),
            ));
        }
        if self.recipient_id != recipient_id || !job.authorizes(recipient_id) {
            return Err(SwarmValidationError::Unauthorized(
                "recipientId".to_string(),
            ));
        }
        if self.snapshot_root != job.snapshot_root {
            return Err(SwarmValidationError::InvalidValue(
                "capability snapshotRoot".to_string(),
            ));
        }
        if self.allowed_object_ids.is_empty() {
            return Err(SwarmValidationError::Required(
                "allowedObjectIds".to_string(),
            ));
        }
        if self.allowed_object_ids.len() as u64 > MAX_SWARM_OBJECTS {
            return Err(SwarmValidationError::Limit("allowedObjectIds".to_string()));
        }
        let mut objects = HashSet::with_capacity(self.allowed_object_ids.len());
        for object_id in &self.allowed_object_ids {
            validate_token("allowedObjectId", object_id)?;
            if !objects.insert(object_id) {
                return Err(SwarmValidationError::Duplicate(
                    "allowedObjectId".to_string(),
                ));
            }
        }
        if self.operations.is_empty() {
            return Err(SwarmValidationError::Required("operations".to_string()));
        }
        validate_token("nonce", &self.nonce)?;
        validate_encoded_bytes("signature", &self.signature, None)?;
        if self.expires_at > job.expires_at || self.expires_at <= now {
            return Err(SwarmValidationError::InvalidValue(
                "capability expiry".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmHello {
    pub version: u32,
    pub job_id: String,
    pub sender_id: String,
    pub sender_public_key: String,
    pub sender_fingerprint: String,
    pub nonce: String,
    pub supported_versions: Vec<u32>,
    pub signature: String,
}

impl SwarmHello {
    pub fn validate(&self) -> Result<(), SwarmValidationError> {
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue("version".to_string()));
        }
        validate_token("jobId", &self.job_id)?;
        validate_token("senderId", &self.sender_id)?;
        validate_public_key(&self.sender_public_key)?;
        validate_token("senderFingerprint", &self.sender_fingerprint)?;
        validate_token("nonce", &self.nonce)?;
        if !self.supported_versions.contains(&SWARM_PROTOCOL_VERSION) {
            return Err(SwarmValidationError::InvalidValue(
                "supportedVersions".to_string(),
            ));
        }
        validate_encoded_bytes("signature", &self.signature, None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmAccept {
    pub version: u32,
    pub job_id: String,
    pub recipient_id: String,
    pub capability_nonce: String,
    pub destination: String,
    pub conflict_policy: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmError {
    pub version: u32,
    pub job_id: Option<String>,
    pub code: String,
    pub retryable: bool,
    pub message: String,
}

fn validate_token(field: &str, value: &str) -> Result<(), SwarmValidationError> {
    if value.is_empty() {
        return Err(SwarmValidationError::Required(field.to_string()));
    }
    if value.len() > MAX_SWARM_ID_BYTES {
        return Err(SwarmValidationError::Limit(field.to_string()));
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SwarmValidationError::InvalidValue(field.to_string()));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), SwarmValidationError> {
    validate_encoded_bytes("senderPublicKey", value, Some(32))
}

fn validate_sha256(value: &str) -> Result<(), SwarmValidationError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SwarmValidationError::InvalidValue("sha256".to_string()));
    }
    Ok(())
}

fn validate_encoded_bytes(
    field: &str,
    value: &str,
    expected_len: Option<usize>,
) -> Result<(), SwarmValidationError> {
    if value.is_empty() {
        return Err(SwarmValidationError::Required(field.to_string()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SwarmValidationError::InvalidValue(format!("{field} encoding")))?;
    if let Some(expected_len) = expected_len {
        if decoded.len() != expected_len {
            return Err(SwarmValidationError::InvalidValue(field.to_string()));
        }
    }
    Ok(())
}

fn validate_path_component(value: &str) -> Result<(), SwarmValidationError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(|character| character.is_control())
    {
        return Err(SwarmValidationError::InvalidValue(
            "directory entry name".to_string(),
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), SwarmValidationError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(SwarmValidationError::InvalidValue(
            "relativePath".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> SwarmJob {
        SwarmJob {
            kind: "zapdrop_swarm_job".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: "job-1".to_string(),
            sender_id: "sender-1".to_string(),
            sender_public_key: URL_SAFE_NO_PAD.encode([7u8; 32]),
            sender_fingerprint: "aa:bb".to_string(),
            snapshot_root: "root-1".to_string(),
            recipient_ids: vec!["receiver-1".to_string(), "receiver-2".to_string()],
            distribution_mode: DistributionMode::Direct,
            chunk_profile: ChunkProfile::default(),
            content_key_id: "key-1".to_string(),
            created_at: 100,
            expires_at: 1000,
            signature: URL_SAFE_NO_PAD.encode([1u8; 64]),
        }
    }

    #[test]
    fn validates_job_and_authorization_set() {
        let job = sample_job();
        job.validate_at(200).unwrap();
        assert!(job.authorizes("receiver-1"));
        assert!(!job.authorizes("unknown"));
    }

    #[test]
    fn rejects_duplicate_recipients_and_expired_jobs() {
        let mut job = sample_job();
        job.recipient_ids = vec!["receiver-1".to_string(), "receiver-1".to_string()];
        assert!(matches!(
            job.validate_at(200),
            Err(SwarmValidationError::Duplicate(_))
        ));
        let mut expired = sample_job();
        expired.expires_at = 150;
        assert!(expired.validate_at(200).is_err());
    }

    #[test]
    fn rejects_noncanonical_directory_entries() {
        let node = DirectoryNode {
            kind: "zapdrop_directory_node".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            object_id: "directory-1".to_string(),
            entries: vec![
                DirectoryEntry {
                    name: "z.txt".to_string(),
                    kind: ObjectKind::File,
                    size: 1,
                    object_id: "z".to_string(),
                },
                DirectoryEntry {
                    name: "a.txt".to_string(),
                    kind: ObjectKind::File,
                    size: 1,
                    object_id: "a".to_string(),
                },
            ],
        };
        assert!(matches!(
            node.validate(),
            Err(SwarmValidationError::NonCanonical(_))
        ));
    }

    #[test]
    fn round_trips_the_job_with_wire_kind() {
        let job = sample_job();
        let encoded = serde_json::to_string(&job).unwrap();
        assert!(encoded.contains("zapdrop_swarm_job"));
        let decoded: SwarmJob = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.version, SWARM_PROTOCOL_VERSION);
        decoded.validate_at(200).unwrap();
    }
}
