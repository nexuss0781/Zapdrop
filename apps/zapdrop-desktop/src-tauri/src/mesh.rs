#[cfg(feature = "swarm-tree-mesh")]
use crate::secure::{EncryptedFrame, SecureChannel, SecureError};
use crate::swarm::{
    CapabilityOperation, SwarmJob, SwarmValidationError, MAX_SWARM_OBJECTS, MAX_SWARM_RECIPIENTS,
    SWARM_PROTOCOL_VERSION,
};
#[cfg(feature = "swarm-tree-mesh")]
use crate::swarm::{EncryptedPieceHeader, MAX_PIECE_SIZE};
#[cfg(feature = "swarm-tree-mesh")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "swarm-tree-mesh")]
use sha2::{Digest, Sha256};
#[cfg(feature = "swarm-tree-mesh")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BRANCH_CHILDREN: usize = 8;
const MAX_RELAY_BYTES: u64 = 1 << 50;
#[cfg(feature = "swarm-tree-mesh")]
const MAX_RELAY_STORAGE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "swarm-tree-mesh")]
const MAX_RELAY_STORED_PIECES: usize = 1024;
#[cfg(feature = "swarm-tree-mesh")]
const MAX_BRANCH_ASSIGNMENT_OBJECTS: usize = 4_096;
#[cfg(feature = "swarm-tree-mesh")]
const MAX_RELAY_CONNECTIONS: usize = 8;
#[cfg(feature = "swarm-tree-mesh")]
const BRANCH_ASSIGNMENT_AAD: &[u8] = b"zapdrop/swarm/v2/tree-mesh/branch-assignment";
#[cfg(feature = "swarm-tree-mesh")]
const RELAY_CONNECTION_REQUEST_AAD: &[u8] = b"zapdrop/swarm/v2/tree-mesh/relay-connection-request";
#[cfg(feature = "swarm-tree-mesh")]
const RELAY_CONNECTION_RESPONSE_AAD: &[u8] =
    b"zapdrop/swarm/v2/tree-mesh/relay-connection-response";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayGrant {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub relay_id: String,
    pub child_ids: Vec<String>,
    pub allowed_object_ids: Vec<String>,
    pub operations: Vec<CapabilityOperation>,
    pub max_bytes: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: String,
}

impl RelayGrant {
    pub fn validate_for(&self, job: &SwarmJob, now: u64) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_relay_grant" || self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue(
                "relay grant header".to_string(),
            ));
        }
        if self.job_id != job.job_id || self.snapshot_root != job.snapshot_root {
            return Err(SwarmValidationError::InvalidValue(
                "relay grant job binding".to_string(),
            ));
        }
        if job.distribution_mode == crate::swarm::DistributionMode::Direct
            || job.distribution_mode == crate::swarm::DistributionMode::Queued
        {
            return Err(SwarmValidationError::Unauthorized(
                "relay operation in direct mode".to_string(),
            ));
        }
        if !job.authorizes(&self.relay_id) {
            return Err(SwarmValidationError::Unauthorized("relayId".to_string()));
        }
        if self.child_ids.is_empty() || self.child_ids.len() > MAX_BRANCH_CHILDREN {
            return Err(SwarmValidationError::Limit("childIds".to_string()));
        }
        let mut children = HashSet::with_capacity(self.child_ids.len());
        for child in &self.child_ids {
            if !job.authorizes(child) || !children.insert(child) || child == &self.relay_id {
                return Err(SwarmValidationError::Unauthorized("childIds".to_string()));
            }
        }
        if self.allowed_object_ids.is_empty()
            || self.allowed_object_ids.len() as u64 > MAX_SWARM_OBJECTS
        {
            return Err(SwarmValidationError::Limit("allowedObjectIds".to_string()));
        }
        let mut objects = HashSet::with_capacity(self.allowed_object_ids.len());
        for object in &self.allowed_object_ids {
            if object.is_empty() || object.len() > 128 || !objects.insert(object) {
                return Err(SwarmValidationError::InvalidValue(
                    "allowedObjectIds".to_string(),
                ));
            }
        }
        if !self.operations.contains(&CapabilityOperation::ForwardPiece)
            || self.operations.iter().any(|operation| {
                *operation != CapabilityOperation::ForwardPiece
                    && *operation != CapabilityOperation::ReadPiece
            })
        {
            return Err(SwarmValidationError::Unauthorized(
                "relay operations".to_string(),
            ));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_RELAY_BYTES {
            return Err(SwarmValidationError::Limit("maxBytes".to_string()));
        }
        if self.expires_at > job.expires_at || self.expires_at <= now {
            return Err(SwarmValidationError::InvalidValue(
                "relay grant expiry".to_string(),
            ));
        }
        if self.nonce.is_empty() || self.signature.is_empty() {
            return Err(SwarmValidationError::Required(
                "relay grant proof".to_string(),
            ));
        }
        Ok(())
    }

    pub fn permits_child(&self, child_id: &str) -> bool {
        self.child_ids.iter().any(|value| value == child_id)
    }

    pub fn permits_object(&self, object_id: &str, bytes: u64) -> bool {
        self.allowed_object_ids
            .iter()
            .any(|value| value == object_id)
            && bytes <= self.max_bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TopologyCandidate {
    pub peer_id: String,
    pub throughput_bytes_per_second: f64,
    pub round_trip_ms: f64,
    pub retry_rate: f64,
    pub available_bytes: u64,
    pub relay_consent: bool,
    pub battery_constrained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyChoice {
    Direct,
    Relay,
}

pub fn choose_relay(
    job: &SwarmJob,
    candidates: &[TopologyCandidate],
    required_bytes: u64,
) -> Option<String> {
    if !matches!(
        job.distribution_mode,
        crate::swarm::DistributionMode::Tree | crate::swarm::DistributionMode::Mesh
    ) {
        return None;
    }
    candidates
        .iter()
        .filter(|candidate| {
            job.authorizes(&candidate.peer_id)
                && candidate.relay_consent
                && !candidate.battery_constrained
                && candidate.available_bytes >= required_bytes
                && candidate.throughput_bytes_per_second.is_finite()
                && candidate.throughput_bytes_per_second > 0.0
                && candidate.round_trip_ms.is_finite()
                && candidate.round_trip_ms >= 0.0
                && candidate.retry_rate.is_finite()
                && (0.0..=1.0).contains(&candidate.retry_rate)
        })
        .max_by(|left, right| relay_score(left).total_cmp(&relay_score(right)))
        .map(|candidate| candidate.peer_id.clone())
}

fn relay_score(candidate: &TopologyCandidate) -> f64 {
    candidate.throughput_bytes_per_second / (1.0 + candidate.round_trip_ms)
        * (1.0 - candidate.retry_rate)
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TopologyPlan {
    DirectFallback {
        reason: String,
    },
    Relay {
        job_id: String,
        snapshot_root: String,
        relay_id: String,
        child_ids: Vec<String>,
        allowed_object_ids: Vec<String>,
        max_bytes: u64,
        expires_at: u64,
    },
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn plan_topology(
    job: &SwarmJob,
    candidates: &[TopologyCandidate],
    grant: Option<&RelayGrant>,
    required_bytes: u64,
    now: u64,
) -> Result<TopologyPlan, SwarmValidationError> {
    if !matches!(
        job.distribution_mode,
        crate::swarm::DistributionMode::Tree | crate::swarm::DistributionMode::Mesh
    ) {
        return Ok(TopologyPlan::DirectFallback {
            reason: "job distribution mode is direct-only".to_string(),
        });
    }
    let Some(relay_id) = choose_relay(job, candidates, required_bytes) else {
        return Ok(TopologyPlan::DirectFallback {
            reason: "no authorized and consented relay satisfies capacity constraints".to_string(),
        });
    };
    let Some(grant) = grant else {
        return Ok(TopologyPlan::DirectFallback {
            reason: "authorized relay has no valid capability grant".to_string(),
        });
    };
    grant.validate_for(job, now)?;
    if grant.relay_id != relay_id {
        return Err(SwarmValidationError::Unauthorized(
            "relay grant candidate mismatch".to_string(),
        ));
    }
    if required_bytes > grant.max_bytes {
        return Ok(TopologyPlan::DirectFallback {
            reason: "relay grant byte budget is smaller than the planned transfer".to_string(),
        });
    }
    Ok(TopologyPlan::Relay {
        job_id: job.job_id.clone(),
        snapshot_root: job.snapshot_root.clone(),
        relay_id,
        child_ids: grant.child_ids.clone(),
        allowed_object_ids: grant.allowed_object_ids.clone(),
        max_bytes: grant.max_bytes,
        expires_at: grant.expires_at,
    })
}

#[cfg(feature = "swarm-tree-mesh")]
fn seal_wire_json<T: Serialize>(
    channel: &mut SecureChannel,
    value: &T,
    aad: &[u8],
) -> Result<EncryptedFrame, SecureError> {
    let plaintext = serde_json::to_vec(value)
        .map_err(|error| SecureError::Invalid(format!("wire serialization: {error}")))?;
    channel.seal(&plaintext, aad)
}

#[cfg(feature = "swarm-tree-mesh")]
fn open_wire_json<T: for<'de> Deserialize<'de>>(
    channel: &mut SecureChannel,
    frame: &EncryptedFrame,
    aad: &[u8],
) -> Result<T, SecureError> {
    let plaintext = channel.open(frame, aad)?;
    serde_json::from_slice(&plaintext)
        .map_err(|error| SecureError::Invalid(format!("wire deserialization: {error}")))
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn seal_branch_assignment(
    channel: &mut SecureChannel,
    assignment: &WireBranchAssignment,
) -> Result<EncryptedFrame, SecureError> {
    seal_wire_json(channel, assignment, BRANCH_ASSIGNMENT_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn open_branch_assignment(
    channel: &mut SecureChannel,
    frame: &EncryptedFrame,
) -> Result<WireBranchAssignment, SecureError> {
    open_wire_json(channel, frame, BRANCH_ASSIGNMENT_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn seal_relay_connection_request(
    channel: &mut SecureChannel,
    request: &RelayConnectionRequest,
) -> Result<EncryptedFrame, SecureError> {
    seal_wire_json(channel, request, RELAY_CONNECTION_REQUEST_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn open_relay_connection_request(
    channel: &mut SecureChannel,
    frame: &EncryptedFrame,
) -> Result<RelayConnectionRequest, SecureError> {
    open_wire_json(channel, frame, RELAY_CONNECTION_REQUEST_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn seal_relay_connection_response(
    channel: &mut SecureChannel,
    response: &RelayConnectionResponse,
) -> Result<EncryptedFrame, SecureError> {
    seal_wire_json(channel, response, RELAY_CONNECTION_RESPONSE_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
pub fn open_relay_connection_response(
    channel: &mut SecureChannel,
    frame: &EncryptedFrame,
) -> Result<RelayConnectionResponse, SecureError> {
    open_wire_json(channel, frame, RELAY_CONNECTION_RESPONSE_AAD)
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireBranchAssignment {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub relay_id: String,
    pub parent_id: String,
    pub child_id: String,
    pub allowed_object_ids: Vec<String>,
    pub max_bytes: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[cfg(feature = "swarm-tree-mesh")]
impl WireBranchAssignment {
    pub fn validate_for(
        &self,
        job: &SwarmJob,
        grant: &RelayGrant,
        now: u64,
    ) -> Result<(), SwarmValidationError> {
        grant.validate_for(job, now)?;
        if self.kind != "zapdrop_branch_assignment"
            || self.version != SWARM_PROTOCOL_VERSION
            || self.job_id != job.job_id
            || self.snapshot_root != job.snapshot_root
            || self.relay_id != grant.relay_id
            || self.parent_id != job.sender_id
            || !grant.permits_child(&self.child_id)
            || self.child_id == self.relay_id
        {
            return Err(SwarmValidationError::Unauthorized(
                "branch assignment scope".to_string(),
            ));
        }
        if self.allowed_object_ids.is_empty()
            || self.allowed_object_ids.len() > MAX_BRANCH_ASSIGNMENT_OBJECTS
            || self.max_bytes == 0
            || self.max_bytes > grant.max_bytes
            || self.expires_at <= now
            || self.expires_at > grant.expires_at
            || self.nonce.is_empty()
            || self.nonce.len() > 128
        {
            return Err(SwarmValidationError::Limit(
                "branch assignment bounds".to_string(),
            ));
        }
        let allowed = grant.allowed_object_ids.iter().collect::<HashSet<_>>();
        let mut objects = HashSet::with_capacity(self.allowed_object_ids.len());
        for object_id in &self.allowed_object_ids {
            if !allowed.contains(object_id) || !objects.insert(object_id) {
                return Err(SwarmValidationError::Unauthorized(
                    "branch assignment objects".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayConnectionRequest {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub relay_id: String,
    pub parent_id: String,
    pub child_id: String,
    pub assignment_nonce: String,
}

#[cfg(feature = "swarm-tree-mesh")]
impl RelayConnectionRequest {
    pub fn from_assignment(assignment: &WireBranchAssignment) -> Self {
        Self {
            kind: "zapdrop_relay_connection_request".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: assignment.job_id.clone(),
            snapshot_root: assignment.snapshot_root.clone(),
            relay_id: assignment.relay_id.clone(),
            parent_id: assignment.parent_id.clone(),
            child_id: assignment.child_id.clone(),
            assignment_nonce: assignment.nonce.clone(),
        }
    }

    pub fn validate_for(
        &self,
        job: &SwarmJob,
        assignment: &WireBranchAssignment,
        now: u64,
    ) -> Result<(), SwarmValidationError> {
        assignment
            .validate_for(
                job,
                &RelayGrant {
                    kind: "zapdrop_relay_grant".to_string(),
                    version: SWARM_PROTOCOL_VERSION,
                    job_id: job.job_id.clone(),
                    snapshot_root: job.snapshot_root.clone(),
                    relay_id: assignment.relay_id.clone(),
                    child_ids: vec![assignment.child_id.clone()],
                    allowed_object_ids: assignment.allowed_object_ids.clone(),
                    operations: vec![CapabilityOperation::ForwardPiece],
                    max_bytes: assignment.max_bytes,
                    expires_at: assignment.expires_at,
                    nonce: assignment.nonce.clone(),
                    signature: "wire-assignment-parent-validated".to_string(),
                },
                now,
            )
            .map_err(|_| {
                SwarmValidationError::Unauthorized("relay connection request".to_string())
            })?;
        if self.kind != "zapdrop_relay_connection_request"
            || self.version != SWARM_PROTOCOL_VERSION
            || self.job_id != assignment.job_id
            || self.snapshot_root != assignment.snapshot_root
            || self.relay_id != assignment.relay_id
            || self.parent_id != assignment.parent_id
            || self.child_id != assignment.child_id
            || self.assignment_nonce != assignment.nonce
        {
            return Err(SwarmValidationError::Unauthorized(
                "relay connection request binding".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayConnectionResponse {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub relay_id: String,
    pub child_id: String,
    pub assignment_nonce: String,
    pub accepted: bool,
    pub reason: Option<String>,
}

#[cfg(feature = "swarm-tree-mesh")]
impl RelayConnectionResponse {
    pub fn validate_for(
        &self,
        job: &SwarmJob,
        assignment: &WireBranchAssignment,
        now: u64,
    ) -> Result<(), SwarmValidationError> {
        assignment
            .validate_for(
                job,
                &RelayGrant {
                    kind: "zapdrop_relay_grant".to_string(),
                    version: SWARM_PROTOCOL_VERSION,
                    job_id: job.job_id.clone(),
                    snapshot_root: job.snapshot_root.clone(),
                    relay_id: assignment.relay_id.clone(),
                    child_ids: vec![assignment.child_id.clone()],
                    allowed_object_ids: assignment.allowed_object_ids.clone(),
                    operations: vec![CapabilityOperation::ForwardPiece],
                    max_bytes: assignment.max_bytes,
                    expires_at: assignment.expires_at,
                    nonce: assignment.nonce.clone(),
                    signature: "wire-assignment-parent-validated".to_string(),
                },
                now,
            )
            .map_err(|_| {
                SwarmValidationError::Unauthorized("relay connection response".to_string())
            })?;
        if self.kind != "zapdrop_relay_connection_response"
            || self.version != SWARM_PROTOCOL_VERSION
            || self.job_id != assignment.job_id
            || self.snapshot_root != assignment.snapshot_root
            || self.relay_id != assignment.relay_id
            || self.child_id != assignment.child_id
            || self.assignment_nonce != assignment.nonce
        {
            return Err(SwarmValidationError::Unauthorized(
                "relay connection response binding".to_string(),
            ));
        }
        if !self.accepted && self.reason.as_deref().unwrap_or_default().trim().is_empty() {
            return Err(SwarmValidationError::Required(
                "relay connection rejection reason".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionState {
    Assigned,
    Connected,
}

#[cfg(feature = "swarm-tree-mesh")]
pub struct RelayConnectionOrchestrator {
    job_id: String,
    snapshot_root: String,
    assignments: HashMap<String, (WireBranchAssignment, RelayConnectionState)>,
}

#[cfg(feature = "swarm-tree-mesh")]
impl RelayConnectionOrchestrator {
    pub fn new(job: &SwarmJob) -> Self {
        Self {
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            assignments: HashMap::new(),
        }
    }

    pub fn assign(
        &mut self,
        job: &SwarmJob,
        grant: &RelayGrant,
        assignment: WireBranchAssignment,
        now: u64,
    ) -> Result<RelayConnectionRequest, SwarmValidationError> {
        if self.job_id != job.job_id || self.snapshot_root != job.snapshot_root {
            return Err(SwarmValidationError::Unauthorized(
                "relay orchestrator job scope".to_string(),
            ));
        }
        assignment.validate_for(job, grant, now)?;
        if self.assignments.len() >= MAX_RELAY_CONNECTIONS
            && !self.assignments.contains_key(&assignment.child_id)
        {
            return Err(SwarmValidationError::Limit(
                "relay branch connections".to_string(),
            ));
        }
        if self.assignments.contains_key(&assignment.child_id) {
            return Err(SwarmValidationError::Duplicate(
                "relay child assignment".to_string(),
            ));
        }
        let request = RelayConnectionRequest::from_assignment(&assignment);
        self.assignments.insert(
            assignment.child_id.clone(),
            (assignment, RelayConnectionState::Assigned),
        );
        Ok(request)
    }

    pub fn complete(
        &mut self,
        job: &SwarmJob,
        response: &RelayConnectionResponse,
        now: u64,
    ) -> Result<(), SwarmValidationError> {
        let Some((assignment, state)) = self.assignments.get_mut(&response.child_id) else {
            return Err(SwarmValidationError::Unauthorized(
                "unknown relay branch".to_string(),
            ));
        };
        response.validate_for(job, assignment, now)?;
        if !response.accepted {
            return Err(SwarmValidationError::Unauthorized(
                "relay connection rejected".to_string(),
            ));
        }
        *state = RelayConnectionState::Connected;
        Ok(())
    }

    pub fn state(&self, child_id: &str) -> Option<RelayConnectionState> {
        self.assignments.get(child_id).map(|(_, state)| *state)
    }

    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayPieceEnvelope {
    pub header: EncryptedPieceHeader,
    pub ciphertext: String,
}

#[cfg(feature = "swarm-tree-mesh")]
fn validate_relay_piece(
    job: &SwarmJob,
    grant: &RelayGrant,
    child_id: &str,
    envelope: &RelayPieceEnvelope,
    now: u64,
) -> Result<usize, SwarmValidationError> {
    grant.validate_for(job, now)?;
    if !grant.permits_child(child_id) {
        return Err(SwarmValidationError::Unauthorized("childId".to_string()));
    }
    let header = &envelope.header;
    if header.job_id != job.job_id
        || !grant.permits_object(&header.object_id, header.ciphertext_length)
    {
        return Err(SwarmValidationError::Unauthorized(
            "piece scope".to_string(),
        ));
    }
    header.validate_against(&job.chunk_profile)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|_| SwarmValidationError::InvalidValue("ciphertext encoding".to_string()))?;
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_PIECE_SIZE as usize + 64
        || ciphertext.len() as u64 != header.ciphertext_length
    {
        return Err(SwarmValidationError::Limit("relay ciphertext".to_string()));
    }
    let digest = Sha256::digest(&ciphertext)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != header.ciphertext_sha256 {
        return Err(SwarmValidationError::InvalidValue(
            "relay ciphertext digest".to_string(),
        ));
    }
    Ok(ciphertext.len())
}

#[cfg(feature = "swarm-tree-mesh")]
#[derive(Debug, Clone)]
struct StoredRelayPiece {
    envelope: RelayPieceEnvelope,
}

#[cfg(feature = "swarm-tree-mesh")]
pub struct RelayPieceStore {
    job_id: String,
    relay_id: String,
    max_bytes: u64,
    bytes_used: u64,
    pieces: HashMap<(String, String, u64), StoredRelayPiece>,
}

#[cfg(feature = "swarm-tree-mesh")]
impl RelayPieceStore {
    pub fn new(job: &SwarmJob, grant: &RelayGrant, now: u64) -> Result<Self, SwarmValidationError> {
        grant.validate_for(job, now)?;
        Ok(Self {
            job_id: job.job_id.clone(),
            relay_id: grant.relay_id.clone(),
            max_bytes: grant.max_bytes.min(MAX_RELAY_STORAGE_BYTES),
            bytes_used: 0,
            pieces: HashMap::new(),
        })
    }

    pub fn insert(
        &mut self,
        job: &SwarmJob,
        grant: &RelayGrant,
        child_id: &str,
        envelope: RelayPieceEnvelope,
        now: u64,
    ) -> Result<bool, SwarmValidationError> {
        if self.job_id != job.job_id || self.relay_id != grant.relay_id {
            return Err(SwarmValidationError::Unauthorized(
                "relay store job scope".to_string(),
            ));
        }
        let ciphertext_bytes = validate_relay_piece(job, grant, child_id, &envelope, now)?;
        let key = (
            envelope.header.object_id.clone(),
            envelope.header.piece_id.clone(),
            envelope.header.index,
        );
        if let Some(existing) = self.pieces.get(&key) {
            if existing.envelope == envelope {
                return Ok(false);
            }
            return Err(SwarmValidationError::InvalidValue(
                "conflicting relay piece".to_string(),
            ));
        }
        if self.pieces.len() >= MAX_RELAY_STORED_PIECES {
            return Err(SwarmValidationError::Limit(
                "relay stored pieces".to_string(),
            ));
        }
        let next_bytes = self
            .bytes_used
            .checked_add(ciphertext_bytes as u64)
            .ok_or_else(|| SwarmValidationError::Limit("relay storage bytes".to_string()))?;
        if next_bytes > self.max_bytes {
            return Err(SwarmValidationError::Limit(
                "relay storage bytes".to_string(),
            ));
        }
        self.bytes_used = next_bytes;
        self.pieces.insert(key, StoredRelayPiece { envelope });
        Ok(true)
    }

    pub fn get_for_child(
        &self,
        job: &SwarmJob,
        grant: &RelayGrant,
        child_id: &str,
        object_id: &str,
        piece_id: &str,
        index: u64,
        now: u64,
    ) -> Result<Option<RelayPieceEnvelope>, SwarmValidationError> {
        if self.job_id != job.job_id || self.relay_id != grant.relay_id {
            return Err(SwarmValidationError::Unauthorized(
                "relay store job scope".to_string(),
            ));
        }
        if !grant.permits_child(child_id) {
            return Err(SwarmValidationError::Unauthorized("childId".to_string()));
        }
        grant.validate_for(job, now)?;
        Ok(self
            .pieces
            .get(&(object_id.to_string(), piece_id.to_string(), index))
            .map(|piece| piece.envelope.clone()))
    }

    pub fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    pub fn len(&self) -> usize {
        self.pieces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BranchRevocation {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub branch_root_id: String,
    pub revoked_peer_ids: Vec<String>,
    pub issued_at: u64,
    pub reason: String,
}

impl BranchRevocation {
    pub fn is_revoked(&self, peer_id: &str) -> bool {
        self.revoked_peer_ids.iter().any(|value| value == peer_id)
    }

    pub fn validate(&self, job: &SwarmJob, now: u64) -> Result<(), SwarmValidationError> {
        if self.kind != "zapdrop_branch_revocation" || self.version != SWARM_PROTOCOL_VERSION {
            return Err(SwarmValidationError::InvalidValue(
                "revocation header".to_string(),
            ));
        }
        if self.job_id != job.job_id || self.branch_root_id.is_empty() {
            return Err(SwarmValidationError::InvalidValue(
                "revocation binding".to_string(),
            ));
        }
        if self.revoked_peer_ids.is_empty() || self.revoked_peer_ids.len() > MAX_SWARM_RECIPIENTS {
            return Err(SwarmValidationError::Limit("revokedPeerIds".to_string()));
        }
        if self.issued_at > now.saturating_add(300) {
            return Err(SwarmValidationError::InvalidValue(
                "revocation timestamp".to_string(),
            ));
        }
        if self.reason.trim().is_empty() || self.reason.len() > 512 {
            return Err(SwarmValidationError::InvalidValue(
                "revocation reason".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::{ChunkProfile, DistributionMode};

    fn job(mode: DistributionMode) -> SwarmJob {
        SwarmJob {
            kind: "zapdrop_swarm_job".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: "job-1".to_string(),
            sender_id: "sender".to_string(),
            sender_public_key: "cHVi".to_string(),
            sender_fingerprint: "fp".to_string(),
            snapshot_root: "root-1".to_string(),
            recipient_ids: vec!["relay".to_string(), "child".to_string()],
            distribution_mode: mode,
            chunk_profile: ChunkProfile::default(),
            content_key_id: "key-1".to_string(),
            created_at: 1,
            expires_at: 10_000,
            signature: "sig".to_string(),
        }
    }

    fn grant() -> RelayGrant {
        RelayGrant {
            kind: "zapdrop_relay_grant".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: "job-1".to_string(),
            snapshot_root: "root-1".to_string(),
            relay_id: "relay".to_string(),
            child_ids: vec!["child".to_string()],
            allowed_object_ids: vec!["object-1".to_string()],
            operations: vec![CapabilityOperation::ForwardPiece],
            max_bytes: 100,
            expires_at: 9_000,
            nonce: "nonce".to_string(),
            signature: "sig".to_string(),
        }
    }

    #[test]
    fn relay_grant_is_scoped_to_authorized_tree_children_and_objects() {
        let grant = grant();
        grant
            .validate_for(&job(DistributionMode::Tree), 100)
            .unwrap();
        assert!(grant.permits_child("child"));
        assert!(grant.permits_object("object-1", 100));
        assert!(!grant.permits_object("object-2", 100));
        assert!(grant
            .validate_for(&job(DistributionMode::Direct), 100)
            .is_err());
    }

    #[test]
    fn topology_selection_ignores_unconsented_or_unauthorized_relays() {
        let selected = choose_relay(
            &job(DistributionMode::Tree),
            &[
                TopologyCandidate {
                    peer_id: "attacker".to_string(),
                    throughput_bytes_per_second: 10_000.0,
                    round_trip_ms: 1.0,
                    retry_rate: 0.0,
                    available_bytes: 1_000,
                    relay_consent: true,
                    battery_constrained: false,
                },
                TopologyCandidate {
                    peer_id: "relay".to_string(),
                    throughput_bytes_per_second: 100.0,
                    round_trip_ms: 5.0,
                    retry_rate: 0.1,
                    available_bytes: 1_000,
                    relay_consent: true,
                    battery_constrained: false,
                },
            ],
            100,
        );
        assert_eq!(selected.as_deref(), Some("relay"));
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_topology_plan_preserves_direct_fallback() {
        let candidates = [TopologyCandidate {
            peer_id: "relay".to_string(),
            throughput_bytes_per_second: 100.0,
            round_trip_ms: 5.0,
            retry_rate: 0.1,
            available_bytes: 1_000,
            relay_consent: true,
            battery_constrained: false,
        }];
        let relay_grant = grant();

        assert_eq!(
            plan_topology(
                &job(DistributionMode::Direct),
                &candidates,
                Some(&relay_grant),
                100,
                100,
            )
            .unwrap(),
            TopologyPlan::DirectFallback {
                reason: "job distribution mode is direct-only".to_string(),
            }
        );
        assert_eq!(
            plan_topology(&job(DistributionMode::Tree), &candidates, None, 100, 100,).unwrap(),
            TopologyPlan::DirectFallback {
                reason: "authorized relay has no valid capability grant".to_string(),
            }
        );
        assert_eq!(
            plan_topology(
                &job(DistributionMode::Tree),
                &candidates,
                Some(&relay_grant),
                100,
                100,
            )
            .unwrap(),
            TopologyPlan::Relay {
                job_id: "job-1".to_string(),
                snapshot_root: "root-1".to_string(),
                relay_id: "relay".to_string(),
                child_ids: vec!["child".to_string()],
                allowed_object_ids: vec!["object-1".to_string()],
                max_bytes: 100,
                expires_at: 9_000,
            }
        );
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_wire_branch_assignment_orchestrates_relay_connection() {
        let job = job(DistributionMode::Tree);
        let grant = grant();
        let assignment = WireBranchAssignment {
            kind: "zapdrop_branch_assignment".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            parent_id: "sender".to_string(),
            child_id: "child".to_string(),
            allowed_object_ids: vec!["object-1".to_string()],
            max_bytes: 100,
            expires_at: 8_000,
            nonce: "assignment-1".to_string(),
        };
        assignment.validate_for(&job, &grant, 100).unwrap();
        let request = RelayConnectionRequest::from_assignment(&assignment);
        request.validate_for(&job, &assignment, 100).unwrap();
        let wire = serde_json::to_vec(&request).unwrap();
        let decoded: RelayConnectionRequest = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded, request);

        let mut orchestrator = RelayConnectionOrchestrator::new(&job);
        orchestrator
            .assign(&job, &grant, assignment.clone(), 100)
            .unwrap();
        assert_eq!(
            orchestrator.state("child"),
            Some(RelayConnectionState::Assigned)
        );
        let response = RelayConnectionResponse {
            kind: "zapdrop_relay_connection_response".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            child_id: "child".to_string(),
            assignment_nonce: "assignment-1".to_string(),
            accepted: true,
            reason: None,
        };
        orchestrator.complete(&job, &response, 100).unwrap();
        assert_eq!(
            orchestrator.state("child"),
            Some(RelayConnectionState::Connected)
        );
        assert_eq!(orchestrator.len(), 1);
        assert!(orchestrator.assign(&job, &grant, assignment, 100).is_err());
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_wire_branch_assignment_rejects_scope_and_replay_tampering() {
        let job = job(DistributionMode::Mesh);
        let grant = grant();
        let mut assignment = WireBranchAssignment {
            kind: "zapdrop_branch_assignment".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            parent_id: "sender".to_string(),
            child_id: "child".to_string(),
            allowed_object_ids: vec!["object-2".to_string()],
            max_bytes: 100,
            expires_at: 8_000,
            nonce: "assignment-2".to_string(),
        };
        assert!(assignment.validate_for(&job, &grant, 100).is_err());
        assignment.allowed_object_ids = vec!["object-1".to_string()];
        let mut orchestrator = RelayConnectionOrchestrator::new(&job);
        orchestrator
            .assign(&job, &grant, assignment.clone(), 100)
            .unwrap();
        let mut response = RelayConnectionResponse {
            kind: "zapdrop_relay_connection_response".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            child_id: "child".to_string(),
            assignment_nonce: "wrong-nonce".to_string(),
            accepted: true,
            reason: None,
        };
        assert!(orchestrator.complete(&job, &response, 100).is_err());
        response.assignment_nonce = assignment.nonce.clone();
        response.child_id = "attacker".to_string();
        assert!(orchestrator.complete(&job, &response, 100).is_err());
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_wire_messages_use_authenticated_ordered_channels() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let fingerprint = Sha256::digest(signing.verifying_key().to_bytes())
            .iter()
            .take(12)
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let (hello_parent, keys_parent) = crate::secure::SecureHandshake::create(
            &signing,
            "wire-session".to_string(),
            "parent".to_string(),
            fingerprint.clone(),
        )
        .unwrap();
        let (hello_relay, keys_relay) = crate::secure::SecureHandshake::create(
            &signing,
            "wire-session".to_string(),
            "relay".to_string(),
            fingerprint.clone(),
        )
        .unwrap();
        let mut parent = crate::secure::establish_channel(
            &keys_parent,
            &hello_parent,
            &hello_relay,
            &signing.verifying_key(),
            "relay",
            &fingerprint,
            crate::secure::ChannelRole::Initiator,
        )
        .unwrap();
        let mut relay = crate::secure::establish_channel(
            &keys_relay,
            &hello_relay,
            &hello_parent,
            &signing.verifying_key(),
            "parent",
            &fingerprint,
            crate::secure::ChannelRole::Responder,
        )
        .unwrap();
        let job = job(DistributionMode::Tree);
        let grant = grant();
        let assignment = WireBranchAssignment {
            kind: "zapdrop_branch_assignment".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            parent_id: "sender".to_string(),
            child_id: "child".to_string(),
            allowed_object_ids: vec!["object-1".to_string()],
            max_bytes: 100,
            expires_at: 8_000,
            nonce: "wire-assignment".to_string(),
        };
        let assignment_frame = seal_branch_assignment(&mut parent, &assignment).unwrap();
        let decoded_assignment = open_branch_assignment(&mut relay, &assignment_frame).unwrap();
        decoded_assignment.validate_for(&job, &grant, 100).unwrap();

        let request = RelayConnectionRequest::from_assignment(&assignment);
        let request_frame = seal_relay_connection_request(&mut parent, &request).unwrap();
        let decoded_request = open_relay_connection_request(&mut relay, &request_frame).unwrap();
        decoded_request
            .validate_for(&job, &assignment, 100)
            .unwrap();
        let response = RelayConnectionResponse {
            kind: "zapdrop_relay_connection_response".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job.job_id.clone(),
            snapshot_root: job.snapshot_root.clone(),
            relay_id: "relay".to_string(),
            child_id: "child".to_string(),
            assignment_nonce: assignment.nonce.clone(),
            accepted: true,
            reason: None,
        };
        let response_frame = seal_relay_connection_response(&mut relay, &response).unwrap();
        let decoded_response =
            open_relay_connection_response(&mut parent, &response_frame).unwrap();
        decoded_response
            .validate_for(&job, &assignment, 100)
            .unwrap();
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_relay_storage_forwards_opaque_encrypted_pieces() {
        let job = job(DistributionMode::Tree);
        let grant = grant();
        let job_key = crate::secure::JobKey::generate();
        let (header, ciphertext) = crate::secure::seal_piece(
            &job_key,
            &job.job_id,
            &job.snapshot_root,
            "piece-1",
            "object-1",
            0,
            0,
            b"opaque piece",
        )
        .unwrap();
        let envelope = RelayPieceEnvelope {
            header,
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        };
        let mut store = RelayPieceStore::new(&job, &grant, 100).unwrap();
        assert!(store
            .insert(&job, &grant, "child", envelope.clone(), 100)
            .unwrap());
        assert!(!store
            .insert(&job, &grant, "child", envelope.clone(), 100)
            .unwrap());
        assert_eq!(store.len(), 1);
        assert_eq!(store.bytes_used(), ciphertext.len() as u64);
        let forwarded = store
            .get_for_child(&job, &grant, "child", "object-1", "piece-1", 0, 100)
            .unwrap();
        assert_eq!(forwarded, Some(envelope.clone()));
        assert_eq!(
            crate::secure::open_piece(
                &job_key,
                &job.snapshot_root,
                &envelope.header,
                &URL_SAFE_NO_PAD.decode(&envelope.ciphertext).unwrap(),
            )
            .unwrap(),
            b"opaque piece"
        );

        let mut wrong_child = envelope.clone();
        assert!(store
            .insert(&job, &grant, "attacker", wrong_child.clone(), 100)
            .is_err());
        wrong_child.header.object_id = "object-2".to_string();
        assert!(store
            .insert(&job, &grant, "child", wrong_child, 100)
            .is_err());
        let mut tampered = envelope.clone();
        tampered.ciphertext = URL_SAFE_NO_PAD.encode(b"tampered");
        assert!(store.insert(&job, &grant, "child", tampered, 100).is_err());

        let mut limited_grant = grant.clone();
        limited_grant.max_bytes = 1;
        let mut limited_store = RelayPieceStore::new(&job, &limited_grant, 100).unwrap();
        assert!(limited_store
            .insert(&job, &limited_grant, "child", envelope, 100)
            .is_err());
    }

    #[cfg(feature = "swarm-tree-mesh")]
    #[test]
    fn feature_gated_topology_plan_rejects_invalid_or_mismatched_grants() {
        let candidates = [TopologyCandidate {
            peer_id: "relay".to_string(),
            throughput_bytes_per_second: 100.0,
            round_trip_ms: 5.0,
            retry_rate: 0.1,
            available_bytes: 1_000,
            relay_consent: true,
            battery_constrained: false,
        }];
        let mut invalid_grant = grant();
        invalid_grant.allowed_object_ids.clear();
        assert!(plan_topology(
            &job(DistributionMode::Mesh),
            &candidates,
            Some(&invalid_grant),
            100,
            100,
        )
        .is_err());

        let mut mismatched_grant = grant();
        mismatched_grant.relay_id = "child".to_string();
        assert!(plan_topology(
            &job(DistributionMode::Tree),
            &candidates,
            Some(&mismatched_grant),
            100,
            100,
        )
        .is_err());

        assert_eq!(
            plan_topology(
                &job(DistributionMode::Tree),
                &candidates,
                Some(&grant()),
                101,
                100,
            )
            .unwrap(),
            TopologyPlan::DirectFallback {
                reason: "relay grant byte budget is smaller than the planned transfer".to_string(),
            }
        );
    }
}
