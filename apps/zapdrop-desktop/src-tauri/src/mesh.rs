use crate::swarm::{
    CapabilityOperation, SwarmJob, SwarmValidationError, MAX_SWARM_OBJECTS, MAX_SWARM_RECIPIENTS,
    SWARM_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BRANCH_CHILDREN: usize = 8;
const MAX_RELAY_BYTES: u64 = 1 << 50;

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
}
