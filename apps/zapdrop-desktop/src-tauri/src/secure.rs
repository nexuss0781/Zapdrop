use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::swarm::{EncryptedPieceHeader, SwarmJob, SWARM_PROTOCOL_VERSION};

pub const SECURE_PROFILE_ID: &str = "x25519-hkdf-sha256-chacha20poly1305";
pub const MAX_CHANNEL_FRAMES: u64 = 1 << 32;
pub const MAX_CHANNEL_PLAINTEXT_BYTES: u64 = 1 << 40;

const HANDSHAKE_KIND: &str = "zapdrop_secure_hello";
const CHANNEL_DOMAIN: &str = "zapdrop/swarm/v2/channel";
const JOB_KEY_DOMAIN: &str = "zapdrop/swarm/v2/job-key";
const PIECE_DOMAIN: &str = "zapdrop/swarm/v2/piece";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureError {
    Invalid(String),
    AuthenticationFailed,
    ReplayOrOutOfOrder,
    SequenceExhausted,
    CryptographicFailure,
}

impl fmt::Display for SecureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(value) => write!(formatter, "invalid secure value: {value}"),
            Self::AuthenticationFailed => write!(formatter, "secure authentication failed"),
            Self::ReplayOrOutOfOrder => write!(formatter, "secure frame replayed or out of order"),
            Self::SequenceExhausted => write!(formatter, "secure frame sequence exhausted"),
            Self::CryptographicFailure => {
                write!(formatter, "secure cryptographic operation failed")
            }
        }
    }
}

impl std::error::Error for SecureError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecureHandshake {
    pub kind: String,
    pub version: u32,
    pub session_id: String,
    pub device_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub supported_profiles: Vec<String>,
    pub timestamp: u64,
    pub signature: String,
}

pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn public_key(&self) -> String {
        encode_url(self.public.as_bytes())
    }
}

impl SecureHandshake {
    pub fn create(
        signing_key: &SigningKey,
        session_id: String,
        device_id: String,
        fingerprint: String,
    ) -> Result<(Self, EphemeralKeypair), SecureError> {
        validate_token("sessionId", &session_id)?;
        validate_token("deviceId", &device_id)?;
        validate_token("fingerprint", &fingerprint)?;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let timestamp = epoch_seconds();
        let mut handshake = Self {
            kind: HANDSHAKE_KIND.to_string(),
            version: SWARM_PROTOCOL_VERSION,
            session_id,
            device_id,
            public_key: encode_url(&signing_key.verifying_key().to_bytes()),
            fingerprint,
            ephemeral_public_key: encode_url(public.as_bytes()),
            nonce: encode_url(&nonce),
            supported_profiles: vec![SECURE_PROFILE_ID.to_string()],
            timestamp,
            signature: String::new(),
        };
        handshake.signature = encode_url(&signing_key.sign(&handshake.signing_bytes()).to_bytes());
        Ok((handshake, EphemeralKeypair { secret, public }))
    }

    pub fn validate(&self) -> Result<(), SecureError> {
        self.validate_at(epoch_seconds())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), SecureError> {
        if self.kind != HANDSHAKE_KIND {
            return Err(SecureError::Invalid("handshake kind".to_string()));
        }
        if self.version != SWARM_PROTOCOL_VERSION {
            return Err(SecureError::Invalid("handshake version".to_string()));
        }
        validate_token("sessionId", &self.session_id)?;
        validate_token("deviceId", &self.device_id)?;
        validate_bytes("publicKey", &self.public_key, Some(32))?;
        validate_token("fingerprint", &self.fingerprint)?;
        validate_bytes("ephemeralPublicKey", &self.ephemeral_public_key, Some(32))?;
        validate_bytes("nonce", &self.nonce, Some(32))?;
        if !self
            .supported_profiles
            .iter()
            .any(|profile| profile == SECURE_PROFILE_ID)
        {
            return Err(SecureError::Invalid("secure profile".to_string()));
        }
        validate_bytes("signature", &self.signature, Some(64))?;
        if self.timestamp.abs_diff(now) > 5 * 60 {
            return Err(SecureError::Invalid("handshake timestamp".to_string()));
        }
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), SecureError> {
        self.validate()?;
        let signature_bytes = decode_url("signature", &self.signature)?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| SecureError::Invalid("signature length".to_string()))?;
        let signature = Signature::from_bytes(&signature_array);
        verifying_key
            .verify(&self.signing_bytes(), &signature)
            .map_err(|_| SecureError::AuthenticationFailed)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&HandshakeUnsigned {
            kind: &self.kind,
            version: self.version,
            session_id: &self.session_id,
            device_id: &self.device_id,
            public_key: &self.public_key,
            fingerprint: &self.fingerprint,
            ephemeral_public_key: &self.ephemeral_public_key,
            nonce: &self.nonce,
            supported_profiles: &self.supported_profiles,
            timestamp: self.timestamp,
        })
        .expect("secure handshake fields are serializable")
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HandshakeUnsigned<'a> {
    kind: &'a str,
    version: u32,
    session_id: &'a str,
    device_id: &'a str,
    public_key: &'a str,
    fingerprint: &'a str,
    ephemeral_public_key: &'a str,
    nonce: &'a str,
    supported_profiles: &'a [String],
    timestamp: u64,
}

pub fn transcript_hash(
    first: &SecureHandshake,
    second: &SecureHandshake,
) -> Result<[u8; 32], SecureError> {
    first.validate()?;
    second.validate()?;
    if first.session_id != second.session_id {
        return Err(SecureError::Invalid(
            "handshake session mismatch".to_string(),
        ));
    }
    let (left, right) = if first.device_id <= second.device_id {
        (first, second)
    } else {
        (second, first)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"zapdrop/swarm/v2/transcript\0");
    hasher.update(left.signing_bytes());
    hasher.update([0]);
    hasher.update(right.signing_bytes());
    Ok(hasher.finalize().into())
}

pub fn establish_channel(
    local: &EphemeralKeypair,
    local_handshake: &SecureHandshake,
    peer_handshake: &SecureHandshake,
    peer_verifying_key: &VerifyingKey,
    expected_peer_id: &str,
    expected_peer_fingerprint: &str,
    role: ChannelRole,
) -> Result<SecureChannel, SecureError> {
    local_handshake.validate()?;
    peer_handshake.verify(peer_verifying_key)?;
    let derived_fingerprint = public_key_fingerprint(peer_verifying_key);
    if peer_handshake.device_id != expected_peer_id
        || peer_handshake.public_key != encode_url(&peer_verifying_key.to_bytes())
        || peer_handshake.fingerprint != expected_peer_fingerprint
        || peer_handshake.fingerprint != derived_fingerprint
        || !peer_handshake
            .supported_profiles
            .iter()
            .any(|profile| profile == SECURE_PROFILE_ID)
    {
        return Err(SecureError::AuthenticationFailed);
    }
    let peer_bytes = decode_url("ephemeralPublicKey", &peer_handshake.ephemeral_public_key)?;
    let peer_public = PublicKey::from(
        <[u8; 32]>::try_from(peer_bytes.as_slice())
            .map_err(|_| SecureError::Invalid("ephemeral public key length".to_string()))?,
    );
    let transcript = transcript_hash(local_handshake, peer_handshake)?;

    let shared = local.secret.diffie_hellman(&peer_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(SecureError::AuthenticationFailed);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&transcript), shared.as_bytes());
    let mut initiator_to_responder = [0u8; 32];
    let mut responder_to_initiator = [0u8; 32];
    hkdf.expand(
        b"zapdrop/swarm/v2/channel/initiator-to-responder",
        &mut initiator_to_responder,
    )
    .map_err(|_| SecureError::CryptographicFailure)?;
    hkdf.expand(
        b"zapdrop/swarm/v2/channel/responder-to-initiator",
        &mut responder_to_initiator,
    )
    .map_err(|_| SecureError::CryptographicFailure)?;
    let (send_key, receive_key) = match role {
        ChannelRole::Initiator => (initiator_to_responder, responder_to_initiator),
        ChannelRole::Responder => (responder_to_initiator, initiator_to_responder),
    };
    Ok(SecureChannel {
        send_key: SecretKey::new(send_key),
        receive_key: SecretKey::new(receive_key),
        next_send_sequence: 0,
        next_receive_sequence: 0,
        sent_plaintext_bytes: 0,
        received_plaintext_bytes: 0,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedFrame {
    pub sequence: u64,
    pub ciphertext: String,
    pub tag: String,
}

pub struct SecureChannel {
    send_key: SecretKey,
    receive_key: SecretKey,
    next_send_sequence: u64,
    next_receive_sequence: u64,
    sent_plaintext_bytes: u64,
    received_plaintext_bytes: u64,
}

impl SecureChannel {
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedFrame, SecureError> {
        let sequence = self.next_send_sequence;
        if sequence >= MAX_CHANNEL_FRAMES
            || !plaintext_within_limit(self.sent_plaintext_bytes, plaintext.len() as u64)
        {
            return Err(SecureError::SequenceExhausted);
        }
        let nonce_bytes = sequence_nonce(sequence);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = plaintext.to_vec();
        let tag = ChaCha20Poly1305::new(Key::from_slice(self.send_key.as_bytes()))
            .encrypt_in_place_detached(nonce, &channel_aad(sequence, aad), &mut ciphertext)
            .map_err(|_| SecureError::CryptographicFailure)?;
        self.next_send_sequence += 1;
        self.sent_plaintext_bytes = self
            .sent_plaintext_bytes
            .saturating_add(plaintext.len() as u64);
        Ok(EncryptedFrame {
            sequence,
            ciphertext: encode_url(&ciphertext),
            tag: encode_url(&tag),
        })
    }

    pub fn wrap_job_key(
        &self,
        job: &SwarmJob,
        recipient_id: &str,
        key_id: &str,
        job_key: &JobKey,
    ) -> Result<JobKeyEnvelope, SecureError> {
        let channel_key = JobKey::from_bytes(*self.send_key.as_bytes());
        provision_job_key(job, recipient_id, key_id, job_key, &channel_key)
    }

    pub fn unwrap_job_key(
        &self,
        envelope: &JobKeyEnvelope,
        job: &SwarmJob,
        recipient_id: &str,
    ) -> Result<JobKey, SecureError> {
        let channel_key = JobKey::from_bytes(*self.receive_key.as_bytes());
        open_job_key(envelope, job, recipient_id, &channel_key)
    }

    pub fn open(&mut self, frame: &EncryptedFrame, aad: &[u8]) -> Result<Vec<u8>, SecureError> {
        if frame.sequence != self.next_receive_sequence || frame.sequence >= MAX_CHANNEL_FRAMES {
            return Err(SecureError::ReplayOrOutOfOrder);
        }
        let ciphertext = decode_url("frame ciphertext", &frame.ciphertext)?;
        let tag_bytes = decode_url("frame tag", &frame.tag)?;
        if tag_bytes.len() != 16 {
            return Err(SecureError::Invalid("frame tag length".to_string()));
        }
        let nonce_bytes = sequence_nonce(frame.sequence);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = ciphertext;
        let tag = Tag::from_slice(&tag_bytes);
        ChaCha20Poly1305::new(Key::from_slice(self.receive_key.as_bytes()))
            .decrypt_in_place_detached(
                nonce,
                &channel_aad(frame.sequence, aad),
                &mut plaintext,
                tag,
            )
            .map_err(|_| SecureError::AuthenticationFailed)?;
        if !plaintext_within_limit(self.received_plaintext_bytes, plaintext.len() as u64) {
            return Err(SecureError::SequenceExhausted);
        }
        self.next_receive_sequence += 1;
        self.received_plaintext_bytes = self
            .received_plaintext_bytes
            .saturating_add(plaintext.len() as u64);
        Ok(plaintext)
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct JobKey([u8; 32]);

impl JobKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JobKeyEnvelope {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub key_id: String,
    pub recipient_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

pub fn provision_job_key(
    job: &SwarmJob,
    recipient_id: &str,
    key_id: &str,
    job_key: &JobKey,
    channel_key: &JobKey,
) -> Result<JobKeyEnvelope, SecureError> {
    if !job.authorizes(recipient_id) {
        return Err(SecureError::Invalid(
            "recipient is not in the job".to_string(),
        ));
    }
    validate_token("keyId", key_id)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut ciphertext = job_key.as_bytes().to_vec();
    let aad = job_key_aad(&job.job_id, &job.snapshot_root, key_id, recipient_id);
    let tag = ChaCha20Poly1305::new(Key::from_slice(channel_key.as_bytes()))
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut ciphertext)
        .map_err(|_| SecureError::CryptographicFailure)?;
    Ok(JobKeyEnvelope {
        kind: "zapdrop_job_key_envelope".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        job_id: job.job_id.clone(),
        snapshot_root: job.snapshot_root.clone(),
        key_id: key_id.to_string(),
        recipient_id: recipient_id.to_string(),
        nonce: encode_url(&nonce_bytes),
        ciphertext: encode_url(&ciphertext),
        tag: encode_url(&tag),
    })
}

pub fn open_job_key(
    envelope: &JobKeyEnvelope,
    job: &SwarmJob,
    recipient_id: &str,
    channel_key: &JobKey,
) -> Result<JobKey, SecureError> {
    if envelope.kind != "zapdrop_job_key_envelope" || envelope.version != SWARM_PROTOCOL_VERSION {
        return Err(SecureError::Invalid("job-key envelope header".to_string()));
    }
    if envelope.job_id != job.job_id
        || envelope.snapshot_root != job.snapshot_root
        || envelope.key_id != job.content_key_id
        || envelope.recipient_id != recipient_id
        || !job.authorizes(recipient_id)
    {
        return Err(SecureError::AuthenticationFailed);
    }
    let nonce = decode_url("nonce", &envelope.nonce)?;
    let mut ciphertext = decode_url("ciphertext", &envelope.ciphertext)?;
    let tag = decode_url("tag", &envelope.tag)?;
    if nonce.len() != 12 || ciphertext.len() != 32 || tag.len() != 16 {
        return Err(SecureError::Invalid("job-key envelope lengths".to_string()));
    }
    let aad = job_key_aad(
        &job.job_id,
        &job.snapshot_root,
        &envelope.key_id,
        recipient_id,
    );
    ChaCha20Poly1305::new(Key::from_slice(channel_key.as_bytes()))
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut ciphertext,
            Tag::from_slice(&tag),
        )
        .map_err(|_| SecureError::AuthenticationFailed)?;
    Ok(JobKey::from_bytes(ciphertext.try_into().map_err(|_| {
        SecureError::Invalid("job-key length".to_string())
    })?))
}

pub fn piece_aad(
    job_id: &str,
    snapshot_root: &str,
    piece_id: &str,
    object_id: &str,
    index: u64,
    offset: u64,
    plaintext_length: u64,
) -> Vec<u8> {
    serde_json::to_vec(&PieceAad {
        domain: PIECE_DOMAIN,
        job_id,
        snapshot_root,
        piece_id,
        object_id,
        index,
        offset,
        plaintext_length,
    })
    .expect("piece AAD is serializable")
}

pub fn job_key_aad(job_id: &str, snapshot_root: &str, key_id: &str, recipient_id: &str) -> Vec<u8> {
    serde_json::to_vec(&JobKeyAad {
        domain: JOB_KEY_DOMAIN,
        job_id,
        snapshot_root,
        key_id,
        recipient_id,
    })
    .expect("job-key AAD is serializable")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PieceAad<'a> {
    domain: &'static str,
    job_id: &'a str,
    snapshot_root: &'a str,
    piece_id: &'a str,
    object_id: &'a str,
    index: u64,
    offset: u64,
    plaintext_length: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobKeyAad<'a> {
    domain: &'static str,
    job_id: &'a str,
    snapshot_root: &'a str,
    key_id: &'a str,
    recipient_id: &'a str,
}

pub fn seal_piece(
    job_key: &JobKey,
    job_id: &str,
    snapshot_root: &str,
    piece_id: &str,
    object_id: &str,
    index: u64,
    offset: u64,
    plaintext: &[u8],
) -> Result<(EncryptedPieceHeader, Vec<u8>), SecureError> {
    if plaintext.is_empty() {
        return Err(SecureError::Invalid("empty piece".to_string()));
    }
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = piece_aad(
        job_id,
        snapshot_root,
        piece_id,
        object_id,
        index,
        offset,
        plaintext.len() as u64,
    );
    let mut ciphertext = plaintext.to_vec();
    let tag = ChaCha20Poly1305::new(Key::from_slice(job_key.as_bytes()))
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut ciphertext)
        .map_err(|_| SecureError::CryptographicFailure)?;
    let ciphertext_sha256 = hex_digest(&ciphertext);
    Ok((
        EncryptedPieceHeader {
            kind: "zapdrop_encrypted_piece".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: job_id.to_string(),
            piece_id: piece_id.to_string(),
            object_id: object_id.to_string(),
            index,
            offset,
            plaintext_length: plaintext.len() as u64,
            ciphertext_length: ciphertext.len() as u64,
            nonce: encode_url(&nonce_bytes),
            ciphertext_sha256,
            tag: encode_url(&tag),
        },
        ciphertext,
    ))
}

pub fn open_piece(
    job_key: &JobKey,
    snapshot_root: &str,
    header: &EncryptedPieceHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SecureError> {
    let nonce = decode_url("nonce", &header.nonce)?;
    let tag = decode_url("tag", &header.tag)?;
    if nonce.len() != 12 || tag.len() != 16 || ciphertext.len() as u64 != header.ciphertext_length {
        return Err(SecureError::Invalid("piece envelope lengths".to_string()));
    }
    if hex_digest(ciphertext) != header.ciphertext_sha256 {
        return Err(SecureError::AuthenticationFailed);
    }
    let aad = piece_aad(
        &header.job_id,
        snapshot_root,
        &header.piece_id,
        &header.object_id,
        header.index,
        header.offset,
        header.plaintext_length,
    );
    let mut plaintext = ciphertext.to_vec();
    ChaCha20Poly1305::new(Key::from_slice(job_key.as_bytes()))
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut plaintext,
            Tag::from_slice(&tag),
        )
        .map_err(|_| SecureError::AuthenticationFailed)?;
    if plaintext.len() as u64 != header.plaintext_length {
        return Err(SecureError::Invalid("plaintext length".to_string()));
    }
    Ok(plaintext)
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; 32]);

impl SecretKey {
    fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn plaintext_within_limit(used: u64, next: u64) -> bool {
    next <= MAX_CHANNEL_PLAINTEXT_BYTES && used <= MAX_CHANNEL_PLAINTEXT_BYTES.saturating_sub(next)
}

fn sequence_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn channel_aad(sequence: u64, aad: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(CHANNEL_DOMAIN.len() + 8 + aad.len());
    result.extend_from_slice(CHANNEL_DOMAIN.as_bytes());
    result.extend_from_slice(&sequence.to_be_bytes());
    result.extend_from_slice(aad);
    result
}

fn public_key_fingerprint(key: &VerifyingKey) -> String {
    Sha256::digest(key.to_bytes())
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn encode_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_url(field: &str, value: &str) -> Result<Vec<u8>, SecureError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SecureError::Invalid(format!("{field} encoding")))
}

fn validate_bytes(
    field: &str,
    value: &str,
    expected_len: Option<usize>,
) -> Result<(), SecureError> {
    let decoded = decode_url(field, value)?;
    if let Some(expected_len) = expected_len {
        if decoded.len() != expected_len {
            return Err(SecureError::Invalid(field.to_string()));
        }
    }
    Ok(())
}

fn validate_token(field: &str, value: &str) -> Result<(), SecureError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SecureError::Invalid(field.to_string()));
    }
    Ok(())
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
    use crate::swarm::{ChunkProfile, DistributionMode};

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn sample_job() -> SwarmJob {
        SwarmJob {
            kind: "zapdrop_swarm_job".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            job_id: "job-1".to_string(),
            sender_id: "sender-1".to_string(),
            sender_public_key: URL_SAFE_NO_PAD.encode([7u8; 32]),
            sender_fingerprint: "aa:bb".to_string(),
            snapshot_root: "root-1".to_string(),
            recipient_ids: vec!["receiver-1".to_string()],
            distribution_mode: DistributionMode::Direct,
            chunk_profile: ChunkProfile::default(),
            content_key_id: "key-1".to_string(),
            created_at: 100,
            expires_at: 1000,
            signature: URL_SAFE_NO_PAD.encode([1u8; 64]),
        }
    }

    #[test]
    fn authenticated_handshakes_derive_usable_directional_channels() {
        let alice_signing = signing_key();
        let bob_signing = signing_key();
        let (alice_hello, alice_keys) = SecureHandshake::create(
            &alice_signing,
            "session-1".to_string(),
            "alice".to_string(),
            public_key_fingerprint(&alice_signing.verifying_key()),
        )
        .unwrap();
        let (bob_hello, bob_keys) = SecureHandshake::create(
            &bob_signing,
            "session-1".to_string(),
            "bob".to_string(),
            public_key_fingerprint(&bob_signing.verifying_key()),
        )
        .unwrap();
        alice_hello
            .verify(&bob_signing.verifying_key())
            .unwrap_err();
        bob_hello.verify(&bob_signing.verifying_key()).unwrap();
        alice_hello.verify(&alice_signing.verifying_key()).unwrap();
        let mut alice = establish_channel(
            &alice_keys,
            &alice_hello,
            &bob_hello,
            &bob_signing.verifying_key(),
            "bob",
            &public_key_fingerprint(&bob_signing.verifying_key()),
            ChannelRole::Initiator,
        )
        .unwrap();
        let mut bob = establish_channel(
            &bob_keys,
            &bob_hello,
            &alice_hello,
            &alice_signing.verifying_key(),
            "alice",
            &public_key_fingerprint(&alice_signing.verifying_key()),
            ChannelRole::Responder,
        )
        .unwrap();
        let frame = alice.seal(b"secret control", b"job-1").unwrap();
        assert_eq!(bob.open(&frame, b"job-1").unwrap(), b"secret control");
        assert!(matches!(
            bob.open(&frame, b"job-1"),
            Err(SecureError::ReplayOrOutOfOrder)
        ));
    }

    #[test]
    fn channel_lifetime_limits_fail_closed_at_exact_boundaries() {
        assert!(plaintext_within_limit(MAX_CHANNEL_PLAINTEXT_BYTES - 1, 1));
        assert!(!plaintext_within_limit(MAX_CHANNEL_PLAINTEXT_BYTES, 1));
        assert!(!plaintext_within_limit(0, MAX_CHANNEL_PLAINTEXT_BYTES + 1));

        let mut channel = SecureChannel {
            send_key: SecretKey::new([7u8; 32]),
            receive_key: SecretKey::new([8u8; 32]),
            next_send_sequence: MAX_CHANNEL_FRAMES,
            next_receive_sequence: 0,
            sent_plaintext_bytes: 0,
            received_plaintext_bytes: 0,
        };
        assert!(matches!(
            channel.seal(b"payload", b"lifetime"),
            Err(SecureError::SequenceExhausted)
        ));

        channel.next_send_sequence = 0;
        channel.sent_plaintext_bytes = MAX_CHANNEL_PLAINTEXT_BYTES;
        assert!(matches!(
            channel.seal(b"payload", b"lifetime"),
            Err(SecureError::SequenceExhausted)
        ));

        let mut sender = SecureChannel {
            send_key: SecretKey::new([9u8; 32]),
            receive_key: SecretKey::new([8u8; 32]),
            next_send_sequence: 0,
            next_receive_sequence: 0,
            sent_plaintext_bytes: 0,
            received_plaintext_bytes: 0,
        };
        let mut receiver = SecureChannel {
            send_key: SecretKey::new([8u8; 32]),
            receive_key: SecretKey::new([9u8; 32]),
            next_send_sequence: 0,
            next_receive_sequence: 0,
            sent_plaintext_bytes: 0,
            received_plaintext_bytes: MAX_CHANNEL_PLAINTEXT_BYTES,
        };
        let frame = sender.seal(b"payload", b"lifetime").unwrap();
        assert!(matches!(
            receiver.open(&frame, b"lifetime"),
            Err(SecureError::SequenceExhausted)
        ));
    }

    #[test]
    fn channel_rejects_aad_tampering() {
        let signing = signing_key();
        let (hello_a, keys_a) = SecureHandshake::create(
            &signing,
            "s".to_string(),
            "a".to_string(),
            public_key_fingerprint(&signing.verifying_key()),
        )
        .unwrap();
        let (hello_b, keys_b) = SecureHandshake::create(
            &signing,
            "s".to_string(),
            "b".to_string(),
            public_key_fingerprint(&signing.verifying_key()),
        )
        .unwrap();
        let mut a = establish_channel(
            &keys_a,
            &hello_a,
            &hello_b,
            &signing.verifying_key(),
            "b",
            &public_key_fingerprint(&signing.verifying_key()),
            ChannelRole::Initiator,
        )
        .unwrap();
        let mut b = establish_channel(
            &keys_b,
            &hello_b,
            &hello_a,
            &signing.verifying_key(),
            "a",
            &public_key_fingerprint(&signing.verifying_key()),
            ChannelRole::Responder,
        )
        .unwrap();
        let frame = a.seal(b"payload", b"correct").unwrap();
        assert!(matches!(
            b.open(&frame, b"wrong"),
            Err(SecureError::AuthenticationFailed)
        ));
    }

    #[test]
    fn job_key_envelope_is_bound_to_job_and_recipient() {
        let job = sample_job();
        let content_key = JobKey::generate();
        let channel_key = JobKey::generate();
        let envelope =
            provision_job_key(&job, "receiver-1", "key-1", &content_key, &channel_key).unwrap();
        let opened = open_job_key(&envelope, &job, "receiver-1", &channel_key).unwrap();
        assert_eq!(opened.as_bytes(), content_key.as_bytes());
        assert!(open_job_key(&envelope, &job, "wrong", &channel_key).is_err());
    }

    #[test]
    fn job_key_envelope_rejects_wrong_content_key_id() {
        let job = sample_job();
        let content_key = JobKey::generate();
        let channel_key = JobKey::generate();
        let mut envelope =
            provision_job_key(&job, "receiver-1", "key-1", &content_key, &channel_key).unwrap();
        envelope.key_id = "other-key".to_string();
        assert!(matches!(
            open_job_key(&envelope, &job, "receiver-1", &channel_key),
            Err(SecureError::AuthenticationFailed)
        ));
    }

    #[test]
    fn encrypted_piece_requires_the_exact_snapshot_aad() {
        let key = JobKey::generate();
        let (header, ciphertext) = seal_piece(
            &key,
            "job-1",
            "root-1",
            "piece-1",
            "file-1",
            0,
            0,
            b"piece data",
        )
        .unwrap();
        assert_eq!(
            open_piece(&key, "root-1", &header, &ciphertext).unwrap(),
            b"piece data"
        );
        assert!(matches!(
            open_piece(&key, "root-2", &header, &ciphertext),
            Err(SecureError::AuthenticationFailed)
        ));
    }
}
