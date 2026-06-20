use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroWatchtowerPrivateEvidenceBusResult<T> = Result<T, String>;

pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PROTOCOL_VERSION: &str =
    "nebula-monero-watchtower-private-evidence-bus-v1";
pub const PROTOCOL_VERSION: &str = MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PROTOCOL_VERSION;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SCHEMA_VERSION: u64 = 1;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_HEIGHT: u64 = 912;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_ENVELOPE_SCHEME: &str =
    "ML-KEM-1024+XChaCha20-Poly1305-private-evidence-envelope-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-watchtower-evidence-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_QUORUM_SCHEME: &str =
    "weighted-pq-watchtower-quorum-bundle-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-evidence-sponsorship-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_FRAUD_ROUTE_SCHEME: &str =
    "privacy-preserving-fraud-route-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DISPUTE_RECEIPT_SCHEME: &str =
    "watchtower-private-dispute-receipt-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SLASHING_HANDOFF_SCHEME: &str =
    "watchtower-private-slashing-handoff-v1";
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 720;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_REORG_TTL_BLOCKS: u64 = 72;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_RESERVE_TTL_BLOCKS: u64 = 288;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_KEY_IMAGE_TTL_BLOCKS: u64 = 144;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 96;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MIN_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_BASE_SPONSOR_FEE_UNITS: u64 = 500;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MAX_SPONSOR_FEE_UNITS: u64 = 8_000;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_SPONSOR_POOL_UNITS: u64 = 1_000_000;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_HIGH_SEVERITY_WEIGHT: u64 = 2;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_SLASHING_WINDOW_BLOCKS: u64 = 144;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS: u64 = 10_000;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_ENVELOPES: usize = 262_144;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SIGNATURES: usize = 524_288;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_QUORUM_BUNDLES: usize = 131_072;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SPONSORSHIPS: usize = 131_072;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_FRAUD_ROUTES: usize = 131_072;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_RECEIPTS: usize = 131_072;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SLASHING_HANDOFFS: usize = 131_072;
pub const MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChannel {
    KeyImage,
    Reorg,
    Reserve,
    Endpoint,
    Exit,
    Privacy,
}

impl EvidenceChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyImage => "key_image",
            Self::Reorg => "reorg",
            Self::Reserve => "reserve",
            Self::Endpoint => "endpoint",
            Self::Exit => "exit",
            Self::Privacy => "privacy",
        }
    }

    pub fn ttl_blocks(self, config: &MoneroWatchtowerPrivateEvidenceBusConfig) -> u64 {
        match self {
            Self::KeyImage => config.key_image_ttl_blocks,
            Self::Reorg => config.reorg_ttl_blocks,
            Self::Reserve => config.reserve_ttl_blocks,
            Self::Endpoint | Self::Exit | Self::Privacy => config.evidence_ttl_blocks,
        }
        .max(1)
    }

    pub fn route_priority(self) -> u64 {
        match self {
            Self::KeyImage => 95,
            Self::Reserve => 90,
            Self::Reorg => 85,
            Self::Endpoint => 70,
            Self::Exit => 65,
            Self::Privacy => 60,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    KeyImageDoubleSpend,
    KeyImageReuse,
    ReorgDepthExceeded,
    ReorgWithheld,
    ReserveShortfall,
    ReserveViewEquivocation,
    EndpointCensorship,
    ExitDelay,
    PrivacyLeak,
    InvalidProof,
    Custom(String),
}

impl EvidenceKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::KeyImageDoubleSpend => "key_image_double_spend".to_string(),
            Self::KeyImageReuse => "key_image_reuse".to_string(),
            Self::ReorgDepthExceeded => "reorg_depth_exceeded".to_string(),
            Self::ReorgWithheld => "reorg_withheld".to_string(),
            Self::ReserveShortfall => "reserve_shortfall".to_string(),
            Self::ReserveViewEquivocation => "reserve_view_equivocation".to_string(),
            Self::EndpointCensorship => "endpoint_censorship".to_string(),
            Self::ExitDelay => "exit_delay".to_string(),
            Self::PrivacyLeak => "privacy_leak".to_string(),
            Self::InvalidProof => "invalid_proof".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn channel(&self) -> EvidenceChannel {
        match self {
            Self::KeyImageDoubleSpend | Self::KeyImageReuse => EvidenceChannel::KeyImage,
            Self::ReorgDepthExceeded | Self::ReorgWithheld => EvidenceChannel::Reorg,
            Self::ReserveShortfall | Self::ReserveViewEquivocation => EvidenceChannel::Reserve,
            Self::EndpointCensorship => EvidenceChannel::Endpoint,
            Self::ExitDelay => EvidenceChannel::Exit,
            Self::PrivacyLeak | Self::InvalidProof | Self::Custom(_) => EvidenceChannel::Privacy,
        }
    }

    pub fn high_severity(&self) -> bool {
        matches!(
            self,
            Self::KeyImageDoubleSpend
                | Self::ReorgDepthExceeded
                | Self::ReserveShortfall
                | Self::PrivacyLeak
                | Self::InvalidProof
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Sealed,
    Sponsored,
    Routed,
    QuorumPending,
    QuorumReached,
    Disputed,
    HandoffReady,
    SlashingSubmitted,
    Settled,
    Rejected,
    Expired,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Sponsored => "sponsored",
            Self::Routed => "routed",
            Self::QuorumPending => "quorum_pending",
            Self::QuorumReached => "quorum_reached",
            Self::Disputed => "disputed",
            Self::HandoffReady => "handoff_ready",
            Self::SlashingSubmitted => "slashing_submitted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Submitted,
    Accepted,
    Superseded,
    Rejected,
}

impl SignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Applied,
    Settled,
    Revoked,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudRouteStatus {
    Open,
    Routed,
    DisputeOpened,
    Resolved,
    Failed,
    Expired,
}

impl FraudRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Routed => "routed",
            Self::DisputeOpened => "dispute_opened",
            Self::Resolved => "resolved",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeOutcome {
    Pending,
    FraudProven,
    FraudRejected,
    PrivacyViolation,
    InsufficientQuorum,
    Expired,
}

impl DisputeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::FraudProven => "fraud_proven",
            Self::FraudRejected => "fraud_rejected",
            Self::PrivacyViolation => "privacy_violation",
            Self::InsufficientQuorum => "insufficient_quorum",
            Self::Expired => "expired",
        }
    }

    pub fn slashing_eligible(self) -> bool {
        matches!(self, Self::FraudProven | Self::PrivacyViolation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingHandoffStatus {
    Prepared,
    Submitted,
    Accepted,
    Rejected,
    Expired,
}

impl SlashingHandoffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerPrivateEvidenceBusConfig {
    pub schema_version: u64,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub envelope_scheme: String,
    pub pq_signature_scheme: String,
    pub quorum_scheme: String,
    pub sponsorship_scheme: String,
    pub fraud_route_scheme: String,
    pub dispute_receipt_scheme: String,
    pub slashing_handoff_scheme: String,
    pub evidence_ttl_blocks: u64,
    pub reorg_ttl_blocks: u64,
    pub reserve_ttl_blocks: u64,
    pub key_image_ttl_blocks: u64,
    pub dispute_window_blocks: u64,
    pub slashing_window_blocks: u64,
    pub min_quorum_weight: u64,
    pub min_privacy_set_size: u64,
    pub base_sponsor_fee_units: u64,
    pub max_sponsor_fee_units: u64,
    pub sponsor_pool_units: u64,
    pub high_severity_weight: u64,
}

impl MoneroWatchtowerPrivateEvidenceBusConfig {
    pub fn devnet() -> Self {
        Self {
            schema_version: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SCHEMA_VERSION,
            network: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_HASH_SUITE.to_string(),
            envelope_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_ENVELOPE_SCHEME.to_string(),
            pq_signature_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PQ_SIGNATURE_SCHEME
                .to_string(),
            quorum_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_QUORUM_SCHEME.to_string(),
            sponsorship_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SPONSORSHIP_SCHEME
                .to_string(),
            fraud_route_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_FRAUD_ROUTE_SCHEME
                .to_string(),
            dispute_receipt_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DISPUTE_RECEIPT_SCHEME
                .to_string(),
            slashing_handoff_scheme: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_SLASHING_HANDOFF_SCHEME
                .to_string(),
            evidence_ttl_blocks: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_EVIDENCE_TTL_BLOCKS,
            reorg_ttl_blocks: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_REORG_TTL_BLOCKS,
            reserve_ttl_blocks: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_RESERVE_TTL_BLOCKS,
            key_image_ttl_blocks:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_KEY_IMAGE_TTL_BLOCKS,
            dispute_window_blocks:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            slashing_window_blocks:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_SLASHING_WINDOW_BLOCKS,
            min_quorum_weight: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MIN_QUORUM_WEIGHT,
            min_privacy_set_size:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            base_sponsor_fee_units:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_BASE_SPONSOR_FEE_UNITS,
            max_sponsor_fee_units:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_MAX_SPONSOR_FEE_UNITS,
            sponsor_pool_units: MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_SPONSOR_POOL_UNITS,
            high_severity_weight:
                MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEFAULT_HIGH_SEVERITY_WEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "envelope_scheme": self.envelope_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "quorum_scheme": self.quorum_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "fraud_route_scheme": self.fraud_route_scheme,
            "dispute_receipt_scheme": self.dispute_receipt_scheme,
            "slashing_handoff_scheme": self.slashing_handoff_scheme,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "reorg_ttl_blocks": self.reorg_ttl_blocks,
            "reserve_ttl_blocks": self.reserve_ttl_blocks,
            "key_image_ttl_blocks": self.key_image_ttl_blocks,
            "dispute_window_blocks": self.dispute_window_blocks,
            "slashing_window_blocks": self.slashing_window_blocks,
            "min_quorum_weight": self.min_quorum_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "base_sponsor_fee_units": self.base_sponsor_fee_units,
            "max_sponsor_fee_units": self.max_sponsor_fee_units,
            "sponsor_pool_units": self.sponsor_pool_units,
            "high_severity_weight": self.high_severity_weight
        })
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("network", &self.network)?;
        ensure_non_empty("asset id", &self.asset_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("hash suite", &self.hash_suite)?;
        ensure_non_empty("envelope scheme", &self.envelope_scheme)?;
        ensure_non_empty("pq signature scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("quorum scheme", &self.quorum_scheme)?;
        ensure_non_empty("sponsorship scheme", &self.sponsorship_scheme)?;
        ensure_non_empty("fraud route scheme", &self.fraud_route_scheme)?;
        ensure_non_empty("dispute receipt scheme", &self.dispute_receipt_scheme)?;
        ensure_non_empty("slashing handoff scheme", &self.slashing_handoff_scheme)?;
        ensure_positive("evidence ttl blocks", self.evidence_ttl_blocks)?;
        ensure_positive("reorg ttl blocks", self.reorg_ttl_blocks)?;
        ensure_positive("reserve ttl blocks", self.reserve_ttl_blocks)?;
        ensure_positive("key image ttl blocks", self.key_image_ttl_blocks)?;
        ensure_positive("dispute window blocks", self.dispute_window_blocks)?;
        ensure_positive("slashing window blocks", self.slashing_window_blocks)?;
        ensure_positive("min quorum weight", self.min_quorum_weight)?;
        ensure_positive("min privacy set size", self.min_privacy_set_size)?;
        if self.base_sponsor_fee_units > self.max_sponsor_fee_units {
            return Err("base sponsor fee cannot exceed max sponsor fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEvidenceEnvelope {
    pub envelope_id: String,
    pub channel: EvidenceChannel,
    pub kind: EvidenceKind,
    pub reporter_commitment: String,
    pub subject_commitment: String,
    pub monero_context_root: String,
    pub evidence_ciphertext_hash: String,
    pub evidence_plaintext_commitment: String,
    pub view_key_commitment: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: EnvelopeStatus,
    pub sponsorship_id: Option<String>,
    pub route_id: Option<String>,
    pub quorum_bundle_id: Option<String>,
    pub dispute_receipt_id: Option<String>,
    pub slashing_handoff_id: Option<String>,
    pub tags: BTreeSet<String>,
}

impl EncryptedEvidenceEnvelope {
    pub fn new(
        config: &MoneroWatchtowerPrivateEvidenceBusConfig,
        kind: EvidenceKind,
        reporter_commitment: &str,
        subject_commitment: &str,
        monero_context_root: &str,
        evidence_plaintext_commitment: &str,
        view_key_commitment: &str,
        privacy_set_size: u64,
        opened_at_height: u64,
        envelope_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        config.validate()?;
        ensure_non_empty("reporter commitment", reporter_commitment)?;
        ensure_non_empty("subject commitment", subject_commitment)?;
        ensure_non_empty("monero context root", monero_context_root)?;
        ensure_non_empty(
            "evidence plaintext commitment",
            evidence_plaintext_commitment,
        )?;
        ensure_non_empty("view key commitment", view_key_commitment)?;
        if privacy_set_size < config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        let channel = kind.channel();
        let expires_at_height = opened_at_height.saturating_add(channel.ttl_blocks(config));
        let evidence_ciphertext_hash = evidence_ciphertext_hash(
            &kind,
            reporter_commitment,
            subject_commitment,
            monero_context_root,
            evidence_plaintext_commitment,
            view_key_commitment,
            opened_at_height,
            envelope_nonce,
        );
        let nullifier = evidence_nullifier(
            reporter_commitment,
            subject_commitment,
            evidence_plaintext_commitment,
            envelope_nonce,
        );
        let envelope_id = evidence_envelope_id(
            channel,
            &kind,
            reporter_commitment,
            subject_commitment,
            &evidence_ciphertext_hash,
            opened_at_height,
            envelope_nonce,
        );
        let mut tags = BTreeSet::new();
        let _ = tags.insert(channel.as_str().to_string());
        if kind.high_severity() {
            let _ = tags.insert("high_severity".to_string());
        }
        Ok(Self {
            envelope_id,
            channel,
            kind,
            reporter_commitment: reporter_commitment.to_string(),
            subject_commitment: subject_commitment.to_string(),
            monero_context_root: monero_context_root.to_string(),
            evidence_ciphertext_hash,
            evidence_plaintext_commitment: evidence_plaintext_commitment.to_string(),
            view_key_commitment: view_key_commitment.to_string(),
            nullifier,
            privacy_set_size,
            opened_at_height,
            expires_at_height,
            status: EnvelopeStatus::Sealed,
            sponsorship_id: None,
            route_id: None,
            quorum_bundle_id: None,
            dispute_receipt_id: None,
            slashing_handoff_id: None,
            tags,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "channel": self.channel.as_str(),
            "kind": self.kind.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "subject_commitment": self.subject_commitment,
            "monero_context_root": self.monero_context_root,
            "evidence_ciphertext_hash": self.evidence_ciphertext_hash,
            "evidence_plaintext_commitment": self.evidence_plaintext_commitment,
            "view_key_commitment": self.view_key_commitment,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "sponsorship_id": self.sponsorship_id,
            "route_id": self.route_id,
            "quorum_bundle_id": self.quorum_bundle_id,
            "dispute_receipt_id": self.dispute_receipt_id,
            "slashing_handoff_id": self.slashing_handoff_id,
            "tags": self.tags
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &MoneroWatchtowerPrivateEvidenceBusConfig,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("reporter commitment", &self.reporter_commitment)?;
        ensure_non_empty("subject commitment", &self.subject_commitment)?;
        ensure_non_empty("monero context root", &self.monero_context_root)?;
        ensure_non_empty("ciphertext hash", &self.evidence_ciphertext_hash)?;
        ensure_non_empty("plaintext commitment", &self.evidence_plaintext_commitment)?;
        ensure_non_empty("view key commitment", &self.view_key_commitment)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("envelope privacy set below minimum".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("envelope expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height && !self.status.terminal()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatchtowerSignature {
    pub signature_id: String,
    pub envelope_id: String,
    pub watcher_commitment: String,
    pub watcher_key_id: String,
    pub transcript_root: String,
    pub signature_commitment: String,
    pub signature_weight: u64,
    pub signed_at_height: u64,
    pub status: SignatureStatus,
}

impl PqWatchtowerSignature {
    pub fn new(
        envelope: &EncryptedEvidenceEnvelope,
        watcher_commitment: &str,
        watcher_key_id: &str,
        signature_weight: u64,
        signed_at_height: u64,
        signature_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("watcher commitment", watcher_commitment)?;
        ensure_non_empty("watcher key id", watcher_key_id)?;
        ensure_positive("signature weight", signature_weight)?;
        let transcript_root = pq_signature_transcript_root(
            &envelope.envelope_id,
            &envelope.evidence_ciphertext_hash,
            watcher_commitment,
            watcher_key_id,
            signed_at_height,
        );
        let signature_commitment =
            pq_signature_commitment(watcher_commitment, watcher_key_id, &transcript_root);
        let signature_id = pq_signature_id(
            &envelope.envelope_id,
            watcher_commitment,
            watcher_key_id,
            &signature_commitment,
            signature_nonce,
        );
        Ok(Self {
            signature_id,
            envelope_id: envelope.envelope_id.clone(),
            watcher_commitment: watcher_commitment.to_string(),
            watcher_key_id: watcher_key_id.to_string(),
            transcript_root,
            signature_commitment,
            signature_weight,
            signed_at_height,
            status: SignatureStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "envelope_id": self.envelope_id,
            "watcher_commitment": self.watcher_commitment,
            "watcher_key_id": self.watcher_key_id,
            "transcript_root": self.transcript_root,
            "signature_commitment": self.signature_commitment,
            "signature_weight": self.signature_weight,
            "signed_at_height": self.signed_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-PQ-SIGNATURE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("signature id", &self.signature_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("watcher commitment", &self.watcher_commitment)?;
        ensure_non_empty("watcher key id", &self.watcher_key_id)?;
        ensure_non_empty("transcript root", &self.transcript_root)?;
        ensure_non_empty("signature commitment", &self.signature_commitment)?;
        ensure_positive("signature weight", self.signature_weight)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerQuorumBundle {
    pub bundle_id: String,
    pub envelope_id: String,
    pub signature_ids: BTreeSet<String>,
    pub watcher_commitments: BTreeSet<String>,
    pub quorum_weight: u64,
    pub required_weight: u64,
    pub bundle_root: String,
    pub formed_at_height: u64,
}

impl WatchtowerQuorumBundle {
    pub fn new(
        envelope_id: &str,
        signatures: &[PqWatchtowerSignature],
        required_weight: u64,
        formed_at_height: u64,
        bundle_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("envelope id", envelope_id)?;
        ensure_positive("required weight", required_weight)?;
        let mut signature_ids = BTreeSet::new();
        let mut watcher_commitments = BTreeSet::new();
        let mut quorum_weight = 0_u64;
        let mut signature_records = Vec::new();
        for signature in signatures {
            if signature.envelope_id != envelope_id {
                return Err("quorum signature references a different envelope".to_string());
            }
            if signature.status.counts_for_quorum() {
                let _ = signature_ids.insert(signature.signature_id.clone());
                let _ = watcher_commitments.insert(signature.watcher_commitment.clone());
                quorum_weight = quorum_weight.saturating_add(signature.signature_weight);
                signature_records.push(signature.public_record());
            }
        }
        if quorum_weight < required_weight {
            return Err("quorum weight below required threshold".to_string());
        }
        let bundle_root = merkle_root(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-QUORUM-SIGNATURES",
            &signature_records,
        );
        let bundle_id = quorum_bundle_id(
            envelope_id,
            &bundle_root,
            quorum_weight,
            required_weight,
            formed_at_height,
            bundle_nonce,
        );
        Ok(Self {
            bundle_id,
            envelope_id: envelope_id.to_string(),
            signature_ids,
            watcher_commitments,
            quorum_weight,
            required_weight,
            bundle_root,
            formed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "envelope_id": self.envelope_id,
            "signature_ids": self.signature_ids,
            "watcher_commitments": self.watcher_commitments,
            "quorum_weight": self.quorum_weight,
            "required_weight": self.required_weight,
            "bundle_root": self.bundle_root,
            "formed_at_height": self.formed_at_height
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-QUORUM-BUNDLE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("bundle id", &self.bundle_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("bundle root", &self.bundle_root)?;
        ensure_positive("required weight", self.required_weight)?;
        if self.quorum_weight < self.required_weight {
            return Err("bundle quorum weight below required weight".to_string());
        }
        if self.signature_ids.is_empty() {
            return Err("bundle requires at least one signature".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeEvidenceSponsorship {
    pub sponsorship_id: String,
    pub envelope_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub fee_units: u64,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeEvidenceSponsorship {
    pub fn new(
        config: &MoneroWatchtowerPrivateEvidenceBusConfig,
        envelope: &EncryptedEvidenceEnvelope,
        sponsor_commitment: &str,
        fee_units: u64,
        rebate_bps: u64,
        opened_at_height: u64,
        sponsorship_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("sponsor commitment", sponsor_commitment)?;
        if fee_units < config.base_sponsor_fee_units || fee_units > config.max_sponsor_fee_units {
            return Err("sponsorship fee outside configured bounds".to_string());
        }
        if rebate_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("sponsorship rebate exceeds max bps".to_string());
        }
        let sponsorship_id = sponsorship_id(
            &envelope.envelope_id,
            sponsor_commitment,
            fee_units,
            rebate_bps,
            sponsorship_nonce,
        );
        Ok(Self {
            sponsorship_id,
            envelope_id: envelope.envelope_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: config.fee_asset_id.clone(),
            fee_units,
            rebate_bps,
            opened_at_height,
            status: SponsorshipStatus::Offered,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "envelope_id": self.envelope_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "fee_units": self.fee_units,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("sponsorship id", &self.sponsorship_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("sponsorship fee units", self.fee_units)?;
        if self.rebate_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("sponsorship rebate exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudRoute {
    pub route_id: String,
    pub envelope_id: String,
    pub channel: EvidenceChannel,
    pub route_committee_root: String,
    pub destination_module: String,
    pub priority: u64,
    pub privacy_budget_bps: u64,
    pub routed_at_height: u64,
    pub status: FraudRouteStatus,
}

impl FraudRoute {
    pub fn new(
        envelope: &EncryptedEvidenceEnvelope,
        route_committee_root: &str,
        destination_module: &str,
        privacy_budget_bps: u64,
        routed_at_height: u64,
        route_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("route committee root", route_committee_root)?;
        ensure_non_empty("destination module", destination_module)?;
        if privacy_budget_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("privacy budget exceeds max bps".to_string());
        }
        let priority =
            envelope.channel.route_priority() + if envelope.kind.high_severity() { 10 } else { 0 };
        let route_id = fraud_route_id(
            &envelope.envelope_id,
            envelope.channel,
            route_committee_root,
            destination_module,
            routed_at_height,
            route_nonce,
        );
        Ok(Self {
            route_id,
            envelope_id: envelope.envelope_id.clone(),
            channel: envelope.channel,
            route_committee_root: route_committee_root.to_string(),
            destination_module: destination_module.to_string(),
            priority,
            privacy_budget_bps,
            routed_at_height,
            status: FraudRouteStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "envelope_id": self.envelope_id,
            "channel": self.channel.as_str(),
            "route_committee_root": self.route_committee_root,
            "destination_module": self.destination_module,
            "priority": self.priority,
            "privacy_budget_bps": self.privacy_budget_bps,
            "routed_at_height": self.routed_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-FRAUD-ROUTE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("route id", &self.route_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("route committee root", &self.route_committee_root)?;
        ensure_non_empty("destination module", &self.destination_module)?;
        if self.privacy_budget_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("privacy budget exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeReceipt {
    pub receipt_id: String,
    pub envelope_id: String,
    pub route_id: String,
    pub quorum_bundle_id: String,
    pub dispute_committee_root: String,
    pub outcome: DisputeOutcome,
    pub receipt_root: String,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl DisputeReceipt {
    pub fn new(
        envelope_id: &str,
        route_id: &str,
        quorum_bundle_id: &str,
        dispute_committee_root: &str,
        outcome: DisputeOutcome,
        opened_at_height: u64,
        receipt_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("envelope id", envelope_id)?;
        ensure_non_empty("route id", route_id)?;
        ensure_non_empty("quorum bundle id", quorum_bundle_id)?;
        ensure_non_empty("dispute committee root", dispute_committee_root)?;
        let receipt_root = dispute_receipt_root(
            envelope_id,
            route_id,
            quorum_bundle_id,
            dispute_committee_root,
            outcome,
            opened_at_height,
        );
        let receipt_id = dispute_receipt_id(envelope_id, route_id, &receipt_root, receipt_nonce);
        Ok(Self {
            receipt_id,
            envelope_id: envelope_id.to_string(),
            route_id: route_id.to_string(),
            quorum_bundle_id: quorum_bundle_id.to_string(),
            dispute_committee_root: dispute_committee_root.to_string(),
            outcome,
            receipt_root,
            opened_at_height,
            resolved_at_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "envelope_id": self.envelope_id,
            "route_id": self.route_id,
            "quorum_bundle_id": self.quorum_bundle_id,
            "dispute_committee_root": self.dispute_committee_root,
            "outcome": self.outcome.as_str(),
            "receipt_root": self.receipt_root,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-DISPUTE-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("route id", &self.route_id)?;
        ensure_non_empty("quorum bundle id", &self.quorum_bundle_id)?;
        ensure_non_empty("dispute committee root", &self.dispute_committee_root)?;
        ensure_non_empty("receipt root", &self.receipt_root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingHandoff {
    pub handoff_id: String,
    pub envelope_id: String,
    pub receipt_id: String,
    pub target_commitment: String,
    pub slashing_module: String,
    pub penalty_bps: u64,
    pub handoff_root: String,
    pub prepared_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlashingHandoffStatus,
}

impl SlashingHandoff {
    pub fn new(
        config: &MoneroWatchtowerPrivateEvidenceBusConfig,
        receipt: &DisputeReceipt,
        target_commitment: &str,
        slashing_module: &str,
        penalty_bps: u64,
        prepared_at_height: u64,
        handoff_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        ensure_non_empty("target commitment", target_commitment)?;
        ensure_non_empty("slashing module", slashing_module)?;
        if !receipt.outcome.slashing_eligible() {
            return Err("receipt outcome is not slashing eligible".to_string());
        }
        if penalty_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("penalty exceeds max bps".to_string());
        }
        let expires_at_height = prepared_at_height.saturating_add(config.slashing_window_blocks);
        let handoff_root = slashing_handoff_root(
            &receipt.envelope_id,
            &receipt.receipt_id,
            target_commitment,
            slashing_module,
            penalty_bps,
            prepared_at_height,
        );
        let handoff_id = slashing_handoff_id(
            &receipt.envelope_id,
            &receipt.receipt_id,
            &handoff_root,
            handoff_nonce,
        );
        Ok(Self {
            handoff_id,
            envelope_id: receipt.envelope_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            target_commitment: target_commitment.to_string(),
            slashing_module: slashing_module.to_string(),
            penalty_bps,
            handoff_root,
            prepared_at_height,
            expires_at_height,
            status: SlashingHandoffStatus::Prepared,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "envelope_id": self.envelope_id,
            "receipt_id": self.receipt_id,
            "target_commitment": self.target_commitment,
            "slashing_module": self.slashing_module,
            "penalty_bps": self.penalty_bps,
            "handoff_root": self.handoff_root,
            "prepared_at_height": self.prepared_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SLASHING-HANDOFF",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        ensure_non_empty("handoff id", &self.handoff_id)?;
        ensure_non_empty("envelope id", &self.envelope_id)?;
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("target commitment", &self.target_commitment)?;
        ensure_non_empty("slashing module", &self.slashing_module)?;
        ensure_non_empty("handoff root", &self.handoff_root)?;
        if self.expires_at_height <= self.prepared_at_height {
            return Err("slashing handoff expiry must be after prepared height".to_string());
        }
        if self.penalty_bps > MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_BPS {
            return Err("penalty exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerPrivateEvidenceBusRoots {
    pub config_root: String,
    pub envelope_root: String,
    pub key_image_channel_root: String,
    pub reorg_channel_root: String,
    pub reserve_channel_root: String,
    pub signature_root: String,
    pub quorum_bundle_root: String,
    pub sponsorship_root: String,
    pub fraud_route_root: String,
    pub dispute_receipt_root: String,
    pub slashing_handoff_root: String,
    pub event_root: String,
}

impl MoneroWatchtowerPrivateEvidenceBusRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "envelope_root": self.envelope_root,
            "key_image_channel_root": self.key_image_channel_root,
            "reorg_channel_root": self.reorg_channel_root,
            "reserve_channel_root": self.reserve_channel_root,
            "signature_root": self.signature_root,
            "quorum_bundle_root": self.quorum_bundle_root,
            "sponsorship_root": self.sponsorship_root,
            "fraud_route_root": self.fraud_route_root,
            "dispute_receipt_root": self.dispute_receipt_root,
            "slashing_handoff_root": self.slashing_handoff_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerPrivateEvidenceBusCounters {
    pub height: u64,
    pub envelopes: u64,
    pub key_image_envelopes: u64,
    pub reorg_envelopes: u64,
    pub reserve_envelopes: u64,
    pub signatures: u64,
    pub quorum_bundles: u64,
    pub sponsorships: u64,
    pub fraud_routes: u64,
    pub dispute_receipts: u64,
    pub slashing_handoffs: u64,
    pub open_envelopes: u64,
    pub high_severity_envelopes: u64,
    pub sponsored_fee_units: u64,
    pub slashing_ready: u64,
}

impl MoneroWatchtowerPrivateEvidenceBusCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "envelopes": self.envelopes,
            "key_image_envelopes": self.key_image_envelopes,
            "reorg_envelopes": self.reorg_envelopes,
            "reserve_envelopes": self.reserve_envelopes,
            "signatures": self.signatures,
            "quorum_bundles": self.quorum_bundles,
            "sponsorships": self.sponsorships,
            "fraud_routes": self.fraud_routes,
            "dispute_receipts": self.dispute_receipts,
            "slashing_handoffs": self.slashing_handoffs,
            "open_envelopes": self.open_envelopes,
            "high_severity_envelopes": self.high_severity_envelopes,
            "sponsored_fee_units": self.sponsored_fee_units,
            "slashing_ready": self.slashing_ready
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerPrivateEvidenceBusState {
    pub height: u64,
    pub config: MoneroWatchtowerPrivateEvidenceBusConfig,
    pub envelopes: BTreeMap<String, EncryptedEvidenceEnvelope>,
    pub key_image_channel: BTreeSet<String>,
    pub reorg_channel: BTreeSet<String>,
    pub reserve_channel: BTreeSet<String>,
    pub signatures: BTreeMap<String, PqWatchtowerSignature>,
    pub quorum_bundles: BTreeMap<String, WatchtowerQuorumBundle>,
    pub sponsorships: BTreeMap<String, LowFeeEvidenceSponsorship>,
    pub fraud_routes: BTreeMap<String, FraudRoute>,
    pub dispute_receipts: BTreeMap<String, DisputeReceipt>,
    pub slashing_handoffs: BTreeMap<String, SlashingHandoff>,
    pub event_log: Vec<Value>,
}

impl MoneroWatchtowerPrivateEvidenceBusState {
    pub fn new(height: u64, config: MoneroWatchtowerPrivateEvidenceBusConfig) -> Self {
        Self {
            height,
            config,
            envelopes: BTreeMap::new(),
            key_image_channel: BTreeSet::new(),
            reorg_channel: BTreeSet::new(),
            reserve_channel: BTreeSet::new(),
            signatures: BTreeMap::new(),
            quorum_bundles: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            fraud_routes: BTreeMap::new(),
            dispute_receipts: BTreeMap::new(),
            slashing_handoffs: BTreeMap::new(),
            event_log: Vec::new(),
        }
    }

    pub fn devnet() -> MoneroWatchtowerPrivateEvidenceBusResult<Self> {
        let config = MoneroWatchtowerPrivateEvidenceBusConfig::devnet();
        let mut state = Self::new(
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_DEVNET_HEIGHT,
            config.clone(),
        );

        let key_image = EncryptedEvidenceEnvelope::new(
            &config,
            EvidenceKind::KeyImageDoubleSpend,
            "reporter:watchtower-alpha",
            "subject:exit-policy-001",
            &sample_root("monero-key-image-context", "alpha"),
            &sample_root("plaintext-key-image-double-spend", "alpha"),
            &sample_root("view-key-share", "alpha"),
            2_048,
            state.height,
            1,
        )?;
        let reserve = EncryptedEvidenceEnvelope::new(
            &config,
            EvidenceKind::ReserveShortfall,
            "reporter:watchtower-beta",
            "subject:reserve-vault-001",
            &sample_root("monero-reserve-context", "beta"),
            &sample_root("plaintext-reserve-shortfall", "beta"),
            &sample_root("view-key-share", "beta"),
            4_096,
            state.height.saturating_add(1),
            2,
        )?;
        let reorg = EncryptedEvidenceEnvelope::new(
            &config,
            EvidenceKind::ReorgDepthExceeded,
            "reporter:watchtower-gamma",
            "subject:bridge-finality-epoch-009",
            &sample_root("monero-reorg-context", "gamma"),
            &sample_root("plaintext-reorg-depth", "gamma"),
            &sample_root("view-key-share", "gamma"),
            1_024,
            state.height.saturating_add(2),
            3,
        )?;

        state.submit_envelope(key_image)?;
        state.submit_envelope(reserve)?;
        state.submit_envelope(reorg)?;

        let envelope_ids = state.envelopes.keys().cloned().collect::<Vec<_>>();
        for (index, envelope_id) in envelope_ids.iter().enumerate() {
            let watcher_a = format!("watcher:{}:alpha", index);
            let watcher_b = format!("watcher:{}:beta", index);
            let first = state.sign_envelope(envelope_id, &watcher_a, "ml-dsa-key-alpha", 2, 10)?;
            let second = state.sign_envelope(envelope_id, &watcher_b, "slh-dsa-key-beta", 1, 11)?;
            let _ = state.form_quorum_bundle(envelope_id, &[first, second], 20)?;
            let sponsorship = state.sponsor_envelope(
                envelope_id,
                "sponsor:low-fee-evidence-pool",
                config.base_sponsor_fee_units,
                8_000,
                30,
            )?;
            let route = state.route_envelope(
                envelope_id,
                &sample_root("fraud-route-committee", envelope_id),
                "private_rollup_fraud_proof",
                850,
                40,
            )?;
            let _ = state.record_event("devnet_sponsorship", &sponsorship);
            let _ = state.record_event("devnet_route", &route);
        }

        let first_envelope = state
            .envelopes
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet missing envelope".to_string())?;
        let first_route = state
            .envelopes
            .get(&first_envelope)
            .and_then(|envelope| envelope.route_id.clone())
            .ok_or_else(|| "devnet missing route".to_string())?;
        let first_bundle = state
            .envelopes
            .get(&first_envelope)
            .and_then(|envelope| envelope.quorum_bundle_id.clone())
            .ok_or_else(|| "devnet missing quorum bundle".to_string())?;
        let receipt = state.open_dispute_receipt(
            &first_envelope,
            &first_route,
            &first_bundle,
            &sample_root("dispute-committee", "alpha"),
            DisputeOutcome::FraudProven,
            50,
        )?;
        let _ = state.prepare_slashing_handoff(
            &receipt,
            "subject:exit-policy-001",
            "monero_watchtower_slashing",
            3_500,
            60,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        new_height: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if new_height < self.height {
            return Err("height cannot decrease".to_string());
        }
        self.height = new_height;
        let expired = self
            .envelopes
            .iter()
            .filter_map(|(id, envelope)| {
                if envelope.expired_at(new_height) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for envelope_id in expired {
            if let Some(envelope) = self.envelopes.get_mut(&envelope_id) {
                envelope.status = EnvelopeStatus::Expired;
            }
            self.record_event("envelope_expired", &envelope_id)?;
        }
        Ok(self.state_root())
    }

    pub fn submit_envelope(
        &mut self,
        envelope: EncryptedEvidenceEnvelope,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        self.config.validate()?;
        envelope.validate(&self.config)?;
        if self.envelopes.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_ENVELOPES {
            return Err("envelope capacity reached".to_string());
        }
        if self.envelopes.contains_key(&envelope.envelope_id) {
            return Err("duplicate evidence envelope".to_string());
        }
        if self
            .envelopes
            .values()
            .any(|existing| existing.nullifier == envelope.nullifier)
        {
            return Err("duplicate evidence nullifier".to_string());
        }
        let envelope_id = envelope.envelope_id.clone();
        self.index_channel(envelope.channel, &envelope_id);
        self.record_event("envelope_submitted", &envelope.public_record())?;
        let _ = self.envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn sign_envelope(
        &mut self,
        envelope_id: &str,
        watcher_commitment: &str,
        watcher_key_id: &str,
        signature_weight: u64,
        signature_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.signatures.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SIGNATURES {
            return Err("signature capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get(envelope_id)
            .cloned()
            .ok_or_else(|| "unknown envelope".to_string())?;
        if envelope.status.terminal() {
            return Err("cannot sign terminal envelope".to_string());
        }
        let signature = PqWatchtowerSignature::new(
            &envelope,
            watcher_commitment,
            watcher_key_id,
            signature_weight,
            self.height,
            signature_nonce,
        )?;
        signature.validate()?;
        let signature_id = signature.signature_id.clone();
        if self.signatures.contains_key(&signature_id) {
            return Err("duplicate signature".to_string());
        }
        self.record_event("pq_signature_submitted", &signature.public_record())?;
        let _ = self.signatures.insert(signature_id.clone(), signature);
        if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
            envelope.status = EnvelopeStatus::QuorumPending;
        }
        Ok(signature_id)
    }

    pub fn form_quorum_bundle(
        &mut self,
        envelope_id: &str,
        signature_ids: &[String],
        bundle_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.quorum_bundles.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_QUORUM_BUNDLES {
            return Err("quorum bundle capacity reached".to_string());
        }
        let signatures = signature_ids
            .iter()
            .map(|id| {
                self.signatures
                    .get(id)
                    .cloned()
                    .ok_or_else(|| "unknown quorum signature".to_string())
            })
            .collect::<MoneroWatchtowerPrivateEvidenceBusResult<Vec<_>>>()?;
        let required = self.required_weight_for_envelope(envelope_id)?;
        let bundle = WatchtowerQuorumBundle::new(
            envelope_id,
            &signatures,
            required,
            self.height,
            bundle_nonce,
        )?;
        bundle.validate()?;
        let bundle_id = bundle.bundle_id.clone();
        if self.quorum_bundles.contains_key(&bundle_id) {
            return Err("duplicate quorum bundle".to_string());
        }
        self.record_event("quorum_bundle_formed", &bundle.public_record())?;
        let _ = self.quorum_bundles.insert(bundle_id.clone(), bundle);
        if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
            envelope.status = EnvelopeStatus::QuorumReached;
            envelope.quorum_bundle_id = Some(bundle_id.clone());
        }
        Ok(bundle_id)
    }

    pub fn sponsor_envelope(
        &mut self,
        envelope_id: &str,
        sponsor_commitment: &str,
        fee_units: u64,
        rebate_bps: u64,
        sponsorship_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.sponsorships.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get(envelope_id)
            .cloned()
            .ok_or_else(|| "unknown envelope".to_string())?;
        let sponsorship = LowFeeEvidenceSponsorship::new(
            &self.config,
            &envelope,
            sponsor_commitment,
            fee_units,
            rebate_bps,
            self.height,
            sponsorship_nonce,
        )?;
        sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        if self.sponsorships.contains_key(&sponsorship_id) {
            return Err("duplicate sponsorship".to_string());
        }
        self.record_event("evidence_sponsored", &sponsorship.public_record())?;
        let _ = self
            .sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
            envelope.status = EnvelopeStatus::Sponsored;
            envelope.sponsorship_id = Some(sponsorship_id.clone());
        }
        Ok(sponsorship_id)
    }

    pub fn route_envelope(
        &mut self,
        envelope_id: &str,
        route_committee_root: &str,
        destination_module: &str,
        privacy_budget_bps: u64,
        route_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.fraud_routes.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_FRAUD_ROUTES {
            return Err("fraud route capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get(envelope_id)
            .cloned()
            .ok_or_else(|| "unknown envelope".to_string())?;
        let route = FraudRoute::new(
            &envelope,
            route_committee_root,
            destination_module,
            privacy_budget_bps,
            self.height,
            route_nonce,
        )?;
        route.validate()?;
        let route_id = route.route_id.clone();
        if self.fraud_routes.contains_key(&route_id) {
            return Err("duplicate fraud route".to_string());
        }
        self.record_event("fraud_route_opened", &route.public_record())?;
        let _ = self.fraud_routes.insert(route_id.clone(), route);
        if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
            envelope.status = EnvelopeStatus::Routed;
            envelope.route_id = Some(route_id.clone());
        }
        Ok(route_id)
    }

    pub fn open_dispute_receipt(
        &mut self,
        envelope_id: &str,
        route_id: &str,
        quorum_bundle_id: &str,
        dispute_committee_root: &str,
        outcome: DisputeOutcome,
        receipt_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.dispute_receipts.len() >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_RECEIPTS {
            return Err("dispute receipt capacity reached".to_string());
        }
        if !self.envelopes.contains_key(envelope_id) {
            return Err("unknown envelope".to_string());
        }
        if !self.fraud_routes.contains_key(route_id) {
            return Err("unknown fraud route".to_string());
        }
        if !self.quorum_bundles.contains_key(quorum_bundle_id) {
            return Err("unknown quorum bundle".to_string());
        }
        let receipt = DisputeReceipt::new(
            envelope_id,
            route_id,
            quorum_bundle_id,
            dispute_committee_root,
            outcome,
            self.height,
            receipt_nonce,
        )?;
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        self.record_event("dispute_receipt_opened", &receipt.public_record())?;
        let _ = self.dispute_receipts.insert(receipt_id.clone(), receipt);
        if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
            envelope.status = EnvelopeStatus::Disputed;
            envelope.dispute_receipt_id = Some(receipt_id.clone());
        }
        if let Some(route) = self.fraud_routes.get_mut(route_id) {
            route.status = FraudRouteStatus::DisputeOpened;
        }
        Ok(receipt_id)
    }

    pub fn prepare_slashing_handoff(
        &mut self,
        receipt_id: &str,
        target_commitment: &str,
        slashing_module: &str,
        penalty_bps: u64,
        handoff_nonce: u64,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        if self.slashing_handoffs.len()
            >= MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SLASHING_HANDOFFS
        {
            return Err("slashing handoff capacity reached".to_string());
        }
        let receipt = self
            .dispute_receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| "unknown dispute receipt".to_string())?;
        let handoff = SlashingHandoff::new(
            &self.config,
            &receipt,
            target_commitment,
            slashing_module,
            penalty_bps,
            self.height,
            handoff_nonce,
        )?;
        handoff.validate()?;
        let handoff_id = handoff.handoff_id.clone();
        self.record_event("slashing_handoff_prepared", &handoff.public_record())?;
        let _ = self.slashing_handoffs.insert(handoff_id.clone(), handoff);
        if let Some(envelope) = self.envelopes.get_mut(&receipt.envelope_id) {
            envelope.status = EnvelopeStatus::HandoffReady;
            envelope.slashing_handoff_id = Some(handoff_id.clone());
        }
        Ok(handoff_id)
    }

    pub fn roots(&self) -> MoneroWatchtowerPrivateEvidenceBusRoots {
        let config_root = domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-CONFIG",
            &[HashPart::Json(&self.config.public_record())],
            32,
        );
        let envelope_records = self
            .envelopes
            .values()
            .map(EncryptedEvidenceEnvelope::public_record)
            .collect::<Vec<_>>();
        let signature_records = self
            .signatures
            .values()
            .map(PqWatchtowerSignature::public_record)
            .collect::<Vec<_>>();
        let bundle_records = self
            .quorum_bundles
            .values()
            .map(WatchtowerQuorumBundle::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(LowFeeEvidenceSponsorship::public_record)
            .collect::<Vec<_>>();
        let route_records = self
            .fraud_routes
            .values()
            .map(FraudRoute::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .dispute_receipts
            .values()
            .map(DisputeReceipt::public_record)
            .collect::<Vec<_>>();
        let handoff_records = self
            .slashing_handoffs
            .values()
            .map(SlashingHandoff::public_record)
            .collect::<Vec<_>>();
        MoneroWatchtowerPrivateEvidenceBusRoots {
            config_root,
            envelope_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-ENVELOPES",
                &envelope_records,
            ),
            key_image_channel_root: set_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-KEY-IMAGE-CHANNEL",
                &self.key_image_channel,
            ),
            reorg_channel_root: set_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-REORG-CHANNEL",
                &self.reorg_channel,
            ),
            reserve_channel_root: set_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-RESERVE-CHANNEL",
                &self.reserve_channel,
            ),
            signature_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SIGNATURES",
                &signature_records,
            ),
            quorum_bundle_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-QUORUM-BUNDLES",
                &bundle_records,
            ),
            sponsorship_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SPONSORSHIPS",
                &sponsorship_records,
            ),
            fraud_route_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-FRAUD-ROUTES",
                &route_records,
            ),
            dispute_receipt_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-DISPUTE-RECEIPTS",
                &receipt_records,
            ),
            slashing_handoff_root: merkle_root(
                "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SLASHING-HANDOFFS",
                &handoff_records,
            ),
            event_root: merkle_root("MONERO-WATCHTOWER-PRIVATE-EVIDENCE-EVENTS", &self.event_log),
        }
    }

    pub fn counters(&self) -> MoneroWatchtowerPrivateEvidenceBusCounters {
        let mut key_image_envelopes = 0_u64;
        let mut reorg_envelopes = 0_u64;
        let mut reserve_envelopes = 0_u64;
        let mut open_envelopes = 0_u64;
        let mut high_severity_envelopes = 0_u64;
        for envelope in self.envelopes.values() {
            match envelope.channel {
                EvidenceChannel::KeyImage => {
                    key_image_envelopes = key_image_envelopes.saturating_add(1)
                }
                EvidenceChannel::Reorg => reorg_envelopes = reorg_envelopes.saturating_add(1),
                EvidenceChannel::Reserve => reserve_envelopes = reserve_envelopes.saturating_add(1),
                EvidenceChannel::Endpoint | EvidenceChannel::Exit | EvidenceChannel::Privacy => {}
            }
            if !envelope.status.terminal() {
                open_envelopes = open_envelopes.saturating_add(1);
            }
            if envelope.kind.high_severity() {
                high_severity_envelopes = high_severity_envelopes.saturating_add(1);
            }
        }
        let sponsored_fee_units = self
            .sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.live())
            .fold(0_u64, |acc, sponsorship| {
                acc.saturating_add(sponsorship.fee_units)
            });
        let slashing_ready = self
            .slashing_handoffs
            .values()
            .filter(|handoff| handoff.status == SlashingHandoffStatus::Prepared)
            .count() as u64;
        MoneroWatchtowerPrivateEvidenceBusCounters {
            height: self.height,
            envelopes: self.envelopes.len() as u64,
            key_image_envelopes,
            reorg_envelopes,
            reserve_envelopes,
            signatures: self.signatures.len() as u64,
            quorum_bundles: self.quorum_bundles.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            fraud_routes: self.fraud_routes.len() as u64,
            dispute_receipts: self.dispute_receipts.len() as u64,
            slashing_handoffs: self.slashing_handoffs.len() as u64,
            open_envelopes,
            high_severity_envelopes,
            sponsored_fee_units,
            slashing_ready,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            let _ = object.insert(
                "monero_watchtower_private_evidence_bus_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-BUS-STATE",
            &[
                HashPart::Str(MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record_without_state_root()),
            ],
            32,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
        self.config.validate()?;
        ensure_collection_limit(
            "envelopes",
            self.envelopes.len(),
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_ENVELOPES,
        )?;
        ensure_collection_limit(
            "signatures",
            self.signatures.len(),
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SIGNATURES,
        )?;
        ensure_collection_limit(
            "quorum bundles",
            self.quorum_bundles.len(),
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_QUORUM_BUNDLES,
        )?;
        ensure_collection_limit(
            "sponsorships",
            self.sponsorships.len(),
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_SPONSORSHIPS,
        )?;
        let mut nullifiers = BTreeSet::new();
        for envelope in self.envelopes.values() {
            envelope.validate(&self.config)?;
            if !nullifiers.insert(envelope.nullifier.clone()) {
                return Err("duplicate envelope nullifier".to_string());
            }
            if envelope.channel == EvidenceChannel::KeyImage
                && !self.key_image_channel.contains(&envelope.envelope_id)
            {
                return Err("key image envelope missing channel index".to_string());
            }
            if envelope.channel == EvidenceChannel::Reorg
                && !self.reorg_channel.contains(&envelope.envelope_id)
            {
                return Err("reorg envelope missing channel index".to_string());
            }
            if envelope.channel == EvidenceChannel::Reserve
                && !self.reserve_channel.contains(&envelope.envelope_id)
            {
                return Err("reserve envelope missing channel index".to_string());
            }
        }
        for signature in self.signatures.values() {
            signature.validate()?;
            if !self.envelopes.contains_key(&signature.envelope_id) {
                return Err("signature references unknown envelope".to_string());
            }
        }
        for bundle in self.quorum_bundles.values() {
            bundle.validate()?;
            if !self.envelopes.contains_key(&bundle.envelope_id) {
                return Err("bundle references unknown envelope".to_string());
            }
            for signature_id in &bundle.signature_ids {
                if !self.signatures.contains_key(signature_id) {
                    return Err("bundle references unknown signature".to_string());
                }
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.envelopes.contains_key(&sponsorship.envelope_id) {
                return Err("sponsorship references unknown envelope".to_string());
            }
        }
        for route in self.fraud_routes.values() {
            route.validate()?;
            if !self.envelopes.contains_key(&route.envelope_id) {
                return Err("route references unknown envelope".to_string());
            }
        }
        for receipt in self.dispute_receipts.values() {
            receipt.validate()?;
            if !self.envelopes.contains_key(&receipt.envelope_id) {
                return Err("receipt references unknown envelope".to_string());
            }
            if !self.fraud_routes.contains_key(&receipt.route_id) {
                return Err("receipt references unknown route".to_string());
            }
            if !self.quorum_bundles.contains_key(&receipt.quorum_bundle_id) {
                return Err("receipt references unknown quorum bundle".to_string());
            }
        }
        for handoff in self.slashing_handoffs.values() {
            handoff.validate()?;
            if !self.envelopes.contains_key(&handoff.envelope_id) {
                return Err("handoff references unknown envelope".to_string());
            }
            if !self.dispute_receipts.contains_key(&handoff.receipt_id) {
                return Err("handoff references unknown receipt".to_string());
            }
        }
        Ok(())
    }

    fn index_channel(&mut self, channel: EvidenceChannel, envelope_id: &str) {
        match channel {
            EvidenceChannel::KeyImage => {
                let _ = self.key_image_channel.insert(envelope_id.to_string());
            }
            EvidenceChannel::Reorg => {
                let _ = self.reorg_channel.insert(envelope_id.to_string());
            }
            EvidenceChannel::Reserve => {
                let _ = self.reserve_channel.insert(envelope_id.to_string());
            }
            EvidenceChannel::Endpoint | EvidenceChannel::Exit | EvidenceChannel::Privacy => {}
        }
    }

    fn required_weight_for_envelope(
        &self,
        envelope_id: &str,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<u64> {
        let envelope = self
            .envelopes
            .get(envelope_id)
            .ok_or_else(|| "unknown envelope".to_string())?;
        let severity_weight = if envelope.kind.high_severity() {
            self.config.high_severity_weight
        } else {
            0
        };
        Ok(self
            .config
            .min_quorum_weight
            .saturating_add(severity_weight))
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        payload: &impl Serialize,
    ) -> MoneroWatchtowerPrivateEvidenceBusResult<String> {
        ensure_collection_limit(
            "event log",
            self.event_log.len(),
            MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_MAX_EVENTS,
        )?;
        let payload_value = serde_json::to_value(payload).map_err(|err| err.to_string())?;
        let event_id = event_id(
            event_kind,
            self.height,
            &payload_value,
            self.event_log.len() as u64,
        );
        let event = json!({
            "event_id": event_id,
            "event_kind": event_kind,
            "height": self.height,
            "payload": payload_value
        });
        self.event_log.push(event);
        Ok(event_id)
    }
}

pub fn devnet() -> MoneroWatchtowerPrivateEvidenceBusResult<MoneroWatchtowerPrivateEvidenceBusState>
{
    MoneroWatchtowerPrivateEvidenceBusState::devnet()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn evidence_envelope_id(
    channel: EvidenceChannel,
    kind: &EvidenceKind,
    reporter_commitment: &str,
    subject_commitment: &str,
    evidence_ciphertext_hash: &str,
    opened_at_height: u64,
    envelope_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel.as_str()),
            HashPart::Str(&kind.as_str()),
            HashPart::Str(reporter_commitment),
            HashPart::Str(subject_commitment),
            HashPart::Str(evidence_ciphertext_hash),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(envelope_nonce as i128),
        ],
        32,
    )
}

pub fn evidence_ciphertext_hash(
    kind: &EvidenceKind,
    reporter_commitment: &str,
    subject_commitment: &str,
    monero_context_root: &str,
    evidence_plaintext_commitment: &str,
    view_key_commitment: &str,
    opened_at_height: u64,
    envelope_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_ENVELOPE_SCHEME),
            HashPart::Str(&kind.as_str()),
            HashPart::Str(reporter_commitment),
            HashPart::Str(subject_commitment),
            HashPart::Str(monero_context_root),
            HashPart::Str(evidence_plaintext_commitment),
            HashPart::Str(view_key_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(envelope_nonce as i128),
        ],
        32,
    )
}

pub fn evidence_nullifier(
    reporter_commitment: &str,
    subject_commitment: &str,
    evidence_plaintext_commitment: &str,
    envelope_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reporter_commitment),
            HashPart::Str(subject_commitment),
            HashPart::Str(evidence_plaintext_commitment),
            HashPart::Int(envelope_nonce as i128),
        ],
        32,
    )
}

pub fn pq_signature_transcript_root(
    envelope_id: &str,
    evidence_ciphertext_hash: &str,
    watcher_commitment: &str,
    watcher_key_id: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-PQ-SIGNATURE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_PQ_SIGNATURE_SCHEME),
            HashPart::Str(envelope_id),
            HashPart::Str(evidence_ciphertext_hash),
            HashPart::Str(watcher_commitment),
            HashPart::Str(watcher_key_id),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_signature_commitment(
    watcher_commitment: &str,
    watcher_key_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-PQ-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_commitment),
            HashPart::Str(watcher_key_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn pq_signature_id(
    envelope_id: &str,
    watcher_commitment: &str,
    watcher_key_id: &str,
    signature_commitment: &str,
    signature_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-PQ-SIGNATURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(watcher_commitment),
            HashPart::Str(watcher_key_id),
            HashPart::Str(signature_commitment),
            HashPart::Int(signature_nonce as i128),
        ],
        32,
    )
}

pub fn quorum_bundle_id(
    envelope_id: &str,
    bundle_root: &str,
    quorum_weight: u64,
    required_weight: u64,
    formed_at_height: u64,
    bundle_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-QUORUM-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_PRIVATE_EVIDENCE_BUS_QUORUM_SCHEME),
            HashPart::Str(envelope_id),
            HashPart::Str(bundle_root),
            HashPart::Int(quorum_weight as i128),
            HashPart::Int(required_weight as i128),
            HashPart::Int(formed_at_height as i128),
            HashPart::Int(bundle_nonce as i128),
        ],
        32,
    )
}

pub fn sponsorship_id(
    envelope_id: &str,
    sponsor_commitment: &str,
    fee_units: u64,
    rebate_bps: u64,
    sponsorship_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(fee_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Int(sponsorship_nonce as i128),
        ],
        32,
    )
}

pub fn fraud_route_id(
    envelope_id: &str,
    channel: EvidenceChannel,
    route_committee_root: &str,
    destination_module: &str,
    routed_at_height: u64,
    route_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-FRAUD-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(channel.as_str()),
            HashPart::Str(route_committee_root),
            HashPart::Str(destination_module),
            HashPart::Int(routed_at_height as i128),
            HashPart::Int(route_nonce as i128),
        ],
        32,
    )
}

pub fn dispute_receipt_root(
    envelope_id: &str,
    route_id: &str,
    quorum_bundle_id: &str,
    dispute_committee_root: &str,
    outcome: DisputeOutcome,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-DISPUTE-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(route_id),
            HashPart::Str(quorum_bundle_id),
            HashPart::Str(dispute_committee_root),
            HashPart::Str(outcome.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn dispute_receipt_id(
    envelope_id: &str,
    route_id: &str,
    receipt_root: &str,
    receipt_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-DISPUTE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(route_id),
            HashPart::Str(receipt_root),
            HashPart::Int(receipt_nonce as i128),
        ],
        32,
    )
}

pub fn slashing_handoff_root(
    envelope_id: &str,
    receipt_id: &str,
    target_commitment: &str,
    slashing_module: &str,
    penalty_bps: u64,
    prepared_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SLASHING-HANDOFF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(receipt_id),
            HashPart::Str(target_commitment),
            HashPart::Str(slashing_module),
            HashPart::Int(penalty_bps as i128),
            HashPart::Int(prepared_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_handoff_id(
    envelope_id: &str,
    receipt_id: &str,
    handoff_root: &str,
    handoff_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-SLASHING-HANDOFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(receipt_id),
            HashPart::Str(handoff_root),
            HashPart::Int(handoff_nonce as i128),
        ],
        32,
    )
}

fn event_id(event_kind: &str, height: u64, payload: &Value, event_nonce: u64) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Int(height as i128),
            HashPart::Json(payload),
            HashPart::Int(event_nonce as i128),
        ],
        32,
    )
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-PRIVATE-EVIDENCE-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(label: &str, value: u64) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_collection_limit(
    label: &str,
    len: usize,
    max: usize,
) -> MoneroWatchtowerPrivateEvidenceBusResult<()> {
    if len > max {
        Err(format!("{label} exceeds capacity"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_is_deterministic_and_valid() {
        let first = MoneroWatchtowerPrivateEvidenceBusState::devnet();
        let second = MoneroWatchtowerPrivateEvidenceBusState::devnet();
        assert!(first.is_ok());
        assert!(second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            assert_eq!(first.state_root(), second.state_root());
            assert!(first.validate().is_ok());
        }
    }

    #[test]
    fn height_update_is_monotonic() {
        if let Ok(mut state) = MoneroWatchtowerPrivateEvidenceBusState::devnet() {
            let original = state.height;
            assert!(state.update_height(original.saturating_add(1)).is_ok());
            assert!(state.update_height(original).is_err());
        }
    }

    #[test]
    fn low_privacy_envelope_is_rejected() {
        let config = MoneroWatchtowerPrivateEvidenceBusConfig::devnet();
        let envelope = EncryptedEvidenceEnvelope::new(
            &config,
            EvidenceKind::PrivacyLeak,
            "reporter",
            "subject",
            "context",
            "plaintext",
            "view-key",
            4,
            1,
            1,
        );
        assert!(envelope.is_err());
    }
}
