use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, HashPart};

pub type PqOracleAttestationMeshResult<T> = Result<T, String>;

pub const PQ_ORACLE_ATTESTATION_MESH_PROTOCOL_VERSION: &str = "nebula-pq-oracle-mesh-v1";
pub const PQ_ORACLE_ATTESTATION_MESH_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_ORACLE_ATTESTATION_MESH_FALLBACK_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_ORACLE_ATTESTATION_MESH_COMMITMENT_SCHEME: &str = "shake256-poseidon-hybrid";
pub const PQ_ORACLE_ATTESTATION_MESH_PROOF_SYSTEM: &str = "zk-oracle-attestation-v1";
pub const PQ_ORACLE_ATTESTATION_MESH_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_ORACLE_ATTESTATION_MESH_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 90;
pub const PQ_ORACLE_ATTESTATION_MESH_DEFAULT_CHALLENGE_TTL_BLOCKS: u64 = 360;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_FEEDS: usize = 512;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_COMMITTEES: usize = 128;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_MEMBERS: usize = 2_048;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_UPDATES: usize = 8_192;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_ATTESTATIONS: usize = 16_384;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_CHALLENGES: usize = 4_096;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_SPONSORS: usize = 512;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_RECEIPTS: usize = 8_192;
pub const PQ_ORACLE_ATTESTATION_MESH_MAX_EVENTS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleFeedKind {
    XmrUsd,
    TokenPrice,
    AmmTwap,
    LendingCollateral,
    PerpFunding,
    StablecoinPeg,
    ReserveCoverage,
    ProofFee,
    DataAvailabilityFee,
    SequencerLatency,
}

impl PqOracleFeedKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::XmrUsd => "xmr_usd",
            Self::TokenPrice => "token_price",
            Self::AmmTwap => "amm_twap",
            Self::LendingCollateral => "lending_collateral",
            Self::PerpFunding => "perp_funding",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::ReserveCoverage => "reserve_coverage",
            Self::ProofFee => "proof_fee",
            Self::DataAvailabilityFee => "data_availability_fee",
            Self::SequencerLatency => "sequencer_latency",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleFeedStatus {
    Active,
    Paused,
    Quarantined,
    Retired,
}

impl PqOracleFeedStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_updates(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleCommitteeRole {
    Publisher,
    Aggregator,
    Watchtower,
    Challenger,
    FeeSponsor,
}

impl PqOracleCommitteeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::Aggregator => "aggregator",
            Self::Watchtower => "watchtower",
            Self::Challenger => "challenger",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleMemberStatus {
    Active,
    Suspended,
    Rotating,
    Slashed,
    Retired,
}

impl PqOracleMemberStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Rotating => "rotating",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleUpdateStatus {
    Pending,
    Attested,
    Accepted,
    Challenged,
    Rejected,
    Expired,
}

impl PqOracleUpdateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Attested => "attested",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleAttestationStatus {
    Submitted,
    Counted,
    Duplicate,
    Invalid,
    Expired,
}

impl PqOracleAttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleChallengeKind {
    StaleFeed,
    DivergentMedian,
    InvalidSignature,
    InsufficientQuorum,
    PrivacyLeak,
    FeeAbuse,
}

impl PqOracleChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaleFeed => "stale_feed",
            Self::DivergentMedian => "divergent_median",
            Self::InvalidSignature => "invalid_signature",
            Self::InsufficientQuorum => "insufficient_quorum",
            Self::PrivacyLeak => "privacy_leak",
            Self::FeeAbuse => "fee_abuse",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    Expired,
}

impl PqOracleChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleSponsorStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl PqOracleSponsorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleReceiptStatus {
    Pending,
    Posted,
    Audited,
    Disputed,
}

impl PqOracleReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Audited => "audited",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqOracleEventKind {
    FeedRegistered,
    CommitteeRotated,
    UpdateAccepted,
    AttestationCounted,
    ChallengeOpened,
    ChallengeResolved,
    SponsorDebited,
    PrivacyReceiptPosted,
}

impl PqOracleEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FeedRegistered => "feed_registered",
            Self::CommitteeRotated => "committee_rotated",
            Self::UpdateAccepted => "update_accepted",
            Self::AttestationCounted => "attestation_counted",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::SponsorDebited => "sponsor_debited",
            Self::PrivacyReceiptPosted => "privacy_receipt_posted",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestationMeshConfig {
    pub protocol_version: String,
    pub epoch_length_blocks: u64,
    pub update_ttl_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub min_quorum_weight_bps: u64,
    pub stale_feed_blocks: u64,
    pub max_deviation_bps: u64,
    pub low_fee_update_budget_units: u64,
    pub pq_signature_scheme: String,
    pub fallback_signature_scheme: String,
    pub commitment_scheme: String,
    pub proof_system: String,
}

impl Default for PqOracleAttestationMeshConfig {
    fn default() -> Self {
        Self {
            protocol_version: PQ_ORACLE_ATTESTATION_MESH_PROTOCOL_VERSION.to_string(),
            epoch_length_blocks: PQ_ORACLE_ATTESTATION_MESH_DEFAULT_EPOCH_BLOCKS,
            update_ttl_blocks: PQ_ORACLE_ATTESTATION_MESH_DEFAULT_UPDATE_TTL_BLOCKS,
            challenge_ttl_blocks: PQ_ORACLE_ATTESTATION_MESH_DEFAULT_CHALLENGE_TTL_BLOCKS,
            min_quorum_weight_bps: 6_700,
            stale_feed_blocks: 30,
            max_deviation_bps: 750,
            low_fee_update_budget_units: 2_500_000,
            pq_signature_scheme: PQ_ORACLE_ATTESTATION_MESH_PQ_SIGNATURE_SCHEME.to_string(),
            fallback_signature_scheme: PQ_ORACLE_ATTESTATION_MESH_FALLBACK_SIGNATURE_SCHEME
                .to_string(),
            commitment_scheme: PQ_ORACLE_ATTESTATION_MESH_COMMITMENT_SCHEME.to_string(),
            proof_system: PQ_ORACLE_ATTESTATION_MESH_PROOF_SYSTEM.to_string(),
        }
    }
}

impl PqOracleAttestationMeshConfig {
    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.protocol_version.trim().is_empty() {
            return Err("pq oracle mesh protocol version cannot be empty".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("pq oracle mesh epoch length must be positive".to_string());
        }
        if self.update_ttl_blocks == 0 || self.challenge_ttl_blocks == 0 {
            return Err("pq oracle mesh ttl values must be positive".to_string());
        }
        if self.min_quorum_weight_bps == 0 || self.min_quorum_weight_bps > 10_000 {
            return Err("pq oracle mesh quorum bps out of range".to_string());
        }
        if self.stale_feed_blocks == 0 {
            return Err("pq oracle mesh stale feed window must be positive".to_string());
        }
        if self.max_deviation_bps > 100_000 {
            return Err("pq oracle mesh max deviation is too large".to_string());
        }
        if self.low_fee_update_budget_units == 0 {
            return Err("pq oracle mesh low fee budget must be positive".to_string());
        }
        if self.pq_signature_scheme.trim().is_empty()
            || self.fallback_signature_scheme.trim().is_empty()
            || self.commitment_scheme.trim().is_empty()
            || self.proof_system.trim().is_empty()
        {
            return Err("pq oracle mesh cryptographic labels cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_attestation_mesh_config",
            "protocol_version": self.protocol_version,
            "epoch_length_blocks": self.epoch_length_blocks,
            "update_ttl_blocks": self.update_ttl_blocks,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "min_quorum_weight_bps": self.min_quorum_weight_bps,
            "stale_feed_blocks": self.stale_feed_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "low_fee_update_budget_units": self.low_fee_update_budget_units,
            "pq_signature_scheme": self.pq_signature_scheme,
            "fallback_signature_scheme": self.fallback_signature_scheme,
            "commitment_scheme": self.commitment_scheme,
            "proof_system": self.proof_system,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleFeed {
    pub feed_id: String,
    pub label: String,
    pub feed_kind: PqOracleFeedKind,
    pub status: PqOracleFeedStatus,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub precision: u32,
    pub min_update_interval_blocks: u64,
    pub max_staleness_blocks: u64,
    pub privacy_scope_root: String,
    pub risk_policy_root: String,
    pub registered_at_height: u64,
}

impl PqOracleFeed {
    pub fn new(
        label: &str,
        feed_kind: PqOracleFeedKind,
        base_asset: &str,
        quote_asset: &str,
        precision: u32,
        registered_at_height: u64,
        policy: &Value,
    ) -> PqOracleAttestationMeshResult<Self> {
        if label.trim().is_empty() || base_asset.trim().is_empty() || quote_asset.trim().is_empty()
        {
            return Err("pq oracle feed labels cannot be empty".to_string());
        }
        if precision > 18 {
            return Err("pq oracle feed precision is too high".to_string());
        }
        let base_asset_commitment = pq_oracle_string_root("FEED-BASE-ASSET", base_asset);
        let quote_asset_commitment = pq_oracle_string_root("FEED-QUOTE-ASSET", quote_asset);
        let risk_policy_root = pq_oracle_payload_root("FEED-RISK-POLICY", policy);
        let privacy_scope_root = pq_oracle_payload_root(
            "FEED-PRIVACY-SCOPE",
            &json!({
                "visibility": "commitment-only",
                "label": label,
                "feed_kind": feed_kind.as_str(),
            }),
        );
        let feed_id = pq_oracle_feed_id(
            label,
            &feed_kind,
            &base_asset_commitment,
            &quote_asset_commitment,
        );
        let feed = Self {
            feed_id,
            label: label.to_string(),
            feed_kind,
            status: PqOracleFeedStatus::Active,
            base_asset_commitment,
            quote_asset_commitment,
            precision,
            min_update_interval_blocks: 1,
            max_staleness_blocks: PQ_ORACLE_ATTESTATION_MESH_DEFAULT_UPDATE_TTL_BLOCKS,
            privacy_scope_root,
            risk_policy_root,
            registered_at_height,
        };
        feed.validate()?;
        Ok(feed)
    }

    pub fn with_update_windows(
        mut self,
        min_update_interval_blocks: u64,
        max_staleness_blocks: u64,
    ) -> Self {
        self.min_update_interval_blocks = min_update_interval_blocks.max(1);
        self.max_staleness_blocks = max_staleness_blocks.max(1);
        self
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.feed_id.trim().is_empty() || self.label.trim().is_empty() {
            return Err("pq oracle feed identifiers cannot be empty".to_string());
        }
        if self.base_asset_commitment.trim().is_empty()
            || self.quote_asset_commitment.trim().is_empty()
            || self.privacy_scope_root.trim().is_empty()
            || self.risk_policy_root.trim().is_empty()
        {
            return Err("pq oracle feed roots cannot be empty".to_string());
        }
        if self.precision > 18 {
            return Err("pq oracle feed precision is too high".to_string());
        }
        if self.min_update_interval_blocks == 0 || self.max_staleness_blocks == 0 {
            return Err("pq oracle feed update windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_feed",
            "feed_id": self.feed_id,
            "label": self.label,
            "feed_kind": self.feed_kind.as_str(),
            "status": self.status.as_str(),
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "precision": self.precision,
            "min_update_interval_blocks": self.min_update_interval_blocks,
            "max_staleness_blocks": self.max_staleness_blocks,
            "privacy_scope_root": self.privacy_scope_root,
            "risk_policy_root": self.risk_policy_root,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleCommitteeMember {
    pub member_id: String,
    pub label: String,
    pub role: PqOracleCommitteeRole,
    pub status: PqOracleMemberStatus,
    pub weight_bps: u64,
    pub pq_public_key_commitment: String,
    pub fallback_public_key_commitment: String,
    pub endpoint_commitment: String,
    pub stake_commitment: String,
    pub joined_at_height: u64,
}

impl PqOracleCommitteeMember {
    pub fn new(
        label: &str,
        role: PqOracleCommitteeRole,
        weight_bps: u64,
        endpoint: &str,
        stake_units: u64,
        joined_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if label.trim().is_empty() || endpoint.trim().is_empty() {
            return Err("pq oracle member labels cannot be empty".to_string());
        }
        if weight_bps == 0 || weight_bps > 10_000 {
            return Err("pq oracle member weight bps out of range".to_string());
        }
        if stake_units == 0 {
            return Err("pq oracle member stake must be positive".to_string());
        }
        let pq_public_key_commitment = pq_oracle_payload_root(
            "MEMBER-PQ-PUBKEY",
            &json!({
                "scheme": PQ_ORACLE_ATTESTATION_MESH_PQ_SIGNATURE_SCHEME,
                "label": label,
            }),
        );
        let fallback_public_key_commitment = pq_oracle_payload_root(
            "MEMBER-FALLBACK-PUBKEY",
            &json!({
                "scheme": PQ_ORACLE_ATTESTATION_MESH_FALLBACK_SIGNATURE_SCHEME,
                "label": label,
            }),
        );
        let endpoint_commitment = pq_oracle_string_root("MEMBER-ENDPOINT", endpoint);
        let stake_commitment = pq_oracle_amount_commitment("MEMBER-STAKE", stake_units);
        let member_id =
            pq_oracle_member_id(label, &role, &pq_public_key_commitment, joined_at_height);
        let member = Self {
            member_id,
            label: label.to_string(),
            role,
            status: PqOracleMemberStatus::Active,
            weight_bps,
            pq_public_key_commitment,
            fallback_public_key_commitment,
            endpoint_commitment,
            stake_commitment,
            joined_at_height,
        };
        member.validate()?;
        Ok(member)
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.member_id.trim().is_empty() || self.label.trim().is_empty() {
            return Err("pq oracle member identifiers cannot be empty".to_string());
        }
        if self.weight_bps == 0 || self.weight_bps > 10_000 {
            return Err("pq oracle member weight bps out of range".to_string());
        }
        if self.pq_public_key_commitment.trim().is_empty()
            || self.fallback_public_key_commitment.trim().is_empty()
            || self.endpoint_commitment.trim().is_empty()
            || self.stake_commitment.trim().is_empty()
        {
            return Err("pq oracle member commitments cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_committee_member",
            "member_id": self.member_id,
            "label": self.label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight_bps": self.weight_bps,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "fallback_public_key_commitment": self.fallback_public_key_commitment,
            "endpoint_commitment": self.endpoint_commitment,
            "stake_commitment": self.stake_commitment,
            "joined_at_height": self.joined_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub status: PqOracleFeedStatus,
    pub member_ids: Vec<String>,
    pub member_root: String,
    pub quorum_weight_bps: u64,
    pub feed_scope_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PqOracleCommittee {
    pub fn new(
        epoch: u64,
        member_ids: &[String],
        feed_ids: &[String],
        quorum_weight_bps: u64,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if member_ids.is_empty() {
            return Err("pq oracle committee needs members".to_string());
        }
        if activated_at_height >= expires_at_height {
            return Err("pq oracle committee expiry must be after activation".to_string());
        }
        if quorum_weight_bps == 0 || quorum_weight_bps > 10_000 {
            return Err("pq oracle committee quorum bps out of range".to_string());
        }
        let member_root = pq_oracle_string_set_root("COMMITTEE-MEMBER", member_ids);
        let feed_scope_root = pq_oracle_string_set_root("COMMITTEE-FEED-SCOPE", feed_ids);
        let committee_id = pq_oracle_committee_id(epoch, &member_root, &feed_scope_root);
        let committee = Self {
            committee_id,
            epoch,
            status: PqOracleFeedStatus::Active,
            member_ids: member_ids.to_vec(),
            member_root,
            quorum_weight_bps,
            feed_scope_root,
            activated_at_height,
            expires_at_height,
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.committee_id.trim().is_empty() || self.member_root.trim().is_empty() {
            return Err("pq oracle committee identifiers cannot be empty".to_string());
        }
        if self.member_ids.is_empty() {
            return Err("pq oracle committee needs members".to_string());
        }
        if self.quorum_weight_bps == 0 || self.quorum_weight_bps > 10_000 {
            return Err("pq oracle committee quorum bps out of range".to_string());
        }
        if self.activated_at_height >= self.expires_at_height {
            return Err("pq oracle committee expiry must be after activation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_committee",
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "member_root": self.member_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "feed_scope_root": self.feed_scope_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleFeedUpdate {
    pub update_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub status: PqOracleUpdateStatus,
    pub median_value_commitment: String,
    pub confidence_interval_root: String,
    pub source_bundle_root: String,
    pub privacy_proof_root: String,
    pub low_fee_lane: bool,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub accepted_at_height: Option<u64>,
}

impl PqOracleFeedUpdate {
    pub fn new(
        feed_id: &str,
        committee_id: &str,
        median_units: u64,
        confidence_bps: u64,
        source_labels: &[String],
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if feed_id.trim().is_empty() || committee_id.trim().is_empty() {
            return Err("pq oracle feed update identifiers cannot be empty".to_string());
        }
        if submitted_at_height >= expires_at_height {
            return Err("pq oracle update expiry must be after submission".to_string());
        }
        if confidence_bps > 10_000 {
            return Err("pq oracle update confidence bps out of range".to_string());
        }
        let median_value_commitment = pq_oracle_amount_commitment("UPDATE-MEDIAN", median_units);
        let confidence_interval_root = pq_oracle_payload_root(
            "UPDATE-CONFIDENCE",
            &json!({"confidence_bps": confidence_bps}),
        );
        let source_bundle_root = pq_oracle_string_set_root("UPDATE-SOURCES", source_labels);
        let privacy_proof_root = pq_oracle_payload_root(
            "UPDATE-PRIVACY-PROOF",
            &json!({
                "proof_system": PQ_ORACLE_ATTESTATION_MESH_PROOF_SYSTEM,
                "source_bundle_root": source_bundle_root,
                "feed_id": feed_id,
            }),
        );
        let update_id = pq_oracle_update_id(
            feed_id,
            committee_id,
            &median_value_commitment,
            submitted_at_height,
        );
        let update = Self {
            update_id,
            feed_id: feed_id.to_string(),
            committee_id: committee_id.to_string(),
            status: PqOracleUpdateStatus::Pending,
            median_value_commitment,
            confidence_interval_root,
            source_bundle_root,
            privacy_proof_root,
            low_fee_lane: false,
            submitted_at_height,
            expires_at_height,
            accepted_at_height: None,
        };
        update.validate()?;
        Ok(update)
    }

    pub fn with_low_fee_lane(mut self) -> Self {
        self.low_fee_lane = true;
        self
    }

    pub fn accept(&mut self, height: u64) -> PqOracleAttestationMeshResult<()> {
        if height < self.submitted_at_height {
            return Err("pq oracle update cannot accept before submission".to_string());
        }
        self.status = PqOracleUpdateStatus::Accepted;
        self.accepted_at_height = Some(height);
        Ok(())
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.update_id.trim().is_empty()
            || self.feed_id.trim().is_empty()
            || self.committee_id.trim().is_empty()
        {
            return Err("pq oracle update identifiers cannot be empty".to_string());
        }
        if self.median_value_commitment.trim().is_empty()
            || self.confidence_interval_root.trim().is_empty()
            || self.source_bundle_root.trim().is_empty()
            || self.privacy_proof_root.trim().is_empty()
        {
            return Err("pq oracle update roots cannot be empty".to_string());
        }
        if self.submitted_at_height >= self.expires_at_height {
            return Err("pq oracle update expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_feed_update",
            "update_id": self.update_id,
            "feed_id": self.feed_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "median_value_commitment": self.median_value_commitment,
            "confidence_interval_root": self.confidence_interval_root,
            "source_bundle_root": self.source_bundle_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_lane": self.low_fee_lane,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub update_id: String,
    pub member_id: String,
    pub status: PqOracleAttestationStatus,
    pub signature_root: String,
    pub transcript_root: String,
    pub weight_bps: u64,
    pub submitted_at_height: u64,
}

impl PqOracleAttestation {
    pub fn new(
        update_id: &str,
        member_id: &str,
        signature_label: &str,
        weight_bps: u64,
        submitted_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if update_id.trim().is_empty()
            || member_id.trim().is_empty()
            || signature_label.trim().is_empty()
        {
            return Err("pq oracle attestation identifiers cannot be empty".to_string());
        }
        if weight_bps == 0 || weight_bps > 10_000 {
            return Err("pq oracle attestation weight bps out of range".to_string());
        }
        let signature_root = pq_oracle_payload_root(
            "ATTESTATION-SIGNATURE",
            &json!({
                "scheme": PQ_ORACLE_ATTESTATION_MESH_PQ_SIGNATURE_SCHEME,
                "signature_label": signature_label,
            }),
        );
        let transcript_root = pq_oracle_payload_root(
            "ATTESTATION-TRANSCRIPT",
            &json!({
                "update_id": update_id,
                "member_id": member_id,
                "signature_root": signature_root,
            }),
        );
        let attestation_id =
            pq_oracle_attestation_id(update_id, member_id, &signature_root, submitted_at_height);
        let attestation = Self {
            attestation_id,
            update_id: update_id.to_string(),
            member_id: member_id.to_string(),
            status: PqOracleAttestationStatus::Submitted,
            signature_root,
            transcript_root,
            weight_bps,
            submitted_at_height,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn counted(mut self) -> Self {
        self.status = PqOracleAttestationStatus::Counted;
        self
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.attestation_id.trim().is_empty()
            || self.update_id.trim().is_empty()
            || self.member_id.trim().is_empty()
        {
            return Err("pq oracle attestation identifiers cannot be empty".to_string());
        }
        if self.signature_root.trim().is_empty() || self.transcript_root.trim().is_empty() {
            return Err("pq oracle attestation roots cannot be empty".to_string());
        }
        if self.weight_bps == 0 || self.weight_bps > 10_000 {
            return Err("pq oracle attestation weight bps out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_attestation",
            "attestation_id": self.attestation_id,
            "update_id": self.update_id,
            "member_id": self.member_id,
            "status": self.status.as_str(),
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "weight_bps": self.weight_bps,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleChallenge {
    pub challenge_id: String,
    pub update_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: PqOracleChallengeKind,
    pub status: PqOracleChallengeStatus,
    pub evidence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PqOracleChallenge {
    pub fn new(
        update_id: &str,
        challenger_label: &str,
        challenge_kind: PqOracleChallengeKind,
        evidence: &Value,
        bond_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if update_id.trim().is_empty() || challenger_label.trim().is_empty() {
            return Err("pq oracle challenge identifiers cannot be empty".to_string());
        }
        if opened_at_height >= expires_at_height {
            return Err("pq oracle challenge expiry must be after open".to_string());
        }
        if bond_units == 0 {
            return Err("pq oracle challenge bond must be positive".to_string());
        }
        let challenger_commitment = pq_oracle_string_root("CHALLENGER", challenger_label);
        let evidence_root = pq_oracle_payload_root("CHALLENGE-EVIDENCE", evidence);
        let bond_commitment = pq_oracle_amount_commitment("CHALLENGE-BOND", bond_units);
        let challenge_id = pq_oracle_challenge_id(
            update_id,
            &challenger_commitment,
            &challenge_kind,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            update_id: update_id.to_string(),
            challenger_commitment,
            challenge_kind,
            status: PqOracleChallengeStatus::Open,
            evidence_root,
            bond_commitment,
            opened_at_height,
            expires_at_height,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.challenge_id.trim().is_empty()
            || self.update_id.trim().is_empty()
            || self.challenger_commitment.trim().is_empty()
        {
            return Err("pq oracle challenge identifiers cannot be empty".to_string());
        }
        if self.evidence_root.trim().is_empty() || self.bond_commitment.trim().is_empty() {
            return Err("pq oracle challenge roots cannot be empty".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("pq oracle challenge expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_challenge",
            "challenge_id": self.challenge_id,
            "update_id": self.update_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleLowFeeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: PqOracleSponsorStatus,
    pub available_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub feed_allowlist_root: String,
    pub policy_root: String,
}

impl PqOracleLowFeeSponsor {
    pub fn new(
        sponsor_label: &str,
        available_units: u64,
        feed_ids: &[String],
        policy: &Value,
    ) -> PqOracleAttestationMeshResult<Self> {
        if sponsor_label.trim().is_empty() {
            return Err("pq oracle sponsor label cannot be empty".to_string());
        }
        if available_units == 0 {
            return Err("pq oracle sponsor budget must be positive".to_string());
        }
        let sponsor_commitment = pq_oracle_string_root("SPONSOR", sponsor_label);
        let feed_allowlist_root = pq_oracle_string_set_root("SPONSOR-FEED", feed_ids);
        let policy_root = pq_oracle_payload_root("SPONSOR-POLICY", policy);
        let sponsor_id =
            pq_oracle_sponsor_id(&sponsor_commitment, &feed_allowlist_root, &policy_root);
        let sponsor = Self {
            sponsor_id,
            sponsor_commitment,
            status: PqOracleSponsorStatus::Active,
            available_units,
            reserved_units: 0,
            spent_units: 0,
            feed_allowlist_root,
            policy_root,
        };
        sponsor.validate()?;
        Ok(sponsor)
    }

    pub fn reserve(&mut self, units: u64) -> PqOracleAttestationMeshResult<()> {
        if units == 0 {
            return Err("pq oracle sponsor reserve must be positive".to_string());
        }
        if self.available_units < units {
            return Err("pq oracle sponsor insufficient available units".to_string());
        }
        self.available_units = self.available_units.saturating_sub(units);
        self.reserved_units = self.reserved_units.saturating_add(units);
        if self.available_units == 0 {
            self.status = PqOracleSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn settle(&mut self, units: u64) -> PqOracleAttestationMeshResult<()> {
        if units == 0 {
            return Err("pq oracle sponsor settlement must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("pq oracle sponsor settlement exceeds reserve".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.sponsor_id.trim().is_empty() || self.sponsor_commitment.trim().is_empty() {
            return Err("pq oracle sponsor identifiers cannot be empty".to_string());
        }
        if self.feed_allowlist_root.trim().is_empty() || self.policy_root.trim().is_empty() {
            return Err("pq oracle sponsor roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_low_fee_sponsor",
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "feed_allowlist_root": self.feed_allowlist_root,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOraclePrivacyReceipt {
    pub receipt_id: String,
    pub update_id: String,
    pub feed_id: String,
    pub receipt_status: PqOracleReceiptStatus,
    pub disclosed_field_root: String,
    pub retained_secret_root: String,
    pub sponsor_debit_root: String,
    pub posted_at_height: u64,
}

impl PqOraclePrivacyReceipt {
    pub fn new(
        update_id: &str,
        feed_id: &str,
        disclosed_fields: &[String],
        retained_secret_label: &str,
        sponsor_ids: &[String],
        posted_at_height: u64,
    ) -> PqOracleAttestationMeshResult<Self> {
        if update_id.trim().is_empty()
            || feed_id.trim().is_empty()
            || retained_secret_label.trim().is_empty()
        {
            return Err("pq oracle privacy receipt identifiers cannot be empty".to_string());
        }
        let disclosed_field_root = pq_oracle_string_set_root("RECEIPT-DISCLOSED", disclosed_fields);
        let retained_secret_root = pq_oracle_string_root("RECEIPT-SECRET", retained_secret_label);
        let sponsor_debit_root = pq_oracle_string_set_root("RECEIPT-SPONSORS", sponsor_ids);
        let receipt_id = pq_oracle_privacy_receipt_id(
            update_id,
            feed_id,
            &disclosed_field_root,
            posted_at_height,
        );
        let receipt = Self {
            receipt_id,
            update_id: update_id.to_string(),
            feed_id: feed_id.to_string(),
            receipt_status: PqOracleReceiptStatus::Posted,
            disclosed_field_root,
            retained_secret_root,
            sponsor_debit_root,
            posted_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.update_id.trim().is_empty()
            || self.feed_id.trim().is_empty()
        {
            return Err("pq oracle privacy receipt identifiers cannot be empty".to_string());
        }
        if self.disclosed_field_root.trim().is_empty()
            || self.retained_secret_root.trim().is_empty()
            || self.sponsor_debit_root.trim().is_empty()
        {
            return Err("pq oracle privacy receipt roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_privacy_receipt",
            "receipt_id": self.receipt_id,
            "update_id": self.update_id,
            "feed_id": self.feed_id,
            "receipt_status": self.receipt_status.as_str(),
            "disclosed_field_root": self.disclosed_field_root,
            "retained_secret_root": self.retained_secret_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleMeshEvent {
    pub event_id: String,
    pub event_kind: PqOracleEventKind,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl PqOracleMeshEvent {
    pub fn new(
        event_kind: PqOracleEventKind,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> PqOracleAttestationMeshResult<Self> {
        if subject_id.trim().is_empty() {
            return Err("pq oracle mesh event subject cannot be empty".to_string());
        }
        let payload_root = pq_oracle_payload_root("EVENT-PAYLOAD", payload);
        let event_id = pq_oracle_event_id(&event_kind, subject_id, height, &payload_root);
        let event = Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        if self.event_id.trim().is_empty()
            || self.subject_id.trim().is_empty()
            || self.payload_root.trim().is_empty()
        {
            return Err("pq oracle mesh event identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_mesh_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestationMeshRoots {
    pub feed_root: String,
    pub member_root: String,
    pub committee_root: String,
    pub update_root: String,
    pub attestation_root: String,
    pub challenge_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
    pub event_root: String,
}

impl PqOracleAttestationMeshRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_attestation_mesh_roots",
            "feed_root": self.feed_root,
            "member_root": self.member_root,
            "committee_root": self.committee_root,
            "update_root": self.update_root,
            "attestation_root": self.attestation_root,
            "challenge_root": self.challenge_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestationMeshCounters {
    pub feed_count: u64,
    pub active_feed_count: u64,
    pub active_member_count: u64,
    pub active_committee_count: u64,
    pub pending_update_count: u64,
    pub accepted_update_count: u64,
    pub counted_attestation_count: u64,
    pub open_challenge_count: u64,
    pub active_sponsor_count: u64,
    pub receipt_count: u64,
    pub event_count: u64,
    pub available_sponsor_units: u64,
}

impl PqOracleAttestationMeshCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_attestation_mesh_counters",
            "feed_count": self.feed_count,
            "active_feed_count": self.active_feed_count,
            "active_member_count": self.active_member_count,
            "active_committee_count": self.active_committee_count,
            "pending_update_count": self.pending_update_count,
            "accepted_update_count": self.accepted_update_count,
            "counted_attestation_count": self.counted_attestation_count,
            "open_challenge_count": self.open_challenge_count,
            "active_sponsor_count": self.active_sponsor_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
            "available_sponsor_units": self.available_sponsor_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestationMeshState {
    pub config: PqOracleAttestationMeshConfig,
    pub height: u64,
    pub active_committee_id: Option<String>,
    pub feeds: BTreeMap<String, PqOracleFeed>,
    pub members: BTreeMap<String, PqOracleCommitteeMember>,
    pub committees: BTreeMap<String, PqOracleCommittee>,
    pub updates: BTreeMap<String, PqOracleFeedUpdate>,
    pub attestations: BTreeMap<String, PqOracleAttestation>,
    pub challenges: BTreeMap<String, PqOracleChallenge>,
    pub sponsors: BTreeMap<String, PqOracleLowFeeSponsor>,
    pub receipts: BTreeMap<String, PqOraclePrivacyReceipt>,
    pub events: BTreeMap<String, PqOracleMeshEvent>,
}

impl Default for PqOracleAttestationMeshState {
    fn default() -> Self {
        Self {
            config: PqOracleAttestationMeshConfig::default(),
            height: 0,
            active_committee_id: None,
            feeds: BTreeMap::new(),
            members: BTreeMap::new(),
            committees: BTreeMap::new(),
            updates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            challenges: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl PqOracleAttestationMeshState {
    pub fn new(config: PqOracleAttestationMeshConfig) -> PqOracleAttestationMeshResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> PqOracleAttestationMeshResult<Self> {
        let mut state = Self::new(PqOracleAttestationMeshConfig::default())?;
        state.height = 1;

        let xmr_feed = PqOracleFeed::new(
            "devnet-xmr-usd",
            PqOracleFeedKind::XmrUsd,
            "XMR",
            "USD",
            8,
            state.height,
            &json!({"deviation_bps": 350, "uses": ["bridge", "fees", "stablecoin"]}),
        )?
        .with_update_windows(1, state.config.stale_feed_blocks);
        let xmr_feed_id = xmr_feed.feed_id.clone();
        state.insert_feed(xmr_feed)?;

        let proof_fee_feed = PqOracleFeed::new(
            "devnet-proof-fee",
            PqOracleFeedKind::ProofFee,
            "proof-work",
            "piconero",
            0,
            state.height,
            &json!({"deviation_bps": 600, "uses": ["proof-market", "low-fee-sponsor"]}),
        )?;
        let proof_fee_feed_id = proof_fee_feed.feed_id.clone();
        state.insert_feed(proof_fee_feed)?;

        let mut member_ids = Vec::new();
        for (label, role, weight) in [
            (
                "devnet-oracle-publisher-1",
                PqOracleCommitteeRole::Publisher,
                2_500u64,
            ),
            (
                "devnet-oracle-publisher-2",
                PqOracleCommitteeRole::Publisher,
                2_500u64,
            ),
            (
                "devnet-oracle-aggregator",
                PqOracleCommitteeRole::Aggregator,
                3_000u64,
            ),
            (
                "devnet-oracle-watchtower",
                PqOracleCommitteeRole::Watchtower,
                2_000u64,
            ),
        ] {
            let member = PqOracleCommitteeMember::new(
                label,
                role,
                weight,
                &format!("inproc://{label}"),
                100_000,
                state.height,
            )?;
            member_ids.push(member.member_id.clone());
            state.insert_member(member)?;
        }

        let feed_ids = vec![xmr_feed_id.clone(), proof_fee_feed_id.clone()];
        let committee = PqOracleCommittee::new(
            1,
            &member_ids,
            &feed_ids,
            state.config.min_quorum_weight_bps,
            state.height,
            state
                .height
                .saturating_add(state.config.epoch_length_blocks),
        )?;
        let committee_id = committee.committee_id.clone();
        state.active_committee_id = Some(committee_id.clone());
        state.insert_committee(committee)?;

        let sponsor = PqOracleLowFeeSponsor::new(
            "devnet-oracle-low-fee-sponsor",
            state.config.low_fee_update_budget_units,
            &feed_ids,
            &json!({"mode": "devnet", "max_per_update": 500}),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor(sponsor)?;

        let update = PqOracleFeedUpdate::new(
            &xmr_feed_id,
            &committee_id,
            17_500_000_000,
            9_800,
            &[
                "publisher-a".to_string(),
                "publisher-b".to_string(),
                "aggregator-median".to_string(),
            ],
            state.height,
            state.height.saturating_add(state.config.update_ttl_blocks),
        )?
        .with_low_fee_lane();
        let update_id = update.update_id.clone();
        state.insert_update(update)?;

        for (member_id, weight) in member_ids.iter().zip([2_500u64, 2_500, 3_000, 2_000]) {
            let attestation = PqOracleAttestation::new(
                &update_id,
                member_id,
                &format!("sig-{member_id}"),
                weight,
                state.height.saturating_add(1),
            )?
            .counted();
            state.insert_attestation(attestation)?;
        }
        state.accept_update_if_quorum(&update_id)?;

        let receipt = PqOraclePrivacyReceipt::new(
            &update_id,
            &xmr_feed_id,
            &[
                "median_value_commitment".to_string(),
                "confidence_interval_root".to_string(),
            ],
            "source-observations-hidden",
            &[sponsor_id.clone()],
            state.height.saturating_add(2),
        )?;
        state.insert_receipt(receipt)?;

        state.insert_event(PqOracleMeshEvent::new(
            PqOracleEventKind::FeedRegistered,
            &xmr_feed_id,
            state.height,
            &json!({"source": "devnet"}),
        )?)?;
        state.insert_event(PqOracleMeshEvent::new(
            PqOracleEventKind::UpdateAccepted,
            &update_id,
            state.height.saturating_add(2),
            &json!({"committee_id": committee_id}),
        )?)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqOracleAttestationMeshResult<()> {
        self.height = height;
        self.expire_records();
        Ok(())
    }

    pub fn insert_feed(&mut self, feed: PqOracleFeed) -> PqOracleAttestationMeshResult<()> {
        if self.feeds.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_FEEDS
            && !self.feeds.contains_key(&feed.feed_id)
        {
            return Err("pq oracle mesh feed limit exceeded".to_string());
        }
        feed.validate()?;
        self.feeds.insert(feed.feed_id.clone(), feed);
        Ok(())
    }

    pub fn insert_member(
        &mut self,
        member: PqOracleCommitteeMember,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.members.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_MEMBERS
            && !self.members.contains_key(&member.member_id)
        {
            return Err("pq oracle mesh member limit exceeded".to_string());
        }
        member.validate()?;
        self.members.insert(member.member_id.clone(), member);
        Ok(())
    }

    pub fn insert_committee(
        &mut self,
        committee: PqOracleCommittee,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.committees.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_COMMITTEES
            && !self.committees.contains_key(&committee.committee_id)
        {
            return Err("pq oracle mesh committee limit exceeded".to_string());
        }
        for member_id in &committee.member_ids {
            if !self.members.contains_key(member_id) {
                return Err("pq oracle mesh committee references unknown member".to_string());
            }
        }
        committee.validate()?;
        self.committees
            .insert(committee.committee_id.clone(), committee);
        Ok(())
    }

    pub fn insert_update(
        &mut self,
        update: PqOracleFeedUpdate,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.updates.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_UPDATES
            && !self.updates.contains_key(&update.update_id)
        {
            return Err("pq oracle mesh update limit exceeded".to_string());
        }
        let feed = self
            .feeds
            .get(&update.feed_id)
            .ok_or_else(|| "pq oracle mesh update references unknown feed".to_string())?;
        if !feed.status.accepts_updates() {
            return Err("pq oracle mesh feed is not accepting updates".to_string());
        }
        if !self.committees.contains_key(&update.committee_id) {
            return Err("pq oracle mesh update references unknown committee".to_string());
        }
        update.validate()?;
        self.updates.insert(update.update_id.clone(), update);
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqOracleAttestation,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.attestations.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_ATTESTATIONS
            && !self.attestations.contains_key(&attestation.attestation_id)
        {
            return Err("pq oracle mesh attestation limit exceeded".to_string());
        }
        if !self.updates.contains_key(&attestation.update_id) {
            return Err("pq oracle mesh attestation references unknown update".to_string());
        }
        if !self.members.contains_key(&attestation.member_id) {
            return Err("pq oracle mesh attestation references unknown member".to_string());
        }
        let duplicate = self.attestations.values().any(|existing| {
            existing.update_id == attestation.update_id
                && existing.member_id == attestation.member_id
                && existing.attestation_id != attestation.attestation_id
        });
        if duplicate {
            return Err("pq oracle mesh duplicate member attestation".to_string());
        }
        attestation.validate()?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: PqOracleChallenge,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.challenges.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_CHALLENGES
            && !self.challenges.contains_key(&challenge.challenge_id)
        {
            return Err("pq oracle mesh challenge limit exceeded".to_string());
        }
        if !self.updates.contains_key(&challenge.update_id) {
            return Err("pq oracle mesh challenge references unknown update".to_string());
        }
        challenge.validate()?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: PqOracleLowFeeSponsor,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.sponsors.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_SPONSORS
            && !self.sponsors.contains_key(&sponsor.sponsor_id)
        {
            return Err("pq oracle mesh sponsor limit exceeded".to_string());
        }
        sponsor.validate()?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: PqOraclePrivacyReceipt,
    ) -> PqOracleAttestationMeshResult<()> {
        if self.receipts.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_RECEIPTS
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("pq oracle mesh receipt limit exceeded".to_string());
        }
        if !self.updates.contains_key(&receipt.update_id) {
            return Err("pq oracle mesh receipt references unknown update".to_string());
        }
        if !self.feeds.contains_key(&receipt.feed_id) {
            return Err("pq oracle mesh receipt references unknown feed".to_string());
        }
        receipt.validate()?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_event(&mut self, event: PqOracleMeshEvent) -> PqOracleAttestationMeshResult<()> {
        if self.events.len() >= PQ_ORACLE_ATTESTATION_MESH_MAX_EVENTS
            && !self.events.contains_key(&event.event_id)
        {
            return Err("pq oracle mesh event limit exceeded".to_string());
        }
        event.validate()?;
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn accept_update_if_quorum(
        &mut self,
        update_id: &str,
    ) -> PqOracleAttestationMeshResult<()> {
        let update = self
            .updates
            .get(update_id)
            .ok_or_else(|| "pq oracle mesh update missing for quorum".to_string())?
            .clone();
        let committee = self
            .committees
            .get(&update.committee_id)
            .ok_or_else(|| "pq oracle mesh committee missing for quorum".to_string())?;
        let counted_weight = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.update_id == update_id
                    && attestation.status == PqOracleAttestationStatus::Counted
            })
            .map(|attestation| attestation.weight_bps)
            .fold(0u64, u64::saturating_add);
        if counted_weight < committee.quorum_weight_bps {
            return Err("pq oracle mesh update lacks quorum".to_string());
        }
        let update = self
            .updates
            .get_mut(update_id)
            .ok_or_else(|| "pq oracle mesh update missing after quorum".to_string())?;
        update.accept(self.height)?;
        Ok(())
    }

    pub fn active_feed_ids(&self) -> Vec<String> {
        self.feeds
            .values()
            .filter(|feed| feed.status == PqOracleFeedStatus::Active)
            .map(|feed| feed.feed_id.clone())
            .collect()
    }

    pub fn active_committee_ids(&self) -> Vec<String> {
        self.committees
            .values()
            .filter(|committee| committee.status == PqOracleFeedStatus::Active)
            .map(|committee| committee.committee_id.clone())
            .collect()
    }

    pub fn pending_update_ids(&self) -> Vec<String> {
        self.updates
            .values()
            .filter(|update| {
                matches!(
                    update.status,
                    PqOracleUpdateStatus::Pending | PqOracleUpdateStatus::Attested
                )
            })
            .map(|update| update.update_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| {
                matches!(
                    challenge.status,
                    PqOracleChallengeStatus::Open | PqOracleChallengeStatus::EvidenceSubmitted
                )
            })
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn available_sponsor_units(&self) -> u64 {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.status == PqOracleSponsorStatus::Active)
            .map(|sponsor| sponsor.available_units)
            .fold(0u64, u64::saturating_add)
    }

    pub fn roots(&self) -> PqOracleAttestationMeshRoots {
        PqOracleAttestationMeshRoots {
            feed_root: pq_oracle_record_root(
                "FEEDS",
                &self
                    .feeds
                    .values()
                    .map(PqOracleFeed::public_record)
                    .collect::<Vec<_>>(),
            ),
            member_root: pq_oracle_record_root(
                "MEMBERS",
                &self
                    .members
                    .values()
                    .map(PqOracleCommitteeMember::public_record)
                    .collect::<Vec<_>>(),
            ),
            committee_root: pq_oracle_record_root(
                "COMMITTEES",
                &self
                    .committees
                    .values()
                    .map(PqOracleCommittee::public_record)
                    .collect::<Vec<_>>(),
            ),
            update_root: pq_oracle_record_root(
                "UPDATES",
                &self
                    .updates
                    .values()
                    .map(PqOracleFeedUpdate::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root: pq_oracle_record_root(
                "ATTESTATIONS",
                &self
                    .attestations
                    .values()
                    .map(PqOracleAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: pq_oracle_record_root(
                "CHALLENGES",
                &self
                    .challenges
                    .values()
                    .map(PqOracleChallenge::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_root: pq_oracle_record_root(
                "SPONSORS",
                &self
                    .sponsors
                    .values()
                    .map(PqOracleLowFeeSponsor::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: pq_oracle_record_root(
                "RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(PqOraclePrivacyReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_root: pq_oracle_record_root(
                "EVENTS",
                &self
                    .events
                    .values()
                    .map(PqOracleMeshEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PqOracleAttestationMeshCounters {
        PqOracleAttestationMeshCounters {
            feed_count: self.feeds.len() as u64,
            active_feed_count: self.active_feed_ids().len() as u64,
            active_member_count: self
                .members
                .values()
                .filter(|member| member.status == PqOracleMemberStatus::Active)
                .count() as u64,
            active_committee_count: self.active_committee_ids().len() as u64,
            pending_update_count: self.pending_update_ids().len() as u64,
            accepted_update_count: self
                .updates
                .values()
                .filter(|update| update.status == PqOracleUpdateStatus::Accepted)
                .count() as u64,
            counted_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status == PqOracleAttestationStatus::Counted)
                .count() as u64,
            open_challenge_count: self.open_challenge_ids().len() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status == PqOracleSponsorStatus::Active)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            event_count: self.events.len() as u64,
            available_sponsor_units: self.available_sponsor_units(),
        }
    }

    pub fn validate(&self) -> PqOracleAttestationMeshResult<()> {
        self.config.validate()?;
        for feed in self.feeds.values() {
            feed.validate()?;
        }
        for member in self.members.values() {
            member.validate()?;
        }
        for committee in self.committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.members.contains_key(member_id) {
                    return Err("pq oracle mesh committee references missing member".to_string());
                }
            }
        }
        for update in self.updates.values() {
            update.validate()?;
            if !self.feeds.contains_key(&update.feed_id) {
                return Err("pq oracle mesh update references missing feed".to_string());
            }
            if !self.committees.contains_key(&update.committee_id) {
                return Err("pq oracle mesh update references missing committee".to_string());
            }
        }
        let mut attestation_pairs = BTreeSet::new();
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.updates.contains_key(&attestation.update_id)
                || !self.members.contains_key(&attestation.member_id)
            {
                return Err("pq oracle mesh attestation references missing state".to_string());
            }
            let pair = format!("{}:{}", attestation.update_id, attestation.member_id);
            if !attestation_pairs.insert(pair) {
                return Err("pq oracle mesh duplicate attestation pair".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.updates.contains_key(&challenge.update_id) {
                return Err("pq oracle mesh challenge references missing update".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.updates.contains_key(&receipt.update_id)
                || !self.feeds.contains_key(&receipt.feed_id)
            {
                return Err("pq oracle mesh receipt references missing state".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_oracle_attestation_mesh_state",
            "config": self.config.public_record(),
            "height": self.height,
            "active_committee_id": self.active_committee_id,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_feed_ids": self.active_feed_ids(),
            "active_committee_ids": self.active_committee_ids(),
            "pending_update_ids": self.pending_update_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_oracle_attestation_mesh_state_root_from_record(&self.public_record())
    }

    fn expire_records(&mut self) {
        for update in self.updates.values_mut() {
            if self.height >= update.expires_at_height
                && matches!(
                    update.status,
                    PqOracleUpdateStatus::Pending | PqOracleUpdateStatus::Attested
                )
            {
                update.status = PqOracleUpdateStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if self.height >= challenge.expires_at_height
                && matches!(
                    challenge.status,
                    PqOracleChallengeStatus::Open | PqOracleChallengeStatus::EvidenceSubmitted
                )
            {
                challenge.status = PqOracleChallengeStatus::Expired;
            }
        }
        for committee in self.committees.values_mut() {
            if self.height >= committee.expires_at_height {
                committee.status = PqOracleFeedStatus::Retired;
            }
        }
    }
}

pub fn pq_oracle_attestation_mesh_state_root_from_record(record: &Value) -> String {
    pq_oracle_payload_root("STATE", record)
}

pub fn pq_oracle_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PQ-ORACLE-ATTESTATION-MESH-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn pq_oracle_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PQ-ORACLE-ATTESTATION-MESH-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn pq_oracle_string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    domain_hash(
        &format!("PQ-ORACLE-ATTESTATION-MESH-{domain}"),
        &sorted
            .iter()
            .map(|value| HashPart::Str(value))
            .collect::<Vec<_>>(),
        32,
    )
}

pub fn pq_oracle_amount_commitment(domain: &str, units: u64) -> String {
    domain_hash(
        &format!("PQ-ORACLE-ATTESTATION-MESH-{domain}"),
        &[HashPart::Int(units as i128)],
        32,
    )
}

pub fn pq_oracle_feed_id(
    label: &str,
    feed_kind: &PqOracleFeedKind,
    base_asset_commitment: &str,
    quote_asset_commitment: &str,
) -> String {
    domain_hash(
        "PQ-ORACLE-FEED-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(feed_kind.as_str()),
            HashPart::Str(base_asset_commitment),
            HashPart::Str(quote_asset_commitment),
        ],
        32,
    )
}

pub fn pq_oracle_member_id(
    label: &str,
    role: &PqOracleCommitteeRole,
    pq_public_key_commitment: &str,
    joined_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-MEMBER-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(role.as_str()),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Int(joined_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_committee_id(epoch: u64, member_root: &str, feed_scope_root: &str) -> String {
    domain_hash(
        "PQ-ORACLE-COMMITTEE-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Str(member_root),
            HashPart::Str(feed_scope_root),
        ],
        32,
    )
}

pub fn pq_oracle_update_id(
    feed_id: &str,
    committee_id: &str,
    median_value_commitment: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-UPDATE-ID",
        &[
            HashPart::Str(feed_id),
            HashPart::Str(committee_id),
            HashPart::Str(median_value_commitment),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_attestation_id(
    update_id: &str,
    member_id: &str,
    signature_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(update_id),
            HashPart::Str(member_id),
            HashPart::Str(signature_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_challenge_id(
    update_id: &str,
    challenger_commitment: &str,
    challenge_kind: &PqOracleChallengeKind,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-CHALLENGE-ID",
        &[
            HashPart::Str(update_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_sponsor_id(
    sponsor_commitment: &str,
    feed_allowlist_root: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "PQ-ORACLE-SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(feed_allowlist_root),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn pq_oracle_privacy_receipt_id(
    update_id: &str,
    feed_id: &str,
    disclosed_field_root: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-PRIVACY-RECEIPT-ID",
        &[
            HashPart::Str(update_id),
            HashPart::Str(feed_id),
            HashPart::Str(disclosed_field_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_event_id(
    event_kind: &PqOracleEventKind,
    subject_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "PQ-ORACLE-EVENT-ID",
        &[
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn pq_oracle_record_root(domain: &str, records: &[Value]) -> String {
    let mut roots = records
        .iter()
        .map(|record| pq_oracle_payload_root("RECORD", record))
        .collect::<Vec<_>>();
    roots.sort();
    pq_oracle_string_set_root(domain, &roots)
}
