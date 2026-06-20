use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateZkAppchainBridgeSchedulerResult<T> = Result<T, String>;

pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-private-zk-appchain-bridge-scheduler-v1";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-committee-v1";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+HPKE-XChaCha20Poly1305-appchain-message-v1";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROOF_SUITE: &str =
    "recursive-plonk-fri-confidential-appchain-bridge-v1";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_RELEASE_SUITE: &str =
    "delayed-release-threshold-decryption-v1";
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEVNET_HEIGHT: u64 = 4_096;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_MAX_RECORDS: usize = 16_384;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_FINALITY_BLOCKS: u64 = 8;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_FAST_WINDOW_MS: u64 = 550;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_CHALLENGE_BLOCKS: u64 = 96;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 24;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_MESSAGES_PER_LANE: usize = 512;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_JOBS_PER_LANE: usize = 128;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_RELEASE_BATCH_ITEMS: usize = 256;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_SPONSOR_BUDGET_MICRO_XMR: u64 = 250_000;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_COMMITTEE_STAKE: u64 = 1_000_000;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_PRIVACY_SET: u64 = 64;
pub const PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_SLASH_BPS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppchainLaneKind {
    ConfidentialContracts,
    PrivateDefi,
    BridgeDeposits,
    BridgeWithdrawals,
    OracleUpdates,
    Governance,
    EmergencyChallenge,
    Maintenance,
}

impl AppchainLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialContracts => "confidential_contracts",
            Self::PrivateDefi => "private_defi",
            Self::BridgeDeposits => "bridge_deposits",
            Self::BridgeWithdrawals => "bridge_withdrawals",
            Self::OracleUpdates => "oracle_updates",
            Self::Governance => "governance",
            Self::EmergencyChallenge => "emergency_challenge",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyChallenge => 10_000,
            Self::BridgeWithdrawals => 9_200,
            Self::BridgeDeposits => 8_800,
            Self::PrivateDefi => 8_400,
            Self::ConfidentialContracts => 7_900,
            Self::OracleUpdates => 7_000,
            Self::Governance => 5_500,
            Self::Maintenance => 3_000,
        }
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::ConfidentialContracts | Self::PrivateDefi | Self::Maintenance
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Paused,
    Draining,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_messages(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    Queued,
    Sponsored,
    Sequenced,
    Proving,
    Aggregated,
    FinalityPending,
    ReleaseQueued,
    Released,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl MessageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Sequenced => "sequenced",
            Self::Proving => "proving",
            Self::Aggregated => "aggregated",
            Self::FinalityPending => "finality_pending",
            Self::ReleaseQueued => "release_queued",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Sponsored
                | Self::Sequenced
                | Self::Proving
                | Self::Aggregated
                | Self::FinalityPending
                | Self::ReleaseQueued
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Exhausted,
    Paused,
    Quarantined,
    Closed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Closed => "closed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLaneKind {
    FastFinality,
    DefiSettlement,
    ContractExecution,
    BridgeAccounting,
    ReleaseEligibility,
    ChallengeReplay,
}

impl ProofLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastFinality => "fast_finality",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractExecution => "contract_execution",
            Self::BridgeAccounting => "bridge_accounting",
            Self::ReleaseEligibility => "release_eligibility",
            Self::ChallengeReplay => "challenge_replay",
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            Self::FastFinality => 450,
            Self::DefiSettlement => 800,
            Self::ContractExecution => 950,
            Self::BridgeAccounting => 1_100,
            Self::ReleaseEligibility => 1_400,
            Self::ChallengeReplay => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    WitnessLocked,
    Proving,
    Proved,
    Aggregating,
    Aggregated,
    Attested,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WitnessLocked => "witness_locked",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Aggregating => "aggregating",
            Self::Aggregated => "aggregated",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::WitnessLocked
                | Self::Proving
                | Self::Proved
                | Self::Aggregating
                | Self::Aggregated
                | Self::Attested
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityWindowStatus {
    Open,
    Preconfirmed,
    Proven,
    Final,
    Challenged,
    Reorged,
    Expired,
}

impl FinalityWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Preconfirmed => "preconfirmed",
            Self::Proven => "proven",
            Self::Final => "final",
            Self::Challenged => "challenged",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBatchStatus {
    Building,
    Sealed,
    DelayActive,
    Ready,
    Released,
    Challenged,
    Slashed,
    Cancelled,
}

impl ReleaseBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Sealed => "sealed",
            Self::DelayActive => "delay_active",
            Self::Ready => "ready",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Quarantined,
    Revoked,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    pub fn trusted(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidPqSignature,
    ConflictingFinalityVote,
    WithheldDecryptionShare,
    InvalidProofAggregate,
    CensoredMessage,
    SponsorMisaccounting,
    PrematureRelease,
    ReplayNonce,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::ConflictingFinalityVote => "conflicting_finality_vote",
            Self::WithheldDecryptionShare => "withheld_decryption_share",
            Self::InvalidProofAggregate => "invalid_proof_aggregate",
            Self::CensoredMessage => "censored_message",
            Self::SponsorMisaccounting => "sponsor_misaccounting",
            Self::PrematureRelease => "premature_release",
            Self::ReplayNonce => "replay_nonce",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    UnderReview,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub encryption_suite: String,
    pub proof_suite: String,
    pub release_suite: String,
    pub max_records: usize,
    pub max_lanes: usize,
    pub max_messages_per_lane: usize,
    pub max_jobs_per_lane: usize,
    pub max_release_batch_items: usize,
    pub finality_blocks: u64,
    pub fast_window_ms: u64,
    pub challenge_blocks: u64,
    pub release_delay_blocks: u64,
    pub default_sponsor_budget_micro_xmr: u64,
    pub min_committee_stake_micro_xmr: u64,
    pub min_privacy_set_size: u64,
    pub default_slash_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_fee_micro_xmr: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_SCHEMA_VERSION,
            hash_suite: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_HASH_SUITE.to_string(),
            pq_attestation_suite: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PQ_ATTESTATION_SUITE
                .to_string(),
            encryption_suite: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_ENCRYPTION_SUITE.to_string(),
            proof_suite: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROOF_SUITE.to_string(),
            release_suite: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_RELEASE_SUITE.to_string(),
            max_records: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_MAX_RECORDS,
            max_lanes: 64,
            max_messages_per_lane:
                PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_MESSAGES_PER_LANE,
            max_jobs_per_lane: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_JOBS_PER_LANE,
            max_release_batch_items:
                PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MAX_RELEASE_BATCH_ITEMS,
            finality_blocks: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_FINALITY_BLOCKS,
            fast_window_ms: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_FAST_WINDOW_MS,
            challenge_blocks: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_CHALLENGE_BLOCKS,
            release_delay_blocks: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_RELEASE_DELAY_BLOCKS,
            default_sponsor_budget_micro_xmr:
                PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            min_committee_stake_micro_xmr:
                PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_COMMITTEE_STAKE,
            min_privacy_set_size: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_PRIVACY_SET,
            default_slash_bps: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_SLASH_BPS,
            low_fee_rebate_bps: 8_500,
            max_fee_micro_xmr: 20_000,
        }
    }

    pub fn validate(&self) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "config.chain_id")?;
        ensure_not_empty(&self.protocol_version, "protocol_version")?;
        ensure_not_empty(&self.hash_suite, "hash_suite")?;
        ensure_not_empty(&self.pq_attestation_suite, "pq_attestation_suite")?;
        ensure_not_empty(&self.encryption_suite, "encryption_suite")?;
        ensure_not_empty(&self.proof_suite, "proof_suite")?;
        ensure_not_empty(&self.release_suite, "release_suite")?;
        ensure_nonzero(self.schema_version, "schema_version")?;
        ensure_nonzero(self.max_records as u64, "max_records")?;
        ensure_nonzero(self.max_lanes as u64, "max_lanes")?;
        ensure_nonzero(self.max_messages_per_lane as u64, "max_messages_per_lane")?;
        ensure_nonzero(self.max_jobs_per_lane as u64, "max_jobs_per_lane")?;
        ensure_nonzero(
            self.max_release_batch_items as u64,
            "max_release_batch_items",
        )?;
        ensure_nonzero(self.finality_blocks, "finality_blocks")?;
        ensure_nonzero(self.fast_window_ms, "fast_window_ms")?;
        ensure_nonzero(self.challenge_blocks, "challenge_blocks")?;
        ensure_nonzero(self.release_delay_blocks, "release_delay_blocks")?;
        ensure_nonzero(
            self.default_sponsor_budget_micro_xmr,
            "default_sponsor_budget_micro_xmr",
        )?;
        ensure_nonzero(
            self.min_committee_stake_micro_xmr,
            "min_committee_stake_micro_xmr",
        )?;
        ensure_nonzero(self.min_privacy_set_size, "min_privacy_set_size")?;
        ensure_bps(self.default_slash_bps, "default_slash_bps")?;
        ensure_bps(self.low_fee_rebate_bps, "low_fee_rebate_bps")?;
        ensure_nonzero(self.max_fee_micro_xmr, "max_fee_micro_xmr")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "encryption_suite": self.encryption_suite,
            "proof_suite": self.proof_suite,
            "release_suite": self.release_suite,
            "max_records": self.max_records,
            "max_lanes": self.max_lanes,
            "max_messages_per_lane": self.max_messages_per_lane,
            "max_jobs_per_lane": self.max_jobs_per_lane,
            "max_release_batch_items": self.max_release_batch_items,
            "finality_blocks": self.finality_blocks,
            "fast_window_ms": self.fast_window_ms,
            "challenge_blocks": self.challenge_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "default_sponsor_budget_micro_xmr": self.default_sponsor_budget_micro_xmr,
            "min_committee_stake_micro_xmr": self.min_committee_stake_micro_xmr,
            "min_privacy_set_size": self.min_privacy_set_size,
            "default_slash_bps": self.default_slash_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_fee_micro_xmr": self.max_fee_micro_xmr,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub lanes: u64,
    pub committee_members: u64,
    pub messages: u64,
    pub sponsors: u64,
    pub sponsorships: u64,
    pub proof_jobs: u64,
    pub finality_windows: u64,
    pub release_batches: u64,
    pub pq_attestations: u64,
    pub evidences: u64,
    pub released_messages: u64,
    pub challenged_messages: u64,
    pub slashed_committee_members: u64,
    pub sponsored_fee_micro_xmr: u64,
    pub burned_fee_micro_xmr: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "committee_members": self.committee_members,
            "messages": self.messages,
            "sponsors": self.sponsors,
            "sponsorships": self.sponsorships,
            "proof_jobs": self.proof_jobs,
            "finality_windows": self.finality_windows,
            "release_batches": self.release_batches,
            "pq_attestations": self.pq_attestations,
            "evidences": self.evidences,
            "released_messages": self.released_messages,
            "challenged_messages": self.challenged_messages,
            "slashed_committee_members": self.slashed_committee_members,
            "sponsored_fee_micro_xmr": self.sponsored_fee_micro_xmr,
            "burned_fee_micro_xmr": self.burned_fee_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub committee_root: String,
    pub message_root: String,
    pub sponsor_root: String,
    pub sponsorship_root: String,
    pub proof_job_root: String,
    pub finality_window_root: String,
    pub release_batch_root: String,
    pub pq_attestation_root: String,
    pub evidence_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "committee_root": self.committee_root,
            "message_root": self.message_root,
            "sponsor_root": self.sponsor_root,
            "sponsorship_root": self.sponsorship_root,
            "proof_job_root": self.proof_job_root,
            "finality_window_root": self.finality_window_root,
            "release_batch_root": self.release_batch_root,
            "pq_attestation_root": self.pq_attestation_root,
            "evidence_root": self.evidence_root,
            "nullifier_root": self.nullifier_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppchainLane {
    pub lane_id: String,
    pub appchain_id: String,
    pub kind: AppchainLaneKind,
    pub status: LaneStatus,
    pub committee_id: String,
    pub route_policy_id: String,
    pub encrypted_mempool_root: String,
    pub current_message_count: u64,
    pub pending_fee_micro_xmr: u64,
    pub priority_weight: u64,
    pub max_message_bytes: u64,
    pub min_privacy_set_size: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl AppchainLane {
    pub fn new(
        appchain_id: &str,
        kind: AppchainLaneKind,
        committee_id: &str,
        route_policy_id: &str,
        max_message_bytes: u64,
        min_privacy_set_size: u64,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(appchain_id, "appchain_id")?;
        ensure_not_empty(committee_id, "committee_id")?;
        ensure_not_empty(route_policy_id, "route_policy_id")?;
        ensure_nonzero(max_message_bytes, "max_message_bytes")?;
        ensure_nonzero(min_privacy_set_size, "min_privacy_set_size")?;
        let id_payload = json!({
            "appchain_id": appchain_id,
            "kind": kind.as_str(),
            "committee_id": committee_id,
            "route_policy_id": route_policy_id,
            "height": height,
        });
        let lane_id = id_hash("PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-LANE-ID", &id_payload);
        Ok(Self {
            lane_id,
            appchain_id: appchain_id.to_string(),
            kind,
            status: LaneStatus::Active,
            committee_id: committee_id.to_string(),
            route_policy_id: route_policy_id.to_string(),
            encrypted_mempool_root: merkle_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-LANE-EMPTY-MEMPOOL",
                &[],
            ),
            current_message_count: 0,
            pending_fee_micro_xmr: 0,
            priority_weight: kind.priority_weight(),
            max_message_bytes,
            min_privacy_set_size,
            created_height: height,
            updated_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "appchain_id": self.appchain_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "route_policy_id": self.route_policy_id,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "current_message_count": self.current_message_count,
            "pending_fee_micro_xmr": self.pending_fee_micro_xmr,
            "priority_weight": self.priority_weight,
            "max_message_bytes": self.max_message_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeCommitteeMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_id: String,
    pub pq_public_key_commitment: String,
    pub decryption_share_commitment: String,
    pub stake_micro_xmr: u64,
    pub reputation_score: u64,
    pub slashed: bool,
    pub joined_height: u64,
    pub updated_height: u64,
}

impl BridgeCommitteeMember {
    pub fn new(
        committee_id: &str,
        operator_id: &str,
        pq_public_key_commitment: &str,
        decryption_share_commitment: &str,
        stake_micro_xmr: u64,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(committee_id, "committee_id")?;
        ensure_not_empty(operator_id, "operator_id")?;
        ensure_not_empty(pq_public_key_commitment, "pq_public_key_commitment")?;
        ensure_not_empty(decryption_share_commitment, "decryption_share_commitment")?;
        ensure_nonzero(stake_micro_xmr, "stake_micro_xmr")?;
        let id_payload = json!({
            "committee_id": committee_id,
            "operator_id": operator_id,
            "pq_public_key_commitment": pq_public_key_commitment,
            "height": height,
        });
        let member_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-COMMITTEE-MEMBER-ID",
            &id_payload,
        );
        Ok(Self {
            member_id,
            committee_id: committee_id.to_string(),
            operator_id: operator_id.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            decryption_share_commitment: decryption_share_commitment.to_string(),
            stake_micro_xmr,
            reputation_score: 10_000,
            slashed: false,
            joined_height: height,
            updated_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_id": self.operator_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "decryption_share_commitment": self.decryption_share_commitment,
            "stake_micro_xmr": self.stake_micro_xmr,
            "reputation_score": self.reputation_score,
            "slashed": self.slashed,
            "joined_height": self.joined_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBridgeMessage {
    pub message_id: String,
    pub lane_id: String,
    pub appchain_id: String,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub encrypted_payload_commitment: String,
    pub ciphertext_root: String,
    pub nonce_nullifier: String,
    pub fee_micro_xmr: u64,
    pub sponsored_fee_micro_xmr: u64,
    pub message_bytes: u64,
    pub priority_score: u64,
    pub status: MessageStatus,
    pub proof_job_id: Option<String>,
    pub release_batch_id: Option<String>,
    pub finality_window_id: Option<String>,
    pub queued_height: u64,
    pub updated_height: u64,
    pub expires_height: u64,
}

impl EncryptedBridgeMessage {
    pub fn new(
        lane: &AppchainLane,
        sender_commitment: &str,
        recipient_commitment: &str,
        encrypted_payload_commitment: &str,
        ciphertext_root: &str,
        nonce_nullifier: &str,
        fee_micro_xmr: u64,
        message_bytes: u64,
        height: u64,
        expires_height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(sender_commitment, "sender_commitment")?;
        ensure_not_empty(recipient_commitment, "recipient_commitment")?;
        ensure_not_empty(encrypted_payload_commitment, "encrypted_payload_commitment")?;
        ensure_not_empty(ciphertext_root, "ciphertext_root")?;
        ensure_not_empty(nonce_nullifier, "nonce_nullifier")?;
        ensure_nonzero(message_bytes, "message_bytes")?;
        ensure_monotonic(expires_height, height, "expires_height")?;
        if message_bytes > lane.max_message_bytes {
            return Err(format!(
                "message_bytes {message_bytes} exceeds lane max {}",
                lane.max_message_bytes
            ));
        }
        let id_payload = json!({
            "lane_id": lane.lane_id,
            "appchain_id": lane.appchain_id,
            "sender_commitment": sender_commitment,
            "recipient_commitment": recipient_commitment,
            "encrypted_payload_commitment": encrypted_payload_commitment,
            "ciphertext_root": ciphertext_root,
            "nonce_nullifier": nonce_nullifier,
            "height": height,
        });
        let message_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-ENCRYPTED-MESSAGE-ID",
            &id_payload,
        );
        Ok(Self {
            message_id,
            lane_id: lane.lane_id.clone(),
            appchain_id: lane.appchain_id.clone(),
            sender_commitment: sender_commitment.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            encrypted_payload_commitment: encrypted_payload_commitment.to_string(),
            ciphertext_root: ciphertext_root.to_string(),
            nonce_nullifier: nonce_nullifier.to_string(),
            fee_micro_xmr,
            sponsored_fee_micro_xmr: 0,
            message_bytes,
            priority_score: lane.priority_weight.saturating_add(fee_micro_xmr),
            status: MessageStatus::Queued,
            proof_job_id: None,
            release_batch_id: None,
            finality_window_id: None,
            queued_height: height,
            updated_height: height,
            expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "lane_id": self.lane_id,
            "appchain_id": self.appchain_id,
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "encrypted_payload_commitment": self.encrypted_payload_commitment,
            "ciphertext_root": self.ciphertext_root,
            "nonce_nullifier": self.nonce_nullifier,
            "fee_micro_xmr": self.fee_micro_xmr,
            "sponsored_fee_micro_xmr": self.sponsored_fee_micro_xmr,
            "message_bytes": self.message_bytes,
            "priority_score": self.priority_score,
            "status": self.status.as_str(),
            "proof_job_id": self.proof_job_id,
            "release_batch_id": self.release_batch_id,
            "finality_window_id": self.finality_window_id,
            "queued_height": self.queued_height,
            "updated_height": self.updated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSponsorAccount {
    pub sponsor_id: String,
    pub owner_commitment: String,
    pub route_policy_id: String,
    pub eligible_lane_kinds: BTreeSet<AppchainLaneKind>,
    pub budget_micro_xmr: u64,
    pub reserved_micro_xmr: u64,
    pub spent_micro_xmr: u64,
    pub max_fee_per_message_micro_xmr: u64,
    pub rebate_bps: u64,
    pub status: SponsorStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl RouteSponsorAccount {
    pub fn new(
        owner_commitment: &str,
        route_policy_id: &str,
        eligible_lane_kinds: BTreeSet<AppchainLaneKind>,
        budget_micro_xmr: u64,
        max_fee_per_message_micro_xmr: u64,
        rebate_bps: u64,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(owner_commitment, "owner_commitment")?;
        ensure_not_empty(route_policy_id, "route_policy_id")?;
        ensure_nonzero(budget_micro_xmr, "budget_micro_xmr")?;
        ensure_nonzero(
            max_fee_per_message_micro_xmr,
            "max_fee_per_message_micro_xmr",
        )?;
        ensure_bps(rebate_bps, "rebate_bps")?;
        if eligible_lane_kinds.is_empty() {
            return Err("eligible_lane_kinds must not be empty".to_string());
        }
        let kind_values = eligible_lane_kinds
            .iter()
            .map(|kind| Value::String(kind.as_str().to_string()))
            .collect::<Vec<_>>();
        let id_payload = json!({
            "owner_commitment": owner_commitment,
            "route_policy_id": route_policy_id,
            "eligible_lane_kinds": kind_values,
            "height": height,
        });
        let sponsor_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-ROUTE-SPONSOR-ID",
            &id_payload,
        );
        Ok(Self {
            sponsor_id,
            owner_commitment: owner_commitment.to_string(),
            route_policy_id: route_policy_id.to_string(),
            eligible_lane_kinds,
            budget_micro_xmr,
            reserved_micro_xmr: 0,
            spent_micro_xmr: 0,
            max_fee_per_message_micro_xmr,
            rebate_bps,
            status: SponsorStatus::Active,
            created_height: height,
            updated_height: height,
        })
    }

    pub fn available_micro_xmr(&self) -> u64 {
        self.budget_micro_xmr
            .saturating_sub(self.reserved_micro_xmr)
            .saturating_sub(self.spent_micro_xmr)
    }

    pub fn can_sponsor(&self, lane_kind: AppchainLaneKind, fee_micro_xmr: u64) -> bool {
        self.status.usable()
            && self.eligible_lane_kinds.contains(&lane_kind)
            && fee_micro_xmr <= self.max_fee_per_message_micro_xmr
            && self.available_micro_xmr() >= fee_micro_xmr
    }

    pub fn public_record(&self) -> Value {
        let lanes = self
            .eligible_lane_kinds
            .iter()
            .map(|kind| Value::String(kind.as_str().to_string()))
            .collect::<Vec<_>>();
        json!({
            "sponsor_id": self.sponsor_id,
            "owner_commitment": self.owner_commitment,
            "route_policy_id": self.route_policy_id,
            "eligible_lane_kinds": lanes,
            "budget_micro_xmr": self.budget_micro_xmr,
            "reserved_micro_xmr": self.reserved_micro_xmr,
            "spent_micro_xmr": self.spent_micro_xmr,
            "available_micro_xmr": self.available_micro_xmr(),
            "max_fee_per_message_micro_xmr": self.max_fee_per_message_micro_xmr,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub message_id: String,
    pub lane_id: String,
    pub reserved_fee_micro_xmr: u64,
    pub rebate_bps: u64,
    pub settlement_root: String,
    pub created_height: u64,
    pub settled_height: Option<u64>,
}

impl RouteSponsorship {
    pub fn new(
        sponsor: &RouteSponsorAccount,
        message: &EncryptedBridgeMessage,
        reserved_fee_micro_xmr: u64,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_nonzero(reserved_fee_micro_xmr, "reserved_fee_micro_xmr")?;
        let id_payload = json!({
            "sponsor_id": sponsor.sponsor_id,
            "message_id": message.message_id,
            "lane_id": message.lane_id,
            "reserved_fee_micro_xmr": reserved_fee_micro_xmr,
            "height": height,
        });
        let sponsorship_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-SPONSORSHIP-ID",
            &id_payload,
        );
        let settlement_payload = json!({
            "sponsorship_id": sponsorship_id,
            "sponsor_id": sponsor.sponsor_id,
            "message_id": message.message_id,
            "reserved_fee_micro_xmr": reserved_fee_micro_xmr,
        });
        Ok(Self {
            sponsorship_id,
            sponsor_id: sponsor.sponsor_id.clone(),
            message_id: message.message_id.clone(),
            lane_id: message.lane_id.clone(),
            reserved_fee_micro_xmr,
            rebate_bps: sponsor.rebate_bps,
            settlement_root: record_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-SPONSORSHIP-SETTLEMENT",
                &settlement_payload,
            ),
            created_height: height,
            settled_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "message_id": self.message_id,
            "lane_id": self.lane_id,
            "reserved_fee_micro_xmr": self.reserved_fee_micro_xmr,
            "rebate_bps": self.rebate_bps,
            "settlement_root": self.settlement_root,
            "created_height": self.created_height,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofAggregationJob {
    pub job_id: String,
    pub lane_id: String,
    pub proof_lane: ProofLaneKind,
    pub message_ids: Vec<String>,
    pub witness_root: String,
    pub recursive_input_root: String,
    pub aggregate_proof_root: String,
    pub public_input_root: String,
    pub prover_committee_id: String,
    pub target_latency_ms: u64,
    pub status: ProofJobStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub expires_height: u64,
}

impl ProofAggregationJob {
    pub fn new(
        lane_id: &str,
        proof_lane: ProofLaneKind,
        message_ids: Vec<String>,
        witness_root: &str,
        recursive_input_root: &str,
        prover_committee_id: &str,
        height: u64,
        expires_height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(lane_id, "lane_id")?;
        ensure_not_empty(witness_root, "witness_root")?;
        ensure_not_empty(recursive_input_root, "recursive_input_root")?;
        ensure_not_empty(prover_committee_id, "prover_committee_id")?;
        ensure_monotonic(expires_height, height, "expires_height")?;
        if message_ids.is_empty() {
            return Err("message_ids must not be empty".to_string());
        }
        let id_payload = json!({
            "lane_id": lane_id,
            "proof_lane": proof_lane.as_str(),
            "message_ids": message_ids.clone(),
            "witness_root": witness_root,
            "recursive_input_root": recursive_input_root,
            "prover_committee_id": prover_committee_id,
            "height": height,
        });
        let job_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PROOF-JOB-ID",
            &id_payload,
        );
        Ok(Self {
            job_id,
            lane_id: lane_id.to_string(),
            proof_lane,
            message_ids,
            witness_root: witness_root.to_string(),
            recursive_input_root: recursive_input_root.to_string(),
            aggregate_proof_root: merkle_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PROOF-JOB-EMPTY-AGGREGATE",
                &[],
            ),
            public_input_root: merkle_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PROOF-JOB-EMPTY-PUBLIC-INPUT",
                &[],
            ),
            prover_committee_id: prover_committee_id.to_string(),
            target_latency_ms: proof_lane.target_latency_ms(),
            status: ProofJobStatus::Queued,
            created_height: height,
            updated_height: height,
            expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "lane_id": self.lane_id,
            "proof_lane": self.proof_lane.as_str(),
            "message_ids": self.message_ids,
            "witness_root": self.witness_root,
            "recursive_input_root": self.recursive_input_root,
            "aggregate_proof_root": self.aggregate_proof_root,
            "public_input_root": self.public_input_root,
            "prover_committee_id": self.prover_committee_id,
            "target_latency_ms": self.target_latency_ms,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityWindow {
    pub window_id: String,
    pub lane_id: String,
    pub message_ids: Vec<String>,
    pub proof_job_id: String,
    pub preconfirm_root: String,
    pub finality_root: String,
    pub opens_height: u64,
    pub closes_height: u64,
    pub fast_window_ms: u64,
    pub status: FinalityWindowStatus,
    pub updated_height: u64,
}

impl FinalityWindow {
    pub fn new(
        lane_id: &str,
        message_ids: Vec<String>,
        proof_job_id: &str,
        preconfirm_root: &str,
        opens_height: u64,
        closes_height: u64,
        fast_window_ms: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(lane_id, "lane_id")?;
        ensure_not_empty(proof_job_id, "proof_job_id")?;
        ensure_not_empty(preconfirm_root, "preconfirm_root")?;
        ensure_nonzero(fast_window_ms, "fast_window_ms")?;
        ensure_monotonic(closes_height, opens_height, "closes_height")?;
        if message_ids.is_empty() {
            return Err("message_ids must not be empty".to_string());
        }
        let id_payload = json!({
            "lane_id": lane_id,
            "message_ids": message_ids.clone(),
            "proof_job_id": proof_job_id,
            "preconfirm_root": preconfirm_root,
            "opens_height": opens_height,
            "closes_height": closes_height,
        });
        let window_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-FINALITY-WINDOW-ID",
            &id_payload,
        );
        let finality_record = json!({
            "window_id": window_id,
            "lane_id": lane_id,
            "proof_job_id": proof_job_id,
            "preconfirm_root": preconfirm_root,
            "closes_height": closes_height,
        });
        Ok(Self {
            window_id,
            lane_id: lane_id.to_string(),
            message_ids,
            proof_job_id: proof_job_id.to_string(),
            preconfirm_root: preconfirm_root.to_string(),
            finality_root: record_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-FINALITY-ROOT",
                &finality_record,
            ),
            opens_height,
            closes_height,
            fast_window_ms,
            status: FinalityWindowStatus::Open,
            updated_height: opens_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "message_ids": self.message_ids,
            "proof_job_id": self.proof_job_id,
            "preconfirm_root": self.preconfirm_root,
            "finality_root": self.finality_root,
            "opens_height": self.opens_height,
            "closes_height": self.closes_height,
            "fast_window_ms": self.fast_window_ms,
            "status": self.status.as_str(),
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub message_ids: Vec<String>,
    pub delayed_release_root: String,
    pub threshold_decryption_root: String,
    pub release_commitment_root: String,
    pub earliest_release_height: u64,
    pub sealed_height: u64,
    pub released_height: Option<u64>,
    pub status: ReleaseBatchStatus,
}

impl ReleaseBatch {
    pub fn new(
        lane_id: &str,
        message_ids: Vec<String>,
        delayed_release_root: &str,
        threshold_decryption_root: &str,
        sealed_height: u64,
        earliest_release_height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(lane_id, "lane_id")?;
        ensure_not_empty(delayed_release_root, "delayed_release_root")?;
        ensure_not_empty(threshold_decryption_root, "threshold_decryption_root")?;
        ensure_monotonic(
            earliest_release_height,
            sealed_height,
            "earliest_release_height",
        )?;
        if message_ids.is_empty() {
            return Err("message_ids must not be empty".to_string());
        }
        let id_payload = json!({
            "lane_id": lane_id,
            "message_ids": message_ids.clone(),
            "delayed_release_root": delayed_release_root,
            "threshold_decryption_root": threshold_decryption_root,
            "sealed_height": sealed_height,
            "earliest_release_height": earliest_release_height,
        });
        let batch_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-RELEASE-BATCH-ID",
            &id_payload,
        );
        let release_payload = json!({
            "batch_id": batch_id,
            "lane_id": lane_id,
            "message_ids": message_ids.clone(),
            "delayed_release_root": delayed_release_root,
            "threshold_decryption_root": threshold_decryption_root,
        });
        Ok(Self {
            batch_id,
            lane_id: lane_id.to_string(),
            message_ids,
            delayed_release_root: delayed_release_root.to_string(),
            threshold_decryption_root: threshold_decryption_root.to_string(),
            release_commitment_root: record_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-RELEASE-COMMITMENT",
                &release_payload,
            ),
            earliest_release_height,
            sealed_height,
            released_height: None,
            status: ReleaseBatchStatus::Sealed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "message_ids": self.message_ids,
            "delayed_release_root": self.delayed_release_root,
            "threshold_decryption_root": self.threshold_decryption_root,
            "release_commitment_root": self.release_commitment_root,
            "earliest_release_height": self.earliest_release_height,
            "sealed_height": self.sealed_height,
            "released_height": self.released_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub target_id: String,
    pub target_kind: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub status: PqAttestationStatus,
    pub created_height: u64,
    pub verified_height: Option<u64>,
}

impl PqAttestation {
    pub fn new(
        committee_id: &str,
        member_id: &str,
        target_id: &str,
        target_kind: &str,
        signature_commitment: &str,
        transcript_root: &str,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(committee_id, "committee_id")?;
        ensure_not_empty(member_id, "member_id")?;
        ensure_not_empty(target_id, "target_id")?;
        ensure_not_empty(target_kind, "target_kind")?;
        ensure_not_empty(signature_commitment, "signature_commitment")?;
        ensure_not_empty(transcript_root, "transcript_root")?;
        let id_payload = json!({
            "committee_id": committee_id,
            "member_id": member_id,
            "target_id": target_id,
            "target_kind": target_kind,
            "signature_commitment": signature_commitment,
            "transcript_root": transcript_root,
            "height": height,
        });
        let attestation_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PQ-ATTESTATION-ID",
            &id_payload,
        );
        Ok(Self {
            attestation_id,
            committee_id: committee_id.to_string(),
            member_id: member_id.to_string(),
            target_id: target_id.to_string(),
            target_kind: target_kind.to_string(),
            signature_commitment: signature_commitment.to_string(),
            transcript_root: transcript_root.to_string(),
            status: PqAttestationStatus::Pending,
            created_height: height,
            verified_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "verified_height": self.verified_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub reporter_commitment: String,
    pub accused_member_id: Option<String>,
    pub target_id: String,
    pub target_kind: String,
    pub evidence_root: String,
    pub slashing_root: String,
    pub bond_micro_xmr: u64,
    pub slash_bps: u64,
    pub status: EvidenceStatus,
    pub submitted_height: u64,
    pub resolved_height: Option<u64>,
}

impl ChallengeEvidence {
    pub fn new(
        kind: EvidenceKind,
        reporter_commitment: &str,
        accused_member_id: Option<String>,
        target_id: &str,
        target_kind: &str,
        evidence_root: &str,
        bond_micro_xmr: u64,
        slash_bps: u64,
        height: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        ensure_not_empty(reporter_commitment, "reporter_commitment")?;
        ensure_not_empty(target_id, "target_id")?;
        ensure_not_empty(target_kind, "target_kind")?;
        ensure_not_empty(evidence_root, "evidence_root")?;
        ensure_nonzero(bond_micro_xmr, "bond_micro_xmr")?;
        ensure_bps(slash_bps, "slash_bps")?;
        let id_payload = json!({
            "kind": kind.as_str(),
            "reporter_commitment": reporter_commitment,
            "accused_member_id": accused_member_id.clone(),
            "target_id": target_id,
            "target_kind": target_kind,
            "evidence_root": evidence_root,
            "height": height,
        });
        let evidence_id = id_hash(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-CHALLENGE-EVIDENCE-ID",
            &id_payload,
        );
        let slashing_payload = json!({
            "evidence_id": evidence_id,
            "kind": kind.as_str(),
            "target_id": target_id,
            "accused_member_id": accused_member_id.clone(),
            "slash_bps": slash_bps,
        });
        Ok(Self {
            evidence_id,
            kind,
            reporter_commitment: reporter_commitment.to_string(),
            accused_member_id,
            target_id: target_id.to_string(),
            target_kind: target_kind.to_string(),
            evidence_root: evidence_root.to_string(),
            slashing_root: record_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-SLASHING-ROOT",
                &slashing_payload,
            ),
            bond_micro_xmr,
            slash_bps,
            status: EvidenceStatus::Submitted,
            submitted_height: height,
            resolved_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "accused_member_id": self.accused_member_id,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "evidence_root": self.evidence_root,
            "slashing_root": self.slashing_root,
            "bond_micro_xmr": self.bond_micro_xmr,
            "slash_bps": self.slash_bps,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "resolved_height": self.resolved_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lanes: BTreeMap<String, AppchainLane>,
    pub committee_members: BTreeMap<String, BridgeCommitteeMember>,
    pub messages: BTreeMap<String, EncryptedBridgeMessage>,
    pub sponsors: BTreeMap<String, RouteSponsorAccount>,
    pub sponsorships: BTreeMap<String, RouteSponsorship>,
    pub proof_jobs: BTreeMap<String, ProofAggregationJob>,
    pub finality_windows: BTreeMap<String, FinalityWindow>,
    pub release_batches: BTreeMap<String, ReleaseBatch>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub evidences: BTreeMap<String, ChallengeEvidence>,
    pub nullifiers: BTreeSet<String>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateZkAppchainBridgeSchedulerResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            lanes: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            messages: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            release_batches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            evidences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            counters: Counters::default(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            height: PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            messages: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            release_batches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            evidences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            counters: Counters::default(),
        };
        let committee_id = "devnet-private-zk-appchain-bridge-committee";
        let _ = state.register_committee_member(
            committee_id,
            "devnet-bridge-operator-alpha",
            "pq-key-commitment-devnet-alpha",
            "decrypt-share-commitment-devnet-alpha",
            2_000_000,
        );
        let _ = state.register_committee_member(
            committee_id,
            "devnet-bridge-operator-beta",
            "pq-key-commitment-devnet-beta",
            "decrypt-share-commitment-devnet-beta",
            2_000_000,
        );
        let _ = state.register_committee_member(
            committee_id,
            "devnet-bridge-operator-gamma",
            "pq-key-commitment-devnet-gamma",
            "decrypt-share-commitment-devnet-gamma",
            2_000_000,
        );
        let _ = state.create_lane(
            "private-defi-devnet",
            AppchainLaneKind::PrivateDefi,
            committee_id,
            "low-fee-defi-route-policy-devnet",
            64_000,
            PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_PRIVACY_SET,
        );
        let _ = state.create_lane(
            "confidential-contracts-devnet",
            AppchainLaneKind::ConfidentialContracts,
            committee_id,
            "low-fee-contract-route-policy-devnet",
            96_000,
            PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_MIN_PRIVACY_SET,
        );
        let mut eligible = BTreeSet::new();
        let _ = eligible.insert(AppchainLaneKind::PrivateDefi);
        let _ = eligible.insert(AppchainLaneKind::ConfidentialContracts);
        let _ = state.create_sponsor(
            "devnet-sponsor-owner-commitment",
            "low-fee-defi-route-policy-devnet",
            eligible,
            PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            2_000,
            8_500,
        );
        state
    }

    pub fn update_height(&mut self, height: u64) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        ensure_monotonic(height, self.height, "height")?;
        self.height = height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        self.update_height(height)
    }

    pub fn create_lane(
        &mut self,
        appchain_id: &str,
        kind: AppchainLaneKind,
        committee_id: &str,
        route_policy_id: &str,
        max_message_bytes: u64,
        min_privacy_set_size: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        self.ensure_committee_has_quorum(committee_id)?;
        if min_privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "min_privacy_set_size {min_privacy_set_size} below config minimum {}",
                self.config.min_privacy_set_size
            ));
        }
        let lane = AppchainLane::new(
            appchain_id,
            kind,
            committee_id,
            route_policy_id,
            max_message_bytes,
            min_privacy_set_size,
            self.height,
        )?;
        let lane_id = lane.lane_id.clone();
        if self.lanes.contains_key(&lane_id) {
            return Err(format!("lane {lane_id} already exists"));
        }
        let _ = self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes = self.lanes.len() as u64;
        Ok(lane_id)
    }

    pub fn set_lane_status(
        &mut self,
        lane_id: &str,
        status: LaneStatus,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        lane.status = status;
        lane.updated_height = self.height;
        Ok(())
    }

    pub fn register_committee_member(
        &mut self,
        committee_id: &str,
        operator_id: &str,
        pq_public_key_commitment: &str,
        decryption_share_commitment: &str,
        stake_micro_xmr: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        if stake_micro_xmr < self.config.min_committee_stake_micro_xmr {
            return Err(format!(
                "stake_micro_xmr {stake_micro_xmr} below config minimum {}",
                self.config.min_committee_stake_micro_xmr
            ));
        }
        let member = BridgeCommitteeMember::new(
            committee_id,
            operator_id,
            pq_public_key_commitment,
            decryption_share_commitment,
            stake_micro_xmr,
            self.height,
        )?;
        let member_id = member.member_id.clone();
        if self.committee_members.contains_key(&member_id) {
            return Err(format!("committee member {member_id} already exists"));
        }
        let _ = self.committee_members.insert(member_id.clone(), member);
        self.counters.committee_members = self.committee_members.len() as u64;
        Ok(member_id)
    }

    pub fn submit_encrypted_message(
        &mut self,
        lane_id: &str,
        sender_commitment: &str,
        recipient_commitment: &str,
        encrypted_payload_commitment: &str,
        ciphertext_root: &str,
        nonce_nullifier: &str,
        fee_micro_xmr: u64,
        message_bytes: u64,
        ttl_blocks: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        ensure_nonzero(ttl_blocks, "ttl_blocks")?;
        if fee_micro_xmr > self.config.max_fee_micro_xmr {
            return Err(format!(
                "fee_micro_xmr {fee_micro_xmr} exceeds config max {}",
                self.config.max_fee_micro_xmr
            ));
        }
        if self.nullifiers.contains(nonce_nullifier) {
            return Err(format!("nonce_nullifier {nonce_nullifier} already used"));
        }
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        if !lane.status.accepts_messages() {
            return Err(format!("lane {lane_id} status does not accept messages"));
        }
        let lane_message_count = self
            .messages
            .values()
            .filter(|message| message.lane_id == lane_id && message.status.live())
            .count();
        self.ensure_capacity(
            lane_message_count,
            self.config.max_messages_per_lane,
            "messages per lane",
        )?;
        let expires_height = self.height.saturating_add(ttl_blocks);
        let message = EncryptedBridgeMessage::new(
            lane,
            sender_commitment,
            recipient_commitment,
            encrypted_payload_commitment,
            ciphertext_root,
            nonce_nullifier,
            fee_micro_xmr,
            message_bytes,
            self.height,
            expires_height,
        )?;
        let message_id = message.message_id.clone();
        if self.messages.contains_key(&message_id) {
            return Err(format!("message {message_id} already exists"));
        }
        let _ = self.nullifiers.insert(nonce_nullifier.to_string());
        let _ = self.messages.insert(message_id.clone(), message);
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.current_message_count = lane.current_message_count.saturating_add(1);
            lane.pending_fee_micro_xmr = lane.pending_fee_micro_xmr.saturating_add(fee_micro_xmr);
            lane.updated_height = self.height;
            let lane_messages = self
                .messages
                .values()
                .filter(|message| message.lane_id == lane_id && message.status.live())
                .map(EncryptedBridgeMessage::public_record)
                .collect::<Vec<_>>();
            lane.encrypted_mempool_root = merkle_root(
                "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-LANE-MEMPOOL",
                &lane_messages,
            );
        }
        self.counters.messages = self.messages.len() as u64;
        Ok(message_id)
    }

    pub fn create_sponsor(
        &mut self,
        owner_commitment: &str,
        route_policy_id: &str,
        eligible_lane_kinds: BTreeSet<AppchainLaneKind>,
        budget_micro_xmr: u64,
        max_fee_per_message_micro_xmr: u64,
        rebate_bps: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        let sponsor = RouteSponsorAccount::new(
            owner_commitment,
            route_policy_id,
            eligible_lane_kinds,
            budget_micro_xmr,
            max_fee_per_message_micro_xmr,
            rebate_bps,
            self.height,
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        if self.sponsors.contains_key(&sponsor_id) {
            return Err(format!("sponsor {sponsor_id} already exists"));
        }
        let _ = self.sponsors.insert(sponsor_id.clone(), sponsor);
        self.counters.sponsors = self.sponsors.len() as u64;
        Ok(sponsor_id)
    }

    pub fn sponsor_message(
        &mut self,
        sponsor_id: &str,
        message_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        let lane_kind = {
            let message = self
                .messages
                .get(message_id)
                .ok_or_else(|| format!("unknown message {message_id}"))?;
            let lane = self
                .lanes
                .get(&message.lane_id)
                .ok_or_else(|| format!("unknown lane {}", message.lane_id))?;
            lane.kind
        };
        let reserved_fee = {
            let message = self
                .messages
                .get(message_id)
                .ok_or_else(|| format!("unknown message {message_id}"))?;
            message.fee_micro_xmr
        };
        let sponsor = self
            .sponsors
            .get(sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {sponsor_id}"))?;
        if !sponsor.can_sponsor(lane_kind, reserved_fee) {
            return Err(format!(
                "sponsor {sponsor_id} cannot sponsor message {message_id}"
            ));
        }
        let message = self
            .messages
            .get(message_id)
            .ok_or_else(|| format!("unknown message {message_id}"))?
            .clone();
        let sponsor_snapshot = self
            .sponsors
            .get(sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {sponsor_id}"))?
            .clone();
        let sponsorship =
            RouteSponsorship::new(&sponsor_snapshot, &message, reserved_fee, self.height)?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        if self.sponsorships.contains_key(&sponsorship_id) {
            return Err(format!("sponsorship {sponsorship_id} already exists"));
        }
        let _ = self
            .sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        if let Some(sponsor) = self.sponsors.get_mut(sponsor_id) {
            sponsor.reserved_micro_xmr = sponsor.reserved_micro_xmr.saturating_add(reserved_fee);
            sponsor.updated_height = self.height;
            if sponsor.available_micro_xmr() == 0 {
                sponsor.status = SponsorStatus::Exhausted;
            }
        }
        if let Some(message) = self.messages.get_mut(message_id) {
            message.sponsored_fee_micro_xmr =
                message.sponsored_fee_micro_xmr.saturating_add(reserved_fee);
            message.status = MessageStatus::Sponsored;
            message.updated_height = self.height;
        }
        self.counters.sponsorships = self.sponsorships.len() as u64;
        self.counters.sponsored_fee_micro_xmr = self
            .counters
            .sponsored_fee_micro_xmr
            .saturating_add(reserved_fee);
        Ok(sponsorship_id)
    }

    pub fn create_proof_job(
        &mut self,
        lane_id: &str,
        proof_lane: ProofLaneKind,
        message_ids: Vec<String>,
        witness_root: &str,
        recursive_input_root: &str,
        prover_committee_id: &str,
        ttl_blocks: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        ensure_nonzero(ttl_blocks, "ttl_blocks")?;
        let active_jobs = self
            .proof_jobs
            .values()
            .filter(|job| job.lane_id == lane_id && job.status.live())
            .count();
        self.ensure_capacity(
            active_jobs,
            self.config.max_jobs_per_lane,
            "proof jobs per lane",
        )?;
        let _ = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        self.ensure_committee_has_quorum(prover_committee_id)?;
        for message_id in &message_ids {
            let message = self
                .messages
                .get(message_id)
                .ok_or_else(|| format!("unknown message {message_id}"))?;
            if message.lane_id != lane_id {
                return Err(format!(
                    "message {message_id} does not belong to lane {lane_id}"
                ));
            }
            if !message.status.live() {
                return Err(format!("message {message_id} is not live"));
            }
        }
        let expires_height = self.height.saturating_add(ttl_blocks);
        let job = ProofAggregationJob::new(
            lane_id,
            proof_lane,
            message_ids.clone(),
            witness_root,
            recursive_input_root,
            prover_committee_id,
            self.height,
            expires_height,
        )?;
        let job_id = job.job_id.clone();
        if self.proof_jobs.contains_key(&job_id) {
            return Err(format!("proof job {job_id} already exists"));
        }
        let _ = self.proof_jobs.insert(job_id.clone(), job);
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.proof_job_id = Some(job_id.clone());
                message.status = MessageStatus::Proving;
                message.updated_height = self.height;
            }
        }
        self.counters.proof_jobs = self.proof_jobs.len() as u64;
        Ok(job_id)
    }

    pub fn mark_proof_aggregated(
        &mut self,
        job_id: &str,
        aggregate_proof_root: &str,
        public_input_root: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        ensure_not_empty(aggregate_proof_root, "aggregate_proof_root")?;
        ensure_not_empty(public_input_root, "public_input_root")?;
        let message_ids = {
            let job = self
                .proof_jobs
                .get_mut(job_id)
                .ok_or_else(|| format!("unknown proof job {job_id}"))?;
            job.aggregate_proof_root = aggregate_proof_root.to_string();
            job.public_input_root = public_input_root.to_string();
            job.status = ProofJobStatus::Aggregated;
            job.updated_height = self.height;
            job.message_ids.clone()
        };
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.status = MessageStatus::Aggregated;
                message.updated_height = self.height;
            }
        }
        Ok(())
    }

    pub fn open_finality_window(
        &mut self,
        proof_job_id: &str,
        preconfirm_root: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        let job = self
            .proof_jobs
            .get(proof_job_id)
            .ok_or_else(|| format!("unknown proof job {proof_job_id}"))?;
        if job.status != ProofJobStatus::Aggregated && job.status != ProofJobStatus::Attested {
            return Err(format!("proof job {proof_job_id} is not aggregated"));
        }
        let closes_height = self.height.saturating_add(self.config.finality_blocks);
        let window = FinalityWindow::new(
            &job.lane_id,
            job.message_ids.clone(),
            proof_job_id,
            preconfirm_root,
            self.height,
            closes_height,
            self.config.fast_window_ms,
        )?;
        let window_id = window.window_id.clone();
        if self.finality_windows.contains_key(&window_id) {
            return Err(format!("finality window {window_id} already exists"));
        }
        let message_ids = window.message_ids.clone();
        let _ = self.finality_windows.insert(window_id.clone(), window);
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.finality_window_id = Some(window_id.clone());
                message.status = MessageStatus::FinalityPending;
                message.updated_height = self.height;
            }
        }
        self.counters.finality_windows = self.finality_windows.len() as u64;
        Ok(window_id)
    }

    pub fn close_finality_window(
        &mut self,
        window_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let message_ids = {
            let window = self
                .finality_windows
                .get_mut(window_id)
                .ok_or_else(|| format!("unknown finality window {window_id}"))?;
            if self.height < window.closes_height {
                return Err(format!(
                    "finality window {window_id} closes at height {}",
                    window.closes_height
                ));
            }
            window.status = FinalityWindowStatus::Final;
            window.updated_height = self.height;
            window.message_ids.clone()
        };
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.status = MessageStatus::ReleaseQueued;
                message.updated_height = self.height;
            }
        }
        Ok(())
    }

    pub fn seal_release_batch(
        &mut self,
        lane_id: &str,
        message_ids: Vec<String>,
        delayed_release_root: &str,
        threshold_decryption_root: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        if message_ids.len() > self.config.max_release_batch_items {
            return Err(format!(
                "release batch item count {} exceeds max {}",
                message_ids.len(),
                self.config.max_release_batch_items
            ));
        }
        let _ = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        for message_id in &message_ids {
            let message = self
                .messages
                .get(message_id)
                .ok_or_else(|| format!("unknown message {message_id}"))?;
            if message.lane_id != lane_id {
                return Err(format!(
                    "message {message_id} does not belong to lane {lane_id}"
                ));
            }
            if message.status != MessageStatus::ReleaseQueued {
                return Err(format!("message {message_id} is not release queued"));
            }
        }
        let earliest_release_height = self.height.saturating_add(self.config.release_delay_blocks);
        let batch = ReleaseBatch::new(
            lane_id,
            message_ids.clone(),
            delayed_release_root,
            threshold_decryption_root,
            self.height,
            earliest_release_height,
        )?;
        let batch_id = batch.batch_id.clone();
        if self.release_batches.contains_key(&batch_id) {
            return Err(format!("release batch {batch_id} already exists"));
        }
        let _ = self.release_batches.insert(batch_id.clone(), batch);
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.release_batch_id = Some(batch_id.clone());
                message.status = MessageStatus::ReleaseQueued;
                message.updated_height = self.height;
            }
        }
        self.counters.release_batches = self.release_batches.len() as u64;
        Ok(batch_id)
    }

    pub fn release_batch(&mut self, batch_id: &str) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let message_ids = {
            let batch = self
                .release_batches
                .get_mut(batch_id)
                .ok_or_else(|| format!("unknown release batch {batch_id}"))?;
            if self.height < batch.earliest_release_height {
                return Err(format!(
                    "release batch {batch_id} earliest release height is {}",
                    batch.earliest_release_height
                ));
            }
            batch.status = ReleaseBatchStatus::Released;
            batch.released_height = Some(self.height);
            batch.message_ids.clone()
        };
        for message_id in message_ids {
            if let Some(message) = self.messages.get_mut(&message_id) {
                message.status = MessageStatus::Released;
                message.updated_height = self.height;
                self.counters.released_messages = self.counters.released_messages.saturating_add(1);
            }
        }
        Ok(())
    }

    pub fn submit_pq_attestation(
        &mut self,
        committee_id: &str,
        member_id: &str,
        target_id: &str,
        target_kind: &str,
        signature_commitment: &str,
        transcript_root: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        let member = self
            .committee_members
            .get(member_id)
            .ok_or_else(|| format!("unknown committee member {member_id}"))?;
        if member.committee_id != committee_id {
            return Err(format!(
                "member {member_id} does not belong to {committee_id}"
            ));
        }
        if member.slashed {
            return Err(format!("member {member_id} is slashed"));
        }
        let attestation = PqAttestation::new(
            committee_id,
            member_id,
            target_id,
            target_kind,
            signature_commitment,
            transcript_root,
            self.height,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        if self.pq_attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let _ = self
            .pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        Ok(attestation_id)
    }

    pub fn verify_pq_attestation(
        &mut self,
        attestation_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let attestation = self
            .pq_attestations
            .get_mut(attestation_id)
            .ok_or_else(|| format!("unknown attestation {attestation_id}"))?;
        if attestation.status == PqAttestationStatus::Revoked {
            return Err(format!("attestation {attestation_id} is revoked"));
        }
        attestation.status = PqAttestationStatus::Verified;
        attestation.verified_height = Some(self.height);
        Ok(())
    }

    pub fn aggregate_attestations_for_target(
        &mut self,
        target_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        ensure_not_empty(target_id, "target_id")?;
        let mut count = 0_u64;
        let mut records = Vec::new();
        for attestation in self.pq_attestations.values_mut() {
            if attestation.target_id == target_id && attestation.status.trusted() {
                attestation.status = PqAttestationStatus::Aggregated;
                records.push(attestation.public_record());
                count = count.saturating_add(1);
            }
        }
        if count == 0 {
            return Err(format!("no trusted attestations for target {target_id}"));
        }
        Ok(merkle_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-AGGREGATED-ATTESTATIONS",
            &records,
        ))
    }

    pub fn submit_challenge_evidence(
        &mut self,
        kind: EvidenceKind,
        reporter_commitment: &str,
        accused_member_id: Option<String>,
        target_id: &str,
        target_kind: &str,
        evidence_root: &str,
        bond_micro_xmr: u64,
    ) -> PrivateZkAppchainBridgeSchedulerResult<String> {
        self.ensure_total_capacity()?;
        if let Some(member_id) = accused_member_id.as_ref() {
            let _ = self
                .committee_members
                .get(member_id)
                .ok_or_else(|| format!("unknown accused member {member_id}"))?;
        }
        let evidence = ChallengeEvidence::new(
            kind,
            reporter_commitment,
            accused_member_id,
            target_id,
            target_kind,
            evidence_root,
            bond_micro_xmr,
            self.config.default_slash_bps,
            self.height,
        )?;
        let evidence_id = evidence.evidence_id.clone();
        if self.evidences.contains_key(&evidence_id) {
            return Err(format!("evidence {evidence_id} already exists"));
        }
        let _ = self.evidences.insert(evidence_id.clone(), evidence);
        self.mark_target_challenged(target_id);
        self.counters.evidences = self.evidences.len() as u64;
        self.counters.challenged_messages = self.counters.challenged_messages.saturating_add(1);
        Ok(evidence_id)
    }

    pub fn accept_challenge_and_slash(
        &mut self,
        evidence_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let (accused_member_id, target_id) = {
            let evidence = self
                .evidences
                .get_mut(evidence_id)
                .ok_or_else(|| format!("unknown evidence {evidence_id}"))?;
            evidence.status = EvidenceStatus::Slashed;
            evidence.resolved_height = Some(self.height);
            (
                evidence.accused_member_id.clone(),
                evidence.target_id.clone(),
            )
        };
        if let Some(member_id) = accused_member_id {
            if let Some(member) = self.committee_members.get_mut(&member_id) {
                member.slashed = true;
                member.updated_height = self.height;
                member.reputation_score = member.reputation_score.saturating_sub(5_000);
                self.counters.slashed_committee_members =
                    self.counters.slashed_committee_members.saturating_add(1);
            }
        }
        self.mark_target_slashed(&target_id);
        Ok(())
    }

    pub fn reject_challenge(
        &mut self,
        evidence_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let evidence = self
            .evidences
            .get_mut(evidence_id)
            .ok_or_else(|| format!("unknown evidence {evidence_id}"))?;
        evidence.status = EvidenceStatus::Rejected;
        evidence.resolved_height = Some(self.height);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-CONFIG",
            &self.config.public_record(),
        );
        let lane_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-LANES",
            &self
                .lanes
                .values()
                .map(AppchainLane::public_record)
                .collect::<Vec<_>>(),
        );
        let committee_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-COMMITTEE",
            &self
                .committee_members
                .values()
                .map(BridgeCommitteeMember::public_record)
                .collect::<Vec<_>>(),
        );
        let message_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-MESSAGES",
            &self
                .messages
                .values()
                .map(EncryptedBridgeMessage::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-SPONSORS",
            &self
                .sponsors
                .values()
                .map(RouteSponsorAccount::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-SPONSORSHIPS",
            &self
                .sponsorships
                .values()
                .map(RouteSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        let proof_job_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PROOF-JOBS",
            &self
                .proof_jobs
                .values()
                .map(ProofAggregationJob::public_record)
                .collect::<Vec<_>>(),
        );
        let finality_window_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-FINALITY-WINDOWS",
            &self
                .finality_windows
                .values()
                .map(FinalityWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let release_batch_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-RELEASE-BATCHES",
            &self
                .release_batches
                .values()
                .map(ReleaseBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_attestation_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-PQ-ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let evidence_root = map_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-EVIDENCE",
            &self
                .evidences
                .values()
                .map(ChallengeEvidence::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_values = self
            .nullifiers
            .iter()
            .map(|nullifier| Value::String(nullifier.clone()))
            .collect::<Vec<_>>();
        let nullifier_root = merkle_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-NULLIFIERS",
            &nullifier_values,
        );
        let counters_root = record_root(
            "PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-COUNTERS",
            &self.counters.public_record(),
        );
        let state_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root.clone(),
            "lane_root": lane_root.clone(),
            "committee_root": committee_root.clone(),
            "message_root": message_root.clone(),
            "sponsor_root": sponsor_root.clone(),
            "sponsorship_root": sponsorship_root.clone(),
            "proof_job_root": proof_job_root.clone(),
            "finality_window_root": finality_window_root.clone(),
            "release_batch_root": release_batch_root.clone(),
            "pq_attestation_root": pq_attestation_root.clone(),
            "evidence_root": evidence_root.clone(),
            "nullifier_root": nullifier_root.clone(),
            "counters_root": counters_root.clone(),
        });
        let state_root = record_root("PRIVATE-ZK-APPCHAIN-BRIDGE-SCHEDULER-STATE", &state_record);
        Roots {
            config_root,
            lane_root,
            committee_root,
            message_root,
            sponsor_root,
            sponsorship_root,
            proof_job_root,
            finality_window_root,
            release_batch_root,
            pq_attestation_root,
            evidence_root,
            nullifier_root,
            counters_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters.public_record(),
            "lane_count": self.lanes.len(),
            "committee_member_count": self.committee_members.len(),
            "message_count": self.messages.len(),
            "sponsor_count": self.sponsors.len(),
            "proof_job_count": self.proof_jobs.len(),
            "release_batch_count": self.release_batches.len(),
            "evidence_count": self.evidences.len(),
        })
    }

    pub fn validate(&self) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        self.config.validate()?;
        let mut seen_nullifiers = BTreeSet::new();
        for lane in self.lanes.values() {
            ensure_not_empty(&lane.lane_id, "lane.lane_id")?;
            ensure_not_empty(&lane.appchain_id, "lane.appchain_id")?;
            ensure_not_empty(&lane.committee_id, "lane.committee_id")?;
            ensure_not_empty(&lane.route_policy_id, "lane.route_policy_id")?;
            ensure_nonzero(lane.max_message_bytes, "lane.max_message_bytes")?;
            ensure_nonzero(lane.min_privacy_set_size, "lane.min_privacy_set_size")?;
            ensure_monotonic(
                lane.updated_height,
                lane.created_height,
                "lane.updated_height",
            )?;
            self.ensure_committee_has_quorum(&lane.committee_id)?;
        }
        for member in self.committee_members.values() {
            ensure_not_empty(&member.member_id, "member.member_id")?;
            ensure_not_empty(&member.committee_id, "member.committee_id")?;
            ensure_not_empty(&member.operator_id, "member.operator_id")?;
            ensure_not_empty(
                &member.pq_public_key_commitment,
                "member.pq_public_key_commitment",
            )?;
            ensure_not_empty(
                &member.decryption_share_commitment,
                "member.decryption_share_commitment",
            )?;
            ensure_nonzero(member.stake_micro_xmr, "member.stake_micro_xmr")?;
            ensure_monotonic(
                member.updated_height,
                member.joined_height,
                "member.updated_height",
            )?;
        }
        for message in self.messages.values() {
            ensure_not_empty(&message.message_id, "message.message_id")?;
            ensure_not_empty(&message.lane_id, "message.lane_id")?;
            let _ = self
                .lanes
                .get(&message.lane_id)
                .ok_or_else(|| format!("message {} references unknown lane", message.message_id))?;
            ensure_not_empty(&message.nonce_nullifier, "message.nonce_nullifier")?;
            if !seen_nullifiers.insert(message.nonce_nullifier.clone()) {
                return Err(format!(
                    "duplicate message nonce_nullifier {}",
                    message.nonce_nullifier
                ));
            }
            ensure_monotonic(
                message.expires_height,
                message.queued_height,
                "message.expires_height",
            )?;
            ensure_monotonic(
                message.updated_height,
                message.queued_height,
                "message.updated_height",
            )?;
        }
        for sponsor in self.sponsors.values() {
            ensure_not_empty(&sponsor.sponsor_id, "sponsor.sponsor_id")?;
            ensure_not_empty(&sponsor.owner_commitment, "sponsor.owner_commitment")?;
            ensure_not_empty(&sponsor.route_policy_id, "sponsor.route_policy_id")?;
            ensure_nonzero(sponsor.budget_micro_xmr, "sponsor.budget_micro_xmr")?;
            ensure_nonzero(
                sponsor.max_fee_per_message_micro_xmr,
                "sponsor.max_fee_per_message_micro_xmr",
            )?;
            ensure_bps(sponsor.rebate_bps, "sponsor.rebate_bps")?;
        }
        for sponsorship in self.sponsorships.values() {
            let _ = self.sponsors.get(&sponsorship.sponsor_id).ok_or_else(|| {
                format!(
                    "sponsorship {} references unknown sponsor",
                    sponsorship.sponsorship_id
                )
            })?;
            let _ = self.messages.get(&sponsorship.message_id).ok_or_else(|| {
                format!(
                    "sponsorship {} references unknown message",
                    sponsorship.sponsorship_id
                )
            })?;
            ensure_nonzero(
                sponsorship.reserved_fee_micro_xmr,
                "sponsorship.reserved_fee_micro_xmr",
            )?;
        }
        for job in self.proof_jobs.values() {
            let _ = self
                .lanes
                .get(&job.lane_id)
                .ok_or_else(|| format!("job {} references unknown lane", job.job_id))?;
            ensure_not_empty(&job.witness_root, "job.witness_root")?;
            ensure_not_empty(&job.recursive_input_root, "job.recursive_input_root")?;
            ensure_monotonic(job.expires_height, job.created_height, "job.expires_height")?;
            for message_id in &job.message_ids {
                let _ = self.messages.get(message_id).ok_or_else(|| {
                    format!("job {} references unknown message {message_id}", job.job_id)
                })?;
            }
        }
        for window in self.finality_windows.values() {
            ensure_monotonic(
                window.closes_height,
                window.opens_height,
                "window.closes_height",
            )?;
            let _ = self.proof_jobs.get(&window.proof_job_id).ok_or_else(|| {
                format!(
                    "finality window {} references unknown proof job",
                    window.window_id
                )
            })?;
        }
        for batch in self.release_batches.values() {
            ensure_monotonic(
                batch.earliest_release_height,
                batch.sealed_height,
                "batch.earliest_release_height",
            )?;
            for message_id in &batch.message_ids {
                let _ = self.messages.get(message_id).ok_or_else(|| {
                    format!(
                        "release batch {} references unknown message {message_id}",
                        batch.batch_id
                    )
                })?;
            }
        }
        for attestation in self.pq_attestations.values() {
            let _ = self
                .committee_members
                .get(&attestation.member_id)
                .ok_or_else(|| {
                    format!(
                        "attestation {} references unknown member",
                        attestation.attestation_id
                    )
                })?;
            ensure_not_empty(&attestation.target_id, "attestation.target_id")?;
            ensure_not_empty(
                &attestation.signature_commitment,
                "attestation.signature_commitment",
            )?;
        }
        for evidence in self.evidences.values() {
            ensure_not_empty(&evidence.evidence_id, "evidence.evidence_id")?;
            ensure_not_empty(&evidence.target_id, "evidence.target_id")?;
            ensure_not_empty(&evidence.evidence_root, "evidence.evidence_root")?;
            ensure_bps(evidence.slash_bps, "evidence.slash_bps")?;
        }
        self.ensure_total_capacity()?;
        Ok(())
    }

    fn ensure_capacity(
        &self,
        current: usize,
        max: usize,
        label: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        if current >= max {
            return Err(format!("{label} capacity {max} reached"));
        }
        Ok(())
    }

    fn ensure_total_capacity(&self) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        let total = self.lanes.len()
            + self.committee_members.len()
            + self.messages.len()
            + self.sponsors.len()
            + self.sponsorships.len()
            + self.proof_jobs.len()
            + self.finality_windows.len()
            + self.release_batches.len()
            + self.pq_attestations.len()
            + self.evidences.len();
        self.ensure_capacity(total, self.config.max_records, "total records")
    }

    fn ensure_committee_has_quorum(
        &self,
        committee_id: &str,
    ) -> PrivateZkAppchainBridgeSchedulerResult<()> {
        ensure_not_empty(committee_id, "committee_id")?;
        let active_members = self
            .committee_members
            .values()
            .filter(|member| member.committee_id == committee_id && !member.slashed)
            .count();
        if active_members < 2 {
            return Err(format!(
                "committee {committee_id} needs at least two active members"
            ));
        }
        Ok(())
    }

    fn mark_target_challenged(&mut self, target_id: &str) {
        if let Some(message) = self.messages.get_mut(target_id) {
            message.status = MessageStatus::Challenged;
            message.updated_height = self.height;
        }
        if let Some(job) = self.proof_jobs.get_mut(target_id) {
            job.status = ProofJobStatus::Challenged;
            job.updated_height = self.height;
        }
        if let Some(window) = self.finality_windows.get_mut(target_id) {
            window.status = FinalityWindowStatus::Challenged;
            window.updated_height = self.height;
        }
        if let Some(batch) = self.release_batches.get_mut(target_id) {
            batch.status = ReleaseBatchStatus::Challenged;
        }
    }

    fn mark_target_slashed(&mut self, target_id: &str) {
        if let Some(message) = self.messages.get_mut(target_id) {
            message.status = MessageStatus::Slashed;
            message.updated_height = self.height;
        }
        if let Some(job) = self.proof_jobs.get_mut(target_id) {
            job.status = ProofJobStatus::Slashed;
            job.updated_height = self.height;
        }
        if let Some(batch) = self.release_batches.get_mut(target_id) {
            batch.status = ReleaseBatchStatus::Slashed;
        }
    }

    fn expire_stale_records(&mut self) {
        for message in self.messages.values_mut() {
            if message.status.live() && self.height > message.expires_height {
                message.status = MessageStatus::Expired;
                message.updated_height = self.height;
            }
        }
        for job in self.proof_jobs.values_mut() {
            if job.status.live() && self.height > job.expires_height {
                job.status = ProofJobStatus::Expired;
                job.updated_height = self.height;
            }
        }
        for window in self.finality_windows.values_mut() {
            if window.status == FinalityWindowStatus::Open && self.height > window.closes_height {
                window.status = FinalityWindowStatus::Expired;
                window.updated_height = self.height;
            }
        }
        for batch in self.release_batches.values_mut() {
            if batch.status == ReleaseBatchStatus::Sealed
                && self.height >= batch.earliest_release_height
            {
                batch.status = ReleaseBatchStatus::Ready;
            }
        }
        for evidence in self.evidences.values_mut() {
            if matches!(
                evidence.status,
                EvidenceStatus::Submitted | EvidenceStatus::UnderReview
            ) && self.height
                > evidence
                    .submitted_height
                    .saturating_add(self.config.challenge_blocks)
            {
                evidence.status = EvidenceStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    record_root(domain, record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn id_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn map_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn ensure_not_empty(value: &str, label: &str) -> PrivateZkAppchainBridgeSchedulerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_nonzero(value: u64, label: &str) -> PrivateZkAppchainBridgeSchedulerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateZkAppchainBridgeSchedulerResult<()> {
    if value > PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_MAX_BPS {
        return Err(format!(
            "{label} {value} exceeds {}",
            PRIVATE_ZK_APPCHAIN_BRIDGE_SCHEDULER_MAX_BPS
        ));
    }
    Ok(())
}

fn ensure_monotonic(
    next: u64,
    current: u64,
    label: &str,
) -> PrivateZkAppchainBridgeSchedulerResult<()> {
    if next < current {
        return Err(format!("{label} must be >= {current}, got {next}"));
    }
    Ok(())
}

fn ensure_eq(left: &str, right: &str, label: &str) -> PrivateZkAppchainBridgeSchedulerResult<()> {
    if left != right {
        return Err(format!("{label} mismatch: {left} != {right}"));
    }
    Ok(())
}
