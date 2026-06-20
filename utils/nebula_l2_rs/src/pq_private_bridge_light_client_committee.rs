use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqPrivateBridgeLightClientCommitteeResult<T> = Result<T, String>;

pub const PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION: &str =
    "nebula-pq-private-bridge-light-client-committee-v1";

const PROTOCOL_ID: &str = "pq-private-bridge-light-client-committee";
const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
const MONERO_HEADER_COMMITMENT_SUITE: &str = "monero-header-commitment-v2";
const PQ_AGGREGATE_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-aggregate";
const PQ_BACKUP_SIGNATURE_SUITE: &str = "SLH-DSA-SHAKE-256f";
const PQ_KEM_SUITE: &str = "ML-KEM-1024";
const PRIVACY_PROOF_RECEIPT_SUITE: &str = "private-proof-receipt-nullifier-redaction-v1";
const DA_WITNESS_SUITE: &str = "da-backed-witness-bundle-v1";
const ROTATION_SUITE: &str = "overlapping-pq-light-client-committee-rotation-v1";
const EMERGENCY_FALLBACK_SUITE: &str = "emergency-monero-bridge-light-client-fallback-v1";
const DEFAULT_HEIGHT: u64 = 24_576;
const DEFAULT_EPOCH_BLOCKS: u64 = 240;
const DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 48;
const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
const DEFAULT_HEADER_FINALITY_DEPTH: u64 = 20;
const DEFAULT_FAST_QUORUM_BPS: u64 = 8_000;
const DEFAULT_SAFE_QUORUM_BPS: u64 = 6_700;
const DEFAULT_PRIVACY_QUORUM_BPS: u64 = 7_500;
const DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 8_500;
const DEFAULT_MIN_SECURITY_BITS: u64 = 256;
const DEFAULT_MAX_HEADERS_PER_BUNDLE: u64 = 64;
const DEFAULT_MAX_RECEIPTS_PER_WINDOW: u64 = 256;
const DEFAULT_MAX_WITNESS_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_LOW_LATENCY_TARGET_MS: u64 = 1_200;
const DEFAULT_LOW_FEE_MICRO_UNITS: u64 = 4;
const DEFAULT_CHALLENGE_BOND_MICRO_UNITS: u64 = 500_000;
const DEFAULT_FALLBACK_DELAY_BLOCKS: u64 = 12;
const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    HeaderProver,
    BridgeValidator,
    PrivacyAuditor,
    DaWitness,
    ChallengeGuardian,
    RotationCoordinator,
    EmergencySigner,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderProver => "header_prover",
            Self::BridgeValidator => "bridge_validator",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::DaWitness => "da_witness",
            Self::ChallengeGuardian => "challenge_guardian",
            Self::RotationCoordinator => "rotation_coordinator",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Pending,
    Active,
    Warming,
    Overlap,
    Jailed,
    Retired,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Warming => "warming",
            Self::Overlap => "overlap",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::Warming | Self::Overlap)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderStatus {
    Observed,
    Committed,
    Aggregated,
    ChallengeOpen,
    Finalized,
    Reorged,
    Rejected,
}

impl HeaderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Committed => "committed",
            Self::Aggregated => "aggregated",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable_for_bridge(self) -> bool {
        matches!(
            self,
            Self::Aggregated | Self::ChallengeOpen | Self::Finalized
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Prepared,
    Released,
    Settled,
    Challenged,
    Revoked,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Released => "released",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Prepared | Self::Released | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Escalated,
    Resolved,
    Expired,
    Cancelled,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted | Self::Escalated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackStatus {
    Armed,
    Monitoring,
    Active,
    Recovering,
    Resolved,
    Disabled,
}

impl FallbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Monitoring => "monitoring",
            Self::Active => "active",
            Self::Recovering => "recovering",
            Self::Resolved => "resolved",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_id: String,
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub bridged_asset_id: String,
    pub committee_id: String,
    pub epoch_blocks: u64,
    pub rotation_overlap_blocks: u64,
    pub challenge_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub header_finality_depth: u64,
    pub fast_quorum_bps: u64,
    pub safe_quorum_bps: u64,
    pub privacy_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub min_security_bits: u64,
    pub max_headers_per_bundle: u64,
    pub max_receipts_per_window: u64,
    pub max_witness_bytes: u64,
    pub low_latency_target_ms: u64,
    pub low_fee_micro_units: u64,
    pub challenge_bond_micro_units: u64,
    pub fallback_delay_blocks: u64,
    pub hash_suite: String,
    pub monero_header_commitment_suite: String,
    pub pq_aggregate_signature_suite: String,
    pub pq_backup_signature_suite: String,
    pub pq_kem_suite: String,
    pub privacy_proof_receipt_suite: String,
    pub da_witness_suite: String,
    pub rotation_suite: String,
    pub emergency_fallback_suite: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub committee_root: String,
    pub active_committee_root: String,
    pub monero_header_root: String,
    pub header_commitment_root: String,
    pub pq_signature_root: String,
    pub aggregate_signature_root: String,
    pub quorum_certificate_root: String,
    pub rotation_root: String,
    pub private_receipt_root: String,
    pub privacy_nullifier_root: String,
    pub challenge_window_root: String,
    pub da_witness_bundle_root: String,
    pub fallback_root: String,
    pub bridge_event_root: String,
    pub low_fee_lane_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub committee_members: u64,
    pub active_committee_members: u64,
    pub jailed_committee_members: u64,
    pub retired_committee_members: u64,
    pub monero_headers: u64,
    pub usable_monero_headers: u64,
    pub header_commitments: u64,
    pub finalized_header_commitments: u64,
    pub pq_signatures: u64,
    pub accepted_pq_signatures: u64,
    pub aggregate_signatures: u64,
    pub quorum_certificates: u64,
    pub rotations: u64,
    pub active_rotations: u64,
    pub private_receipts: u64,
    pub live_private_receipts: u64,
    pub privacy_nullifiers: u64,
    pub challenge_windows: u64,
    pub open_challenge_windows: u64,
    pub da_witness_bundles: u64,
    pub available_witness_bundles: u64,
    pub fallback_events: u64,
    pub active_fallback_events: u64,
    pub bridge_events: u64,
    pub low_fee_lanes: u64,
    pub public_events: u64,
    pub total_committee_weight: u64,
    pub active_committee_weight: u64,
    pub total_attested_weight: u64,
    pub total_witness_bytes: u64,
    pub total_low_fee_micro_units: u64,
    pub total_challenge_bond_micro_units: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub committee_members: Vec<Value>,
    pub monero_headers: Vec<Value>,
    pub header_commitments: Vec<Value>,
    pub pq_signatures: Vec<Value>,
    pub aggregate_signatures: Vec<Value>,
    pub quorum_certificates: Vec<Value>,
    pub rotations: Vec<Value>,
    pub private_receipts: Vec<Value>,
    pub privacy_nullifiers: Vec<Value>,
    pub challenge_windows: Vec<Value>,
    pub da_witness_bundles: Vec<Value>,
    pub fallback_events: Vec<Value>,
    pub bridge_events: Vec<Value>,
    pub low_fee_lanes: Vec<Value>,
    pub public_events: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_id: String,
    pub role: CommitteeRole,
    pub status: CommitteeStatus,
    pub weight: u64,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub stake_commitment: String,
    pub latency_score: u64,
    pub privacy_score: u64,
    pub joined_at_height: u64,
    pub rotation_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroHeaderCommitment {
    pub header_id: String,
    pub network: String,
    pub height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub tx_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub difficulty_commitment: String,
    pub cumulative_work_commitment: String,
    pub timestamp_bucket: u64,
    pub finality_depth: u64,
    pub status: HeaderStatus,
    pub commitment_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSignatureShare {
    pub share_id: String,
    pub member_id: String,
    pub header_id: String,
    pub signed_root: String,
    pub signature_commitment: String,
    pub backup_signature_commitment: String,
    pub signed_at_height: u64,
    pub security_bits: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub aggregate_id: String,
    pub header_id: String,
    pub committee_epoch: u64,
    pub participant_root: String,
    pub aggregate_signature_commitment: String,
    pub backup_signature_commitment: String,
    pub attested_weight: u64,
    pub quorum_bps: u64,
    pub created_at_height: u64,
    pub fast_path: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationPlan {
    pub rotation_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub announced_at_height: u64,
    pub activates_at_height: u64,
    pub overlap_until_height: u64,
    pub outgoing_root: String,
    pub incoming_root: String,
    pub handoff_certificate_root: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateProofReceipt {
    pub receipt_id: String,
    pub header_id: String,
    pub bridge_event_id: String,
    pub nullifier_commitment: String,
    pub proof_public_input_root: String,
    pub encrypted_witness_root: String,
    pub receipt_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReceiptStatus,
    pub fee_micro_units: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeWindow {
    pub challenge_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub bond_micro_units: u64,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub status: ChallengeStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaWitnessBundle {
    pub bundle_id: String,
    pub header_id: String,
    pub receipt_root: String,
    pub da_commitment: String,
    pub shard_root: String,
    pub erasure_profile_root: String,
    pub availability_certificate_root: String,
    pub witness_bytes: u64,
    pub published_at_height: u64,
    pub available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyFallbackEvent {
    pub fallback_id: String,
    pub reason: String,
    pub subject_id: String,
    pub subject_root: String,
    pub activated_at_height: u64,
    pub recovery_height: u64,
    pub emergency_quorum_root: String,
    pub replacement_committee_root: String,
    pub status: FallbackStatus,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_id: PROTOCOL_ID.to_string(),
            protocol_version: PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            bridged_asset_id: "wxmr-devnet".to_string(),
            committee_id: "pq-private-bridge-light-client-devnet-committee".to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            rotation_overlap_blocks: DEFAULT_ROTATION_OVERLAP_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            header_finality_depth: DEFAULT_HEADER_FINALITY_DEPTH,
            fast_quorum_bps: DEFAULT_FAST_QUORUM_BPS,
            safe_quorum_bps: DEFAULT_SAFE_QUORUM_BPS,
            privacy_quorum_bps: DEFAULT_PRIVACY_QUORUM_BPS,
            emergency_quorum_bps: DEFAULT_EMERGENCY_QUORUM_BPS,
            min_security_bits: DEFAULT_MIN_SECURITY_BITS,
            max_headers_per_bundle: DEFAULT_MAX_HEADERS_PER_BUNDLE,
            max_receipts_per_window: DEFAULT_MAX_RECEIPTS_PER_WINDOW,
            max_witness_bytes: DEFAULT_MAX_WITNESS_BYTES,
            low_latency_target_ms: DEFAULT_LOW_LATENCY_TARGET_MS,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            challenge_bond_micro_units: DEFAULT_CHALLENGE_BOND_MICRO_UNITS,
            fallback_delay_blocks: DEFAULT_FALLBACK_DELAY_BLOCKS,
            hash_suite: HASH_SUITE.to_string(),
            monero_header_commitment_suite: MONERO_HEADER_COMMITMENT_SUITE.to_string(),
            pq_aggregate_signature_suite: PQ_AGGREGATE_SIGNATURE_SUITE.to_string(),
            pq_backup_signature_suite: PQ_BACKUP_SIGNATURE_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            privacy_proof_receipt_suite: PRIVACY_PROOF_RECEIPT_SUITE.to_string(),
            da_witness_suite: DA_WITNESS_SUITE.to_string(),
            rotation_suite: ROTATION_SUITE.to_string(),
            emergency_fallback_suite: EMERGENCY_FALLBACK_SUITE.to_string(),
        }
    }
}

impl Config {
    fn validate(&self) -> PqPrivateBridgeLightClientCommitteeResult<()> {
        ensure_non_empty(&self.protocol_id, "protocol id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.bridged_asset_id, "bridged asset id")?;
        ensure_non_empty(&self.committee_id, "committee id")?;
        ensure_bps(self.fast_quorum_bps, "fast quorum bps")?;
        ensure_bps(self.safe_quorum_bps, "safe quorum bps")?;
        ensure_bps(self.privacy_quorum_bps, "privacy quorum bps")?;
        ensure_bps(self.emergency_quorum_bps, "emergency quorum bps")?;
        ensure_at_least(
            self.fast_quorum_bps,
            self.safe_quorum_bps,
            "fast quorum bps",
        )?;
        ensure_at_least(
            self.privacy_quorum_bps,
            self.safe_quorum_bps,
            "privacy quorum bps",
        )?;
        ensure_at_least(
            self.emergency_quorum_bps,
            self.safe_quorum_bps,
            "emergency quorum bps",
        )?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.rotation_overlap_blocks, "rotation overlap blocks")?;
        ensure_positive(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_positive(self.receipt_ttl_blocks, "receipt ttl blocks")?;
        ensure_positive(self.header_finality_depth, "header finality depth")?;
        ensure_positive(self.min_security_bits, "min security bits")?;
        ensure_positive(self.max_headers_per_bundle, "max headers per bundle")?;
        ensure_positive(self.max_receipts_per_window, "max receipts per window")?;
        ensure_positive(self.max_witness_bytes, "max witness bytes")?;
        ensure_positive(self.low_latency_target_ms, "low latency target ms")?;
        ensure_positive(self.low_fee_micro_units, "low fee micro units")?;
        ensure_positive(
            self.challenge_bond_micro_units,
            "challenge bond micro units",
        )?;
        ensure_positive(self.fallback_delay_blocks, "fallback delay blocks")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(
            &self.monero_header_commitment_suite,
            "monero header commitment suite",
        )?;
        ensure_non_empty(
            &self.pq_aggregate_signature_suite,
            "pq aggregate signature suite",
        )?;
        ensure_non_empty(&self.pq_backup_signature_suite, "pq backup signature suite")?;
        ensure_non_empty(&self.pq_kem_suite, "pq kem suite")?;
        ensure_non_empty(
            &self.privacy_proof_receipt_suite,
            "privacy proof receipt suite",
        )?;
        ensure_non_empty(&self.da_witness_suite, "da witness suite")?;
        ensure_non_empty(&self.rotation_suite, "rotation suite")?;
        ensure_non_empty(&self.emergency_fallback_suite, "emergency fallback suite")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_id": self.protocol_id,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "bridged_asset_id": self.bridged_asset_id,
            "committee_id": self.committee_id,
            "epoch_blocks": self.epoch_blocks,
            "rotation_overlap_blocks": self.rotation_overlap_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "header_finality_depth": self.header_finality_depth,
            "fast_quorum_bps": self.fast_quorum_bps,
            "safe_quorum_bps": self.safe_quorum_bps,
            "privacy_quorum_bps": self.privacy_quorum_bps,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "min_security_bits": self.min_security_bits,
            "max_headers_per_bundle": self.max_headers_per_bundle,
            "max_receipts_per_window": self.max_receipts_per_window,
            "max_witness_bytes": self.max_witness_bytes,
            "low_latency_target_ms": self.low_latency_target_ms,
            "low_fee_micro_units": self.low_fee_micro_units,
            "challenge_bond_micro_units": self.challenge_bond_micro_units,
            "fallback_delay_blocks": self.fallback_delay_blocks,
            "hash_suite": self.hash_suite,
            "monero_header_commitment_suite": self.monero_header_commitment_suite,
            "pq_aggregate_signature_suite": self.pq_aggregate_signature_suite,
            "pq_backup_signature_suite": self.pq_backup_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "privacy_proof_receipt_suite": self.privacy_proof_receipt_suite,
            "da_witness_suite": self.da_witness_suite,
            "rotation_suite": self.rotation_suite,
            "emergency_fallback_suite": self.emergency_fallback_suite,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl State {
    pub fn devnet() -> PqPrivateBridgeLightClientCommitteeResult<Self> {
        let config = Config::default();
        let mut state = Self {
            height: DEFAULT_HEIGHT,
            config,
            committee_members: Vec::new(),
            monero_headers: Vec::new(),
            header_commitments: Vec::new(),
            pq_signatures: Vec::new(),
            aggregate_signatures: Vec::new(),
            quorum_certificates: Vec::new(),
            rotations: Vec::new(),
            private_receipts: Vec::new(),
            privacy_nullifiers: Vec::new(),
            challenge_windows: Vec::new(),
            da_witness_bundles: Vec::new(),
            fallback_events: Vec::new(),
            bridge_events: Vec::new(),
            low_fee_lanes: Vec::new(),
            public_events: Vec::new(),
        };
        state.seed_devnet_records();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqPrivateBridgeLightClientCommitteeResult<()> {
        self.config.validate()?;
        if self.config.chain_id != CHAIN_ID {
            return Err("state chain id does not match crate chain id".to_string());
        }
        ensure_unique(&self.committee_members, "member_id", "committee member")?;
        ensure_unique(&self.monero_headers, "header_id", "monero header")?;
        ensure_unique(&self.header_commitments, "header_id", "header commitment")?;
        ensure_unique(&self.pq_signatures, "share_id", "pq signature share")?;
        ensure_unique(
            &self.aggregate_signatures,
            "aggregate_id",
            "aggregate signature",
        )?;
        ensure_unique(
            &self.quorum_certificates,
            "certificate_id",
            "quorum certificate",
        )?;
        ensure_unique(&self.rotations, "rotation_id", "rotation")?;
        ensure_unique(&self.private_receipts, "receipt_id", "private receipt")?;
        ensure_unique(
            &self.privacy_nullifiers,
            "nullifier_id",
            "privacy nullifier",
        )?;
        ensure_unique(&self.challenge_windows, "challenge_id", "challenge window")?;
        ensure_unique(&self.da_witness_bundles, "bundle_id", "da witness bundle")?;
        ensure_unique(&self.fallback_events, "fallback_id", "fallback event")?;
        ensure_unique(&self.bridge_events, "event_id", "bridge event")?;
        ensure_unique(&self.low_fee_lanes, "lane_id", "low fee lane")?;
        ensure_record_chain(
            &self.committee_members,
            &self.config.chain_id,
            "committee member",
        )?;
        ensure_record_chain(&self.monero_headers, &self.config.chain_id, "monero header")?;
        ensure_record_chain(
            &self.header_commitments,
            &self.config.chain_id,
            "header commitment",
        )?;
        ensure_record_chain(&self.pq_signatures, &self.config.chain_id, "pq signature")?;
        ensure_record_chain(
            &self.aggregate_signatures,
            &self.config.chain_id,
            "aggregate signature",
        )?;
        ensure_record_chain(
            &self.quorum_certificates,
            &self.config.chain_id,
            "quorum certificate",
        )?;
        ensure_record_chain(&self.rotations, &self.config.chain_id, "rotation")?;
        ensure_record_chain(
            &self.private_receipts,
            &self.config.chain_id,
            "private receipt",
        )?;
        ensure_record_chain(
            &self.challenge_windows,
            &self.config.chain_id,
            "challenge window",
        )?;
        ensure_record_chain(
            &self.da_witness_bundles,
            &self.config.chain_id,
            "da witness bundle",
        )?;
        ensure_record_chain(
            &self.fallback_events,
            &self.config.chain_id,
            "fallback event",
        )?;
        let counters = self.counters();
        if counters.active_committee_weight == 0 {
            return Err("active committee weight must be non-zero".to_string());
        }
        let required_safe =
            threshold_weight(counters.total_committee_weight, self.config.safe_quorum_bps);
        if counters.active_committee_weight < required_safe {
            return Err("active committee weight is below safe quorum threshold".to_string());
        }
        for aggregate in &self.aggregate_signatures {
            let attested = value_u64(aggregate, "attested_weight")?;
            let quorum_bps = value_u64(aggregate, "quorum_bps")?;
            ensure_bps(quorum_bps, "aggregate quorum bps")?;
            let required = threshold_weight(counters.total_committee_weight, quorum_bps);
            if attested < required {
                return Err(format!(
                    "aggregate signature below quorum: {} < {}",
                    attested, required
                ));
            }
        }
        for bundle in &self.da_witness_bundles {
            let witness_bytes = value_u64(bundle, "witness_bytes")?;
            if witness_bytes > self.config.max_witness_bytes {
                return Err("da witness bundle exceeds configured byte limit".to_string());
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqPrivateBridgeLightClientCommitteeResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> PqPrivateBridgeLightClientCommitteeResult<()> {
        self.height = self.height.saturating_add(delta);
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let active_committee = self
            .committee_members
            .iter()
            .filter(|record| match value_str(record, "status") {
                Ok(status) => is_active_committee_status(status),
                Err(_) => false,
            })
            .cloned()
            .collect::<Vec<_>>();
        let roots_without_state = json!({
            "config_root": config_root,
            "committee_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-COMMITTEE", &self.committee_members),
            "active_committee_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-ACTIVE-COMMITTEE", &active_committee),
            "monero_header_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-MONERO-HEADER", &self.monero_headers),
            "header_commitment_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-HEADER-COMMITMENT", &self.header_commitments),
            "pq_signature_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-PQ-SIGNATURE", &self.pq_signatures),
            "aggregate_signature_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-AGGREGATE-SIGNATURE", &self.aggregate_signatures),
            "quorum_certificate_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-QUORUM-CERTIFICATE", &self.quorum_certificates),
            "rotation_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-ROTATION", &self.rotations),
            "private_receipt_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-PRIVATE-RECEIPT", &self.private_receipts),
            "privacy_nullifier_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-PRIVACY-NULLIFIER", &self.privacy_nullifiers),
            "challenge_window_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-CHALLENGE-WINDOW", &self.challenge_windows),
            "da_witness_bundle_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-DA-WITNESS-BUNDLE", &self.da_witness_bundles),
            "fallback_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-FALLBACK", &self.fallback_events),
            "bridge_event_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-BRIDGE-EVENT", &self.bridge_events),
            "low_fee_lane_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-LOW-FEE-LANE", &self.low_fee_lanes),
            "public_event_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-PUBLIC-EVENT", &self.public_events),
        });
        Roots {
            config_root: value_string_or_empty(&roots_without_state, "config_root"),
            committee_root: value_string_or_empty(&roots_without_state, "committee_root"),
            active_committee_root: value_string_or_empty(
                &roots_without_state,
                "active_committee_root",
            ),
            monero_header_root: value_string_or_empty(&roots_without_state, "monero_header_root"),
            header_commitment_root: value_string_or_empty(
                &roots_without_state,
                "header_commitment_root",
            ),
            pq_signature_root: value_string_or_empty(&roots_without_state, "pq_signature_root"),
            aggregate_signature_root: value_string_or_empty(
                &roots_without_state,
                "aggregate_signature_root",
            ),
            quorum_certificate_root: value_string_or_empty(
                &roots_without_state,
                "quorum_certificate_root",
            ),
            rotation_root: value_string_or_empty(&roots_without_state, "rotation_root"),
            private_receipt_root: value_string_or_empty(
                &roots_without_state,
                "private_receipt_root",
            ),
            privacy_nullifier_root: value_string_or_empty(
                &roots_without_state,
                "privacy_nullifier_root",
            ),
            challenge_window_root: value_string_or_empty(
                &roots_without_state,
                "challenge_window_root",
            ),
            da_witness_bundle_root: value_string_or_empty(
                &roots_without_state,
                "da_witness_bundle_root",
            ),
            fallback_root: value_string_or_empty(&roots_without_state, "fallback_root"),
            bridge_event_root: value_string_or_empty(&roots_without_state, "bridge_event_root"),
            low_fee_lane_root: value_string_or_empty(&roots_without_state, "low_fee_lane_root"),
            public_event_root: value_string_or_empty(&roots_without_state, "public_event_root"),
            state_root: domain_hash(
                "PQ-PRIVATE-BRIDGE-LC-ROOTS",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION),
                    HashPart::Json(&roots_without_state),
                ],
                32,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        let active_committee_members =
            count_by_status(&self.committee_members, is_active_committee_status);
        let jailed_committee_members =
            count_by_status(&self.committee_members, |status| status == "jailed");
        let retired_committee_members =
            count_by_status(&self.committee_members, |status| status == "retired");
        let total_committee_weight = sum_u64(&self.committee_members, "weight");
        let active_committee_weight = self
            .committee_members
            .iter()
            .filter(|record| match value_str(record, "status") {
                Ok(status) => is_active_committee_status(status),
                Err(_) => false,
            })
            .map(|record| match value_u64(record, "weight") {
                Ok(value) => value,
                Err(_) => 0,
            })
            .sum();
        Counters {
            committee_members: self.committee_members.len() as u64,
            active_committee_members,
            jailed_committee_members,
            retired_committee_members,
            monero_headers: self.monero_headers.len() as u64,
            usable_monero_headers: count_by_status(&self.monero_headers, is_usable_header_status),
            header_commitments: self.header_commitments.len() as u64,
            finalized_header_commitments: count_by_status(&self.header_commitments, |status| {
                status == "finalized"
            }),
            pq_signatures: self.pq_signatures.len() as u64,
            accepted_pq_signatures: self
                .pq_signatures
                .iter()
                .filter(|record| value_bool(record, "accepted"))
                .count() as u64,
            aggregate_signatures: self.aggregate_signatures.len() as u64,
            quorum_certificates: self.quorum_certificates.len() as u64,
            rotations: self.rotations.len() as u64,
            active_rotations: self
                .rotations
                .iter()
                .filter(|record| value_bool(record, "active"))
                .count() as u64,
            private_receipts: self.private_receipts.len() as u64,
            live_private_receipts: count_by_status(&self.private_receipts, is_live_receipt_status),
            privacy_nullifiers: self.privacy_nullifiers.len() as u64,
            challenge_windows: self.challenge_windows.len() as u64,
            open_challenge_windows: count_by_status(
                &self.challenge_windows,
                is_active_challenge_status,
            ),
            da_witness_bundles: self.da_witness_bundles.len() as u64,
            available_witness_bundles: self
                .da_witness_bundles
                .iter()
                .filter(|record| value_bool(record, "available"))
                .count() as u64,
            fallback_events: self.fallback_events.len() as u64,
            active_fallback_events: count_by_status(
                &self.fallback_events,
                is_active_fallback_status,
            ),
            bridge_events: self.bridge_events.len() as u64,
            low_fee_lanes: self.low_fee_lanes.len() as u64,
            public_events: self.public_events.len() as u64,
            total_committee_weight,
            active_committee_weight,
            total_attested_weight: sum_u64(&self.aggregate_signatures, "attested_weight"),
            total_witness_bytes: sum_u64(&self.da_witness_bundles, "witness_bytes"),
            total_low_fee_micro_units: sum_u64(&self.private_receipts, "fee_micro_units"),
            total_challenge_bond_micro_units: sum_u64(&self.challenge_windows, "bond_micro_units"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots(),
            "counters": self.counters(),
            "latency_posture": self.latency_posture_record(),
            "privacy_posture": self.privacy_posture_record(),
            "bridge_safety_posture": self.bridge_safety_posture_record(),
            "policy_catalog_root": policy_catalog_root(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    fn seed_devnet_records(&mut self) {
        let members = vec![
            ("aurora", CommitteeRole::HeaderProver, 18, 99, 96),
            ("borealis", CommitteeRole::BridgeValidator, 17, 97, 94),
            ("cipher", CommitteeRole::PrivacyAuditor, 16, 96, 99),
            ("delta", CommitteeRole::DaWitness, 15, 94, 95),
            ("ember", CommitteeRole::ChallengeGuardian, 14, 93, 96),
            ("flux", CommitteeRole::RotationCoordinator, 12, 92, 93),
            ("glacier", CommitteeRole::EmergencySigner, 10, 91, 94),
        ];
        for (index, (label, role, weight, latency, privacy)) in members.into_iter().enumerate() {
            let member = CommitteeMember {
                member_id: id_hash("MEMBER", label),
                operator_id: format!("devnet-{}-operator", label),
                role,
                status: if index < 6 {
                    CommitteeStatus::Active
                } else {
                    CommitteeStatus::Overlap
                },
                weight,
                pq_public_key_commitment: id_hash("PQ-PUBLIC-KEY", label),
                backup_public_key_commitment: id_hash("BACKUP-PUBLIC-KEY", label),
                kem_public_key_commitment: id_hash("KEM-PUBLIC-KEY", label),
                stake_commitment: id_hash("STAKE", label),
                latency_score: latency,
                privacy_score: privacy,
                joined_at_height: DEFAULT_HEIGHT.saturating_sub(1_200 + index as u64),
                rotation_epoch: DEFAULT_HEIGHT / DEFAULT_EPOCH_BLOCKS,
            };
            self.committee_members.push(member_record(&member));
        }
        for offset in 0..6_u64 {
            let monero_height = DEFAULT_HEIGHT + offset;
            let header = MoneroHeaderCommitment {
                header_id: id_hash("HEADER", &format!("{}", monero_height)),
                network: self.config.monero_network.clone(),
                height: monero_height,
                block_hash: id_hash("MONERO-BLOCK", &format!("{}", monero_height)),
                previous_block_hash: id_hash(
                    "MONERO-PREVIOUS-BLOCK",
                    &format!("{}", monero_height.saturating_sub(1)),
                ),
                tx_root: id_hash("MONERO-TX-ROOT", &format!("{}", monero_height)),
                output_root: id_hash("MONERO-OUTPUT-ROOT", &format!("{}", monero_height)),
                key_image_root: id_hash("MONERO-KEY-IMAGE-ROOT", &format!("{}", monero_height)),
                difficulty_commitment: id_hash(
                    "MONERO-DIFFICULTY",
                    &format!("{}", monero_height / 720),
                ),
                cumulative_work_commitment: id_hash("MONERO-WORK", &format!("{}", monero_height)),
                timestamp_bucket: 1_720_000_000 + (offset * 120),
                finality_depth: self.config.header_finality_depth + offset,
                status: if offset < 4 {
                    HeaderStatus::Finalized
                } else {
                    HeaderStatus::Aggregated
                },
                commitment_root: String::new(),
            };
            let mut record = header_record(&header);
            let commitment_root = root_from_record(&record);
            insert_string(&mut record, "commitment_root", commitment_root);
            self.monero_headers.push(record.clone());
            self.header_commitments.push(record);
        }
        let active_members = self
            .committee_members
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>();
        for header in &self.header_commitments {
            let header_id = value_string_or_empty(header, "header_id");
            let signed_root = root_from_record(header);
            for member in active_members.iter().take(5) {
                let member_id = value_string_or_empty(member, "member_id");
                let share = PqSignatureShare {
                    share_id: id_hash("PQ-SHARE", &format!("{}:{}", member_id, header_id)),
                    member_id,
                    header_id: header_id.clone(),
                    signed_root: signed_root.clone(),
                    signature_commitment: id_hash("PQ-SIGNATURE", &signed_root),
                    backup_signature_commitment: id_hash("PQ-BACKUP-SIGNATURE", &signed_root),
                    signed_at_height: self.height,
                    security_bits: self.config.min_security_bits,
                    accepted: true,
                };
                self.pq_signatures.push(signature_share_record(&share));
            }
            let participant_root = merkle_root("PQ-PRIVATE-BRIDGE-LC-PARTICIPANT", &active_members);
            let aggregate = AggregateSignature {
                aggregate_id: id_hash("AGGREGATE", &header_id),
                header_id: header_id.clone(),
                committee_epoch: self.height / self.config.epoch_blocks,
                participant_root: participant_root.clone(),
                aggregate_signature_commitment: id_hash(
                    "AGGREGATE-SIGNATURE",
                    &format!("{}:{}", header_id, participant_root),
                ),
                backup_signature_commitment: id_hash("AGGREGATE-BACKUP", &header_id),
                attested_weight: 80,
                quorum_bps: self.config.fast_quorum_bps,
                created_at_height: self.height,
                fast_path: true,
            };
            self.aggregate_signatures.push(aggregate_record(&aggregate));
            self.quorum_certificates
                .push(quorum_certificate_record(&aggregate));
        }
        self.seed_rotation_and_private_lanes();
    }

    fn seed_rotation_and_private_lanes(&mut self) {
        let outgoing_root = merkle_root(
            "PQ-PRIVATE-BRIDGE-LC-ROTATION-OUTGOING",
            &self.committee_members,
        );
        let incoming_root = domain_hash(
            "PQ-PRIVATE-BRIDGE-LC-INCOMING-COMMITTEE",
            &[HashPart::Str(&outgoing_root)],
            32,
        );
        let rotation = RotationPlan {
            rotation_id: id_hash("ROTATION", "devnet-overlap"),
            from_epoch: self.height / self.config.epoch_blocks,
            to_epoch: (self.height / self.config.epoch_blocks).saturating_add(1),
            announced_at_height: self
                .height
                .saturating_sub(self.config.rotation_overlap_blocks),
            activates_at_height: self
                .height
                .saturating_add(self.config.rotation_overlap_blocks),
            overlap_until_height: self
                .height
                .saturating_add(self.config.rotation_overlap_blocks * 2),
            outgoing_root,
            incoming_root,
            handoff_certificate_root: id_hash("ROTATION-HANDOFF", "devnet-overlap"),
            active: true,
        };
        self.rotations.push(rotation_record(&rotation));
        for index in 0..4_u64 {
            let header_id = match self.header_commitments.get(index as usize) {
                Some(value) => value_string_or_empty(value, "header_id"),
                None => String::new(),
            };
            let event_id = id_hash("BRIDGE-EVENT", &format!("private-event-{}", index));
            let receipt = PrivateProofReceipt {
                receipt_id: id_hash("PRIVATE-RECEIPT", &format!("{}:{}", header_id, index)),
                header_id: header_id.clone(),
                bridge_event_id: event_id,
                nullifier_commitment: id_hash(
                    "PRIVATE-NULLIFIER",
                    &format!("{}:{}", header_id, index),
                ),
                proof_public_input_root: id_hash(
                    "PROOF-PUBLIC-INPUT",
                    &format!("{}:{}", header_id, index),
                ),
                encrypted_witness_root: id_hash(
                    "ENCRYPTED-WITNESS",
                    &format!("{}:{}", header_id, index),
                ),
                receipt_root: id_hash("RECEIPT-ROOT", &format!("{}:{}", header_id, index)),
                issued_at_height: self.height + index,
                expires_at_height: self.height + index + self.config.receipt_ttl_blocks,
                status: if index < 3 {
                    ReceiptStatus::Released
                } else {
                    ReceiptStatus::Prepared
                },
                fee_micro_units: self.config.low_fee_micro_units,
            };
            self.private_receipts.push(private_receipt_record(&receipt));
            self.privacy_nullifiers
                .push(privacy_nullifier_record(&receipt));
            self.bridge_events.push(bridge_event_record(&receipt));
            self.low_fee_lanes.push(low_fee_lane_record(&receipt));
        }
        for index in 0..3_u64 {
            let header_id = match self.header_commitments.get(index as usize) {
                Some(value) => value_string_or_empty(value, "header_id"),
                None => String::new(),
            };
            let receipt_slice = self
                .private_receipts
                .iter()
                .take((index + 1) as usize)
                .cloned()
                .collect::<Vec<_>>();
            let bundle = DaWitnessBundle {
                bundle_id: id_hash("DA-WITNESS-BUNDLE", &format!("{}:{}", header_id, index)),
                header_id: header_id.clone(),
                receipt_root: merkle_root("PQ-PRIVATE-BRIDGE-LC-BUNDLE-RECEIPT", &receipt_slice),
                da_commitment: id_hash("DA-COMMITMENT", &format!("{}:{}", header_id, index)),
                shard_root: id_hash("DA-SHARD-ROOT", &format!("{}:{}", header_id, index)),
                erasure_profile_root: id_hash("DA-ERASURE", &format!("{}:{}", header_id, index)),
                availability_certificate_root: id_hash(
                    "DA-AVAILABILITY",
                    &format!("{}:{}", header_id, index),
                ),
                witness_bytes: 64_000 + (index * 2_048),
                published_at_height: self.height + index,
                available: true,
            };
            self.da_witness_bundles
                .push(da_witness_bundle_record(&bundle));
        }
        let subject_id = value_string_or_empty(&self.header_commitments[4], "header_id");
        let subject_root = root_from_record(&self.header_commitments[4]);
        let challenge = ChallengeWindow {
            challenge_id: id_hash("CHALLENGE", "devnet-low-latency-window"),
            subject_id: subject_id.clone(),
            subject_root: subject_root.clone(),
            opened_at_height: self.height,
            closes_at_height: self.height + self.config.challenge_window_blocks,
            bond_micro_units: self.config.challenge_bond_micro_units,
            challenger_commitment: id_hash("CHALLENGER", "devnet-watchtower"),
            evidence_root: id_hash("CHALLENGE-EVIDENCE", "devnet-low-latency-window"),
            status: ChallengeStatus::Open,
        };
        self.challenge_windows.push(challenge_record(&challenge));
        let fallback = EmergencyFallbackEvent {
            fallback_id: id_hash("FALLBACK", "devnet-watch-only-recovery"),
            reason: "da_witness_delay".to_string(),
            subject_id,
            subject_root,
            activated_at_height: self.height + self.config.fallback_delay_blocks,
            recovery_height: self.height
                + self.config.fallback_delay_blocks
                + self.config.header_finality_depth,
            emergency_quorum_root: id_hash("EMERGENCY-QUORUM", "devnet-watch-only-recovery"),
            replacement_committee_root: id_hash(
                "REPLACEMENT-COMMITTEE",
                "devnet-watch-only-recovery",
            ),
            status: FallbackStatus::Monitoring,
        };
        self.fallback_events.push(fallback_record(&fallback));
        self.public_events.push(json!({
            "chain_id": CHAIN_ID,
            "event_id": id_hash("PUBLIC-EVENT", "devnet-committee-ready"),
            "event_kind": "pq_private_bridge_light_client_committee_ready",
            "height": self.height,
            "committee_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-COMMITTEE", &self.committee_members),
        }));
    }

    fn latency_posture_record(&self) -> Value {
        json!({
            "target_ms": self.config.low_latency_target_ms,
            "fast_quorum_bps": self.config.fast_quorum_bps,
            "challenge_window_blocks": self.config.challenge_window_blocks,
            "fast_aggregates": self.aggregate_signatures.iter().filter(|record| value_bool(record, "fast_path")).count() as u64,
            "open_challenges": self.counters().open_challenge_windows,
        })
    }

    fn privacy_posture_record(&self) -> Value {
        json!({
            "privacy_quorum_bps": self.config.privacy_quorum_bps,
            "private_receipts": self.private_receipts.len() as u64,
            "privacy_nullifier_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-PRIVACY-NULLIFIER", &self.privacy_nullifiers),
            "encrypted_witness_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-ENCRYPTED-WITNESS", &self.private_receipts),
            "proof_receipt_suite": self.config.privacy_proof_receipt_suite,
        })
    }

    fn bridge_safety_posture_record(&self) -> Value {
        json!({
            "safe_quorum_bps": self.config.safe_quorum_bps,
            "emergency_quorum_bps": self.config.emergency_quorum_bps,
            "fallback_events": self.fallback_events.len() as u64,
            "active_fallback_events": self.counters().active_fallback_events,
            "da_witness_bundle_root": merkle_root("PQ-PRIVATE-BRIDGE-LC-DA-WITNESS-BUNDLE", &self.da_witness_bundles),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-PRIVATE-BRIDGE-LC-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PqPrivateBridgeLightClientCommitteeResult<State> {
    State::devnet()
}

fn member_record(member: &CommitteeMember) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "committee_member", "member_id": member.member_id, "operator_id": member.operator_id, "role": member.role.as_str(), "status": member.status.as_str(), "weight": member.weight, "pq_public_key_commitment": member.pq_public_key_commitment, "backup_public_key_commitment": member.backup_public_key_commitment, "kem_public_key_commitment": member.kem_public_key_commitment, "stake_commitment": member.stake_commitment, "latency_score": member.latency_score, "privacy_score": member.privacy_score, "joined_at_height": member.joined_at_height, "rotation_epoch": member.rotation_epoch})
}

fn header_record(header: &MoneroHeaderCommitment) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "monero_header_commitment", "header_id": header.header_id, "network": header.network, "height": header.height, "block_hash": header.block_hash, "previous_block_hash": header.previous_block_hash, "tx_root": header.tx_root, "output_root": header.output_root, "key_image_root": header.key_image_root, "difficulty_commitment": header.difficulty_commitment, "cumulative_work_commitment": header.cumulative_work_commitment, "timestamp_bucket": header.timestamp_bucket, "finality_depth": header.finality_depth, "status": header.status.as_str(), "commitment_root": header.commitment_root})
}

fn signature_share_record(share: &PqSignatureShare) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "pq_signature_share", "share_id": share.share_id, "member_id": share.member_id, "header_id": share.header_id, "signed_root": share.signed_root, "signature_commitment": share.signature_commitment, "backup_signature_commitment": share.backup_signature_commitment, "signed_at_height": share.signed_at_height, "security_bits": share.security_bits, "accepted": share.accepted})
}

fn aggregate_record(aggregate: &AggregateSignature) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "aggregate_signature", "aggregate_id": aggregate.aggregate_id, "header_id": aggregate.header_id, "committee_epoch": aggregate.committee_epoch, "participant_root": aggregate.participant_root, "aggregate_signature_commitment": aggregate.aggregate_signature_commitment, "backup_signature_commitment": aggregate.backup_signature_commitment, "attested_weight": aggregate.attested_weight, "quorum_bps": aggregate.quorum_bps, "created_at_height": aggregate.created_at_height, "fast_path": aggregate.fast_path})
}

fn quorum_certificate_record(aggregate: &AggregateSignature) -> Value {
    let aggregate_value = aggregate_record(aggregate);
    json!({"chain_id": CHAIN_ID, "record_kind": "quorum_certificate", "certificate_id": id_hash("QUORUM-CERTIFICATE", &aggregate.aggregate_id), "aggregate_id": aggregate.aggregate_id, "header_id": aggregate.header_id, "certificate_root": root_from_record(&aggregate_value), "participant_root": aggregate.participant_root, "attested_weight": aggregate.attested_weight, "quorum_bps": aggregate.quorum_bps, "created_at_height": aggregate.created_at_height})
}

fn rotation_record(rotation: &RotationPlan) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "rotation_plan", "rotation_id": rotation.rotation_id, "from_epoch": rotation.from_epoch, "to_epoch": rotation.to_epoch, "announced_at_height": rotation.announced_at_height, "activates_at_height": rotation.activates_at_height, "overlap_until_height": rotation.overlap_until_height, "outgoing_root": rotation.outgoing_root, "incoming_root": rotation.incoming_root, "handoff_certificate_root": rotation.handoff_certificate_root, "active": rotation.active})
}

fn private_receipt_record(receipt: &PrivateProofReceipt) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "private_proof_receipt", "receipt_id": receipt.receipt_id, "header_id": receipt.header_id, "bridge_event_id": receipt.bridge_event_id, "nullifier_commitment": receipt.nullifier_commitment, "proof_public_input_root": receipt.proof_public_input_root, "encrypted_witness_root": receipt.encrypted_witness_root, "receipt_root": receipt.receipt_root, "issued_at_height": receipt.issued_at_height, "expires_at_height": receipt.expires_at_height, "status": receipt.status.as_str(), "fee_micro_units": receipt.fee_micro_units})
}

fn privacy_nullifier_record(receipt: &PrivateProofReceipt) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "privacy_nullifier", "nullifier_id": id_hash("NULLIFIER-ID", &receipt.nullifier_commitment), "receipt_id": receipt.receipt_id, "header_id": receipt.header_id, "nullifier_commitment": receipt.nullifier_commitment, "spent": false, "created_at_height": receipt.issued_at_height})
}

fn bridge_event_record(receipt: &PrivateProofReceipt) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "bridge_event", "event_id": receipt.bridge_event_id, "event_kind": "private_bridge_proof_receipt", "header_id": receipt.header_id, "receipt_id": receipt.receipt_id, "event_root": receipt.receipt_root, "emitted_at_height": receipt.issued_at_height})
}

fn low_fee_lane_record(receipt: &PrivateProofReceipt) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "low_fee_lane", "lane_id": id_hash("LOW-FEE-LANE", &receipt.receipt_id), "receipt_id": receipt.receipt_id, "fee_micro_units": receipt.fee_micro_units, "sponsored": true, "settlement_priority": "fast_private_bridge", "created_at_height": receipt.issued_at_height})
}

fn challenge_record(challenge: &ChallengeWindow) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "challenge_window", "challenge_id": challenge.challenge_id, "subject_id": challenge.subject_id, "subject_root": challenge.subject_root, "opened_at_height": challenge.opened_at_height, "closes_at_height": challenge.closes_at_height, "bond_micro_units": challenge.bond_micro_units, "challenger_commitment": challenge.challenger_commitment, "evidence_root": challenge.evidence_root, "status": challenge.status.as_str()})
}

fn da_witness_bundle_record(bundle: &DaWitnessBundle) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "da_witness_bundle", "bundle_id": bundle.bundle_id, "header_id": bundle.header_id, "receipt_root": bundle.receipt_root, "da_commitment": bundle.da_commitment, "shard_root": bundle.shard_root, "erasure_profile_root": bundle.erasure_profile_root, "availability_certificate_root": bundle.availability_certificate_root, "witness_bytes": bundle.witness_bytes, "published_at_height": bundle.published_at_height, "available": bundle.available})
}

fn fallback_record(fallback: &EmergencyFallbackEvent) -> Value {
    json!({"chain_id": CHAIN_ID, "record_kind": "emergency_fallback_event", "fallback_id": fallback.fallback_id, "reason": fallback.reason, "subject_id": fallback.subject_id, "subject_root": fallback.subject_root, "activated_at_height": fallback.activated_at_height, "recovery_height": fallback.recovery_height, "emergency_quorum_root": fallback.emergency_quorum_root, "replacement_committee_root": fallback.replacement_committee_root, "status": fallback.status.as_str()})
}

fn ensure_non_empty(value: &str, label: &str) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{} must not be empty", label));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    if value == 0 {
        return Err(format!("{} must be positive", label));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    if value == 0 || value > MAX_BPS {
        return Err(format!("{} must be within 1..={} bps", label, MAX_BPS));
    }
    Ok(())
}

fn ensure_at_least(
    value: u64,
    minimum: u64,
    label: &str,
) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    if value < minimum {
        return Err(format!("{} must be at least {}", label, minimum));
    }
    Ok(())
}

fn ensure_unique(
    records: &[Value],
    field: &str,
    label: &str,
) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    let mut seen = BTreeSet::new();
    for record in records {
        let id = value_str(record, field)?;
        if !seen.insert(id.to_string()) {
            return Err(format!("duplicate {} {}", label, id));
        }
    }
    Ok(())
}

fn ensure_record_chain(
    records: &[Value],
    chain_id: &str,
    label: &str,
) -> PqPrivateBridgeLightClientCommitteeResult<()> {
    for record in records {
        let record_chain = value_str(record, "chain_id")?;
        if record_chain != chain_id {
            return Err(format!("{} chain id mismatch", label));
        }
    }
    Ok(())
}

fn value_str<'a>(
    record: &'a Value,
    field: &str,
) -> PqPrivateBridgeLightClientCommitteeResult<&'a str> {
    record
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {}", field))
}

fn value_u64(record: &Value, field: &str) -> PqPrivateBridgeLightClientCommitteeResult<u64> {
    record
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 field {}", field))
}

fn value_bool(record: &Value, field: &str) -> bool {
    match record.get(field).and_then(Value::as_bool) {
        Some(value) => value,
        None => false,
    }
}

fn value_string_or_empty(record: &Value, field: &str) -> String {
    match record.get(field).and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn insert_string(record: &mut Value, field: &str, value: String) {
    if let Value::Object(map) = record {
        map.insert(field.to_string(), Value::String(value));
    }
}

fn count_by_status<F>(records: &[Value], predicate: F) -> u64
where
    F: Fn(&str) -> bool,
{
    records
        .iter()
        .filter(|record| match value_str(record, "status") {
            Ok(status) => predicate(status),
            Err(_) => false,
        })
        .count() as u64
}

fn sum_u64(records: &[Value], field: &str) -> u64 {
    records
        .iter()
        .map(|record| match value_u64(record, field) {
            Ok(value) => value,
            Err(_) => 0,
        })
        .sum()
}

fn threshold_weight(total_weight: u64, bps: u64) -> u64 {
    total_weight.saturating_mul(bps).saturating_add(MAX_BPS - 1) / MAX_BPS
}

fn is_active_committee_status(status: &str) -> bool {
    matches!(status, "active" | "warming" | "overlap")
}

fn is_usable_header_status(status: &str) -> bool {
    matches!(status, "aggregated" | "challenge_open" | "finalized")
}

fn is_live_receipt_status(status: &str) -> bool {
    matches!(status, "prepared" | "released" | "settled")
}

fn is_active_challenge_status(status: &str) -> bool {
    matches!(status, "open" | "evidence_submitted" | "escalated")
}

fn is_active_fallback_status(status: &str) -> bool {
    matches!(status, "armed" | "monitoring" | "active" | "recovering")
}

fn id_hash(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PQ-PRIVATE-BRIDGE-LC-{}", domain),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn indexed_policy_record(index: u64, name: &str, capability: &str, root: &str) -> Value {
    json!({"chain_id": CHAIN_ID, "index": index, "name": name, "capability": capability, "root": root, "protocol_version": PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION})
}

fn policy_catalog_root() -> String {
    let records = policy_catalog_records();
    merkle_root("PQ-PRIVATE-BRIDGE-LC-POLICY-CATALOG", &records)
}

fn policy_catalog_records() -> Vec<Value> {
    vec![
        indexed_policy_record(
            0,
            "policy_000",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_000"),
        ),
        indexed_policy_record(
            1,
            "policy_001",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_001"),
        ),
        indexed_policy_record(
            2,
            "policy_002",
            "committee_rotation",
            &id_hash("POLICY", "policy_002"),
        ),
        indexed_policy_record(
            3,
            "policy_003",
            "private_receipt",
            &id_hash("POLICY", "policy_003"),
        ),
        indexed_policy_record(
            4,
            "policy_004",
            "challenge_window",
            &id_hash("POLICY", "policy_004"),
        ),
        indexed_policy_record(
            5,
            "policy_005",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_005"),
        ),
        indexed_policy_record(
            6,
            "policy_006",
            "emergency_fallback",
            &id_hash("POLICY", "policy_006"),
        ),
        indexed_policy_record(
            7,
            "policy_007",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_007"),
        ),
        indexed_policy_record(
            8,
            "policy_008",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_008"),
        ),
        indexed_policy_record(
            9,
            "policy_009",
            "committee_rotation",
            &id_hash("POLICY", "policy_009"),
        ),
        indexed_policy_record(
            10,
            "policy_010",
            "private_receipt",
            &id_hash("POLICY", "policy_010"),
        ),
        indexed_policy_record(
            11,
            "policy_011",
            "challenge_window",
            &id_hash("POLICY", "policy_011"),
        ),
        indexed_policy_record(
            12,
            "policy_012",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_012"),
        ),
        indexed_policy_record(
            13,
            "policy_013",
            "emergency_fallback",
            &id_hash("POLICY", "policy_013"),
        ),
        indexed_policy_record(
            14,
            "policy_014",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_014"),
        ),
        indexed_policy_record(
            15,
            "policy_015",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_015"),
        ),
        indexed_policy_record(
            16,
            "policy_016",
            "committee_rotation",
            &id_hash("POLICY", "policy_016"),
        ),
        indexed_policy_record(
            17,
            "policy_017",
            "private_receipt",
            &id_hash("POLICY", "policy_017"),
        ),
        indexed_policy_record(
            18,
            "policy_018",
            "challenge_window",
            &id_hash("POLICY", "policy_018"),
        ),
        indexed_policy_record(
            19,
            "policy_019",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_019"),
        ),
        indexed_policy_record(
            20,
            "policy_020",
            "emergency_fallback",
            &id_hash("POLICY", "policy_020"),
        ),
        indexed_policy_record(
            21,
            "policy_021",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_021"),
        ),
        indexed_policy_record(
            22,
            "policy_022",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_022"),
        ),
        indexed_policy_record(
            23,
            "policy_023",
            "committee_rotation",
            &id_hash("POLICY", "policy_023"),
        ),
        indexed_policy_record(
            24,
            "policy_024",
            "private_receipt",
            &id_hash("POLICY", "policy_024"),
        ),
        indexed_policy_record(
            25,
            "policy_025",
            "challenge_window",
            &id_hash("POLICY", "policy_025"),
        ),
        indexed_policy_record(
            26,
            "policy_026",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_026"),
        ),
        indexed_policy_record(
            27,
            "policy_027",
            "emergency_fallback",
            &id_hash("POLICY", "policy_027"),
        ),
        indexed_policy_record(
            28,
            "policy_028",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_028"),
        ),
        indexed_policy_record(
            29,
            "policy_029",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_029"),
        ),
        indexed_policy_record(
            30,
            "policy_030",
            "committee_rotation",
            &id_hash("POLICY", "policy_030"),
        ),
        indexed_policy_record(
            31,
            "policy_031",
            "private_receipt",
            &id_hash("POLICY", "policy_031"),
        ),
        indexed_policy_record(
            32,
            "policy_032",
            "challenge_window",
            &id_hash("POLICY", "policy_032"),
        ),
        indexed_policy_record(
            33,
            "policy_033",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_033"),
        ),
        indexed_policy_record(
            34,
            "policy_034",
            "emergency_fallback",
            &id_hash("POLICY", "policy_034"),
        ),
        indexed_policy_record(
            35,
            "policy_035",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_035"),
        ),
        indexed_policy_record(
            36,
            "policy_036",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_036"),
        ),
        indexed_policy_record(
            37,
            "policy_037",
            "committee_rotation",
            &id_hash("POLICY", "policy_037"),
        ),
        indexed_policy_record(
            38,
            "policy_038",
            "private_receipt",
            &id_hash("POLICY", "policy_038"),
        ),
        indexed_policy_record(
            39,
            "policy_039",
            "challenge_window",
            &id_hash("POLICY", "policy_039"),
        ),
        indexed_policy_record(
            40,
            "policy_040",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_040"),
        ),
        indexed_policy_record(
            41,
            "policy_041",
            "emergency_fallback",
            &id_hash("POLICY", "policy_041"),
        ),
        indexed_policy_record(
            42,
            "policy_042",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_042"),
        ),
        indexed_policy_record(
            43,
            "policy_043",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_043"),
        ),
        indexed_policy_record(
            44,
            "policy_044",
            "committee_rotation",
            &id_hash("POLICY", "policy_044"),
        ),
        indexed_policy_record(
            45,
            "policy_045",
            "private_receipt",
            &id_hash("POLICY", "policy_045"),
        ),
        indexed_policy_record(
            46,
            "policy_046",
            "challenge_window",
            &id_hash("POLICY", "policy_046"),
        ),
        indexed_policy_record(
            47,
            "policy_047",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_047"),
        ),
        indexed_policy_record(
            48,
            "policy_048",
            "emergency_fallback",
            &id_hash("POLICY", "policy_048"),
        ),
        indexed_policy_record(
            49,
            "policy_049",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_049"),
        ),
        indexed_policy_record(
            50,
            "policy_050",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_050"),
        ),
        indexed_policy_record(
            51,
            "policy_051",
            "committee_rotation",
            &id_hash("POLICY", "policy_051"),
        ),
        indexed_policy_record(
            52,
            "policy_052",
            "private_receipt",
            &id_hash("POLICY", "policy_052"),
        ),
        indexed_policy_record(
            53,
            "policy_053",
            "challenge_window",
            &id_hash("POLICY", "policy_053"),
        ),
        indexed_policy_record(
            54,
            "policy_054",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_054"),
        ),
        indexed_policy_record(
            55,
            "policy_055",
            "emergency_fallback",
            &id_hash("POLICY", "policy_055"),
        ),
        indexed_policy_record(
            56,
            "policy_056",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_056"),
        ),
        indexed_policy_record(
            57,
            "policy_057",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_057"),
        ),
        indexed_policy_record(
            58,
            "policy_058",
            "committee_rotation",
            &id_hash("POLICY", "policy_058"),
        ),
        indexed_policy_record(
            59,
            "policy_059",
            "private_receipt",
            &id_hash("POLICY", "policy_059"),
        ),
        indexed_policy_record(
            60,
            "policy_060",
            "challenge_window",
            &id_hash("POLICY", "policy_060"),
        ),
        indexed_policy_record(
            61,
            "policy_061",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_061"),
        ),
        indexed_policy_record(
            62,
            "policy_062",
            "emergency_fallback",
            &id_hash("POLICY", "policy_062"),
        ),
        indexed_policy_record(
            63,
            "policy_063",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_063"),
        ),
        indexed_policy_record(
            64,
            "policy_064",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_064"),
        ),
        indexed_policy_record(
            65,
            "policy_065",
            "committee_rotation",
            &id_hash("POLICY", "policy_065"),
        ),
        indexed_policy_record(
            66,
            "policy_066",
            "private_receipt",
            &id_hash("POLICY", "policy_066"),
        ),
        indexed_policy_record(
            67,
            "policy_067",
            "challenge_window",
            &id_hash("POLICY", "policy_067"),
        ),
        indexed_policy_record(
            68,
            "policy_068",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_068"),
        ),
        indexed_policy_record(
            69,
            "policy_069",
            "emergency_fallback",
            &id_hash("POLICY", "policy_069"),
        ),
        indexed_policy_record(
            70,
            "policy_070",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_070"),
        ),
        indexed_policy_record(
            71,
            "policy_071",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_071"),
        ),
        indexed_policy_record(
            72,
            "policy_072",
            "committee_rotation",
            &id_hash("POLICY", "policy_072"),
        ),
        indexed_policy_record(
            73,
            "policy_073",
            "private_receipt",
            &id_hash("POLICY", "policy_073"),
        ),
        indexed_policy_record(
            74,
            "policy_074",
            "challenge_window",
            &id_hash("POLICY", "policy_074"),
        ),
        indexed_policy_record(
            75,
            "policy_075",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_075"),
        ),
        indexed_policy_record(
            76,
            "policy_076",
            "emergency_fallback",
            &id_hash("POLICY", "policy_076"),
        ),
        indexed_policy_record(
            77,
            "policy_077",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_077"),
        ),
        indexed_policy_record(
            78,
            "policy_078",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_078"),
        ),
        indexed_policy_record(
            79,
            "policy_079",
            "committee_rotation",
            &id_hash("POLICY", "policy_079"),
        ),
        indexed_policy_record(
            80,
            "policy_080",
            "private_receipt",
            &id_hash("POLICY", "policy_080"),
        ),
        indexed_policy_record(
            81,
            "policy_081",
            "challenge_window",
            &id_hash("POLICY", "policy_081"),
        ),
        indexed_policy_record(
            82,
            "policy_082",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_082"),
        ),
        indexed_policy_record(
            83,
            "policy_083",
            "emergency_fallback",
            &id_hash("POLICY", "policy_083"),
        ),
        indexed_policy_record(
            84,
            "policy_084",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_084"),
        ),
        indexed_policy_record(
            85,
            "policy_085",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_085"),
        ),
        indexed_policy_record(
            86,
            "policy_086",
            "committee_rotation",
            &id_hash("POLICY", "policy_086"),
        ),
        indexed_policy_record(
            87,
            "policy_087",
            "private_receipt",
            &id_hash("POLICY", "policy_087"),
        ),
        indexed_policy_record(
            88,
            "policy_088",
            "challenge_window",
            &id_hash("POLICY", "policy_088"),
        ),
        indexed_policy_record(
            89,
            "policy_089",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_089"),
        ),
        indexed_policy_record(
            90,
            "policy_090",
            "emergency_fallback",
            &id_hash("POLICY", "policy_090"),
        ),
        indexed_policy_record(
            91,
            "policy_091",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_091"),
        ),
        indexed_policy_record(
            92,
            "policy_092",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_092"),
        ),
        indexed_policy_record(
            93,
            "policy_093",
            "committee_rotation",
            &id_hash("POLICY", "policy_093"),
        ),
        indexed_policy_record(
            94,
            "policy_094",
            "private_receipt",
            &id_hash("POLICY", "policy_094"),
        ),
        indexed_policy_record(
            95,
            "policy_095",
            "challenge_window",
            &id_hash("POLICY", "policy_095"),
        ),
        indexed_policy_record(
            96,
            "policy_096",
            "da_witness_bundle",
            &id_hash("POLICY", "policy_096"),
        ),
        indexed_policy_record(
            97,
            "policy_097",
            "emergency_fallback",
            &id_hash("POLICY", "policy_097"),
        ),
        indexed_policy_record(
            98,
            "policy_098",
            "monero_header_commitment",
            &id_hash("POLICY", "policy_098"),
        ),
        indexed_policy_record(
            99,
            "policy_099",
            "pq_aggregate_signature",
            &id_hash("POLICY", "policy_099"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_validates_and_has_stable_roots() {
        let state = devnet().map_err(|err| format!("devnet error: {}", err));
        assert!(state.is_ok());
        if let Ok(state) = state {
            assert!(state.validate().is_ok());
            assert_eq!(state.config.chain_id, CHAIN_ID);
            assert_eq!(
                state.config.protocol_version,
                PQ_PRIVATE_BRIDGE_LIGHT_CLIENT_COMMITTEE_PROTOCOL_VERSION
            );
            assert!(!state.roots().state_root.is_empty());
            assert!(!state.state_root().is_empty());
            assert!(
                state.counters().active_committee_weight
                    >= threshold_weight(
                        state.counters().total_committee_weight,
                        state.config.safe_quorum_bps
                    )
            );
        }
    }

    #[test]
    fn policy_catalog_is_deterministic() {
        let first = policy_catalog_root();
        let second = policy_catalog_root();
        assert_eq!(first, second);
        assert_eq!(policy_catalog_records().len(), 100);
    }
}
