use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateWatchtowerReorgLiquidityInsuranceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_REORG_LIQUIDITY_INSURANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-watchtower-reorg-liquidity-insurance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_WATCHTOWER_REORG_LIQUIDITY_INSURANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const CHAIN_ID_LABEL: &str = "nebula-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-private-watchtower-reorg-liquidity-insurance-devnet";
pub const DEVNET_HEIGHT: u64 = 912_384;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ml-dsa-87+slh-dsa-shake-192f-reorg-liquidity-watchtower-v1";
pub const PQ_ENCRYPTION_SUITE: &str = "ml-kem-1024-private-evidence-bundle-v1";
pub const PRIVACY_EVIDENCE_SCHEME: &str = "roots-only-monero-watchtower-evidence-bundle-v1";
pub const LIQUIDITY_INSURANCE_SCHEME: &str = "private-defi-bridge-liquidity-insurance-policy-v1";
pub const FAST_WITHDRAWAL_COVERAGE_SCHEME: &str = "emergency-fast-withdrawal-coverage-v1";
pub const RESERVE_RECOVERY_SCHEME: &str = "private-reserve-recovery-claim-v1";
pub const FEE_SPONSOR_SCHEME: &str = "low-fee-private-watchtower-sponsor-pool-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-watchtower-slashing-evidence-root-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHTOWER_QUORUM: u16 = 5;
pub const DEFAULT_MIN_QUORUM_WEIGHT: u64 = 9;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const DEFAULT_REORG_ALERT_DEPTH: u64 = 12;
pub const DEFAULT_REORG_HALT_DEPTH: u64 = 32;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_FAST_WITHDRAWAL_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_MAX_FEE_SPONSOR_BPS: u64 = 7_500;
pub const DEFAULT_RESERVE_TARGET_BPS: u64 = 12_500;
pub const DEFAULT_MAX_POLICY_COVERAGE_UNITS: u64 = 50_000_000_000;
pub const DEFAULT_MAX_FAST_WITHDRAWAL_UNITS: u64 = 10_000_000_000;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_RISK_SMOOTHING_BPS: u64 = 2_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_OBSERVATIONS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_POLICIES: usize = 524_288;
pub const MAX_FAST_COVERAGES: usize = 524_288;
pub const MAX_RESERVE_CLAIMS: usize = 524_288;
pub const MAX_SPONSOR_POOLS: usize = 131_072;
pub const MAX_EVIDENCE_BUNDLES: usize = 1_048_576;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 1_048_576;
pub const MAX_RISK_SCORES: usize = 524_288;
pub const MAX_SLASHING_EVIDENCE: usize = 524_288;
pub const MAX_EVENTS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    StableTip,
    CandidateReorg,
    DeepReorg,
    LiquidityStress,
    BridgeExitDelay,
    ReserveShortfall,
    FeeSpike,
    PrivacySetRegression,
    SlashingSignal,
}

impl ObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableTip => "stable_tip",
            Self::CandidateReorg => "candidate_reorg",
            Self::DeepReorg => "deep_reorg",
            Self::LiquidityStress => "liquidity_stress",
            Self::BridgeExitDelay => "bridge_exit_delay",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::FeeSpike => "fee_spike",
            Self::PrivacySetRegression => "privacy_set_regression",
            Self::SlashingSignal => "slashing_signal",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::StableTip => 500,
            Self::CandidateReorg => 3_500,
            Self::DeepReorg => 9_000,
            Self::LiquidityStress => 5_500,
            Self::BridgeExitDelay => 4_500,
            Self::ReserveShortfall => 8_000,
            Self::FeeSpike => 2_500,
            Self::PrivacySetRegression => 6_500,
            Self::SlashingSignal => 7_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    Encrypted,
    PrivacyChecked,
    QuorumPending,
    Attested,
    Actionable,
    Dismissed,
    Expired,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Encrypted => "encrypted",
            Self::PrivacyChecked => "privacy_checked",
            Self::QuorumPending => "quorum_pending",
            Self::Attested => "attested",
            Self::Actionable => "actionable",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgAttestationKind {
    ForkChoice,
    HeaderContinuity,
    DepthBound,
    ExitRollback,
    ReserveImpact,
    LiquidityImpact,
    EmergencyHalt,
}

impl ReorgAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForkChoice => "fork_choice",
            Self::HeaderContinuity => "header_continuity",
            Self::DepthBound => "depth_bound",
            Self::ExitRollback => "exit_rollback",
            Self::ReserveImpact => "reserve_impact",
            Self::LiquidityImpact => "liquidity_impact",
            Self::EmergencyHalt => "emergency_halt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Superseded,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    BridgeLiquidity,
    PrivateDefiRoute,
    MarketMakerBackstop,
    EmergencyExit,
    ReserveRecovery,
}

impl PolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::PrivateDefiRoute => "private_defi_route",
            Self::MarketMakerBackstop => "market_maker_backstop",
            Self::EmergencyExit => "emergency_exit",
            Self::ReserveRecovery => "reserve_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Quoted,
    Active,
    Locked,
    Claimed,
    Paid,
    Denied,
    Expired,
    Cancelled,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Claimed => "claimed",
            Self::Paid => "paid",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::Active | Self::Locked | Self::Claimed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastWithdrawalStatus {
    Requested,
    Covered,
    SponsorMatched,
    Executed,
    Settled,
    Expired,
    Denied,
}

impl FastWithdrawalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Covered => "covered",
            Self::SponsorMatched => "sponsor_matched",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Denied => "denied",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveClaimStatus {
    Committed,
    EvidencePending,
    QuorumAccepted,
    RecoveryQueued,
    Paid,
    Denied,
    Expired,
}

impl ReserveClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::EvidencePending => "evidence_pending",
            Self::QuorumAccepted => "quorum_accepted",
            Self::RecoveryQueued => "recovery_queued",
            Self::Paid => "paid",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Open,
    Throttled,
    Exhausted,
    Paused,
    Closed,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleKind {
    PrivateObservation,
    ReorgProof,
    LiquidityProof,
    ReserveProof,
    FeeSponsorProof,
    SlashingProof,
}

impl EvidenceBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateObservation => "private_observation",
            Self::ReorgProof => "reorg_proof",
            Self::LiquidityProof => "liquidity_proof",
            Self::ReserveProof => "reserve_proof",
            Self::FeeSponsorProof => "fee_sponsor_proof",
            Self::SlashingProof => "slashing_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleStatus {
    Committed,
    Encrypted,
    NullifierChecked,
    QuorumLinked,
    Disclosed,
    Rejected,
}

impl EvidenceBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Encrypted => "encrypted",
            Self::NullifierChecked => "nullifier_checked",
            Self::QuorumLinked => "quorum_linked",
            Self::Disclosed => "disclosed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ObservationRecorded,
    AttestationAccepted,
    PolicyActivated,
    FastWithdrawalCovered,
    ReserveClaimQueued,
    SponsorDebit,
    EvidenceBundled,
    RiskScored,
    SlashingFiled,
    SettlementPaid,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObservationRecorded => "observation_recorded",
            Self::AttestationAccepted => "attestation_accepted",
            Self::PolicyActivated => "policy_activated",
            Self::FastWithdrawalCovered => "fast_withdrawal_covered",
            Self::ReserveClaimQueued => "reserve_claim_queued",
            Self::SponsorDebit => "sponsor_debit",
            Self::EvidenceBundled => "evidence_bundled",
            Self::RiskScored => "risk_scored",
            Self::SlashingFiled => "slashing_filed",
            Self::SettlementPaid => "settlement_paid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingKind {
    FalseObservation,
    WithheldReorg,
    ForgedAttestation,
    DuplicateNullifier,
    ReserveMisreport,
    LiquidityGriefing,
    PrivacyLeak,
}

impl SlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseObservation => "false_observation",
            Self::WithheldReorg => "withheld_reorg",
            Self::ForgedAttestation => "forged_attestation",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::ReserveMisreport => "reserve_misreport",
            Self::LiquidityGriefing => "liquidity_griefing",
            Self::PrivacyLeak => "privacy_leak",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Filed,
    EvidenceLinked,
    QuorumAccepted,
    Appealed,
    Slashed,
    Dismissed,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceLinked => "evidence_linked",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Appealed => "appealed",
            Self::Slashed => "slashed",
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Normal,
    Watch,
    Elevated,
    Throttled,
    Emergency,
    Halted,
}

impl RiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Throttled => "throttled",
            Self::Emergency => "emergency",
            Self::Halted => "halted",
        }
    }

    pub fn score_floor_bps(self) -> u64 {
        match self {
            Self::Normal => 0,
            Self::Watch => 2_000,
            Self::Elevated => 4_000,
            Self::Throttled => 6_500,
            Self::Emergency => 8_500,
            Self::Halted => 10_000,
        }
    }
    pub fn allows_new_policy(self) -> bool {
        matches!(self, Self::Normal | Self::Watch | Self::Elevated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub committee_id: String,
    pub min_pq_security_bits: u16,
    pub min_watchtower_quorum: u16,
    pub min_quorum_weight: u64,
    pub min_privacy_set_size: u64,
    pub monero_finality_depth: u64,
    pub reorg_alert_depth: u64,
    pub reorg_halt_depth: u64,
    pub policy_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub fast_withdrawal_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub low_fee_target_micro_units: u64,
    pub max_fee_sponsor_bps: u64,
    pub reserve_target_bps: u64,
    pub max_policy_coverage_units: u64,
    pub max_fast_withdrawal_units: u64,
    pub max_slash_bps: u64,
    pub risk_smoothing_bps: u64,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "committee_id": self.committee_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watchtower_quorum": self.min_watchtower_quorum,
            "min_quorum_weight": self.min_quorum_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_finality_depth": self.monero_finality_depth,
            "reorg_alert_depth": self.reorg_alert_depth,
            "reorg_halt_depth": self.reorg_halt_depth,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "fast_withdrawal_ttl_blocks": self.fast_withdrawal_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "max_fee_sponsor_bps": self.max_fee_sponsor_bps,
            "reserve_target_bps": self.reserve_target_bps,
            "max_policy_coverage_units": self.max_policy_coverage_units,
            "max_fast_withdrawal_units": self.max_fast_withdrawal_units,
            "max_slash_bps": self.max_slash_bps,
            "risk_smoothing_bps": self.risk_smoothing_bps,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_observation_seq: u64,
    pub next_attestation_seq: u64,
    pub next_policy_seq: u64,
    pub next_fast_withdrawal_seq: u64,
    pub next_reserve_claim_seq: u64,
    pub next_sponsor_pool_seq: u64,
    pub next_evidence_bundle_seq: u64,
    pub next_receipt_seq: u64,
    pub next_risk_score_seq: u64,
    pub next_slashing_seq: u64,
    pub next_event_seq: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "next_observation_seq": self.next_observation_seq,
            "next_attestation_seq": self.next_attestation_seq,
            "next_policy_seq": self.next_policy_seq,
            "next_fast_withdrawal_seq": self.next_fast_withdrawal_seq,
            "next_reserve_claim_seq": self.next_reserve_claim_seq,
            "next_sponsor_pool_seq": self.next_sponsor_pool_seq,
            "next_evidence_bundle_seq": self.next_evidence_bundle_seq,
            "next_receipt_seq": self.next_receipt_seq,
            "next_risk_score_seq": self.next_risk_score_seq,
            "next_slashing_seq": self.next_slashing_seq,
            "next_event_seq": self.next_event_seq,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWatchtowerObservationRequest {
    pub watchtower_id: String,
    pub observation_kind: ObservationKind,
    pub monero_height: u64,
    pub monero_tip_hash: String,
    pub l2_height: u64,
    pub l2_state_root: String,
    pub bridge_lane_id: String,
    pub subject_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_signature_root: String,
    pub reported_at_height: u64,
}

impl PrivateWatchtowerObservationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "watchtower_id": self.watchtower_id,
            "observation_kind": self.observation_kind.as_str(),
            "monero_height": self.monero_height,
            "monero_tip_hash": self.monero_tip_hash,
            "l2_height": self.l2_height,
            "l2_state_root": self.l2_state_root,
            "bridge_lane_id": self.bridge_lane_id,
            "subject_commitment": self.subject_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_root": self.pq_signature_root,
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PRIVATEWATCHTOWEROBSERVATIONREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWatchtowerObservation {
    pub observation_id: String,
    pub watchtower_id: String,
    pub observation_kind: ObservationKind,
    pub status: ObservationStatus,
    pub monero_height: u64,
    pub monero_tip_hash: String,
    pub l2_height: u64,
    pub l2_state_root: String,
    pub bridge_lane_id: String,
    pub subject_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_signature_root: String,
    pub risk_hint_bps: u64,
    pub reported_at_height: u64,
    pub updated_at_height: u64,
}

impl PrivateWatchtowerObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "watchtower_id": self.watchtower_id,
            "observation_kind": self.observation_kind.as_str(),
            "status": self.status.as_str(),
            "monero_height": self.monero_height,
            "monero_tip_hash": self.monero_tip_hash,
            "l2_height": self.l2_height,
            "l2_state_root": self.l2_state_root,
            "bridge_lane_id": self.bridge_lane_id,
            "subject_commitment": self.subject_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_root": self.pq_signature_root,
            "risk_hint_bps": self.risk_hint_bps,
            "reported_at_height": self.reported_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PRIVATEWATCHTOWEROBSERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReorgAttestationRequest {
    pub observation_id: String,
    pub attestor_id: String,
    pub attestation_kind: ReorgAttestationKind,
    pub fork_depth: u64,
    pub canonical_tip_root: String,
    pub contested_tip_root: String,
    pub liquidity_impact_units: u64,
    pub reserve_impact_units: u64,
    pub quorum_weight: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub signature_root: String,
    pub submitted_at_height: u64,
}

impl PqReorgAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "attestor_id": self.attestor_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "fork_depth": self.fork_depth,
            "canonical_tip_root": self.canonical_tip_root,
            "contested_tip_root": self.contested_tip_root,
            "liquidity_impact_units": self.liquidity_impact_units,
            "reserve_impact_units": self.reserve_impact_units,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PQREORGATTESTATIONREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReorgAttestation {
    pub attestation_id: String,
    pub observation_id: String,
    pub attestor_id: String,
    pub attestation_kind: ReorgAttestationKind,
    pub status: AttestationStatus,
    pub fork_depth: u64,
    pub canonical_tip_root: String,
    pub contested_tip_root: String,
    pub liquidity_impact_units: u64,
    pub reserve_impact_units: u64,
    pub quorum_weight: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub signature_root: String,
    pub submitted_at_height: u64,
    pub accepted_at_height: u64,
}

impl PqReorgAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "observation_id": self.observation_id,
            "attestor_id": self.attestor_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "status": self.status.as_str(),
            "fork_depth": self.fork_depth,
            "canonical_tip_root": self.canonical_tip_root,
            "contested_tip_root": self.contested_tip_root,
            "liquidity_impact_units": self.liquidity_impact_units,
            "reserve_impact_units": self.reserve_impact_units,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "submitted_at_height": self.submitted_at_height,
            "accepted_at_height": self.accepted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PQREORGATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityInsurancePolicyRequest {
    pub owner_commitment: String,
    pub policy_kind: PolicyKind,
    pub route_commitment: String,
    pub coverage_units: u64,
    pub premium_units: u64,
    pub deductible_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub evidence_bundle_id: String,
    pub starts_at_height: u64,
}

impl LiquidityInsurancePolicyRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "owner_commitment": self.owner_commitment,
            "policy_kind": self.policy_kind.as_str(),
            "route_commitment": self.route_commitment,
            "coverage_units": self.coverage_units,
            "premium_units": self.premium_units,
            "deductible_bps": self.deductible_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "evidence_bundle_id": self.evidence_bundle_id,
            "starts_at_height": self.starts_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("LIQUIDITYINSURANCEPOLICYREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityInsurancePolicy {
    pub policy_id: String,
    pub owner_commitment: String,
    pub policy_kind: PolicyKind,
    pub status: PolicyStatus,
    pub route_commitment: String,
    pub coverage_units: u64,
    pub premium_units: u64,
    pub deductible_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub evidence_bundle_id: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub claimed_units: u64,
    pub paid_units: u64,
}

impl LiquidityInsurancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "owner_commitment": self.owner_commitment,
            "policy_kind": self.policy_kind.as_str(),
            "status": self.status.as_str(),
            "route_commitment": self.route_commitment,
            "coverage_units": self.coverage_units,
            "premium_units": self.premium_units,
            "deductible_bps": self.deductible_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "evidence_bundle_id": self.evidence_bundle_id,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "claimed_units": self.claimed_units,
            "paid_units": self.paid_units,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("LIQUIDITYINSURANCEPOLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalCoverageRequest {
    pub policy_id: String,
    pub withdrawal_commitment: String,
    pub recipient_commitment: String,
    pub coverage_units: u64,
    pub sponsor_pool_id: String,
    pub max_fee_micro_units: u64,
    pub evidence_bundle_id: String,
    pub requested_at_height: u64,
}

impl FastWithdrawalCoverageRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "withdrawal_commitment": self.withdrawal_commitment,
            "recipient_commitment": self.recipient_commitment,
            "coverage_units": self.coverage_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "evidence_bundle_id": self.evidence_bundle_id,
            "requested_at_height": self.requested_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("FASTWITHDRAWALCOVERAGEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalCoverage {
    pub coverage_id: String,
    pub policy_id: String,
    pub withdrawal_commitment: String,
    pub recipient_commitment: String,
    pub status: FastWithdrawalStatus,
    pub coverage_units: u64,
    pub sponsor_pool_id: String,
    pub max_fee_micro_units: u64,
    pub evidence_bundle_id: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
}

impl FastWithdrawalCoverage {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "coverage_id": self.coverage_id,
            "policy_id": self.policy_id,
            "withdrawal_commitment": self.withdrawal_commitment,
            "recipient_commitment": self.recipient_commitment,
            "status": self.status.as_str(),
            "coverage_units": self.coverage_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "evidence_bundle_id": self.evidence_bundle_id,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("FASTWITHDRAWALCOVERAGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRecoveryClaimRequest {
    pub policy_id: String,
    pub claimant_commitment: String,
    pub reserve_epoch_root: String,
    pub loss_commitment: String,
    pub claim_units: u64,
    pub evidence_bundle_id: String,
    pub observation_id: String,
    pub submitted_at_height: u64,
}

impl ReserveRecoveryClaimRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "claimant_commitment": self.claimant_commitment,
            "reserve_epoch_root": self.reserve_epoch_root,
            "loss_commitment": self.loss_commitment,
            "claim_units": self.claim_units,
            "evidence_bundle_id": self.evidence_bundle_id,
            "observation_id": self.observation_id,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("RESERVERECOVERYCLAIMREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRecoveryClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub claimant_commitment: String,
    pub status: ReserveClaimStatus,
    pub reserve_epoch_root: String,
    pub loss_commitment: String,
    pub claim_units: u64,
    pub approved_units: u64,
    pub evidence_bundle_id: String,
    pub observation_id: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub paid_at_height: u64,
}

impl ReserveRecoveryClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "claimant_commitment": self.claimant_commitment,
            "status": self.status.as_str(),
            "reserve_epoch_root": self.reserve_epoch_root,
            "loss_commitment": self.loss_commitment,
            "claim_units": self.claim_units,
            "approved_units": self.approved_units,
            "evidence_bundle_id": self.evidence_bundle_id,
            "observation_id": self.observation_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "paid_at_height": self.paid_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("RESERVERECOVERYCLAIM", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorPoolRequest {
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub max_sponsor_bps: u64,
    pub fee_floor_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}

impl FeeSponsorPoolRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "max_sponsor_bps": self.max_sponsor_bps,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("FEESPONSORPOOLREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub status: SponsorPoolStatus,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_sponsor_bps: u64,
    pub fee_floor_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl FeeSponsorPool {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "max_sponsor_bps": self.max_sponsor_bps,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("FEESPONSORPOOL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyEvidenceBundleRequest {
    pub bundle_kind: EvidenceBundleKind,
    pub subject_id: String,
    pub ciphertext_root: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub disclosure_root: String,
    pub privacy_set_size: u64,
    pub pq_encryption_root: String,
    pub created_at_height: u64,
}

impl PrivacyEvidenceBundleRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "bundle_kind": self.bundle_kind.as_str(),
            "subject_id": self.subject_id,
            "ciphertext_root": self.ciphertext_root,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_root": self.disclosure_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_encryption_root": self.pq_encryption_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PRIVACYEVIDENCEBUNDLEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyEvidenceBundle {
    pub bundle_id: String,
    pub bundle_kind: EvidenceBundleKind,
    pub subject_id: String,
    pub status: EvidenceBundleStatus,
    pub ciphertext_root: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub disclosure_root: String,
    pub privacy_set_size: u64,
    pub pq_encryption_root: String,
    pub created_at_height: u64,
    pub linked_at_height: u64,
}

impl PrivacyEvidenceBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "bundle_kind": self.bundle_kind.as_str(),
            "subject_id": self.subject_id,
            "status": self.status.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_root": self.disclosure_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_encryption_root": self.pq_encryption_root,
            "created_at_height": self.created_at_height,
            "linked_at_height": self.linked_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PRIVACYEVIDENCEBUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub evidence_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "evidence_root": self.evidence_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SETTLEMENTRECEIPTREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub evidence_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "evidence_root": self.evidence_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SETTLEMENTRECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScoreRequest {
    pub scope_id: String,
    pub observation_id: String,
    pub policy_id: String,
    pub liquidity_depth_units: u64,
    pub insured_exposure_units: u64,
    pub reserve_units: u64,
    pub fee_pressure_bps: u64,
    pub reorg_depth: u64,
    pub privacy_set_size: u64,
    pub scored_at_height: u64,
}

impl RiskScoreRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scope_id": self.scope_id,
            "observation_id": self.observation_id,
            "policy_id": self.policy_id,
            "liquidity_depth_units": self.liquidity_depth_units,
            "insured_exposure_units": self.insured_exposure_units,
            "reserve_units": self.reserve_units,
            "fee_pressure_bps": self.fee_pressure_bps,
            "reorg_depth": self.reorg_depth,
            "privacy_set_size": self.privacy_set_size,
            "scored_at_height": self.scored_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("RISKSCOREREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScore {
    pub risk_score_id: String,
    pub scope_id: String,
    pub observation_id: String,
    pub policy_id: String,
    pub band: RiskBand,
    pub score_bps: u64,
    pub liquidity_depth_units: u64,
    pub insured_exposure_units: u64,
    pub reserve_units: u64,
    pub fee_pressure_bps: u64,
    pub reorg_depth: u64,
    pub privacy_set_size: u64,
    pub scored_at_height: u64,
}

impl RiskScore {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "risk_score_id": self.risk_score_id,
            "scope_id": self.scope_id,
            "observation_id": self.observation_id,
            "policy_id": self.policy_id,
            "band": self.band.as_str(),
            "score_bps": self.score_bps,
            "liquidity_depth_units": self.liquidity_depth_units,
            "insured_exposure_units": self.insured_exposure_units,
            "reserve_units": self.reserve_units,
            "fee_pressure_bps": self.fee_pressure_bps,
            "reorg_depth": self.reorg_depth,
            "privacy_set_size": self.privacy_set_size,
            "scored_at_height": self.scored_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("RISKSCORE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceRequest {
    pub watchtower_id: String,
    pub slashing_kind: SlashingKind,
    pub observation_id: String,
    pub attestation_id: String,
    pub evidence_bundle_id: String,
    pub loss_units: u64,
    pub recommended_slash_bps: u64,
    pub filed_by_commitment: String,
    pub filed_at_height: u64,
}

impl SlashingEvidenceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "watchtower_id": self.watchtower_id,
            "slashing_kind": self.slashing_kind.as_str(),
            "observation_id": self.observation_id,
            "attestation_id": self.attestation_id,
            "evidence_bundle_id": self.evidence_bundle_id,
            "loss_units": self.loss_units,
            "recommended_slash_bps": self.recommended_slash_bps,
            "filed_by_commitment": self.filed_by_commitment,
            "filed_at_height": self.filed_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SLASHINGEVIDENCEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub slashing_id: String,
    pub watchtower_id: String,
    pub slashing_kind: SlashingKind,
    pub status: SlashingStatus,
    pub observation_id: String,
    pub attestation_id: String,
    pub evidence_bundle_id: String,
    pub loss_units: u64,
    pub recommended_slash_bps: u64,
    pub filed_by_commitment: String,
    pub filed_at_height: u64,
    pub resolved_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "slashing_id": self.slashing_id,
            "watchtower_id": self.watchtower_id,
            "slashing_kind": self.slashing_kind.as_str(),
            "status": self.status.as_str(),
            "observation_id": self.observation_id,
            "attestation_id": self.attestation_id,
            "evidence_bundle_id": self.evidence_bundle_id,
            "loss_units": self.loss_units,
            "recommended_slash_bps": self.recommended_slash_bps,
            "filed_by_commitment": self.filed_by_commitment,
            "filed_at_height": self.filed_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SLASHINGEVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("RUNTIMEEVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub observation_root: String,
    pub attestation_root: String,
    pub policy_root: String,
    pub fast_withdrawal_root: String,
    pub reserve_claim_root: String,
    pub sponsor_pool_root: String,
    pub evidence_bundle_root: String,
    pub settlement_receipt_root: String,
    pub risk_score_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "observation_root": self.observation_root,
            "attestation_root": self.attestation_root,
            "policy_root": self.policy_root,
            "fast_withdrawal_root": self.fast_withdrawal_root,
            "reserve_claim_root": self.reserve_claim_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "evidence_bundle_root": self.evidence_bundle_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "risk_score_root": self.risk_score_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "event_root": self.event_root,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub observations: BTreeMap<String, PrivateWatchtowerObservation>,
    pub used_observation_nullifiers: BTreeSet<String>,
    pub attestations: BTreeMap<String, PqReorgAttestation>,
    pub policies: BTreeMap<String, LiquidityInsurancePolicy>,
    pub fast_coverages: BTreeMap<String, FastWithdrawalCoverage>,
    pub reserve_claims: BTreeMap<String, ReserveRecoveryClaim>,
    pub sponsor_pools: BTreeMap<String, FeeSponsorPool>,
    pub evidence_bundles: BTreeMap<String, PrivacyEvidenceBundle>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub risk_scores: BTreeMap<String, RiskScore>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watchtower_quorum: DEFAULT_MIN_WATCHTOWER_QUORUM,
            min_quorum_weight: DEFAULT_MIN_QUORUM_WEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            monero_finality_depth: DEFAULT_MONERO_FINALITY_DEPTH,
            reorg_alert_depth: DEFAULT_REORG_ALERT_DEPTH,
            reorg_halt_depth: DEFAULT_REORG_HALT_DEPTH,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            claim_window_blocks: DEFAULT_CLAIM_WINDOW_BLOCKS,
            fast_withdrawal_ttl_blocks: DEFAULT_FAST_WITHDRAWAL_TTL_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            max_fee_sponsor_bps: DEFAULT_MAX_FEE_SPONSOR_BPS,
            reserve_target_bps: DEFAULT_RESERVE_TARGET_BPS,
            max_policy_coverage_units: DEFAULT_MAX_POLICY_COVERAGE_UNITS,
            max_fast_withdrawal_units: DEFAULT_MAX_FAST_WITHDRAWAL_UNITS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            risk_smoothing_bps: DEFAULT_RISK_SMOOTHING_BPS,
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            next_observation_seq: 1,
            next_attestation_seq: 1,
            next_policy_seq: 1,
            next_fast_withdrawal_seq: 1,
            next_reserve_claim_seq: 1,
            next_sponsor_pool_seq: 1,
            next_evidence_bundle_seq: 1,
            next_receipt_seq: 1,
            next_risk_score_seq: 1,
            next_slashing_seq: 1,
            next_event_seq: 1,
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            observations: BTreeMap::new(),
            used_observation_nullifiers: BTreeSet::new(),
            attestations: BTreeMap::new(),
            policies: BTreeMap::new(),
            fast_coverages: BTreeMap::new(),
            reserve_claims: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            evidence_bundles: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            risk_scores: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            observation_root: map_root("OBSERVATION", &self.observations),
            attestation_root: map_root("ATTESTATION", &self.attestations),
            policy_root: map_root("POLICY", &self.policies),
            fast_withdrawal_root: map_root("FAST-WITHDRAWAL", &self.fast_coverages),
            reserve_claim_root: map_root("RESERVE-CLAIM", &self.reserve_claims),
            sponsor_pool_root: map_root("SPONSOR-POOL", &self.sponsor_pools),
            evidence_bundle_root: map_root("EVIDENCE-BUNDLE", &self.evidence_bundles),
            settlement_receipt_root: map_root("SETTLEMENT-RECEIPT", &self.settlement_receipts),
            risk_score_root: map_root("RISK-SCORE", &self.risk_scores),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence),
            event_root: map_root("EVENT", &self.events),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID_LABEL,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "pq_encryption_suite": PQ_ENCRYPTION_SUITE,
            "privacy_evidence_scheme": PRIVACY_EVIDENCE_SCHEME,
            "liquidity_insurance_scheme": LIQUIDITY_INSURANCE_SCHEME,
            "fast_withdrawal_coverage_scheme": FAST_WITHDRAWAL_COVERAGE_SCHEME,
            "reserve_recovery_scheme": RESERVE_RECOVERY_SCHEME,
            "fee_sponsor_scheme": FEE_SPONSOR_SCHEME,
            "slashing_evidence_scheme": SLASHING_EVIDENCE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        runtime_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn push_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        payload_root: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(self.events.len(), MAX_EVENTS, "events")?;
        let event_id = runtime_sequence_id(
            "event",
            self.counters.next_event_seq,
            &[subject_id, payload_root],
        );
        self.counters.next_event_seq = self.counters.next_event_seq.saturating_add(1);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root.to_string(),
            height,
        };
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn record_private_watchtower_observation(
        &mut self,
        request: PrivateWatchtowerObservationRequest,
    ) -> Result<String> {
        ensure_capacity(self.observations.len(), MAX_OBSERVATIONS, "observations")?;
        ensure_nonempty("watchtower_id", &request.watchtower_id)?;
        ensure_nonempty("encrypted_payload_root", &request.encrypted_payload_root)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        if self
            .used_observation_nullifiers
            .contains(&request.nullifier)
        {
            return Err("observation nullifier already used".to_string());
        }
        let risk_hint_bps = clamp_bps(
            request.observation_kind.risk_weight_bps()
                + privacy_penalty_bps(request.privacy_set_size, self.config.min_privacy_set_size),
        );
        let observation_id = observation_id(&request);
        let observation = PrivateWatchtowerObservation {
            observation_id: observation_id.clone(),
            watchtower_id: request.watchtower_id,
            observation_kind: request.observation_kind,
            status: ObservationStatus::Encrypted,
            monero_height: request.monero_height,
            monero_tip_hash: request.monero_tip_hash,
            l2_height: request.l2_height,
            l2_state_root: request.l2_state_root,
            bridge_lane_id: request.bridge_lane_id,
            subject_commitment: request.subject_commitment,
            encrypted_payload_root: request.encrypted_payload_root,
            nullifier: request.nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_signature_root: request.pq_signature_root,
            risk_hint_bps,
            reported_at_height: request.reported_at_height,
            updated_at_height: request.reported_at_height,
        };
        let root = observation.record_root();
        self.used_observation_nullifiers.insert(request.nullifier);
        self.observations
            .insert(observation_id.clone(), observation);
        self.push_event(
            "private_watchtower_observation_recorded",
            &observation_id,
            &root,
            request.reported_at_height,
        )?;
        Ok(observation_id)
    }

    pub fn attest_pq_reorg(&mut self, request: PqReorgAttestationRequest) -> Result<String> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_nonempty("observation_id", &request.observation_id)?;
        ensure_min(
            "pq_security_bits",
            request.pq_security_bits as u64,
            self.config.min_pq_security_bits as u64,
        )?;
        let observation = self
            .observations
            .get_mut(&request.observation_id)
            .ok_or_else(|| "unknown observation".to_string())?;
        observation.status = if request.quorum_weight >= self.config.min_quorum_weight {
            ObservationStatus::Attested
        } else {
            ObservationStatus::QuorumPending
        };
        observation.updated_at_height = request.submitted_at_height;
        let status = if request.quorum_weight >= self.config.min_quorum_weight {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::WeakQuorum
        };
        let attestation_id = attestation_id(&request);
        let attestation = PqReorgAttestation {
            attestation_id: attestation_id.clone(),
            observation_id: request.observation_id,
            attestor_id: request.attestor_id,
            attestation_kind: request.attestation_kind,
            status,
            fork_depth: request.fork_depth,
            canonical_tip_root: request.canonical_tip_root,
            contested_tip_root: request.contested_tip_root,
            liquidity_impact_units: request.liquidity_impact_units,
            reserve_impact_units: request.reserve_impact_units,
            quorum_weight: request.quorum_weight,
            pq_security_bits: request.pq_security_bits,
            attestation_root: request.attestation_root,
            signature_root: request.signature_root,
            submitted_at_height: request.submitted_at_height,
            accepted_at_height: request.submitted_at_height,
        };
        let root = attestation.record_root();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event(
            "pq_reorg_attestation_recorded",
            &attestation_id,
            &root,
            request.submitted_at_height,
        )?;
        Ok(attestation_id)
    }

    pub fn open_liquidity_insurance_policy(
        &mut self,
        request: LiquidityInsurancePolicyRequest,
    ) -> Result<String> {
        ensure_capacity(self.policies.len(), MAX_POLICIES, "policies")?;
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_max(
            "coverage_units",
            request.coverage_units,
            self.config.max_policy_coverage_units,
        )?;
        ensure_max("deductible_bps", request.deductible_bps, MAX_BPS)?;
        ensure_max("max_fee_bps", request.max_fee_bps, MAX_BPS)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        let policy_id = policy_id(&request);
        let policy = LiquidityInsurancePolicy {
            policy_id: policy_id.clone(),
            owner_commitment: request.owner_commitment,
            policy_kind: request.policy_kind,
            status: PolicyStatus::Active,
            route_commitment: request.route_commitment,
            coverage_units: request.coverage_units,
            premium_units: request.premium_units,
            deductible_bps: request.deductible_bps,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            evidence_bundle_id: request.evidence_bundle_id,
            starts_at_height: request.starts_at_height,
            expires_at_height: request
                .starts_at_height
                .saturating_add(self.config.policy_ttl_blocks),
            claimed_units: 0,
            paid_units: 0,
        };
        let root = policy.record_root();
        self.policies.insert(policy_id.clone(), policy);
        self.push_event(
            "liquidity_insurance_policy_opened",
            &policy_id,
            &root,
            request.starts_at_height,
        )?;
        Ok(policy_id)
    }

    pub fn cover_fast_withdrawal(
        &mut self,
        request: FastWithdrawalCoverageRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.fast_coverages.len(),
            MAX_FAST_COVERAGES,
            "fast coverages",
        )?;
        let policy = self
            .policies
            .get_mut(&request.policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        if !policy.status.open() {
            return Err("policy is not open".to_string());
        }
        ensure_max(
            "coverage_units",
            request.coverage_units,
            self.config.max_fast_withdrawal_units,
        )?;
        if policy.claimed_units.saturating_add(request.coverage_units) > policy.coverage_units {
            return Err("coverage exceeds policy capacity".to_string());
        }
        policy.claimed_units = policy.claimed_units.saturating_add(request.coverage_units);
        policy.status = PolicyStatus::Locked;
        let coverage_id = fast_withdrawal_coverage_id(&request);
        let coverage = FastWithdrawalCoverage {
            coverage_id: coverage_id.clone(),
            policy_id: request.policy_id,
            withdrawal_commitment: request.withdrawal_commitment,
            recipient_commitment: request.recipient_commitment,
            status: FastWithdrawalStatus::Covered,
            coverage_units: request.coverage_units,
            sponsor_pool_id: request.sponsor_pool_id,
            max_fee_micro_units: request.max_fee_micro_units,
            evidence_bundle_id: request.evidence_bundle_id,
            requested_at_height: request.requested_at_height,
            expires_at_height: request
                .requested_at_height
                .saturating_add(self.config.fast_withdrawal_ttl_blocks),
            settled_at_height: 0,
        };
        let root = coverage.record_root();
        self.fast_coverages.insert(coverage_id.clone(), coverage);
        self.push_event(
            "fast_withdrawal_covered",
            &coverage_id,
            &root,
            request.requested_at_height,
        )?;
        Ok(coverage_id)
    }

    pub fn submit_reserve_recovery_claim(
        &mut self,
        request: ReserveRecoveryClaimRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.reserve_claims.len(),
            MAX_RESERVE_CLAIMS,
            "reserve claims",
        )?;
        let policy = self
            .policies
            .get_mut(&request.policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        if !policy.status.open() {
            return Err("policy is not open".to_string());
        }
        if policy.claimed_units.saturating_add(request.claim_units) > policy.coverage_units {
            return Err("claim exceeds policy capacity".to_string());
        }
        policy.claimed_units = policy.claimed_units.saturating_add(request.claim_units);
        policy.status = PolicyStatus::Claimed;
        let claim_id = reserve_recovery_claim_id(&request);
        let claim = ReserveRecoveryClaim {
            claim_id: claim_id.clone(),
            policy_id: request.policy_id,
            claimant_commitment: request.claimant_commitment,
            status: ReserveClaimStatus::EvidencePending,
            reserve_epoch_root: request.reserve_epoch_root,
            loss_commitment: request.loss_commitment,
            claim_units: request.claim_units,
            approved_units: 0,
            evidence_bundle_id: request.evidence_bundle_id,
            observation_id: request.observation_id,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.claim_window_blocks),
            paid_at_height: 0,
        };
        let root = claim.record_root();
        self.reserve_claims.insert(claim_id.clone(), claim);
        self.push_event(
            "reserve_recovery_claim_submitted",
            &claim_id,
            &root,
            request.submitted_at_height,
        )?;
        Ok(claim_id)
    }

    pub fn open_fee_sponsor_pool(&mut self, request: FeeSponsorPoolRequest) -> Result<String> {
        ensure_capacity(self.sponsor_pools.len(), MAX_SPONSOR_POOLS, "sponsor pools")?;
        ensure_max(
            "max_sponsor_bps",
            request.max_sponsor_bps,
            self.config.max_fee_sponsor_bps,
        )?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        let pool_id = fee_sponsor_pool_id(&request);
        let pool = FeeSponsorPool {
            pool_id: pool_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            lane_id: request.lane_id,
            status: SponsorPoolStatus::Open,
            budget_units: request.budget_units,
            spent_units: 0,
            max_sponsor_bps: request.max_sponsor_bps,
            fee_floor_micro_units: request.fee_floor_micro_units,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
        };
        let root = pool.record_root();
        self.sponsor_pools.insert(pool_id.clone(), pool);
        self.push_event(
            "fee_sponsor_pool_opened",
            &pool_id,
            &root,
            request.opened_at_height,
        )?;
        Ok(pool_id)
    }

    pub fn debit_fee_sponsor_pool(
        &mut self,
        pool_id: &str,
        subject_id: &str,
        amount_units: u64,
        height: u64,
    ) -> Result<String> {
        let pool = self
            .sponsor_pools
            .get_mut(pool_id)
            .ok_or_else(|| "unknown sponsor pool".to_string())?;
        if pool.status != SponsorPoolStatus::Open {
            return Err("sponsor pool is not open".to_string());
        }
        if pool.spent_units.saturating_add(amount_units) > pool.budget_units {
            pool.status = SponsorPoolStatus::Exhausted;
            return Err("sponsor pool exhausted".to_string());
        }
        pool.spent_units = pool.spent_units.saturating_add(amount_units);
        pool.updated_at_height = height;
        if pool.spent_units == pool.budget_units {
            pool.status = SponsorPoolStatus::Exhausted;
        }
        let request = SettlementReceiptRequest {
            receipt_kind: ReceiptKind::SponsorDebit,
            subject_id: subject_id.to_string(),
            amount_units,
            fee_units: 0,
            state_root_before: String::new(),
            state_root_after: self.state_root(),
            evidence_root: pool_id.to_string(),
            settled_at_height: height,
        };
        self.record_settlement_receipt(request)
    }

    pub fn commit_privacy_evidence_bundle(
        &mut self,
        request: PrivacyEvidenceBundleRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.evidence_bundles.len(),
            MAX_EVIDENCE_BUNDLES,
            "evidence bundles",
        )?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        let bundle_id = privacy_evidence_bundle_id(&request);
        let bundle = PrivacyEvidenceBundle {
            bundle_id: bundle_id.clone(),
            bundle_kind: request.bundle_kind,
            subject_id: request.subject_id,
            status: EvidenceBundleStatus::Encrypted,
            ciphertext_root: request.ciphertext_root,
            commitment_root: request.commitment_root,
            nullifier_root: request.nullifier_root,
            disclosure_root: request.disclosure_root,
            privacy_set_size: request.privacy_set_size,
            pq_encryption_root: request.pq_encryption_root,
            created_at_height: request.created_at_height,
            linked_at_height: 0,
        };
        let root = bundle.record_root();
        self.evidence_bundles.insert(bundle_id.clone(), bundle);
        self.push_event(
            "privacy_evidence_bundle_committed",
            &bundle_id,
            &root,
            request.created_at_height,
        )?;
        Ok(bundle_id)
    }

    pub fn record_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
            "settlement receipts",
        )?;
        let receipt_id = settlement_receipt_id(&request);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            receipt_kind: request.receipt_kind,
            subject_id: request.subject_id,
            amount_units: request.amount_units,
            fee_units: request.fee_units,
            state_root_before: request.state_root_before,
            state_root_after: request.state_root_after,
            evidence_root: request.evidence_root,
            settled_at_height: request.settled_at_height,
        };
        let root = receipt.record_root();
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.push_event(
            "settlement_receipt_recorded",
            &receipt_id,
            &root,
            request.settled_at_height,
        )?;
        Ok(receipt_id)
    }

    pub fn score_risk(&mut self, request: RiskScoreRequest) -> Result<String> {
        ensure_capacity(self.risk_scores.len(), MAX_RISK_SCORES, "risk scores")?;
        let score_bps = risk_score_bps(&request, &self.config);
        let band = risk_band(score_bps);
        let risk_score_id = risk_score_id(&request, score_bps, band);
        let score = RiskScore {
            risk_score_id: risk_score_id.clone(),
            scope_id: request.scope_id,
            observation_id: request.observation_id,
            policy_id: request.policy_id,
            band,
            score_bps,
            liquidity_depth_units: request.liquidity_depth_units,
            insured_exposure_units: request.insured_exposure_units,
            reserve_units: request.reserve_units,
            fee_pressure_bps: request.fee_pressure_bps,
            reorg_depth: request.reorg_depth,
            privacy_set_size: request.privacy_set_size,
            scored_at_height: request.scored_at_height,
        };
        let root = score.record_root();
        self.risk_scores.insert(risk_score_id.clone(), score);
        self.push_event(
            "risk_score_recorded",
            &risk_score_id,
            &root,
            request.scored_at_height,
        )?;
        Ok(risk_score_id)
    }

    pub fn file_slashing_evidence(&mut self, request: SlashingEvidenceRequest) -> Result<String> {
        ensure_capacity(
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
            "slashing evidence",
        )?;
        ensure_max(
            "recommended_slash_bps",
            request.recommended_slash_bps,
            self.config.max_slash_bps,
        )?;
        let slashing_id = slashing_evidence_id(&request);
        let evidence = SlashingEvidence {
            slashing_id: slashing_id.clone(),
            watchtower_id: request.watchtower_id,
            slashing_kind: request.slashing_kind,
            status: SlashingStatus::Filed,
            observation_id: request.observation_id,
            attestation_id: request.attestation_id,
            evidence_bundle_id: request.evidence_bundle_id,
            loss_units: request.loss_units,
            recommended_slash_bps: request.recommended_slash_bps,
            filed_by_commitment: request.filed_by_commitment,
            filed_at_height: request.filed_at_height,
            resolved_at_height: 0,
        };
        let root = evidence.record_root();
        self.slashing_evidence.insert(slashing_id.clone(), evidence);
        self.push_event(
            "slashing_evidence_filed",
            &slashing_id,
            &root,
            request.filed_at_height,
        )?;
        Ok(slashing_id)
    }
}
pub fn observation_id(request: &PrivateWatchtowerObservationRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-OBSERVATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.watchtower_id),
            HashPart::Str(request.observation_kind.as_str()),
            HashPart::U64(request.monero_height),
            HashPart::Str(&request.monero_tip_hash),
            HashPart::U64(request.l2_height),
            HashPart::Str(&request.l2_state_root),
            HashPart::Str(&request.bridge_lane_id),
            HashPart::Str(&request.subject_commitment),
            HashPart::Str(&request.encrypted_payload_root),
            HashPart::Str(&request.nullifier),
        ],
        32,
    )
}

pub fn attestation_id(request: &PqReorgAttestationRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.attestor_id),
            HashPart::Str(request.attestation_kind.as_str()),
            HashPart::U64(request.fork_depth),
            HashPart::Str(&request.canonical_tip_root),
            HashPart::Str(&request.contested_tip_root),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.signature_root),
        ],
        32,
    )
}

pub fn policy_id(request: &LiquidityInsurancePolicyRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-POLICY-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.policy_kind.as_str()),
            HashPart::Str(&request.route_commitment),
            HashPart::U64(request.coverage_units),
            HashPart::U64(request.premium_units),
            HashPart::U64(request.starts_at_height),
        ],
        32,
    )
}

pub fn fast_withdrawal_coverage_id(request: &FastWithdrawalCoverageRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-FAST-WITHDRAWAL-COVERAGE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.withdrawal_commitment),
            HashPart::Str(&request.recipient_commitment),
            HashPart::U64(request.coverage_units),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::U64(request.requested_at_height),
        ],
        32,
    )
}

pub fn reserve_recovery_claim_id(request: &ReserveRecoveryClaimRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-RESERVE-RECOVERY-CLAIM-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.claimant_commitment),
            HashPart::Str(&request.reserve_epoch_root),
            HashPart::Str(&request.loss_commitment),
            HashPart::U64(request.claim_units),
            HashPart::Str(&request.observation_id),
            HashPart::U64(request.submitted_at_height),
        ],
        32,
    )
}

pub fn fee_sponsor_pool_id(request: &FeeSponsorPoolRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-FEE-SPONSOR-POOL-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.lane_id),
            HashPart::U64(request.budget_units),
            HashPart::U64(request.max_sponsor_bps),
            HashPart::U64(request.opened_at_height),
        ],
        32,
    )
}

pub fn privacy_evidence_bundle_id(request: &PrivacyEvidenceBundleRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-PRIVACY-EVIDENCE-BUNDLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(request.bundle_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.ciphertext_root),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.disclosure_root),
            HashPart::U64(request.created_at_height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::U64(request.amount_units),
            HashPart::U64(request.fee_units),
            HashPart::Str(&request.state_root_after),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.settled_at_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(request: &SlashingEvidenceRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.watchtower_id),
            HashPart::Str(request.slashing_kind.as_str()),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.evidence_bundle_id),
            HashPart::U64(request.loss_units),
            HashPart::U64(request.recommended_slash_bps),
            HashPart::U64(request.filed_at_height),
        ],
        32,
    )
}

pub fn risk_score_id(request: &RiskScoreRequest, score_bps: u64, band: RiskBand) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-RISK-SCORE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Str(&request.scope_id),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.policy_id),
            HashPart::U64(score_bps),
            HashPart::Str(band.as_str()),
            HashPart::U64(request.scored_at_height),
        ],
        32,
    )
}

pub fn runtime_sequence_id(label: &str, sequence: u64, parts: &[&str]) -> String {
    let leaf = json!({"label": label, "sequence": sequence, "parts": parts});
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-SEQUENCE-ID",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(&leaf)],
        32,
    )
}

pub fn runtime_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID_LABEL),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn runtime_state_root_from_record(record: &Value) -> String {
    runtime_payload_root("STATE", record)
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Config {
    fn public_record(&self) -> Value {
        Config::public_record(self)
    }
}

impl PublicRecord for Counters {
    fn public_record(&self) -> Value {
        Counters::public_record(self)
    }
}

impl PublicRecord for PrivateWatchtowerObservationRequest {
    fn public_record(&self) -> Value {
        PrivateWatchtowerObservationRequest::public_record(self)
    }
}

impl PublicRecord for PrivateWatchtowerObservation {
    fn public_record(&self) -> Value {
        PrivateWatchtowerObservation::public_record(self)
    }
}

impl PublicRecord for PqReorgAttestationRequest {
    fn public_record(&self) -> Value {
        PqReorgAttestationRequest::public_record(self)
    }
}

impl PublicRecord for PqReorgAttestation {
    fn public_record(&self) -> Value {
        PqReorgAttestation::public_record(self)
    }
}

impl PublicRecord for LiquidityInsurancePolicyRequest {
    fn public_record(&self) -> Value {
        LiquidityInsurancePolicyRequest::public_record(self)
    }
}

impl PublicRecord for LiquidityInsurancePolicy {
    fn public_record(&self) -> Value {
        LiquidityInsurancePolicy::public_record(self)
    }
}

impl PublicRecord for FastWithdrawalCoverageRequest {
    fn public_record(&self) -> Value {
        FastWithdrawalCoverageRequest::public_record(self)
    }
}

impl PublicRecord for FastWithdrawalCoverage {
    fn public_record(&self) -> Value {
        FastWithdrawalCoverage::public_record(self)
    }
}

impl PublicRecord for ReserveRecoveryClaimRequest {
    fn public_record(&self) -> Value {
        ReserveRecoveryClaimRequest::public_record(self)
    }
}

impl PublicRecord for ReserveRecoveryClaim {
    fn public_record(&self) -> Value {
        ReserveRecoveryClaim::public_record(self)
    }
}

impl PublicRecord for FeeSponsorPoolRequest {
    fn public_record(&self) -> Value {
        FeeSponsorPoolRequest::public_record(self)
    }
}

impl PublicRecord for FeeSponsorPool {
    fn public_record(&self) -> Value {
        FeeSponsorPool::public_record(self)
    }
}

impl PublicRecord for PrivacyEvidenceBundleRequest {
    fn public_record(&self) -> Value {
        PrivacyEvidenceBundleRequest::public_record(self)
    }
}

impl PublicRecord for PrivacyEvidenceBundle {
    fn public_record(&self) -> Value {
        PrivacyEvidenceBundle::public_record(self)
    }
}

impl PublicRecord for SettlementReceiptRequest {
    fn public_record(&self) -> Value {
        SettlementReceiptRequest::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for RiskScoreRequest {
    fn public_record(&self) -> Value {
        RiskScoreRequest::public_record(self)
    }
}

impl PublicRecord for RiskScore {
    fn public_record(&self) -> Value {
        RiskScore::public_record(self)
    }
}

impl PublicRecord for SlashingEvidenceRequest {
    fn public_record(&self) -> Value {
        SlashingEvidenceRequest::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

impl PublicRecord for RuntimeEvent {
    fn public_record(&self) -> Value {
        RuntimeEvent::public_record(self)
    }
}

impl PublicRecord for Roots {
    fn public_record(&self) -> Value {
        Roots::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(id, value)| json!({"id": id, "record": value.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-WATCHTOWER-REORG-LIQUIDITY-INSURANCE-{domain}"),
        &leaves,
    )
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}
fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
fn ensure_min(label: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        Err(format!("{label} below minimum {min}"))
    } else {
        Ok(())
    }
}
fn ensure_max(label: &str, value: u64, max: u64) -> Result<()> {
    if value > max {
        Err(format!("{label} above maximum {max}"))
    } else {
        Ok(())
    }
}
fn clamp_bps(value: u64) -> u64 {
    value.min(MAX_BPS)
}
fn privacy_penalty_bps(privacy_set_size: u64, min_privacy_set_size: u64) -> u64 {
    if privacy_set_size >= min_privacy_set_size {
        0
    } else {
        let deficit = min_privacy_set_size.saturating_sub(privacy_set_size);
        clamp_bps(deficit.saturating_mul(MAX_BPS) / min_privacy_set_size.max(1))
    }
}

pub fn risk_score_bps(request: &RiskScoreRequest, config: &Config) -> u64 {
    let exposure_bps = if request.reserve_units == 0 {
        MAX_BPS
    } else {
        request.insured_exposure_units.saturating_mul(MAX_BPS) / request.reserve_units
    };
    let liquidity_bps = if request.liquidity_depth_units == 0 {
        MAX_BPS
    } else {
        request.insured_exposure_units.saturating_mul(MAX_BPS) / request.liquidity_depth_units
    };
    let reorg_bps = request.reorg_depth.saturating_mul(MAX_BPS) / config.reorg_halt_depth.max(1);
    let privacy_bps = privacy_penalty_bps(request.privacy_set_size, config.min_privacy_set_size);
    clamp_bps(
        exposure_bps / 4
            + liquidity_bps / 4
            + request.fee_pressure_bps / 5
            + reorg_bps / 5
            + privacy_bps / 10,
    )
}

pub fn risk_band(score_bps: u64) -> RiskBand {
    match score_bps {
        0..=1_999 => RiskBand::Normal,
        2_000..=3_999 => RiskBand::Watch,
        4_000..=6_499 => RiskBand::Elevated,
        6_500..=8_499 => RiskBand::Throttled,
        8_500..=9_999 => RiskBand::Emergency,
        _ => RiskBand::Halted,
    }
}
