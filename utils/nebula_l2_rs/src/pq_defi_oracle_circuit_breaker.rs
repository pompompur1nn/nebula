use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PqDefiOracleCircuitBreakerResult<T> = Result<T, String>;

pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PROTOCOL_VERSION: &str =
    "nebula-pq-defi-oracle-circuit-breaker-v1";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_RISK_PROOF_SYSTEM: &str = "private-defi-risk-envelope-v1";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_RESUMPTION_PROOF_SYSTEM: &str =
    "private-oracle-resumption-proof-v1";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PUBLIC_RECORD_SCHEME: &str =
    "privacy-preserving-public-incident-record-v1";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEVNET_HEIGHT: u64 = 1_286;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS: u64 = 10_000;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_FAST_HALT_TTL_BLOCKS: u64 = 36;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_RESUMPTION_DELAY_BLOCKS: u64 = 18;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MIN_QUORUM_BPS: u64 = 6_700;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_SUPERMAJORITY_BPS: u64 = 7_500;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_FAST_HALT_BPS: u64 = 6_000;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MAX_DEVIATION_BPS: u64 = 850;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_CAUTION_DEVIATION_BPS: u64 = 300;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_RESUME_DEVIATION_BPS: u64 = 120;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_EMERGENCY_FEE_CAP: u64 = 5;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_SPONSOR_BUDGET: u64 = 180_000;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_FEEDS: usize = 2_048;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_COMMITTEES: usize = 512;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_MEMBERS: usize = 16_384;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_ATTESTATIONS: usize = 262_144;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_RISK_ENVELOPES: usize = 131_072;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_GUARD_RAILS: usize = 65_536;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_HALT_LANES: usize = 16_384;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_RESUMPTION_PROOFS: usize = 16_384;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_EMERGENCY_VOTES: usize = 262_144;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_PUBLIC_RECORDS: usize = 262_144;
pub const PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    Spot,
    AmmTwap,
    LendingCollateral,
    PerpIndex,
    PerpFunding,
    StablecoinPeg,
    VaultShare,
    MoneroReserve,
    ProofFee,
    SequencerLatency,
}

impl FeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::AmmTwap => "amm_twap",
            Self::LendingCollateral => "lending_collateral",
            Self::PerpIndex => "perp_index",
            Self::PerpFunding => "perp_funding",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::VaultShare => "vault_share",
            Self::MoneroReserve => "monero_reserve",
            Self::ProofFee => "proof_fee",
            Self::SequencerLatency => "sequencer_latency",
        }
    }

    pub fn heartbeat_blocks(self) -> u64 {
        match self {
            Self::Spot | Self::PerpIndex | Self::StablecoinPeg => 4,
            Self::AmmTwap | Self::PerpFunding => 8,
            Self::LendingCollateral | Self::VaultShare => 12,
            Self::MoneroReserve => 10,
            Self::ProofFee | Self::SequencerLatency => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Active,
    Caution,
    Guarded,
    Halted,
    Quarantined,
    Retired,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Caution => "caution",
            Self::Guarded => "guarded",
            Self::Halted => "halted",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Active | Self::Caution | Self::Guarded)
    }

    pub fn guarded(self) -> bool {
        matches!(self, Self::Guarded | Self::Halted | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Publisher,
    Aggregator,
    RiskGuardian,
    FastHaltSigner,
    ResumptionSigner,
    SponsorAuditor,
    Watchtower,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::Aggregator => "aggregator",
            Self::RiskGuardian => "risk_guardian",
            Self::FastHaltSigner => "fast_halt_signer",
            Self::ResumptionSigner => "resumption_signer",
            Self::SponsorAuditor => "sponsor_auditor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Suspended,
    RotatingOut,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::RotatingOut => "rotating_out",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Counted,
    Duplicate,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskEnvelopeStatus {
    Pending,
    Verified,
    WeakPrivacy,
    Invalid,
    Expired,
}

impl RiskEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::WeakPrivacy => "weak_privacy",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardRailKind {
    AmmSwapPause,
    AmmTwapWiden,
    LendingBorrowFreeze,
    LendingLiquidationPause,
    PerpReduceOnly,
    PerpFundingClamp,
    StablecoinMintPause,
    VaultWithdrawalThrottle,
}

impl GuardRailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmSwapPause => "amm_swap_pause",
            Self::AmmTwapWiden => "amm_twap_widen",
            Self::LendingBorrowFreeze => "lending_borrow_freeze",
            Self::LendingLiquidationPause => "lending_liquidation_pause",
            Self::PerpReduceOnly => "perp_reduce_only",
            Self::PerpFundingClamp => "perp_funding_clamp",
            Self::StablecoinMintPause => "stablecoin_mint_pause",
            Self::VaultWithdrawalThrottle => "vault_withdrawal_throttle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardRailStatus {
    Armed,
    Triggered,
    CoolingDown,
    Cleared,
    Retired,
}

impl GuardRailStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::CoolingDown => "cooling_down",
            Self::Cleared => "cleared",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaltLaneKind {
    OracleDivergence,
    StaleFeed,
    PqSignatureFailure,
    PrivacyLeak,
    LiquidityShock,
    ReserveBreak,
    SequencerLatency,
    GovernanceVeto,
}

impl HaltLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OracleDivergence => "oracle_divergence",
            Self::StaleFeed => "stale_feed",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::PrivacyLeak => "privacy_leak",
            Self::LiquidityShock => "liquidity_shock",
            Self::ReserveBreak => "reserve_break",
            Self::SequencerLatency => "sequencer_latency",
            Self::GovernanceVeto => "governance_veto",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaltLaneStatus {
    Open,
    Escalated,
    Executed,
    Cancelled,
    Expired,
}

impl HaltLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Escalated => "escalated",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumptionStatus {
    Proposed,
    Proved,
    Accepted,
    Rejected,
    Expired,
}

impl ResumptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Proved => "proved",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyVoteChoice {
    Halt,
    Guard,
    Resume,
    Reject,
    Abstain,
}

impl EmergencyVoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Halt => "halt",
            Self::Guard => "guard",
            Self::Resume => "resume",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    FeedHeartbeat,
    HaltActivated,
    GuardRailTriggered,
    ResumptionAccepted,
    VoteTally,
    PrivacyAudit,
    SponsorDebit,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeedHeartbeat => "feed_heartbeat",
            Self::HaltActivated => "halt_activated",
            Self::GuardRailTriggered => "guard_rail_triggered",
            Self::ResumptionAccepted => "resumption_accepted",
            Self::VoteTally => "vote_tally",
            Self::PrivacyAudit => "privacy_audit",
            Self::SponsorDebit => "sponsor_debit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fast_halt_ttl_blocks: u64,
    pub resumption_delay_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub fast_halt_bps: u64,
    pub max_deviation_bps: u64,
    pub caution_deviation_bps: u64,
    pub resume_deviation_bps: u64,
    pub min_privacy_set_size: u64,
    pub emergency_vote_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub fee_asset_id: String,
    pub risk_proof_system: String,
    pub resumption_proof_system: String,
    pub public_record_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_EPOCH_BLOCKS,
            attestation_ttl_blocks: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            fast_halt_ttl_blocks: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_FAST_HALT_TTL_BLOCKS,
            resumption_delay_blocks: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_RESUMPTION_DELAY_BLOCKS,
            min_pq_security_bits: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MIN_SECURITY_BITS,
            min_quorum_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MIN_QUORUM_BPS,
            supermajority_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_SUPERMAJORITY_BPS,
            fast_halt_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_FAST_HALT_BPS,
            max_deviation_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_MAX_DEVIATION_BPS,
            caution_deviation_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_CAUTION_DEVIATION_BPS,
            resume_deviation_bps: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_RESUME_DEVIATION_BPS,
            min_privacy_set_size: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_PRIVACY_SET_SIZE,
            emergency_vote_fee_cap_units: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_EMERGENCY_FEE_CAP,
            sponsor_budget_units: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEFAULT_SPONSOR_BUDGET,
            fee_asset_id: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_FEE_ASSET_ID.to_string(),
            risk_proof_system: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_RISK_PROOF_SYSTEM.to_string(),
            resumption_proof_system: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_RESUMPTION_PROOF_SYSTEM
                .to_string(),
            public_record_scheme: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PUBLIC_RECORD_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fast_halt_ttl_blocks": self.fast_halt_ttl_blocks,
            "resumption_delay_blocks": self.resumption_delay_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_quorum_bps": self.min_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "fast_halt_bps": self.fast_halt_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "caution_deviation_bps": self.caution_deviation_bps,
            "resume_deviation_bps": self.resume_deviation_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "emergency_vote_fee_cap_units": self.emergency_vote_fee_cap_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "fee_asset_id": self.fee_asset_id,
            "risk_proof_system": self.risk_proof_system,
            "resumption_proof_system": self.resumption_proof_system,
            "public_record_scheme": self.public_record_scheme,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feed {
    pub feed_id: String,
    pub symbol: String,
    pub kind: FeedKind,
    pub status: FeedStatus,
    pub committee_id: String,
    pub decimals: u8,
    pub last_price_commitment: String,
    pub last_update_height: u64,
    pub heartbeat_blocks: u64,
    pub max_deviation_bps: u64,
    pub privacy_set_size: u64,
    pub guarded_protocols: BTreeSet<String>,
}

impl Feed {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "symbol": self.symbol,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "decimals": self.decimals,
            "last_price_commitment": self.last_price_commitment,
            "last_update_height": self.last_update_height,
            "heartbeat_blocks": self.heartbeat_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "privacy_set_size": self.privacy_set_size,
            "guarded_protocols": set_values(&self.guarded_protocols),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    pub committee_id: String,
    pub feed_ids: BTreeSet<String>,
    pub roles: BTreeSet<CommitteeRole>,
    pub member_ids: BTreeSet<String>,
    pub threshold_bps: u64,
    pub fast_halt_threshold_bps: u64,
    pub resumption_threshold_bps: u64,
    pub epoch: u64,
    pub activation_height: u64,
    pub rotation_root: String,
}

impl Committee {
    pub fn public_record(&self) -> Value {
        let roles = self
            .roles
            .iter()
            .map(|role| json!(role.as_str()))
            .collect::<Vec<_>>();
        json!({
            "committee_id": self.committee_id,
            "feed_ids": set_values(&self.feed_ids),
            "roles": roles,
            "member_ids": set_values(&self.member_ids),
            "threshold_bps": self.threshold_bps,
            "fast_halt_threshold_bps": self.fast_halt_threshold_bps,
            "resumption_threshold_bps": self.resumption_threshold_bps,
            "epoch": self.epoch,
            "activation_height": self.activation_height,
            "rotation_root": self.rotation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_commitment: String,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub role: CommitteeRole,
    pub status: MemberStatus,
    pub voting_power: u64,
    pub stake_commitment: String,
    pub joined_height: u64,
    pub security_bits: u16,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "voting_power": self.voting_power,
            "stake_commitment": self.stake_commitment,
            "joined_height": self.joined_height,
            "security_bits": self.security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub update_height: u64,
    pub valid_until_height: u64,
    pub price_commitment: String,
    pub deviation_bps: u64,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub status: AttestationStatus,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "feed_id": self.feed_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "update_height": self.update_height,
            "valid_until_height": self.valid_until_height,
            "price_commitment": self.price_commitment,
            "deviation_bps": self.deviation_bps,
            "pq_signature_commitment": self.pq_signature_commitment,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRiskEnvelope {
    pub envelope_id: String,
    pub feed_id: String,
    pub protocol_id: String,
    pub range_commitment: String,
    pub risk_score_commitment: String,
    pub proof_root: String,
    pub privacy_set_size: u64,
    pub leakage_budget_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: RiskEnvelopeStatus,
}

impl PrivateRiskEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "feed_id": self.feed_id,
            "protocol_id": self.protocol_id,
            "range_commitment": self.range_commitment,
            "risk_score_commitment": self.risk_score_commitment,
            "proof_root": self.proof_root,
            "privacy_set_size": self.privacy_set_size,
            "leakage_budget_bps": self.leakage_budget_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardRail {
    pub guard_rail_id: String,
    pub protocol_id: String,
    pub feed_id: String,
    pub kind: GuardRailKind,
    pub status: GuardRailStatus,
    pub trigger_deviation_bps: u64,
    pub resume_deviation_bps: u64,
    pub throttle_bps: u64,
    pub last_trigger_height: u64,
    pub cooldown_until_height: u64,
    pub evidence_root: String,
}

impl GuardRail {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_rail_id": self.guard_rail_id,
            "protocol_id": self.protocol_id,
            "feed_id": self.feed_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "trigger_deviation_bps": self.trigger_deviation_bps,
            "resume_deviation_bps": self.resume_deviation_bps,
            "throttle_bps": self.throttle_bps,
            "last_trigger_height": self.last_trigger_height,
            "cooldown_until_height": self.cooldown_until_height,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastHaltLane {
    pub lane_id: String,
    pub feed_id: String,
    pub protocol_id: String,
    pub kind: HaltLaneKind,
    pub status: HaltLaneStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub signer_committee_id: String,
    pub signer_weight_bps: u64,
    pub evidence_root: String,
    pub nullifier: String,
}

impl FastHaltLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "feed_id": self.feed_id,
            "protocol_id": self.protocol_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "signer_committee_id": self.signer_committee_id,
            "signer_weight_bps": self.signer_weight_bps,
            "evidence_root": self.evidence_root,
            "nullifier": self.nullifier,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumptionProof {
    pub proof_id: String,
    pub feed_id: String,
    pub protocol_id: String,
    pub halted_lane_id: String,
    pub proposal_height: u64,
    pub executable_height: u64,
    pub valid_until_height: u64,
    pub median_commitment: String,
    pub deviation_bps: u64,
    pub proof_root: String,
    pub signer_weight_bps: u64,
    pub status: ResumptionStatus,
}

impl ResumptionProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "feed_id": self.feed_id,
            "protocol_id": self.protocol_id,
            "halted_lane_id": self.halted_lane_id,
            "proposal_height": self.proposal_height,
            "executable_height": self.executable_height,
            "valid_until_height": self.valid_until_height,
            "median_commitment": self.median_commitment,
            "deviation_bps": self.deviation_bps,
            "proof_root": self.proof_root,
            "signer_weight_bps": self.signer_weight_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyVote {
    pub vote_id: String,
    pub lane_id: String,
    pub voter_commitment: String,
    pub choice: EmergencyVoteChoice,
    pub voting_power: u64,
    pub fee_units: u64,
    pub sponsor_id: String,
    pub vote_height: u64,
    pub pq_signature_commitment: String,
    pub nullifier: String,
}

impl EmergencyVote {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "lane_id": self.lane_id,
            "voter_commitment": self.voter_commitment,
            "choice": self.choice.as_str(),
            "voting_power": self.voting_power,
            "fee_units": self.fee_units,
            "sponsor_id": self.sponsor_id,
            "vote_height": self.vote_height,
            "pq_signature_commitment": self.pq_signature_commitment,
            "nullifier": self.nullifier,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicCircuitRecord {
    pub record_id: String,
    pub kind: PublicRecordKind,
    pub subject_id: String,
    pub height: u64,
    pub public_commitment: String,
    pub privacy_preserving_summary: String,
    pub affected_protocols_root: String,
    pub proof_root: String,
}

impl PublicCircuitRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "public_commitment": self.public_commitment,
            "privacy_preserving_summary": self.privacy_preserving_summary,
            "affected_protocols_root": self.affected_protocols_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub fee_cap_units: u64,
    pub active: bool,
    pub audit_root: String,
}

impl Sponsor {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "fee_cap_units": self.fee_cap_units,
            "active": self.active,
            "audit_root": self.audit_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
}

impl Event {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub feed_root: String,
    pub committee_root: String,
    pub member_root: String,
    pub attestation_root: String,
    pub private_risk_envelope_root: String,
    pub guard_rail_root: String,
    pub fast_halt_lane_root: String,
    pub resumption_proof_root: String,
    pub emergency_vote_root: String,
    pub sponsor_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "feed_root": self.feed_root,
            "committee_root": self.committee_root,
            "member_root": self.member_root,
            "attestation_root": self.attestation_root,
            "private_risk_envelope_root": self.private_risk_envelope_root,
            "guard_rail_root": self.guard_rail_root,
            "fast_halt_lane_root": self.fast_halt_lane_root,
            "resumption_proof_root": self.resumption_proof_root,
            "emergency_vote_root": self.emergency_vote_root,
            "sponsor_root": self.sponsor_root,
            "public_record_root": self.public_record_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub feeds: u64,
    pub committees: u64,
    pub members: u64,
    pub active_members: u64,
    pub attestations: u64,
    pub counted_attestations: u64,
    pub verified_risk_envelopes: u64,
    pub active_guard_rails: u64,
    pub triggered_guard_rails: u64,
    pub open_halt_lanes: u64,
    pub executed_halt_lanes: u64,
    pub accepted_resumptions: u64,
    pub emergency_votes: u64,
    pub sponsored_vote_units: u64,
    pub public_records: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "feeds": self.feeds,
            "committees": self.committees,
            "members": self.members,
            "active_members": self.active_members,
            "attestations": self.attestations,
            "counted_attestations": self.counted_attestations,
            "verified_risk_envelopes": self.verified_risk_envelopes,
            "active_guard_rails": self.active_guard_rails,
            "triggered_guard_rails": self.triggered_guard_rails,
            "open_halt_lanes": self.open_halt_lanes,
            "executed_halt_lanes": self.executed_halt_lanes,
            "accepted_resumptions": self.accepted_resumptions,
            "emergency_votes": self.emergency_votes,
            "sponsored_vote_units": self.sponsored_vote_units,
            "public_records": self.public_records,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub config: Config,
    pub feeds: BTreeMap<String, Feed>,
    pub committees: BTreeMap<String, Committee>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub risk_envelopes: BTreeMap<String, PrivateRiskEnvelope>,
    pub guard_rails: BTreeMap<String, GuardRail>,
    pub fast_halt_lanes: BTreeMap<String, FastHaltLane>,
    pub resumption_proofs: BTreeMap<String, ResumptionProof>,
    pub emergency_votes: BTreeMap<String, EmergencyVote>,
    pub sponsors: BTreeMap<String, Sponsor>,
    pub public_records: BTreeMap<String, PublicCircuitRecord>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<Event>,
}

impl State {
    pub fn devnet() -> PqDefiOracleCircuitBreakerResult<Self> {
        let height = PQ_DEFI_ORACLE_CIRCUIT_BREAKER_DEVNET_HEIGHT;
        let config = Config::devnet();
        let mut feeds = BTreeMap::new();
        let mut committees = BTreeMap::new();
        let mut members = BTreeMap::new();
        let mut attestations = BTreeMap::new();
        let mut risk_envelopes = BTreeMap::new();
        let mut guard_rails = BTreeMap::new();
        let mut fast_halt_lanes = BTreeMap::new();
        let mut resumption_proofs = BTreeMap::new();
        let mut emergency_votes = BTreeMap::new();
        let mut sponsors = BTreeMap::new();
        let mut public_records = BTreeMap::new();
        let mut nullifiers = BTreeSet::new();
        let mut events = Vec::new();

        for (feed_id, symbol, kind, status, protocols, offset, deviation) in [
            (
                "feed:xmr-usd",
                "XMR/USD",
                FeedKind::Spot,
                FeedStatus::Active,
                vec!["amm:xmr-usd", "lend:xmr", "perp:xmr-usd"],
                2_u64,
                80_u64,
            ),
            (
                "feed:dxmr-usd",
                "DXMR/USD",
                FeedKind::StablecoinPeg,
                FeedStatus::Caution,
                vec!["amm:dxmr-usd", "lend:dxmr"],
                3_u64,
                180_u64,
            ),
            (
                "feed:xmr-twap",
                "XMR/TWAP",
                FeedKind::AmmTwap,
                FeedStatus::Guarded,
                vec!["amm:xmr-usd", "vault:xmr-delta"],
                6_u64,
                360_u64,
            ),
            (
                "feed:xmr-perp",
                "XMR-PERP",
                FeedKind::PerpIndex,
                FeedStatus::Halted,
                vec!["perp:xmr-usd"],
                9_u64,
                1_140_u64,
            ),
            (
                "feed:monero-reserve",
                "MONERO-RESERVE",
                FeedKind::MoneroReserve,
                FeedStatus::Active,
                vec!["bridge:xmr", "vault:xmr-delta"],
                5_u64,
                95_u64,
            ),
        ] {
            let committee_id = format!("committee:{feed_id}");
            let guarded_protocols = protocols
                .iter()
                .map(|protocol| (*protocol).to_string())
                .collect::<BTreeSet<_>>();
            let price_record = json!({
                "feed_id": feed_id,
                "symbol": symbol,
                "height": height.saturating_sub(offset),
                "deviation_bps": deviation,
            });
            feeds.insert(
                feed_id.to_string(),
                Feed {
                    feed_id: feed_id.to_string(),
                    symbol: symbol.to_string(),
                    kind,
                    status,
                    committee_id: committee_id.clone(),
                    decimals: 8,
                    last_price_commitment: root_from_record(&price_record),
                    last_update_height: height.saturating_sub(offset),
                    heartbeat_blocks: kind.heartbeat_blocks(),
                    max_deviation_bps: config.max_deviation_bps,
                    privacy_set_size: config.min_privacy_set_size + offset * 64,
                    guarded_protocols,
                },
            );
        }

        for feed in feeds.values() {
            let mut committee_member_ids = BTreeSet::new();
            for index in 0..5_u64 {
                let member_id = format!("member:{}:{index}", feed.feed_id);
                committee_member_ids.insert(member_id.clone());
                let role = match index {
                    0 => CommitteeRole::Publisher,
                    1 => CommitteeRole::Aggregator,
                    2 => CommitteeRole::RiskGuardian,
                    3 => CommitteeRole::FastHaltSigner,
                    _ => CommitteeRole::Watchtower,
                };
                let seed = json!({
                    "member_id": member_id,
                    "feed_id": feed.feed_id,
                    "index": index,
                });
                members.insert(
                    member_id.clone(),
                    CommitteeMember {
                        member_id: member_id.clone(),
                        committee_id: feed.committee_id.clone(),
                        operator_commitment: domain_hash(
                            "PQ-DEFI-ORACLE-CB-OPERATOR",
                            &[HashPart::Json(&seed)],
                            32,
                        ),
                        pq_public_key_commitment: domain_hash(
                            "PQ-DEFI-ORACLE-CB-PQ-PUBKEY",
                            &[HashPart::Json(&seed)],
                            32,
                        ),
                        backup_public_key_commitment: domain_hash(
                            "PQ-DEFI-ORACLE-CB-BACKUP-PUBKEY",
                            &[HashPart::Json(&seed)],
                            32,
                        ),
                        role,
                        status: MemberStatus::Active,
                        voting_power: 2_000,
                        stake_commitment: domain_hash(
                            "PQ-DEFI-ORACLE-CB-STAKE",
                            &[HashPart::Json(&seed)],
                            32,
                        ),
                        joined_height: height.saturating_sub(400 + index),
                        security_bits: 256,
                    },
                );
            }
            let mut roles = BTreeSet::new();
            roles.insert(CommitteeRole::Publisher);
            roles.insert(CommitteeRole::Aggregator);
            roles.insert(CommitteeRole::RiskGuardian);
            roles.insert(CommitteeRole::FastHaltSigner);
            roles.insert(CommitteeRole::ResumptionSigner);
            roles.insert(CommitteeRole::Watchtower);
            let mut feed_ids = BTreeSet::new();
            feed_ids.insert(feed.feed_id.clone());
            let rotation_record = json!({
                "committee_id": feed.committee_id,
                "epoch": height / config.epoch_blocks,
                "members": set_values(&committee_member_ids),
            });
            committees.insert(
                feed.committee_id.clone(),
                Committee {
                    committee_id: feed.committee_id.clone(),
                    feed_ids,
                    roles,
                    member_ids: committee_member_ids,
                    threshold_bps: config.min_quorum_bps,
                    fast_halt_threshold_bps: config.fast_halt_bps,
                    resumption_threshold_bps: config.supermajority_bps,
                    epoch: height / config.epoch_blocks,
                    activation_height: height.saturating_sub(360),
                    rotation_root: root_from_record(&rotation_record),
                },
            );
        }

        for feed in feeds.values() {
            let member_ids = match committees.get(&feed.committee_id) {
                Some(committee) => committee.member_ids.iter().cloned().collect::<Vec<_>>(),
                None => Vec::new(),
            };
            for (index, member_id) in member_ids.iter().take(4).enumerate() {
                let attestation_record = json!({
                    "feed_id": feed.feed_id,
                    "member_id": member_id,
                    "height": feed.last_update_height,
                    "index": index,
                });
                let attestation_id = deterministic_id("attestation", &attestation_record);
                attestations.insert(
                    attestation_id.clone(),
                    PqAttestation {
                        attestation_id,
                        feed_id: feed.feed_id.clone(),
                        committee_id: feed.committee_id.clone(),
                        member_id: member_id.clone(),
                        update_height: feed.last_update_height,
                        valid_until_height: feed
                            .last_update_height
                            .saturating_add(config.attestation_ttl_blocks),
                        price_commitment: feed.last_price_commitment.clone(),
                        deviation_bps: feed.max_deviation_bps / 4 + index as u64 * 7,
                        pq_signature_commitment: domain_hash(
                            "PQ-DEFI-ORACLE-CB-ATTESTATION-SIG",
                            &[HashPart::Json(&attestation_record)],
                            32,
                        ),
                        transcript_root: root_from_record(&attestation_record),
                        status: AttestationStatus::Counted,
                    },
                );
            }
        }

        for (feed_id, protocol_id, leakage_budget_bps, status) in [
            (
                "feed:xmr-usd",
                "lend:xmr",
                22_u64,
                RiskEnvelopeStatus::Verified,
            ),
            (
                "feed:dxmr-usd",
                "amm:dxmr-usd",
                28_u64,
                RiskEnvelopeStatus::Verified,
            ),
            (
                "feed:xmr-twap",
                "vault:xmr-delta",
                35_u64,
                RiskEnvelopeStatus::Verified,
            ),
            (
                "feed:xmr-perp",
                "perp:xmr-usd",
                31_u64,
                RiskEnvelopeStatus::Verified,
            ),
        ] {
            let record = json!({
                "feed_id": feed_id,
                "protocol_id": protocol_id,
                "height": height,
            });
            let envelope_id = deterministic_id("risk-envelope", &record);
            risk_envelopes.insert(
                envelope_id.clone(),
                PrivateRiskEnvelope {
                    envelope_id,
                    feed_id: feed_id.to_string(),
                    protocol_id: protocol_id.to_string(),
                    range_commitment: domain_hash(
                        "PQ-DEFI-ORACLE-CB-RANGE",
                        &[HashPart::Json(&record)],
                        32,
                    ),
                    risk_score_commitment: domain_hash(
                        "PQ-DEFI-ORACLE-CB-RISK-SCORE",
                        &[HashPart::Json(&record)],
                        32,
                    ),
                    proof_root: domain_hash(
                        "PQ-DEFI-ORACLE-CB-RISK-PROOF",
                        &[HashPart::Json(&record)],
                        32,
                    ),
                    privacy_set_size: config.min_privacy_set_size + 512,
                    leakage_budget_bps,
                    valid_from_height: height.saturating_sub(12),
                    valid_until_height: height.saturating_add(72),
                    status,
                },
            );
        }

        for (protocol_id, feed_id, kind, status, trigger, resume, throttle) in [
            (
                "amm:xmr-usd",
                "feed:xmr-twap",
                GuardRailKind::AmmTwapWiden,
                GuardRailStatus::Triggered,
                300_u64,
                100_u64,
                2_500_u64,
            ),
            (
                "lend:xmr",
                "feed:xmr-usd",
                GuardRailKind::LendingLiquidationPause,
                GuardRailStatus::Armed,
                650_u64,
                120_u64,
                10_000_u64,
            ),
            (
                "perp:xmr-usd",
                "feed:xmr-perp",
                GuardRailKind::PerpReduceOnly,
                GuardRailStatus::Triggered,
                700_u64,
                120_u64,
                10_000_u64,
            ),
            (
                "vault:xmr-delta",
                "feed:monero-reserve",
                GuardRailKind::VaultWithdrawalThrottle,
                GuardRailStatus::Armed,
                500_u64,
                120_u64,
                3_000_u64,
            ),
        ] {
            let record = json!({
                "protocol_id": protocol_id,
                "feed_id": feed_id,
                "kind": kind.as_str(),
            });
            let guard_rail_id = deterministic_id("guard-rail", &record);
            guard_rails.insert(
                guard_rail_id.clone(),
                GuardRail {
                    guard_rail_id,
                    protocol_id: protocol_id.to_string(),
                    feed_id: feed_id.to_string(),
                    kind,
                    status,
                    trigger_deviation_bps: trigger,
                    resume_deviation_bps: resume,
                    throttle_bps: throttle,
                    last_trigger_height: height.saturating_sub(5),
                    cooldown_until_height: height.saturating_add(30),
                    evidence_root: root_from_record(&record),
                },
            );
        }

        let halt_record = json!({
            "feed_id": "feed:xmr-perp",
            "protocol_id": "perp:xmr-usd",
            "kind": HaltLaneKind::OracleDivergence.as_str(),
            "height": height,
        });
        let halt_lane_id = deterministic_id("halt-lane", &halt_record);
        let halt_nullifier = deterministic_id("halt-nullifier", &halt_record);
        nullifiers.insert(halt_nullifier.clone());
        fast_halt_lanes.insert(
            halt_lane_id.clone(),
            FastHaltLane {
                lane_id: halt_lane_id.clone(),
                feed_id: "feed:xmr-perp".to_string(),
                protocol_id: "perp:xmr-usd".to_string(),
                kind: HaltLaneKind::OracleDivergence,
                status: HaltLaneStatus::Executed,
                opened_height: height.saturating_sub(9),
                expires_height: height.saturating_add(config.fast_halt_ttl_blocks),
                signer_committee_id: "committee:feed:xmr-perp".to_string(),
                signer_weight_bps: 8_000,
                evidence_root: root_from_record(&halt_record),
                nullifier: halt_nullifier,
            },
        );

        let resume_record = json!({
            "feed_id": "feed:xmr-twap",
            "protocol_id": "amm:xmr-usd",
            "halted_lane_id": halt_lane_id,
            "height": height,
        });
        let proof_id = deterministic_id("resumption-proof", &resume_record);
        resumption_proofs.insert(
            proof_id.clone(),
            ResumptionProof {
                proof_id,
                feed_id: "feed:xmr-twap".to_string(),
                protocol_id: "amm:xmr-usd".to_string(),
                halted_lane_id: halt_lane_id.clone(),
                proposal_height: height.saturating_sub(4),
                executable_height: height.saturating_add(config.resumption_delay_blocks),
                valid_until_height: height.saturating_add(60),
                median_commitment: domain_hash(
                    "PQ-DEFI-ORACLE-CB-RESUME-MEDIAN",
                    &[HashPart::Json(&resume_record)],
                    32,
                ),
                deviation_bps: 90,
                proof_root: domain_hash(
                    "PQ-DEFI-ORACLE-CB-RESUMPTION-PROOF",
                    &[HashPart::Json(&resume_record)],
                    32,
                ),
                signer_weight_bps: 8_000,
                status: ResumptionStatus::Proved,
            },
        );

        let sponsor_record = json!({"sponsor": "emergency-sponsor", "height": height});
        sponsors.insert(
            "sponsor:emergency".to_string(),
            Sponsor {
                sponsor_id: "sponsor:emergency".to_string(),
                sponsor_commitment: domain_hash(
                    "PQ-DEFI-ORACLE-CB-SPONSOR",
                    &[HashPart::Json(&sponsor_record)],
                    32,
                ),
                budget_units: config.sponsor_budget_units,
                spent_units: 20,
                fee_cap_units: config.emergency_vote_fee_cap_units,
                active: true,
                audit_root: root_from_record(&sponsor_record),
            },
        );

        for index in 0..8_u64 {
            let vote_record = json!({
                "lane_id": halt_lane_id,
                "index": index,
                "choice": "halt",
            });
            let vote_id = deterministic_id("emergency-vote", &vote_record);
            let nullifier = deterministic_id("emergency-vote-nullifier", &vote_record);
            nullifiers.insert(nullifier.clone());
            emergency_votes.insert(
                vote_id.clone(),
                EmergencyVote {
                    vote_id,
                    lane_id: halt_lane_id.clone(),
                    voter_commitment: domain_hash(
                        "PQ-DEFI-ORACLE-CB-VOTER",
                        &[HashPart::Json(&vote_record)],
                        32,
                    ),
                    choice: EmergencyVoteChoice::Halt,
                    voting_power: 1_000,
                    fee_units: 2,
                    sponsor_id: "sponsor:emergency".to_string(),
                    vote_height: height.saturating_sub(3),
                    pq_signature_commitment: domain_hash(
                        "PQ-DEFI-ORACLE-CB-EMERGENCY-VOTE-SIG",
                        &[HashPart::Json(&vote_record)],
                        32,
                    ),
                    nullifier,
                },
            );
        }

        for (kind, subject_id, summary) in [
            (
                PublicRecordKind::FeedHeartbeat,
                "feed:xmr-usd",
                "commitment-only heartbeat with private median retained by committee",
            ),
            (
                PublicRecordKind::GuardRailTriggered,
                "perp:xmr-usd",
                "perp venue moved reduce-only after divergent private oracle envelope",
            ),
            (
                PublicRecordKind::HaltActivated,
                "perp:xmr-usd",
                "fast halt lane executed with post-quantum signer quorum",
            ),
            (
                PublicRecordKind::VoteTally,
                halt_lane_id.as_str(),
                "low-fee emergency votes tallied without revealing voter identities",
            ),
        ] {
            let record = json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "height": height,
            });
            let record_id = deterministic_id("public-circuit-record", &record);
            let affected = vec![json!(subject_id)];
            public_records.insert(
                record_id.clone(),
                PublicCircuitRecord {
                    record_id,
                    kind,
                    subject_id: subject_id.to_string(),
                    height,
                    public_commitment: root_from_record(&record),
                    privacy_preserving_summary: summary.to_string(),
                    affected_protocols_root: merkle_root(
                        "PQ-DEFI-ORACLE-CB-AFFECTED-PROTOCOL",
                        &affected,
                    ),
                    proof_root: domain_hash(
                        "PQ-DEFI-ORACLE-CB-PUBLIC-RECORD-PROOF",
                        &[HashPart::Json(&record)],
                        32,
                    ),
                },
            );
        }

        for public_record in public_records.values() {
            events.push(Event {
                event_id: deterministic_id("event", &public_record.public_record()),
                height: public_record.height,
                kind: public_record.kind.as_str().to_string(),
                subject_id: public_record.subject_id.clone(),
                record_root: root_from_record(&public_record.public_record()),
            });
        }

        let state = Self {
            height,
            protocol_version: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PROTOCOL_VERSION.to_string(),
            hash_suite: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_HASH_SUITE.to_string(),
            pq_signature_scheme: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_PQ_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            kem_scheme: PQ_DEFI_ORACLE_CIRCUIT_BREAKER_KEM_SCHEME.to_string(),
            config,
            feeds,
            committees,
            members,
            attestations,
            risk_envelopes,
            guard_rails,
            fast_halt_lanes,
            resumption_proofs,
            emergency_votes,
            sponsors,
            public_records,
            nullifiers,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqDefiOracleCircuitBreakerResult<()> {
        validate_config(&self.config)?;
        validate_len(
            "feeds",
            self.feeds.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_FEEDS,
        )?;
        validate_len(
            "committees",
            self.committees.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_COMMITTEES,
        )?;
        validate_len(
            "members",
            self.members.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_MEMBERS,
        )?;
        validate_len(
            "attestations",
            self.attestations.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_ATTESTATIONS,
        )?;
        validate_len(
            "risk envelopes",
            self.risk_envelopes.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_RISK_ENVELOPES,
        )?;
        validate_len(
            "guard rails",
            self.guard_rails.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_GUARD_RAILS,
        )?;
        validate_len(
            "fast halt lanes",
            self.fast_halt_lanes.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_HALT_LANES,
        )?;
        validate_len(
            "resumption proofs",
            self.resumption_proofs.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_RESUMPTION_PROOFS,
        )?;
        validate_len(
            "emergency votes",
            self.emergency_votes.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_EMERGENCY_VOTES,
        )?;
        validate_len(
            "public records",
            self.public_records.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_PUBLIC_RECORDS,
        )?;
        validate_len(
            "events",
            self.events.len(),
            PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_EVENTS,
        )?;

        for (feed_id, feed) in &self.feeds {
            require(feed_id == &feed.feed_id, "feed map key mismatch")?;
            require(
                self.committees.contains_key(&feed.committee_id),
                "feed references missing committee",
            )?;
            require(
                feed.decimals <= 18,
                "feed decimals exceed supported precision",
            )?;
            require(
                feed.max_deviation_bps <= self.config.max_deviation_bps,
                "feed deviation exceeds config",
            )?;
            require(
                feed.privacy_set_size >= self.config.min_privacy_set_size,
                "feed privacy set below minimum",
            )?;
            if feed.status.accepts_attestations() {
                require(
                    self.height
                        <= feed
                            .last_update_height
                            .saturating_add(feed.heartbeat_blocks),
                    "active feed heartbeat is stale",
                )?;
            }
        }

        for (committee_id, committee) in &self.committees {
            require(
                committee_id == &committee.committee_id,
                "committee map key mismatch",
            )?;
            require(!committee.feed_ids.is_empty(), "committee has no feeds")?;
            require(!committee.member_ids.is_empty(), "committee has no members")?;
            require(
                committee.threshold_bps >= self.config.min_quorum_bps,
                "committee quorum below config minimum",
            )?;
            require(
                committee.fast_halt_threshold_bps >= self.config.fast_halt_bps,
                "committee fast halt threshold below config minimum",
            )?;
            require(
                committee.resumption_threshold_bps >= self.config.supermajority_bps,
                "committee resumption threshold below supermajority",
            )?;
            for feed_id in &committee.feed_ids {
                require(
                    self.feeds.contains_key(feed_id),
                    "committee references missing feed",
                )?;
            }
            for member_id in &committee.member_ids {
                require(
                    self.members.contains_key(member_id),
                    "committee references missing member",
                )?;
            }
        }

        for (member_id, member) in &self.members {
            require(member_id == &member.member_id, "member map key mismatch")?;
            require(
                self.committees.contains_key(&member.committee_id),
                "member references missing committee",
            )?;
            require(
                member.voting_power > 0,
                "member voting power must be positive",
            )?;
            require(
                member.security_bits >= self.config.min_pq_security_bits,
                "member PQ security below minimum",
            )?;
        }

        let mut counted_attestors = BTreeSet::new();
        for (attestation_id, attestation) in &self.attestations {
            require(
                attestation_id == &attestation.attestation_id,
                "attestation map key mismatch",
            )?;
            require(
                self.feeds.contains_key(&attestation.feed_id),
                "attestation references missing feed",
            )?;
            require(
                self.committees.contains_key(&attestation.committee_id),
                "attestation references missing committee",
            )?;
            let member = match self.members.get(&attestation.member_id) {
                Some(member) => member,
                None => return Err("attestation references missing member".to_string()),
            };
            require(member.status.can_vote(), "attestation member cannot vote")?;
            require(
                attestation.valid_until_height >= attestation.update_height,
                "attestation validity window is inverted",
            )?;
            require(
                attestation.deviation_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
                "attestation deviation exceeds bps range",
            )?;
            if attestation.status == AttestationStatus::Counted {
                let key = format!("{}:{}", attestation.feed_id, attestation.member_id);
                require(
                    counted_attestors.insert(key),
                    "duplicate counted attestation for feed and member",
                )?;
            }
        }

        for envelope in self.risk_envelopes.values() {
            require(
                self.feeds.contains_key(&envelope.feed_id),
                "risk envelope references missing feed",
            )?;
            require(
                envelope.valid_until_height >= envelope.valid_from_height,
                "risk envelope validity window is inverted",
            )?;
            if envelope.status == RiskEnvelopeStatus::Verified {
                require(
                    envelope.privacy_set_size >= self.config.min_privacy_set_size,
                    "verified risk envelope privacy set below minimum",
                )?;
                require(
                    envelope.leakage_budget_bps <= self.config.resume_deviation_bps,
                    "risk envelope leakage budget exceeds private resume bound",
                )?;
            }
        }

        for guard_rail in self.guard_rails.values() {
            require(
                self.feeds.contains_key(&guard_rail.feed_id),
                "guard rail references missing feed",
            )?;
            require(
                guard_rail.trigger_deviation_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
                "guard rail trigger exceeds bps range",
            )?;
            require(
                guard_rail.resume_deviation_bps <= guard_rail.trigger_deviation_bps,
                "guard rail resume threshold exceeds trigger threshold",
            )?;
            require(
                guard_rail.throttle_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
                "guard rail throttle exceeds bps range",
            )?;
        }

        for lane in self.fast_halt_lanes.values() {
            require(
                self.feeds.contains_key(&lane.feed_id),
                "halt lane references missing feed",
            )?;
            require(
                self.committees.contains_key(&lane.signer_committee_id),
                "halt lane references missing signer committee",
            )?;
            require(
                lane.expires_height >= lane.opened_height,
                "halt lane validity window is inverted",
            )?;
            require(
                lane.signer_weight_bps >= self.config.fast_halt_bps,
                "halt lane signer weight below fast halt threshold",
            )?;
            require(
                self.nullifiers.contains(&lane.nullifier),
                "halt lane nullifier missing from public nullifier set",
            )?;
        }

        for proof in self.resumption_proofs.values() {
            require(
                self.feeds.contains_key(&proof.feed_id),
                "resumption proof references missing feed",
            )?;
            require(
                self.fast_halt_lanes.contains_key(&proof.halted_lane_id),
                "resumption proof references missing halt lane",
            )?;
            require(
                proof.executable_height >= proof.proposal_height,
                "resumption executable height precedes proposal",
            )?;
            require(
                proof.valid_until_height >= proof.executable_height,
                "resumption proof expires before executable height",
            )?;
            require(
                proof.signer_weight_bps >= self.config.supermajority_bps,
                "resumption proof signer weight below supermajority",
            )?;
            if proof.status == ResumptionStatus::Accepted {
                require(
                    proof.deviation_bps <= self.config.resume_deviation_bps,
                    "accepted resumption proof deviation exceeds resume bound",
                )?;
            }
        }

        for vote in self.emergency_votes.values() {
            require(
                self.fast_halt_lanes.contains_key(&vote.lane_id),
                "emergency vote references missing halt lane",
            )?;
            require(
                self.sponsors.contains_key(&vote.sponsor_id),
                "emergency vote references missing sponsor",
            )?;
            require(
                vote.fee_units <= self.config.emergency_vote_fee_cap_units,
                "emergency vote fee exceeds low-fee cap",
            )?;
            require(
                self.nullifiers.contains(&vote.nullifier),
                "emergency vote nullifier missing from public nullifier set",
            )?;
        }

        for sponsor in self.sponsors.values() {
            require(
                sponsor.spent_units <= sponsor.budget_units,
                "sponsor spent units exceed budget",
            )?;
            require(
                sponsor.fee_cap_units <= self.config.emergency_vote_fee_cap_units,
                "sponsor fee cap exceeds config cap",
            )?;
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqDefiOracleCircuitBreakerResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PqDefiOracleCircuitBreakerResult<()> {
        require(height >= self.height, "new height cannot go backwards")?;
        self.height = height;
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            feed_root: map_root("PQ-DEFI-ORACLE-CB-FEED", &self.feeds),
            committee_root: map_root("PQ-DEFI-ORACLE-CB-COMMITTEE", &self.committees),
            member_root: map_root("PQ-DEFI-ORACLE-CB-MEMBER", &self.members),
            attestation_root: map_root("PQ-DEFI-ORACLE-CB-ATTESTATION", &self.attestations),
            private_risk_envelope_root: map_root(
                "PQ-DEFI-ORACLE-CB-RISK-ENVELOPE",
                &self.risk_envelopes,
            ),
            guard_rail_root: map_root("PQ-DEFI-ORACLE-CB-GUARD-RAIL", &self.guard_rails),
            fast_halt_lane_root: map_root("PQ-DEFI-ORACLE-CB-HALT-LANE", &self.fast_halt_lanes),
            resumption_proof_root: map_root(
                "PQ-DEFI-ORACLE-CB-RESUMPTION-PROOF",
                &self.resumption_proofs,
            ),
            emergency_vote_root: map_root(
                "PQ-DEFI-ORACLE-CB-EMERGENCY-VOTE",
                &self.emergency_votes,
            ),
            sponsor_root: map_root("PQ-DEFI-ORACLE-CB-SPONSOR", &self.sponsors),
            public_record_root: map_root("PQ-DEFI-ORACLE-CB-PUBLIC-RECORD", &self.public_records),
            nullifier_root: merkle_root(
                "PQ-DEFI-ORACLE-CB-NULLIFIER",
                &set_values(&self.nullifiers),
            ),
            event_root: merkle_root(
                "PQ-DEFI-ORACLE-CB-EVENT",
                &self
                    .events
                    .iter()
                    .map(Event::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            feeds: self.feeds.len() as u64,
            committees: self.committees.len() as u64,
            members: self.members.len() as u64,
            active_members: self
                .members
                .values()
                .filter(|member| member.status.can_vote())
                .count() as u64,
            attestations: self.attestations.len() as u64,
            counted_attestations: self
                .attestations
                .values()
                .filter(|attestation| attestation.status == AttestationStatus::Counted)
                .count() as u64,
            verified_risk_envelopes: self
                .risk_envelopes
                .values()
                .filter(|envelope| envelope.status == RiskEnvelopeStatus::Verified)
                .count() as u64,
            active_guard_rails: self
                .guard_rails
                .values()
                .filter(|guard_rail| {
                    matches!(
                        guard_rail.status,
                        GuardRailStatus::Armed
                            | GuardRailStatus::Triggered
                            | GuardRailStatus::CoolingDown
                    )
                })
                .count() as u64,
            triggered_guard_rails: self
                .guard_rails
                .values()
                .filter(|guard_rail| guard_rail.status == GuardRailStatus::Triggered)
                .count() as u64,
            open_halt_lanes: self
                .fast_halt_lanes
                .values()
                .filter(|lane| {
                    matches!(
                        lane.status,
                        HaltLaneStatus::Open | HaltLaneStatus::Escalated
                    )
                })
                .count() as u64,
            executed_halt_lanes: self
                .fast_halt_lanes
                .values()
                .filter(|lane| lane.status == HaltLaneStatus::Executed)
                .count() as u64,
            accepted_resumptions: self
                .resumption_proofs
                .values()
                .filter(|proof| proof.status == ResumptionStatus::Accepted)
                .count() as u64,
            emergency_votes: self.emergency_votes.len() as u64,
            sponsored_vote_units: self
                .emergency_votes
                .values()
                .map(|vote| vote.fee_units)
                .sum(),
            public_records: self.public_records.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PQ-DEFI-ORACLE-CB-STATE",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Json(&self.roots().public_record()),
                HashPart::Json(&self.counters().public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash("PQ-DEFI-ORACLE-CB-RECORD", &[HashPart::Json(record)], 32)
}

pub fn devnet() -> PqDefiOracleCircuitBreakerResult<State> {
    State::devnet()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Feed {
    fn public_record(&self) -> Value {
        Feed::public_record(self)
    }
}

impl PublicRecord for Committee {
    fn public_record(&self) -> Value {
        Committee::public_record(self)
    }
}

impl PublicRecord for CommitteeMember {
    fn public_record(&self) -> Value {
        CommitteeMember::public_record(self)
    }
}

impl PublicRecord for PqAttestation {
    fn public_record(&self) -> Value {
        PqAttestation::public_record(self)
    }
}

impl PublicRecord for PrivateRiskEnvelope {
    fn public_record(&self) -> Value {
        PrivateRiskEnvelope::public_record(self)
    }
}

impl PublicRecord for GuardRail {
    fn public_record(&self) -> Value {
        GuardRail::public_record(self)
    }
}

impl PublicRecord for FastHaltLane {
    fn public_record(&self) -> Value {
        FastHaltLane::public_record(self)
    }
}

impl PublicRecord for ResumptionProof {
    fn public_record(&self) -> Value {
        ResumptionProof::public_record(self)
    }
}

impl PublicRecord for EmergencyVote {
    fn public_record(&self) -> Value {
        EmergencyVote::public_record(self)
    }
}

impl PublicRecord for Sponsor {
    fn public_record(&self) -> Value {
        Sponsor::public_record(self)
    }
}

impl PublicRecord for PublicCircuitRecord {
    fn public_record(&self) -> Value {
        PublicCircuitRecord::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let values = records
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn set_values(values: &BTreeSet<String>) -> Vec<Value> {
    values.iter().map(|value| json!(value)).collect()
}

fn deterministic_id(prefix: &str, record: &Value) -> String {
    let digest = domain_hash(
        "PQ-DEFI-ORACLE-CB-ID",
        &[HashPart::Str(prefix), HashPart::Json(record)],
        16,
    );
    format!("{prefix}:{digest}")
}

fn validate_config(config: &Config) -> PqDefiOracleCircuitBreakerResult<()> {
    require(config.epoch_blocks > 0, "epoch blocks must be positive")?;
    require(
        config.attestation_ttl_blocks > 0,
        "attestation ttl must be positive",
    )?;
    require(
        config.fast_halt_ttl_blocks > 0,
        "fast halt ttl must be positive",
    )?;
    require(
        config.resumption_delay_blocks > 0,
        "resumption delay must be positive",
    )?;
    require(
        config.min_pq_security_bits >= 192,
        "minimum PQ security bits too low",
    )?;
    require(
        config.min_quorum_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
        "minimum quorum exceeds bps range",
    )?;
    require(
        config.supermajority_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
        "supermajority exceeds bps range",
    )?;
    require(
        config.fast_halt_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
        "fast halt threshold exceeds bps range",
    )?;
    require(
        config.max_deviation_bps <= PQ_DEFI_ORACLE_CIRCUIT_BREAKER_MAX_BPS,
        "max deviation exceeds bps range",
    )?;
    require(
        config.caution_deviation_bps <= config.max_deviation_bps,
        "caution deviation exceeds max deviation",
    )?;
    require(
        config.resume_deviation_bps <= config.caution_deviation_bps,
        "resume deviation exceeds caution deviation",
    )?;
    require(
        config.min_privacy_set_size > 0,
        "minimum privacy set size must be positive",
    )?;
    require(
        config.emergency_vote_fee_cap_units > 0,
        "emergency vote fee cap must be positive",
    )?;
    require(
        config.sponsor_budget_units >= config.emergency_vote_fee_cap_units,
        "sponsor budget must cover at least one vote",
    )?;
    Ok(())
}

fn validate_len(name: &str, len: usize, max: usize) -> PqDefiOracleCircuitBreakerResult<()> {
    require(len <= max, &format!("{name} exceeds maximum"))
}

fn require(condition: bool, message: &str) -> PqDefiOracleCircuitBreakerResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
