use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateOracleRiskCommitteeResult<T> = Result<T, String>;

pub const PRIVATE_ORACLE_RISK_COMMITTEE_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_PROTOCOL_ID: &str =
    "nebula-private-oracle-risk-committee-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEVNET_HEIGHT: u64 = 918;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_SEALING_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-sealed-price-attestation-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_RANGE_PROOF_SYSTEM: &str =
    "confidential-price-range-proof-envelope-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_VOTE_PROOF_SYSTEM: &str =
    "pq-signed-risk-vote-batch-proof-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_GUARD_RAIL_SCHEME: &str =
    "private-liquidation-guard-rails-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_SPONSOR_SCHEME: &str =
    "low-fee-private-oracle-update-sponsorship-v1";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_VOTE_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_ROTATION_DELAY_BLOCKS: u64 = 96;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SLASH_WINDOW_BLOCKS: u64 = 240;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 768;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SUPERMAJORITY_BPS: u64 = 7_500;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MAX_DEVIATION_BPS: u64 = 800;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_CAUTION_DEVIATION_BPS: u64 = 350;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_LIQUIDATION_HALT_BPS: u64 = 1_250;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SPONSOR_FEE_CAP_UNITS: u64 = 4;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 120_000;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MEMBER_BOND_UNITS: u64 = 250_000;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_REPORTER_REWARD_BPS: u64 = 1_000;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MARKETS: usize = 2_048;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MEMBERS: usize = 16_384;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_COMMITTEES: usize = 512;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RANGE_ENVELOPES: usize = 262_144;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RISK_VOTES: usize = 524_288;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_GUARD_RAILS: usize = 65_536;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SPONSORS: usize = 65_536;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ROTATIONS: usize = 32_768;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SLASHING_CASES: usize = 65_536;
pub const PRIVATE_ORACLE_RISK_COMMITTEE_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskMarketKind {
    Spot,
    PerpIndex,
    LendingCollateral,
    StablecoinPeg,
    VaultShare,
    AmmTwap,
    FundingRate,
    MoneroReserve,
    ProofFee,
    SequencerLatency,
}

impl RiskMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::PerpIndex => "perp_index",
            Self::LendingCollateral => "lending_collateral",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::VaultShare => "vault_share",
            Self::AmmTwap => "amm_twap",
            Self::FundingRate => "funding_rate",
            Self::MoneroReserve => "monero_reserve",
            Self::ProofFee => "proof_fee",
            Self::SequencerLatency => "sequencer_latency",
        }
    }

    pub fn default_heartbeat_blocks(self) -> u64 {
        match self {
            Self::Spot | Self::PerpIndex | Self::StablecoinPeg => 4,
            Self::AmmTwap | Self::FundingRate => 8,
            Self::LendingCollateral | Self::VaultShare => 12,
            Self::MoneroReserve => 10,
            Self::ProofFee | Self::SequencerLatency => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskMarketStatus {
    Active,
    Caution,
    Guarded,
    Halted,
    Quarantined,
    Retired,
}

impl RiskMarketStatus {
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

    pub fn allows_liquidations(self) -> bool {
        matches!(self, Self::Active | Self::Caution)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    PriceAttester,
    RiskVoter,
    LiquidationGuardian,
    SponsorAuditor,
    Watchtower,
    RotationSigner,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceAttester => "price_attester",
            Self::RiskVoter => "risk_voter",
            Self::LiquidationGuardian => "liquidation_guardian",
            Self::SponsorAuditor => "sponsor_auditor",
            Self::Watchtower => "watchtower",
            Self::RotationSigner => "rotation_signer",
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

    pub fn voting(self) -> bool {
        matches!(self, Self::Active | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedAttestationStatus {
    Submitted,
    RangeChecked,
    Counted,
    Rejected,
    Expired,
    Challenged,
}

impl SealedAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RangeChecked => "range_checked",
            Self::Counted => "counted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeEnvelopeStatus {
    Pending,
    Verified,
    Weak,
    Invalid,
    Expired,
}

impl RangeEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Weak => "weak",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVoteKind {
    Accept,
    Caution,
    RaiseMargin,
    ClampPrice,
    HaltLiquidations,
    QuarantineMarket,
    SlashMember,
    RotateCommittee,
}

impl RiskVoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Caution => "caution",
            Self::RaiseMargin => "raise_margin",
            Self::ClampPrice => "clamp_price",
            Self::HaltLiquidations => "halt_liquidations",
            Self::QuarantineMarket => "quarantine_market",
            Self::SlashMember => "slash_member",
            Self::RotateCommittee => "rotate_committee",
        }
    }

    pub fn restrictive(self) -> bool {
        matches!(
            self,
            Self::RaiseMargin
                | Self::ClampPrice
                | Self::HaltLiquidations
                | Self::QuarantineMarket
                | Self::SlashMember
                | Self::RotateCommittee
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVoteStatus {
    Submitted,
    Counted,
    Duplicate,
    InvalidSignature,
    InsufficientRole,
    Expired,
}

impl RiskVoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::InvalidSignature => "invalid_signature",
            Self::InsufficientRole => "insufficient_role",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardRailMode {
    ObserveOnly,
    SoftClamp,
    MarginRaise,
    AuctionOnly,
    HaltLiquidations,
    FullQuarantine,
}

impl GuardRailMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::SoftClamp => "soft_clamp",
            Self::MarginRaise => "margin_raise",
            Self::AuctionOnly => "auction_only",
            Self::HaltLiquidations => "halt_liquidations",
            Self::FullQuarantine => "full_quarantine",
        }
    }

    pub fn blocks_liquidations(self) -> bool {
        matches!(self, Self::HaltLiquidations | Self::FullQuarantine)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Scheduled,
    PendingSignatures,
    Executed,
    Cancelled,
    Challenged,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::PendingSignatures => "pending_signatures",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingCaseKind {
    BadRangeProof,
    InvalidPqSignature,
    PriceDivergence,
    RevealedSealedPayload,
    SponsorOverspend,
    GuardRailBypass,
    RotationEquivocation,
    OfflineDuringEmergency,
}

impl SlashingCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRangeProof => "bad_range_proof",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::PriceDivergence => "price_divergence",
            Self::RevealedSealedPayload => "revealed_sealed_payload",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::GuardRailBypass => "guard_rail_bypass",
            Self::RotationEquivocation => "rotation_equivocation",
            Self::OfflineDuringEmergency => "offline_during_emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingCaseStatus {
    Open,
    EvidenceAccepted,
    Upheld,
    Rejected,
    Expired,
}

impl SlashingCaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeEventKind {
    MarketRegistered,
    MemberJoined,
    SealedAttestationSubmitted,
    RangeEnvelopeVerified,
    RiskVoteCounted,
    GuardRailApplied,
    SponsorDebited,
    CommitteeRotationScheduled,
    CommitteeRotationExecuted,
    SlashingCaseOpened,
    MemberSlashed,
    StateValidated,
}

impl CommitteeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketRegistered => "market_registered",
            Self::MemberJoined => "member_joined",
            Self::SealedAttestationSubmitted => "sealed_attestation_submitted",
            Self::RangeEnvelopeVerified => "range_envelope_verified",
            Self::RiskVoteCounted => "risk_vote_counted",
            Self::GuardRailApplied => "guard_rail_applied",
            Self::SponsorDebited => "sponsor_debited",
            Self::CommitteeRotationScheduled => "committee_rotation_scheduled",
            Self::CommitteeRotationExecuted => "committee_rotation_executed",
            Self::SlashingCaseOpened => "slashing_case_opened",
            Self::MemberSlashed => "member_slashed",
            Self::StateValidated => "state_validated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleRiskCommitteeConfig {
    pub chain_id: String,
    pub protocol_version: u32,
    pub protocol_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub sealing_scheme: String,
    pub range_proof_system: String,
    pub vote_proof_system: String,
    pub guard_rail_scheme: String,
    pub sponsor_scheme: String,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub vote_ttl_blocks: u64,
    pub rotation_delay_blocks: u64,
    pub slash_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_deviation_bps: u64,
    pub caution_deviation_bps: u64,
    pub liquidation_halt_bps: u64,
    pub sponsor_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub member_bond_units: u64,
    pub slash_bps: u64,
    pub reporter_reward_bps: u64,
}

impl PrivateOracleRiskCommitteeConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_ORACLE_RISK_COMMITTEE_PROTOCOL_VERSION,
            protocol_id: PRIVATE_ORACLE_RISK_COMMITTEE_PROTOCOL_ID.to_string(),
            hash_suite: PRIVATE_ORACLE_RISK_COMMITTEE_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_PQ_KEM_SCHEME.to_string(),
            sealing_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_SEALING_SCHEME.to_string(),
            range_proof_system: PRIVATE_ORACLE_RISK_COMMITTEE_RANGE_PROOF_SYSTEM.to_string(),
            vote_proof_system: PRIVATE_ORACLE_RISK_COMMITTEE_VOTE_PROOF_SYSTEM.to_string(),
            guard_rail_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_GUARD_RAIL_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_ORACLE_RISK_COMMITTEE_SPONSOR_SCHEME.to_string(),
            fee_asset_id: PRIVATE_ORACLE_RISK_COMMITTEE_FEE_ASSET_ID.to_string(),
            monero_network: PRIVATE_ORACLE_RISK_COMMITTEE_MONERO_NETWORK.to_string(),
            epoch_blocks: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_EPOCH_BLOCKS,
            attestation_ttl_blocks: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            vote_ttl_blocks: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_VOTE_TTL_BLOCKS,
            rotation_delay_blocks: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_ROTATION_DELAY_BLOCKS,
            slash_window_blocks: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SLASH_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_quorum_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MIN_QUORUM_BPS,
            supermajority_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SUPERMAJORITY_BPS,
            max_deviation_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MAX_DEVIATION_BPS,
            caution_deviation_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_CAUTION_DEVIATION_BPS,
            liquidation_halt_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_LIQUIDATION_HALT_BPS,
            sponsor_fee_cap_units: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SPONSOR_FEE_CAP_UNITS,
            sponsor_budget_units: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SPONSOR_BUDGET_UNITS,
            member_bond_units: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_MEMBER_BOND_UNITS,
            slash_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_SLASH_BPS,
            reporter_reward_bps: PRIVATE_ORACLE_RISK_COMMITTEE_DEFAULT_REPORTER_REWARD_BPS,
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private oracle risk committee chain id mismatch".to_string());
        }
        if self.protocol_version == 0 {
            return Err(
                "private oracle risk committee protocol version must be nonzero".to_string(),
            );
        }
        if self.epoch_blocks == 0 || self.attestation_ttl_blocks == 0 || self.vote_ttl_blocks == 0 {
            return Err("private oracle risk committee timing windows must be nonzero".to_string());
        }
        if self.min_quorum_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.supermajority_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.max_deviation_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.caution_deviation_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.liquidation_halt_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.slash_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.reporter_reward_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
        {
            return Err("private oracle risk committee bps parameter out of range".to_string());
        }
        if self.caution_deviation_bps > self.max_deviation_bps {
            return Err("caution deviation cannot exceed maximum deviation".to_string());
        }
        if self.max_deviation_bps > self.liquidation_halt_bps {
            return Err("maximum deviation cannot exceed liquidation halt threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "sealing_scheme": self.sealing_scheme,
            "range_proof_system": self.range_proof_system,
            "vote_proof_system": self.vote_proof_system,
            "guard_rail_scheme": self.guard_rail_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "epoch_blocks": self.epoch_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "vote_ttl_blocks": self.vote_ttl_blocks,
            "rotation_delay_blocks": self.rotation_delay_blocks,
            "slash_window_blocks": self.slash_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_quorum_bps": self.min_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "caution_deviation_bps": self.caution_deviation_bps,
            "liquidation_halt_bps": self.liquidation_halt_bps,
            "sponsor_fee_cap_units": self.sponsor_fee_cap_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "member_bond_units": self.member_bond_units,
            "slash_bps": self.slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskMarket {
    pub market_id: String,
    pub symbol: String,
    pub kind: RiskMarketKind,
    pub status: RiskMarketStatus,
    pub quote_asset_id: String,
    pub settlement_asset_id: String,
    pub committee_id: String,
    pub heartbeat_blocks: u64,
    pub min_sources: u64,
    pub max_deviation_bps: u64,
    pub caution_deviation_bps: u64,
    pub liquidation_halt_bps: u64,
    pub last_attestation_height: u64,
    pub last_guard_rail_id: Option<String>,
    pub metadata_commitment: String,
}

impl RiskMarket {
    pub fn new(
        market_id: &str,
        symbol: &str,
        kind: RiskMarketKind,
        committee_id: &str,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        Self {
            market_id: market_id.to_string(),
            symbol: symbol.to_string(),
            kind,
            status: RiskMarketStatus::Active,
            quote_asset_id: "asset:usd".to_string(),
            settlement_asset_id: PRIVATE_ORACLE_RISK_COMMITTEE_FEE_ASSET_ID.to_string(),
            committee_id: committee_id.to_string(),
            heartbeat_blocks: kind.default_heartbeat_blocks(),
            min_sources: 5,
            max_deviation_bps: config.max_deviation_bps,
            caution_deviation_bps: config.caution_deviation_bps,
            liquidation_halt_bps: config.liquidation_halt_bps,
            last_attestation_height: 0,
            last_guard_rail_id: None,
            metadata_commitment: risk_committee_hash(
                "MARKET-METADATA",
                &[
                    HashPart::Str(market_id),
                    HashPart::Str(symbol),
                    HashPart::Str(kind.as_str()),
                ],
            ),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.market_id.is_empty() || self.symbol.is_empty() || self.committee_id.is_empty() {
            return Err("risk market id, symbol, and committee id are required".to_string());
        }
        if self.heartbeat_blocks == 0 || self.min_sources == 0 {
            return Err("risk market heartbeat and minimum sources must be nonzero".to_string());
        }
        if self.caution_deviation_bps > self.max_deviation_bps {
            return Err("risk market caution deviation exceeds maximum deviation".to_string());
        }
        if self.max_deviation_bps > self.liquidation_halt_bps {
            return Err("risk market max deviation exceeds liquidation halt threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "symbol": self.symbol,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "quote_asset_id": self.quote_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "committee_id": self.committee_id,
            "heartbeat_blocks": self.heartbeat_blocks,
            "min_sources": self.min_sources,
            "max_deviation_bps": self.max_deviation_bps,
            "caution_deviation_bps": self.caution_deviation_bps,
            "liquidation_halt_bps": self.liquidation_halt_bps,
            "last_attestation_height": self.last_attestation_height,
            "last_guard_rail_id": self.last_guard_rail_id,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("MARKET", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub status: MemberStatus,
    pub roles: BTreeSet<CommitteeRole>,
    pub pq_public_key_commitment: String,
    pub pq_backup_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub stake_bond_units: u64,
    pub voting_weight_bps: u64,
    pub joined_height: u64,
    pub last_seen_height: u64,
    pub slash_count: u64,
    pub reputation_score: u64,
}

impl CommitteeMember {
    pub fn devnet(index: u64, height: u64, config: &PrivateOracleRiskCommitteeConfig) -> Self {
        let member_id = format!("risk-member-{index:02}");
        let mut roles = BTreeSet::new();
        roles.insert(CommitteeRole::PriceAttester);
        roles.insert(CommitteeRole::RiskVoter);
        roles.insert(CommitteeRole::Watchtower);
        if index % 2 == 0 {
            roles.insert(CommitteeRole::LiquidationGuardian);
        }
        if index % 3 == 0 {
            roles.insert(CommitteeRole::SponsorAuditor);
            roles.insert(CommitteeRole::RotationSigner);
        }
        Self {
            member_id: member_id.clone(),
            operator_label: format!("devnet-risk-operator-{index:02}"),
            status: MemberStatus::Active,
            roles,
            pq_public_key_commitment: risk_committee_hash(
                "MEMBER-PQ-KEY",
                &[HashPart::Str(&member_id), HashPart::Int(index as i128)],
            ),
            pq_backup_key_commitment: risk_committee_hash(
                "MEMBER-PQ-BACKUP-KEY",
                &[HashPart::Str(&member_id), HashPart::Int(index as i128)],
            ),
            kem_public_key_commitment: risk_committee_hash(
                "MEMBER-KEM-KEY",
                &[HashPart::Str(&member_id), HashPart::Int(index as i128)],
            ),
            stake_bond_units: config.member_bond_units,
            voting_weight_bps: 1_000,
            joined_height: height,
            last_seen_height: height,
            slash_count: 0,
            reputation_score: 1_000,
        }
    }

    pub fn has_role(&self, role: CommitteeRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.member_id.is_empty() || self.operator_label.is_empty() {
            return Err("committee member id and operator label are required".to_string());
        }
        if self.roles.is_empty() {
            return Err("committee member must carry at least one role".to_string());
        }
        if self.voting_weight_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS {
            return Err("committee member voting weight out of range".to_string());
        }
        if self.pq_public_key_commitment.is_empty()
            || self.pq_backup_key_commitment.is_empty()
            || self.kem_public_key_commitment.is_empty()
        {
            return Err("committee member key commitments are required".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roles = self
            .roles
            .iter()
            .map(|role| Value::String(role.as_str().to_string()))
            .collect::<Vec<_>>();
        json!({
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "status": self.status.as_str(),
            "roles": roles,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "pq_backup_key_commitment": self.pq_backup_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "stake_bond_units": self.stake_bond_units,
            "voting_weight_bps": self.voting_weight_bps,
            "joined_height": self.joined_height,
            "last_seen_height": self.last_seen_height,
            "slash_count": self.slash_count,
            "reputation_score": self.reputation_score,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("MEMBER", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub status: RotationStatus,
    pub member_ids: BTreeSet<String>,
    pub quorum_bps: u64,
    pub supermajority_bps: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub rotation_nonce: u64,
    pub transcript_commitment: String,
}

impl RiskCommittee {
    pub fn devnet(
        height: u64,
        member_ids: BTreeSet<String>,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        Self {
            committee_id: "risk-committee-devnet-0".to_string(),
            epoch: 0,
            status: RotationStatus::Executed,
            member_ids,
            quorum_bps: config.min_quorum_bps,
            supermajority_bps: config.supermajority_bps,
            activation_height: height,
            retirement_height: None,
            rotation_nonce: 0,
            transcript_commitment: risk_committee_hash(
                "COMMITTEE-TRANSCRIPT",
                &[HashPart::Int(height as i128)],
            ),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.committee_id.is_empty() {
            return Err("risk committee id is required".to_string());
        }
        if self.member_ids.is_empty() {
            return Err("risk committee must include members".to_string());
        }
        if self.quorum_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
            || self.supermajority_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS
        {
            return Err("risk committee threshold out of range".to_string());
        }
        if self.quorum_bps > self.supermajority_bps {
            return Err("risk committee quorum cannot exceed supermajority".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let member_ids = self
            .member_ids
            .iter()
            .map(|member_id| Value::String(member_id.clone()))
            .collect::<Vec<_>>();
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "member_ids": member_ids,
            "quorum_bps": self.quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "rotation_nonce": self.rotation_nonce,
            "transcript_commitment": self.transcript_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("COMMITTEE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPriceAttestation {
    pub attestation_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub epoch: u64,
    pub height: u64,
    pub expires_height: u64,
    pub status: SealedAttestationStatus,
    pub sealed_price_commitment: String,
    pub sealed_payload_ciphertext_root: String,
    pub nonce_commitment: String,
    pub range_envelope_id: String,
    pub sponsor_id: Option<String>,
    pub pq_signature_commitment: String,
    pub public_metadata_root: String,
}

impl SealedPriceAttestation {
    pub fn new(
        attestation_id: &str,
        market_id: &str,
        committee_id: &str,
        member_id: &str,
        range_envelope_id: &str,
        height: u64,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        let sealed_price_commitment = risk_committee_hash(
            "SEALED-PRICE",
            &[
                HashPart::Str(attestation_id),
                HashPart::Str(market_id),
                HashPart::Str(member_id),
                HashPart::Int(height as i128),
            ],
        );
        Self {
            attestation_id: attestation_id.to_string(),
            market_id: market_id.to_string(),
            committee_id: committee_id.to_string(),
            member_id: member_id.to_string(),
            epoch: height / config.epoch_blocks,
            height,
            expires_height: height.saturating_add(config.attestation_ttl_blocks),
            status: SealedAttestationStatus::Submitted,
            sealed_payload_ciphertext_root: risk_committee_hash(
                "SEALED-PAYLOAD-CIPHERTEXT",
                &[HashPart::Str(&sealed_price_commitment)],
            ),
            nonce_commitment: risk_committee_hash(
                "ATTESTATION-NONCE",
                &[HashPart::Str(attestation_id)],
            ),
            sealed_price_commitment,
            range_envelope_id: range_envelope_id.to_string(),
            sponsor_id: None,
            pq_signature_commitment: risk_committee_hash(
                "ATTESTATION-PQ-SIGNATURE",
                &[HashPart::Str(attestation_id), HashPart::Str(member_id)],
            ),
            public_metadata_root: risk_committee_hash(
                "ATTESTATION-METADATA",
                &[HashPart::Str(market_id), HashPart::Str(committee_id)],
            ),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.attestation_id.is_empty()
            || self.market_id.is_empty()
            || self.committee_id.is_empty()
            || self.member_id.is_empty()
            || self.range_envelope_id.is_empty()
        {
            return Err("sealed price attestation identity fields are required".to_string());
        }
        if self.expires_height < self.height {
            return Err("sealed price attestation expires before submission".to_string());
        }
        if self.sealed_price_commitment.is_empty()
            || self.sealed_payload_ciphertext_root.is_empty()
            || self.pq_signature_commitment.is_empty()
        {
            return Err("sealed price attestation commitments are required".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "epoch": self.epoch,
            "height": self.height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "sealed_price_commitment": self.sealed_price_commitment,
            "sealed_payload_ciphertext_root": self.sealed_payload_ciphertext_root,
            "nonce_commitment": self.nonce_commitment,
            "range_envelope_id": self.range_envelope_id,
            "sponsor_id": self.sponsor_id,
            "pq_signature_commitment": self.pq_signature_commitment,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash(
            "SEALED-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProofEnvelope {
    pub envelope_id: String,
    pub market_id: String,
    pub proof_system: String,
    pub status: RangeEnvelopeStatus,
    pub lower_bound_commitment: String,
    pub upper_bound_commitment: String,
    pub median_hint_commitment: String,
    pub proof_commitment: String,
    pub verifier_key_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RangeProofEnvelope {
    pub fn new(
        envelope_id: &str,
        market_id: &str,
        height: u64,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        Self {
            envelope_id: envelope_id.to_string(),
            market_id: market_id.to_string(),
            proof_system: config.range_proof_system.clone(),
            status: RangeEnvelopeStatus::Pending,
            lower_bound_commitment: risk_committee_hash(
                "RANGE-LOWER",
                &[HashPart::Str(envelope_id)],
            ),
            upper_bound_commitment: risk_committee_hash(
                "RANGE-UPPER",
                &[HashPart::Str(envelope_id)],
            ),
            median_hint_commitment: risk_committee_hash(
                "RANGE-MEDIAN-HINT",
                &[HashPart::Str(envelope_id)],
            ),
            proof_commitment: risk_committee_hash("RANGE-PROOF", &[HashPart::Str(envelope_id)]),
            verifier_key_commitment: risk_committee_hash(
                "RANGE-VERIFIER-KEY",
                &[HashPart::Str(market_id)],
            ),
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            created_height: height,
            expires_height: height.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn validate(
        &self,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> PrivateOracleRiskCommitteeResult<()> {
        if self.envelope_id.is_empty() || self.market_id.is_empty() || self.proof_system.is_empty()
        {
            return Err(
                "range proof envelope id, market, and proof system are required".to_string(),
            );
        }
        if self.expires_height < self.created_height {
            return Err("range proof envelope expires before creation".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("range proof envelope privacy set below policy".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("range proof envelope pq security below policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "market_id": self.market_id,
            "proof_system": self.proof_system,
            "status": self.status.as_str(),
            "lower_bound_commitment": self.lower_bound_commitment,
            "upper_bound_commitment": self.upper_bound_commitment,
            "median_hint_commitment": self.median_hint_commitment,
            "proof_commitment": self.proof_commitment,
            "verifier_key_commitment": self.verifier_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("RANGE-ENVELOPE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskVote {
    pub vote_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub attestation_id: Option<String>,
    pub kind: RiskVoteKind,
    pub status: RiskVoteStatus,
    pub weight_bps: u64,
    pub height: u64,
    pub expires_height: u64,
    pub risk_delta_bps: u64,
    pub evidence_root: String,
    pub pq_signature_commitment: String,
    pub nullifier: String,
}

impl PqRiskVote {
    pub fn new(
        vote_id: &str,
        market_id: &str,
        committee_id: &str,
        member_id: &str,
        kind: RiskVoteKind,
        height: u64,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        Self {
            vote_id: vote_id.to_string(),
            market_id: market_id.to_string(),
            committee_id: committee_id.to_string(),
            member_id: member_id.to_string(),
            attestation_id: None,
            kind,
            status: RiskVoteStatus::Submitted,
            weight_bps: 0,
            height,
            expires_height: height.saturating_add(config.vote_ttl_blocks),
            risk_delta_bps: 0,
            evidence_root: risk_committee_hash("RISK-VOTE-EVIDENCE", &[HashPart::Str(vote_id)]),
            pq_signature_commitment: risk_committee_hash(
                "RISK-VOTE-PQ-SIGNATURE",
                &[
                    HashPart::Str(vote_id),
                    HashPart::Str(member_id),
                    HashPart::Str(kind.as_str()),
                ],
            ),
            nullifier: risk_committee_hash(
                "RISK-VOTE-NULLIFIER",
                &[
                    HashPart::Str(market_id),
                    HashPart::Str(member_id),
                    HashPart::Int(height as i128),
                ],
            ),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.vote_id.is_empty()
            || self.market_id.is_empty()
            || self.committee_id.is_empty()
            || self.member_id.is_empty()
        {
            return Err("risk vote identity fields are required".to_string());
        }
        if self.expires_height < self.height {
            return Err("risk vote expires before submission".to_string());
        }
        if self.weight_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS {
            return Err("risk vote weight out of range".to_string());
        }
        if self.risk_delta_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS {
            return Err("risk vote risk delta out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "weight_bps": self.weight_bps,
            "height": self.height,
            "expires_height": self.expires_height,
            "risk_delta_bps": self.risk_delta_bps,
            "evidence_root": self.evidence_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "nullifier": self.nullifier,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("RISK-VOTE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationGuardRail {
    pub guard_rail_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub mode: GuardRailMode,
    pub activated_height: u64,
    pub expires_height: u64,
    pub triggering_vote_ids: BTreeSet<String>,
    pub triggering_attestation_ids: BTreeSet<String>,
    pub price_clamp_commitment: String,
    pub margin_multiplier_bps: u64,
    pub max_liquidation_notional_commitment: String,
    pub public_reason_code: String,
}

impl LiquidationGuardRail {
    pub fn new(
        guard_rail_id: &str,
        market_id: &str,
        committee_id: &str,
        mode: GuardRailMode,
        height: u64,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        Self {
            guard_rail_id: guard_rail_id.to_string(),
            market_id: market_id.to_string(),
            committee_id: committee_id.to_string(),
            mode,
            activated_height: height,
            expires_height: height.saturating_add(config.vote_ttl_blocks),
            triggering_vote_ids: BTreeSet::new(),
            triggering_attestation_ids: BTreeSet::new(),
            price_clamp_commitment: risk_committee_hash(
                "GUARD-RAIL-CLAMP",
                &[HashPart::Str(guard_rail_id)],
            ),
            margin_multiplier_bps: PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS,
            max_liquidation_notional_commitment: risk_committee_hash(
                "GUARD-RAIL-NOTIONAL",
                &[HashPart::Str(guard_rail_id)],
            ),
            public_reason_code: mode.as_str().to_string(),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.guard_rail_id.is_empty()
            || self.market_id.is_empty()
            || self.committee_id.is_empty()
        {
            return Err("liquidation guard rail identity fields are required".to_string());
        }
        if self.expires_height < self.activated_height {
            return Err("liquidation guard rail expires before activation".to_string());
        }
        if self.margin_multiplier_bps > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS * 5 {
            return Err("liquidation guard rail margin multiplier out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let vote_ids = self
            .triggering_vote_ids
            .iter()
            .map(|vote_id| Value::String(vote_id.clone()))
            .collect::<Vec<_>>();
        let attestation_ids = self
            .triggering_attestation_ids
            .iter()
            .map(|attestation_id| Value::String(attestation_id.clone()))
            .collect::<Vec<_>>();
        json!({
            "guard_rail_id": self.guard_rail_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "mode": self.mode.as_str(),
            "activated_height": self.activated_height,
            "expires_height": self.expires_height,
            "triggering_vote_ids": vote_ids,
            "triggering_attestation_ids": attestation_ids,
            "price_clamp_commitment": self.price_clamp_commitment,
            "margin_multiplier_bps": self.margin_multiplier_bps,
            "max_liquidation_notional_commitment": self.max_liquidation_notional_commitment,
            "public_reason_code": self.public_reason_code,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("GUARD-RAIL", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleUpdateSponsor {
    pub sponsor_id: String,
    pub owner_commitment: String,
    pub status: SponsorshipStatus,
    pub market_ids: BTreeSet<String>,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub per_update_cap_units: u64,
    pub privacy_pool_commitment: String,
    pub audit_nullifier_root: String,
    pub last_debit_height: u64,
}

impl OracleUpdateSponsor {
    pub fn devnet(config: &PrivateOracleRiskCommitteeConfig) -> Self {
        let mut market_ids = BTreeSet::new();
        market_ids.insert("xmr-usd".to_string());
        market_ids.insert("dxmr-usd".to_string());
        Self {
            sponsor_id: "risk-sponsor-devnet-0".to_string(),
            owner_commitment: risk_committee_hash("SPONSOR-OWNER", &[HashPart::Str("devnet")]),
            status: SponsorshipStatus::Active,
            market_ids,
            fee_asset_id: config.fee_asset_id.clone(),
            budget_units: config.sponsor_budget_units,
            spent_units: 0,
            per_update_cap_units: config.sponsor_fee_cap_units,
            privacy_pool_commitment: risk_committee_hash(
                "SPONSOR-PRIVACY-POOL",
                &[HashPart::Str("devnet")],
            ),
            audit_nullifier_root: risk_committee_hash(
                "SPONSOR-AUDIT-NULLIFIER",
                &[HashPart::Str("devnet")],
            ),
            last_debit_height: 0,
        }
    }

    pub fn remaining_budget_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn can_sponsor(&self, market_id: &str, fee_units: u64) -> bool {
        self.status == SponsorshipStatus::Active
            && self.market_ids.contains(market_id)
            && fee_units <= self.per_update_cap_units
            && fee_units <= self.remaining_budget_units()
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.sponsor_id.is_empty() || self.owner_commitment.is_empty() {
            return Err("oracle update sponsor id and owner commitment are required".to_string());
        }
        if self.spent_units > self.budget_units {
            return Err("oracle update sponsor spent units exceed budget".to_string());
        }
        if self.per_update_cap_units == 0 {
            return Err("oracle update sponsor per update cap must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let market_ids = self
            .market_ids
            .iter()
            .map(|market_id| Value::String(market_id.clone()))
            .collect::<Vec<_>>();
        json!({
            "sponsor_id": self.sponsor_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "market_ids": market_ids,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_budget_units": self.remaining_budget_units(),
            "per_update_cap_units": self.per_update_cap_units,
            "privacy_pool_commitment": self.privacy_pool_commitment,
            "audit_nullifier_root": self.audit_nullifier_root,
            "last_debit_height": self.last_debit_height,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("SPONSOR", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeRotation {
    pub rotation_id: String,
    pub old_committee_id: String,
    pub new_committee_id: String,
    pub status: RotationStatus,
    pub scheduled_height: u64,
    pub executable_height: u64,
    pub executed_height: Option<u64>,
    pub retiring_member_ids: BTreeSet<String>,
    pub joining_member_ids: BTreeSet<String>,
    pub pq_signature_commitments: BTreeMap<String, String>,
    pub transcript_commitment: String,
}

impl CommitteeRotation {
    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.rotation_id.is_empty()
            || self.old_committee_id.is_empty()
            || self.new_committee_id.is_empty()
        {
            return Err("committee rotation identity fields are required".to_string());
        }
        if self.executable_height < self.scheduled_height {
            return Err("committee rotation executable height precedes schedule".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let retiring_member_ids = self
            .retiring_member_ids
            .iter()
            .map(|member_id| Value::String(member_id.clone()))
            .collect::<Vec<_>>();
        let joining_member_ids = self
            .joining_member_ids
            .iter()
            .map(|member_id| Value::String(member_id.clone()))
            .collect::<Vec<_>>();
        json!({
            "rotation_id": self.rotation_id,
            "old_committee_id": self.old_committee_id,
            "new_committee_id": self.new_committee_id,
            "status": self.status.as_str(),
            "scheduled_height": self.scheduled_height,
            "executable_height": self.executable_height,
            "executed_height": self.executed_height,
            "retiring_member_ids": retiring_member_ids,
            "joining_member_ids": joining_member_ids,
            "pq_signature_commitments": self.pq_signature_commitments,
            "transcript_commitment": self.transcript_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("ROTATION", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingCase {
    pub case_id: String,
    pub kind: SlashingCaseKind,
    pub status: SlashingCaseStatus,
    pub accused_member_id: String,
    pub reporter_member_id: String,
    pub market_id: Option<String>,
    pub opened_height: u64,
    pub expires_height: u64,
    pub resolved_height: Option<u64>,
    pub evidence_root: String,
    pub penalty_units: u64,
    pub reporter_reward_units: u64,
    pub affected_attestation_ids: BTreeSet<String>,
    pub affected_vote_ids: BTreeSet<String>,
}

impl SlashingCase {
    pub fn new(
        case_id: &str,
        kind: SlashingCaseKind,
        accused_member_id: &str,
        reporter_member_id: &str,
        height: u64,
        config: &PrivateOracleRiskCommitteeConfig,
    ) -> Self {
        let penalty_units = config.member_bond_units.saturating_mul(config.slash_bps)
            / PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS;
        Self {
            case_id: case_id.to_string(),
            kind,
            status: SlashingCaseStatus::Open,
            accused_member_id: accused_member_id.to_string(),
            reporter_member_id: reporter_member_id.to_string(),
            market_id: None,
            opened_height: height,
            expires_height: height.saturating_add(config.slash_window_blocks),
            resolved_height: None,
            evidence_root: risk_committee_hash(
                "SLASH-EVIDENCE",
                &[HashPart::Str(case_id), HashPart::Str(kind.as_str())],
            ),
            penalty_units,
            reporter_reward_units: penalty_units.saturating_mul(config.reporter_reward_bps)
                / PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS,
            affected_attestation_ids: BTreeSet::new(),
            affected_vote_ids: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<()> {
        if self.case_id.is_empty()
            || self.accused_member_id.is_empty()
            || self.reporter_member_id.is_empty()
        {
            return Err("slashing case identity fields are required".to_string());
        }
        if self.expires_height < self.opened_height {
            return Err("slashing case expires before opening".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let affected_attestation_ids = self
            .affected_attestation_ids
            .iter()
            .map(|attestation_id| Value::String(attestation_id.clone()))
            .collect::<Vec<_>>();
        let affected_vote_ids = self
            .affected_vote_ids
            .iter()
            .map(|vote_id| Value::String(vote_id.clone()))
            .collect::<Vec<_>>();
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "accused_member_id": self.accused_member_id,
            "reporter_member_id": self.reporter_member_id,
            "market_id": self.market_id,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "resolved_height": self.resolved_height,
            "evidence_root": self.evidence_root,
            "penalty_units": self.penalty_units,
            "reporter_reward_units": self.reporter_reward_units,
            "affected_attestation_ids": affected_attestation_ids,
            "affected_vote_ids": affected_vote_ids,
        })
    }

    pub fn commitment(&self) -> String {
        risk_committee_hash("SLASHING-CASE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCommitteeEvent {
    pub event_id: String,
    pub kind: CommitteeEventKind,
    pub height: u64,
    pub subject_id: String,
    pub market_id: Option<String>,
    pub committee_id: Option<String>,
    pub payload_root: String,
}

impl RiskCommitteeEvent {
    pub fn new(kind: CommitteeEventKind, height: u64, subject_id: &str, payload: &Value) -> Self {
        let payload_root = risk_committee_hash("EVENT-PAYLOAD", &[HashPart::Json(payload)]);
        let event_id = risk_committee_hash(
            "EVENT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Int(height as i128),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
            ],
        );
        Self {
            event_id,
            kind,
            height,
            subject_id: subject_id.to_string(),
            market_id: None,
            committee_id: None,
            payload_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "height": self.height,
            "subject_id": self.subject_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleRiskCommitteeRoots {
    pub config_root: String,
    pub market_root: String,
    pub member_root: String,
    pub committee_root: String,
    pub attestation_root: String,
    pub range_envelope_root: String,
    pub risk_vote_root: String,
    pub guard_rail_root: String,
    pub sponsor_root: String,
    pub rotation_root: String,
    pub slashing_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl PrivateOracleRiskCommitteeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "market_root": self.market_root,
            "member_root": self.member_root,
            "committee_root": self.committee_root,
            "attestation_root": self.attestation_root,
            "range_envelope_root": self.range_envelope_root,
            "risk_vote_root": self.risk_vote_root,
            "guard_rail_root": self.guard_rail_root,
            "sponsor_root": self.sponsor_root,
            "rotation_root": self.rotation_root,
            "slashing_root": self.slashing_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleRiskCommitteeCounters {
    pub height: u64,
    pub markets: usize,
    pub active_markets: usize,
    pub members: usize,
    pub active_members: usize,
    pub committees: usize,
    pub sealed_attestations: usize,
    pub counted_attestations: usize,
    pub range_envelopes: usize,
    pub verified_range_envelopes: usize,
    pub risk_votes: usize,
    pub counted_votes: usize,
    pub active_guard_rails: usize,
    pub sponsors: usize,
    pub rotations: usize,
    pub slashing_cases: usize,
    pub events: usize,
}

impl PrivateOracleRiskCommitteeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "markets": self.markets,
            "active_markets": self.active_markets,
            "members": self.members,
            "active_members": self.active_members,
            "committees": self.committees,
            "sealed_attestations": self.sealed_attestations,
            "counted_attestations": self.counted_attestations,
            "range_envelopes": self.range_envelopes,
            "verified_range_envelopes": self.verified_range_envelopes,
            "risk_votes": self.risk_votes,
            "counted_votes": self.counted_votes,
            "active_guard_rails": self.active_guard_rails,
            "sponsors": self.sponsors,
            "rotations": self.rotations,
            "slashing_cases": self.slashing_cases,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleRiskCommitteeState {
    pub config: PrivateOracleRiskCommitteeConfig,
    pub height: u64,
    pub markets: BTreeMap<String, RiskMarket>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub committees: BTreeMap<String, RiskCommittee>,
    pub sealed_attestations: BTreeMap<String, SealedPriceAttestation>,
    pub range_envelopes: BTreeMap<String, RangeProofEnvelope>,
    pub risk_votes: BTreeMap<String, PqRiskVote>,
    pub guard_rails: BTreeMap<String, LiquidationGuardRail>,
    pub sponsors: BTreeMap<String, OracleUpdateSponsor>,
    pub rotations: BTreeMap<String, CommitteeRotation>,
    pub slashing_cases: BTreeMap<String, SlashingCase>,
    pub events: BTreeMap<String, RiskCommitteeEvent>,
}

impl PrivateOracleRiskCommitteeState {
    pub fn new(config: PrivateOracleRiskCommitteeConfig) -> PrivateOracleRiskCommitteeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            markets: BTreeMap::new(),
            members: BTreeMap::new(),
            committees: BTreeMap::new(),
            sealed_attestations: BTreeMap::new(),
            range_envelopes: BTreeMap::new(),
            risk_votes: BTreeMap::new(),
            guard_rails: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            rotations: BTreeMap::new(),
            slashing_cases: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PrivateOracleRiskCommitteeResult<Self> {
        let config = PrivateOracleRiskCommitteeConfig::devnet();
        let mut state = Self::new(config)?;
        state.set_height(PRIVATE_ORACLE_RISK_COMMITTEE_DEVNET_HEIGHT)?;

        for index in 0..10 {
            state.register_member(CommitteeMember::devnet(index, state.height, &state.config))?;
        }
        let member_ids = state.members.keys().cloned().collect::<BTreeSet<_>>();
        state.register_committee(RiskCommittee::devnet(
            state.height,
            member_ids,
            &state.config,
        ))?;

        state.register_market(RiskMarket::new(
            "xmr-usd",
            "XMR/USD",
            RiskMarketKind::Spot,
            "risk-committee-devnet-0",
            &state.config,
        ))?;
        state.register_market(RiskMarket::new(
            "dxmr-usd",
            "DXMR/USD",
            RiskMarketKind::StablecoinPeg,
            "risk-committee-devnet-0",
            &state.config,
        ))?;
        state.register_market(RiskMarket::new(
            "xmr-perp-index",
            "XMR-PERP",
            RiskMarketKind::PerpIndex,
            "risk-committee-devnet-0",
            &state.config,
        ))?;

        state.register_sponsor(OracleUpdateSponsor::devnet(&state.config))?;
        let envelope =
            RangeProofEnvelope::new("range-xmr-usd-0", "xmr-usd", state.height, &state.config);
        state.register_range_envelope(envelope)?;
        let attestation = SealedPriceAttestation::new(
            "sealed-xmr-usd-0",
            "xmr-usd",
            "risk-committee-devnet-0",
            "risk-member-00",
            "range-xmr-usd-0",
            state.height,
            &state.config,
        );
        state.submit_sealed_attestation(attestation, Some("risk-sponsor-devnet-0"), 2)?;
        state.verify_range_envelope("range-xmr-usd-0")?;
        state.count_attestation("sealed-xmr-usd-0")?;
        let vote = PqRiskVote::new(
            "risk-vote-xmr-usd-0",
            "xmr-usd",
            "risk-committee-devnet-0",
            "risk-member-01",
            RiskVoteKind::Accept,
            state.height,
            &state.config,
        );
        state.submit_risk_vote(vote)?;
        state.count_risk_vote("risk-vote-xmr-usd-0")?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateOracleRiskCommitteeResult<String> {
        if height < self.height {
            return Err("private oracle risk committee height cannot decrease".to_string());
        }
        self.height = height;
        for attestation in self.sealed_attestations.values_mut() {
            if attestation.status != SealedAttestationStatus::Counted
                && attestation.expires_height < height
            {
                attestation.status = SealedAttestationStatus::Expired;
            }
        }
        for envelope in self.range_envelopes.values_mut() {
            if envelope.status == RangeEnvelopeStatus::Pending && envelope.expires_height < height {
                envelope.status = RangeEnvelopeStatus::Expired;
            }
        }
        for vote in self.risk_votes.values_mut() {
            if vote.status == RiskVoteStatus::Submitted && vote.expires_height < height {
                vote.status = RiskVoteStatus::Expired;
            }
        }
        self.push_event(
            CommitteeEventKind::StateValidated,
            "height",
            &json!({"height": height}),
        );
        Ok(self.state_root())
    }

    pub fn register_market(
        &mut self,
        market: RiskMarket,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.markets.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MARKETS {
            return Err("private oracle risk committee market capacity exceeded".to_string());
        }
        market.validate()?;
        if !self.committees.contains_key(&market.committee_id) {
            return Err("risk market committee is unknown".to_string());
        }
        let market_id = market.market_id.clone();
        self.markets.insert(market_id.clone(), market);
        self.push_event(
            CommitteeEventKind::MarketRegistered,
            &market_id,
            &json!({"market_id": market_id}),
        );
        Ok(self.state_root())
    }

    pub fn register_member(
        &mut self,
        member: CommitteeMember,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.members.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MEMBERS {
            return Err("private oracle risk committee member capacity exceeded".to_string());
        }
        member.validate()?;
        let member_id = member.member_id.clone();
        self.members.insert(member_id.clone(), member);
        self.push_event(
            CommitteeEventKind::MemberJoined,
            &member_id,
            &json!({"member_id": member_id}),
        );
        Ok(self.state_root())
    }

    pub fn register_committee(
        &mut self,
        committee: RiskCommittee,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.committees.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_COMMITTEES {
            return Err("private oracle risk committee capacity exceeded".to_string());
        }
        committee.validate()?;
        for member_id in &committee.member_ids {
            if !self.members.contains_key(member_id) {
                return Err(format!(
                    "risk committee references unknown member {member_id}"
                ));
            }
        }
        let committee_id = committee.committee_id.clone();
        self.committees.insert(committee_id.clone(), committee);
        self.push_event(
            CommitteeEventKind::CommitteeRotationExecuted,
            &committee_id,
            &json!({"committee_id": committee_id}),
        );
        Ok(self.state_root())
    }

    pub fn register_sponsor(
        &mut self,
        sponsor: OracleUpdateSponsor,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.sponsors.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SPONSORS {
            return Err("private oracle risk committee sponsor capacity exceeded".to_string());
        }
        sponsor.validate()?;
        for market_id in &sponsor.market_ids {
            if !self.markets.contains_key(market_id) {
                return Err(format!(
                    "oracle update sponsor references unknown market {market_id}"
                ));
            }
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsors.insert(sponsor_id, sponsor);
        Ok(self.state_root())
    }

    pub fn register_range_envelope(
        &mut self,
        envelope: RangeProofEnvelope,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.range_envelopes.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RANGE_ENVELOPES {
            return Err(
                "private oracle risk committee range envelope capacity exceeded".to_string(),
            );
        }
        envelope.validate(&self.config)?;
        if !self.markets.contains_key(&envelope.market_id) {
            return Err("range proof envelope market is unknown".to_string());
        }
        let envelope_id = envelope.envelope_id.clone();
        self.range_envelopes.insert(envelope_id, envelope);
        Ok(self.state_root())
    }

    pub fn submit_sealed_attestation(
        &mut self,
        mut attestation: SealedPriceAttestation,
        sponsor_id: Option<&str>,
        fee_units: u64,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.sealed_attestations.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ATTESTATIONS {
            return Err("private oracle risk committee attestation capacity exceeded".to_string());
        }
        attestation.validate()?;
        self.ensure_market_accepts(&attestation.market_id)?;
        self.ensure_member_role(&attestation.member_id, CommitteeRole::PriceAttester)?;
        if !self
            .range_envelopes
            .contains_key(&attestation.range_envelope_id)
        {
            return Err("sealed price attestation range envelope is unknown".to_string());
        }
        if let Some(sponsor_id) = sponsor_id {
            self.debit_sponsor(sponsor_id, &attestation.market_id, fee_units)?;
            attestation.sponsor_id = Some(sponsor_id.to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        if let Some(market) = self.markets.get_mut(&attestation.market_id) {
            market.last_attestation_height = attestation.height;
        }
        self.sealed_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event(
            CommitteeEventKind::SealedAttestationSubmitted,
            &attestation_id,
            &json!({"attestation_id": attestation_id}),
        );
        Ok(self.state_root())
    }

    pub fn verify_range_envelope(
        &mut self,
        envelope_id: &str,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        let public_record = {
            let envelope = self
                .range_envelopes
                .get_mut(envelope_id)
                .ok_or_else(|| "range proof envelope not found".to_string())?;
            envelope.validate(&self.config)?;
            envelope.status = RangeEnvelopeStatus::Verified;
            envelope.public_record()
        };
        self.push_event(
            CommitteeEventKind::RangeEnvelopeVerified,
            envelope_id,
            &public_record,
        );
        Ok(self.state_root())
    }

    pub fn count_attestation(
        &mut self,
        attestation_id: &str,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        let envelope_id = {
            let attestation = self
                .sealed_attestations
                .get(attestation_id)
                .ok_or_else(|| "sealed price attestation not found".to_string())?;
            attestation.range_envelope_id.clone()
        };
        let envelope = self
            .range_envelopes
            .get(&envelope_id)
            .ok_or_else(|| "sealed price attestation range envelope missing".to_string())?;
        if envelope.status != RangeEnvelopeStatus::Verified {
            return Err("sealed price attestation range envelope is not verified".to_string());
        }
        if let Some(attestation) = self.sealed_attestations.get_mut(attestation_id) {
            attestation.status = SealedAttestationStatus::Counted;
        }
        Ok(self.state_root())
    }

    pub fn submit_risk_vote(
        &mut self,
        vote: PqRiskVote,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.risk_votes.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RISK_VOTES {
            return Err("private oracle risk committee vote capacity exceeded".to_string());
        }
        vote.validate()?;
        self.ensure_market_accepts(&vote.market_id)?;
        self.ensure_member_role(&vote.member_id, CommitteeRole::RiskVoter)?;
        if self
            .risk_votes
            .values()
            .any(|existing| existing.nullifier == vote.nullifier)
        {
            let mut duplicate = vote;
            duplicate.status = RiskVoteStatus::Duplicate;
            self.risk_votes.insert(duplicate.vote_id.clone(), duplicate);
            return Ok(self.state_root());
        }
        let vote_id = vote.vote_id.clone();
        self.risk_votes.insert(vote_id, vote);
        Ok(self.state_root())
    }

    pub fn count_risk_vote(&mut self, vote_id: &str) -> PrivateOracleRiskCommitteeResult<String> {
        let member_id = {
            let vote = self
                .risk_votes
                .get(vote_id)
                .ok_or_else(|| "risk vote not found".to_string())?;
            vote.member_id.clone()
        };
        let weight_bps = self
            .members
            .get(&member_id)
            .map(|member| member.voting_weight_bps)
            .ok_or_else(|| "risk vote member not found".to_string())?;
        let public_record = {
            let vote = self
                .risk_votes
                .get_mut(vote_id)
                .ok_or_else(|| "risk vote not found".to_string())?;
            vote.weight_bps = weight_bps;
            vote.status = RiskVoteStatus::Counted;
            vote.public_record()
        };
        self.push_event(CommitteeEventKind::RiskVoteCounted, vote_id, &public_record);
        Ok(self.state_root())
    }

    pub fn apply_guard_rail(
        &mut self,
        guard_rail: LiquidationGuardRail,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.guard_rails.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_GUARD_RAILS {
            return Err("private oracle risk committee guard rail capacity exceeded".to_string());
        }
        guard_rail.validate()?;
        self.ensure_market_accepts(&guard_rail.market_id)?;
        let guard_rail_id = guard_rail.guard_rail_id.clone();
        let market_id = guard_rail.market_id.clone();
        let mode = guard_rail.mode;
        self.guard_rails.insert(guard_rail_id.clone(), guard_rail);
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.last_guard_rail_id = Some(guard_rail_id.clone());
            market.status = if mode.blocks_liquidations() {
                RiskMarketStatus::Halted
            } else if mode == GuardRailMode::ObserveOnly {
                RiskMarketStatus::Caution
            } else {
                RiskMarketStatus::Guarded
            };
        }
        self.push_event(
            CommitteeEventKind::GuardRailApplied,
            &guard_rail_id,
            &json!({"guard_rail_id": guard_rail_id, "market_id": market_id, "mode": mode.as_str()}),
        );
        Ok(self.state_root())
    }

    pub fn schedule_rotation(
        &mut self,
        rotation_id: &str,
        old_committee_id: &str,
        new_committee: RiskCommittee,
        retiring_member_ids: BTreeSet<String>,
        joining_member_ids: BTreeSet<String>,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.rotations.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ROTATIONS {
            return Err("private oracle risk committee rotation capacity exceeded".to_string());
        }
        if !self.committees.contains_key(old_committee_id) {
            return Err("rotation old committee is unknown".to_string());
        }
        new_committee.validate()?;
        let new_committee_id = new_committee.committee_id.clone();
        let rotation = CommitteeRotation {
            rotation_id: rotation_id.to_string(),
            old_committee_id: old_committee_id.to_string(),
            new_committee_id: new_committee_id.clone(),
            status: RotationStatus::Scheduled,
            scheduled_height: self.height,
            executable_height: self
                .height
                .saturating_add(self.config.rotation_delay_blocks),
            executed_height: None,
            retiring_member_ids,
            joining_member_ids,
            pq_signature_commitments: BTreeMap::new(),
            transcript_commitment: risk_committee_hash(
                "ROTATION-TRANSCRIPT",
                &[
                    HashPart::Str(rotation_id),
                    HashPart::Str(old_committee_id),
                    HashPart::Str(&new_committee_id),
                ],
            ),
        };
        rotation.validate()?;
        self.committees.insert(new_committee_id, new_committee);
        self.rotations.insert(rotation_id.to_string(), rotation);
        self.push_event(
            CommitteeEventKind::CommitteeRotationScheduled,
            rotation_id,
            &json!({"rotation_id": rotation_id}),
        );
        Ok(self.state_root())
    }

    pub fn execute_rotation(
        &mut self,
        rotation_id: &str,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        let new_committee_id = {
            let rotation = self
                .rotations
                .get(rotation_id)
                .ok_or_else(|| "committee rotation not found".to_string())?;
            if self.height < rotation.executable_height {
                return Err("committee rotation delay has not elapsed".to_string());
            }
            rotation.new_committee_id.clone()
        };
        if let Some(rotation) = self.rotations.get_mut(rotation_id) {
            rotation.status = RotationStatus::Executed;
            rotation.executed_height = Some(self.height);
        }
        if let Some(committee) = self.committees.get_mut(&new_committee_id) {
            committee.status = RotationStatus::Executed;
            committee.activation_height = self.height;
        }
        self.push_event(
            CommitteeEventKind::CommitteeRotationExecuted,
            rotation_id,
            &json!({"rotation_id": rotation_id, "new_committee_id": new_committee_id}),
        );
        Ok(self.state_root())
    }

    pub fn open_slashing_case(
        &mut self,
        case: SlashingCase,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        if self.slashing_cases.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SLASHING_CASES {
            return Err("private oracle risk committee slashing capacity exceeded".to_string());
        }
        case.validate()?;
        if !self.members.contains_key(&case.accused_member_id)
            || !self.members.contains_key(&case.reporter_member_id)
        {
            return Err("slashing case member reference is unknown".to_string());
        }
        let case_id = case.case_id.clone();
        self.slashing_cases.insert(case_id.clone(), case);
        self.push_event(
            CommitteeEventKind::SlashingCaseOpened,
            &case_id,
            &json!({"case_id": case_id}),
        );
        Ok(self.state_root())
    }

    pub fn uphold_slashing_case(
        &mut self,
        case_id: &str,
    ) -> PrivateOracleRiskCommitteeResult<String> {
        let accused_member_id = {
            let case = self
                .slashing_cases
                .get_mut(case_id)
                .ok_or_else(|| "slashing case not found".to_string())?;
            case.status = SlashingCaseStatus::Upheld;
            case.resolved_height = Some(self.height);
            case.accused_member_id.clone()
        };
        if let Some(member) = self.members.get_mut(&accused_member_id) {
            member.status = MemberStatus::Slashed;
            member.slash_count = member.slash_count.saturating_add(1);
            member.stake_bond_units = member.stake_bond_units.saturating_sub(
                self.config
                    .member_bond_units
                    .saturating_mul(self.config.slash_bps)
                    / PRIVATE_ORACLE_RISK_COMMITTEE_MAX_BPS,
            );
        }
        self.push_event(
            CommitteeEventKind::MemberSlashed,
            case_id,
            &json!({"case_id": case_id, "accused_member_id": accused_member_id}),
        );
        Ok(self.state_root())
    }

    pub fn roots(&self) -> PrivateOracleRiskCommitteeRoots {
        let config_root = risk_committee_hash(
            "CONFIG-ROOT",
            &[HashPart::Json(&self.config.public_record())],
        );
        let market_root = map_root("MARKETS", &self.markets, |market| market.public_record());
        let member_root = map_root("MEMBERS", &self.members, |member| member.public_record());
        let committee_root = map_root("COMMITTEES", &self.committees, |committee| {
            committee.public_record()
        });
        let attestation_root = map_root("ATTESTATIONS", &self.sealed_attestations, |attestation| {
            attestation.public_record()
        });
        let range_envelope_root = map_root("RANGE-ENVELOPES", &self.range_envelopes, |envelope| {
            envelope.public_record()
        });
        let risk_vote_root = map_root("RISK-VOTES", &self.risk_votes, |vote| vote.public_record());
        let guard_rail_root = map_root("GUARD-RAILS", &self.guard_rails, |guard_rail| {
            guard_rail.public_record()
        });
        let sponsor_root = map_root("SPONSORS", &self.sponsors, |sponsor| {
            sponsor.public_record()
        });
        let rotation_root = map_root("ROTATIONS", &self.rotations, |rotation| {
            rotation.public_record()
        });
        let slashing_root = map_root("SLASHING", &self.slashing_cases, |case| {
            case.public_record()
        });
        let event_root = map_root("EVENTS", &self.events, |event| event.public_record());
        let state_root = risk_committee_hash(
            "STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&market_root),
                HashPart::Str(&member_root),
                HashPart::Str(&committee_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&range_envelope_root),
                HashPart::Str(&risk_vote_root),
                HashPart::Str(&guard_rail_root),
                HashPart::Str(&sponsor_root),
                HashPart::Str(&rotation_root),
                HashPart::Str(&slashing_root),
                HashPart::Str(&event_root),
                HashPart::Int(self.height as i128),
            ],
        );
        PrivateOracleRiskCommitteeRoots {
            config_root,
            market_root,
            member_root,
            committee_root,
            attestation_root,
            range_envelope_root,
            risk_vote_root,
            guard_rail_root,
            sponsor_root,
            rotation_root,
            slashing_root,
            event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateOracleRiskCommitteeCounters {
        PrivateOracleRiskCommitteeCounters {
            height: self.height,
            markets: self.markets.len(),
            active_markets: self
                .markets
                .values()
                .filter(|market| market.status.accepts_attestations())
                .count(),
            members: self.members.len(),
            active_members: self
                .members
                .values()
                .filter(|member| member.status.voting())
                .count(),
            committees: self.committees.len(),
            sealed_attestations: self.sealed_attestations.len(),
            counted_attestations: self
                .sealed_attestations
                .values()
                .filter(|attestation| attestation.status == SealedAttestationStatus::Counted)
                .count(),
            range_envelopes: self.range_envelopes.len(),
            verified_range_envelopes: self
                .range_envelopes
                .values()
                .filter(|envelope| envelope.status == RangeEnvelopeStatus::Verified)
                .count(),
            risk_votes: self.risk_votes.len(),
            counted_votes: self
                .risk_votes
                .values()
                .filter(|vote| vote.status == RiskVoteStatus::Counted)
                .count(),
            active_guard_rails: self
                .guard_rails
                .values()
                .filter(|guard_rail| guard_rail.expires_height >= self.height)
                .count(),
            sponsors: self.sponsors.len(),
            rotations: self.rotations.len(),
            slashing_cases: self.slashing_cases.len(),
            events: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateOracleRiskCommitteeResult<String> {
        self.config.validate()?;
        if self.markets.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MARKETS
            || self.members.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_MEMBERS
            || self.committees.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_COMMITTEES
            || self.sealed_attestations.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ATTESTATIONS
            || self.range_envelopes.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RANGE_ENVELOPES
            || self.risk_votes.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_RISK_VOTES
            || self.guard_rails.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_GUARD_RAILS
            || self.sponsors.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SPONSORS
            || self.rotations.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_ROTATIONS
            || self.slashing_cases.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_SLASHING_CASES
            || self.events.len() > PRIVATE_ORACLE_RISK_COMMITTEE_MAX_EVENTS
        {
            return Err("private oracle risk committee capacity exceeded".to_string());
        }
        for member in self.members.values() {
            member.validate()?;
        }
        for committee in self.committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.members.contains_key(member_id) {
                    return Err(format!("committee references unknown member {member_id}"));
                }
            }
        }
        for market in self.markets.values() {
            market.validate()?;
            if !self.committees.contains_key(&market.committee_id) {
                return Err(format!(
                    "market references unknown committee {}",
                    market.committee_id
                ));
            }
        }
        for envelope in self.range_envelopes.values() {
            envelope.validate(&self.config)?;
            if !self.markets.contains_key(&envelope.market_id) {
                return Err(format!(
                    "range envelope references unknown market {}",
                    envelope.market_id
                ));
            }
        }
        for attestation in self.sealed_attestations.values() {
            attestation.validate()?;
            if !self.markets.contains_key(&attestation.market_id) {
                return Err(format!(
                    "attestation references unknown market {}",
                    attestation.market_id
                ));
            }
            if !self.members.contains_key(&attestation.member_id) {
                return Err(format!(
                    "attestation references unknown member {}",
                    attestation.member_id
                ));
            }
            if !self
                .range_envelopes
                .contains_key(&attestation.range_envelope_id)
            {
                return Err(format!(
                    "attestation references unknown range envelope {}",
                    attestation.range_envelope_id
                ));
            }
        }
        for vote in self.risk_votes.values() {
            vote.validate()?;
            if !self.members.contains_key(&vote.member_id) {
                return Err(format!("vote references unknown member {}", vote.member_id));
            }
        }
        for guard_rail in self.guard_rails.values() {
            guard_rail.validate()?;
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for rotation in self.rotations.values() {
            rotation.validate()?;
        }
        for case in self.slashing_cases.values() {
            case.validate()?;
        }
        Ok(self.state_root())
    }

    fn ensure_market_accepts(&self, market_id: &str) -> PrivateOracleRiskCommitteeResult<()> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "risk market not found".to_string())?;
        if !market.status.accepts_attestations() {
            return Err("risk market does not accept private oracle attestations".to_string());
        }
        Ok(())
    }

    fn ensure_member_role(
        &self,
        member_id: &str,
        role: CommitteeRole,
    ) -> PrivateOracleRiskCommitteeResult<()> {
        let member = self
            .members
            .get(member_id)
            .ok_or_else(|| "committee member not found".to_string())?;
        if !member.status.voting() {
            return Err("committee member is not eligible to vote or attest".to_string());
        }
        if !member.has_role(role) {
            return Err(format!(
                "committee member lacks required role {}",
                role.as_str()
            ));
        }
        Ok(())
    }

    fn debit_sponsor(
        &mut self,
        sponsor_id: &str,
        market_id: &str,
        fee_units: u64,
    ) -> PrivateOracleRiskCommitteeResult<()> {
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "oracle update sponsor not found".to_string())?;
        if !sponsor.can_sponsor(market_id, fee_units) {
            return Err("oracle update sponsor cannot cover this update".to_string());
        }
        sponsor.spent_units = sponsor.spent_units.saturating_add(fee_units);
        sponsor.last_debit_height = self.height;
        if sponsor.remaining_budget_units() == 0 {
            sponsor.status = SponsorshipStatus::Exhausted;
        }
        self.push_event(
            CommitteeEventKind::SponsorDebited,
            sponsor_id,
            &json!({"sponsor_id": sponsor_id, "market_id": market_id, "fee_units": fee_units}),
        );
        Ok(())
    }

    fn push_event(&mut self, kind: CommitteeEventKind, subject_id: &str, payload: &Value) {
        if self.events.len() >= PRIVATE_ORACLE_RISK_COMMITTEE_MAX_EVENTS {
            return;
        }
        let event = RiskCommitteeEvent::new(kind, self.height, subject_id, payload);
        self.events.insert(event.event_id.clone(), event);
    }
}

fn risk_committee_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-ORACLE-RISK-COMMITTEE:{domain}"),
        parts,
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-ORACLE-RISK-COMMITTEE:{domain}"), &leaves)
}
