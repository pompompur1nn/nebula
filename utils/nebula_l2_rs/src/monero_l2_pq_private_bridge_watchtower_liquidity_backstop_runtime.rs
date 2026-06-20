use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_WATCHTOWER_LIQUIDITY_BACKSTOP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-watchtower-liquidity-backstop-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_WATCHTOWER_LIQUIDITY_BACKSTOP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-private-bridge-watchtower-liquidity-backstop-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_371_200;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-192f-private-bridge-watchtower-backstop-v1";
pub const PQ_ENCRYPTION_SUITE: &str = "ml-kem-1024-sealed-backstop-evidence-bundle-v1";
pub const COVERAGE_POOL_SCHEME: &str = "watchtower-coverage-pool-commitment-root-v1";
pub const LIQUIDITY_BACKSTOP_SCHEME: &str = "private-bridge-liquidity-backstop-commitment-root-v1";
pub const RESERVE_PROOF_SCHEME: &str = "monero-bridge-reserve-proof-coverage-root-v1";
pub const REORG_INSURANCE_SCHEME: &str = "private-bridge-reorg-liquidation-insurance-root-v1";
pub const OUTAGE_CLAIM_SCHEME: &str = "private-bridge-outage-claim-root-v1";
pub const SEALED_QUOTE_SCHEME: &str = "sealed-maker-liquidity-quote-root-v1";
pub const EMERGENCY_EXIT_SCHEME: &str = "private-emergency-exit-reservation-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "watchtower-liquidity-nullifier-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "watchtower-liquidity-backstop-slashing-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHTOWER_QUORUM: u16 = 5;
pub const DEFAULT_MIN_QUORUM_WEIGHT: u64 = 9;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_MAKER_QUOTE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_COVERAGE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RESERVE_PROOF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_OUTAGE_CLAIM_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REORG_INSURANCE_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_NULLIFIER_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_SLASH_FALSE_ATTESTATION_BPS: u64 = 5_000;
pub const DEFAULT_SLASH_WITHHELD_LIQUIDITY_BPS: u64 = 2_500;
pub const DEFAULT_SLASH_DUPLICATE_NULLIFIER_BPS: u64 = 3_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_COVERAGE_POOLS: usize = 262_144;
pub const MAX_BACKSTOP_COMMITMENTS: usize = 1_048_576;
pub const MAX_RESERVE_PROOFS: usize = 1_048_576;
pub const MAX_REORG_INSURANCE: usize = 524_288;
pub const MAX_OUTAGE_CLAIMS: usize = 524_288;
pub const MAX_SEALED_QUOTES: usize = 2_097_152;
pub const MAX_EMERGENCY_EXITS: usize = 1_048_576;
pub const MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const MAX_PQ_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 2_097_152;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLane {
    LowFee,
    Standard,
    FastExit,
    MakerBackstop,
    ReorgRescue,
    Emergency,
}

impl CoverageLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::FastExit => "fast_exit",
            Self::MakerBackstop => "maker_backstop",
            Self::ReorgRescue => "reorg_rescue",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::ReorgRescue => 960,
            Self::FastExit => 900,
            Self::MakerBackstop => 840,
            Self::Standard => 720,
            Self::LowFee => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofKind {
    ViewKeyAudit,
    RingMemberSampling,
    HeaderContinuity,
    ReserveLiabilityNet,
    MakerLiquidity,
    EmergencyExit,
}

impl ReserveProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKeyAudit => "view_key_audit",
            Self::RingMemberSampling => "ring_member_sampling",
            Self::HeaderContinuity => "header_continuity",
            Self::ReserveLiabilityNet => "reserve_liability_net",
            Self::MakerLiquidity => "maker_liquidity",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceKind {
    Reorg,
    Liquidation,
    BridgeOutage,
    MakerDefault,
    ReserveShortfall,
}

impl InsuranceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::Liquidation => "liquidation",
            Self::BridgeOutage => "bridge_outage",
            Self::MakerDefault => "maker_default",
            Self::ReserveShortfall => "reserve_shortfall",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageClaimKind {
    RelayUnavailable,
    FinalityDelay,
    ExitQueueStall,
    ReserveOracleGap,
    WatchtowerQuorumGap,
    MakerWithdrawalFailure,
}

impl OutageClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayUnavailable => "relay_unavailable",
            Self::FinalityDelay => "finality_delay",
            Self::ExitQueueStall => "exit_queue_stall",
            Self::ReserveOracleGap => "reserve_oracle_gap",
            Self::WatchtowerQuorumGap => "watchtower_quorum_gap",
            Self::MakerWithdrawalFailure => "maker_withdrawal_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CoveragePoolSolvent,
    ReserveProofAccepted,
    QuoteWellFormed,
    ExitReserved,
    OutageObserved,
    ReorgBounded,
    NullifierUnique,
    SlashReady,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoveragePoolSolvent => "coverage_pool_solvent",
            Self::ReserveProofAccepted => "reserve_proof_accepted",
            Self::QuoteWellFormed => "quote_well_formed",
            Self::ExitReserved => "exit_reserved",
            Self::OutageObserved => "outage_observed",
            Self::ReorgBounded => "reorg_bounded",
            Self::NullifierUnique => "nullifier_unique",
            Self::SlashReady => "slash_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    PoolCommitment,
    BackstopNullifier,
    ReserveProofNullifier,
    QuoteNullifier,
    ExitNullifier,
    ClaimNullifier,
    AttestationNullifier,
    SlashNullifier,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolCommitment => "pool_commitment",
            Self::BackstopNullifier => "backstop_nullifier",
            Self::ReserveProofNullifier => "reserve_proof_nullifier",
            Self::QuoteNullifier => "quote_nullifier",
            Self::ExitNullifier => "exit_nullifier",
            Self::ClaimNullifier => "claim_nullifier",
            Self::AttestationNullifier => "attestation_nullifier",
            Self::SlashNullifier => "slash_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    FalseReserveProof,
    FalseOutageClaim,
    WithheldLiquidity,
    QuoteDefault,
    DuplicateNullifier,
    PqAttestationForgery,
    EmergencyExitTheft,
    ReorgConcealment,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseReserveProof => "false_reserve_proof",
            Self::FalseOutageClaim => "false_outage_claim",
            Self::WithheldLiquidity => "withheld_liquidity",
            Self::QuoteDefault => "quote_default",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::PqAttestationForgery => "pq_attestation_forgery",
            Self::EmergencyExitTheft => "emergency_exit_theft",
            Self::ReorgConcealment => "reorg_concealment",
        }
    }
}

status_enum!(CoveragePoolStatus {
    Opening => "opening",
    Active => "active",
    Throttled => "throttled",
    ClaimLocked => "claim_locked",
    Settling => "settling",
    Draining => "draining",
    Closed => "closed",
    Slashed => "slashed"
});

impl CoveragePoolStatus {
    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Opening | Self::Active | Self::Throttled)
    }
}

status_enum!(BackstopStatus {
    Sealed => "sealed",
    Admitted => "admitted",
    Reserved => "reserved",
    Deployed => "deployed",
    Released => "released",
    Expired => "expired",
    Slashed => "slashed"
});

impl BackstopStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::Reserved | Self::Deployed
        )
    }
}

status_enum!(ProofStatus {
    Submitted => "submitted",
    PrivacyChecked => "privacy_checked",
    QuorumPending => "quorum_pending",
    Accepted => "accepted",
    Superseded => "superseded",
    Expired => "expired",
    Rejected => "rejected",
    Slashed => "slashed"
});

status_enum!(InsuranceStatus {
    Quoted => "quoted",
    Bound => "bound",
    ClaimPending => "claim_pending",
    Paid => "paid",
    Denied => "denied",
    Expired => "expired",
    Cancelled => "cancelled",
    Slashed => "slashed"
});

status_enum!(ClaimStatus {
    Filed => "filed",
    PrivacyChecked => "privacy_checked",
    Attested => "attested",
    Covered => "covered",
    Paid => "paid",
    Denied => "denied",
    Expired => "expired",
    Slashed => "slashed"
});

status_enum!(QuoteStatus {
    Sealed => "sealed",
    Opened => "opened",
    Reserved => "reserved",
    Filled => "filled",
    Cancelled => "cancelled",
    Expired => "expired",
    Defaulted => "defaulted",
    Slashed => "slashed"
});

status_enum!(ExitStatus {
    Reserved => "reserved",
    Attested => "attested",
    LiquidityLocked => "liquidity_locked",
    Submitted => "submitted",
    Finalized => "finalized",
    Cancelled => "cancelled",
    Expired => "expired",
    Slashed => "slashed"
});

status_enum!(FenceStatus {
    Committed => "committed",
    Active => "active",
    Spent => "spent",
    Expired => "expired",
    Disputed => "disputed",
    Slashed => "slashed"
});

status_enum!(AttestationStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    WeakQuorum => "weak_quorum",
    Superseded => "superseded",
    Rejected => "rejected",
    Slashed => "slashed"
});

status_enum!(SlashingStatus {
    Filed => "filed",
    Fenced => "fenced",
    Attested => "attested",
    DisclosurePending => "disclosure_pending",
    Accepted => "accepted",
    Rejected => "rejected",
    Settled => "settled"
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub committee_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub pq_encryption_suite: String,
    pub coverage_pool_scheme: String,
    pub liquidity_backstop_scheme: String,
    pub reserve_proof_scheme: String,
    pub reorg_insurance_scheme: String,
    pub outage_claim_scheme: String,
    pub sealed_quote_scheme: String,
    pub emergency_exit_scheme: String,
    pub privacy_fence_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_watchtower_quorum: u16,
    pub min_quorum_weight: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub low_fee_target_micro_units: u64,
    pub maker_quote_ttl_blocks: u64,
    pub coverage_ttl_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub outage_claim_window_blocks: u64,
    pub emergency_exit_ttl_blocks: u64,
    pub reorg_insurance_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub nullifier_ttl_blocks: u64,
    pub slash_false_attestation_bps: u64,
    pub slash_withheld_liquidity_bps: u64,
    pub slash_duplicate_nullifier_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            pq_encryption_suite: PQ_ENCRYPTION_SUITE.to_string(),
            coverage_pool_scheme: COVERAGE_POOL_SCHEME.to_string(),
            liquidity_backstop_scheme: LIQUIDITY_BACKSTOP_SCHEME.to_string(),
            reserve_proof_scheme: RESERVE_PROOF_SCHEME.to_string(),
            reorg_insurance_scheme: REORG_INSURANCE_SCHEME.to_string(),
            outage_claim_scheme: OUTAGE_CLAIM_SCHEME.to_string(),
            sealed_quote_scheme: SEALED_QUOTE_SCHEME.to_string(),
            emergency_exit_scheme: EMERGENCY_EXIT_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watchtower_quorum: DEFAULT_MIN_WATCHTOWER_QUORUM,
            min_quorum_weight: DEFAULT_MIN_QUORUM_WEIGHT,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            maker_quote_ttl_blocks: DEFAULT_MAKER_QUOTE_TTL_BLOCKS,
            coverage_ttl_blocks: DEFAULT_COVERAGE_TTL_BLOCKS,
            reserve_proof_ttl_blocks: DEFAULT_RESERVE_PROOF_TTL_BLOCKS,
            outage_claim_window_blocks: DEFAULT_OUTAGE_CLAIM_WINDOW_BLOCKS,
            emergency_exit_ttl_blocks: DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS,
            reorg_insurance_ttl_blocks: DEFAULT_REORG_INSURANCE_TTL_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            nullifier_ttl_blocks: DEFAULT_NULLIFIER_TTL_BLOCKS,
            slash_false_attestation_bps: DEFAULT_SLASH_FALSE_ATTESTATION_BPS,
            slash_withheld_liquidity_bps: DEFAULT_SLASH_WITHHELD_LIQUIDITY_BPS,
            slash_duplicate_nullifier_bps: DEFAULT_SLASH_DUPLICATE_NULLIFIER_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "committee_id": self.committee_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "pq_encryption_suite": self.pq_encryption_suite,
            "coverage_pool_scheme": self.coverage_pool_scheme,
            "liquidity_backstop_scheme": self.liquidity_backstop_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "reorg_insurance_scheme": self.reorg_insurance_scheme,
            "outage_claim_scheme": self.outage_claim_scheme,
            "sealed_quote_scheme": self.sealed_quote_scheme,
            "emergency_exit_scheme": self.emergency_exit_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watchtower_quorum": self.min_watchtower_quorum,
            "min_quorum_weight": self.min_quorum_weight,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "max_pool_utilization_bps": self.max_pool_utilization_bps,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "maker_quote_ttl_blocks": self.maker_quote_ttl_blocks,
            "coverage_ttl_blocks": self.coverage_ttl_blocks,
            "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
            "outage_claim_window_blocks": self.outage_claim_window_blocks,
            "emergency_exit_ttl_blocks": self.emergency_exit_ttl_blocks,
            "reorg_insurance_ttl_blocks": self.reorg_insurance_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "nullifier_ttl_blocks": self.nullifier_ttl_blocks,
            "slash_false_attestation_bps": self.slash_false_attestation_bps,
            "slash_withheld_liquidity_bps": self.slash_withheld_liquidity_bps,
            "slash_duplicate_nullifier_bps": self.slash_duplicate_nullifier_bps,
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_bps("min_reserve_coverage_bps", self.min_reserve_coverage_bps)?;
        require_bps(
            "target_reserve_coverage_bps",
            self.target_reserve_coverage_bps,
        )?;
        require_bps("max_pool_utilization_bps", self.max_pool_utilization_bps)?;
        require_bps(
            "slash_false_attestation_bps",
            self.slash_false_attestation_bps,
        )?;
        require_bps(
            "slash_withheld_liquidity_bps",
            self.slash_withheld_liquidity_bps,
        )?;
        require_bps(
            "slash_duplicate_nullifier_bps",
            self.slash_duplicate_nullifier_bps,
        )?;
        if self.target_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("target reserve coverage below minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("minimum pq security bits below runtime floor".to_string());
        }
        if self.min_watchtower_quorum == 0 || self.min_quorum_weight == 0 {
            return Err("watchtower quorum must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub coverage_pools: u64,
    pub backstop_commitments: u64,
    pub reserve_proofs: u64,
    pub reorg_insurance: u64,
    pub outage_claims: u64,
    pub sealed_quotes: u64,
    pub emergency_exits: u64,
    pub privacy_fences: u64,
    pub pq_attestations: u64,
    pub slashing_evidence: u64,
    pub events: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            coverage_pools: 0,
            backstop_commitments: 0,
            reserve_proofs: 0,
            reorg_insurance: 0,
            outage_claims: 0,
            sealed_quotes: 0,
            emergency_exits: 0,
            privacy_fences: 0,
            pq_attestations: 0,
            slashing_evidence: 0,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coverage_pools": self.coverage_pools,
            "backstop_commitments": self.backstop_commitments,
            "reserve_proofs": self.reserve_proofs,
            "reorg_insurance": self.reorg_insurance,
            "outage_claims": self.outage_claims,
            "sealed_quotes": self.sealed_quotes,
            "emergency_exits": self.emergency_exits,
            "privacy_fences": self.privacy_fences,
            "pq_attestations": self.pq_attestations,
            "slashing_evidence": self.slashing_evidence,
            "events": self.events,
        })
    }

    pub fn root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub coverage_pool_root: String,
    pub backstop_commitment_root: String,
    pub reserve_proof_root: String,
    pub reorg_insurance_root: String,
    pub outage_claim_root: String,
    pub sealed_quote_root: String,
    pub emergency_exit_root: String,
    pub privacy_fence_root: String,
    pub pq_attestation_root: String,
    pub slashing_evidence_root: String,
    pub spent_nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "coverage_pool_root": self.coverage_pool_root,
            "backstop_commitment_root": self.backstop_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "reorg_insurance_root": self.reorg_insurance_root,
            "outage_claim_root": self.outage_claim_root,
            "sealed_quote_root": self.sealed_quote_root,
            "emergency_exit_root": self.emergency_exit_root,
            "privacy_fence_root": self.privacy_fence_root,
            "pq_attestation_root": self.pq_attestation_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "event_root": self.event_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerCoveragePool {
    pub pool_id: String,
    pub lane: CoverageLane,
    pub operator_commitment: String,
    pub reserve_commitment_root: String,
    pub coverage_commitment_root: String,
    pub liquidity_floor_units: u64,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: CoveragePoolStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl WatchtowerCoveragePool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "operator_commitment": self.operator_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "coverage_commitment_root": self.coverage_commitment_root,
            "liquidity_floor_units": self.liquidity_floor_units,
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "utilization_bps": self.utilization_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("WATCHTOWER-COVERAGE-POOL", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("pool_id", &self.pool_id)?;
        require_root("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_root("coverage_commitment_root", &self.coverage_commitment_root)?;
        require_bps("utilization_bps", self.utilization_bps)?;
        require_height_window(
            "coverage pool",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("coverage pool privacy set below runtime floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("coverage pool pq security below runtime floor".to_string());
        }
        if self.capacity_units < self.liquidity_floor_units {
            return Err("coverage pool capacity below liquidity floor".to_string());
        }
        if self.reserved_units > self.capacity_units {
            return Err("coverage pool reserved units exceed capacity".to_string());
        }
        if self.utilization_bps > config.max_pool_utilization_bps {
            return Err("coverage pool utilization exceeds runtime cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBackstopCommitment {
    pub commitment_id: String,
    pub pool_id: String,
    pub maker_commitment: String,
    pub sealed_liquidity_root: String,
    pub quote_root: String,
    pub reserve_proof_id: String,
    pub amount_units: u64,
    pub fee_micro_units: u64,
    pub status: BackstopStatus,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityBackstopCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "maker_commitment": self.maker_commitment,
            "sealed_liquidity_root": self.sealed_liquidity_root,
            "quote_root": self.quote_root,
            "reserve_proof_id": self.reserve_proof_id,
            "amount_units": self.amount_units,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("LIQUIDITY-BACKSTOP-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("commitment_id", &self.commitment_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root("sealed_liquidity_root", &self.sealed_liquidity_root)?;
        require_root("quote_root", &self.quote_root)?;
        validate_hash("reserve_proof_id", &self.reserve_proof_id)?;
        require_positive("amount_units", self.amount_units)?;
        require_height_window(
            "liquidity backstop commitment",
            self.committed_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProof {
    pub proof_id: String,
    pub kind: ReserveProofKind,
    pub pool_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub witness_committee_root: String,
    pub status: ProofStatus,
    pub proved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "kind": self.kind.as_str(),
            "pool_id": self.pool_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "witness_committee_root": self.witness_committee_root,
            "status": self.status.as_str(),
            "proved_at_height": self.proved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("RESERVE-PROOF", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("proof_id", &self.proof_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root("reserve_root", &self.reserve_root)?;
        require_root("liability_root", &self.liability_root)?;
        require_root("witness_committee_root", &self.witness_committee_root)?;
        require_bps("coverage_bps", self.coverage_bps)?;
        require_height_window(
            "reserve proof",
            self.proved_at_height,
            self.expires_at_height,
        )?;
        if self.coverage_bps < config.min_reserve_coverage_bps {
            return Err("reserve proof coverage below runtime minimum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("reserve proof privacy set below runtime floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("reserve proof pq security below runtime floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgLiquidationInsurance {
    pub insurance_id: String,
    pub kind: InsuranceKind,
    pub pool_id: String,
    pub insured_commitment: String,
    pub coverage_root: String,
    pub premium_micro_units: u64,
    pub coverage_units: u64,
    pub deductible_bps: u64,
    pub status: InsuranceStatus,
    pub bound_at_height: u64,
    pub expires_at_height: u64,
}

impl ReorgLiquidationInsurance {
    pub fn public_record(&self) -> Value {
        json!({
            "insurance_id": self.insurance_id,
            "kind": self.kind.as_str(),
            "pool_id": self.pool_id,
            "insured_commitment": self.insured_commitment,
            "coverage_root": self.coverage_root,
            "premium_micro_units": self.premium_micro_units,
            "coverage_units": self.coverage_units,
            "deductible_bps": self.deductible_bps,
            "status": self.status.as_str(),
            "bound_at_height": self.bound_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("REORG-LIQUIDATION-INSURANCE", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("insurance_id", &self.insurance_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root("coverage_root", &self.coverage_root)?;
        require_positive("coverage_units", self.coverage_units)?;
        require_bps("deductible_bps", self.deductible_bps)?;
        require_height_window(
            "reorg liquidation insurance",
            self.bound_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeOutageClaim {
    pub claim_id: String,
    pub kind: OutageClaimKind,
    pub pool_id: String,
    pub claimant_commitment: String,
    pub outage_observation_root: String,
    pub affected_exit_root: String,
    pub requested_units: u64,
    pub covered_units: u64,
    pub status: ClaimStatus,
    pub filed_at_height: u64,
    pub expires_at_height: u64,
}

impl BridgeOutageClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "kind": self.kind.as_str(),
            "pool_id": self.pool_id,
            "claimant_commitment": self.claimant_commitment,
            "outage_observation_root": self.outage_observation_root,
            "affected_exit_root": self.affected_exit_root,
            "requested_units": self.requested_units,
            "covered_units": self.covered_units,
            "status": self.status.as_str(),
            "filed_at_height": self.filed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("BRIDGE-OUTAGE-CLAIM", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("claim_id", &self.claim_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root("outage_observation_root", &self.outage_observation_root)?;
        require_root("affected_exit_root", &self.affected_exit_root)?;
        require_positive("requested_units", self.requested_units)?;
        if self.covered_units > self.requested_units {
            return Err("covered units exceed requested units".to_string());
        }
        require_height_window(
            "bridge outage claim",
            self.filed_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedMakerQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub maker_commitment: String,
    pub sealed_quote_root: String,
    pub route_commitment_root: String,
    pub amount_units: u64,
    pub fee_micro_units: u64,
    pub max_delay_blocks: u64,
    pub status: QuoteStatus,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedMakerQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "maker_commitment": self.maker_commitment,
            "sealed_quote_root": self.sealed_quote_root,
            "route_commitment_root": self.route_commitment_root,
            "amount_units": self.amount_units,
            "fee_micro_units": self.fee_micro_units,
            "max_delay_blocks": self.max_delay_blocks,
            "status": self.status.as_str(),
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("SEALED-MAKER-QUOTE", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("quote_id", &self.quote_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root("sealed_quote_root", &self.sealed_quote_root)?;
        require_root("route_commitment_root", &self.route_commitment_root)?;
        require_positive("amount_units", self.amount_units)?;
        require_height_window(
            "sealed maker quote",
            self.sealed_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyExitReservation {
    pub reservation_id: String,
    pub pool_id: String,
    pub exit_commitment: String,
    pub destination_commitment_root: String,
    pub withdrawal_proof_root: String,
    pub reserved_units: u64,
    pub priority_weight: u64,
    pub status: ExitStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl EmergencyExitReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "pool_id": self.pool_id,
            "exit_commitment": self.exit_commitment,
            "destination_commitment_root": self.destination_commitment_root,
            "withdrawal_proof_root": self.withdrawal_proof_root,
            "reserved_units": self.reserved_units,
            "priority_weight": self.priority_weight,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("EMERGENCY-EXIT-RESERVATION", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("reservation_id", &self.reservation_id)?;
        validate_hash("pool_id", &self.pool_id)?;
        require_root(
            "destination_commitment_root",
            &self.destination_commitment_root,
        )?;
        require_root("withdrawal_proof_root", &self.withdrawal_proof_root)?;
        require_positive("reserved_units", self.reserved_units)?;
        require_height_window(
            "emergency exit reservation",
            self.reserved_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub status: FenceStatus,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "inserted_at_height": self.inserted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVACY-FENCE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("fence_id", &self.fence_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("commitment_root", &self.commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy fence set size below runtime floor".to_string());
        }
        require_height_window(
            "privacy fence",
            self.inserted_at_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment_root: String,
    pub aggregate_signature_root: String,
    pub quorum_count: u16,
    pub quorum_weight: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment_root": self.signer_commitment_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "quorum_count": self.quorum_count,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("attestation_id", &self.attestation_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("subject_root", &self.subject_root)?;
        require_root("signer_commitment_root", &self.signer_commitment_root)?;
        require_root("aggregate_signature_root", &self.aggregate_signature_root)?;
        if self.quorum_count < config.min_watchtower_quorum {
            return Err("attestation quorum count below runtime minimum".to_string());
        }
        if self.quorum_weight < config.min_quorum_weight {
            return Err("attestation quorum weight below runtime minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security below runtime minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashReason,
    pub subject_id: String,
    pub accused_commitment: String,
    pub evidence_root: String,
    pub fence_id: String,
    pub attestation_id: String,
    pub slash_bps: u64,
    pub status: SlashingStatus,
    pub filed_at_height: u64,
    pub disclosure_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason.as_str(),
            "subject_id": self.subject_id,
            "accused_commitment": self.accused_commitment,
            "evidence_root": self.evidence_root,
            "fence_id": self.fence_id,
            "attestation_id": self.attestation_id,
            "slash_bps": self.slash_bps,
            "status": self.status.as_str(),
            "filed_at_height": self.filed_at_height,
            "disclosure_height": self.disclosure_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        validate_hash("evidence_id", &self.evidence_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("evidence_root", &self.evidence_root)?;
        validate_hash("fence_id", &self.fence_id)?;
        validate_hash("attestation_id", &self.attestation_id)?;
        require_bps("slash_bps", self.slash_bps)?;
        require_height_window(
            "slashing evidence",
            self.filed_at_height,
            self.disclosure_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        record_root("RUNTIME-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub coverage_pools: BTreeMap<String, WatchtowerCoveragePool>,
    pub backstop_commitments: BTreeMap<String, LiquidityBackstopCommitment>,
    pub reserve_proofs: BTreeMap<String, ReserveProof>,
    pub reorg_insurance: BTreeMap<String, ReorgLiquidationInsurance>,
    pub outage_claims: BTreeMap<String, BridgeOutageClaim>,
    pub sealed_quotes: BTreeMap<String, SealedMakerQuote>,
    pub emergency_exits: BTreeMap<String, EmergencyExitReservation>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::new(),
            height,
            coverage_pools: BTreeMap::new(),
            backstop_commitments: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            reorg_insurance: BTreeMap::new(),
            outage_claims: BTreeMap::new(),
            sealed_quotes: BTreeMap::new(),
            emergency_exits: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config: config.clone(),
            counters: Counters::new(),
            height: DEVNET_HEIGHT,
            coverage_pools: BTreeMap::new(),
            backstop_commitments: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            reorg_insurance: BTreeMap::new(),
            outage_claims: BTreeMap::new(),
            sealed_quotes: BTreeMap::new(),
            emergency_exits: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        };

        let reserve_root = commitment("devnet-primary-reserve-root");
        let liability_root = commitment("devnet-primary-liability-root");
        let witness_root = commitment("devnet-watchtower-committee-root");
        let pool_id = coverage_pool_id(
            CoverageLane::FastExit,
            "devnet-watchtower-operator",
            &reserve_root,
            DEVNET_HEIGHT,
        );
        let proof_id = reserve_proof_id(
            ReserveProofKind::ReserveLiabilityNet,
            &pool_id,
            &reserve_root,
            &liability_root,
            DEVNET_HEIGHT,
        );
        let quote_root = commitment("devnet-maker-sealed-quote");
        let quote_id = sealed_quote_id(
            &pool_id,
            "devnet-maker-commitment",
            &quote_root,
            DEVNET_HEIGHT,
        );
        let commitment_id = backstop_commitment_id(
            &pool_id,
            "devnet-maker-commitment",
            &quote_root,
            25_000_000_000,
            DEVNET_HEIGHT + 1,
        );
        let exit_root = commitment("devnet-emergency-exit-destination");
        let reservation_id = emergency_exit_id(
            &pool_id,
            "devnet-exit-commitment",
            &exit_root,
            DEVNET_HEIGHT + 2,
        );
        let insurance_id = insurance_id(
            InsuranceKind::Reorg,
            &pool_id,
            "devnet-insured-commitment",
            DEVNET_HEIGHT + 3,
        );
        let claim_id = outage_claim_id(
            OutageClaimKind::FinalityDelay,
            &pool_id,
            "devnet-claimant-commitment",
            DEVNET_HEIGHT + 4,
        );
        let fence_id = privacy_fence_id(
            FenceKind::ClaimNullifier,
            &claim_id,
            &commitment("devnet-claim-fence-commitment"),
            &commitment("devnet-claim-nullifier"),
            DEVNET_HEIGHT + 5,
        );
        let attestation_id = pq_attestation_id(
            AttestationKind::OutageObserved,
            &claim_id,
            &commitment("devnet-claim-subject-root"),
            DEVNET_HEIGHT + 6,
        );
        let slash_id = slashing_evidence_id(
            SlashReason::FalseOutageClaim,
            &claim_id,
            "devnet-accused-watchtower",
            DEVNET_HEIGHT + 7,
        );

        let pool = WatchtowerCoveragePool {
            pool_id: pool_id.clone(),
            lane: CoverageLane::FastExit,
            operator_commitment: "devnet-watchtower-operator".to_string(),
            reserve_commitment_root: reserve_root.clone(),
            coverage_commitment_root: commitment("devnet-coverage-commitment-root"),
            liquidity_floor_units: 50_000_000_000,
            capacity_units: 250_000_000_000,
            reserved_units: 25_000_000_000,
            utilization_bps: 1_000,
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            status: CoveragePoolStatus::Active,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + config.coverage_ttl_blocks,
        };
        let proof = ReserveProof {
            proof_id: proof_id.clone(),
            kind: ReserveProofKind::ReserveLiabilityNet,
            pool_id: pool_id.clone(),
            reserve_root: reserve_root.clone(),
            liability_root,
            coverage_bps: config.target_reserve_coverage_bps,
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            witness_committee_root: witness_root.clone(),
            status: ProofStatus::Accepted,
            proved_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + config.reserve_proof_ttl_blocks,
        };
        let quote = SealedMakerQuote {
            quote_id: quote_id.clone(),
            pool_id: pool_id.clone(),
            maker_commitment: "devnet-maker-commitment".to_string(),
            sealed_quote_root: quote_root.clone(),
            route_commitment_root: commitment("devnet-maker-route-root"),
            amount_units: 25_000_000_000,
            fee_micro_units: config.low_fee_target_micro_units,
            max_delay_blocks: 12,
            status: QuoteStatus::Reserved,
            sealed_at_height: DEVNET_HEIGHT + 1,
            expires_at_height: DEVNET_HEIGHT + config.maker_quote_ttl_blocks,
        };
        let backstop = LiquidityBackstopCommitment {
            commitment_id: commitment_id.clone(),
            pool_id: pool_id.clone(),
            maker_commitment: "devnet-maker-commitment".to_string(),
            sealed_liquidity_root: commitment("devnet-sealed-liquidity-root"),
            quote_root,
            reserve_proof_id: proof_id.clone(),
            amount_units: 25_000_000_000,
            fee_micro_units: config.low_fee_target_micro_units,
            status: BackstopStatus::Reserved,
            committed_at_height: DEVNET_HEIGHT + 1,
            expires_at_height: DEVNET_HEIGHT + config.coverage_ttl_blocks,
        };
        let exit = EmergencyExitReservation {
            reservation_id: reservation_id.clone(),
            pool_id: pool_id.clone(),
            exit_commitment: "devnet-exit-commitment".to_string(),
            destination_commitment_root: exit_root,
            withdrawal_proof_root: commitment("devnet-withdrawal-proof-root"),
            reserved_units: 10_000_000_000,
            priority_weight: CoverageLane::Emergency.priority_weight(),
            status: ExitStatus::Attested,
            reserved_at_height: DEVNET_HEIGHT + 2,
            expires_at_height: DEVNET_HEIGHT + config.emergency_exit_ttl_blocks,
        };
        let insurance = ReorgLiquidationInsurance {
            insurance_id,
            kind: InsuranceKind::Reorg,
            pool_id: pool_id.clone(),
            insured_commitment: "devnet-insured-commitment".to_string(),
            coverage_root: commitment("devnet-reorg-insurance-coverage"),
            premium_micro_units: 45_000,
            coverage_units: 100_000_000_000,
            deductible_bps: 500,
            status: InsuranceStatus::Bound,
            bound_at_height: DEVNET_HEIGHT + 3,
            expires_at_height: DEVNET_HEIGHT + config.reorg_insurance_ttl_blocks,
        };
        let claim = BridgeOutageClaim {
            claim_id: claim_id.clone(),
            kind: OutageClaimKind::FinalityDelay,
            pool_id,
            claimant_commitment: "devnet-claimant-commitment".to_string(),
            outage_observation_root: commitment("devnet-outage-observation-root"),
            affected_exit_root: commitment("devnet-affected-exit-root"),
            requested_units: 5_000_000_000,
            covered_units: 5_000_000_000,
            status: ClaimStatus::Attested,
            filed_at_height: DEVNET_HEIGHT + 4,
            expires_at_height: DEVNET_HEIGHT + config.outage_claim_window_blocks,
        };
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind: FenceKind::ClaimNullifier,
            subject_id: claim_id.clone(),
            commitment_root: commitment("devnet-claim-fence-commitment"),
            nullifier_root: commitment("devnet-claim-nullifier"),
            privacy_set_size: config.min_privacy_set_size,
            status: FenceStatus::Active,
            inserted_at_height: DEVNET_HEIGHT + 5,
            expires_at_height: DEVNET_HEIGHT + config.nullifier_ttl_blocks,
        };
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            kind: AttestationKind::OutageObserved,
            subject_id: claim_id.clone(),
            subject_root: commitment("devnet-claim-subject-root"),
            signer_commitment_root: witness_root,
            aggregate_signature_root: commitment("devnet-aggregate-signature-root"),
            quorum_count: config.min_watchtower_quorum,
            quorum_weight: config.min_quorum_weight,
            pq_security_bits: config.min_pq_security_bits,
            status: AttestationStatus::Accepted,
            attested_at_height: DEVNET_HEIGHT + 6,
        };
        let slash = SlashingEvidence {
            evidence_id: slash_id,
            reason: SlashReason::FalseOutageClaim,
            subject_id: claim_id,
            accused_commitment: "devnet-accused-watchtower".to_string(),
            evidence_root: commitment("devnet-slashing-evidence-root"),
            fence_id,
            attestation_id,
            slash_bps: config.slash_false_attestation_bps,
            status: SlashingStatus::Filed,
            filed_at_height: DEVNET_HEIGHT + 7,
            disclosure_height: DEVNET_HEIGHT + 7 + config.settlement_delay_blocks,
        };

        let _ = state.insert_coverage_pool(pool);
        let _ = state.insert_reserve_proof(proof);
        let _ = state.insert_sealed_quote(quote);
        let _ = state.insert_backstop_commitment(backstop);
        let _ = state.insert_emergency_exit(exit);
        let _ = state.insert_reorg_insurance(insurance);
        let _ = state.insert_outage_claim(claim);
        let _ = state.insert_privacy_fence(fence);
        let _ = state.insert_pq_attestation(attestation);
        let _ = state.insert_slashing_evidence(slash);
        state
    }

    pub fn insert_coverage_pool(&mut self, pool: WatchtowerCoveragePool) -> Result<()> {
        require_capacity(
            "coverage pools",
            self.coverage_pools.len(),
            MAX_COVERAGE_POOLS,
        )?;
        pool.validate(&self.config)?;
        self.emit_event(
            "coverage_pool",
            &pool.pool_id,
            &pool.root(),
            pool.opened_at_height,
        );
        self.counters.coverage_pools = self.counters.coverage_pools.saturating_add(1);
        self.coverage_pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn insert_backstop_commitment(
        &mut self,
        commitment: LiquidityBackstopCommitment,
    ) -> Result<()> {
        require_capacity(
            "backstop commitments",
            self.backstop_commitments.len(),
            MAX_BACKSTOP_COMMITMENTS,
        )?;
        commitment.validate()?;
        let pool = self
            .coverage_pools
            .get(&commitment.pool_id)
            .ok_or_else(|| "unknown coverage pool for backstop commitment".to_string())?;
        if !pool.status.accepts_commitments() {
            return Err("coverage pool does not accept commitments".to_string());
        }
        if !self
            .reserve_proofs
            .contains_key(&commitment.reserve_proof_id)
        {
            return Err("unknown reserve proof for backstop commitment".to_string());
        }
        self.emit_event(
            "backstop_commitment",
            &commitment.commitment_id,
            &commitment.root(),
            commitment.committed_at_height,
        );
        self.counters.backstop_commitments = self.counters.backstop_commitments.saturating_add(1);
        self.backstop_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_reserve_proof(&mut self, proof: ReserveProof) -> Result<()> {
        require_capacity(
            "reserve proofs",
            self.reserve_proofs.len(),
            MAX_RESERVE_PROOFS,
        )?;
        proof.validate(&self.config)?;
        if !self.coverage_pools.contains_key(&proof.pool_id) {
            return Err("unknown coverage pool for reserve proof".to_string());
        }
        self.emit_event(
            "reserve_proof",
            &proof.proof_id,
            &proof.root(),
            proof.proved_at_height,
        );
        self.counters.reserve_proofs = self.counters.reserve_proofs.saturating_add(1);
        self.reserve_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_reorg_insurance(&mut self, insurance: ReorgLiquidationInsurance) -> Result<()> {
        require_capacity(
            "reorg insurance",
            self.reorg_insurance.len(),
            MAX_REORG_INSURANCE,
        )?;
        insurance.validate()?;
        if !self.coverage_pools.contains_key(&insurance.pool_id) {
            return Err("unknown coverage pool for reorg insurance".to_string());
        }
        self.emit_event(
            "reorg_liquidation_insurance",
            &insurance.insurance_id,
            &insurance.root(),
            insurance.bound_at_height,
        );
        self.counters.reorg_insurance = self.counters.reorg_insurance.saturating_add(1);
        self.reorg_insurance
            .insert(insurance.insurance_id.clone(), insurance);
        Ok(())
    }

    pub fn insert_outage_claim(&mut self, claim: BridgeOutageClaim) -> Result<()> {
        require_capacity("outage claims", self.outage_claims.len(), MAX_OUTAGE_CLAIMS)?;
        claim.validate()?;
        if !self.coverage_pools.contains_key(&claim.pool_id) {
            return Err("unknown coverage pool for outage claim".to_string());
        }
        self.emit_event(
            "outage_claim",
            &claim.claim_id,
            &claim.root(),
            claim.filed_at_height,
        );
        self.counters.outage_claims = self.counters.outage_claims.saturating_add(1);
        self.outage_claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn insert_sealed_quote(&mut self, quote: SealedMakerQuote) -> Result<()> {
        require_capacity("sealed quotes", self.sealed_quotes.len(), MAX_SEALED_QUOTES)?;
        quote.validate()?;
        if !self.coverage_pools.contains_key(&quote.pool_id) {
            return Err("unknown coverage pool for sealed quote".to_string());
        }
        self.emit_event(
            "sealed_quote",
            &quote.quote_id,
            &quote.root(),
            quote.sealed_at_height,
        );
        self.counters.sealed_quotes = self.counters.sealed_quotes.saturating_add(1);
        self.sealed_quotes.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn insert_emergency_exit(&mut self, reservation: EmergencyExitReservation) -> Result<()> {
        require_capacity(
            "emergency exits",
            self.emergency_exits.len(),
            MAX_EMERGENCY_EXITS,
        )?;
        reservation.validate()?;
        if !self.coverage_pools.contains_key(&reservation.pool_id) {
            return Err("unknown coverage pool for emergency exit".to_string());
        }
        self.emit_event(
            "emergency_exit",
            &reservation.reservation_id,
            &reservation.root(),
            reservation.reserved_at_height,
        );
        self.counters.emergency_exits = self.counters.emergency_exits.saturating_add(1);
        self.emergency_exits
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn insert_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        require_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            MAX_PRIVACY_FENCES,
        )?;
        fence.validate(&self.config)?;
        if self.spent_nullifiers.contains(&fence.nullifier_root) {
            return Err("duplicate privacy fence nullifier".to_string());
        }
        self.spent_nullifiers.insert(fence.nullifier_root.clone());
        self.emit_event(
            "privacy_fence",
            &fence.fence_id,
            &fence.root(),
            fence.inserted_at_height,
        );
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        require_capacity(
            "pq attestations",
            self.pq_attestations.len(),
            MAX_PQ_ATTESTATIONS,
        )?;
        attestation.validate(&self.config)?;
        self.emit_event(
            "pq_attestation",
            &attestation.attestation_id,
            &attestation.root(),
            attestation.attested_at_height,
        );
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        require_capacity(
            "slashing evidence",
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
        )?;
        evidence.validate()?;
        if !self.privacy_fences.contains_key(&evidence.fence_id) {
            return Err("unknown privacy fence for slashing evidence".to_string());
        }
        if !self.pq_attestations.contains_key(&evidence.attestation_id) {
            return Err("unknown pq attestation for slashing evidence".to_string());
        }
        self.emit_event(
            "slashing_evidence",
            &evidence.evidence_id,
            &evidence.root(),
            evidence.filed_at_height,
        );
        self.counters.slashing_evidence = self.counters.slashing_evidence.saturating_add(1);
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            coverage_pool_root: collection_root(
                "COVERAGE-POOLS",
                self.coverage_pools
                    .values()
                    .map(WatchtowerCoveragePool::public_record),
            ),
            backstop_commitment_root: collection_root(
                "BACKSTOP-COMMITMENTS",
                self.backstop_commitments
                    .values()
                    .map(LiquidityBackstopCommitment::public_record),
            ),
            reserve_proof_root: collection_root(
                "RESERVE-PROOFS",
                self.reserve_proofs
                    .values()
                    .map(ReserveProof::public_record),
            ),
            reorg_insurance_root: collection_root(
                "REORG-INSURANCE",
                self.reorg_insurance
                    .values()
                    .map(ReorgLiquidationInsurance::public_record),
            ),
            outage_claim_root: collection_root(
                "OUTAGE-CLAIMS",
                self.outage_claims
                    .values()
                    .map(BridgeOutageClaim::public_record),
            ),
            sealed_quote_root: collection_root(
                "SEALED-QUOTES",
                self.sealed_quotes
                    .values()
                    .map(SealedMakerQuote::public_record),
            ),
            emergency_exit_root: collection_root(
                "EMERGENCY-EXITS",
                self.emergency_exits
                    .values()
                    .map(EmergencyExitReservation::public_record),
            ),
            privacy_fence_root: collection_root(
                "PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            pq_attestation_root: collection_root(
                "PQ-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record),
            ),
            slashing_evidence_root: collection_root(
                "SLASHING-EVIDENCE",
                self.slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record),
            ),
            spent_nullifier_root: collection_root(
                "SPENT-NULLIFIERS",
                self.spent_nullifiers.iter().map(|value| json!(value)),
            ),
            event_root: collection_root(
                "EVENTS",
                self.events.values().map(RuntimeEvent::public_record),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "coverage_pools": self.coverage_pools.values().map(WatchtowerCoveragePool::public_record).collect::<Vec<_>>(),
            "backstop_commitments": self.backstop_commitments.values().map(LiquidityBackstopCommitment::public_record).collect::<Vec<_>>(),
            "reserve_proofs": self.reserve_proofs.values().map(ReserveProof::public_record).collect::<Vec<_>>(),
            "reorg_insurance": self.reorg_insurance.values().map(ReorgLiquidationInsurance::public_record).collect::<Vec<_>>(),
            "outage_claims": self.outage_claims.values().map(BridgeOutageClaim::public_record).collect::<Vec<_>>(),
            "sealed_quotes": self.sealed_quotes.values().map(SealedMakerQuote::public_record).collect::<Vec<_>>(),
            "emergency_exits": self.emergency_exits.values().map(EmergencyExitReservation::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqAttestation::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "spent_nullifier_root": roots.spent_nullifier_root,
            "events": self.events.values().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str, subject_root: &str, height: u64) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let sequence = self.counters.events.saturating_add(1);
        let event_id = runtime_event_id(kind, subject_id, subject_root, height, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
        };
        self.counters.events = sequence;
        self.events.insert(event_id, event);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-WATCHTOWER-LIQUIDITY-BACKSTOP-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn coverage_pool_id(
    lane: CoverageLane,
    operator_commitment: &str,
    reserve_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-COVERAGE-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(reserve_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn backstop_commitment_id(
    pool_id: &str,
    maker_commitment: &str,
    quote_root: &str,
    amount_units: u64,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-BACKSTOP-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(maker_commitment),
            HashPart::Str(quote_root),
            HashPart::U64(amount_units),
            HashPart::U64(committed_at_height),
        ],
        32,
    )
}

pub fn reserve_proof_id(
    kind: ReserveProofKind,
    pool_id: &str,
    reserve_root: &str,
    liability_root: &str,
    proved_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(pool_id),
            HashPart::Str(reserve_root),
            HashPart::Str(liability_root),
            HashPart::U64(proved_at_height),
        ],
        32,
    )
}

pub fn insurance_id(
    kind: InsuranceKind,
    pool_id: &str,
    insured_commitment: &str,
    bound_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-INSURANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(pool_id),
            HashPart::Str(insured_commitment),
            HashPart::U64(bound_at_height),
        ],
        32,
    )
}

pub fn outage_claim_id(
    kind: OutageClaimKind,
    pool_id: &str,
    claimant_commitment: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-OUTAGE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(pool_id),
            HashPart::Str(claimant_commitment),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn sealed_quote_id(
    pool_id: &str,
    maker_commitment: &str,
    sealed_quote_root: &str,
    sealed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-SEALED-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(maker_commitment),
            HashPart::Str(sealed_quote_root),
            HashPart::U64(sealed_at_height),
        ],
        32,
    )
}

pub fn emergency_exit_id(
    pool_id: &str,
    exit_commitment: &str,
    destination_root: &str,
    reserved_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-EMERGENCY-EXIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(exit_commitment),
            HashPart::Str(destination_root),
            HashPart::U64(reserved_at_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    commitment_root: &str,
    nullifier_root: &str,
    inserted_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(inserted_at_height),
        ],
        32,
    )
}

pub fn pq_attestation_id(
    kind: AttestationKind,
    subject_id: &str,
    subject_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(attested_at_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    reason: SlashReason,
    subject_id: &str,
    accused_commitment: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reason.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(accused_commitment),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn runtime_event_id(
    kind: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WATCHTOWER-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() < 32 {
        Err(format!("{label} must be a commitment root"))
    } else {
        Ok(())
    }
}

fn validate_hash(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!("{label} must be a 32-byte hex hash"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_height_window(label: &str, start: u64, end: u64) -> Result<()> {
    if end <= start {
        Err(format!("{label} height window is empty"))
    } else {
        Ok(())
    }
}

fn require_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_is_deterministic() {
        let a = State::devnet();
        let b = State::devnet();
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(devnet_state_root(), a.state_root());
    }

    #[test]
    fn public_record_round_trips_root_helper() {
        let state = State::devnet();
        let record = state.public_record_without_state_root();
        assert_eq!(state_root_from_public_record(&record), state.state_root());
    }
}
