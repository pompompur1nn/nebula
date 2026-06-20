use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_WATCHTOWER_EXECUTION_DISPUTE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-watchtower-execution-dispute-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_WATCHTOWER_EXECUTION_DISPUTE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-private-bridge-watchtower-execution-dispute-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_493_760;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_COMMITTEE_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-execution-dispute-committee-v1";
pub const EVIDENCE_ENVELOPE_SCHEME: &str = "ml-kem-1024-sealed-watchtower-evidence-envelope-v1";
pub const DISPUTE_TICKET_SCHEME: &str = "private-confidential-execution-dispute-ticket-v1";
pub const FINALITY_WINDOW_SCHEME: &str = "monero-l2-reorg-finality-window-root-v1";
pub const LIQUIDITY_PENALTY_SCHEME: &str = "liquidity-backstop-penalty-commitment-root-v1";
pub const SELECTIVE_DISCLOSURE_SCHEME: &str = "private-selective-disclosure-root-v1";
pub const FEE_ROUTING_SCHEME: &str = "fee-aware-dispute-routing-root-v1";
pub const SLASHING_LEDGER_SCHEME: &str = "execution-dispute-slashing-ledger-root-v1";
pub const APPEAL_LEDGER_SCHEME: &str = "execution-dispute-appeal-ledger-root-v1";
pub const SETTLEMENT_LEDGER_SCHEME: &str = "execution-dispute-settlement-ledger-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "execution-dispute-nullifier-fence-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITTEE_SIGNERS: u16 = 5;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 9;
pub const DEFAULT_REORG_GUARD_BLOCKS: u64 = 32;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 48;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_APPEAL_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_MAX_ROUTE_FEE_MICRO_UNITS: u64 = 20_000;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 6_000;
pub const DEFAULT_LIQUIDITY_DEFAULT_PENALTY_BPS: u64 = 2_500;
pub const DEFAULT_FALSE_EXECUTION_PENALTY_BPS: u64 = 5_000;
pub const DEFAULT_WITHHELD_DISCLOSURE_PENALTY_BPS: u64 = 3_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_EVIDENCE_ENVELOPES: usize = 1_048_576;
pub const MAX_COMMITTEE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_DISPUTE_TICKETS: usize = 1_048_576;
pub const MAX_FINALITY_WINDOWS: usize = 524_288;
pub const MAX_LIQUIDITY_PENALTIES: usize = 524_288;
pub const MAX_DISCLOSURE_ROOTS: usize = 1_048_576;
pub const MAX_FEE_ROUTES: usize = 524_288;
pub const MAX_SLASHING_LEDGER_ENTRIES: usize = 524_288;
pub const MAX_APPEAL_LEDGER_ENTRIES: usize = 262_144;
pub const MAX_SETTLEMENT_LEDGER_ENTRIES: usize = 524_288;
pub const MAX_PRIVACY_FENCES: usize = 2_097_152;
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
pub enum EvidenceKind {
    ExecutionMismatch,
    InvalidWitness,
    FeeOvercharge,
    LiquidityDefault,
    ReorgConcealment,
    FinalityViolation,
    DisclosureWithheld,
    SettlementEquivocation,
    TokenDeltaMismatch,
    ContractStateDivergence,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionMismatch => "execution_mismatch",
            Self::InvalidWitness => "invalid_witness",
            Self::FeeOvercharge => "fee_overcharge",
            Self::LiquidityDefault => "liquidity_default",
            Self::ReorgConcealment => "reorg_concealment",
            Self::FinalityViolation => "finality_violation",
            Self::DisclosureWithheld => "disclosure_withheld",
            Self::SettlementEquivocation => "settlement_equivocation",
            Self::TokenDeltaMismatch => "token_delta_mismatch",
            Self::ContractStateDivergence => "contract_state_divergence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    EvidenceSeen,
    EnvelopeWellFormed,
    TicketAdmissible,
    FinalityWindowValid,
    ReorgRiskBounded,
    LiquidityDefaultObserved,
    DisclosureRootValid,
    FeeRouteAccepted,
    SlashReady,
    SettlementReady,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceSeen => "evidence_seen",
            Self::EnvelopeWellFormed => "envelope_well_formed",
            Self::TicketAdmissible => "ticket_admissible",
            Self::FinalityWindowValid => "finality_window_valid",
            Self::ReorgRiskBounded => "reorg_risk_bounded",
            Self::LiquidityDefaultObserved => "liquidity_default_observed",
            Self::DisclosureRootValid => "disclosure_root_valid",
            Self::FeeRouteAccepted => "fee_route_accepted",
            Self::SlashReady => "slash_ready",
            Self::SettlementReady => "settlement_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketKind {
    ExecutionReceipt,
    SettlementManifest,
    FastExitFill,
    TokenMintBurn,
    ContractCall,
    ReserveDebit,
    FeeSponsorRebate,
}

impl TicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionReceipt => "execution_receipt",
            Self::SettlementManifest => "settlement_manifest",
            Self::FastExitFill => "fast_exit_fill",
            Self::TokenMintBurn => "token_mint_burn",
            Self::ContractCall => "contract_call",
            Self::ReserveDebit => "reserve_debit",
            Self::FeeSponsorRebate => "fee_sponsor_rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLane {
    LowFee,
    Standard,
    Fast,
    ReorgEmergency,
    LiquidityBackstop,
    GovernanceAppeal,
}

impl RouteLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::ReorgEmergency => "reorg_emergency",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::GovernanceAppeal => "governance_appeal",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::ReorgEmergency => 1_000,
            Self::LiquidityBackstop => 940,
            Self::Fast => 900,
            Self::GovernanceAppeal => 820,
            Self::Standard => 720,
            Self::LowFee => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    EvidenceNullifier,
    TicketNullifier,
    DisclosureNullifier,
    RouteNullifier,
    SlashNullifier,
    AppealNullifier,
    SettlementNullifier,
    KeyImage,
    ViewTag,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceNullifier => "evidence_nullifier",
            Self::TicketNullifier => "ticket_nullifier",
            Self::DisclosureNullifier => "disclosure_nullifier",
            Self::RouteNullifier => "route_nullifier",
            Self::SlashNullifier => "slash_nullifier",
            Self::AppealNullifier => "appeal_nullifier",
            Self::SettlementNullifier => "settlement_nullifier",
            Self::KeyImage => "key_image",
            Self::ViewTag => "view_tag",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    FalseExecution,
    InvalidDispute,
    WithheldDisclosure,
    LiquidityDefault,
    ReorgConcealment,
    DuplicateNullifier,
    FeeRouteFraud,
    SettlementEquivocation,
    PqCommitteeForgery,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseExecution => "false_execution",
            Self::InvalidDispute => "invalid_dispute",
            Self::WithheldDisclosure => "withheld_disclosure",
            Self::LiquidityDefault => "liquidity_default",
            Self::ReorgConcealment => "reorg_concealment",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FeeRouteFraud => "fee_route_fraud",
            Self::SettlementEquivocation => "settlement_equivocation",
            Self::PqCommitteeForgery => "pq_committee_forgery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    Dismissed,
    ChallengerPaid,
    AccusedReleased,
    SlashApplied,
    LiquidityBackstopPaid,
    AppealSustained,
    ManifestCorrected,
    PrivateRefund,
}

impl SettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismissed => "dismissed",
            Self::ChallengerPaid => "challenger_paid",
            Self::AccusedReleased => "accused_released",
            Self::SlashApplied => "slash_applied",
            Self::LiquidityBackstopPaid => "liquidity_backstop_paid",
            Self::AppealSustained => "appeal_sustained",
            Self::ManifestCorrected => "manifest_corrected",
            Self::PrivateRefund => "private_refund",
        }
    }
}

status_enum!(EvidenceStatus {
    Sealed => "sealed",
    Fenced => "fenced",
    Attested => "attested",
    Ticketed => "ticketed",
    Routed => "routed",
    Disclosed => "disclosed",
    Slashed => "slashed",
    Settled => "settled",
    Rejected => "rejected"
});

status_enum!(AttestationStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    WeakQuorum => "weak_quorum",
    Superseded => "superseded",
    Rejected => "rejected",
    Slashed => "slashed"
});

status_enum!(TicketStatus {
    Opened => "opened",
    PrivacyChecked => "privacy_checked",
    FinalityPending => "finality_pending",
    Admissible => "admissible",
    Routed => "routed",
    SlashingPending => "slashing_pending",
    Appealed => "appealed",
    Settled => "settled",
    Rejected => "rejected"
});

status_enum!(FinalityWindowStatus {
    Guarded => "guarded",
    ReorgRisk => "reorg_risk",
    Finalized => "finalized",
    Expired => "expired",
    Disputed => "disputed"
});

status_enum!(PenaltyStatus {
    Proposed => "proposed",
    Attested => "attested",
    Locked => "locked",
    Applied => "applied",
    Released => "released",
    Appealed => "appealed",
    Rejected => "rejected"
});

status_enum!(DisclosureStatus {
    Committed => "committed",
    Waiting => "waiting",
    Open => "open",
    Revealed => "revealed",
    Consumed => "consumed",
    Expired => "expired"
});

status_enum!(RouteStatus {
    Quoted => "quoted",
    Selected => "selected",
    CommitteeAccepted => "committee_accepted",
    Executed => "executed",
    Expired => "expired",
    Disputed => "disputed"
});

status_enum!(SlashStatus {
    Filed => "filed",
    QuorumPending => "quorum_pending",
    Attested => "attested",
    AppealOpen => "appeal_open",
    Accepted => "accepted",
    Rejected => "rejected",
    Settled => "settled"
});

status_enum!(AppealStatus {
    Open => "open",
    EvidenceCommitted => "evidence_committed",
    CommitteeReview => "committee_review",
    Sustained => "sustained",
    Rejected => "rejected",
    Expired => "expired"
});

status_enum!(SettlementStatus {
    Draft => "draft",
    AwaitingDelay => "awaiting_delay",
    Finalized => "finalized",
    Superseded => "superseded",
    Reversed => "reversed"
});

status_enum!(FenceStatus {
    Committed => "committed",
    Active => "active",
    Spent => "spent",
    Expired => "expired",
    Disputed => "disputed"
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
    pub pq_committee_suite: String,
    pub evidence_envelope_scheme: String,
    pub dispute_ticket_scheme: String,
    pub finality_window_scheme: String,
    pub liquidity_penalty_scheme: String,
    pub selective_disclosure_scheme: String,
    pub fee_routing_scheme: String,
    pub slashing_ledger_scheme: String,
    pub appeal_ledger_scheme: String,
    pub settlement_ledger_scheme: String,
    pub privacy_fence_scheme: String,
    pub min_privacy_set_size: u64,
    pub target_pq_security_bits: u16,
    pub min_committee_signers: u16,
    pub min_committee_weight: u64,
    pub reorg_guard_blocks: u64,
    pub finality_delay_blocks: u64,
    pub dispute_window_blocks: u64,
    pub appeal_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub low_fee_target_micro_units: u64,
    pub max_route_fee_micro_units: u64,
    pub max_slash_bps: u64,
    pub liquidity_default_penalty_bps: u64,
    pub false_execution_penalty_bps: u64,
    pub withheld_disclosure_penalty_bps: u64,
    pub max_evidence_envelopes: usize,
    pub max_committee_attestations: usize,
    pub max_dispute_tickets: usize,
    pub max_finality_windows: usize,
    pub max_liquidity_penalties: usize,
    pub max_disclosure_roots: usize,
    pub max_fee_routes: usize,
    pub max_slashing_ledger_entries: usize,
    pub max_appeal_ledger_entries: usize,
    pub max_settlement_ledger_entries: usize,
    pub max_privacy_fences: usize,
    pub max_events: usize,
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
            pq_committee_suite: PQ_COMMITTEE_SUITE.to_string(),
            evidence_envelope_scheme: EVIDENCE_ENVELOPE_SCHEME.to_string(),
            dispute_ticket_scheme: DISPUTE_TICKET_SCHEME.to_string(),
            finality_window_scheme: FINALITY_WINDOW_SCHEME.to_string(),
            liquidity_penalty_scheme: LIQUIDITY_PENALTY_SCHEME.to_string(),
            selective_disclosure_scheme: SELECTIVE_DISCLOSURE_SCHEME.to_string(),
            fee_routing_scheme: FEE_ROUTING_SCHEME.to_string(),
            slashing_ledger_scheme: SLASHING_LEDGER_SCHEME.to_string(),
            appeal_ledger_scheme: APPEAL_LEDGER_SCHEME.to_string(),
            settlement_ledger_scheme: SETTLEMENT_LEDGER_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_committee_signers: DEFAULT_MIN_COMMITTEE_SIGNERS,
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            reorg_guard_blocks: DEFAULT_REORG_GUARD_BLOCKS,
            finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            appeal_window_blocks: DEFAULT_APPEAL_WINDOW_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            max_route_fee_micro_units: DEFAULT_MAX_ROUTE_FEE_MICRO_UNITS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            liquidity_default_penalty_bps: DEFAULT_LIQUIDITY_DEFAULT_PENALTY_BPS,
            false_execution_penalty_bps: DEFAULT_FALSE_EXECUTION_PENALTY_BPS,
            withheld_disclosure_penalty_bps: DEFAULT_WITHHELD_DISCLOSURE_PENALTY_BPS,
            max_evidence_envelopes: MAX_EVIDENCE_ENVELOPES,
            max_committee_attestations: MAX_COMMITTEE_ATTESTATIONS,
            max_dispute_tickets: MAX_DISPUTE_TICKETS,
            max_finality_windows: MAX_FINALITY_WINDOWS,
            max_liquidity_penalties: MAX_LIQUIDITY_PENALTIES,
            max_disclosure_roots: MAX_DISCLOSURE_ROOTS,
            max_fee_routes: MAX_FEE_ROUTES,
            max_slashing_ledger_entries: MAX_SLASHING_LEDGER_ENTRIES,
            max_appeal_ledger_entries: MAX_APPEAL_LEDGER_ENTRIES,
            max_settlement_ledger_entries: MAX_SETTLEMENT_LEDGER_ENTRIES,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_events: MAX_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_positive("min_committee_signers", self.min_committee_signers as u64)?;
        require_positive("min_committee_weight", self.min_committee_weight)?;
        require_positive("reorg_guard_blocks", self.reorg_guard_blocks)?;
        require_positive("finality_delay_blocks", self.finality_delay_blocks)?;
        require_positive("dispute_window_blocks", self.dispute_window_blocks)?;
        require_positive("appeal_window_blocks", self.appeal_window_blocks)?;
        require_positive("settlement_delay_blocks", self.settlement_delay_blocks)?;
        require_bps("max_slash_bps", self.max_slash_bps)?;
        require_bps(
            "liquidity_default_penalty_bps",
            self.liquidity_default_penalty_bps,
        )?;
        require_bps(
            "false_execution_penalty_bps",
            self.false_execution_penalty_bps,
        )?;
        require_bps(
            "withheld_disclosure_penalty_bps",
            self.withheld_disclosure_penalty_bps,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub evidence_envelopes: u64,
    pub committee_attestations: u64,
    pub dispute_tickets: u64,
    pub finality_windows: u64,
    pub liquidity_penalties: u64,
    pub disclosure_roots: u64,
    pub fee_routes: u64,
    pub slashing_entries: u64,
    pub appeal_entries: u64,
    pub settlement_entries: u64,
    pub privacy_fences: u64,
    pub accepted_disputes: u64,
    pub rejected_disputes: u64,
    pub finalized_settlements: u64,
    pub total_route_fee_micro_units: u128,
    pub total_locked_penalty_micro_units: u128,
    pub total_slashed_micro_units: u128,
    pub total_released_micro_units: u128,
    pub events: u64,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            evidence_envelopes: 0,
            committee_attestations: 0,
            dispute_tickets: 0,
            finality_windows: 0,
            liquidity_penalties: 0,
            disclosure_roots: 0,
            fee_routes: 0,
            slashing_entries: 0,
            appeal_entries: 0,
            settlement_entries: 0,
            privacy_fences: 0,
            accepted_disputes: 0,
            rejected_disputes: 0,
            finalized_settlements: 0,
            total_route_fee_micro_units: 0,
            total_locked_penalty_micro_units: 0,
            total_slashed_micro_units: 0,
            total_released_micro_units: 0,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_envelopes": self.evidence_envelopes,
            "committee_attestations": self.committee_attestations,
            "dispute_tickets": self.dispute_tickets,
            "finality_windows": self.finality_windows,
            "liquidity_penalties": self.liquidity_penalties,
            "disclosure_roots": self.disclosure_roots,
            "fee_routes": self.fee_routes,
            "slashing_entries": self.slashing_entries,
            "appeal_entries": self.appeal_entries,
            "settlement_entries": self.settlement_entries,
            "privacy_fences": self.privacy_fences,
            "accepted_disputes": self.accepted_disputes,
            "rejected_disputes": self.rejected_disputes,
            "finalized_settlements": self.finalized_settlements,
            "total_route_fee_micro_units": self.total_route_fee_micro_units.to_string(),
            "total_locked_penalty_micro_units": self.total_locked_penalty_micro_units.to_string(),
            "total_slashed_micro_units": self.total_slashed_micro_units.to_string(),
            "total_released_micro_units": self.total_released_micro_units.to_string(),
            "events": self.events,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub evidence_envelope_root: String,
    pub committee_attestation_root: String,
    pub dispute_ticket_root: String,
    pub finality_window_root: String,
    pub liquidity_penalty_root: String,
    pub disclosure_root: String,
    pub fee_route_root: String,
    pub slashing_ledger_root: String,
    pub appeal_ledger_root: String,
    pub settlement_ledger_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: config.root(),
            counters_root: counters.root(),
            evidence_envelope_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-EVIDENCE"),
            committee_attestation_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-COMMITTEE"),
            dispute_ticket_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-TICKET"),
            finality_window_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-FINALITY"),
            liquidity_penalty_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-PENALTY"),
            disclosure_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-DISCLOSURE"),
            fee_route_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-ROUTE"),
            slashing_ledger_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-SLASH"),
            appeal_ledger_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-APPEAL"),
            settlement_ledger_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-SETTLEMENT"),
            privacy_fence_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-FENCE"),
            nullifier_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-NULLIFIER"),
            event_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-EVENT"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeSignature {
    pub suite: String,
    pub signer_commitment: String,
    pub signing_key_commitment: String,
    pub transcript_root: String,
    pub signature_commitment: String,
    pub weight: u64,
}

impl PqCommitteeSignature {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.suite != config.pq_committee_suite {
            return Err("unsupported pq committee suite".to_string());
        }
        require_non_empty("signer_commitment", &self.signer_commitment)?;
        require_root("signing_key_commitment", &self.signing_key_commitment)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("signature_commitment", &self.signature_commitment)?;
        require_positive("weight", self.weight)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerEvidenceEnvelope {
    pub envelope_id: String,
    pub kind: EvidenceKind,
    pub watcher_commitment: String,
    pub subject_id: String,
    pub execution_root: String,
    pub sealed_payload_root: String,
    pub ciphertext_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub monero_anchor_height: u64,
    pub l2_anchor_height: u64,
    pub privacy_set_size: u64,
    pub disclosed_root: Option<String>,
    pub quorum_root: String,
    pub status: EvidenceStatus,
}

impl WatchtowerEvidenceEnvelope {
    pub fn new(
        kind: EvidenceKind,
        watcher_commitment: &str,
        subject_id: &str,
        execution_root: &str,
        ciphertext_root: &str,
        witness_commitment_root: &str,
        nullifier_root: &str,
        monero_anchor_height: u64,
        l2_anchor_height: u64,
        privacy_set_size: u64,
    ) -> Self {
        let sealed_payload_root = evidence_payload_root(
            kind,
            subject_id,
            execution_root,
            ciphertext_root,
            witness_commitment_root,
        );
        let envelope_id = evidence_envelope_id(
            kind,
            watcher_commitment,
            subject_id,
            &sealed_payload_root,
            nullifier_root,
            l2_anchor_height,
        );
        Self {
            envelope_id,
            kind,
            watcher_commitment: watcher_commitment.to_string(),
            subject_id: subject_id.to_string(),
            execution_root: execution_root.to_string(),
            sealed_payload_root,
            ciphertext_root: ciphertext_root.to_string(),
            witness_commitment_root: witness_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            monero_anchor_height,
            l2_anchor_height,
            privacy_set_size,
            disclosed_root: None,
            quorum_root: empty_root("MONERO-L2-PQ-EXECUTION-DISPUTE-EVIDENCE-QUORUM"),
            status: EvidenceStatus::Sealed,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("watcher_commitment", &self.watcher_commitment)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("execution_root", &self.execution_root)?;
        require_root("sealed_payload_root", &self.sealed_payload_root)?;
        require_root("ciphertext_root", &self.ciphertext_root)?;
        require_root("witness_commitment_root", &self.witness_commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("evidence privacy set below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-EVIDENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub envelope_id: String,
    pub ticket_id: Option<String>,
    pub statement_root: String,
    pub signer_commitment: String,
    pub weight: u64,
    pub signature: PqCommitteeSignature,
    pub attested_at_height: u64,
    pub status: AttestationStatus,
}

impl PqCommitteeAttestation {
    pub fn new(
        kind: AttestationKind,
        envelope_id: &str,
        ticket_id: Option<String>,
        statement_root: &str,
        signature: PqCommitteeSignature,
        attested_at_height: u64,
    ) -> Self {
        let attestation_id = pq_committee_attestation_id(
            kind,
            envelope_id,
            ticket_id.as_deref().unwrap_or(""),
            &signature.signer_commitment,
            statement_root,
            attested_at_height,
        );
        Self {
            attestation_id,
            kind,
            envelope_id: envelope_id.to_string(),
            ticket_id,
            statement_root: statement_root.to_string(),
            signer_commitment: signature.signer_commitment.clone(),
            weight: signature.weight,
            signature,
            attested_at_height,
            status: AttestationStatus::Submitted,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("envelope_id", &self.envelope_id)?;
        require_root("statement_root", &self.statement_root)?;
        self.signature.validate(config)?;
        if self.signer_commitment != self.signature.signer_commitment {
            return Err("attestation signer does not match signature signer".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialExecutionDisputeTicket {
    pub ticket_id: String,
    pub kind: TicketKind,
    pub envelope_id: String,
    pub claimant_commitment: String,
    pub accused_commitment: String,
    pub disputed_execution_root: String,
    pub expected_execution_root: String,
    pub private_input_root: String,
    pub private_output_root: String,
    pub token_delta_root: String,
    pub fee_commitment_root: String,
    pub ticket_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub route_id: Option<String>,
    pub slash_entry_id: Option<String>,
    pub appeal_entry_id: Option<String>,
    pub settlement_entry_id: Option<String>,
    pub status: TicketStatus,
}

impl ConfidentialExecutionDisputeTicket {
    pub fn new(
        kind: TicketKind,
        envelope_id: &str,
        claimant_commitment: &str,
        accused_commitment: &str,
        disputed_execution_root: &str,
        expected_execution_root: &str,
        private_input_root: &str,
        private_output_root: &str,
        token_delta_root: &str,
        fee_commitment_root: &str,
        ticket_nullifier_root: &str,
        opened_at_height: u64,
        dispute_window_blocks: u64,
    ) -> Self {
        let expires_at_height = opened_at_height.saturating_add(dispute_window_blocks);
        let ticket_id = dispute_ticket_id(
            kind,
            envelope_id,
            claimant_commitment,
            accused_commitment,
            ticket_nullifier_root,
            opened_at_height,
        );
        Self {
            ticket_id,
            kind,
            envelope_id: envelope_id.to_string(),
            claimant_commitment: claimant_commitment.to_string(),
            accused_commitment: accused_commitment.to_string(),
            disputed_execution_root: disputed_execution_root.to_string(),
            expected_execution_root: expected_execution_root.to_string(),
            private_input_root: private_input_root.to_string(),
            private_output_root: private_output_root.to_string(),
            token_delta_root: token_delta_root.to_string(),
            fee_commitment_root: fee_commitment_root.to_string(),
            ticket_nullifier_root: ticket_nullifier_root.to_string(),
            opened_at_height,
            expires_at_height,
            route_id: None,
            slash_entry_id: None,
            appeal_entry_id: None,
            settlement_entry_id: None,
            status: TicketStatus::Opened,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("envelope_id", &self.envelope_id)?;
        require_non_empty("claimant_commitment", &self.claimant_commitment)?;
        require_non_empty("accused_commitment", &self.accused_commitment)?;
        require_root("disputed_execution_root", &self.disputed_execution_root)?;
        require_root("expected_execution_root", &self.expected_execution_root)?;
        require_root("private_input_root", &self.private_input_root)?;
        require_root("private_output_root", &self.private_output_root)?;
        require_root("token_delta_root", &self.token_delta_root)?;
        require_root("fee_commitment_root", &self.fee_commitment_root)?;
        require_root("ticket_nullifier_root", &self.ticket_nullifier_root)?;
        require_height_window("ticket", self.opened_at_height, self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-TICKET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgFinalityWindow {
    pub window_id: String,
    pub envelope_id: String,
    pub subject_id: String,
    pub monero_start_height: u64,
    pub monero_observed_height: u64,
    pub monero_finality_height: u64,
    pub l2_start_height: u64,
    pub l2_finality_height: u64,
    pub anchor_block_root: String,
    pub parent_chain_root: String,
    pub reorg_evidence_root: String,
    pub risk_score_bps: u64,
    pub status: FinalityWindowStatus,
}

impl ReorgFinalityWindow {
    pub fn new(
        envelope_id: &str,
        subject_id: &str,
        monero_observed_height: u64,
        l2_start_height: u64,
        anchor_block_root: &str,
        parent_chain_root: &str,
        reorg_evidence_root: &str,
        risk_score_bps: u64,
        config: &Config,
    ) -> Self {
        let monero_start_height = monero_observed_height.saturating_sub(config.reorg_guard_blocks);
        let monero_finality_height =
            monero_observed_height.saturating_add(config.finality_delay_blocks);
        let l2_finality_height = l2_start_height.saturating_add(config.finality_delay_blocks);
        let window_id = finality_window_id(
            envelope_id,
            subject_id,
            monero_observed_height,
            anchor_block_root,
            l2_start_height,
        );
        Self {
            window_id,
            envelope_id: envelope_id.to_string(),
            subject_id: subject_id.to_string(),
            monero_start_height,
            monero_observed_height,
            monero_finality_height,
            l2_start_height,
            l2_finality_height,
            anchor_block_root: anchor_block_root.to_string(),
            parent_chain_root: parent_chain_root.to_string(),
            reorg_evidence_root: reorg_evidence_root.to_string(),
            risk_score_bps,
            status: FinalityWindowStatus::Guarded,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("envelope_id", &self.envelope_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("anchor_block_root", &self.anchor_block_root)?;
        require_root("parent_chain_root", &self.parent_chain_root)?;
        require_root("reorg_evidence_root", &self.reorg_evidence_root)?;
        require_bps("risk_score_bps", self.risk_score_bps)?;
        require_height_window(
            "monero finality",
            self.monero_start_height,
            self.monero_finality_height,
        )?;
        require_height_window("l2 finality", self.l2_start_height, self.l2_finality_height)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-FINALITY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBackstopPenalty {
    pub penalty_id: String,
    pub ticket_id: String,
    pub provider_commitment: String,
    pub backstop_pool_id: String,
    pub reason: SlashReason,
    pub penalty_bps: u64,
    pub locked_amount_micro_units: u128,
    pub penalty_amount_micro_units: u128,
    pub bond_commitment_root: String,
    pub payout_commitment_root: String,
    pub proposed_at_height: u64,
    pub status: PenaltyStatus,
}

impl LiquidityBackstopPenalty {
    pub fn new(
        ticket_id: &str,
        provider_commitment: &str,
        backstop_pool_id: &str,
        reason: SlashReason,
        penalty_bps: u64,
        locked_amount_micro_units: u128,
        bond_commitment_root: &str,
        payout_commitment_root: &str,
        proposed_at_height: u64,
    ) -> Self {
        let penalty_amount_micro_units = bps_amount(locked_amount_micro_units, penalty_bps);
        let penalty_id = liquidity_penalty_id(
            ticket_id,
            provider_commitment,
            backstop_pool_id,
            reason,
            bond_commitment_root,
            proposed_at_height,
        );
        Self {
            penalty_id,
            ticket_id: ticket_id.to_string(),
            provider_commitment: provider_commitment.to_string(),
            backstop_pool_id: backstop_pool_id.to_string(),
            reason,
            penalty_bps,
            locked_amount_micro_units,
            penalty_amount_micro_units,
            bond_commitment_root: bond_commitment_root.to_string(),
            payout_commitment_root: payout_commitment_root.to_string(),
            proposed_at_height,
            status: PenaltyStatus::Proposed,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("provider_commitment", &self.provider_commitment)?;
        require_non_empty("backstop_pool_id", &self.backstop_pool_id)?;
        require_bps("penalty_bps", self.penalty_bps)?;
        if self.penalty_bps > config.max_slash_bps {
            return Err("penalty exceeds configured slash cap".to_string());
        }
        require_root("bond_commitment_root", &self.bond_commitment_root)?;
        require_root("payout_commitment_root", &self.payout_commitment_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "penalty_id": self.penalty_id,
            "ticket_id": self.ticket_id,
            "provider_commitment": self.provider_commitment,
            "backstop_pool_id": self.backstop_pool_id,
            "reason": self.reason,
            "penalty_bps": self.penalty_bps,
            "locked_amount_micro_units": self.locked_amount_micro_units.to_string(),
            "penalty_amount_micro_units": self.penalty_amount_micro_units.to_string(),
            "bond_commitment_root": self.bond_commitment_root,
            "payout_commitment_root": self.payout_commitment_root,
            "proposed_at_height": self.proposed_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-PENALTY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSelectiveDisclosureRoot {
    pub disclosure_id: String,
    pub envelope_id: String,
    pub ticket_id: String,
    pub disclosure_root: String,
    pub policy_root: String,
    pub viewer_set_root: String,
    pub redaction_root: String,
    pub nullifier_root: String,
    pub available_from_height: u64,
    pub expires_at_height: u64,
    pub status: DisclosureStatus,
}

impl PrivateSelectiveDisclosureRoot {
    pub fn new(
        envelope_id: &str,
        ticket_id: &str,
        disclosure_root: &str,
        policy_root: &str,
        viewer_set_root: &str,
        redaction_root: &str,
        nullifier_root: &str,
        available_from_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let disclosure_id = selective_disclosure_id(
            envelope_id,
            ticket_id,
            disclosure_root,
            nullifier_root,
            available_from_height,
        );
        Self {
            disclosure_id,
            envelope_id: envelope_id.to_string(),
            ticket_id: ticket_id.to_string(),
            disclosure_root: disclosure_root.to_string(),
            policy_root: policy_root.to_string(),
            viewer_set_root: viewer_set_root.to_string(),
            redaction_root: redaction_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            available_from_height,
            expires_at_height,
            status: DisclosureStatus::Committed,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("envelope_id", &self.envelope_id)?;
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_root("disclosure_root", &self.disclosure_root)?;
        require_root("policy_root", &self.policy_root)?;
        require_root("viewer_set_root", &self.viewer_set_root)?;
        require_root("redaction_root", &self.redaction_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_height_window(
            "disclosure",
            self.available_from_height,
            self.expires_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-DISCLOSURE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeAwareDisputeRoute {
    pub route_id: String,
    pub ticket_id: String,
    pub lane: RouteLane,
    pub fee_asset_id: String,
    pub quoted_fee_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub route_priority: u64,
    pub relayer_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub route_commitment_root: String,
    pub selected_at_height: u64,
    pub expires_at_height: u64,
    pub status: RouteStatus,
}

impl FeeAwareDisputeRoute {
    pub fn new(
        ticket_id: &str,
        lane: RouteLane,
        fee_asset_id: &str,
        quoted_fee_micro_units: u64,
        max_fee_micro_units: u64,
        relayer_commitment: &str,
        sponsor_commitment: Option<String>,
        route_commitment_root: &str,
        selected_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let expires_at_height = selected_at_height.saturating_add(ttl_blocks);
        let route_priority = lane
            .priority_weight()
            .saturating_sub(quoted_fee_micro_units / 1_000);
        let route_id = fee_route_id(
            ticket_id,
            lane,
            relayer_commitment,
            route_commitment_root,
            selected_at_height,
        );
        Self {
            route_id,
            ticket_id: ticket_id.to_string(),
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            quoted_fee_micro_units,
            max_fee_micro_units,
            route_priority,
            relayer_commitment: relayer_commitment.to_string(),
            sponsor_commitment,
            route_commitment_root: route_commitment_root.to_string(),
            selected_at_height,
            expires_at_height,
            status: RouteStatus::Quoted,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("relayer_commitment", &self.relayer_commitment)?;
        require_root("route_commitment_root", &self.route_commitment_root)?;
        if self.quoted_fee_micro_units > self.max_fee_micro_units {
            return Err("quoted route fee exceeds caller maximum".to_string());
        }
        if self.quoted_fee_micro_units > config.max_route_fee_micro_units {
            return Err("quoted route fee exceeds runtime maximum".to_string());
        }
        require_height_window("fee route", self.selected_at_height, self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-ROUTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingLedgerEntry {
    pub slash_entry_id: String,
    pub ticket_id: String,
    pub envelope_id: String,
    pub accused_commitment: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub committee_root: String,
    pub penalty_id: Option<String>,
    pub slash_bps: u64,
    pub locked_amount_micro_units: u128,
    pub slash_amount_micro_units: u128,
    pub filed_at_height: u64,
    pub appeal_deadline_height: u64,
    pub status: SlashStatus,
}

impl SlashingLedgerEntry {
    pub fn new(
        ticket_id: &str,
        envelope_id: &str,
        accused_commitment: &str,
        reason: SlashReason,
        evidence_root: &str,
        committee_root: &str,
        penalty_id: Option<String>,
        slash_bps: u64,
        locked_amount_micro_units: u128,
        filed_at_height: u64,
        appeal_window_blocks: u64,
    ) -> Self {
        let appeal_deadline_height = filed_at_height.saturating_add(appeal_window_blocks);
        let slash_amount_micro_units = bps_amount(locked_amount_micro_units, slash_bps);
        let slash_entry_id = slashing_ledger_id(
            ticket_id,
            envelope_id,
            accused_commitment,
            reason,
            evidence_root,
            filed_at_height,
        );
        Self {
            slash_entry_id,
            ticket_id: ticket_id.to_string(),
            envelope_id: envelope_id.to_string(),
            accused_commitment: accused_commitment.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            committee_root: committee_root.to_string(),
            penalty_id,
            slash_bps,
            locked_amount_micro_units,
            slash_amount_micro_units,
            filed_at_height,
            appeal_deadline_height,
            status: SlashStatus::Filed,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("envelope_id", &self.envelope_id)?;
        require_non_empty("accused_commitment", &self.accused_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_root("committee_root", &self.committee_root)?;
        require_bps("slash_bps", self.slash_bps)?;
        if self.slash_bps > config.max_slash_bps {
            return Err("slash entry exceeds configured slash cap".to_string());
        }
        require_height_window(
            "slash appeal",
            self.filed_at_height,
            self.appeal_deadline_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slash_entry_id": self.slash_entry_id,
            "ticket_id": self.ticket_id,
            "envelope_id": self.envelope_id,
            "accused_commitment": self.accused_commitment,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "committee_root": self.committee_root,
            "penalty_id": self.penalty_id,
            "slash_bps": self.slash_bps,
            "locked_amount_micro_units": self.locked_amount_micro_units.to_string(),
            "slash_amount_micro_units": self.slash_amount_micro_units.to_string(),
            "filed_at_height": self.filed_at_height,
            "appeal_deadline_height": self.appeal_deadline_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-SLASH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealLedgerEntry {
    pub appeal_entry_id: String,
    pub slash_entry_id: String,
    pub ticket_id: String,
    pub appellant_commitment: String,
    pub appeal_root: String,
    pub rebuttal_disclosure_root: String,
    pub bond_commitment_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: AppealStatus,
}

impl AppealLedgerEntry {
    pub fn new(
        slash_entry_id: &str,
        ticket_id: &str,
        appellant_commitment: &str,
        appeal_root: &str,
        rebuttal_disclosure_root: &str,
        bond_commitment_root: &str,
        opened_at_height: u64,
        appeal_window_blocks: u64,
    ) -> Self {
        let expires_at_height = opened_at_height.saturating_add(appeal_window_blocks);
        let appeal_entry_id = appeal_ledger_id(
            slash_entry_id,
            ticket_id,
            appellant_commitment,
            appeal_root,
            opened_at_height,
        );
        Self {
            appeal_entry_id,
            slash_entry_id: slash_entry_id.to_string(),
            ticket_id: ticket_id.to_string(),
            appellant_commitment: appellant_commitment.to_string(),
            appeal_root: appeal_root.to_string(),
            rebuttal_disclosure_root: rebuttal_disclosure_root.to_string(),
            bond_commitment_root: bond_commitment_root.to_string(),
            opened_at_height,
            expires_at_height,
            status: AppealStatus::Open,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("slash_entry_id", &self.slash_entry_id)?;
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("appellant_commitment", &self.appellant_commitment)?;
        require_root("appeal_root", &self.appeal_root)?;
        require_root("rebuttal_disclosure_root", &self.rebuttal_disclosure_root)?;
        require_root("bond_commitment_root", &self.bond_commitment_root)?;
        require_height_window("appeal", self.opened_at_height, self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-APPEAL",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementLedgerEntry {
    pub settlement_entry_id: String,
    pub ticket_id: String,
    pub slash_entry_id: Option<String>,
    pub appeal_entry_id: Option<String>,
    pub kind: SettlementKind,
    pub settlement_root: String,
    pub payout_root: String,
    pub corrected_state_root: String,
    pub fee_receipt_root: String,
    pub finalized_at_height: u64,
    pub delay_until_height: u64,
    pub status: SettlementStatus,
}

impl SettlementLedgerEntry {
    pub fn new(
        ticket_id: &str,
        slash_entry_id: Option<String>,
        appeal_entry_id: Option<String>,
        kind: SettlementKind,
        settlement_root: &str,
        payout_root: &str,
        corrected_state_root: &str,
        fee_receipt_root: &str,
        finalized_at_height: u64,
        settlement_delay_blocks: u64,
    ) -> Self {
        let delay_until_height = finalized_at_height.saturating_add(settlement_delay_blocks);
        let settlement_entry_id = settlement_ledger_id(
            ticket_id,
            slash_entry_id.as_deref().unwrap_or(""),
            kind,
            settlement_root,
            finalized_at_height,
        );
        Self {
            settlement_entry_id,
            ticket_id: ticket_id.to_string(),
            slash_entry_id,
            appeal_entry_id,
            kind,
            settlement_root: settlement_root.to_string(),
            payout_root: payout_root.to_string(),
            corrected_state_root: corrected_state_root.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            finalized_at_height,
            delay_until_height,
            status: SettlementStatus::Draft,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_root("payout_root", &self.payout_root)?;
        require_root("corrected_state_root", &self.corrected_state_root)?;
        require_root("fee_receipt_root", &self.fee_receipt_root)?;
        require_height_window(
            "settlement delay",
            self.finalized_at_height,
            self.delay_until_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-SETTLEMENT",
            &self.public_record(),
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
    pub policy_root: String,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
    pub status: FenceStatus,
}

impl PrivacyFence {
    pub fn new(
        kind: FenceKind,
        subject_id: &str,
        commitment_root: &str,
        nullifier_root: &str,
        policy_root: &str,
        inserted_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let expires_at_height = inserted_at_height.saturating_add(ttl_blocks);
        let fence_id = privacy_fence_id(
            kind,
            subject_id,
            commitment_root,
            nullifier_root,
            inserted_at_height,
        );
        Self {
            fence_id,
            kind,
            subject_id: subject_id.to_string(),
            commitment_root: commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            policy_root: policy_root.to_string(),
            inserted_at_height,
            expires_at_height,
            status: FenceStatus::Committed,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("commitment_root", &self.commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("policy_root", &self.policy_root)?;
        require_height_window(
            "privacy fence",
            self.inserted_at_height,
            self.expires_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-FENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub evidence_envelopes: BTreeMap<String, WatchtowerEvidenceEnvelope>,
    pub committee_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub dispute_tickets: BTreeMap<String, ConfidentialExecutionDisputeTicket>,
    pub finality_windows: BTreeMap<String, ReorgFinalityWindow>,
    pub liquidity_penalties: BTreeMap<String, LiquidityBackstopPenalty>,
    pub disclosure_roots: BTreeMap<String, PrivateSelectiveDisclosureRoot>,
    pub fee_routes: BTreeMap<String, FeeAwareDisputeRoute>,
    pub slashing_ledger: BTreeMap<String, SlashingLedgerEntry>,
    pub appeal_ledger: BTreeMap<String, AppealLedgerEntry>,
    pub settlement_ledger: BTreeMap<String, SettlementLedgerEntry>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifier_index: BTreeSet<String>,
    pub attestations_by_envelope: BTreeMap<String, BTreeSet<String>>,
    pub attestations_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub tickets_by_envelope: BTreeMap<String, BTreeSet<String>>,
    pub routes_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub slashes_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub appeals_by_slash: BTreeMap<String, BTreeSet<String>>,
    pub settlements_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::empty();
        Self {
            config,
            counters,
            height: DEVNET_HEIGHT,
            evidence_envelopes: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            dispute_tickets: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            liquidity_penalties: BTreeMap::new(),
            disclosure_roots: BTreeMap::new(),
            fee_routes: BTreeMap::new(),
            slashing_ledger: BTreeMap::new(),
            appeal_ledger: BTreeMap::new(),
            settlement_ledger: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            attestations_by_envelope: BTreeMap::new(),
            attestations_by_ticket: BTreeMap::new(),
            tickets_by_envelope: BTreeMap::new(),
            routes_by_ticket: BTreeMap::new(),
            slashes_by_ticket: BTreeMap::new(),
            appeals_by_slash: BTreeMap::new(),
            settlements_by_ticket: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn with_config(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self::devnet();
        state.config = config;
        state.height = height;
        Ok(state)
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.refresh_time_windows();
        Ok(())
    }

    pub fn insert_evidence_envelope(&mut self, envelope: WatchtowerEvidenceEnvelope) -> Result<()> {
        require_capacity(
            "evidence envelopes",
            self.evidence_envelopes.len(),
            self.config.max_evidence_envelopes,
        )?;
        envelope.validate(&self.config)?;
        if self.evidence_envelopes.contains_key(&envelope.envelope_id) {
            return Err("duplicate evidence envelope".to_string());
        }
        self.insert_nullifier(&envelope.nullifier_root)?;
        self.record_event(
            "evidence_envelope",
            &envelope.envelope_id,
            &envelope.root(),
            envelope.l2_anchor_height,
        )?;
        self.counters.evidence_envelopes = self.counters.evidence_envelopes.saturating_add(1);
        self.evidence_envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        Ok(())
    }

    pub fn open_evidence_envelope(
        &mut self,
        kind: EvidenceKind,
        watcher_commitment: &str,
        subject_id: &str,
        execution_root: &str,
        ciphertext_root: &str,
        witness_commitment_root: &str,
        nullifier_root: &str,
        monero_anchor_height: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        let envelope = WatchtowerEvidenceEnvelope::new(
            kind,
            watcher_commitment,
            subject_id,
            execution_root,
            ciphertext_root,
            witness_commitment_root,
            nullifier_root,
            monero_anchor_height,
            self.height,
            privacy_set_size,
        );
        let envelope_id = envelope.envelope_id.clone();
        self.insert_evidence_envelope(envelope)?;
        Ok(envelope_id)
    }

    pub fn insert_committee_attestation(
        &mut self,
        mut attestation: PqCommitteeAttestation,
    ) -> Result<()> {
        require_capacity(
            "committee attestations",
            self.committee_attestations.len(),
            self.config.max_committee_attestations,
        )?;
        attestation.validate(&self.config)?;
        if !self
            .evidence_envelopes
            .contains_key(&attestation.envelope_id)
        {
            return Err("unknown evidence envelope for committee attestation".to_string());
        }
        if let Some(ticket_id) = &attestation.ticket_id {
            if !self.dispute_tickets.contains_key(ticket_id) {
                return Err("unknown dispute ticket for committee attestation".to_string());
            }
        }
        attestation.status = AttestationStatus::Accepted;
        let attestation_root = attestation.root();
        self.record_event(
            "committee_attestation",
            &attestation.attestation_id,
            &attestation_root,
            attestation.attested_at_height,
        )?;
        self.attestations_by_envelope
            .entry(attestation.envelope_id.clone())
            .or_default()
            .insert(attestation.attestation_id.clone());
        if let Some(ticket_id) = &attestation.ticket_id {
            self.attestations_by_ticket
                .entry(ticket_id.clone())
                .or_default()
                .insert(attestation.attestation_id.clone());
        }
        self.counters.committee_attestations =
            self.counters.committee_attestations.saturating_add(1);
        let envelope_id = attestation.envelope_id.clone();
        let ticket_id = attestation.ticket_id.clone();
        self.committee_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_quorum_for_envelope(&envelope_id);
        if let Some(ticket_id) = ticket_id {
            self.refresh_quorum_for_ticket(&ticket_id);
        }
        Ok(())
    }

    pub fn open_dispute_ticket(
        &mut self,
        kind: TicketKind,
        envelope_id: &str,
        claimant_commitment: &str,
        accused_commitment: &str,
        disputed_execution_root: &str,
        expected_execution_root: &str,
        private_input_root: &str,
        private_output_root: &str,
        token_delta_root: &str,
        fee_commitment_root: &str,
        ticket_nullifier_root: &str,
    ) -> Result<String> {
        require_capacity(
            "dispute tickets",
            self.dispute_tickets.len(),
            self.config.max_dispute_tickets,
        )?;
        if !self.evidence_envelopes.contains_key(envelope_id) {
            return Err("unknown evidence envelope for dispute ticket".to_string());
        }
        let ticket = ConfidentialExecutionDisputeTicket::new(
            kind,
            envelope_id,
            claimant_commitment,
            accused_commitment,
            disputed_execution_root,
            expected_execution_root,
            private_input_root,
            private_output_root,
            token_delta_root,
            fee_commitment_root,
            ticket_nullifier_root,
            self.height,
            self.config.dispute_window_blocks,
        );
        ticket.validate()?;
        self.insert_nullifier(&ticket.ticket_nullifier_root)?;
        let ticket_id = ticket.ticket_id.clone();
        self.record_event("dispute_ticket", &ticket_id, &ticket.root(), self.height)?;
        self.tickets_by_envelope
            .entry(envelope_id.to_string())
            .or_default()
            .insert(ticket_id.clone());
        self.counters.dispute_tickets = self.counters.dispute_tickets.saturating_add(1);
        self.dispute_tickets.insert(ticket_id.clone(), ticket);
        if let Some(envelope) = self.evidence_envelopes.get_mut(envelope_id) {
            envelope.status = EvidenceStatus::Ticketed;
        }
        Ok(ticket_id)
    }

    pub fn insert_finality_window(&mut self, window: ReorgFinalityWindow) -> Result<()> {
        require_capacity(
            "finality windows",
            self.finality_windows.len(),
            self.config.max_finality_windows,
        )?;
        window.validate()?;
        if !self.evidence_envelopes.contains_key(&window.envelope_id) {
            return Err("unknown evidence envelope for finality window".to_string());
        }
        self.record_event(
            "finality_window",
            &window.window_id,
            &window.root(),
            self.height,
        )?;
        self.counters.finality_windows = self.counters.finality_windows.saturating_add(1);
        self.finality_windows
            .insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn create_finality_window(
        &mut self,
        envelope_id: &str,
        anchor_block_root: &str,
        parent_chain_root: &str,
        reorg_evidence_root: &str,
        risk_score_bps: u64,
    ) -> Result<String> {
        let envelope = self
            .evidence_envelopes
            .get(envelope_id)
            .ok_or_else(|| "unknown evidence envelope for finality window".to_string())?;
        let window = ReorgFinalityWindow::new(
            envelope_id,
            &envelope.subject_id,
            envelope.monero_anchor_height,
            self.height,
            anchor_block_root,
            parent_chain_root,
            reorg_evidence_root,
            risk_score_bps,
            &self.config,
        );
        let window_id = window.window_id.clone();
        self.insert_finality_window(window)?;
        Ok(window_id)
    }

    pub fn insert_liquidity_penalty(&mut self, penalty: LiquidityBackstopPenalty) -> Result<()> {
        require_capacity(
            "liquidity penalties",
            self.liquidity_penalties.len(),
            self.config.max_liquidity_penalties,
        )?;
        penalty.validate(&self.config)?;
        if !self.dispute_tickets.contains_key(&penalty.ticket_id) {
            return Err("unknown dispute ticket for liquidity penalty".to_string());
        }
        self.record_event(
            "liquidity_penalty",
            &penalty.penalty_id,
            &penalty.root(),
            self.height,
        )?;
        self.counters.total_locked_penalty_micro_units = self
            .counters
            .total_locked_penalty_micro_units
            .saturating_add(penalty.locked_amount_micro_units);
        self.counters.liquidity_penalties = self.counters.liquidity_penalties.saturating_add(1);
        self.liquidity_penalties
            .insert(penalty.penalty_id.clone(), penalty);
        Ok(())
    }

    pub fn commit_selective_disclosure(
        &mut self,
        envelope_id: &str,
        ticket_id: &str,
        disclosure_root: &str,
        policy_root: &str,
        viewer_set_root: &str,
        redaction_root: &str,
        nullifier_root: &str,
    ) -> Result<String> {
        require_capacity(
            "disclosure roots",
            self.disclosure_roots.len(),
            self.config.max_disclosure_roots,
        )?;
        if !self.evidence_envelopes.contains_key(envelope_id) {
            return Err("unknown evidence envelope for selective disclosure".to_string());
        }
        if !self.dispute_tickets.contains_key(ticket_id) {
            return Err("unknown dispute ticket for selective disclosure".to_string());
        }
        let disclosure = PrivateSelectiveDisclosureRoot::new(
            envelope_id,
            ticket_id,
            disclosure_root,
            policy_root,
            viewer_set_root,
            redaction_root,
            nullifier_root,
            self.height,
            self.height.saturating_add(self.config.appeal_window_blocks),
        );
        disclosure.validate()?;
        self.insert_nullifier(&disclosure.nullifier_root)?;
        let disclosure_id = disclosure.disclosure_id.clone();
        self.record_event(
            "selective_disclosure",
            &disclosure_id,
            &disclosure.root(),
            self.height,
        )?;
        self.counters.disclosure_roots = self.counters.disclosure_roots.saturating_add(1);
        self.disclosure_roots
            .insert(disclosure_id.clone(), disclosure);
        if let Some(envelope) = self.evidence_envelopes.get_mut(envelope_id) {
            envelope.disclosed_root = Some(disclosure_root.to_string());
            envelope.status = EvidenceStatus::Disclosed;
        }
        Ok(disclosure_id)
    }

    pub fn select_fee_route(
        &mut self,
        ticket_id: &str,
        lane: RouteLane,
        quoted_fee_micro_units: u64,
        max_fee_micro_units: u64,
        relayer_commitment: &str,
        sponsor_commitment: Option<String>,
        route_commitment_root: &str,
    ) -> Result<String> {
        require_capacity(
            "fee routes",
            self.fee_routes.len(),
            self.config.max_fee_routes,
        )?;
        if !self.dispute_tickets.contains_key(ticket_id) {
            return Err("unknown dispute ticket for fee route".to_string());
        }
        let route = FeeAwareDisputeRoute::new(
            ticket_id,
            lane,
            &self.config.fee_asset_id,
            quoted_fee_micro_units,
            max_fee_micro_units,
            relayer_commitment,
            sponsor_commitment,
            route_commitment_root,
            self.height,
            self.config.dispute_window_blocks,
        );
        route.validate(&self.config)?;
        let route_id = route.route_id.clone();
        self.record_event("fee_route", &route_id, &route.root(), self.height)?;
        self.routes_by_ticket
            .entry(ticket_id.to_string())
            .or_default()
            .insert(route_id.clone());
        self.counters.total_route_fee_micro_units = self
            .counters
            .total_route_fee_micro_units
            .saturating_add(quoted_fee_micro_units as u128);
        self.counters.fee_routes = self.counters.fee_routes.saturating_add(1);
        self.fee_routes.insert(route_id.clone(), route);
        if let Some(ticket) = self.dispute_tickets.get_mut(ticket_id) {
            ticket.route_id = Some(route_id.clone());
            ticket.status = TicketStatus::Routed;
        }
        Ok(route_id)
    }

    pub fn file_slashing_entry(
        &mut self,
        ticket_id: &str,
        reason: SlashReason,
        penalty_id: Option<String>,
        slash_bps: u64,
        locked_amount_micro_units: u128,
    ) -> Result<String> {
        require_capacity(
            "slashing ledger",
            self.slashing_ledger.len(),
            self.config.max_slashing_ledger_entries,
        )?;
        let ticket = self
            .dispute_tickets
            .get(ticket_id)
            .ok_or_else(|| "unknown dispute ticket for slashing entry".to_string())?;
        if let Some(penalty_id) = &penalty_id {
            if !self.liquidity_penalties.contains_key(penalty_id) {
                return Err("unknown liquidity penalty for slashing entry".to_string());
            }
        }
        self.require_quorum_for_ticket(ticket_id)?;
        let evidence_root = self
            .evidence_envelopes
            .get(&ticket.envelope_id)
            .map(WatchtowerEvidenceEnvelope::root)
            .ok_or_else(|| "missing evidence envelope for ticket".to_string())?;
        let committee_root = self.committee_root_for_ticket(ticket_id);
        let slash = SlashingLedgerEntry::new(
            ticket_id,
            &ticket.envelope_id,
            &ticket.accused_commitment,
            reason,
            &evidence_root,
            &committee_root,
            penalty_id,
            slash_bps,
            locked_amount_micro_units,
            self.height,
            self.config.appeal_window_blocks,
        );
        slash.validate(&self.config)?;
        let slash_entry_id = slash.slash_entry_id.clone();
        self.record_event(
            "slashing_entry",
            &slash_entry_id,
            &slash.root(),
            self.height,
        )?;
        self.slashes_by_ticket
            .entry(ticket_id.to_string())
            .or_default()
            .insert(slash_entry_id.clone());
        self.counters.slashing_entries = self.counters.slashing_entries.saturating_add(1);
        self.slashing_ledger.insert(slash_entry_id.clone(), slash);
        if let Some(ticket) = self.dispute_tickets.get_mut(ticket_id) {
            ticket.slash_entry_id = Some(slash_entry_id.clone());
            ticket.status = TicketStatus::SlashingPending;
        }
        Ok(slash_entry_id)
    }

    pub fn open_appeal(
        &mut self,
        slash_entry_id: &str,
        appellant_commitment: &str,
        appeal_root: &str,
        rebuttal_disclosure_root: &str,
        bond_commitment_root: &str,
    ) -> Result<String> {
        require_capacity(
            "appeal ledger",
            self.appeal_ledger.len(),
            self.config.max_appeal_ledger_entries,
        )?;
        let slash = self
            .slashing_ledger
            .get(slash_entry_id)
            .ok_or_else(|| "unknown slashing entry for appeal".to_string())?;
        if self.height > slash.appeal_deadline_height {
            return Err("appeal window expired".to_string());
        }
        let appeal = AppealLedgerEntry::new(
            slash_entry_id,
            &slash.ticket_id,
            appellant_commitment,
            appeal_root,
            rebuttal_disclosure_root,
            bond_commitment_root,
            self.height,
            self.config.appeal_window_blocks,
        );
        appeal.validate()?;
        let appeal_entry_id = appeal.appeal_entry_id.clone();
        self.record_event(
            "appeal_entry",
            &appeal_entry_id,
            &appeal.root(),
            self.height,
        )?;
        self.appeals_by_slash
            .entry(slash_entry_id.to_string())
            .or_default()
            .insert(appeal_entry_id.clone());
        self.counters.appeal_entries = self.counters.appeal_entries.saturating_add(1);
        self.appeal_ledger.insert(appeal_entry_id.clone(), appeal);
        if let Some(slash) = self.slashing_ledger.get_mut(slash_entry_id) {
            slash.status = SlashStatus::AppealOpen;
        }
        Ok(appeal_entry_id)
    }

    pub fn settle_ticket(
        &mut self,
        ticket_id: &str,
        kind: SettlementKind,
        settlement_root: &str,
        payout_root: &str,
        corrected_state_root: &str,
        fee_receipt_root: &str,
    ) -> Result<String> {
        require_capacity(
            "settlement ledger",
            self.settlement_ledger.len(),
            self.config.max_settlement_ledger_entries,
        )?;
        let ticket = self
            .dispute_tickets
            .get(ticket_id)
            .ok_or_else(|| "unknown dispute ticket for settlement".to_string())?;
        self.require_quorum_for_ticket(ticket_id)?;
        let settlement = SettlementLedgerEntry::new(
            ticket_id,
            ticket.slash_entry_id.clone(),
            ticket.appeal_entry_id.clone(),
            kind,
            settlement_root,
            payout_root,
            corrected_state_root,
            fee_receipt_root,
            self.height,
            self.config.settlement_delay_blocks,
        );
        settlement.validate()?;
        let settlement_entry_id = settlement.settlement_entry_id.clone();
        self.record_event(
            "settlement_entry",
            &settlement_entry_id,
            &settlement.root(),
            self.height,
        )?;
        self.settlements_by_ticket
            .entry(ticket_id.to_string())
            .or_default()
            .insert(settlement_entry_id.clone());
        self.counters.settlement_entries = self.counters.settlement_entries.saturating_add(1);
        self.settlement_ledger
            .insert(settlement_entry_id.clone(), settlement);
        if let Some(ticket) = self.dispute_tickets.get_mut(ticket_id) {
            ticket.settlement_entry_id = Some(settlement_entry_id.clone());
            ticket.status = TicketStatus::Settled;
        }
        Ok(settlement_entry_id)
    }

    pub fn finalize_settlement(&mut self, settlement_entry_id: &str) -> Result<()> {
        {
            let settlement = self
                .settlement_ledger
                .get_mut(settlement_entry_id)
                .ok_or_else(|| "unknown settlement entry".to_string())?;
            if self.height < settlement.delay_until_height {
                return Err("settlement delay has not elapsed".to_string());
            }
            settlement.status = SettlementStatus::Finalized;
        }
        self.counters.finalized_settlements = self.counters.finalized_settlements.saturating_add(1);
        let subject_root = self.subject_root(settlement_entry_id);
        self.record_event(
            "settlement_finalized",
            settlement_entry_id,
            &subject_root,
            self.height,
        )
    }

    pub fn accept_slash(&mut self, slash_entry_id: &str) -> Result<()> {
        let slash_amount_micro_units = {
            let slash = self
                .slashing_ledger
                .get_mut(slash_entry_id)
                .ok_or_else(|| "unknown slashing entry".to_string())?;
            slash.status = SlashStatus::Accepted;
            slash.slash_amount_micro_units
        };
        self.counters.accepted_disputes = self.counters.accepted_disputes.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(slash_amount_micro_units);
        let subject_root = self.subject_root(slash_entry_id);
        self.record_event("slash_accepted", slash_entry_id, &subject_root, self.height)
    }

    pub fn reject_slash(&mut self, slash_entry_id: &str) -> Result<()> {
        let locked_amount_micro_units = {
            let slash = self
                .slashing_ledger
                .get_mut(slash_entry_id)
                .ok_or_else(|| "unknown slashing entry".to_string())?;
            slash.status = SlashStatus::Rejected;
            slash.locked_amount_micro_units
        };
        self.counters.rejected_disputes = self.counters.rejected_disputes.saturating_add(1);
        self.counters.total_released_micro_units = self
            .counters
            .total_released_micro_units
            .saturating_add(locked_amount_micro_units);
        let subject_root = self.subject_root(slash_entry_id);
        self.record_event("slash_rejected", slash_entry_id, &subject_root, self.height)
    }

    pub fn insert_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        require_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        fence.validate()?;
        self.insert_nullifier(&fence.nullifier_root)?;
        self.record_event(
            "privacy_fence",
            &fence.fence_id,
            &fence.root(),
            fence.inserted_at_height,
        )?;
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            evidence_envelope_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-EVIDENCE",
                self.evidence_envelopes
                    .values()
                    .map(WatchtowerEvidenceEnvelope::public_record),
            ),
            committee_attestation_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-COMMITTEE",
                self.committee_attestations
                    .values()
                    .map(PqCommitteeAttestation::public_record),
            ),
            dispute_ticket_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-TICKET",
                self.dispute_tickets
                    .values()
                    .map(ConfidentialExecutionDisputeTicket::public_record),
            ),
            finality_window_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-FINALITY",
                self.finality_windows
                    .values()
                    .map(ReorgFinalityWindow::public_record),
            ),
            liquidity_penalty_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-PENALTY",
                self.liquidity_penalties
                    .values()
                    .map(LiquidityBackstopPenalty::public_record),
            ),
            disclosure_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-DISCLOSURE",
                self.disclosure_roots
                    .values()
                    .map(PrivateSelectiveDisclosureRoot::public_record),
            ),
            fee_route_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-ROUTE",
                self.fee_routes
                    .values()
                    .map(FeeAwareDisputeRoute::public_record),
            ),
            slashing_ledger_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-SLASH",
                self.slashing_ledger
                    .values()
                    .map(SlashingLedgerEntry::public_record),
            ),
            appeal_ledger_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-APPEAL",
                self.appeal_ledger
                    .values()
                    .map(AppealLedgerEntry::public_record),
            ),
            settlement_ledger_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-SETTLEMENT",
                self.settlement_ledger
                    .values()
                    .map(SettlementLedgerEntry::public_record),
            ),
            privacy_fence_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-FENCE",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            nullifier_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-NULLIFIER",
                self.nullifier_index
                    .iter()
                    .map(|nullifier| json!({ "nullifier_root": nullifier })),
            ),
            event_root: collection_root(
                "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE-EVENT",
                self.events.values().map(RuntimeEvent::public_record),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "evidence_envelope_count": self.evidence_envelopes.len(),
            "committee_attestation_count": self.committee_attestations.len(),
            "dispute_ticket_count": self.dispute_tickets.len(),
            "finality_window_count": self.finality_windows.len(),
            "liquidity_penalty_count": self.liquidity_penalties.len(),
            "disclosure_root_count": self.disclosure_roots.len(),
            "fee_route_count": self.fee_routes.len(),
            "slashing_ledger_count": self.slashing_ledger.len(),
            "appeal_ledger_count": self.appeal_ledger.len(),
            "settlement_ledger_count": self.settlement_ledger.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "nullifier_count": self.nullifier_index.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn public_state(&self) -> Value {
        self.public_record()
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn refresh_time_windows(&mut self) {
        for window in self.finality_windows.values_mut() {
            if self.height >= window.l2_finality_height {
                window.status = FinalityWindowStatus::Finalized;
            } else if window.risk_score_bps > 0 {
                window.status = FinalityWindowStatus::ReorgRisk;
            }
        }
        for ticket in self.dispute_tickets.values_mut() {
            if self.height > ticket.expires_at_height && ticket.status != TicketStatus::Settled {
                ticket.status = TicketStatus::Rejected;
            }
        }
        for disclosure in self.disclosure_roots.values_mut() {
            if self.height >= disclosure.available_from_height
                && disclosure.status == DisclosureStatus::Committed
            {
                disclosure.status = DisclosureStatus::Open;
            }
            if self.height > disclosure.expires_at_height {
                disclosure.status = DisclosureStatus::Expired;
            }
        }
    }

    fn insert_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        if self.nullifier_index.contains(nullifier_root) {
            return Err("duplicate privacy nullifier".to_string());
        }
        self.nullifier_index.insert(nullifier_root.to_string());
        Ok(())
    }

    fn require_quorum_for_ticket(&self, ticket_id: &str) -> Result<()> {
        let ids = self
            .attestations_by_ticket
            .get(ticket_id)
            .ok_or_else(|| "missing committee attestations for ticket".to_string())?;
        let mut signers = BTreeSet::new();
        let mut weight = 0_u64;
        for attestation_id in ids {
            if let Some(attestation) = self.committee_attestations.get(attestation_id) {
                signers.insert(attestation.signer_commitment.clone());
                weight = weight.saturating_add(attestation.weight);
            }
        }
        if signers.len() < self.config.min_committee_signers as usize {
            return Err("committee signer count below configured minimum".to_string());
        }
        if weight < self.config.min_committee_weight {
            return Err("committee weight below configured minimum".to_string());
        }
        Ok(())
    }

    fn refresh_quorum_for_envelope(&mut self, envelope_id: &str) {
        let root = self.committee_root_for_envelope(envelope_id);
        if let Some(envelope) = self.evidence_envelopes.get_mut(envelope_id) {
            envelope.quorum_root = root;
            let ids = self
                .attestations_by_envelope
                .get(envelope_id)
                .map(BTreeSet::len)
                .unwrap_or(0);
            if ids >= self.config.min_committee_signers as usize {
                envelope.status = EvidenceStatus::Attested;
            }
        }
    }

    fn refresh_quorum_for_ticket(&mut self, ticket_id: &str) {
        if self.require_quorum_for_ticket(ticket_id).is_ok() {
            if let Some(ticket) = self.dispute_tickets.get_mut(ticket_id) {
                if ticket.status == TicketStatus::Opened
                    || ticket.status == TicketStatus::PrivacyChecked
                {
                    ticket.status = TicketStatus::Admissible;
                }
            }
        }
    }

    fn committee_root_for_envelope(&self, envelope_id: &str) -> String {
        let records = self
            .committee_attestations
            .values()
            .filter(|attestation| attestation.envelope_id == envelope_id)
            .map(PqCommitteeAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-EXECUTION-DISPUTE-COMMITTEE-ENVELOPE",
            &records,
        )
    }

    fn committee_root_for_ticket(&self, ticket_id: &str) -> String {
        let records = self
            .committee_attestations
            .values()
            .filter(|attestation| attestation.ticket_id.as_deref() == Some(ticket_id))
            .map(PqCommitteeAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-EXECUTION-DISPUTE-COMMITTEE-TICKET", &records)
    }

    fn subject_root(&self, subject_id: &str) -> String {
        if let Some(value) = self.evidence_envelopes.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.committee_attestations.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.dispute_tickets.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.finality_windows.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.liquidity_penalties.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.disclosure_roots.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.fee_routes.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.slashing_ledger.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.appeal_ledger.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.settlement_ledger.get(subject_id) {
            return value.root();
        }
        if let Some(value) = self.privacy_fences.get(subject_id) {
            return value.root();
        }
        string_root("MONERO-L2-PQ-EXECUTION-DISPUTE-UNKNOWN-SUBJECT", subject_id)
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
    ) -> Result<()> {
        require_capacity("events", self.events.len(), self.config.max_events)?;
        let sequence = self.counters.events.saturating_add(1);
        let event_id = runtime_event_id(event_kind, subject_id, subject_root, height, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
        };
        self.counters.events = sequence;
        self.events.insert(event_id, event);
        Ok(())
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn evidence_payload_root(
    kind: EvidenceKind,
    subject_id: &str,
    execution_root: &str,
    ciphertext_root: &str,
    witness_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-EVIDENCE-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(execution_root),
            HashPart::Str(ciphertext_root),
            HashPart::Str(witness_commitment_root),
        ],
        32,
    )
}

pub fn evidence_envelope_id(
    kind: EvidenceKind,
    watcher_commitment: &str,
    subject_id: &str,
    sealed_payload_root: &str,
    nullifier_root: &str,
    l2_anchor_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(watcher_commitment),
            HashPart::Str(subject_id),
            HashPart::Str(sealed_payload_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(l2_anchor_height),
        ],
        32,
    )
}

pub fn pq_committee_attestation_id(
    kind: AttestationKind,
    envelope_id: &str,
    ticket_id: &str,
    signer_commitment: &str,
    statement_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(envelope_id),
            HashPart::Str(ticket_id),
            HashPart::Str(signer_commitment),
            HashPart::Str(statement_root),
            HashPart::U64(attested_at_height),
        ],
        32,
    )
}

pub fn dispute_ticket_id(
    kind: TicketKind,
    envelope_id: &str,
    claimant_commitment: &str,
    accused_commitment: &str,
    ticket_nullifier_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(envelope_id),
            HashPart::Str(claimant_commitment),
            HashPart::Str(accused_commitment),
            HashPart::Str(ticket_nullifier_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn finality_window_id(
    envelope_id: &str,
    subject_id: &str,
    monero_observed_height: u64,
    anchor_block_root: &str,
    l2_start_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-FINALITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(subject_id),
            HashPart::U64(monero_observed_height),
            HashPart::Str(anchor_block_root),
            HashPart::U64(l2_start_height),
        ],
        32,
    )
}

pub fn liquidity_penalty_id(
    ticket_id: &str,
    provider_commitment: &str,
    backstop_pool_id: &str,
    reason: SlashReason,
    bond_commitment_root: &str,
    proposed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-LIQUIDITY-PENALTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(provider_commitment),
            HashPart::Str(backstop_pool_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(bond_commitment_root),
            HashPart::U64(proposed_at_height),
        ],
        32,
    )
}

pub fn selective_disclosure_id(
    envelope_id: &str,
    ticket_id: &str,
    disclosure_root: &str,
    nullifier_root: &str,
    available_from_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(ticket_id),
            HashPart::Str(disclosure_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(available_from_height),
        ],
        32,
    )
}

pub fn fee_route_id(
    ticket_id: &str,
    lane: RouteLane,
    relayer_commitment: &str,
    route_commitment_root: &str,
    selected_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-FEE-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(relayer_commitment),
            HashPart::Str(route_commitment_root),
            HashPart::U64(selected_at_height),
        ],
        32,
    )
}

pub fn slashing_ledger_id(
    ticket_id: &str,
    envelope_id: &str,
    accused_commitment: &str,
    reason: SlashReason,
    evidence_root: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(envelope_id),
            HashPart::Str(accused_commitment),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn appeal_ledger_id(
    slash_entry_id: &str,
    ticket_id: &str,
    appellant_commitment: &str,
    appeal_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-APPEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(slash_entry_id),
            HashPart::Str(ticket_id),
            HashPart::Str(appellant_commitment),
            HashPart::Str(appeal_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn settlement_ledger_id(
    ticket_id: &str,
    slash_entry_id: &str,
    kind: SettlementKind,
    settlement_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(slash_entry_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(settlement_root),
            HashPart::U64(finalized_at_height),
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
        "MONERO-L2-PQ-EXECUTION-DISPUTE-FENCE-ID",
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

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
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

pub fn payload_root(domain: &str, record: &Value) -> String {
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-EXECUTION-DISPUTE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn commitment(label: &str) -> String {
    string_root("MONERO-L2-PQ-EXECUTION-DISPUTE-COMMITMENT", label)
}

pub fn disclosure_set_root(disclosures: &BTreeSet<String>) -> String {
    let leaves = disclosures
        .iter()
        .map(|disclosure| json!({ "disclosure": disclosure }))
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-EXECUTION-DISPUTE-DISCLOSURE-SET", &leaves)
}

pub fn route_quote_root(routes: &BTreeMap<String, u64>) -> String {
    let leaves = routes
        .iter()
        .map(|(route_id, fee)| json!({ "route_id": route_id, "fee_micro_units": fee }))
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-EXECUTION-DISPUTE-ROUTE-QUOTE", &leaves)
}

pub fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
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
