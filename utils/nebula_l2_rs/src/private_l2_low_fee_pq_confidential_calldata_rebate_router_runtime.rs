use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialCalldataRebateRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialCalldataRebateRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_REBATE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-calldata-rebate-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_REBATE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_SPONSOR_ATTESTATION_SUITE: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-confidential-calldata-sponsor-v1";
pub const CONFIDENTIAL_CALLDATA_SUITE: &str =
    "monero-private-l2-confidential-calldata-rebate-envelope-v1";
pub const REBATE_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-calldata-rebate-settlement-receipt-v1";
pub const COMPRESSION_HINT_SUITE: &str = "private-l2-calldata-compression-routing-hint-v1";
pub const REDACTION_BUDGET_SUITE: &str = "privacy-redaction-budget-confidential-rebate-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_210_000;
pub const DEVNET_EPOCH: u64 = 44_448;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "piconero-calldata-rebate-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 4_200;
pub const DEFAULT_MIN_SPONSOR_LIQUIDITY_MICROS: u64 = 25_000_000;
pub const DEFAULT_MIN_COHORT_CALLS: u64 = 32;
pub const DEFAULT_TARGET_COHORT_CALLS: u64 = 512;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 256;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_ROUTES: usize = 262_144;
pub const DEFAULT_MAX_SPONSORS: usize = 65_536;
pub const DEFAULT_MAX_COHORTS: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_COMPRESSION_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINES: usize = 262_144;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_DEVNET_FIXTURES: usize = 4_096;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 4_194_304;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:ROOTS";
const D_ROUTES: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:ROUTES";
const D_SPONSORS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:SPONSORS";
const D_COHORTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:COHORTS";
const D_ATTESTATIONS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:ATTESTATIONS";
const D_RECEIPTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:RECEIPTS";
const D_HINTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:HINTS";
const D_QUARANTINE: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:QUARANTINE";
const D_REDACTION: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:REDACTION";
const D_FIXTURES: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:FIXTURES";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:EVENTS";
const D_PUBLIC: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-ROUTER:PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataRouteKind {
    MoneroShieldedPayment,
    PrivateSwap,
    ConfidentialContractCall,
    BridgeExit,
    BridgeDeposit,
    PaymasterSponsoredCall,
    BatchSettlement,
    WalletSync,
    OraclePacket,
    EmergencyCancel,
}

impl CalldataRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroShieldedPayment => "monero_shielded_payment",
            Self::PrivateSwap => "private_swap",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::BridgeDeposit => "bridge_deposit",
            Self::PaymasterSponsoredCall => "paymaster_sponsored_call",
            Self::BatchSettlement => "batch_settlement",
            Self::WalletSync => "wallet_sync",
            Self::OraclePacket => "oracle_packet",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::BridgeExit => 9_700,
            Self::BridgeDeposit => 9_500,
            Self::ConfidentialContractCall => 9_200,
            Self::PrivateSwap => 9_000,
            Self::MoneroShieldedPayment => 8_800,
            Self::PaymasterSponsoredCall => 8_600,
            Self::BatchSettlement => 8_200,
            Self::OraclePacket => 7_400,
            Self::WalletSync => 6_900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Draft,
    Open,
    Congested,
    SponsorLimited,
    Draining,
    Paused,
    Expired,
    Retired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Congested => "congested",
            Self::SponsorLimited => "sponsor_limited",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Draft | Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pending,
    Active,
    Throttled,
    Quarantined,
    Exhausted,
    Retired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    WalletPayment,
    DexSwap,
    NftTransfer,
    DefiIntent,
    BridgeFlow,
    ContractBatch,
    DustConsolidation,
    ComplianceSafeView,
    DevnetDemo,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletPayment => "wallet_payment",
            Self::DexSwap => "dex_swap",
            Self::NftTransfer => "nft_transfer",
            Self::DefiIntent => "defi_intent",
            Self::BridgeFlow => "bridge_flow",
            Self::ContractBatch => "contract_batch",
            Self::DustConsolidation => "dust_consolidation",
            Self::ComplianceSafeView => "compliance_safe_view",
            Self::DevnetDemo => "devnet_demo",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Collecting,
    Eligible,
    Routed,
    Receipted,
    Settled,
    Expired,
    Quarantined,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Eligible => "eligible",
            Self::Routed => "routed",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    None,
    Brotli,
    Zstd,
    Rle,
    Dictionary,
    MoneroRingDelta,
    CallSelectorPack,
}

impl CompressionCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Brotli => "brotli",
            Self::Zstd => "zstd",
            Self::Rle => "rle",
            Self::Dictionary => "dictionary",
            Self::MoneroRingDelta => "monero_ring_delta",
            Self::CallSelectorPack => "call_selector_pack",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    SponsorLocked,
    ProofVerified,
    Rebated,
    Settled,
    Challenged,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SponsorLocked => "sponsor_locked",
            Self::ProofVerified => "proof_verified",
            Self::Rebated => "rebated",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    SponsorOverspend,
    DuplicateNullifier,
    ExpiredWindow,
    PqAttestationMismatch,
    RedactionBudgetExceeded,
    CompressionFraud,
    RouteCapExceeded,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorOverspend => "sponsor_overspend",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::ExpiredWindow => "expired_window",
            Self::PqAttestationMismatch => "pq_attestation_mismatch",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::CompressionFraud => "compression_fraud",
            Self::RouteCapExceeded => "route_cap_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_sponsor_attestation_suite: String,
    pub confidential_calldata_suite: String,
    pub rebate_settlement_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_sponsor_liquidity_micros: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_cohort_calls: u64,
    pub target_cohort_calls: u64,
    pub route_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub max_routes: usize,
    pub max_sponsors: usize,
    pub max_cohorts: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
    pub max_compression_hints: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_devnet_fixtures: usize,
    pub max_public_events: usize,
    pub enable_demo_routes: bool,
    pub enable_overspend_quarantine: bool,
    pub enable_public_safe_summaries: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_sponsor_attestation_suite: PQ_SPONSOR_ATTESTATION_SUITE.to_string(),
            confidential_calldata_suite: CONFIDENTIAL_CALLDATA_SUITE.to_string(),
            rebate_settlement_suite: REBATE_SETTLEMENT_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_sponsor_liquidity_micros: DEFAULT_MIN_SPONSOR_LIQUIDITY_MICROS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_cohort_calls: DEFAULT_MIN_COHORT_CALLS,
            target_cohort_calls: DEFAULT_TARGET_COHORT_CALLS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_routes: DEFAULT_MAX_ROUTES,
            max_sponsors: DEFAULT_MAX_SPONSORS,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_compression_hints: DEFAULT_MAX_COMPRESSION_HINTS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_devnet_fixtures: DEFAULT_MAX_DEVNET_FIXTURES,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
            enable_demo_routes: true,
            enable_overspend_quarantine: true,
            enable_public_safe_summaries: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub routes_registered: u64,
    pub routes_open: u64,
    pub sponsors_registered: u64,
    pub sponsors_active: u64,
    pub sponsor_liquidity_micros: u64,
    pub sponsor_locked_micros: u64,
    pub cohorts_registered: u64,
    pub cohorts_eligible: u64,
    pub calls_routed: u64,
    pub calldata_bytes_original: u64,
    pub calldata_bytes_compressed: u64,
    pub attestations_verified: u64,
    pub settlement_receipts: u64,
    pub rebate_micros_settled: u64,
    pub compression_hints: u64,
    pub expiry_windows_open: u64,
    pub overspend_quarantines: u64,
    pub redaction_budgets: u64,
    pub redaction_units_reserved: u64,
    pub public_events: u64,
    pub devnet_fixtures: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub route_root: String,
    pub sponsor_root: String,
    pub cohort_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub compression_hint_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub fixture_root: String,
    pub public_event_root: String,
    pub deterministic_route_commitment_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryWindow {
    pub opens_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub grace_blocks: u64,
    pub quarantine_after_l2_height: u64,
}

impl ExpiryWindow {
    pub fn new(open_height: u64, ttl_blocks: u64, grace_blocks: u64) -> Self {
        let closes_at_l2_height = open_height.saturating_add(ttl_blocks);
        Self {
            opens_at_l2_height: open_height,
            closes_at_l2_height,
            grace_blocks,
            quarantine_after_l2_height: closes_at_l2_height.saturating_add(grace_blocks),
        }
    }

    pub fn is_open(&self, l2_height: u64) -> bool {
        l2_height >= self.opens_at_l2_height && l2_height <= self.closes_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalldataRebateRoute {
    pub route_id: String,
    pub route_kind: CalldataRouteKind,
    pub status: RouteStatus,
    pub sponsor_id: String,
    pub cohort_kind: CohortKind,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub base_fee_cap_micros: u64,
    pub max_calldata_bytes: u64,
    pub max_calls_per_window: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub priority_weight: u64,
    pub privacy_set_floor: u64,
    pub deterministic_route_commitment: String,
    pub compression_hint_ids: BTreeSet<String>,
    pub eligible_cohort_ids: BTreeSet<String>,
    pub expiry_window: ExpiryWindow,
}

impl CalldataRebateRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "status": self.status.as_str(),
            "sponsor_id": self.sponsor_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "base_fee_cap_micros": self.base_fee_cap_micros,
            "max_calldata_bytes": self.max_calldata_bytes,
            "max_calls_per_window": self.max_calls_per_window,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "priority_weight": self.priority_weight,
            "privacy_set_floor": self.privacy_set_floor,
            "deterministic_route_commitment": self.deterministic_route_commitment,
            "compression_hint_ids": self.compression_hint_ids,
            "eligible_cohort_ids": self.eligible_cohort_ids,
            "expiry_window": self.expiry_window.public_record(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("CALLDATA-REBATE-ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorLiquidity {
    pub sponsor_id: String,
    pub sponsor_label: String,
    pub status: SponsorStatus,
    pub route_ids: BTreeSet<String>,
    pub available_liquidity_micros: u64,
    pub locked_liquidity_micros: u64,
    pub settled_rebate_micros: u64,
    pub overspend_limit_micros: u64,
    pub fee_asset_id: String,
    pub refund_address_commitment: String,
    pub pq_verification_key_commitment: String,
    pub privacy_pool_commitment: String,
    pub last_attestation_id: Option<String>,
    pub expiry_window: ExpiryWindow,
}

impl SponsorLiquidity {
    pub fn total_liquidity_micros(&self) -> u64 {
        self.available_liquidity_micros
            .saturating_add(self.locked_liquidity_micros)
            .saturating_add(self.settled_rebate_micros)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_label": self.sponsor_label,
            "status": self.status.as_str(),
            "route_ids": self.route_ids,
            "available_liquidity_micros": self.available_liquidity_micros,
            "locked_liquidity_micros": self.locked_liquidity_micros,
            "settled_rebate_micros": self.settled_rebate_micros,
            "overspend_limit_micros": self.overspend_limit_micros,
            "fee_asset_id": self.fee_asset_id,
            "refund_address_commitment": self.refund_address_commitment,
            "pq_verification_key_commitment": self.pq_verification_key_commitment,
            "privacy_pool_commitment": self.privacy_pool_commitment,
            "last_attestation_id": self.last_attestation_id,
            "expiry_window": self.expiry_window.public_record(),
            "total_liquidity_micros": self.total_liquidity_micros(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("SPONSOR-LIQUIDITY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EligibleCallCohort {
    pub cohort_id: String,
    pub cohort_kind: CohortKind,
    pub status: CohortStatus,
    pub route_id: String,
    pub sponsor_id: String,
    pub call_count: u64,
    pub distinct_wallet_commitments: u64,
    pub privacy_set_size: u64,
    pub original_calldata_bytes: u64,
    pub compressed_calldata_bytes: u64,
    pub fee_paid_micros: u64,
    pub expected_rebate_micros: u64,
    pub nullifier_root: String,
    pub call_commitment_root: String,
    pub redacted_metadata_root: String,
    pub compression_hint_id: Option<String>,
    pub expiry_window: ExpiryWindow,
}

impl EligibleCallCohort {
    pub fn compression_savings_bps(&self) -> u64 {
        if self.original_calldata_bytes == 0 {
            0
        } else {
            let saved = self
                .original_calldata_bytes
                .saturating_sub(self.compressed_calldata_bytes);
            saved.saturating_mul(MAX_BPS) / self.original_calldata_bytes
        }
    }

    pub fn eligible(&self, config: &Config) -> bool {
        self.call_count >= config.min_cohort_calls
            && self.privacy_set_size >= config.min_privacy_set_size
            && matches!(
                self.status,
                CohortStatus::Eligible | CohortStatus::Routed | CohortStatus::Receipted
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "status": self.status.as_str(),
            "route_id": self.route_id,
            "sponsor_id": self.sponsor_id,
            "call_count": self.call_count,
            "distinct_wallet_commitments": self.distinct_wallet_commitments,
            "privacy_set_size": self.privacy_set_size,
            "original_calldata_bytes": self.original_calldata_bytes,
            "compressed_calldata_bytes": self.compressed_calldata_bytes,
            "compression_savings_bps": self.compression_savings_bps(),
            "fee_paid_micros": self.fee_paid_micros,
            "expected_rebate_micros": self.expected_rebate_micros,
            "nullifier_root": self.nullifier_root,
            "call_commitment_root": self.call_commitment_root,
            "redacted_metadata_root": self.redacted_metadata_root,
            "compression_hint_id": self.compression_hint_id,
            "expiry_window": self.expiry_window.public_record(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("ELIGIBLE-CALL-COHORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub sponsor_id: String,
    pub route_id: String,
    pub cohort_id: Option<String>,
    pub suite: String,
    pub pq_security_bits: u16,
    pub verifying_key_commitment: String,
    pub sponsor_liquidity_root: String,
    pub route_commitment: String,
    pub signed_payload_root: String,
    pub signature_commitment: String,
    pub attested_rebate_cap_micros: u64,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub verified: bool,
}

impl PqSponsorAttestation {
    pub fn live(&self, l2_height: u64) -> bool {
        self.verified && l2_height <= self.expires_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sponsor_id": self.sponsor_id,
            "route_id": self.route_id,
            "cohort_id": self.cohort_id,
            "suite": self.suite,
            "pq_security_bits": self.pq_security_bits,
            "verifying_key_commitment": self.verifying_key_commitment,
            "sponsor_liquidity_root": self.sponsor_liquidity_root,
            "route_commitment": self.route_commitment,
            "signed_payload_root": self.signed_payload_root,
            "signature_commitment": self.signature_commitment,
            "attested_rebate_cap_micros": self.attested_rebate_cap_micros,
            "attested_at_l2_height": self.attested_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "verified": self.verified,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PQ-SPONSOR-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlementReceipt {
    pub receipt_id: String,
    pub settlement_status: SettlementStatus,
    pub route_id: String,
    pub sponsor_id: String,
    pub cohort_id: String,
    pub attestation_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub fee_paid_micros: u64,
    pub rebate_due_micros: u64,
    pub rebate_paid_micros: u64,
    pub sponsor_locked_micros: u64,
    pub settlement_l2_height: u64,
    pub monero_anchor_height: u64,
    pub settlement_nullifier_root: String,
    pub settlement_receipt_root: String,
    pub redacted_public_summary_root: String,
    pub expiry_window: ExpiryWindow,
}

impl RebateSettlementReceipt {
    pub fn unpaid_rebate_micros(&self) -> u64 {
        self.rebate_due_micros
            .saturating_sub(self.rebate_paid_micros)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_status": self.settlement_status.as_str(),
            "route_id": self.route_id,
            "sponsor_id": self.sponsor_id,
            "cohort_id": self.cohort_id,
            "attestation_id": self.attestation_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "fee_paid_micros": self.fee_paid_micros,
            "rebate_due_micros": self.rebate_due_micros,
            "rebate_paid_micros": self.rebate_paid_micros,
            "unpaid_rebate_micros": self.unpaid_rebate_micros(),
            "sponsor_locked_micros": self.sponsor_locked_micros,
            "settlement_l2_height": self.settlement_l2_height,
            "monero_anchor_height": self.monero_anchor_height,
            "settlement_nullifier_root": self.settlement_nullifier_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "redacted_public_summary_root": self.redacted_public_summary_root,
            "expiry_window": self.expiry_window.public_record(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("REBATE-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionHint {
    pub hint_id: String,
    pub route_id: String,
    pub cohort_id: Option<String>,
    pub codec: CompressionCodec,
    pub dictionary_commitment: Option<String>,
    pub original_bytes_estimate: u64,
    pub compressed_bytes_estimate: u64,
    pub min_savings_bps: u64,
    pub hint_payload_root: String,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl CompressionHint {
    pub fn estimated_savings_bps(&self) -> u64 {
        if self.original_bytes_estimate == 0 {
            0
        } else {
            let saved = self
                .original_bytes_estimate
                .saturating_sub(self.compressed_bytes_estimate);
            saved.saturating_mul(MAX_BPS) / self.original_bytes_estimate
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "route_id": self.route_id,
            "cohort_id": self.cohort_id,
            "codec": self.codec.as_str(),
            "dictionary_commitment": self.dictionary_commitment,
            "original_bytes_estimate": self.original_bytes_estimate,
            "compressed_bytes_estimate": self.compressed_bytes_estimate,
            "estimated_savings_bps": self.estimated_savings_bps(),
            "min_savings_bps": self.min_savings_bps,
            "hint_payload_root": self.hint_payload_root,
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(COMPRESSION_HINT_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OverspendQuarantine {
    pub quarantine_id: String,
    pub reason: QuarantineReason,
    pub sponsor_id: String,
    pub route_id: Option<String>,
    pub cohort_id: Option<String>,
    pub receipt_id: Option<String>,
    pub claimed_spend_micros: u64,
    pub authorized_spend_micros: u64,
    pub overspend_micros: u64,
    pub evidence_root: String,
    pub opened_at_l2_height: u64,
    pub releases_at_l2_height: u64,
    pub public_safe_note: String,
}

impl OverspendQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "reason": self.reason.as_str(),
            "sponsor_id": self.sponsor_id,
            "route_id": self.route_id,
            "cohort_id": self.cohort_id,
            "receipt_id": self.receipt_id,
            "claimed_spend_micros": self.claimed_spend_micros,
            "authorized_spend_micros": self.authorized_spend_micros,
            "overspend_micros": self.overspend_micros,
            "evidence_root": self.evidence_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "releases_at_l2_height": self.releases_at_l2_height,
            "public_safe_note": self.public_safe_note,
        })
    }

    pub fn root(&self) -> String {
        payload_root("OVERSPEND-QUARANTINE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub route_id: String,
    pub cohort_id: Option<String>,
    pub sponsor_id: String,
    pub window_start_l2_height: u64,
    pub window_end_l2_height: u64,
    pub k_anonymity_floor: u64,
    pub max_public_fields: u64,
    pub reserved_redaction_units: u64,
    pub consumed_redaction_units: u64,
    pub redacted_field_labels: BTreeSet<String>,
    pub budget_commitment: String,
}

impl PrivacyRedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.reserved_redaction_units
            .saturating_sub(self.consumed_redaction_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "route_id": self.route_id,
            "cohort_id": self.cohort_id,
            "sponsor_id": self.sponsor_id,
            "window_start_l2_height": self.window_start_l2_height,
            "window_end_l2_height": self.window_end_l2_height,
            "k_anonymity_floor": self.k_anonymity_floor,
            "max_public_fields": self.max_public_fields,
            "reserved_redaction_units": self.reserved_redaction_units,
            "consumed_redaction_units": self.consumed_redaction_units,
            "remaining_units": self.remaining_units(),
            "redacted_field_labels": self.redacted_field_labels,
            "budget_commitment": self.budget_commitment,
        })
    }

    pub fn root(&self) -> String {
        payload_root(REDACTION_BUDGET_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub route_ids: BTreeSet<String>,
    pub sponsor_ids: BTreeSet<String>,
    pub cohort_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub fixture_root: String,
    pub created_at_l2_height: u64,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DEVNET-FIXTURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub l2_height: u64,
    pub payload_root: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PUBLIC-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub routes: BTreeMap<String, CalldataRebateRoute>,
    pub sponsors: BTreeMap<String, SponsorLiquidity>,
    pub cohorts: BTreeMap<String, EligibleCallCohort>,
    pub attestations: BTreeMap<String, PqSponsorAttestation>,
    pub settlement_receipts: BTreeMap<String, RebateSettlementReceipt>,
    pub compression_hints: BTreeMap<String, CompressionHint>,
    pub overspend_quarantines: BTreeMap<String, OverspendQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
    pub public_events: BTreeMap<String, PublicEvent>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height: DEVNET_HEIGHT,
            monero_height: DEVNET_HEIGHT.saturating_add(210_000),
            epoch: DEVNET_EPOCH,
            routes: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            compression_hints: BTreeMap::new(),
            overspend_quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
            public_events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.install_devnet_fixture();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let route_id = "route:demo:paymaster-batch".to_string();
        let sponsor_id = "sponsor:demo:wallet-growth".to_string();
        let cohort_id = "cohort:demo:wallet-payments:0002".to_string();
        let hint_id = "hint:demo:selector-pack:0002".to_string();
        let receipt_id = "receipt:demo:rebate:0002".to_string();
        let attestation_id = "attestation:demo:wallet-growth:0002".to_string();
        let budget_id = "redaction:demo:wallet-growth:0002".to_string();

        let hint = CompressionHint {
            hint_id: hint_id.clone(),
            route_id: route_id.clone(),
            cohort_id: Some(cohort_id.clone()),
            codec: CompressionCodec::CallSelectorPack,
            dictionary_commitment: Some(commitment("demo-selector-dictionary-v2")),
            original_bytes_estimate: 196_608,
            compressed_bytes_estimate: 61_440,
            min_savings_bps: 5_800,
            hint_payload_root: payload_root("DEMO-HINT-PAYLOAD", &json!({"hint": hint_id})),
            created_at_l2_height: state.l2_height,
            expires_at_l2_height: state
                .l2_height
                .saturating_add(state.config.route_ttl_blocks),
        };
        state.add_compression_hint(hint).ok();

        let route = CalldataRebateRoute {
            route_id: route_id.clone(),
            route_kind: CalldataRouteKind::PaymasterSponsoredCall,
            status: RouteStatus::Open,
            sponsor_id: sponsor_id.clone(),
            cohort_kind: CohortKind::WalletPayment,
            lane_id: "lane:low-fee:paymaster".to_string(),
            fee_asset_id: state.config.fee_asset_id.clone(),
            rebate_asset_id: state.config.rebate_asset_id.clone(),
            base_fee_cap_micros: 14,
            max_calldata_bytes: 524_288,
            max_calls_per_window: 1_024,
            target_rebate_bps: 2_100,
            max_rebate_bps: 3_600,
            priority_weight: CalldataRouteKind::PaymasterSponsoredCall.default_priority(),
            privacy_set_floor: state.config.min_privacy_set_size,
            deterministic_route_commitment: deterministic_route_commitment(
                &route_id,
                &sponsor_id,
                "paymaster-wallet-batch",
            ),
            compression_hint_ids: BTreeSet::from([hint_id.clone()]),
            eligible_cohort_ids: BTreeSet::from([cohort_id.clone()]),
            expiry_window: ExpiryWindow::new(state.l2_height, state.config.route_ttl_blocks, 12),
        };
        state.register_route(route).ok();

        let sponsor = SponsorLiquidity {
            sponsor_id: sponsor_id.clone(),
            sponsor_label: "demo wallet growth sponsor".to_string(),
            status: SponsorStatus::Active,
            route_ids: BTreeSet::from([route_id.clone()]),
            available_liquidity_micros: 95_000_000,
            locked_liquidity_micros: 1_250_000,
            settled_rebate_micros: 420_000,
            overspend_limit_micros: 2_000_000,
            fee_asset_id: state.config.fee_asset_id.clone(),
            refund_address_commitment: commitment("demo-refund-wallet-growth"),
            pq_verification_key_commitment: commitment("demo-pq-vk-wallet-growth"),
            privacy_pool_commitment: commitment("demo-privacy-pool-wallet-growth"),
            last_attestation_id: Some(attestation_id.clone()),
            expiry_window: ExpiryWindow::new(
                state.l2_height,
                state.config.attestation_ttl_blocks,
                8,
            ),
        };
        state.register_sponsor(sponsor).ok();

        let cohort = EligibleCallCohort {
            cohort_id: cohort_id.clone(),
            cohort_kind: CohortKind::WalletPayment,
            status: CohortStatus::Receipted,
            route_id: route_id.clone(),
            sponsor_id: sponsor_id.clone(),
            call_count: 768,
            distinct_wallet_commitments: 731,
            privacy_set_size: 1_572_864,
            original_calldata_bytes: 196_608,
            compressed_calldata_bytes: 61_440,
            fee_paid_micros: 5_376,
            expected_rebate_micros: 1_129,
            nullifier_root: sample_merkle("demo-wallet-nullifier", 16),
            call_commitment_root: sample_merkle("demo-wallet-call", 24),
            redacted_metadata_root: sample_merkle("demo-wallet-redacted", 8),
            compression_hint_id: Some(hint_id),
            expiry_window: ExpiryWindow::new(state.l2_height, state.config.receipt_ttl_blocks, 24),
        };
        state.register_cohort(cohort).ok();

        let attestation = PqSponsorAttestation {
            attestation_id: attestation_id.clone(),
            sponsor_id: sponsor_id.clone(),
            route_id: route_id.clone(),
            cohort_id: Some(cohort_id.clone()),
            suite: PQ_SPONSOR_ATTESTATION_SUITE.to_string(),
            pq_security_bits: state.config.min_pq_security_bits,
            verifying_key_commitment: commitment("demo-pq-vk-wallet-growth"),
            sponsor_liquidity_root: state
                .sponsors
                .get(&sponsor_id)
                .map(SponsorLiquidity::root)
                .unwrap_or_else(|| empty_root("missing-sponsor")),
            route_commitment: state
                .routes
                .get(&route_id)
                .map(CalldataRebateRoute::root)
                .unwrap_or_else(|| empty_root("missing-route")),
            signed_payload_root: payload_root(
                "DEMO-SPONSOR-ATTESTATION-PAYLOAD",
                &json!({"sponsor_id": sponsor_id, "route_id": route_id, "cohort_id": cohort_id}),
            ),
            signature_commitment: commitment("demo-ml-dsa-signature-wallet-growth"),
            attested_rebate_cap_micros: 1_500_000,
            attested_at_l2_height: state.l2_height,
            expires_at_l2_height: state
                .l2_height
                .saturating_add(state.config.attestation_ttl_blocks),
            verified: true,
        };
        state.record_attestation(attestation).ok();

        let receipt = RebateSettlementReceipt {
            receipt_id: receipt_id.clone(),
            settlement_status: SettlementStatus::Settled,
            route_id: route_id.clone(),
            sponsor_id: sponsor_id.clone(),
            cohort_id: cohort_id.clone(),
            attestation_id,
            fee_asset_id: state.config.fee_asset_id.clone(),
            rebate_asset_id: state.config.rebate_asset_id.clone(),
            fee_paid_micros: 5_376,
            rebate_due_micros: 1_129,
            rebate_paid_micros: 1_129,
            sponsor_locked_micros: 1_250_000,
            settlement_l2_height: state.l2_height.saturating_add(2),
            monero_anchor_height: state.monero_height,
            settlement_nullifier_root: sample_merkle("demo-settlement-nullifier", 12),
            settlement_receipt_root: sample_merkle("demo-settlement-receipt", 12),
            redacted_public_summary_root: sample_merkle("demo-public-summary", 6),
            expiry_window: ExpiryWindow::new(state.l2_height, state.config.receipt_ttl_blocks, 24),
        };
        state.record_settlement_receipt(receipt).ok();

        let budget = PrivacyRedactionBudget {
            budget_id,
            route_id,
            cohort_id: Some(cohort_id),
            sponsor_id,
            window_start_l2_height: state.l2_height,
            window_end_l2_height: state
                .l2_height
                .saturating_add(state.config.redaction_window_blocks),
            k_anonymity_floor: state.config.min_privacy_set_size,
            max_public_fields: 5,
            reserved_redaction_units: 8_192,
            consumed_redaction_units: 1_536,
            redacted_field_labels: BTreeSet::from([
                "wallet_commitment".to_string(),
                "call_selector".to_string(),
                "refund_address".to_string(),
            ]),
            budget_commitment: commitment("demo-redaction-budget-wallet-growth"),
        };
        state.reserve_redaction_budget(budget).ok();
        state.refresh_roots();
        state
    }

    pub fn register_route(&mut self, route: CalldataRebateRoute) -> Result<()> {
        ensure_capacity(self.routes.len(), self.config.max_routes, "routes")?;
        ensure_bps(route.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(route.max_rebate_bps, "max_rebate_bps")?;
        if route.max_rebate_bps < route.target_rebate_bps {
            return Err("max_rebate_bps must be >= target_rebate_bps".to_string());
        }
        self.push_event("route_registered", &route.route_id, &route.public_record())?;
        self.routes.insert(route.route_id.clone(), route);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_sponsor(&mut self, sponsor: SponsorLiquidity) -> Result<()> {
        ensure_capacity(self.sponsors.len(), self.config.max_sponsors, "sponsors")?;
        if sponsor.available_liquidity_micros < self.config.min_sponsor_liquidity_micros {
            return Err("sponsor liquidity below configured floor".to_string());
        }
        self.push_event(
            "sponsor_liquidity_registered",
            &sponsor.sponsor_id,
            &sponsor.public_record(),
        )?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_cohort(&mut self, cohort: EligibleCallCohort) -> Result<()> {
        ensure_capacity(self.cohorts.len(), self.config.max_cohorts, "cohorts")?;
        if cohort.call_count < self.config.min_cohort_calls {
            return Err("cohort call count below eligibility floor".to_string());
        }
        if cohort.privacy_set_size < self.config.min_privacy_set_size {
            return Err("cohort privacy set below eligibility floor".to_string());
        }
        self.push_event(
            "cohort_registered",
            &cohort.cohort_id,
            &cohort.public_record(),
        )?;
        self.cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_attestation(&mut self, attestation: PqSponsorAttestation) -> Result<()> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ sponsor attestation below security floor".to_string());
        }
        if !attestation.verified {
            return Err("PQ sponsor attestation must be verified".to_string());
        }
        self.push_event(
            "pq_sponsor_attestation_verified",
            &attestation.attestation_id,
            &attestation.public_record(),
        )?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_settlement_receipt(&mut self, receipt: RebateSettlementReceipt) -> Result<()> {
        ensure_capacity(
            self.settlement_receipts.len(),
            self.config.max_receipts,
            "settlement_receipts",
        )?;
        if receipt.rebate_paid_micros > receipt.sponsor_locked_micros {
            self.open_quarantine(
                QuarantineReason::SponsorOverspend,
                &receipt.sponsor_id,
                Some(receipt.route_id.clone()),
                Some(receipt.cohort_id.clone()),
                Some(receipt.receipt_id.clone()),
                receipt.rebate_paid_micros,
                receipt.sponsor_locked_micros,
            )?;
        }
        self.push_event(
            "rebate_settlement_receipt_recorded",
            &receipt.receipt_id,
            &receipt.public_record(),
        )?;
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_compression_hint(&mut self, hint: CompressionHint) -> Result<()> {
        ensure_capacity(
            self.compression_hints.len(),
            self.config.max_compression_hints,
            "compression_hints",
        )?;
        if hint.estimated_savings_bps() < hint.min_savings_bps {
            return Err("compression hint below minimum savings".to_string());
        }
        self.push_event(
            "compression_hint_added",
            &hint.hint_id,
            &hint.public_record(),
        )?;
        self.compression_hints.insert(hint.hint_id.clone(), hint);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction_budgets",
        )?;
        if budget.consumed_redaction_units > budget.reserved_redaction_units {
            self.open_quarantine(
                QuarantineReason::RedactionBudgetExceeded,
                &budget.sponsor_id,
                Some(budget.route_id.clone()),
                budget.cohort_id.clone(),
                None,
                budget.consumed_redaction_units,
                budget.reserved_redaction_units,
            )?;
        }
        self.push_event(
            "privacy_redaction_budget_reserved",
            &budget.budget_id,
            &budget.public_record(),
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_quarantine(
        &mut self,
        reason: QuarantineReason,
        sponsor_id: &str,
        route_id: Option<String>,
        cohort_id: Option<String>,
        receipt_id: Option<String>,
        claimed_spend_micros: u64,
        authorized_spend_micros: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.overspend_quarantines.len(),
            self.config.max_quarantines,
            "overspend_quarantines",
        )?;
        let quarantine_id = deterministic_id(
            "quarantine",
            &[
                sponsor_id,
                reason.as_str(),
                route_id.as_deref().unwrap_or("none"),
                cohort_id.as_deref().unwrap_or("none"),
                receipt_id.as_deref().unwrap_or("none"),
            ],
        );
        let quarantine = OverspendQuarantine {
            quarantine_id: quarantine_id.clone(),
            reason,
            sponsor_id: sponsor_id.to_string(),
            route_id,
            cohort_id,
            receipt_id,
            claimed_spend_micros,
            authorized_spend_micros,
            overspend_micros: claimed_spend_micros.saturating_sub(authorized_spend_micros),
            evidence_root: payload_root(
                "QUARANTINE-EVIDENCE",
                &json!({
                    "sponsor_id": sponsor_id,
                    "claimed_spend_micros": claimed_spend_micros,
                    "authorized_spend_micros": authorized_spend_micros,
                }),
            ),
            opened_at_l2_height: self.l2_height,
            releases_at_l2_height: self
                .l2_height
                .saturating_add(self.config.quarantine_ttl_blocks),
            public_safe_note: "sponsor spend claim exceeded authorized envelope".to_string(),
        };
        self.push_event(
            "overspend_quarantine_opened",
            &quarantine_id,
            &quarantine.public_record(),
        )?;
        self.overspend_quarantines
            .insert(quarantine_id.clone(), quarantine);
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.computed_roots_without_state();
        let mut record = self.public_record_without_state_root(&roots);
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        let roots = self.computed_roots_without_state();
        state_root_from_record(&self.public_record_without_state_root(&roots))
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.computed_counters();
        self.roots = self.computed_roots_without_state();
        self.roots.state_root = self.state_root();
    }

    fn computed_counters(&self) -> Counters {
        Counters {
            routes_registered: self.routes.len() as u64,
            routes_open: self
                .routes
                .values()
                .filter(|route| route.status.accepts_calls())
                .count() as u64,
            sponsors_registered: self.sponsors.len() as u64,
            sponsors_active: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.can_sponsor())
                .count() as u64,
            sponsor_liquidity_micros: self
                .sponsors
                .values()
                .map(SponsorLiquidity::total_liquidity_micros)
                .sum(),
            sponsor_locked_micros: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.locked_liquidity_micros)
                .sum(),
            cohorts_registered: self.cohorts.len() as u64,
            cohorts_eligible: self
                .cohorts
                .values()
                .filter(|cohort| cohort.eligible(&self.config))
                .count() as u64,
            calls_routed: self.cohorts.values().map(|cohort| cohort.call_count).sum(),
            calldata_bytes_original: self
                .cohorts
                .values()
                .map(|cohort| cohort.original_calldata_bytes)
                .sum(),
            calldata_bytes_compressed: self
                .cohorts
                .values()
                .map(|cohort| cohort.compressed_calldata_bytes)
                .sum(),
            attestations_verified: self
                .attestations
                .values()
                .filter(|attestation| attestation.verified)
                .count() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebate_micros_settled: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.rebate_paid_micros)
                .sum(),
            compression_hints: self.compression_hints.len() as u64,
            expiry_windows_open: self
                .routes
                .values()
                .filter(|route| route.expiry_window.is_open(self.l2_height))
                .count() as u64,
            overspend_quarantines: self.overspend_quarantines.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            redaction_units_reserved: self
                .redaction_budgets
                .values()
                .map(|budget| budget.reserved_redaction_units)
                .sum(),
            public_events: self.public_events.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        }
    }

    fn computed_roots_without_state(&self) -> Roots {
        let counters = self.computed_counters();
        Roots {
            config_root: self.config.root(),
            counters_root: counters.root(),
            route_root: map_root(D_ROUTES, &self.routes, CalldataRebateRoute::public_record),
            sponsor_root: map_root(D_SPONSORS, &self.sponsors, SponsorLiquidity::public_record),
            cohort_root: map_root(D_COHORTS, &self.cohorts, EligibleCallCohort::public_record),
            attestation_root: map_root(
                D_ATTESTATIONS,
                &self.attestations,
                PqSponsorAttestation::public_record,
            ),
            receipt_root: map_root(
                D_RECEIPTS,
                &self.settlement_receipts,
                RebateSettlementReceipt::public_record,
            ),
            compression_hint_root: map_root(
                D_HINTS,
                &self.compression_hints,
                CompressionHint::public_record,
            ),
            quarantine_root: map_root(
                D_QUARANTINE,
                &self.overspend_quarantines,
                OverspendQuarantine::public_record,
            ),
            redaction_budget_root: map_root(
                D_REDACTION,
                &self.redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            fixture_root: map_root(
                D_FIXTURES,
                &self.devnet_fixtures,
                DevnetFixture::public_record,
            ),
            public_event_root: map_root(D_EVENTS, &self.public_events, PublicEvent::public_record),
            deterministic_route_commitment_root: deterministic_route_root(&self.routes),
            state_root: String::new(),
        }
    }

    fn public_record_without_state_root(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.computed_counters().public_record(),
            "roots": roots.public_record(),
            "routes": self.routes.values().map(CalldataRebateRoute::public_record).collect::<Vec<_>>(),
            "sponsors": self.sponsors.values().map(SponsorLiquidity::public_record).collect::<Vec<_>>(),
            "eligible_call_cohorts": self.cohorts.values().map(EligibleCallCohort::public_record).collect::<Vec<_>>(),
            "pq_sponsor_attestations": self.attestations.values().map(PqSponsorAttestation::public_record).collect::<Vec<_>>(),
            "rebate_settlement_receipts": self.settlement_receipts.values().map(RebateSettlementReceipt::public_record).collect::<Vec<_>>(),
            "compression_hints": self.compression_hints.values().map(CompressionHint::public_record).collect::<Vec<_>>(),
            "overspend_quarantines": self.overspend_quarantines.values().map(OverspendQuarantine::public_record).collect::<Vec<_>>(),
            "privacy_redaction_budgets": self.redaction_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(DevnetFixture::public_record).collect::<Vec<_>>(),
            "public_events": self.public_events.values().map(PublicEvent::public_record).collect::<Vec<_>>(),
        })
    }

    fn install_devnet_fixture(&mut self) {
        let sponsor_id = "sponsor:devnet:monero-wallets".to_string();
        let route_id = "route:devnet:monero-shielded-payments".to_string();
        let cohort_id = "cohort:devnet:shielded-payments:0001".to_string();
        let hint_id = "hint:devnet:ring-delta:0001".to_string();
        let attestation_id = "attestation:devnet:monero-wallets:0001".to_string();
        let receipt_id = "receipt:devnet:rebate:0001".to_string();
        let budget_id = "redaction:devnet:monero-wallets:0001".to_string();

        let hint = CompressionHint {
            hint_id: hint_id.clone(),
            route_id: route_id.clone(),
            cohort_id: Some(cohort_id.clone()),
            codec: CompressionCodec::MoneroRingDelta,
            dictionary_commitment: Some(commitment("devnet-ring-delta-dictionary")),
            original_bytes_estimate: 131_072,
            compressed_bytes_estimate: 45_056,
            min_savings_bps: 5_000,
            hint_payload_root: payload_root("DEVNET-HINT-PAYLOAD", &json!({"hint": hint_id})),
            created_at_l2_height: self.l2_height,
            expires_at_l2_height: self.l2_height.saturating_add(self.config.route_ttl_blocks),
        };
        self.compression_hints.insert(hint_id.clone(), hint);

        let route = CalldataRebateRoute {
            route_id: route_id.clone(),
            route_kind: CalldataRouteKind::MoneroShieldedPayment,
            status: RouteStatus::Open,
            sponsor_id: sponsor_id.clone(),
            cohort_kind: CohortKind::WalletPayment,
            lane_id: "lane:low-fee:monero-payments".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            base_fee_cap_micros: 11,
            max_calldata_bytes: 262_144,
            max_calls_per_window: 768,
            target_rebate_bps: self.config.target_rebate_bps,
            max_rebate_bps: self.config.max_rebate_bps,
            priority_weight: CalldataRouteKind::MoneroShieldedPayment.default_priority(),
            privacy_set_floor: self.config.min_privacy_set_size,
            deterministic_route_commitment: deterministic_route_commitment(
                &route_id,
                &sponsor_id,
                "monero-shielded-payments",
            ),
            compression_hint_ids: BTreeSet::from([hint_id.clone()]),
            eligible_cohort_ids: BTreeSet::from([cohort_id.clone()]),
            expiry_window: ExpiryWindow::new(self.l2_height, self.config.route_ttl_blocks, 12),
        };
        self.routes.insert(route_id.clone(), route);

        let sponsor = SponsorLiquidity {
            sponsor_id: sponsor_id.clone(),
            sponsor_label: "devnet monero wallet fee sponsor".to_string(),
            status: SponsorStatus::Active,
            route_ids: BTreeSet::from([route_id.clone()]),
            available_liquidity_micros: 125_000_000,
            locked_liquidity_micros: 875_000,
            settled_rebate_micros: 96_000,
            overspend_limit_micros: 1_000_000,
            fee_asset_id: self.config.fee_asset_id.clone(),
            refund_address_commitment: commitment("devnet-monero-wallet-refund"),
            pq_verification_key_commitment: commitment("devnet-monero-wallet-pq-vk"),
            privacy_pool_commitment: commitment("devnet-monero-wallet-privacy-pool"),
            last_attestation_id: Some(attestation_id.clone()),
            expiry_window: ExpiryWindow::new(self.l2_height, self.config.attestation_ttl_blocks, 8),
        };
        self.sponsors.insert(sponsor_id.clone(), sponsor);

        let cohort = EligibleCallCohort {
            cohort_id: cohort_id.clone(),
            cohort_kind: CohortKind::WalletPayment,
            status: CohortStatus::Receipted,
            route_id: route_id.clone(),
            sponsor_id: sponsor_id.clone(),
            call_count: 512,
            distinct_wallet_commitments: 489,
            privacy_set_size: 1_048_576,
            original_calldata_bytes: 131_072,
            compressed_calldata_bytes: 45_056,
            fee_paid_micros: 5_632,
            expected_rebate_micros: 1_014,
            nullifier_root: sample_merkle("devnet-nullifier", 16),
            call_commitment_root: sample_merkle("devnet-call", 24),
            redacted_metadata_root: sample_merkle("devnet-redacted", 8),
            compression_hint_id: Some(hint_id),
            expiry_window: ExpiryWindow::new(self.l2_height, self.config.receipt_ttl_blocks, 24),
        };
        self.cohorts.insert(cohort_id.clone(), cohort);

        let route_root = self
            .routes
            .get(&route_id)
            .map(CalldataRebateRoute::root)
            .unwrap_or_else(|| empty_root("route"));
        let sponsor_root = self
            .sponsors
            .get(&sponsor_id)
            .map(SponsorLiquidity::root)
            .unwrap_or_else(|| empty_root("sponsor"));
        let attestation = PqSponsorAttestation {
            attestation_id: attestation_id.clone(),
            sponsor_id: sponsor_id.clone(),
            route_id: route_id.clone(),
            cohort_id: Some(cohort_id.clone()),
            suite: PQ_SPONSOR_ATTESTATION_SUITE.to_string(),
            pq_security_bits: self.config.min_pq_security_bits,
            verifying_key_commitment: commitment("devnet-monero-wallet-pq-vk"),
            sponsor_liquidity_root: sponsor_root,
            route_commitment: route_root,
            signed_payload_root: payload_root(
                "DEVNET-SPONSOR-ATTESTATION-PAYLOAD",
                &json!({"sponsor_id": sponsor_id, "route_id": route_id, "cohort_id": cohort_id}),
            ),
            signature_commitment: commitment("devnet-ml-dsa-signature-monero-wallet"),
            attested_rebate_cap_micros: 1_000_000,
            attested_at_l2_height: self.l2_height,
            expires_at_l2_height: self
                .l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
            verified: true,
        };
        self.attestations
            .insert(attestation_id.clone(), attestation);

        let receipt = RebateSettlementReceipt {
            receipt_id: receipt_id.clone(),
            settlement_status: SettlementStatus::Settled,
            route_id: route_id.clone(),
            sponsor_id: sponsor_id.clone(),
            cohort_id: cohort_id.clone(),
            attestation_id,
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            fee_paid_micros: 5_632,
            rebate_due_micros: 1_014,
            rebate_paid_micros: 1_014,
            sponsor_locked_micros: 875_000,
            settlement_l2_height: self.l2_height.saturating_add(1),
            monero_anchor_height: self.monero_height,
            settlement_nullifier_root: sample_merkle("devnet-settlement-nullifier", 12),
            settlement_receipt_root: sample_merkle("devnet-settlement-receipt", 12),
            redacted_public_summary_root: sample_merkle("devnet-public-summary", 6),
            expiry_window: ExpiryWindow::new(self.l2_height, self.config.receipt_ttl_blocks, 24),
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);

        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            route_id: route_id.clone(),
            cohort_id: Some(cohort_id.clone()),
            sponsor_id: sponsor_id.clone(),
            window_start_l2_height: self.l2_height,
            window_end_l2_height: self
                .l2_height
                .saturating_add(self.config.redaction_window_blocks),
            k_anonymity_floor: self.config.min_privacy_set_size,
            max_public_fields: 4,
            reserved_redaction_units: 4_096,
            consumed_redaction_units: 768,
            redacted_field_labels: BTreeSet::from([
                "wallet_commitment".to_string(),
                "ring_member_hint".to_string(),
                "refund_address".to_string(),
            ]),
            budget_commitment: commitment("devnet-redaction-budget-monero-wallets"),
        };
        self.redaction_budgets.insert(budget_id, budget);

        let fixture_id = "fixture:devnet:confidential-calldata-rebate-router".to_string();
        let fixture = DevnetFixture {
            fixture_id: fixture_id.clone(),
            label: "devnet low-fee confidential calldata rebate routing fixture".to_string(),
            route_ids: BTreeSet::from([route_id]),
            sponsor_ids: BTreeSet::from([sponsor_id]),
            cohort_ids: BTreeSet::from([cohort_id]),
            receipt_ids: BTreeSet::from([receipt_id]),
            fixture_root: payload_root("DEVNET-FIXTURE-PAYLOAD", &json!({"fixture": fixture_id})),
            created_at_l2_height: self.l2_height,
        };
        self.devnet_fixtures.insert(fixture_id.clone(), fixture);
        let fixture_record = self
            .devnet_fixtures
            .get(&fixture_id)
            .map(DevnetFixture::public_record)
            .unwrap_or_else(|| json!({}));
        self.public_events.insert(
            "event:devnet:fixture-installed".to_string(),
            PublicEvent {
                event_id: "event:devnet:fixture-installed".to_string(),
                event_kind: "devnet_fixture_installed".to_string(),
                subject_id: fixture_id,
                l2_height: self.l2_height,
                payload_root: payload_root("PUBLIC-EVENT-PAYLOAD", &fixture_record),
            },
        );
    }

    fn push_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value) -> Result<()> {
        ensure_capacity(
            self.public_events.len(),
            self.config.max_public_events,
            "public_events",
        )?;
        let event_id = deterministic_id(
            "event",
            &[
                event_kind,
                subject_id,
                &self.l2_height.to_string(),
                &self.public_events.len().to_string(),
            ],
        );
        self.public_events.insert(
            event_id.clone(),
            PublicEvent {
                event_id,
                event_kind: event_kind.to_string(),
                subject_id: subject_id.to_string(),
                l2_height: self.l2_height,
                payload_root: payload_root("PUBLIC-EVENT-PAYLOAD", payload),
            },
        );
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root(D_STATE, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn deterministic_route_root(routes: &BTreeMap<String, CalldataRebateRoute>) -> String {
    let leaves = routes
        .values()
        .map(|route| {
            json!({
                "route_id": route.route_id,
                "sponsor_id": route.sponsor_id,
                "deterministic_route_commitment": route.deterministic_route_commitment,
                "expiry_window": route.expiry_window.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("DETERMINISTIC-ROUTE-COMMITMENTS", &leaves)
}

fn deterministic_route_commitment(route_id: &str, sponsor_id: &str, salt: &str) -> String {
    payload_root(
        "DETERMINISTIC-CALLDATA-REBATE-ROUTE",
        &json!({
            "route_id": route_id,
            "sponsor_id": sponsor_id,
            "salt": salt,
            "protocol_version": PROTOCOL_VERSION,
        }),
    )
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    format!("{prefix}:{}", domain_hash(prefix, &hash_parts, 32))
}

fn commitment(label: &str) -> String {
    payload_root("CONFIDENTIAL-COMMITMENT", &json!({ "label": label }))
}

fn sample_merkle(prefix: &str, count: usize) -> String {
    let leaves = (0..count)
        .map(|index| json!({ "sample": prefix, "index": index }))
        .collect::<Vec<_>>();
    merkle_root(prefix, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}

fn payload_root(domain: &str, value: &Value) -> String {
    let parts = [
        HashPart::Str(domain),
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::Json(value),
    ];
    domain_hash(D_PUBLIC, &parts, 32)
}
