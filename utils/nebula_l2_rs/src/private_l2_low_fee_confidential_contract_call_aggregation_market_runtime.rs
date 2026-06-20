use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<T> =
    Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-confidential-contract-call-aggregation-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_HASH_SUITE:
    &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SEALED_CALL_SUITE: &str =
    "ml-kem-1024+x25519-hybrid-sealed-confidential-contract-call-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_QUOTE_SUITE:
    &str = "deterministic-low-fee-private-call-aggregation-quote-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_COMPRESSION_SUITE: &str =
    "calldata-proof-compression-reservation-market-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_PROOF_SUITE:
    &str = "recursive-stark-confidential-contract-call-aggregation-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SLASHING_SUITE: &str =
    "fee-gouging-invalid-aggregation-slasher-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEVNET_HEIGHT:
    u64 = 1_146_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS: u64 =
    10_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_LANES:
    usize = 128;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_CALLS:
    usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_QUOTES:
    usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_PRIVACY_SETS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_SLASHING_EVENTS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    262_144;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS: u64 =
    7;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    15;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    8;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    8_800;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 =
    10;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    8;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_CALL_TTL_BLOCKS: u64 =
    40;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 =
    96;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_CALLS: usize =
    16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationLaneKind {
    DefiSwap,
    Lending,
    Perpetuals,
    AccountAbstraction,
    TokenTransfer,
    BridgeRelay,
    SettlementHook,
    ContractAutomation,
    EmergencyEscape,
}

impl AggregationLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::AccountAbstraction => "account_abstraction",
            Self::TokenTransfer => "token_transfer",
            Self::BridgeRelay => "bridge_relay",
            Self::SettlementHook => "settlement_hook",
            Self::ContractAutomation => "contract_automation",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::SettlementHook => 9_700,
            Self::BridgeRelay => 9_400,
            Self::Perpetuals => 9_100,
            Self::DefiSwap => 8_900,
            Self::Lending => 8_500,
            Self::ContractAutomation => 8_100,
            Self::AccountAbstraction => 7_800,
            Self::TokenTransfer => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    SponsorOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::SponsorOnly => "sponsor_only",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::SponsorOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialCallKind {
    Invoke,
    MultiCall,
    Delegate,
    DefiSwap,
    LendingAction,
    MarginAction,
    TokenTransfer,
    BridgeAction,
    AutomationHook,
}

impl ConfidentialCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::MultiCall => "multi_call",
            Self::Delegate => "delegate",
            Self::DefiSwap => "defi_swap",
            Self::LendingAction => "lending_action",
            Self::MarginAction => "margin_action",
            Self::TokenTransfer => "token_transfer",
            Self::BridgeAction => "bridge_action",
            Self::AutomationHook => "automation_hook",
        }
    }

    pub fn complexity_units(self) -> u64 {
        match self {
            Self::AutomationHook => 52,
            Self::MultiCall => 48,
            Self::MarginAction => 42,
            Self::DefiSwap => 36,
            Self::LendingAction => 32,
            Self::BridgeAction => 30,
            Self::Delegate => 28,
            Self::Invoke => 24,
            Self::TokenTransfer => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Submitted,
    Quoted,
    Reserved,
    Aggregated,
    Settled,
    Rebated,
    Expired,
    Rejected,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Submitted | Self::Quoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregatorClass {
    SequencerOperated,
    CommunitySolver,
    FastEdgeCompressor,
    ProofMarketMaker,
    SponsorBacked,
    BridgeRelay,
}

impl AggregatorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOperated => "sequencer_operated",
            Self::CommunitySolver => "community_solver",
            Self::FastEdgeCompressor => "fast_edge_compressor",
            Self::ProofMarketMaker => "proof_market_maker",
            Self::SponsorBacked => "sponsor_backed",
            Self::BridgeRelay => "bridge_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Held,
    Bound,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Bound => "bound",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proving,
    SettlementReady,
    Settled,
    Disputed,
    Slashed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidAggregation,
    FeeGouging,
    MissingReservation,
    PrivacySetUnderflow,
    DuplicateNullifier,
    SettlementMismatch,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAggregation => "invalid_aggregation",
            Self::FeeGouging => "fee_gouging",
            Self::MissingReservation => "missing_reservation",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::SettlementMismatch => "settlement_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub sealed_call_suite: String,
    pub quote_suite: String,
    pub compression_suite: String,
    pub proof_suite: String,
    pub slashing_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub call_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_lanes: usize,
    pub max_calls: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_privacy_sets: usize,
    pub max_slashing_events: usize,
    pub max_batch_calls: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SCHEMA_VERSION,
            hash_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_HASH_SUITE
                    .to_string(),
            sealed_call_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SEALED_CALL_SUITE
                    .to_string(),
            quote_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_QUOTE_SUITE
                    .to_string(),
            compression_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_COMPRESSION_SUITE
                    .to_string(),
            proof_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_PROOF_SUITE
                    .to_string(),
            slashing_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_SLASHING_SUITE
                    .to_string(),
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            target_user_fee_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            call_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_CALL_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            max_lanes:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_LANES,
            max_calls:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_CALLS,
            max_quotes:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_REBATES,
            max_privacy_sets:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_PRIVACY_SETS,
            max_slashing_events:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_SLASHING_EVENTS,
            max_batch_calls:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_CALLS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_confidential_contract_call_aggregation_market_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "sealed_call_suite": self.sealed_call_suite,
            "quote_suite": self.quote_suite,
            "compression_suite": self.compression_suite,
            "proof_suite": self.proof_suite,
            "slashing_suite": self.slashing_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "call_ttl_blocks": self.call_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "max_batch_calls": self.max_batch_calls,
        })
    }

    pub fn validate(
        &self,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<()> {
        if self.max_user_fee_bps
            > PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS
        {
            return Err("confidential call aggregation max user fee exceeds bps scale".to_string());
        }
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("confidential call aggregation target fee exceeds max fee".to_string());
        }
        if self.sponsor_cover_bps
            > PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS
        {
            return Err(
                "confidential call aggregation sponsor cover exceeds bps scale".to_string(),
            );
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("confidential call aggregation privacy set config invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_nonce: u64,
    pub next_call_nonce: u64,
    pub next_quote_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_privacy_set_nonce: u64,
    pub next_slashing_nonce: u64,
    pub calls_submitted: u64,
    pub quotes_posted: u64,
    pub reservations_opened: u64,
    pub batches_aggregated: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub slashing_events: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub call_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_set_root: String,
    pub slashing_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            lane_root: empty_root("LANE"),
            call_root: empty_root("CALL"),
            quote_root: empty_root("QUOTE"),
            reservation_root: empty_root("RESERVATION"),
            batch_root: empty_root("BATCH"),
            receipt_root: empty_root("RECEIPT"),
            rebate_root: empty_root("REBATE"),
            privacy_set_root: empty_root("PRIVACY-SET"),
            slashing_root: empty_root("SLASHING"),
            consumed_nullifier_root: empty_root("CONSUMED-NULLIFIER"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregationLane {
    pub lane_id: String,
    pub kind: AggregationLaneKind,
    pub status: LaneStatus,
    pub operator_id: String,
    pub sponsor_pool_id: String,
    pub contract_namespace_root: String,
    pub priority_weight: u64,
    pub max_user_fee_bps: u64,
    pub opened_height: u64,
}

impl AggregationLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_id": self.operator_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "contract_namespace_root": self.contract_namespace_root,
            "priority_weight": self.priority_weight,
            "max_user_fee_bps": self.max_user_fee_bps,
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitSealedCallRequest {
    pub lane_id: String,
    pub caller_commitment: String,
    pub contract_id: String,
    pub call_kind: ConfidentialCallKind,
    pub sealed_call_root: String,
    pub calldata_ciphertext_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub fee_token_id: String,
    pub max_user_fee_bps: u64,
    pub declared_calldata_bytes: u64,
    pub declared_proof_bytes: u64,
    pub pq_security_bits: u16,
    pub privacy_set_id: String,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCallCommitment {
    pub call_id: String,
    pub status: CallStatus,
    pub lane_id: String,
    pub caller_commitment: String,
    pub contract_id: String,
    pub call_kind: ConfidentialCallKind,
    pub sealed_call_root: String,
    pub calldata_ciphertext_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub fee_token_id: String,
    pub max_user_fee_bps: u64,
    pub declared_calldata_bytes: u64,
    pub declared_proof_bytes: u64,
    pub pq_security_bits: u16,
    pub privacy_set_id: String,
    pub selected_quote_id: Option<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedCallCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "status": self.status.as_str(),
            "lane_id": self.lane_id,
            "caller_commitment": self.caller_commitment,
            "contract_id": self.contract_id,
            "call_kind": self.call_kind.as_str(),
            "sealed_call_root": self.sealed_call_root,
            "calldata_ciphertext_root": self.calldata_ciphertext_root,
            "witness_commitment_root": self.witness_commitment_root,
            "nullifier_root": self.nullifier_root,
            "fee_token_id": self.fee_token_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "declared_calldata_bytes": self.declared_calldata_bytes,
            "declared_proof_bytes": self.declared_proof_bytes,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_id": self.privacy_set_id,
            "selected_quote_id": self.selected_quote_id,
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostAggregatorQuoteRequest {
    pub lane_id: String,
    pub aggregator_id: String,
    pub aggregator_class: AggregatorClass,
    pub fee_token_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub calldata_unit_price_micros: u64,
    pub proof_unit_price_micros: u64,
    pub min_calls: u64,
    pub max_calls: u64,
    pub compression_ratio_bps: u64,
    pub bond_amount_micros: u64,
    pub quote_commitment_root: String,
    pub posted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregatorQuote {
    pub quote_id: String,
    pub status: QuoteStatus,
    pub lane_id: String,
    pub aggregator_id: String,
    pub aggregator_class: AggregatorClass,
    pub fee_token_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub calldata_unit_price_micros: u64,
    pub proof_unit_price_micros: u64,
    pub min_calls: u64,
    pub max_calls: u64,
    pub compression_ratio_bps: u64,
    pub bond_amount_micros: u64,
    pub quote_commitment_root: String,
    pub posted_height: u64,
    pub expires_height: u64,
    pub filled_calls: u64,
}

impl AggregatorQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "status": self.status.as_str(),
            "lane_id": self.lane_id,
            "aggregator_id": self.aggregator_id,
            "aggregator_class": self.aggregator_class.as_str(),
            "fee_token_id": self.fee_token_id,
            "user_fee_bps": self.user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "calldata_unit_price_micros": self.calldata_unit_price_micros,
            "proof_unit_price_micros": self.proof_unit_price_micros,
            "min_calls": self.min_calls,
            "max_calls": self.max_calls,
            "compression_ratio_bps": self.compression_ratio_bps,
            "bond_amount_micros": self.bond_amount_micros,
            "quote_commitment_root": self.quote_commitment_root,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
            "filled_calls": self.filled_calls,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveCompressionRequest {
    pub call_id: String,
    pub quote_id: String,
    pub calldata_bytes_reserved: u64,
    pub proof_bytes_reserved: u64,
    pub reservation_commitment_root: String,
    pub reserved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionReservation {
    pub reservation_id: String,
    pub status: ReservationStatus,
    pub call_id: String,
    pub quote_id: String,
    pub aggregator_id: String,
    pub calldata_bytes_reserved: u64,
    pub proof_bytes_reserved: u64,
    pub reservation_commitment_root: String,
    pub reserved_height: u64,
    pub expires_height: u64,
}

impl CompressionReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "call_id": self.call_id,
            "quote_id": self.quote_id,
            "aggregator_id": self.aggregator_id,
            "calldata_bytes_reserved": self.calldata_bytes_reserved,
            "proof_bytes_reserved": self.proof_bytes_reserved,
            "reservation_commitment_root": self.reservation_commitment_root,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateBatchRequest {
    pub lane_id: String,
    pub aggregator_id: String,
    pub quote_id: String,
    pub call_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub sealed_call_root: String,
    pub reservation_root: String,
    pub compressed_calldata_root: String,
    pub compressed_proof_root: String,
    pub aggregate_nullifier_root: String,
    pub privacy_set_root: String,
    pub public_input_root: String,
    pub batch_proof_root: String,
    pub total_user_fee_bps: u64,
    pub total_rebate_micros: u64,
    pub planned_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregatedBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub lane_id: String,
    pub aggregator_id: String,
    pub quote_id: String,
    pub call_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub sealed_call_root: String,
    pub reservation_root: String,
    pub compressed_calldata_root: String,
    pub compressed_proof_root: String,
    pub aggregate_nullifier_root: String,
    pub privacy_set_root: String,
    pub public_input_root: String,
    pub batch_proof_root: String,
    pub total_user_fee_bps: u64,
    pub total_rebate_micros: u64,
    pub planned_height: u64,
    pub expires_height: u64,
}

impl AggregatedBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "lane_id": self.lane_id,
            "aggregator_id": self.aggregator_id,
            "quote_id": self.quote_id,
            "call_ids": self.call_ids,
            "reservation_ids": self.reservation_ids,
            "sealed_call_root": self.sealed_call_root,
            "reservation_root": self.reservation_root,
            "compressed_calldata_root": self.compressed_calldata_root,
            "compressed_proof_root": self.compressed_proof_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "privacy_set_root": self.privacy_set_root,
            "public_input_root": self.public_input_root,
            "batch_proof_root": self.batch_proof_root,
            "total_user_fee_bps": self.total_user_fee_bps,
            "total_rebate_micros": self.total_rebate_micros,
            "planned_height": self.planned_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishSettlementReceiptRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_delta_root: String,
    pub event_root: String,
    pub fee_paid_micros: u64,
    pub sponsor_paid_micros: u64,
    pub settled_height: u64,
    pub finalized_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_delta_root: String,
    pub event_root: String,
    pub fee_paid_micros: u64,
    pub sponsor_paid_micros: u64,
    pub public_record_hash: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_height: u64,
    pub finalized_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "state_delta_root": self.state_delta_root,
            "event_root": self.event_root,
            "fee_paid_micros": self.fee_paid_micros,
            "sponsor_paid_micros": self.sponsor_paid_micros,
            "public_record_hash": self.public_record_hash,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_height": self.settled_height,
            "finalized_height": self.finalized_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub status: RebateStatus,
    pub call_id: String,
    pub batch_id: String,
    pub quote_id: String,
    pub recipient_commitment: String,
    pub amount_micros: u64,
    pub rebate_bps: u64,
    pub claim_nullifier: String,
    pub claim_root: String,
    pub issued_height: u64,
    pub claimable_height: u64,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "call_id": self.call_id,
            "batch_id": self.batch_id,
            "quote_id": self.quote_id,
            "recipient_commitment": self.recipient_commitment,
            "amount_micros": self.amount_micros,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier": self.claim_nullifier,
            "claim_root": self.claim_root,
            "issued_height": self.issued_height,
            "claimable_height": self.claimable_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacySetAccount {
    pub privacy_set_id: String,
    pub lane_id: String,
    pub set_size: u64,
    pub minimum_set_size: u64,
    pub anonymity_set_root: String,
    pub member_commitment_root: String,
    pub nullifier_root: String,
    pub accounted_call_count: u64,
    pub opened_height: u64,
    pub last_accounted_height: u64,
}

impl PrivacySetAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_set_id": self.privacy_set_id,
            "lane_id": self.lane_id,
            "set_size": self.set_size,
            "minimum_set_size": self.minimum_set_size,
            "anonymity_set_root": self.anonymity_set_root,
            "member_commitment_root": self.member_commitment_root,
            "nullifier_root": self.nullifier_root,
            "accounted_call_count": self.accounted_call_count,
            "opened_height": self.opened_height,
            "last_accounted_height": self.last_accounted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashAggregatorRequest {
    pub batch_id: Option<String>,
    pub quote_id: Option<String>,
    pub aggregator_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_bps: u64,
    pub slashed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvent {
    pub slashing_id: String,
    pub batch_id: Option<String>,
    pub quote_id: Option<String>,
    pub aggregator_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_bps: u64,
    pub bond_slashed_micros: u64,
    pub slashed_height: u64,
}

impl SlashingEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "batch_id": self.batch_id,
            "quote_id": self.quote_id,
            "aggregator_id": self.aggregator_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_commitment": self.reporter_commitment,
            "slash_bps": self.slash_bps,
            "bond_slashed_micros": self.bond_slashed_micros,
            "slashed_height": self.slashed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub lanes: BTreeMap<String, AggregationLane>,
    pub calls: BTreeMap<String, SealedCallCommitment>,
    pub quotes: BTreeMap<String, AggregatorQuote>,
    pub reservations: BTreeMap<String, CompressionReservation>,
    pub batches: BTreeMap<String, AggregatedBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub privacy_sets: BTreeMap<String, PrivacySetAccount>,
    pub slashing_events: BTreeMap<String, SlashingEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            current_height:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            calls: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_sets: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.recompute();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height =
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEVNET_HEIGHT;
        let defi_lane = sample_lane(AggregationLaneKind::DefiSwap, "devnet-defi-agg", height);
        let bridge_lane = sample_lane(AggregationLaneKind::BridgeRelay, "devnet-xmr-agg", height);
        let hook_lane = sample_lane(
            AggregationLaneKind::SettlementHook,
            "devnet-settlement-agg",
            height,
        );
        state.insert_lane(defi_lane.clone()).ok();
        state.insert_lane(bridge_lane).ok();
        state.insert_lane(hook_lane).ok();

        let privacy_set_id = privacy_set_id(&defi_lane.lane_id, "devnet-privacy-ring");
        state.privacy_sets.insert(
            privacy_set_id.clone(),
            sample_privacy_set(&defi_lane.lane_id, &privacy_set_id, height),
        );
        let call = sample_call(&defi_lane.lane_id, &privacy_set_id, "devnet-call-0", height);
        let call_id = call.call_id.clone();
        state.calls.insert(call_id.clone(), call);
        let quote = sample_quote(&defi_lane.lane_id, "aggregator-devnet-fast-01", height);
        let quote_id = quote.quote_id.clone();
        state.quotes.insert(quote_id.clone(), quote);
        let reservation =
            sample_reservation(&call_id, &quote_id, "aggregator-devnet-fast-01", height);
        let reservation_id = reservation.reservation_id.clone();
        state
            .reservations
            .insert(reservation_id.clone(), reservation);
        let batch = sample_batch(
            &defi_lane.lane_id,
            "aggregator-devnet-fast-01",
            &quote_id,
            vec![call_id],
            vec![reservation_id],
            height + 1,
        );
        state.batches.insert(batch.batch_id.clone(), batch);
        state.recompute();
        state
    }

    pub fn insert_lane(
        &mut self,
        lane: AggregationLane,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<()> {
        if self.lanes.len() >= self.config.max_lanes && !self.lanes.contains_key(&lane.lane_id) {
            return Err("confidential call aggregation lane capacity exceeded".to_string());
        }
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.recompute();
        Ok(())
    }

    pub fn submit_sealed_call(
        &mut self,
        request: SubmitSealedCallRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<SealedCallCommitment>
    {
        self.config.validate()?;
        self.ensure_capacity(self.calls.len(), self.config.max_calls, "calls")?;
        validate_root(&request.sealed_call_root, "sealed call root")?;
        validate_root(
            &request.calldata_ciphertext_root,
            "calldata ciphertext root",
        )?;
        validate_root(&request.witness_commitment_root, "witness commitment root")?;
        validate_root(&request.nullifier_root, "nullifier root")?;
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "confidential call aggregation lane missing".to_string())?;
        if !lane.status.accepts_calls() {
            return Err("confidential call aggregation lane does not accept calls".to_string());
        }
        if request.max_user_fee_bps > lane.max_user_fee_bps
            || request.max_user_fee_bps > self.config.max_user_fee_bps
        {
            return Err(
                "confidential call aggregation call fee cap exceeds lane policy".to_string(),
            );
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("confidential call aggregation pq security below minimum".to_string());
        }
        let privacy_set = self
            .privacy_sets
            .get_mut(&request.privacy_set_id)
            .ok_or_else(|| "confidential call aggregation privacy set missing".to_string())?;
        if privacy_set.set_size < privacy_set.minimum_set_size {
            return Err("confidential call aggregation privacy set under minimum".to_string());
        }
        privacy_set.accounted_call_count += 1;
        privacy_set.last_accounted_height = request.submitted_height;
        let nonce = self.counters.next_call_nonce;
        self.counters.next_call_nonce += 1;
        let call_id = call_id(&request, nonce);
        let call = SealedCallCommitment {
            call_id,
            status: CallStatus::Submitted,
            lane_id: request.lane_id,
            caller_commitment: request.caller_commitment,
            contract_id: request.contract_id,
            call_kind: request.call_kind,
            sealed_call_root: request.sealed_call_root,
            calldata_ciphertext_root: request.calldata_ciphertext_root,
            witness_commitment_root: request.witness_commitment_root,
            nullifier_root: request.nullifier_root,
            fee_token_id: request.fee_token_id,
            max_user_fee_bps: request.max_user_fee_bps,
            declared_calldata_bytes: request.declared_calldata_bytes,
            declared_proof_bytes: request.declared_proof_bytes,
            pq_security_bits: request.pq_security_bits,
            privacy_set_id: request.privacy_set_id,
            selected_quote_id: None,
            reservation_id: None,
            batch_id: None,
            submitted_height: request.submitted_height,
            expires_height: request.submitted_height + self.config.call_ttl_blocks,
        };
        self.current_height = self.current_height.max(call.submitted_height);
        self.counters.calls_submitted += 1;
        self.calls.insert(call.call_id.clone(), call.clone());
        self.recompute();
        Ok(call)
    }

    pub fn post_aggregator_quote(
        &mut self,
        request: PostAggregatorQuoteRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<AggregatorQuote>
    {
        self.config.validate()?;
        self.ensure_capacity(self.quotes.len(), self.config.max_quotes, "quotes")?;
        validate_root(&request.quote_commitment_root, "quote commitment root")?;
        if !self.lanes.contains_key(&request.lane_id) {
            return Err("confidential call aggregation quote lane missing".to_string());
        }
        if request.user_fee_bps > self.config.max_user_fee_bps {
            return Err("confidential call aggregation quote fee gouging".to_string());
        }
        if request.rebate_bps > request.user_fee_bps {
            return Err("confidential call aggregation rebate exceeds quoted fee".to_string());
        }
        if request.max_calls < request.min_calls || request.max_calls == 0 {
            return Err("confidential call aggregation quote call range invalid".to_string());
        }
        let nonce = self.counters.next_quote_nonce;
        self.counters.next_quote_nonce += 1;
        let quote = AggregatorQuote {
            quote_id: quote_id(&request, nonce),
            status: QuoteStatus::Posted,
            lane_id: request.lane_id,
            aggregator_id: request.aggregator_id,
            aggregator_class: request.aggregator_class,
            fee_token_id: request.fee_token_id,
            user_fee_bps: request.user_fee_bps,
            rebate_bps: request.rebate_bps,
            sponsor_cover_bps: request.sponsor_cover_bps,
            calldata_unit_price_micros: request.calldata_unit_price_micros,
            proof_unit_price_micros: request.proof_unit_price_micros,
            min_calls: request.min_calls,
            max_calls: request.max_calls,
            compression_ratio_bps: request.compression_ratio_bps,
            bond_amount_micros: request.bond_amount_micros,
            quote_commitment_root: request.quote_commitment_root,
            posted_height: request.posted_height,
            expires_height: request.posted_height + self.config.quote_ttl_blocks,
            filled_calls: 0,
        };
        self.current_height = self.current_height.max(quote.posted_height);
        self.counters.quotes_posted += 1;
        self.quotes.insert(quote.quote_id.clone(), quote.clone());
        self.recompute();
        Ok(quote)
    }

    pub fn reserve_compression(
        &mut self,
        request: ReserveCompressionRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<CompressionReservation>
    {
        self.ensure_capacity(
            self.reservations.len(),
            self.config.max_reservations,
            "reservations",
        )?;
        validate_root(
            &request.reservation_commitment_root,
            "reservation commitment root",
        )?;
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "confidential call aggregation quote missing".to_string())?;
        if !quote.status.selectable() || request.reserved_height > quote.expires_height {
            return Err("confidential call aggregation quote is not reservable".to_string());
        }
        let call = self
            .calls
            .get_mut(&request.call_id)
            .ok_or_else(|| "confidential call aggregation call missing".to_string())?;
        if !call.status.live() || request.reserved_height > call.expires_height {
            return Err("confidential call aggregation call is not reservable".to_string());
        }
        if call.max_user_fee_bps < quote.user_fee_bps {
            return Err(
                "confidential call aggregation selected quote exceeds user fee cap".to_string(),
            );
        }
        if request.calldata_bytes_reserved < call.declared_calldata_bytes
            || request.proof_bytes_reserved < call.declared_proof_bytes
        {
            return Err("confidential call aggregation reservation undersized".to_string());
        }
        let nonce = self.counters.next_reservation_nonce;
        self.counters.next_reservation_nonce += 1;
        let reservation = CompressionReservation {
            reservation_id: reservation_id(&request, nonce),
            status: ReservationStatus::Held,
            call_id: request.call_id.clone(),
            quote_id: request.quote_id.clone(),
            aggregator_id: quote.aggregator_id.clone(),
            calldata_bytes_reserved: request.calldata_bytes_reserved,
            proof_bytes_reserved: request.proof_bytes_reserved,
            reservation_commitment_root: request.reservation_commitment_root,
            reserved_height: request.reserved_height,
            expires_height: request.reserved_height + self.config.reservation_ttl_blocks,
        };
        quote.status = QuoteStatus::Selected;
        quote.filled_calls += 1;
        call.status = CallStatus::Reserved;
        call.selected_quote_id = Some(request.quote_id);
        call.reservation_id = Some(reservation.reservation_id.clone());
        self.current_height = self.current_height.max(reservation.reserved_height);
        self.counters.reservations_opened += 1;
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute();
        Ok(reservation)
    }

    pub fn aggregate_batch(
        &mut self,
        request: AggregateBatchRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<AggregatedBatch>
    {
        self.ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        if request.call_ids.is_empty() || request.call_ids.len() > self.config.max_batch_calls {
            return Err("confidential call aggregation batch call count invalid".to_string());
        }
        validate_root(&request.sealed_call_root, "sealed call root")?;
        validate_root(&request.reservation_root, "reservation root")?;
        validate_root(
            &request.compressed_calldata_root,
            "compressed calldata root",
        )?;
        validate_root(&request.compressed_proof_root, "compressed proof root")?;
        validate_root(
            &request.aggregate_nullifier_root,
            "aggregate nullifier root",
        )?;
        validate_root(&request.privacy_set_root, "privacy set root")?;
        validate_root(&request.public_input_root, "public input root")?;
        validate_root(&request.batch_proof_root, "batch proof root")?;
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "confidential call aggregation batch quote missing".to_string())?;
        if quote.aggregator_id != request.aggregator_id {
            return Err("confidential call aggregation batch aggregator mismatch".to_string());
        }
        if request.total_user_fee_bps > self.config.max_user_fee_bps
            || request.total_user_fee_bps > quote.user_fee_bps
        {
            return Err("confidential call aggregation batch fee gouging".to_string());
        }
        let reservation_set = request
            .reservation_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for call_id in &request.call_ids {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| "confidential call aggregation batch call missing".to_string())?;
            if call.lane_id != request.lane_id
                || call.selected_quote_id.as_deref() != Some(&request.quote_id)
            {
                return Err("confidential call aggregation batch call quote mismatch".to_string());
            }
            let reservation_id = call.reservation_id.as_ref().ok_or_else(|| {
                "confidential call aggregation call missing reservation".to_string()
            })?;
            if !reservation_set.contains(reservation_id) {
                return Err("confidential call aggregation reservation set incomplete".to_string());
            }
            if self.consumed_nullifiers.contains(&call.nullifier_root) {
                return Err("confidential call aggregation duplicate nullifier".to_string());
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .reservations
                .get(reservation_id)
                .ok_or_else(|| "confidential call aggregation reservation missing".to_string())?;
            if reservation.quote_id != request.quote_id
                || reservation.aggregator_id != request.aggregator_id
                || request.planned_height > reservation.expires_height
            {
                return Err(
                    "confidential call aggregation reservation invalid for batch".to_string(),
                );
            }
        }
        let nonce = self.counters.next_batch_nonce;
        self.counters.next_batch_nonce += 1;
        let batch = AggregatedBatch {
            batch_id: batch_id(&request, nonce),
            status: BatchStatus::SettlementReady,
            lane_id: request.lane_id,
            aggregator_id: request.aggregator_id,
            quote_id: request.quote_id,
            call_ids: request.call_ids,
            reservation_ids: request.reservation_ids,
            sealed_call_root: request.sealed_call_root,
            reservation_root: request.reservation_root,
            compressed_calldata_root: request.compressed_calldata_root,
            compressed_proof_root: request.compressed_proof_root,
            aggregate_nullifier_root: request.aggregate_nullifier_root,
            privacy_set_root: request.privacy_set_root,
            public_input_root: request.public_input_root,
            batch_proof_root: request.batch_proof_root,
            total_user_fee_bps: request.total_user_fee_bps,
            total_rebate_micros: request.total_rebate_micros,
            planned_height: request.planned_height,
            expires_height: request.planned_height + self.config.batch_ttl_blocks,
        };
        for call_id in &batch.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = CallStatus::Aggregated;
                call.batch_id = Some(batch.batch_id.clone());
                self.consumed_nullifiers.insert(call.nullifier_root.clone());
            }
        }
        for reservation_id in &batch.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        if let Some(quote) = self.quotes.get_mut(&batch.quote_id) {
            quote.status = QuoteStatus::Filled;
        }
        self.current_height = self.current_height.max(batch.planned_height);
        self.counters.batches_aggregated += 1;
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        self.recompute();
        Ok(batch)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<SettlementReceipt>
    {
        self.ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        validate_root(&request.settlement_tx_root, "settlement tx root")?;
        validate_root(&request.settlement_proof_root, "settlement proof root")?;
        validate_root(&request.state_delta_root, "state delta root")?;
        validate_root(&request.event_root, "event root")?;
        let state_root_before = self.state_root();
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "confidential call aggregation settlement batch missing".to_string())?;
        if !batch.status.can_settle() || request.settled_height > batch.expires_height {
            return Err("confidential call aggregation batch cannot settle".to_string());
        }
        batch.status = BatchStatus::Settled;
        for call_id in &batch.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = CallStatus::Settled;
            }
        }
        let quote_id = batch.quote_id.clone();
        let batch_id = batch.batch_id.clone();
        let call_ids = batch.call_ids.clone();
        self.current_height = self.current_height.max(request.settled_height);
        let receipt_seed = json!({
            "batch_id": batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "settled_height": request.settled_height,
        });
        let receipt_id = id_from_record(
            "RECEIPT-ID",
            &receipt_seed,
            self.counters.next_receipt_nonce,
        );
        self.counters.next_receipt_nonce += 1;
        let public_record_hash = public_record_root(&receipt_seed);
        let mut receipt = SettlementReceipt {
            receipt_id,
            status: if request.finalized_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            batch_id: batch_id.clone(),
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            state_delta_root: request.state_delta_root,
            event_root: request.event_root,
            fee_paid_micros: request.fee_paid_micros,
            sponsor_paid_micros: request.sponsor_paid_micros,
            public_record_hash,
            state_root_before,
            state_root_after: String::new(),
            settled_height: request.settled_height,
            finalized_height: request.finalized_height,
        };
        self.counters.receipts_published += 1;
        self.issue_rebates(&batch_id, &quote_id, &call_ids, request.settled_height)?;
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute();
        receipt.state_root_after = self.state_root();
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute();
        Ok(receipt)
    }

    pub fn slash_aggregator(
        &mut self,
        request: SlashAggregatorRequest,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<SlashingEvent> {
        self.ensure_capacity(
            self.slashing_events.len(),
            self.config.max_slashing_events,
            "slashing events",
        )?;
        validate_root(&request.evidence_root, "slashing evidence root")?;
        if request.slash_bps
            > PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS
        {
            return Err("confidential call aggregation slash bps exceeds scale".to_string());
        }
        let mut bond = 0;
        if let Some(quote_id) = &request.quote_id {
            let quote = self
                .quotes
                .get_mut(quote_id)
                .ok_or_else(|| "confidential call aggregation slash quote missing".to_string())?;
            quote.status = QuoteStatus::Slashed;
            bond = quote.bond_amount_micros;
        }
        if let Some(batch_id) = &request.batch_id {
            let batch = self
                .batches
                .get_mut(batch_id)
                .ok_or_else(|| "confidential call aggregation slash batch missing".to_string())?;
            batch.status = BatchStatus::Slashed;
        }
        let event = SlashingEvent {
            slashing_id: id_from_record(
                "SLASHING-ID",
                &json!({
                    "aggregator_id": request.aggregator_id,
                    "reason": request.reason.as_str(),
                    "evidence_root": request.evidence_root,
                }),
                self.counters.next_slashing_nonce,
            ),
            batch_id: request.batch_id,
            quote_id: request.quote_id,
            aggregator_id: request.aggregator_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            reporter_commitment: request.reporter_commitment,
            slash_bps: request.slash_bps,
            bond_slashed_micros: bond.saturating_mul(request.slash_bps)
                / PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS,
            slashed_height: request.slashed_height,
        };
        self.counters.next_slashing_nonce += 1;
        self.counters.slashing_events += 1;
        self.current_height = self.current_height.max(event.slashed_height);
        self.slashing_events
            .insert(event.slashing_id.clone(), event.clone());
        self.recompute();
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.compute_roots_without_state();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height_hint": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEVNET_HEIGHT,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": roots,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn recompute(&mut self) {
        self.counters.public_records = 1;
        let public_record = self.public_record();
        let mut roots = self.compute_roots_without_state();
        roots.public_record_root = public_record_root(&public_record);
        roots.state_root = state_root_from_record(&public_record);
        self.roots = roots;
    }

    fn compute_roots_without_state(&self) -> Roots {
        Roots {
            lane_root: merkle_root(
                domain("LANE").as_str(),
                &self
                    .lanes
                    .values()
                    .map(AggregationLane::public_record)
                    .collect::<Vec<_>>(),
            ),
            call_root: merkle_root(
                domain("CALL").as_str(),
                &self
                    .calls
                    .values()
                    .map(SealedCallCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            quote_root: merkle_root(
                domain("QUOTE").as_str(),
                &self
                    .quotes
                    .values()
                    .map(AggregatorQuote::public_record)
                    .collect::<Vec<_>>(),
            ),
            reservation_root: merkle_root(
                domain("RESERVATION").as_str(),
                &self
                    .reservations
                    .values()
                    .map(CompressionReservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_root: merkle_root(
                domain("BATCH").as_str(),
                &self
                    .batches
                    .values()
                    .map(AggregatedBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: merkle_root(
                domain("RECEIPT").as_str(),
                &self
                    .receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: merkle_root(
                domain("REBATE").as_str(),
                &self
                    .rebates
                    .values()
                    .map(RebateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_set_root: merkle_root(
                domain("PRIVACY-SET").as_str(),
                &self
                    .privacy_sets
                    .values()
                    .map(PrivacySetAccount::public_record)
                    .collect::<Vec<_>>(),
            ),
            slashing_root: merkle_root(
                domain("SLASHING").as_str(),
                &self
                    .slashing_events
                    .values()
                    .map(SlashingEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
            consumed_nullifier_root: merkle_root(
                domain("CONSUMED-NULLIFIER").as_str(),
                &self
                    .consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!({ "nullifier_root": nullifier }))
                    .collect::<Vec<_>>(),
            ),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }

    fn ensure_capacity(
        &self,
        len: usize,
        max: usize,
        label: &str,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<()> {
        if len >= max {
            Err(format!(
                "confidential call aggregation {} capacity exceeded",
                label
            ))
        } else {
            Ok(())
        }
    }

    fn issue_rebates(
        &mut self,
        batch_id: &str,
        quote_id: &str,
        call_ids: &[String],
        height: u64,
    ) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<()> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| "confidential call aggregation rebate quote missing".to_string())?;
        let rebate_bps = quote.rebate_bps;
        for call_id in call_ids {
            self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| "confidential call aggregation rebate call missing".to_string())?;
            let nonce = self.counters.next_rebate_nonce;
            self.counters.next_rebate_nonce += 1;
            let amount_micros = (call.call_kind.complexity_units() * 1_000 * rebate_bps)
                / PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_MAX_BPS;
            let rebate_seed = json!({
                "call_id": call_id,
                "batch_id": batch_id,
                "quote_id": quote_id,
                "nonce": nonce,
            });
            let rebate_id = id_from_record("REBATE-ID", &rebate_seed, nonce);
            let rebate = RebateRecord {
                rebate_id: rebate_id.clone(),
                status: RebateStatus::Claimable,
                call_id: call_id.clone(),
                batch_id: batch_id.to_string(),
                quote_id: quote_id.to_string(),
                recipient_commitment: call.caller_commitment.clone(),
                amount_micros,
                rebate_bps,
                claim_nullifier: stable_commitment("rebate-claim-nullifier", &rebate_id),
                claim_root: root_from_record(domain("REBATE-CLAIM").as_str(), &rebate_seed),
                issued_height: height,
                claimable_height: height,
            };
            call.status = CallStatus::Rebated;
            self.counters.rebates_issued += 1;
            self.rebates.insert(rebate_id, rebate);
        }
        Ok(())
    }
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record(domain("PUBLIC-RECORD").as_str(), record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(domain("STATE").as_str(), record)
}

pub fn root_from_record(domain_label: &str, record: &Value) -> String {
    domain_hash(domain_label, &[HashPart::Json(record)], 32)
}

pub fn stable_commitment(label: &str, seed: &str) -> String {
    domain_hash(
        domain("COMMITMENT").as_str(),
        &[HashPart::Str(label), HashPart::Str(seed)],
        32,
    )
}

pub fn lane_id(kind: AggregationLaneKind, seed: &str) -> String {
    domain_hash(
        domain("LANE-ID").as_str(),
        &[HashPart::Str(kind.as_str()), HashPart::Str(seed)],
        20,
    )
}

pub fn privacy_set_id(lane_id: &str, seed: &str) -> String {
    domain_hash(
        domain("PRIVACY-SET-ID").as_str(),
        &[HashPart::Str(lane_id), HashPart::Str(seed)],
        20,
    )
}

pub fn call_id(request: &SubmitSealedCallRequest, nonce: u64) -> String {
    id_from_record(
        "CALL-ID",
        &json!({
            "lane_id": request.lane_id,
            "caller_commitment": request.caller_commitment,
            "contract_id": request.contract_id,
            "sealed_call_root": request.sealed_call_root,
            "nonce": nonce,
        }),
        nonce,
    )
}

pub fn quote_id(request: &PostAggregatorQuoteRequest, nonce: u64) -> String {
    id_from_record(
        "QUOTE-ID",
        &json!({
            "lane_id": request.lane_id,
            "aggregator_id": request.aggregator_id,
            "fee_token_id": request.fee_token_id,
            "user_fee_bps": request.user_fee_bps,
            "nonce": nonce,
        }),
        nonce,
    )
}

pub fn reservation_id(request: &ReserveCompressionRequest, nonce: u64) -> String {
    id_from_record(
        "RESERVATION-ID",
        &json!({
            "call_id": request.call_id,
            "quote_id": request.quote_id,
            "reservation_commitment_root": request.reservation_commitment_root,
            "nonce": nonce,
        }),
        nonce,
    )
}

pub fn batch_id(request: &AggregateBatchRequest, nonce: u64) -> String {
    id_from_record(
        "BATCH-ID",
        &json!({
            "lane_id": request.lane_id,
            "aggregator_id": request.aggregator_id,
            "quote_id": request.quote_id,
            "sealed_call_root": request.sealed_call_root,
            "public_input_root": request.public_input_root,
            "nonce": nonce,
        }),
        nonce,
    )
}

pub fn id_from_record(label: &str, record: &Value, nonce: u64) -> String {
    domain_hash(
        domain(label).as_str(),
        &[HashPart::Json(record), HashPart::Int(nonce as i128)],
        20,
    )
}

fn validate_root(
    value: &str,
    label: &str,
) -> PrivateL2LowFeeConfidentialContractCallAggregationMarketRuntimeResult<()> {
    if value.len() < 32 {
        Err(format!(
            "confidential call aggregation {} is too short",
            label
        ))
    } else {
        Ok(())
    }
}

fn domain(label: &str) -> String {
    format!(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CONTRACT-CALL-AGGREGATION-MARKET-{}",
        label
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(domain(label).as_str(), &[])
}

fn sample_lane(kind: AggregationLaneKind, seed: &str, height: u64) -> AggregationLane {
    let lane_id = lane_id(kind, seed);
    AggregationLane {
        lane_id: lane_id.clone(),
        kind,
        status: LaneStatus::Open,
        operator_id: format!("operator-{}", seed),
        sponsor_pool_id: format!("sponsor-pool-{}", seed),
        contract_namespace_root: root_from_record(
            domain("DEVNET-CONTRACT-NAMESPACE").as_str(),
            &json!({"lane_id": lane_id, "kind": kind.as_str()}),
        ),
        priority_weight: kind.priority_weight(),
        max_user_fee_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
        opened_height: height,
    }
}

fn sample_privacy_set(lane_id: &str, privacy_set_id: &str, height: u64) -> PrivacySetAccount {
    PrivacySetAccount {
        privacy_set_id: privacy_set_id.to_string(),
        lane_id: lane_id.to_string(),
        set_size:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
        minimum_set_size:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
        anonymity_set_root: root_from_record(
            domain("DEVNET-ANONYMITY-SET").as_str(),
            &json!({"privacy_set_id": privacy_set_id}),
        ),
        member_commitment_root: root_from_record(
            domain("DEVNET-MEMBER-COMMITMENT").as_str(),
            &json!({"privacy_set_id": privacy_set_id}),
        ),
        nullifier_root: root_from_record(
            domain("DEVNET-PRIVACY-NULLIFIER").as_str(),
            &json!({"privacy_set_id": privacy_set_id}),
        ),
        accounted_call_count: 0,
        opened_height: height,
        last_accounted_height: height,
    }
}

fn sample_call(
    lane_id: &str,
    privacy_set_id: &str,
    seed: &str,
    height: u64,
) -> SealedCallCommitment {
    let request = SubmitSealedCallRequest {
        lane_id: lane_id.to_string(),
        caller_commitment: stable_commitment("devnet-caller", seed),
        contract_id: "devnet-private-amm".to_string(),
        call_kind: ConfidentialCallKind::DefiSwap,
        sealed_call_root: root_from_record(domain("DEVNET-SEALED-CALL").as_str(), &json!({"seed": seed})),
        calldata_ciphertext_root: root_from_record(domain("DEVNET-CALLDATA").as_str(), &json!({"seed": seed})),
        witness_commitment_root: root_from_record(domain("DEVNET-WITNESS").as_str(), &json!({"seed": seed})),
        nullifier_root: root_from_record(domain("DEVNET-NULLIFIER").as_str(), &json!({"seed": seed})),
        fee_token_id: "nebula".to_string(),
        max_user_fee_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
        declared_calldata_bytes: 1_024,
        declared_proof_bytes: 4_096,
        pq_security_bits:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        privacy_set_id: privacy_set_id.to_string(),
        submitted_height: height,
    };
    SealedCallCommitment {
        call_id: call_id(&request, 0),
        status: CallStatus::Reserved,
        lane_id: request.lane_id,
        caller_commitment: request.caller_commitment,
        contract_id: request.contract_id,
        call_kind: request.call_kind,
        sealed_call_root: request.sealed_call_root,
        calldata_ciphertext_root: request.calldata_ciphertext_root,
        witness_commitment_root: request.witness_commitment_root,
        nullifier_root: request.nullifier_root,
        fee_token_id: request.fee_token_id,
        max_user_fee_bps: request.max_user_fee_bps,
        declared_calldata_bytes: request.declared_calldata_bytes,
        declared_proof_bytes: request.declared_proof_bytes,
        pq_security_bits: request.pq_security_bits,
        privacy_set_id: request.privacy_set_id,
        selected_quote_id: None,
        reservation_id: None,
        batch_id: None,
        submitted_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_CALL_TTL_BLOCKS,
    }
}

fn sample_quote(lane_id: &str, aggregator_id: &str, height: u64) -> AggregatorQuote {
    let request = PostAggregatorQuoteRequest {
        lane_id: lane_id.to_string(),
        aggregator_id: aggregator_id.to_string(),
        aggregator_class: AggregatorClass::SequencerOperated,
        fee_token_id: "nebula".to_string(),
        user_fee_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
        rebate_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
        sponsor_cover_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
        calldata_unit_price_micros: 3,
        proof_unit_price_micros: 7,
        min_calls: 1,
        max_calls: 16_384,
        compression_ratio_bps: 3_500,
        bond_amount_micros: 10_000_000,
        quote_commitment_root: root_from_record(
            domain("DEVNET-QUOTE").as_str(),
            &json!({"lane_id": lane_id, "aggregator_id": aggregator_id}),
        ),
        posted_height: height,
    };
    AggregatorQuote {
        quote_id: quote_id(&request, 0),
        status: QuoteStatus::Selected,
        lane_id: request.lane_id,
        aggregator_id: request.aggregator_id,
        aggregator_class: request.aggregator_class,
        fee_token_id: request.fee_token_id,
        user_fee_bps: request.user_fee_bps,
        rebate_bps: request.rebate_bps,
        sponsor_cover_bps: request.sponsor_cover_bps,
        calldata_unit_price_micros: request.calldata_unit_price_micros,
        proof_unit_price_micros: request.proof_unit_price_micros,
        min_calls: request.min_calls,
        max_calls: request.max_calls,
        compression_ratio_bps: request.compression_ratio_bps,
        bond_amount_micros: request.bond_amount_micros,
        quote_commitment_root: request.quote_commitment_root,
        posted_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
        filled_calls: 1,
    }
}

fn sample_reservation(
    call_id: &str,
    quote_id: &str,
    aggregator_id: &str,
    height: u64,
) -> CompressionReservation {
    let request = ReserveCompressionRequest {
        call_id: call_id.to_string(),
        quote_id: quote_id.to_string(),
        calldata_bytes_reserved: 1_024,
        proof_bytes_reserved: 4_096,
        reservation_commitment_root: root_from_record(
            domain("DEVNET-RESERVATION").as_str(),
            &json!({"call_id": call_id, "quote_id": quote_id}),
        ),
        reserved_height: height,
    };
    CompressionReservation {
        reservation_id: reservation_id(&request, 0),
        status: ReservationStatus::Consumed,
        call_id: request.call_id,
        quote_id: request.quote_id,
        aggregator_id: aggregator_id.to_string(),
        calldata_bytes_reserved: request.calldata_bytes_reserved,
        proof_bytes_reserved: request.proof_bytes_reserved,
        reservation_commitment_root: request.reservation_commitment_root,
        reserved_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
    }
}

fn sample_batch(
    lane_id: &str,
    aggregator_id: &str,
    quote_id: &str,
    call_ids: Vec<String>,
    reservation_ids: Vec<String>,
    height: u64,
) -> AggregatedBatch {
    let request = AggregateBatchRequest {
        lane_id: lane_id.to_string(),
        aggregator_id: aggregator_id.to_string(),
        quote_id: quote_id.to_string(),
        call_ids,
        reservation_ids,
        sealed_call_root: root_from_record(domain("DEVNET-BATCH-CALL").as_str(), &json!({"lane_id": lane_id})),
        reservation_root: root_from_record(domain("DEVNET-BATCH-RESERVATION").as_str(), &json!({"lane_id": lane_id})),
        compressed_calldata_root: root_from_record(domain("DEVNET-COMPRESSED-CALLDATA").as_str(), &json!({"lane_id": lane_id})),
        compressed_proof_root: root_from_record(domain("DEVNET-COMPRESSED-PROOF").as_str(), &json!({"lane_id": lane_id})),
        aggregate_nullifier_root: root_from_record(domain("DEVNET-BATCH-NULLIFIER").as_str(), &json!({"lane_id": lane_id})),
        privacy_set_root: root_from_record(domain("DEVNET-BATCH-PRIVACY").as_str(), &json!({"lane_id": lane_id})),
        public_input_root: root_from_record(domain("DEVNET-BATCH-PUBLIC-INPUT").as_str(), &json!({"lane_id": lane_id})),
        batch_proof_root: root_from_record(domain("DEVNET-BATCH-PROOF").as_str(), &json!({"lane_id": lane_id})),
        total_user_fee_bps:
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
        total_rebate_micros: 3_000,
        planned_height: height,
    };
    AggregatedBatch {
        batch_id: batch_id(&request, 0),
        status: BatchStatus::SettlementReady,
        lane_id: request.lane_id,
        aggregator_id: request.aggregator_id,
        quote_id: request.quote_id,
        call_ids: request.call_ids,
        reservation_ids: request.reservation_ids,
        sealed_call_root: request.sealed_call_root,
        reservation_root: request.reservation_root,
        compressed_calldata_root: request.compressed_calldata_root,
        compressed_proof_root: request.compressed_proof_root,
        aggregate_nullifier_root: request.aggregate_nullifier_root,
        privacy_set_root: request.privacy_set_root,
        public_input_root: request.public_input_root,
        batch_proof_root: request.batch_proof_root,
        total_user_fee_bps: request.total_user_fee_bps,
        total_rebate_micros: request.total_rebate_micros,
        planned_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CONTRACT_CALL_AGGREGATION_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
    }
}
