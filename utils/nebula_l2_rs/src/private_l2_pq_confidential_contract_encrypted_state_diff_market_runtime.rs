use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractEncryptedStateDiffMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STATE_DIFF_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-encrypted-state-diff-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STATE_DIFF_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_DIFF_SUITE: &str =
    "ml-kem-1024+xwing-confidential-contract-encrypted-state-diff-v1";
pub const WITNESS_CHUNK_SUITE: &str = "threshold-ml-kem-1024-encrypted-contract-witness-chunk-v1";
pub const PQ_EXECUTION_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-contract-execution-attestation-v1";
pub const FAST_SETTLEMENT_LANE_SUITE: &str =
    "private-l2-fast-confidential-contract-state-diff-settlement-lane-v1";
pub const LOW_FEE_REUSE_SUITE: &str =
    "private-l2-low-fee-encrypted-state-diff-data-reuse-ticket-v1";
pub const SELECTIVE_DISCLOSURE_SUITE: &str =
    "private-l2-selective-contract-state-diff-disclosure-ticket-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "privacy-budgeted-redacted-operator-state-diff-market-summary-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "operator-safe-encrypted-state-diff-market-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_976_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_642_000;
pub const DEVNET_EPOCH: u64 = 13_104;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_DIFF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CHUNK_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_REUSE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_FAST_LANE_TARGET_MS: u64 = 450;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_REUSE_REBATE_BPS: u64 = 6;
pub const DEFAULT_FAST_LANE_PREMIUM_BPS: u64 = 18;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_BUDGET_BPS: u64 = 380;
pub const DEFAULT_MAX_DIFF_MARKETS: usize = 262_144;
pub const DEFAULT_MAX_ENCRYPTED_DIFFS: usize = 4_194_304;
pub const DEFAULT_MAX_WITNESS_CHUNKS: usize = 8_388_608;
pub const DEFAULT_MAX_BUYER_ORDERS: usize = 4_194_304;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffMarketKind {
    ContractStorage,
    PrivateCallTrace,
    FheSlotDelta,
    TokenBalanceDelta,
    OracleCallbackDelta,
    DefiPositionDelta,
    BridgeReserveDelta,
    GovernanceSecretDelta,
}

impl DiffMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStorage => "contract_storage",
            Self::PrivateCallTrace => "private_call_trace",
            Self::FheSlotDelta => "fhe_slot_delta",
            Self::TokenBalanceDelta => "token_balance_delta",
            Self::OracleCallbackDelta => "oracle_callback_delta",
            Self::DefiPositionDelta => "defi_position_delta",
            Self::BridgeReserveDelta => "bridge_reserve_delta",
            Self::GovernanceSecretDelta => "governance_secret_delta",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Warm,
    Saturated,
    Settling,
    Suspended,
    Retired,
}

impl MarketStatus {
    pub fn accepts_supply(self) -> bool {
        matches!(self, Self::Open | Self::Warm | Self::Saturated)
    }

    pub fn accepts_orders(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Warm | Self::Saturated | Self::Settling
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warm => "warm",
            Self::Saturated => "saturated",
            Self::Settling => "settling",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Supplied,
    Chunked,
    Attested,
    Ordered,
    Settling,
    Settled,
    Disclosed,
    Expired,
    Slashed,
}

impl DiffStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Supplied | Self::Chunked | Self::Attested | Self::Ordered | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Reserved,
    Uploaded,
    Available,
    Reused,
    Disclosed,
    Expired,
    Slashed,
}

impl ChunkStatus {
    pub fn reusable(self) -> bool {
        matches!(self, Self::Uploaded | Self::Available | Self::Reused)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Posted,
    PartiallyFilled,
    Filled,
    Settling,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}

impl OrderStatus {
    pub fn fillable(self) -> bool {
        matches!(self, Self::Posted | Self::PartiallyFilled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ExecutionCorrectness,
    WitnessAvailability,
    RedactionSafety,
    FastLaneEligibility,
    LowFeeReuseEligibility,
    SelectiveDisclosure,
    SettlementFinality,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Hold,
    Reject,
    Slash,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLaneKind {
    Background,
    LowFeeReuse,
    Interactive,
    Fast,
    Emergency,
}

impl SettlementLaneKind {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Background => 1,
            Self::LowFeeReuse => 2,
            Self::Interactive => 4,
            Self::Fast => 8,
            Self::Emergency => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Preconfirmed,
    Proved,
    Finalized,
    ReorgHeld,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    ClawedBack,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    DiffHeader,
    ChunkAvailability,
    ExecutionAttestation,
    FeeRebate,
    SettlementReceipt,
    OperatorSafeSummary,
    EmergencyAudit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_diff_suite: String,
    pub witness_chunk_suite: String,
    pub pq_execution_attestation_suite: String,
    pub fast_settlement_lane_suite: String,
    pub low_fee_reuse_suite: String,
    pub selective_disclosure_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub diff_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub chunk_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub reuse_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub fast_lane_target_ms: u64,
    pub max_user_fee_bps: u64,
    pub reuse_rebate_bps: u64,
    pub fast_lane_premium_bps: u64,
    pub redaction_epoch_blocks: u64,
    pub redaction_budget_bps: u64,
    pub max_diff_markets: usize,
    pub max_encrypted_diffs: usize,
    pub max_witness_chunks: usize,
    pub max_buyer_orders: usize,
    pub max_pq_attestations: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub deterministic_roots_required: bool,
    pub redact_operator_metadata_by_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_diff_suite: ENCRYPTED_DIFF_SUITE.to_string(),
            witness_chunk_suite: WITNESS_CHUNK_SUITE.to_string(),
            pq_execution_attestation_suite: PQ_EXECUTION_ATTESTATION_SUITE.to_string(),
            fast_settlement_lane_suite: FAST_SETTLEMENT_LANE_SUITE.to_string(),
            low_fee_reuse_suite: LOW_FEE_REUSE_SUITE.to_string(),
            selective_disclosure_suite: SELECTIVE_DISCLOSURE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            diff_ttl_blocks: DEFAULT_DIFF_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            chunk_ttl_blocks: DEFAULT_CHUNK_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            reuse_ttl_blocks: DEFAULT_REUSE_TTL_BLOCKS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            fast_lane_target_ms: DEFAULT_FAST_LANE_TARGET_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            reuse_rebate_bps: DEFAULT_REUSE_REBATE_BPS,
            fast_lane_premium_bps: DEFAULT_FAST_LANE_PREMIUM_BPS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            redaction_budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
            max_diff_markets: DEFAULT_MAX_DIFF_MARKETS,
            max_encrypted_diffs: DEFAULT_MAX_ENCRYPTED_DIFFS,
            max_witness_chunks: DEFAULT_MAX_WITNESS_CHUNKS,
            max_buyer_orders: DEFAULT_MAX_BUYER_ORDERS,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            deterministic_roots_required: true,
            redact_operator_metadata_by_default: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_encrypted_state_diff_market_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "encrypted_diff_suite": self.encrypted_diff_suite,
            "witness_chunk_suite": self.witness_chunk_suite,
            "pq_execution_attestation_suite": self.pq_execution_attestation_suite,
            "fast_settlement_lane_suite": self.fast_settlement_lane_suite,
            "low_fee_reuse_suite": self.low_fee_reuse_suite,
            "selective_disclosure_suite": self.selective_disclosure_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "operator_summary_suite": self.operator_summary_suite,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "diff_ttl_blocks": self.diff_ttl_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "chunk_ttl_blocks": self.chunk_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "reuse_ttl_blocks": self.reuse_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "fast_lane_target_ms": self.fast_lane_target_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "reuse_rebate_bps": self.reuse_rebate_bps,
            "fast_lane_premium_bps": self.fast_lane_premium_bps,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "redaction_budget_bps": self.redaction_budget_bps,
            "max_diff_markets": self.max_diff_markets,
            "max_encrypted_diffs": self.max_encrypted_diffs,
            "max_witness_chunks": self.max_witness_chunks,
            "max_buyer_orders": self.max_buyer_orders,
            "max_pq_attestations": self.max_pq_attestations,
            "max_settlements": self.max_settlements,
            "max_rebates": self.max_rebates,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_operator_summaries": self.max_operator_summaries,
            "deterministic_roots_required": self.deterministic_roots_required,
            "redact_operator_metadata_by_default": self.redact_operator_metadata_by_default,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub diff_markets_open: u64,
    pub encrypted_diffs_live: u64,
    pub encrypted_diffs_settled: u64,
    pub witness_chunks_available: u64,
    pub buyer_orders_fillable: u64,
    pub buyer_orders_settled: u64,
    pub pq_attestations_accepted: u64,
    pub fast_settlements_finalized: u64,
    pub low_fee_reuse_tickets: u64,
    pub rebates_paid: u64,
    pub redaction_budgets_active: u64,
    pub operator_summaries_redacted: u64,
    pub total_diff_bytes: u64,
    pub total_reused_bytes: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub diff_market_root: String,
    pub encrypted_diff_root: String,
    pub witness_chunk_root: String,
    pub buyer_order_root: String,
    pub pq_attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub reuse_ticket_root: String,
    pub selective_disclosure_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            diff_market_root: empty_root("diff-markets"),
            encrypted_diff_root: empty_root("encrypted-diffs"),
            witness_chunk_root: empty_root("witness-chunks"),
            buyer_order_root: empty_root("buyer-orders"),
            pq_attestation_root: empty_root("pq-attestations"),
            settlement_root: empty_root("settlements"),
            rebate_root: empty_root("rebates"),
            reuse_ticket_root: empty_root("reuse-tickets"),
            selective_disclosure_root: empty_root("selective-disclosures"),
            redaction_budget_root: empty_root("redaction-budgets"),
            operator_summary_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiffMarket {
    pub market_id: String,
    pub contract_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub kind: DiffMarketKind,
    pub status: MarketStatus,
    pub base_state_root: String,
    pub target_state_root: String,
    pub ask_fee_micro_units: u64,
    pub available_diff_bytes: u64,
    pub reused_diff_bytes: u64,
    pub min_privacy_set_size: u64,
    pub pq_key_commitment: String,
    pub redaction_policy_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl DiffMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "contract_id": self.contract_id,
            "shard_id": self.shard_id,
            "operator_id": redacted_operator(&self.operator_id),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "base_state_root": self.base_state_root,
            "target_state_root": self.target_state_root,
            "ask_fee_micro_units": self.ask_fee_micro_units,
            "available_diff_bytes": self.available_diff_bytes,
            "reused_diff_bytes": self.reused_diff_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_key_commitment": self.pq_key_commitment,
            "redaction_policy_root": self.redaction_policy_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateDiff {
    pub diff_id: String,
    pub market_id: String,
    pub supplier_id: String,
    pub contract_id: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub encrypted_diff_root: String,
    pub encrypted_metadata_root: String,
    pub witness_manifest_root: String,
    pub nullifier_set_root: String,
    pub diff_bytes: u64,
    pub chunk_count: u64,
    pub fee_micro_units: u64,
    pub reuse_discount_bps: u64,
    pub status: DiffStatus,
    pub supplied_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedStateDiff {
    pub fn public_record(&self) -> Value {
        json!({
            "diff_id": self.diff_id,
            "market_id": self.market_id,
            "supplier_id": redacted_operator(&self.supplier_id),
            "contract_id": self.contract_id,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "encrypted_diff_root": self.encrypted_diff_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "witness_manifest_root": self.witness_manifest_root,
            "nullifier_set_root": self.nullifier_set_root,
            "diff_bytes": self.diff_bytes,
            "chunk_count": self.chunk_count,
            "fee_micro_units": self.fee_micro_units,
            "reuse_discount_bps": self.reuse_discount_bps,
            "status": self.status,
            "supplied_at_height": self.supplied_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWitnessChunk {
    pub chunk_id: String,
    pub diff_id: String,
    pub market_id: String,
    pub chunk_index: u64,
    pub encrypted_chunk_root: String,
    pub availability_commitment: String,
    pub erasure_set_root: String,
    pub ciphertext_bytes: u64,
    pub reuse_count: u64,
    pub status: ChunkStatus,
    pub uploaded_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedWitnessChunk {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuyerOrder {
    pub order_id: String,
    pub buyer_id: String,
    pub market_id: String,
    pub contract_id: String,
    pub requested_kind: DiffMarketKind,
    pub max_fee_micro_units: u64,
    pub requested_diff_bytes: u64,
    pub min_reuse_bps: u64,
    pub fast_lane_required: bool,
    pub disclosure_scope: DisclosureScope,
    pub order_commitment: String,
    pub status: OrderStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl BuyerOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "buyer_id": redacted_operator(&self.buyer_id),
            "market_id": self.market_id,
            "contract_id": self.contract_id,
            "requested_kind": self.requested_kind,
            "max_fee_micro_units": self.max_fee_micro_units,
            "requested_diff_bytes": self.requested_diff_bytes,
            "min_reuse_bps": self.min_reuse_bps,
            "fast_lane_required": self.fast_lane_required,
            "disclosure_scope": self.disclosure_scope,
            "order_commitment": self.order_commitment,
            "status": self.status,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExecutionAttestation {
    pub attestation_id: String,
    pub diff_id: String,
    pub market_id: String,
    pub attestor_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub execution_root: String,
    pub witness_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqExecutionAttestation {
    pub fn accepted(&self) -> bool {
        self.verdict == AttestationVerdict::Accept
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "diff_id": self.diff_id,
            "market_id": self.market_id,
            "attestor_id": redacted_operator(&self.attestor_id),
            "kind": self.kind,
            "verdict": self.verdict,
            "execution_root": self.execution_root,
            "witness_root": self.witness_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Settlement {
    pub settlement_id: String,
    pub order_id: String,
    pub diff_id: String,
    pub market_id: String,
    pub lane_kind: SettlementLaneKind,
    pub status: SettlementStatus,
    pub settlement_root: String,
    pub receipt_root: String,
    pub fee_micro_units: u64,
    pub fast_lane_premium_micro_units: u64,
    pub finalized_at_height: Option<u64>,
    pub queued_at_height: u64,
}

impl Settlement {
    pub fn finalized(&self) -> bool {
        self.status == SettlementStatus::Finalized
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeDataReuseTicket {
    pub ticket_id: String,
    pub chunk_id: String,
    pub diff_id: String,
    pub buyer_id: String,
    pub reusable_bytes: u64,
    pub discount_bps: u64,
    pub ticket_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeDataReuseTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "chunk_id": self.chunk_id,
            "diff_id": self.diff_id,
            "buyer_id": redacted_operator(&self.buyer_id),
            "reusable_bytes": self.reusable_bytes,
            "discount_bps": self.discount_bps,
            "ticket_commitment": self.ticket_commitment,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub order_id: String,
    pub settlement_id: String,
    pub beneficiary_id: String,
    pub status: RebateStatus,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub fee_asset_id: String,
    pub reason_root: String,
    pub earned_at_height: u64,
    pub paid_at_height: Option<u64>,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "order_id": self.order_id,
            "settlement_id": self.settlement_id,
            "beneficiary_id": redacted_operator(&self.beneficiary_id),
            "status": self.status,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "reason_root": self.reason_root,
            "earned_at_height": self.earned_at_height,
            "paid_at_height": self.paid_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureTicket {
    pub disclosure_id: String,
    pub diff_id: String,
    pub order_id: String,
    pub scope: DisclosureScope,
    pub auditor_cohort_root: String,
    pub disclosed_field_root: String,
    pub redacted_field_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureTicket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub market_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub max_redaction_bps: u64,
    pub spent_redaction_bps: u64,
    pub allowed_scopes: BTreeSet<DisclosureScope>,
    pub budget_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn remaining_bps(&self) -> u64 {
        self.max_redaction_bps
            .saturating_sub(self.spent_redaction_bps)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "market_id": self.market_id,
            "operator_id": redacted_operator(&self.operator_id),
            "epoch": self.epoch,
            "max_redaction_bps": self.max_redaction_bps,
            "spent_redaction_bps": self.spent_redaction_bps,
            "remaining_bps": self.remaining_bps(),
            "allowed_scopes": self.allowed_scopes,
            "budget_root": self.budget_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub market_id: String,
    pub epoch: u64,
    pub supplied_diff_count: u64,
    pub available_chunk_count: u64,
    pub settled_order_count: u64,
    pub fast_lane_finality_ms_p50: u64,
    pub reuse_hit_bps: u64,
    pub rebate_paid_micro_units: u64,
    pub redacted: bool,
    pub public_summary_root: String,
    pub emitted_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": redacted_operator(&self.operator_id),
            "market_id": self.market_id,
            "epoch": self.epoch,
            "supplied_diff_count": self.supplied_diff_count,
            "available_chunk_count": self.available_chunk_count,
            "settled_order_count": self.settled_order_count,
            "fast_lane_finality_ms_p50": self.fast_lane_finality_ms_p50,
            "reuse_hit_bps": self.reuse_hit_bps,
            "rebate_paid_micro_units": self.rebate_paid_micro_units,
            "redacted": self.redacted,
            "public_summary_root": self.public_summary_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub roots: Roots,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub diff_markets: BTreeMap<String, DiffMarket>,
    pub encrypted_diffs: BTreeMap<String, EncryptedStateDiff>,
    pub witness_chunks: BTreeMap<String, EncryptedWitnessChunk>,
    pub buyer_orders: BTreeMap<String, BuyerOrder>,
    pub pq_attestations: BTreeMap<String, PqExecutionAttestation>,
    pub settlements: BTreeMap<String, Settlement>,
    pub reuse_tickets: BTreeMap<String, LowFeeDataReuseTicket>,
    pub rebates: BTreeMap<String, Rebate>,
    pub selective_disclosures: BTreeMap<String, SelectiveDisclosureTicket>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub market_diff_index: BTreeMap<String, BTreeSet<String>>,
    pub diff_chunk_index: BTreeMap<String, BTreeSet<String>>,
    pub market_order_index: BTreeMap<String, BTreeSet<String>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            roots: Roots::default(),
            counters: Counters::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            diff_markets: BTreeMap::new(),
            encrypted_diffs: BTreeMap::new(),
            witness_chunks: BTreeMap::new(),
            buyer_orders: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            reuse_tickets: BTreeMap::new(),
            rebates: BTreeMap::new(),
            selective_disclosures: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            market_diff_index: BTreeMap::new(),
            diff_chunk_index: BTreeMap::new(),
            market_order_index: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let market = sample_market(
            "diff-market-devnet-contract-vault",
            "contract-confidential-vault",
            "private-shard-00",
            "operator-alpha",
            DiffMarketKind::ContractStorage,
            DEVNET_L2_HEIGHT,
        );
        let market_id = market.market_id.clone();
        state
            .insert_diff_market(market)
            .expect("valid devnet market");
        let diff_id = state
            .supply_encrypted_diff(EncryptedStateDiff {
                diff_id: "encrypted-diff-vault-0001".to_string(),
                market_id: market_id.clone(),
                supplier_id: "operator-alpha".to_string(),
                contract_id: "contract-confidential-vault".to_string(),
                read_set_root: sample_root("read-set", "vault-0001"),
                write_set_root: sample_root("write-set", "vault-0001"),
                encrypted_diff_root: sample_root("encrypted-diff", "vault-0001"),
                encrypted_metadata_root: sample_root("encrypted-metadata", "vault-0001"),
                witness_manifest_root: sample_root("witness-manifest", "vault-0001"),
                nullifier_set_root: sample_root("nullifier-set", "vault-0001"),
                diff_bytes: 196_608,
                chunk_count: 3,
                fee_micro_units: 920,
                reuse_discount_bps: 360,
                status: DiffStatus::Supplied,
                supplied_at_height: DEVNET_L2_HEIGHT - 4,
                expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_DIFF_TTL_BLOCKS,
            })
            .expect("valid devnet diff");
        for index in 0..3 {
            state
                .insert_witness_chunk(sample_chunk(&diff_id, &market_id, index, DEVNET_L2_HEIGHT))
                .expect("valid devnet chunk");
        }
        let order_id = state
            .post_buyer_order(BuyerOrder {
                order_id: "buyer-order-fast-vault-0001".to_string(),
                buyer_id: "buyer-beta".to_string(),
                market_id: market_id.clone(),
                contract_id: "contract-confidential-vault".to_string(),
                requested_kind: DiffMarketKind::ContractStorage,
                max_fee_micro_units: 1_200,
                requested_diff_bytes: 131_072,
                min_reuse_bps: 250,
                fast_lane_required: true,
                disclosure_scope: DisclosureScope::SettlementReceipt,
                order_commitment: sample_root("order", "fast-vault-0001"),
                status: OrderStatus::Posted,
                posted_at_height: DEVNET_L2_HEIGHT - 2,
                expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_ORDER_TTL_BLOCKS,
            })
            .expect("valid devnet order");
        state
            .attach_pq_attestation(sample_attestation(&diff_id, &market_id, DEVNET_L2_HEIGHT))
            .expect("valid devnet attestation");
        let settlement_id = state
            .queue_settlement(Settlement {
                settlement_id: "settlement-fast-vault-0001".to_string(),
                order_id: order_id.clone(),
                diff_id: diff_id.clone(),
                market_id: market_id.clone(),
                lane_kind: SettlementLaneKind::Fast,
                status: SettlementStatus::Finalized,
                settlement_root: sample_root("settlement", "fast-vault-0001"),
                receipt_root: sample_root("receipt", "fast-vault-0001"),
                fee_micro_units: 1_086,
                fast_lane_premium_micro_units: 18,
                finalized_at_height: Some(DEVNET_L2_HEIGHT),
                queued_at_height: DEVNET_L2_HEIGHT - 1,
            })
            .expect("valid devnet settlement");
        state
            .issue_reuse_ticket(LowFeeDataReuseTicket {
                ticket_id: "reuse-ticket-vault-chunk-0".to_string(),
                chunk_id: "chunk-encrypted-diff-vault-0001-0".to_string(),
                diff_id: diff_id.clone(),
                buyer_id: "buyer-beta".to_string(),
                reusable_bytes: 65_536,
                discount_bps: 360,
                ticket_commitment: sample_root("reuse-ticket", "vault-chunk-0"),
                issued_at_height: DEVNET_L2_HEIGHT,
                expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_REUSE_TTL_BLOCKS,
            })
            .expect("valid devnet reuse ticket");
        state
            .insert_rebate(Rebate {
                rebate_id: "rebate-fast-vault-0001".to_string(),
                order_id,
                settlement_id,
                beneficiary_id: "buyer-beta".to_string(),
                status: RebateStatus::Paid,
                rebate_bps: DEFAULT_REUSE_REBATE_BPS,
                rebate_micro_units: 64,
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                reason_root: sample_root("rebate-reason", "fast-vault-0001"),
                earned_at_height: DEVNET_L2_HEIGHT,
                paid_at_height: Some(DEVNET_L2_HEIGHT),
            })
            .expect("valid devnet rebate");
        state
            .insert_selective_disclosure(SelectiveDisclosureTicket {
                disclosure_id: "disclosure-vault-operator-safe".to_string(),
                diff_id: diff_id.clone(),
                order_id: "buyer-order-fast-vault-0001".to_string(),
                scope: DisclosureScope::OperatorSafeSummary,
                auditor_cohort_root: sample_root("auditor-cohort", "vault"),
                disclosed_field_root: sample_root("disclosed-fields", "vault"),
                redacted_field_root: sample_root("redacted-fields", "vault"),
                issued_at_height: DEVNET_L2_HEIGHT,
                expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_DISCLOSURE_TTL_BLOCKS,
            })
            .expect("valid devnet disclosure");
        state
            .insert_redaction_budget(sample_redaction_budget(
                &market_id,
                DEVNET_EPOCH,
                DEVNET_L2_HEIGHT,
            ))
            .expect("valid devnet redaction budget");
        state
            .insert_operator_summary(sample_operator_summary(
                &market_id,
                DEVNET_EPOCH,
                DEVNET_L2_HEIGHT,
            ))
            .expect("valid devnet operator summary");
        state.refresh_roots();
        state
    }

    pub fn insert_diff_market(&mut self, market: DiffMarket) -> Result<()> {
        ensure!(!market.market_id.trim().is_empty(), "market_id is required");
        ensure!(
            market.min_privacy_set_size >= self.config.min_privacy_set_size,
            "market privacy set is below runtime minimum"
        );
        if self.diff_markets.len() >= self.config.max_diff_markets
            && !self.diff_markets.contains_key(&market.market_id)
        {
            return Err("diff market capacity exceeded".to_string());
        }
        self.market_diff_index
            .entry(market.market_id.clone())
            .or_default();
        self.market_order_index
            .entry(market.market_id.clone())
            .or_default();
        self.diff_markets.insert(market.market_id.clone(), market);
        self.refresh_roots();
        Ok(())
    }

    pub fn supply_encrypted_diff(&mut self, mut diff: EncryptedStateDiff) -> Result<String> {
        ensure!(!diff.diff_id.trim().is_empty(), "diff_id is required");
        let market = self
            .diff_markets
            .get_mut(&diff.market_id)
            .ok_or_else(|| format!("unknown diff market {}", diff.market_id))?;
        ensure!(
            market.status.accepts_supply(),
            "market {} is not accepting diff supply",
            diff.market_id
        );
        ensure!(
            diff.reuse_discount_bps <= MAX_BPS,
            "reuse discount exceeds max bps"
        );
        if self.encrypted_diffs.len() >= self.config.max_encrypted_diffs
            && !self.encrypted_diffs.contains_key(&diff.diff_id)
        {
            return Err("encrypted diff capacity exceeded".to_string());
        }
        if diff.expires_at_height == 0 {
            diff.expires_at_height = self.l2_height + self.config.diff_ttl_blocks;
        }
        market.available_diff_bytes = market.available_diff_bytes.saturating_add(diff.diff_bytes);
        market.updated_at_height = self.l2_height;
        let diff_id = diff.diff_id.clone();
        self.market_diff_index
            .entry(diff.market_id.clone())
            .or_default()
            .insert(diff_id.clone());
        self.diff_chunk_index.entry(diff_id.clone()).or_default();
        self.encrypted_diffs.insert(diff_id.clone(), diff);
        self.refresh_roots();
        Ok(diff_id)
    }

    pub fn insert_witness_chunk(&mut self, chunk: EncryptedWitnessChunk) -> Result<()> {
        ensure!(!chunk.chunk_id.trim().is_empty(), "chunk_id is required");
        ensure!(
            self.encrypted_diffs.contains_key(&chunk.diff_id),
            "unknown diff {}",
            chunk.diff_id
        );
        if self.witness_chunks.len() >= self.config.max_witness_chunks
            && !self.witness_chunks.contains_key(&chunk.chunk_id)
        {
            return Err("witness chunk capacity exceeded".to_string());
        }
        self.diff_chunk_index
            .entry(chunk.diff_id.clone())
            .or_default()
            .insert(chunk.chunk_id.clone());
        if let Some(diff) = self.encrypted_diffs.get_mut(&chunk.diff_id) {
            if diff.status == DiffStatus::Supplied {
                diff.status = DiffStatus::Chunked;
            }
        }
        self.witness_chunks.insert(chunk.chunk_id.clone(), chunk);
        self.refresh_roots();
        Ok(())
    }

    pub fn post_buyer_order(&mut self, order: BuyerOrder) -> Result<String> {
        ensure!(!order.order_id.trim().is_empty(), "order_id is required");
        let market = self
            .diff_markets
            .get(&order.market_id)
            .ok_or_else(|| format!("unknown diff market {}", order.market_id))?;
        ensure!(
            market.status.accepts_orders(),
            "market {} is not accepting buyer orders",
            order.market_id
        );
        ensure!(
            order.min_reuse_bps <= MAX_BPS,
            "min reuse bps exceeds max bps"
        );
        if self.buyer_orders.len() >= self.config.max_buyer_orders
            && !self.buyer_orders.contains_key(&order.order_id)
        {
            return Err("buyer order capacity exceeded".to_string());
        }
        let order_id = order.order_id.clone();
        self.market_order_index
            .entry(order.market_id.clone())
            .or_default()
            .insert(order_id.clone());
        self.buyer_orders.insert(order_id.clone(), order);
        self.refresh_roots();
        Ok(order_id)
    }

    pub fn attach_pq_attestation(&mut self, attestation: PqExecutionAttestation) -> Result<()> {
        ensure!(
            !attestation.attestation_id.trim().is_empty(),
            "attestation_id is required"
        );
        ensure!(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "pq security bits below runtime minimum"
        );
        ensure!(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below runtime minimum"
        );
        ensure!(
            self.encrypted_diffs.contains_key(&attestation.diff_id),
            "unknown diff {}",
            attestation.diff_id
        );
        if self.pq_attestations.len() >= self.config.max_pq_attestations
            && !self
                .pq_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("pq attestation capacity exceeded".to_string());
        }
        if attestation.accepted() {
            if let Some(diff) = self.encrypted_diffs.get_mut(&attestation.diff_id) {
                diff.status = DiffStatus::Attested;
            }
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_settlement(&mut self, settlement: Settlement) -> Result<String> {
        ensure!(
            !settlement.settlement_id.trim().is_empty(),
            "settlement_id is required"
        );
        ensure!(
            self.buyer_orders.contains_key(&settlement.order_id),
            "unknown order {}",
            settlement.order_id
        );
        ensure!(
            self.encrypted_diffs.contains_key(&settlement.diff_id),
            "unknown diff {}",
            settlement.diff_id
        );
        if self.settlements.len() >= self.config.max_settlements
            && !self.settlements.contains_key(&settlement.settlement_id)
        {
            return Err("settlement capacity exceeded".to_string());
        }
        if let Some(order) = self.buyer_orders.get_mut(&settlement.order_id) {
            order.status = if settlement.finalized() {
                OrderStatus::Settled
            } else {
                OrderStatus::Settling
            };
        }
        if let Some(diff) = self.encrypted_diffs.get_mut(&settlement.diff_id) {
            diff.status = if settlement.finalized() {
                DiffStatus::Settled
            } else {
                DiffStatus::Settling
            };
        }
        let settlement_id = settlement.settlement_id.clone();
        self.settlements.insert(settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_reuse_ticket(&mut self, ticket: LowFeeDataReuseTicket) -> Result<()> {
        ensure!(
            self.witness_chunks.contains_key(&ticket.chunk_id),
            "unknown chunk {}",
            ticket.chunk_id
        );
        ensure!(
            ticket.discount_bps <= MAX_BPS,
            "reuse discount exceeds max bps"
        );
        if self.reuse_tickets.len() >= self.config.max_rebates
            && !self.reuse_tickets.contains_key(&ticket.ticket_id)
        {
            return Err("reuse ticket capacity exceeded".to_string());
        }
        if let Some(chunk) = self.witness_chunks.get_mut(&ticket.chunk_id) {
            chunk.reuse_count = chunk.reuse_count.saturating_add(1);
            chunk.status = ChunkStatus::Reused;
        }
        if let Some(market) = self.diff_markets.get_mut(
            self.encrypted_diffs
                .get(&ticket.diff_id)
                .map(|diff| diff.market_id.as_str())
                .unwrap_or_default(),
        ) {
            market.reused_diff_bytes = market
                .reused_diff_bytes
                .saturating_add(ticket.reusable_bytes);
        }
        self.reuse_tickets.insert(ticket.ticket_id.clone(), ticket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_rebate(&mut self, rebate: Rebate) -> Result<()> {
        ensure!(rebate.rebate_bps <= MAX_BPS, "rebate bps exceeds max bps");
        if self.rebates.len() >= self.config.max_rebates
            && !self.rebates.contains_key(&rebate.rebate_id)
        {
            return Err("rebate capacity exceeded".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_selective_disclosure(&mut self, ticket: SelectiveDisclosureTicket) -> Result<()> {
        ensure!(
            self.encrypted_diffs.contains_key(&ticket.diff_id),
            "unknown diff {}",
            ticket.diff_id
        );
        self.selective_disclosures
            .insert(ticket.disclosure_id.clone(), ticket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            budget.max_redaction_bps <= self.config.redaction_budget_bps,
            "redaction budget exceeds runtime cap"
        );
        if self.redaction_budgets.len() >= self.config.max_redaction_budgets
            && !self.redaction_budgets.contains_key(&budget.budget_id)
        {
            return Err("redaction budget capacity exceeded".to_string());
        }
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        if self.operator_summaries.len() >= self.config.max_operator_summaries
            && !self.operator_summaries.contains_key(&summary.summary_id)
        {
            return Err("operator summary capacity exceeded".to_string());
        }
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_encrypted_state_diff_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "mode": self.config.mode.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "diff_market_root": self.roots.diff_market_root,
                "encrypted_diff_root": self.roots.encrypted_diff_root,
                "witness_chunk_root": self.roots.witness_chunk_root,
                "buyer_order_root": self.roots.buyer_order_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "settlement_root": self.roots.settlement_root,
                "rebate_root": self.roots.rebate_root,
                "reuse_ticket_root": self.roots.reuse_ticket_root,
                "selective_disclosure_root": self.roots.selective_disclosure_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "counters_root": self.roots.counters_root,
            },
            "diff_market_count": self.diff_markets.len(),
            "encrypted_diff_count": self.encrypted_diffs.len(),
            "witness_chunk_count": self.witness_chunks.len(),
            "buyer_order_count": self.buyer_orders.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "settlement_count": self.settlements.len(),
            "reuse_ticket_count": self.reuse_tickets.len(),
            "rebate_count": self.rebates.len(),
            "selective_disclosure_count": self.selective_disclosures.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_safe_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.config_root = deterministic_record_root("config", &self.config.public_record());
        self.roots.diff_market_root = public_record_root(
            "diff-markets",
            &values_record(&self.diff_markets, DiffMarket::public_record),
        );
        self.roots.encrypted_diff_root = public_record_root(
            "encrypted-diffs",
            &values_record(&self.encrypted_diffs, EncryptedStateDiff::public_record),
        );
        self.roots.witness_chunk_root = public_record_root(
            "witness-chunks",
            &values_record(&self.witness_chunks, EncryptedWitnessChunk::public_record),
        );
        self.roots.buyer_order_root = public_record_root(
            "buyer-orders",
            &values_record(&self.buyer_orders, BuyerOrder::public_record),
        );
        self.roots.pq_attestation_root = public_record_root(
            "pq-attestations",
            &values_record(&self.pq_attestations, PqExecutionAttestation::public_record),
        );
        self.roots.settlement_root = public_record_root(
            "settlements",
            &values_record(&self.settlements, Settlement::public_record),
        );
        self.roots.rebate_root = public_record_root(
            "rebates",
            &values_record(&self.rebates, Rebate::public_record),
        );
        self.roots.reuse_ticket_root = public_record_root(
            "reuse-tickets",
            &values_record(&self.reuse_tickets, LowFeeDataReuseTicket::public_record),
        );
        self.roots.selective_disclosure_root = public_record_root(
            "selective-disclosures",
            &values_record(
                &self.selective_disclosures,
                SelectiveDisclosureTicket::public_record,
            ),
        );
        self.roots.redaction_budget_root = public_record_root(
            "redaction-budgets",
            &values_record(&self.redaction_budgets, RedactionBudget::public_record),
        );
        self.roots.operator_summary_root = public_record_root(
            "operator-summaries",
            &values_record(&self.operator_summaries, OperatorSummary::public_record),
        );
        self.roots.counters_root =
            deterministic_record_root("counters", &self.counters.public_record());
        self.roots.state_root = self.state_root();
    }

    fn derive_counters(&self) -> Counters {
        Counters {
            diff_markets_open: self
                .diff_markets
                .values()
                .filter(|market| market.status.accepts_orders())
                .count() as u64,
            encrypted_diffs_live: self
                .encrypted_diffs
                .values()
                .filter(|diff| diff.status.live())
                .count() as u64,
            encrypted_diffs_settled: self
                .encrypted_diffs
                .values()
                .filter(|diff| diff.status == DiffStatus::Settled)
                .count() as u64,
            witness_chunks_available: self
                .witness_chunks
                .values()
                .filter(|chunk| chunk.status.reusable())
                .count() as u64,
            buyer_orders_fillable: self
                .buyer_orders
                .values()
                .filter(|order| order.status.fillable())
                .count() as u64,
            buyer_orders_settled: self
                .buyer_orders
                .values()
                .filter(|order| order.status == OrderStatus::Settled)
                .count() as u64,
            pq_attestations_accepted: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.accepted())
                .count() as u64,
            fast_settlements_finalized: self
                .settlements
                .values()
                .filter(|settlement| {
                    settlement.finalized()
                        && matches!(
                            settlement.lane_kind,
                            SettlementLaneKind::Fast | SettlementLaneKind::Emergency
                        )
                })
                .count() as u64,
            low_fee_reuse_tickets: self.reuse_tickets.len() as u64,
            rebates_paid: self
                .rebates
                .values()
                .filter(|rebate| rebate.status == RebateStatus::Paid)
                .count() as u64,
            redaction_budgets_active: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.active_at(self.l2_height))
                .count() as u64,
            operator_summaries_redacted: self
                .operator_summaries
                .values()
                .filter(|summary| summary.redacted)
                .count() as u64,
            total_diff_bytes: self
                .encrypted_diffs
                .values()
                .map(|diff| diff.diff_bytes)
                .sum(),
            total_reused_bytes: self
                .reuse_tickets
                .values()
                .map(|ticket| ticket.reusable_bytes)
                .sum(),
            total_fee_micro_units: self
                .settlements
                .values()
                .map(|settlement| settlement.fee_micro_units)
                .sum(),
            total_rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:{domain}-ROOT"),
        records,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn redacted_operator(operator_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:REDACTED-OPERATOR",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(operator_id)],
        16,
    )
}

fn sample_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-STATE-DIFF-MARKET:SAMPLE:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(seed)],
        32,
    )
}

fn sample_market(
    market_id: &str,
    contract_id: &str,
    shard_id: &str,
    operator_id: &str,
    kind: DiffMarketKind,
    height: u64,
) -> DiffMarket {
    DiffMarket {
        market_id: market_id.to_string(),
        contract_id: contract_id.to_string(),
        shard_id: shard_id.to_string(),
        operator_id: operator_id.to_string(),
        kind,
        status: MarketStatus::Warm,
        base_state_root: sample_root("base-state", market_id),
        target_state_root: sample_root("target-state", market_id),
        ask_fee_micro_units: 900,
        available_diff_bytes: 0,
        reused_diff_bytes: 0,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_key_commitment: sample_root("pq-key", operator_id),
        redaction_policy_root: sample_root("redaction-policy", market_id),
        opened_at_height: height.saturating_sub(144),
        updated_at_height: height,
    }
}

fn sample_chunk(
    diff_id: &str,
    market_id: &str,
    chunk_index: u64,
    height: u64,
) -> EncryptedWitnessChunk {
    EncryptedWitnessChunk {
        chunk_id: format!("chunk-{diff_id}-{chunk_index}"),
        diff_id: diff_id.to_string(),
        market_id: market_id.to_string(),
        chunk_index,
        encrypted_chunk_root: sample_root("encrypted-chunk", &format!("{diff_id}-{chunk_index}")),
        availability_commitment: sample_root("availability", &format!("{diff_id}-{chunk_index}")),
        erasure_set_root: sample_root("erasure-set", &format!("{diff_id}-{chunk_index}")),
        ciphertext_bytes: 65_536,
        reuse_count: 0,
        status: ChunkStatus::Available,
        uploaded_at_height: height.saturating_sub(3),
        expires_at_height: height + DEFAULT_CHUNK_TTL_BLOCKS,
    }
}

fn sample_attestation(diff_id: &str, market_id: &str, height: u64) -> PqExecutionAttestation {
    PqExecutionAttestation {
        attestation_id: "pq-attestation-vault-0001".to_string(),
        diff_id: diff_id.to_string(),
        market_id: market_id.to_string(),
        attestor_id: "attestor-gamma".to_string(),
        kind: AttestationKind::ExecutionCorrectness,
        verdict: AttestationVerdict::Accept,
        execution_root: sample_root("execution", diff_id),
        witness_root: sample_root("witness", diff_id),
        pq_signature_root: sample_root("pq-signature", diff_id),
        transcript_root: sample_root("transcript", diff_id),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        issued_at_height: height.saturating_sub(1),
        expires_at_height: height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_redaction_budget(market_id: &str, epoch: u64, height: u64) -> RedactionBudget {
    let mut allowed_scopes = BTreeSet::new();
    allowed_scopes.insert(DisclosureScope::OperatorSafeSummary);
    allowed_scopes.insert(DisclosureScope::SettlementReceipt);
    RedactionBudget {
        budget_id: "redaction-budget-vault-epoch".to_string(),
        market_id: market_id.to_string(),
        operator_id: "operator-alpha".to_string(),
        epoch,
        max_redaction_bps: DEFAULT_REDACTION_BUDGET_BPS,
        spent_redaction_bps: 92,
        allowed_scopes,
        budget_root: sample_root("redaction-budget", market_id),
        opened_at_height: height.saturating_sub(DEFAULT_REDACTION_EPOCH_BLOCKS / 2),
        expires_at_height: height + DEFAULT_REDACTION_EPOCH_BLOCKS,
    }
}

fn sample_operator_summary(market_id: &str, epoch: u64, height: u64) -> OperatorSummary {
    OperatorSummary {
        summary_id: "operator-summary-vault-epoch".to_string(),
        operator_id: "operator-alpha".to_string(),
        market_id: market_id.to_string(),
        epoch,
        supplied_diff_count: 1,
        available_chunk_count: 3,
        settled_order_count: 1,
        fast_lane_finality_ms_p50: 392,
        reuse_hit_bps: 3_333,
        rebate_paid_micro_units: 64,
        redacted: true,
        public_summary_root: sample_root("operator-summary", market_id),
        emitted_at_height: height,
    }
}
