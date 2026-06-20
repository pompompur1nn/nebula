use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-netting-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTER_SUITE: &str =
    "pq-confidential-contract-sealed-storage-receipt-fee-netting-router-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-storage-receipt-fee-netting-router-public-record-v1";
pub const ROUTER_PLAN_SCHEME: &str = "sealed-storage-receipt-fee-netting-router-plan-root-v1";
pub const ROUTER_EDGE_SCHEME: &str = "sealed-storage-receipt-fee-netting-router-edge-root-v1";
pub const ROUTED_RECEIPT_SCHEME: &str = "sealed-storage-receipt-fee-netting-routed-receipt-root-v1";
pub const NETTING_INTENT_SCHEME: &str =
    "confidential-contract-sealed-storage-netting-intent-root-v1";
pub const LIQUIDITY_HINT_SCHEME: &str =
    "confidential-contract-sealed-storage-fee-liquidity-hint-root-v1";
pub const ROUTER_QUOTE_SCHEME: &str = "low-fee-confidential-receipt-netting-router-quote-root-v1";
pub const ROUTER_ATTESTATION_SCHEME: &str =
    "pq-confidential-receipt-netting-router-attestation-root-v1";
pub const ROUTER_BATCH_SCHEME: &str = "fast-confidential-receipt-netting-router-batch-root-v1";
pub const REPLAY_GUARD_SCHEME: &str = "confidential-receipt-netting-router-replay-guard-root-v1";
pub const SETTLEMENT_TRACK_SCHEME: &str =
    "confidential-contract-receipt-netting-router-settlement-track-root-v1";
pub const FEE_LEDGER_SCHEME: &str =
    "confidential-contract-receipt-netting-router-fee-ledger-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "netting-router-privacy-pq-policy-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str =
    "storage-receipt-netting-router-roots-only-public-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 6_021_888;
pub const DEVNET_EPOCH: u64 = 11_761;
pub const DEFAULT_ROUTE_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_ROUTE_HOPS: u8 = 4;
pub const DEFAULT_MAX_ROUTER_EDGES: usize = 32_768;
pub const DEFAULT_MAX_ROUTED_RECEIPTS_PER_PLAN: usize = 16_384;
pub const DEFAULT_MAX_INTENTS_PER_PLAN: usize = 12_288;
pub const DEFAULT_MAX_QUOTES_PER_PLAN: usize = 8_192;
pub const DEFAULT_MAX_BATCH_MATCHES: usize = 6_144;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 8_388_608;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT: u64 = 98_304;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_ROUTER_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_ROUTER_REBATE_BPS: u64 = 22;
pub const DEFAULT_HOP_COMPRESSION_REBATE_BPS: u64 = 11;
pub const DEFAULT_CONGESTION_FEE_BPS: u64 = 4;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_400;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterLane {
    ContractExecution,
    DefiRouter,
    BridgeExit,
    BridgeEntry,
    OracleRefresh,
    GovernanceAction,
    AccountRecovery,
    EmergencyStorage,
    PayrollStream,
    CrossShardSync,
    BatchMaintenance,
}

impl RouterLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractExecution => "contract_execution",
            Self::DefiRouter => "defi_router",
            Self::BridgeExit => "bridge_exit",
            Self::BridgeEntry => "bridge_entry",
            Self::OracleRefresh => "oracle_refresh",
            Self::GovernanceAction => "governance_action",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyStorage => "emergency_storage",
            Self::PayrollStream => "payroll_stream",
            Self::CrossShardSync => "cross_shard_sync",
            Self::BatchMaintenance => "batch_maintenance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyStorage => 10_000,
            Self::AccountRecovery => 9_850,
            Self::BridgeExit => 9_550,
            Self::BridgeEntry => 9_350,
            Self::CrossShardSync => 9_100,
            Self::OracleRefresh => 8_950,
            Self::DefiRouter => 8_750,
            Self::ContractExecution => 8_500,
            Self::PayrollStream => 8_200,
            Self::GovernanceAction => 8_000,
            Self::BatchMaintenance => 7_650,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterPlanStatus {
    Announced,
    AcceptingReceipts,
    Routing,
    Quoting,
    PqAttested,
    FastSettling,
    Settled,
    Cancelled,
    Expired,
}

impl RouterPlanStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Announced | Self::AcceptingReceipts)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::AcceptingReceipts
                | Self::Routing
                | Self::Quoting
                | Self::PqAttested
                | Self::FastSettling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEdgeKind {
    LocalNetting,
    CrossContract,
    CrossShard,
    BridgeIngress,
    BridgeEgress,
    FeeSponsor,
    RebateReturn,
    RecoveryFallback,
}

impl RouteEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalNetting => "local_netting",
            Self::CrossContract => "cross_contract",
            Self::CrossShard => "cross_shard",
            Self::BridgeIngress => "bridge_ingress",
            Self::BridgeEgress => "bridge_egress",
            Self::FeeSponsor => "fee_sponsor",
            Self::RebateReturn => "rebate_return",
            Self::RecoveryFallback => "recovery_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutedReceiptStatus {
    Sealed,
    ReplayGuarded,
    IntentBound,
    Routed,
    Quoted,
    Netted,
    Settled,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl RoutedReceiptStatus {
    pub fn routable(self) -> bool {
        matches!(
            self,
            Self::ReplayGuarded | Self::IntentBound | Self::Routed | Self::Quoted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingIntentStatus {
    Pending,
    RouteLocked,
    QuoteReady,
    PartiallyNetted,
    FullyNetted,
    DustRefund,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterQuoteStatus {
    Proposed,
    FeeDeltaBound,
    LiquidityChecked,
    ExecutorAttested,
    VerifierAttested,
    QuorumReady,
    Included,
    Challenged,
    Rejected,
}

impl RouterQuoteStatus {
    pub fn settlement_ready(self) -> bool {
        matches!(
            self,
            Self::FeeDeltaBound
                | Self::LiquidityChecked
                | Self::ExecutorAttested
                | Self::VerifierAttested
                | Self::QuorumReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAttestationRole {
    RoutePlanner,
    NettingExecutor,
    ReceiptVerifier,
    LiquidityAuditor,
    PrivacySetAuditor,
    Watchtower,
}

impl RouterAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoutePlanner => "route_planner",
            Self::NettingExecutor => "netting_executor",
            Self::ReceiptVerifier => "receipt_verifier",
            Self::LiquidityAuditor => "liquidity_auditor",
            Self::PrivacySetAuditor => "privacy_set_auditor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGuardStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastRouterBatchStatus {
    Queued,
    PqQuorum,
    FastFinal,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementTrackStatus {
    Open,
    Sealed,
    FastFinal,
    Settled,
    Suspended,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub route_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_route_hops: u8,
    pub max_router_edges: usize,
    pub max_routed_receipts_per_plan: usize,
    pub max_intents_per_plan: usize,
    pub max_quotes_per_plan: usize,
    pub max_batch_matches: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub max_storage_keys_per_receipt: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_micro_fee: u64,
    pub base_micro_fee: u64,
    pub router_operator_fee_bps: u64,
    pub router_rebate_bps: u64,
    pub hop_compression_rebate_bps: u64,
    pub congestion_fee_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub prefer_low_fee_routes: bool,
    pub prefer_fast_receipt_settlement: bool,
    pub require_pq_attestations: bool,
    pub require_replay_guards: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            route_window_blocks: DEFAULT_ROUTE_WINDOW_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_route_hops: DEFAULT_MAX_ROUTE_HOPS,
            max_router_edges: DEFAULT_MAX_ROUTER_EDGES,
            max_routed_receipts_per_plan: DEFAULT_MAX_ROUTED_RECEIPTS_PER_PLAN,
            max_intents_per_plan: DEFAULT_MAX_INTENTS_PER_PLAN,
            max_quotes_per_plan: DEFAULT_MAX_QUOTES_PER_PLAN,
            max_batch_matches: DEFAULT_MAX_BATCH_MATCHES,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            max_storage_keys_per_receipt: DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            router_operator_fee_bps: DEFAULT_ROUTER_OPERATOR_FEE_BPS,
            router_rebate_bps: DEFAULT_ROUTER_REBATE_BPS,
            hop_compression_rebate_bps: DEFAULT_HOP_COMPRESSION_REBATE_BPS,
            congestion_fee_bps: DEFAULT_CONGESTION_FEE_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            prefer_low_fee_routes: true,
            prefer_fast_receipt_settlement: true,
            require_pq_attestations: true,
            require_replay_guards: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported netting router protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported netting router schema version".to_string());
        }
        if self.route_window_blocks == 0 {
            return Err("route_window_blocks must be positive".to_string());
        }
        if self.fast_settlement_blocks == 0 {
            return Err("fast_settlement_blocks must be positive".to_string());
        }
        if self.replay_window_blocks < self.route_window_blocks {
            return Err("replay_window_blocks must cover route_window_blocks".to_string());
        }
        if self.max_route_hops == 0 {
            return Err("max_route_hops must be positive".to_string());
        }
        if self.max_router_edges == 0 {
            return Err("max_router_edges must be positive".to_string());
        }
        if self.max_routed_receipts_per_plan == 0 {
            return Err("max_routed_receipts_per_plan must be positive".to_string());
        }
        if self.max_intents_per_plan == 0 {
            return Err("max_intents_per_plan must be positive".to_string());
        }
        if self.max_quotes_per_plan == 0 {
            return Err("max_quotes_per_plan must be positive".to_string());
        }
        if self.max_batch_matches == 0 {
            return Err("max_batch_matches must be positive".to_string());
        }
        if self.max_receipt_bytes_per_batch == 0 {
            return Err("max_receipt_bytes_per_batch must be positive".to_string());
        }
        if self.max_storage_keys_per_receipt == 0 {
            return Err("max_storage_keys_per_receipt must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set thresholds are invalid".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        for (name, bps) in [
            ("router_operator_fee_bps", self.router_operator_fee_bps),
            ("router_rebate_bps", self.router_rebate_bps),
            (
                "hop_compression_rebate_bps",
                self.hop_compression_rebate_bps,
            ),
            ("congestion_fee_bps", self.congestion_fee_bps),
            ("quorum_bps", self.quorum_bps),
            ("fast_finality_quorum_bps", self.fast_finality_quorum_bps),
        ] {
            if bps > MAX_BPS {
                return Err(format!("{name} exceeds MAX_BPS"));
            }
        }
        if self.fast_finality_quorum_bps < self.quorum_bps {
            return Err("fast finality quorum cannot be below base quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "route_window_blocks": self.route_window_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_route_hops": self.max_route_hops,
            "max_router_edges": self.max_router_edges,
            "max_routed_receipts_per_plan": self.max_routed_receipts_per_plan,
            "max_intents_per_plan": self.max_intents_per_plan,
            "max_quotes_per_plan": self.max_quotes_per_plan,
            "max_batch_matches": self.max_batch_matches,
            "max_receipt_bytes_per_batch": self.max_receipt_bytes_per_batch,
            "max_storage_keys_per_receipt": self.max_storage_keys_per_receipt,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_micro_fee": self.min_micro_fee,
            "base_micro_fee": self.base_micro_fee,
            "router_operator_fee_bps": self.router_operator_fee_bps,
            "router_rebate_bps": self.router_rebate_bps,
            "hop_compression_rebate_bps": self.hop_compression_rebate_bps,
            "congestion_fee_bps": self.congestion_fee_bps,
            "quorum_bps": self.quorum_bps,
            "fast_finality_quorum_bps": self.fast_finality_quorum_bps,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "prefer_low_fee_routes": self.prefer_low_fee_routes,
            "prefer_fast_receipt_settlement": self.prefer_fast_receipt_settlement,
            "require_pq_attestations": self.require_pq_attestations,
            "require_replay_guards": self.require_replay_guards,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub router_plans_opened: u64,
    pub router_edges_registered: u64,
    pub routed_receipts_submitted: u64,
    pub netting_intents_bound: u64,
    pub liquidity_hints_registered: u64,
    pub router_quotes_proposed: u64,
    pub router_attestations_recorded: u64,
    pub replay_guards_consumed: u64,
    pub fast_batches_finalized: u64,
    pub settlement_tracks_opened: u64,
    pub fee_ledger_entries_appended: u64,
    pub receipts_settled: u64,
    pub receipts_refunded: u64,
    pub receipts_repriced: u64,
    pub duplicate_receipts_rejected: u64,
    pub total_receipt_bytes_routed: u64,
    pub total_storage_keys_routed: u64,
    pub gross_micro_fees_quoted: u64,
    pub net_micro_fees_settled: u64,
    pub rebate_micro_fees_returned: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "router_plans_opened": self.router_plans_opened,
            "router_edges_registered": self.router_edges_registered,
            "routed_receipts_submitted": self.routed_receipts_submitted,
            "netting_intents_bound": self.netting_intents_bound,
            "liquidity_hints_registered": self.liquidity_hints_registered,
            "router_quotes_proposed": self.router_quotes_proposed,
            "router_attestations_recorded": self.router_attestations_recorded,
            "replay_guards_consumed": self.replay_guards_consumed,
            "fast_batches_finalized": self.fast_batches_finalized,
            "settlement_tracks_opened": self.settlement_tracks_opened,
            "fee_ledger_entries_appended": self.fee_ledger_entries_appended,
            "receipts_settled": self.receipts_settled,
            "receipts_refunded": self.receipts_refunded,
            "receipts_repriced": self.receipts_repriced,
            "duplicate_receipts_rejected": self.duplicate_receipts_rejected,
            "total_receipt_bytes_routed": self.total_receipt_bytes_routed,
            "total_storage_keys_routed": self.total_storage_keys_routed,
            "gross_micro_fees_quoted": self.gross_micro_fees_quoted,
            "net_micro_fees_settled": self.net_micro_fees_settled,
            "rebate_micro_fees_returned": self.rebate_micro_fees_returned,
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub router_plan_root: String,
    pub router_edge_root: String,
    pub routed_receipt_root: String,
    pub netting_intent_root: String,
    pub liquidity_hint_root: String,
    pub router_quote_root: String,
    pub router_attestation_root: String,
    pub router_batch_root: String,
    pub replay_guard_root: String,
    pub settlement_track_root: String,
    pub fee_ledger_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "router_plan_root": self.router_plan_root,
            "router_edge_root": self.router_edge_root,
            "routed_receipt_root": self.routed_receipt_root,
            "netting_intent_root": self.netting_intent_root,
            "liquidity_hint_root": self.liquidity_hint_root,
            "router_quote_root": self.router_quote_root,
            "router_attestation_root": self.router_attestation_root,
            "router_batch_root": self.router_batch_root,
            "replay_guard_root": self.replay_guard_root,
            "settlement_track_root": self.settlement_track_root,
            "fee_ledger_root": self.fee_ledger_root,
            "policy_root": self.policy_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterPlanInput {
    pub lane: RouterLane,
    pub source_namespace_root: String,
    pub target_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub router_committee_root: String,
    pub liquidity_hint_set_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_route_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
    pub plan_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterEdgeInput {
    pub plan_id: String,
    pub edge_kind: RouteEdgeKind,
    pub source_contract_commitment: String,
    pub target_contract_commitment: String,
    pub source_storage_root: String,
    pub target_storage_root: String,
    pub fee_asset_commitment: String,
    pub liquidity_hint_root: String,
    pub max_hops_from_source: u8,
    pub edge_weight_bps: u64,
    pub edge_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RoutedReceiptInput {
    pub plan_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub route_hint_root: String,
    pub replay_nullifier_root: String,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub receipt_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingIntentInput {
    pub plan_id: String,
    pub receipt_ids: Vec<String>,
    pub route_edge_ids: Vec<String>,
    pub aggregate_position_commitment_root: String,
    pub aggregate_fee_delta_root: String,
    pub settlement_lane_root: String,
    pub privacy_witness_root: String,
    pub intent_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LiquidityHintInput {
    pub plan_id: String,
    pub router_edge_id: String,
    pub sponsor_commitment: String,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub rebate_commitment_root: String,
    pub available_liquidity_bucket: u64,
    pub expires_height: u64,
    pub hint_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterQuoteInput {
    pub plan_id: String,
    pub intent_id: String,
    pub liquidity_hint_ids: Vec<String>,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub routed_receipt_batch_root: String,
    pub netted_fee_delta_root: String,
    pub quote_price_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub quote_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterAttestationInput {
    pub quote_id: String,
    pub role: RouterAttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_route_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastRouterBatchInput {
    pub plan_id: String,
    pub quote_ids: Vec<String>,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub aggregate_receipt_root: String,
    pub aggregate_storage_root: String,
    pub aggregate_fee_ledger_root: String,
    pub batch_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementTrackInput {
    pub batch_id: String,
    pub plan_id: String,
    pub settlement_lane_root: String,
    pub pre_settlement_root: String,
    pub post_settlement_root: String,
    pub receipt_count: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub track_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeLedgerEntryInput {
    pub settlement_track_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub router_rebate_note_commitment: String,
    pub fee_delta_commitment_root: String,
    pub accounting_delta_root: String,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub ledger_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterPlan {
    pub plan_id: String,
    pub lane: RouterLane,
    pub status: RouterPlanStatus,
    pub source_namespace_root: String,
    pub target_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub router_committee_root: String,
    pub liquidity_hint_set_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_route_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
    pub opened_height: u64,
    pub route_deadline_height: u64,
    pub fast_settlement_deadline_height: u64,
}

impl RouterPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "source_namespace_root": self.source_namespace_root,
            "target_namespace_root": self.target_namespace_root,
            "eligible_contract_set_root": self.eligible_contract_set_root,
            "router_committee_root": self.router_committee_root,
            "liquidity_hint_set_root": self.liquidity_hint_set_root,
            "target_receipt_bytes": self.target_receipt_bytes,
            "target_storage_keys": self.target_storage_keys,
            "min_route_micro_fee": self.min_route_micro_fee,
            "privacy_set_size": self.privacy_set_size,
            "pq_policy_root": self.pq_policy_root,
            "opened_height": self.opened_height,
            "route_deadline_height": self.route_deadline_height,
            "fast_settlement_deadline_height": self.fast_settlement_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTER-PLAN", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterEdge {
    pub edge_id: String,
    pub plan_id: String,
    pub edge_kind: RouteEdgeKind,
    pub source_contract_commitment: String,
    pub target_contract_commitment: String,
    pub source_storage_root: String,
    pub target_storage_root: String,
    pub fee_asset_commitment: String,
    pub liquidity_hint_root: String,
    pub max_hops_from_source: u8,
    pub edge_weight_bps: u64,
    pub opened_height: u64,
}

impl RouterEdge {
    pub fn public_record(&self) -> Value {
        json!({
            "edge_id": self.edge_id,
            "plan_id": self.plan_id,
            "edge_kind": self.edge_kind.as_str(),
            "source_contract_commitment": self.source_contract_commitment,
            "target_contract_commitment": self.target_contract_commitment,
            "source_storage_root": self.source_storage_root,
            "target_storage_root": self.target_storage_root,
            "fee_asset_commitment": self.fee_asset_commitment,
            "liquidity_hint_root": self.liquidity_hint_root,
            "max_hops_from_source": self.max_hops_from_source,
            "edge_weight_bps": self.edge_weight_bps,
            "opened_height": self.opened_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTER-EDGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RoutedReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub status: RoutedReceiptStatus,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub route_hint_root: String,
    pub replay_nullifier_root: String,
    pub quoted_micro_fee: u64,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl RoutedReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "payer_note_commitment": self.payer_note_commitment,
            "sealed_receipt_root": self.sealed_receipt_root,
            "encrypted_storage_delta_root": self.encrypted_storage_delta_root,
            "route_hint_root": self.route_hint_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "quoted_micro_fee": self.quoted_micro_fee,
            "max_micro_fee": self.max_micro_fee,
            "receipt_bytes_upper_bound": self.receipt_bytes_upper_bound,
            "storage_keys_upper_bound": self.storage_keys_upper_bound,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTED-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingIntent {
    pub intent_id: String,
    pub plan_id: String,
    pub status: NettingIntentStatus,
    pub receipt_ids: Vec<String>,
    pub route_edge_ids: Vec<String>,
    pub aggregate_position_commitment_root: String,
    pub aggregate_fee_delta_root: String,
    pub settlement_lane_root: String,
    pub privacy_witness_root: String,
    pub created_height: u64,
}

impl NettingIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "receipt_ids_root": string_list_root("INTENT-RECEIPT-IDS", &self.receipt_ids),
            "route_edge_ids_root": string_list_root("INTENT-ROUTE-EDGE-IDS", &self.route_edge_ids),
            "aggregate_position_commitment_root": self.aggregate_position_commitment_root,
            "aggregate_fee_delta_root": self.aggregate_fee_delta_root,
            "settlement_lane_root": self.settlement_lane_root,
            "privacy_witness_root": self.privacy_witness_root,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("NETTING-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LiquidityHint {
    pub hint_id: String,
    pub plan_id: String,
    pub router_edge_id: String,
    pub sponsor_commitment: String,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub rebate_commitment_root: String,
    pub available_liquidity_bucket: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl LiquidityHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "plan_id": self.plan_id,
            "router_edge_id": self.router_edge_id,
            "sponsor_commitment": self.sponsor_commitment,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "low_fee_curve_root": self.low_fee_curve_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "available_liquidity_bucket": self.available_liquidity_bucket,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LIQUIDITY-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterQuote {
    pub quote_id: String,
    pub plan_id: String,
    pub intent_id: String,
    pub status: RouterQuoteStatus,
    pub liquidity_hint_ids: Vec<String>,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub routed_receipt_batch_root: String,
    pub netted_fee_delta_root: String,
    pub quote_price_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub estimated_net_micro_fee: u64,
    pub estimated_rebate_micro_fee: u64,
    pub proposed_height: u64,
}

impl RouterQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "plan_id": self.plan_id,
            "intent_id": self.intent_id,
            "status": self.status,
            "liquidity_hint_ids_root": string_list_root("QUOTE-LIQUIDITY-HINT-IDS", &self.liquidity_hint_ids),
            "pre_storage_root": self.pre_storage_root,
            "post_storage_root": self.post_storage_root,
            "routed_receipt_batch_root": self.routed_receipt_batch_root,
            "netted_fee_delta_root": self.netted_fee_delta_root,
            "quote_price_root": self.quote_price_root,
            "receipt_bytes": self.receipt_bytes,
            "storage_keys_touched": self.storage_keys_touched,
            "gross_micro_fee": self.gross_micro_fee,
            "estimated_net_micro_fee": self.estimated_net_micro_fee,
            "estimated_rebate_micro_fee": self.estimated_rebate_micro_fee,
            "proposed_height": self.proposed_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTER-QUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouterAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub role: RouterAttestationRole,
    pub status: RouterAttestationStatus,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_route_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl RouterAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "quote_id": self.quote_id,
            "role": self.role.as_str(),
            "status": self.status,
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "attested_route_root": self.attested_route_root,
            "attested_receipt_root": self.attested_receipt_root,
            "attested_storage_root": self.attested_storage_root,
            "pq_public_key_digest": self.pq_public_key_digest,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTER-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayGuard {
    pub replay_guard_id: String,
    pub plan_id: String,
    pub receipt_id: String,
    pub replay_nullifier_root: String,
    pub status: ReplayGuardStatus,
    pub reserved_height: u64,
    pub expires_height: u64,
}

impl ReplayGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_guard_id": self.replay_guard_id,
            "plan_id": self.plan_id,
            "receipt_id": self.receipt_id,
            "replay_nullifier_root": self.replay_nullifier_root,
            "status": self.status,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("REPLAY-GUARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastRouterBatch {
    pub batch_id: String,
    pub plan_id: String,
    pub quote_ids: Vec<String>,
    pub status: FastRouterBatchStatus,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub aggregate_receipt_root: String,
    pub aggregate_storage_root: String,
    pub aggregate_fee_ledger_root: String,
    pub total_receipt_bytes: u64,
    pub total_storage_keys: u64,
    pub total_net_micro_fee: u64,
    pub finalized_height: u64,
}

impl FastRouterBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "plan_id": self.plan_id,
            "quote_ids_root": string_list_root("FAST-ROUTER-BATCH-QUOTE-IDS", &self.quote_ids),
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "settlement_lane_root": self.settlement_lane_root,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "aggregate_storage_root": self.aggregate_storage_root,
            "aggregate_fee_ledger_root": self.aggregate_fee_ledger_root,
            "total_receipt_bytes": self.total_receipt_bytes,
            "total_storage_keys": self.total_storage_keys,
            "total_net_micro_fee": self.total_net_micro_fee,
            "finalized_height": self.finalized_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAST-ROUTER-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementTrack {
    pub settlement_track_id: String,
    pub batch_id: String,
    pub plan_id: String,
    pub settlement_lane_root: String,
    pub pre_settlement_root: String,
    pub post_settlement_root: String,
    pub status: SettlementTrackStatus,
    pub receipt_count: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub opened_height: u64,
}

impl SettlementTrack {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_track_id": self.settlement_track_id,
            "batch_id": self.batch_id,
            "plan_id": self.plan_id,
            "settlement_lane_root": self.settlement_lane_root,
            "pre_settlement_root": self.pre_settlement_root,
            "post_settlement_root": self.post_settlement_root,
            "status": self.status,
            "receipt_count": self.receipt_count,
            "net_micro_fee": self.net_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "opened_height": self.opened_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-TRACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeLedgerEntry {
    pub ledger_entry_id: String,
    pub settlement_track_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub router_rebate_note_commitment: String,
    pub fee_delta_commitment_root: String,
    pub accounting_delta_root: String,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub appended_height: u64,
}

impl FeeLedgerEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "ledger_entry_id": self.ledger_entry_id,
            "settlement_track_id": self.settlement_track_id,
            "contract_commitment": self.contract_commitment,
            "payer_note_commitment": self.payer_note_commitment,
            "router_rebate_note_commitment": self.router_rebate_note_commitment,
            "fee_delta_commitment_root": self.fee_delta_commitment_root,
            "accounting_delta_root": self.accounting_delta_root,
            "receipt_count": self.receipt_count,
            "storage_keys_touched": self.storage_keys_touched,
            "gross_micro_fee": self.gross_micro_fee,
            "net_micro_fee": self.net_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "appended_height": self.appended_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-LEDGER-ENTRY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub router_plans: BTreeMap<String, RouterPlan>,
    pub router_edges: BTreeMap<String, RouterEdge>,
    pub routed_receipts: BTreeMap<String, RoutedReceipt>,
    pub netting_intents: BTreeMap<String, NettingIntent>,
    pub liquidity_hints: BTreeMap<String, LiquidityHint>,
    pub router_quotes: BTreeMap<String, RouterQuote>,
    pub router_attestations: BTreeMap<String, RouterAttestation>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub fast_batches: BTreeMap<String, FastRouterBatch>,
    pub settlement_tracks: BTreeMap<String, SettlementTrack>,
    pub fee_ledger_entries: BTreeMap<String, FeeLedgerEntry>,
    pub consumed_replay_nullifier_roots: BTreeSet<String>,
    pub policy_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            router_plans: BTreeMap::new(),
            router_edges: BTreeMap::new(),
            routed_receipts: BTreeMap::new(),
            netting_intents: BTreeMap::new(),
            liquidity_hints: BTreeMap::new(),
            router_quotes: BTreeMap::new(),
            router_attestations: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            fast_batches: BTreeMap::new(),
            settlement_tracks: BTreeMap::new(),
            fee_ledger_entries: BTreeMap::new(),
            consumed_replay_nullifier_roots: BTreeSet::new(),
            policy_roots: BTreeSet::new(),
        };
        state.policy_roots.insert(state.policy_root());
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet netting router config is valid");
        let plan_id = state
            .open_router_plan(RouterPlanInput {
                lane: RouterLane::DefiRouter,
                source_namespace_root: "storage:namespace:root:private-dex-source".to_string(),
                target_namespace_root: "storage:namespace:root:private-dex-target".to_string(),
                eligible_contract_set_root: "contract:set:root:router-eligible-defi".to_string(),
                router_committee_root: "committee:root:pq-netting-router-devnet".to_string(),
                liquidity_hint_set_root: "liquidity:hint:set:root:devnet-router".to_string(),
                target_receipt_bytes: 393_216,
                target_storage_keys: 49_152,
                min_route_micro_fee: 1,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                pq_policy_root: state.policy_root(),
                plan_nonce: 1,
            })
            .expect("devnet router plan opens");
        let edge_id = state
            .register_router_edge(RouterEdgeInput {
                plan_id: plan_id.clone(),
                edge_kind: RouteEdgeKind::LocalNetting,
                source_contract_commitment: "contract:commitment:private-dex-router".to_string(),
                target_contract_commitment: "contract:commitment:private-dex-vault".to_string(),
                source_storage_root: "storage:root:private-dex-router:before".to_string(),
                target_storage_root: "storage:root:private-dex-vault:before".to_string(),
                fee_asset_commitment: "asset:commitment:piconero-devnet".to_string(),
                liquidity_hint_root: "liquidity:hint:root:local-netting".to_string(),
                max_hops_from_source: 1,
                edge_weight_bps: 8_500,
                edge_nonce: 1,
            })
            .expect("devnet router edge registers");
        let receipt_id = state
            .submit_routed_receipt(RoutedReceiptInput {
                plan_id: plan_id.clone(),
                contract_commitment: "contract:commitment:private-dex-router".to_string(),
                payer_note_commitment: "note:commitment:router-fee-payer:001".to_string(),
                sealed_receipt_root: "sealed:receipt:root:router:ml-kem:001".to_string(),
                encrypted_storage_delta_root: "encrypted:storage-delta:root:router:001".to_string(),
                route_hint_root: "route:hint:root:local-netting:001".to_string(),
                replay_nullifier_root: "nullifier:root:netting-router:001".to_string(),
                max_micro_fee: 3,
                receipt_bytes_upper_bound: 98_304,
                storage_keys_upper_bound: 12_288,
                receipt_nonce: 1,
            })
            .expect("devnet routed receipt accepts");
        let intent_id = state
            .bind_netting_intent(NettingIntentInput {
                plan_id: plan_id.clone(),
                receipt_ids: vec![receipt_id.clone()],
                route_edge_ids: vec![edge_id.clone()],
                aggregate_position_commitment_root: "position:commitment:root:router:001"
                    .to_string(),
                aggregate_fee_delta_root: "fee:delta:root:router:001".to_string(),
                settlement_lane_root: "settlement:lane:root:fast-router:001".to_string(),
                privacy_witness_root: "privacy:witness:root:router:001".to_string(),
                intent_nonce: 1,
            })
            .expect("devnet intent binds");
        let hint_id = state
            .register_liquidity_hint(LiquidityHintInput {
                plan_id: plan_id.clone(),
                router_edge_id: edge_id,
                sponsor_commitment: "sponsor:commitment:router:devnet:001".to_string(),
                liquidity_commitment_root: "liquidity:commitment:root:router:001".to_string(),
                low_fee_curve_root: "low-fee:curve:root:router:001".to_string(),
                rebate_commitment_root: "rebate:commitment:root:router:001".to_string(),
                available_liquidity_bucket: 64,
                expires_height: DEVNET_HEIGHT + 64,
                hint_nonce: 1,
            })
            .expect("devnet liquidity hint registers");
        let quote_id = state
            .propose_router_quote(RouterQuoteInput {
                plan_id: plan_id.clone(),
                intent_id: intent_id.clone(),
                liquidity_hint_ids: vec![hint_id],
                pre_storage_root: "storage:root:aggregate:router:before".to_string(),
                post_storage_root: "storage:root:aggregate:router:after".to_string(),
                routed_receipt_batch_root: "receipt:batch:root:router:001".to_string(),
                netted_fee_delta_root: "netted:fee:delta:root:router:001".to_string(),
                quote_price_root: "quote:price:root:low-fee-router:001".to_string(),
                receipt_bytes: 49_152,
                storage_keys_touched: 4_096,
                gross_micro_fee: 3,
                quote_nonce: 1,
            })
            .expect("devnet quote proposes");
        let _planner = state
            .attest_router_quote(RouterAttestationInput {
                quote_id: quote_id.clone(),
                role: RouterAttestationRole::RoutePlanner,
                committee_id: "committee:pq-router-planners:devnet:01".to_string(),
                signer_set_root: "signer:set:root:router-planners:01".to_string(),
                attested_route_root: "route:root:attested:router:001".to_string(),
                attested_receipt_root: "receipt:batch:root:router:001".to_string(),
                attested_storage_root: "storage:root:aggregate:router:after".to_string(),
                pq_public_key_digest: "pq-key:digest:router-planner:001".to_string(),
                pq_signature_root: "pq-signature:root:router-planner:001".to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
                attestation_nonce: 1,
            })
            .expect("devnet planner attests");
        let _verifier = state
            .attest_router_quote(RouterAttestationInput {
                quote_id: quote_id.clone(),
                role: RouterAttestationRole::ReceiptVerifier,
                committee_id: "committee:pq-router-verifiers:devnet:01".to_string(),
                signer_set_root: "signer:set:root:router-verifiers:01".to_string(),
                attested_route_root: "route:root:attested:router:001".to_string(),
                attested_receipt_root: "receipt:batch:root:router:001".to_string(),
                attested_storage_root: "storage:root:aggregate:router:after".to_string(),
                pq_public_key_digest: "pq-key:digest:router-verifier:001".to_string(),
                pq_signature_root: "pq-signature:root:router-verifier:001".to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
                attestation_nonce: 2,
            })
            .expect("devnet verifier attests");
        let batch_id = state
            .finalize_fast_router_batch(FastRouterBatchInput {
                plan_id: plan_id.clone(),
                quote_ids: vec![quote_id],
                operator_commitment: "operator:commitment:fast-router:001".to_string(),
                settlement_lane_root: "settlement:lane:root:fast-router:001".to_string(),
                aggregate_receipt_root: "receipt:aggregate:root:fast-router:001".to_string(),
                aggregate_storage_root: "storage:aggregate:root:fast-router:001".to_string(),
                aggregate_fee_ledger_root: "fee-ledger:aggregate:root:fast-router:001".to_string(),
                batch_nonce: 1,
            })
            .expect("devnet fast batch finalizes");
        let track_id = state
            .open_settlement_track(SettlementTrackInput {
                batch_id,
                plan_id,
                settlement_lane_root: "settlement:lane:root:fast-router:001".to_string(),
                pre_settlement_root: "settlement:root:before:router:001".to_string(),
                post_settlement_root: "settlement:root:after:router:001".to_string(),
                receipt_count: 1,
                net_micro_fee: 2,
                rebate_micro_fee: 1,
                track_nonce: 1,
            })
            .expect("devnet settlement track opens");
        let _ledger = state
            .append_fee_ledger_entry(FeeLedgerEntryInput {
                settlement_track_id: track_id,
                contract_commitment: "contract:commitment:private-dex-router".to_string(),
                payer_note_commitment: "note:commitment:router-fee-payer:001".to_string(),
                router_rebate_note_commitment: "note:commitment:router-rebate:001".to_string(),
                fee_delta_commitment_root: "fee:delta:commitment:root:router:001".to_string(),
                accounting_delta_root: "accounting:delta:root:router:001".to_string(),
                receipt_count: 1,
                storage_keys_touched: 4_096,
                gross_micro_fee: 3,
                net_micro_fee: 2,
                rebate_micro_fee: 1,
                ledger_nonce: 1,
            })
            .expect("devnet ledger appends");
        state
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<String> {
        if new_height < self.current_height {
            return Err("new height cannot be below current height".to_string());
        }
        self.current_height = new_height;
        self.current_epoch = self.current_height / 512;
        self.expire_stale_records();
        self.recompute_roots();
        Ok(self.state_root())
    }

    pub fn open_router_plan(&mut self, input: RouterPlanInput) -> Result<String> {
        require_non_empty("source_namespace_root", &input.source_namespace_root)?;
        require_non_empty("target_namespace_root", &input.target_namespace_root)?;
        require_non_empty(
            "eligible_contract_set_root",
            &input.eligible_contract_set_root,
        )?;
        require_non_empty("router_committee_root", &input.router_committee_root)?;
        require_non_empty("liquidity_hint_set_root", &input.liquidity_hint_set_root)?;
        require_non_empty("pq_policy_root", &input.pq_policy_root)?;
        if input.target_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("target receipt bytes exceed router batch limit".to_string());
        }
        if input.target_storage_keys > self.config.max_storage_keys_per_receipt {
            return Err("target storage keys exceed router receipt limit".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set size below router minimum".to_string());
        }
        let plan_id = router_plan_id(
            input.lane,
            &input.source_namespace_root,
            &input.target_namespace_root,
            &input.router_committee_root,
            input.plan_nonce,
        );
        if self.router_plans.contains_key(&plan_id) {
            return Err("router plan already exists".to_string());
        }
        let plan = RouterPlan {
            plan_id: plan_id.clone(),
            lane: input.lane,
            status: RouterPlanStatus::AcceptingReceipts,
            source_namespace_root: input.source_namespace_root,
            target_namespace_root: input.target_namespace_root,
            eligible_contract_set_root: input.eligible_contract_set_root,
            router_committee_root: input.router_committee_root,
            liquidity_hint_set_root: input.liquidity_hint_set_root,
            target_receipt_bytes: input.target_receipt_bytes,
            target_storage_keys: input.target_storage_keys,
            min_route_micro_fee: input.min_route_micro_fee.max(self.config.min_micro_fee),
            privacy_set_size: input.privacy_set_size,
            pq_policy_root: input.pq_policy_root,
            opened_height: self.current_height,
            route_deadline_height: self
                .current_height
                .saturating_add(self.config.route_window_blocks),
            fast_settlement_deadline_height: self
                .current_height
                .saturating_add(self.config.route_window_blocks)
                .saturating_add(self.config.fast_settlement_blocks),
        };
        self.router_plans.insert(plan_id.clone(), plan);
        self.counters.router_plans_opened = self.counters.router_plans_opened.saturating_add(1);
        self.recompute_roots();
        Ok(plan_id)
    }

    pub fn register_router_edge(&mut self, input: RouterEdgeInput) -> Result<String> {
        self.ensure_plan_accepts_routes(&input.plan_id)?;
        require_non_empty(
            "source_contract_commitment",
            &input.source_contract_commitment,
        )?;
        require_non_empty(
            "target_contract_commitment",
            &input.target_contract_commitment,
        )?;
        require_non_empty("source_storage_root", &input.source_storage_root)?;
        require_non_empty("target_storage_root", &input.target_storage_root)?;
        require_non_empty("fee_asset_commitment", &input.fee_asset_commitment)?;
        require_non_empty("liquidity_hint_root", &input.liquidity_hint_root)?;
        if input.max_hops_from_source == 0
            || input.max_hops_from_source > self.config.max_route_hops
        {
            return Err("router edge hop count exceeds router policy".to_string());
        }
        if input.edge_weight_bps > MAX_BPS {
            return Err("router edge weight exceeds MAX_BPS".to_string());
        }
        if self.router_edges_for_plan(&input.plan_id) >= self.config.max_router_edges {
            return Err("router edge limit reached".to_string());
        }
        let edge_id = router_edge_id(
            &input.plan_id,
            input.edge_kind,
            &input.source_contract_commitment,
            &input.target_contract_commitment,
            input.edge_nonce,
        );
        if self.router_edges.contains_key(&edge_id) {
            return Err("router edge already exists".to_string());
        }
        let edge = RouterEdge {
            edge_id: edge_id.clone(),
            plan_id: input.plan_id,
            edge_kind: input.edge_kind,
            source_contract_commitment: input.source_contract_commitment,
            target_contract_commitment: input.target_contract_commitment,
            source_storage_root: input.source_storage_root,
            target_storage_root: input.target_storage_root,
            fee_asset_commitment: input.fee_asset_commitment,
            liquidity_hint_root: input.liquidity_hint_root,
            max_hops_from_source: input.max_hops_from_source,
            edge_weight_bps: input.edge_weight_bps,
            opened_height: self.current_height,
        };
        self.router_edges.insert(edge_id.clone(), edge);
        self.counters.router_edges_registered =
            self.counters.router_edges_registered.saturating_add(1);
        self.recompute_roots();
        Ok(edge_id)
    }

    pub fn submit_routed_receipt(&mut self, input: RoutedReceiptInput) -> Result<String> {
        let lane = self.ensure_plan_accepts_receipts(&input.plan_id)?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("payer_note_commitment", &input.payer_note_commitment)?;
        require_non_empty("sealed_receipt_root", &input.sealed_receipt_root)?;
        require_non_empty(
            "encrypted_storage_delta_root",
            &input.encrypted_storage_delta_root,
        )?;
        require_non_empty("route_hint_root", &input.route_hint_root)?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        if self
            .consumed_replay_nullifier_roots
            .contains(&input.replay_nullifier_root)
        {
            self.counters.duplicate_receipts_rejected =
                self.counters.duplicate_receipts_rejected.saturating_add(1);
            return Err("replay nullifier already consumed".to_string());
        }
        if input.receipt_bytes_upper_bound > self.config.max_receipt_bytes_per_batch {
            return Err("receipt bytes exceed router limit".to_string());
        }
        if input.storage_keys_upper_bound > self.config.max_storage_keys_per_receipt {
            return Err("storage keys exceed router receipt limit".to_string());
        }
        let receipt_id = routed_receipt_id(
            &input.plan_id,
            &input.contract_commitment,
            &input.sealed_receipt_root,
            input.receipt_nonce,
        );
        if self.routed_receipts.contains_key(&receipt_id) {
            self.counters.duplicate_receipts_rejected =
                self.counters.duplicate_receipts_rejected.saturating_add(1);
            return Err("routed receipt already exists".to_string());
        }
        let quoted_micro_fee = estimate_router_micro_fee(
            &self.config,
            lane,
            input.max_micro_fee,
            input.receipt_bytes_upper_bound,
            1,
        );
        let receipt = RoutedReceipt {
            receipt_id: receipt_id.clone(),
            plan_id: input.plan_id.clone(),
            status: RoutedReceiptStatus::ReplayGuarded,
            contract_commitment: input.contract_commitment,
            payer_note_commitment: input.payer_note_commitment,
            sealed_receipt_root: input.sealed_receipt_root,
            encrypted_storage_delta_root: input.encrypted_storage_delta_root,
            route_hint_root: input.route_hint_root,
            replay_nullifier_root: input.replay_nullifier_root.clone(),
            quoted_micro_fee,
            max_micro_fee: input.max_micro_fee,
            receipt_bytes_upper_bound: input.receipt_bytes_upper_bound,
            storage_keys_upper_bound: input.storage_keys_upper_bound,
            submitted_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        let replay_guard_id = replay_guard_id(
            &input.plan_id,
            &receipt_id,
            &input.replay_nullifier_root,
            input.receipt_nonce,
        );
        let guard = ReplayGuard {
            replay_guard_id: replay_guard_id.clone(),
            plan_id: input.plan_id,
            receipt_id: receipt_id.clone(),
            replay_nullifier_root: input.replay_nullifier_root.clone(),
            status: ReplayGuardStatus::Armed,
            reserved_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        self.consumed_replay_nullifier_roots
            .insert(input.replay_nullifier_root);
        self.routed_receipts.insert(receipt_id.clone(), receipt);
        self.replay_guards.insert(replay_guard_id, guard);
        self.counters.routed_receipts_submitted =
            self.counters.routed_receipts_submitted.saturating_add(1);
        self.counters.replay_guards_consumed =
            self.counters.replay_guards_consumed.saturating_add(1);
        self.counters.total_receipt_bytes_routed = self
            .counters
            .total_receipt_bytes_routed
            .saturating_add(input.receipt_bytes_upper_bound);
        self.counters.total_storage_keys_routed = self
            .counters
            .total_storage_keys_routed
            .saturating_add(input.storage_keys_upper_bound);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn bind_netting_intent(&mut self, input: NettingIntentInput) -> Result<String> {
        self.ensure_plan_exists(&input.plan_id)?;
        require_non_empty(
            "aggregate_position_commitment_root",
            &input.aggregate_position_commitment_root,
        )?;
        require_non_empty("aggregate_fee_delta_root", &input.aggregate_fee_delta_root)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("privacy_witness_root", &input.privacy_witness_root)?;
        if input.receipt_ids.is_empty() {
            return Err("netting intent requires at least one receipt".to_string());
        }
        if input.route_edge_ids.is_empty() {
            return Err("netting intent requires at least one router edge".to_string());
        }
        if self.intents_for_plan(&input.plan_id) >= self.config.max_intents_per_plan {
            return Err("netting intent limit reached".to_string());
        }
        for receipt_id in &input.receipt_ids {
            let receipt = self
                .routed_receipts
                .get(receipt_id)
                .ok_or_else(|| "unknown routed receipt".to_string())?;
            if receipt.plan_id != input.plan_id {
                return Err("routed receipt belongs to a different plan".to_string());
            }
            if !receipt.status.routable() {
                return Err("routed receipt is not routable".to_string());
            }
        }
        for edge_id in &input.route_edge_ids {
            let edge = self
                .router_edges
                .get(edge_id)
                .ok_or_else(|| "unknown router edge".to_string())?;
            if edge.plan_id != input.plan_id {
                return Err("router edge belongs to a different plan".to_string());
            }
        }
        let intent_id = netting_intent_id(
            &input.plan_id,
            &input.aggregate_position_commitment_root,
            &input.aggregate_fee_delta_root,
            input.intent_nonce,
        );
        if self.netting_intents.contains_key(&intent_id) {
            return Err("netting intent already exists".to_string());
        }
        for receipt_id in &input.receipt_ids {
            if let Some(receipt) = self.routed_receipts.get_mut(receipt_id) {
                receipt.status = RoutedReceiptStatus::IntentBound;
            }
        }
        if let Some(plan) = self.router_plans.get_mut(&input.plan_id) {
            plan.status = RouterPlanStatus::Routing;
        }
        let intent = NettingIntent {
            intent_id: intent_id.clone(),
            plan_id: input.plan_id,
            status: NettingIntentStatus::RouteLocked,
            receipt_ids: input.receipt_ids,
            route_edge_ids: input.route_edge_ids,
            aggregate_position_commitment_root: input.aggregate_position_commitment_root,
            aggregate_fee_delta_root: input.aggregate_fee_delta_root,
            settlement_lane_root: input.settlement_lane_root,
            privacy_witness_root: input.privacy_witness_root,
            created_height: self.current_height,
        };
        self.netting_intents.insert(intent_id.clone(), intent);
        self.counters.netting_intents_bound = self.counters.netting_intents_bound.saturating_add(1);
        self.recompute_roots();
        Ok(intent_id)
    }

    pub fn register_liquidity_hint(&mut self, input: LiquidityHintInput) -> Result<String> {
        self.ensure_plan_exists(&input.plan_id)?;
        require_non_empty("sponsor_commitment", &input.sponsor_commitment)?;
        require_non_empty(
            "liquidity_commitment_root",
            &input.liquidity_commitment_root,
        )?;
        require_non_empty("low_fee_curve_root", &input.low_fee_curve_root)?;
        require_non_empty("rebate_commitment_root", &input.rebate_commitment_root)?;
        let edge = self
            .router_edges
            .get(&input.router_edge_id)
            .ok_or_else(|| "unknown router edge".to_string())?;
        if edge.plan_id != input.plan_id {
            return Err("liquidity hint edge belongs to a different plan".to_string());
        }
        if input.expires_height <= self.current_height {
            return Err("liquidity hint must expire in the future".to_string());
        }
        let hint_id = liquidity_hint_id(
            &input.plan_id,
            &input.router_edge_id,
            &input.sponsor_commitment,
            input.hint_nonce,
        );
        if self.liquidity_hints.contains_key(&hint_id) {
            return Err("liquidity hint already exists".to_string());
        }
        let hint = LiquidityHint {
            hint_id: hint_id.clone(),
            plan_id: input.plan_id,
            router_edge_id: input.router_edge_id,
            sponsor_commitment: input.sponsor_commitment,
            liquidity_commitment_root: input.liquidity_commitment_root,
            low_fee_curve_root: input.low_fee_curve_root,
            rebate_commitment_root: input.rebate_commitment_root,
            available_liquidity_bucket: input.available_liquidity_bucket,
            opened_height: self.current_height,
            expires_height: input.expires_height,
        };
        self.liquidity_hints.insert(hint_id.clone(), hint);
        self.counters.liquidity_hints_registered =
            self.counters.liquidity_hints_registered.saturating_add(1);
        self.recompute_roots();
        Ok(hint_id)
    }

    pub fn propose_router_quote(&mut self, input: RouterQuoteInput) -> Result<String> {
        let lane = self.ensure_plan_exists(&input.plan_id)?;
        require_non_empty("pre_storage_root", &input.pre_storage_root)?;
        require_non_empty("post_storage_root", &input.post_storage_root)?;
        require_non_empty(
            "routed_receipt_batch_root",
            &input.routed_receipt_batch_root,
        )?;
        require_non_empty("netted_fee_delta_root", &input.netted_fee_delta_root)?;
        require_non_empty("quote_price_root", &input.quote_price_root)?;
        let intent = self
            .netting_intents
            .get(&input.intent_id)
            .ok_or_else(|| "unknown netting intent".to_string())?;
        if intent.plan_id != input.plan_id {
            return Err("netting intent belongs to a different plan".to_string());
        }
        if input.liquidity_hint_ids.is_empty() {
            return Err("router quote requires liquidity hint coverage".to_string());
        }
        if self.quotes_for_plan(&input.plan_id) >= self.config.max_quotes_per_plan {
            return Err("router quote limit reached".to_string());
        }
        if input.receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("router quote receipt bytes exceed batch limit".to_string());
        }
        if input.storage_keys_touched > self.config.max_storage_keys_per_receipt {
            return Err("router quote storage keys exceed receipt limit".to_string());
        }
        for hint_id in &input.liquidity_hint_ids {
            let hint = self
                .liquidity_hints
                .get(hint_id)
                .ok_or_else(|| "unknown liquidity hint".to_string())?;
            if hint.plan_id != input.plan_id {
                return Err("liquidity hint belongs to a different plan".to_string());
            }
            if hint.expires_height <= self.current_height {
                return Err("liquidity hint is expired".to_string());
            }
        }
        let quote_id = router_quote_id(
            &input.plan_id,
            &input.intent_id,
            &input.netted_fee_delta_root,
            input.quote_nonce,
        );
        if self.router_quotes.contains_key(&quote_id) {
            return Err("router quote already exists".to_string());
        }
        let hop_count = intent.route_edge_ids.len() as u8;
        let estimated_net_micro_fee = estimate_router_micro_fee(
            &self.config,
            lane,
            input.gross_micro_fee,
            input.receipt_bytes,
            hop_count.max(1),
        );
        let estimated_rebate_micro_fee = input
            .gross_micro_fee
            .saturating_sub(estimated_net_micro_fee)
            .max(bps(input.gross_micro_fee, self.config.router_rebate_bps));
        for receipt_id in &intent.receipt_ids {
            if let Some(receipt) = self.routed_receipts.get_mut(receipt_id) {
                receipt.status = RoutedReceiptStatus::Quoted;
                receipt.quoted_micro_fee = estimated_net_micro_fee;
            }
        }
        if let Some(intent) = self.netting_intents.get_mut(&input.intent_id) {
            intent.status = NettingIntentStatus::QuoteReady;
        }
        if let Some(plan) = self.router_plans.get_mut(&input.plan_id) {
            plan.status = RouterPlanStatus::Quoting;
        }
        let quote = RouterQuote {
            quote_id: quote_id.clone(),
            plan_id: input.plan_id,
            intent_id: input.intent_id,
            status: RouterQuoteStatus::LiquidityChecked,
            liquidity_hint_ids: input.liquidity_hint_ids,
            pre_storage_root: input.pre_storage_root,
            post_storage_root: input.post_storage_root,
            routed_receipt_batch_root: input.routed_receipt_batch_root,
            netted_fee_delta_root: input.netted_fee_delta_root,
            quote_price_root: input.quote_price_root,
            receipt_bytes: input.receipt_bytes,
            storage_keys_touched: input.storage_keys_touched,
            gross_micro_fee: input.gross_micro_fee,
            estimated_net_micro_fee,
            estimated_rebate_micro_fee,
            proposed_height: self.current_height,
        };
        self.router_quotes.insert(quote_id.clone(), quote);
        self.counters.router_quotes_proposed =
            self.counters.router_quotes_proposed.saturating_add(1);
        self.counters.gross_micro_fees_quoted = self
            .counters
            .gross_micro_fees_quoted
            .saturating_add(input.gross_micro_fee);
        self.recompute_roots();
        Ok(quote_id)
    }

    pub fn attest_router_quote(&mut self, input: RouterAttestationInput) -> Result<String> {
        require_non_empty("committee_id", &input.committee_id)?;
        require_non_empty("signer_set_root", &input.signer_set_root)?;
        require_non_empty("attested_route_root", &input.attested_route_root)?;
        require_non_empty("attested_receipt_root", &input.attested_receipt_root)?;
        require_non_empty("attested_storage_root", &input.attested_storage_root)?;
        require_non_empty("pq_public_key_digest", &input.pq_public_key_digest)?;
        require_non_empty("pq_signature_root", &input.pq_signature_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("router attestation below minimum PQ security bits".to_string());
        }
        if input.quorum_weight_bps > MAX_BPS {
            return Err("router attestation quorum exceeds MAX_BPS".to_string());
        }
        let quote = self
            .router_quotes
            .get_mut(&input.quote_id)
            .ok_or_else(|| "unknown router quote".to_string())?;
        if !quote.status.settlement_ready() {
            return Err("router quote is not ready for attestation".to_string());
        }
        let attestation_id = router_attestation_id(
            &input.quote_id,
            &input.committee_id,
            input.role,
            input.attestation_nonce,
        );
        if self.router_attestations.contains_key(&attestation_id) {
            return Err("router attestation already exists".to_string());
        }
        quote.status = match input.role {
            RouterAttestationRole::RoutePlanner
            | RouterAttestationRole::NettingExecutor
            | RouterAttestationRole::LiquidityAuditor => RouterQuoteStatus::ExecutorAttested,
            RouterAttestationRole::ReceiptVerifier
            | RouterAttestationRole::PrivacySetAuditor
            | RouterAttestationRole::Watchtower => RouterQuoteStatus::VerifierAttested,
        };
        let attestation = RouterAttestation {
            attestation_id: attestation_id.clone(),
            quote_id: input.quote_id.clone(),
            role: input.role,
            status: RouterAttestationStatus::Verified,
            committee_id: input.committee_id,
            signer_set_root: input.signer_set_root,
            attested_route_root: input.attested_route_root,
            attested_receipt_root: input.attested_receipt_root,
            attested_storage_root: input.attested_storage_root,
            pq_public_key_digest: input.pq_public_key_digest,
            pq_signature_root: input.pq_signature_root,
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            attested_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        self.router_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.router_attestations_recorded =
            self.counters.router_attestations_recorded.saturating_add(1);
        self.refresh_quote_quorum(&input.quote_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn finalize_fast_router_batch(&mut self, input: FastRouterBatchInput) -> Result<String> {
        self.ensure_plan_exists(&input.plan_id)?;
        require_non_empty("operator_commitment", &input.operator_commitment)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("aggregate_receipt_root", &input.aggregate_receipt_root)?;
        require_non_empty("aggregate_storage_root", &input.aggregate_storage_root)?;
        require_non_empty(
            "aggregate_fee_ledger_root",
            &input.aggregate_fee_ledger_root,
        )?;
        if input.quote_ids.is_empty() {
            return Err("fast router batch requires quotes".to_string());
        }
        if input.quote_ids.len() > self.config.max_batch_matches {
            return Err("fast router batch quote limit exceeded".to_string());
        }
        let mut total_receipt_bytes = 0u64;
        let mut total_storage_keys = 0u64;
        let mut total_net_micro_fee = 0u64;
        for quote_id in &input.quote_ids {
            let quote = self
                .router_quotes
                .get(quote_id)
                .ok_or_else(|| "unknown router quote".to_string())?;
            if quote.plan_id != input.plan_id {
                return Err("router quote belongs to a different plan".to_string());
            }
            if !matches!(
                quote.status,
                RouterQuoteStatus::QuorumReady
                    | RouterQuoteStatus::ExecutorAttested
                    | RouterQuoteStatus::VerifierAttested
            ) {
                return Err("router quote lacks PQ quorum".to_string());
            }
            total_receipt_bytes = total_receipt_bytes.saturating_add(quote.receipt_bytes);
            total_storage_keys = total_storage_keys.saturating_add(quote.storage_keys_touched);
            total_net_micro_fee = total_net_micro_fee.saturating_add(quote.estimated_net_micro_fee);
        }
        if total_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("fast router batch exceeds receipt byte limit".to_string());
        }
        let batch_id = fast_router_batch_id(
            &input.operator_commitment,
            &input.settlement_lane_root,
            self.current_height,
            input.batch_nonce,
        );
        if self.fast_batches.contains_key(&batch_id) {
            return Err("fast router batch already exists".to_string());
        }
        for quote_id in &input.quote_ids {
            if let Some(quote) = self.router_quotes.get_mut(quote_id) {
                quote.status = RouterQuoteStatus::Included;
            }
            if let Some(intent_id) = self
                .router_quotes
                .get(quote_id)
                .map(|quote| quote.intent_id.clone())
            {
                if let Some(intent) = self.netting_intents.get_mut(&intent_id) {
                    intent.status = NettingIntentStatus::FullyNetted;
                    for receipt_id in &intent.receipt_ids {
                        if let Some(receipt) = self.routed_receipts.get_mut(receipt_id) {
                            receipt.status = RoutedReceiptStatus::Netted;
                        }
                    }
                }
            }
        }
        if let Some(plan) = self.router_plans.get_mut(&input.plan_id) {
            plan.status = RouterPlanStatus::FastSettling;
        }
        let batch = FastRouterBatch {
            batch_id: batch_id.clone(),
            plan_id: input.plan_id,
            quote_ids: input.quote_ids,
            status: FastRouterBatchStatus::FastFinal,
            operator_commitment: input.operator_commitment,
            settlement_lane_root: input.settlement_lane_root,
            aggregate_receipt_root: input.aggregate_receipt_root,
            aggregate_storage_root: input.aggregate_storage_root,
            aggregate_fee_ledger_root: input.aggregate_fee_ledger_root,
            total_receipt_bytes,
            total_storage_keys,
            total_net_micro_fee,
            finalized_height: self.current_height,
        };
        self.fast_batches.insert(batch_id.clone(), batch);
        self.counters.fast_batches_finalized =
            self.counters.fast_batches_finalized.saturating_add(1);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn open_settlement_track(&mut self, input: SettlementTrackInput) -> Result<String> {
        self.ensure_plan_exists(&input.plan_id)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("pre_settlement_root", &input.pre_settlement_root)?;
        require_non_empty("post_settlement_root", &input.post_settlement_root)?;
        let batch = self
            .fast_batches
            .get(&input.batch_id)
            .ok_or_else(|| "unknown fast router batch".to_string())?;
        if batch.plan_id != input.plan_id {
            return Err("fast router batch belongs to a different plan".to_string());
        }
        let settlement_track_id = settlement_track_id(
            &input.batch_id,
            &input.settlement_lane_root,
            &input.post_settlement_root,
            input.track_nonce,
        );
        if self.settlement_tracks.contains_key(&settlement_track_id) {
            return Err("settlement track already exists".to_string());
        }
        let track = SettlementTrack {
            settlement_track_id: settlement_track_id.clone(),
            batch_id: input.batch_id.clone(),
            plan_id: input.plan_id.clone(),
            settlement_lane_root: input.settlement_lane_root,
            pre_settlement_root: input.pre_settlement_root,
            post_settlement_root: input.post_settlement_root,
            status: SettlementTrackStatus::FastFinal,
            receipt_count: input.receipt_count,
            net_micro_fee: input.net_micro_fee,
            rebate_micro_fee: input.rebate_micro_fee,
            opened_height: self.current_height,
        };
        if let Some(batch) = self.fast_batches.get_mut(&input.batch_id) {
            batch.status = FastRouterBatchStatus::Settled;
        }
        if let Some(plan) = self.router_plans.get_mut(&input.plan_id) {
            plan.status = RouterPlanStatus::Settled;
        }
        self.settlement_tracks
            .insert(settlement_track_id.clone(), track);
        self.counters.settlement_tracks_opened =
            self.counters.settlement_tracks_opened.saturating_add(1);
        self.counters.receipts_settled = self
            .counters
            .receipts_settled
            .saturating_add(input.receipt_count);
        self.counters.net_micro_fees_settled = self
            .counters
            .net_micro_fees_settled
            .saturating_add(input.net_micro_fee);
        self.counters.rebate_micro_fees_returned = self
            .counters
            .rebate_micro_fees_returned
            .saturating_add(input.rebate_micro_fee);
        self.recompute_roots();
        Ok(settlement_track_id)
    }

    pub fn append_fee_ledger_entry(&mut self, input: FeeLedgerEntryInput) -> Result<String> {
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("payer_note_commitment", &input.payer_note_commitment)?;
        require_non_empty(
            "router_rebate_note_commitment",
            &input.router_rebate_note_commitment,
        )?;
        require_non_empty(
            "fee_delta_commitment_root",
            &input.fee_delta_commitment_root,
        )?;
        require_non_empty("accounting_delta_root", &input.accounting_delta_root)?;
        if !self
            .settlement_tracks
            .contains_key(&input.settlement_track_id)
        {
            return Err("unknown settlement track".to_string());
        }
        let ledger_entry_id = fee_ledger_entry_id(
            &input.settlement_track_id,
            &input.contract_commitment,
            &input.fee_delta_commitment_root,
            input.ledger_nonce,
        );
        if self.fee_ledger_entries.contains_key(&ledger_entry_id) {
            return Err("fee ledger entry already exists".to_string());
        }
        let entry = FeeLedgerEntry {
            ledger_entry_id: ledger_entry_id.clone(),
            settlement_track_id: input.settlement_track_id,
            contract_commitment: input.contract_commitment,
            payer_note_commitment: input.payer_note_commitment,
            router_rebate_note_commitment: input.router_rebate_note_commitment,
            fee_delta_commitment_root: input.fee_delta_commitment_root,
            accounting_delta_root: input.accounting_delta_root,
            receipt_count: input.receipt_count,
            storage_keys_touched: input.storage_keys_touched,
            gross_micro_fee: input.gross_micro_fee,
            net_micro_fee: input.net_micro_fee,
            rebate_micro_fee: input.rebate_micro_fee,
            appended_height: self.current_height,
        };
        self.fee_ledger_entries
            .insert(ledger_entry_id.clone(), entry);
        self.counters.fee_ledger_entries_appended =
            self.counters.fee_ledger_entries_appended.saturating_add(1);
        self.recompute_roots();
        Ok(ledger_entry_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            router_plan_root: merkle_record_root(
                ROUTER_PLAN_SCHEME,
                self.router_plans
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            router_edge_root: merkle_record_root(
                ROUTER_EDGE_SCHEME,
                self.router_edges
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            routed_receipt_root: merkle_record_root(
                ROUTED_RECEIPT_SCHEME,
                self.routed_receipts
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            netting_intent_root: merkle_record_root(
                NETTING_INTENT_SCHEME,
                self.netting_intents
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            liquidity_hint_root: merkle_record_root(
                LIQUIDITY_HINT_SCHEME,
                self.liquidity_hints
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            router_quote_root: merkle_record_root(
                ROUTER_QUOTE_SCHEME,
                self.router_quotes
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            router_attestation_root: merkle_record_root(
                ROUTER_ATTESTATION_SCHEME,
                self.router_attestations
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            router_batch_root: merkle_record_root(
                ROUTER_BATCH_SCHEME,
                self.fast_batches
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            replay_guard_root: merkle_record_root(
                REPLAY_GUARD_SCHEME,
                self.replay_guards
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_track_root: merkle_record_root(
                SETTLEMENT_TRACK_SCHEME,
                self.settlement_tracks
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            fee_ledger_root: merkle_record_root(
                FEE_LEDGER_SCHEME,
                self.fee_ledger_entries
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            policy_root: self.policy_root(),
            public_record_root: String::new(),
        };
        roots.public_record_root = payload_root(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.current_height,
                "epoch": self.current_epoch,
                "roots_without_public_record_root": {
                    "config_root": roots.config_root,
                    "counters_root": roots.counters_root,
                    "router_plan_root": roots.router_plan_root,
                    "router_edge_root": roots.router_edge_root,
                    "routed_receipt_root": roots.routed_receipt_root,
                    "netting_intent_root": roots.netting_intent_root,
                    "liquidity_hint_root": roots.liquidity_hint_root,
                    "router_quote_root": roots.router_quote_root,
                    "router_attestation_root": roots.router_attestation_root,
                    "router_batch_root": roots.router_batch_root,
                    "replay_guard_root": roots.replay_guard_root,
                    "settlement_track_root": roots.settlement_track_root,
                    "fee_ledger_root": roots.fee_ledger_root,
                    "policy_root": roots.policy_root,
                },
            }),
        );
        roots
    }

    pub fn recompute_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": self.current_height,
            "epoch": self.current_epoch,
            "roots": self.roots().public_record(),
        }))
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.current_height,
            "epoch": self.current_epoch,
            "state_root": self.state_root(),
            "roots_only": true,
            "roots": roots.public_record(),
            "privacy_policy": {
                "roots_only_public_records": self.config.require_roots_only_public_records,
                "sealed_receipt_payloads_redacted": true,
                "encrypted_storage_deltas_redacted": true,
                "contract_identity_commitments_only": true,
                "route_hints_commitment_only": true,
                "liquidity_amounts_bucketed": true,
                "pq_attestation_roots_only": true,
                "replay_nullifier_roots_only": true,
                "fee_ledger_commitments_only": true,
            },
        })
    }

    fn ensure_plan_exists(&self, plan_id: &str) -> Result<RouterLane> {
        self.router_plans
            .get(plan_id)
            .map(|plan| plan.lane)
            .ok_or_else(|| "unknown router plan".to_string())
    }

    fn ensure_plan_accepts_receipts(&self, plan_id: &str) -> Result<RouterLane> {
        let plan = self
            .router_plans
            .get(plan_id)
            .ok_or_else(|| "unknown router plan".to_string())?;
        if !plan.status.accepts_receipts() {
            return Err("router plan is not accepting receipts".to_string());
        }
        if self.current_height > plan.route_deadline_height {
            return Err("router plan route window closed".to_string());
        }
        Ok(plan.lane)
    }

    fn ensure_plan_accepts_routes(&self, plan_id: &str) -> Result<RouterLane> {
        let plan = self
            .router_plans
            .get(plan_id)
            .ok_or_else(|| "unknown router plan".to_string())?;
        if !plan.status.active() {
            return Err("router plan is not active".to_string());
        }
        if self.current_height > plan.fast_settlement_deadline_height {
            return Err("router plan fast settlement window closed".to_string());
        }
        Ok(plan.lane)
    }

    fn router_edges_for_plan(&self, plan_id: &str) -> usize {
        self.router_edges
            .values()
            .filter(|edge| edge.plan_id == plan_id)
            .count()
    }

    fn intents_for_plan(&self, plan_id: &str) -> usize {
        self.netting_intents
            .values()
            .filter(|intent| intent.plan_id == plan_id)
            .count()
    }

    fn quotes_for_plan(&self, plan_id: &str) -> usize {
        self.router_quotes
            .values()
            .filter(|quote| quote.plan_id == plan_id)
            .count()
    }

    fn refresh_quote_quorum(&mut self, quote_id: &str) {
        let quorum_weight = self
            .router_attestations
            .values()
            .filter(|attestation| {
                attestation.quote_id == quote_id
                    && matches!(
                        attestation.status,
                        RouterAttestationStatus::Verified | RouterAttestationStatus::Aggregated
                    )
            })
            .fold(0u64, |acc, attestation| {
                acc.saturating_add(attestation.quorum_weight_bps)
            });
        if quorum_weight >= self.config.fast_finality_quorum_bps {
            if let Some(quote) = self.router_quotes.get_mut(quote_id) {
                quote.status = RouterQuoteStatus::QuorumReady;
            }
            for attestation in self.router_attestations.values_mut() {
                if attestation.quote_id == quote_id
                    && matches!(attestation.status, RouterAttestationStatus::Verified)
                {
                    attestation.status = RouterAttestationStatus::Aggregated;
                }
            }
        }
    }

    fn policy_root(&self) -> String {
        payload_root(
            POLICY_ROOT_SCHEME,
            &json!({
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "max_route_hops": self.config.max_route_hops,
                "quorum_bps": self.config.quorum_bps,
                "fast_finality_quorum_bps": self.config.fast_finality_quorum_bps,
                "prefer_low_fee_routes": self.config.prefer_low_fee_routes,
                "prefer_fast_receipt_settlement": self.config.prefer_fast_receipt_settlement,
                "require_pq_attestations": self.config.require_pq_attestations,
                "require_replay_guards": self.config.require_replay_guards,
            }),
        )
    }

    fn expire_stale_records(&mut self) {
        for plan in self.router_plans.values_mut() {
            if plan.status.active() && self.current_height > plan.fast_settlement_deadline_height {
                plan.status = RouterPlanStatus::Expired;
            }
        }
        for receipt in self.routed_receipts.values_mut() {
            if receipt.status.routable() && self.current_height > receipt.expires_height {
                receipt.status = RoutedReceiptStatus::Expired;
            }
        }
        for intent in self.netting_intents.values_mut() {
            if matches!(
                intent.status,
                NettingIntentStatus::Pending
                    | NettingIntentStatus::RouteLocked
                    | NettingIntentStatus::QuoteReady
            ) && self.current_height.saturating_sub(intent.created_height)
                > self.config.replay_window_blocks
            {
                intent.status = NettingIntentStatus::Expired;
            }
        }
        for hint in self.liquidity_hints.values_mut() {
            if self.current_height > hint.expires_height {
                hint.available_liquidity_bucket = 0;
            }
        }
        for attestation in self.router_attestations.values_mut() {
            if matches!(
                attestation.status,
                RouterAttestationStatus::Pending | RouterAttestationStatus::Verified
            ) && self.current_height > attestation.expires_height
            {
                attestation.status = RouterAttestationStatus::Expired;
            }
        }
        for guard in self.replay_guards.values_mut() {
            if matches!(
                guard.status,
                ReplayGuardStatus::Reserved | ReplayGuardStatus::Armed
            ) && self.current_height > guard.expires_height
            {
                guard.status = ReplayGuardStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn router_plan_id(
    lane: RouterLane,
    source_namespace_root: &str,
    target_namespace_root: &str,
    router_committee_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:PLAN-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_namespace_root),
            HashPart::Str(target_namespace_root),
            HashPart::Str(router_committee_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn router_edge_id(
    plan_id: &str,
    edge_kind: RouteEdgeKind,
    source_contract_commitment: &str,
    target_contract_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:EDGE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(edge_kind.as_str()),
            HashPart::Str(source_contract_commitment),
            HashPart::Str(target_contract_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn routed_receipt_id(
    plan_id: &str,
    contract_commitment: &str,
    sealed_receipt_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_receipt_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn netting_intent_id(
    plan_id: &str,
    aggregate_position_commitment_root: &str,
    aggregate_fee_delta_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:INTENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(aggregate_position_commitment_root),
            HashPart::Str(aggregate_fee_delta_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn liquidity_hint_id(
    plan_id: &str,
    router_edge_id: &str,
    sponsor_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:LIQUIDITY-HINT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(router_edge_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn router_quote_id(
    plan_id: &str,
    intent_id: &str,
    netted_fee_delta_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(intent_id),
            HashPart::Str(netted_fee_delta_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn router_attestation_id(
    quote_id: &str,
    committee_id: &str,
    role: RouterAttestationRole,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(quote_id),
            HashPart::Str(committee_id),
            HashPart::Str(role.as_str()),
            HashPart::U64(nonce),
        ],
    )
}

pub fn replay_guard_id(
    plan_id: &str,
    receipt_id: &str,
    replay_nullifier_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:REPLAY-GUARD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(receipt_id),
            HashPart::Str(replay_nullifier_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn fast_router_batch_id(
    operator_commitment: &str,
    settlement_lane_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::Str(settlement_lane_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_track_id(
    batch_id: &str,
    settlement_lane_root: &str,
    post_settlement_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:SETTLEMENT-TRACK-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_lane_root),
            HashPart::Str(post_settlement_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn fee_ledger_entry_id(
    settlement_track_id: &str,
    contract_commitment: &str,
    fee_delta_commitment_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:FEE-LEDGER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_track_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(fee_delta_commitment_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn estimate_router_micro_fee(
    config: &Config,
    lane: RouterLane,
    max_micro_fee: u64,
    receipt_bytes: u64,
    route_hops: u8,
) -> u64 {
    let byte_component = receipt_bytes.saturating_add(4095) / 4096;
    let priority_discount = lane.priority_weight() / 1_600;
    let hop_component =
        u64::from(route_hops.saturating_sub(1)).saturating_mul(config.base_micro_fee);
    let hop_rebate = bps(
        hop_component.saturating_add(max_micro_fee),
        config.hop_compression_rebate_bps,
    );
    let mut fee = max_micro_fee
        .max(config.base_micro_fee)
        .saturating_add(byte_component)
        .saturating_add(hop_component)
        .saturating_add(config.router_operator_fee_bps)
        .saturating_add(config.congestion_fee_bps)
        .saturating_sub(priority_discount)
        .saturating_sub(hop_rebate);
    fee = fee.saturating_sub(bps(fee, config.router_rebate_bps));
    fee.max(config.min_micro_fee)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-ROUTER:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        payload_root(domain, &json!({ "empty": true }))
    } else {
        merkle_root(domain, records)
    }
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    payload_root(domain, &json!({ "values": values }))
}

fn merkle_record_root(domain: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        payload_root(domain, &json!({ "empty": true }))
    } else {
        let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(domain, &values)
    }
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be non-empty"))
    } else {
        Ok(())
    }
}
