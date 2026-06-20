use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-receipt-streaming-index-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_640_000;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_RECEIPT_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-streaming-receipt-attestation-v1";
pub const CONFIDENTIAL_STREAM_SUITE: &str = "zk-confidential-receipt-stream-index-redaction-v1";
pub const DEFAULT_SHARD_COUNT: u16 = 8;
pub const DEFAULT_MAX_STREAM_LAG_MS: u64 = 320;
pub const DEFAULT_MAX_QUEUE_DEPTH: u32 = 16_384;
pub const DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_REBATE_BPS: u16 = 1_500;

const D_STATE: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:ROOTS";
const D_STREAMS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:STREAMS";
const D_CHECKPOINTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:CHECKPOINTS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:ATTESTATIONS";
const D_CURSORS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:CURSORS";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:EVENTS";
const D_FILLS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:FILLS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:REDACTIONS";
const D_BACKPRESSURE: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:BACKPRESSURE";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    WalletScan,
    ContractEvent,
    DefiFill,
    FeeRebate,
    BridgeSettlement,
    Liquidation,
    OracleUpdate,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::ContractEvent => "contract_event",
            Self::DefiFill => "defi_fill",
            Self::FeeRebate => "fee_rebate",
            Self::BridgeSettlement => "bridge_settlement",
            Self::Liquidation => "liquidation",
            Self::OracleUpdate => "oracle_update",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamLane {
    Instant,
    Fast,
    LowFee,
    Defi,
    Wallet,
    Operator,
}

impl StreamLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::LowFee => "low_fee",
            Self::Defi => "defi",
            Self::Wallet => "wallet",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureMode {
    Accepting,
    Coalescing,
    SheddingLowFee,
    Paused,
}

impl BackpressureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Coalescing => "coalescing",
            Self::SheddingLowFee => "shedding_low_fee",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub shard_count: u16,
    pub max_stream_lag_ms: u64,
    pub max_queue_depth: u32,
    pub max_receipts_per_checkpoint: u32,
    pub wallet_cursor_window: u64,
    pub public_summary_window: u64,
    pub privacy_budget_units: u64,
    pub min_redaction_k_anonymity: u16,
    pub min_pq_security_bits: u16,
    pub fee_asset_id: String,
    pub base_receipt_fee_micros: u64,
    pub low_fee_lane_discount_bps: u16,
    pub rebate_bps: u16,
    pub enable_defi_receipts: bool,
    pub enable_contract_event_receipts: bool,
    pub enable_operator_safe_public_summaries: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            shard_count: DEFAULT_SHARD_COUNT,
            max_stream_lag_ms: DEFAULT_MAX_STREAM_LAG_MS,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            max_receipts_per_checkpoint: 2_048,
            wallet_cursor_window: 4_096,
            public_summary_window: 128,
            privacy_budget_units: DEFAULT_PRIVACY_BUDGET_UNITS,
            min_redaction_k_anonymity: 32,
            min_pq_security_bits: 256,
            fee_asset_id: "piconero-devnet".to_string(),
            base_receipt_fee_micros: 7,
            low_fee_lane_discount_bps: 4_000,
            rebate_bps: DEFAULT_REBATE_BPS,
            enable_defi_receipts: true,
            enable_contract_event_receipts: true,
            enable_operator_safe_public_summaries: true,
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
    pub streams_opened: u64,
    pub receipts_ingested: u64,
    pub receipts_indexed: u64,
    pub attestations_verified: u64,
    pub checkpoints_sealed: u64,
    pub wallet_cursors_advanced: u64,
    pub contract_events: u64,
    pub defi_fills: u64,
    pub fee_rebates: u64,
    pub redactions_applied: u64,
    pub backpressure_events: u64,
    pub dropped_low_fee_receipts: u64,
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
    pub streams_root: String,
    pub checkpoints_root: String,
    pub attestations_root: String,
    pub wallet_cursors_root: String,
    pub contract_events_root: String,
    pub defi_fills_root: String,
    pub fee_rebates_root: String,
    pub redactions_root: String,
    pub backpressure_root: String,
    pub public_log_root: String,
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
pub struct ReceiptStreamRequest {
    pub stream_id: String,
    pub wallet_view_tag_commitment: String,
    pub shard_id: u16,
    pub lane: StreamLane,
    pub receipt_kinds: BTreeSet<ReceiptKind>,
    pub cursor_hint: String,
    pub max_lag_ms: u64,
    pub max_fee_micros: u64,
    pub encrypted_filter: String,
    pub pq_session_key_commitment: String,
}

impl ReceiptStreamRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "wallet_view_tag_commitment": self.wallet_view_tag_commitment,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "receipt_kinds": self.receipt_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "cursor_hint": self.cursor_hint,
            "max_lag_ms": self.max_lag_ms,
            "max_fee_micros": self.max_fee_micros,
            "encrypted_filter_root": payload_root("STREAM-ENCRYPTED-FILTER", &json!(self.encrypted_filter)),
            "pq_session_key_commitment": self.pq_session_key_commitment
        })
    }

    pub fn root(&self) -> String {
        payload_root("RECEIPT-STREAM-REQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptStream {
    pub stream_id: String,
    pub shard_id: u16,
    pub lane: StreamLane,
    pub opened_height: u64,
    pub last_sequence: u64,
    pub queue_depth: u32,
    pub lag_ms: u64,
    pub fee_rate_micros: u64,
    pub cursor_root: String,
    pub filter_root: String,
    pub accepting: bool,
}

impl ReceiptStream {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "opened_height": self.opened_height,
            "last_sequence": self.last_sequence,
            "queue_depth": self.queue_depth,
            "lag_ms": self.lag_ms,
            "fee_rate_micros": self.fee_rate_micros,
            "cursor_root": self.cursor_root,
            "filter_root": self.filter_root,
            "accepting": self.accepting
        })
    }

    pub fn root(&self) -> String {
        payload_root("RECEIPT-STREAM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialReceipt {
    pub receipt_id: String,
    pub stream_id: String,
    pub shard_id: u16,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub lane: StreamLane,
    pub nullifier_commitment: String,
    pub wallet_hint_root: String,
    pub event_or_fill_root: String,
    pub fee_paid_micros: u64,
    pub rebate_eligible_micros: u64,
    pub encrypted_payload: String,
    pub redaction_policy_id: String,
}

impl ConfidentialReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "stream_id": self.stream_id,
            "shard_id": self.shard_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "nullifier_commitment": self.nullifier_commitment,
            "wallet_hint_root": self.wallet_hint_root,
            "event_or_fill_root": self.event_or_fill_root,
            "fee_paid_micros": self.fee_paid_micros,
            "rebate_eligible_micros": self.rebate_eligible_micros,
            "encrypted_payload_root": payload_root("RECEIPT-SEALED-PAYLOAD", &json!(self.encrypted_payload)),
            "redaction_policy_id": self.redaction_policy_id
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIDENTIAL-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardIndexCheckpoint {
    pub checkpoint_id: String,
    pub shard_id: u16,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub stream_count: u32,
    pub receipt_count: u32,
    pub receipt_root: String,
    pub cursor_root: String,
    pub sealed_height: u64,
    pub operator_summary_root: String,
}

impl ShardIndexCheckpoint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("SHARD-INDEX-CHECKPOINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptAttestation {
    pub attestation_id: String,
    pub checkpoint_id: String,
    pub signer_committee_id: String,
    pub pq_suite: String,
    pub min_security_bits: u16,
    pub signature_weight: u64,
    pub attested_receipt_root: String,
    pub public_key_set_root: String,
    pub signature_root: String,
    pub accepted: bool,
}

impl PqReceiptAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PQ-RECEIPT-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanCursor {
    pub cursor_id: String,
    pub wallet_commitment: String,
    pub shard_id: u16,
    pub stream_id: String,
    pub last_sequence: u64,
    pub last_checkpoint_id: String,
    pub view_tag_bucket: String,
    pub cursor_commitment: String,
    pub spendable_hint_root: String,
}

impl WalletScanCursor {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("WALLET-SCAN-CURSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractEventReceipt {
    pub event_id: String,
    pub receipt_id: String,
    pub contract_commitment: String,
    pub topic_root: String,
    pub state_diff_root: String,
    pub caller_commitment: String,
    pub gas_used_commitment: String,
    pub searchable_tags: BTreeSet<String>,
}

impl ContractEventReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONTRACT-EVENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefiFillReceipt {
    pub fill_id: String,
    pub receipt_id: String,
    pub pool_commitment: String,
    pub route_commitment: String,
    pub input_asset_commitment: String,
    pub output_asset_commitment: String,
    pub notional_commitment: String,
    pub price_band_root: String,
    pub solver_commitment: String,
    pub low_fee_batch_id: String,
}

impl DefiFillReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DEFI-FILL-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateReceipt {
    pub rebate_id: String,
    pub receipt_id: String,
    pub wallet_commitment: String,
    pub fee_asset_id: String,
    pub paid_micros: u64,
    pub rebate_micros: u64,
    pub reason: String,
    pub settlement_commitment: String,
}

impl FeeRebateReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("FEE-REBATE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub policy_id: String,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub k_anonymity_floor: u16,
    pub allowed_fields: BTreeSet<String>,
    pub denied_fields: BTreeSet<String>,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("REDACTION-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureSignal {
    pub signal_id: String,
    pub shard_id: u16,
    pub mode: BackpressureMode,
    pub queue_depth: u32,
    pub lag_ms: u64,
    pub shed_lane: Option<StreamLane>,
    pub operator_note_root: String,
    pub active: bool,
}

impl BackpressureSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "shard_id": self.shard_id,
            "mode": self.mode.as_str(),
            "queue_depth": self.queue_depth,
            "lag_ms": self.lag_ms,
            "shed_lane": self.shed_lane.map(|lane| lane.as_str()),
            "operator_note_root": self.operator_note_root,
            "active": self.active
        })
    }

    pub fn root(&self) -> String {
        payload_root("BACKPRESSURE-SIGNAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicSummary {
    pub summary_id: String,
    pub height: u64,
    pub shard_id: u16,
    pub checkpoint_id: String,
    pub mode: BackpressureMode,
    pub receipts_indexed: u64,
    pub avg_lag_ms: u64,
    pub fee_rebates_micros: u64,
    pub redacted: bool,
    pub roots: Roots,
}

impl OperatorPublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "shard_id": self.shard_id,
            "checkpoint_id": self.checkpoint_id,
            "mode": self.mode.as_str(),
            "receipts_indexed": self.receipts_indexed,
            "avg_lag_ms": self.avg_lag_ms,
            "fee_rebates_micros": self.fee_rebates_micros,
            "redacted": self.redacted,
            "roots": self.roots.public_record()
        })
    }

    pub fn root(&self) -> String {
        payload_root("OPERATOR-PUBLIC-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub streams: BTreeMap<String, ReceiptStream>,
    pub receipts: BTreeMap<String, ConfidentialReceipt>,
    pub checkpoints: BTreeMap<String, ShardIndexCheckpoint>,
    pub attestations: BTreeMap<String, PqReceiptAttestation>,
    pub wallet_cursors: BTreeMap<String, WalletScanCursor>,
    pub contract_events: BTreeMap<String, ContractEventReceipt>,
    pub defi_fills: BTreeMap<String, DefiFillReceipt>,
    pub fee_rebates: BTreeMap<String, FeeRebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub backpressure: BTreeMap<String, BackpressureSignal>,
    pub public_log: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            streams: BTreeMap::new(),
            receipts: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            attestations: BTreeMap::new(),
            wallet_cursors: BTreeMap::new(),
            contract_events: BTreeMap::new(),
            defi_fills: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            backpressure: BTreeMap::new(),
            public_log: BTreeMap::new(),
        };

        let request = ReceiptStreamRequest {
            stream_id: "stream-devnet-wallet-fast-0".to_string(),
            wallet_view_tag_commitment: dev_hash("wallet-view-tag", 0),
            shard_id: 2,
            lane: StreamLane::Fast,
            receipt_kinds: BTreeSet::from([
                ReceiptKind::WalletScan,
                ReceiptKind::ContractEvent,
                ReceiptKind::DefiFill,
                ReceiptKind::FeeRebate,
            ]),
            cursor_hint: "cursor-bucket-2-0000".to_string(),
            max_lag_ms: 250,
            max_fee_micros: 48,
            encrypted_filter: "sealed-filter-devnet-wallet-fast-0".to_string(),
            pq_session_key_commitment: dev_hash("pq-session-key", 0),
        };
        state.open_stream(request).expect("devnet stream opens");

        for sequence in 1..=6 {
            let kind = match sequence {
                1 | 4 => ReceiptKind::WalletScan,
                2 => ReceiptKind::ContractEvent,
                3 | 6 => ReceiptKind::DefiFill,
                _ => ReceiptKind::FeeRebate,
            };
            let receipt = ConfidentialReceipt {
                receipt_id: format!("rcpt-devnet-2-{sequence:04}"),
                stream_id: "stream-devnet-wallet-fast-0".to_string(),
                shard_id: 2,
                sequence,
                kind,
                lane: StreamLane::Fast,
                nullifier_commitment: dev_hash("nullifier", sequence),
                wallet_hint_root: dev_hash("wallet-hint", sequence),
                event_or_fill_root: dev_hash("event-fill", sequence),
                fee_paid_micros: 9 + sequence,
                rebate_eligible_micros: if matches!(kind, ReceiptKind::FeeRebate) {
                    12
                } else {
                    0
                },
                encrypted_payload: format!("sealed-receipt-payload-{sequence}"),
                redaction_policy_id: "policy-devnet-public-safe".to_string(),
            };
            state
                .ingest_receipt(receipt)
                .expect("devnet receipt ingests");
        }

        state.contract_events.insert(
            "event-devnet-swap-0002".to_string(),
            ContractEventReceipt {
                event_id: "event-devnet-swap-0002".to_string(),
                receipt_id: "rcpt-devnet-2-0002".to_string(),
                contract_commitment: dev_hash("contract-swap", 2),
                topic_root: dev_hash("topic-swap-filled", 2),
                state_diff_root: dev_hash("state-diff", 2),
                caller_commitment: dev_hash("caller", 2),
                gas_used_commitment: dev_hash("gas", 2),
                searchable_tags: BTreeSet::from(["swap".to_string(), "private_amm".to_string()]),
            },
        );
        state.defi_fills.insert(
            "fill-devnet-amm-0003".to_string(),
            DefiFillReceipt {
                fill_id: "fill-devnet-amm-0003".to_string(),
                receipt_id: "rcpt-devnet-2-0003".to_string(),
                pool_commitment: dev_hash("pool-xmr-usdc", 3),
                route_commitment: dev_hash("route", 3),
                input_asset_commitment: dev_hash("asset-xmr", 3),
                output_asset_commitment: dev_hash("asset-usdc", 3),
                notional_commitment: dev_hash("notional", 3),
                price_band_root: dev_hash("price-band", 3),
                solver_commitment: dev_hash("solver", 3),
                low_fee_batch_id: "batch-low-fee-defi-0001".to_string(),
            },
        );
        state.fee_rebates.insert(
            "rebate-devnet-0005".to_string(),
            FeeRebateReceipt {
                rebate_id: "rebate-devnet-0005".to_string(),
                receipt_id: "rcpt-devnet-2-0005".to_string(),
                wallet_commitment: dev_hash("wallet", 5),
                fee_asset_id: state.config.fee_asset_id.clone(),
                paid_micros: 14,
                rebate_micros: 2,
                reason: "low_fee_private_batch_netting".to_string(),
                settlement_commitment: dev_hash("rebate-settlement", 5),
            },
        );
        state.redaction_budgets.insert(
            "policy-devnet-public-safe".to_string(),
            RedactionBudget {
                policy_id: "policy-devnet-public-safe".to_string(),
                budget_units: state.config.privacy_budget_units,
                consumed_units: 4_200,
                k_anonymity_floor: state.config.min_redaction_k_anonymity,
                allowed_fields: BTreeSet::from([
                    "receipt_id".to_string(),
                    "shard_id".to_string(),
                    "kind".to_string(),
                    "fee_paid_micros".to_string(),
                ]),
                denied_fields: BTreeSet::from([
                    "encrypted_payload".to_string(),
                    "wallet_hint".to_string(),
                    "view_key".to_string(),
                ]),
            },
        );
        state.backpressure.insert(
            "bp-devnet-shard-2".to_string(),
            BackpressureSignal {
                signal_id: "bp-devnet-shard-2".to_string(),
                shard_id: 2,
                mode: BackpressureMode::Coalescing,
                queue_depth: 1_024,
                lag_ms: 188,
                shed_lane: Some(StreamLane::LowFee),
                operator_note_root: dev_hash("operator-note", 2),
                active: true,
            },
        );
        state.seal_checkpoint(2).expect("devnet checkpoint seals");
        state.refresh_roots();
        state.record_operator_summary();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn open_stream(&mut self, request: ReceiptStreamRequest) -> Result<String> {
        if request.shard_id >= self.config.shard_count {
            return Err(format!("unknown shard {}", request.shard_id));
        }
        if request.max_lag_ms > self.config.max_stream_lag_ms {
            return Err(format!("stream lag {} exceeds config", request.max_lag_ms));
        }
        let stream_id = request.stream_id.clone();
        let stream = ReceiptStream {
            stream_id: stream_id.clone(),
            shard_id: request.shard_id,
            lane: request.lane,
            opened_height: DEVNET_HEIGHT,
            last_sequence: 0,
            queue_depth: 0,
            lag_ms: request.max_lag_ms,
            fee_rate_micros: lane_fee(&request.lane, &self.config),
            cursor_root: payload_root("INITIAL-CURSOR", &json!(request.cursor_hint)),
            filter_root: request.root(),
            accepting: true,
        };
        self.counters.streams_opened = self.counters.streams_opened.saturating_add(1);
        self.public_log
            .insert(format!("stream:{stream_id}"), stream.public_record());
        self.streams.insert(stream_id.clone(), stream);
        self.refresh_roots();
        Ok(stream_id)
    }

    pub fn ingest_receipt(&mut self, receipt: ConfidentialReceipt) -> Result<String> {
        let stream = self
            .streams
            .get_mut(&receipt.stream_id)
            .ok_or_else(|| format!("missing stream {}", receipt.stream_id))?;
        if !stream.accepting {
            return Err(format!("stream {} is not accepting", receipt.stream_id));
        }
        if stream.queue_depth >= self.config.max_queue_depth {
            self.counters.backpressure_events = self.counters.backpressure_events.saturating_add(1);
            if receipt.lane == StreamLane::LowFee {
                self.counters.dropped_low_fee_receipts =
                    self.counters.dropped_low_fee_receipts.saturating_add(1);
            }
            return Err("receipt queue is backpressured".to_string());
        }
        stream.last_sequence = stream.last_sequence.max(receipt.sequence);
        stream.queue_depth = stream.queue_depth.saturating_add(1);
        stream.lag_ms = stream.lag_ms.saturating_sub(8);

        self.counters.receipts_ingested = self.counters.receipts_ingested.saturating_add(1);
        self.counters.receipts_indexed = self.counters.receipts_indexed.saturating_add(1);
        if matches!(receipt.kind, ReceiptKind::ContractEvent) {
            self.counters.contract_events = self.counters.contract_events.saturating_add(1);
        }
        if matches!(receipt.kind, ReceiptKind::DefiFill) {
            self.counters.defi_fills = self.counters.defi_fills.saturating_add(1);
        }
        if matches!(receipt.kind, ReceiptKind::FeeRebate) {
            self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        }
        self.public_log.insert(
            format!("receipt:{}", receipt.receipt_id),
            redacted_receipt_summary(&receipt),
        );
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn advance_wallet_cursor(&mut self, cursor: WalletScanCursor) {
        self.counters.wallet_cursors_advanced =
            self.counters.wallet_cursors_advanced.saturating_add(1);
        self.public_log.insert(
            format!("cursor:{}", cursor.cursor_id),
            json!({
                "cursor_id": cursor.cursor_id,
                "shard_id": cursor.shard_id,
                "stream_id": cursor.stream_id,
                "last_sequence": cursor.last_sequence,
                "last_checkpoint_id": cursor.last_checkpoint_id
            }),
        );
        self.wallet_cursors.insert(cursor.cursor_id.clone(), cursor);
        self.refresh_roots();
    }

    pub fn seal_checkpoint(&mut self, shard_id: u16) -> Result<String> {
        let shard_receipts = self
            .receipts
            .values()
            .filter(|receipt| receipt.shard_id == shard_id)
            .map(ConfidentialReceipt::public_record)
            .collect::<Vec<_>>();
        if shard_receipts.is_empty() {
            return Err(format!("no receipts for shard {shard_id}"));
        }
        let from_sequence = self
            .receipts
            .values()
            .filter(|receipt| receipt.shard_id == shard_id)
            .map(|receipt| receipt.sequence)
            .min()
            .unwrap_or_default();
        let to_sequence = self
            .receipts
            .values()
            .filter(|receipt| receipt.shard_id == shard_id)
            .map(|receipt| receipt.sequence)
            .max()
            .unwrap_or_default();
        let checkpoint_id = format!("chk-shard-{shard_id}-{to_sequence:08}");
        let receipt_root = merkle_root(D_CHECKPOINTS, &shard_receipts);
        let checkpoint = ShardIndexCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            shard_id,
            from_sequence,
            to_sequence,
            stream_count: self
                .streams
                .values()
                .filter(|stream| stream.shard_id == shard_id)
                .count() as u32,
            receipt_count: shard_receipts.len() as u32,
            receipt_root: receipt_root.clone(),
            cursor_root: merkle_records(D_CURSORS, &self.wallet_cursors),
            sealed_height: DEVNET_HEIGHT + to_sequence,
            operator_summary_root: payload_root(
                "CHECKPOINT-OPERATOR-SUMMARY",
                &json!({ "shard_id": shard_id, "receipt_count": shard_receipts.len() }),
            ),
        };
        let attestation = PqReceiptAttestation {
            attestation_id: format!("attest-{checkpoint_id}"),
            checkpoint_id: checkpoint_id.clone(),
            signer_committee_id: "committee-devnet-fast-receipts".to_string(),
            pq_suite: PQ_RECEIPT_ATTESTATION_SUITE.to_string(),
            min_security_bits: self.config.min_pq_security_bits,
            signature_weight: 5,
            attested_receipt_root: receipt_root,
            public_key_set_root: dev_hash("committee-pq-keyset", shard_id as u64),
            signature_root: dev_hash("pq-signature-aggregate", to_sequence),
            accepted: true,
        };
        self.counters.checkpoints_sealed = self.counters.checkpoints_sealed.saturating_add(1);
        self.counters.attestations_verified = self.counters.attestations_verified.saturating_add(1);
        self.public_log.insert(
            format!("checkpoint:{checkpoint_id}"),
            checkpoint.public_record(),
        );
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        self.refresh_roots();
        Ok(checkpoint_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            streams_root: merkle_records(D_STREAMS, &self.streams),
            checkpoints_root: merkle_records(D_CHECKPOINTS, &self.checkpoints),
            attestations_root: merkle_records(D_ATTESTATIONS, &self.attestations),
            wallet_cursors_root: merkle_records(D_CURSORS, &self.wallet_cursors),
            contract_events_root: merkle_records(D_EVENTS, &self.contract_events),
            defi_fills_root: merkle_records(D_FILLS, &self.defi_fills),
            fee_rebates_root: merkle_records(D_REBATES, &self.fee_rebates),
            redactions_root: merkle_records(D_REDACTIONS, &self.redaction_budgets),
            backpressure_root: merkle_records(D_BACKPRESSURE, &self.backpressure),
            public_log_root: merkle_records(D_PUBLIC, &self.public_log),
        };
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "stream_count": self.streams.len(),
            "receipt_count": self.receipts.len(),
            "checkpoint_count": self.checkpoints.len(),
            "attestation_count": self.attestations.len(),
            "wallet_cursor_count": self.wallet_cursors.len(),
            "contract_event_count": self.contract_events.len(),
            "defi_fill_count": self.defi_fills.len(),
            "fee_rebate_count": self.fee_rebates.len(),
            "redaction_policy_count": self.redaction_budgets.len(),
            "backpressure_count": self.backpressure.len(),
            "public_log": self.public_log
        })
    }

    fn record_operator_summary(&mut self) {
        let checkpoint = self
            .checkpoints
            .values()
            .next_back()
            .map(|checkpoint| checkpoint.checkpoint_id.clone())
            .unwrap_or_else(|| "checkpoint-none".to_string());
        let mode = self
            .backpressure
            .values()
            .next()
            .map(|signal| signal.mode)
            .unwrap_or(BackpressureMode::Accepting);
        let avg_lag_ms = if self.streams.is_empty() {
            0
        } else {
            self.streams
                .values()
                .map(|stream| stream.lag_ms)
                .sum::<u64>()
                / self.streams.len() as u64
        };
        let summary = OperatorPublicSummary {
            summary_id: "summary-devnet-receipt-stream-index".to_string(),
            height: DEVNET_HEIGHT + self.counters.receipts_indexed,
            shard_id: 2,
            checkpoint_id: checkpoint,
            mode,
            receipts_indexed: self.counters.receipts_indexed,
            avg_lag_ms,
            fee_rebates_micros: self
                .fee_rebates
                .values()
                .map(|rebate| rebate.rebate_micros)
                .sum(),
            redacted: true,
            roots: self.roots.clone(),
        };
        self.public_log
            .insert("operator:summary".to_string(), summary.public_record());
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

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn lane_fee(lane: &StreamLane, config: &Config) -> u64 {
    match lane {
        StreamLane::Instant => config.base_receipt_fee_micros.saturating_mul(3),
        StreamLane::Fast => config.base_receipt_fee_micros.saturating_mul(2),
        StreamLane::LowFee => {
            config
                .base_receipt_fee_micros
                .saturating_mul((10_000 - config.low_fee_lane_discount_bps) as u64)
                / 10_000
        }
        StreamLane::Defi => config
            .base_receipt_fee_micros
            .saturating_mul(2)
            .saturating_add(1),
        StreamLane::Wallet => config.base_receipt_fee_micros,
        StreamLane::Operator => 0,
    }
}

fn redacted_receipt_summary(receipt: &ConfidentialReceipt) -> Value {
    json!({
        "receipt_id": receipt.receipt_id,
        "stream_id": receipt.stream_id,
        "shard_id": receipt.shard_id,
        "sequence": receipt.sequence,
        "kind": receipt.kind.as_str(),
        "lane": receipt.lane.as_str(),
        "fee_paid_micros": receipt.fee_paid_micros,
        "rebate_eligible_micros": receipt.rebate_eligible_micros,
        "payload_redacted": true,
        "operator_safe": true,
        "receipt_root": receipt.root()
    })
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-RECEIPT-STREAM-INDEX:DEVNET",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
