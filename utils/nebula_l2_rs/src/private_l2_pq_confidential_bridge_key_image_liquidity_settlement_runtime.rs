use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeKeyImageLiquiditySettlementRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_KEY_IMAGE_LIQUIDITY_SETTLEMENT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-bridge-key-image-liquidity-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_KEY_IMAGE_LIQUIDITY_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const KEY_IMAGE_EVIDENCE_SUITE: &str =
    "monero-ringct-key-image-nullifier-evidence-confidential-root-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-key-image-liquidity-attestation-v1";
pub const LIQUIDITY_NETTING_SUITE: &str =
    "low-fee-confidential-bridge-key-image-liquidity-netting-root-v1";
pub const SETTLEMENT_SUITE: &str = "operator-safe-monero-key-image-liquidity-settlement-root-v1";
pub const REBATE_SUITE: &str = "key-image-liquidity-settlement-fee-rebate-root-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "roots-only-key-image-liquidity-settlement-redaction-budget-v1";
pub const PUBLIC_RECORD_SUITE: &str = "public-key-image-liquidity-settlement-operator-record-v1";
pub const PUBLIC_ROOT_SUITE: &str = "public-key-image-liquidity-settlement-root-envelope-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_key_images_addresses_amounts_view_keys_spend_keys_or_linkage_graphs";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BRIDGE_ASSET_ID: &str = "xmr-key-image-liquidity-note-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_FAST_SETTLEMENT_SLOTS: u64 = 24;
pub const DEFAULT_NETTING_WINDOW_SLOTS: u64 = 12;
pub const DEFAULT_EVIDENCE_TTL_SLOTS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 144;
pub const DEFAULT_SETTLEMENT_TTL_SLOTS: u64 = 96;
pub const DEFAULT_MAX_SETTLEMENT_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_NET_FEE_BPS: u64 = 7;
pub const DEFAULT_REBATE_BPS: u64 = 5_000;
pub const DEFAULT_MIN_POOL_RESERVE_ATOMIC_UNITS: u64 = 120_000_000_000;
pub const DEFAULT_MIN_NETTABLE_ATOMIC_UNITS: u64 = 1_000_000_000;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const DEFAULT_REDACTION_BUDGET_FIELDS: u32 = 16;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u32 = 1_024;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEVNET_L2_HEIGHT: u64 = 3_744_320;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_912_640;
pub const DEVNET_EPOCH: u64 = 9_216;
pub const DEVNET_SLOT: u64 = 384;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_KEY_IMAGE_EVIDENCE: usize = 8_388_608;
pub const MAX_PQ_ATTESTATIONS: usize = 8_388_608;
pub const MAX_NETTING_BATCHES: usize = 1_048_576;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    BridgeIngress,
    FastExit,
    MarketMaker,
    BackstopReserve,
    FeeSponsor,
    EmergencySettlement,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeIngress => "bridge_ingress",
            Self::FastExit => "fast_exit",
            Self::MarketMaker => "market_maker",
            Self::BackstopReserve => "backstop_reserve",
            Self::FeeSponsor => "fee_sponsor",
            Self::EmergencySettlement => "emergency_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Planned,
    Active,
    NettingOnly,
    Throttled,
    SettlementOnly,
    Quarantined,
    Retired,
}

impl PoolStatus {
    pub fn accepts_evidence(self) -> bool {
        matches!(self, Self::Active | Self::NettingOnly | Self::Throttled)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(
            self,
            Self::Active | Self::NettingOnly | Self::Throttled | Self::SettlementOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyImageFamily {
    RingCtKeyImage,
    SeraphisNullifier,
    HybridKeyImageNullifier,
    AtomicSwapClaim,
    BridgeWithdrawal,
    WalletRecovery,
}

impl KeyImageFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RingCtKeyImage => "ringct_key_image",
            Self::SeraphisNullifier => "seraphis_nullifier",
            Self::HybridKeyImageNullifier => "hybrid_key_image_nullifier",
            Self::AtomicSwapClaim => "atomic_swap_claim",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Admitted,
    Attested,
    Netted,
    Settled,
    Rebated,
    Quarantined,
    Rejected,
    Expired,
    Redacted,
}

impl EvidenceStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Admitted | Self::Attested | Self::Netted
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rebated | Self::Rejected | Self::Expired | Self::Redacted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    KeyImageUniquenessChecked,
    MoneroInclusionChecked,
    NullifierBucketSealed,
    LiquidityReserveChecked,
    FeeCapObserved,
    PrivacySetObserved,
    SettlementReady,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Quorum,
    StrongQuorum,
    Applied,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Quorum | Self::StrongQuorum | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingMode {
    SameAsset,
    CrossPool,
    FastExitOffset,
    RebateOffset,
    EmergencyCompression,
}

impl NettingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameAsset => "same_asset",
            Self::CrossPool => "cross_pool",
            Self::FastExitOffset => "fast_exit_offset",
            Self::RebateOffset => "rebate_offset",
            Self::EmergencyCompression => "emergency_compression",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    Collecting,
    Balanced,
    SettlementReady,
    Settled,
    Expired,
    Quarantined,
}

impl NettingStatus {
    pub fn accepts_evidence(self) -> bool {
        matches!(self, Self::Open | Self::Collecting | Self::Balanced)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    SettleFast,
    SettleNetted,
    SettleWithRebate,
    DeferForPrivacy,
    Quarantine,
    Reject,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettleFast => "settle_fast",
            Self::SettleNetted => "settle_netted",
            Self::SettleWithRebate => "settle_with_rebate",
            Self::DeferForPrivacy => "defer_for_privacy",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub key_image_evidence_suite: String,
    pub pq_attestation_suite: String,
    pub liquidity_netting_suite: String,
    pub settlement_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub fast_settlement_slots: u64,
    pub netting_window_slots: u64,
    pub evidence_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub settlement_ttl_slots: u64,
    pub max_settlement_fee_bps: u64,
    pub target_net_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_pool_reserve_atomic_units: u64,
    pub min_nettable_atomic_units: u64,
    pub max_public_redaction_bytes: u64,
    pub public_operator_summaries: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            key_image_evidence_suite: KEY_IMAGE_EVIDENCE_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            liquidity_netting_suite: LIQUIDITY_NETTING_SUITE.to_string(),
            settlement_suite: SETTLEMENT_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            fast_settlement_slots: DEFAULT_FAST_SETTLEMENT_SLOTS,
            netting_window_slots: DEFAULT_NETTING_WINDOW_SLOTS,
            evidence_ttl_slots: DEFAULT_EVIDENCE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            settlement_ttl_slots: DEFAULT_SETTLEMENT_TTL_SLOTS,
            max_settlement_fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            target_net_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_pool_reserve_atomic_units: DEFAULT_MIN_POOL_RESERVE_ATOMIC_UNITS,
            min_nettable_atomic_units: DEFAULT_MIN_NETTABLE_ATOMIC_UNITS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            public_operator_summaries: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_opened: u64,
    pub evidence_submitted: u64,
    pub evidence_attested: u64,
    pub duplicate_preventions: u64,
    pub pq_attestations_recorded: u64,
    pub netting_batches_opened: u64,
    pub evidence_netted: u64,
    pub settlements_executed: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub total_gross_atomic_units: u64,
    pub total_net_atomic_units: u64,
    pub total_fee_atomic_units: u64,
    pub total_rebate_atomic_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub pools_root: String,
    pub key_image_evidence_root: String,
    pub pq_attestations_root: String,
    pub netting_batches_root: String,
    pub settlements_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub counters_root: String,
    pub public_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            pools_root: empty_root("pools"),
            key_image_evidence_root: empty_root("key-image-evidence"),
            pq_attestations_root: empty_root("pq-attestations"),
            netting_batches_root: empty_root("netting-batches"),
            settlements_root: empty_root("settlements"),
            rebates_root: empty_root("rebates"),
            redaction_budgets_root: empty_root("redaction-budgets"),
            operator_summaries_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            public_root: empty_root("public"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPool {
    pub pool_id: String,
    pub pool_kind: PoolKind,
    pub status: PoolStatus,
    pub asset_id: String,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_atomic_units: u64,
    pub available_atomic_units: u64,
    pub netted_atomic_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub active_evidence_count: u64,
    pub active_batch_count: u64,
    pub opened_slot: u64,
    pub updated_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyImageEvidence {
    pub evidence_id: String,
    pub pool_id: String,
    pub family: KeyImageFamily,
    pub status: EvidenceStatus,
    pub sealed_key_image_root: String,
    pub nullifier_commitment_root: String,
    pub monero_tx_set_root: String,
    pub membership_witness_root: String,
    pub amount_commitment_root: String,
    pub bridge_receipt_root: String,
    pub privacy_set_size: u64,
    pub gross_atomic_units: u64,
    pub requested_fee_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub attestation_count: u64,
    pub quorum_weight_bps: u64,
    pub netting_batch_id: Option<String>,
    pub settlement_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub evidence_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub min_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub observed_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub mode: NettingMode,
    pub status: NettingStatus,
    pub evidence_root: String,
    pub counterparty_root: String,
    pub gross_atomic_units: u64,
    pub net_atomic_units: u64,
    pub fee_atomic_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub evidence_count: u64,
    pub opened_slot: u64,
    pub closes_slot: u64,
    pub settlement_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySettlement {
    pub settlement_id: String,
    pub pool_id: String,
    pub batch_id: Option<String>,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub key_image_evidence_root: String,
    pub liquidity_delta_root: String,
    pub operator_receipt_root: String,
    pub gross_atomic_units: u64,
    pub net_atomic_units: u64,
    pub fee_atomic_units: u64,
    pub settled_slot: u64,
    pub expires_slot: u64,
    pub evidence_count: u64,
    pub final_privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub pool_id: String,
    pub sponsor_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_atomic_units: u64,
    pub rebate_bps: u64,
    pub reason: String,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub roots_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub slot: u64,
    pub pool_count: u64,
    pub active_pool_count: u64,
    pub evidence_count: u64,
    pub netting_batch_count: u64,
    pub settlement_count: u64,
    pub rebate_count: u64,
    pub gross_atomic_units: u64,
    pub net_atomic_units: u64,
    pub median_fee_bps: u64,
    pub target_net_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub public_root: String,
    pub privacy_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, LiquidityPool>,
    pub key_image_evidence: BTreeMap<String, KeyImageEvidence>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub netting_batches: BTreeMap<String, NettingBatch>,
    pub settlements: BTreeMap<String, LiquiditySettlement>,
    pub rebates: BTreeMap<String, SettlementRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            key_image_evidence: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolRequest {
    pub pool_kind: PoolKind,
    pub asset_id: String,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_atomic_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitKeyImageEvidenceRequest {
    pub pool_id: String,
    pub family: KeyImageFamily,
    pub sealed_key_image_root: String,
    pub nullifier_commitment_root: String,
    pub monero_tx_set_root: String,
    pub membership_witness_root: String,
    pub amount_commitment_root: String,
    pub bridge_receipt_root: String,
    pub privacy_set_size: u64,
    pub gross_atomic_units: u64,
    pub requested_fee_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordPqAttestationRequest {
    pub evidence_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub min_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub observed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenNettingBatchRequest {
    pub pool_id: String,
    pub mode: NettingMode,
    pub evidence_ids: Vec<String>,
    pub evidence_root: String,
    pub counterparty_root: String,
    pub gross_atomic_units: u64,
    pub net_atomic_units: u64,
    pub fee_atomic_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecuteSettlementRequest {
    pub pool_id: String,
    pub batch_id: Option<String>,
    pub evidence_ids: Vec<String>,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub key_image_evidence_root: String,
    pub liquidity_delta_root: String,
    pub operator_receipt_root: String,
    pub gross_atomic_units: u64,
    pub net_atomic_units: u64,
    pub fee_atomic_units: u64,
    pub settled_slot: u64,
    pub final_privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub settlement_id: String,
    pub sponsor_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_atomic_units: u64,
    pub rebate_bps: u64,
    pub reason: String,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub slot: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

impl State {
    pub fn open_pool(&mut self, request: OpenPoolRequest) -> Result<String> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "pools")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_hashish(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_hashish(&request.public_hint_root, "public_hint_root")?;
        ensure_hashish(&request.reserve_commitment_root, "reserve_commitment_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure!(
            request.max_fee_bps <= self.config.max_settlement_fee_bps,
            "max_fee_bps exceeds configured settlement fee cap"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy_set_size below configured minimum"
        );
        ensure!(
            request.reserve_atomic_units >= self.config.min_pool_reserve_atomic_units,
            "reserve_atomic_units below configured minimum"
        );

        let pool_id = stable_id(
            "pool",
            &[
                HashPart::Str(request.pool_kind.as_str()),
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.sealed_pool_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        ensure!(!self.pools.contains_key(&pool_id), "pool already exists");
        self.pools.insert(
            pool_id.clone(),
            LiquidityPool {
                pool_id: pool_id.clone(),
                pool_kind: request.pool_kind,
                status: PoolStatus::Active,
                asset_id: request.asset_id,
                sealed_pool_root: request.sealed_pool_root,
                public_hint_root: request.public_hint_root,
                reserve_commitment_root: request.reserve_commitment_root,
                reserve_atomic_units: request.reserve_atomic_units,
                available_atomic_units: request.reserve_atomic_units,
                netted_atomic_units: 0,
                max_fee_bps: request.max_fee_bps,
                privacy_set_size: request.privacy_set_size,
                active_evidence_count: 0,
                active_batch_count: 0,
                opened_slot: request.opened_slot,
                updated_slot: request.opened_slot,
            },
        );
        self.counters.pools_opened += 1;
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn submit_key_image_evidence(
        &mut self,
        request: SubmitKeyImageEvidenceRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.key_image_evidence.len(),
            MAX_KEY_IMAGE_EVIDENCE,
            "key_image_evidence",
        )?;
        ensure_bps(request.requested_fee_bps, "requested_fee_bps")?;
        ensure_hashish(&request.sealed_key_image_root, "sealed_key_image_root")?;
        ensure_hashish(
            &request.nullifier_commitment_root,
            "nullifier_commitment_root",
        )?;
        ensure_hashish(&request.monero_tx_set_root, "monero_tx_set_root")?;
        ensure_hashish(&request.membership_witness_root, "membership_witness_root")?;
        ensure_hashish(&request.amount_commitment_root, "amount_commitment_root")?;
        ensure_hashish(&request.bridge_receipt_root, "bridge_receipt_root")?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy_set_size below configured minimum"
        );
        ensure!(
            request.gross_atomic_units >= self.config.min_nettable_atomic_units,
            "gross_atomic_units below configured netting minimum"
        );
        ensure!(
            request.requested_fee_bps <= self.config.max_settlement_fee_bps,
            "requested fee exceeds configured cap"
        );
        ensure!(
            !self
                .consumed_nullifier_roots
                .contains(&request.nullifier_commitment_root),
            "nullifier commitment root already consumed"
        );
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| "pool not found".to_string())?;
        ensure!(
            pool.status.accepts_evidence(),
            "pool does not accept key-image evidence"
        );
        ensure!(
            request.privacy_set_size
                >= pool
                    .privacy_set_size
                    .min(self.config.target_privacy_set_size),
            "evidence privacy set is weaker than pool target"
        );

        let evidence_id = stable_id(
            "evidence",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(request.family.as_str()),
                HashPart::Str(&request.nullifier_commitment_root),
                HashPart::Str(&request.bridge_receipt_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        ensure!(
            !self.key_image_evidence.contains_key(&evidence_id),
            "evidence already exists"
        );

        self.consumed_nullifier_roots
            .insert(request.nullifier_commitment_root.clone());
        pool.active_evidence_count += 1;
        pool.updated_slot = request.submitted_slot;
        self.key_image_evidence.insert(
            evidence_id.clone(),
            KeyImageEvidence {
                evidence_id: evidence_id.clone(),
                pool_id: request.pool_id,
                family: request.family,
                status: EvidenceStatus::Admitted,
                sealed_key_image_root: request.sealed_key_image_root,
                nullifier_commitment_root: request.nullifier_commitment_root,
                monero_tx_set_root: request.monero_tx_set_root,
                membership_witness_root: request.membership_witness_root,
                amount_commitment_root: request.amount_commitment_root,
                bridge_receipt_root: request.bridge_receipt_root,
                privacy_set_size: request.privacy_set_size,
                gross_atomic_units: request.gross_atomic_units,
                requested_fee_bps: request.requested_fee_bps,
                submitted_slot: request.submitted_slot,
                expires_slot: request.submitted_slot + self.config.evidence_ttl_slots,
                attestation_count: 0,
                quorum_weight_bps: 0,
                netting_batch_id: None,
                settlement_id: None,
            },
        );
        self.counters.evidence_submitted += 1;
        self.counters.total_gross_atomic_units = self
            .counters
            .total_gross_atomic_units
            .saturating_add(request.gross_atomic_units);
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn record_pq_attestation(&mut self, request: RecordPqAttestationRequest) -> Result<String> {
        ensure_capacity(
            self.pq_attestations.len(),
            MAX_PQ_ATTESTATIONS,
            "pq_attestations",
        )?;
        ensure_hashish(&request.committee_root, "committee_root")?;
        ensure_hashish(&request.statement_root, "statement_root")?;
        ensure_hashish(&request.pq_signature_root, "pq_signature_root")?;
        ensure_hashish(&request.kem_ciphertext_root, "kem_ciphertext_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        ensure!(
            request.min_security_bits >= self.config.min_pq_security_bits,
            "min_security_bits below configured PQ floor"
        );
        let evidence = self
            .key_image_evidence
            .get_mut(&request.evidence_id)
            .ok_or_else(|| "evidence not found".to_string())?;
        ensure!(evidence.status.live(), "evidence is not live");

        let status = if request.quorum_weight_bps >= DEFAULT_STRONG_ATTESTATION_QUORUM_BPS {
            AttestationStatus::StrongQuorum
        } else if request.quorum_weight_bps >= self.config.min_pq_security_bits as u64
            && request.quorum_weight_bps >= DEFAULT_MIN_ATTESTATION_QUORUM_BPS
        {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Submitted
        };
        let attestation_id = stable_id(
            "pq-attestation",
            &[
                HashPart::Str(&request.evidence_id),
                HashPart::Str(&request.statement_root),
                HashPart::Str(&request.pq_signature_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        ensure!(
            !self.pq_attestations.contains_key(&attestation_id),
            "attestation already exists"
        );
        self.pq_attestations.insert(
            attestation_id.clone(),
            PqAttestation {
                attestation_id: attestation_id.clone(),
                evidence_id: request.evidence_id.clone(),
                kind: request.kind,
                status,
                committee_root: request.committee_root,
                statement_root: request.statement_root,
                pq_signature_root: request.pq_signature_root,
                kem_ciphertext_root: request.kem_ciphertext_root,
                min_security_bits: request.min_security_bits,
                quorum_weight_bps: request.quorum_weight_bps,
                observed_slot: request.observed_slot,
                expires_slot: request.observed_slot + self.config.attestation_ttl_slots,
            },
        );
        evidence.attestation_count += 1;
        evidence.quorum_weight_bps = evidence.quorum_weight_bps.max(request.quorum_weight_bps);
        if status.accepted() {
            evidence.status = EvidenceStatus::Attested;
            self.counters.evidence_attested += 1;
        }
        self.counters.pq_attestations_recorded += 1;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_netting_batch(&mut self, request: OpenNettingBatchRequest) -> Result<String> {
        ensure_capacity(
            self.netting_batches.len(),
            MAX_NETTING_BATCHES,
            "netting_batches",
        )?;
        ensure!(
            !request.evidence_ids.is_empty(),
            "evidence_ids must not be empty"
        );
        ensure_hashish(&request.evidence_root, "evidence_root")?;
        ensure_hashish(&request.counterparty_root, "counterparty_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy_set_size below configured minimum"
        );
        ensure!(
            request.net_atomic_units <= request.gross_atomic_units,
            "net_atomic_units must be <= gross_atomic_units"
        );
        ensure!(
            request.fee_atomic_units <= request.gross_atomic_units,
            "fee_atomic_units must be <= gross_atomic_units"
        );
        ensure!(
            request.max_fee_bps <= self.config.max_settlement_fee_bps,
            "max_fee_bps exceeds configured settlement fee cap"
        );
        let pool_status = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "pool not found".to_string())?
            .status;
        ensure!(
            pool_status.accepts_settlement(),
            "pool cannot net liquidity"
        );

        let evidence_count = request.evidence_ids.len() as u64;
        for evidence_id in &request.evidence_ids {
            let evidence = self
                .key_image_evidence
                .get(evidence_id)
                .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;
            ensure!(
                evidence.pool_id == request.pool_id,
                "evidence pool mismatch"
            );
            ensure!(
                matches!(
                    evidence.status,
                    EvidenceStatus::Admitted | EvidenceStatus::Attested
                ),
                "evidence must be admitted or attested before netting"
            );
            ensure!(
                evidence.quorum_weight_bps >= DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
                "evidence lacks minimum attestation quorum"
            );
        }

        let batch_id = stable_id(
            "netting-batch",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(request.mode.as_str()),
                HashPart::Str(&request.evidence_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        ensure!(
            !self.netting_batches.contains_key(&batch_id),
            "netting batch already exists"
        );
        for evidence_id in &request.evidence_ids {
            let evidence = self
                .key_image_evidence
                .get_mut(evidence_id)
                .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;
            evidence.status = EvidenceStatus::Netted;
            evidence.netting_batch_id = Some(batch_id.clone());
            self.counters.evidence_netted += 1;
        }
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.active_batch_count += 1;
            pool.netted_atomic_units = pool
                .netted_atomic_units
                .saturating_add(request.net_atomic_units);
            pool.available_atomic_units = pool
                .available_atomic_units
                .saturating_sub(request.net_atomic_units);
            pool.updated_slot = request.opened_slot;
        }

        self.netting_batches.insert(
            batch_id.clone(),
            NettingBatch {
                batch_id: batch_id.clone(),
                pool_id: request.pool_id,
                mode: request.mode,
                status: NettingStatus::SettlementReady,
                evidence_root: request.evidence_root,
                counterparty_root: request.counterparty_root,
                gross_atomic_units: request.gross_atomic_units,
                net_atomic_units: request.net_atomic_units,
                fee_atomic_units: request.fee_atomic_units,
                max_fee_bps: request.max_fee_bps,
                privacy_set_size: request.privacy_set_size,
                evidence_count,
                opened_slot: request.opened_slot,
                closes_slot: request.opened_slot + self.config.netting_window_slots,
                settlement_id: None,
            },
        );
        self.counters.netting_batches_opened += 1;
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn execute_settlement(&mut self, request: ExecuteSettlementRequest) -> Result<String> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        ensure_hashish(&request.settlement_root, "settlement_root")?;
        ensure_hashish(&request.key_image_evidence_root, "key_image_evidence_root")?;
        ensure_hashish(&request.liquidity_delta_root, "liquidity_delta_root")?;
        ensure_hashish(&request.operator_receipt_root, "operator_receipt_root")?;
        ensure!(
            request.net_atomic_units <= request.gross_atomic_units,
            "net_atomic_units must be <= gross_atomic_units"
        );
        ensure!(
            request.fee_atomic_units <= request.gross_atomic_units,
            "fee_atomic_units must be <= gross_atomic_units"
        );
        ensure!(
            request.final_privacy_set_size >= self.config.min_privacy_set_size,
            "final_privacy_set_size below configured minimum"
        );
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "pool not found".to_string())?;
        ensure!(
            pool.status.accepts_settlement(),
            "pool does not accept settlement"
        );
        if let Some(batch_id) = &request.batch_id {
            let batch = self
                .netting_batches
                .get(batch_id)
                .ok_or_else(|| "netting batch not found".to_string())?;
            ensure!(batch.pool_id == request.pool_id, "batch pool mismatch");
            ensure!(
                batch.status == NettingStatus::SettlementReady,
                "netting batch is not settlement ready"
            );
        }
        for evidence_id in &request.evidence_ids {
            let evidence = self
                .key_image_evidence
                .get(evidence_id)
                .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;
            ensure!(
                evidence.pool_id == request.pool_id,
                "evidence pool mismatch"
            );
            ensure!(
                matches!(
                    evidence.status,
                    EvidenceStatus::Attested | EvidenceStatus::Netted
                ),
                "evidence is not settlement ready"
            );
        }
        ensure!(
            pool.available_atomic_units
                .saturating_add(pool.netted_atomic_units)
                >= request.net_atomic_units,
            "insufficient pool liquidity"
        );

        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::Str(&request.settlement_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        ensure!(
            !self.settlements.contains_key(&settlement_id),
            "settlement already exists"
        );
        for evidence_id in &request.evidence_ids {
            let evidence = self
                .key_image_evidence
                .get_mut(evidence_id)
                .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;
            evidence.status = EvidenceStatus::Settled;
            evidence.settlement_id = Some(settlement_id.clone());
        }
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.netting_batches.get_mut(batch_id) {
                batch.status = NettingStatus::Settled;
                batch.settlement_id = Some(settlement_id.clone());
            }
        }
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.netted_atomic_units = pool
                .netted_atomic_units
                .saturating_sub(request.net_atomic_units);
            pool.updated_slot = request.settled_slot;
        }

        self.settlements.insert(
            settlement_id.clone(),
            LiquiditySettlement {
                settlement_id: settlement_id.clone(),
                pool_id: request.pool_id,
                batch_id: request.batch_id,
                decision: request.decision,
                settlement_root: request.settlement_root,
                key_image_evidence_root: request.key_image_evidence_root,
                liquidity_delta_root: request.liquidity_delta_root,
                operator_receipt_root: request.operator_receipt_root,
                gross_atomic_units: request.gross_atomic_units,
                net_atomic_units: request.net_atomic_units,
                fee_atomic_units: request.fee_atomic_units,
                settled_slot: request.settled_slot,
                expires_slot: request.settled_slot + self.config.settlement_ttl_slots,
                evidence_count: request.evidence_ids.len() as u64,
                final_privacy_set_size: request.final_privacy_set_size,
            },
        );
        self.counters.settlements_executed += 1;
        self.counters.total_net_atomic_units = self
            .counters
            .total_net_atomic_units
            .saturating_add(request.net_atomic_units);
        self.counters.total_fee_atomic_units = self
            .counters
            .total_fee_atomic_units
            .saturating_add(request.fee_atomic_units);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<String> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_hashish(&request.sponsor_root, "sponsor_root")?;
        ensure_hashish(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_non_empty(&request.reason, "reason")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        ensure!(
            request.rebate_bps <= self.config.rebate_bps,
            "rebate_bps exceeds configured cap"
        );
        let settlement = self
            .settlements
            .get(&request.settlement_id)
            .ok_or_else(|| "settlement not found".to_string())?;
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.settlement_id),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        ensure!(
            !self.rebates.contains_key(&rebate_id),
            "rebate already exists"
        );
        self.rebates.insert(
            rebate_id.clone(),
            SettlementRebate {
                rebate_id: rebate_id.clone(),
                settlement_id: request.settlement_id,
                pool_id: settlement.pool_id.clone(),
                sponsor_root: request.sponsor_root,
                beneficiary_group_root: request.beneficiary_group_root,
                asset_id: request.asset_id,
                amount_atomic_units: request.amount_atomic_units,
                rebate_bps: request.rebate_bps,
                reason: request.reason,
                issued_slot: request.issued_slot,
                expires_slot: request.expires_slot,
            },
        );
        self.counters.rebates_issued += 1;
        self.counters.total_rebate_atomic_units = self
            .counters
            .total_rebate_atomic_units
            .saturating_add(request.amount_atomic_units);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction_budgets",
        )?;
        ensure!(
            !request.public_fields.is_empty(),
            "public_fields must not be empty"
        );
        ensure!(
            !request.redacted_fields.is_empty(),
            "redacted_fields must not be empty"
        );
        ensure!(
            request.actual_public_bytes <= request.max_public_bytes,
            "actual_public_bytes exceeds max_public_bytes"
        );
        ensure!(
            request.max_public_bytes <= self.config.max_public_redaction_bytes,
            "max_public_bytes exceeds configured limit"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy_set_size below configured minimum"
        );
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::U64(request.actual_public_bytes),
                HashPart::U64(request.privacy_set_size),
            ],
        );
        self.redaction_budgets.insert(
            budget_id.clone(),
            RedactionBudget {
                budget_id: budget_id.clone(),
                target_id: request.target_id,
                public_fields: request.public_fields,
                redacted_fields: request.redacted_fields,
                max_public_bytes: request.max_public_bytes,
                actual_public_bytes: request.actual_public_bytes,
                privacy_set_size: request.privacy_set_size,
                roots_only: true,
            },
        );
        self.counters.redaction_budgets_published += 1;
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let public_root = self.roots.public_root.clone();
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::U64(request.slot),
                HashPart::Str(&public_root),
                HashPart::U64(self.counters.operator_summaries_published + 1),
            ],
        );
        let active_pool_count = self
            .pools
            .values()
            .filter(|pool| pool.status.accepts_settlement())
            .count() as u64;
        self.operator_summaries.insert(
            summary_id.clone(),
            OperatorSummary {
                summary_id: summary_id.clone(),
                slot: request.slot,
                pool_count: self.pools.len() as u64,
                active_pool_count,
                evidence_count: self.key_image_evidence.len() as u64,
                netting_batch_count: self.netting_batches.len() as u64,
                settlement_count: self.settlements.len() as u64,
                rebate_count: self.rebates.len() as u64,
                gross_atomic_units: self.counters.total_gross_atomic_units,
                net_atomic_units: self.counters.total_net_atomic_units,
                median_fee_bps: request.median_fee_bps,
                target_net_fee_bps: self.config.target_net_fee_bps,
                attestation_quorum_bps: request.attestation_quorum_bps,
                public_root,
                privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            },
        );
        self.counters.operator_summaries_published += 1;
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.pools_root = map_root("pools", &self.pools);
        self.roots.key_image_evidence_root =
            map_root("key-image-evidence", &self.key_image_evidence);
        self.roots.pq_attestations_root = map_root("pq-attestations", &self.pq_attestations);
        self.roots.netting_batches_root = map_root("netting-batches", &self.netting_batches);
        self.roots.settlements_root = map_root("settlements", &self.settlements);
        self.roots.rebates_root = map_root("rebates", &self.rebates);
        self.roots.redaction_budgets_root = map_root("redaction-budgets", &self.redaction_budgets);
        self.roots.operator_summaries_root =
            map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.public_root = merkle_root(
            "bridge-key-image-liquidity-settlement:public-root",
            &[json!({
                "protocol_version": self.config.protocol_version,
                "pools_root": self.roots.pools_root,
                "key_image_evidence_root": self.roots.key_image_evidence_root,
                "pq_attestations_root": self.roots.pq_attestations_root,
                "netting_batches_root": self.roots.netting_batches_root,
                "settlements_root": self.roots.settlements_root,
                "rebates_root": self.roots.rebates_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "operator_summaries_root": self.roots.operator_summaries_root,
                "privacy_boundary": PRIVACY_BOUNDARY,
            })],
        );
        self.roots.state_root = merkle_root(
            "bridge-key-image-liquidity-settlement:state-root",
            &[json!({
                "config": self.config,
                "counters": self.counters,
                "roots": {
                    "pools_root": self.roots.pools_root,
                    "key_image_evidence_root": self.roots.key_image_evidence_root,
                    "pq_attestations_root": self.roots.pq_attestations_root,
                    "netting_batches_root": self.roots.netting_batches_root,
                    "settlements_root": self.roots.settlements_root,
                    "rebates_root": self.roots.rebates_root,
                    "redaction_budgets_root": self.roots.redaction_budgets_root,
                    "operator_summaries_root": self.roots.operator_summaries_root,
                    "counters_root": self.roots.counters_root,
                    "public_root": self.roots.public_root,
                }
            })],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "public_root_suite": PUBLIC_ROOT_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "counters": self.counters,
            "roots": self.roots,
            "pool_count": self.pools.len(),
            "evidence_count": self.key_image_evidence.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "netting_batch_count": self.netting_batches.len(),
            "settlement_count": self.settlements.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "pools": self.pools.values().map(|pool| json!({
                "pool_id": pool.pool_id,
                "pool_kind": pool.pool_kind,
                "status": pool.status,
                "asset_id": pool.asset_id,
                "public_hint_root": pool.public_hint_root,
                "reserve_atomic_units": pool.reserve_atomic_units,
                "available_atomic_units": pool.available_atomic_units,
                "max_fee_bps": pool.max_fee_bps,
                "privacy_set_size": pool.privacy_set_size,
                "active_evidence_count": pool.active_evidence_count,
                "active_batch_count": pool.active_batch_count,
            })).collect::<Vec<_>>(),
            "key_image_evidence": self.key_image_evidence.values().map(|evidence| json!({
                "evidence_id": evidence.evidence_id,
                "pool_id": evidence.pool_id,
                "family": evidence.family,
                "status": evidence.status,
                "monero_tx_set_root": evidence.monero_tx_set_root,
                "bridge_receipt_root": evidence.bridge_receipt_root,
                "privacy_set_size": evidence.privacy_set_size,
                "gross_atomic_units": evidence.gross_atomic_units,
                "requested_fee_bps": evidence.requested_fee_bps,
                "submitted_slot": evidence.submitted_slot,
                "expires_slot": evidence.expires_slot,
                "attestation_count": evidence.attestation_count,
                "quorum_weight_bps": evidence.quorum_weight_bps,
                "netting_batch_id": evidence.netting_batch_id,
                "settlement_id": evidence.settlement_id,
            })).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(|attestation| json!({
                "attestation_id": attestation.attestation_id,
                "evidence_id": attestation.evidence_id,
                "kind": attestation.kind,
                "status": attestation.status,
                "statement_root": attestation.statement_root,
                "min_security_bits": attestation.min_security_bits,
                "quorum_weight_bps": attestation.quorum_weight_bps,
                "observed_slot": attestation.observed_slot,
                "expires_slot": attestation.expires_slot,
            })).collect::<Vec<_>>(),
            "netting_batches": self.netting_batches.values().collect::<Vec<_>>(),
            "settlements": self.settlements.values().collect::<Vec<_>>(),
            "rebates": self.rebates.values().collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool_id = state
        .open_pool(OpenPoolRequest {
            pool_kind: PoolKind::FastExit,
            asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            reserve_commitment_root: sample_hash("reserve", 1),
            reserve_atomic_units: 180_000_000_000,
            max_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet key-image liquidity pool opened");
    let evidence_a = state
        .submit_key_image_evidence(SubmitKeyImageEvidenceRequest {
            pool_id: pool_id.clone(),
            family: KeyImageFamily::RingCtKeyImage,
            sealed_key_image_root: sample_hash("sealed-key-image", 1),
            nullifier_commitment_root: sample_hash("nullifier", 1),
            monero_tx_set_root: sample_hash("monero-tx-set", 1),
            membership_witness_root: sample_hash("membership", 1),
            amount_commitment_root: sample_hash("amount", 1),
            bridge_receipt_root: sample_hash("bridge-receipt", 1),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            gross_atomic_units: 12_500_000_000,
            requested_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            submitted_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet key-image evidence submitted");
    let evidence_b = state
        .submit_key_image_evidence(SubmitKeyImageEvidenceRequest {
            pool_id: pool_id.clone(),
            family: KeyImageFamily::HybridKeyImageNullifier,
            sealed_key_image_root: sample_hash("sealed-key-image", 2),
            nullifier_commitment_root: sample_hash("nullifier", 2),
            monero_tx_set_root: sample_hash("monero-tx-set", 2),
            membership_witness_root: sample_hash("membership", 2),
            amount_commitment_root: sample_hash("amount", 2),
            bridge_receipt_root: sample_hash("bridge-receipt", 2),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            gross_atomic_units: 8_250_000_000,
            requested_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            submitted_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet second key-image evidence submitted");
    for (index, evidence_id) in [evidence_a.clone(), evidence_b.clone()]
        .into_iter()
        .enumerate()
    {
        state
            .record_pq_attestation(RecordPqAttestationRequest {
                evidence_id,
                kind: AttestationKind::SettlementReady,
                committee_root: sample_hash("committee", index as u64 + 1),
                statement_root: sample_hash("statement", index as u64 + 1),
                pq_signature_root: sample_hash("pq-signature", index as u64 + 1),
                kem_ciphertext_root: sample_hash("kem-ciphertext", index as u64 + 1),
                min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
                observed_slot: DEVNET_SLOT + 4 + index as u64,
            })
            .expect("devnet PQ attestation recorded");
    }
    let batch_id = state
        .open_netting_batch(OpenNettingBatchRequest {
            pool_id: pool_id.clone(),
            mode: NettingMode::FastExitOffset,
            evidence_ids: vec![evidence_a.clone(), evidence_b.clone()],
            evidence_root: sample_hash("evidence-root", 1),
            counterparty_root: sample_hash("counterparty", 1),
            gross_atomic_units: 20_750_000_000,
            net_atomic_units: 3_750_000_000,
            fee_atomic_units: 2_900_000,
            max_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet netting batch opened");
    let settlement_id = state
        .execute_settlement(ExecuteSettlementRequest {
            pool_id: pool_id.clone(),
            batch_id: Some(batch_id),
            evidence_ids: vec![evidence_a, evidence_b],
            decision: SettlementDecision::SettleWithRebate,
            settlement_root: sample_hash("settlement", 1),
            key_image_evidence_root: sample_hash("settlement-evidence", 1),
            liquidity_delta_root: sample_hash("liquidity-delta", 1),
            operator_receipt_root: sample_hash("operator-receipt", 1),
            gross_atomic_units: 20_750_000_000,
            net_atomic_units: 3_750_000_000,
            fee_atomic_units: 2_900_000,
            settled_slot: DEVNET_SLOT + 10,
            final_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet settlement executed");
    state
        .issue_rebate(IssueRebateRequest {
            settlement_id: settlement_id.clone(),
            sponsor_root: sample_hash("sponsor", 1),
            beneficiary_group_root: sample_hash("beneficiary", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_atomic_units: 1_450_000,
            rebate_bps: DEFAULT_REBATE_BPS,
            reason: "low_fee_netting_rebate".to_string(),
            issued_slot: DEVNET_SLOT + 11,
            expires_slot: DEVNET_SLOT + DEFAULT_SETTLEMENT_TTL_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: settlement_id,
            public_fields: [
                "settlement_id",
                "pool_id",
                "decision",
                "gross_atomic_units",
                "net_atomic_units",
                "fee_atomic_units",
                "final_privacy_set_size",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "sealed_key_image_root",
                "nullifier_commitment_root",
                "membership_witness_root",
                "amount_commitment_root",
                "pq_signature_root",
                "kem_ciphertext_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 1_104,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            slot: DEVNET_SLOT + 12,
            median_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .open_pool(OpenPoolRequest {
            pool_kind: PoolKind::BackstopReserve,
            asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            reserve_commitment_root: sample_hash("reserve", 2),
            reserve_atomic_units: 240_000_000_000,
            max_fee_bps: DEFAULT_TARGET_NET_FEE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_slot: DEVNET_SLOT + 32,
        })
        .expect("demo backstop pool opened");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("bridge-key-image-liquidity-settlement:{domain}:id"),
        parts,
        24,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("bridge-key-image-liquidity-settlement:{domain}"),
        &[],
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    merkle_root(
        &format!("bridge-key-image-liquidity-settlement:{domain}"),
        &[json!(value)],
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("bridge-key-image-liquidity-settlement:{domain}"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "bridge-key-image-liquidity-settlement:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_hashish(value: &str, name: &str) -> Result<()> {
    ensure_non_empty(value, name)?;
    if value.len() < 16 {
        return Err(format!("{name} must be a commitment/root-like value"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
