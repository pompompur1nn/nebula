use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialStateWitnessDeltaCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_DELTA_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-state-witness-delta-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_DELTA_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CACHE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-state-witness-delta-cache-v1";
pub const PQ_ENVELOPE_SUITE: &str = "ML-KEM-1024-threshold-witness-delta-cache-envelope-v1";
pub const WITNESS_DELTA_SUITE: &str = "nova-pq-confidential-state-witness-delta-v1";
pub const CONTRACT_DELTA_PACK_SUITE: &str =
    "private-contract-storage-delta-pack-recursive-witness-v1";
pub const LOW_FEE_COUPON_SUITE: &str = "low-fee-state-witness-delta-cache-coupon-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "privacy-budgeted-state-witness-redaction-root-v1";
pub const BRIDGE_HINT_SUITE: &str = "monero-bridge-output-witness-hint-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-witness-cache-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_880_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_560_000;
pub const DEVNET_EPOCH: u64 = 12_288;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_CACHE_HIT_BPS: u64 = 8_800;
pub const DEFAULT_TARGET_REFRESH_MS: u64 = 18;
pub const DEFAULT_MAX_REFRESH_MS: u64 = 80;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_COUPON_REBATE_BPS: u64 = 5;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET_BPS: u64 = 420;
pub const DEFAULT_DELTA_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_CACHE_LANES: usize = 65_536;
pub const DEFAULT_MAX_DELTA_RECORDS: usize = 4_194_304;
pub const DEFAULT_MAX_PRECONFIRMATION_HINTS: usize = 2_097_152;
pub const DEFAULT_MAX_CONTRACT_DELTA_PACKS: usize = 1_048_576;
pub const DEFAULT_MAX_CACHE_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_LOW_FEE_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_BRIDGE_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_ROOTS: usize = 2_097_152;
pub const DEFAULT_MAX_EVICTION_RECORDS: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHING_RECORDS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_SUMMARIES: usize = 2_097_152;

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
pub enum CacheLaneKind {
    HotAccounts,
    ContractStorage,
    DefiNetting,
    MoneroBridgeOutput,
    RecursiveProof,
    OracleFeed,
    FeeCoupon,
    EscapeHatch,
}

impl CacheLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccounts => "hot_accounts",
            Self::ContractStorage => "contract_storage",
            Self::DefiNetting => "defi_netting",
            Self::MoneroBridgeOutput => "monero_bridge_output",
            Self::RecursiveProof => "recursive_proof",
            Self::OracleFeed => "oracle_feed",
            Self::FeeCoupon => "fee_coupon",
            Self::EscapeHatch => "escape_hatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLaneStatus {
    Open,
    Hot,
    Saturated,
    Draining,
    Suspended,
    Retired,
}

impl CacheLaneStatus {
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::Saturated)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hot => "hot",
            Self::Saturated => "saturated",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaStatus {
    Proposed,
    Cached,
    Warmed,
    Consumed,
    Evicted,
    Challenged,
    Slashed,
    Expired,
}

impl DeltaStatus {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Proposed | Self::Cached | Self::Warmed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Cached => "cached",
            Self::Warmed => "warmed",
            Self::Consumed => "consumed",
            Self::Evicted => "evicted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintKind {
    PreconfirmationReadSet,
    ContractWriteSet,
    DefiSettlementPath,
    BridgeOutput,
    RecursiveProofCarry,
    CouponSpend,
}

impl HintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreconfirmationReadSet => "preconfirmation_read_set",
            Self::ContractWriteSet => "contract_write_set",
            Self::DefiSettlementPath => "defi_settlement_path",
            Self::BridgeOutput => "bridge_output",
            Self::RecursiveProofCarry => "recursive_proof_carry",
            Self::CouponSpend => "coupon_spend",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Cache,
    Hold,
    Reject,
    Slash,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingKind {
    InvalidPqCacheAttestation,
    WithheldWitnessDelta,
    BadRedactionRoot,
    BridgeOutputMismatch,
    CouponDoubleSpend,
    LaneEquivocation,
}

impl SlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqCacheAttestation => "invalid_pq_cache_attestation",
            Self::WithheldWitnessDelta => "withheld_witness_delta",
            Self::BadRedactionRoot => "bad_redaction_root",
            Self::BridgeOutputMismatch => "bridge_output_mismatch",
            Self::CouponDoubleSpend => "coupon_double_spend",
            Self::LaneEquivocation => "lane_equivocation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_cache_hit_bps: u64,
    pub target_refresh_ms: u64,
    pub max_refresh_ms: u64,
    pub max_user_fee_bps: u64,
    pub coupon_rebate_bps: u64,
    pub privacy_redaction_budget_bps: u64,
    pub delta_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_cache_lanes: usize,
    pub max_delta_records: usize,
    pub max_preconfirmation_hints: usize,
    pub max_contract_delta_packs: usize,
    pub max_cache_attestations: usize,
    pub max_low_fee_coupons: usize,
    pub max_bridge_hints: usize,
    pub max_redaction_roots: usize,
    pub max_eviction_records: usize,
    pub max_slashing_records: usize,
    pub max_public_summaries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_cache_hit_bps: DEFAULT_TARGET_CACHE_HIT_BPS,
            target_refresh_ms: DEFAULT_TARGET_REFRESH_MS,
            max_refresh_ms: DEFAULT_MAX_REFRESH_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            coupon_rebate_bps: DEFAULT_COUPON_REBATE_BPS,
            privacy_redaction_budget_bps: DEFAULT_PRIVACY_REDACTION_BUDGET_BPS,
            delta_ttl_blocks: DEFAULT_DELTA_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_cache_lanes: DEFAULT_MAX_CACHE_LANES,
            max_delta_records: DEFAULT_MAX_DELTA_RECORDS,
            max_preconfirmation_hints: DEFAULT_MAX_PRECONFIRMATION_HINTS,
            max_contract_delta_packs: DEFAULT_MAX_CONTRACT_DELTA_PACKS,
            max_cache_attestations: DEFAULT_MAX_CACHE_ATTESTATIONS,
            max_low_fee_coupons: DEFAULT_MAX_LOW_FEE_COUPONS,
            max_bridge_hints: DEFAULT_MAX_BRIDGE_HINTS,
            max_redaction_roots: DEFAULT_MAX_REDACTION_ROOTS,
            max_eviction_records: DEFAULT_MAX_EVICTION_RECORDS,
            max_slashing_records: DEFAULT_MAX_SLASHING_RECORDS,
            max_public_summaries: DEFAULT_MAX_PUBLIC_SUMMARIES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub delta_count: u64,
    pub live_delta_count: u64,
    pub hot_delta_count: u64,
    pub preconfirmation_hint_count: u64,
    pub contract_delta_pack_count: u64,
    pub cache_attestation_count: u64,
    pub low_fee_coupon_count: u64,
    pub bridge_hint_count: u64,
    pub redaction_root_count: u64,
    pub eviction_count: u64,
    pub slashing_count: u64,
    pub public_summary_count: u64,
    pub total_delta_bytes: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub average_refresh_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub cache_lane_root: String,
    pub delta_record_root: String,
    pub preconfirmation_hint_root: String,
    pub contract_delta_pack_root: String,
    pub cache_attestation_root: String,
    pub low_fee_coupon_root: String,
    pub bridge_hint_root: String,
    pub redaction_root: String,
    pub eviction_root: String,
    pub slashing_root: String,
    pub public_summary_root: String,
    pub operator_safe_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:empty",
            &[],
        );
        Self {
            cache_lane_root: empty.clone(),
            delta_record_root: empty.clone(),
            preconfirmation_hint_root: empty.clone(),
            contract_delta_pack_root: empty.clone(),
            cache_attestation_root: empty.clone(),
            low_fee_coupon_root: empty.clone(),
            bridge_hint_root: empty.clone(),
            redaction_root: empty.clone(),
            eviction_root: empty.clone(),
            slashing_root: empty.clone(),
            public_summary_root: empty.clone(),
            operator_safe_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLaneRecord {
    pub lane_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub kind: CacheLaneKind,
    pub status: CacheLaneStatus,
    pub capacity_bytes: u64,
    pub hot_bytes: u64,
    pub cache_hit_bps: u64,
    pub average_refresh_ms: u64,
    pub pq_attestation_key_commitment: String,
    pub privacy_fence_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessDeltaRecord {
    pub delta_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub account_hint_tag: String,
    pub base_state_root: String,
    pub delta_commitment_root: String,
    pub witness_blob_root: String,
    pub redacted_witness_root: String,
    pub nullifier_set_root: String,
    pub status: DeltaStatus,
    pub priority_score: u64,
    pub delta_bytes: u64,
    pub fee_micro_units: u64,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationWitnessHint {
    pub hint_id: String,
    pub delta_id: String,
    pub lane_id: String,
    pub hint_kind: HintKind,
    pub encrypted_hint_root: String,
    pub read_set_root: String,
    pub expected_output_root: String,
    pub preconfirmation_id: String,
    pub confidence_bps: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStorageDeltaPack {
    pub pack_id: String,
    pub contract_id: String,
    pub lane_id: String,
    pub storage_slot_root: String,
    pub read_delta_root: String,
    pub write_delta_root: String,
    pub recursive_proof_hint_root: String,
    pub defi_position_root: String,
    pub packed_delta_count: u64,
    pub compressed_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub delta_id: String,
    pub operator_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheCoupon {
    pub coupon_id: String,
    pub delta_id: String,
    pub sponsor_id: String,
    pub holder_commitment: String,
    pub fee_asset_id: String,
    pub rebate_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub nullifier_root: String,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeOutputWitnessHint {
    pub bridge_hint_id: String,
    pub delta_id: String,
    pub monero_output_commitment: String,
    pub output_index_root: String,
    pub ring_member_root: String,
    pub view_tag_root: String,
    pub bridge_batch_id: String,
    pub l2_claim_root: String,
    pub monero_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionRoot {
    pub redaction_id: String,
    pub delta_id: String,
    pub privacy_budget_bps: u64,
    pub redacted_field_root: String,
    pub auditor_view_root: String,
    pub operator_public_root: String,
    pub min_privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionRecord {
    pub eviction_id: String,
    pub delta_id: String,
    pub lane_id: String,
    pub evicted_by: String,
    pub reason: String,
    pub freed_bytes: u64,
    pub evicted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRecord {
    pub slashing_id: String,
    pub delta_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub kind: SlashingKind,
    pub evidence_root: String,
    pub slash_micro_units: u64,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub public_epoch: u64,
    pub cache_hit_bps: u64,
    pub hot_delta_count: u64,
    pub fee_saved_micro_units: u64,
    pub privacy_redaction_root: String,
    pub public_note: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheDeltaRequest {
    pub lane_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub account_hint_tag: String,
    pub base_state_root: String,
    pub witness_blob_root: String,
    pub nullifier_set_root: String,
    pub priority_score: u64,
    pub delta_bytes: u64,
    pub fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub lanes: BTreeMap<String, CacheLaneRecord>,
    pub deltas: BTreeMap<String, WitnessDeltaRecord>,
    pub preconfirmation_hints: BTreeMap<String, PreconfirmationWitnessHint>,
    pub contract_delta_packs: BTreeMap<String, ContractStorageDeltaPack>,
    pub cache_attestations: BTreeMap<String, PqCacheAttestation>,
    pub low_fee_coupons: BTreeMap<String, LowFeeCacheCoupon>,
    pub bridge_hints: BTreeMap<String, BridgeOutputWitnessHint>,
    pub redaction_roots: BTreeMap<String, PrivacyRedactionRoot>,
    pub evictions: BTreeMap<String, EvictionRecord>,
    pub slashings: BTreeMap<String, SlashingRecord>,
    pub public_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub hot_delta_index: BTreeMap<String, BTreeSet<String>>,
    pub counters: Counters,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            lanes: BTreeMap::new(),
            deltas: BTreeMap::new(),
            preconfirmation_hints: BTreeMap::new(),
            contract_delta_packs: BTreeMap::new(),
            cache_attestations: BTreeMap::new(),
            low_fee_coupons: BTreeMap::new(),
            bridge_hints: BTreeMap::new(),
            redaction_roots: BTreeMap::new(),
            evictions: BTreeMap::new(),
            slashings: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            hot_delta_index: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
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

    pub fn insert_lane(&mut self, record: CacheLaneRecord) -> Result<()> {
        if self.lanes.len() >= self.config.max_cache_lanes
            && !self.lanes.contains_key(&record.lane_id)
        {
            return Err("cache lane capacity exceeded".to_string());
        }
        self.hot_delta_index
            .entry(record.lane_id.clone())
            .or_default();
        self.lanes.insert(record.lane_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn cache_delta(&mut self, request: CacheDeltaRequest) -> Result<String> {
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| format!("unknown cache lane {}", request.lane_id))?;
        if !lane.status.accepts_writes() {
            return Err(format!(
                "cache lane {} is not accepting writes",
                request.lane_id
            ));
        }
        if self.deltas.len() >= self.config.max_delta_records {
            return Err("witness delta capacity exceeded".to_string());
        }
        if request.delta_bytes > lane.capacity_bytes {
            return Err("witness delta exceeds lane capacity".to_string());
        }

        let delta_json = json!({
            "account_hint_tag": request.account_hint_tag,
            "base_state_root": request.base_state_root,
            "contract_id": request.contract_id,
            "delta_bytes": request.delta_bytes,
            "fee_micro_units": request.fee_micro_units,
            "lane_id": request.lane_id,
            "nullifier_set_root": request.nullifier_set_root,
            "priority_score": request.priority_score,
            "shard_id": request.shard_id,
            "witness_blob_root": request.witness_blob_root,
        });
        let delta_id = domain_hash(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:delta-id",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.l2_height),
                HashPart::Json(&delta_json),
            ],
            32,
        );
        let delta_commitment_root = domain_hash(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:commitment",
            &[HashPart::Str(&delta_id), HashPart::Json(&delta_json)],
            32,
        );
        let redacted_witness_root = domain_hash(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:redacted",
            &[
                HashPart::Str(&delta_id),
                HashPart::Str(&request.account_hint_tag),
                HashPart::Str(&request.nullifier_set_root),
            ],
            32,
        );
        let record = WitnessDeltaRecord {
            delta_id: delta_id.clone(),
            lane_id: request.lane_id.clone(),
            shard_id: request.shard_id,
            contract_id: request.contract_id,
            account_hint_tag: request.account_hint_tag,
            base_state_root: request.base_state_root,
            delta_commitment_root,
            witness_blob_root: request.witness_blob_root,
            redacted_witness_root,
            nullifier_set_root: request.nullifier_set_root,
            status: DeltaStatus::Cached,
            priority_score: request.priority_score,
            delta_bytes: request.delta_bytes,
            fee_micro_units: request.fee_micro_units,
            expires_at_height: self.l2_height + self.config.delta_ttl_blocks,
            created_at_height: self.l2_height,
        };
        self.hot_delta_index
            .entry(request.lane_id)
            .or_default()
            .insert(delta_id.clone());
        self.deltas.insert(delta_id.clone(), record);
        self.refresh_roots();
        Ok(delta_id)
    }

    pub fn add_preconfirmation_hint(&mut self, hint: PreconfirmationWitnessHint) -> Result<()> {
        if self.preconfirmation_hints.len() >= self.config.max_preconfirmation_hints
            && !self.preconfirmation_hints.contains_key(&hint.hint_id)
        {
            return Err("preconfirmation witness hint capacity exceeded".to_string());
        }
        if !self.deltas.contains_key(&hint.delta_id) {
            return Err(format!("unknown delta {}", hint.delta_id));
        }
        self.preconfirmation_hints
            .insert(hint.hint_id.clone(), hint);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_contract_delta_pack(&mut self, pack: ContractStorageDeltaPack) -> Result<()> {
        if self.contract_delta_packs.len() >= self.config.max_contract_delta_packs
            && !self.contract_delta_packs.contains_key(&pack.pack_id)
        {
            return Err("contract storage delta pack capacity exceeded".to_string());
        }
        self.contract_delta_packs.insert(pack.pack_id.clone(), pack);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_cache_attestation(&mut self, attestation: PqCacheAttestation) -> Result<()> {
        if self.cache_attestations.len() >= self.config.max_cache_attestations
            && !self
                .cache_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("cache attestation capacity exceeded".to_string());
        }
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("cache attestation below PQ security floor".to_string());
        }
        self.cache_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_low_fee_coupon(&mut self, coupon: LowFeeCacheCoupon) -> Result<()> {
        if coupon.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("coupon exceeds configured max user fee".to_string());
        }
        if self.low_fee_coupons.len() >= self.config.max_low_fee_coupons
            && !self.low_fee_coupons.contains_key(&coupon.coupon_id)
        {
            return Err("low-fee cache coupon capacity exceeded".to_string());
        }
        self.low_fee_coupons
            .insert(coupon.coupon_id.clone(), coupon);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_bridge_hint(&mut self, hint: BridgeOutputWitnessHint) -> Result<()> {
        if self.bridge_hints.len() >= self.config.max_bridge_hints
            && !self.bridge_hints.contains_key(&hint.bridge_hint_id)
        {
            return Err("bridge output witness hint capacity exceeded".to_string());
        }
        self.bridge_hints.insert(hint.bridge_hint_id.clone(), hint);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_redaction_root(&mut self, root: PrivacyRedactionRoot) -> Result<()> {
        if root.privacy_budget_bps > self.config.privacy_redaction_budget_bps {
            return Err("privacy redaction exceeds configured budget".to_string());
        }
        if root.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy redaction below minimum anonymity set".to_string());
        }
        self.redaction_roots.insert(root.redaction_id.clone(), root);
        self.refresh_roots();
        Ok(())
    }

    pub fn evict_delta(&mut self, record: EvictionRecord) -> Result<()> {
        let delta = self
            .deltas
            .get_mut(&record.delta_id)
            .ok_or_else(|| format!("unknown delta {}", record.delta_id))?;
        delta.status = DeltaStatus::Evicted;
        if let Some(index) = self.hot_delta_index.get_mut(&record.lane_id) {
            index.remove(&record.delta_id);
        }
        self.evictions.insert(record.eviction_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_slashing(&mut self, record: SlashingRecord) -> Result<()> {
        if let Some(delta) = self.deltas.get_mut(&record.delta_id) {
            delta.status = DeltaStatus::Slashed;
        }
        self.slashings.insert(record.slashing_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_public_summary(&mut self, summary: OperatorSafeSummary) -> Result<()> {
        if self.public_summaries.len() >= self.config.max_public_summaries
            && !self.public_summaries.contains_key(&summary.summary_id)
        {
            return Err("public summary capacity exceeded".to_string());
        }
        self.public_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_cache_attestation_suite": PQ_CACHE_ATTESTATION_SUITE,
            "pq_envelope_suite": PQ_ENVELOPE_SUITE,
            "witness_delta_suite": WITNESS_DELTA_SUITE,
            "contract_delta_pack_suite": CONTRACT_DELTA_PACK_SUITE,
            "low_fee_coupon_suite": LOW_FEE_COUPON_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "bridge_hint_suite": BRIDGE_HINT_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "mode": self.config.mode.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "counters": self.counters,
            "roots": self.roots,
            "operator_safe_summaries": self.public_summaries.values().collect::<Vec<_>>(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.cache_lane_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:lanes",
            self.lanes.values(),
        );
        self.roots.delta_record_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:deltas",
            self.deltas.values(),
        );
        self.roots.preconfirmation_hint_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:preconfirmation-hints",
            self.preconfirmation_hints.values(),
        );
        self.roots.contract_delta_pack_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:contract-delta-packs",
            self.contract_delta_packs.values(),
        );
        self.roots.cache_attestation_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:cache-attestations",
            self.cache_attestations.values(),
        );
        self.roots.low_fee_coupon_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:low-fee-coupons",
            self.low_fee_coupons.values(),
        );
        self.roots.bridge_hint_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:bridge-hints",
            self.bridge_hints.values(),
        );
        self.roots.redaction_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:redaction-roots",
            self.redaction_roots.values(),
        );
        self.roots.eviction_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:evictions",
            self.evictions.values(),
        );
        self.roots.slashing_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:slashings",
            self.slashings.values(),
        );
        self.roots.public_summary_root = root_from_values(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:public-summaries",
            self.public_summaries.values(),
        );
        self.roots.operator_safe_root = domain_hash(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:operator-safe-root",
            &[
                HashPart::Str(&self.roots.public_summary_root),
                HashPart::U64(self.counters.hot_delta_count),
                HashPart::U64(self.counters.total_rebate_micro_units),
            ],
            32,
        );
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        let roots = json!({
            "bridge_hint_root": self.roots.bridge_hint_root,
            "cache_attestation_root": self.roots.cache_attestation_root,
            "cache_lane_root": self.roots.cache_lane_root,
            "contract_delta_pack_root": self.roots.contract_delta_pack_root,
            "delta_record_root": self.roots.delta_record_root,
            "eviction_root": self.roots.eviction_root,
            "low_fee_coupon_root": self.roots.low_fee_coupon_root,
            "operator_safe_root": self.roots.operator_safe_root,
            "preconfirmation_hint_root": self.roots.preconfirmation_hint_root,
            "public_summary_root": self.roots.public_summary_root,
            "redaction_root": self.roots.redaction_root,
            "slashing_root": self.roots.slashing_root,
        });
        domain_hash(
            "private-l2-fast-pq-confidential-state-witness-delta-cache:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Json(&roots),
            ],
            32,
        )
    }

    fn derive_counters(&self) -> Counters {
        let live_delta_count = self
            .deltas
            .values()
            .filter(|delta| delta.status.is_live())
            .count() as u64;
        let hot_delta_count = self
            .hot_delta_index
            .values()
            .map(|delta_ids| delta_ids.len() as u64)
            .sum();
        let total_delta_bytes = self
            .deltas
            .values()
            .map(|delta| delta.delta_bytes)
            .sum::<u64>();
        let total_fee_micro_units = self
            .deltas
            .values()
            .map(|delta| delta.fee_micro_units)
            .sum::<u64>();
        let total_rebate_micro_units = self
            .low_fee_coupons
            .values()
            .map(|coupon| coupon.rebate_micro_units)
            .sum::<u64>();
        let average_refresh_ms = if self.lanes.is_empty() {
            0
        } else {
            self.lanes
                .values()
                .map(|lane| lane.average_refresh_ms)
                .sum::<u64>()
                / self.lanes.len() as u64
        };

        Counters {
            lane_count: self.lanes.len() as u64,
            delta_count: self.deltas.len() as u64,
            live_delta_count,
            hot_delta_count,
            preconfirmation_hint_count: self.preconfirmation_hints.len() as u64,
            contract_delta_pack_count: self.contract_delta_packs.len() as u64,
            cache_attestation_count: self.cache_attestations.len() as u64,
            low_fee_coupon_count: self.low_fee_coupons.len() as u64,
            bridge_hint_count: self.bridge_hints.len() as u64,
            redaction_root_count: self.redaction_roots.len() as u64,
            eviction_count: self.evictions.len() as u64,
            slashing_count: self.slashings.len() as u64,
            public_summary_count: self.public_summaries.len() as u64,
            total_delta_bytes,
            total_fee_micro_units,
            total_rebate_micro_units,
            average_refresh_ms,
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let lane_a = sample_lane(
        "lane-hot-accounts-a",
        "shard-0007",
        "operator-cache-alpha",
        CacheLaneKind::HotAccounts,
        CacheLaneStatus::Hot,
        67_108_864,
        42_467_328,
        9_180,
        14,
        state.l2_height,
    );
    let lane_b = sample_lane(
        "lane-contract-storage-b",
        "shard-0011",
        "operator-cache-beta",
        CacheLaneKind::ContractStorage,
        CacheLaneStatus::Open,
        134_217_728,
        61_865_984,
        8_740,
        19,
        state.l2_height,
    );
    let lane_c = sample_lane(
        "lane-monero-bridge-c",
        "shard-bridge-03",
        "operator-cache-gamma",
        CacheLaneKind::MoneroBridgeOutput,
        CacheLaneStatus::Hot,
        33_554_432,
        19_922_944,
        8_960,
        16,
        state.l2_height,
    );
    state.insert_lane(lane_a).expect("sample lane a");
    state.insert_lane(lane_b).expect("sample lane b");
    state.insert_lane(lane_c).expect("sample lane c");

    let delta_0 = state
        .cache_delta(sample_request(
            "lane-hot-accounts-a",
            "shard-0007",
            "private-swap-router-v4",
            "acct-hint-vtag-7f21",
            24_576,
            430,
            1_000,
        ))
        .expect("sample delta 0");
    let delta_1 = state
        .cache_delta(sample_request(
            "lane-contract-storage-b",
            "shard-0011",
            "confidential-lending-pool-v3",
            "acct-hint-vtag-42ac",
            65_536,
            710,
            940,
        ))
        .expect("sample delta 1");
    let delta_2 = state
        .cache_delta(sample_request(
            "lane-monero-bridge-c",
            "shard-bridge-03",
            "monero-exit-router-v2",
            "bridge-output-vtag-2d09",
            18_432,
            390,
            920,
        ))
        .expect("sample delta 2");

    state
        .add_preconfirmation_hint(sample_hint(
            "hint-preconf-swap-0",
            &delta_0,
            "lane-hot-accounts-a",
            HintKind::PreconfirmationReadSet,
            "preconf-swap-000044",
            9_300,
            state.l2_height,
        ))
        .expect("sample hint 0");
    state
        .add_preconfirmation_hint(sample_hint(
            "hint-contract-write-1",
            &delta_1,
            "lane-contract-storage-b",
            HintKind::ContractWriteSet,
            "preconf-lend-000128",
            9_120,
            state.l2_height,
        ))
        .expect("sample hint 1");
    state
        .add_contract_delta_pack(sample_contract_pack(
            "pack-lending-001",
            "confidential-lending-pool-v3",
            "lane-contract-storage-b",
            48,
            18_944,
        ))
        .expect("sample contract pack");
    state
        .add_cache_attestation(sample_attestation(
            "attest-alpha-0001",
            "lane-hot-accounts-a",
            &delta_0,
            "operator-cache-alpha",
            AttestationVerdict::Cache,
            state.l2_height,
        ))
        .expect("sample attestation 0");
    state
        .add_cache_attestation(sample_attestation(
            "attest-beta-0001",
            "lane-contract-storage-b",
            &delta_1,
            "operator-cache-beta",
            AttestationVerdict::Cache,
            state.l2_height,
        ))
        .expect("sample attestation 1");
    state
        .add_low_fee_coupon(sample_coupon(
            "coupon-sponsor-0",
            &delta_0,
            "fee-sponsor-mesh-02",
            24,
            state.l2_height,
        ))
        .expect("sample coupon 0");
    state
        .add_low_fee_coupon(sample_coupon(
            "coupon-bridge-1",
            &delta_2,
            "bridge-rebate-vault-01",
            18,
            state.l2_height,
        ))
        .expect("sample coupon 1");
    state
        .add_bridge_hint(sample_bridge_hint(
            "bridge-hint-0",
            &delta_2,
            "bridge-batch-xmr-00093",
            state.monero_height,
        ))
        .expect("sample bridge hint");
    state
        .add_redaction_root(sample_redaction(
            "redaction-swap-0",
            &delta_0,
            220,
            DEFAULT_MIN_PRIVACY_SET_SIZE,
        ))
        .expect("sample redaction 0");
    state
        .add_redaction_root(sample_redaction(
            "redaction-bridge-0",
            &delta_2,
            260,
            DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        ))
        .expect("sample redaction 1");
    state
        .add_public_summary(sample_summary(
            "summary-alpha-epoch-12288",
            "lane-hot-accounts-a",
            "operator-cache-alpha",
            state.epoch,
            9_180,
            1,
            1_240,
        ))
        .expect("sample summary 0");
    state
        .add_public_summary(sample_summary(
            "summary-gamma-epoch-12288",
            "lane-monero-bridge-c",
            "operator-cache-gamma",
            state.epoch,
            8_960,
            1,
            960,
        ))
        .expect("sample summary 1");
    state.refresh_roots();
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

fn root_from_values<'a, T, I>(domain: &str, values: I) -> String
where
    T: Serialize + 'a,
    I: Iterator<Item = &'a T>,
{
    let leaves = values
        .map(|value| serde_json::to_value(value).expect("runtime record serialization"))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_lane(
    lane_id: &str,
    shard_id: &str,
    operator_id: &str,
    kind: CacheLaneKind,
    status: CacheLaneStatus,
    capacity_bytes: u64,
    hot_bytes: u64,
    cache_hit_bps: u64,
    average_refresh_ms: u64,
    height: u64,
) -> CacheLaneRecord {
    CacheLaneRecord {
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        operator_id: operator_id.to_string(),
        kind,
        status,
        capacity_bytes,
        hot_bytes,
        cache_hit_bps,
        average_refresh_ms,
        pq_attestation_key_commitment: sample_root("pq-key", lane_id),
        privacy_fence_root: sample_root("privacy-fence", shard_id),
        opened_at_height: height - 96,
        updated_at_height: height,
    }
}

fn sample_request(
    lane_id: &str,
    shard_id: &str,
    contract_id: &str,
    account_hint_tag: &str,
    delta_bytes: u64,
    fee_micro_units: u64,
    priority_score: u64,
) -> CacheDeltaRequest {
    CacheDeltaRequest {
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        contract_id: contract_id.to_string(),
        account_hint_tag: account_hint_tag.to_string(),
        base_state_root: sample_root("base-state", contract_id),
        witness_blob_root: sample_root("witness-blob", account_hint_tag),
        nullifier_set_root: sample_root("nullifier-set", shard_id),
        priority_score,
        delta_bytes,
        fee_micro_units,
    }
}

fn sample_hint(
    hint_id: &str,
    delta_id: &str,
    lane_id: &str,
    hint_kind: HintKind,
    preconfirmation_id: &str,
    confidence_bps: u64,
    height: u64,
) -> PreconfirmationWitnessHint {
    PreconfirmationWitnessHint {
        hint_id: hint_id.to_string(),
        delta_id: delta_id.to_string(),
        lane_id: lane_id.to_string(),
        hint_kind,
        encrypted_hint_root: sample_root("encrypted-hint", hint_id),
        read_set_root: sample_root("read-set", delta_id),
        expected_output_root: sample_root("expected-output", preconfirmation_id),
        preconfirmation_id: preconfirmation_id.to_string(),
        confidence_bps,
        expires_at_height: height + DEFAULT_HINT_TTL_BLOCKS,
    }
}

fn sample_contract_pack(
    pack_id: &str,
    contract_id: &str,
    lane_id: &str,
    packed_delta_count: u64,
    compressed_bytes: u64,
) -> ContractStorageDeltaPack {
    ContractStorageDeltaPack {
        pack_id: pack_id.to_string(),
        contract_id: contract_id.to_string(),
        lane_id: lane_id.to_string(),
        storage_slot_root: sample_root("storage-slots", pack_id),
        read_delta_root: sample_root("read-delta", contract_id),
        write_delta_root: sample_root("write-delta", contract_id),
        recursive_proof_hint_root: sample_root("recursive-proof-hint", pack_id),
        defi_position_root: sample_root("defi-position", contract_id),
        packed_delta_count,
        compressed_bytes,
    }
}

fn sample_attestation(
    attestation_id: &str,
    lane_id: &str,
    delta_id: &str,
    operator_id: &str,
    verdict: AttestationVerdict,
    height: u64,
) -> PqCacheAttestation {
    PqCacheAttestation {
        attestation_id: attestation_id.to_string(),
        lane_id: lane_id.to_string(),
        delta_id: delta_id.to_string(),
        operator_id: operator_id.to_string(),
        verdict,
        pq_signature_root: sample_root("pq-signature", attestation_id),
        transcript_root: sample_root("cache-transcript", delta_id),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        attested_at_height: height,
        expires_at_height: height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_coupon(
    coupon_id: &str,
    delta_id: &str,
    sponsor_id: &str,
    rebate_micro_units: u64,
    height: u64,
) -> LowFeeCacheCoupon {
    LowFeeCacheCoupon {
        coupon_id: coupon_id.to_string(),
        delta_id: delta_id.to_string(),
        sponsor_id: sponsor_id.to_string(),
        holder_commitment: sample_root("coupon-holder", coupon_id),
        fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        rebate_micro_units,
        max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        nullifier_root: sample_root("coupon-nullifier", delta_id),
        expires_at_height: height + DEFAULT_COUPON_TTL_BLOCKS,
    }
}

fn sample_bridge_hint(
    bridge_hint_id: &str,
    delta_id: &str,
    bridge_batch_id: &str,
    monero_height: u64,
) -> BridgeOutputWitnessHint {
    BridgeOutputWitnessHint {
        bridge_hint_id: bridge_hint_id.to_string(),
        delta_id: delta_id.to_string(),
        monero_output_commitment: sample_root("monero-output", bridge_hint_id),
        output_index_root: sample_root("output-index", bridge_batch_id),
        ring_member_root: sample_root("ring-members", delta_id),
        view_tag_root: sample_root("view-tags", bridge_hint_id),
        bridge_batch_id: bridge_batch_id.to_string(),
        l2_claim_root: sample_root("l2-claim", delta_id),
        monero_height,
    }
}

fn sample_redaction(
    redaction_id: &str,
    delta_id: &str,
    privacy_budget_bps: u64,
    min_privacy_set_size: u64,
) -> PrivacyRedactionRoot {
    PrivacyRedactionRoot {
        redaction_id: redaction_id.to_string(),
        delta_id: delta_id.to_string(),
        privacy_budget_bps,
        redacted_field_root: sample_root("redacted-fields", redaction_id),
        auditor_view_root: sample_root("auditor-view", delta_id),
        operator_public_root: sample_root("operator-public", redaction_id),
        min_privacy_set_size,
    }
}

fn sample_summary(
    summary_id: &str,
    lane_id: &str,
    operator_id: &str,
    public_epoch: u64,
    cache_hit_bps: u64,
    hot_delta_count: u64,
    fee_saved_micro_units: u64,
) -> OperatorSafeSummary {
    OperatorSafeSummary {
        summary_id: summary_id.to_string(),
        lane_id: lane_id.to_string(),
        operator_id: operator_id.to_string(),
        public_epoch,
        cache_hit_bps,
        hot_delta_count,
        fee_saved_micro_units,
        privacy_redaction_root: sample_root("summary-redaction", summary_id),
        public_note: "redacted aggregate only; no account, view key, or output linkage".to_string(),
    }
}

fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("private-l2-fast-pq-confidential-state-witness-delta-cache:sample:{domain}"),
        &[HashPart::Str(label)],
        32,
    )
}
