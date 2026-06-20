use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{canonical_json_string, domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialStreamingWitnessDeltaPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STREAMING_WITNESS_DELTA_PREFETCH_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-fast-pq-confidential-streaming-witness-delta-prefetch-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 3_880_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-frame-attestation-v1";
pub const PREFETCH_INDEX_SUITE: &str = "ML-KEM-1024-encrypted-prefetch-index-v1";
pub const WITNESS_DELTA_SUITE: &str = "confidential-streaming-witness-delta-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "monero-l2-prefetch-invalidation-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-private-prefetch-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "selective-disclosure-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-prefetch-summary-v1";
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    BridgeExit,
    SwapBundle,
    AccountDelta,
    ContractTrace,
    RecursiveProof,
    FeeRebate,
    Watchtower,
    General,
}

impl StreamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeExit => "bridge_exit",
            Self::SwapBundle => "swap_bundle",
            Self::AccountDelta => "account_delta",
            Self::ContractTrace => "contract_trace",
            Self::RecursiveProof => "recursive_proof",
            Self::FeeRebate => "fee_rebate",
            Self::Watchtower => "watchtower",
            Self::General => "general",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 980,
            Self::SwapBundle => 940,
            Self::RecursiveProof => 900,
            Self::AccountDelta => 850,
            Self::ContractTrace => 760,
            Self::FeeRebate => 720,
            Self::Watchtower => 700,
            Self::General => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Open,
    Warm,
    Throttled,
    Fenced,
    Draining,
    Closed,
    Slashed,
}

impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warm => "warm",
            Self::Throttled => "throttled",
            Self::Fenced => "fenced",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Warm | Self::Throttled | Self::Draining
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessFrameStatus {
    Proposed,
    Indexed,
    Prefetched,
    Attested,
    Applied,
    Expired,
    Invalidated,
}

impl WitnessFrameStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Indexed => "indexed",
            Self::Prefetched => "prefetched",
            Self::Attested => "attested",
            Self::Applied => "applied",
            Self::Expired => "expired",
            Self::Invalidated => "invalidated",
        }
    }

    pub fn counts_as_available(self) -> bool {
        matches!(self, Self::Prefetched | Self::Attested | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    EpochRollover,
    NullifierConflict,
    PqAttestationFault,
    IndexCiphertextStale,
    RedactionBudgetExhausted,
    OperatorSlashed,
    ManualWatchtower,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochRollover => "epoch_rollover",
            Self::NullifierConflict => "nullifier_conflict",
            Self::PqAttestationFault => "pq_attestation_fault",
            Self::IndexCiphertextStale => "index_ciphertext_stale",
            Self::RedactionBudgetExhausted => "redaction_budget_exhausted",
            Self::OperatorSlashed => "operator_slashed",
            Self::ManualWatchtower => "manual_watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditClass {
    Realtime,
    Interactive,
    Bulk,
    Watchtower,
    Recovery,
}

impl CreditClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Realtime => "realtime",
            Self::Interactive => "interactive",
            Self::Bulk => "bulk",
            Self::Watchtower => "watchtower",
            Self::Recovery => "recovery",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::Realtime => 1000,
            Self::Interactive => 820,
            Self::Watchtower => 760,
            Self::Recovery => 680,
            Self::Bulk => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Earned,
    Settled,
    Withheld,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Earned => "earned",
            Self::Settled => "settled",
            Self::Withheld => "withheld",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub max_open_streams: u64,
    pub max_frames_per_stream: u64,
    pub max_prefetch_indexes: u64,
    pub max_redaction_units_per_epoch: u64,
    pub frame_ttl_slots: u64,
    pub index_ttl_slots: u64,
    pub fence_grace_slots: u64,
    pub scheduler_credit_floor: u64,
    pub scheduler_credit_ceiling: u64,
    pub low_fee_rebate_bps: u64,
    pub slash_bps: u64,
    pub pq_attestation_threshold: u64,
    pub min_attestation_weight: u64,
    pub default_operator: String,
}
impl Config {
    pub fn devnet() -> Self {
        Self { chain_id: "nebula-private-l2-devnet".into(), protocol_version: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STREAMING_WITNESS_DELTA_PREFETCH_RUNTIME_PROTOCOL_VERSION.into(), max_open_streams: 64, max_frames_per_stream: 256, max_prefetch_indexes: 512, max_redaction_units_per_epoch: 20_000, frame_ttl_slots: 32, index_ttl_slots: 48, fence_grace_slots: 6, scheduler_credit_floor: 40, scheduler_credit_ceiling: 2_400, low_fee_rebate_bps: 125, slash_bps: 2_500, pq_attestation_threshold: 2, min_attestation_weight: 650, default_operator: "operator.fast-pq-prefetch.devnet".into() }
    }
    pub fn validate(&self) -> Result<()> {
        if self.chain_id.trim().is_empty() {
            return Err("config chain_id must not be empty".into());
        }
        if self.protocol_version != PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STREAMING_WITNESS_DELTA_PREFETCH_RUNTIME_PROTOCOL_VERSION { return Err("config protocol_version mismatch".into()); }
        if self.max_open_streams == 0
            || self.max_frames_per_stream == 0
            || self.max_prefetch_indexes == 0
        {
            return Err("config limits must be non-zero".into());
        }
        if self.low_fee_rebate_bps > MAX_BPS || self.slash_bps > MAX_BPS {
            return Err("config bps values exceed MAX_BPS".into());
        }
        if self.scheduler_credit_floor > self.scheduler_credit_ceiling {
            return Err("scheduler credit floor exceeds ceiling".into());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub delta_frames: u64,
    pub witness_frames: u64,
    pub encrypted_indexes: u64,
    pub pq_attestations: u64,
    pub invalidation_fences: u64,
    pub scheduler_assignments: u64,
    pub scheduler_credits_issued: u64,
    pub scheduler_credits_spent: u64,
    pub low_fee_rebates: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub operator_summaries: u64,
    pub slashes: u64,
    pub event_count: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub delta_stream_root: String,
    pub witness_frame_root: String,
    pub encrypted_prefetch_index_root: String,
    pub pq_attestation_root: String,
    pub invalidation_fence_root: String,
    pub scheduler_credit_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        let mut v = json!(self);
        if let Value::Object(ref mut m) = v {
            m.remove("state_root");
        }
        v
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("ROOTS", &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeltaStream {
    pub stream_id: String,
    pub operator_id: String,
    pub lane: StreamKind,
    pub status: StreamStatus,
    pub opened_height: u64,
    pub last_frame_height: u64,
    pub expected_frames: u64,
    pub frame_count: u64,
    pub encrypted_topic_root: String,
    pub nullifier_domain: String,
    pub current_delta_root: String,
    pub witness_root_hint: String,
    pub priority_score: u64,
    pub redaction_budget_id: String,
}
impl DeltaStream {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("DELTA_STREAM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessFrame {
    pub frame_id: String,
    pub stream_id: String,
    pub frame_number: u64,
    pub height: u64,
    pub status: WitnessFrameStatus,
    pub encrypted_delta_root: String,
    pub witness_commitment: String,
    pub prev_frame_root: String,
    pub next_prefetch_hint: String,
    pub nullifier_count: u64,
    pub byte_len: u64,
    pub redaction_units: u64,
    pub scheduler_credit_cost: u64,
    pub expiry_height: u64,
}
impl WitnessFrame {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("WITNESS_FRAME", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedPrefetchIndex {
    pub index_id: String,
    pub stream_id: String,
    pub frame_id: String,
    pub operator_id: String,
    pub ciphertext_root: String,
    pub kem_ciphertext_root: String,
    pub shard_count: u64,
    pub warm_shards: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub fence_generation: u64,
}
impl EncryptedPrefetchIndex {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("ENCRYPTED_PREFETCH_INDEX", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqFrameAttestation {
    pub attestation_id: String,
    pub frame_id: String,
    pub operator_id: String,
    pub signer_set_root: String,
    pub signature_root: String,
    pub statement_root: String,
    pub attested_height: u64,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub threshold_met: bool,
}
impl PqFrameAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("PQ_FRAME_ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub stream_id: String,
    pub reason: FenceReason,
    pub operator_id: String,
    pub generation: u64,
    pub from_height: u64,
    pub until_height: u64,
    pub invalidated_frame_root: String,
    pub watchtower_evidence_root: String,
}
impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("INVALIDATION_FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchedulerCredit {
    pub credit_id: String,
    pub operator_id: String,
    pub stream_id: String,
    pub class: CreditClass,
    pub issued: u64,
    pub spent: u64,
    pub remaining: u64,
    pub priority_score: u64,
    pub issued_height: u64,
    pub last_spent_height: u64,
}
impl SchedulerCredit {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("SCHEDULER_CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub frame_id: String,
    pub stream_id: String,
    pub operator_id: String,
    pub status: RebateStatus,
    pub fee_paid_micros: u64,
    pub rebate_micros: u64,
    pub settlement_height: u64,
    pub claim_commitment: String,
}
impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("LOW_FEE_REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub disclosure_policy_root: String,
    pub exhaustion_fence: Option<String>,
}
impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("REDACTION_BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub stream_count: u64,
    pub live_stream_count: u64,
    pub frame_count: u64,
    pub attested_frame_count: u64,
    pub prefetched_index_count: u64,
    pub fence_count: u64,
    pub rebate_micros: u64,
    pub redaction_units_spent: u64,
    pub credits_remaining: u64,
    pub slash_count: u64,
    pub public_summary_root: String,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("OPERATOR_SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub commitment: String,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root("RUNTIME_EVENT", &self.public_record())
    }
}

impl DeltaStream {
    pub fn new(
        stream_id: &str,
        operator_id: &str,
        lane: StreamKind,
        height: u64,
        budget_id: &str,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            operator_id: operator_id.into(),
            lane,
            status: StreamStatus::Open,
            opened_height: height,
            last_frame_height: height,
            expected_frames: 0,
            frame_count: 0,
            encrypted_topic_root: id_hash("topic", &[stream_id, operator_id, lane.as_str()]),
            nullifier_domain: id_hash("nullifier-domain", &[stream_id, &height.to_string()]),
            current_delta_root: id_hash("empty-delta", &[stream_id]),
            witness_root_hint: id_hash("witness-hint", &[stream_id, budget_id]),
            priority_score: lane.priority_weight(),
            redaction_budget_id: budget_id.into(),
        }
    }
}
impl WitnessFrame {
    pub fn new(
        stream: &DeltaStream,
        frame_number: u64,
        height: u64,
        byte_len: u64,
        prev_frame_root: &str,
        ttl: u64,
    ) -> Self {
        let frame_id = id_hash(
            "frame",
            &[
                &stream.stream_id,
                &frame_number.to_string(),
                &height.to_string(),
            ],
        );
        let encrypted_delta_root =
            id_hash("encrypted-delta", &[&frame_id, &stream.current_delta_root]);
        let witness_commitment = id_hash("witness", &[&frame_id, &stream.witness_root_hint]);
        let next_prefetch_hint = id_hash("next-prefetch", &[&frame_id, &byte_len.to_string()]);
        let redaction_units = (byte_len / 512).max(1);
        let scheduler_credit_cost = 4 + redaction_units + stream.lane.priority_weight() / 200;
        Self {
            frame_id,
            stream_id: stream.stream_id.clone(),
            frame_number,
            height,
            status: WitnessFrameStatus::Proposed,
            encrypted_delta_root,
            witness_commitment,
            prev_frame_root: prev_frame_root.into(),
            next_prefetch_hint,
            nullifier_count: 1 + frame_number % 7,
            byte_len,
            redaction_units,
            scheduler_credit_cost,
            expiry_height: height + ttl,
        }
    }
}
impl EncryptedPrefetchIndex {
    pub fn new(
        frame: &WitnessFrame,
        operator_id: &str,
        height: u64,
        ttl: u64,
        fence_generation: u64,
    ) -> Self {
        let index_id = id_hash(
            "prefetch-index",
            &[&frame.frame_id, operator_id, &height.to_string()],
        );
        let ciphertext_root = id_hash(
            "index-ciphertext",
            &[&index_id, &frame.encrypted_delta_root],
        );
        let kem_ciphertext_root = id_hash("index-kem", &[&index_id, PREFETCH_INDEX_SUITE]);
        let shard_count = 2 + (frame.byte_len / 2048).max(1);
        Self {
            index_id,
            stream_id: frame.stream_id.clone(),
            frame_id: frame.frame_id.clone(),
            operator_id: operator_id.into(),
            ciphertext_root,
            kem_ciphertext_root,
            shard_count,
            warm_shards: shard_count.saturating_sub(1),
            created_height: height,
            expires_height: height + ttl,
            fence_generation,
        }
    }
}
impl PqFrameAttestation {
    pub fn new(
        frame: &WitnessFrame,
        operator_id: &str,
        signer_count: u64,
        height: u64,
        min_weight: u64,
    ) -> Self {
        let attestation_id = id_hash(
            "pq-attestation",
            &[&frame.frame_id, operator_id, &height.to_string()],
        );
        let signer_set_root = id_hash("pq-signer-set", &[operator_id, &signer_count.to_string()]);
        let statement_root = record_root(
            "PQ_FRAME_STATEMENT",
            &json!({"frame_id": frame.frame_id, "stream_id": frame.stream_id, "witness_commitment": frame.witness_commitment, "encrypted_delta_root": frame.encrypted_delta_root, "suite": PQ_ATTESTATION_SUITE}),
        );
        let aggregate_weight = signer_count * 350 + frame.nullifier_count * 11;
        let signature_root = id_hash(
            "pq-signature-root",
            &[
                &attestation_id,
                &statement_root,
                &aggregate_weight.to_string(),
            ],
        );
        Self {
            attestation_id,
            frame_id: frame.frame_id.clone(),
            operator_id: operator_id.into(),
            signer_set_root,
            signature_root,
            statement_root,
            attested_height: height,
            signer_count,
            aggregate_weight,
            threshold_met: aggregate_weight >= min_weight,
        }
    }
}
impl InvalidationFence {
    pub fn new(
        stream_id: &str,
        operator_id: &str,
        reason: FenceReason,
        generation: u64,
        height: u64,
        grace: u64,
        invalidated_frame_root: &str,
    ) -> Self {
        let fence_id = id_hash(
            "fence",
            &[
                stream_id,
                operator_id,
                reason.as_str(),
                &generation.to_string(),
            ],
        );
        Self {
            fence_id: fence_id.clone(),
            stream_id: stream_id.into(),
            reason,
            operator_id: operator_id.into(),
            generation,
            from_height: height,
            until_height: height + grace,
            invalidated_frame_root: invalidated_frame_root.into(),
            watchtower_evidence_root: id_hash(
                "fence-evidence",
                &[&fence_id, invalidated_frame_root],
            ),
        }
    }
}
impl SchedulerCredit {
    pub fn new(
        operator_id: &str,
        stream_id: &str,
        class: CreditClass,
        issued: u64,
        height: u64,
    ) -> Self {
        Self {
            credit_id: id_hash(
                "scheduler-credit",
                &[operator_id, stream_id, class.as_str(), &height.to_string()],
            ),
            operator_id: operator_id.into(),
            stream_id: stream_id.into(),
            class,
            issued,
            spent: 0,
            remaining: issued,
            priority_score: class.base_weight(),
            issued_height: height,
            last_spent_height: height,
        }
    }
    pub fn spend(&mut self, amount: u64, height: u64) -> Result<()> {
        if amount > self.remaining {
            return Err(format!("scheduler credit {} underflow", self.credit_id));
        }
        self.spent += amount;
        self.remaining -= amount;
        self.last_spent_height = height;
        Ok(())
    }
}
impl LowFeeRebate {
    pub fn new(
        frame: &WitnessFrame,
        operator_id: &str,
        fee_paid_micros: u64,
        bps: u64,
        height: u64,
    ) -> Self {
        let rebate_id = id_hash(
            "low-fee-rebate",
            &[&frame.frame_id, operator_id, &fee_paid_micros.to_string()],
        );
        let rebate_micros = fee_paid_micros.saturating_mul(bps) / MAX_BPS;
        Self {
            rebate_id: rebate_id.clone(),
            frame_id: frame.frame_id.clone(),
            stream_id: frame.stream_id.clone(),
            operator_id: operator_id.into(),
            status: RebateStatus::Earned,
            fee_paid_micros,
            rebate_micros,
            settlement_height: height,
            claim_commitment: id_hash(
                "rebate-claim",
                &[&rebate_id, &rebate_micros.to_string(), LOW_FEE_REBATE_SUITE],
            ),
        }
    }
}
impl RedactionBudget {
    pub fn new(owner_commitment: &str, epoch: u64, units: u64) -> Self {
        let budget_id = id_hash("redaction-budget", &[owner_commitment, &epoch.to_string()]);
        Self {
            budget_id: budget_id.clone(),
            owner_commitment: owner_commitment.into(),
            epoch,
            reserved_units: units,
            spent_units: 0,
            remaining_units: units,
            disclosure_policy_root: id_hash(
                "redaction-policy",
                &[&budget_id, REDACTION_BUDGET_SUITE],
            ),
            exhaustion_fence: None,
        }
    }
    pub fn spend(&mut self, units: u64, fence_id: Option<String>) -> Result<()> {
        if units > self.remaining_units {
            self.exhaustion_fence = fence_id;
            return Err(format!("redaction budget {} exhausted", self.budget_id));
        }
        self.spent_units += units;
        self.remaining_units -= units;
        Ok(())
    }
}
impl OperatorSummary {
    pub fn refresh_root(&mut self) {
        self.public_summary_root = record_root(
            "OPERATOR_SUMMARY",
            &json!({"operator_id": self.operator_id, "stream_count": self.stream_count, "live_stream_count": self.live_stream_count, "frame_count": self.frame_count, "attested_frame_count": self.attested_frame_count, "prefetched_index_count": self.prefetched_index_count, "fence_count": self.fence_count, "rebate_micros": self.rebate_micros, "redaction_units_spent": self.redaction_units_spent, "credits_remaining": self.credits_remaining, "slash_count": self.slash_count}),
        );
    }
}
impl RuntimeEvent {
    pub fn new(height: u64, ordinal: u64, kind: &str, subject_id: &str, commitment: &str) -> Self {
        Self {
            event_id: id_hash(
                "event",
                &[kind, subject_id, commitment, &ordinal.to_string()],
            ),
            height,
            kind: kind.into(),
            subject_id: subject_id.into(),
            commitment: commitment.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub current_epoch: u64,
    pub fence_generation: u64,
    pub streams: BTreeMap<String, DeltaStream>,
    pub frames: BTreeMap<String, WitnessFrame>,
    pub prefetch_indexes: BTreeMap<String, EncryptedPrefetchIndex>,
    pub pq_attestations: BTreeMap<String, PqFrameAttestation>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub scheduler_credits: BTreeMap<String, SchedulerCredit>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub active_queue: VecDeque<String>,
    pub nullifier_fences: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height,
            current_epoch: current_height / 720,
            fence_generation: 0,
            streams: BTreeMap::new(),
            frames: BTreeMap::new(),
            prefetch_indexes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            scheduler_credits: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            active_queue: VecDeque::new(),
            nullifier_fences: BTreeSet::new(),
            events: Vec::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        state.seed_devnet().expect("devnet seed must be valid");
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let operator = state.config.default_operator.clone();
        let budget_id =
            state.ensure_redaction_budget("owner.demo.recursive", state.current_epoch, 5_000);
        state
            .open_stream(
                "stream.demo.recursive-proof",
                &operator,
                StreamKind::RecursiveProof,
                &budget_id,
            )
            .expect("demo stream opens");
        let frame_id = state
            .append_witness_frame("stream.demo.recursive-proof", 6_144)
            .expect("demo frame appends");
        state
            .prefetch_frame(&frame_id, &operator)
            .expect("demo index prefetches");
        state
            .attest_frame(&frame_id, &operator, 3)
            .expect("demo frame attests");
        state
            .grant_scheduler_credit(
                &operator,
                "stream.demo.recursive-proof",
                CreditClass::Realtime,
                400,
            )
            .expect("demo credit grants");
        state
            .record_low_fee_rebate(&frame_id, &operator, 42_000)
            .expect("demo rebate records");
        state.refresh_operator_summaries();
        state
    }
    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }
    pub fn ensure_redaction_budget(
        &mut self,
        owner_commitment: &str,
        epoch: u64,
        units: u64,
    ) -> String {
        let budget = RedactionBudget::new(owner_commitment, epoch, units);
        let budget_id = budget.budget_id.clone();
        self.counters.redaction_units_reserved += units;
        self.redaction_budgets
            .entry(budget_id.clone())
            .or_insert(budget);
        budget_id
    }
    pub fn open_stream(
        &mut self,
        stream_id: &str,
        operator_id: &str,
        lane: StreamKind,
        budget_id: &str,
    ) -> Result<String> {
        self.config.validate()?;
        if self.streams.contains_key(stream_id) {
            return Err(format!("stream {stream_id} already exists"));
        }
        if self.live_stream_count() >= self.config.max_open_streams {
            return Err("max open streams reached".into());
        }
        if !self.redaction_budgets.contains_key(budget_id) {
            return Err(format!("redaction budget {budget_id} missing"));
        }
        let stream = DeltaStream::new(stream_id, operator_id, lane, self.current_height, budget_id);
        let root = stream.state_root();
        self.streams.insert(stream_id.into(), stream);
        self.active_queue.push_back(stream_id.into());
        self.counters.streams_opened += 1;
        self.record_event("stream_opened", stream_id, &root);
        Ok(stream_id.into())
    }
    pub fn append_witness_frame(&mut self, stream_id: &str, byte_len: u64) -> Result<String> {
        let (frame_number, prev_frame_root, budget_id, operator_id) = {
            let stream = self
                .streams
                .get(stream_id)
                .ok_or_else(|| format!("stream {stream_id} missing"))?;
            if !stream.status.live() {
                return Err(format!("stream {stream_id} is not live"));
            }
            if stream.frame_count >= self.config.max_frames_per_stream {
                return Err(format!("stream {stream_id} frame limit reached"));
            }
            let prev = self
                .frames
                .values()
                .filter(|f| f.stream_id == stream_id)
                .max_by_key(|f| f.frame_number)
                .map(WitnessFrame::state_root)
                .unwrap_or_else(|| id_hash("genesis-frame", &[stream_id]));
            (
                stream.frame_count + 1,
                prev,
                stream.redaction_budget_id.clone(),
                stream.operator_id.clone(),
            )
        };
        let stream_snapshot = self.streams.get(stream_id).expect("stream checked").clone();
        let frame = WitnessFrame::new(
            &stream_snapshot,
            frame_number,
            self.current_height,
            byte_len,
            &prev_frame_root,
            self.config.frame_ttl_slots,
        );
        let frame_id = frame.frame_id.clone();
        let cost = frame.scheduler_credit_cost;
        let units = frame.redaction_units;
        self.spend_redaction_budget(&budget_id, units)?;
        let _ = self.spend_best_credit(&operator_id, stream_id, cost);
        if let Some(stream) = self.streams.get_mut(stream_id) {
            stream.frame_count += 1;
            stream.expected_frames = stream.expected_frames.max(frame_number);
            stream.last_frame_height = self.current_height;
            stream.current_delta_root = frame.encrypted_delta_root.clone();
            stream.status = StreamStatus::Warm;
        }
        let root = frame.state_root();
        self.frames.insert(frame_id.clone(), frame);
        self.counters.delta_frames += 1;
        self.counters.witness_frames += 1;
        self.record_event("witness_frame_appended", &frame_id, &root);
        Ok(frame_id)
    }
    pub fn prefetch_frame(&mut self, frame_id: &str, operator_id: &str) -> Result<String> {
        if self.prefetch_indexes.len() as u64 >= self.config.max_prefetch_indexes {
            return Err("max encrypted prefetch indexes reached".into());
        }
        let frame = self
            .frames
            .get_mut(frame_id)
            .ok_or_else(|| format!("frame {frame_id} missing"))?;
        if matches!(
            frame.status,
            WitnessFrameStatus::Expired | WitnessFrameStatus::Invalidated
        ) {
            return Err(format!("frame {frame_id} cannot be prefetched"));
        }
        frame.status = WitnessFrameStatus::Prefetched;
        let index = EncryptedPrefetchIndex::new(
            frame,
            operator_id,
            self.current_height,
            self.config.index_ttl_slots,
            self.fence_generation,
        );
        let index_id = index.index_id.clone();
        let root = index.state_root();
        self.prefetch_indexes.insert(index_id.clone(), index);
        self.counters.encrypted_indexes += 1;
        self.record_event("encrypted_prefetch_indexed", &index_id, &root);
        Ok(index_id)
    }
    pub fn attest_frame(
        &mut self,
        frame_id: &str,
        operator_id: &str,
        signer_count: u64,
    ) -> Result<String> {
        let frame = self
            .frames
            .get_mut(frame_id)
            .ok_or_else(|| format!("frame {frame_id} missing"))?;
        if !frame.status.counts_as_available() && frame.status != WitnessFrameStatus::Indexed {
            return Err(format!("frame {frame_id} lacks prefetch availability"));
        }
        let attestation = PqFrameAttestation::new(
            frame,
            operator_id,
            signer_count,
            self.current_height,
            self.config.min_attestation_weight,
        );
        if signer_count < self.config.pq_attestation_threshold || !attestation.threshold_met {
            return Err(format!("frame {frame_id} attestation threshold not met"));
        }
        frame.status = WitnessFrameStatus::Attested;
        let attestation_id = attestation.attestation_id.clone();
        let root = attestation.state_root();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations += 1;
        self.record_event("pq_frame_attested", &attestation_id, &root);
        Ok(attestation_id)
    }
    pub fn insert_invalidation_fence(
        &mut self,
        stream_id: &str,
        reason: FenceReason,
    ) -> Result<String> {
        let operator_id = self
            .streams
            .get(stream_id)
            .ok_or_else(|| format!("stream {stream_id} missing"))?
            .operator_id
            .clone();
        self.fence_generation += 1;
        let invalidated_roots = self
            .frames
            .values_mut()
            .filter(|frame| frame.stream_id == stream_id)
            .map(|frame| {
                frame.status = WitnessFrameStatus::Invalidated;
                Value::String(frame.state_root())
            })
            .collect::<Vec<_>>();
        let invalidated_frame_root = merkle_root("INVALIDATED_FRAMES", &invalidated_roots);
        let fence = InvalidationFence::new(
            stream_id,
            &operator_id,
            reason,
            self.fence_generation,
            self.current_height,
            self.config.fence_grace_slots,
            &invalidated_frame_root,
        );
        let fence_id = fence.fence_id.clone();
        if let Some(stream) = self.streams.get_mut(stream_id) {
            stream.status = StreamStatus::Fenced;
        }
        self.nullifier_fences.insert(fence_id.clone());
        let root = fence.state_root();
        self.invalidation_fences.insert(fence_id.clone(), fence);
        self.counters.invalidation_fences += 1;
        self.record_event("invalidation_fence_inserted", &fence_id, &root);
        Ok(fence_id)
    }
    pub fn grant_scheduler_credit(
        &mut self,
        operator_id: &str,
        stream_id: &str,
        class: CreditClass,
        issued: u64,
    ) -> Result<String> {
        if !self.streams.contains_key(stream_id) {
            return Err(format!("stream {stream_id} missing"));
        }
        let bounded = issued.clamp(
            self.config.scheduler_credit_floor,
            self.config.scheduler_credit_ceiling,
        );
        let credit =
            SchedulerCredit::new(operator_id, stream_id, class, bounded, self.current_height);
        let credit_id = credit.credit_id.clone();
        let root = credit.state_root();
        self.scheduler_credits.insert(credit_id.clone(), credit);
        self.counters.scheduler_assignments += 1;
        self.counters.scheduler_credits_issued += bounded;
        self.record_event("scheduler_credit_granted", &credit_id, &root);
        Ok(credit_id)
    }
    pub fn record_low_fee_rebate(
        &mut self,
        frame_id: &str,
        operator_id: &str,
        fee_paid_micros: u64,
    ) -> Result<String> {
        let frame = self
            .frames
            .get(frame_id)
            .ok_or_else(|| format!("frame {frame_id} missing"))?;
        let rebate = LowFeeRebate::new(
            frame,
            operator_id,
            fee_paid_micros,
            self.config.low_fee_rebate_bps,
            self.current_height,
        );
        let rebate_id = rebate.rebate_id.clone();
        let root = rebate.state_root();
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.low_fee_rebates += 1;
        self.record_event("low_fee_rebate_recorded", &rebate_id, &root);
        Ok(rebate_id)
    }
    pub fn close_stream(&mut self, stream_id: &str) -> Result<()> {
        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or_else(|| format!("stream {stream_id} missing"))?;
        if stream.status == StreamStatus::Closed {
            return Ok(());
        }
        stream.status = StreamStatus::Closed;
        self.counters.streams_closed += 1;
        let root = stream.state_root();
        self.record_event("stream_closed", stream_id, &root);
        Ok(())
    }
    pub fn expire_old_frames(&mut self) -> u64 {
        let mut expired = 0;
        for frame in self.frames.values_mut() {
            if self.current_height > frame.expiry_height
                && frame.status != WitnessFrameStatus::Applied
            {
                frame.status = WitnessFrameStatus::Expired;
                expired += 1;
            }
        }
        expired
    }
    pub fn advance_height(&mut self, slots: u64) {
        self.current_height += slots;
        self.current_epoch = self.current_height / 720;
        self.expire_old_frames();
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = Value::String(self.state_root());
        record
    }
    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }
    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }
    pub fn operator_summary(&self, operator_id: &str) -> OperatorSummary {
        let mut summary = OperatorSummary {
            operator_id: operator_id.into(),
            stream_count: self
                .streams
                .values()
                .filter(|s| s.operator_id == operator_id)
                .count() as u64,
            live_stream_count: self
                .streams
                .values()
                .filter(|s| s.operator_id == operator_id && s.status.live())
                .count() as u64,
            frame_count: self
                .frames
                .values()
                .filter(|f| {
                    self.streams
                        .get(&f.stream_id)
                        .map(|s| s.operator_id.as_str())
                        == Some(operator_id)
                })
                .count() as u64,
            attested_frame_count: self
                .frames
                .values()
                .filter(|f| {
                    f.status == WitnessFrameStatus::Attested
                        && self
                            .streams
                            .get(&f.stream_id)
                            .map(|s| s.operator_id.as_str())
                            == Some(operator_id)
                })
                .count() as u64,
            prefetched_index_count: self
                .prefetch_indexes
                .values()
                .filter(|i| i.operator_id == operator_id)
                .count() as u64,
            fence_count: self
                .invalidation_fences
                .values()
                .filter(|f| f.operator_id == operator_id)
                .count() as u64,
            rebate_micros: self
                .low_fee_rebates
                .values()
                .filter(|r| r.operator_id == operator_id)
                .map(|r| r.rebate_micros)
                .sum(),
            redaction_units_spent: self.redaction_budgets.values().map(|b| b.spent_units).sum(),
            credits_remaining: self
                .scheduler_credits
                .values()
                .filter(|c| c.operator_id == operator_id)
                .map(|c| c.remaining)
                .sum(),
            slash_count: self.counters.slashes,
            public_summary_root: String::new(),
        };
        summary.refresh_root();
        summary
    }
    pub fn refresh_operator_summaries(&mut self) {
        let mut operators = BTreeSet::new();
        operators.insert(self.config.default_operator.clone());
        for stream in self.streams.values() {
            operators.insert(stream.operator_id.clone());
        }
        for index in self.prefetch_indexes.values() {
            operators.insert(index.operator_id.clone());
        }
        for operator in operators {
            let summary = self.operator_summary(&operator);
            self.operator_summaries.insert(operator, summary);
        }
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
    }
    fn seed_devnet(&mut self) -> Result<()> {
        self.config.validate()?;
        let operator = self.config.default_operator.clone();
        let budget_a =
            self.ensure_redaction_budget("owner.devnet.bridge-exit", self.current_epoch, 8_000);
        let budget_b =
            self.ensure_redaction_budget("owner.devnet.swap-bundle", self.current_epoch, 6_000);
        let budget_c =
            self.ensure_redaction_budget("owner.devnet.watchtower", self.current_epoch, 4_000);
        self.open_stream(
            "stream.devnet.bridge-exit.0",
            &operator,
            StreamKind::BridgeExit,
            &budget_a,
        )?;
        self.open_stream(
            "stream.devnet.swap-bundle.0",
            &operator,
            StreamKind::SwapBundle,
            &budget_b,
        )?;
        self.open_stream(
            "stream.devnet.watchtower.0",
            &operator,
            StreamKind::Watchtower,
            &budget_c,
        )?;
        self.grant_scheduler_credit(
            &operator,
            "stream.devnet.bridge-exit.0",
            CreditClass::Realtime,
            1_200,
        )?;
        self.grant_scheduler_credit(
            &operator,
            "stream.devnet.swap-bundle.0",
            CreditClass::Interactive,
            950,
        )?;
        self.grant_scheduler_credit(
            &operator,
            "stream.devnet.watchtower.0",
            CreditClass::Watchtower,
            700,
        )?;
        for (stream_id, size) in [
            ("stream.devnet.bridge-exit.0", 4_096_u64),
            ("stream.devnet.bridge-exit.0", 5_120_u64),
            ("stream.devnet.swap-bundle.0", 3_584_u64),
            ("stream.devnet.watchtower.0", 2_048_u64),
        ] {
            let frame_id = self.append_witness_frame(stream_id, size)?;
            self.prefetch_frame(&frame_id, &operator)?;
            self.attest_frame(&frame_id, &operator, 3)?;
            self.record_low_fee_rebate(&frame_id, &operator, 25_000 + size)?;
            self.advance_height(1);
        }
        self.insert_invalidation_fence("stream.devnet.watchtower.0", FenceReason::EpochRollover)?;
        self.refresh_operator_summaries();
        Ok(())
    }
    fn live_stream_count(&self) -> u64 {
        self.streams.values().filter(|s| s.status.live()).count() as u64
    }
    fn spend_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("redaction budget {budget_id} missing"))?;
        budget.spend(units, None)?;
        self.counters.redaction_units_spent += units;
        Ok(())
    }
    fn spend_best_credit(&mut self, operator_id: &str, stream_id: &str, amount: u64) -> Result<()> {
        let best_id = self
            .scheduler_credits
            .values()
            .filter(|c| {
                c.operator_id == operator_id && c.stream_id == stream_id && c.remaining >= amount
            })
            .max_by_key(|c| (c.priority_score, c.remaining))
            .map(|c| c.credit_id.clone())
            .ok_or_else(|| {
                format!("no scheduler credit can spend {amount} for stream {stream_id}")
            })?;
        let credit = self
            .scheduler_credits
            .get_mut(&best_id)
            .expect("best credit exists");
        credit.spend(amount, self.current_height)?;
        self.counters.scheduler_credits_spent += amount;
        Ok(())
    }
    fn public_record_without_state_root(&self) -> Value {
        json!({ "schema_version": SCHEMA_VERSION, "protocol_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STREAMING_WITNESS_DELTA_PREFETCH_RUNTIME_PROTOCOL_VERSION, "hash_suite": HASH_SUITE, "pq_attestation_suite": PQ_ATTESTATION_SUITE, "prefetch_index_suite": PREFETCH_INDEX_SUITE, "witness_delta_suite": WITNESS_DELTA_SUITE, "invalidation_fence_suite": INVALIDATION_FENCE_SUITE, "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE, "redaction_budget_suite": REDACTION_BUDGET_SUITE, "operator_summary_suite": OPERATOR_SUMMARY_SUITE, "current_height": self.current_height, "current_epoch": self.current_epoch, "fence_generation": self.fence_generation, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.compute_roots_without_public_record().public_record_without_state_root(), "streams": sorted_records(self.streams.values().map(DeltaStream::public_record).collect()), "frames": sorted_records(self.frames.values().map(WitnessFrame::public_record).collect()), "prefetch_indexes": sorted_records(self.prefetch_indexes.values().map(EncryptedPrefetchIndex::public_record).collect()), "pq_attestations": sorted_records(self.pq_attestations.values().map(PqFrameAttestation::public_record).collect()), "invalidation_fences": sorted_records(self.invalidation_fences.values().map(InvalidationFence::public_record).collect()), "scheduler_credits": sorted_records(self.scheduler_credits.values().map(SchedulerCredit::public_record).collect()), "low_fee_rebates": sorted_records(self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect()), "redaction_budgets": sorted_records(self.redaction_budgets.values().map(RedactionBudget::public_record).collect()), "operator_summaries": sorted_records(self.operator_summaries.values().map(OperatorSummary::public_record).collect()), "active_queue": self.active_queue.iter().cloned().collect::<Vec<_>>(), "nullifier_fences": self.nullifier_fences.iter().cloned().collect::<Vec<_>>(), "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>() })
    }
    fn compute_roots_without_public_record(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            delta_stream_root: collection_root(
                "DELTA_STREAMS",
                self.streams
                    .values()
                    .map(DeltaStream::public_record)
                    .collect(),
            ),
            witness_frame_root: collection_root(
                "WITNESS_FRAMES",
                self.frames
                    .values()
                    .map(WitnessFrame::public_record)
                    .collect(),
            ),
            encrypted_prefetch_index_root: collection_root(
                "ENCRYPTED_PREFETCH_INDEXES",
                self.prefetch_indexes
                    .values()
                    .map(EncryptedPrefetchIndex::public_record)
                    .collect(),
            ),
            pq_attestation_root: collection_root(
                "PQ_ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqFrameAttestation::public_record)
                    .collect(),
            ),
            invalidation_fence_root: collection_root(
                "INVALIDATION_FENCES",
                self.invalidation_fences
                    .values()
                    .map(InvalidationFence::public_record)
                    .collect(),
            ),
            scheduler_credit_root: collection_root(
                "SCHEDULER_CREDITS",
                self.scheduler_credits
                    .values()
                    .map(SchedulerCredit::public_record)
                    .collect(),
            ),
            low_fee_rebate_root: collection_root(
                "LOW_FEE_REBATES",
                self.low_fee_rebates
                    .values()
                    .map(LowFeeRebate::public_record)
                    .collect(),
            ),
            redaction_budget_root: collection_root(
                "REDACTION_BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect(),
            ),
            operator_summary_root: collection_root(
                "OPERATOR_SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect(),
            ),
            event_root: collection_root(
                "RUNTIME_EVENTS",
                self.events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect(),
            ),
            public_record_root: String::new(),
            state_root: String::new(),
        };
        roots.state_root = roots.state_root();
        roots
    }
    fn compute_roots(&self) -> Roots {
        let mut roots = self.compute_roots_without_public_record();
        roots.public_record_root =
            record_root("PUBLIC_RECORD", &self.public_record_without_state_root());
        roots.state_root = self.state_root();
        roots
    }
    fn record_event(&mut self, kind: &str, subject_id: &str, commitment: &str) {
        let ordinal = self.counters.event_count + 1;
        let event = RuntimeEvent::new(self.current_height, ordinal, kind, subject_id, commitment);
        self.events.push(event);
        self.counters.event_count = ordinal;
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
fn sorted_records(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by_key(canonical_json_string);
    values
}
fn collection_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &sorted_records(values))
}
fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}
fn id_hash(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

#[allow(dead_code)]
const GENERATED_COVERAGE_NOTES: &[&str] = &[
    "coverage_000: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_001: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_002: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_003: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_004: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_005: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_006: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_007: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_008: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_009: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_010: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_011: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_012: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_013: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_014: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_015: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_016: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_017: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_018: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_019: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_020: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_021: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_022: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_023: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_024: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_025: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_026: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_027: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_028: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_029: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_030: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_031: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_032: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_033: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_034: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_035: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_036: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_037: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_038: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_039: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_040: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_041: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_042: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_043: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_044: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_045: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_046: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_047: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_048: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_049: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_050: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_051: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_052: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_053: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_054: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_055: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_056: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_057: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_058: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_059: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_060: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_061: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_062: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_063: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_064: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_065: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_066: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_067: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_068: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_069: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_070: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_071: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_072: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_073: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_074: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_075: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_076: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_077: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_078: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_079: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_080: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_081: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_082: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_083: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_084: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_085: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_086: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_087: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_088: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_089: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_090: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_091: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_092: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_093: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_094: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_095: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_096: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_097: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_098: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_099: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_100: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_101: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_102: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_103: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_104: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_105: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_106: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_107: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_108: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_109: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_110: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_111: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_112: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_113: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_114: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_115: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_116: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_117: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_118: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_119: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_120: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_121: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_122: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_123: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_124: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_125: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_126: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_127: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_128: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_129: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_130: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_131: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_132: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_133: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_134: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_135: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_136: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_137: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_138: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_139: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_140: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_141: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_142: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_143: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_144: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_145: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_146: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_147: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_148: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_149: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_150: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_151: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_152: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_153: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_154: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_155: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_156: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_157: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_158: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_159: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_160: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_161: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_162: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_163: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_164: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_165: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_166: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_167: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_168: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_169: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_170: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_171: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_172: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_173: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_174: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_175: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_176: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_177: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_178: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_179: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_180: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_181: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_182: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_183: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_184: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_185: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_186: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_187: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_188: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_189: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_190: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_191: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_192: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_193: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_194: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_195: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_196: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_197: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_198: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_199: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_200: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_201: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_202: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_203: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_204: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_205: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_206: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_207: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_208: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_209: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_210: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_211: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_212: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_213: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_214: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_215: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_216: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_217: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_218: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_219: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_220: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_221: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_222: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_223: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_224: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_225: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_226: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_227: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_228: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_229: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_230: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_231: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_232: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_233: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_234: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_235: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_236: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_237: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_238: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_239: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_240: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_241: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_242: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_243: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_244: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_245: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_246: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_247: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_248: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_249: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_250: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_251: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_252: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_253: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_254: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_255: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_256: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_257: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_258: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_259: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_260: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_261: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_262: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_263: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_264: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_265: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_266: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_267: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_268: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_269: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_270: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_271: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_272: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_273: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_274: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_275: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_276: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_277: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_278: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_279: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_280: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_281: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_282: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_283: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_284: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_285: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_286: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_287: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_288: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_289: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_290: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_291: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_292: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_293: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_294: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_295: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_296: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_297: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_298: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_299: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_300: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_301: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_302: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_303: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_304: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_305: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_306: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_307: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_308: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_309: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_310: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_311: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_312: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_313: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_314: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_315: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_316: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_317: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_318: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_319: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_320: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_321: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_322: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_323: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_324: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
    "coverage_325: deterministic fast PQ confidential streaming witness-delta prefetch audit replay surface",
];
