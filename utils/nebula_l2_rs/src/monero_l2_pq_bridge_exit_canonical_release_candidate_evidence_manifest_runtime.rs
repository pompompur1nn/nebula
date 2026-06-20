use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalReleaseCandidateEvidenceManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_CANDIDATE_EVIDENCE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-release-candidate-evidence-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_CANDIDATE_EVIDENCE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-candidate-evidence-manifest-v1";
pub const DEFAULT_MIN_REQUIRED_READY_LANES: u64 = 7;
pub const DEFAULT_MAX_DEFERRED_LANES: u64 = 4;
pub const DEFAULT_MAX_WATCH_LANES: u64 = 2;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_LEAK_UNITS: u64 = 2;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 35_000_000;
pub const DEFAULT_MAX_EVIDENCE_ITEMS: usize = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLane {
    ExecutionReplayBundle,
    LiveFeedBoundary,
    WalletClaimExport,
    PqKeyRotationReleaseDrill,
    ReserveProofHandoff,
    PrivacyAuditArtifact,
    HeavyGateReadinessReceipt,
    ProductionBlockerBurnDown,
    SecurityAudit,
    OperatorRunbook,
}

impl EvidenceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionReplayBundle => "execution_replay_bundle",
            Self::LiveFeedBoundary => "live_feed_boundary",
            Self::WalletClaimExport => "wallet_claim_export",
            Self::PqKeyRotationReleaseDrill => "pq_key_rotation_release_drill",
            Self::ReserveProofHandoff => "reserve_proof_handoff",
            Self::PrivacyAuditArtifact => "privacy_audit_artifact",
            Self::HeavyGateReadinessReceipt => "heavy_gate_readiness_receipt",
            Self::ProductionBlockerBurnDown => "production_blocker_burn_down",
            Self::SecurityAudit => "security_audit",
            Self::OperatorRunbook => "operator_runbook",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::ExecutionReplayBundle => 0,
            Self::LiveFeedBoundary => 1,
            Self::WalletClaimExport => 2,
            Self::PqKeyRotationReleaseDrill => 3,
            Self::ReserveProofHandoff => 4,
            Self::PrivacyAuditArtifact => 5,
            Self::HeavyGateReadinessReceipt => 6,
            Self::ProductionBlockerBurnDown => 7,
            Self::SecurityAudit => 8,
            Self::OperatorRunbook => 9,
        }
    }

    pub fn is_user_escape_critical(self) -> bool {
        matches!(
            self,
            Self::ExecutionReplayBundle
                | Self::LiveFeedBoundary
                | Self::WalletClaimExport
                | Self::PqKeyRotationReleaseDrill
                | Self::ReserveProofHandoff
                | Self::PrivacyAuditArtifact
                | Self::HeavyGateReadinessReceipt
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Ready,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_user_escape(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Deferred | Self::Blocked | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBlocker {
    MissingEvidenceRoot,
    NonCanonicalOrder,
    OperatorCooperationRequired,
    LiveFeedNotConnected,
    CargoRuntimeDeferred,
    HeavyGateNotExecuted,
    SecurityAuditDeferred,
    PrivacyAuditDeferred,
    PqWeightTooLow,
    ReserveCoverageTooLow,
    FeeCapExceeded,
    MetadataBudgetExceeded,
    ProductionSignoffMissing,
}

impl EvidenceBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingEvidenceRoot => "missing_evidence_root",
            Self::NonCanonicalOrder => "non_canonical_order",
            Self::OperatorCooperationRequired => "operator_cooperation_required",
            Self::LiveFeedNotConnected => "live_feed_not_connected",
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::HeavyGateNotExecuted => "heavy_gate_not_executed",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::PrivacyAuditDeferred => "privacy_audit_deferred",
            Self::PqWeightTooLow => "pq_weight_too_low",
            Self::ReserveCoverageTooLow => "reserve_coverage_too_low",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::ProductionSignoffMissing => "production_signoff_missing",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::MissingEvidenceRoot => "release_candidate_evidence",
            Self::NonCanonicalOrder => "canonical_replay_bundle",
            Self::OperatorCooperationRequired => "forced_exit_contract",
            Self::LiveFeedNotConnected => "live_feed_boundary",
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::HeavyGateNotExecuted => "heavy_gate_readiness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::PrivacyAuditDeferred => "privacy_audit",
            Self::PqWeightTooLow => "pq_release_authority",
            Self::ReserveCoverageTooLow => "reserve_proof_handoff",
            Self::FeeCapExceeded => "fee_policy",
            Self::MetadataBudgetExceeded => "privacy_budget",
            Self::ProductionSignoffMissing => "release_management",
        }
    }

    pub fn blocks_user_escape(self) -> bool {
        matches!(
            self,
            Self::MissingEvidenceRoot
                | Self::NonCanonicalOrder
                | Self::OperatorCooperationRequired
                | Self::PqWeightTooLow
                | Self::ReserveCoverageTooLow
                | Self::FeeCapExceeded
                | Self::MetadataBudgetExceeded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCandidateVerdict {
    ReadyToScheduleHeavyGate,
    ReadyButDeferredEvidence,
    Watch,
    Blocked,
    Rejected,
}

impl ReleaseCandidateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyToScheduleHeavyGate => "ready_to_schedule_heavy_gate",
            Self::ReadyButDeferredEvidence => "ready_but_deferred_evidence",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn user_answer(self) -> &'static str {
        match self {
            Self::ReadyToScheduleHeavyGate | Self::ReadyButDeferredEvidence => {
                "release_candidate_evidence_preserves_user_escape_design"
            }
            Self::Watch => "release_candidate_evidence_needs_followup_before_heavy_gate",
            Self::Blocked => "release_candidate_evidence_blocks_user_escape_review",
            Self::Rejected => "release_candidate_evidence_rejected",
        }
    }

    pub fn production_answer(self) -> &'static str {
        match self {
            Self::ReadyToScheduleHeavyGate => {
                "heavy_gate_can_be_scheduled_but_production_release_still_needs_execution_and_audits"
            }
            Self::ReadyButDeferredEvidence => {
                "heavy_gate_inputs_exist_but_deferred_evidence_keeps_production_blocked"
            }
            Self::Watch => "production_release_requires_watch_items_to_clear",
            Self::Blocked => "production_release_blocked",
            Self::Rejected => "production_release_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_required_ready_lanes: u64,
    pub max_deferred_lanes: u64,
    pub max_watch_lanes: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_leak_units: u64,
    pub max_fee_atomic: u64,
    pub max_evidence_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_required_ready_lanes: DEFAULT_MIN_REQUIRED_READY_LANES,
            max_deferred_lanes: DEFAULT_MAX_DEFERRED_LANES,
            max_watch_lanes: DEFAULT_MAX_WATCH_LANES,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_metadata_leak_units: DEFAULT_MAX_METADATA_LEAK_UNITS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            max_evidence_items: DEFAULT_MAX_EVIDENCE_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceInput {
    pub lane: EvidenceLane,
    pub required: bool,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub live_feed_connected: bool,
    pub operator_independent: bool,
    pub cargo_runtime_executed: bool,
    pub heavy_gate_executed: bool,
    pub security_audit_signed: bool,
    pub privacy_audit_signed: bool,
    pub production_signoff: bool,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_leak_units: u64,
    pub fee_atomic: u64,
}

impl EvidenceInput {
    pub fn leaf(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_ordinal": self.lane.ordinal(),
            "required": self.required,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "live_feed_connected": self.live_feed_connected,
            "operator_independent": self.operator_independent,
            "cargo_runtime_executed": self.cargo_runtime_executed,
            "heavy_gate_executed": self.heavy_gate_executed,
            "security_audit_signed": self.security_audit_signed,
            "privacy_audit_signed": self.privacy_audit_signed,
            "production_signoff": self.production_signoff,
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_leak_units": self.metadata_leak_units,
            "fee_atomic": self.fee_atomic,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceItem {
    pub index: u64,
    pub lane: EvidenceLane,
    pub required: bool,
    pub status: EvidenceStatus,
    pub blocker: Option<EvidenceBlocker>,
    pub owner_lane: Option<String>,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub item_root: String,
    pub user_escape_ready: bool,
    pub production_ready: bool,
}

impl EvidenceItem {
    pub fn from_input(index: u64, input: EvidenceInput, config: &Config) -> Self {
        let blocker = derive_blocker(index, &input, config);
        let status = derive_status(blocker, &input);
        let user_escape_ready = input.lane.is_user_escape_critical()
            && !status.blocks_user_escape()
            && input.operator_independent;
        let production_ready = !status.blocks_production()
            && input.live_feed_connected
            && input.cargo_runtime_executed
            && input.heavy_gate_executed
            && input.security_audit_signed
            && input.privacy_audit_signed
            && input.production_signoff;
        let owner_lane = blocker.map(|value| value.owner_lane().to_string());
        let item_leaf = json!({
            "index": index,
            "lane": input.lane.as_str(),
            "required": input.required,
            "status": status.as_str(),
            "blocker": blocker.map(EvidenceBlocker::as_str),
            "owner_lane": owner_lane,
            "evidence_root": input.evidence_root,
            "public_root": input.public_root,
            "committed_root": input.committed_root,
            "encrypted_root": input.encrypted_root,
            "wallet_recovery_root": input.wallet_recovery_root,
            "user_escape_ready": user_escape_ready,
            "production_ready": production_ready,
        });
        let item_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-release-candidate-evidence-item",
            &[HashPart::Json(&item_leaf)],
            32,
        );
        Self {
            index,
            lane: input.lane,
            required: input.required,
            status,
            blocker,
            owner_lane,
            evidence_root: input.evidence_root,
            public_root: input.public_root,
            committed_root: input.committed_root,
            encrypted_root: input.encrypted_root,
            wallet_recovery_root: input.wallet_recovery_root,
            item_root,
            user_escape_ready,
            production_ready,
        }
    }

    pub fn leaf(&self) -> Value {
        json!({
            "index": self.index,
            "lane": self.lane.as_str(),
            "required": self.required,
            "status": self.status.as_str(),
            "blocker": self.blocker.map(EvidenceBlocker::as_str),
            "owner_lane": self.owner_lane,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "item_root": self.item_root,
            "user_escape_ready": self.user_escape_ready,
            "production_ready": self.production_ready,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCounters {
    pub ready: u64,
    pub watch: u64,
    pub deferred: u64,
    pub blocked: u64,
    pub rejected: u64,
    pub required: u64,
    pub user_escape_ready: u64,
    pub production_ready: u64,
}

impl EvidenceCounters {
    pub fn ingest(&mut self, item: &EvidenceItem) {
        match item.status {
            EvidenceStatus::Ready => self.ready += 1,
            EvidenceStatus::Watch => self.watch += 1,
            EvidenceStatus::Deferred => self.deferred += 1,
            EvidenceStatus::Blocked => self.blocked += 1,
            EvidenceStatus::Rejected => self.rejected += 1,
        }
        if item.required {
            self.required += 1;
        }
        if item.user_escape_ready {
            self.user_escape_ready += 1;
        }
        if item.production_ready {
            self.production_ready += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.ready + self.watch + self.deferred + self.blocked + self.rejected
    }

    pub fn has_user_escape_blocker(&self) -> bool {
        self.blocked > 0 || self.rejected > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseCandidateEvidenceManifest {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub manifest_suite: String,
    pub verdict: ReleaseCandidateVerdict,
    pub user_answer: String,
    pub production_answer: String,
    pub manifest_root: String,
    pub item_root: String,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub blocker_root: String,
    pub counters: EvidenceCounters,
    pub blocker_counts: BTreeMap<String, u64>,
    pub items: Vec<EvidenceItem>,
}

impl ReleaseCandidateEvidenceManifest {
    pub fn from_items(config: &Config, items: Vec<EvidenceItem>) -> Self {
        let mut counters = EvidenceCounters::default();
        let mut blocker_counts = BTreeMap::new();
        for item in &items {
            counters.ingest(item);
            if let Some(blocker) = item.blocker {
                *blocker_counts
                    .entry(blocker.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }
        let item_leaves = items.iter().map(EvidenceItem::leaf).collect::<Vec<_>>();
        let evidence_leaves = items
            .iter()
            .map(|item| json!({ "lane": item.lane.as_str(), "root": item.evidence_root }))
            .collect::<Vec<_>>();
        let public_leaves = items
            .iter()
            .map(|item| json!({ "lane": item.lane.as_str(), "root": item.public_root }))
            .collect::<Vec<_>>();
        let committed_leaves = items
            .iter()
            .map(|item| json!({ "lane": item.lane.as_str(), "root": item.committed_root }))
            .collect::<Vec<_>>();
        let encrypted_leaves = items
            .iter()
            .map(|item| json!({ "lane": item.lane.as_str(), "root": item.encrypted_root }))
            .collect::<Vec<_>>();
        let wallet_leaves = items
            .iter()
            .map(|item| json!({ "lane": item.lane.as_str(), "root": item.wallet_recovery_root }))
            .collect::<Vec<_>>();
        let blocker_leaves = blocker_counts
            .iter()
            .map(|(blocker, count)| json!({ "blocker": blocker, "count": count }))
            .collect::<Vec<_>>();

        let item_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-evidence-items",
            &item_leaves,
        );
        let evidence_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-evidence-roots",
            &evidence_leaves,
        );
        let public_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-public-roots",
            &public_leaves,
        );
        let committed_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-committed-roots",
            &committed_leaves,
        );
        let encrypted_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-encrypted-roots",
            &encrypted_leaves,
        );
        let wallet_recovery_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-wallet-roots",
            &wallet_leaves,
        );
        let blocker_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-candidate-blocker-roots",
            &blocker_leaves,
        );
        let verdict = derive_verdict(config, &counters);
        let manifest_payload = json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": config.chain_id,
            "manifest_suite": MANIFEST_SUITE,
            "verdict": verdict.as_str(),
            "user_answer": verdict.user_answer(),
            "production_answer": verdict.production_answer(),
            "item_root": item_root,
            "evidence_root": evidence_root,
            "public_root": public_root,
            "committed_root": committed_root,
            "encrypted_root": encrypted_root,
            "wallet_recovery_root": wallet_recovery_root,
            "blocker_root": blocker_root,
            "counters": counters,
        });
        let manifest_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-release-candidate-evidence-manifest",
            &[HashPart::Json(&manifest_payload)],
            32,
        );
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: config.chain_id.clone(),
            manifest_suite: MANIFEST_SUITE.to_string(),
            verdict,
            user_answer: verdict.user_answer().to_string(),
            production_answer: verdict.production_answer().to_string(),
            manifest_root,
            item_root,
            evidence_root,
            public_root,
            committed_root,
            encrypted_root,
            wallet_recovery_root,
            blocker_root,
            counters,
            blocker_counts,
            items,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "manifest_suite": self.manifest_suite,
            "verdict": self.verdict.as_str(),
            "user_answer": self.user_answer,
            "production_answer": self.production_answer,
            "manifest_root": self.manifest_root,
            "item_root": self.item_root,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "blocker_root": self.blocker_root,
            "counters": self.counters,
            "blocker_counts": self.blocker_counts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub manifest: ReleaseCandidateEvidenceManifest,
}

impl State {
    pub fn new() -> Self {
        Self::from_inputs(Config::default(), default_inputs())
    }

    pub fn from_inputs(config: Config, inputs: Vec<EvidenceInput>) -> Self {
        let items = inputs
            .into_iter()
            .enumerate()
            .map(|(index, input)| EvidenceItem::from_input(index as u64, input, &config))
            .collect::<Vec<_>>();
        let manifest = ReleaseCandidateEvidenceManifest::from_items(&config, items);
        Self { config, manifest }
    }

    pub fn ingest(&mut self, input: EvidenceInput) -> Result<()> {
        if self.manifest.items.len() >= self.config.max_evidence_items {
            return Err("release-candidate evidence manifest item limit reached".to_string());
        }
        let mut inputs = self
            .manifest
            .items
            .iter()
            .map(evidence_item_to_input)
            .collect::<Vec<_>>();
        inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), inputs);
        Ok(())
    }

    pub fn can_schedule_heavy_gate(&self) -> bool {
        matches!(
            self.manifest.verdict,
            ReleaseCandidateVerdict::ReadyToScheduleHeavyGate
                | ReleaseCandidateVerdict::ReadyButDeferredEvidence
        )
    }

    pub fn production_blocked(&self) -> bool {
        !matches!(
            self.manifest.verdict,
            ReleaseCandidateVerdict::ReadyToScheduleHeavyGate
        ) || self.manifest.counters.deferred > 0
            || self
                .manifest
                .blocker_counts
                .contains_key("production_signoff_missing")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "min_required_ready_lanes": self.config.min_required_ready_lanes,
                "max_deferred_lanes": self.config.max_deferred_lanes,
                "max_watch_lanes": self.config.max_watch_lanes,
                "min_pq_weight_bps": self.config.min_pq_weight_bps,
                "min_reserve_coverage_bps": self.config.min_reserve_coverage_bps,
                "max_metadata_leak_units": self.config.max_metadata_leak_units,
                "max_fee_atomic": self.config.max_fee_atomic,
                "max_evidence_items": self.config.max_evidence_items,
            },
            "manifest": self.manifest.public_record(),
            "can_schedule_heavy_gate": self.can_schedule_heavy_gate(),
            "production_blocked": self.production_blocked(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_value(&self.public_record())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

pub fn devnet() -> State {
    State::new()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn state_root_from_value(value: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-release-candidate-evidence-manifest-state",
        &[HashPart::Json(value)],
        32,
    )
}

fn derive_blocker(index: u64, input: &EvidenceInput, config: &Config) -> Option<EvidenceBlocker> {
    if input.evidence_root.is_empty()
        || input.public_root.is_empty()
        || input.committed_root.is_empty()
        || input.encrypted_root.is_empty()
    {
        return Some(EvidenceBlocker::MissingEvidenceRoot);
    }
    if index != input.lane.ordinal() {
        return Some(EvidenceBlocker::NonCanonicalOrder);
    }
    if !input.operator_independent && input.lane.is_user_escape_critical() {
        return Some(EvidenceBlocker::OperatorCooperationRequired);
    }
    if input.pq_weight_bps < config.min_pq_weight_bps
        && matches!(input.lane, EvidenceLane::PqKeyRotationReleaseDrill)
    {
        return Some(EvidenceBlocker::PqWeightTooLow);
    }
    if input.reserve_coverage_bps < config.min_reserve_coverage_bps
        && matches!(input.lane, EvidenceLane::ReserveProofHandoff)
    {
        return Some(EvidenceBlocker::ReserveCoverageTooLow);
    }
    if input.metadata_leak_units > config.max_metadata_leak_units {
        return Some(EvidenceBlocker::MetadataBudgetExceeded);
    }
    if input.fee_atomic > config.max_fee_atomic {
        return Some(EvidenceBlocker::FeeCapExceeded);
    }
    if !input.live_feed_connected && matches!(input.lane, EvidenceLane::LiveFeedBoundary) {
        return Some(EvidenceBlocker::LiveFeedNotConnected);
    }
    if !input.cargo_runtime_executed {
        return Some(EvidenceBlocker::CargoRuntimeDeferred);
    }
    if !input.heavy_gate_executed {
        return Some(EvidenceBlocker::HeavyGateNotExecuted);
    }
    if !input.privacy_audit_signed && matches!(input.lane, EvidenceLane::PrivacyAuditArtifact) {
        return Some(EvidenceBlocker::PrivacyAuditDeferred);
    }
    if !input.security_audit_signed && matches!(input.lane, EvidenceLane::SecurityAudit) {
        return Some(EvidenceBlocker::SecurityAuditDeferred);
    }
    if !input.production_signoff && matches!(input.lane, EvidenceLane::ProductionBlockerBurnDown) {
        return Some(EvidenceBlocker::ProductionSignoffMissing);
    }
    None
}

fn derive_status(blocker: Option<EvidenceBlocker>, input: &EvidenceInput) -> EvidenceStatus {
    match blocker {
        None => EvidenceStatus::Ready,
        Some(EvidenceBlocker::LiveFeedNotConnected)
        | Some(EvidenceBlocker::CargoRuntimeDeferred)
        | Some(EvidenceBlocker::HeavyGateNotExecuted)
        | Some(EvidenceBlocker::SecurityAuditDeferred)
        | Some(EvidenceBlocker::PrivacyAuditDeferred)
        | Some(EvidenceBlocker::ProductionSignoffMissing) => EvidenceStatus::Deferred,
        Some(blocker) if blocker.blocks_user_escape() => EvidenceStatus::Blocked,
        Some(_) if input.required => EvidenceStatus::Blocked,
        Some(_) => EvidenceStatus::Rejected,
    }
}

fn derive_verdict(config: &Config, counters: &EvidenceCounters) -> ReleaseCandidateVerdict {
    if counters.rejected > 0 {
        return ReleaseCandidateVerdict::Rejected;
    }
    if counters.has_user_escape_blocker() {
        return ReleaseCandidateVerdict::Blocked;
    }
    if counters.watch > config.max_watch_lanes {
        return ReleaseCandidateVerdict::Watch;
    }
    if counters.user_escape_ready < config.min_required_ready_lanes {
        return ReleaseCandidateVerdict::Blocked;
    }
    if counters.deferred > config.max_deferred_lanes {
        return ReleaseCandidateVerdict::Blocked;
    }
    if counters.watch > 0 {
        return ReleaseCandidateVerdict::Watch;
    }
    if counters.deferred > 0 {
        ReleaseCandidateVerdict::ReadyButDeferredEvidence
    } else {
        ReleaseCandidateVerdict::ReadyToScheduleHeavyGate
    }
}

fn evidence_item_to_input(item: &EvidenceItem) -> EvidenceInput {
    EvidenceInput {
        lane: item.lane,
        required: item.required,
        evidence_root: item.evidence_root.clone(),
        public_root: item.public_root.clone(),
        committed_root: item.committed_root.clone(),
        encrypted_root: item.encrypted_root.clone(),
        wallet_recovery_root: item.wallet_recovery_root.clone(),
        live_feed_connected: item.production_ready,
        operator_independent: item.user_escape_ready,
        cargo_runtime_executed: item.production_ready,
        heavy_gate_executed: item.production_ready,
        security_audit_signed: item.production_ready,
        privacy_audit_signed: item.production_ready,
        production_signoff: item.production_ready,
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
    }
}

fn default_inputs() -> Vec<EvidenceInput> {
    [
        EvidenceLane::ExecutionReplayBundle,
        EvidenceLane::LiveFeedBoundary,
        EvidenceLane::WalletClaimExport,
        EvidenceLane::PqKeyRotationReleaseDrill,
        EvidenceLane::ReserveProofHandoff,
        EvidenceLane::PrivacyAuditArtifact,
        EvidenceLane::HeavyGateReadinessReceipt,
        EvidenceLane::ProductionBlockerBurnDown,
        EvidenceLane::SecurityAudit,
        EvidenceLane::OperatorRunbook,
    ]
    .iter()
    .map(|lane| default_input(*lane))
    .collect()
}

fn default_input(lane: EvidenceLane) -> EvidenceInput {
    let lane_name = lane.as_str();
    let evidence_payload = json!({
        "lane": lane_name,
        "artifact": "canonical-release-candidate-evidence",
        "wallet_metadata": "redacted",
    });
    let public_payload = json!({
        "lane": lane_name,
        "public_anchor": "redacted-release-candidate-anchor",
    });
    let committed_payload = json!({
        "lane": lane_name,
        "commitment": "release-candidate-commitment",
    });
    let encrypted_payload = json!({
        "lane": lane_name,
        "encrypted": "wallet-auditor-shard",
    });
    let wallet_payload = json!({
        "lane": lane_name,
        "wallet_local": "claim-reconstruction-root",
    });
    EvidenceInput {
        lane,
        required: !matches!(
            lane,
            EvidenceLane::SecurityAudit | EvidenceLane::OperatorRunbook
        ),
        evidence_root: domain_hash(
            "monero-l2-pq-bridge-exit-release-candidate-evidence-root",
            &[HashPart::Json(&evidence_payload)],
            32,
        ),
        public_root: domain_hash(
            "monero-l2-pq-bridge-exit-release-candidate-public-root",
            &[HashPart::Json(&public_payload)],
            32,
        ),
        committed_root: domain_hash(
            "monero-l2-pq-bridge-exit-release-candidate-committed-root",
            &[HashPart::Json(&committed_payload)],
            32,
        ),
        encrypted_root: domain_hash(
            "monero-l2-pq-bridge-exit-release-candidate-encrypted-root",
            &[HashPart::Json(&encrypted_payload)],
            32,
        ),
        wallet_recovery_root: domain_hash(
            "monero-l2-pq-bridge-exit-release-candidate-wallet-root",
            &[HashPart::Json(&wallet_payload)],
            32,
        ),
        live_feed_connected: !matches!(lane, EvidenceLane::LiveFeedBoundary),
        operator_independent: true,
        cargo_runtime_executed: !matches!(
            lane,
            EvidenceLane::HeavyGateReadinessReceipt | EvidenceLane::ProductionBlockerBurnDown
        ),
        heavy_gate_executed: !matches!(lane, EvidenceLane::HeavyGateReadinessReceipt),
        security_audit_signed: !matches!(lane, EvidenceLane::SecurityAudit),
        privacy_audit_signed: !matches!(lane, EvidenceLane::PrivacyAuditArtifact),
        production_signoff: !matches!(lane, EvidenceLane::ProductionBlockerBurnDown),
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS + 900,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS + 1_500,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
    }
}
