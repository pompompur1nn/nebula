use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalHeavyGateTranscriptRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-heavy-gate-transcript-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const TRANSCRIPT_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-heavy-gate-transcript-v1";
pub const DEFAULT_MIN_STAGE_COUNT: u64 = 7;
pub const DEFAULT_MIN_READY_STAGES: u64 = 6;
pub const DEFAULT_MAX_WATCH_STAGES: u64 = 2;
pub const DEFAULT_MAX_DEFERRED_STAGES: u64 = 2;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_TRANSCRIPT_VECTORS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalTranscriptStage {
    DepositLockVector,
    PqWatcherAttestationVector,
    PrivateNoteTransferVector,
    SettlementExitVector,
    ChallengeReleaseVector,
    WalletReconstructionVector,
    HeavyGateExecutionPlan,
}

impl CanonicalTranscriptStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockVector => "deposit_lock_vector",
            Self::PqWatcherAttestationVector => "pq_watcher_attestation_vector",
            Self::PrivateNoteTransferVector => "private_note_transfer_vector",
            Self::SettlementExitVector => "settlement_exit_vector",
            Self::ChallengeReleaseVector => "challenge_release_vector",
            Self::WalletReconstructionVector => "wallet_reconstruction_vector",
            Self::HeavyGateExecutionPlan => "heavy_gate_execution_plan",
        }
    }

    pub fn is_forced_exit_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLockVector
                | Self::PqWatcherAttestationVector
                | Self::SettlementExitVector
                | Self::ChallengeReleaseVector
                | Self::WalletReconstructionVector
        )
    }

    pub fn canonical_order(self) -> u64 {
        match self {
            Self::DepositLockVector => 10,
            Self::PqWatcherAttestationVector => 20,
            Self::PrivateNoteTransferVector => 30,
            Self::SettlementExitVector => 40,
            Self::ChallengeReleaseVector => 50,
            Self::WalletReconstructionVector => 60,
            Self::HeavyGateExecutionPlan => 70,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalVectorStatus {
    Ready,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl CanonicalVectorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_wallet_answer(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }

    pub fn blocks_production_answer(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Deferred | Self::Blocked | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEvidenceDomain {
    MoneroLock,
    PqWatcherQuorum,
    PrivateState,
    SettlementReceipt,
    ForcedExitChallenge,
    WalletRecovery,
    RuntimeHarness,
    SecurityAudit,
}

impl CanonicalEvidenceDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLock => "monero_lock",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::PrivateState => "private_state",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExitChallenge => "forced_exit_challenge",
            Self::WalletRecovery => "wallet_recovery",
            Self::RuntimeHarness => "runtime_harness",
            Self::SecurityAudit => "security_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalBlockerKind {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    NoBaseLayerVerifier,
    MissingDepositVector,
    MissingPqWatcherVector,
    MissingPrivateTransferVector,
    MissingSettlementExitVector,
    MissingChallengeReleaseVector,
    MissingWalletReconstructionVector,
    PrivacyBudgetTooSmall,
    FeeCapExceeded,
    PqWeightTooLow,
    MoneroConfirmationsTooLow,
    TranscriptOrderBroken,
}

impl CanonicalBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::MissingDepositVector => "missing_deposit_vector",
            Self::MissingPqWatcherVector => "missing_pq_watcher_vector",
            Self::MissingPrivateTransferVector => "missing_private_transfer_vector",
            Self::MissingSettlementExitVector => "missing_settlement_exit_vector",
            Self::MissingChallengeReleaseVector => "missing_challenge_release_vector",
            Self::MissingWalletReconstructionVector => "missing_wallet_reconstruction_vector",
            Self::PrivacyBudgetTooSmall => "privacy_budget_too_small",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PqWeightTooLow => "pq_weight_too_low",
            Self::MoneroConfirmationsTooLow => "monero_confirmations_too_low",
            Self::TranscriptOrderBroken => "transcript_order_broken",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::NoBaseLayerVerifier => "monero_evidence_policy",
            Self::MissingDepositVector => "deposit_lock_vector",
            Self::MissingPqWatcherVector => "pq_watcher_vector",
            Self::MissingPrivateTransferVector => "private_transfer_vector",
            Self::MissingSettlementExitVector => "settlement_exit_vector",
            Self::MissingChallengeReleaseVector => "challenge_release_vector",
            Self::MissingWalletReconstructionVector => "wallet_reconstruction_vector",
            Self::PrivacyBudgetTooSmall => "privacy_review",
            Self::FeeCapExceeded => "fee_policy",
            Self::PqWeightTooLow => "pq_control_plane",
            Self::MoneroConfirmationsTooLow => "monero_finality_policy",
            Self::TranscriptOrderBroken => "canonical_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptVerdict {
    ReadyForFixtureRun,
    ReadyButHeavyGateDeferred,
    Watch,
    Blocked,
    Rejected,
}

impl TranscriptVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForFixtureRun => "ready_for_fixture_run",
            Self::ReadyButHeavyGateDeferred => "ready_but_heavy_gate_deferred",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_stage_count: u64,
    pub min_ready_stages: u64,
    pub max_watch_stages: u64,
    pub max_deferred_stages: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_weight_bps: u64,
    pub min_monero_confirmations: u64,
    pub max_transcript_vectors: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_stage_count: DEFAULT_MIN_STAGE_COUNT,
            min_ready_stages: DEFAULT_MIN_READY_STAGES,
            max_watch_stages: DEFAULT_MAX_WATCH_STAGES,
            max_deferred_stages: DEFAULT_MAX_DEFERRED_STAGES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            max_transcript_vectors: DEFAULT_MAX_TRANSCRIPT_VECTORS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalVectorInput {
    pub stage: CanonicalTranscriptStage,
    pub domain: CanonicalEvidenceDomain,
    pub label: String,
    pub prior_root: String,
    pub vector_root: String,
    pub expected_next_root: String,
    pub monero_confirmations: u64,
    pub pq_weight_bps: u64,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub transcript_order: u64,
    pub heavy_gate_required: String,
    pub heavy_gate_available: String,
    pub fixture_backed: String,
    pub wallet_reconstructable: String,
    pub production_release_required: String,
}

impl CanonicalVectorInput {
    pub fn input_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-vector-input",
            &[
                HashPart::Str(self.stage.as_str()),
                HashPart::Str(self.domain.as_str()),
                HashPart::Str(&self.label),
                HashPart::Str(&self.prior_root),
                HashPart::Str(&self.vector_root),
                HashPart::Str(&self.expected_next_root),
                HashPart::U64(self.monero_confirmations),
                HashPart::U64(self.pq_weight_bps),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.fee_bps),
                HashPart::U64(self.transcript_order),
                HashPart::Str(&self.heavy_gate_required),
                HashPart::Str(&self.heavy_gate_available),
                HashPart::Str(&self.fixture_backed),
                HashPart::Str(&self.wallet_reconstructable),
                HashPart::Str(&self.production_release_required),
            ],
            32,
        )
    }

    pub fn requires_heavy_gate(&self) -> bool {
        self.heavy_gate_required == "required"
    }

    pub fn heavy_gate_is_available(&self) -> bool {
        self.heavy_gate_available == "available"
    }

    pub fn is_fixture_backed(&self) -> bool {
        self.fixture_backed == "fixture_backed"
    }

    pub fn wallet_can_reconstruct(&self) -> bool {
        self.wallet_reconstructable == "reconstructable"
    }

    pub fn requires_production_release(&self) -> bool {
        self.production_release_required == "required"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalVectorRecord {
    pub stage: CanonicalTranscriptStage,
    pub domain: CanonicalEvidenceDomain,
    pub status: CanonicalVectorStatus,
    pub label: String,
    pub input_root: String,
    pub vector_root: String,
    pub expected_next_root: String,
    pub transcript_link_root: String,
    pub public_commitment_root: String,
    pub encrypted_payload_root: String,
    pub wallet_recovery_root: String,
    pub blocker: Option<CanonicalBlockerKind>,
    pub remediation: String,
    pub forced_exit_critical: String,
    pub production_lane: String,
    pub record_root: String,
}

impl CanonicalVectorRecord {
    pub fn blocks_wallet(&self) -> bool {
        self.status.blocks_wallet_answer()
            || self.forced_exit_critical == "critical_blocked"
            || matches!(
                self.blocker,
                Some(
                    CanonicalBlockerKind::MissingDepositVector
                        | CanonicalBlockerKind::MissingPqWatcherVector
                        | CanonicalBlockerKind::MissingSettlementExitVector
                        | CanonicalBlockerKind::MissingChallengeReleaseVector
                        | CanonicalBlockerKind::MissingWalletReconstructionVector
                )
            )
    }

    pub fn blocks_production(&self) -> bool {
        self.status.blocks_production_answer()
            || self.blocker.is_some()
            || self.production_lane != "ready"
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TranscriptCounters {
    pub total_vectors: u64,
    pub ready_vectors: u64,
    pub watch_vectors: u64,
    pub deferred_vectors: u64,
    pub blocked_vectors: u64,
    pub rejected_vectors: u64,
    pub forced_exit_critical_vectors: u64,
    pub wallet_blocking_vectors: u64,
    pub production_blocking_vectors: u64,
    pub heavy_gate_required_vectors: u64,
}

impl TranscriptCounters {
    pub fn observe(&mut self, input: &CanonicalVectorInput, record: &CanonicalVectorRecord) {
        self.total_vectors += 1;
        match record.status {
            CanonicalVectorStatus::Ready => self.ready_vectors += 1,
            CanonicalVectorStatus::Watch => self.watch_vectors += 1,
            CanonicalVectorStatus::Deferred => self.deferred_vectors += 1,
            CanonicalVectorStatus::Blocked => self.blocked_vectors += 1,
            CanonicalVectorStatus::Rejected => self.rejected_vectors += 1,
        }
        if record.stage.is_forced_exit_critical() {
            self.forced_exit_critical_vectors += 1;
        }
        if record.blocks_wallet() {
            self.wallet_blocking_vectors += 1;
        }
        if record.blocks_production() {
            self.production_blocking_vectors += 1;
        }
        if input.requires_heavy_gate() {
            self.heavy_gate_required_vectors += 1;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalTranscript {
    pub transcript_id: String,
    pub verdict: TranscriptVerdict,
    pub vector_root: String,
    pub input_root: String,
    pub blocker_root: String,
    pub counter_root: String,
    pub stage_order_root: String,
    pub wallet_answer: String,
    pub production_answer: String,
    pub operator_summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub inputs: Vec<CanonicalVectorInput>,
    pub records: Vec<CanonicalVectorRecord>,
    pub counters: TranscriptCounters,
    pub blockers: Vec<CanonicalBlockerKind>,
    pub stage_index: BTreeMap<String, String>,
    pub transcript: CanonicalTranscript,
}

impl State {
    pub fn new(config: Config) -> Self {
        let inputs = default_inputs(&config);
        Self::from_inputs(config, inputs)
    }

    pub fn from_inputs(config: Config, inputs: Vec<CanonicalVectorInput>) -> Self {
        let limited_inputs = inputs
            .into_iter()
            .take(config.max_transcript_vectors)
            .collect::<Vec<_>>();
        let mut counters = TranscriptCounters::default();
        let mut blockers = Vec::new();
        let mut records = Vec::new();
        let mut stage_index = BTreeMap::new();

        for input in &limited_inputs {
            let record = derive_record(&config, input);
            counters.observe(input, &record);
            if let Some(blocker) = record.blocker {
                if !blockers.contains(&blocker) {
                    blockers.push(blocker);
                }
            }
            stage_index.insert(input.stage.as_str().to_string(), record.record_root.clone());
            records.push(record);
        }

        blockers.sort();
        let transcript = build_transcript(&config, &limited_inputs, &records, &counters, &blockers);

        Self {
            config,
            inputs: limited_inputs,
            records,
            counters,
            blockers,
            stage_index,
            transcript,
        }
    }

    pub fn ingest(&mut self, input: CanonicalVectorInput) -> Result<()> {
        if self.inputs.len() >= self.config.max_transcript_vectors {
            return Err("canonical transcript vector capacity reached".to_string());
        }
        self.inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), self.inputs.clone());
        Ok(())
    }

    pub fn wallet_path_is_clear(&self) -> bool {
        self.counters.wallet_blocking_vectors == 0
            && self.counters.ready_vectors >= self.config.min_ready_stages
    }

    pub fn production_is_blocked(&self) -> bool {
        !self.blockers.is_empty()
            || self.counters.deferred_vectors > 0
            || self.counters.watch_vectors > self.config.max_watch_stages
            || self.counters.production_blocking_vectors > 0
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-heavy-gate-transcript-state",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.transcript.transcript_id),
                HashPart::Str(&self.transcript.vector_root),
                HashPart::Str(&self.transcript.input_root),
                HashPart::Str(&self.transcript.blocker_root),
                HashPart::Str(&self.transcript.counter_root),
                HashPart::Str(&self.transcript.stage_order_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let vectors = self
            .records
            .iter()
            .map(public_vector_record)
            .collect::<Vec<_>>();
        let blockers = self
            .blockers
            .iter()
            .map(|blocker| {
                json!({
                    "kind": blocker.as_str(),
                    "owner_lane": blocker.owner_lane(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "transcript_suite": TRANSCRIPT_SUITE,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "transcript": {
                "transcript_id": self.transcript.transcript_id,
                "verdict": self.transcript.verdict.as_str(),
                "vector_root": self.transcript.vector_root,
                "input_root": self.transcript.input_root,
                "blocker_root": self.transcript.blocker_root,
                "counter_root": self.transcript.counter_root,
                "stage_order_root": self.transcript.stage_order_root,
                "wallet_answer": self.transcript.wallet_answer,
                "production_answer": self.transcript.production_answer,
                "operator_summary": self.transcript.operator_summary,
            },
            "counters": {
                "total_vectors": self.counters.total_vectors,
                "ready_vectors": self.counters.ready_vectors,
                "watch_vectors": self.counters.watch_vectors,
                "deferred_vectors": self.counters.deferred_vectors,
                "blocked_vectors": self.counters.blocked_vectors,
                "rejected_vectors": self.counters.rejected_vectors,
                "forced_exit_critical_vectors": self.counters.forced_exit_critical_vectors,
                "wallet_blocking_vectors": self.counters.wallet_blocking_vectors,
                "production_blocking_vectors": self.counters.production_blocking_vectors,
                "heavy_gate_required_vectors": self.counters.heavy_gate_required_vectors,
            },
            "blockers": blockers,
            "stage_index": self.stage_index,
            "vectors": vectors,
        })
    }
}

pub fn devnet() -> State {
    State::new(Config::default())
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn default_inputs(config: &Config) -> Vec<CanonicalVectorInput> {
    let seed_root = seed_root(&config.chain_id);
    let deposit_root = canonical_root("deposit-lock", &seed_root, "accepted-finalized-lock", 10);
    let pq_root = canonical_root("pq-watcher", &deposit_root, "epoch-attestation-quorum", 20);
    let private_root = canonical_root("private-transfer", &pq_root, "note-to-receipt-link", 30);
    let settlement_root = canonical_root(
        "settlement-exit",
        &private_root,
        "receipt-to-claim-link",
        40,
    );
    let challenge_root =
        canonical_root("challenge-release", &settlement_root, "timeout-release", 50);
    let wallet_root = canonical_root(
        "wallet-reconstruction",
        &challenge_root,
        "local-evidence-pack",
        60,
    );
    let heavy_gate_root = canonical_root(
        "heavy-gate-plan",
        &wallet_root,
        "deferred-runtime-harness",
        70,
    );

    vec![
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::DepositLockVector,
            domain: CanonicalEvidenceDomain::MoneroLock,
            label: "canonical finalized Monero deposit lock vector".to_string(),
            prior_root: seed_root,
            vector_root: deposit_root.clone(),
            expected_next_root: pq_root.clone(),
            monero_confirmations: config.min_monero_confirmations + 6,
            pq_weight_bps: config.min_pq_weight_bps,
            privacy_set_size: config.min_privacy_set_size + 64,
            fee_bps: 7,
            transcript_order: CanonicalTranscriptStage::DepositLockVector.canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::PqWatcherAttestationVector,
            domain: CanonicalEvidenceDomain::PqWatcherQuorum,
            label: "canonical PQ watcher quorum attestation vector".to_string(),
            prior_root: deposit_root,
            vector_root: pq_root.clone(),
            expected_next_root: private_root.clone(),
            monero_confirmations: config.min_monero_confirmations + 5,
            pq_weight_bps: config.min_pq_weight_bps + 800,
            privacy_set_size: config.min_privacy_set_size + 48,
            fee_bps: 8,
            transcript_order: CanonicalTranscriptStage::PqWatcherAttestationVector
                .canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::PrivateNoteTransferVector,
            domain: CanonicalEvidenceDomain::PrivateState,
            label: "canonical deposit note to private transfer receipt vector".to_string(),
            prior_root: pq_root,
            vector_root: private_root.clone(),
            expected_next_root: settlement_root.clone(),
            monero_confirmations: 0,
            pq_weight_bps: config.min_pq_weight_bps,
            privacy_set_size: config.min_privacy_set_size + 256,
            fee_bps: 9,
            transcript_order: CanonicalTranscriptStage::PrivateNoteTransferVector.canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::SettlementExitVector,
            domain: CanonicalEvidenceDomain::SettlementReceipt,
            label: "canonical settlement receipt to exit claim vector".to_string(),
            prior_root: private_root,
            vector_root: settlement_root.clone(),
            expected_next_root: challenge_root.clone(),
            monero_confirmations: 0,
            pq_weight_bps: config.min_pq_weight_bps,
            privacy_set_size: config.min_privacy_set_size + 128,
            fee_bps: 10,
            transcript_order: CanonicalTranscriptStage::SettlementExitVector.canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::ChallengeReleaseVector,
            domain: CanonicalEvidenceDomain::ForcedExitChallenge,
            label: "canonical forced-exit challenge timeout release vector".to_string(),
            prior_root: settlement_root,
            vector_root: challenge_root.clone(),
            expected_next_root: wallet_root.clone(),
            monero_confirmations: 0,
            pq_weight_bps: config.min_pq_weight_bps + 400,
            privacy_set_size: config.min_privacy_set_size + 96,
            fee_bps: 11,
            transcript_order: CanonicalTranscriptStage::ChallengeReleaseVector.canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::WalletReconstructionVector,
            domain: CanonicalEvidenceDomain::WalletRecovery,
            label: "canonical wallet reconstruction vector for force exit".to_string(),
            prior_root: challenge_root,
            vector_root: wallet_root.clone(),
            expected_next_root: heavy_gate_root.clone(),
            monero_confirmations: 0,
            pq_weight_bps: config.min_pq_weight_bps,
            privacy_set_size: config.min_privacy_set_size + 96,
            fee_bps: 12,
            transcript_order: CanonicalTranscriptStage::WalletReconstructionVector
                .canonical_order(),
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
        CanonicalVectorInput {
            stage: CanonicalTranscriptStage::HeavyGateExecutionPlan,
            domain: CanonicalEvidenceDomain::RuntimeHarness,
            label: "canonical heavy-gate runtime harness vector remains deferred".to_string(),
            prior_root: wallet_root,
            vector_root: heavy_gate_root,
            expected_next_root: canonical_root(
                "audit-signoff",
                "heavy-gate-runtime",
                "deferred-audit",
                80,
            ),
            monero_confirmations: 0,
            pq_weight_bps: config.min_pq_weight_bps,
            privacy_set_size: config.min_privacy_set_size + 32,
            fee_bps: 13,
            transcript_order: CanonicalTranscriptStage::HeavyGateExecutionPlan.canonical_order(),
            heavy_gate_required: "required".to_string(),
            heavy_gate_available: "deferred".to_string(),
            fixture_backed: "fixture_backed".to_string(),
            wallet_reconstructable: "reconstructable".to_string(),
            production_release_required: "required".to_string(),
        },
    ]
}

pub fn derive_record(config: &Config, input: &CanonicalVectorInput) -> CanonicalVectorRecord {
    let status = derive_status(config, input);
    let blocker = derive_blocker(config, input, status);
    let input_root = input.input_root();
    let transcript_link_root = transcript_link_root(input, &input_root);
    let public_commitment_root = commitment_root("public", input, &transcript_link_root);
    let encrypted_payload_root = commitment_root("encrypted", input, &transcript_link_root);
    let wallet_recovery_root = commitment_root("wallet", input, &transcript_link_root);
    let forced_exit_critical =
        if input.stage.is_forced_exit_critical() && status.blocks_wallet_answer() {
            "critical_blocked"
        } else if input.stage.is_forced_exit_critical() {
            "critical"
        } else {
            "supporting"
        }
        .to_string();
    let production_lane = if status.blocks_production_answer() || blocker.is_some() {
        "blocked"
    } else {
        "ready"
    }
    .to_string();
    let remediation = remediation_hint(input.stage, status, blocker);
    let record_root = vector_record_root(
        input.stage,
        input.domain,
        status,
        &input_root,
        &input.vector_root,
        &transcript_link_root,
        blocker,
    );

    CanonicalVectorRecord {
        stage: input.stage,
        domain: input.domain,
        status,
        label: input.label.clone(),
        input_root,
        vector_root: input.vector_root.clone(),
        expected_next_root: input.expected_next_root.clone(),
        transcript_link_root,
        public_commitment_root,
        encrypted_payload_root,
        wallet_recovery_root,
        blocker,
        remediation,
        forced_exit_critical,
        production_lane,
        record_root,
    }
}

pub fn derive_status(config: &Config, input: &CanonicalVectorInput) -> CanonicalVectorStatus {
    if input.fee_bps > config.max_user_fee_bps {
        return CanonicalVectorStatus::Rejected;
    }
    if input.privacy_set_size < config.min_privacy_set_size {
        return CanonicalVectorStatus::Rejected;
    }
    if input.pq_weight_bps < config.min_pq_weight_bps {
        return CanonicalVectorStatus::Rejected;
    }
    if matches!(input.domain, CanonicalEvidenceDomain::MoneroLock)
        && input.monero_confirmations < config.min_monero_confirmations
    {
        return CanonicalVectorStatus::Blocked;
    }
    if input.transcript_order != input.stage.canonical_order() {
        return CanonicalVectorStatus::Blocked;
    }
    if input.requires_heavy_gate() && !input.heavy_gate_is_available() {
        return CanonicalVectorStatus::Deferred;
    }
    if !input.is_fixture_backed() || !input.wallet_can_reconstruct() {
        return CanonicalVectorStatus::Watch;
    }
    CanonicalVectorStatus::Ready
}

pub fn derive_blocker(
    config: &Config,
    input: &CanonicalVectorInput,
    status: CanonicalVectorStatus,
) -> Option<CanonicalBlockerKind> {
    if input.fee_bps > config.max_user_fee_bps {
        return Some(CanonicalBlockerKind::FeeCapExceeded);
    }
    if input.privacy_set_size < config.min_privacy_set_size {
        return Some(CanonicalBlockerKind::PrivacyBudgetTooSmall);
    }
    if input.pq_weight_bps < config.min_pq_weight_bps {
        return Some(CanonicalBlockerKind::PqWeightTooLow);
    }
    if matches!(input.domain, CanonicalEvidenceDomain::MoneroLock)
        && input.monero_confirmations < config.min_monero_confirmations
    {
        return Some(CanonicalBlockerKind::MoneroConfirmationsTooLow);
    }
    if input.transcript_order != input.stage.canonical_order() {
        return Some(CanonicalBlockerKind::TranscriptOrderBroken);
    }
    if input.requires_heavy_gate() && !input.heavy_gate_is_available() {
        return Some(CanonicalBlockerKind::CargoRuntimeDeferred);
    }
    if status == CanonicalVectorStatus::Watch {
        return match input.stage {
            CanonicalTranscriptStage::DepositLockVector => {
                Some(CanonicalBlockerKind::MissingDepositVector)
            }
            CanonicalTranscriptStage::PqWatcherAttestationVector => {
                Some(CanonicalBlockerKind::MissingPqWatcherVector)
            }
            CanonicalTranscriptStage::PrivateNoteTransferVector => {
                Some(CanonicalBlockerKind::MissingPrivateTransferVector)
            }
            CanonicalTranscriptStage::SettlementExitVector => {
                Some(CanonicalBlockerKind::MissingSettlementExitVector)
            }
            CanonicalTranscriptStage::ChallengeReleaseVector => {
                Some(CanonicalBlockerKind::MissingChallengeReleaseVector)
            }
            CanonicalTranscriptStage::WalletReconstructionVector => {
                Some(CanonicalBlockerKind::MissingWalletReconstructionVector)
            }
            CanonicalTranscriptStage::HeavyGateExecutionPlan => {
                Some(CanonicalBlockerKind::CargoRuntimeDeferred)
            }
        };
    }
    if input.stage == CanonicalTranscriptStage::DepositLockVector {
        return Some(CanonicalBlockerKind::NoBaseLayerVerifier);
    }
    None
}

pub fn build_transcript(
    config: &Config,
    inputs: &[CanonicalVectorInput],
    records: &[CanonicalVectorRecord],
    counters: &TranscriptCounters,
    blockers: &[CanonicalBlockerKind],
) -> CanonicalTranscript {
    let verdict = derive_verdict(config, counters, blockers);
    let input_root = inputs_root(inputs);
    let vector_root = records_root(records);
    let blocker_root = blockers_root(blockers);
    let counter_root = counters_root(counters);
    let stage_order_root = stage_order_root(records);
    let transcript_id = transcript_id(
        &config.chain_id,
        verdict,
        &input_root,
        &vector_root,
        &blocker_root,
        &stage_order_root,
    );
    let wallet_answer = wallet_answer(verdict, counters);
    let production_answer = production_answer(verdict, blockers);
    let operator_summary = operator_summary(verdict, counters, blockers);

    CanonicalTranscript {
        transcript_id,
        verdict,
        vector_root,
        input_root,
        blocker_root,
        counter_root,
        stage_order_root,
        wallet_answer,
        production_answer,
        operator_summary,
    }
}

pub fn derive_verdict(
    config: &Config,
    counters: &TranscriptCounters,
    blockers: &[CanonicalBlockerKind],
) -> TranscriptVerdict {
    if counters.rejected_vectors > 0 {
        return TranscriptVerdict::Rejected;
    }
    if counters.blocked_vectors > 0 || counters.wallet_blocking_vectors > 0 {
        return TranscriptVerdict::Blocked;
    }
    if counters.total_vectors < config.min_stage_count
        || counters.ready_vectors < config.min_ready_stages
    {
        return TranscriptVerdict::Watch;
    }
    if counters.watch_vectors > config.max_watch_stages
        || counters.deferred_vectors > config.max_deferred_stages
    {
        return TranscriptVerdict::Watch;
    }
    if !blockers.is_empty() || counters.deferred_vectors > 0 {
        return TranscriptVerdict::ReadyButHeavyGateDeferred;
    }
    TranscriptVerdict::ReadyForFixtureRun
}

pub fn public_vector_record(record: &CanonicalVectorRecord) -> Value {
    json!({
        "stage": record.stage.as_str(),
        "domain": record.domain.as_str(),
        "status": record.status.as_str(),
        "label": record.label,
        "input_root": record.input_root,
        "vector_root": record.vector_root,
        "expected_next_root": record.expected_next_root,
        "transcript_link_root": record.transcript_link_root,
        "public_commitment_root": record.public_commitment_root,
        "encrypted_payload_root": record.encrypted_payload_root,
        "wallet_recovery_root": record.wallet_recovery_root,
        "blocker": record.blocker.map(|blocker| blocker.as_str()),
        "remediation": record.remediation,
        "forced_exit_critical": record.forced_exit_critical,
        "production_lane": record.production_lane,
        "record_root": record.record_root,
    })
}

pub fn seed_root(chain_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-heavy-gate-transcript-seed",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(TRANSCRIPT_SUITE),
        ],
        32,
    )
}

pub fn canonical_root(domain: &str, prior_root: &str, label: &str, order: u64) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-canonical-vector-{domain}"),
        &[
            HashPart::Str(prior_root),
            HashPart::Str(label),
            HashPart::U64(order),
        ],
        32,
    )
}

pub fn transcript_link_root(input: &CanonicalVectorInput, input_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-transcript-link",
        &[
            HashPart::Str(input.stage.as_str()),
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(&input.prior_root),
            HashPart::Str(&input.vector_root),
            HashPart::Str(&input.expected_next_root),
            HashPart::Str(input_root),
        ],
        32,
    )
}

pub fn commitment_root(kind: &str, input: &CanonicalVectorInput, link_root: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-canonical-{kind}-commitment"),
        &[
            HashPart::Str(input.stage.as_str()),
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(&input.vector_root),
            HashPart::Str(link_root),
            HashPart::Str(&input.wallet_reconstructable),
        ],
        32,
    )
}

pub fn vector_record_root(
    stage: CanonicalTranscriptStage,
    domain: CanonicalEvidenceDomain,
    status: CanonicalVectorStatus,
    input_root: &str,
    vector_root: &str,
    link_root: &str,
    blocker: Option<CanonicalBlockerKind>,
) -> String {
    let blocker_label = blocker.map(|blocker| blocker.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-vector-record",
        &[
            HashPart::Str(stage.as_str()),
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(vector_root),
            HashPart::Str(link_root),
            HashPart::Str(blocker_label),
        ],
        32,
    )
}

pub fn inputs_root(inputs: &[CanonicalVectorInput]) -> String {
    let leaves = inputs
        .iter()
        .map(CanonicalVectorInput::input_root)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-transcript-inputs",
        leaves.as_slice(),
    )
}

pub fn records_root(records: &[CanonicalVectorRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| record.record_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-transcript-records",
        leaves.as_slice(),
    )
}

pub fn blockers_root(blockers: &[CanonicalBlockerKind]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| blocker.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-transcript-blockers",
        leaves.as_slice(),
    )
}

pub fn stage_order_root(records: &[CanonicalVectorRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            domain_hash(
                "monero-l2-pq-bridge-exit-canonical-stage-order-leaf",
                &[
                    HashPart::Str(record.stage.as_str()),
                    HashPart::U64(record.stage.canonical_order()),
                    HashPart::Str(&record.record_root),
                ],
                16,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-stage-order",
        leaves.as_slice(),
    )
}

pub fn counters_root(counters: &TranscriptCounters) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-transcript-counters",
        &[
            HashPart::U64(counters.total_vectors),
            HashPart::U64(counters.ready_vectors),
            HashPart::U64(counters.watch_vectors),
            HashPart::U64(counters.deferred_vectors),
            HashPart::U64(counters.blocked_vectors),
            HashPart::U64(counters.rejected_vectors),
            HashPart::U64(counters.forced_exit_critical_vectors),
            HashPart::U64(counters.wallet_blocking_vectors),
            HashPart::U64(counters.production_blocking_vectors),
            HashPart::U64(counters.heavy_gate_required_vectors),
        ],
        32,
    )
}

pub fn transcript_id(
    chain_id: &str,
    verdict: TranscriptVerdict,
    input_root: &str,
    vector_root: &str,
    blocker_root: &str,
    stage_order_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-transcript-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(vector_root),
            HashPart::Str(blocker_root),
            HashPart::Str(stage_order_root),
        ],
        16,
    )
}

pub fn remediation_hint(
    stage: CanonicalTranscriptStage,
    status: CanonicalVectorStatus,
    blocker: Option<CanonicalBlockerKind>,
) -> String {
    if status == CanonicalVectorStatus::Ready && blocker.is_none() {
        return format!("{} vector is ready for fixture execution", stage.as_str());
    }

    match blocker {
        Some(CanonicalBlockerKind::CargoRuntimeDeferred) => {
            "run the heavy cargo/runtime harness and replace deferred vector roots"
        }
        Some(CanonicalBlockerKind::SecurityAuditDeferred) => {
            "collect security and privacy audit signoff after vector execution"
        }
        Some(CanonicalBlockerKind::NoBaseLayerVerifier) => {
            "keep the Monero no-base-layer-verifier assumption explicit in release gating"
        }
        Some(CanonicalBlockerKind::MissingDepositVector) => {
            "bind the canonical deposit lock vector to Monero finality and watcher evidence"
        }
        Some(CanonicalBlockerKind::MissingPqWatcherVector) => {
            "bind the PQ watcher vector to signer epochs, quorum thresholds, and release roots"
        }
        Some(CanonicalBlockerKind::MissingPrivateTransferVector) => {
            "bind private note, nullifier, encrypted receipt, scan hint, and fee roots"
        }
        Some(CanonicalBlockerKind::MissingSettlementExitVector) => {
            "bind settlement receipt roots to exit claim and release authorization roots"
        }
        Some(CanonicalBlockerKind::MissingChallengeReleaseVector) => {
            "bind challenge-window replay, timeout eligibility, and release decision roots"
        }
        Some(CanonicalBlockerKind::MissingWalletReconstructionVector) => {
            "bind wallet-local reconstruction inputs and emergency exit material"
        }
        Some(CanonicalBlockerKind::PrivacyBudgetTooSmall) => {
            "increase privacy set size or reduce public disclosure in the vector"
        }
        Some(CanonicalBlockerKind::FeeCapExceeded) => {
            "lower the user-facing fee cap before including the vector in the transcript"
        }
        Some(CanonicalBlockerKind::PqWeightTooLow) => {
            "raise PQ signer weight or quarantine weak signer epochs"
        }
        Some(CanonicalBlockerKind::MoneroConfirmationsTooLow) => {
            "wait for deeper Monero confirmations or reject the vector"
        }
        Some(CanonicalBlockerKind::TranscriptOrderBroken) => {
            "restore canonical deposit-to-release stage ordering"
        }
        None => "replace watch or deferred evidence with a canonical fixture vector",
    }
    .to_string()
}

pub fn wallet_answer(verdict: TranscriptVerdict, counters: &TranscriptCounters) -> String {
    match verdict {
        TranscriptVerdict::ReadyForFixtureRun => {
            "wallet can follow the canonical get-in, transact-private, force-out transcript"
                .to_string()
        }
        TranscriptVerdict::ReadyButHeavyGateDeferred => format!(
            "wallet-critical vectors are clear, but {} heavy-gate vectors remain deferred",
            counters.deferred_vectors
        ),
        TranscriptVerdict::Watch => {
            "wallet path is watch-listed until vector coverage and execution readiness improve"
                .to_string()
        }
        TranscriptVerdict::Blocked => {
            "wallet path is blocked by a missing or inconsistent critical vector".to_string()
        }
        TranscriptVerdict::Rejected => {
            "wallet path rejected by a fee, privacy, finality, ordering, or PQ threshold"
                .to_string()
        }
    }
}

pub fn production_answer(verdict: TranscriptVerdict, blockers: &[CanonicalBlockerKind]) -> String {
    if blockers.is_empty() && verdict == TranscriptVerdict::ReadyForFixtureRun {
        return "production still needs live handlers, cargo/runtime execution, and audit signoff"
            .to_string();
    }

    let lanes = blockers
        .iter()
        .map(|blocker| blocker.owner_lane())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "production blocked while verdict={} and blocker_lanes=[{}]",
        verdict.as_str(),
        lanes
    )
}

pub fn operator_summary(
    verdict: TranscriptVerdict,
    counters: &TranscriptCounters,
    blockers: &[CanonicalBlockerKind],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "verdict={} total={} ready={} watch={} deferred={} blocked={} rejected={} forced_exit_critical={} wallet_blocking={} production_blocking={} heavy_gate_required={} blockers=[{}]",
        verdict.as_str(),
        counters.total_vectors,
        counters.ready_vectors,
        counters.watch_vectors,
        counters.deferred_vectors,
        counters.blocked_vectors,
        counters.rejected_vectors,
        counters.forced_exit_critical_vectors,
        counters.wallet_blocking_vectors,
        counters.production_blocking_vectors,
        counters.heavy_gate_required_vectors,
        blocker_labels
    )
}
