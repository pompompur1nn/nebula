use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalHeavyGateExecutionChecklistRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_CHECKLIST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-checklist-v1";
pub const DEFAULT_MIN_REQUIRED_ITEMS: u64 = 12;
pub const DEFAULT_MIN_READY_ITEMS: u64 = 9;
pub const DEFAULT_MAX_DEFERRED_ITEMS: u64 = 4;
pub const DEFAULT_MAX_WATCH_ITEMS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistDomain {
    DepositLock,
    MoneroFinality,
    PqWatcherAttestation,
    PrivateNoteTransfer,
    SettlementExit,
    ChallengeRelease,
    WalletReconstruction,
    StaticVerifier,
    NegativeCaseManifest,
    RuntimeHarnessFixture,
    PrivacyPqInvariant,
    ReleaseBlockerMatrix,
    SecurityAudit,
}

impl ChecklistDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::MoneroFinality => "monero_finality",
            Self::PqWatcherAttestation => "pq_watcher_attestation",
            Self::PrivateNoteTransfer => "private_note_transfer",
            Self::SettlementExit => "settlement_exit",
            Self::ChallengeRelease => "challenge_release",
            Self::WalletReconstruction => "wallet_reconstruction",
            Self::StaticVerifier => "static_verifier",
            Self::NegativeCaseManifest => "negative_case_manifest",
            Self::RuntimeHarnessFixture => "runtime_harness_fixture",
            Self::PrivacyPqInvariant => "privacy_pq_invariant",
            Self::ReleaseBlockerMatrix => "release_blocker_matrix",
            Self::SecurityAudit => "security_audit",
        }
    }

    pub fn is_wallet_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLock
                | Self::MoneroFinality
                | Self::PqWatcherAttestation
                | Self::SettlementExit
                | Self::ChallengeRelease
                | Self::WalletReconstruction
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistItemStatus {
    Ready,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl ChecklistItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_wallet(self) -> bool {
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
pub enum ChecklistBlockerKind {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    NoBaseLayerVerifier,
    MissingCanonicalVector,
    MissingStaticVerifier,
    MissingNegativeCaseManifest,
    MissingRuntimeHarnessFixture,
    MissingPrivacyPqInvariantMatrix,
    MissingReleaseBlockerMatrix,
    MissingWalletRunbook,
    FeeCapExceeded,
    PrivacySetTooSmall,
    PqWeightTooLow,
    MoneroConfirmationsTooLow,
    NonCanonicalOrder,
}

impl ChecklistBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::MissingCanonicalVector => "missing_canonical_vector",
            Self::MissingStaticVerifier => "missing_static_verifier",
            Self::MissingNegativeCaseManifest => "missing_negative_case_manifest",
            Self::MissingRuntimeHarnessFixture => "missing_runtime_harness_fixture",
            Self::MissingPrivacyPqInvariantMatrix => "missing_privacy_pq_invariant_matrix",
            Self::MissingReleaseBlockerMatrix => "missing_release_blocker_matrix",
            Self::MissingWalletRunbook => "missing_wallet_runbook",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::PqWeightTooLow => "pq_weight_too_low",
            Self::MoneroConfirmationsTooLow => "monero_confirmations_too_low",
            Self::NonCanonicalOrder => "non_canonical_order",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::NoBaseLayerVerifier => "monero_evidence_policy",
            Self::MissingCanonicalVector => "canonical_vectors",
            Self::MissingStaticVerifier => "static_verifier",
            Self::MissingNegativeCaseManifest => "negative_case_manifest",
            Self::MissingRuntimeHarnessFixture => "runtime_harness_fixture",
            Self::MissingPrivacyPqInvariantMatrix => "privacy_pq_invariants",
            Self::MissingReleaseBlockerMatrix => "release_blockers",
            Self::MissingWalletRunbook => "wallet_force_exit_runbook",
            Self::FeeCapExceeded => "fee_policy",
            Self::PrivacySetTooSmall => "privacy_review",
            Self::PqWeightTooLow => "pq_control_plane",
            Self::MoneroConfirmationsTooLow => "monero_finality_policy",
            Self::NonCanonicalOrder => "canonical_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistVerdict {
    ReadyForFixtureExecution,
    ReadyButCargoDeferred,
    Watch,
    Blocked,
    Rejected,
}

impl ChecklistVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForFixtureExecution => "ready_for_fixture_execution",
            Self::ReadyButCargoDeferred => "ready_but_cargo_deferred",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_required_items: u64,
    pub min_ready_items: u64,
    pub max_deferred_items: u64,
    pub max_watch_items: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_weight_bps: u64,
    pub min_monero_confirmations: u64,
    pub max_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_required_items: DEFAULT_MIN_REQUIRED_ITEMS,
            min_ready_items: DEFAULT_MIN_READY_ITEMS,
            max_deferred_items: DEFAULT_MAX_DEFERRED_ITEMS,
            max_watch_items: DEFAULT_MAX_WATCH_ITEMS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            max_items: DEFAULT_MAX_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistInput {
    pub domain: ChecklistDomain,
    pub label: String,
    pub canonical_stage_root: String,
    pub expected_prior_root: String,
    pub expected_next_root: String,
    pub evidence_root: String,
    pub assertion_root: String,
    pub wallet_recovery_root: String,
    pub monero_confirmations: u64,
    pub pq_weight_bps: u64,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub canonical_order: u64,
    pub expected_order: u64,
    pub cargo_required: String,
    pub cargo_available: String,
    pub audit_required: String,
    pub audit_available: String,
    pub wallet_required: String,
    pub wallet_available: String,
}

impl ChecklistInput {
    pub fn input_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-checklist-input",
            &[
                HashPart::Str(self.domain.as_str()),
                HashPart::Str(&self.label),
                HashPart::Str(&self.canonical_stage_root),
                HashPart::Str(&self.expected_prior_root),
                HashPart::Str(&self.expected_next_root),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(&self.assertion_root),
                HashPart::Str(&self.wallet_recovery_root),
                HashPart::U64(self.monero_confirmations),
                HashPart::U64(self.pq_weight_bps),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.fee_bps),
                HashPart::U64(self.canonical_order),
                HashPart::U64(self.expected_order),
                HashPart::Str(&self.cargo_required),
                HashPart::Str(&self.cargo_available),
                HashPart::Str(&self.audit_required),
                HashPart::Str(&self.audit_available),
                HashPart::Str(&self.wallet_required),
                HashPart::Str(&self.wallet_available),
            ],
            32,
        )
    }

    pub fn cargo_is_required(&self) -> bool {
        self.cargo_required == "required"
    }

    pub fn cargo_is_available(&self) -> bool {
        self.cargo_available == "available"
    }

    pub fn audit_is_required(&self) -> bool {
        self.audit_required == "required"
    }

    pub fn audit_is_available(&self) -> bool {
        self.audit_available == "available"
    }

    pub fn wallet_is_required(&self) -> bool {
        self.wallet_required == "required"
    }

    pub fn wallet_is_available(&self) -> bool {
        self.wallet_available == "available"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub domain: ChecklistDomain,
    pub status: ChecklistItemStatus,
    pub label: String,
    pub input_root: String,
    pub checklist_root: String,
    pub continuity_root: String,
    pub wallet_answer_root: String,
    pub production_answer_root: String,
    pub blocker: Option<ChecklistBlockerKind>,
    pub owner_lane: String,
    pub remediation: String,
    pub wallet_lane: String,
    pub production_lane: String,
    pub item_root: String,
}

impl ChecklistItem {
    pub fn blocks_wallet(&self) -> bool {
        self.status.blocks_wallet() && matches!(self.wallet_lane.as_str(), "critical" | "blocked")
    }

    pub fn blocks_production(&self) -> bool {
        self.status.blocks_production() || self.blocker.is_some() || self.production_lane != "ready"
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistCounters {
    pub total_items: u64,
    pub ready_items: u64,
    pub watch_items: u64,
    pub deferred_items: u64,
    pub blocked_items: u64,
    pub rejected_items: u64,
    pub wallet_critical_items: u64,
    pub wallet_blocking_items: u64,
    pub production_blocking_items: u64,
    pub cargo_required_items: u64,
    pub audit_required_items: u64,
}

impl ChecklistCounters {
    pub fn observe(&mut self, input: &ChecklistInput, item: &ChecklistItem) {
        self.total_items += 1;
        match item.status {
            ChecklistItemStatus::Ready => self.ready_items += 1,
            ChecklistItemStatus::Watch => self.watch_items += 1,
            ChecklistItemStatus::Deferred => self.deferred_items += 1,
            ChecklistItemStatus::Blocked => self.blocked_items += 1,
            ChecklistItemStatus::Rejected => self.rejected_items += 1,
        }
        if input.domain.is_wallet_critical() || input.wallet_is_required() {
            self.wallet_critical_items += 1;
        }
        if item.blocks_wallet() {
            self.wallet_blocking_items += 1;
        }
        if item.blocks_production() {
            self.production_blocking_items += 1;
        }
        if input.cargo_is_required() {
            self.cargo_required_items += 1;
        }
        if input.audit_is_required() {
            self.audit_required_items += 1;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeavyGateChecklist {
    pub checklist_id: String,
    pub verdict: ChecklistVerdict,
    pub input_root: String,
    pub item_root: String,
    pub blocker_root: String,
    pub counter_root: String,
    pub owner_lane_root: String,
    pub wallet_answer: String,
    pub production_answer: String,
    pub operator_summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub inputs: Vec<ChecklistInput>,
    pub items: Vec<ChecklistItem>,
    pub counters: ChecklistCounters,
    pub blockers: Vec<ChecklistBlockerKind>,
    pub owner_lanes: BTreeMap<String, String>,
    pub checklist: HeavyGateChecklist,
}

impl State {
    pub fn new(config: Config) -> Self {
        let inputs = default_inputs(&config);
        Self::from_inputs(config, inputs)
    }

    pub fn from_inputs(config: Config, inputs: Vec<ChecklistInput>) -> Self {
        let limited_inputs = inputs
            .into_iter()
            .take(config.max_items)
            .collect::<Vec<_>>();
        let mut counters = ChecklistCounters::default();
        let mut blockers = Vec::new();
        let mut items = Vec::new();
        let mut owner_lanes = BTreeMap::new();

        for input in &limited_inputs {
            let item = derive_item(&config, input);
            counters.observe(input, &item);
            if let Some(blocker) = item.blocker {
                if !blockers.contains(&blocker) {
                    blockers.push(blocker);
                }
            }
            owner_lanes.insert(input.domain.as_str().to_string(), item.owner_lane.clone());
            items.push(item);
        }

        blockers.sort();
        let checklist = build_checklist(&config, &limited_inputs, &items, &counters, &blockers);

        Self {
            config,
            inputs: limited_inputs,
            items,
            counters,
            blockers,
            owner_lanes,
            checklist,
        }
    }

    pub fn ingest(&mut self, input: ChecklistInput) -> Result<()> {
        if self.inputs.len() >= self.config.max_items {
            return Err("canonical heavy-gate checklist capacity reached".to_string());
        }
        self.inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), self.inputs.clone());
        Ok(())
    }

    pub fn wallet_path_clear(&self) -> bool {
        self.counters.wallet_blocking_items == 0
            && self.counters.ready_items >= self.config.min_ready_items
    }

    pub fn production_blocked(&self) -> bool {
        !self.blockers.is_empty()
            || self.counters.deferred_items > 0
            || self.counters.production_blocking_items > 0
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-heavy-gate-checklist-state",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.checklist.checklist_id),
                HashPart::Str(&self.checklist.input_root),
                HashPart::Str(&self.checklist.item_root),
                HashPart::Str(&self.checklist.blocker_root),
                HashPart::Str(&self.checklist.counter_root),
                HashPart::Str(&self.checklist.owner_lane_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let items = self
            .items
            .iter()
            .map(public_item_record)
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
            "checklist_suite": CHECKLIST_SUITE,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "checklist": {
                "checklist_id": self.checklist.checklist_id,
                "verdict": self.checklist.verdict.as_str(),
                "input_root": self.checklist.input_root,
                "item_root": self.checklist.item_root,
                "blocker_root": self.checklist.blocker_root,
                "counter_root": self.checklist.counter_root,
                "owner_lane_root": self.checklist.owner_lane_root,
                "wallet_answer": self.checklist.wallet_answer,
                "production_answer": self.checklist.production_answer,
                "operator_summary": self.checklist.operator_summary,
            },
            "counters": {
                "total_items": self.counters.total_items,
                "ready_items": self.counters.ready_items,
                "watch_items": self.counters.watch_items,
                "deferred_items": self.counters.deferred_items,
                "blocked_items": self.counters.blocked_items,
                "rejected_items": self.counters.rejected_items,
                "wallet_critical_items": self.counters.wallet_critical_items,
                "wallet_blocking_items": self.counters.wallet_blocking_items,
                "production_blocking_items": self.counters.production_blocking_items,
                "cargo_required_items": self.counters.cargo_required_items,
                "audit_required_items": self.counters.audit_required_items,
            },
            "blockers": blockers,
            "owner_lanes": self.owner_lanes,
            "items": items,
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

pub fn default_inputs(config: &Config) -> Vec<ChecklistInput> {
    let seed = seed_root(&config.chain_id);
    let deposit = checklist_stage_root("deposit", &seed, "canonical-deposit-lock", 10);
    let finality = checklist_stage_root("finality", &deposit, "monero-finality-casebook", 20);
    let pq = checklist_stage_root("pq-watcher", &finality, "canonical-pq-attestation", 30);
    let private = checklist_stage_root("private-note", &pq, "private-note-transfer", 40);
    let settlement = checklist_stage_root("settlement", &private, "settlement-exit-vector", 50);
    let challenge = checklist_stage_root("challenge", &settlement, "challenge-release-vector", 60);
    let wallet = checklist_stage_root("wallet", &challenge, "wallet-reconstruction-vector", 70);
    let static_verifier = checklist_stage_root("static-verifier", &wallet, "static-verifier", 80);
    let negative = checklist_stage_root(
        "negative-cases",
        &static_verifier,
        "negative-case-manifest",
        90,
    );
    let runtime = checklist_stage_root(
        "runtime-harness",
        &negative,
        "deferred-runtime-harness",
        100,
    );
    let invariant = checklist_stage_root("invariants", &runtime, "privacy-pq-invariants", 110);
    let blockers = checklist_stage_root("blockers", &invariant, "release-blocker-matrix", 120);
    let audit = checklist_stage_root("audit", &blockers, "deferred-security-audit", 130);

    vec![
        input(
            ChecklistDomain::DepositLock,
            "canonical deposit lock vector must be fixture-backed",
            &seed,
            &deposit,
            &finality,
            config.min_monero_confirmations + 6,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 256,
            6,
            10,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::MoneroFinality,
            "Monero finality and no-base-layer-verifier risk must be explicit",
            &deposit,
            &finality,
            &pq,
            config.min_monero_confirmations + 6,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 192,
            7,
            20,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::PqWatcherAttestation,
            "PQ watcher attestation vector must bind signer epoch and release authority",
            &finality,
            &pq,
            &private,
            config.min_monero_confirmations,
            config.min_pq_weight_bps + 700,
            config.min_privacy_set_size + 128,
            8,
            30,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::PrivateNoteTransfer,
            "private note transfer vector must preserve note and receipt continuity",
            &pq,
            &private,
            &settlement,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 512,
            9,
            40,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::SettlementExit,
            "settlement exit vector must bind receipt and exit claim roots",
            &private,
            &settlement,
            &challenge,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 256,
            10,
            50,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::ChallengeRelease,
            "challenge release vector must replay timeout and invalid challenge cases",
            &settlement,
            &challenge,
            &wallet,
            0,
            config.min_pq_weight_bps + 300,
            config.min_privacy_set_size + 192,
            11,
            60,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::WalletReconstruction,
            "wallet reconstruction vector must prove user-local escape evidence",
            &challenge,
            &wallet,
            &static_verifier,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 192,
            12,
            70,
            "not_required",
            "available",
            "not_required",
            "available",
            "required",
            "available",
        ),
        input(
            ChecklistDomain::StaticVerifier,
            "static verifier must check canonical vector continuity",
            &wallet,
            &static_verifier,
            &negative,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 64,
            13,
            80,
            "not_required",
            "available",
            "not_required",
            "available",
            "not_required",
            "available",
        ),
        input(
            ChecklistDomain::NegativeCaseManifest,
            "negative manifest must list fail-closed vectors",
            &static_verifier,
            &negative,
            &runtime,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 64,
            14,
            90,
            "not_required",
            "available",
            "not_required",
            "available",
            "not_required",
            "available",
        ),
        input(
            ChecklistDomain::RuntimeHarnessFixture,
            "runtime harness fixture remains deferred until cargo gates resume",
            &negative,
            &runtime,
            &invariant,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 64,
            15,
            100,
            "required",
            "deferred",
            "not_required",
            "available",
            "not_required",
            "available",
        ),
        input(
            ChecklistDomain::PrivacyPqInvariant,
            "privacy and PQ invariant matrix must be satisfied before release",
            &runtime,
            &invariant,
            &blockers,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 96,
            16,
            110,
            "not_required",
            "available",
            "not_required",
            "available",
            "not_required",
            "available",
        ),
        input(
            ChecklistDomain::ReleaseBlockerMatrix,
            "release blocker matrix must keep production blocked until execution",
            &invariant,
            &blockers,
            &audit,
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 64,
            17,
            120,
            "not_required",
            "available",
            "not_required",
            "available",
            "not_required",
            "available",
        ),
        input(
            ChecklistDomain::SecurityAudit,
            "security and privacy audit remains deferred until execution roots exist",
            &blockers,
            &audit,
            &checklist_stage_root("post-audit", &audit, "production-hold", 140),
            0,
            config.min_pq_weight_bps,
            config.min_privacy_set_size + 64,
            18,
            130,
            "not_required",
            "available",
            "required",
            "deferred",
            "not_required",
            "available",
        ),
    ]
}

pub fn input(
    domain: ChecklistDomain,
    label: &str,
    prior_root: &str,
    stage_root: &str,
    next_root: &str,
    monero_confirmations: u64,
    pq_weight_bps: u64,
    privacy_set_size: u64,
    fee_bps: u64,
    order: u64,
    cargo_required: &str,
    cargo_available: &str,
    audit_required: &str,
    audit_available: &str,
    wallet_required: &str,
    wallet_available: &str,
) -> ChecklistInput {
    let evidence_root = derived_root("evidence", domain, stage_root, order);
    let assertion_root = derived_root("assertion", domain, &evidence_root, order);
    let wallet_recovery_root = derived_root("wallet", domain, &assertion_root, order);

    ChecklistInput {
        domain,
        label: label.to_string(),
        canonical_stage_root: stage_root.to_string(),
        expected_prior_root: prior_root.to_string(),
        expected_next_root: next_root.to_string(),
        evidence_root,
        assertion_root,
        wallet_recovery_root,
        monero_confirmations,
        pq_weight_bps,
        privacy_set_size,
        fee_bps,
        canonical_order: order,
        expected_order: order,
        cargo_required: cargo_required.to_string(),
        cargo_available: cargo_available.to_string(),
        audit_required: audit_required.to_string(),
        audit_available: audit_available.to_string(),
        wallet_required: wallet_required.to_string(),
        wallet_available: wallet_available.to_string(),
    }
}

pub fn derive_item(config: &Config, input: &ChecklistInput) -> ChecklistItem {
    let status = derive_status(config, input);
    let blocker = derive_blocker(config, input, status);
    let input_root = input.input_root();
    let checklist_root = checklist_item_root(input, status, blocker);
    let continuity_root = continuity_root(input, &input_root);
    let wallet_answer_root = answer_root("wallet", input, status, &continuity_root);
    let production_answer_root = answer_root("production", input, status, &continuity_root);
    let owner_lane = blocker
        .map(|value| value.owner_lane())
        .unwrap_or(input.domain.as_str())
        .to_string();
    let wallet_lane = if input.domain.is_wallet_critical() && status.blocks_wallet() {
        "blocked"
    } else if input.domain.is_wallet_critical() || input.wallet_is_required() {
        "critical"
    } else {
        "supporting"
    }
    .to_string();
    let production_lane = if status.blocks_production() || blocker.is_some() {
        "blocked"
    } else {
        "ready"
    }
    .to_string();
    let remediation = remediation_hint(input.domain, status, blocker);
    let item_root = item_root(
        input.domain,
        status,
        &input_root,
        &checklist_root,
        &continuity_root,
        blocker,
    );

    ChecklistItem {
        domain: input.domain,
        status,
        label: input.label.clone(),
        input_root,
        checklist_root,
        continuity_root,
        wallet_answer_root,
        production_answer_root,
        blocker,
        owner_lane,
        remediation,
        wallet_lane,
        production_lane,
        item_root,
    }
}

pub fn derive_status(config: &Config, input: &ChecklistInput) -> ChecklistItemStatus {
    if input.fee_bps > config.max_user_fee_bps {
        return ChecklistItemStatus::Rejected;
    }
    if input.privacy_set_size < config.min_privacy_set_size {
        return ChecklistItemStatus::Rejected;
    }
    if input.pq_weight_bps < config.min_pq_weight_bps {
        return ChecklistItemStatus::Rejected;
    }
    if input.canonical_order != input.expected_order {
        return ChecklistItemStatus::Blocked;
    }
    if matches!(
        input.domain,
        ChecklistDomain::DepositLock | ChecklistDomain::MoneroFinality
    ) && input.monero_confirmations < config.min_monero_confirmations
    {
        return ChecklistItemStatus::Blocked;
    }
    if input.cargo_is_required() && !input.cargo_is_available() {
        return ChecklistItemStatus::Deferred;
    }
    if input.audit_is_required() && !input.audit_is_available() {
        return ChecklistItemStatus::Deferred;
    }
    if input.wallet_is_required() && !input.wallet_is_available() {
        return ChecklistItemStatus::Blocked;
    }
    ChecklistItemStatus::Ready
}

pub fn derive_blocker(
    config: &Config,
    input: &ChecklistInput,
    status: ChecklistItemStatus,
) -> Option<ChecklistBlockerKind> {
    if input.fee_bps > config.max_user_fee_bps {
        return Some(ChecklistBlockerKind::FeeCapExceeded);
    }
    if input.privacy_set_size < config.min_privacy_set_size {
        return Some(ChecklistBlockerKind::PrivacySetTooSmall);
    }
    if input.pq_weight_bps < config.min_pq_weight_bps {
        return Some(ChecklistBlockerKind::PqWeightTooLow);
    }
    if input.canonical_order != input.expected_order {
        return Some(ChecklistBlockerKind::NonCanonicalOrder);
    }
    if matches!(
        input.domain,
        ChecklistDomain::DepositLock | ChecklistDomain::MoneroFinality
    ) && input.monero_confirmations < config.min_monero_confirmations
    {
        return Some(ChecklistBlockerKind::MoneroConfirmationsTooLow);
    }
    if input.cargo_is_required() && !input.cargo_is_available() {
        return Some(ChecklistBlockerKind::CargoRuntimeDeferred);
    }
    if input.audit_is_required() && !input.audit_is_available() {
        return Some(ChecklistBlockerKind::SecurityAuditDeferred);
    }
    if input.wallet_is_required() && !input.wallet_is_available() {
        return Some(ChecklistBlockerKind::MissingWalletRunbook);
    }
    if input.domain == ChecklistDomain::MoneroFinality {
        return Some(ChecklistBlockerKind::NoBaseLayerVerifier);
    }
    if status == ChecklistItemStatus::Watch {
        return match input.domain {
            ChecklistDomain::StaticVerifier => Some(ChecklistBlockerKind::MissingStaticVerifier),
            ChecklistDomain::NegativeCaseManifest => {
                Some(ChecklistBlockerKind::MissingNegativeCaseManifest)
            }
            ChecklistDomain::RuntimeHarnessFixture => {
                Some(ChecklistBlockerKind::MissingRuntimeHarnessFixture)
            }
            ChecklistDomain::PrivacyPqInvariant => {
                Some(ChecklistBlockerKind::MissingPrivacyPqInvariantMatrix)
            }
            ChecklistDomain::ReleaseBlockerMatrix => {
                Some(ChecklistBlockerKind::MissingReleaseBlockerMatrix)
            }
            _ => Some(ChecklistBlockerKind::MissingCanonicalVector),
        };
    }
    None
}

pub fn build_checklist(
    config: &Config,
    inputs: &[ChecklistInput],
    items: &[ChecklistItem],
    counters: &ChecklistCounters,
    blockers: &[ChecklistBlockerKind],
) -> HeavyGateChecklist {
    let verdict = derive_verdict(config, counters, blockers);
    let input_root = inputs_root(inputs);
    let item_root = items_root(items);
    let blocker_root = blockers_root(blockers);
    let counter_root = counters_root(counters);
    let owner_lane_root = owner_lane_root(items);
    let checklist_id = checklist_id(
        &config.chain_id,
        verdict,
        &input_root,
        &item_root,
        &blocker_root,
        &owner_lane_root,
    );
    let wallet_answer = wallet_answer(verdict, counters);
    let production_answer = production_answer(verdict, blockers);
    let operator_summary = operator_summary(verdict, counters, blockers);

    HeavyGateChecklist {
        checklist_id,
        verdict,
        input_root,
        item_root,
        blocker_root,
        counter_root,
        owner_lane_root,
        wallet_answer,
        production_answer,
        operator_summary,
    }
}

pub fn derive_verdict(
    config: &Config,
    counters: &ChecklistCounters,
    blockers: &[ChecklistBlockerKind],
) -> ChecklistVerdict {
    if counters.rejected_items > 0 {
        return ChecklistVerdict::Rejected;
    }
    if counters.blocked_items > 0 || counters.wallet_blocking_items > 0 {
        return ChecklistVerdict::Blocked;
    }
    if counters.total_items < config.min_required_items
        || counters.ready_items < config.min_ready_items
    {
        return ChecklistVerdict::Watch;
    }
    if counters.watch_items > config.max_watch_items
        || counters.deferred_items > config.max_deferred_items
    {
        return ChecklistVerdict::Watch;
    }
    if !blockers.is_empty() || counters.deferred_items > 0 {
        return ChecklistVerdict::ReadyButCargoDeferred;
    }
    ChecklistVerdict::ReadyForFixtureExecution
}

pub fn public_item_record(item: &ChecklistItem) -> Value {
    json!({
        "domain": item.domain.as_str(),
        "status": item.status.as_str(),
        "label": item.label,
        "input_root": item.input_root,
        "checklist_root": item.checklist_root,
        "continuity_root": item.continuity_root,
        "wallet_answer_root": item.wallet_answer_root,
        "production_answer_root": item.production_answer_root,
        "blocker": item.blocker.map(|blocker| blocker.as_str()),
        "owner_lane": item.owner_lane,
        "remediation": item.remediation,
        "wallet_lane": item.wallet_lane,
        "production_lane": item.production_lane,
        "item_root": item.item_root,
    })
}

pub fn seed_root(chain_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-heavy-gate-checklist-seed",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHECKLIST_SUITE),
        ],
        32,
    )
}

pub fn checklist_stage_root(domain: &str, prior_root: &str, label: &str, order: u64) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-canonical-checklist-stage-{domain}"),
        &[
            HashPart::Str(prior_root),
            HashPart::Str(label),
            HashPart::U64(order),
        ],
        32,
    )
}

pub fn derived_root(kind: &str, domain: ChecklistDomain, root: &str, order: u64) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-canonical-checklist-{kind}"),
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(root),
            HashPart::U64(order),
        ],
        32,
    )
}

pub fn continuity_root(input: &ChecklistInput, input_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-checklist-continuity",
        &[
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(&input.expected_prior_root),
            HashPart::Str(&input.canonical_stage_root),
            HashPart::Str(&input.expected_next_root),
            HashPart::Str(input_root),
        ],
        32,
    )
}

pub fn checklist_item_root(
    input: &ChecklistInput,
    status: ChecklistItemStatus,
    blocker: Option<ChecklistBlockerKind>,
) -> String {
    let blocker_label = blocker.map(|value| value.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-checklist-item",
        &[
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&input.input_root()),
            HashPart::Str(&input.evidence_root),
            HashPart::Str(&input.assertion_root),
            HashPart::Str(blocker_label),
        ],
        32,
    )
}

pub fn answer_root(
    answer_domain: &str,
    input: &ChecklistInput,
    status: ChecklistItemStatus,
    continuity_root: &str,
) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-canonical-checklist-{answer_domain}-answer"),
        &[
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(continuity_root),
            HashPart::Str(&input.wallet_recovery_root),
        ],
        32,
    )
}

pub fn item_root(
    domain: ChecklistDomain,
    status: ChecklistItemStatus,
    input_root: &str,
    checklist_root: &str,
    continuity_root: &str,
    blocker: Option<ChecklistBlockerKind>,
) -> String {
    let blocker_label = blocker.map(|value| value.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-checklist-item-root",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(checklist_root),
            HashPart::Str(continuity_root),
            HashPart::Str(blocker_label),
        ],
        32,
    )
}

pub fn inputs_root(inputs: &[ChecklistInput]) -> String {
    let leaves = inputs
        .iter()
        .map(ChecklistInput::input_root)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-checklist-inputs",
        leaves.as_slice(),
    )
}

pub fn items_root(items: &[ChecklistItem]) -> String {
    let leaves = items
        .iter()
        .map(|item| item.item_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-checklist-items",
        leaves.as_slice(),
    )
}

pub fn blockers_root(blockers: &[ChecklistBlockerKind]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| blocker.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-checklist-blockers",
        leaves.as_slice(),
    )
}

pub fn owner_lane_root(items: &[ChecklistItem]) -> String {
    let leaves = items
        .iter()
        .map(|item| {
            domain_hash(
                "monero-l2-pq-bridge-exit-canonical-checklist-owner-lane-leaf",
                &[
                    HashPart::Str(item.domain.as_str()),
                    HashPart::Str(&item.owner_lane),
                    HashPart::Str(&item.item_root),
                ],
                16,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-checklist-owner-lanes",
        leaves.as_slice(),
    )
}

pub fn counters_root(counters: &ChecklistCounters) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-checklist-counters",
        &[
            HashPart::U64(counters.total_items),
            HashPart::U64(counters.ready_items),
            HashPart::U64(counters.watch_items),
            HashPart::U64(counters.deferred_items),
            HashPart::U64(counters.blocked_items),
            HashPart::U64(counters.rejected_items),
            HashPart::U64(counters.wallet_critical_items),
            HashPart::U64(counters.wallet_blocking_items),
            HashPart::U64(counters.production_blocking_items),
            HashPart::U64(counters.cargo_required_items),
            HashPart::U64(counters.audit_required_items),
        ],
        32,
    )
}

pub fn checklist_id(
    chain_id: &str,
    verdict: ChecklistVerdict,
    input_root: &str,
    item_root: &str,
    blocker_root: &str,
    owner_lane_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-heavy-gate-checklist-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(item_root),
            HashPart::Str(blocker_root),
            HashPart::Str(owner_lane_root),
        ],
        16,
    )
}

pub fn remediation_hint(
    domain: ChecklistDomain,
    status: ChecklistItemStatus,
    blocker: Option<ChecklistBlockerKind>,
) -> String {
    if status == ChecklistItemStatus::Ready && blocker.is_none() {
        return format!(
            "{} checklist item is ready for heavy-gate fixture execution",
            domain.as_str()
        );
    }

    match blocker {
        Some(ChecklistBlockerKind::CargoRuntimeDeferred) => {
            "resume cargo/runtime execution and bind real heavy-gate result roots"
        }
        Some(ChecklistBlockerKind::SecurityAuditDeferred) => {
            "collect security and privacy audit signoff after runtime roots exist"
        }
        Some(ChecklistBlockerKind::NoBaseLayerVerifier) => {
            "keep Monero no-base-layer-verifier risk visible in release gating"
        }
        Some(ChecklistBlockerKind::MissingCanonicalVector) => {
            "wire all canonical vector roots into the transcript before execution"
        }
        Some(ChecklistBlockerKind::MissingStaticVerifier) => {
            "bind static verifier roots for canonical stage ordering and continuity"
        }
        Some(ChecklistBlockerKind::MissingNegativeCaseManifest) => {
            "bind fail-closed negative cases for invalid bridge/exit vectors"
        }
        Some(ChecklistBlockerKind::MissingRuntimeHarnessFixture) => {
            "materialize runtime harness fixtures and expected assertion roots"
        }
        Some(ChecklistBlockerKind::MissingPrivacyPqInvariantMatrix) => {
            "bind privacy and PQ invariant matrix roots before release"
        }
        Some(ChecklistBlockerKind::MissingReleaseBlockerMatrix) => {
            "bind release blocker matrix and clearing order roots"
        }
        Some(ChecklistBlockerKind::MissingWalletRunbook) => {
            "bind wallet force-exit runbook roots and user-local evidence"
        }
        Some(ChecklistBlockerKind::FeeCapExceeded) => "lower user-facing fees under policy cap",
        Some(ChecklistBlockerKind::PrivacySetTooSmall) => {
            "increase privacy set or reduce public disclosure"
        }
        Some(ChecklistBlockerKind::PqWeightTooLow) => {
            "raise PQ signer weight or quarantine weak epochs"
        }
        Some(ChecklistBlockerKind::MoneroConfirmationsTooLow) => {
            "wait for deeper Monero confirmations before accepting the vector"
        }
        Some(ChecklistBlockerKind::NonCanonicalOrder) => {
            "restore canonical deposit-to-release checklist ordering"
        }
        None => "replace watch or deferred checklist evidence with bound fixture roots",
    }
    .to_string()
}

pub fn wallet_answer(verdict: ChecklistVerdict, counters: &ChecklistCounters) -> String {
    match verdict {
        ChecklistVerdict::ReadyForFixtureExecution => {
            "wallet can follow the canonical force-exit checklist from local evidence".to_string()
        }
        ChecklistVerdict::ReadyButCargoDeferred => format!(
            "wallet-critical checklist is clear, but {} cargo/audit items remain deferred",
            counters.deferred_items
        ),
        ChecklistVerdict::Watch => {
            "wallet path is watch-listed until checklist coverage and execution roots improve"
                .to_string()
        }
        ChecklistVerdict::Blocked => {
            "wallet path is blocked by a critical checklist item".to_string()
        }
        ChecklistVerdict::Rejected => {
            "wallet path rejected by checklist fee, privacy, PQ, finality, or ordering policy"
                .to_string()
        }
    }
}

pub fn production_answer(verdict: ChecklistVerdict, blockers: &[ChecklistBlockerKind]) -> String {
    if blockers.is_empty() && verdict == ChecklistVerdict::ReadyForFixtureExecution {
        return "production still requires live handlers, cargo/runtime execution, and audit signoff"
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
    verdict: ChecklistVerdict,
    counters: &ChecklistCounters,
    blockers: &[ChecklistBlockerKind],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "verdict={} total={} ready={} watch={} deferred={} blocked={} rejected={} wallet_critical={} wallet_blocking={} production_blocking={} cargo_required={} audit_required={} blockers=[{}]",
        verdict.as_str(),
        counters.total_items,
        counters.ready_items,
        counters.watch_items,
        counters.deferred_items,
        counters.blocked_items,
        counters.rejected_items,
        counters.wallet_critical_items,
        counters.wallet_blocking_items,
        counters.production_blocking_items,
        counters.cargo_required_items,
        counters.audit_required_items,
        blocker_labels
    )
}
