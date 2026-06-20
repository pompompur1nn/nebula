use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalRuntimeHarnessFixtureManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RUNTIME_HARNESS_FIXTURE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-runtime-harness-fixture-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RUNTIME_HARNESS_FIXTURE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-runtime-harness-fixture-manifest-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 42_480;
pub const DEFAULT_REQUIRED_VECTOR_COUNT: u64 = 7;
pub const DEFAULT_REQUIRED_PASS_COUNT: u64 = 5;
pub const DEFAULT_REQUIRED_REJECT_COUNT: u64 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalHarnessLane {
    DepositLock,
    PqWatcherAttestation,
    SettlementExit,
    ChallengeRelease,
    PrivateNoteTransfer,
    WalletReconstruction,
    HeavyGateTranscript,
}

impl CanonicalHarnessLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PqWatcherAttestation => "pq_watcher_attestation",
            Self::SettlementExit => "settlement_exit",
            Self::ChallengeRelease => "challenge_release",
            Self::PrivateNoteTransfer => "private_note_transfer",
            Self::WalletReconstruction => "wallet_reconstruction",
            Self::HeavyGateTranscript => "heavy_gate_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExpectedOutcome {
    Pass,
    Reject,
}

impl HarnessExpectedOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredExecutionStatus {
    DeferredUntilCargoRuntime,
    DeferredUntilLiveAdapter,
    DeferredUntilProofBackend,
}

impl DeferredExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeferredUntilCargoRuntime => "deferred_until_cargo_runtime",
            Self::DeferredUntilLiveAdapter => "deferred_until_live_adapter",
            Self::DeferredUntilProofBackend => "deferred_until_proof_backend",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    CargoHarnessBinding,
    LiveSettlementAdapter,
    PqAuthorityQuorum,
    ProofBackend,
    PrivacyReceiptScanner,
    ReleaseGateSignoff,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoHarnessBinding => "cargo_harness_binding",
            Self::LiveSettlementAdapter => "live_settlement_adapter",
            Self::PqAuthorityQuorum => "pq_authority_quorum",
            Self::ProofBackend => "proof_backend",
            Self::PrivacyReceiptScanner => "privacy_receipt_scanner",
            Self::ReleaseGateSignoff => "release_gate_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestReadiness {
    FixturePlanBound,
    ExecutionDeferred,
    ProductionBlocked,
}

impl ManifestReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixturePlanBound => "fixture_plan_bound",
            Self::ExecutionDeferred => "execution_deferred",
            Self::ProductionBlocked => "production_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub manifest_suite: String,
    pub devnet_height: u64,
    pub required_vector_count: u64,
    pub required_pass_count: u64,
    pub required_reject_count: u64,
    pub cargo_execution_deferred: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: MANIFEST_SUITE.to_string(),
            devnet_height: DEFAULT_DEVNET_HEIGHT,
            required_vector_count: DEFAULT_REQUIRED_VECTOR_COUNT,
            required_pass_count: DEFAULT_REQUIRED_PASS_COUNT,
            required_reject_count: DEFAULT_REQUIRED_REJECT_COUNT,
            cargo_execution_deferred: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "devnet_height": self.devnet_height,
            "required_vector_count": self.required_vector_count,
            "required_pass_count": self.required_pass_count,
            "required_reject_count": self.required_reject_count,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalVectorRootRequirement {
    pub vector_id: String,
    pub lane: CanonicalHarnessLane,
    pub canonical_vector_root: String,
    pub fixture_payload_commitment: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub transcript_root: String,
    pub verifier_key_root: String,
    pub requirement_root: String,
}

impl CanonicalVectorRootRequirement {
    pub fn new(
        lane: CanonicalHarnessLane,
        vector_id: &str,
        public_input_label: &str,
        witness_label: &str,
        transcript_label: &str,
        verifier_label: &str,
    ) -> Self {
        let canonical_vector_root = labeled_root("canonical-vector", vector_id);
        let fixture_payload_commitment =
            fixture_payload_commitment(lane, vector_id, &canonical_vector_root);
        let public_input_root = labeled_root("public-input", public_input_label);
        let witness_commitment_root = labeled_root("witness-commitment", witness_label);
        let transcript_root = labeled_root("transcript", transcript_label);
        let verifier_key_root = labeled_root("verifier-key", verifier_label);
        let requirement_root = canonical_requirement_root(
            lane,
            vector_id,
            &canonical_vector_root,
            &fixture_payload_commitment,
            &public_input_root,
            &witness_commitment_root,
            &transcript_root,
            &verifier_key_root,
        );
        Self {
            vector_id: vector_id.to_string(),
            lane,
            canonical_vector_root,
            fixture_payload_commitment,
            public_input_root,
            witness_commitment_root,
            transcript_root,
            verifier_key_root,
            requirement_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vector_id": self.vector_id,
            "lane": self.lane.as_str(),
            "canonical_vector_root": self.canonical_vector_root,
            "fixture_payload_commitment": self.fixture_payload_commitment,
            "public_input_root": self.public_input_root,
            "witness_commitment_root": self.witness_commitment_root,
            "transcript_root": self.transcript_root,
            "verifier_key_root": self.verifier_key_root,
            "requirement_root": self.requirement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HarnessAssertionPlan {
    pub assertion_id: String,
    pub assertion_name: String,
    pub expected_outcome: HarnessExpectedOutcome,
    pub required_log_commitment_root: String,
    pub assertion_root: String,
    pub rejection_reason_root: String,
    pub acceptance_receipt_root: String,
}

impl HarnessAssertionPlan {
    pub fn new(
        assertion_name: &str,
        expected_outcome: HarnessExpectedOutcome,
        log_label: &str,
        rejection_label: &str,
        acceptance_label: &str,
    ) -> Self {
        let required_log_commitment_root = labeled_root("required-log", log_label);
        let rejection_reason_root = labeled_root("rejection-reason", rejection_label);
        let acceptance_receipt_root = labeled_root("acceptance-receipt", acceptance_label);
        let assertion_root = assertion_plan_root(
            assertion_name,
            expected_outcome,
            &required_log_commitment_root,
            &rejection_reason_root,
            &acceptance_receipt_root,
        );
        let assertion_id = assertion_plan_id(assertion_name, &assertion_root);
        Self {
            assertion_id,
            assertion_name: assertion_name.to_string(),
            expected_outcome,
            required_log_commitment_root,
            assertion_root,
            rejection_reason_root,
            acceptance_receipt_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "assertion_id": self.assertion_id,
            "assertion_name": self.assertion_name,
            "expected_outcome": self.expected_outcome.as_str(),
            "required_log_commitment_root": self.required_log_commitment_root,
            "assertion_root": self.assertion_root,
            "rejection_reason_root": self.rejection_reason_root,
            "acceptance_receipt_root": self.acceptance_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeHarnessTestPlan {
    pub test_id: String,
    pub test_name: String,
    pub cargo_filter: String,
    pub lane: CanonicalHarnessLane,
    pub expected_outcome: HarnessExpectedOutcome,
    pub vector_requirement: CanonicalVectorRootRequirement,
    pub assertion_plan: HarnessAssertionPlan,
    pub fixture_payload_commitment: String,
    pub log_commitment_root: String,
    pub assertion_root: String,
    pub public_record_root: String,
    pub deferred_execution_status: DeferredExecutionStatus,
    pub plan_root: String,
}

impl RuntimeHarnessTestPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_name: &str,
        cargo_filter: &str,
        lane: CanonicalHarnessLane,
        expected_outcome: HarnessExpectedOutcome,
        vector_requirement: CanonicalVectorRootRequirement,
        assertion_plan: HarnessAssertionPlan,
        deferred_execution_status: DeferredExecutionStatus,
    ) -> Self {
        let fixture_payload_commitment = vector_requirement.fixture_payload_commitment.clone();
        let log_commitment_root = assertion_plan.required_log_commitment_root.clone();
        let assertion_root = assertion_plan.assertion_root.clone();
        let public_record_root = test_public_record_root(
            test_name,
            cargo_filter,
            lane,
            expected_outcome,
            &vector_requirement.requirement_root,
            &assertion_root,
        );
        let plan_root = runtime_harness_test_plan_root(
            test_name,
            cargo_filter,
            lane,
            expected_outcome,
            &vector_requirement.canonical_vector_root,
            &fixture_payload_commitment,
            &log_commitment_root,
            &assertion_root,
            deferred_execution_status,
            &public_record_root,
        );
        let test_id = runtime_harness_test_plan_id(test_name, &plan_root);
        Self {
            test_id,
            test_name: test_name.to_string(),
            cargo_filter: cargo_filter.to_string(),
            lane,
            expected_outcome,
            vector_requirement,
            assertion_plan,
            fixture_payload_commitment,
            log_commitment_root,
            assertion_root,
            public_record_root,
            deferred_execution_status,
            plan_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "test_id": self.test_id,
            "test_name": self.test_name,
            "cargo_filter": self.cargo_filter,
            "lane": self.lane.as_str(),
            "expected_outcome": self.expected_outcome.as_str(),
            "vector_requirement": self.vector_requirement.public_record(),
            "assertion_plan": self.assertion_plan.public_record(),
            "fixture_payload_commitment": self.fixture_payload_commitment,
            "log_commitment_root": self.log_commitment_root,
            "assertion_root": self.assertion_root,
            "public_record_root": self.public_record_root,
            "deferred_execution_status": self.deferred_execution_status.as_str(),
            "plan_root": self.plan_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionBlocker {
    pub blocker_id: String,
    pub kind: ProductionBlockerKind,
    pub owner: String,
    pub blocker_summary: String,
    pub required_evidence_root: String,
    pub release_gate_root: String,
    pub blocks_public_release: bool,
    pub blocker_root: String,
}

impl ProductionBlocker {
    pub fn new(
        kind: ProductionBlockerKind,
        owner: &str,
        blocker_summary: &str,
        evidence_label: &str,
        blocks_public_release: bool,
    ) -> Self {
        let required_evidence_root = labeled_root("blocker-evidence", evidence_label);
        let release_gate_root = labeled_root("release-gate", blocker_summary);
        let blocker_root = production_blocker_root(
            kind,
            owner,
            blocker_summary,
            &required_evidence_root,
            &release_gate_root,
            blocks_public_release,
        );
        let blocker_id = production_blocker_id(kind, &blocker_root);
        Self {
            blocker_id,
            kind,
            owner: owner.to_string(),
            blocker_summary: blocker_summary.to_string(),
            required_evidence_root,
            release_gate_root,
            blocks_public_release,
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "owner": self.owner,
            "blocker_summary": self.blocker_summary,
            "required_evidence_root": self.required_evidence_root,
            "release_gate_root": self.release_gate_root,
            "blocks_public_release": self.blocks_public_release,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevnetHarnessData {
    pub network_id: String,
    pub chain_id: String,
    pub height: u64,
    pub canonical_tip_root: String,
    pub bridge_contract_root: String,
    pub operator_set_root: String,
    pub pq_verifier_set_root: String,
    pub fixture_namespace_root: String,
}

impl DevnetHarnessData {
    pub fn from_config(config: &Config) -> Self {
        let network_id = "monero-l2-pq-bridge-exit-devnet".to_string();
        let canonical_tip_root = devnet_root("canonical-tip", config.devnet_height);
        let bridge_contract_root = devnet_root("bridge-contract", config.devnet_height);
        let operator_set_root = devnet_root("operator-set", config.devnet_height);
        let pq_verifier_set_root = devnet_root("pq-verifier-set", config.devnet_height);
        let fixture_namespace_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-DEVNET-NAMESPACE",
            &[
                HashPart::Str(&network_id),
                HashPart::Str(&config.chain_id),
                HashPart::U64(config.devnet_height),
                HashPart::Str(&canonical_tip_root),
                HashPart::Str(&bridge_contract_root),
            ],
            32,
        );
        Self {
            network_id,
            chain_id: config.chain_id.clone(),
            height: config.devnet_height,
            canonical_tip_root,
            bridge_contract_root,
            operator_set_root,
            pq_verifier_set_root,
            fixture_namespace_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "height": self.height,
            "canonical_tip_root": self.canonical_tip_root,
            "bridge_contract_root": self.bridge_contract_root,
            "operator_set_root": self.operator_set_root,
            "pq_verifier_set_root": self.pq_verifier_set_root,
            "fixture_namespace_root": self.fixture_namespace_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("devnet_harness_data", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestRoots {
    pub config_root: String,
    pub devnet_root: String,
    pub test_plan_root: String,
    pub vector_requirement_root: String,
    pub log_commitment_root: String,
    pub assertion_root: String,
    pub fixture_payload_commitment_root: String,
    pub production_blocker_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl ManifestRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "devnet_root": self.devnet_root,
            "test_plan_root": self.test_plan_root,
            "vector_requirement_root": self.vector_requirement_root,
            "log_commitment_root": self.log_commitment_root,
            "assertion_root": self.assertion_root,
            "fixture_payload_commitment_root": self.fixture_payload_commitment_root,
            "production_blocker_root": self.production_blocker_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub readiness: ManifestReadiness,
    pub devnet_data: DevnetHarnessData,
    pub tests: BTreeMap<String, RuntimeHarnessTestPlan>,
    pub production_blockers: BTreeMap<String, ProductionBlocker>,
    pub roots: ManifestRoots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let devnet_data = DevnetHarnessData::from_config(&config);
        let tests = canonical_devnet_tests();
        let production_blockers = canonical_production_blockers();
        let readiness = if production_blockers
            .values()
            .any(|blocker| blocker.blocks_public_release)
        {
            ManifestReadiness::ProductionBlocked
        } else if config.cargo_execution_deferred {
            ManifestReadiness::ExecutionDeferred
        } else {
            ManifestReadiness::FixturePlanBound
        };
        let roots = manifest_roots(&config, &devnet_data, &tests, &production_blockers);
        Self {
            config,
            readiness,
            devnet_data,
            tests,
            production_blockers,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        let tests = self
            .tests
            .values()
            .map(RuntimeHarnessTestPlan::public_record)
            .collect::<Vec<_>>();
        let production_blockers = self
            .production_blockers
            .values()
            .map(ProductionBlocker::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "readiness": self.readiness.as_str(),
            "devnet_data": self.devnet_data.public_record(),
            "tests": tests,
            "production_blockers": production_blockers,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn required_test_names(&self) -> Vec<String> {
        self.tests
            .values()
            .map(|test| test.test_name.clone())
            .collect()
    }

    pub fn cargo_filters(&self) -> Vec<String> {
        self.tests
            .values()
            .map(|test| test.cargo_filter.clone())
            .collect()
    }

    pub fn expected_pass_count(&self) -> u64 {
        self.tests
            .values()
            .filter(|test| test.expected_outcome == HarnessExpectedOutcome::Pass)
            .count() as u64
    }

    pub fn expected_reject_count(&self) -> u64 {
        self.tests
            .values()
            .filter(|test| test.expected_outcome == HarnessExpectedOutcome::Reject)
            .count() as u64
    }

    pub fn validate_shape(&self) -> Result<()> {
        ensure(
            self.tests.len() as u64 == self.config.required_vector_count,
            "canonical harness vector count does not match config",
        )?;
        ensure(
            self.expected_pass_count() == self.config.required_pass_count,
            "canonical harness pass count does not match config",
        )?;
        ensure(
            self.expected_reject_count() == self.config.required_reject_count,
            "canonical harness reject count does not match config",
        )?;
        ensure(
            !self.production_blockers.is_empty(),
            "canonical harness production blockers must be recorded",
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

pub fn canonical_devnet_tests() -> BTreeMap<String, RuntimeHarnessTestPlan> {
    let plans = vec![
        RuntimeHarnessTestPlan::new(
            "canonical_deposit_lock_accepts_finalized_monero_lock",
            "bridge_exit::canonical::deposit_lock::accepts_finalized_monero_lock",
            CanonicalHarnessLane::DepositLock,
            HarnessExpectedOutcome::Pass,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::DepositLock,
                "canonical-deposit-lock-finalized-v1",
                "monero-lock-finality-64",
                "deposit-witness-redacted",
                "deposit-lock-transcript",
                "deposit-lock-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "deposit lock canonicalizes finality proof",
                HarnessExpectedOutcome::Pass,
                "deposit-lock-accepted-log",
                "none",
                "deposit-lock-release-receipt",
            ),
            DeferredExecutionStatus::DeferredUntilCargoRuntime,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_deposit_lock_rejects_reorged_lock",
            "bridge_exit::canonical::deposit_lock::rejects_reorged_lock",
            CanonicalHarnessLane::DepositLock,
            HarnessExpectedOutcome::Reject,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::DepositLock,
                "canonical-deposit-lock-reorged-v1",
                "monero-lock-reorg-depth-3",
                "reorg-witness-redacted",
                "deposit-lock-reorg-transcript",
                "deposit-lock-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "deposit lock rejects orphaned evidence",
                HarnessExpectedOutcome::Reject,
                "deposit-lock-rejected-log",
                "orphaned-monero-header-chain",
                "none",
            ),
            DeferredExecutionStatus::DeferredUntilLiveAdapter,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_pq_watcher_attestation_accepts_quorum",
            "bridge_exit::canonical::pq_watcher::accepts_quorum",
            CanonicalHarnessLane::PqWatcherAttestation,
            HarnessExpectedOutcome::Pass,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::PqWatcherAttestation,
                "canonical-pq-watcher-quorum-v1",
                "pq-watcher-threshold-public-input",
                "pq-watcher-signature-witness",
                "pq-attestation-transcript",
                "pq-authority-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "pq watcher quorum binds release claim",
                HarnessExpectedOutcome::Pass,
                "pq-watcher-quorum-log",
                "none",
                "pq-watcher-attestation-receipt",
            ),
            DeferredExecutionStatus::DeferredUntilProofBackend,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_settlement_exit_accepts_bound_receipt",
            "bridge_exit::canonical::settlement_exit::accepts_bound_receipt",
            CanonicalHarnessLane::SettlementExit,
            HarnessExpectedOutcome::Pass,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::SettlementExit,
                "canonical-settlement-exit-bound-receipt-v1",
                "settlement-exit-public-input",
                "settlement-exit-private-witness",
                "settlement-exit-transcript",
                "settlement-exit-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "settlement exit emits bound public receipt",
                HarnessExpectedOutcome::Pass,
                "settlement-exit-accepted-log",
                "none",
                "settlement-exit-public-receipt",
            ),
            DeferredExecutionStatus::DeferredUntilCargoRuntime,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_challenge_release_rejects_late_dispute",
            "bridge_exit::canonical::challenge_release::rejects_late_dispute",
            CanonicalHarnessLane::ChallengeRelease,
            HarnessExpectedOutcome::Reject,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::ChallengeRelease,
                "canonical-challenge-release-late-dispute-v1",
                "challenge-window-expired-public-input",
                "late-dispute-witness",
                "challenge-release-transcript",
                "challenge-release-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "challenge release rejects late dispute",
                HarnessExpectedOutcome::Reject,
                "challenge-release-rejected-log",
                "challenge-window-expired",
                "none",
            ),
            DeferredExecutionStatus::DeferredUntilCargoRuntime,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_private_note_transfer_preserves_receipt_privacy",
            "bridge_exit::canonical::private_note_transfer::preserves_receipt_privacy",
            CanonicalHarnessLane::PrivateNoteTransfer,
            HarnessExpectedOutcome::Pass,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::PrivateNoteTransfer,
                "canonical-private-note-transfer-receipt-v1",
                "private-note-transfer-public-input",
                "private-note-transfer-witness",
                "private-note-transfer-transcript",
                "private-note-transfer-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "private note transfer binds nullifier without link leak",
                HarnessExpectedOutcome::Pass,
                "private-note-transfer-accepted-log",
                "none",
                "private-note-transfer-receipt",
            ),
            DeferredExecutionStatus::DeferredUntilProofBackend,
        ),
        RuntimeHarnessTestPlan::new(
            "canonical_wallet_reconstruction_accepts_view_key_scan",
            "bridge_exit::canonical::wallet_reconstruction::accepts_view_key_scan",
            CanonicalHarnessLane::WalletReconstruction,
            HarnessExpectedOutcome::Pass,
            CanonicalVectorRootRequirement::new(
                CanonicalHarnessLane::WalletReconstruction,
                "canonical-wallet-reconstruction-view-key-scan-v1",
                "wallet-reconstruction-public-input",
                "wallet-view-key-scan-witness",
                "wallet-reconstruction-transcript",
                "wallet-reconstruction-verifier-key",
            ),
            HarnessAssertionPlan::new(
                "wallet reconstruction restores spendable exit note set",
                HarnessExpectedOutcome::Pass,
                "wallet-reconstruction-accepted-log",
                "none",
                "wallet-reconstruction-receipt",
            ),
            DeferredExecutionStatus::DeferredUntilLiveAdapter,
        ),
    ];
    plans
        .into_iter()
        .map(|plan| (plan.test_id.clone(), plan))
        .collect()
}

pub fn canonical_production_blockers() -> BTreeMap<String, ProductionBlocker> {
    let blockers = vec![
        ProductionBlocker::new(
            ProductionBlockerKind::CargoHarnessBinding,
            "runtime-harness",
            "cargo runtime tests are declared as fixture data and await execution binding",
            "cargo-runtime-binding-green-report",
            true,
        ),
        ProductionBlocker::new(
            ProductionBlockerKind::LiveSettlementAdapter,
            "bridge-settlement",
            "live settlement adapter must prove devnet receipt parity",
            "live-settlement-adapter-parity-report",
            true,
        ),
        ProductionBlocker::new(
            ProductionBlockerKind::PqAuthorityQuorum,
            "pq-authority",
            "post-quantum authority quorum requires live key ceremony evidence",
            "pq-authority-quorum-ceremony-report",
            true,
        ),
        ProductionBlocker::new(
            ProductionBlockerKind::ProofBackend,
            "proof-runtime",
            "proof backend must bind canonical vectors to verifier keys",
            "proof-backend-vector-binding-report",
            true,
        ),
        ProductionBlocker::new(
            ProductionBlockerKind::PrivacyReceiptScanner,
            "wallet-runtime",
            "privacy receipt scanner must preserve wallet reconstruction coverage",
            "privacy-receipt-scanner-coverage-report",
            true,
        ),
        ProductionBlocker::new(
            ProductionBlockerKind::ReleaseGateSignoff,
            "release-coordination",
            "release gate signoff waits for canonical harness report roots",
            "release-gate-signoff-evidence-report",
            true,
        ),
    ];
    blockers
        .into_iter()
        .map(|blocker| (blocker.blocker_id.clone(), blocker))
        .collect()
}

pub fn manifest_roots(
    config: &Config,
    devnet_data: &DevnetHarnessData,
    tests: &BTreeMap<String, RuntimeHarnessTestPlan>,
    production_blockers: &BTreeMap<String, ProductionBlocker>,
) -> ManifestRoots {
    let config_root = config.state_root();
    let devnet_root = devnet_data.state_root();
    let test_plan_root = test_plan_merkle_root(tests);
    let vector_requirement_root = vector_requirement_merkle_root(tests);
    let log_commitment_root = log_commitment_merkle_root(tests);
    let assertion_root = assertion_merkle_root(tests);
    let fixture_payload_commitment_root = fixture_payload_commitment_merkle_root(tests);
    let production_blocker_root = production_blocker_merkle_root(production_blockers);
    let public_record_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-PUBLIC-RECORD-ROOT",
        &[
            HashPart::Str(&config_root),
            HashPart::Str(&devnet_root),
            HashPart::Str(&test_plan_root),
            HashPart::Str(&vector_requirement_root),
            HashPart::Str(&log_commitment_root),
            HashPart::Str(&assertion_root),
            HashPart::Str(&fixture_payload_commitment_root),
            HashPart::Str(&production_blocker_root),
        ],
        32,
    );
    let state_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&devnet_root),
            HashPart::Str(&public_record_root),
        ],
        32,
    );
    ManifestRoots {
        config_root,
        devnet_root,
        test_plan_root,
        vector_requirement_root,
        log_commitment_root,
        assertion_root,
        fixture_payload_commitment_root,
        production_blocker_root,
        public_record_root,
        state_root,
    }
}

pub fn test_plan_merkle_root(tests: &BTreeMap<String, RuntimeHarnessTestPlan>) -> String {
    let records = tests
        .values()
        .map(|test| {
            json!({
                "test_id": test.test_id,
                "test_name": test.test_name,
                "cargo_filter": test.cargo_filter,
                "lane": test.lane.as_str(),
                "expected_outcome": test.expected_outcome.as_str(),
                "plan_root": test.plan_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-TEST-PLANS",
        &records,
    )
}

pub fn vector_requirement_merkle_root(tests: &BTreeMap<String, RuntimeHarnessTestPlan>) -> String {
    let records = tests
        .values()
        .map(|test| test.vector_requirement.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-VECTOR-REQUIREMENTS",
        &records,
    )
}

pub fn log_commitment_merkle_root(tests: &BTreeMap<String, RuntimeHarnessTestPlan>) -> String {
    let records = tests
        .values()
        .map(|test| {
            json!({
                "test_id": test.test_id,
                "test_name": test.test_name,
                "log_commitment_root": test.log_commitment_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-LOG-COMMITMENTS",
        &records,
    )
}

pub fn assertion_merkle_root(tests: &BTreeMap<String, RuntimeHarnessTestPlan>) -> String {
    let records = tests
        .values()
        .map(|test| test.assertion_plan.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-ASSERTIONS",
        &records,
    )
}

pub fn fixture_payload_commitment_merkle_root(
    tests: &BTreeMap<String, RuntimeHarnessTestPlan>,
) -> String {
    let records = tests
        .values()
        .map(|test| {
            json!({
                "test_id": test.test_id,
                "lane": test.lane.as_str(),
                "fixture_payload_commitment": test.fixture_payload_commitment,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-FIXTURE-PAYLOADS",
        &records,
    )
}

pub fn production_blocker_merkle_root(blockers: &BTreeMap<String, ProductionBlocker>) -> String {
    let records = blockers
        .values()
        .map(ProductionBlocker::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-PRODUCTION-BLOCKERS",
        &records,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_requirement_root(
    lane: CanonicalHarnessLane,
    vector_id: &str,
    canonical_vector_root: &str,
    fixture_payload_commitment: &str,
    public_input_root: &str,
    witness_commitment_root: &str,
    transcript_root: &str,
    verifier_key_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-REQUIREMENT",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(vector_id),
            HashPart::Str(canonical_vector_root),
            HashPart::Str(fixture_payload_commitment),
            HashPart::Str(public_input_root),
            HashPart::Str(witness_commitment_root),
            HashPart::Str(transcript_root),
            HashPart::Str(verifier_key_root),
        ],
        32,
    )
}

pub fn fixture_payload_commitment(
    lane: CanonicalHarnessLane,
    vector_id: &str,
    canonical_vector_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-FIXTURE-PAYLOAD",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(vector_id),
            HashPart::Str(canonical_vector_root),
        ],
        32,
    )
}

pub fn assertion_plan_root(
    assertion_name: &str,
    expected_outcome: HarnessExpectedOutcome,
    required_log_commitment_root: &str,
    rejection_reason_root: &str,
    acceptance_receipt_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-ASSERTION-PLAN",
        &[
            HashPart::Str(assertion_name),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(required_log_commitment_root),
            HashPart::Str(rejection_reason_root),
            HashPart::Str(acceptance_receipt_root),
        ],
        32,
    )
}

pub fn assertion_plan_id(assertion_name: &str, assertion_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-ASSERTION-ID",
        &[HashPart::Str(assertion_name), HashPart::Str(assertion_root)],
        16,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn test_public_record_root(
    test_name: &str,
    cargo_filter: &str,
    lane: CanonicalHarnessLane,
    expected_outcome: HarnessExpectedOutcome,
    vector_requirement_root: &str,
    assertion_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-TEST-PUBLIC-RECORD",
        &[
            HashPart::Str(test_name),
            HashPart::Str(cargo_filter),
            HashPart::Str(lane.as_str()),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(vector_requirement_root),
            HashPart::Str(assertion_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_harness_test_plan_root(
    test_name: &str,
    cargo_filter: &str,
    lane: CanonicalHarnessLane,
    expected_outcome: HarnessExpectedOutcome,
    canonical_vector_root: &str,
    fixture_payload_commitment: &str,
    log_commitment_root: &str,
    assertion_root: &str,
    deferred_execution_status: DeferredExecutionStatus,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-TEST-PLAN",
        &[
            HashPart::Str(test_name),
            HashPart::Str(cargo_filter),
            HashPart::Str(lane.as_str()),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(canonical_vector_root),
            HashPart::Str(fixture_payload_commitment),
            HashPart::Str(log_commitment_root),
            HashPart::Str(assertion_root),
            HashPart::Str(deferred_execution_status.as_str()),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

pub fn runtime_harness_test_plan_id(test_name: &str, plan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-TEST-ID",
        &[HashPart::Str(test_name), HashPart::Str(plan_root)],
        16,
    )
}

pub fn production_blocker_root(
    kind: ProductionBlockerKind,
    owner: &str,
    blocker_summary: &str,
    required_evidence_root: &str,
    release_gate_root: &str,
    blocks_public_release: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-PRODUCTION-BLOCKER",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner),
            HashPart::Str(blocker_summary),
            HashPart::Str(required_evidence_root),
            HashPart::Str(release_gate_root),
            HashPart::Str(bool_str(blocks_public_release)),
        ],
        32,
    )
}

pub fn production_blocker_id(kind: ProductionBlockerKind, blocker_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-PRODUCTION-BLOCKER-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(blocker_root)],
        16,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn labeled_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-LABELED-ROOT",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

pub fn devnet_root(kind: &str, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HARNESS-DEVNET-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
