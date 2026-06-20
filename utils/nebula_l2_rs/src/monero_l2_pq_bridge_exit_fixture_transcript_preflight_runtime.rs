use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitFixtureTranscriptPreflightRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FIXTURE_TRANSCRIPT_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-fixture-transcript-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FIXTURE_TRANSCRIPT_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PREFLIGHT_SUITE: &str =
    "monero-l2-pq-bridge-exit-get-in-move-private-force-out-preflight-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 731_200;
pub const DEFAULT_MIN_REQUIRED_STAGES: u64 = 11;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStageKind {
    DepositLockEvidence,
    PqWatcherCertificate,
    PrivateNoteMint,
    PrivateTransferReceipt,
    SettlementReceipt,
    ForcedExitClaim,
    ChallengeWindow,
    ReleaseAuthorization,
    WalletRecovery,
    PrivacyBudget,
    CargoRuntimeExecutionDeferral,
}

impl PreflightStageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockEvidence => "deposit_lock_evidence",
            Self::PqWatcherCertificate => "pq_watcher_certificate",
            Self::PrivateNoteMint => "private_note_mint",
            Self::PrivateTransferReceipt => "private_transfer_receipt",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::ChallengeWindow => "challenge_window",
            Self::ReleaseAuthorization => "release_authorization",
            Self::WalletRecovery => "wallet_recovery",
            Self::PrivacyBudget => "privacy_budget",
            Self::CargoRuntimeExecutionDeferral => "cargo_runtime_execution_deferral",
        }
    }

    pub fn all() -> [Self; 11] {
        [
            Self::DepositLockEvidence,
            Self::PqWatcherCertificate,
            Self::PrivateNoteMint,
            Self::PrivateTransferReceipt,
            Self::SettlementReceipt,
            Self::ForcedExitClaim,
            Self::ChallengeWindow,
            Self::ReleaseAuthorization,
            Self::WalletRecovery,
            Self::PrivacyBudget,
            Self::CargoRuntimeExecutionDeferral,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Ready,
    Deferred,
    Blocked,
    Rejected,
}

impl PreflightStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn passes_fixture(self) -> bool {
        matches!(self, Self::Ready | Self::Deferred)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionClass {
    MissingRequiredRoot,
    InconsistentTranscript,
    PrivacyBudgetExceeded,
    ChallengeWindowInvalid,
    ReleaseAuthorityMissing,
    RuntimeExecutionDeferred,
    ProductionBlocked,
}

impl RejectionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRequiredRoot => "missing_required_root",
            Self::InconsistentTranscript => "inconsistent_transcript",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::ChallengeWindowInvalid => "challenge_window_invalid",
            Self::ReleaseAuthorityMissing => "release_authority_missing",
            Self::RuntimeExecutionDeferred => "runtime_execution_deferred",
            Self::ProductionBlocked => "production_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerScope {
    Fixture,
    UserExit,
    Production,
}

impl BlockerScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::UserExit => "user_exit",
            Self::Production => "production",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub preflight_suite: String,
    pub base_height: u64,
    pub min_required_stages: u64,
    pub min_privacy_set_size: u64,
    pub min_challenge_window_blocks: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_execution_deferred: bool,
    pub production_release_allowed: bool,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            preflight_suite: PREFLIGHT_SUITE.to_string(),
            base_height: DEFAULT_DEVNET_HEIGHT,
            min_required_stages: DEFAULT_MIN_REQUIRED_STAGES,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_challenge_window_blocks: DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS,
            cargo_checks_deferred: true,
            runtime_execution_deferred: true,
            production_release_allowed: false,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "preflight_suite": self.preflight_suite,
            "base_height": self.base_height,
            "min_required_stages": self.min_required_stages,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_challenge_window_blocks": self.min_challenge_window_blocks,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequiredRoots {
    pub deposit_lock_root: String,
    pub pq_certificate_root: String,
    pub note_mint_root: String,
    pub private_transfer_receipt_root: String,
    pub settlement_receipt_root: String,
    pub forced_exit_claim_root: String,
    pub challenge_window_root: String,
    pub release_authorization_root: String,
    pub wallet_recovery_root: String,
    pub privacy_budget_root: String,
    pub cargo_runtime_deferral_root: String,
}

impl RequiredRoots {
    pub fn devnet(transcript_id: &str) -> Self {
        Self {
            deposit_lock_root: label_root("deposit_lock", transcript_id),
            pq_certificate_root: label_root("pq_watcher_certificate", transcript_id),
            note_mint_root: label_root("private_note_mint", transcript_id),
            private_transfer_receipt_root: label_root("private_transfer_receipt", transcript_id),
            settlement_receipt_root: label_root("settlement_receipt", transcript_id),
            forced_exit_claim_root: label_root("forced_exit_claim", transcript_id),
            challenge_window_root: label_root("challenge_window", transcript_id),
            release_authorization_root: label_root("release_authorization", transcript_id),
            wallet_recovery_root: label_root("wallet_recovery", transcript_id),
            privacy_budget_root: label_root("privacy_budget", transcript_id),
            cargo_runtime_deferral_root: label_root("cargo_runtime_deferral", transcript_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deposit_lock_root": self.deposit_lock_root,
            "pq_certificate_root": self.pq_certificate_root,
            "note_mint_root": self.note_mint_root,
            "private_transfer_receipt_root": self.private_transfer_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "challenge_window_root": self.challenge_window_root,
            "release_authorization_root": self.release_authorization_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "privacy_budget_root": self.privacy_budget_root,
            "cargo_runtime_deferral_root": self.cargo_runtime_deferral_root,
        })
    }

    pub fn root_for(&self, kind: PreflightStageKind) -> &str {
        match kind {
            PreflightStageKind::DepositLockEvidence => &self.deposit_lock_root,
            PreflightStageKind::PqWatcherCertificate => &self.pq_certificate_root,
            PreflightStageKind::PrivateNoteMint => &self.note_mint_root,
            PreflightStageKind::PrivateTransferReceipt => &self.private_transfer_receipt_root,
            PreflightStageKind::SettlementReceipt => &self.settlement_receipt_root,
            PreflightStageKind::ForcedExitClaim => &self.forced_exit_claim_root,
            PreflightStageKind::ChallengeWindow => &self.challenge_window_root,
            PreflightStageKind::ReleaseAuthorization => &self.release_authorization_root,
            PreflightStageKind::WalletRecovery => &self.wallet_recovery_root,
            PreflightStageKind::PrivacyBudget => &self.privacy_budget_root,
            PreflightStageKind::CargoRuntimeExecutionDeferral => &self.cargo_runtime_deferral_root,
        }
    }

    pub fn state_root(&self) -> String {
        record_root("required_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightTranscriptRequest {
    pub transcript_id: String,
    pub route_id: String,
    pub account_commitment: String,
    pub deposit_amount_commitment: String,
    pub required_roots: RequiredRoots,
    pub privacy_set_size: u64,
    pub privacy_budget_units: u64,
    pub privacy_budget_limit: u64,
    pub challenge_window_blocks: u64,
    pub deposit_height: u64,
    pub settlement_height: u64,
    pub release_height: u64,
    pub cargo_command_root: String,
    pub runtime_invocation_root: String,
}

impl PreflightTranscriptRequest {
    pub fn devnet(config: &Config) -> Self {
        let transcript_id = "devnet-get-in-move-private-force-out-preflight-0001".to_string();
        let route_id = "monero-private-l2-forced-exit-route-devnet".to_string();
        Self {
            transcript_id: transcript_id.clone(),
            route_id,
            account_commitment: label_root("account_commitment", "devnet-wallet-account"),
            deposit_amount_commitment: label_root("amount_commitment", "devnet-xmr-lock"),
            required_roots: RequiredRoots::devnet(&transcript_id),
            privacy_set_size: config.min_privacy_set_size,
            privacy_budget_units: 8,
            privacy_budget_limit: 16,
            challenge_window_blocks: config.min_challenge_window_blocks,
            deposit_height: config.base_height,
            settlement_height: config.base_height + config.min_challenge_window_blocks + 4,
            release_height: config.base_height + config.min_challenge_window_blocks + 12,
            cargo_command_root: label_root("cargo_command", "cargo-check-deferred"),
            runtime_invocation_root: label_root("runtime_invocation", "runtime-tests-deferred"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "route_id": self.route_id,
            "account_commitment": self.account_commitment,
            "deposit_amount_commitment": self.deposit_amount_commitment,
            "required_roots": self.required_roots.public_record(),
            "privacy_set_size": self.privacy_set_size,
            "privacy_budget_units": self.privacy_budget_units,
            "privacy_budget_limit": self.privacy_budget_limit,
            "challenge_window_blocks": self.challenge_window_blocks,
            "deposit_height": self.deposit_height,
            "settlement_height": self.settlement_height,
            "release_height": self.release_height,
            "cargo_command_root": self.cargo_command_root,
            "runtime_invocation_root": self.runtime_invocation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight_request", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightStage {
    pub stage_id: String,
    pub transcript_id: String,
    pub sequence: u64,
    pub kind: PreflightStageKind,
    pub status: PreflightStatus,
    pub required_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub public_surface_root: String,
    pub state_surface_root: String,
    pub requirement: String,
    pub observed: String,
}

impl PreflightStage {
    pub fn new(
        request: &PreflightTranscriptRequest,
        sequence: u64,
        kind: PreflightStageKind,
        status: PreflightStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
    ) -> Self {
        let required_root = request.required_roots.root_for(kind).to_string();
        let requirement = requirement.into();
        let observed = observed.into();
        let observed_root = stage_observed_root(&request.transcript_id, kind, &observed);
        let evidence_root = stage_evidence_root(
            &request.transcript_id,
            kind,
            &required_root,
            &observed_root,
            status,
        );
        let public_surface_root = public_surface_root(&request.transcript_id, kind, &evidence_root);
        let state_surface_root = state_surface_root(&request.transcript_id, kind, &evidence_root);
        let stage_id = preflight_stage_id(&request.transcript_id, sequence, kind, &evidence_root);
        Self {
            stage_id,
            transcript_id: request.transcript_id.clone(),
            sequence,
            kind,
            status,
            required_root,
            observed_root,
            evidence_root,
            public_surface_root,
            state_surface_root,
            requirement,
            observed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "stage_id": self.stage_id,
            "transcript_id": self.transcript_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "required_root": self.required_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "public_surface_root": self.public_surface_root,
            "state_surface_root": self.state_surface_root,
            "requirement": self.requirement,
            "observed": self.observed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight_stage", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightBlocker {
    pub blocker_id: String,
    pub transcript_id: String,
    pub stage_kind: PreflightStageKind,
    pub rejection_class: RejectionClass,
    pub scope: BlockerScope,
    pub blocks_fixture: bool,
    pub blocks_user_exit: bool,
    pub blocks_production: bool,
    pub evidence_root: String,
    pub message: String,
    pub remediation: String,
}

impl PreflightBlocker {
    pub fn new(
        transcript_id: &str,
        stage_kind: PreflightStageKind,
        rejection_class: RejectionClass,
        scope: BlockerScope,
        evidence_root: impl Into<String>,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let evidence_root = evidence_root.into();
        let message = message.into();
        let remediation = remediation.into();
        let blocks_fixture = matches!(scope, BlockerScope::Fixture);
        let blocks_user_exit = matches!(scope, BlockerScope::UserExit);
        let blocks_production = matches!(scope, BlockerScope::Production);
        let blocker_id = preflight_blocker_id(
            transcript_id,
            stage_kind,
            rejection_class,
            scope,
            &evidence_root,
        );
        Self {
            blocker_id,
            transcript_id: transcript_id.to_string(),
            stage_kind,
            rejection_class,
            scope,
            blocks_fixture,
            blocks_user_exit,
            blocks_production,
            evidence_root,
            message,
            remediation,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "transcript_id": self.transcript_id,
            "stage_kind": self.stage_kind.as_str(),
            "rejection_class": self.rejection_class.as_str(),
            "scope": self.scope.as_str(),
            "blocks_fixture": self.blocks_fixture,
            "blocks_user_exit": self.blocks_user_exit,
            "blocks_production": self.blocks_production,
            "evidence_root": self.evidence_root,
            "message": self.message,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightTranscript {
    pub transcript_id: String,
    pub route_id: String,
    pub status: PreflightStatus,
    pub request_root: String,
    pub required_root: String,
    pub stage_root: String,
    pub blocker_root: String,
    pub public_surface_root: String,
    pub state_surface_root: String,
    pub ready_stages: u64,
    pub deferred_stages: u64,
    pub blocked_stages: u64,
    pub rejected_stages: u64,
    pub fixture_blockers: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
    pub stages: BTreeMap<String, PreflightStage>,
    pub blockers: BTreeMap<String, PreflightBlocker>,
    pub transcript_root: String,
}

impl PreflightTranscript {
    pub fn public_record(&self) -> Value {
        let stages = self
            .stages
            .values()
            .map(PreflightStage::public_record)
            .collect::<Vec<_>>();
        let blockers = self
            .blockers
            .values()
            .map(PreflightBlocker::public_record)
            .collect::<Vec<_>>();
        json!({
            "transcript_id": self.transcript_id,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "request_root": self.request_root,
            "required_root": self.required_root,
            "stage_root": self.stage_root,
            "blocker_root": self.blocker_root,
            "public_surface_root": self.public_surface_root,
            "state_surface_root": self.state_surface_root,
            "ready_stages": self.ready_stages,
            "deferred_stages": self.deferred_stages,
            "blocked_stages": self.blocked_stages,
            "rejected_stages": self.rejected_stages,
            "fixture_blockers": self.fixture_blockers,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
            "stages": stages,
            "blockers": blockers,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.transcript_root.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub transcripts_recorded: u64,
    pub transcripts_ready: u64,
    pub transcripts_deferred: u64,
    pub transcripts_blocked: u64,
    pub transcripts_rejected: u64,
    pub stages_recorded: u64,
    pub stages_ready: u64,
    pub stages_deferred: u64,
    pub stages_blocked: u64,
    pub stages_rejected: u64,
    pub fixture_blockers: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "transcripts_recorded": self.transcripts_recorded,
            "transcripts_ready": self.transcripts_ready,
            "transcripts_deferred": self.transcripts_deferred,
            "transcripts_blocked": self.transcripts_blocked,
            "transcripts_rejected": self.transcripts_rejected,
            "stages_recorded": self.stages_recorded,
            "stages_ready": self.stages_ready,
            "stages_deferred": self.stages_deferred,
            "stages_blocked": self.stages_blocked,
            "stages_rejected": self.stages_rejected,
            "fixture_blockers": self.fixture_blockers,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub transcript_root: String,
    pub stage_root: String,
    pub blocker_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            transcript_root: empty_root("preflight_transcripts"),
            stage_root: empty_root("preflight_stages"),
            blocker_root: empty_root("preflight_blockers"),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "transcript_root": self.transcript_root,
            "stage_root": self.stage_root,
            "blocker_root": self.blocker_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.stage_root),
                HashPart::Str(&self.blocker_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_transcript: Option<PreflightTranscript>,
    pub transcripts: BTreeMap<String, PreflightTranscript>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_transcript: None,
            transcripts: BTreeMap::new(),
            counters,
            roots,
        };
        let request = PreflightTranscriptRequest::devnet(&state.config);
        state
            .record_preflight(request)
            .expect("devnet bridge/exit fixture transcript preflight");
        state
    }

    pub fn record_preflight(&mut self, request: PreflightTranscriptRequest) -> Result<String> {
        self.validate_request(&request)?;
        if self.transcripts.contains_key(&request.transcript_id) {
            return Err(format!(
                "preflight transcript {} already recorded",
                request.transcript_id
            ));
        }
        let stages = build_stages(&self.config, &request);
        ensure_required_stage_coverage(&stages)?;
        let blockers = build_blockers(&self.config, &request, &stages);
        let transcript = assemble_transcript(&self.config, request, stages, blockers);
        let transcript_id = transcript.transcript_id.clone();
        self.record_transcript(transcript);
        Ok(transcript_id)
    }

    pub fn validate_request(&self, request: &PreflightTranscriptRequest) -> Result<()> {
        if request.transcript_id.is_empty() {
            return Err("transcript_id is required".to_string());
        }
        if request.route_id.is_empty() {
            return Err("route_id is required".to_string());
        }
        if request.account_commitment.is_empty() {
            return Err("account commitment root is required".to_string());
        }
        if request.deposit_amount_commitment.is_empty() {
            return Err("deposit amount commitment root is required".to_string());
        }
        if missing_required_roots(&request.required_roots).len() > 0 {
            return Err("one or more required preflight roots are missing".to_string());
        }
        if request.settlement_height < request.deposit_height {
            return Err("settlement height cannot precede deposit height".to_string());
        }
        if request.release_height < request.settlement_height {
            return Err("release height cannot precede settlement height".to_string());
        }
        Ok(())
    }

    fn record_transcript(&mut self, transcript: PreflightTranscript) {
        self.counters.transcripts_recorded += 1;
        self.counters.stages_recorded += transcript.stages.len() as u64;
        self.counters.stages_ready += transcript.ready_stages;
        self.counters.stages_deferred += transcript.deferred_stages;
        self.counters.stages_blocked += transcript.blocked_stages;
        self.counters.stages_rejected += transcript.rejected_stages;
        self.counters.fixture_blockers += transcript.fixture_blockers;
        self.counters.user_exit_blockers += transcript.user_exit_blockers;
        self.counters.production_blockers += transcript.production_blockers;
        match transcript.status {
            PreflightStatus::Ready => self.counters.transcripts_ready += 1,
            PreflightStatus::Deferred => self.counters.transcripts_deferred += 1,
            PreflightStatus::Blocked => self.counters.transcripts_blocked += 1,
            PreflightStatus::Rejected => self.counters.transcripts_rejected += 1,
        }
        self.latest_transcript = Some(transcript.clone());
        self.transcripts
            .insert(transcript.transcript_id.clone(), transcript);
        self.prune_to_limit();
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let transcript_records = self
            .transcripts
            .values()
            .map(PreflightTranscript::public_record)
            .collect::<Vec<_>>();
        let stage_records = self
            .transcripts
            .values()
            .flat_map(|transcript| {
                transcript
                    .stages
                    .values()
                    .map(PreflightStage::public_record)
            })
            .collect::<Vec<_>>();
        let blocker_records = self
            .transcripts
            .values()
            .flat_map(|transcript| {
                transcript
                    .blockers
                    .values()
                    .map(PreflightBlocker::public_record)
            })
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            transcript_root: map_root("preflight_transcripts", transcript_records),
            stage_root: map_root("preflight_stages", stage_records),
            blocker_root: map_root("preflight_blockers", blocker_records),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    fn prune_to_limit(&mut self) {
        while self.transcripts.len() > self.config.max_public_records {
            if let Some(oldest) = self.transcripts.keys().next().cloned() {
                self.transcripts.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "preflight_suite": self.config.preflight_suite,
            "latest_transcript": self.latest_transcript.as_ref().map(PreflightTranscript::public_record),
            "transcript_count": self.transcripts.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn production_release_allowed(&self) -> bool {
        self.config.production_release_allowed
            && !self.config.cargo_checks_deferred
            && !self.config.runtime_execution_deferred
            && self
                .latest_transcript
                .as_ref()
                .map(|transcript| transcript.production_blockers == 0)
                .unwrap_or(false)
    }
}

fn build_stages(
    config: &Config,
    request: &PreflightTranscriptRequest,
) -> BTreeMap<String, PreflightStage> {
    let mut stages = BTreeMap::new();
    for (sequence, stage) in [
        deposit_lock_stage(request),
        pq_watcher_stage(request),
        note_mint_stage(request),
        private_transfer_stage(request),
        settlement_stage(request),
        forced_exit_stage(request),
        challenge_window_stage(config, request),
        release_authorization_stage(config, request),
        wallet_recovery_stage(request),
        privacy_budget_stage(config, request),
        cargo_runtime_deferral_stage(config, request),
    ]
    .into_iter()
    .enumerate()
    {
        let mut stage = stage;
        stage.sequence = sequence as u64;
        stage.stage_id = preflight_stage_id(
            &stage.transcript_id,
            stage.sequence,
            stage.kind,
            &stage.evidence_root,
        );
        stages.insert(stage.kind.as_str().to_string(), stage);
    }
    stages
}

fn deposit_lock_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        0,
        PreflightStageKind::DepositLockEvidence,
        PreflightStatus::Ready,
        "deposit lock evidence must bind Monero lock root, amount commitment, and account commitment",
        format!(
            "deposit_root={} amount_commitment={} account_commitment={}",
            request.required_roots.deposit_lock_root,
            request.deposit_amount_commitment,
            request.account_commitment
        ),
    )
}

fn pq_watcher_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        1,
        PreflightStageKind::PqWatcherCertificate,
        PreflightStatus::Ready,
        "PQ watcher certificate must bind signer epoch, watched deposit root, and route id",
        format!(
            "pq_certificate_root={} deposit_root={} route_id={}",
            request.required_roots.pq_certificate_root,
            request.required_roots.deposit_lock_root,
            request.route_id
        ),
    )
}

fn note_mint_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        2,
        PreflightStageKind::PrivateNoteMint,
        PreflightStatus::Ready,
        "private note mint must consume deposit certificate and publish only note commitment roots",
        format!(
            "note_mint_root={} pq_certificate_root={}",
            request.required_roots.note_mint_root, request.required_roots.pq_certificate_root
        ),
    )
}

fn private_transfer_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        3,
        PreflightStageKind::PrivateTransferReceipt,
        PreflightStatus::Ready,
        "private transfer receipt must bind nullifier, output, encrypted receipt, and recovery roots",
        format!(
            "receipt_root={} wallet_recovery_root={}",
            request.required_roots.private_transfer_receipt_root,
            request.required_roots.wallet_recovery_root
        ),
    )
}

fn settlement_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        4,
        PreflightStageKind::SettlementReceipt,
        PreflightStatus::Ready,
        "settlement receipt must anchor transfer receipt and forced-exit claim surfaces",
        format!(
            "settlement_root={} transfer_receipt_root={} settlement_height={}",
            request.required_roots.settlement_receipt_root,
            request.required_roots.private_transfer_receipt_root,
            request.settlement_height
        ),
    )
}

fn forced_exit_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        5,
        PreflightStageKind::ForcedExitClaim,
        PreflightStatus::Ready,
        "forced-exit claim must prove user can exit after private movement without plaintext leakage",
        format!(
            "claim_root={} settlement_root={}",
            request.required_roots.forced_exit_claim_root,
            request.required_roots.settlement_receipt_root
        ),
    )
}

fn challenge_window_stage(config: &Config, request: &PreflightTranscriptRequest) -> PreflightStage {
    let status = if request.challenge_window_blocks >= config.min_challenge_window_blocks {
        PreflightStatus::Ready
    } else {
        PreflightStatus::Blocked
    };
    PreflightStage::new(
        request,
        6,
        PreflightStageKind::ChallengeWindow,
        status,
        "challenge window must remain open long enough for watcher dispute and user recovery",
        format!(
            "challenge_window_root={} observed_blocks={} min_blocks={}",
            request.required_roots.challenge_window_root,
            request.challenge_window_blocks,
            config.min_challenge_window_blocks
        ),
    )
}

fn release_authorization_stage(
    config: &Config,
    request: &PreflightTranscriptRequest,
) -> PreflightStage {
    let status = if config.production_release_allowed {
        PreflightStatus::Ready
    } else {
        PreflightStatus::Deferred
    };
    PreflightStage::new(
        request,
        7,
        PreflightStageKind::ReleaseAuthorization,
        status,
        "release authorization must stay deferred until production release is explicitly enabled",
        format!(
            "release_authorization_root={} release_height={} production_release_allowed={}",
            request.required_roots.release_authorization_root,
            request.release_height,
            bool_str(config.production_release_allowed)
        ),
    )
}

fn wallet_recovery_stage(request: &PreflightTranscriptRequest) -> PreflightStage {
    PreflightStage::new(
        request,
        8,
        PreflightStageKind::WalletRecovery,
        PreflightStatus::Ready,
        "wallet recovery must bind scan hints, forced-exit locator, and recovery ciphertext roots",
        format!(
            "wallet_recovery_root={} release_height={}",
            request.required_roots.wallet_recovery_root, request.release_height
        ),
    )
}

fn privacy_budget_stage(config: &Config, request: &PreflightTranscriptRequest) -> PreflightStage {
    let status = if request.privacy_set_size >= config.min_privacy_set_size
        && request.privacy_budget_units <= request.privacy_budget_limit
    {
        PreflightStatus::Ready
    } else {
        PreflightStatus::Rejected
    };
    PreflightStage::new(
        request,
        9,
        PreflightStageKind::PrivacyBudget,
        status,
        "privacy budget must keep public transcript to roots and meet minimum anonymity set",
        format!(
            "privacy_budget_root={} privacy_set_size={} min_privacy_set_size={} budget_units={} budget_limit={}",
            request.required_roots.privacy_budget_root,
            request.privacy_set_size,
            config.min_privacy_set_size,
            request.privacy_budget_units,
            request.privacy_budget_limit
        ),
    )
}

fn cargo_runtime_deferral_stage(
    config: &Config,
    request: &PreflightTranscriptRequest,
) -> PreflightStage {
    let status = if config.cargo_checks_deferred || config.runtime_execution_deferred {
        PreflightStatus::Deferred
    } else {
        PreflightStatus::Ready
    };
    PreflightStage::new(
        request,
        10,
        PreflightStageKind::CargoRuntimeExecutionDeferral,
        status,
        "cargo and runtime execution are explicit release blockers while deferred",
        format!(
            "cargo_deferral_root={} cargo_deferred={} runtime_deferred={} cargo_command_root={} runtime_invocation_root={}",
            request.required_roots.cargo_runtime_deferral_root,
            bool_str(config.cargo_checks_deferred),
            bool_str(config.runtime_execution_deferred),
            request.cargo_command_root,
            request.runtime_invocation_root
        ),
    )
}

fn build_blockers(
    config: &Config,
    request: &PreflightTranscriptRequest,
    stages: &BTreeMap<String, PreflightStage>,
) -> BTreeMap<String, PreflightBlocker> {
    let mut blockers = BTreeMap::new();
    for root_name in missing_required_roots(&request.required_roots) {
        let blocker = PreflightBlocker::new(
            &request.transcript_id,
            PreflightStageKind::DepositLockEvidence,
            RejectionClass::MissingRequiredRoot,
            BlockerScope::Fixture,
            label_root("missing_required_root", root_name),
            format!("required root {} is missing", root_name),
            "rebuild fixture transcript request with every required root populated",
        );
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    for stage in stages.values() {
        if stage.status == PreflightStatus::Blocked || stage.status == PreflightStatus::Rejected {
            let rejection_class = match stage.kind {
                PreflightStageKind::ChallengeWindow => RejectionClass::ChallengeWindowInvalid,
                PreflightStageKind::ReleaseAuthorization => RejectionClass::ReleaseAuthorityMissing,
                PreflightStageKind::PrivacyBudget => RejectionClass::PrivacyBudgetExceeded,
                _ => RejectionClass::InconsistentTranscript,
            };
            let scope = if stage.status == PreflightStatus::Rejected {
                BlockerScope::Fixture
            } else {
                BlockerScope::UserExit
            };
            let blocker = PreflightBlocker::new(
                &request.transcript_id,
                stage.kind,
                rejection_class,
                scope,
                stage.evidence_root.clone(),
                format!("stage {} is {}", stage.kind.as_str(), stage.status.as_str()),
                "repair the stage evidence before using the transcript for bridge/exit proofs",
            );
            blockers.insert(blocker.blocker_id.clone(), blocker);
        }
    }
    if config.cargo_checks_deferred || config.runtime_execution_deferred {
        let blocker = PreflightBlocker::new(
            &request.transcript_id,
            PreflightStageKind::CargoRuntimeExecutionDeferral,
            RejectionClass::RuntimeExecutionDeferred,
            BlockerScope::Production,
            request.required_roots.cargo_runtime_deferral_root.clone(),
            "cargo check, runtime execution, or both are intentionally deferred",
            "materialize the fixture as executable cargo/runtime coverage and clear the deferral flags",
        );
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    if !config.production_release_allowed {
        let blocker = PreflightBlocker::new(
            &request.transcript_id,
            PreflightStageKind::ReleaseAuthorization,
            RejectionClass::ProductionBlocked,
            BlockerScope::Production,
            request.required_roots.release_authorization_root.clone(),
            "production release is explicitly disabled for this preflight runtime",
            "flip production release only after live adapters, cargo/runtime execution, and audit signoff are complete",
        );
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    blockers
}

fn assemble_transcript(
    config: &Config,
    request: PreflightTranscriptRequest,
    stages: BTreeMap<String, PreflightStage>,
    blockers: BTreeMap<String, PreflightBlocker>,
) -> PreflightTranscript {
    let ready_stages = count_stages(&stages, PreflightStatus::Ready);
    let deferred_stages = count_stages(&stages, PreflightStatus::Deferred);
    let blocked_stages = count_stages(&stages, PreflightStatus::Blocked);
    let rejected_stages = count_stages(&stages, PreflightStatus::Rejected);
    let fixture_blockers = blockers
        .values()
        .filter(|blocker| blocker.blocks_fixture)
        .count() as u64;
    let user_exit_blockers = blockers
        .values()
        .filter(|blocker| blocker.blocks_user_exit)
        .count() as u64;
    let production_blockers = blockers
        .values()
        .filter(|blocker| blocker.blocks_production)
        .count() as u64;
    let status = transcript_status(
        fixture_blockers,
        user_exit_blockers,
        production_blockers,
        rejected_stages,
        blocked_stages,
        deferred_stages,
    );
    let stage_records = stages
        .values()
        .map(PreflightStage::public_record)
        .collect::<Vec<_>>();
    let blocker_records = blockers
        .values()
        .map(PreflightBlocker::public_record)
        .collect::<Vec<_>>();
    let public_surface_records = stages
        .values()
        .map(|stage| {
            json!({
                "stage": stage.kind.as_str(),
                "public_surface_root": stage.public_surface_root,
                "status": stage.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let state_surface_records = stages
        .values()
        .map(|stage| {
            json!({
                "stage": stage.kind.as_str(),
                "state_surface_root": stage.state_surface_root,
                "status": stage.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let request_root = request.state_root();
    let required_root = request.required_roots.state_root();
    let stage_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STAGES",
        &stage_records,
    );
    let blocker_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-BLOCKERS",
        &blocker_records,
    );
    let public_surface_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-PUBLIC-SURFACES",
        &public_surface_records,
    );
    let state_surface_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STATE-SURFACES",
        &state_surface_records,
    );
    let transcript_root = preflight_transcript_root(
        config,
        &request.transcript_id,
        status,
        &request_root,
        &required_root,
        &stage_root,
        &blocker_root,
        &public_surface_root,
        &state_surface_root,
    );
    PreflightTranscript {
        transcript_id: request.transcript_id,
        route_id: request.route_id,
        status,
        request_root,
        required_root,
        stage_root,
        blocker_root,
        public_surface_root,
        state_surface_root,
        ready_stages,
        deferred_stages,
        blocked_stages,
        rejected_stages,
        fixture_blockers,
        user_exit_blockers,
        production_blockers,
        stages,
        blockers,
        transcript_root,
    }
}

fn transcript_status(
    fixture_blockers: u64,
    user_exit_blockers: u64,
    production_blockers: u64,
    rejected_stages: u64,
    blocked_stages: u64,
    deferred_stages: u64,
) -> PreflightStatus {
    if fixture_blockers > 0 || rejected_stages > 0 {
        PreflightStatus::Rejected
    } else if user_exit_blockers > 0 || blocked_stages > 0 {
        PreflightStatus::Blocked
    } else if production_blockers > 0 || deferred_stages > 0 {
        PreflightStatus::Deferred
    } else {
        PreflightStatus::Ready
    }
}

fn count_stages(stages: &BTreeMap<String, PreflightStage>, status: PreflightStatus) -> u64 {
    stages
        .values()
        .filter(|stage| stage.status == status)
        .count() as u64
}

fn ensure_required_stage_coverage(stages: &BTreeMap<String, PreflightStage>) -> Result<()> {
    let observed = stages
        .values()
        .map(|stage| stage.kind)
        .collect::<BTreeSet<_>>();
    let missing = PreflightStageKind::all()
        .into_iter()
        .filter(|kind| !observed.contains(kind))
        .map(PreflightStageKind::as_str)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "preflight omitted required stage coverage: {}",
            missing.join(",")
        ))
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn preflight_stage_id(
    transcript_id: &str,
    sequence: u64,
    kind: PreflightStageKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STAGE-ID",
        &[
            HashPart::Str(transcript_id),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn preflight_blocker_id(
    transcript_id: &str,
    kind: PreflightStageKind,
    rejection_class: RejectionClass,
    scope: BlockerScope,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-BLOCKER-ID",
        &[
            HashPart::Str(transcript_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(rejection_class.as_str()),
            HashPart::Str(scope.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn stage_observed_root(
    transcript_id: &str,
    kind: PreflightStageKind,
    observed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STAGE-OBSERVED",
        &[
            HashPart::Str(transcript_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(observed),
        ],
        32,
    )
}

pub fn stage_evidence_root(
    transcript_id: &str,
    kind: PreflightStageKind,
    required_root: &str,
    observed_root: &str,
    status: PreflightStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STAGE-EVIDENCE",
        &[
            HashPart::Str(transcript_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(required_root),
            HashPart::Str(observed_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

pub fn public_surface_root(
    transcript_id: &str,
    kind: PreflightStageKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-PUBLIC-SURFACE",
        &[
            HashPart::Str(transcript_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn state_surface_root(
    transcript_id: &str,
    kind: PreflightStageKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-STATE-SURFACE",
        &[
            HashPart::Str(transcript_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn preflight_transcript_root(
    config: &Config,
    transcript_id: &str,
    status: PreflightStatus,
    request_root: &str,
    required_root: &str,
    stage_root: &str,
    blocker_root: &str,
    public_surface_root: &str,
    state_surface_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-TRANSCRIPT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&config.protocol_version),
            HashPart::Str(transcript_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(request_root),
            HashPart::Str(required_root),
            HashPart::Str(stage_root),
            HashPart::Str(blocker_root),
            HashPart::Str(public_surface_root),
            HashPart::Str(state_surface_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-{}",
            domain
        ),
        &records,
    )
}

pub fn empty_root(domain: &str) -> String {
    map_root(domain, Vec::new())
}

pub fn label_root(domain: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-TRANSCRIPT-PREFLIGHT-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn missing_required_roots(roots: &RequiredRoots) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if roots.deposit_lock_root.is_empty() {
        missing.push("deposit_lock_root");
    }
    if roots.pq_certificate_root.is_empty() {
        missing.push("pq_certificate_root");
    }
    if roots.note_mint_root.is_empty() {
        missing.push("note_mint_root");
    }
    if roots.private_transfer_receipt_root.is_empty() {
        missing.push("private_transfer_receipt_root");
    }
    if roots.settlement_receipt_root.is_empty() {
        missing.push("settlement_receipt_root");
    }
    if roots.forced_exit_claim_root.is_empty() {
        missing.push("forced_exit_claim_root");
    }
    if roots.challenge_window_root.is_empty() {
        missing.push("challenge_window_root");
    }
    if roots.release_authorization_root.is_empty() {
        missing.push("release_authorization_root");
    }
    if roots.wallet_recovery_root.is_empty() {
        missing.push("wallet_recovery_root");
    }
    if roots.privacy_budget_root.is_empty() {
        missing.push("privacy_budget_root");
    }
    if roots.cargo_runtime_deferral_root.is_empty() {
        missing.push("cargo_runtime_deferral_root");
    }
    missing
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
