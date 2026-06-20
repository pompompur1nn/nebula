use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalTranscriptStaticVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_TRANSCRIPT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-transcript-static-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_TRANSCRIPT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VERIFIER_SUITE: &str = "canonical-get-in-move-private-force-out-static-verifier-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_FORCE_OUT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_TRANSCRIPTS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalStage {
    GetIn,
    MovePrivate,
    ForceOut,
}

impl CanonicalStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GetIn => "get_in",
            Self::MovePrivate => "move_private",
            Self::ForceOut => "force_out",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::GetIn => 0,
            Self::MovePrivate => 1,
            Self::ForceOut => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheckKind {
    StageOrdering,
    VectorRootContinuity,
    RootSeparation,
    WalletReconstructionContinuity,
    PqWatcherLinkage,
    MoneroNoBaseLayerVerifierBlocked,
    FeePrivacyThresholds,
    ProductionBlockers,
    PublicRecordStateRoot,
    DevnetDataRoot,
}

impl StaticCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StageOrdering => "stage_ordering",
            Self::VectorRootContinuity => "vector_root_continuity",
            Self::RootSeparation => "public_committed_encrypted_root_separation",
            Self::WalletReconstructionContinuity => "wallet_reconstruction_continuity",
            Self::PqWatcherLinkage => "pq_watcher_linkage",
            Self::MoneroNoBaseLayerVerifierBlocked => "monero_no_base_layer_verifier_blocked",
            Self::FeePrivacyThresholds => "fee_privacy_thresholds",
            Self::ProductionBlockers => "production_blockers",
            Self::PublicRecordStateRoot => "public_record_state_root",
            Self::DevnetDataRoot => "devnet_data_root",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::StageOrdering,
            Self::VectorRootContinuity,
            Self::RootSeparation,
            Self::WalletReconstructionContinuity,
            Self::PqWatcherLinkage,
            Self::MoneroNoBaseLayerVerifierBlocked,
            Self::FeePrivacyThresholds,
            Self::ProductionBlockers,
            Self::PublicRecordStateRoot,
            Self::DevnetDataRoot,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Watch,
    Failed,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlocker {
    MoneroBaseLayerCannotVerifyPqProofs,
    DevnetFixtureOnly,
    ReleaseGuardDisabled,
}

impl ProductionBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBaseLayerCannotVerifyPqProofs => {
                "monero_base_layer_cannot_verify_pq_proofs"
            }
            Self::DevnetFixtureOnly => "devnet_fixture_only",
            Self::ReleaseGuardDisabled => "release_guard_disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub verifier_suite: String,
    pub min_pq_security_bits: u16,
    pub min_watcher_quorum: u64,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u64,
    pub low_fee_cap_atomic: u128,
    pub force_out_window_blocks: u64,
    pub require_monero_no_base_layer_verifier_blocker: bool,
    pub production_release_allowed: bool,
    pub max_transcripts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            verifier_suite: VERIFIER_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            force_out_window_blocks: DEFAULT_FORCE_OUT_WINDOW_BLOCKS,
            require_monero_no_base_layer_verifier_blocker: true,
            production_release_allowed: false,
            max_transcripts: DEFAULT_MAX_TRANSCRIPTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "verifier_suite": self.verifier_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "force_out_window_blocks": self.force_out_window_blocks,
            "require_monero_no_base_layer_verifier_blocker": self.require_monero_no_base_layer_verifier_blocker,
            "production_release_allowed": self.production_release_allowed,
            "max_transcripts": self.max_transcripts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalTranscriptRoot {
    pub transcript_id: String,
    pub stage: CanonicalStage,
    pub sequence: u64,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub input_vector_root: String,
    pub output_vector_root: String,
    pub wallet_reconstruction_root: String,
    pub pq_watcher_root: String,
    pub monero_base_layer_verifier_root: String,
    pub fee_atomic: u128,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub pq_security_bits: u16,
    pub watcher_quorum: u64,
    pub force_out_window_blocks: u64,
    pub production_blockers: Vec<ProductionBlocker>,
}

impl CanonicalTranscriptRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "stage": self.stage.as_str(),
            "sequence": self.sequence,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "input_vector_root": self.input_vector_root,
            "output_vector_root": self.output_vector_root,
            "wallet_reconstruction_root": self.wallet_reconstruction_root,
            "pq_watcher_root": self.pq_watcher_root,
            "monero_base_layer_verifier_root": self.monero_base_layer_verifier_root,
            "fee_atomic": self.fee_atomic.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "pq_security_bits": self.pq_security_bits,
            "watcher_quorum": self.watcher_quorum,
            "force_out_window_blocks": self.force_out_window_blocks,
            "production_blockers": self.production_blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-ROOT",
            &[
                HashPart::Str(&self.transcript_id),
                HashPart::Str(self.stage.as_str()),
                HashPart::U64(self.sequence),
                HashPart::Str(&self.public_root),
                HashPart::Str(&self.committed_root),
                HashPart::Str(&self.encrypted_root),
                HashPart::Str(&self.input_vector_root),
                HashPart::Str(&self.output_vector_root),
                HashPart::Str(&self.wallet_reconstruction_root),
                HashPart::Str(&self.pq_watcher_root),
                HashPart::Str(&self.monero_base_layer_verifier_root),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::U64(self.watcher_quorum),
                HashPart::U64(self.force_out_window_blocks),
                HashPart::Json(&json!(self
                    .production_blockers
                    .iter()
                    .map(|blocker| blocker.as_str())
                    .collect::<Vec<_>>())),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaticCheck {
    pub check_id: String,
    pub kind: StaticCheckKind,
    pub status: CheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
}

impl StaticCheck {
    pub fn new(
        kind: StaticCheckKind,
        status: CheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_root: String,
    ) -> Self {
        Self {
            check_id: stable_id("check", &format!("{}:{evidence_root}", kind.as_str())),
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("static_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub transcripts_verified: u64,
    pub checks_run: u64,
    pub checks_passed: u64,
    pub checks_watch: u64,
    pub checks_failed: u64,
    pub root_continuity_failures: u64,
    pub production_blockers_seen: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "transcripts_verified": self.transcripts_verified,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "checks_watch": self.checks_watch,
            "checks_failed": self.checks_failed,
            "root_continuity_failures": self.root_continuity_failures,
            "production_blockers_seen": self.production_blockers_seen,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationReport {
    pub report_id: String,
    pub status: ReportStatus,
    pub transcript_root: String,
    pub check_root: String,
    pub public_record_root: String,
    pub state_root: String,
    pub checks: BTreeMap<String, StaticCheck>,
}

impl VerificationReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "transcript_root": self.transcript_root,
            "check_root": self.check_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
            "checks": self.checks.values().map(StaticCheck::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub transcript_root: String,
    pub check_root: String,
    pub public_record_root: String,
    pub devnet_data_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "transcript_root": self.transcript_root,
            "check_root": self.check_root,
            "public_record_root": self.public_record_root,
            "devnet_data_root": self.devnet_data_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub transcripts: Vec<CanonicalTranscriptRoot>,
    pub report: VerificationReport,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, transcripts: Vec<CanonicalTranscriptRoot>) -> Result<Self> {
        ensure(
            transcripts.len() <= config.max_transcripts,
            "canonical transcript capacity exceeded",
        )?;
        let checks = evaluate_static_checks(&config, &transcripts);
        ensure(
            StaticCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "canonical transcript verifier omitted a required static check",
        )?;
        let status = aggregate_status(&checks);
        let counters = counters_from_checks(&transcripts, &checks);
        let transcript_root = transcript_root(&transcripts);
        let check_root = checks_root(&checks);
        let public_record_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-PUBLIC-RECORD",
            &[
                json!({"config_root": config.state_root()}),
                json!({"transcript_root": transcript_root}),
                json!({"check_root": check_root}),
                json!({"counters": counters.public_record()}),
            ],
        );
        let report_state_root =
            report_state_root(status, &transcript_root, &check_root, &public_record_root);
        let report = VerificationReport {
            report_id: stable_id("verification_report", &report_state_root),
            status,
            transcript_root: transcript_root.clone(),
            check_root: check_root.clone(),
            public_record_root: public_record_root.clone(),
            state_root: report_state_root,
            checks,
        };
        let devnet_data_root = devnet_data_root(&transcripts, &report);
        let roots = roots_for(
            &config,
            &transcript_root,
            &check_root,
            &public_record_root,
            &devnet_data_root,
            &counters,
        );
        Ok(Self {
            config,
            transcripts,
            report,
            counters,
            roots,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let transcripts = devnet_transcripts(&config);
        match Self::new(config, transcripts) {
            Ok(state) => state,
            Err(_) => empty_state(),
        }
    }

    pub fn verify(&mut self) -> Result<String> {
        let rebuilt = Self::new(self.config.clone(), self.transcripts.clone())?;
        let report_id = rebuilt.report.report_id.clone();
        *self = rebuilt;
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "canonical_transcripts": self.transcripts.iter().map(CanonicalTranscriptRoot::public_record).collect::<Vec<_>>(),
            "report": self.report.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn devnet_data(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "canonical_transcripts": self.transcripts.iter().map(CanonicalTranscriptRoot::public_record).collect::<Vec<_>>(),
            "report_root": self.report.state_root,
            "devnet_data_root": self.roots.devnet_data_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn check(&self, kind: StaticCheckKind) -> Option<&StaticCheck> {
        self.report.checks.get(kind.as_str())
    }
}

pub fn evaluate_static_checks(
    config: &Config,
    transcripts: &[CanonicalTranscriptRoot],
) -> BTreeMap<String, StaticCheck> {
    let mut checks = BTreeMap::new();
    for check in [
        check_stage_ordering(transcripts),
        check_vector_root_continuity(transcripts),
        check_root_separation(transcripts),
        check_wallet_reconstruction_continuity(transcripts),
        check_pq_watcher_linkage(config, transcripts),
        check_monero_blocker(config, transcripts),
        check_fee_privacy_thresholds(config, transcripts),
        check_production_blockers(config, transcripts),
        check_public_record_state_root(transcripts),
        check_devnet_data(transcripts),
    ] {
        checks.insert(check.kind.as_str().to_string(), check);
    }
    checks
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

pub fn devnet_data() -> Value {
    devnet().devnet_data()
}

pub fn canonical_transcript_root(transcripts: &[CanonicalTranscriptRoot]) -> String {
    transcript_root(transcripts)
}

pub fn root_for_public_record(kind: &str, record: &Value) -> String {
    record_root(kind, record)
}

fn check_stage_ordering(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let observed = transcripts
        .iter()
        .map(|item| format!("{}:{}", item.sequence, item.stage.as_str()))
        .collect::<Vec<_>>();
    let ok = transcripts.len() == 3
        && transcripts
            .iter()
            .enumerate()
            .all(|(idx, item)| item.sequence == idx as u64 && item.stage.ordinal() == idx as u64);
    StaticCheck::new(
        StaticCheckKind::StageOrdering,
        status(ok),
        "canonical stages must be get-in, move-private, force-out with contiguous sequence",
        observed.join(","),
        evidence_root("stage_ordering", &json!({"observed": observed})),
    )
}

fn check_vector_root_continuity(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let mut broken = Vec::new();
    for pair in transcripts.windows(2) {
        if pair[0].output_vector_root != pair[1].input_vector_root {
            broken.push(format!(
                "{}->{}",
                pair[0].stage.as_str(),
                pair[1].stage.as_str()
            ));
        }
    }
    StaticCheck::new(
        StaticCheckKind::VectorRootContinuity,
        status(broken.is_empty() && !transcripts.is_empty()),
        "each stage output vector root must equal the next stage input vector root",
        format!("broken_links={}", broken.join(",")),
        evidence_root("vector_root_continuity", &json!({"broken_links": broken})),
    )
}

fn check_root_separation(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let bad = transcripts
        .iter()
        .filter(|item| {
            item.public_root.is_empty()
                || item.committed_root.is_empty()
                || item.encrypted_root.is_empty()
                || item.public_root == item.committed_root
                || item.public_root == item.encrypted_root
                || item.committed_root == item.encrypted_root
        })
        .map(|item| item.transcript_id.clone())
        .collect::<Vec<_>>();
    StaticCheck::new(
        StaticCheckKind::RootSeparation,
        status(bad.is_empty() && !transcripts.is_empty()),
        "public, committed, and encrypted material roots must be present and distinct",
        format!("violations={}", bad.join(",")),
        evidence_root("root_separation", &json!({"violations": bad})),
    )
}

fn check_wallet_reconstruction_continuity(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let roots = transcripts
        .iter()
        .map(|item| item.wallet_reconstruction_root.clone())
        .collect::<Vec<_>>();
    let ok = !roots.is_empty() && roots.iter().all(|root| !root.is_empty());
    StaticCheck::new(
        StaticCheckKind::WalletReconstructionContinuity,
        status(ok),
        "every transcript stage must carry a wallet reconstruction root",
        format!("wallet_roots={}", roots.join(",")),
        evidence_root(
            "wallet_reconstruction_continuity",
            &json!({"wallet_roots": roots}),
        ),
    )
}

fn check_pq_watcher_linkage(
    config: &Config,
    transcripts: &[CanonicalTranscriptRoot],
) -> StaticCheck {
    let bad = transcripts
        .iter()
        .filter(|item| {
            item.pq_watcher_root.is_empty()
                || item.pq_security_bits < config.min_pq_security_bits
                || item.watcher_quorum < config.min_watcher_quorum
        })
        .map(|item| item.transcript_id.clone())
        .collect::<Vec<_>>();
    StaticCheck::new(
        StaticCheckKind::PqWatcherLinkage,
        status(bad.is_empty() && !transcripts.is_empty()),
        "PQ watcher roots must be linked with quorum and security floors",
        format!("violations={}", bad.join(",")),
        evidence_root("pq_watcher_linkage", &json!({"violations": bad})),
    )
}

fn check_monero_blocker(config: &Config, transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let required = config.require_monero_no_base_layer_verifier_blocker;
    let blocked = transcripts.iter().all(|item| {
        item.monero_base_layer_verifier_root == no_base_layer_verifier_root()
            && item
                .production_blockers
                .contains(&ProductionBlocker::MoneroBaseLayerCannotVerifyPqProofs)
    });
    StaticCheck::new(
        StaticCheckKind::MoneroNoBaseLayerVerifierBlocked,
        status(!required || blocked),
        "canonical exit transcript must explicitly block Monero base-layer PQ verification",
        format!("required={required}, blocked={blocked}"),
        evidence_root(
            "monero_no_base_layer_verifier_blocked",
            &json!({"required": required, "blocked": blocked}),
        ),
    )
}

fn check_fee_privacy_thresholds(
    config: &Config,
    transcripts: &[CanonicalTranscriptRoot],
) -> StaticCheck {
    let bad = transcripts
        .iter()
        .filter(|item| {
            item.fee_atomic > config.low_fee_cap_atomic
                || item.privacy_set_size < config.min_privacy_set_size
                || item.metadata_leakage_units > config.max_metadata_leakage_units
                || item.force_out_window_blocks > config.force_out_window_blocks
        })
        .map(|item| item.transcript_id.clone())
        .collect::<Vec<_>>();
    StaticCheck::new(
        StaticCheckKind::FeePrivacyThresholds,
        status(bad.is_empty() && !transcripts.is_empty()),
        "fees, privacy sets, metadata leakage, and force-out windows must satisfy thresholds",
        format!("violations={}", bad.join(",")),
        evidence_root("fee_privacy_thresholds", &json!({"violations": bad})),
    )
}

fn check_production_blockers(
    config: &Config,
    transcripts: &[CanonicalTranscriptRoot],
) -> StaticCheck {
    let blocker_count = transcripts
        .iter()
        .map(|item| item.production_blockers.len() as u64)
        .sum::<u64>();
    let ok = if config.production_release_allowed {
        blocker_count == 0
    } else {
        blocker_count > 0
    };
    StaticCheck::new(
        StaticCheckKind::ProductionBlockers,
        if ok {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        "production release must remain blocked for devnet canonical transcript fixtures",
        format!(
            "production_release_allowed={}, blocker_count={}",
            config.production_release_allowed, blocker_count
        ),
        evidence_root(
            "production_blockers",
            &json!({"production_release_allowed": config.production_release_allowed, "blocker_count": blocker_count}),
        ),
    )
}

fn check_public_record_state_root(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let root = transcript_root(transcripts);
    let public_root = record_root(
        "transcripts_public_record",
        &json!({"transcript_root": root}),
    );
    let recomputed = record_root(
        "transcripts_state_root",
        &json!({"public_record_root": public_root}),
    );
    StaticCheck::new(
        StaticCheckKind::PublicRecordStateRoot,
        status(!root.is_empty() && !public_root.is_empty() && !recomputed.is_empty()),
        "public_record and state_root surfaces must be reproducible from transcript roots",
        format!("public_record_root={public_root}, state_root={recomputed}"),
        evidence_root(
            "public_record_state_root",
            &json!({"public_record_root": public_root, "state_root": recomputed}),
        ),
    )
}

fn check_devnet_data(transcripts: &[CanonicalTranscriptRoot]) -> StaticCheck {
    let has_devnet = transcripts.iter().all(|item| {
        item.production_blockers
            .contains(&ProductionBlocker::DevnetFixtureOnly)
    });
    StaticCheck::new(
        StaticCheckKind::DevnetDataRoot,
        status(has_devnet && transcripts.len() == 3),
        "devnet data must include all canonical get-in, move-private, and force-out fixtures",
        format!("has_devnet={}, count={}", has_devnet, transcripts.len()),
        evidence_root(
            "devnet_data_root",
            &json!({"has_devnet": has_devnet, "count": transcripts.len()}),
        ),
    )
}

fn devnet_transcripts(config: &Config) -> Vec<CanonicalTranscriptRoot> {
    let wallet_root = fixture_root("wallet-reconstruction", "devnet-canonical-wallet");
    let watcher_root = fixture_root("pq-watcher", "devnet-canonical-watchers");
    let base_blocker_root = no_base_layer_verifier_root();
    let initial_vector_root = fixture_root("vector", "initial-locked-xmr");
    let private_vector_root = fixture_root("vector", "private-note-after-get-in");
    let moved_vector_root = fixture_root("vector", "private-note-after-move");
    let force_out_vector_root = fixture_root("vector", "force-out-claim-ready");
    vec![
        devnet_transcript(
            config,
            CanonicalStage::GetIn,
            0,
            &initial_vector_root,
            &private_vector_root,
            &wallet_root,
            &watcher_root,
            &base_blocker_root,
        ),
        devnet_transcript(
            config,
            CanonicalStage::MovePrivate,
            1,
            &private_vector_root,
            &moved_vector_root,
            &wallet_root,
            &watcher_root,
            &base_blocker_root,
        ),
        devnet_transcript(
            config,
            CanonicalStage::ForceOut,
            2,
            &moved_vector_root,
            &force_out_vector_root,
            &wallet_root,
            &watcher_root,
            &base_blocker_root,
        ),
    ]
}

fn devnet_transcript(
    config: &Config,
    stage: CanonicalStage,
    sequence: u64,
    input_vector_root: &str,
    output_vector_root: &str,
    wallet_reconstruction_root: &str,
    pq_watcher_root: &str,
    monero_base_layer_verifier_root: &str,
) -> CanonicalTranscriptRoot {
    let seed = format!("{}-{sequence}", stage.as_str());
    CanonicalTranscriptRoot {
        transcript_id: stable_id("canonical_transcript", &seed),
        stage,
        sequence,
        public_root: fixture_root("public", &seed),
        committed_root: fixture_root("committed", &seed),
        encrypted_root: fixture_root("encrypted", &seed),
        input_vector_root: input_vector_root.to_string(),
        output_vector_root: output_vector_root.to_string(),
        wallet_reconstruction_root: wallet_reconstruction_root.to_string(),
        pq_watcher_root: pq_watcher_root.to_string(),
        monero_base_layer_verifier_root: monero_base_layer_verifier_root.to_string(),
        fee_atomic: config.low_fee_cap_atomic / 2,
        privacy_set_size: config.min_privacy_set_size * 2,
        metadata_leakage_units: config.max_metadata_leakage_units,
        pq_security_bits: config.min_pq_security_bits,
        watcher_quorum: config.min_watcher_quorum,
        force_out_window_blocks: config.force_out_window_blocks,
        production_blockers: vec![
            ProductionBlocker::MoneroBaseLayerCannotVerifyPqProofs,
            ProductionBlocker::DevnetFixtureOnly,
            ProductionBlocker::ReleaseGuardDisabled,
        ],
    }
}

fn aggregate_status(checks: &BTreeMap<String, StaticCheck>) -> ReportStatus {
    if checks
        .values()
        .any(|check| check.status == CheckStatus::Failed)
    {
        ReportStatus::Failed
    } else if checks
        .values()
        .any(|check| check.status == CheckStatus::Watch)
    {
        ReportStatus::Watch
    } else {
        ReportStatus::Passed
    }
}

fn counters_from_checks(
    transcripts: &[CanonicalTranscriptRoot],
    checks: &BTreeMap<String, StaticCheck>,
) -> Counters {
    Counters {
        transcripts_verified: transcripts.len() as u64,
        checks_run: checks.len() as u64,
        checks_passed: checks
            .values()
            .filter(|check| check.status == CheckStatus::Passed)
            .count() as u64,
        checks_watch: checks
            .values()
            .filter(|check| check.status == CheckStatus::Watch)
            .count() as u64,
        checks_failed: checks
            .values()
            .filter(|check| check.status == CheckStatus::Failed)
            .count() as u64,
        root_continuity_failures: checks
            .get(StaticCheckKind::VectorRootContinuity.as_str())
            .filter(|check| check.status == CheckStatus::Failed)
            .map(|_| 1)
            .unwrap_or(0),
        production_blockers_seen: transcripts
            .iter()
            .map(|item| item.production_blockers.len() as u64)
            .sum(),
    }
}

fn roots_for(
    config: &Config,
    transcript_root: &str,
    check_root: &str,
    public_record_root: &str,
    devnet_data_root: &str,
    counters: &Counters,
) -> Roots {
    let config_root = config.state_root();
    let counters_root = counters.state_root();
    let state_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-STATE",
        &[
            HashPart::Str(&config_root),
            HashPart::Str(transcript_root),
            HashPart::Str(check_root),
            HashPart::Str(public_record_root),
            HashPart::Str(devnet_data_root),
            HashPart::Str(&counters_root),
        ],
        32,
    );
    Roots {
        config_root,
        transcript_root: transcript_root.to_string(),
        check_root: check_root.to_string(),
        public_record_root: public_record_root.to_string(),
        devnet_data_root: devnet_data_root.to_string(),
        counters_root,
        state_root,
    }
}

fn empty_state() -> State {
    let config = Config::devnet();
    let counters = Counters::default();
    let checks = BTreeMap::new();
    let transcript_root = transcript_root(&[]);
    let check_root = checks_root(&checks);
    let public_record_root = record_root("empty_public_record", &json!({}));
    let report_state_root = report_state_root(
        ReportStatus::Failed,
        &transcript_root,
        &check_root,
        &public_record_root,
    );
    let report = VerificationReport {
        report_id: stable_id("verification_report", &report_state_root),
        status: ReportStatus::Failed,
        transcript_root: transcript_root.clone(),
        check_root: check_root.clone(),
        public_record_root: public_record_root.clone(),
        state_root: report_state_root,
        checks,
    };
    let devnet_data_root = devnet_data_root(&[], &report);
    let roots = roots_for(
        &config,
        &transcript_root,
        &check_root,
        &public_record_root,
        &devnet_data_root,
        &counters,
    );
    State {
        config,
        transcripts: Vec::new(),
        report,
        counters,
        roots,
    }
}

fn transcript_root(transcripts: &[CanonicalTranscriptRoot]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-ROOTS",
        &transcripts
            .iter()
            .map(CanonicalTranscriptRoot::public_record)
            .collect::<Vec<_>>(),
    )
}

fn checks_root(checks: &BTreeMap<String, StaticCheck>) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-CHECKS",
        &checks
            .values()
            .map(StaticCheck::public_record)
            .collect::<Vec<_>>(),
    )
}

fn devnet_data_root(
    transcripts: &[CanonicalTranscriptRoot],
    report: &VerificationReport,
) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-DEVNET-DATA",
        &[
            json!({"transcripts": transcripts.iter().map(CanonicalTranscriptRoot::public_record).collect::<Vec<_>>()}),
            json!({"report": report.public_record()}),
        ],
    )
}

fn report_state_root(
    status: ReportStatus,
    transcript_root: &str,
    check_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(transcript_root),
            HashPart::Str(check_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn evidence_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn fixture_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn no_base_layer_verifier_root() -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-NO-BASE-LAYER-VERIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str("monero_consensus_does_not_verify_l2_pq_static_transcripts"),
        ],
        32,
    )
}

pub fn stable_id(kind: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT-STATIC-VERIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(value),
        ],
        16,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn status(ok: bool) -> CheckStatus {
    if ok {
        CheckStatus::Passed
    } else {
        CheckStatus::Failed
    }
}
