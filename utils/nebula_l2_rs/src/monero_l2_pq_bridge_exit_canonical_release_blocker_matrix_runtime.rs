use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalReleaseBlockerMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_BLOCKER_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-release-blocker-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_BLOCKER_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_BLOCKER_MATRIX_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-matrix-v1";
pub const DEFAULT_MIN_BLOCKERS: usize = 9;
pub const DEFAULT_CANONICAL_TRANSCRIPT_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-transcript-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    NoBaseLayerVerifierRisk,
    LiveHandlerMissing,
    ReserveLiquidityNotExecuted,
    PrivacyReviewPending,
    PqKeyVerificationDeferred,
    WalletEvidenceWatch,
    ProductionSignoffHold,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::NoBaseLayerVerifierRisk => "no_base_layer_verifier_risk",
            Self::LiveHandlerMissing => "live_handler_missing",
            Self::ReserveLiquidityNotExecuted => "reserve_liquidity_not_executed",
            Self::PrivacyReviewPending => "privacy_review_pending",
            Self::PqKeyVerificationDeferred => "pq_key_verification_deferred",
            Self::WalletEvidenceWatch => "wallet_evidence_watch",
            Self::ProductionSignoffHold => "production_signoff_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Informational,
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerLane {
    CargoRuntime,
    SecurityAudit,
    ProtocolSafety,
    OperatorIntegration,
    ReserveLiquidity,
    Privacy,
    PqKeyManagement,
    WalletEvidence,
    ProductionGovernance,
}

impl OwnerLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntime => "cargo_runtime",
            Self::SecurityAudit => "security_audit",
            Self::ProtocolSafety => "protocol_safety",
            Self::OperatorIntegration => "operator_integration",
            Self::ReserveLiquidity => "reserve_liquidity",
            Self::Privacy => "privacy",
            Self::PqKeyManagement => "pq_key_management",
            Self::WalletEvidence => "wallet_evidence",
            Self::ProductionGovernance => "production_governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Open,
    EvidenceWatch,
    Deferred,
    SignoffHold,
    Cleared,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceWatch => "evidence_watch",
            Self::Deferred => "deferred",
            Self::SignoffHold => "signoff_hold",
            Self::Cleared => "cleared",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDisposition {
    Blocked,
    Hold,
    Watch,
    Clear,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Hold => "hold",
            Self::Watch => "watch",
            Self::Clear => "clear",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub matrix_suite: String,
    pub canonical_transcript_id: String,
    pub min_blockers: usize,
    pub production_release_allowed: bool,
    pub requires_public_record: bool,
    pub requires_devnet_data: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            matrix_suite: RELEASE_BLOCKER_MATRIX_SUITE.to_string(),
            canonical_transcript_id: DEFAULT_CANONICAL_TRANSCRIPT_ID.to_string(),
            min_blockers: DEFAULT_MIN_BLOCKERS,
            production_release_allowed: false,
            requires_public_record: true,
            requires_devnet_data: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "matrix_suite": self.matrix_suite,
            "canonical_transcript_id": self.canonical_transcript_id,
            "min_blockers": self.min_blockers,
            "production_release_allowed": self.production_release_allowed,
            "requires_public_record": self.requires_public_record,
            "requires_devnet_data": self.requires_devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevnetData {
    pub devnet_id: String,
    pub epoch: u64,
    pub bridge_exit_height: u64,
    pub canonical_exit_id: String,
    pub transfer_id: String,
    pub operator_set_root: String,
    pub watcher_set_root: String,
    pub reserve_snapshot_root: String,
    pub wallet_evidence_root: String,
}

impl DevnetData {
    pub fn public_record(&self) -> Value {
        json!({
            "devnet_id": self.devnet_id,
            "epoch": self.epoch,
            "bridge_exit_height": self.bridge_exit_height,
            "canonical_exit_id": self.canonical_exit_id,
            "transfer_id": self.transfer_id,
            "operator_set_root": self.operator_set_root,
            "watcher_set_root": self.watcher_set_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "wallet_evidence_root": self.wallet_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("devnet-data", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub severity: BlockerSeverity,
    pub owner_lane: OwnerLane,
    pub status: BlockerStatus,
    pub clearing_order: u64,
    pub canonical_transcript_root: String,
    pub source_root: String,
    pub evidence_root: String,
    pub acceptance_root: String,
    pub devnet_root: String,
    pub public_record_root: String,
    pub state_root: String,
    pub title: String,
    pub required_clearance: String,
    pub blocks_user_release: bool,
    pub blocks_production_release: bool,
}

impl ReleaseBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "owner_lane": self.owner_lane.as_str(),
            "status": self.status.as_str(),
            "clearing_order": self.clearing_order,
            "canonical_transcript_root": self.canonical_transcript_root,
            "source_root": self.source_root,
            "evidence_root": self.evidence_root,
            "acceptance_root": self.acceptance_root,
            "devnet_root": self.devnet_root,
            "title": self.title,
            "required_clearance": self.required_clearance,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production_release": self.blocks_production_release,
        })
    }

    pub fn root_payload(&self) -> Value {
        let public_record = self.public_record();
        json!({
            "public_record": public_record,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn is_open(&self) -> bool {
        self.status != BlockerStatus::Cleared
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MatrixSummary {
    pub disposition: ReleaseDisposition,
    pub blocker_count: usize,
    pub open_blocker_count: usize,
    pub production_blocker_count: usize,
    pub max_severity: BlockerSeverity,
    pub clearing_order_root: String,
    pub owner_lane_root: String,
    pub blocker_root: String,
}

impl MatrixSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "disposition": self.disposition.as_str(),
            "blocker_count": self.blocker_count,
            "open_blocker_count": self.open_blocker_count,
            "production_blocker_count": self.production_blocker_count,
            "max_severity": self.max_severity.as_str(),
            "max_severity_score": self.max_severity.score(),
            "clearing_order_root": self.clearing_order_root,
            "owner_lane_root": self.owner_lane_root,
            "blocker_root": self.blocker_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("matrix-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub devnet_data: DevnetData,
    pub blockers: Vec<ReleaseBlocker>,
    pub summary: MatrixSummary,
    pub config_root: String,
    pub devnet_data_root: String,
    pub blocker_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn from_parts(
        config: Config,
        devnet_data: DevnetData,
        mut blockers: Vec<ReleaseBlocker>,
    ) -> Result<Self> {
        if blockers.len() < config.min_blockers {
            return Err(format!(
                "release blocker matrix requires at least {} blockers",
                config.min_blockers
            ));
        }

        blockers.sort_by_key(|blocker| blocker.clearing_order);
        let blocker_root = blockers_root(&blockers);
        let summary = summarize(&blockers, &blocker_root);
        let config_root = config.state_root();
        let devnet_data_root = devnet_data.state_root();
        let summary_root = summary.state_root();
        let public_record = state_public_record(
            &config,
            &devnet_data,
            &blockers,
            &summary,
            &config_root,
            &devnet_data_root,
            &blocker_root,
            &summary_root,
        );
        let public_record_root = record_root("matrix-public-record", &public_record);
        let state_root = matrix_state_root(
            &config_root,
            &devnet_data_root,
            &blocker_root,
            &summary_root,
            &public_record_root,
        );

        Ok(Self {
            config,
            devnet_data,
            blockers,
            summary,
            config_root,
            devnet_data_root,
            blocker_root,
            summary_root,
            public_record_root,
            state_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let devnet_data = devnet_data(&config);
        let blockers = canonical_devnet_blockers(&config, &devnet_data);
        Self::from_parts(config, devnet_data, blockers)
            .unwrap_or_else(|error| fallback_state(error.as_str()))
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.devnet_data,
            &self.blockers,
            &self.summary,
            &self.config_root,
            &self.devnet_data_root,
            &self.blocker_root,
            &self.summary_root,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn open_blockers(&self) -> Vec<ReleaseBlocker> {
        self.blockers
            .iter()
            .filter(|blocker| blocker.is_open())
            .cloned()
            .collect()
    }

    pub fn blockers_for_owner(&self, owner_lane: OwnerLane) -> Vec<ReleaseBlocker> {
        self.blockers
            .iter()
            .filter(|blocker| blocker.owner_lane == owner_lane)
            .cloned()
            .collect()
    }

    pub fn clearing_order(&self) -> Vec<String> {
        self.blockers
            .iter()
            .map(|blocker| blocker.blocker_id.clone())
            .collect()
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

pub fn blocker_id(kind: BlockerKind, transfer_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(transfer_id)],
        16,
    )
}

pub fn blocker_public_root(blocker: &ReleaseBlocker) -> String {
    record_root("blocker-public", &blocker.public_record())
}

fn canonical_devnet_blockers(config: &Config, devnet_data: &DevnetData) -> Vec<ReleaseBlocker> {
    let transcript_root = transcript_root(config, devnet_data);
    vec![
        build_blocker(
            devnet_data,
            BlockerKind::CargoRuntimeDeferred,
            BlockerSeverity::ReleaseStop,
            OwnerLane::CargoRuntime,
            BlockerStatus::Deferred,
            10,
            &transcript_root,
            "cargo checks and runtime vectors remain deferred for canonical exit",
            "run cargo/runtime gate and commit passing vector roots",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::SecurityAuditDeferred,
            BlockerSeverity::ReleaseStop,
            OwnerLane::SecurityAudit,
            BlockerStatus::Deferred,
            20,
            &transcript_root,
            "security audit acceptance is deferred from release record",
            "attach signed audit report and issue acceptance root",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::NoBaseLayerVerifierRisk,
            BlockerSeverity::Critical,
            OwnerLane::ProtocolSafety,
            BlockerStatus::Open,
            30,
            &transcript_root,
            "base layer verifier is absent from canonical release path",
            "publish verifier risk waiver or verifier implementation proof",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::LiveHandlerMissing,
            BlockerSeverity::Critical,
            OwnerLane::OperatorIntegration,
            BlockerStatus::Open,
            40,
            &transcript_root,
            "live exit handler is missing from operator execution lane",
            "ship handler wiring and record live adapter receipt",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::ReserveLiquidityNotExecuted,
            BlockerSeverity::Critical,
            OwnerLane::ReserveLiquidity,
            BlockerStatus::Open,
            50,
            &transcript_root,
            "reserve and liquidity release were not executed on devnet",
            "execute reserve release and publish liquidity receipt roots",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::PrivacyReviewPending,
            BlockerSeverity::Major,
            OwnerLane::Privacy,
            BlockerStatus::Open,
            60,
            &transcript_root,
            "privacy review is pending for canonical transcript exposure",
            "complete privacy review and bind redaction acceptance root",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::PqKeyVerificationDeferred,
            BlockerSeverity::Major,
            OwnerLane::PqKeyManagement,
            BlockerStatus::Deferred,
            70,
            &transcript_root,
            "post quantum key verification remains deferred",
            "verify hybrid key bundle and attach signer quorum root",
            true,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::WalletEvidenceWatch,
            BlockerSeverity::Watch,
            OwnerLane::WalletEvidence,
            BlockerStatus::EvidenceWatch,
            80,
            &transcript_root,
            "wallet evidence is on watch until user-visible proof is stable",
            "stabilize wallet evidence export and record watch clearance",
            false,
            true,
        ),
        build_blocker(
            devnet_data,
            BlockerKind::ProductionSignoffHold,
            BlockerSeverity::ReleaseStop,
            OwnerLane::ProductionGovernance,
            BlockerStatus::SignoffHold,
            90,
            &transcript_root,
            "production signoff is held pending all blocker clearances",
            "collect production owner signoff after prior clearing order",
            true,
            true,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn build_blocker(
    devnet_data: &DevnetData,
    kind: BlockerKind,
    severity: BlockerSeverity,
    owner_lane: OwnerLane,
    status: BlockerStatus,
    clearing_order: u64,
    canonical_transcript_root: &str,
    title: &str,
    required_clearance: &str,
    blocks_user_release: bool,
    blocks_production_release: bool,
) -> ReleaseBlocker {
    let blocker_id = blocker_id(kind, &devnet_data.transfer_id);
    let source_root = source_root(
        kind,
        owner_lane,
        canonical_transcript_root,
        &devnet_data.transfer_id,
    );
    let evidence_root = evidence_root(
        kind,
        status,
        &devnet_data.wallet_evidence_root,
        &source_root,
    );
    let acceptance_root = acceptance_root(
        kind,
        severity,
        owner_lane,
        clearing_order,
        required_clearance,
    );
    let devnet_root = devnet_data.state_root();
    let public_record = json!({
        "blocker_id": blocker_id,
        "kind": kind.as_str(),
        "severity": severity.as_str(),
        "owner_lane": owner_lane.as_str(),
        "status": status.as_str(),
        "clearing_order": clearing_order,
        "canonical_transcript_root": canonical_transcript_root,
        "source_root": source_root,
        "evidence_root": evidence_root,
        "acceptance_root": acceptance_root,
        "devnet_root": devnet_root,
        "title": title,
        "required_clearance": required_clearance,
        "blocks_user_release": blocks_user_release,
        "blocks_production_release": blocks_production_release,
    });
    let public_record_root = record_root("blocker-public", &public_record);
    let state_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-STATE",
        &[
            HashPart::Str(&blocker_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(owner_lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(clearing_order),
            HashPart::Str(&source_root),
            HashPart::Str(&evidence_root),
            HashPart::Str(&acceptance_root),
            HashPart::Str(&devnet_root),
            HashPart::Str(&public_record_root),
        ],
        32,
    );

    ReleaseBlocker {
        blocker_id,
        kind,
        severity,
        owner_lane,
        status,
        clearing_order,
        canonical_transcript_root: canonical_transcript_root.to_string(),
        source_root,
        evidence_root,
        acceptance_root,
        devnet_root,
        public_record_root,
        state_root,
        title: title.to_string(),
        required_clearance: required_clearance.to_string(),
        blocks_user_release,
        blocks_production_release,
    }
}

fn summarize(blockers: &[ReleaseBlocker], blocker_root: &str) -> MatrixSummary {
    let open_blocker_count = blockers.iter().filter(|blocker| blocker.is_open()).count();
    let production_blocker_count = blockers
        .iter()
        .filter(|blocker| blocker.blocks_production_release && blocker.is_open())
        .count();
    let max_severity = blockers
        .iter()
        .map(|blocker| blocker.severity)
        .max_by_key(|severity| severity.score())
        .unwrap_or(BlockerSeverity::Informational);
    let disposition = if production_blocker_count > 0 {
        ReleaseDisposition::Blocked
    } else if open_blocker_count > 0 {
        ReleaseDisposition::Hold
    } else {
        ReleaseDisposition::Clear
    };

    MatrixSummary {
        disposition,
        blocker_count: blockers.len(),
        open_blocker_count,
        production_blocker_count,
        max_severity,
        clearing_order_root: clearing_order_root(blockers),
        owner_lane_root: owner_lane_root(blockers),
        blocker_root: blocker_root.to_string(),
    }
}

fn devnet_data(config: &Config) -> DevnetData {
    let canonical_exit_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-EXIT-ID",
        &[HashPart::Str(&config.canonical_transcript_id)],
        16,
    );
    let transfer_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSFER-ID",
        &[HashPart::Str(&canonical_exit_id), HashPart::Str("devnet")],
        16,
    );
    let operator_set_root = named_root("operator-set", &transfer_id);
    let watcher_set_root = named_root("watcher-set", &transfer_id);
    let reserve_snapshot_root = named_root("reserve-snapshot", &transfer_id);
    let wallet_evidence_root = named_root("wallet-evidence", &transfer_id);

    DevnetData {
        devnet_id: "nebula-local-devnet".to_string(),
        epoch: 7,
        bridge_exit_height: 184_320,
        canonical_exit_id,
        transfer_id,
        operator_set_root,
        watcher_set_root,
        reserve_snapshot_root,
        wallet_evidence_root,
    }
}

fn state_public_record(
    config: &Config,
    devnet_data: &DevnetData,
    blockers: &[ReleaseBlocker],
    summary: &MatrixSummary,
    config_root: &str,
    devnet_data_root: &str,
    blocker_root: &str,
    summary_root: &str,
) -> Value {
    json!({
        "config": config.public_record(),
        "devnet_data": devnet_data.public_record(),
        "blockers": blockers.iter().map(ReleaseBlocker::public_record).collect::<Vec<_>>(),
        "summary": summary.public_record(),
        "roots": {
            "config_root": config_root,
            "devnet_data_root": devnet_data_root,
            "blocker_root": blocker_root,
            "summary_root": summary_root,
        }
    })
}

fn blockers_root(blockers: &[ReleaseBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(ReleaseBlocker::root_payload)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-MATRIX",
        &leaves,
    )
}

fn clearing_order_root(blockers: &[ReleaseBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| {
            json!({
                "blocker_id": blocker.blocker_id,
                "clearing_order": blocker.clearing_order,
                "owner_lane": blocker.owner_lane.as_str(),
                "severity": blocker.severity.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-CLEARING-ORDER",
        &leaves,
    )
}

fn owner_lane_root(blockers: &[ReleaseBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| {
            json!({
                "owner_lane": blocker.owner_lane.as_str(),
                "blocker_id": blocker.blocker_id,
                "status": blocker.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-OWNER-LANES",
        &leaves,
    )
}

fn transcript_root(config: &Config, devnet_data: &DevnetData) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-TRANSCRIPT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&config.canonical_transcript_id),
            HashPart::Str(&devnet_data.canonical_exit_id),
            HashPart::Str(&devnet_data.transfer_id),
            HashPart::U64(devnet_data.bridge_exit_height),
        ],
        32,
    )
}

fn source_root(
    kind: BlockerKind,
    owner_lane: OwnerLane,
    canonical_transcript_root: &str,
    transfer_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-SOURCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_lane.as_str()),
            HashPart::Str(canonical_transcript_root),
            HashPart::Str(transfer_id),
        ],
        32,
    )
}

fn evidence_root(
    kind: BlockerKind,
    status: BlockerStatus,
    wallet_evidence_root: &str,
    source_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-EVIDENCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(wallet_evidence_root),
            HashPart::Str(source_root),
        ],
        32,
    )
}

fn acceptance_root(
    kind: BlockerKind,
    severity: BlockerSeverity,
    owner_lane: OwnerLane,
    clearing_order: u64,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-ACCEPTANCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(owner_lane.as_str()),
            HashPart::U64(clearing_order),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn matrix_state_root(
    config_root: &str,
    devnet_data_root: &str,
    blocker_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-MATRIX-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(devnet_data_root),
            HashPart::Str(blocker_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-MATRIX-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn named_root(kind: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RELEASE-BLOCKER-MATRIX-NAMED-ROOT",
        &[HashPart::Str(kind), HashPart::Str(value)],
        32,
    )
}

fn fallback_state(error: &str) -> State {
    let config = Config::devnet();
    let devnet_data = devnet_data(&config);
    let fallback_record = json!({
        "error": error,
        "chain_id": config.chain_id,
        "protocol_version": config.protocol_version,
    });
    let fallback_root = record_root("fallback", &fallback_record);
    let summary = MatrixSummary {
        disposition: ReleaseDisposition::Blocked,
        blocker_count: 0,
        open_blocker_count: 0,
        production_blocker_count: 0,
        max_severity: BlockerSeverity::ReleaseStop,
        clearing_order_root: fallback_root.clone(),
        owner_lane_root: fallback_root.clone(),
        blocker_root: fallback_root.clone(),
    };
    let config_root = config.state_root();
    let devnet_data_root = devnet_data.state_root();
    let summary_root = summary.state_root();
    let public_record_root = record_root("fallback-public-record", &fallback_record);
    let state_root = matrix_state_root(
        &config_root,
        &devnet_data_root,
        &fallback_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        devnet_data,
        blockers: Vec::new(),
        summary,
        config_root,
        devnet_data_root,
        blocker_root: fallback_root,
        summary_root,
        public_record_root,
        state_root,
    }
}
