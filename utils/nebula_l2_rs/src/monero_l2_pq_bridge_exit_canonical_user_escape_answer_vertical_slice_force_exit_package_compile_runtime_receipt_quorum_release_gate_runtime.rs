use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeReceiptQuorumReleaseGateRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_RECEIPT_QUORUM_RELEASE_GATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-receipt-quorum-release-gate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_RECEIPT_QUORUM_RELEASE_GATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_GATE_SUITE: &str =
    "monero-l2-pq-force-exit-package-compile-runtime-receipt-quorum-release-gate-v1";
pub const DEFAULT_MIN_COMPILE_RECEIPTS: u64 = 3;
pub const DEFAULT_MIN_RUNTIME_REPLAY_RECEIPTS: u64 = 3;
pub const DEFAULT_MIN_REVIEWER_QUORUM: u64 = 4;
pub const DEFAULT_MAX_RECEIPT_AGE_BLOCKS: u64 = 144;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_gate_suite: String,
    pub min_compile_receipts: u64,
    pub min_runtime_replay_receipts: u64,
    pub min_reviewer_quorum: u64,
    pub max_receipt_age_blocks: u64,
    pub require_cargo_check_receipt: bool,
    pub require_cargo_test_receipt: bool,
    pub require_clippy_receipt: bool,
    pub require_runtime_replay_receipts: bool,
    pub require_reviewer_quorum: bool,
    pub require_threshold_evidence: bool,
    pub reject_stale_receipts: bool,
    pub require_replacement_manifest_root: bool,
    pub fail_closed_in_production: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_gate_suite: RELEASE_GATE_SUITE.to_string(),
            min_compile_receipts: DEFAULT_MIN_COMPILE_RECEIPTS,
            min_runtime_replay_receipts: DEFAULT_MIN_RUNTIME_REPLAY_RECEIPTS,
            min_reviewer_quorum: DEFAULT_MIN_REVIEWER_QUORUM,
            max_receipt_age_blocks: DEFAULT_MAX_RECEIPT_AGE_BLOCKS,
            require_cargo_check_receipt: true,
            require_cargo_test_receipt: true,
            require_clippy_receipt: true,
            require_runtime_replay_receipts: true,
            require_reviewer_quorum: true,
            require_threshold_evidence: true,
            reject_stale_receipts: true,
            require_replacement_manifest_root: true,
            fail_closed_in_production: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_compile_family_count(&self) -> u64 {
        [
            self.require_cargo_check_receipt,
            self.require_cargo_test_receipt,
            self.require_clippy_receipt,
        ]
        .iter()
        .filter(|required| **required)
        .count() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_gate_suite": self.release_gate_suite,
            "min_compile_receipts": self.min_compile_receipts,
            "min_runtime_replay_receipts": self.min_runtime_replay_receipts,
            "min_reviewer_quorum": self.min_reviewer_quorum,
            "max_receipt_age_blocks": self.max_receipt_age_blocks,
            "required_compile_family_count": self.required_compile_family_count(),
            "require_cargo_check_receipt": self.require_cargo_check_receipt,
            "require_cargo_test_receipt": self.require_cargo_test_receipt,
            "require_clippy_receipt": self.require_clippy_receipt,
            "require_runtime_replay_receipts": self.require_runtime_replay_receipts,
            "require_reviewer_quorum": self.require_reviewer_quorum,
            "require_threshold_evidence": self.require_threshold_evidence,
            "reject_stale_receipts": self.reject_stale_receipts,
            "require_replacement_manifest_root": self.require_replacement_manifest_root,
            "fail_closed_in_production": self.fail_closed_in_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateLane {
    CargoCheck,
    CargoTest,
    Clippy,
    RuntimeReplay,
    ReviewerQuorum,
    ThresholdEvidence,
    ReplacementManifest,
}

impl GateLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::Clippy => "clippy",
            Self::RuntimeReplay => "runtime_replay",
            Self::ReviewerQuorum => "reviewer_quorum",
            Self::ThresholdEvidence => "threshold_evidence",
            Self::ReplacementManifest => "replacement_manifest",
        }
    }

    pub fn ordered() -> &'static [Self] {
        &[
            Self::CargoCheck,
            Self::CargoTest,
            Self::Clippy,
            Self::RuntimeReplay,
            Self::ReviewerQuorum,
            Self::ThresholdEvidence,
            Self::ReplacementManifest,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Accepted,
    HeldForQuorum,
    RejectedStaleReceipt,
    MissingReplacementManifest,
    FailClosedProduction,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::HeldForQuorum => "held_for_quorum",
            Self::RejectedStaleReceipt => "rejected_stale_receipt",
            Self::MissingReplacementManifest => "missing_replacement_manifest",
            Self::FailClosedProduction => "fail_closed_production",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateReceipt {
    pub receipt_id: String,
    pub lane: GateLane,
    pub receipt_root: String,
    pub replay_receipt_root: String,
    pub reviewer_quorum_root: String,
    pub threshold_evidence_root: String,
    pub replacement_manifest_root: String,
    pub observed_height: u64,
    pub current_height: u64,
    pub status: GateStatus,
    pub stale_rejected: bool,
    pub release_blocked: bool,
}

impl GateReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GateLane,
        receipt_root: &str,
        replay_receipt_root: &str,
        reviewer_quorum_root: &str,
        threshold_evidence_root: &str,
        replacement_manifest_root: &str,
        observed_height: u64,
        current_height: u64,
        config: &Config,
    ) -> Self {
        let age = current_height.saturating_sub(observed_height);
        let stale_rejected = config.reject_stale_receipts && age > config.max_receipt_age_blocks;
        let status = if stale_rejected {
            GateStatus::RejectedStaleReceipt
        } else if config.require_replacement_manifest_root && replacement_manifest_root.is_empty() {
            GateStatus::MissingReplacementManifest
        } else if config.fail_closed_in_production
            && (reviewer_quorum_root.is_empty() || threshold_evidence_root.is_empty())
        {
            GateStatus::FailClosedProduction
        } else if receipt_root.is_empty() {
            GateStatus::HeldForQuorum
        } else {
            GateStatus::Accepted
        };
        let release_blocked = status.blocks_release();
        let receipt_id = gate_receipt_id(
            lane,
            receipt_root,
            replay_receipt_root,
            reviewer_quorum_root,
            threshold_evidence_root,
            replacement_manifest_root,
            observed_height,
            current_height,
            status,
        );
        Self {
            receipt_id,
            lane,
            receipt_root: receipt_root.to_string(),
            replay_receipt_root: replay_receipt_root.to_string(),
            reviewer_quorum_root: reviewer_quorum_root.to_string(),
            threshold_evidence_root: threshold_evidence_root.to_string(),
            replacement_manifest_root: replacement_manifest_root.to_string(),
            observed_height,
            current_height,
            status,
            stale_rejected,
            release_blocked,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "receipt_root": self.receipt_root,
            "replay_receipt_root": self.replay_receipt_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "threshold_evidence_root": self.threshold_evidence_root,
            "replacement_manifest_root": self.replacement_manifest_root,
            "observed_height": self.observed_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
            "stale_rejected": self.stale_rejected,
            "release_blocked": self.release_blocked,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub total_gate_receipts: u64,
    pub accepted_gate_receipts: u64,
    pub compile_receipt_roots: u64,
    pub runtime_replay_receipt_roots: u64,
    pub reviewer_quorum_roots: u64,
    pub threshold_evidence_roots: u64,
    pub stale_rejected_receipts: u64,
    pub replacement_manifest_roots: u64,
    pub release_blockers: u64,
}

impl Counters {
    pub fn from_receipts(receipts: &[GateReceipt]) -> Self {
        Self {
            total_gate_receipts: receipts.len() as u64,
            accepted_gate_receipts: receipts
                .iter()
                .filter(|receipt| receipt.status == GateStatus::Accepted)
                .count() as u64,
            compile_receipt_roots: receipts
                .iter()
                .filter(|receipt| {
                    matches!(
                        receipt.lane,
                        GateLane::CargoCheck | GateLane::CargoTest | GateLane::Clippy
                    ) && !receipt.receipt_root.is_empty()
                })
                .count() as u64,
            runtime_replay_receipt_roots: receipts
                .iter()
                .filter(|receipt| !receipt.replay_receipt_root.is_empty())
                .count() as u64,
            reviewer_quorum_roots: receipts
                .iter()
                .filter(|receipt| !receipt.reviewer_quorum_root.is_empty())
                .count() as u64,
            threshold_evidence_roots: receipts
                .iter()
                .filter(|receipt| !receipt.threshold_evidence_root.is_empty())
                .count() as u64,
            stale_rejected_receipts: receipts
                .iter()
                .filter(|receipt| receipt.stale_rejected)
                .count() as u64,
            replacement_manifest_roots: receipts
                .iter()
                .filter(|receipt| !receipt.replacement_manifest_root.is_empty())
                .count() as u64,
            release_blockers: receipts
                .iter()
                .filter(|receipt| receipt.release_blocked)
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_gate_receipts": self.total_gate_receipts,
            "accepted_gate_receipts": self.accepted_gate_receipts,
            "compile_receipt_roots": self.compile_receipt_roots,
            "runtime_replay_receipt_roots": self.runtime_replay_receipt_roots,
            "reviewer_quorum_roots": self.reviewer_quorum_roots,
            "threshold_evidence_roots": self.threshold_evidence_roots,
            "stale_rejected_receipts": self.stale_rejected_receipts,
            "replacement_manifest_roots": self.replacement_manifest_roots,
            "release_blockers": self.release_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub gate_receipt_root: String,
    pub compile_receipt_root: String,
    pub runtime_replay_receipt_root: String,
    pub reviewer_quorum_root: String,
    pub threshold_evidence_root: String,
    pub stale_rejection_root: String,
    pub replacement_manifest_root: String,
    pub counters_root: String,
    pub verdict_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn from_parts(config: &Config, receipts: &[GateReceipt], counters: &Counters) -> Self {
        let gate_records = receipts
            .iter()
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let compile_records = receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.lane,
                    GateLane::CargoCheck | GateLane::CargoTest | GateLane::Clippy
                )
            })
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let replay_records = receipts
            .iter()
            .filter(|receipt| receipt.lane == GateLane::RuntimeReplay)
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let quorum_records = receipts
            .iter()
            .filter(|receipt| !receipt.reviewer_quorum_root.is_empty())
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let threshold_records = receipts
            .iter()
            .filter(|receipt| !receipt.threshold_evidence_root.is_empty())
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let stale_records = receipts
            .iter()
            .filter(|receipt| receipt.stale_rejected)
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let manifest_records = receipts
            .iter()
            .filter(|receipt| !receipt.replacement_manifest_root.is_empty())
            .map(GateReceipt::public_record)
            .collect::<Vec<_>>();
        let config_root = config.state_root();
        let gate_receipt_root = merkle_root("RELEASE-GATE-RECEIPTS", &gate_records);
        let compile_receipt_root = merkle_root("RELEASE-GATE-COMPILE-RECEIPTS", &compile_records);
        let runtime_replay_receipt_root =
            merkle_root("RELEASE-GATE-RUNTIME-REPLAY-RECEIPTS", &replay_records);
        let reviewer_quorum_root = merkle_root("RELEASE-GATE-REVIEWER-QUORUM", &quorum_records);
        let threshold_evidence_root =
            merkle_root("RELEASE-GATE-THRESHOLD-EVIDENCE", &threshold_records);
        let stale_rejection_root = merkle_root("RELEASE-GATE-STALE-REJECTIONS", &stale_records);
        let replacement_manifest_root =
            merkle_root("RELEASE-GATE-REPLACEMENT-MANIFESTS", &manifest_records);
        let counters_root = counters.state_root();
        let verdict_root = release_gate_verdict_root(config, counters);
        let state_root = domain_hash(
            "RELEASE-GATE-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config_root),
                HashPart::Str(&gate_receipt_root),
                HashPart::Str(&compile_receipt_root),
                HashPart::Str(&runtime_replay_receipt_root),
                HashPart::Str(&reviewer_quorum_root),
                HashPart::Str(&threshold_evidence_root),
                HashPart::Str(&stale_rejection_root),
                HashPart::Str(&replacement_manifest_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&verdict_root),
            ],
            32,
        );
        Self {
            config_root,
            gate_receipt_root,
            compile_receipt_root,
            runtime_replay_receipt_root,
            reviewer_quorum_root,
            threshold_evidence_root,
            stale_rejection_root,
            replacement_manifest_root,
            counters_root,
            verdict_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "gate_receipt_root": self.gate_receipt_root,
            "compile_receipt_root": self.compile_receipt_root,
            "runtime_replay_receipt_root": self.runtime_replay_receipt_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "threshold_evidence_root": self.threshold_evidence_root,
            "stale_rejection_root": self.stale_rejection_root,
            "replacement_manifest_root": self.replacement_manifest_root,
            "counters_root": self.counters_root,
            "verdict_root": self.verdict_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGateVerdict {
    pub verdict_id: String,
    pub status: String,
    pub hold_release_verdict: String,
    pub production_status: String,
    pub release_allowed: bool,
    pub production_fail_closed: bool,
    pub stale_receipt_rejected: bool,
    pub replacement_manifest_required: bool,
    pub replacement_manifest_observed: bool,
}

impl ReleaseGateVerdict {
    pub fn from_parts(config: &Config, counters: &Counters, roots: &Roots) -> Self {
        let compile_ready = counters.compile_receipt_roots >= config.min_compile_receipts;
        let replay_ready =
            counters.runtime_replay_receipt_roots >= config.min_runtime_replay_receipts;
        let quorum_ready = counters.reviewer_quorum_roots >= config.min_reviewer_quorum;
        let threshold_ready =
            !config.require_threshold_evidence || counters.threshold_evidence_roots > 0;
        let replacement_manifest_observed = counters.replacement_manifest_roots > 0;
        let manifest_ready =
            !config.require_replacement_manifest_root || replacement_manifest_observed;
        let stale_receipt_rejected = counters.stale_rejected_receipts > 0;
        let release_allowed = compile_ready
            && replay_ready
            && quorum_ready
            && threshold_ready
            && manifest_ready
            && !stale_receipt_rejected
            && counters.release_blockers == 0;
        let production_fail_closed = config.fail_closed_in_production && !release_allowed;
        let status = if production_fail_closed {
            "fail_closed_production"
        } else if release_allowed {
            "release"
        } else {
            "hold"
        }
        .to_string();
        let hold_release_verdict = if release_allowed {
            "release_compile_runtime_receipt_quorum_gate"
        } else {
            "hold_until_compile_runtime_receipt_quorum_manifest_is_live"
        }
        .to_string();
        let production_status = if production_fail_closed {
            "production_fail_closed_until_fresh_receipt_quorum_release_gate_passes"
        } else {
            "production_release_gate_passed"
        }
        .to_string();
        let verdict_id = domain_hash(
            "RELEASE-GATE-VERDICT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&roots.gate_receipt_root),
                HashPart::Str(&roots.compile_receipt_root),
                HashPart::Str(&roots.runtime_replay_receipt_root),
                HashPart::Str(&roots.reviewer_quorum_root),
                HashPart::Str(&roots.threshold_evidence_root),
                HashPart::Str(&roots.stale_rejection_root),
                HashPart::Str(&roots.replacement_manifest_root),
                HashPart::Json(&counters.public_record()),
                HashPart::Str(&status),
            ],
            32,
        );
        Self {
            verdict_id,
            status,
            hold_release_verdict,
            production_status,
            release_allowed,
            production_fail_closed,
            stale_receipt_rejected,
            replacement_manifest_required: config.require_replacement_manifest_root,
            replacement_manifest_observed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "status": self.status,
            "hold_release_verdict": self.hold_release_verdict,
            "production_status": self.production_status,
            "release_allowed": self.release_allowed,
            "production_fail_closed": self.production_fail_closed,
            "stale_receipt_rejected": self.stale_receipt_rejected,
            "replacement_manifest_required": self.replacement_manifest_required,
            "replacement_manifest_observed": self.replacement_manifest_observed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub gate_receipts: Vec<GateReceipt>,
    pub counters: Counters,
    pub roots: Roots,
    pub verdict: ReleaseGateVerdict,
}

impl State {
    pub fn new(config: Config, gate_receipts: Vec<GateReceipt>) -> Result<Self> {
        validate_config(&config)?;
        let counters = Counters::from_receipts(&gate_receipts);
        let roots = Roots::from_parts(&config, &gate_receipts, &counters);
        let verdict = ReleaseGateVerdict::from_parts(&config, &counters, &roots);
        Ok(Self {
            config,
            gate_receipts,
            counters,
            roots,
            verdict,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet(), devnet_gate_receipts()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn production_hold(&self) -> bool {
        !self.verdict.release_allowed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "gate_receipts": self
                .gate_receipts
                .iter()
                .map(GateReceipt::public_record)
                .collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "verdict": self.verdict.public_record(),
            "production_hold": self.production_hold(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

fn devnet_gate_receipts() -> Vec<GateReceipt> {
    let config = Config::devnet();
    let current_height = 77;
    GateLane::ordered()
        .iter()
        .enumerate()
        .map(|(index, lane)| {
            let lane_label = lane.as_str();
            GateReceipt::new(
                *lane,
                &fixture_root("receipt", lane_label),
                &fixture_root("runtime-replay", lane_label),
                &fixture_root("reviewer-quorum", lane_label),
                &fixture_root("threshold-evidence", lane_label),
                &fixture_root("replacement-manifest", lane_label),
                current_height.saturating_sub(index as u64),
                current_height,
                &config,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn gate_receipt_id(
    lane: GateLane,
    receipt_root: &str,
    replay_receipt_root: &str,
    reviewer_quorum_root: &str,
    threshold_evidence_root: &str,
    replacement_manifest_root: &str,
    observed_height: u64,
    current_height: u64,
    status: GateStatus,
) -> String {
    domain_hash(
        "RELEASE-GATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(receipt_root),
            HashPart::Str(replay_receipt_root),
            HashPart::Str(reviewer_quorum_root),
            HashPart::Str(threshold_evidence_root),
            HashPart::Str(replacement_manifest_root),
            HashPart::U64(observed_height),
            HashPart::U64(current_height),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

pub fn release_gate_verdict_root(config: &Config, counters: &Counters) -> String {
    domain_hash(
        "RELEASE-GATE-VERDICT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&config.public_record()),
            HashPart::Json(&counters.public_record()),
        ],
        32,
    )
}

pub fn fixture_root(kind: &str, value: &str) -> String {
    domain_hash(
        "RELEASE-GATE-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "RELEASE-GATE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("compile runtime receipt quorum release gate chain mismatch".to_string());
    }
    if config.protocol_version != PROTOCOL_VERSION {
        return Err("compile runtime receipt quorum release gate protocol mismatch".to_string());
    }
    if config.min_compile_receipts == 0 {
        return Err(
            "compile runtime receipt quorum release gate requires compile receipts".to_string(),
        );
    }
    if config.min_runtime_replay_receipts == 0 {
        return Err(
            "compile runtime receipt quorum release gate requires runtime replay receipts"
                .to_string(),
        );
    }
    if config.min_reviewer_quorum == 0 {
        return Err(
            "compile runtime receipt quorum release gate requires reviewer quorum".to_string(),
        );
    }
    Ok(())
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let current_height = 1;
    let receipt = GateReceipt::new(
        GateLane::ReplacementManifest,
        &fixture_root("fallback-receipt", &reason),
        "",
        "",
        "",
        "",
        current_height,
        current_height,
        &config,
    );
    let gate_receipts = vec![receipt];
    let counters = Counters::from_receipts(&gate_receipts);
    let roots = Roots::from_parts(&config, &gate_receipts, &counters);
    let verdict = ReleaseGateVerdict::from_parts(&config, &counters, &roots);
    State {
        config,
        gate_receipts,
        counters,
        roots,
        verdict,
    }
}
