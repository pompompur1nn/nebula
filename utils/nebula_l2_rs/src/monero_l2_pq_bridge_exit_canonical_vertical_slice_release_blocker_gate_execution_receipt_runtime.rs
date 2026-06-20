use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerGateExecutionReceiptRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-execution-receipts-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-candidate-devnet-v1";
pub const REQUIRED_RECEIPT_ENVELOPES: usize = 12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptEnvelopeKind {
    CargoRuntimeDeferred,
    LiveFeedSwapMissing,
    ForcedExitDrillMissing,
    IndependentAuditOpen,
    PrivacyLeakageReviewOpen,
    PqVerificationPending,
    ReserveProofMissing,
    ProductionReleaseHeld,
    ExpectedNoGoRoots,
    OperatorEvidenceRoot,
    WalletVisibleNoGoRoot,
    FailClosedReceiptRoot,
}

impl ReceiptEnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::LiveFeedSwapMissing => "live_feed_swap_missing",
            Self::ForcedExitDrillMissing => "forced_exit_drill_missing",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::PrivacyLeakageReviewOpen => "privacy_leakage_review_open",
            Self::PqVerificationPending => "pq_verification_pending",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::ProductionReleaseHeld => "production_release_held",
            Self::ExpectedNoGoRoots => "expected_no_go_roots",
            Self::OperatorEvidenceRoot => "operator_evidence_root",
            Self::WalletVisibleNoGoRoot => "wallet_visible_no_go_root",
            Self::FailClosedReceiptRoot => "fail_closed_receipt_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAudience {
    CargoRuntime,
    Operator,
    Wallet,
    Auditor,
    ReleaseGovernance,
}

impl ReceiptAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntime => "cargo_runtime",
            Self::Operator => "operator",
            Self::Wallet => "wallet",
            Self::Auditor => "auditor",
            Self::ReleaseGovernance => "release_governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDecision {
    NoGo,
}

impl ReceiptDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHold {
    Held,
}

impl ReleaseHold {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub required_receipt_envelopes: usize,
    pub cargo_runtime_execution_allowed: bool,
    pub release_execution_allowed: bool,
    pub fail_closed_on_missing_receipt: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            required_receipt_envelopes: REQUIRED_RECEIPT_ENVELOPES,
            cargo_runtime_execution_allowed: false,
            release_execution_allowed: false,
            fail_closed_on_missing_receipt: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_suite": self.receipt_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "required_receipt_envelopes": self.required_receipt_envelopes,
            "cargo_runtime_execution_allowed": self.cargo_runtime_execution_allowed,
            "release_execution_allowed": self.release_execution_allowed,
            "fail_closed_on_missing_receipt": self.fail_closed_on_missing_receipt,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEnvelope {
    pub envelope_id: String,
    pub sequence: u64,
    pub kind: ReceiptEnvelopeKind,
    pub audience: ReceiptAudience,
    pub decision: ReceiptDecision,
    pub observed_status: String,
    pub blocked_execution: String,
    pub required_clearance: String,
    pub source_root: String,
    pub no_go_root: String,
    pub receipt_root: String,
    pub cargo_runtime_deferred: bool,
    pub release_blocked: bool,
}

impl ReceiptEnvelope {
    pub fn new(
        sequence: u64,
        kind: ReceiptEnvelopeKind,
        audience: ReceiptAudience,
        observed_status: impl Into<String>,
        blocked_execution: impl Into<String>,
        required_clearance: impl Into<String>,
    ) -> Self {
        let decision = ReceiptDecision::NoGo;
        let observed_status = observed_status.into();
        let blocked_execution = blocked_execution.into();
        let required_clearance = required_clearance.into();
        let source_root = source_root(
            sequence,
            kind,
            audience,
            &observed_status,
            &blocked_execution,
            &required_clearance,
        );
        let no_go_root = no_go_root(
            sequence,
            kind,
            audience,
            decision,
            &observed_status,
            &blocked_execution,
            &required_clearance,
            &source_root,
        );
        let receipt_root = receipt_root(
            sequence,
            kind,
            audience,
            decision,
            &source_root,
            &no_go_root,
        );
        let envelope_id = envelope_id(sequence, kind, &receipt_root);

        Self {
            envelope_id,
            sequence,
            kind,
            audience,
            decision,
            observed_status,
            blocked_execution,
            required_clearance,
            source_root,
            no_go_root,
            receipt_root,
            cargo_runtime_deferred: true,
            release_blocked: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "audience": self.audience.as_str(),
            "decision": self.decision.as_str(),
            "observed_status": self.observed_status,
            "blocked_execution": self.blocked_execution,
            "required_clearance": self.required_clearance,
            "source_root": self.source_root,
            "no_go_root": self.no_go_root,
            "receipt_root": self.receipt_root,
            "cargo_runtime_deferred": self.cargo_runtime_deferred,
            "release_blocked": self.release_blocked,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_envelope", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptSummary {
    pub decision: ReceiptDecision,
    pub release_hold: ReleaseHold,
    pub envelope_count: usize,
    pub cargo_runtime_deferred_count: usize,
    pub release_blocked_count: usize,
    pub expected_no_go_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_no_go_root: String,
    pub fail_closed_receipt_root: String,
    pub release_hold_root: String,
}

impl ReceiptSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "release_hold": self.release_hold.as_str(),
            "envelope_count": self.envelope_count,
            "cargo_runtime_deferred_count": self.cargo_runtime_deferred_count,
            "release_blocked_count": self.release_blocked_count,
            "expected_no_go_root": self.expected_no_go_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_no_go_root": self.wallet_visible_no_go_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "release_hold_root": self.release_hold_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipt_envelopes: BTreeMap<String, ReceiptEnvelope>,
    pub summary: ReceiptSummary,
    pub cargo_runtime_deferred_root: String,
    pub live_feed_swap_missing_root: String,
    pub forced_exit_drill_missing_root: String,
    pub independent_audit_open_root: String,
    pub privacy_leakage_review_open_root: String,
    pub pq_verification_pending_root: String,
    pub reserve_proof_missing_root: String,
    pub production_release_held_root: String,
    pub expected_no_go_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_no_go_root: String,
    pub fail_closed_receipt_root: String,
    pub release_hold_root: String,
    pub config_root: String,
    pub envelope_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        match Self::try_devnet() {
            Ok(state) => state,
            Err(error) => fallback_state(error),
        }
    }

    pub fn try_devnet() -> Result<Self> {
        let config = Config::devnet();
        let receipt_envelopes = deterministic_receipt_envelopes();
        if receipt_envelopes.len() != config.required_receipt_envelopes {
            return Err(
                "release-blocker execution receipt envelope cardinality mismatch".to_string(),
            );
        }

        let cargo_runtime_deferred_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::CargoRuntimeDeferred,
            "CARGO-RUNTIME-DEFERRED",
        );
        let live_feed_swap_missing_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::LiveFeedSwapMissing,
            "LIVE-FEED-SWAP-MISSING",
        );
        let forced_exit_drill_missing_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::ForcedExitDrillMissing,
            "FORCED-EXIT-DRILL-MISSING",
        );
        let independent_audit_open_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::IndependentAuditOpen,
            "INDEPENDENT-AUDIT-OPEN",
        );
        let privacy_leakage_review_open_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::PrivacyLeakageReviewOpen,
            "PRIVACY-LEAKAGE-REVIEW-OPEN",
        );
        let pq_verification_pending_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::PqVerificationPending,
            "PQ-VERIFICATION-PENDING",
        );
        let reserve_proof_missing_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::ReserveProofMissing,
            "RESERVE-PROOF-MISSING",
        );
        let production_release_held_root = kind_root(
            &receipt_envelopes,
            ReceiptEnvelopeKind::ProductionReleaseHeld,
            "PRODUCTION-RELEASE-HELD",
        );
        let expected_no_go_root = expected_no_go_root(&receipt_envelopes);
        let operator_evidence_root = audience_root(&receipt_envelopes, ReceiptAudience::Operator);
        let wallet_visible_no_go_root = audience_root(&receipt_envelopes, ReceiptAudience::Wallet);
        let fail_closed_receipt_root = fail_closed_receipt_root(
            &expected_no_go_root,
            &operator_evidence_root,
            &wallet_visible_no_go_root,
        );
        let release_hold_root = release_hold_root(&expected_no_go_root, &fail_closed_receipt_root);
        let summary = summarize_receipts(
            &receipt_envelopes,
            &expected_no_go_root,
            &operator_evidence_root,
            &wallet_visible_no_go_root,
            &fail_closed_receipt_root,
            &release_hold_root,
        );
        let config_root = config.state_root();
        let envelope_records = envelope_records(&receipt_envelopes);
        let envelope_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-ENVELOPES",
            &envelope_records,
        );
        let summary_root = summary.state_root();
        let public_record = state_public_record(
            &config,
            &receipt_envelopes,
            &summary,
            &config_root,
            &envelope_root,
            &expected_no_go_root,
            &operator_evidence_root,
            &wallet_visible_no_go_root,
            &fail_closed_receipt_root,
            &release_hold_root,
            &summary_root,
        );
        let public_record_root = record_root("state_public_record", &public_record);
        let state_root = execution_receipt_state_root(
            &config_root,
            &envelope_root,
            &expected_no_go_root,
            &operator_evidence_root,
            &wallet_visible_no_go_root,
            &fail_closed_receipt_root,
            &release_hold_root,
            &summary_root,
            &public_record_root,
        );

        Ok(Self {
            config,
            receipt_envelopes,
            summary,
            cargo_runtime_deferred_root,
            live_feed_swap_missing_root,
            forced_exit_drill_missing_root,
            independent_audit_open_root,
            privacy_leakage_review_open_root,
            pq_verification_pending_root,
            reserve_proof_missing_root,
            production_release_held_root,
            expected_no_go_root,
            operator_evidence_root,
            wallet_visible_no_go_root,
            fail_closed_receipt_root,
            release_hold_root,
            config_root,
            envelope_root,
            summary_root,
            public_record_root,
            state_root,
        })
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.receipt_envelopes,
            &self.summary,
            &self.config_root,
            &self.envelope_root,
            &self.expected_no_go_root,
            &self.operator_evidence_root,
            &self.wallet_visible_no_go_root,
            &self.fail_closed_receipt_root,
            &self.release_hold_root,
            &self.summary_root,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
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

fn deterministic_receipt_envelopes() -> BTreeMap<String, ReceiptEnvelope> {
    let envelopes = vec![
        ReceiptEnvelope::new(
            1,
            ReceiptEnvelopeKind::CargoRuntimeDeferred,
            ReceiptAudience::CargoRuntime,
            "cargo_runtime_execution_deferred",
            "release_blocker_gate_runtime_execution",
            "enable cargo-family verification and archive deterministic runtime receipt",
        ),
        ReceiptEnvelope::new(
            2,
            ReceiptEnvelopeKind::LiveFeedSwapMissing,
            ReceiptAudience::Operator,
            "fixture_feed_still_bound",
            "live_bridge_exit_feed",
            "swap fixture feed roots to live feed roots and bind handoff evidence",
        ),
        ReceiptEnvelope::new(
            3,
            ReceiptEnvelopeKind::ForcedExitDrillMissing,
            ReceiptAudience::Operator,
            "forced_exit_drill_receipt_missing",
            "forced_exit_spine_release",
            "run forced-exit drill and publish replay transcript root",
        ),
        ReceiptEnvelope::new(
            4,
            ReceiptEnvelopeKind::IndependentAuditOpen,
            ReceiptAudience::Auditor,
            "independent_audit_signoff_open",
            "production_release_candidate",
            "attach independent audit completion receipt",
        ),
        ReceiptEnvelope::new(
            5,
            ReceiptEnvelopeKind::PrivacyLeakageReviewOpen,
            ReceiptAudience::Auditor,
            "privacy_leakage_review_open",
            "wallet_visible_exit_metadata",
            "attach privacy leakage review closure receipt",
        ),
        ReceiptEnvelope::new(
            6,
            ReceiptEnvelopeKind::PqVerificationPending,
            ReceiptAudience::Operator,
            "pq_key_verification_pending",
            "post_quantum_bridge_exit_keys",
            "verify PQ key bundle and bind verification receipt",
        ),
        ReceiptEnvelope::new(
            7,
            ReceiptEnvelopeKind::ReserveProofMissing,
            ReceiptAudience::Operator,
            "reserve_proof_receipt_missing",
            "reserve_backed_exit_release",
            "publish reserve proof ownership and handoff receipt",
        ),
        ReceiptEnvelope::new(
            8,
            ReceiptEnvelopeKind::ProductionReleaseHeld,
            ReceiptAudience::ReleaseGovernance,
            "production_release_hold_active",
            "production_release",
            "clear every blocker envelope before replacing no-go roots",
        ),
        ReceiptEnvelope::new(
            9,
            ReceiptEnvelopeKind::ExpectedNoGoRoots,
            ReceiptAudience::ReleaseGovernance,
            "expected_no_go_roots_preserved",
            "go_decision_substitution",
            "retain expected no-go roots until cargo/runtime execution is allowed",
        ),
        ReceiptEnvelope::new(
            10,
            ReceiptEnvelopeKind::OperatorEvidenceRoot,
            ReceiptAudience::Operator,
            "operator_evidence_root_pending_clearance",
            "operator_release_attestation",
            "bind operator evidence root after live execution receipts exist",
        ),
        ReceiptEnvelope::new(
            11,
            ReceiptEnvelopeKind::WalletVisibleNoGoRoot,
            ReceiptAudience::Wallet,
            "wallet_visible_no_go_root_active",
            "wallet_release_surface",
            "show wallet-visible no-go root until release blocker gates clear",
        ),
        ReceiptEnvelope::new(
            12,
            ReceiptEnvelopeKind::FailClosedReceiptRoot,
            ReceiptAudience::ReleaseGovernance,
            "fail_closed_receipt_root_active",
            "release_blocker_gate_bypass",
            "fail closed whenever a required execution receipt is absent",
        ),
    ];

    envelopes
        .into_iter()
        .map(|envelope| (envelope.kind.as_str().to_string(), envelope))
        .collect()
}

fn envelope_records(envelopes: &BTreeMap<String, ReceiptEnvelope>) -> Vec<Value> {
    envelopes
        .values()
        .map(ReceiptEnvelope::public_record)
        .collect()
}

fn expected_no_go_records(envelopes: &BTreeMap<String, ReceiptEnvelope>) -> Vec<Value> {
    envelopes
        .values()
        .map(|envelope| {
            json!({
                "kind": envelope.kind.as_str(),
                "audience": envelope.audience.as_str(),
                "decision": envelope.decision.as_str(),
                "no_go_root": envelope.no_go_root,
            })
        })
        .collect()
}

fn audience_records(
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    audience: ReceiptAudience,
) -> Vec<Value> {
    envelopes
        .values()
        .filter(|envelope| envelope.audience == audience)
        .map(|envelope| {
            json!({
                "envelope_id": envelope.envelope_id,
                "kind": envelope.kind.as_str(),
                "audience": envelope.audience.as_str(),
                "receipt_root": envelope.receipt_root,
                "no_go_root": envelope.no_go_root,
            })
        })
        .collect()
}

fn kind_records(
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    kind: ReceiptEnvelopeKind,
) -> Vec<Value> {
    envelopes
        .values()
        .filter(|envelope| envelope.kind == kind)
        .map(ReceiptEnvelope::public_record)
        .collect()
}

fn summarize_receipts(
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    expected_no_go_root: &str,
    operator_evidence_root: &str,
    wallet_visible_no_go_root: &str,
    fail_closed_receipt_root: &str,
    release_hold_root: &str,
) -> ReceiptSummary {
    let cargo_runtime_deferred_count = envelopes
        .values()
        .filter(|envelope| envelope.cargo_runtime_deferred)
        .count();
    let release_blocked_count = envelopes
        .values()
        .filter(|envelope| envelope.release_blocked)
        .count();

    ReceiptSummary {
        decision: ReceiptDecision::NoGo,
        release_hold: ReleaseHold::Held,
        envelope_count: envelopes.len(),
        cargo_runtime_deferred_count,
        release_blocked_count,
        expected_no_go_root: expected_no_go_root.to_string(),
        operator_evidence_root: operator_evidence_root.to_string(),
        wallet_visible_no_go_root: wallet_visible_no_go_root.to_string(),
        fail_closed_receipt_root: fail_closed_receipt_root.to_string(),
        release_hold_root: release_hold_root.to_string(),
    }
}

fn state_public_record(
    config: &Config,
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    summary: &ReceiptSummary,
    config_root: &str,
    envelope_root: &str,
    expected_no_go_root: &str,
    operator_evidence_root: &str,
    wallet_visible_no_go_root: &str,
    fail_closed_receipt_root: &str,
    release_hold_root: &str,
    summary_root: &str,
) -> Value {
    json!({
        "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_execution_receipt_state",
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "config": config.public_record(),
        "receipt_envelopes": envelope_records(envelopes),
        "summary": summary.public_record(),
        "roots": {
            "config_root": config_root,
            "envelope_root": envelope_root,
            "expected_no_go_root": expected_no_go_root,
            "operator_evidence_root": operator_evidence_root,
            "wallet_visible_no_go_root": wallet_visible_no_go_root,
            "fail_closed_receipt_root": fail_closed_receipt_root,
            "release_hold_root": release_hold_root,
            "summary_root": summary_root,
        },
        "cargo_runtime_allowed": false,
        "release_allowed": false,
    })
}

fn source_root(
    sequence: u64,
    kind: ReceiptEnvelopeKind,
    audience: ReceiptAudience,
    observed_status: &str,
    blocked_execution: &str,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-SOURCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(audience.as_str()),
            HashPart::Str(observed_status),
            HashPart::Str(blocked_execution),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn no_go_root(
    sequence: u64,
    kind: ReceiptEnvelopeKind,
    audience: ReceiptAudience,
    decision: ReceiptDecision,
    observed_status: &str,
    blocked_execution: &str,
    required_clearance: &str,
    source_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-NO-GO",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(audience.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(observed_status),
            HashPart::Str(blocked_execution),
            HashPart::Str(required_clearance),
            HashPart::Str(source_root),
        ],
        32,
    )
}

fn receipt_root(
    sequence: u64,
    kind: ReceiptEnvelopeKind,
    audience: ReceiptAudience,
    decision: ReceiptDecision,
    source_root: &str,
    no_go_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(audience.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(no_go_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn envelope_id(sequence: u64, kind: ReceiptEnvelopeKind, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(receipt_root),
        ],
        16,
    )
}

fn kind_root(
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    kind: ReceiptEnvelopeKind,
    label: &str,
) -> String {
    let records = kind_records(envelopes, kind);
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-{label}"
        ),
        &records,
    )
}

fn expected_no_go_root(envelopes: &BTreeMap<String, ReceiptEnvelope>) -> String {
    let records = expected_no_go_records(envelopes);
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-EXPECTED-NO-GO",
        &records,
    )
}

fn audience_root(
    envelopes: &BTreeMap<String, ReceiptEnvelope>,
    audience: ReceiptAudience,
) -> String {
    let records = audience_records(envelopes, audience);
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-AUDIENCE-{}",
            audience.as_str()
        ),
        &records,
    )
}

fn fail_closed_receipt_root(
    expected_no_go_root: &str,
    operator_evidence_root: &str,
    wallet_visible_no_go_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-FAIL-CLOSED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ReceiptDecision::NoGo.as_str()),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(operator_evidence_root),
            HashPart::Str(wallet_visible_no_go_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn release_hold_root(expected_no_go_root: &str, fail_closed_receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-RELEASE-HOLD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ReleaseHold::Held.as_str()),
            HashPart::Str(ReceiptDecision::NoGo.as_str()),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(fail_closed_receipt_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn execution_receipt_state_root(
    config_root: &str,
    envelope_root: &str,
    expected_no_go_root: &str,
    operator_evidence_root: &str,
    wallet_visible_no_go_root: &str,
    fail_closed_receipt_root: &str,
    release_hold_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(envelope_root),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(operator_evidence_root),
            HashPart::Str(wallet_visible_no_go_root),
            HashPart::Str(fail_closed_receipt_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn fallback_state(error: String) -> State {
    let config = Config::devnet();
    let receipt_envelopes = BTreeMap::new();
    let fallback_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXECUTION-RECEIPT-FALLBACK",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&error),
        ],
        32,
    );
    let summary = ReceiptSummary {
        decision: ReceiptDecision::NoGo,
        release_hold: ReleaseHold::Held,
        envelope_count: 0,
        cargo_runtime_deferred_count: 0,
        release_blocked_count: 0,
        expected_no_go_root: fallback_root.clone(),
        operator_evidence_root: fallback_root.clone(),
        wallet_visible_no_go_root: fallback_root.clone(),
        fail_closed_receipt_root: fallback_root.clone(),
        release_hold_root: fallback_root.clone(),
    };
    let config_root = config.state_root();
    let envelope_root = fallback_root.clone();
    let expected_no_go_root = fallback_root.clone();
    let operator_evidence_root = fallback_root.clone();
    let wallet_visible_no_go_root = fallback_root.clone();
    let fail_closed_receipt_root = fallback_root.clone();
    let release_hold_root = fallback_root.clone();
    let summary_root = summary.state_root();
    let public_record = state_public_record(
        &config,
        &receipt_envelopes,
        &summary,
        &config_root,
        &envelope_root,
        &expected_no_go_root,
        &operator_evidence_root,
        &wallet_visible_no_go_root,
        &fail_closed_receipt_root,
        &release_hold_root,
        &summary_root,
    );
    let public_record_root = record_root("fallback_state_public_record", &public_record);
    let state_root = execution_receipt_state_root(
        &config_root,
        &envelope_root,
        &expected_no_go_root,
        &operator_evidence_root,
        &wallet_visible_no_go_root,
        &fail_closed_receipt_root,
        &release_hold_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        receipt_envelopes,
        summary,
        cargo_runtime_deferred_root: fallback_root.clone(),
        live_feed_swap_missing_root: fallback_root.clone(),
        forced_exit_drill_missing_root: fallback_root.clone(),
        independent_audit_open_root: fallback_root.clone(),
        privacy_leakage_review_open_root: fallback_root.clone(),
        pq_verification_pending_root: fallback_root.clone(),
        reserve_proof_missing_root: fallback_root.clone(),
        production_release_held_root: fallback_root.clone(),
        expected_no_go_root,
        operator_evidence_root,
        wallet_visible_no_go_root,
        fail_closed_receipt_root,
        release_hold_root,
        config_root,
        envelope_root,
        summary_root,
        public_record_root,
        state_root,
    }
}
