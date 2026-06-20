use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialReleaseReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-adversarial-release-receipt-v1";
pub const FAIL_CLOSED_POLICY: &str = "deny_release_on_any_receipt_guard_failure";
pub const DEFAULT_L2_HEIGHT: u64 = 4_260_224;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_530_224;
pub const DEFAULT_WALLET_EPOCH: u64 = 44;
pub const DEFAULT_MIN_FINALITY_DEPTH: u64 = 20;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_PQ_SIGNATURE_WEIGHT: u64 = 67;
pub const DEFAULT_METADATA_BUDGET_BYTES: u64 = 384;
pub const DEFAULT_MAX_WATCHER_CLUSTER_WEIGHT: u64 = 33;
pub const DEFAULT_REQUIRED_NEGATIVE_CASES: usize = 9;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-receipt-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReceiptCaseKind {
    SignedWrongInstruction,
    StaleWalletReceipt,
    BadBroadcastRoot,
    MissingPqSignature,
    LiquiditySettlementMismatch,
    ReorgSensitiveObservation,
    ReplayedReleaseReceipt,
    MetadataBudgetBreach,
    WatcherCollusionReceipt,
    PositiveControl,
}

impl ReleaseReceiptCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignedWrongInstruction => "signed_wrong_instruction",
            Self::StaleWalletReceipt => "stale_wallet_receipt",
            Self::BadBroadcastRoot => "bad_broadcast_root",
            Self::MissingPqSignature => "missing_pq_signature",
            Self::LiquiditySettlementMismatch => "liquidity_settlement_mismatch",
            Self::ReorgSensitiveObservation => "reorg_sensitive_observation",
            Self::ReplayedReleaseReceipt => "replayed_release_receipt",
            Self::MetadataBudgetBreach => "metadata_budget_breach",
            Self::WatcherCollusionReceipt => "watcher_collusion_receipt",
            Self::PositiveControl => "positive_control",
        }
    }

    pub fn rank(self) -> u64 {
        match self {
            Self::SignedWrongInstruction => 1,
            Self::StaleWalletReceipt => 2,
            Self::BadBroadcastRoot => 3,
            Self::MissingPqSignature => 4,
            Self::LiquiditySettlementMismatch => 5,
            Self::ReorgSensitiveObservation => 6,
            Self::ReplayedReleaseReceipt => 7,
            Self::MetadataBudgetBreach => 8,
            Self::WatcherCollusionReceipt => 9,
            Self::PositiveControl => 10,
        }
    }

    pub fn is_negative(self) -> bool {
        self != Self::PositiveControl
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGuard {
    InstructionBinding,
    WalletFreshness,
    BroadcastRoot,
    PqAuthorization,
    LiquiditySettlement,
    MoneroFinality,
    ReplayNullifier,
    MetadataBudget,
    WatcherIndependence,
}

impl ReceiptGuard {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstructionBinding => "instruction_binding",
            Self::WalletFreshness => "wallet_freshness",
            Self::BroadcastRoot => "broadcast_root",
            Self::PqAuthorization => "pq_authorization",
            Self::LiquiditySettlement => "liquidity_settlement",
            Self::MoneroFinality => "monero_finality",
            Self::ReplayNullifier => "replay_nullifier",
            Self::MetadataBudget => "metadata_budget",
            Self::WatcherIndependence => "watcher_independence",
        }
    }

    pub fn from_case_kind(kind: ReleaseReceiptCaseKind) -> Self {
        match kind {
            ReleaseReceiptCaseKind::SignedWrongInstruction => Self::InstructionBinding,
            ReleaseReceiptCaseKind::StaleWalletReceipt => Self::WalletFreshness,
            ReleaseReceiptCaseKind::BadBroadcastRoot => Self::BroadcastRoot,
            ReleaseReceiptCaseKind::MissingPqSignature => Self::PqAuthorization,
            ReleaseReceiptCaseKind::LiquiditySettlementMismatch => Self::LiquiditySettlement,
            ReleaseReceiptCaseKind::ReorgSensitiveObservation => Self::MoneroFinality,
            ReleaseReceiptCaseKind::ReplayedReleaseReceipt => Self::ReplayNullifier,
            ReleaseReceiptCaseKind::MetadataBudgetBreach => Self::MetadataBudget,
            ReleaseReceiptCaseKind::WatcherCollusionReceipt => Self::WatcherIndependence,
            ReleaseReceiptCaseKind::PositiveControl => Self::InstructionBinding,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerdict {
    Accepted,
    FailClosed,
    Quarantined,
}

impl ReceiptVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::FailClosed => "fail_closed",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAction {
    PermitRelease,
    DenyRelease,
    HoldForReview,
}

impl ReleaseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PermitRelease => "permit_release",
            Self::DenyRelease => "deny_release",
            Self::HoldForReview => "hold_for_review",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_receipt_suite: String,
    pub fail_closed_policy: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub canonical_wallet_epoch: u64,
    pub min_finality_depth: u64,
    pub min_watcher_weight: u64,
    pub min_pq_signature_weight: u64,
    pub metadata_budget_bytes: u64,
    pub max_watcher_cluster_weight: u64,
    pub required_negative_cases: usize,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_receipt_suite: RELEASE_RECEIPT_SUITE.to_string(),
            fail_closed_policy: FAIL_CLOSED_POLICY.to_string(),
            l2_reference_height: DEFAULT_L2_HEIGHT,
            monero_reference_height: DEFAULT_MONERO_HEIGHT,
            canonical_wallet_epoch: DEFAULT_WALLET_EPOCH,
            min_finality_depth: DEFAULT_MIN_FINALITY_DEPTH,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_pq_signature_weight: DEFAULT_MIN_PQ_SIGNATURE_WEIGHT,
            metadata_budget_bytes: DEFAULT_METADATA_BUDGET_BYTES,
            max_watcher_cluster_weight: DEFAULT_MAX_WATCHER_CLUSTER_WEIGHT,
            required_negative_cases: DEFAULT_REQUIRED_NEGATIVE_CASES,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_receipt_suite": self.release_receipt_suite,
            "fail_closed_policy": self.fail_closed_policy,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "canonical_wallet_epoch": self.canonical_wallet_epoch,
            "min_finality_depth": self.min_finality_depth,
            "min_watcher_weight": self.min_watcher_weight,
            "min_pq_signature_weight": self.min_pq_signature_weight,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "max_watcher_cluster_weight": self.max_watcher_cluster_weight,
            "required_negative_cases": self.required_negative_cases,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptCase {
    pub case_id: String,
    pub kind: ReleaseReceiptCaseKind,
    pub guard: ReceiptGuard,
    pub claim_id: String,
    pub receipt_id: String,
    pub release_instruction_id: String,
    pub signed_instruction_id: String,
    pub wallet_receipt_epoch: u64,
    pub expected_wallet_epoch: u64,
    pub broadcast_root: String,
    pub expected_broadcast_root: String,
    pub pq_signature_weight: u64,
    pub expected_pq_signature_weight: u64,
    pub liquidity_settled_piconero: u64,
    pub expected_liquidity_piconero: u64,
    pub monero_observation_depth: u64,
    pub min_observation_depth: u64,
    pub receipt_nullifier: String,
    pub prior_nullifier_uses: u64,
    pub metadata_bytes: u64,
    pub metadata_budget_bytes: u64,
    pub watcher_weight: u64,
    pub watcher_cluster_weight: u64,
    pub max_watcher_cluster_weight: u64,
    pub expected_release_action: ReleaseAction,
    pub summary: String,
    pub blocked_hazard: String,
    pub evidence_refs: Vec<String>,
    pub case_root: String,
}

impl ReleaseReceiptCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ReleaseReceiptCaseKind,
        claim_id: impl Into<String>,
        release_instruction_id: impl Into<String>,
        signed_instruction_id: impl Into<String>,
        wallet_receipt_epoch: u64,
        expected_wallet_epoch: u64,
        broadcast_root: impl Into<String>,
        expected_broadcast_root: impl Into<String>,
        pq_signature_weight: u64,
        expected_pq_signature_weight: u64,
        liquidity_settled_piconero: u64,
        expected_liquidity_piconero: u64,
        monero_observation_depth: u64,
        min_observation_depth: u64,
        prior_nullifier_uses: u64,
        metadata_bytes: u64,
        metadata_budget_bytes: u64,
        watcher_weight: u64,
        watcher_cluster_weight: u64,
        max_watcher_cluster_weight: u64,
        summary: impl Into<String>,
        blocked_hazard: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let release_instruction_id = release_instruction_id.into();
        let signed_instruction_id = signed_instruction_id.into();
        let broadcast_root = broadcast_root.into();
        let expected_broadcast_root = expected_broadcast_root.into();
        let guard = ReceiptGuard::from_case_kind(kind);
        let receipt_id = receipt_id(kind, &claim_id);
        let receipt_nullifier = receipt_nullifier(kind, &claim_id, &receipt_id);
        let expected_release_action = if kind.is_negative() {
            ReleaseAction::DenyRelease
        } else {
            ReleaseAction::PermitRelease
        };
        let evidence_refs = evidence_refs(kind, &claim_id);
        let summary = summary.into();
        let blocked_hazard = blocked_hazard.into();
        let case_id = case_id(kind, &claim_id);
        let mut case = Self {
            case_id,
            kind,
            guard,
            claim_id,
            receipt_id,
            release_instruction_id,
            signed_instruction_id,
            wallet_receipt_epoch,
            expected_wallet_epoch,
            broadcast_root,
            expected_broadcast_root,
            pq_signature_weight,
            expected_pq_signature_weight,
            liquidity_settled_piconero,
            expected_liquidity_piconero,
            monero_observation_depth,
            min_observation_depth,
            receipt_nullifier,
            prior_nullifier_uses,
            metadata_bytes,
            metadata_budget_bytes,
            watcher_weight,
            watcher_cluster_weight,
            max_watcher_cluster_weight,
            expected_release_action,
            summary,
            blocked_hazard,
            evidence_refs,
            case_root: String::new(),
        };
        case.case_root = record_root("release_receipt_case", &case.public_record_without_root());
        case
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "guard": self.guard.as_str(),
            "claim_id": self.claim_id,
            "receipt_id": self.receipt_id,
            "release_instruction_id": self.release_instruction_id,
            "signed_instruction_id": self.signed_instruction_id,
            "wallet_receipt_epoch": self.wallet_receipt_epoch,
            "expected_wallet_epoch": self.expected_wallet_epoch,
            "broadcast_root": self.broadcast_root,
            "expected_broadcast_root": self.expected_broadcast_root,
            "pq_signature_weight": self.pq_signature_weight,
            "expected_pq_signature_weight": self.expected_pq_signature_weight,
            "liquidity_settled_piconero": self.liquidity_settled_piconero,
            "expected_liquidity_piconero": self.expected_liquidity_piconero,
            "monero_observation_depth": self.monero_observation_depth,
            "min_observation_depth": self.min_observation_depth,
            "receipt_nullifier": self.receipt_nullifier,
            "prior_nullifier_uses": self.prior_nullifier_uses,
            "metadata_bytes": self.metadata_bytes,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "watcher_weight": self.watcher_weight,
            "watcher_cluster_weight": self.watcher_cluster_weight,
            "max_watcher_cluster_weight": self.max_watcher_cluster_weight,
            "expected_release_action": self.expected_release_action.as_str(),
            "summary": self.summary,
            "blocked_hazard": self.blocked_hazard,
            "evidence_refs": self.evidence_refs,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut object) = record {
            object.insert("case_root".to_string(), json!(self.case_root));
        }
        record
    }

    pub fn violated_guards(&self) -> Vec<ReceiptGuard> {
        let mut guards = Vec::new();
        if self.release_instruction_id != self.signed_instruction_id {
            guards.push(ReceiptGuard::InstructionBinding);
        }
        if self.wallet_receipt_epoch < self.expected_wallet_epoch {
            guards.push(ReceiptGuard::WalletFreshness);
        }
        if self.broadcast_root != self.expected_broadcast_root {
            guards.push(ReceiptGuard::BroadcastRoot);
        }
        if self.pq_signature_weight < self.expected_pq_signature_weight {
            guards.push(ReceiptGuard::PqAuthorization);
        }
        if self.liquidity_settled_piconero != self.expected_liquidity_piconero {
            guards.push(ReceiptGuard::LiquiditySettlement);
        }
        if self.monero_observation_depth < self.min_observation_depth {
            guards.push(ReceiptGuard::MoneroFinality);
        }
        if self.prior_nullifier_uses > 0 {
            guards.push(ReceiptGuard::ReplayNullifier);
        }
        if self.metadata_bytes > self.metadata_budget_bytes {
            guards.push(ReceiptGuard::MetadataBudget);
        }
        if self.watcher_cluster_weight > self.max_watcher_cluster_weight {
            guards.push(ReceiptGuard::WatcherIndependence);
        }
        guards
    }

    pub fn evaluate(&self) -> ReleaseReceiptEvaluation {
        let violated_guards = self.violated_guards();
        let verdict = if violated_guards.is_empty() {
            ReceiptVerdict::Accepted
        } else if self.watcher_weight < DEFAULT_MIN_WATCHER_WEIGHT {
            ReceiptVerdict::Quarantined
        } else {
            ReceiptVerdict::FailClosed
        };
        let release_action = match verdict {
            ReceiptVerdict::Accepted => ReleaseAction::PermitRelease,
            ReceiptVerdict::FailClosed => ReleaseAction::DenyRelease,
            ReceiptVerdict::Quarantined => ReleaseAction::HoldForReview,
        };
        let release_blocked = release_action != ReleaseAction::PermitRelease;
        let guard_names = violated_guards
            .iter()
            .map(|guard| guard.as_str().to_string())
            .collect::<Vec<_>>();
        let transcript_root = record_root(
            "receipt_evaluation_transcript",
            &json!({
                "case_root": self.case_root,
                "violated_guards": guard_names,
                "verdict": verdict.as_str(),
                "release_action": release_action.as_str(),
                "release_blocked": release_blocked,
            }),
        );
        let evaluation_root = record_root(
            "receipt_evaluation",
            &json!({
                "case_id": self.case_id,
                "receipt_id": self.receipt_id,
                "kind": self.kind.as_str(),
                "guard": self.guard.as_str(),
                "violated_guard_count": violated_guards.len(),
                "verdict": verdict.as_str(),
                "release_action": release_action.as_str(),
                "release_blocked": release_blocked,
                "transcript_root": transcript_root,
            }),
        );
        ReleaseReceiptEvaluation {
            case_id: self.case_id.clone(),
            receipt_id: self.receipt_id.clone(),
            kind: self.kind,
            expected_guard: self.guard,
            violated_guards,
            verdict,
            release_action,
            release_blocked,
            transcript_root,
            evaluation_root,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptEvaluation {
    pub case_id: String,
    pub receipt_id: String,
    pub kind: ReleaseReceiptCaseKind,
    pub expected_guard: ReceiptGuard,
    pub violated_guards: Vec<ReceiptGuard>,
    pub verdict: ReceiptVerdict,
    pub release_action: ReleaseAction,
    pub release_blocked: bool,
    pub transcript_root: String,
    pub evaluation_root: String,
}

impl ReleaseReceiptEvaluation {
    pub fn public_record(&self) -> Value {
        let violated_guards = self
            .violated_guards
            .iter()
            .map(|guard| guard.as_str())
            .collect::<Vec<_>>();
        json!({
            "case_id": self.case_id,
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "expected_guard": self.expected_guard.as_str(),
            "violated_guards": violated_guards,
            "verdict": self.verdict.as_str(),
            "release_action": self.release_action.as_str(),
            "release_blocked": self.release_blocked,
            "transcript_root": self.transcript_root,
            "evaluation_root": self.evaluation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardSummary {
    pub guard: ReceiptGuard,
    pub case_count: u64,
    pub fail_closed_count: u64,
    pub quarantine_count: u64,
    pub accepted_count: u64,
    pub summary_root: String,
}

impl GuardSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "guard": self.guard.as_str(),
            "case_count": self.case_count,
            "fail_closed_count": self.fail_closed_count,
            "quarantine_count": self.quarantine_count,
            "accepted_count": self.accepted_count,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: Vec<ReleaseReceiptCase>,
    pub evaluations: Vec<ReleaseReceiptEvaluation>,
    pub guard_summaries: Vec<GuardSummary>,
    pub case_root: String,
    pub evaluation_root: String,
    pub guard_summary_root: String,
    pub manifest_root: String,
}

impl State {
    pub fn new(config: Config, cases: Vec<ReleaseReceiptCase>) -> Self {
        let evaluations = cases
            .iter()
            .map(ReleaseReceiptCase::evaluate)
            .collect::<Vec<_>>();
        let guard_summaries = guard_summaries(&evaluations);
        let case_records = cases
            .iter()
            .map(ReleaseReceiptCase::public_record)
            .collect::<Vec<_>>();
        let evaluation_records = evaluations
            .iter()
            .map(ReleaseReceiptEvaluation::public_record)
            .collect::<Vec<_>>();
        let summary_records = guard_summaries
            .iter()
            .map(GuardSummary::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(&format!("{DOMAIN}:cases"), &case_records);
        let evaluation_root = merkle_root(&format!("{DOMAIN}:evaluations"), &evaluation_records);
        let guard_summary_root =
            merkle_root(&format!("{DOMAIN}:guard_summaries"), &summary_records);
        let manifest_root = record_root(
            "manifest",
            &json!({
                "config_root": config.state_root(),
                "case_root": case_root,
                "evaluation_root": evaluation_root,
                "guard_summary_root": guard_summary_root,
                "case_count": cases.len(),
                "evaluation_count": evaluations.len(),
            }),
        );
        Self {
            config,
            cases,
            evaluations,
            guard_summaries,
            case_root,
            evaluation_root,
            guard_summary_root,
            manifest_root,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = default_release_receipt_cases(&config);
        Self::new(config, cases)
    }

    pub fn validate(&self) -> Result<ReleaseReceiptScorecard> {
        let negative_case_count = self
            .cases
            .iter()
            .filter(|case| case.kind.is_negative())
            .count();
        if negative_case_count < self.config.required_negative_cases {
            return Err(format!(
                "expected at least {} negative receipt cases, found {}",
                self.config.required_negative_cases, negative_case_count
            ));
        }
        if self.cases.len() != self.evaluations.len() {
            return Err("case and evaluation count mismatch".to_string());
        }
        let mut failures = Vec::new();
        for case in &self.cases {
            let evaluation = match self
                .evaluations
                .iter()
                .find(|evaluation| evaluation.case_id == case.case_id)
            {
                Some(evaluation) => evaluation,
                None => {
                    failures.push(format!("missing evaluation for {}", case.case_id));
                    continue;
                }
            };
            if case.kind.is_negative() && !evaluation.release_blocked {
                failures.push(format!("negative case not blocked: {}", case.case_id));
            }
            if case.kind.is_negative() && evaluation.violated_guards.is_empty() {
                failures.push(format!(
                    "negative case lacks violated guard: {}",
                    case.case_id
                ));
            }
            if !case.kind.is_negative() && evaluation.release_blocked {
                failures.push(format!("positive control blocked: {}", case.case_id));
            }
            if case.expected_release_action != evaluation.release_action {
                failures.push(format!("release action mismatch: {}", case.case_id));
            }
        }
        let fail_closed_count = self
            .evaluations
            .iter()
            .filter(|evaluation| evaluation.verdict == ReceiptVerdict::FailClosed)
            .count() as u64;
        let quarantine_count = self
            .evaluations
            .iter()
            .filter(|evaluation| evaluation.verdict == ReceiptVerdict::Quarantined)
            .count() as u64;
        let accepted_count = self
            .evaluations
            .iter()
            .filter(|evaluation| evaluation.verdict == ReceiptVerdict::Accepted)
            .count() as u64;
        let all_negative_blocked = failures.is_empty()
            && negative_case_count as u64 == fail_closed_count + quarantine_count;
        let scorecard_root = record_root(
            "scorecard",
            &json!({
                "manifest_root": self.manifest_root,
                "negative_case_count": negative_case_count,
                "fail_closed_count": fail_closed_count,
                "quarantine_count": quarantine_count,
                "accepted_count": accepted_count,
                "all_negative_blocked": all_negative_blocked,
                "failure_count": failures.len(),
                "failures": failures,
            }),
        );
        Ok(ReleaseReceiptScorecard {
            manifest_root: self.manifest_root.clone(),
            negative_case_count: negative_case_count as u64,
            fail_closed_count,
            quarantine_count,
            accepted_count,
            all_negative_blocked,
            failures,
            scorecard_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "cases": self.cases.iter().map(ReleaseReceiptCase::public_record).collect::<Vec<_>>(),
            "evaluations": self.evaluations.iter().map(ReleaseReceiptEvaluation::public_record).collect::<Vec<_>>(),
            "guard_summaries": self.guard_summaries.iter().map(GuardSummary::public_record).collect::<Vec<_>>(),
            "case_root": self.case_root,
            "evaluation_root": self.evaluation_root,
            "guard_summary_root": self.guard_summary_root,
            "manifest_root": self.manifest_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_receipt_adversarial_state", &self.public_record())
    }

    pub fn case_by_kind(&self, kind: ReleaseReceiptCaseKind) -> Option<&ReleaseReceiptCase> {
        self.cases.iter().find(|case| case.kind == kind)
    }

    pub fn evaluation_by_case_id(&self, case_id: &str) -> Option<&ReleaseReceiptEvaluation> {
        self.evaluations
            .iter()
            .find(|evaluation| evaluation.case_id == case_id)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptScorecard {
    pub manifest_root: String,
    pub negative_case_count: u64,
    pub fail_closed_count: u64,
    pub quarantine_count: u64,
    pub accepted_count: u64,
    pub all_negative_blocked: bool,
    pub failures: Vec<String>,
    pub scorecard_root: String,
}

impl ReleaseReceiptScorecard {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_root": self.manifest_root,
            "negative_case_count": self.negative_case_count,
            "fail_closed_count": self.fail_closed_count,
            "quarantine_count": self.quarantine_count,
            "accepted_count": self.accepted_count,
            "all_negative_blocked": self.all_negative_blocked,
            "failures": self.failures,
            "scorecard_root": self.scorecard_root,
        })
    }
}

pub fn default_release_receipt_cases(config: &Config) -> Vec<ReleaseReceiptCase> {
    let canonical_instruction = deterministic_root("instruction", "canonical-release");
    let canonical_broadcast = deterministic_root("broadcast", "canonical-release");
    vec![
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::SignedWrongInstruction,
            "claim-adversarial-release-001",
            canonical_instruction.clone(),
            deterministic_root("instruction", "foreign-release"),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            8_000_000_000_000,
            8_000_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            192,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            18,
            config.max_watcher_cluster_weight,
            "receipt signature binds to a different release instruction",
            "operator could release funds for a claim the wallet never approved",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::StaleWalletReceipt,
            "claim-adversarial-release-002",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch - 2,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            6_400_000_000_000,
            6_400_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            208,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            21,
            config.max_watcher_cluster_weight,
            "wallet receipt predates the canonical wallet recovery epoch",
            "stale wallet state could approve an already rotated payout view",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::BadBroadcastRoot,
            "claim-adversarial-release-003",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            deterministic_root("broadcast", "tampered-transaction-plan"),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            9_250_000_000_000,
            9_250_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            224,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            24,
            config.max_watcher_cluster_weight,
            "broadcast root does not match the receipt commitment",
            "released Monero transaction could differ from audited payout plan",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::MissingPqSignature,
            "claim-adversarial-release-004",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            0,
            config.min_pq_signature_weight,
            7_750_000_000_000,
            7_750_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            176,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            12,
            config.max_watcher_cluster_weight,
            "receipt omits the post-quantum authority signature weight",
            "classical-only authorization would bypass the release authority spine",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::LiquiditySettlementMismatch,
            "claim-adversarial-release-005",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            5_900_000_000_000,
            6_000_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            240,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            26,
            config.max_watcher_cluster_weight,
            "liquidity settlement amount differs from the release receipt",
            "reserve accounting would overstate completed exit liquidity",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::ReorgSensitiveObservation,
            "claim-adversarial-release-006",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            4_500_000_000_000,
            4_500_000_000_000,
            config.min_finality_depth - 3,
            config.min_finality_depth,
            0,
            216,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            19,
            config.max_watcher_cluster_weight,
            "Monero observation remains inside the reorg watch depth",
            "receipt could finalize against a deposit observation that later moves",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::ReplayedReleaseReceipt,
            "claim-adversarial-release-007",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            3_950_000_000_000,
            3_950_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            1,
            184,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            17,
            config.max_watcher_cluster_weight,
            "release receipt nullifier has already been consumed",
            "replay could create a second settlement for the same exit claim",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::MetadataBudgetBreach,
            "claim-adversarial-release-008",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            2_850_000_000_000,
            2_850_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            config.metadata_budget_bytes + 96,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            20,
            config.max_watcher_cluster_weight,
            "receipt exposes more wallet metadata than the budget allows",
            "wallet-visible release hints could link private exit activity",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::WatcherCollusionReceipt,
            "claim-adversarial-release-009",
            canonical_instruction.clone(),
            canonical_instruction.clone(),
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast.clone(),
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            11_000_000_000_000,
            11_000_000_000_000,
            config.min_finality_depth,
            config.min_finality_depth,
            0,
            256,
            config.metadata_budget_bytes,
            config.min_watcher_weight,
            config.max_watcher_cluster_weight + 19,
            config.max_watcher_cluster_weight,
            "watcher quorum is concentrated in a colluding cluster",
            "receipt could appear quorum-backed while lacking independent observation",
        ),
        ReleaseReceiptCase::new(
            ReleaseReceiptCaseKind::PositiveControl,
            "claim-adversarial-release-010",
            canonical_instruction.clone(),
            canonical_instruction,
            config.canonical_wallet_epoch,
            config.canonical_wallet_epoch,
            canonical_broadcast.clone(),
            canonical_broadcast,
            config.min_pq_signature_weight,
            config.min_pq_signature_weight,
            1_250_000_000_000,
            1_250_000_000_000,
            config.min_finality_depth + 8,
            config.min_finality_depth,
            0,
            160,
            config.metadata_budget_bytes,
            config.min_watcher_weight + 8,
            15,
            config.max_watcher_cluster_weight,
            "control receipt satisfies every release guard",
            "calibrates the fail-closed harness against an admissible release",
        ),
    ]
}

pub fn build_default_state() -> State {
    State::devnet()
}

pub fn build_default_manifest() -> Value {
    State::devnet().public_record()
}

pub fn validate_default_runtime() -> Result<ReleaseReceiptScorecard> {
    State::devnet().validate()
}

pub fn runtime_protocol_markers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("protocol_version".to_string(), PROTOCOL_VERSION.to_string()),
        ("schema_version".to_string(), SCHEMA_VERSION.to_string()),
        ("hash_suite".to_string(), HASH_SUITE.to_string()),
        (
            "release_receipt_suite".to_string(),
            RELEASE_RECEIPT_SUITE.to_string(),
        ),
        (
            "fail_closed_policy".to_string(),
            FAIL_CLOSED_POLICY.to_string(),
        ),
    ])
}

fn guard_summaries(evaluations: &[ReleaseReceiptEvaluation]) -> Vec<GuardSummary> {
    let guards = [
        ReceiptGuard::InstructionBinding,
        ReceiptGuard::WalletFreshness,
        ReceiptGuard::BroadcastRoot,
        ReceiptGuard::PqAuthorization,
        ReceiptGuard::LiquiditySettlement,
        ReceiptGuard::MoneroFinality,
        ReceiptGuard::ReplayNullifier,
        ReceiptGuard::MetadataBudget,
        ReceiptGuard::WatcherIndependence,
    ];
    guards
        .iter()
        .map(|guard| {
            let matched = evaluations
                .iter()
                .filter(|evaluation| evaluation.violated_guards.contains(guard))
                .collect::<Vec<_>>();
            let fail_closed_count = matched
                .iter()
                .filter(|evaluation| evaluation.verdict == ReceiptVerdict::FailClosed)
                .count() as u64;
            let quarantine_count = matched
                .iter()
                .filter(|evaluation| evaluation.verdict == ReceiptVerdict::Quarantined)
                .count() as u64;
            let accepted_count = matched
                .iter()
                .filter(|evaluation| evaluation.verdict == ReceiptVerdict::Accepted)
                .count() as u64;
            let case_count = matched.len() as u64;
            let summary_root = record_root(
                "guard_summary",
                &json!({
                    "guard": guard.as_str(),
                    "case_count": case_count,
                    "fail_closed_count": fail_closed_count,
                    "quarantine_count": quarantine_count,
                    "accepted_count": accepted_count,
                }),
            );
            GuardSummary {
                guard: *guard,
                case_count,
                fail_closed_count,
                quarantine_count,
                accepted_count,
                summary_root,
            }
        })
        .collect()
}

fn case_id(kind: ReleaseReceiptCaseKind, claim_id: &str) -> String {
    format!(
        "adv-release-receipt-{}-{}",
        kind.rank(),
        domain_hash(
            &format!("{DOMAIN}:case_id"),
            &[HashPart::Str(kind.as_str()), HashPart::Str(claim_id)],
            6
        )
    )
}

fn receipt_id(kind: ReleaseReceiptCaseKind, claim_id: &str) -> String {
    format!(
        "release-receipt-{}-{}",
        kind.as_str(),
        domain_hash(
            &format!("{DOMAIN}:receipt_id"),
            &[HashPart::Str(kind.as_str()), HashPart::Str(claim_id)],
            8
        )
    )
}

fn receipt_nullifier(kind: ReleaseReceiptCaseKind, claim_id: &str, receipt_id: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:receipt_nullifier"),
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(claim_id),
            HashPart::Str(receipt_id),
        ],
        32,
    )
}

fn deterministic_root(label: &str, seed: &str) -> String {
    record_root(
        label,
        &json!({
            "label": label,
            "seed": seed,
            "suite": RELEASE_RECEIPT_SUITE,
        }),
    )
}

fn evidence_refs(kind: ReleaseReceiptCaseKind, claim_id: &str) -> Vec<String> {
    let base = domain_hash(
        &format!("{DOMAIN}:evidence_ref"),
        &[HashPart::Str(kind.as_str()), HashPart::Str(claim_id)],
        5,
    );
    vec![
        format!("receipt-input-{base}"),
        format!("watcher-crosscheck-{base}"),
        format!("release-gate-proof-{base}"),
    ]
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(RELEASE_RECEIPT_SUITE),
            HashPart::Json(record),
        ],
        32,
    )
}
