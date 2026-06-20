use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyManifestBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_MANIFEST_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-release-policy-manifest-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_MANIFEST_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_POLICY_SUITE: &str =
    "monero-l2-pq-force-exit-package-release-policy-manifest-binding-v1";
pub const DEFAULT_MIN_RELEASE_LANES: u64 = 8;
pub const DEFAULT_MIN_LIVE_ACCEPTED_LANES: u64 = 8;
pub const DEFAULT_MAX_STALE_HEIGHT_DELTA: u64 = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_policy_suite: String,
    pub min_release_lanes: u64,
    pub min_live_accepted_lanes: u64,
    pub max_stale_height_delta: u64,
    pub require_compile_runtime_quorum: bool,
    pub require_custody_wallet_watchtower_consensus: bool,
    pub require_privacy_regression_guard: bool,
    pub require_pq_rotation_activation: bool,
    pub require_reserve_liquidity_slo: bool,
    pub require_cross_domain_root: bool,
    pub require_heavy_gate_replacement_manifest: bool,
    pub fail_closed_on_any_hold: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_policy_suite: RELEASE_POLICY_SUITE.to_string(),
            min_release_lanes: DEFAULT_MIN_RELEASE_LANES,
            min_live_accepted_lanes: DEFAULT_MIN_LIVE_ACCEPTED_LANES,
            max_stale_height_delta: DEFAULT_MAX_STALE_HEIGHT_DELTA,
            require_compile_runtime_quorum: true,
            require_custody_wallet_watchtower_consensus: true,
            require_privacy_regression_guard: true,
            require_pq_rotation_activation: true,
            require_reserve_liquidity_slo: true,
            require_cross_domain_root: true,
            require_heavy_gate_replacement_manifest: true,
            fail_closed_on_any_hold: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_lane_count(&self) -> u64 {
        [
            self.require_compile_runtime_quorum,
            self.require_custody_wallet_watchtower_consensus,
            self.require_privacy_regression_guard,
            self.require_pq_rotation_activation,
            self.require_reserve_liquidity_slo,
            self.require_cross_domain_root,
            self.require_heavy_gate_replacement_manifest,
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
            "release_policy_suite": self.release_policy_suite,
            "min_release_lanes": self.min_release_lanes,
            "min_live_accepted_lanes": self.min_live_accepted_lanes,
            "max_stale_height_delta": self.max_stale_height_delta,
            "required_lane_count": self.required_lane_count(),
            "require_compile_runtime_quorum": self.require_compile_runtime_quorum,
            "require_custody_wallet_watchtower_consensus": self.require_custody_wallet_watchtower_consensus,
            "require_privacy_regression_guard": self.require_privacy_regression_guard,
            "require_pq_rotation_activation": self.require_pq_rotation_activation,
            "require_reserve_liquidity_slo": self.require_reserve_liquidity_slo,
            "require_cross_domain_root": self.require_cross_domain_root,
            "require_heavy_gate_replacement_manifest": self.require_heavy_gate_replacement_manifest,
            "fail_closed_on_any_hold": self.fail_closed_on_any_hold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseLane {
    CompileRuntimeReceiptQuorum,
    CustodyWalletWatchtowerConsensus,
    PrivacyBudgetRegressionGuard,
    PqRotationActivationGuard,
    ReserveLiquiditySloGate,
    LiveReceiptCrossDomainRoot,
    HeavyGateReplacementManifest,
    OperatorReleaseGovernance,
}

impl ReleaseLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntimeReceiptQuorum => "compile_runtime_receipt_quorum",
            Self::CustodyWalletWatchtowerConsensus => "custody_wallet_watchtower_consensus",
            Self::PrivacyBudgetRegressionGuard => "privacy_budget_regression_guard",
            Self::PqRotationActivationGuard => "pq_rotation_activation_guard",
            Self::ReserveLiquiditySloGate => "reserve_liquidity_slo_gate",
            Self::LiveReceiptCrossDomainRoot => "live_receipt_cross_domain_root",
            Self::HeavyGateReplacementManifest => "heavy_gate_replacement_manifest",
            Self::OperatorReleaseGovernance => "operator_release_governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseLaneStatus {
    LiveAccepted,
    ReviewerPending,
    Stale,
    Deferred,
    Rejected,
}

impl ReleaseLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveAccepted => "live_accepted",
            Self::ReviewerPending => "reviewer_pending",
            Self::Stale => "stale",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_live_accepted(self) -> bool {
        matches!(self, Self::LiveAccepted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBindingEvidence {
    pub evidence_id: String,
    pub lane: ReleaseLane,
    pub adapter_runtime: String,
    pub replacement_manifest_root: String,
    pub accepted_receipt_root: String,
    pub reviewer_quorum_root: String,
    pub release_policy_root: String,
    pub observed_height: u64,
    pub accepted_height: u64,
    pub status: ReleaseLaneStatus,
    pub hold_reason: String,
}

impl ReleaseBindingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ReleaseLane,
        adapter_runtime: &str,
        replacement_manifest_root: &str,
        accepted_receipt_root: &str,
        reviewer_quorum_root: &str,
        release_policy_root: &str,
        observed_height: u64,
        accepted_height: u64,
        status: ReleaseLaneStatus,
        hold_reason: &str,
    ) -> Self {
        let evidence_id = release_binding_evidence_id(
            lane,
            adapter_runtime,
            replacement_manifest_root,
            accepted_receipt_root,
            reviewer_quorum_root,
            release_policy_root,
            observed_height,
            accepted_height,
            status,
            hold_reason,
        );
        Self {
            evidence_id,
            lane,
            adapter_runtime: adapter_runtime.to_string(),
            replacement_manifest_root: replacement_manifest_root.to_string(),
            accepted_receipt_root: accepted_receipt_root.to_string(),
            reviewer_quorum_root: reviewer_quorum_root.to_string(),
            release_policy_root: release_policy_root.to_string(),
            observed_height,
            accepted_height,
            status,
            hold_reason: hold_reason.to_string(),
        }
    }

    pub fn is_live_accepted(&self) -> bool {
        self.status.is_live_accepted()
    }

    pub fn is_stale(&self, config: &Config) -> bool {
        self.observed_height.saturating_sub(self.accepted_height) > config.max_stale_height_delta
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "lane": self.lane.as_str(),
            "adapter_runtime": self.adapter_runtime,
            "replacement_manifest_root": self.replacement_manifest_root,
            "accepted_receipt_root": self.accepted_receipt_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "release_policy_root": self.release_policy_root,
            "observed_height": self.observed_height,
            "accepted_height": self.accepted_height,
            "status": self.status.as_str(),
            "hold_reason": self.hold_reason,
            "live_accepted": self.is_live_accepted(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub total_lanes: u64,
    pub live_accepted_lanes: u64,
    pub reviewer_pending_lanes: u64,
    pub stale_lanes: u64,
    pub deferred_lanes: u64,
    pub rejected_lanes: u64,
    pub required_lanes: u64,
}

impl Counters {
    pub fn from_evidence(config: &Config, evidence: &[ReleaseBindingEvidence]) -> Self {
        Self {
            total_lanes: evidence.len() as u64,
            live_accepted_lanes: evidence
                .iter()
                .filter(|item| {
                    item.status == ReleaseLaneStatus::LiveAccepted && !item.is_stale(config)
                })
                .count() as u64,
            reviewer_pending_lanes: evidence
                .iter()
                .filter(|item| item.status == ReleaseLaneStatus::ReviewerPending)
                .count() as u64,
            stale_lanes: evidence
                .iter()
                .filter(|item| item.status == ReleaseLaneStatus::Stale || item.is_stale(config))
                .count() as u64,
            deferred_lanes: evidence
                .iter()
                .filter(|item| item.status == ReleaseLaneStatus::Deferred)
                .count() as u64,
            rejected_lanes: evidence
                .iter()
                .filter(|item| item.status == ReleaseLaneStatus::Rejected)
                .count() as u64,
            required_lanes: config.required_lane_count().max(config.min_release_lanes),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_lanes": self.total_lanes,
            "live_accepted_lanes": self.live_accepted_lanes,
            "reviewer_pending_lanes": self.reviewer_pending_lanes,
            "stale_lanes": self.stale_lanes,
            "deferred_lanes": self.deferred_lanes,
            "rejected_lanes": self.rejected_lanes,
            "required_lanes": self.required_lanes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleasePolicyVerdict {
    pub verdict_id: String,
    pub accepted_lane_root: String,
    pub pending_lane_root: String,
    pub stale_lane_root: String,
    pub hold_reason_root: String,
    pub release_binding_root: String,
    pub all_required_lanes_accepted: bool,
    pub release_allowed: bool,
    pub production_hold: bool,
    pub status: String,
}

impl ReleasePolicyVerdict {
    pub fn from_parts(
        config: &Config,
        evidence: &[ReleaseBindingEvidence],
        counters: &Counters,
    ) -> Self {
        let accepted = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::LiveAccepted && !item.is_stale(config))
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let pending = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::ReviewerPending)
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let stale = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::Stale || item.is_stale(config))
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let hold_reasons = evidence
            .iter()
            .filter(|item| item.status != ReleaseLaneStatus::LiveAccepted || item.is_stale(config))
            .map(|item| {
                json!({
                    "lane": item.lane.as_str(),
                    "status": item.status.as_str(),
                    "hold_reason": item.hold_reason,
                    "stale": item.is_stale(config),
                })
            })
            .collect::<Vec<_>>();
        let release_bindings = evidence
            .iter()
            .map(|item| {
                json!({
                    "lane": item.lane.as_str(),
                    "replacement_manifest_root": item.replacement_manifest_root,
                    "accepted_receipt_root": item.accepted_receipt_root,
                    "reviewer_quorum_root": item.reviewer_quorum_root,
                    "release_policy_root": item.release_policy_root,
                    "status": item.status.as_str(),
                })
            })
            .collect::<Vec<_>>();

        let accepted_lane_root = merkle_root("RELEASE-POLICY-ACCEPTED-LANE", &accepted);
        let pending_lane_root = merkle_root("RELEASE-POLICY-PENDING-LANE", &pending);
        let stale_lane_root = merkle_root("RELEASE-POLICY-STALE-LANE", &stale);
        let hold_reason_root = merkle_root("RELEASE-POLICY-HOLD-REASON", &hold_reasons);
        let release_binding_root = merkle_root("RELEASE-POLICY-BINDING", &release_bindings);
        let all_required_lanes_accepted = counters.live_accepted_lanes
            >= config.min_live_accepted_lanes
            && counters.live_accepted_lanes >= counters.required_lanes;
        let no_holds = counters.reviewer_pending_lanes == 0
            && counters.stale_lanes == 0
            && counters.deferred_lanes == 0
            && counters.rejected_lanes == 0;
        let release_allowed = all_required_lanes_accepted && no_holds;
        let production_hold = if config.fail_closed_on_any_hold {
            !release_allowed
        } else {
            counters.rejected_lanes > 0
        };
        let status = if release_allowed {
            "release_allowed"
        } else if counters.rejected_lanes > 0 {
            "rejected_hold"
        } else if counters.stale_lanes > 0 {
            "stale_hold"
        } else if counters.deferred_lanes > 0 {
            "deferred_hold"
        } else {
            "reviewer_pending_hold"
        }
        .to_string();
        let verdict_id = release_policy_verdict_id(
            &accepted_lane_root,
            &pending_lane_root,
            &stale_lane_root,
            &hold_reason_root,
            &release_binding_root,
            counters,
            release_allowed,
            &status,
        );
        Self {
            verdict_id,
            accepted_lane_root,
            pending_lane_root,
            stale_lane_root,
            hold_reason_root,
            release_binding_root,
            all_required_lanes_accepted,
            release_allowed,
            production_hold,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "accepted_lane_root": self.accepted_lane_root,
            "pending_lane_root": self.pending_lane_root,
            "stale_lane_root": self.stale_lane_root,
            "hold_reason_root": self.hold_reason_root,
            "release_binding_root": self.release_binding_root,
            "all_required_lanes_accepted": self.all_required_lanes_accepted,
            "release_allowed": self.release_allowed,
            "production_hold": self.production_hold,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub evidence_root: String,
    pub accepted_lane_root: String,
    pub pending_lane_root: String,
    pub stale_lane_root: String,
    pub hold_reason_root: String,
    pub verdict_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn from_parts(
        config: &Config,
        evidence: &[ReleaseBindingEvidence],
        counters: &Counters,
        verdict: &ReleasePolicyVerdict,
    ) -> Self {
        let evidence_records = evidence
            .iter()
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let accepted_records = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::LiveAccepted && !item.is_stale(config))
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let pending_records = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::ReviewerPending)
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let stale_records = evidence
            .iter()
            .filter(|item| item.status == ReleaseLaneStatus::Stale || item.is_stale(config))
            .map(ReleaseBindingEvidence::public_record)
            .collect::<Vec<_>>();
        let hold_records = evidence
            .iter()
            .filter(|item| item.status != ReleaseLaneStatus::LiveAccepted || item.is_stale(config))
            .map(|item| {
                json!({
                    "lane": item.lane.as_str(),
                    "hold_reason": item.hold_reason,
                    "status": item.status.as_str(),
                    "stale": item.is_stale(config),
                })
            })
            .collect::<Vec<_>>();
        let config_record = config.public_record();
        let counters_record = counters.public_record();
        let verdict_record = verdict.public_record();
        let config_root = record_root("config", &config_record);
        let evidence_root = merkle_root("RELEASE-POLICY-EVIDENCE", &evidence_records);
        let accepted_lane_root = merkle_root("RELEASE-POLICY-ACCEPTED", &accepted_records);
        let pending_lane_root = merkle_root("RELEASE-POLICY-PENDING", &pending_records);
        let stale_lane_root = merkle_root("RELEASE-POLICY-STALE", &stale_records);
        let hold_reason_root = merkle_root("RELEASE-POLICY-HOLD", &hold_records);
        let verdict_root = record_root("verdict", &verdict_record);
        let state_root = record_root(
            "state",
            &json!({
                "config_root": config_root,
                "evidence_root": evidence_root,
                "accepted_lane_root": accepted_lane_root,
                "pending_lane_root": pending_lane_root,
                "stale_lane_root": stale_lane_root,
                "hold_reason_root": hold_reason_root,
                "counters": counters_record,
                "verdict_root": verdict_root,
            }),
        );
        Self {
            config_root,
            evidence_root,
            accepted_lane_root,
            pending_lane_root,
            stale_lane_root,
            hold_reason_root,
            verdict_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "evidence_root": self.evidence_root,
            "accepted_lane_root": self.accepted_lane_root,
            "pending_lane_root": self.pending_lane_root,
            "stale_lane_root": self.stale_lane_root,
            "hold_reason_root": self.hold_reason_root,
            "verdict_root": self.verdict_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub release_evidence: Vec<ReleaseBindingEvidence>,
    pub counters: Counters,
    pub verdict: ReleasePolicyVerdict,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, release_evidence: Vec<ReleaseBindingEvidence>) -> Self {
        let counters = Counters::from_evidence(&config, &release_evidence);
        let verdict = ReleasePolicyVerdict::from_parts(&config, &release_evidence, &counters);
        let roots = Roots::from_parts(&config, &release_evidence, &counters, &verdict);
        Self {
            config,
            release_evidence,
            counters,
            verdict,
            roots,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), devnet_release_evidence())
    }

    pub fn production_hold(&self) -> bool {
        self.verdict.production_hold
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "release_evidence": self
                .release_evidence
                .iter()
                .map(ReleaseBindingEvidence::public_record)
                .collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
            "roots": self.roots.public_record(),
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

fn devnet_release_evidence() -> Vec<ReleaseBindingEvidence> {
    vec![
        ReleaseBindingEvidence::new(
            ReleaseLane::CompileRuntimeReceiptQuorum,
            "compile-runtime-receipt-quorum-release-gate",
            &fixture_root("manifest", "compile runtime manifest pending"),
            &fixture_root("accepted", "compile runtime receipt missing"),
            &fixture_root("reviewer", "compile runtime quorum pending"),
            &fixture_root("policy", "compile runtime release policy"),
            77,
            62,
            ReleaseLaneStatus::Deferred,
            "compile and runtime receipt quorum is not live accepted",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::CustodyWalletWatchtowerConsensus,
            "custody-wallet-watchtower-release-consensus",
            &fixture_root("manifest", "custody wallet watchtower manifest pending"),
            &fixture_root("accepted", "cross-party consensus receipt missing"),
            &fixture_root("reviewer", "custody wallet watchtower quorum pending"),
            &fixture_root("policy", "custody wallet watchtower release policy"),
            77,
            74,
            ReleaseLaneStatus::ReviewerPending,
            "custody, wallet, and watchtower roots need matching live acceptance",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::PrivacyBudgetRegressionGuard,
            "privacy-budget-release-regression-guard",
            &fixture_root("manifest", "privacy budget manifest pending"),
            &fixture_root("accepted", "privacy regression guard receipt missing"),
            &fixture_root("reviewer", "privacy reviewer quorum pending"),
            &fixture_root("policy", "privacy release policy"),
            77,
            73,
            ReleaseLaneStatus::ReviewerPending,
            "privacy budget regression guard requires reviewer acceptance",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::PqRotationActivationGuard,
            "pq-rotation-release-activation-guard",
            &fixture_root("manifest", "pq rotation manifest pending"),
            &fixture_root("accepted", "pq activation receipt missing"),
            &fixture_root("reviewer", "pq reviewer quorum pending"),
            &fixture_root("policy", "pq release policy"),
            77,
            70,
            ReleaseLaneStatus::ReviewerPending,
            "PQ rotation activation must replace legacy signer evidence",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::ReserveLiquiditySloGate,
            "reserve-liquidity-release-slo-gate",
            &fixture_root("manifest", "reserve liquidity manifest pending"),
            &fixture_root("accepted", "reserve SLO receipt missing"),
            &fixture_root("reviewer", "reserve reviewer quorum pending"),
            &fixture_root("policy", "reserve liquidity release policy"),
            77,
            63,
            ReleaseLaneStatus::Stale,
            "reserve liquidity SLO evidence is stale relative to release height",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::LiveReceiptCrossDomainRoot,
            "live-receipt-cross-domain-root-aggregator",
            &fixture_root("manifest", "cross domain manifest pending"),
            &fixture_root("accepted", "cross domain aggregate receipt missing"),
            &fixture_root("reviewer", "cross domain reviewer quorum pending"),
            &fixture_root("policy", "cross domain release policy"),
            77,
            72,
            ReleaseLaneStatus::ReviewerPending,
            "cross-domain aggregate root must match all release lanes",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::HeavyGateReplacementManifest,
            "heavy-gate-evidence-replacement-manifest",
            &fixture_root("manifest", "heavy gate replacement manifest"),
            &fixture_root("accepted", "heavy gate manifest receipt missing"),
            &fixture_root("reviewer", "heavy gate manifest reviewer quorum pending"),
            &fixture_root("policy", "heavy gate manifest release policy"),
            77,
            76,
            ReleaseLaneStatus::ReviewerPending,
            "replacement manifest is wired but not live accepted",
        ),
        ReleaseBindingEvidence::new(
            ReleaseLane::OperatorReleaseGovernance,
            "operator-release-governance",
            &fixture_root("manifest", "operator release governance manifest"),
            &fixture_root("accepted", "operator governance release receipt missing"),
            &fixture_root("reviewer", "operator reviewer quorum pending"),
            &fixture_root("policy", "operator release policy"),
            77,
            77,
            ReleaseLaneStatus::ReviewerPending,
            "operator governance release packet still requires live signoff",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
pub fn release_binding_evidence_id(
    lane: ReleaseLane,
    adapter_runtime: &str,
    replacement_manifest_root: &str,
    accepted_receipt_root: &str,
    reviewer_quorum_root: &str,
    release_policy_root: &str,
    observed_height: u64,
    accepted_height: u64,
    status: ReleaseLaneStatus,
    hold_reason: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-BINDING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(adapter_runtime),
            HashPart::Str(replacement_manifest_root),
            HashPart::Str(accepted_receipt_root),
            HashPart::Str(reviewer_quorum_root),
            HashPart::Str(release_policy_root),
            HashPart::U64(observed_height),
            HashPart::U64(accepted_height),
            HashPart::Str(status.as_str()),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

pub fn release_policy_verdict_id(
    accepted_lane_root: &str,
    pending_lane_root: &str,
    stale_lane_root: &str,
    hold_reason_root: &str,
    release_binding_root: &str,
    counters: &Counters,
    release_allowed: bool,
    status: &str,
) -> String {
    let counters_record = counters.public_record();
    domain_hash(
        "RELEASE-POLICY-BINDING-VERDICT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(accepted_lane_root),
            HashPart::Str(pending_lane_root),
            HashPart::Str(stale_lane_root),
            HashPart::Str(hold_reason_root),
            HashPart::Str(release_binding_root),
            HashPart::Json(&counters_record),
            HashPart::Str(if release_allowed {
                "release-allowed"
            } else {
                "release-held"
            }),
            HashPart::Str(status),
        ],
        32,
    )
}

pub fn fixture_root(kind: &str, value: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-BINDING-FIXTURE",
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
        "RELEASE-POLICY-BINDING-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
