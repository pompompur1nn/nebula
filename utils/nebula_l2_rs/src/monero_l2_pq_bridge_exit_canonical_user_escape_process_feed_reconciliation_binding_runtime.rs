use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeProcessFeedReconciliationBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PROCESS_FEED_RECONCILIATION_BINDING_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-process-feed-reconciliation-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PROCESS_FEED_RECONCILIATION_BINDING_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-process-feed-reconciliation-binding";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub lane_id: String,
    pub binding_suite: String,
    pub process_feed_suite: String,
    pub reconciliation_suite: String,
    pub min_process_feed_count: u64,
    pub min_reconciliation_reference_count: u64,
    pub require_manifest_reference: u64,
    pub hold_release_until_runtime_execution: u64,
    pub fail_closed_on_missing_feed: u64,
    pub fail_closed_on_missing_reconciliation: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "canonical_user_escape_process_feed_reconciliation_binding".to_string(),
            binding_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-process-feed-binding-suite-v1"
                    .to_string(),
            process_feed_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-process-feed-suite-v1"
                    .to_string(),
            reconciliation_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-suite-v1"
                    .to_string(),
            min_process_feed_count: 7,
            min_reconciliation_reference_count: 7,
            require_manifest_reference: 1,
            hold_release_until_runtime_execution: 1,
            fail_closed_on_missing_feed: 1,
            fail_closed_on_missing_reconciliation: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "binding_suite": self.binding_suite,
            "process_feed_suite": self.process_feed_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "min_process_feed_count": self.min_process_feed_count,
            "min_reconciliation_reference_count": self.min_reconciliation_reference_count,
            "require_manifest_reference": self.require_manifest_reference,
            "hold_release_until_runtime_execution": self.hold_release_until_runtime_execution,
            "fail_closed_on_missing_feed": self.fail_closed_on_missing_feed,
            "fail_closed_on_missing_reconciliation": self.fail_closed_on_missing_reconciliation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessFeedLane {
    MoneroWatcher,
    PqAuthority,
    WalletScanner,
    Reserve,
    Receipt,
    Release,
    Adversarial,
}

impl ProcessFeedLane {
    pub fn all() -> [Self; 7] {
        [
            Self::MoneroWatcher,
            Self::PqAuthority,
            Self::WalletScanner,
            Self::Reserve,
            Self::Receipt,
            Self::Release,
            Self::Adversarial,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroWatcher => "monero_watcher",
            Self::PqAuthority => "pq_authority",
            Self::WalletScanner => "wallet_scanner",
            Self::Reserve => "reserve",
            Self::Receipt => "receipt",
            Self::Release => "release",
            Self::Adversarial => "adversarial",
        }
    }

    pub fn source_module(self) -> &'static str {
        match self {
            Self::MoneroWatcher => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime"
            }
            Self::PqAuthority => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime"
            }
            Self::WalletScanner => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime"
            }
            Self::Reserve => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime"
            }
            Self::Receipt => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime"
            }
            Self::Release => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_release_process_feed_runtime"
            }
            Self::Adversarial => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime"
            }
        }
    }

    pub fn privacy_boundary(self) -> &'static str {
        match self {
            Self::MoneroWatcher => "public_monero_header_and_lock_roots_only",
            Self::PqAuthority => "public_pq_epoch_and_attestation_roots_only",
            Self::WalletScanner => "wallet_encrypted_scan_roots_only",
            Self::Reserve => "bucketed_reserve_coverage_roots_only",
            Self::Receipt => "receipt_envelope_and_transcript_roots_only",
            Self::Release => "payout_commitment_and_broadcast_roots_only",
            Self::Adversarial => "redacted_blocker_and_wallet_notice_roots_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationTarget {
    Manifest,
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialGap,
    WalletRunbook,
}

impl ReconciliationTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "runtime_output_reconciliation_manifest",
            Self::DepositLock => "deposit_lock_runtime_output_reconciliation",
            Self::PrivateNote => "private_note_runtime_output_reconciliation",
            Self::SettlementReceipt => "settlement_receipt_runtime_output_reconciliation",
            Self::ReleaseVerification => "release_verification_runtime_output_reconciliation",
            Self::AdversarialGap => "adversarial_gap_runtime_output_reconciliation",
            Self::WalletRunbook => "wallet_runbook_runtime_output_reconciliation",
        }
    }

    pub fn source_module(self) -> &'static str {
        match self {
            Self::Manifest => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_runtime_output_reconciliation_manifest_runtime"
            }
            Self::DepositLock => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_runtime_output_reconciliation_runtime"
            }
            Self::PrivateNote => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_private_note_runtime_output_reconciliation_runtime"
            }
            Self::SettlementReceipt => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_runtime_output_reconciliation_runtime"
            }
            Self::ReleaseVerification => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_runtime_output_reconciliation_runtime"
            }
            Self::AdversarialGap => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_gap_runtime_output_reconciliation_runtime"
            }
            Self::WalletRunbook => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_runtime_output_reconciliation_runtime"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessFeedRoot {
    pub lane: ProcessFeedLane,
    pub source_module: String,
    pub state_root: String,
    pub public_record_root: String,
    pub privacy_boundary: String,
    pub present: u64,
}

impl ProcessFeedRoot {
    pub fn devnet(lane: ProcessFeedLane) -> Self {
        let public_record = process_feed_public_record(lane);
        let state_root = process_feed_state_root(lane);
        let public_record_root = record_root("process_feed_public_record", &public_record);
        let present =
            non_empty_flag(&state_root).saturating_mul(non_empty_flag(&public_record_root));
        Self {
            lane,
            source_module: lane.source_module().to_string(),
            state_root,
            public_record_root,
            privacy_boundary: lane.privacy_boundary().to_string(),
            present,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "source_module": self.source_module,
            "state_root": self.state_root,
            "public_record_root": self.public_record_root,
            "privacy_boundary": self.privacy_boundary,
            "present": self.present,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReference {
    pub target: ReconciliationTarget,
    pub source_module: String,
    pub state_root: String,
    pub public_record_root: String,
    pub present: u64,
}

impl ReconciliationReference {
    pub fn devnet(target: ReconciliationTarget) -> Self {
        let public_record = reconciliation_public_record(target);
        let state_root = reconciliation_state_root(target);
        let public_record_root = record_root("reconciliation_public_record", &public_record);
        let present =
            non_empty_flag(&state_root).saturating_mul(non_empty_flag(&public_record_root));
        Self {
            target,
            source_module: target.source_module().to_string(),
            state_root,
            public_record_root,
            present,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "target": self.target,
            "source_module": self.source_module,
            "state_root": self.state_root,
            "public_record_root": self.public_record_root,
            "present": self.present,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRoute {
    pub process_feed_lane: ProcessFeedLane,
    pub reconciliation_target: ReconciliationTarget,
    pub process_feed_root: String,
    pub reconciliation_root: String,
    pub privacy_boundary: String,
    pub required: u64,
    pub feed_present: u64,
    pub reconciliation_present: u64,
    pub ready_for_runtime_harness: u64,
    pub release_allowed_before_harness: u64,
    pub binding_root: String,
}

impl BindingRoute {
    pub fn new(feed: &ProcessFeedRoot, reference: &ReconciliationReference, required: u64) -> Self {
        let feed_present = feed.present;
        let reconciliation_present = reference.present;
        let ready_for_runtime_harness = feed_present
            .saturating_mul(reconciliation_present)
            .saturating_mul(required);
        let release_allowed_before_harness = 0;
        let binding_root = domain_hash(
            &format!("{DOMAIN}:route"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(feed.lane.as_str()),
                HashPart::Str(reference.target.as_str()),
                HashPart::Str(&feed.state_root),
                HashPart::Str(&reference.state_root),
                HashPart::Str(&feed.privacy_boundary),
                HashPart::U64(required),
                HashPart::U64(feed_present),
                HashPart::U64(reconciliation_present),
                HashPart::U64(ready_for_runtime_harness),
                HashPart::U64(release_allowed_before_harness),
            ],
            32,
        );
        Self {
            process_feed_lane: feed.lane,
            reconciliation_target: reference.target,
            process_feed_root: feed.state_root.clone(),
            reconciliation_root: reference.state_root.clone(),
            privacy_boundary: feed.privacy_boundary.clone(),
            required,
            feed_present,
            reconciliation_present,
            ready_for_runtime_harness,
            release_allowed_before_harness,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "process_feed_lane": self.process_feed_lane,
            "reconciliation_target": self.reconciliation_target,
            "process_feed_root": self.process_feed_root,
            "reconciliation_root": self.reconciliation_root,
            "privacy_boundary": self.privacy_boundary,
            "required": self.required,
            "feed_present": self.feed_present,
            "reconciliation_present": self.reconciliation_present,
            "ready_for_runtime_harness": self.ready_for_runtime_harness,
            "release_allowed_before_harness": self.release_allowed_before_harness,
            "binding_root": self.binding_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingGap {
    pub route_root: String,
    pub process_feed_lane: ProcessFeedLane,
    pub reconciliation_target: ReconciliationTarget,
    pub gap_kind: String,
    pub release_hold_reason: String,
    pub gap_root: String,
}

impl BindingGap {
    pub fn from_route(route: &BindingRoute) -> Self {
        let gap_kind = if route.feed_present == 0 {
            "missing_process_feed_root"
        } else if route.reconciliation_present == 0 {
            "missing_reconciliation_reference_root"
        } else if route.ready_for_runtime_harness == 0 {
            "route_not_ready_for_runtime_harness"
        } else {
            "runtime_harness_not_executed"
        }
        .to_string();
        let release_hold_reason = format!(
            "{} keeps {} bound to {} in hold-release mode",
            gap_kind,
            route.process_feed_lane.as_str(),
            route.reconciliation_target.as_str()
        );
        let gap_root = domain_hash(
            &format!("{DOMAIN}:binding-gap"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&route.binding_root),
                HashPart::Str(route.process_feed_lane.as_str()),
                HashPart::Str(route.reconciliation_target.as_str()),
                HashPart::Str(&gap_kind),
                HashPart::Str(&release_hold_reason),
            ],
            32,
        );
        Self {
            route_root: route.binding_root.clone(),
            process_feed_lane: route.process_feed_lane,
            reconciliation_target: route.reconciliation_target,
            gap_kind,
            release_hold_reason,
            gap_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_root": self.route_root,
            "process_feed_lane": self.process_feed_lane,
            "reconciliation_target": self.reconciliation_target,
            "gap_kind": self.gap_kind,
            "release_hold_reason": self.release_hold_reason,
            "gap_root": self.gap_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingVerdict {
    pub process_feed_count: u64,
    pub reconciliation_reference_count: u64,
    pub binding_route_count: u64,
    pub ready_route_count: u64,
    pub binding_gap_count: u64,
    pub manifest_reference_present: u64,
    pub release_allowed: u64,
    pub verdict: String,
    pub verdict_root: String,
}

impl BindingVerdict {
    pub fn from_state(
        config: &Config,
        feeds: &[ProcessFeedRoot],
        references: &[ReconciliationReference],
        routes: &[BindingRoute],
        gaps: &[BindingGap],
    ) -> Self {
        let process_feed_count = feeds.len() as u64;
        let reconciliation_reference_count = references.len() as u64;
        let binding_route_count = routes.len() as u64;
        let ready_route_count = routes
            .iter()
            .filter(|route| route.ready_for_runtime_harness == 1)
            .count() as u64;
        let binding_gap_count = gaps.len() as u64;
        let manifest_reference_present = references.iter().any(|reference| {
            reference.target == ReconciliationTarget::Manifest && reference.present == 1
        }) as u64;
        let release_allowed = 0;
        let verdict = if process_feed_count >= config.min_process_feed_count
            && reconciliation_reference_count >= config.min_reconciliation_reference_count
            && ready_route_count == binding_route_count
            && manifest_reference_present == config.require_manifest_reference
        {
            "process_feed_reconciliation_binding_ready_for_runtime_harness".to_string()
        } else {
            "process_feed_reconciliation_binding_incomplete_hold_release".to_string()
        };
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::U64(process_feed_count),
                HashPart::U64(reconciliation_reference_count),
                HashPart::U64(binding_route_count),
                HashPart::U64(ready_route_count),
                HashPart::U64(binding_gap_count),
                HashPart::U64(manifest_reference_present),
                HashPart::U64(release_allowed),
                HashPart::Str(&verdict),
            ],
            32,
        );
        Self {
            process_feed_count,
            reconciliation_reference_count,
            binding_route_count,
            ready_route_count,
            binding_gap_count,
            manifest_reference_present,
            release_allowed,
            verdict,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "process_feed_count": self.process_feed_count,
            "reconciliation_reference_count": self.reconciliation_reference_count,
            "binding_route_count": self.binding_route_count,
            "ready_route_count": self.ready_route_count,
            "binding_gap_count": self.binding_gap_count,
            "manifest_reference_present": self.manifest_reference_present,
            "release_allowed": self.release_allowed,
            "verdict": self.verdict,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub process_feeds: Vec<ProcessFeedRoot>,
    pub reconciliation_references: Vec<ReconciliationReference>,
    pub binding_routes: Vec<BindingRoute>,
    pub binding_gaps: Vec<BindingGap>,
    pub verdict: BindingVerdict,
    pub process_feed_bundle_root: String,
    pub reconciliation_reference_root: String,
    pub binding_route_root: String,
    pub binding_gap_root: String,
    pub release_hold_root: String,
    pub runtime_harness_handoff_root: String,
}

impl State {
    pub fn new(
        config: Config,
        process_feeds: Vec<ProcessFeedRoot>,
        reconciliation_references: Vec<ReconciliationReference>,
    ) -> Result<Self> {
        validate_inputs(&config, &process_feeds, &reconciliation_references)?;
        let binding_routes = build_routes(&process_feeds, &reconciliation_references);
        let binding_gaps = binding_routes
            .iter()
            .filter(|route| route.ready_for_runtime_harness == 0)
            .map(BindingGap::from_route)
            .collect::<Vec<_>>();
        let verdict = BindingVerdict::from_state(
            &config,
            &process_feeds,
            &reconciliation_references,
            &binding_routes,
            &binding_gaps,
        );
        let process_feed_bundle_root = merkle_root(
            &format!("{DOMAIN}:process-feed-bundle"),
            &process_feeds
                .iter()
                .map(ProcessFeedRoot::public_record)
                .collect::<Vec<_>>(),
        );
        let reconciliation_reference_root = merkle_root(
            &format!("{DOMAIN}:reconciliation-references"),
            &reconciliation_references
                .iter()
                .map(ReconciliationReference::public_record)
                .collect::<Vec<_>>(),
        );
        let binding_route_root = merkle_root(
            &format!("{DOMAIN}:binding-routes"),
            &binding_routes
                .iter()
                .map(BindingRoute::public_record)
                .collect::<Vec<_>>(),
        );
        let binding_gap_root = merkle_root(
            &format!("{DOMAIN}:binding-gaps"),
            &binding_gaps
                .iter()
                .map(BindingGap::public_record)
                .collect::<Vec<_>>(),
        );
        let release_hold_root = release_hold_root(&config, &binding_gap_root, &verdict);
        let runtime_harness_handoff_root = domain_hash(
            &format!("{DOMAIN}:runtime-harness-handoff"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&process_feed_bundle_root),
                HashPart::Str(&reconciliation_reference_root),
                HashPart::Str(&binding_route_root),
                HashPart::Str(&binding_gap_root),
                HashPart::Str(&release_hold_root),
                HashPart::Str(&verdict.verdict_root),
            ],
            32,
        );
        Ok(Self {
            config,
            process_feeds,
            reconciliation_references,
            binding_routes,
            binding_gaps,
            verdict,
            process_feed_bundle_root,
            reconciliation_reference_root,
            binding_route_root,
            binding_gap_root,
            release_hold_root,
            runtime_harness_handoff_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let process_feeds = ProcessFeedLane::all()
            .iter()
            .map(|lane| ProcessFeedRoot::devnet(*lane))
            .collect::<Vec<_>>();
        let reconciliation_references = [
            ReconciliationTarget::Manifest,
            ReconciliationTarget::DepositLock,
            ReconciliationTarget::PrivateNote,
            ReconciliationTarget::SettlementReceipt,
            ReconciliationTarget::ReleaseVerification,
            ReconciliationTarget::AdversarialGap,
            ReconciliationTarget::WalletRunbook,
        ]
        .iter()
        .map(|target| ReconciliationReference::devnet(*target))
        .collect::<Vec<_>>();
        match Self::new(config, process_feeds, reconciliation_references) {
            Ok(state) => state,
            Err(error) => Self::invalid(error),
        }
    }

    pub fn invalid(error: String) -> Self {
        let config = Config::default();
        let verdict = BindingVerdict {
            process_feed_count: 0,
            reconciliation_reference_count: 0,
            binding_route_count: 0,
            ready_route_count: 0,
            binding_gap_count: 1,
            manifest_reference_present: 0,
            release_allowed: 0,
            verdict: "process_feed_reconciliation_binding_invalid_hold_release".to_string(),
            verdict_root: domain_hash(
                &format!("{DOMAIN}:invalid-verdict"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&config.lane_id),
                    HashPart::Str(&error),
                ],
                32,
            ),
        };
        let binding_gap_root = domain_hash(
            &format!("{DOMAIN}:invalid-gap"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&error),
            ],
            32,
        );
        let release_hold_root = release_hold_root(&config, &binding_gap_root, &verdict);
        let runtime_harness_handoff_root = domain_hash(
            &format!("{DOMAIN}:invalid-handoff"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&binding_gap_root),
                HashPart::Str(&release_hold_root),
                HashPart::Str(&verdict.verdict_root),
            ],
            32,
        );
        Self {
            config,
            process_feeds: Vec::new(),
            reconciliation_references: Vec::new(),
            binding_routes: Vec::new(),
            binding_gaps: Vec::new(),
            verdict,
            process_feed_bundle_root: merkle_root(&format!("{DOMAIN}:process-feed-bundle"), &[]),
            reconciliation_reference_root: merkle_root(
                &format!("{DOMAIN}:reconciliation-references"),
                &[],
            ),
            binding_route_root: merkle_root(&format!("{DOMAIN}:binding-routes"), &[]),
            binding_gap_root,
            release_hold_root,
            runtime_harness_handoff_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "process_feed_bundle_root": self.process_feed_bundle_root,
            "reconciliation_reference_root": self.reconciliation_reference_root,
            "binding_route_root": self.binding_route_root,
            "binding_gap_root": self.binding_gap_root,
            "release_hold_root": self.release_hold_root,
            "runtime_harness_handoff_root": self.runtime_harness_handoff_root,
            "verdict": self.verdict.public_record(),
            "process_feeds": self
                .process_feeds
                .iter()
                .map(ProcessFeedRoot::public_record)
                .collect::<Vec<_>>(),
            "reconciliation_references": self
                .reconciliation_references
                .iter()
                .map(ReconciliationReference::public_record)
                .collect::<Vec<_>>(),
            "binding_routes": self
                .binding_routes
                .iter()
                .map(BindingRoute::public_record)
                .collect::<Vec<_>>(),
            "binding_gaps": self
                .binding_gaps
                .iter()
                .map(BindingGap::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "process_feed_bundle_root": self.process_feed_bundle_root,
                "reconciliation_reference_root": self.reconciliation_reference_root,
                "binding_route_root": self.binding_route_root,
                "binding_gap_root": self.binding_gap_root,
                "release_hold_root": self.release_hold_root,
                "runtime_harness_handoff_root": self.runtime_harness_handoff_root,
                "verdict_root": self.verdict.verdict_root,
            }),
        )
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

fn validate_inputs(
    config: &Config,
    process_feeds: &[ProcessFeedRoot],
    reconciliation_references: &[ReconciliationReference],
) -> Result<()> {
    if process_feeds.len() as u64 != config.min_process_feed_count {
        return Err("process feed binding requires seven process feed roots".to_string());
    }
    if reconciliation_references.len() as u64 != config.min_reconciliation_reference_count {
        return Err(
            "process feed binding requires seven reconciliation reference roots".to_string(),
        );
    }
    if !reconciliation_references
        .iter()
        .any(|reference| reference.target == ReconciliationTarget::Manifest)
    {
        return Err("process feed binding requires manifest reconciliation reference".to_string());
    }
    Ok(())
}

fn build_routes(
    feeds: &[ProcessFeedRoot],
    references: &[ReconciliationReference],
) -> Vec<BindingRoute> {
    route_plan()
        .iter()
        .filter_map(|(lane, target)| {
            let feed = feeds.iter().find(|feed| feed.lane == *lane);
            let reference = references
                .iter()
                .find(|reference| reference.target == *target);
            match (feed, reference) {
                (Some(feed), Some(reference)) => Some(BindingRoute::new(feed, reference, 1)),
                _ => None,
            }
        })
        .collect()
}

fn route_plan() -> [(ProcessFeedLane, ReconciliationTarget); 7] {
    [
        (
            ProcessFeedLane::MoneroWatcher,
            ReconciliationTarget::DepositLock,
        ),
        (
            ProcessFeedLane::PqAuthority,
            ReconciliationTarget::ReleaseVerification,
        ),
        (
            ProcessFeedLane::WalletScanner,
            ReconciliationTarget::PrivateNote,
        ),
        (ProcessFeedLane::Reserve, ReconciliationTarget::Manifest),
        (
            ProcessFeedLane::Receipt,
            ReconciliationTarget::SettlementReceipt,
        ),
        (
            ProcessFeedLane::Release,
            ReconciliationTarget::WalletRunbook,
        ),
        (
            ProcessFeedLane::Adversarial,
            ReconciliationTarget::AdversarialGap,
        ),
    ]
}

fn non_empty_flag(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        1
    }
}

fn release_hold_root(config: &Config, binding_gap_root: &str, verdict: &BindingVerdict) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(binding_gap_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(config.hold_release_until_runtime_execution),
            HashPart::U64(verdict.release_allowed),
        ],
        32,
    )
}

fn process_feed_state_root(lane: ProcessFeedLane) -> String {
    match lane {
        ProcessFeedLane::MoneroWatcher => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::state_root()
        }
        ProcessFeedLane::PqAuthority => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()
        }
        ProcessFeedLane::WalletScanner => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()
        }
        ProcessFeedLane::Reserve => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::state_root()
        }
        ProcessFeedLane::Receipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()
        }
        ProcessFeedLane::Release => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_process_feed_runtime::state_root()
        }
        ProcessFeedLane::Adversarial => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::state_root()
        }
    }
}

fn process_feed_public_record(lane: ProcessFeedLane) -> Value {
    match lane {
        ProcessFeedLane::MoneroWatcher => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::public_record()
        }
        ProcessFeedLane::PqAuthority => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::public_record()
        }
        ProcessFeedLane::WalletScanner => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::public_record()
        }
        ProcessFeedLane::Reserve => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::public_record()
        }
        ProcessFeedLane::Receipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::public_record()
        }
        ProcessFeedLane::Release => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_process_feed_runtime::public_record()
        }
        ProcessFeedLane::Adversarial => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::public_record()
        }
    }
}

fn reconciliation_state_root(target: ReconciliationTarget) -> String {
    match target {
        ReconciliationTarget::Manifest => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_runtime_output_reconciliation_manifest_runtime::state_root()
        }
        ReconciliationTarget::DepositLock => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_runtime_output_reconciliation_runtime::state_root()
        }
        ReconciliationTarget::PrivateNote => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_runtime_output_reconciliation_runtime::state_root()
        }
        ReconciliationTarget::SettlementReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_runtime_output_reconciliation_runtime::state_root()
        }
        ReconciliationTarget::ReleaseVerification => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_runtime_output_reconciliation_runtime::state_root()
        }
        ReconciliationTarget::AdversarialGap => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_gap_runtime_output_reconciliation_runtime::state_root()
        }
        ReconciliationTarget::WalletRunbook => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_runtime_output_reconciliation_runtime::state_root()
        }
    }
}

fn reconciliation_public_record(target: ReconciliationTarget) -> Value {
    match target {
        ReconciliationTarget::Manifest => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_runtime_output_reconciliation_manifest_runtime::public_record()
        }
        ReconciliationTarget::DepositLock => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_runtime_output_reconciliation_runtime::public_record()
        }
        ReconciliationTarget::PrivateNote => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_runtime_output_reconciliation_runtime::public_record()
        }
        ReconciliationTarget::SettlementReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_runtime_output_reconciliation_runtime::public_record()
        }
        ReconciliationTarget::ReleaseVerification => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_runtime_output_reconciliation_runtime::public_record()
        }
        ReconciliationTarget::AdversarialGap => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_gap_runtime_output_reconciliation_runtime::public_record()
        }
        ReconciliationTarget::WalletRunbook => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_runtime_output_reconciliation_runtime::public_record()
        }
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
