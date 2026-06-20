use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSecurityReviewSignoffExecutionManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_EXECUTION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-execution-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_EXECUTION_MANIFEST_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-execution-manifest";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub manifest_suite: String,
    pub execution_policy: String,
    pub min_execution_lanes: u64,
    pub require_signoff_bundle_root: u64,
    pub require_acceptance_matrix_root: u64,
    pub require_heavy_gate_schedule_root: u64,
    pub require_heavy_gate_receipt_root: u64,
    pub require_human_review_evidence: u64,
    pub require_live_execution_receipt: u64,
    pub require_release_hold_until_review: u64,
    pub max_release_allowed_lanes: u64,
    pub max_linkage_exports: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            manifest_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-execution-manifest-v1"
                    .to_string(),
            execution_policy:
                "seven-domain-live-evidence-execution-with-release-held-until-review-v1"
                    .to_string(),
            min_execution_lanes: 7,
            require_signoff_bundle_root: 1,
            require_acceptance_matrix_root: 1,
            require_heavy_gate_schedule_root: 1,
            require_heavy_gate_receipt_root: 1,
            require_human_review_evidence: 1,
            require_live_execution_receipt: 1,
            require_release_hold_until_review: 1,
            max_release_allowed_lanes: 0,
            max_linkage_exports: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "manifest_suite": self.manifest_suite,
            "execution_policy": self.execution_policy,
            "min_execution_lanes": self.min_execution_lanes,
            "require_signoff_bundle_root": self.require_signoff_bundle_root,
            "require_acceptance_matrix_root": self.require_acceptance_matrix_root,
            "require_heavy_gate_schedule_root": self.require_heavy_gate_schedule_root,
            "require_heavy_gate_receipt_root": self.require_heavy_gate_receipt_root,
            "require_human_review_evidence": self.require_human_review_evidence,
            "require_live_execution_receipt": self.require_live_execution_receipt,
            "require_release_hold_until_review": self.require_release_hold_until_review,
            "max_release_allowed_lanes": self.max_release_allowed_lanes,
            "max_linkage_exports": self.max_linkage_exports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDomain {
    MoneroFinality,
    WatcherQuorum,
    PqCustody,
    LiquidityReserve,
    ReceiptReplay,
    NullifierSeparation,
    MetadataRedaction,
}

impl ExecutionDomain {
    pub fn ordered() -> [Self; 7] {
        [
            Self::MoneroFinality,
            Self::WatcherQuorum,
            Self::PqCustody,
            Self::LiquidityReserve,
            Self::ReceiptReplay,
            Self::NullifierSeparation,
            Self::MetadataRedaction,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFinality => "monero_finality",
            Self::WatcherQuorum => "watcher_quorum",
            Self::PqCustody => "pq_custody",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::ReceiptReplay => "receipt_replay",
            Self::NullifierSeparation => "nullifier_separation",
            Self::MetadataRedaction => "metadata_redaction",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::MoneroFinality => "monero_finality_live_feed_execution",
            Self::WatcherQuorum => "watcher_quorum_collusion_execution",
            Self::PqCustody => "pq_custody_authority_execution",
            Self::LiquidityReserve => "liquidity_reserve_execution",
            Self::ReceiptReplay => "settlement_receipt_replay_execution",
            Self::NullifierSeparation => "nullifier_separation_wallet_execution",
            Self::MetadataRedaction => "metadata_redaction_wallet_export_execution",
        }
    }

    pub fn execution_question(self) -> &'static str {
        match self {
            Self::MoneroFinality => {
                "Can live Monero finality evidence keep exit release held across shallow confirmations and reorg roots?"
            }
            Self::WatcherQuorum => {
                "Can watcher quorum execution reject colluding, missing, or stale watcher evidence before release?"
            }
            Self::PqCustody => {
                "Can PQ custody execution prove fresh withdrawal authority, rotation state, and release authorization?"
            }
            Self::LiquidityReserve => {
                "Can reserve execution prove exit liquidity coverage and force a hold on exhaustion?"
            }
            Self::ReceiptReplay => {
                "Can receipt execution reject forged, duplicate, or replayed settlement receipts?"
            }
            Self::NullifierSeparation => {
                "Can nullifier execution prove withdrawal separation without exposing private note linkage?"
            }
            Self::MetadataRedaction => {
                "Can wallet export execution prove roots-only reviewer evidence with no linkable metadata?"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    PendingLiveExecution,
    PendingReviewerReceipt,
    BlockedRelease,
}

impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingLiveExecution => "pending_live_execution",
            Self::PendingReviewerReceipt => "pending_reviewer_receipt",
            Self::BlockedRelease => "blocked_release",
        }
    }

    pub fn release_allowed(self) -> u64 {
        match self {
            Self::PendingLiveExecution | Self::PendingReviewerReceipt | Self::BlockedRelease => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoots {
    pub signoff_bundle_state_root: String,
    pub signoff_bundle_root: String,
    pub signoff_packet_root: String,
    pub signoff_release_hold_root: String,
    pub signoff_monero_finality_root: String,
    pub signoff_watcher_quorum_root: String,
    pub signoff_pq_custody_root: String,
    pub signoff_liquidity_root: String,
    pub signoff_receipt_replay_root: String,
    pub signoff_nullifier_root: String,
    pub signoff_metadata_root: String,
    pub acceptance_matrix_state_root: String,
    pub acceptance_matrix_root: String,
    pub acceptance_release_hold_root: String,
    pub heavy_gate_schedule_root: String,
    pub heavy_gate_checklist_root: String,
    pub heavy_gate_execution_receipt_root: String,
    pub heavy_gate_readiness_receipt_root: String,
    pub go_no_go_matrix_root: String,
    pub source_root: String,
}

impl SourceRoots {
    pub fn devnet() -> Self {
        let signoff =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_bundle_runtime::devnet();
        let acceptance =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_threat_model_acceptance_matrix_runtime::devnet();
        let signoff_bundle_state_root = signoff.state_root();
        let signoff_bundle_root = signoff.bundle_root.clone();
        let signoff_packet_root = signoff.packet_root.clone();
        let signoff_release_hold_root = signoff.release_hold_root.clone();
        let signoff_monero_finality_root = signoff.monero_finality_root.clone();
        let signoff_watcher_quorum_root = signoff.watcher_quorum_root.clone();
        let signoff_pq_custody_root = signoff.pq_custody_root.clone();
        let signoff_liquidity_root = signoff.liquidity_root.clone();
        let signoff_receipt_replay_root = signoff.receipt_replay_root.clone();
        let signoff_nullifier_root = signoff.nullifier_root.clone();
        let signoff_metadata_root = signoff.metadata_root.clone();
        let acceptance_matrix_state_root = acceptance.state_root();
        let acceptance_matrix_root = acceptance.matrix_root.clone();
        let acceptance_release_hold_root = acceptance.release_hold_root.clone();
        let heavy_gate_schedule_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_execution_schedule_runtime::state_root();
        let heavy_gate_checklist_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_execution_checklist_runtime::state_root();
        let heavy_gate_execution_receipt_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_execution_receipt_runtime::state_root();
        let heavy_gate_readiness_receipt_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_readiness_receipt_runtime::state_root();
        let go_no_go_matrix_root =
            crate::monero_l2_pq_bridge_exit_canonical_release_candidate_go_no_go_matrix_runtime::state_root();
        let source_root = source_root(
            &signoff_bundle_state_root,
            &signoff_bundle_root,
            &signoff_packet_root,
            &signoff_release_hold_root,
            &acceptance_matrix_root,
            &acceptance_release_hold_root,
            &heavy_gate_schedule_root,
            &heavy_gate_checklist_root,
            &heavy_gate_execution_receipt_root,
            &heavy_gate_readiness_receipt_root,
            &go_no_go_matrix_root,
        );

        Self {
            signoff_bundle_state_root,
            signoff_bundle_root,
            signoff_packet_root,
            signoff_release_hold_root,
            signoff_monero_finality_root,
            signoff_watcher_quorum_root,
            signoff_pq_custody_root,
            signoff_liquidity_root,
            signoff_receipt_replay_root,
            signoff_nullifier_root,
            signoff_metadata_root,
            acceptance_matrix_state_root,
            acceptance_matrix_root,
            acceptance_release_hold_root,
            heavy_gate_schedule_root,
            heavy_gate_checklist_root,
            heavy_gate_execution_receipt_root,
            heavy_gate_readiness_receipt_root,
            go_no_go_matrix_root,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signoff_bundle_state_root": self.signoff_bundle_state_root,
            "signoff_bundle_root": self.signoff_bundle_root,
            "signoff_packet_root": self.signoff_packet_root,
            "signoff_release_hold_root": self.signoff_release_hold_root,
            "signoff_monero_finality_root": self.signoff_monero_finality_root,
            "signoff_watcher_quorum_root": self.signoff_watcher_quorum_root,
            "signoff_pq_custody_root": self.signoff_pq_custody_root,
            "signoff_liquidity_root": self.signoff_liquidity_root,
            "signoff_receipt_replay_root": self.signoff_receipt_replay_root,
            "signoff_nullifier_root": self.signoff_nullifier_root,
            "signoff_metadata_root": self.signoff_metadata_root,
            "acceptance_matrix_state_root": self.acceptance_matrix_state_root,
            "acceptance_matrix_root": self.acceptance_matrix_root,
            "acceptance_release_hold_root": self.acceptance_release_hold_root,
            "heavy_gate_schedule_root": self.heavy_gate_schedule_root,
            "heavy_gate_checklist_root": self.heavy_gate_checklist_root,
            "heavy_gate_execution_receipt_root": self.heavy_gate_execution_receipt_root,
            "heavy_gate_readiness_receipt_root": self.heavy_gate_readiness_receipt_root,
            "go_no_go_matrix_root": self.go_no_go_matrix_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLane {
    pub ordinal: u64,
    pub domain: ExecutionDomain,
    pub owner_lane: String,
    pub execution_question: String,
    pub status: ExecutionStatus,
    pub signoff_packet_root: String,
    pub required_live_root: String,
    pub expected_receipt_root: String,
    pub reviewer_evidence_root: String,
    pub command_root: String,
    pub release_hold_root: String,
    pub live_execution_required: u64,
    pub human_review_required: u64,
    pub release_allowed: u64,
    pub linkage_exports_allowed: u64,
    pub lane_root: String,
}

impl ExecutionLane {
    pub fn devnet(
        config: &Config,
        source: &SourceRoots,
        domain: ExecutionDomain,
        ordinal: u64,
    ) -> Self {
        let status = ExecutionStatus::PendingLiveExecution;
        let signoff_packet_root = signoff_domain_root(source, domain).to_string();
        let required_live_root = required_live_root(domain, source);
        let expected_receipt_root = expected_receipt_root(domain, source);
        let reviewer_evidence_root = reviewer_evidence_root(
            config,
            source,
            domain,
            &signoff_packet_root,
            &required_live_root,
            &expected_receipt_root,
        );
        let command_root =
            command_root(config, domain, &required_live_root, &expected_receipt_root);
        let release_hold_root = lane_release_hold_root(
            config,
            source,
            domain,
            &reviewer_evidence_root,
            &command_root,
        );
        let lane_root = lane_root(
            config,
            source,
            domain,
            ordinal,
            status,
            &signoff_packet_root,
            &required_live_root,
            &expected_receipt_root,
            &reviewer_evidence_root,
            &command_root,
            &release_hold_root,
        );

        Self {
            ordinal,
            domain,
            owner_lane: domain.owner_lane().to_string(),
            execution_question: domain.execution_question().to_string(),
            status,
            signoff_packet_root,
            required_live_root,
            expected_receipt_root,
            reviewer_evidence_root,
            command_root,
            release_hold_root,
            live_execution_required: config.require_live_execution_receipt,
            human_review_required: config.require_human_review_evidence,
            release_allowed: status.release_allowed(),
            linkage_exports_allowed: config.max_linkage_exports,
            lane_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "domain": self.domain.as_str(),
            "owner_lane": self.owner_lane,
            "execution_question": self.execution_question,
            "status": self.status.as_str(),
            "signoff_packet_root": self.signoff_packet_root,
            "required_live_root": self.required_live_root,
            "expected_receipt_root": self.expected_receipt_root,
            "reviewer_evidence_root": self.reviewer_evidence_root,
            "command_root": self.command_root,
            "release_hold_root": self.release_hold_root,
            "live_execution_required": self.live_execution_required,
            "human_review_required": self.human_review_required,
            "release_allowed": self.release_allowed,
            "linkage_exports_allowed": self.linkage_exports_allowed,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionManifestVerdict {
    pub execution_lane_count: u64,
    pub pending_live_execution_count: u64,
    pub pending_reviewer_receipt_count: u64,
    pub blocked_release_count: u64,
    pub release_allowed_count: u64,
    pub release_hold_count: u64,
    pub zero_linkage_lane_count: u64,
    pub live_execution_required_count: u64,
    pub human_review_required_count: u64,
    pub manifest_status: String,
    pub verdict_root: String,
}

impl ExecutionManifestVerdict {
    pub fn new(config: &Config, lanes: &[ExecutionLane]) -> Self {
        let execution_lane_count = lanes.len() as u64;
        let pending_live_execution_count =
            count_status(lanes, ExecutionStatus::PendingLiveExecution);
        let pending_reviewer_receipt_count =
            count_status(lanes, ExecutionStatus::PendingReviewerReceipt);
        let blocked_release_count = count_status(lanes, ExecutionStatus::BlockedRelease);
        let release_allowed_count = lanes
            .iter()
            .filter(|lane| lane.release_allowed == 1)
            .count() as u64;
        let release_hold_count = lanes
            .iter()
            .filter(|lane| lane.release_allowed == 0)
            .count() as u64;
        let zero_linkage_lane_count = lanes
            .iter()
            .filter(|lane| lane.linkage_exports_allowed <= config.max_linkage_exports)
            .count() as u64;
        let live_execution_required_count = lanes
            .iter()
            .filter(|lane| lane.live_execution_required == 1)
            .count() as u64;
        let human_review_required_count = lanes
            .iter()
            .filter(|lane| lane.human_review_required == 1)
            .count() as u64;
        let manifest_status = if execution_lane_count >= config.min_execution_lanes
            && pending_live_execution_count == execution_lane_count
            && release_allowed_count <= config.max_release_allowed_lanes
            && release_hold_count == execution_lane_count
            && zero_linkage_lane_count == execution_lane_count
            && live_execution_required_count == execution_lane_count
            && human_review_required_count == execution_lane_count
        {
            "signoff_execution_manifest_ready_release_held"
        } else {
            "signoff_execution_manifest_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.execution_policy),
                HashPart::U64(execution_lane_count),
                HashPart::U64(pending_live_execution_count),
                HashPart::U64(pending_reviewer_receipt_count),
                HashPart::U64(blocked_release_count),
                HashPart::U64(release_allowed_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(zero_linkage_lane_count),
                HashPart::U64(live_execution_required_count),
                HashPart::U64(human_review_required_count),
                HashPart::Str(&manifest_status),
            ],
            32,
        );

        Self {
            execution_lane_count,
            pending_live_execution_count,
            pending_reviewer_receipt_count,
            blocked_release_count,
            release_allowed_count,
            release_hold_count,
            zero_linkage_lane_count,
            live_execution_required_count,
            human_review_required_count,
            manifest_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let manifest_status =
            "signoff_execution_manifest_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.execution_policy),
                HashPart::Str(reason),
                HashPart::Str(&manifest_status),
            ],
            32,
        );

        Self {
            execution_lane_count: 0,
            pending_live_execution_count: 0,
            pending_reviewer_receipt_count: 0,
            blocked_release_count: 1,
            release_allowed_count: 0,
            release_hold_count: 1,
            zero_linkage_lane_count: 0,
            live_execution_required_count: 0,
            human_review_required_count: 0,
            manifest_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_lane_count": self.execution_lane_count,
            "pending_live_execution_count": self.pending_live_execution_count,
            "pending_reviewer_receipt_count": self.pending_reviewer_receipt_count,
            "blocked_release_count": self.blocked_release_count,
            "release_allowed_count": self.release_allowed_count,
            "release_hold_count": self.release_hold_count,
            "zero_linkage_lane_count": self.zero_linkage_lane_count,
            "live_execution_required_count": self.live_execution_required_count,
            "human_review_required_count": self.human_review_required_count,
            "manifest_status": self.manifest_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source_roots: SourceRoots,
    pub execution_lanes: Vec<ExecutionLane>,
    pub verdict: ExecutionManifestVerdict,
    pub lane_root: String,
    pub monero_finality_execution_root: String,
    pub watcher_quorum_execution_root: String,
    pub pq_custody_execution_root: String,
    pub liquidity_execution_root: String,
    pub receipt_replay_execution_root: String,
    pub nullifier_execution_root: String,
    pub metadata_execution_root: String,
    pub release_hold_root: String,
    pub manifest_root: String,
}

impl State {
    pub fn new(config: Config, source_roots: SourceRoots) -> Result<Self> {
        validate_config(&config)?;
        let execution_lanes = ExecutionDomain::ordered()
            .iter()
            .enumerate()
            .map(|(index, domain)| {
                ExecutionLane::devnet(&config, &source_roots, *domain, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = ExecutionManifestVerdict::new(&config, &execution_lanes);
        let lane_root = lane_vector_root(&execution_lanes);
        let monero_finality_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::MoneroFinality);
        let watcher_quorum_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::WatcherQuorum);
        let pq_custody_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::PqCustody);
        let liquidity_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::LiquidityReserve);
        let receipt_replay_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::ReceiptReplay);
        let nullifier_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::NullifierSeparation);
        let metadata_execution_root =
            domain_lane_root(&execution_lanes, ExecutionDomain::MetadataRedaction);
        let release_hold_root =
            manifest_release_hold_root(&config, &source_roots, &execution_lanes, &verdict);
        let manifest_root = manifest_root(
            &config,
            &source_roots,
            &lane_root,
            &release_hold_root,
            &verdict,
        );

        Ok(Self {
            config,
            source_roots,
            execution_lanes,
            verdict,
            lane_root,
            monero_finality_execution_root,
            watcher_quorum_execution_root,
            pq_custody_execution_root,
            liquidity_execution_root,
            receipt_replay_execution_root,
            nullifier_execution_root,
            metadata_execution_root,
            release_hold_root,
            manifest_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), SourceRoots::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_execution_manifest_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source_roots": self.source_roots.public_record(),
            "lane_root": self.lane_root,
            "monero_finality_execution_root": self.monero_finality_execution_root,
            "watcher_quorum_execution_root": self.watcher_quorum_execution_root,
            "pq_custody_execution_root": self.pq_custody_execution_root,
            "liquidity_execution_root": self.liquidity_execution_root,
            "receipt_replay_execution_root": self.receipt_replay_execution_root,
            "nullifier_execution_root": self.nullifier_execution_root,
            "metadata_execution_root": self.metadata_execution_root,
            "release_hold_root": self.release_hold_root,
            "manifest_root": self.manifest_root,
            "verdict": self.verdict.public_record(),
            "execution_lanes": self
                .execution_lanes
                .iter()
                .map(ExecutionLane::public_record)
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
                "source_root": self.source_roots.state_root(),
                "lane_root": self.lane_root,
                "release_hold_root": self.release_hold_root,
                "manifest_root": self.manifest_root,
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

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("config chain id must match crate chain id".to_string());
    }
    if config.min_execution_lanes < ExecutionDomain::ordered().len() as u64 {
        return Err("minimum execution lane count must cover every signoff domain".to_string());
    }
    if config.require_release_hold_until_review != 1 {
        return Err("signoff execution manifest must keep release held until review".to_string());
    }
    if config.max_release_allowed_lanes != 0 {
        return Err("signoff execution manifest cannot allow release before review".to_string());
    }
    if config.max_linkage_exports != 0 {
        return Err("signoff execution manifest must keep reviewer exports roots-only".to_string());
    }
    Ok(())
}

fn signoff_domain_root(source: &SourceRoots, domain: ExecutionDomain) -> &str {
    match domain {
        ExecutionDomain::MoneroFinality => &source.signoff_monero_finality_root,
        ExecutionDomain::WatcherQuorum => &source.signoff_watcher_quorum_root,
        ExecutionDomain::PqCustody => &source.signoff_pq_custody_root,
        ExecutionDomain::LiquidityReserve => &source.signoff_liquidity_root,
        ExecutionDomain::ReceiptReplay => &source.signoff_receipt_replay_root,
        ExecutionDomain::NullifierSeparation => &source.signoff_nullifier_root,
        ExecutionDomain::MetadataRedaction => &source.signoff_metadata_root,
    }
}

fn required_live_root(domain: ExecutionDomain, source: &SourceRoots) -> String {
    match domain {
        ExecutionDomain::MoneroFinality => domain_hash(
            &format!("{DOMAIN}:monero-finality-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_schedule_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_reorg_collusion_threat_model_manifest_runtime::devnet().state_root()),
            ],
            32,
        ),
        ExecutionDomain::WatcherQuorum => domain_hash(
            &format!("{DOMAIN}:watcher-quorum-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_schedule_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::devnet().state_root()),
            ],
            32,
        ),
        ExecutionDomain::PqCustody => domain_hash(
            &format!("{DOMAIN}:pq-custody-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_schedule_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()),
            ],
            32,
        ),
        ExecutionDomain::LiquidityReserve => domain_hash(
            &format!("{DOMAIN}:liquidity-reserve-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_schedule_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet().state_root()),
            ],
            32,
        ),
        ExecutionDomain::ReceiptReplay => domain_hash(
            &format!("{DOMAIN}:receipt-replay-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_execution_receipt_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_proof_runtime::state_root()),
            ],
            32,
        ),
        ExecutionDomain::NullifierSeparation => domain_hash(
            &format!("{DOMAIN}:nullifier-separation-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.heavy_gate_execution_receipt_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()),
            ],
            32,
        ),
        ExecutionDomain::MetadataRedaction => domain_hash(
            &format!("{DOMAIN}:metadata-redaction-live-root"),
            &[
                HashPart::Str(signoff_domain_root(source, domain)),
                HashPart::Str(&source.signoff_release_hold_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_dry_run_wallet_handoff_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root()),
            ],
            32,
        ),
    }
}

fn expected_receipt_root(domain: ExecutionDomain, source: &SourceRoots) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.heavy_gate_execution_receipt_root),
            HashPart::Str(&source.heavy_gate_readiness_receipt_root),
            HashPart::Str(&source.go_no_go_matrix_root),
            HashPart::Str(&source.acceptance_release_hold_root),
            HashPart::U64(0),
        ],
        32,
    )
}

fn reviewer_evidence_root(
    config: &Config,
    source: &SourceRoots,
    domain: ExecutionDomain,
    signoff_packet_root: &str,
    required_live_root: &str,
    expected_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:reviewer-evidence"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.signoff_bundle_root),
            HashPart::Str(signoff_packet_root),
            HashPart::Str(required_live_root),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(&source.acceptance_matrix_root),
            HashPart::U64(config.require_human_review_evidence),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn command_root(
    config: &Config,
    domain: ExecutionDomain,
    required_live_root: &str,
    expected_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:command"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.manifest_suite),
            HashPart::Str(domain.as_str()),
            HashPart::Str(domain.owner_lane()),
            HashPart::Str(required_live_root),
            HashPart::Str(expected_receipt_root),
            HashPart::U64(config.require_live_execution_receipt),
            HashPart::U64(config.require_release_hold_until_review),
        ],
        32,
    )
}

fn lane_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    domain: ExecutionDomain,
    reviewer_evidence_root: &str,
    command_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.signoff_release_hold_root),
            HashPart::Str(&source.acceptance_release_hold_root),
            HashPart::Str(reviewer_evidence_root),
            HashPart::Str(command_root),
            HashPart::U64(config.require_release_hold_until_review),
            HashPart::U64(0),
        ],
        32,
    )
}

fn lane_root(
    config: &Config,
    source: &SourceRoots,
    domain: ExecutionDomain,
    ordinal: u64,
    status: ExecutionStatus,
    signoff_packet_root: &str,
    required_live_root: &str,
    expected_receipt_root: &str,
    reviewer_evidence_root: &str,
    command_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(&source.source_root),
            HashPart::U64(ordinal),
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(signoff_packet_root),
            HashPart::Str(required_live_root),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(reviewer_evidence_root),
            HashPart::Str(command_root),
            HashPart::Str(release_hold_root),
            HashPart::U64(status.release_allowed()),
        ],
        32,
    )
}

fn count_status(lanes: &[ExecutionLane], status: ExecutionStatus) -> u64 {
    lanes.iter().filter(|lane| lane.status == status).count() as u64
}

fn lane_vector_root(lanes: &[ExecutionLane]) -> String {
    let leaves = lanes
        .iter()
        .map(ExecutionLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:lane-root"), &leaves)
}

fn domain_lane_root(lanes: &[ExecutionLane], domain: ExecutionDomain) -> String {
    let leaves = lanes
        .iter()
        .filter(|lane| lane.domain == domain)
        .map(ExecutionLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{}-lane-root", domain.as_str()), &leaves)
}

fn manifest_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    lanes: &[ExecutionLane],
    verdict: &ExecutionManifestVerdict,
) -> String {
    let leaves = lanes
        .iter()
        .filter(|lane| lane.release_allowed == 0)
        .map(ExecutionLane::public_record)
        .collect::<Vec<_>>();
    let hold_lane_root = merkle_root(&format!("{DOMAIN}:release-hold-lanes"), &leaves);
    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(&source.source_root),
            HashPart::Str(&hold_lane_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_hold_count),
            HashPart::U64(config.require_release_hold_until_review),
        ],
        32,
    )
}

fn manifest_root(
    config: &Config,
    source: &SourceRoots,
    lane_root: &str,
    release_hold_root: &str,
    verdict: &ExecutionManifestVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:manifest"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.manifest_suite),
            HashPart::Str(&source.source_root),
            HashPart::Str(lane_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_allowed_count),
        ],
        32,
    )
}

fn source_root(
    signoff_bundle_state_root: &str,
    signoff_bundle_root: &str,
    signoff_packet_root: &str,
    signoff_release_hold_root: &str,
    acceptance_matrix_root: &str,
    acceptance_release_hold_root: &str,
    heavy_gate_schedule_root: &str,
    heavy_gate_checklist_root: &str,
    heavy_gate_execution_receipt_root: &str,
    heavy_gate_readiness_receipt_root: &str,
    go_no_go_matrix_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(signoff_bundle_state_root),
            HashPart::Str(signoff_bundle_root),
            HashPart::Str(signoff_packet_root),
            HashPart::Str(signoff_release_hold_root),
            HashPart::Str(acceptance_matrix_root),
            HashPart::Str(acceptance_release_hold_root),
            HashPart::Str(heavy_gate_schedule_root),
            HashPart::Str(heavy_gate_checklist_root),
            HashPart::Str(heavy_gate_execution_receipt_root),
            HashPart::Str(heavy_gate_readiness_receipt_root),
            HashPart::Str(go_no_go_matrix_root),
        ],
        32,
    )
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

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let reason_ref = reason.as_str();
    let source_roots = SourceRoots {
        signoff_bundle_state_root: record_root(
            "fallback-signoff-state",
            &json!({ "reason": reason_ref }),
        ),
        signoff_bundle_root: record_root("fallback-signoff", &json!({ "reason": reason_ref })),
        signoff_packet_root: record_root("fallback-packet", &json!({ "reason": reason_ref })),
        signoff_release_hold_root: record_root(
            "fallback-signoff-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        signoff_monero_finality_root: record_root(
            "fallback-monero-finality",
            &json!({ "reason": reason_ref }),
        ),
        signoff_watcher_quorum_root: record_root(
            "fallback-watcher-quorum",
            &json!({ "reason": reason_ref }),
        ),
        signoff_pq_custody_root: record_root(
            "fallback-pq-custody",
            &json!({ "reason": reason_ref }),
        ),
        signoff_liquidity_root: record_root("fallback-liquidity", &json!({ "reason": reason_ref })),
        signoff_receipt_replay_root: record_root(
            "fallback-receipt-replay",
            &json!({ "reason": reason_ref }),
        ),
        signoff_nullifier_root: record_root("fallback-nullifier", &json!({ "reason": reason_ref })),
        signoff_metadata_root: record_root("fallback-metadata", &json!({ "reason": reason_ref })),
        acceptance_matrix_state_root: record_root(
            "fallback-acceptance-state",
            &json!({ "reason": reason_ref }),
        ),
        acceptance_matrix_root: record_root(
            "fallback-acceptance",
            &json!({ "reason": reason_ref }),
        ),
        acceptance_release_hold_root: record_root(
            "fallback-acceptance-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_schedule_root: record_root(
            "fallback-heavy-gate-schedule",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_checklist_root: record_root(
            "fallback-heavy-gate-checklist",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_execution_receipt_root: record_root(
            "fallback-heavy-gate-receipt",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_readiness_receipt_root: record_root(
            "fallback-heavy-gate-readiness",
            &json!({ "reason": reason_ref }),
        ),
        go_no_go_matrix_root: record_root("fallback-go-no-go", &json!({ "reason": reason_ref })),
        source_root: record_root("fallback-source", &json!({ "reason": reason_ref })),
    };
    let execution_lanes = Vec::new();
    let verdict = ExecutionManifestVerdict::fallback(&config, reason_ref);
    let lane_root = lane_vector_root(&execution_lanes);
    let monero_finality_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::MoneroFinality);
    let watcher_quorum_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::WatcherQuorum);
    let pq_custody_execution_root = domain_lane_root(&execution_lanes, ExecutionDomain::PqCustody);
    let liquidity_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::LiquidityReserve);
    let receipt_replay_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::ReceiptReplay);
    let nullifier_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::NullifierSeparation);
    let metadata_execution_root =
        domain_lane_root(&execution_lanes, ExecutionDomain::MetadataRedaction);
    let release_hold_root =
        manifest_release_hold_root(&config, &source_roots, &execution_lanes, &verdict);
    let manifest_root = manifest_root(
        &config,
        &source_roots,
        &lane_root,
        &release_hold_root,
        &verdict,
    );

    State {
        config,
        source_roots,
        execution_lanes,
        verdict,
        lane_root,
        monero_finality_execution_root,
        watcher_quorum_execution_root,
        pq_custody_execution_root,
        liquidity_execution_root,
        receipt_replay_execution_root,
        nullifier_execution_root,
        metadata_execution_root,
        release_hold_root,
        manifest_root,
    }
}
