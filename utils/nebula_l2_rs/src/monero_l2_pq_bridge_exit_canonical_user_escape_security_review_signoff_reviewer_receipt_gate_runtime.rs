use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSecurityReviewSignoffReviewerReceiptGateRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_REVIEWER_RECEIPT_GATE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-reviewer-receipt-gate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_REVIEWER_RECEIPT_GATE_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-reviewer-receipt-gate";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub gate_suite: String,
    pub receipt_policy: String,
    pub min_reviewer_domains: u64,
    pub require_execution_manifest_root: u64,
    pub require_signoff_bundle_root: u64,
    pub require_audit_manifest_root: u64,
    pub require_live_execution_receipt: u64,
    pub require_human_review_receipt: u64,
    pub require_roots_only_receipts: u64,
    pub require_release_hold_until_all_receipts: u64,
    pub max_release_allowed_receipts: u64,
    pub max_linkage_exports: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            gate_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-reviewer-receipt-gate-v1"
                    .to_string(),
            receipt_policy:
                "seven-domain-reviewer-receipt-gate-with-release-held-until-live-human-signoff-v1"
                    .to_string(),
            min_reviewer_domains: 7,
            require_execution_manifest_root: 1,
            require_signoff_bundle_root: 1,
            require_audit_manifest_root: 1,
            require_live_execution_receipt: 1,
            require_human_review_receipt: 1,
            require_roots_only_receipts: 1,
            require_release_hold_until_all_receipts: 1,
            max_release_allowed_receipts: 0,
            max_linkage_exports: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "gate_suite": self.gate_suite,
            "receipt_policy": self.receipt_policy,
            "min_reviewer_domains": self.min_reviewer_domains,
            "require_execution_manifest_root": self.require_execution_manifest_root,
            "require_signoff_bundle_root": self.require_signoff_bundle_root,
            "require_audit_manifest_root": self.require_audit_manifest_root,
            "require_live_execution_receipt": self.require_live_execution_receipt,
            "require_human_review_receipt": self.require_human_review_receipt,
            "require_roots_only_receipts": self.require_roots_only_receipts,
            "require_release_hold_until_all_receipts": self.require_release_hold_until_all_receipts,
            "max_release_allowed_receipts": self.max_release_allowed_receipts,
            "max_linkage_exports": self.max_linkage_exports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerDomain {
    MoneroFinality,
    WatcherQuorum,
    PqCustody,
    LiquidityReserve,
    ReceiptReplay,
    NullifierSeparation,
    MetadataRedaction,
}

impl ReviewerDomain {
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

    pub fn reviewer_lane(self) -> &'static str {
        match self {
            Self::MoneroFinality => "monero_finality_reviewer_receipt",
            Self::WatcherQuorum => "watcher_quorum_reviewer_receipt",
            Self::PqCustody => "pq_custody_reviewer_receipt",
            Self::LiquidityReserve => "liquidity_reserve_reviewer_receipt",
            Self::ReceiptReplay => "receipt_replay_reviewer_receipt",
            Self::NullifierSeparation => "nullifier_separation_reviewer_receipt",
            Self::MetadataRedaction => "metadata_redaction_reviewer_receipt",
        }
    }

    pub fn receipt_question(self) -> &'static str {
        match self {
            Self::MoneroFinality => {
                "Did the reviewer receive live Monero finality roots and keep release held on reorg risk?"
            }
            Self::WatcherQuorum => {
                "Did the reviewer receive watcher quorum roots and keep release held on collusion or stale evidence?"
            }
            Self::PqCustody => {
                "Did the reviewer receive fresh PQ custody roots and keep release held on stale authority evidence?"
            }
            Self::LiquidityReserve => {
                "Did the reviewer receive reserve roots and keep release held when exit coverage is not proven?"
            }
            Self::ReceiptReplay => {
                "Did the reviewer receive receipt replay roots and keep release held on forged or duplicate receipts?"
            }
            Self::NullifierSeparation => {
                "Did the reviewer receive nullifier roots without private note linkage?"
            }
            Self::MetadataRedaction => {
                "Did the reviewer receive wallet export roots with no linkable metadata fields?"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGateStatus {
    PendingLiveReceipt,
    PendingHumanReceipt,
    ReleaseHeld,
}

impl ReceiptGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingLiveReceipt => "pending_live_receipt",
            Self::PendingHumanReceipt => "pending_human_receipt",
            Self::ReleaseHeld => "release_held",
        }
    }

    pub fn release_allowed(self) -> u64 {
        match self {
            Self::PendingLiveReceipt | Self::PendingHumanReceipt | Self::ReleaseHeld => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoots {
    pub execution_manifest_state_root: String,
    pub execution_manifest_root: String,
    pub execution_lane_root: String,
    pub execution_release_hold_root: String,
    pub execution_verdict_root: String,
    pub execution_monero_finality_root: String,
    pub execution_watcher_quorum_root: String,
    pub execution_pq_custody_root: String,
    pub execution_liquidity_root: String,
    pub execution_receipt_replay_root: String,
    pub execution_nullifier_root: String,
    pub execution_metadata_root: String,
    pub signoff_bundle_state_root: String,
    pub signoff_bundle_root: String,
    pub signoff_packet_root: String,
    pub signoff_release_hold_root: String,
    pub audit_manifest_state_root: String,
    pub heavy_gate_execution_receipt_root: String,
    pub heavy_gate_readiness_receipt_root: String,
    pub go_no_go_matrix_root: String,
    pub source_root: String,
}

impl SourceRoots {
    pub fn devnet() -> Self {
        let execution_manifest =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_execution_manifest_runtime::devnet();
        let signoff_bundle =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_bundle_runtime::devnet();
        let audit_manifest =
            crate::monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime::devnet();
        let execution_manifest_state_root = execution_manifest.state_root();
        let execution_manifest_root = execution_manifest.manifest_root.clone();
        let execution_lane_root = execution_manifest.lane_root.clone();
        let execution_release_hold_root = execution_manifest.release_hold_root.clone();
        let execution_verdict_root = execution_manifest.verdict.verdict_root.clone();
        let execution_monero_finality_root =
            execution_manifest.monero_finality_execution_root.clone();
        let execution_watcher_quorum_root =
            execution_manifest.watcher_quorum_execution_root.clone();
        let execution_pq_custody_root = execution_manifest.pq_custody_execution_root.clone();
        let execution_liquidity_root = execution_manifest.liquidity_execution_root.clone();
        let execution_receipt_replay_root =
            execution_manifest.receipt_replay_execution_root.clone();
        let execution_nullifier_root = execution_manifest.nullifier_execution_root.clone();
        let execution_metadata_root = execution_manifest.metadata_execution_root.clone();
        let signoff_bundle_state_root = signoff_bundle.state_root();
        let signoff_bundle_root = signoff_bundle.bundle_root.clone();
        let signoff_packet_root = signoff_bundle.packet_root.clone();
        let signoff_release_hold_root = signoff_bundle.release_hold_root.clone();
        let audit_manifest_state_root = audit_manifest.state_root();
        let heavy_gate_execution_receipt_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_execution_receipt_runtime::state_root();
        let heavy_gate_readiness_receipt_root =
            crate::monero_l2_pq_bridge_exit_canonical_heavy_gate_readiness_receipt_runtime::state_root();
        let go_no_go_matrix_root =
            crate::monero_l2_pq_bridge_exit_canonical_release_candidate_go_no_go_matrix_runtime::state_root();
        let source_root = source_root(
            &execution_manifest_state_root,
            &execution_manifest_root,
            &execution_lane_root,
            &execution_release_hold_root,
            &execution_verdict_root,
            &signoff_bundle_root,
            &signoff_release_hold_root,
            &audit_manifest_state_root,
            &heavy_gate_execution_receipt_root,
            &heavy_gate_readiness_receipt_root,
            &go_no_go_matrix_root,
        );

        Self {
            execution_manifest_state_root,
            execution_manifest_root,
            execution_lane_root,
            execution_release_hold_root,
            execution_verdict_root,
            execution_monero_finality_root,
            execution_watcher_quorum_root,
            execution_pq_custody_root,
            execution_liquidity_root,
            execution_receipt_replay_root,
            execution_nullifier_root,
            execution_metadata_root,
            signoff_bundle_state_root,
            signoff_bundle_root,
            signoff_packet_root,
            signoff_release_hold_root,
            audit_manifest_state_root,
            heavy_gate_execution_receipt_root,
            heavy_gate_readiness_receipt_root,
            go_no_go_matrix_root,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_manifest_state_root": self.execution_manifest_state_root,
            "execution_manifest_root": self.execution_manifest_root,
            "execution_lane_root": self.execution_lane_root,
            "execution_release_hold_root": self.execution_release_hold_root,
            "execution_verdict_root": self.execution_verdict_root,
            "execution_monero_finality_root": self.execution_monero_finality_root,
            "execution_watcher_quorum_root": self.execution_watcher_quorum_root,
            "execution_pq_custody_root": self.execution_pq_custody_root,
            "execution_liquidity_root": self.execution_liquidity_root,
            "execution_receipt_replay_root": self.execution_receipt_replay_root,
            "execution_nullifier_root": self.execution_nullifier_root,
            "execution_metadata_root": self.execution_metadata_root,
            "signoff_bundle_state_root": self.signoff_bundle_state_root,
            "signoff_bundle_root": self.signoff_bundle_root,
            "signoff_packet_root": self.signoff_packet_root,
            "signoff_release_hold_root": self.signoff_release_hold_root,
            "audit_manifest_state_root": self.audit_manifest_state_root,
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
pub struct ReviewerReceiptRequirement {
    pub ordinal: u64,
    pub domain: ReviewerDomain,
    pub reviewer_lane: String,
    pub receipt_question: String,
    pub status: ReceiptGateStatus,
    pub execution_lane_root: String,
    pub live_execution_receipt_root: String,
    pub human_review_receipt_root: String,
    pub redaction_receipt_root: String,
    pub release_decision_root: String,
    pub reviewer_receipt_root: String,
    pub release_hold_root: String,
    pub live_execution_required: u64,
    pub human_review_required: u64,
    pub roots_only_required: u64,
    pub release_allowed: u64,
    pub linkage_exports_allowed: u64,
    pub requirement_root: String,
}

impl ReviewerReceiptRequirement {
    pub fn devnet(
        config: &Config,
        source: &SourceRoots,
        domain: ReviewerDomain,
        ordinal: u64,
    ) -> Self {
        let status = ReceiptGateStatus::PendingLiveReceipt;
        let execution_lane_root = execution_domain_root(source, domain).to_string();
        let live_execution_receipt_root =
            live_execution_receipt_root(config, source, domain, &execution_lane_root);
        let human_review_receipt_root =
            human_review_receipt_root(config, source, domain, &live_execution_receipt_root);
        let redaction_receipt_root =
            redaction_receipt_root(config, source, domain, &human_review_receipt_root);
        let release_decision_root = release_decision_root(
            config,
            source,
            domain,
            &live_execution_receipt_root,
            &human_review_receipt_root,
            &redaction_receipt_root,
        );
        let reviewer_receipt_root = reviewer_receipt_root(
            config,
            source,
            domain,
            &execution_lane_root,
            &live_execution_receipt_root,
            &human_review_receipt_root,
            &redaction_receipt_root,
            &release_decision_root,
        );
        let release_hold_root =
            requirement_release_hold_root(config, source, domain, &reviewer_receipt_root);
        let requirement_root = requirement_root(
            config,
            source,
            domain,
            ordinal,
            status,
            &execution_lane_root,
            &live_execution_receipt_root,
            &human_review_receipt_root,
            &redaction_receipt_root,
            &release_decision_root,
            &reviewer_receipt_root,
            &release_hold_root,
        );

        Self {
            ordinal,
            domain,
            reviewer_lane: domain.reviewer_lane().to_string(),
            receipt_question: domain.receipt_question().to_string(),
            status,
            execution_lane_root,
            live_execution_receipt_root,
            human_review_receipt_root,
            redaction_receipt_root,
            release_decision_root,
            reviewer_receipt_root,
            release_hold_root,
            live_execution_required: config.require_live_execution_receipt,
            human_review_required: config.require_human_review_receipt,
            roots_only_required: config.require_roots_only_receipts,
            release_allowed: status.release_allowed(),
            linkage_exports_allowed: config.max_linkage_exports,
            requirement_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "domain": self.domain.as_str(),
            "reviewer_lane": self.reviewer_lane,
            "receipt_question": self.receipt_question,
            "status": self.status.as_str(),
            "execution_lane_root": self.execution_lane_root,
            "live_execution_receipt_root": self.live_execution_receipt_root,
            "human_review_receipt_root": self.human_review_receipt_root,
            "redaction_receipt_root": self.redaction_receipt_root,
            "release_decision_root": self.release_decision_root,
            "reviewer_receipt_root": self.reviewer_receipt_root,
            "release_hold_root": self.release_hold_root,
            "live_execution_required": self.live_execution_required,
            "human_review_required": self.human_review_required,
            "roots_only_required": self.roots_only_required,
            "release_allowed": self.release_allowed,
            "linkage_exports_allowed": self.linkage_exports_allowed,
            "requirement_root": self.requirement_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerReceiptGateVerdict {
    pub reviewer_domain_count: u64,
    pub pending_live_receipt_count: u64,
    pub pending_human_receipt_count: u64,
    pub release_held_count: u64,
    pub release_allowed_count: u64,
    pub zero_linkage_receipt_count: u64,
    pub live_execution_required_count: u64,
    pub human_review_required_count: u64,
    pub roots_only_required_count: u64,
    pub gate_status: String,
    pub verdict_root: String,
}

impl ReviewerReceiptGateVerdict {
    pub fn new(config: &Config, requirements: &[ReviewerReceiptRequirement]) -> Self {
        let reviewer_domain_count = requirements.len() as u64;
        let pending_live_receipt_count =
            count_status(requirements, ReceiptGateStatus::PendingLiveReceipt);
        let pending_human_receipt_count =
            count_status(requirements, ReceiptGateStatus::PendingHumanReceipt);
        let release_held_count = requirements
            .iter()
            .filter(|item| item.release_allowed == 0)
            .count() as u64;
        let release_allowed_count = requirements
            .iter()
            .filter(|item| item.release_allowed == 1)
            .count() as u64;
        let zero_linkage_receipt_count = requirements
            .iter()
            .filter(|item| item.linkage_exports_allowed <= config.max_linkage_exports)
            .count() as u64;
        let live_execution_required_count = requirements
            .iter()
            .filter(|item| item.live_execution_required == 1)
            .count() as u64;
        let human_review_required_count = requirements
            .iter()
            .filter(|item| item.human_review_required == 1)
            .count() as u64;
        let roots_only_required_count = requirements
            .iter()
            .filter(|item| item.roots_only_required == 1)
            .count() as u64;
        let gate_status = if reviewer_domain_count >= config.min_reviewer_domains
            && pending_live_receipt_count == reviewer_domain_count
            && release_allowed_count <= config.max_release_allowed_receipts
            && release_held_count == reviewer_domain_count
            && zero_linkage_receipt_count == reviewer_domain_count
            && live_execution_required_count == reviewer_domain_count
            && human_review_required_count == reviewer_domain_count
            && roots_only_required_count == reviewer_domain_count
        {
            "reviewer_receipt_gate_ready_for_live_receipts_release_held"
        } else {
            "reviewer_receipt_gate_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.receipt_policy),
                HashPart::U64(reviewer_domain_count),
                HashPart::U64(pending_live_receipt_count),
                HashPart::U64(pending_human_receipt_count),
                HashPart::U64(release_held_count),
                HashPart::U64(release_allowed_count),
                HashPart::U64(zero_linkage_receipt_count),
                HashPart::U64(live_execution_required_count),
                HashPart::U64(human_review_required_count),
                HashPart::U64(roots_only_required_count),
                HashPart::Str(&gate_status),
            ],
            32,
        );

        Self {
            reviewer_domain_count,
            pending_live_receipt_count,
            pending_human_receipt_count,
            release_held_count,
            release_allowed_count,
            zero_linkage_receipt_count,
            live_execution_required_count,
            human_review_required_count,
            roots_only_required_count,
            gate_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let gate_status = "reviewer_receipt_gate_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.receipt_policy),
                HashPart::Str(reason),
                HashPart::Str(&gate_status),
            ],
            32,
        );

        Self {
            reviewer_domain_count: 0,
            pending_live_receipt_count: 0,
            pending_human_receipt_count: 0,
            release_held_count: 1,
            release_allowed_count: 0,
            zero_linkage_receipt_count: 0,
            live_execution_required_count: 0,
            human_review_required_count: 0,
            roots_only_required_count: 0,
            gate_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reviewer_domain_count": self.reviewer_domain_count,
            "pending_live_receipt_count": self.pending_live_receipt_count,
            "pending_human_receipt_count": self.pending_human_receipt_count,
            "release_held_count": self.release_held_count,
            "release_allowed_count": self.release_allowed_count,
            "zero_linkage_receipt_count": self.zero_linkage_receipt_count,
            "live_execution_required_count": self.live_execution_required_count,
            "human_review_required_count": self.human_review_required_count,
            "roots_only_required_count": self.roots_only_required_count,
            "gate_status": self.gate_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source_roots: SourceRoots,
    pub requirements: Vec<ReviewerReceiptRequirement>,
    pub verdict: ReviewerReceiptGateVerdict,
    pub requirement_root: String,
    pub monero_finality_receipt_root: String,
    pub watcher_quorum_receipt_root: String,
    pub pq_custody_receipt_root: String,
    pub liquidity_receipt_root: String,
    pub receipt_replay_receipt_root: String,
    pub nullifier_receipt_root: String,
    pub metadata_receipt_root: String,
    pub release_hold_root: String,
    pub gate_root: String,
}

impl State {
    pub fn new(config: Config, source_roots: SourceRoots) -> Result<Self> {
        validate_config(&config)?;
        let requirements = ReviewerDomain::ordered()
            .iter()
            .enumerate()
            .map(|(index, domain)| {
                ReviewerReceiptRequirement::devnet(
                    &config,
                    &source_roots,
                    *domain,
                    index as u64 + 1,
                )
            })
            .collect::<Vec<_>>();
        let verdict = ReviewerReceiptGateVerdict::new(&config, &requirements);
        let requirement_root = requirement_vector_root(&requirements);
        let monero_finality_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::MoneroFinality);
        let watcher_quorum_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::WatcherQuorum);
        let pq_custody_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::PqCustody);
        let liquidity_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::LiquidityReserve);
        let receipt_replay_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::ReceiptReplay);
        let nullifier_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::NullifierSeparation);
        let metadata_receipt_root =
            domain_requirement_root(&requirements, ReviewerDomain::MetadataRedaction);
        let release_hold_root =
            gate_release_hold_root(&config, &source_roots, &requirements, &verdict);
        let gate_root = gate_root(
            &config,
            &source_roots,
            &requirement_root,
            &release_hold_root,
            &verdict,
        );

        Ok(Self {
            config,
            source_roots,
            requirements,
            verdict,
            requirement_root,
            monero_finality_receipt_root,
            watcher_quorum_receipt_root,
            pq_custody_receipt_root,
            liquidity_receipt_root,
            receipt_replay_receipt_root,
            nullifier_receipt_root,
            metadata_receipt_root,
            release_hold_root,
            gate_root,
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
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_reviewer_receipt_gate_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source_roots": self.source_roots.public_record(),
            "requirement_root": self.requirement_root,
            "monero_finality_receipt_root": self.monero_finality_receipt_root,
            "watcher_quorum_receipt_root": self.watcher_quorum_receipt_root,
            "pq_custody_receipt_root": self.pq_custody_receipt_root,
            "liquidity_receipt_root": self.liquidity_receipt_root,
            "receipt_replay_receipt_root": self.receipt_replay_receipt_root,
            "nullifier_receipt_root": self.nullifier_receipt_root,
            "metadata_receipt_root": self.metadata_receipt_root,
            "release_hold_root": self.release_hold_root,
            "gate_root": self.gate_root,
            "verdict": self.verdict.public_record(),
            "requirements": self
                .requirements
                .iter()
                .map(ReviewerReceiptRequirement::public_record)
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
                "requirement_root": self.requirement_root,
                "release_hold_root": self.release_hold_root,
                "gate_root": self.gate_root,
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
    if config.min_reviewer_domains < ReviewerDomain::ordered().len() as u64 {
        return Err("reviewer receipt gate must cover every security domain".to_string());
    }
    if config.require_release_hold_until_all_receipts != 1 {
        return Err(
            "reviewer receipt gate must keep release held until every receipt exists".to_string(),
        );
    }
    if config.max_release_allowed_receipts != 0 {
        return Err(
            "reviewer receipt gate cannot allow release before reviewer receipts".to_string(),
        );
    }
    if config.max_linkage_exports != 0 {
        return Err("reviewer receipt gate must keep receipts roots-only".to_string());
    }
    Ok(())
}

fn execution_domain_root(source: &SourceRoots, domain: ReviewerDomain) -> &str {
    match domain {
        ReviewerDomain::MoneroFinality => &source.execution_monero_finality_root,
        ReviewerDomain::WatcherQuorum => &source.execution_watcher_quorum_root,
        ReviewerDomain::PqCustody => &source.execution_pq_custody_root,
        ReviewerDomain::LiquidityReserve => &source.execution_liquidity_root,
        ReviewerDomain::ReceiptReplay => &source.execution_receipt_replay_root,
        ReviewerDomain::NullifierSeparation => &source.execution_nullifier_root,
        ReviewerDomain::MetadataRedaction => &source.execution_metadata_root,
    }
}

fn live_execution_receipt_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    execution_lane_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:live-execution-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(execution_lane_root),
            HashPart::Str(&source.execution_manifest_root),
            HashPart::Str(&source.heavy_gate_execution_receipt_root),
            HashPart::Str(&source.heavy_gate_readiness_receipt_root),
            HashPart::U64(config.require_live_execution_receipt),
            HashPart::U64(0),
        ],
        32,
    )
}

fn human_review_receipt_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    live_execution_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:human-review-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.audit_manifest_state_root),
            HashPart::Str(&source.signoff_bundle_root),
            HashPart::Str(&source.signoff_packet_root),
            HashPart::Str(live_execution_receipt_root),
            HashPart::U64(config.require_human_review_receipt),
            HashPart::U64(0),
        ],
        32,
    )
}

fn redaction_receipt_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    human_review_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:redaction-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.signoff_release_hold_root),
            HashPart::Str(human_review_receipt_root),
            HashPart::U64(config.require_roots_only_receipts),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn release_decision_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    live_execution_receipt_root: &str,
    human_review_receipt_root: &str,
    redaction_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-decision"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.execution_release_hold_root),
            HashPart::Str(&source.signoff_release_hold_root),
            HashPart::Str(live_execution_receipt_root),
            HashPart::Str(human_review_receipt_root),
            HashPart::Str(redaction_receipt_root),
            HashPart::Str(&source.go_no_go_matrix_root),
            HashPart::U64(config.require_release_hold_until_all_receipts),
            HashPart::U64(0),
        ],
        32,
    )
}

fn reviewer_receipt_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    execution_lane_root: &str,
    live_execution_receipt_root: &str,
    human_review_receipt_root: &str,
    redaction_receipt_root: &str,
    release_decision_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:reviewer-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.gate_suite),
            HashPart::Str(&source.source_root),
            HashPart::Str(domain.as_str()),
            HashPart::Str(domain.reviewer_lane()),
            HashPart::Str(execution_lane_root),
            HashPart::Str(live_execution_receipt_root),
            HashPart::Str(human_review_receipt_root),
            HashPart::Str(redaction_receipt_root),
            HashPart::Str(release_decision_root),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn requirement_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    reviewer_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:requirement-release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.execution_release_hold_root),
            HashPart::Str(&source.signoff_release_hold_root),
            HashPart::Str(reviewer_receipt_root),
            HashPart::U64(config.require_release_hold_until_all_receipts),
            HashPart::U64(0),
        ],
        32,
    )
}

fn requirement_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewerDomain,
    ordinal: u64,
    status: ReceiptGateStatus,
    execution_lane_root: &str,
    live_execution_receipt_root: &str,
    human_review_receipt_root: &str,
    redaction_receipt_root: &str,
    release_decision_root: &str,
    reviewer_receipt_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:requirement"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(&source.source_root),
            HashPart::U64(ordinal),
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(execution_lane_root),
            HashPart::Str(live_execution_receipt_root),
            HashPart::Str(human_review_receipt_root),
            HashPart::Str(redaction_receipt_root),
            HashPart::Str(release_decision_root),
            HashPart::Str(reviewer_receipt_root),
            HashPart::Str(release_hold_root),
            HashPart::U64(status.release_allowed()),
        ],
        32,
    )
}

fn count_status(requirements: &[ReviewerReceiptRequirement], status: ReceiptGateStatus) -> u64 {
    requirements
        .iter()
        .filter(|item| item.status == status)
        .count() as u64
}

fn requirement_vector_root(requirements: &[ReviewerReceiptRequirement]) -> String {
    let leaves = requirements
        .iter()
        .map(ReviewerReceiptRequirement::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:requirement-root"), &leaves)
}

fn domain_requirement_root(
    requirements: &[ReviewerReceiptRequirement],
    domain: ReviewerDomain,
) -> String {
    let leaves = requirements
        .iter()
        .filter(|item| item.domain == domain)
        .map(ReviewerReceiptRequirement::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("{DOMAIN}:{}-requirement-root", domain.as_str()),
        &leaves,
    )
}

fn gate_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    requirements: &[ReviewerReceiptRequirement],
    verdict: &ReviewerReceiptGateVerdict,
) -> String {
    let leaves = requirements
        .iter()
        .filter(|item| item.release_allowed == 0)
        .map(ReviewerReceiptRequirement::public_record)
        .collect::<Vec<_>>();
    let held_requirement_root = merkle_root(&format!("{DOMAIN}:held-requirement-root"), &leaves);
    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_policy),
            HashPart::Str(&source.source_root),
            HashPart::Str(&held_requirement_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_held_count),
            HashPart::U64(config.require_release_hold_until_all_receipts),
        ],
        32,
    )
}

fn gate_root(
    config: &Config,
    source: &SourceRoots,
    requirement_root: &str,
    release_hold_root: &str,
    verdict: &ReviewerReceiptGateVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:gate"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.gate_suite),
            HashPart::Str(&source.source_root),
            HashPart::Str(requirement_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_allowed_count),
        ],
        32,
    )
}

fn source_root(
    execution_manifest_state_root: &str,
    execution_manifest_root: &str,
    execution_lane_root: &str,
    execution_release_hold_root: &str,
    execution_verdict_root: &str,
    signoff_bundle_root: &str,
    signoff_release_hold_root: &str,
    audit_manifest_state_root: &str,
    heavy_gate_execution_receipt_root: &str,
    heavy_gate_readiness_receipt_root: &str,
    go_no_go_matrix_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(execution_manifest_state_root),
            HashPart::Str(execution_manifest_root),
            HashPart::Str(execution_lane_root),
            HashPart::Str(execution_release_hold_root),
            HashPart::Str(execution_verdict_root),
            HashPart::Str(signoff_bundle_root),
            HashPart::Str(signoff_release_hold_root),
            HashPart::Str(audit_manifest_state_root),
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
        execution_manifest_state_root: record_root(
            "fallback-execution-manifest-state",
            &json!({ "reason": reason_ref }),
        ),
        execution_manifest_root: record_root(
            "fallback-execution-manifest",
            &json!({ "reason": reason_ref }),
        ),
        execution_lane_root: record_root(
            "fallback-execution-lane",
            &json!({ "reason": reason_ref }),
        ),
        execution_release_hold_root: record_root(
            "fallback-execution-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        execution_verdict_root: record_root(
            "fallback-execution-verdict",
            &json!({ "reason": reason_ref }),
        ),
        execution_monero_finality_root: record_root(
            "fallback-monero-finality",
            &json!({ "reason": reason_ref }),
        ),
        execution_watcher_quorum_root: record_root(
            "fallback-watcher-quorum",
            &json!({ "reason": reason_ref }),
        ),
        execution_pq_custody_root: record_root(
            "fallback-pq-custody",
            &json!({ "reason": reason_ref }),
        ),
        execution_liquidity_root: record_root(
            "fallback-liquidity",
            &json!({ "reason": reason_ref }),
        ),
        execution_receipt_replay_root: record_root(
            "fallback-receipt-replay",
            &json!({ "reason": reason_ref }),
        ),
        execution_nullifier_root: record_root(
            "fallback-nullifier",
            &json!({ "reason": reason_ref }),
        ),
        execution_metadata_root: record_root("fallback-metadata", &json!({ "reason": reason_ref })),
        signoff_bundle_state_root: record_root(
            "fallback-signoff-bundle-state",
            &json!({ "reason": reason_ref }),
        ),
        signoff_bundle_root: record_root(
            "fallback-signoff-bundle",
            &json!({ "reason": reason_ref }),
        ),
        signoff_packet_root: record_root(
            "fallback-signoff-packet",
            &json!({ "reason": reason_ref }),
        ),
        signoff_release_hold_root: record_root(
            "fallback-signoff-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        audit_manifest_state_root: record_root(
            "fallback-audit-manifest",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_execution_receipt_root: record_root(
            "fallback-heavy-gate-execution-receipt",
            &json!({ "reason": reason_ref }),
        ),
        heavy_gate_readiness_receipt_root: record_root(
            "fallback-heavy-gate-readiness-receipt",
            &json!({ "reason": reason_ref }),
        ),
        go_no_go_matrix_root: record_root("fallback-go-no-go", &json!({ "reason": reason_ref })),
        source_root: record_root("fallback-source", &json!({ "reason": reason_ref })),
    };
    let requirements = Vec::new();
    let verdict = ReviewerReceiptGateVerdict::fallback(&config, reason_ref);
    let requirement_root = requirement_vector_root(&requirements);
    let monero_finality_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::MoneroFinality);
    let watcher_quorum_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::WatcherQuorum);
    let pq_custody_receipt_root = domain_requirement_root(&requirements, ReviewerDomain::PqCustody);
    let liquidity_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::LiquidityReserve);
    let receipt_replay_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::ReceiptReplay);
    let nullifier_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::NullifierSeparation);
    let metadata_receipt_root =
        domain_requirement_root(&requirements, ReviewerDomain::MetadataRedaction);
    let release_hold_root = gate_release_hold_root(&config, &source_roots, &requirements, &verdict);
    let gate_root = gate_root(
        &config,
        &source_roots,
        &requirement_root,
        &release_hold_root,
        &verdict,
    );

    State {
        config,
        source_roots,
        requirements,
        verdict,
        requirement_root,
        monero_finality_receipt_root,
        watcher_quorum_receipt_root,
        pq_custody_receipt_root,
        liquidity_receipt_root,
        receipt_replay_receipt_root,
        nullifier_receipt_root,
        metadata_receipt_root,
        release_hold_root,
        gate_root,
    }
}
