use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSecurityReviewSignoffBundleRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_BUNDLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-bundle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_SIGNOFF_BUNDLE_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-bundle";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub bundle_suite: String,
    pub review_policy: String,
    pub min_review_domains: u64,
    pub require_acceptance_matrix_root: u64,
    pub require_existing_audit_manifest_root: u64,
    pub require_human_review_before_release: u64,
    pub require_live_execution_before_signoff: u64,
    pub require_release_hold_until_signoff: u64,
    pub max_approved_release_blockers: u64,
    pub max_linkage_fields: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            bundle_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-signoff-bundle-v1"
                    .to_string(),
            review_policy:
                "acceptance-matrix-domain-review-with-release-held-until-human-signoff-v1"
                    .to_string(),
            min_review_domains: 7,
            require_acceptance_matrix_root: 1,
            require_existing_audit_manifest_root: 1,
            require_human_review_before_release: 1,
            require_live_execution_before_signoff: 1,
            require_release_hold_until_signoff: 1,
            max_approved_release_blockers: 0,
            max_linkage_fields: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "bundle_suite": self.bundle_suite,
            "review_policy": self.review_policy,
            "min_review_domains": self.min_review_domains,
            "require_acceptance_matrix_root": self.require_acceptance_matrix_root,
            "require_existing_audit_manifest_root": self.require_existing_audit_manifest_root,
            "require_human_review_before_release": self.require_human_review_before_release,
            "require_live_execution_before_signoff": self.require_live_execution_before_signoff,
            "require_release_hold_until_signoff": self.require_release_hold_until_signoff,
            "max_approved_release_blockers": self.max_approved_release_blockers,
            "max_linkage_fields": self.max_linkage_fields,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDomain {
    MoneroFinality,
    WatcherQuorum,
    PqCustody,
    LiquidityReserve,
    ReceiptReplay,
    NullifierSeparation,
    MetadataRedaction,
}

impl ReviewDomain {
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

    pub fn reviewer_label(self) -> &'static str {
        match self {
            Self::MoneroFinality => "Monero finality reviewer",
            Self::WatcherQuorum => "watcher quorum reviewer",
            Self::PqCustody => "post-quantum custody reviewer",
            Self::LiquidityReserve => "liquidity reserve reviewer",
            Self::ReceiptReplay => "receipt replay reviewer",
            Self::NullifierSeparation => "nullifier separation reviewer",
            Self::MetadataRedaction => "metadata redaction reviewer",
        }
    }

    pub fn review_question(self) -> &'static str {
        match self {
            Self::MoneroFinality => {
                "Do Monero lock, finality, and reorg quarantine roots force a hold when finality is weak?"
            }
            Self::WatcherQuorum => {
                "Do watcher quorum and collusion roots reject or hold forged quorum evidence?"
            }
            Self::PqCustody => {
                "Do PQ authority, rotation, revocation, and withdrawal authorization roots prevent stale custody release?"
            }
            Self::LiquidityReserve => {
                "Do reserve and backstop roots hold release when exit liquidity is below exposure?"
            }
            Self::ReceiptReplay => {
                "Do settlement receipt, transcript replay, and duplicate receipt roots reject forged receipts?"
            }
            Self::NullifierSeparation => {
                "Do private-note, nullifier, wallet-scan, and claim roots reject replayed withdrawals?"
            }
            Self::MetadataRedaction => {
                "Do wallet export and privacy-boundary roots prevent linkable metadata disclosure?"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    PendingLiveExecution,
    PendingHumanReview,
    Blocked,
}

impl ReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingLiveExecution => "pending_live_execution",
            Self::PendingHumanReview => "pending_human_review",
            Self::Blocked => "blocked",
        }
    }

    pub fn release_allowed(self) -> u64 {
        match self {
            Self::PendingLiveExecution | Self::PendingHumanReview | Self::Blocked => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoots {
    pub acceptance_matrix_state_root: String,
    pub acceptance_matrix_public_record_root: String,
    pub acceptance_matrix_root: String,
    pub acceptance_release_hold_root: String,
    pub existing_audit_signoff_state_root: String,
    pub forced_exit_dry_run_root: String,
    pub wallet_handoff_root: String,
    pub process_feed_binding_root: String,
    pub source_root: String,
}

impl SourceRoots {
    pub fn devnet() -> Self {
        let acceptance_matrix =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_threat_model_acceptance_matrix_runtime::devnet();
        let existing_audit =
            crate::monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime::devnet();
        let dry_run =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_vertical_dry_run_runtime::devnet();
        let wallet_handoff =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_dry_run_wallet_handoff_runtime::devnet();
        let acceptance_matrix_state_root = acceptance_matrix.state_root();
        let acceptance_matrix_public_record_root = record_root(
            "acceptance-matrix-public-record",
            &acceptance_matrix.public_record(),
        );
        let acceptance_matrix_root = acceptance_matrix.matrix_root;
        let acceptance_release_hold_root = acceptance_matrix.release_hold_root;
        let existing_audit_signoff_state_root = existing_audit.state_root();
        let forced_exit_dry_run_root = dry_run.state_root();
        let wallet_handoff_root = wallet_handoff.state_root();
        let process_feed_binding_root =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root();
        let source_root = source_root(
            &acceptance_matrix_state_root,
            &acceptance_matrix_root,
            &acceptance_release_hold_root,
            &existing_audit_signoff_state_root,
            &forced_exit_dry_run_root,
            &wallet_handoff_root,
            &process_feed_binding_root,
        );

        Self {
            acceptance_matrix_state_root,
            acceptance_matrix_public_record_root,
            acceptance_matrix_root,
            acceptance_release_hold_root,
            existing_audit_signoff_state_root,
            forced_exit_dry_run_root,
            wallet_handoff_root,
            process_feed_binding_root,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acceptance_matrix_state_root": self.acceptance_matrix_state_root,
            "acceptance_matrix_public_record_root": self.acceptance_matrix_public_record_root,
            "acceptance_matrix_root": self.acceptance_matrix_root,
            "acceptance_release_hold_root": self.acceptance_release_hold_root,
            "existing_audit_signoff_state_root": self.existing_audit_signoff_state_root,
            "forced_exit_dry_run_root": self.forced_exit_dry_run_root,
            "wallet_handoff_root": self.wallet_handoff_root,
            "process_feed_binding_root": self.process_feed_binding_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPacket {
    pub ordinal: u64,
    pub domain: ReviewDomain,
    pub reviewer_label: String,
    pub review_question: String,
    pub status: ReviewStatus,
    pub acceptance_criteria_root: String,
    pub evidence_root: String,
    pub reviewer_packet_root: String,
    pub release_hold_root: String,
    pub manual_review_required: u64,
    pub live_execution_required: u64,
    pub release_allowed: u64,
    pub linkage_fields_allowed: u64,
    pub packet_root: String,
}

impl ReviewPacket {
    pub fn devnet(
        config: &Config,
        source: &SourceRoots,
        domain: ReviewDomain,
        ordinal: u64,
    ) -> Self {
        let status = ReviewStatus::PendingLiveExecution;
        let acceptance_criteria_root = acceptance_criteria_root(domain, source);
        let evidence_root = evidence_root(domain, source);
        let reviewer_packet_root = reviewer_packet_root(
            config,
            source,
            domain,
            &acceptance_criteria_root,
            &evidence_root,
        );
        let release_hold_root =
            domain_release_hold_root(config, source, domain, &reviewer_packet_root);
        let packet_root = domain_hash(
            &format!("{DOMAIN}:review-packet"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(ordinal),
                HashPart::Str(domain.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&acceptance_criteria_root),
                HashPart::Str(&evidence_root),
                HashPart::Str(&reviewer_packet_root),
                HashPart::Str(&release_hold_root),
                HashPart::U64(config.require_human_review_before_release),
                HashPart::U64(config.require_live_execution_before_signoff),
                HashPart::U64(status.release_allowed()),
                HashPart::U64(config.max_linkage_fields),
            ],
            32,
        );

        Self {
            ordinal,
            domain,
            reviewer_label: domain.reviewer_label().to_string(),
            review_question: domain.review_question().to_string(),
            status,
            acceptance_criteria_root,
            evidence_root,
            reviewer_packet_root,
            release_hold_root,
            manual_review_required: config.require_human_review_before_release,
            live_execution_required: config.require_live_execution_before_signoff,
            release_allowed: status.release_allowed(),
            linkage_fields_allowed: config.max_linkage_fields,
            packet_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "domain": self.domain.as_str(),
            "reviewer_label": self.reviewer_label,
            "review_question": self.review_question,
            "status": self.status.as_str(),
            "acceptance_criteria_root": self.acceptance_criteria_root,
            "evidence_root": self.evidence_root,
            "reviewer_packet_root": self.reviewer_packet_root,
            "release_hold_root": self.release_hold_root,
            "manual_review_required": self.manual_review_required,
            "live_execution_required": self.live_execution_required,
            "release_allowed": self.release_allowed,
            "linkage_fields_allowed": self.linkage_fields_allowed,
            "packet_root": self.packet_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignoffBundleVerdict {
    pub review_domain_count: u64,
    pub pending_live_execution_count: u64,
    pub pending_human_review_count: u64,
    pub blocked_count: u64,
    pub release_allowed_count: u64,
    pub release_hold_count: u64,
    pub zero_linkage_domain_count: u64,
    pub bundle_status: String,
    pub verdict_root: String,
}

impl SignoffBundleVerdict {
    pub fn new(config: &Config, packets: &[ReviewPacket]) -> Self {
        let review_domain_count = packets.len() as u64;
        let pending_live_execution_count =
            count_status(packets, ReviewStatus::PendingLiveExecution);
        let pending_human_review_count = count_status(packets, ReviewStatus::PendingHumanReview);
        let blocked_count = count_status(packets, ReviewStatus::Blocked);
        let release_allowed_count = packets
            .iter()
            .filter(|packet| packet.release_allowed == 1)
            .count() as u64;
        let release_hold_count = packets
            .iter()
            .filter(|packet| packet.release_allowed == 0)
            .count() as u64;
        let zero_linkage_domain_count = packets
            .iter()
            .filter(|packet| packet.linkage_fields_allowed <= config.max_linkage_fields)
            .count() as u64;
        let bundle_status = if review_domain_count >= config.min_review_domains
            && release_allowed_count <= config.max_approved_release_blockers
            && release_hold_count == review_domain_count
            && zero_linkage_domain_count == review_domain_count
            && pending_live_execution_count == review_domain_count
        {
            "review_bundle_ready_for_live_execution_release_held"
        } else {
            "review_bundle_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.review_policy),
                HashPart::U64(review_domain_count),
                HashPart::U64(pending_live_execution_count),
                HashPart::U64(pending_human_review_count),
                HashPart::U64(blocked_count),
                HashPart::U64(release_allowed_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(zero_linkage_domain_count),
                HashPart::Str(&bundle_status),
            ],
            32,
        );

        Self {
            review_domain_count,
            pending_live_execution_count,
            pending_human_review_count,
            blocked_count,
            release_allowed_count,
            release_hold_count,
            zero_linkage_domain_count,
            bundle_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let bundle_status = "review_bundle_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.review_policy),
                HashPart::Str(reason),
                HashPart::Str(&bundle_status),
            ],
            32,
        );

        Self {
            review_domain_count: 0,
            pending_live_execution_count: 0,
            pending_human_review_count: 0,
            blocked_count: 1,
            release_allowed_count: 0,
            release_hold_count: 1,
            zero_linkage_domain_count: 0,
            bundle_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "review_domain_count": self.review_domain_count,
            "pending_live_execution_count": self.pending_live_execution_count,
            "pending_human_review_count": self.pending_human_review_count,
            "blocked_count": self.blocked_count,
            "release_allowed_count": self.release_allowed_count,
            "release_hold_count": self.release_hold_count,
            "zero_linkage_domain_count": self.zero_linkage_domain_count,
            "bundle_status": self.bundle_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source_roots: SourceRoots,
    pub review_packets: Vec<ReviewPacket>,
    pub verdict: SignoffBundleVerdict,
    pub packet_root: String,
    pub monero_finality_root: String,
    pub watcher_quorum_root: String,
    pub pq_custody_root: String,
    pub liquidity_root: String,
    pub receipt_replay_root: String,
    pub nullifier_root: String,
    pub metadata_root: String,
    pub release_hold_root: String,
    pub bundle_root: String,
}

impl State {
    pub fn new(config: Config, source_roots: SourceRoots) -> Result<Self> {
        validate_config(&config)?;

        let review_packets = ReviewDomain::ordered()
            .iter()
            .enumerate()
            .map(|(index, domain)| {
                ReviewPacket::devnet(&config, &source_roots, *domain, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = SignoffBundleVerdict::new(&config, &review_packets);
        let packet_root = packet_vector_root(&review_packets);
        let monero_finality_root =
            domain_packet_root(&review_packets, ReviewDomain::MoneroFinality);
        let watcher_quorum_root = domain_packet_root(&review_packets, ReviewDomain::WatcherQuorum);
        let pq_custody_root = domain_packet_root(&review_packets, ReviewDomain::PqCustody);
        let liquidity_root = domain_packet_root(&review_packets, ReviewDomain::LiquidityReserve);
        let receipt_replay_root = domain_packet_root(&review_packets, ReviewDomain::ReceiptReplay);
        let nullifier_root = domain_packet_root(&review_packets, ReviewDomain::NullifierSeparation);
        let metadata_root = domain_packet_root(&review_packets, ReviewDomain::MetadataRedaction);
        let release_hold_root =
            bundle_release_hold_root(&config, &source_roots, &review_packets, &verdict);
        let bundle_root = bundle_root(
            &config,
            &source_roots,
            &verdict,
            &packet_root,
            &release_hold_root,
        );

        Ok(Self {
            config,
            source_roots,
            review_packets,
            verdict,
            packet_root,
            monero_finality_root,
            watcher_quorum_root,
            pq_custody_root,
            liquidity_root,
            receipt_replay_root,
            nullifier_root,
            metadata_root,
            release_hold_root,
            bundle_root,
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
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_security_review_signoff_bundle_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source_roots": self.source_roots.public_record(),
            "packet_root": self.packet_root,
            "monero_finality_root": self.monero_finality_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "pq_custody_root": self.pq_custody_root,
            "liquidity_root": self.liquidity_root,
            "receipt_replay_root": self.receipt_replay_root,
            "nullifier_root": self.nullifier_root,
            "metadata_root": self.metadata_root,
            "release_hold_root": self.release_hold_root,
            "bundle_root": self.bundle_root,
            "verdict": self.verdict.public_record(),
            "review_packets": self
                .review_packets
                .iter()
                .map(ReviewPacket::public_record)
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
                "packet_root": self.packet_root,
                "monero_finality_root": self.monero_finality_root,
                "watcher_quorum_root": self.watcher_quorum_root,
                "pq_custody_root": self.pq_custody_root,
                "liquidity_root": self.liquidity_root,
                "receipt_replay_root": self.receipt_replay_root,
                "nullifier_root": self.nullifier_root,
                "metadata_root": self.metadata_root,
                "release_hold_root": self.release_hold_root,
                "bundle_root": self.bundle_root,
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
    if config.min_review_domains < ReviewDomain::ordered().len() as u64 {
        return Err(
            "minimum review domain count must cover every bridge-exit signoff domain".to_string(),
        );
    }
    if config.require_release_hold_until_signoff != 1 {
        return Err("security review bundle must keep release held until signoff".to_string());
    }
    if config.max_linkage_fields != 0 {
        return Err("security review bundle must preserve zero linkage-field exports".to_string());
    }
    Ok(())
}

fn acceptance_criteria_root(domain: ReviewDomain, source: &SourceRoots) -> String {
    domain_hash(
        &format!("{DOMAIN}:acceptance-criteria"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.acceptance_matrix_root),
            HashPart::Str(&source.acceptance_release_hold_root),
        ],
        32,
    )
}

fn evidence_root(domain: ReviewDomain, source: &SourceRoots) -> String {
    match domain {
        ReviewDomain::MoneroFinality => domain_hash(
            &format!("{DOMAIN}:monero-finality-evidence"),
            &[
                HashPart::Str(&source.acceptance_matrix_state_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_reorg_collusion_threat_model_manifest_runtime::devnet().state_root()),
            ],
            32,
        ),
        ReviewDomain::WatcherQuorum => domain_hash(
            &format!("{DOMAIN}:watcher-quorum-evidence"),
            &[
                HashPart::Str(&source.process_feed_binding_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::devnet().state_root()),
            ],
            32,
        ),
        ReviewDomain::PqCustody => domain_hash(
            &format!("{DOMAIN}:pq-custody-evidence"),
            &[
                HashPart::Str(&source.acceptance_matrix_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()),
            ],
            32,
        ),
        ReviewDomain::LiquidityReserve => domain_hash(
            &format!("{DOMAIN}:liquidity-reserve-evidence"),
            &[
                HashPart::Str(&source.acceptance_matrix_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet().state_root()),
            ],
            32,
        ),
        ReviewDomain::ReceiptReplay => domain_hash(
            &format!("{DOMAIN}:receipt-replay-evidence"),
            &[
                HashPart::Str(&source.acceptance_matrix_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_proof_runtime::state_root()),
            ],
            32,
        ),
        ReviewDomain::NullifierSeparation => domain_hash(
            &format!("{DOMAIN}:nullifier-separation-evidence"),
            &[
                HashPart::Str(&source.acceptance_matrix_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()),
            ],
            32,
        ),
        ReviewDomain::MetadataRedaction => domain_hash(
            &format!("{DOMAIN}:metadata-redaction-evidence"),
            &[
                HashPart::Str(&source.wallet_handoff_root),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root()),
                HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_threat_model_acceptance_matrix_runtime::devnet().reject_root),
            ],
            32,
        ),
    }
}

fn reviewer_packet_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewDomain,
    acceptance_criteria_root: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:reviewer-packet"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.review_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.existing_audit_signoff_state_root),
            HashPart::Str(acceptance_criteria_root),
            HashPart::Str(evidence_root),
            HashPart::U64(config.require_human_review_before_release),
            HashPart::U64(config.require_live_execution_before_signoff),
        ],
        32,
    )
}

fn domain_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    domain: ReviewDomain,
    reviewer_packet_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:domain-release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.review_policy),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.acceptance_release_hold_root),
            HashPart::Str(reviewer_packet_root),
            HashPart::U64(config.require_release_hold_until_signoff),
            HashPart::U64(0),
        ],
        32,
    )
}

fn count_status(packets: &[ReviewPacket], status: ReviewStatus) -> u64 {
    packets
        .iter()
        .filter(|packet| packet.status == status)
        .count() as u64
}

fn packet_vector_root(packets: &[ReviewPacket]) -> String {
    let leaves = packets
        .iter()
        .map(ReviewPacket::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:packet-root"), &leaves)
}

fn domain_packet_root(packets: &[ReviewPacket], domain: ReviewDomain) -> String {
    let leaves = packets
        .iter()
        .filter(|packet| packet.domain == domain)
        .map(ReviewPacket::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("{DOMAIN}:{}-packet-root", domain.as_str()),
        &leaves,
    )
}

fn bundle_release_hold_root(
    config: &Config,
    source: &SourceRoots,
    packets: &[ReviewPacket],
    verdict: &SignoffBundleVerdict,
) -> String {
    let hold_leaves = packets
        .iter()
        .filter(|packet| packet.release_allowed == 0)
        .map(ReviewPacket::public_record)
        .collect::<Vec<_>>();
    let hold_leaf_root = merkle_root(&format!("{DOMAIN}:release-hold-leaf-root"), &hold_leaves);

    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.review_policy),
            HashPart::Str(&source.source_root),
            HashPart::Str(&hold_leaf_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_hold_count),
            HashPart::U64(config.require_release_hold_until_signoff),
        ],
        32,
    )
}

fn bundle_root(
    config: &Config,
    source: &SourceRoots,
    verdict: &SignoffBundleVerdict,
    packet_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:bundle"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.bundle_suite),
            HashPart::Str(&source.source_root),
            HashPart::Str(packet_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_allowed_count),
        ],
        32,
    )
}

fn source_root(
    acceptance_matrix_state_root: &str,
    acceptance_matrix_root: &str,
    acceptance_release_hold_root: &str,
    existing_audit_signoff_state_root: &str,
    forced_exit_dry_run_root: &str,
    wallet_handoff_root: &str,
    process_feed_binding_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(acceptance_matrix_state_root),
            HashPart::Str(acceptance_matrix_root),
            HashPart::Str(acceptance_release_hold_root),
            HashPart::Str(existing_audit_signoff_state_root),
            HashPart::Str(forced_exit_dry_run_root),
            HashPart::Str(wallet_handoff_root),
            HashPart::Str(process_feed_binding_root),
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
    let source_roots = SourceRoots {
        acceptance_matrix_state_root: record_root(
            "fallback-acceptance-matrix-state",
            &json!({ "reason": reason }),
        ),
        acceptance_matrix_public_record_root: record_root(
            "fallback-acceptance-matrix-public",
            &json!({ "reason": reason }),
        ),
        acceptance_matrix_root: record_root(
            "fallback-acceptance-matrix",
            &json!({ "reason": reason }),
        ),
        acceptance_release_hold_root: record_root(
            "fallback-acceptance-release-hold",
            &json!({ "reason": reason }),
        ),
        existing_audit_signoff_state_root: record_root(
            "fallback-existing-audit-signoff",
            &json!({ "reason": reason }),
        ),
        forced_exit_dry_run_root: record_root("fallback-dry-run", &json!({ "reason": reason })),
        wallet_handoff_root: record_root("fallback-wallet-handoff", &json!({ "reason": reason })),
        process_feed_binding_root: record_root(
            "fallback-process-feed",
            &json!({ "reason": reason }),
        ),
        source_root: record_root("fallback-source", &json!({ "reason": reason })),
    };
    let review_packets = Vec::new();
    let verdict = SignoffBundleVerdict::fallback(&config, &reason);
    let packet_root = packet_vector_root(&review_packets);
    let monero_finality_root = domain_packet_root(&review_packets, ReviewDomain::MoneroFinality);
    let watcher_quorum_root = domain_packet_root(&review_packets, ReviewDomain::WatcherQuorum);
    let pq_custody_root = domain_packet_root(&review_packets, ReviewDomain::PqCustody);
    let liquidity_root = domain_packet_root(&review_packets, ReviewDomain::LiquidityReserve);
    let receipt_replay_root = domain_packet_root(&review_packets, ReviewDomain::ReceiptReplay);
    let nullifier_root = domain_packet_root(&review_packets, ReviewDomain::NullifierSeparation);
    let metadata_root = domain_packet_root(&review_packets, ReviewDomain::MetadataRedaction);
    let release_hold_root =
        bundle_release_hold_root(&config, &source_roots, &review_packets, &verdict);
    let bundle_root = bundle_root(
        &config,
        &source_roots,
        &verdict,
        &packet_root,
        &release_hold_root,
    );

    State {
        config,
        source_roots,
        review_packets,
        verdict,
        packet_root,
        monero_finality_root,
        watcher_quorum_root,
        pq_custody_root,
        liquidity_root,
        receipt_replay_root,
        nullifier_root,
        metadata_root,
        release_hold_root,
        bundle_root,
    }
}
