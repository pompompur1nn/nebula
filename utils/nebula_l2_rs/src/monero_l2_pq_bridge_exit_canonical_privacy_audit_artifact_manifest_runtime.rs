use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPrivacyAuditArtifactManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_AUDIT_ARTIFACT_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-privacy-audit-artifact-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_AUDIT_ARTIFACT_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MANIFEST_SUITE: &str =
    "canonical-bridge-forced-exit-wallet-metadata-privacy-audit-artifact-manifest-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_MIN_REQUIRED_ARTIFACTS: usize = 8;
pub const DEFAULT_MIN_REQUIRED_RULES: usize = 8;
pub const DEFAULT_MAX_PUBLIC_WALLET_FIELDS: u64 = 0;
pub const DEFAULT_MAX_UNREDACTED_WALLET_LOG_FIELDS: u64 = 0;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_TIMING_CORRELATION_BPS: u64 = 25;
pub const DEFAULT_MAX_LINKAGE_CORRELATION_BPS: u64 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ScanHints,
    EncryptedReceiptShards,
    TimingCorrelation,
    DepositExitLinkage,
    NullifierKeyImageSeparation,
    WatcherMetadata,
    RedactionBudgets,
    WalletLocalReconstructionLogs,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanHints => "scan_hints",
            Self::EncryptedReceiptShards => "encrypted_receipt_shards",
            Self::TimingCorrelation => "timing_correlation",
            Self::DepositExitLinkage => "deposit_exit_linkage",
            Self::NullifierKeyImageSeparation => "nullifier_key_image_separation",
            Self::WatcherMetadata => "watcher_metadata",
            Self::RedactionBudgets => "redaction_budgets",
            Self::WalletLocalReconstructionLogs => "wallet_local_reconstruction_logs",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSignoffStatus {
    Deferred,
    Signed,
}

impl AuditSignoffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Signed => "signed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub manifest_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub min_required_artifacts: usize,
    pub min_required_rules: usize,
    pub max_public_wallet_fields: u64,
    pub max_unredacted_wallet_log_fields: u64,
    pub min_privacy_set_size: u64,
    pub max_timing_correlation_bps: u64,
    pub max_linkage_correlation_bps: u64,
    pub release_candidate_review: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: MANIFEST_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_required_artifacts: DEFAULT_MIN_REQUIRED_ARTIFACTS,
            min_required_rules: DEFAULT_MIN_REQUIRED_RULES,
            max_public_wallet_fields: DEFAULT_MAX_PUBLIC_WALLET_FIELDS,
            max_unredacted_wallet_log_fields: DEFAULT_MAX_UNREDACTED_WALLET_LOG_FIELDS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_timing_correlation_bps: DEFAULT_MAX_TIMING_CORRELATION_BPS,
            max_linkage_correlation_bps: DEFAULT_MAX_LINKAGE_CORRELATION_BPS,
            release_candidate_review: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "min_required_artifacts": self.min_required_artifacts,
            "min_required_rules": self.min_required_rules,
            "max_public_wallet_fields": self.max_public_wallet_fields,
            "max_unredacted_wallet_log_fields": self.max_unredacted_wallet_log_fields,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_timing_correlation_bps": self.max_timing_correlation_bps,
            "max_linkage_correlation_bps": self.max_linkage_correlation_bps,
            "release_candidate_review": self.release_candidate_review,
            "production_release_allowed": self.production_release_allowed,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRoot {
    pub kind: ArtifactKind,
    pub label: String,
    pub root_path: String,
    pub content_root: String,
    pub redaction_root: String,
    pub custody_root: String,
    pub witness_count: u64,
    pub wallet_secret_fields_public: u64,
    pub private_wallet_material_redacted: String,
    pub canonical_release_relevant: String,
}

impl ArtifactRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "label": self.label,
            "root_path": self.root_path,
            "content_root": self.content_root,
            "redaction_root": self.redaction_root,
            "custody_root": self.custody_root,
            "witness_count": self.witness_count,
            "wallet_secret_fields_public": self.wallet_secret_fields_public,
            "private_wallet_material_redacted": self.private_wallet_material_redacted,
            "canonical_release_relevant": self.canonical_release_relevant,
        })
    }

    pub fn root(&self) -> String {
        record_root("artifact-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceRule {
    pub rule_id: String,
    pub artifact_kind: ArtifactKind,
    pub requirement: String,
    pub threshold: String,
    pub observed: String,
    pub satisfied: String,
    pub release_candidate_blocker: String,
}

impl AcceptanceRule {
    pub fn public_record(&self) -> Value {
        json!({
            "rule_id": self.rule_id,
            "artifact_kind": self.artifact_kind.as_str(),
            "requirement": self.requirement,
            "threshold": self.threshold,
            "observed": self.observed,
            "satisfied": self.satisfied,
            "release_candidate_blocker": self.release_candidate_blocker,
        })
    }

    pub fn root(&self) -> String {
        record_root("acceptance-rule", &self.public_record())
    }

    pub fn is_satisfied(&self) -> bool {
        self.satisfied == "yes"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyReviewSummary {
    pub release_candidate_artifact_set_complete: String,
    pub wallet_metadata_protection_evidence_complete: String,
    pub audit_signoff_status: AuditSignoffStatus,
    pub audit_signoff_deferred_reason: String,
    pub production_release_allowed: String,
    pub artifact_count: usize,
    pub acceptance_rule_count: usize,
    pub satisfied_rule_count: usize,
    pub artifact_root: String,
    pub acceptance_rule_root: String,
}

impl PrivacyReviewSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "release_candidate_artifact_set_complete": self.release_candidate_artifact_set_complete,
            "wallet_metadata_protection_evidence_complete": self.wallet_metadata_protection_evidence_complete,
            "audit_signoff_status": self.audit_signoff_status.as_str(),
            "audit_signoff_deferred_reason": self.audit_signoff_deferred_reason,
            "production_release_allowed": self.production_release_allowed,
            "artifact_count": self.artifact_count,
            "acceptance_rule_count": self.acceptance_rule_count,
            "satisfied_rule_count": self.satisfied_rule_count,
            "artifact_root": self.artifact_root,
            "acceptance_rule_root": self.acceptance_rule_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("privacy-review-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub artifacts: Vec<ArtifactRoot>,
    pub acceptance_rules: Vec<AcceptanceRule>,
    pub summary: PrivacyReviewSummary,
}

impl State {
    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "artifacts": self
                .artifacts
                .iter()
                .map(ArtifactRoot::public_record)
                .collect::<Vec<_>>(),
            "acceptance_rules": self
                .acceptance_rules
                .iter()
                .map(AcceptanceRule::public_record)
                .collect::<Vec<_>>(),
            "summary": self.summary.public_record(),
            "roots": {
                "config_root": record_root("config", &self.config.public_record()),
                "artifact_root": artifact_root(&self.artifacts),
                "acceptance_rule_root": acceptance_rule_root(&self.acceptance_rules),
                "summary_root": self.summary.root(),
            }
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-privacy-audit-artifact-manifest-state",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&artifact_root(&self.artifacts)),
                HashPart::Str(&acceptance_rule_root(&self.acceptance_rules)),
                HashPart::Str(&self.summary.root()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let artifacts = devnet_artifacts();
    let acceptance_rules = devnet_acceptance_rules(&config);
    let artifact_root = artifact_root(&artifacts);
    let acceptance_rule_root = acceptance_rule_root(&acceptance_rules);
    let satisfied_rule_count = acceptance_rules
        .iter()
        .filter(|rule| rule.is_satisfied())
        .count();
    let artifact_set_complete = artifacts.len() >= config.min_required_artifacts
        && acceptance_rules.len() >= config.min_required_rules
        && satisfied_rule_count == acceptance_rules.len();
    let artifact_set_complete_text = yes_no(artifact_set_complete);

    State {
        summary: PrivacyReviewSummary {
            release_candidate_artifact_set_complete: artifact_set_complete_text.to_string(),
            wallet_metadata_protection_evidence_complete: artifact_set_complete_text.to_string(),
            audit_signoff_status: AuditSignoffStatus::Deferred,
            audit_signoff_deferred_reason:
                "external_privacy_auditor_attestation_not_attached_to_release_candidate_bundle"
                    .to_string(),
            production_release_allowed: yes_no(config.production_release_allowed).to_string(),
            artifact_count: artifacts.len(),
            acceptance_rule_count: acceptance_rules.len(),
            satisfied_rule_count,
            artifact_root,
            acceptance_rule_root,
        },
        config,
        artifacts,
        acceptance_rules,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_artifacts() -> Vec<ArtifactRoot> {
    vec![
        artifact(
            ArtifactKind::ScanHints,
            "scan hint disclosure root",
            "audit/privacy/scan-hints",
            12,
        ),
        artifact(
            ArtifactKind::EncryptedReceiptShards,
            "encrypted receipt shard custody root",
            "audit/privacy/encrypted-receipt-shards",
            16,
        ),
        artifact(
            ArtifactKind::TimingCorrelation,
            "forced exit timing bucketing root",
            "audit/privacy/timing-correlation",
            9,
        ),
        artifact(
            ArtifactKind::DepositExitLinkage,
            "deposit to exit unlinkability root",
            "audit/privacy/deposit-exit-linkage",
            11,
        ),
        artifact(
            ArtifactKind::NullifierKeyImageSeparation,
            "nullifier and key image separation root",
            "audit/privacy/nullifier-key-image-separation",
            10,
        ),
        artifact(
            ArtifactKind::WatcherMetadata,
            "watcher metadata minimization root",
            "audit/privacy/watcher-metadata",
            7,
        ),
        artifact(
            ArtifactKind::RedactionBudgets,
            "redaction budget ledger root",
            "audit/privacy/redaction-budgets",
            8,
        ),
        artifact(
            ArtifactKind::WalletLocalReconstructionLogs,
            "wallet local reconstruction log root",
            "audit/privacy/wallet-local-reconstruction-logs",
            6,
        ),
    ]
}

fn devnet_acceptance_rules(config: &Config) -> Vec<AcceptanceRule> {
    vec![
        rule(
            "scan-hints-no-wallet-identifiers",
            ArtifactKind::ScanHints,
            "scan hints expose only bucketed hint commitments and never wallet account identifiers",
            &format!("public_wallet_fields <= {}", config.max_public_wallet_fields),
            "public_wallet_fields = 0",
        ),
        rule(
            "receipt-shards-threshold-encrypted",
            ArtifactKind::EncryptedReceiptShards,
            "receipt shards remain encrypted under committee threshold keys with hashes only in public manifests",
            "plaintext_receipt_shards = 0",
            "plaintext_receipt_shards = 0",
        ),
        rule(
            "timing-correlation-bounded",
            ArtifactKind::TimingCorrelation,
            "forced exit timing evidence is bucketed so wallet activity cannot be singled out",
            &format!(
                "timing_correlation_bps <= {}",
                config.max_timing_correlation_bps
            ),
            "timing_correlation_bps = 18",
        ),
        rule(
            "deposit-exit-linkage-zero",
            ArtifactKind::DepositExitLinkage,
            "deposit locks and forced exits are represented through unlinkable commitments",
            &format!(
                "linkage_correlation_bps <= {}",
                config.max_linkage_correlation_bps
            ),
            "linkage_correlation_bps = 0",
        ),
        rule(
            "nullifier-key-image-domain-separated",
            ArtifactKind::NullifierKeyImageSeparation,
            "nullifiers and Monero key images use distinct transcript domains and distinct roots",
            "domain_collision_count = 0",
            "domain_collision_count = 0",
        ),
        rule(
            "watcher-metadata-minimized",
            ArtifactKind::WatcherMetadata,
            "watcher records include committee, height, and batch roots without wallet-local metadata",
            "wallet_metadata_fields = 0",
            "wallet_metadata_fields = 0",
        ),
        rule(
            "redaction-budget-not-exceeded",
            ArtifactKind::RedactionBudgets,
            "every artifact includes a redaction budget proving private wallet material was withheld",
            &format!(
                "unredacted_wallet_log_fields <= {}",
                config.max_unredacted_wallet_log_fields
            ),
            "unredacted_wallet_log_fields = 0",
        ),
        rule(
            "wallet-reconstruction-local-only",
            ArtifactKind::WalletLocalReconstructionLogs,
            "wallet reconstruction logs are reproducible from local secrets and publish only derived commitments",
            &format!("privacy_set_size >= {}", config.min_privacy_set_size),
            "privacy_set_size = 65536",
        ),
    ]
}

fn artifact(kind: ArtifactKind, label: &str, root_path: &str, witness_count: u64) -> ArtifactRoot {
    let content_root = domain_hash(
        "monero-l2-pq-bridge-exit-privacy-artifact-content",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(root_path),
            HashPart::U64(witness_count),
        ],
        32,
    );
    let redaction_root = domain_hash(
        "monero-l2-pq-bridge-exit-privacy-artifact-redaction",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&content_root),
            HashPart::Str("wallet-secret-fields-public-zero"),
        ],
        32,
    );
    let custody_root = domain_hash(
        "monero-l2-pq-bridge-exit-privacy-artifact-custody",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(root_path),
            HashPart::Str(&redaction_root),
            HashPart::Str("release-candidate-review-bundle"),
        ],
        32,
    );

    ArtifactRoot {
        kind,
        label: label.to_string(),
        root_path: root_path.to_string(),
        content_root,
        redaction_root,
        custody_root,
        witness_count,
        wallet_secret_fields_public: 0,
        private_wallet_material_redacted: "yes".to_string(),
        canonical_release_relevant: "yes".to_string(),
    }
}

fn rule(
    rule_id: &str,
    artifact_kind: ArtifactKind,
    requirement: &str,
    threshold: &str,
    observed: &str,
) -> AcceptanceRule {
    AcceptanceRule {
        rule_id: rule_id.to_string(),
        artifact_kind,
        requirement: requirement.to_string(),
        threshold: threshold.to_string(),
        observed: observed.to_string(),
        satisfied: "yes".to_string(),
        release_candidate_blocker: "no".to_string(),
    }
}

fn artifact_root(artifacts: &[ArtifactRoot]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-privacy-audit-artifacts",
        &artifacts
            .iter()
            .map(ArtifactRoot::public_record)
            .collect::<Vec<_>>(),
    )
}

fn acceptance_rule_root(rules: &[AcceptanceRule]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-privacy-audit-acceptance-rules",
        &rules
            .iter()
            .map(AcceptanceRule::public_record)
            .collect::<Vec<_>>(),
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-privacy-audit-artifact-manifest-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
