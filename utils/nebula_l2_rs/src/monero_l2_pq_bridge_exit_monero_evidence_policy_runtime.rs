use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitMoneroEvidencePolicyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_MONERO_EVIDENCE_POLICY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-monero-evidence-policy-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_MONERO_EVIDENCE_POLICY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EVIDENCE_POLICY_SUITE: &str = "monero-l2-pq-bridge-exit-monero-evidence-policy-v1";
pub const DEFAULT_MIN_LOCK_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_MIN_FINALITY_CONFIRMATIONS: u64 = 20;
pub const DEFAULT_REORG_CHALLENGE_DEPTH: u64 = 20;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 3;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DepositLock,
    ExitRequest,
    HeaderChain,
    ReorgChallenge,
    FinalityAttestation,
    WatcherObservation,
    NegativeCase,
    Redaction,
    ResidualRisk,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::ExitRequest => "exit_request",
            Self::HeaderChain => "header_chain",
            Self::ReorgChallenge => "reorg_challenge",
            Self::FinalityAttestation => "finality_attestation",
            Self::WatcherObservation => "watcher_observation",
            Self::NegativeCase => "negative_case",
            Self::Redaction => "redaction",
            Self::ResidualRisk => "residual_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Deferred,
    Rejected,
    Blocked,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeEvidenceCase {
    MissingLock,
    ShortConfirmationDepth,
    HeaderContinuityBreak,
    ReorgWindowExceeded,
    WatcherQuorumMissing,
    DuplicatedKeyImageCommitment,
    UnredactedPrivatePayload,
    BaseLayerVerifierAbsent,
}

impl NegativeEvidenceCase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLock => "missing_lock",
            Self::ShortConfirmationDepth => "short_confirmation_depth",
            Self::HeaderContinuityBreak => "header_continuity_break",
            Self::ReorgWindowExceeded => "reorg_window_exceeded",
            Self::WatcherQuorumMissing => "watcher_quorum_missing",
            Self::DuplicatedKeyImageCommitment => "duplicated_key_image_commitment",
            Self::UnredactedPrivatePayload => "unredacted_private_payload",
            Self::BaseLayerVerifierAbsent => "base_layer_verifier_absent",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionLevel {
    PublicCommitmentOnly,
    PublicAuditDigest,
    WatcherEncryptedPayload,
}

impl RedactionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicCommitmentOnly => "public_commitment_only",
            Self::PublicAuditDigest => "public_audit_digest",
            Self::WatcherEncryptedPayload => "watcher_encrypted_payload",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlocker {
    NoBaseLayerVerifier,
    CargoChecksDeferred,
    ProductionVerifierMissing,
    PrivacyRedactionRequired,
    LiveWatcherIntegrationMissing,
}

impl ReleaseBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::CargoChecksDeferred => "cargo_checks_deferred",
            Self::ProductionVerifierMissing => "production_verifier_missing",
            Self::PrivacyRedactionRequired => "privacy_redaction_required",
            Self::LiveWatcherIntegrationMissing => "live_watcher_integration_missing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub evidence_policy_suite: String,
    pub min_lock_confirmations: u64,
    pub min_finality_confirmations: u64,
    pub reorg_challenge_depth: u64,
    pub min_watcher_quorum: u64,
    pub base_layer_verifier_enabled: bool,
    pub privacy_redaction_required: bool,
    pub watcher_payloads_encrypted: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            evidence_policy_suite: EVIDENCE_POLICY_SUITE.to_string(),
            min_lock_confirmations: DEFAULT_MIN_LOCK_CONFIRMATIONS,
            min_finality_confirmations: DEFAULT_MIN_FINALITY_CONFIRMATIONS,
            reorg_challenge_depth: DEFAULT_REORG_CHALLENGE_DEPTH,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            base_layer_verifier_enabled: false,
            privacy_redaction_required: true,
            watcher_payloads_encrypted: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "evidence_policy_suite": self.evidence_policy_suite,
            "min_lock_confirmations": self.min_lock_confirmations,
            "min_finality_confirmations": self.min_finality_confirmations,
            "reorg_challenge_depth": self.reorg_challenge_depth,
            "min_watcher_quorum": self.min_watcher_quorum,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "privacy_redaction_required": self.privacy_redaction_required,
            "watcher_payloads_encrypted": self.watcher_payloads_encrypted,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoneroEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub subject_id: String,
    pub monero_height: u64,
    pub confirmations: u64,
    pub watcher_count: u64,
    pub header_hash: String,
    pub previous_header_hash: String,
    pub output_commitment_root: String,
    pub key_image_commitment_root: String,
    pub tx_proof_commitment_root: String,
    pub redaction_level: RedactionLevel,
    pub private_payload_redacted: bool,
    pub encrypted_watcher_payload_root: String,
    pub policy_root: String,
    pub evidence_root: String,
}

impl MoneroEvidence {
    pub fn accepted_lock(config: &Config, subject_id: &str, ordinal: u64) -> Self {
        let monero_height = 3_500_000 + ordinal;
        let confirmations = config.min_lock_confirmations + ordinal % 4;
        let watcher_count = config.min_watcher_quorum;
        let header_hash = labeled_hash("lock-header", subject_id, ordinal);
        let previous_header_hash = labeled_hash("lock-prev-header", subject_id, ordinal);
        let output_commitment_root = labeled_hash("redacted-output-root", subject_id, ordinal);
        let key_image_commitment_root = labeled_hash("key-image-root", subject_id, ordinal);
        let tx_proof_commitment_root = labeled_hash("tx-proof-root", subject_id, ordinal);
        Self::new(
            config,
            EvidenceKind::DepositLock,
            EvidenceStatus::Accepted,
            subject_id,
            monero_height,
            confirmations,
            watcher_count,
            header_hash,
            previous_header_hash,
            output_commitment_root,
            key_image_commitment_root,
            tx_proof_commitment_root,
            RedactionLevel::PublicCommitmentOnly,
            true,
            ordinal,
        )
    }

    pub fn accepted_header(config: &Config, subject_id: &str, ordinal: u64) -> Self {
        let confirmations = config.min_finality_confirmations;
        Self::new(
            config,
            EvidenceKind::HeaderChain,
            EvidenceStatus::Accepted,
            subject_id,
            3_500_100 + ordinal,
            confirmations,
            config.min_watcher_quorum,
            labeled_hash("canonical-header", subject_id, ordinal),
            labeled_hash("canonical-prev-header", subject_id, ordinal),
            labeled_hash("header-output-redacted", subject_id, ordinal),
            labeled_hash("header-key-image-redacted", subject_id, ordinal),
            labeled_hash("header-proof-redacted", subject_id, ordinal),
            RedactionLevel::PublicAuditDigest,
            true,
            ordinal,
        )
    }

    pub fn accepted_finality(config: &Config, subject_id: &str, ordinal: u64) -> Self {
        Self::new(
            config,
            EvidenceKind::FinalityAttestation,
            EvidenceStatus::Accepted,
            subject_id,
            3_500_200 + ordinal,
            config.min_finality_confirmations + 2,
            config.min_watcher_quorum + 1,
            labeled_hash("finality-header", subject_id, ordinal),
            labeled_hash("finality-prev-header", subject_id, ordinal),
            labeled_hash("finality-output-redacted", subject_id, ordinal),
            labeled_hash("finality-key-image-redacted", subject_id, ordinal),
            labeled_hash("finality-proof-redacted", subject_id, ordinal),
            RedactionLevel::PublicAuditDigest,
            true,
            ordinal,
        )
    }

    pub fn accepted_watcher(config: &Config, subject_id: &str, ordinal: u64) -> Self {
        Self::new(
            config,
            EvidenceKind::WatcherObservation,
            EvidenceStatus::Accepted,
            subject_id,
            3_500_300 + ordinal,
            config.min_lock_confirmations + 1,
            config.min_watcher_quorum + 2,
            labeled_hash("watcher-header", subject_id, ordinal),
            labeled_hash("watcher-prev-header", subject_id, ordinal),
            labeled_hash("watcher-output-redacted", subject_id, ordinal),
            labeled_hash("watcher-key-image-redacted", subject_id, ordinal),
            labeled_hash("watcher-proof-redacted", subject_id, ordinal),
            RedactionLevel::WatcherEncryptedPayload,
            true,
            ordinal,
        )
    }

    pub fn negative_case(
        config: &Config,
        case_kind: NegativeEvidenceCase,
        subject_id: &str,
        ordinal: u64,
    ) -> Self {
        let (kind, confirmations, watchers, redacted) = match case_kind {
            NegativeEvidenceCase::MissingLock => (EvidenceKind::DepositLock, 0, 0, true),
            NegativeEvidenceCase::ShortConfirmationDepth => (
                EvidenceKind::FinalityAttestation,
                config.min_lock_confirmations.saturating_sub(1),
                2,
                true,
            ),
            NegativeEvidenceCase::HeaderContinuityBreak => (
                EvidenceKind::HeaderChain,
                config.min_finality_confirmations,
                3,
                true,
            ),
            NegativeEvidenceCase::ReorgWindowExceeded => (
                EvidenceKind::ReorgChallenge,
                config.min_finality_confirmations,
                3,
                true,
            ),
            NegativeEvidenceCase::WatcherQuorumMissing => (
                EvidenceKind::WatcherObservation,
                config.min_lock_confirmations,
                1,
                true,
            ),
            NegativeEvidenceCase::DuplicatedKeyImageCommitment => (
                EvidenceKind::ExitRequest,
                config.min_finality_confirmations,
                3,
                true,
            ),
            NegativeEvidenceCase::UnredactedPrivatePayload => (
                EvidenceKind::Redaction,
                config.min_finality_confirmations,
                3,
                false,
            ),
            NegativeEvidenceCase::BaseLayerVerifierAbsent => (
                EvidenceKind::ResidualRisk,
                config.min_finality_confirmations,
                3,
                true,
            ),
        };
        Self::new(
            config,
            kind,
            EvidenceStatus::Rejected,
            subject_id,
            3_500_400 + ordinal,
            confirmations,
            watchers,
            labeled_hash(case_kind.as_str(), subject_id, ordinal),
            labeled_hash("negative-prev-header", subject_id, ordinal),
            labeled_hash("negative-output-redacted", subject_id, ordinal),
            labeled_hash("negative-key-image-redacted", subject_id, ordinal),
            labeled_hash("negative-proof-redacted", subject_id, ordinal),
            RedactionLevel::PublicCommitmentOnly,
            redacted,
            ordinal,
        )
    }

    fn new(
        config: &Config,
        kind: EvidenceKind,
        status: EvidenceStatus,
        subject_id: &str,
        monero_height: u64,
        confirmations: u64,
        watcher_count: u64,
        header_hash: String,
        previous_header_hash: String,
        output_commitment_root: String,
        key_image_commitment_root: String,
        tx_proof_commitment_root: String,
        redaction_level: RedactionLevel,
        private_payload_redacted: bool,
        ordinal: u64,
    ) -> Self {
        let encrypted_watcher_payload_root = encrypted_payload_root(
            subject_id,
            &header_hash,
            watcher_count,
            config.watcher_payloads_encrypted,
        );
        let policy_root = evidence_policy_root(
            kind,
            status,
            confirmations,
            watcher_count,
            private_payload_redacted,
            &encrypted_watcher_payload_root,
        );
        let evidence_root = evidence_root(
            kind,
            status,
            subject_id,
            monero_height,
            &header_hash,
            &output_commitment_root,
            &key_image_commitment_root,
            &tx_proof_commitment_root,
            &policy_root,
        );
        let evidence_id = evidence_id(kind, subject_id, ordinal, &evidence_root);
        Self {
            evidence_id,
            kind,
            status,
            subject_id: subject_id.to_string(),
            monero_height,
            confirmations,
            watcher_count,
            header_hash,
            previous_header_hash,
            output_commitment_root,
            key_image_commitment_root,
            tx_proof_commitment_root,
            redaction_level,
            private_payload_redacted,
            encrypted_watcher_payload_root,
            policy_root,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
            "monero_height": self.monero_height,
            "confirmations": self.confirmations,
            "watcher_count": self.watcher_count,
            "header_hash": self.header_hash,
            "previous_header_hash": self.previous_header_hash,
            "output_commitment_root": self.output_commitment_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "tx_proof_commitment_root": self.tx_proof_commitment_root,
            "redaction_level": self.redaction_level.as_str(),
            "private_payload_redacted": self.private_payload_redacted,
            "encrypted_watcher_payload_root": self.encrypted_watcher_payload_root,
            "policy_root": self.policy_root,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn redacted_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_id": redacted_subject_id(&self.subject_id),
            "monero_height": self.monero_height,
            "confirmations": self.confirmations,
            "watcher_count": self.watcher_count,
            "header_hash": self.header_hash,
            "output_commitment_root": self.output_commitment_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "tx_proof_commitment_root": self.tx_proof_commitment_root,
            "redaction_level": self.redaction_level.as_str(),
            "private_payload_redacted": self.private_payload_redacted,
            "encrypted_watcher_payload_root": self.encrypted_watcher_payload_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NegativeEvidenceRecord {
    pub case_id: String,
    pub case_kind: NegativeEvidenceCase,
    pub expected_status: EvidenceStatus,
    pub observed_status: EvidenceStatus,
    pub evidence_id: String,
    pub rejection_reason: String,
    pub blocks_release: bool,
    pub evidence_root: String,
    pub case_root: String,
}

impl NegativeEvidenceRecord {
    pub fn from_evidence(case_kind: NegativeEvidenceCase, evidence: &MoneroEvidence) -> Self {
        let expected_status = EvidenceStatus::Rejected;
        let observed_status = evidence.status;
        let blocks_release = true;
        let rejection_reason = case_kind.as_str().to_string();
        let case_root = negative_case_root(
            case_kind,
            expected_status,
            observed_status,
            &evidence.evidence_id,
            &evidence.evidence_root,
        );
        let case_id = negative_case_id(case_kind, &evidence.evidence_id, &case_root);
        Self {
            case_id,
            case_kind,
            expected_status,
            observed_status,
            evidence_id: evidence.evidence_id.clone(),
            rejection_reason,
            blocks_release,
            evidence_root: evidence.evidence_root.clone(),
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "case_kind": self.case_kind.as_str(),
            "expected_status": self.expected_status.as_str(),
            "observed_status": self.observed_status.as_str(),
            "evidence_id": self.evidence_id,
            "rejection_reason": self.rejection_reason,
            "blocks_release": self.blocks_release,
            "evidence_root": self.evidence_root,
            "case_root": self.case_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResidualRiskRecord {
    pub risk_id: String,
    pub label: String,
    pub explicit_residual_risk: String,
    pub base_layer_verifier_enabled: bool,
    pub accepted_by_policy: bool,
    pub production_blocker: bool,
    pub mitigation_root: String,
    pub risk_root: String,
}

impl ResidualRiskRecord {
    pub fn no_base_layer_verifier(config: &Config) -> Self {
        let label = "monero_base_layer_verifier_absent".to_string();
        let explicit_residual_risk = "monero headers, locks, reorgs, and finality evidence are policy-accepted commitments only; this runtime does not verify Monero consensus rules or transaction validity at the base layer".to_string();
        let accepted_by_policy = true;
        let production_blocker = true;
        let mitigation_root = record_root(
            "residual-risk-mitigation",
            &json!({
                "required_before_production": [
                    "native_monero_header_verifier",
                    "transaction_membership_verifier",
                    "reorg_depth_oracle",
                    "watcher_slashing_integration"
                ],
                "cargo_checks_deferred": config.cargo_checks_deferred,
                "production_release_allowed": config.production_release_allowed,
            }),
        );
        let risk_root = residual_risk_root(
            &label,
            config.base_layer_verifier_enabled,
            accepted_by_policy,
            production_blocker,
            &mitigation_root,
        );
        let risk_id = domain_hash(
            "MONERO-EVIDENCE-POLICY-RESIDUAL-RISK-ID",
            &[HashPart::Str(&label), HashPart::Str(&risk_root)],
            32,
        );
        Self {
            risk_id,
            label,
            explicit_residual_risk,
            base_layer_verifier_enabled: config.base_layer_verifier_enabled,
            accepted_by_policy,
            production_blocker,
            mitigation_root,
            risk_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "risk_id": self.risk_id,
            "label": self.label,
            "explicit_residual_risk": self.explicit_residual_risk,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "accepted_by_policy": self.accepted_by_policy,
            "production_blocker": self.production_blocker,
            "mitigation_root": self.mitigation_root,
            "risk_root": self.risk_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionBlockerRecord {
    pub blocker_id: String,
    pub blocker: ReleaseBlocker,
    pub severity: String,
    pub blocks_production: bool,
    pub required_exit: String,
    pub evidence_root: String,
    pub blocker_root: String,
}

impl ProductionBlockerRecord {
    pub fn new(blocker: ReleaseBlocker, required_exit: &str, evidence_root: &str) -> Self {
        let severity = "release_blocking".to_string();
        let blocks_production = true;
        let blocker_root = production_blocker_root(
            blocker,
            &severity,
            blocks_production,
            required_exit,
            evidence_root,
        );
        let blocker_id = domain_hash(
            "MONERO-EVIDENCE-POLICY-PRODUCTION-BLOCKER-ID",
            &[
                HashPart::Str(blocker.as_str()),
                HashPart::Str(required_exit),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Self {
            blocker_id,
            blocker,
            severity,
            blocks_production,
            required_exit: required_exit.to_string(),
            evidence_root: evidence_root.to_string(),
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "blocker": self.blocker.as_str(),
            "severity": self.severity,
            "blocks_production": self.blocks_production,
            "required_exit": self.required_exit,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyReport {
    pub report_id: String,
    pub accepted_evidence_count: u64,
    pub negative_case_count: u64,
    pub production_blocker_count: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub base_layer_verifier_enabled: bool,
    pub deposit_exit_redaction_enforced: bool,
    pub accepted_evidence_root: String,
    pub negative_case_root: String,
    pub residual_risk_root: String,
    pub production_blocker_root: String,
    pub report_root: String,
}

impl PolicyReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "accepted_evidence_count": self.accepted_evidence_count,
            "negative_case_count": self.negative_case_count,
            "production_blocker_count": self.production_blocker_count,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "deposit_exit_redaction_enforced": self.deposit_exit_redaction_enforced,
            "accepted_evidence_root": self.accepted_evidence_root,
            "negative_case_root": self.negative_case_root,
            "residual_risk_root": self.residual_risk_root,
            "production_blocker_root": self.production_blocker_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub accepted_evidence: Vec<MoneroEvidence>,
    pub negative_cases: Vec<NegativeEvidenceRecord>,
    pub residual_risks: Vec<ResidualRiskRecord>,
    pub production_blockers: Vec<ProductionBlockerRecord>,
    pub report: PolicyReport,
    pub config_root: String,
    pub state_root: String,
}

impl State {
    pub fn from_config(config: Config) -> Self {
        let accepted_evidence = vec![
            MoneroEvidence::accepted_lock(&config, "deposit-note-alpha", 1),
            MoneroEvidence::accepted_header(&config, "header-chain-alpha", 2),
            MoneroEvidence::accepted_finality(&config, "finality-attestation-alpha", 3),
            MoneroEvidence::accepted_watcher(&config, "watcher-quorum-alpha", 4),
        ];
        let negative_evidence = [
            NegativeEvidenceCase::MissingLock,
            NegativeEvidenceCase::ShortConfirmationDepth,
            NegativeEvidenceCase::HeaderContinuityBreak,
            NegativeEvidenceCase::ReorgWindowExceeded,
            NegativeEvidenceCase::WatcherQuorumMissing,
            NegativeEvidenceCase::DuplicatedKeyImageCommitment,
            NegativeEvidenceCase::UnredactedPrivatePayload,
            NegativeEvidenceCase::BaseLayerVerifierAbsent,
        ];
        let negative_cases = negative_evidence
            .iter()
            .enumerate()
            .map(|(index, case_kind)| {
                let evidence = MoneroEvidence::negative_case(
                    &config,
                    *case_kind,
                    case_kind.as_str(),
                    index as u64 + 10,
                );
                NegativeEvidenceRecord::from_evidence(*case_kind, &evidence)
            })
            .collect::<Vec<_>>();
        let residual_risks = vec![ResidualRiskRecord::no_base_layer_verifier(&config)];
        let accepted_evidence_root = merkle_from_records(
            "MONERO-EVIDENCE-POLICY-ACCEPTED-EVIDENCE",
            accepted_evidence
                .iter()
                .map(MoneroEvidence::redacted_record)
                .collect::<Vec<_>>(),
        );
        let negative_case_root = merkle_from_records(
            "MONERO-EVIDENCE-POLICY-NEGATIVE-CASE",
            negative_cases
                .iter()
                .map(NegativeEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let residual_risk_root = merkle_from_records(
            "MONERO-EVIDENCE-POLICY-RESIDUAL-RISK",
            residual_risks
                .iter()
                .map(ResidualRiskRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let production_blockers = production_blockers(
            &config,
            &accepted_evidence_root,
            &negative_case_root,
            &residual_risk_root,
        );
        let production_blocker_root = merkle_from_records(
            "MONERO-EVIDENCE-POLICY-PRODUCTION-BLOCKER",
            production_blockers
                .iter()
                .map(ProductionBlockerRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let report = policy_report(
            &config,
            accepted_evidence.len() as u64,
            negative_cases.len() as u64,
            production_blockers.len() as u64,
            &accepted_evidence_root,
            &negative_case_root,
            &residual_risk_root,
            &production_blocker_root,
        );
        let config_root = config.state_root();
        let state_root = state_root_from_parts(
            &config_root,
            &accepted_evidence_root,
            &negative_case_root,
            &residual_risk_root,
            &production_blocker_root,
            &report.report_root,
        );
        Self {
            config,
            accepted_evidence,
            negative_cases,
            residual_risks,
            production_blockers,
            report,
            config_root,
            state_root,
        }
    }

    pub fn devnet() -> Self {
        Self::from_config(Config::devnet())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "accepted_evidence": self.accepted_evidence
                .iter()
                .take(self.config.max_public_records)
                .map(MoneroEvidence::redacted_record)
                .collect::<Vec<_>>(),
            "negative_cases": self.negative_cases
                .iter()
                .take(self.config.max_public_records)
                .map(NegativeEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
            "residual_risks": self.residual_risks
                .iter()
                .map(ResidualRiskRecord::public_record)
                .collect::<Vec<_>>(),
            "production_blockers": self.production_blockers
                .iter()
                .map(ProductionBlockerRecord::public_record)
                .collect::<Vec<_>>(),
            "report": self.report.public_record(),
            "config_root": self.config_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn accepted_evidence_root(&self) -> String {
        merkle_from_records(
            "MONERO-EVIDENCE-POLICY-ACCEPTED-EVIDENCE",
            self.accepted_evidence
                .iter()
                .map(MoneroEvidence::redacted_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn negative_case_root(&self) -> String {
        merkle_from_records(
            "MONERO-EVIDENCE-POLICY-NEGATIVE-CASE",
            self.negative_cases
                .iter()
                .map(NegativeEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn production_blocked(&self) -> bool {
        !self.config.production_release_allowed
            || self
                .production_blockers
                .iter()
                .any(|blocker| blocker.blocks_production)
    }

    pub fn validate_policy(&self) -> Result<()> {
        if self.config.production_release_allowed {
            return Err(
                "production release must remain disabled for this policy runtime".to_string(),
            );
        }
        if !self.config.cargo_checks_deferred {
            return Err(
                "cargo checks must be marked deferred for this standalone runtime".to_string(),
            );
        }
        if self.config.base_layer_verifier_enabled {
            return Err("base layer verifier is not implemented in this runtime".to_string());
        }
        if self
            .accepted_evidence
            .iter()
            .any(|evidence| !evidence.private_payload_redacted)
        {
            return Err("accepted evidence must be redacted before publication".to_string());
        }
        Ok(())
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

fn policy_report(
    config: &Config,
    accepted_evidence_count: u64,
    negative_case_count: u64,
    production_blocker_count: u64,
    accepted_evidence_root: &str,
    negative_case_root: &str,
    residual_risk_root: &str,
    production_blocker_root: &str,
) -> PolicyReport {
    let deposit_exit_redaction_enforced = config.privacy_redaction_required;
    let report_root = domain_hash(
        "MONERO-EVIDENCE-POLICY-REPORT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(accepted_evidence_count),
            HashPart::U64(negative_case_count),
            HashPart::U64(production_blocker_count),
            HashPart::Str(bool_str(config.cargo_checks_deferred)),
            HashPart::Str(bool_str(config.production_release_allowed)),
            HashPart::Str(bool_str(config.base_layer_verifier_enabled)),
            HashPart::Str(bool_str(deposit_exit_redaction_enforced)),
            HashPart::Str(accepted_evidence_root),
            HashPart::Str(negative_case_root),
            HashPart::Str(residual_risk_root),
            HashPart::Str(production_blocker_root),
        ],
        32,
    );
    let report_id = domain_hash(
        "MONERO-EVIDENCE-POLICY-REPORT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(&report_root)],
        32,
    );
    PolicyReport {
        report_id,
        accepted_evidence_count,
        negative_case_count,
        production_blocker_count,
        cargo_checks_deferred: config.cargo_checks_deferred,
        production_release_allowed: config.production_release_allowed,
        base_layer_verifier_enabled: config.base_layer_verifier_enabled,
        deposit_exit_redaction_enforced,
        accepted_evidence_root: accepted_evidence_root.to_string(),
        negative_case_root: negative_case_root.to_string(),
        residual_risk_root: residual_risk_root.to_string(),
        production_blocker_root: production_blocker_root.to_string(),
        report_root,
    }
}

fn production_blockers(
    config: &Config,
    accepted_evidence_root: &str,
    negative_case_root: &str,
    residual_risk_root: &str,
) -> Vec<ProductionBlockerRecord> {
    let mut blockers = Vec::new();
    if !config.base_layer_verifier_enabled {
        blockers.push(ProductionBlockerRecord::new(
            ReleaseBlocker::NoBaseLayerVerifier,
            "ship_native_monero_base_layer_verifier_before_production",
            residual_risk_root,
        ));
        blockers.push(ProductionBlockerRecord::new(
            ReleaseBlocker::ProductionVerifierMissing,
            "bind_lock_header_reorg_finality_evidence_to_consensus_verifier",
            accepted_evidence_root,
        ));
    }
    if config.cargo_checks_deferred {
        blockers.push(ProductionBlockerRecord::new(
            ReleaseBlocker::CargoChecksDeferred,
            "run_cargo_check_test_clippy_for_full_workspace",
            negative_case_root,
        ));
    }
    if config.privacy_redaction_required {
        blockers.push(ProductionBlockerRecord::new(
            ReleaseBlocker::PrivacyRedactionRequired,
            "complete_deposit_exit_redaction_review",
            accepted_evidence_root,
        ));
    }
    blockers.push(ProductionBlockerRecord::new(
        ReleaseBlocker::LiveWatcherIntegrationMissing,
        "replace_policy_fixture_watchers_with_live_slashing_watchers",
        negative_case_root,
    ));
    blockers
}

fn evidence_id(kind: EvidenceKind, subject_id: &str, ordinal: u64, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-EVIDENCE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn evidence_root(
    kind: EvidenceKind,
    status: EvidenceStatus,
    subject_id: &str,
    monero_height: u64,
    header_hash: &str,
    output_commitment_root: &str,
    key_image_commitment_root: &str,
    tx_proof_commitment_root: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(monero_height),
            HashPart::Str(header_hash),
            HashPart::Str(output_commitment_root),
            HashPart::Str(key_image_commitment_root),
            HashPart::Str(tx_proof_commitment_root),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

fn evidence_policy_root(
    kind: EvidenceKind,
    status: EvidenceStatus,
    confirmations: u64,
    watcher_count: u64,
    private_payload_redacted: bool,
    encrypted_watcher_payload_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-RULE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(confirmations),
            HashPart::U64(watcher_count),
            HashPart::Str(bool_str(private_payload_redacted)),
            HashPart::Str(encrypted_watcher_payload_root),
        ],
        32,
    )
}

fn negative_case_root(
    case_kind: NegativeEvidenceCase,
    expected_status: EvidenceStatus,
    observed_status: EvidenceStatus,
    evidence_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-NEGATIVE-CASE-ROOT",
        &[
            HashPart::Str(case_kind.as_str()),
            HashPart::Str(expected_status.as_str()),
            HashPart::Str(observed_status.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn negative_case_id(case_kind: NegativeEvidenceCase, evidence_id: &str, case_root: &str) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-NEGATIVE-CASE-ID",
        &[
            HashPart::Str(case_kind.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(case_root),
        ],
        32,
    )
}

fn residual_risk_root(
    label: &str,
    base_layer_verifier_enabled: bool,
    accepted_by_policy: bool,
    production_blocker: bool,
    mitigation_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-RESIDUAL-RISK-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(bool_str(base_layer_verifier_enabled)),
            HashPart::Str(bool_str(accepted_by_policy)),
            HashPart::Str(bool_str(production_blocker)),
            HashPart::Str(mitigation_root),
        ],
        32,
    )
}

fn production_blocker_root(
    blocker: ReleaseBlocker,
    severity: &str,
    blocks_production: bool,
    required_exit: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-PRODUCTION-BLOCKER-ROOT",
        &[
            HashPart::Str(blocker.as_str()),
            HashPart::Str(severity),
            HashPart::Str(bool_str(blocks_production)),
            HashPart::Str(required_exit),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn encrypted_payload_root(
    subject_id: &str,
    header_hash: &str,
    watcher_count: u64,
    encrypted: bool,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-ENCRYPTED-WATCHER-PAYLOAD",
        &[
            HashPart::Str(redacted_subject_id(subject_id).as_str()),
            HashPart::Str(header_hash),
            HashPart::U64(watcher_count),
            HashPart::Str(bool_str(encrypted)),
        ],
        32,
    )
}

fn state_root_from_parts(
    config_root: &str,
    accepted_evidence_root: &str,
    negative_case_root: &str,
    residual_risk_root: &str,
    production_blocker_root: &str,
    report_root: &str,
) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-STATE-ROOT",
        &[
            HashPart::Str(config_root),
            HashPart::Str(accepted_evidence_root),
            HashPart::Str(negative_case_root),
            HashPart::Str(residual_risk_root),
            HashPart::Str(production_blocker_root),
            HashPart::Str(report_root),
        ],
        32,
    )
}

fn labeled_hash(label: &str, subject_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-LABELED-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn redacted_subject_id(subject_id: &str) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-REDACTED-SUBJECT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(subject_id)],
        20,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-EVIDENCE-POLICY-RECORD-ROOT",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn merkle_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
