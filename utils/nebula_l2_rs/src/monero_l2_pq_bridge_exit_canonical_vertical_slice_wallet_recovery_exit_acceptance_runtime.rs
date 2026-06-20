use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletRecoveryExitAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RECOVERY_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-recovery-exit-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RECOVERY_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-wallet-recovery-exit-acceptance-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-wallet-recovery-exit-acceptance-devnet-v1";
pub const DEFAULT_RECOVERY_EPOCH: u64 = 13;
pub const DEFAULT_L2_FINALIZED_HEIGHT: u64 = 98_144;
pub const DEFAULT_MONERO_FINALIZED_HEIGHT: u64 = 3_492_640;
pub const DEFAULT_MIN_WALLET_EXPORTS: u16 = 3;
pub const DEFAULT_MIN_NOTE_RECONSTRUCTIONS: u16 = 2;
pub const DEFAULT_MIN_PQ_ATTESTATIONS: u16 = 4;
pub const DEFAULT_MIN_RECEIPT_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u16 = 1;
pub const DEFAULT_MAX_BUNDLE_AGE_BLOCKS: u64 = 48;
pub const REQUIRED_ACCEPTANCE_LANES: usize = 10;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceLane {
    WalletScanExport,
    RecoveryKeyBinding,
    PrivateNoteReconstruction,
    NullifierFence,
    ForcedExitClaim,
    PqAuthorityQuorum,
    ObservedReceipt,
    MoneroFinality,
    PrivacyBudget,
    OperatorReleaseGate,
}

impl AcceptanceLane {
    pub fn all() -> [Self; REQUIRED_ACCEPTANCE_LANES] {
        [
            Self::WalletScanExport,
            Self::RecoveryKeyBinding,
            Self::PrivateNoteReconstruction,
            Self::NullifierFence,
            Self::ForcedExitClaim,
            Self::PqAuthorityQuorum,
            Self::ObservedReceipt,
            Self::MoneroFinality,
            Self::PrivacyBudget,
            Self::OperatorReleaseGate,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanExport => "wallet_scan_export",
            Self::RecoveryKeyBinding => "recovery_key_binding",
            Self::PrivateNoteReconstruction => "private_note_reconstruction",
            Self::NullifierFence => "nullifier_fence",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::PqAuthorityQuorum => "pq_authority_quorum",
            Self::ObservedReceipt => "observed_receipt",
            Self::MoneroFinality => "monero_finality",
            Self::PrivacyBudget => "privacy_budget",
            Self::OperatorReleaseGate => "operator_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    WalletExportRoot,
    RecoveryKeyBinding,
    SpendViewLinkage,
    PrivateNoteReconstruction,
    NullifierFence,
    ForcedExitClaim,
    PqAuthorityAttestation,
    ReceiptObservation,
    MoneroFinalityProof,
    PrivacyBudgetReceipt,
    ReleaseGateReceipt,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletExportRoot => "wallet_export_root",
            Self::RecoveryKeyBinding => "recovery_key_binding",
            Self::SpendViewLinkage => "spend_view_linkage",
            Self::PrivateNoteReconstruction => "private_note_reconstruction",
            Self::NullifierFence => "nullifier_fence",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::PqAuthorityAttestation => "pq_authority_attestation",
            Self::ReceiptObservation => "receipt_observation",
            Self::MoneroFinalityProof => "monero_finality_proof",
            Self::PrivacyBudgetReceipt => "privacy_budget_receipt",
            Self::ReleaseGateReceipt => "release_gate_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Sufficient,
    Missing,
    Mismatched,
    Stale,
    Insufficient,
    Quarantined,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Sufficient => "sufficient",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Stale => "stale",
            Self::Insufficient => "insufficient",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn release_blocking(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::Mismatched | Self::Stale | Self::Insufficient | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceVerdict {
    AcceptForcedExit,
    KeepReleaseBlocked,
}

impl AcceptanceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptForcedExit => "accept_forced_exit",
            Self::KeepReleaseBlocked => "keep_release_blocked",
        }
    }

    pub fn release_accepted(self) -> bool {
        self == Self::AcceptForcedExit
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerReason {
    WalletExportMissing,
    RecoveryBindingMismatch,
    NoteReconstructionInsufficient,
    NullifierFenceMismatch,
    ForcedExitClaimMissing,
    PqAuthorityQuorumMissing,
    ReceiptConfirmationMissing,
    MoneroFinalityMissing,
    PrivacyBudgetExceeded,
    OperatorGateHeld,
    BundleExpired,
    BundleQuarantined,
}

impl BlockerReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletExportMissing => "wallet_export_missing",
            Self::RecoveryBindingMismatch => "recovery_binding_mismatch",
            Self::NoteReconstructionInsufficient => "note_reconstruction_insufficient",
            Self::NullifierFenceMismatch => "nullifier_fence_mismatch",
            Self::ForcedExitClaimMissing => "forced_exit_claim_missing",
            Self::PqAuthorityQuorumMissing => "pq_authority_quorum_missing",
            Self::ReceiptConfirmationMissing => "receipt_confirmation_missing",
            Self::MoneroFinalityMissing => "monero_finality_missing",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::OperatorGateHeld => "operator_gate_held",
            Self::BundleExpired => "bundle_expired",
            Self::BundleQuarantined => "bundle_quarantined",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub acceptance_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub recovery_epoch: u64,
    pub l2_finalized_height: u64,
    pub monero_finalized_height: u64,
    pub min_wallet_exports: u16,
    pub min_note_reconstructions: u16,
    pub min_pq_attestations: u16,
    pub min_receipt_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u16,
    pub max_bundle_age_blocks: u64,
    pub forced_exit_acceptance_enabled: bool,
    pub release_requires_all_lanes: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: ACCEPTANCE_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            recovery_epoch: DEFAULT_RECOVERY_EPOCH,
            l2_finalized_height: DEFAULT_L2_FINALIZED_HEIGHT,
            monero_finalized_height: DEFAULT_MONERO_FINALIZED_HEIGHT,
            min_wallet_exports: DEFAULT_MIN_WALLET_EXPORTS,
            min_note_reconstructions: DEFAULT_MIN_NOTE_RECONSTRUCTIONS,
            min_pq_attestations: DEFAULT_MIN_PQ_ATTESTATIONS,
            min_receipt_confirmations: DEFAULT_MIN_RECEIPT_CONFIRMATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            max_bundle_age_blocks: DEFAULT_MAX_BUNDLE_AGE_BLOCKS,
            forced_exit_acceptance_enabled: true,
            release_requires_all_lanes: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "recovery_epoch": self.recovery_epoch,
            "l2_finalized_height": self.l2_finalized_height,
            "monero_finalized_height": self.monero_finalized_height,
            "min_wallet_exports": self.min_wallet_exports,
            "min_note_reconstructions": self.min_note_reconstructions,
            "min_pq_attestations": self.min_pq_attestations,
            "min_receipt_confirmations": self.min_receipt_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "max_bundle_age_blocks": self.max_bundle_age_blocks,
            "forced_exit_acceptance_enabled": self.forced_exit_acceptance_enabled,
            "release_requires_all_lanes": self.release_requires_all_lanes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletRecoveryBundle {
    pub bundle_id: String,
    pub wallet_id: String,
    pub recovery_claim_id: String,
    pub forced_exit_id: String,
    pub claimant_commitment: String,
    pub wallet_export_root: String,
    pub recovery_binding_root: String,
    pub private_note_root: String,
    pub nullifier_fence_root: String,
    pub forced_exit_claim_root: String,
    pub pq_authority_root: String,
    pub observed_receipt_root: String,
    pub monero_finality_root: String,
    pub privacy_budget_root: String,
    pub operator_gate_root: String,
    pub wallet_export_count: u16,
    pub reconstructed_note_count: u16,
    pub pq_attestation_count: u16,
    pub receipt_confirmations: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u16,
    pub created_l2_height: u64,
    pub observed_monero_height: u64,
    pub quarantined: bool,
}

impl WalletRecoveryBundle {
    pub fn new(
        wallet_id: impl Into<String>,
        recovery_claim_id: impl Into<String>,
        forced_exit_id: impl Into<String>,
        counts: BundleCounts,
    ) -> Self {
        let wallet_id = wallet_id.into();
        let recovery_claim_id = recovery_claim_id.into();
        let forced_exit_id = forced_exit_id.into();
        let claimant_commitment = label_root("claimant", &wallet_id);
        let wallet_export_root = label_root("wallet-export", &recovery_claim_id);
        let recovery_binding_root = label_root("recovery-binding", &wallet_id);
        let private_note_root = label_root("private-note", &recovery_claim_id);
        let nullifier_fence_root = label_root("nullifier-fence", &forced_exit_id);
        let forced_exit_claim_root = label_root("forced-exit-claim", &forced_exit_id);
        let pq_authority_root = label_root("pq-authority", &forced_exit_id);
        let observed_receipt_root = label_root("observed-receipt", &forced_exit_id);
        let monero_finality_root = label_root("monero-finality", &forced_exit_id);
        let privacy_budget_root = label_root("privacy-budget", &wallet_id);
        let operator_gate_root = label_root("operator-gate", &forced_exit_id);
        let bundle_id = bundle_id(
            &wallet_id,
            &recovery_claim_id,
            &forced_exit_id,
            counts.created_l2_height,
        );
        Self {
            bundle_id,
            wallet_id,
            recovery_claim_id,
            forced_exit_id,
            claimant_commitment,
            wallet_export_root,
            recovery_binding_root,
            private_note_root,
            nullifier_fence_root,
            forced_exit_claim_root,
            pq_authority_root,
            observed_receipt_root,
            monero_finality_root,
            privacy_budget_root,
            operator_gate_root,
            wallet_export_count: counts.wallet_export_count,
            reconstructed_note_count: counts.reconstructed_note_count,
            pq_attestation_count: counts.pq_attestation_count,
            receipt_confirmations: counts.receipt_confirmations,
            privacy_set_size: counts.privacy_set_size,
            metadata_leakage_units: counts.metadata_leakage_units,
            created_l2_height: counts.created_l2_height,
            observed_monero_height: counts.observed_monero_height,
            quarantined: counts.quarantined,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "wallet_id": self.wallet_id,
            "recovery_claim_id": self.recovery_claim_id,
            "forced_exit_id": self.forced_exit_id,
            "claimant_commitment": self.claimant_commitment,
            "wallet_export_root": self.wallet_export_root,
            "recovery_binding_root": self.recovery_binding_root,
            "private_note_root": self.private_note_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "pq_authority_root": self.pq_authority_root,
            "observed_receipt_root": self.observed_receipt_root,
            "monero_finality_root": self.monero_finality_root,
            "privacy_budget_root": self.privacy_budget_root,
            "operator_gate_root": self.operator_gate_root,
            "wallet_export_count": self.wallet_export_count,
            "reconstructed_note_count": self.reconstructed_note_count,
            "pq_attestation_count": self.pq_attestation_count,
            "receipt_confirmations": self.receipt_confirmations,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "created_l2_height": self.created_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "quarantined": self.quarantined,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet-recovery-bundle", &self.public_record())
    }

    pub fn is_expired(&self, config: &Config) -> bool {
        self.created_l2_height
            .saturating_add(config.max_bundle_age_blocks)
            < config.l2_finalized_height
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCounts {
    pub wallet_export_count: u16,
    pub reconstructed_note_count: u16,
    pub pq_attestation_count: u16,
    pub receipt_confirmations: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u16,
    pub created_l2_height: u64,
    pub observed_monero_height: u64,
    pub quarantined: bool,
}

impl BundleCounts {
    pub fn accepting(created_l2_height: u64, observed_monero_height: u64) -> Self {
        Self {
            wallet_export_count: DEFAULT_MIN_WALLET_EXPORTS,
            reconstructed_note_count: DEFAULT_MIN_NOTE_RECONSTRUCTIONS,
            pq_attestation_count: DEFAULT_MIN_PQ_ATTESTATIONS,
            receipt_confirmations: DEFAULT_MIN_RECEIPT_CONFIRMATIONS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_add(64),
            metadata_leakage_units: 0,
            created_l2_height,
            observed_monero_height,
            quarantined: false,
        }
    }

    pub fn blocked(created_l2_height: u64, observed_monero_height: u64) -> Self {
        Self {
            wallet_export_count: 1,
            reconstructed_note_count: 1,
            pq_attestation_count: 2,
            receipt_confirmations: 3,
            privacy_set_size: 42,
            metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS.saturating_add(4),
            created_l2_height,
            observed_monero_height,
            quarantined: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCheck {
    pub check_id: String,
    pub bundle_id: String,
    pub lane: AcceptanceLane,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub measured_value: u64,
    pub required_value: u64,
    pub evidence_root: String,
    pub expected_root: String,
    pub transcript_root: String,
    pub blocker_reason: Option<BlockerReason>,
}

impl EvidenceCheck {
    pub fn new(
        bundle_id: impl Into<String>,
        lane: AcceptanceLane,
        kind: EvidenceKind,
        status: EvidenceStatus,
        measured_value: u64,
        required_value: u64,
        evidence_root: impl Into<String>,
        expected_root: impl Into<String>,
        blocker_reason: Option<BlockerReason>,
    ) -> Self {
        let bundle_id = bundle_id.into();
        let evidence_root = evidence_root.into();
        let expected_root = expected_root.into();
        let check_id = evidence_check_id(&bundle_id, lane, kind, &evidence_root, &expected_root);
        let transcript_root = evidence_transcript_root(
            &check_id,
            &bundle_id,
            lane,
            kind,
            status,
            measured_value,
            required_value,
            &evidence_root,
            &expected_root,
        );
        Self {
            check_id,
            bundle_id,
            lane,
            kind,
            status,
            measured_value,
            required_value,
            evidence_root,
            expected_root,
            transcript_root,
            blocker_reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "bundle_id": self.bundle_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "measured_value": self.measured_value,
            "required_value": self.required_value,
            "evidence_root": self.evidence_root,
            "expected_root": self.expected_root,
            "transcript_root": self.transcript_root,
            "blocker_reason": self.blocker_reason.map(|reason| reason.as_str()),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("evidence-check", &self.public_record())
    }

    pub fn release_blocking(&self) -> bool {
        self.status.release_blocking() || self.blocker_reason.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceCertificate {
    pub certificate_id: String,
    pub bundle_id: String,
    pub verdict: AcceptanceVerdict,
    pub acceptance_root: String,
    pub blocker_root: String,
    pub evidence_root: String,
    pub bundle_root: String,
    pub release_blocked: bool,
    pub accepted_lanes: u16,
    pub blocked_lanes: u16,
    pub issued_l2_height: u64,
    pub issued_monero_height: u64,
}

impl AcceptanceCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "bundle_id": self.bundle_id,
            "verdict": self.verdict.as_str(),
            "acceptance_root": self.acceptance_root,
            "blocker_root": self.blocker_root,
            "evidence_root": self.evidence_root,
            "bundle_root": self.bundle_root,
            "release_blocked": self.release_blocked,
            "accepted_lanes": self.accepted_lanes,
            "blocked_lanes": self.blocked_lanes,
            "issued_l2_height": self.issued_l2_height,
            "issued_monero_height": self.issued_monero_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("acceptance-certificate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceSummary {
    pub accepted_bundles: u64,
    pub blocked_bundles: u64,
    pub evidence_checks: u64,
    pub blocker_events: u64,
    pub wallet_export_failures: u64,
    pub pq_quorum_failures: u64,
    pub privacy_failures: u64,
    pub finality_failures: u64,
    pub release_gate_failures: u64,
}

impl AcceptanceSummary {
    pub fn empty() -> Self {
        Self {
            accepted_bundles: 0,
            blocked_bundles: 0,
            evidence_checks: 0,
            blocker_events: 0,
            wallet_export_failures: 0,
            pq_quorum_failures: 0,
            privacy_failures: 0,
            finality_failures: 0,
            release_gate_failures: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted_bundles": self.accepted_bundles,
            "blocked_bundles": self.blocked_bundles,
            "evidence_checks": self.evidence_checks,
            "blocker_events": self.blocker_events,
            "wallet_export_failures": self.wallet_export_failures,
            "pq_quorum_failures": self.pq_quorum_failures,
            "privacy_failures": self.privacy_failures,
            "finality_failures": self.finality_failures,
            "release_gate_failures": self.release_gate_failures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("acceptance-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub bundle_root: String,
    pub evidence_root: String,
    pub certificate_root: String,
    pub summary_root: String,
}

impl StateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bundle_root": self.bundle_root,
            "evidence_root": self.evidence_root,
            "certificate_root": self.certificate_root,
            "summary_root": self.summary_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bundles: BTreeMap<String, WalletRecoveryBundle>,
    pub evidence_checks: BTreeMap<String, EvidenceCheck>,
    pub certificates: BTreeMap<String, AcceptanceCertificate>,
    pub summary: AcceptanceSummary,
    pub roots: StateRoots,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            roots: StateRoots {
                config_root: config.state_root(),
                bundle_root: merkle_root("bundle", &[]),
                evidence_root: merkle_root("evidence-check", &[]),
                certificate_root: merkle_root("acceptance-certificate", &[]),
                summary_root: AcceptanceSummary::empty().state_root(),
            },
            config,
            bundles: BTreeMap::new(),
            evidence_checks: BTreeMap::new(),
            certificates: BTreeMap::new(),
            summary: AcceptanceSummary::empty(),
        };
        state.refresh_roots();
        state
    }

    pub fn ingest_bundle(
        &mut self,
        bundle: WalletRecoveryBundle,
    ) -> MoneroL2PqBridgeExitCanonicalVerticalSliceWalletRecoveryExitAcceptanceRuntimeResult<
        AcceptanceCertificate,
    > {
        if self.bundles.contains_key(&bundle.bundle_id) {
            return Err(format!(
                "duplicate wallet recovery bundle {}",
                bundle.bundle_id
            ));
        }
        let checks = self.evaluate_bundle(&bundle);
        for check in checks {
            self.summary.evidence_checks = self.summary.evidence_checks.saturating_add(1);
            if check.release_blocking() {
                self.summary.blocker_events = self.summary.blocker_events.saturating_add(1);
                self.observe_blocker(check.blocker_reason);
            }
            self.evidence_checks.insert(check.check_id.clone(), check);
        }
        self.bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        let certificate = self.certificate_for_bundle(&bundle);
        if certificate.verdict.release_accepted() {
            self.summary.accepted_bundles = self.summary.accepted_bundles.saturating_add(1);
        } else {
            self.summary.blocked_bundles = self.summary.blocked_bundles.saturating_add(1);
        }
        self.certificates
            .insert(certificate.certificate_id.clone(), certificate.clone());
        self.refresh_roots();
        Ok(certificate)
    }

    pub fn evaluate_bundle(&self, bundle: &WalletRecoveryBundle) -> Vec<EvidenceCheck> {
        let mut checks = Vec::new();
        checks.push(self.count_check(
            bundle,
            AcceptanceLane::WalletScanExport,
            EvidenceKind::WalletExportRoot,
            bundle.wallet_export_count as u64,
            self.config.min_wallet_exports as u64,
            &bundle.wallet_export_root,
            BlockerReason::WalletExportMissing,
        ));
        checks.push(self.root_check(
            bundle,
            AcceptanceLane::RecoveryKeyBinding,
            EvidenceKind::RecoveryKeyBinding,
            &bundle.recovery_binding_root,
            &label_root("recovery-binding", &bundle.wallet_id),
            BlockerReason::RecoveryBindingMismatch,
        ));
        checks.push(self.count_check(
            bundle,
            AcceptanceLane::PrivateNoteReconstruction,
            EvidenceKind::PrivateNoteReconstruction,
            bundle.reconstructed_note_count as u64,
            self.config.min_note_reconstructions as u64,
            &bundle.private_note_root,
            BlockerReason::NoteReconstructionInsufficient,
        ));
        checks.push(self.root_check(
            bundle,
            AcceptanceLane::NullifierFence,
            EvidenceKind::NullifierFence,
            &bundle.nullifier_fence_root,
            &label_root("nullifier-fence", &bundle.forced_exit_id),
            BlockerReason::NullifierFenceMismatch,
        ));
        checks.push(self.root_check(
            bundle,
            AcceptanceLane::ForcedExitClaim,
            EvidenceKind::ForcedExitClaim,
            &bundle.forced_exit_claim_root,
            &label_root("forced-exit-claim", &bundle.forced_exit_id),
            BlockerReason::ForcedExitClaimMissing,
        ));
        checks.push(self.count_check(
            bundle,
            AcceptanceLane::PqAuthorityQuorum,
            EvidenceKind::PqAuthorityAttestation,
            bundle.pq_attestation_count as u64,
            self.config.min_pq_attestations as u64,
            &bundle.pq_authority_root,
            BlockerReason::PqAuthorityQuorumMissing,
        ));
        checks.push(self.count_check(
            bundle,
            AcceptanceLane::ObservedReceipt,
            EvidenceKind::ReceiptObservation,
            bundle.receipt_confirmations,
            self.config.min_receipt_confirmations,
            &bundle.observed_receipt_root,
            BlockerReason::ReceiptConfirmationMissing,
        ));
        checks.push(self.finality_check(bundle));
        checks.push(self.privacy_check(bundle));
        checks.push(self.operator_gate_check(bundle));
        checks.push(self.bundle_age_check(bundle));
        checks.push(self.bundle_quarantine_check(bundle));
        checks
    }

    pub fn certificate_for_bundle(&self, bundle: &WalletRecoveryBundle) -> AcceptanceCertificate {
        let mut accepted_lanes = 0_u16;
        let mut blocked_lanes = 0_u16;
        let mut blocker_records = Vec::new();
        let mut evidence_records = Vec::new();
        for check in self.evaluate_bundle(bundle) {
            evidence_records.push((check.check_id.clone(), check.public_record()));
            if check.release_blocking() {
                blocked_lanes = blocked_lanes.saturating_add(1);
                blocker_records.push((check.check_id.clone(), check.public_record()));
            } else {
                accepted_lanes = accepted_lanes.saturating_add(1);
            }
        }
        let evidence_root = merkle_root("WALLET-RECOVERY-ACCEPTANCE-EVIDENCE", &evidence_records);
        let blocker_root = merkle_root("WALLET-RECOVERY-ACCEPTANCE-BLOCKER", &blocker_records);
        let bundle_root = bundle.state_root();
        let release_blocked = blocked_lanes != 0 || !self.config.forced_exit_acceptance_enabled;
        let verdict = if release_blocked {
            AcceptanceVerdict::KeepReleaseBlocked
        } else {
            AcceptanceVerdict::AcceptForcedExit
        };
        let acceptance_root = acceptance_root(
            &bundle.bundle_id,
            verdict,
            accepted_lanes,
            blocked_lanes,
            &evidence_root,
            &blocker_root,
            &bundle_root,
        );
        let certificate_id = certificate_id(&bundle.bundle_id, verdict, &acceptance_root);
        AcceptanceCertificate {
            certificate_id,
            bundle_id: bundle.bundle_id.clone(),
            verdict,
            acceptance_root,
            blocker_root,
            evidence_root,
            bundle_root,
            release_blocked,
            accepted_lanes,
            blocked_lanes,
            issued_l2_height: self.config.l2_finalized_height,
            issued_monero_height: self.config.monero_finalized_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "bundles": map_records(&self.bundles, WalletRecoveryBundle::public_record),
            "evidence_checks": map_records(&self.evidence_checks, EvidenceCheck::public_record),
            "certificates": map_records(&self.certificates, AcceptanceCertificate::public_record),
            "summary": self.summary.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-ACCEPTANCE-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.roots.public_record()),
                HashPart::Json(&self.summary.public_record()),
            ],
            32,
        )
    }

    fn count_check(
        &self,
        bundle: &WalletRecoveryBundle,
        lane: AcceptanceLane,
        kind: EvidenceKind,
        measured_value: u64,
        required_value: u64,
        evidence_root: &str,
        blocker_reason: BlockerReason,
    ) -> EvidenceCheck {
        let status = if measured_value >= required_value {
            EvidenceStatus::Sufficient
        } else {
            EvidenceStatus::Insufficient
        };
        let reason = if status.release_blocking() {
            Some(blocker_reason)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            lane,
            kind,
            status,
            measured_value,
            required_value,
            evidence_root,
            evidence_root,
            reason,
        )
    }

    fn root_check(
        &self,
        bundle: &WalletRecoveryBundle,
        lane: AcceptanceLane,
        kind: EvidenceKind,
        evidence_root: &str,
        expected_root: &str,
        blocker_reason: BlockerReason,
    ) -> EvidenceCheck {
        let status = if evidence_root == expected_root {
            EvidenceStatus::Present
        } else {
            EvidenceStatus::Mismatched
        };
        let reason = if status.release_blocking() {
            Some(blocker_reason)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            lane,
            kind,
            status,
            1,
            1,
            evidence_root,
            expected_root,
            reason,
        )
    }

    fn finality_check(&self, bundle: &WalletRecoveryBundle) -> EvidenceCheck {
        let status = if bundle.observed_monero_height <= self.config.monero_finalized_height {
            EvidenceStatus::Sufficient
        } else {
            EvidenceStatus::Stale
        };
        let reason = if status.release_blocking() {
            Some(BlockerReason::MoneroFinalityMissing)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            AcceptanceLane::MoneroFinality,
            EvidenceKind::MoneroFinalityProof,
            status,
            self.config.monero_finalized_height,
            bundle.observed_monero_height,
            &bundle.monero_finality_root,
            &label_root("monero-finality", &bundle.forced_exit_id),
            reason,
        )
    }

    fn privacy_check(&self, bundle: &WalletRecoveryBundle) -> EvidenceCheck {
        let set_ok = bundle.privacy_set_size >= self.config.min_privacy_set_size;
        let leakage_ok = bundle.metadata_leakage_units <= self.config.max_metadata_leakage_units;
        let status = if set_ok && leakage_ok {
            EvidenceStatus::Sufficient
        } else {
            EvidenceStatus::Insufficient
        };
        let reason = if status.release_blocking() {
            Some(BlockerReason::PrivacyBudgetExceeded)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            AcceptanceLane::PrivacyBudget,
            EvidenceKind::PrivacyBudgetReceipt,
            status,
            bundle.privacy_set_size,
            self.config.min_privacy_set_size,
            &bundle.privacy_budget_root,
            &label_root("privacy-budget", &bundle.wallet_id),
            reason,
        )
    }

    fn operator_gate_check(&self, bundle: &WalletRecoveryBundle) -> EvidenceCheck {
        self.root_check(
            bundle,
            AcceptanceLane::OperatorReleaseGate,
            EvidenceKind::ReleaseGateReceipt,
            &bundle.operator_gate_root,
            &label_root("operator-gate", &bundle.forced_exit_id),
            BlockerReason::OperatorGateHeld,
        )
    }

    fn bundle_age_check(&self, bundle: &WalletRecoveryBundle) -> EvidenceCheck {
        let status = if bundle.is_expired(&self.config) {
            EvidenceStatus::Stale
        } else {
            EvidenceStatus::Sufficient
        };
        let reason = if status.release_blocking() {
            Some(BlockerReason::BundleExpired)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            AcceptanceLane::ForcedExitClaim,
            EvidenceKind::SpendViewLinkage,
            status,
            self.config
                .l2_finalized_height
                .saturating_sub(bundle.created_l2_height),
            self.config.max_bundle_age_blocks,
            &bundle.forced_exit_claim_root,
            &bundle.forced_exit_claim_root,
            reason,
        )
    }

    fn bundle_quarantine_check(&self, bundle: &WalletRecoveryBundle) -> EvidenceCheck {
        let status = if bundle.quarantined {
            EvidenceStatus::Quarantined
        } else {
            EvidenceStatus::Present
        };
        let reason = if status.release_blocking() {
            Some(BlockerReason::BundleQuarantined)
        } else {
            None
        };
        EvidenceCheck::new(
            &bundle.bundle_id,
            AcceptanceLane::OperatorReleaseGate,
            EvidenceKind::ReleaseGateReceipt,
            status,
            0,
            0,
            &bundle.operator_gate_root,
            &bundle.operator_gate_root,
            reason,
        )
    }

    fn observe_blocker(&mut self, reason: Option<BlockerReason>) {
        match reason {
            Some(BlockerReason::WalletExportMissing) => {
                self.summary.wallet_export_failures =
                    self.summary.wallet_export_failures.saturating_add(1);
            }
            Some(BlockerReason::PqAuthorityQuorumMissing) => {
                self.summary.pq_quorum_failures = self.summary.pq_quorum_failures.saturating_add(1);
            }
            Some(BlockerReason::PrivacyBudgetExceeded) => {
                self.summary.privacy_failures = self.summary.privacy_failures.saturating_add(1);
            }
            Some(BlockerReason::MoneroFinalityMissing) => {
                self.summary.finality_failures = self.summary.finality_failures.saturating_add(1);
            }
            Some(BlockerReason::OperatorGateHeld) | Some(BlockerReason::BundleQuarantined) => {
                self.summary.release_gate_failures =
                    self.summary.release_gate_failures.saturating_add(1);
            }
            _ => {}
        }
    }

    fn refresh_roots(&mut self) {
        self.roots = StateRoots {
            config_root: self.config.state_root(),
            bundle_root: map_root("bundle", &self.bundles),
            evidence_root: map_root("evidence-check", &self.evidence_checks),
            certificate_root: map_root("acceptance-certificate", &self.certificates),
            summary_root: self.summary.state_root(),
        };
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone());
    let accepted = WalletRecoveryBundle::new(
        "devnet-wallet-recovery-accept-wallet",
        "devnet-wallet-recovery-accept-claim",
        "devnet-forced-exit-accept-001",
        BundleCounts::accepting(
            config.l2_finalized_height.saturating_sub(8),
            config.monero_finalized_height.saturating_sub(2),
        ),
    );
    let blocked = WalletRecoveryBundle::new(
        "devnet-wallet-recovery-block-wallet",
        "devnet-wallet-recovery-block-claim",
        "devnet-forced-exit-block-001",
        BundleCounts::blocked(
            config.l2_finalized_height.saturating_sub(72),
            config.monero_finalized_height.saturating_add(5),
        ),
    );
    let mut quarantined = WalletRecoveryBundle::new(
        "devnet-wallet-recovery-quarantine-wallet",
        "devnet-wallet-recovery-quarantine-claim",
        "devnet-forced-exit-quarantine-001",
        BundleCounts::accepting(
            config.l2_finalized_height.saturating_sub(7),
            config.monero_finalized_height.saturating_sub(1),
        ),
    );
    quarantined.quarantined = true;
    let _accepted_certificate = state.ingest_bundle(accepted);
    let _blocked_certificate = state.ingest_bundle(blocked);
    let _quarantined_certificate = state.ingest_bundle(quarantined);
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-ACCEPTANCE-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn bundle_id(
    wallet_id: &str,
    recovery_claim_id: &str,
    forced_exit_id: &str,
    created_l2_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(recovery_claim_id),
            HashPart::Str(forced_exit_id),
            HashPart::U64(created_l2_height),
        ],
        32,
    )
}

pub fn evidence_check_id(
    bundle_id: &str,
    lane: AcceptanceLane,
    kind: EvidenceKind,
    evidence_root: &str,
    expected_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-EVIDENCE-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(expected_root),
        ],
        32,
    )
}

pub fn evidence_transcript_root(
    check_id: &str,
    bundle_id: &str,
    lane: AcceptanceLane,
    kind: EvidenceKind,
    status: EvidenceStatus,
    measured_value: u64,
    required_value: u64,
    evidence_root: &str,
    expected_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-EVIDENCE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(check_id),
            HashPart::Str(bundle_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(measured_value),
            HashPart::U64(required_value),
            HashPart::Str(evidence_root),
            HashPart::Str(expected_root),
        ],
        32,
    )
}

pub fn acceptance_root(
    bundle_id: &str,
    verdict: AcceptanceVerdict,
    accepted_lanes: u16,
    blocked_lanes: u16,
    evidence_root: &str,
    blocker_root: &str,
    bundle_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-ACCEPTANCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(verdict.as_str()),
            HashPart::U64(accepted_lanes as u64),
            HashPart::U64(blocked_lanes as u64),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(bundle_root),
        ],
        32,
    )
}

pub fn certificate_id(
    bundle_id: &str,
    verdict: AcceptanceVerdict,
    acceptance_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-ACCEPTANCE-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(acceptance_root),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECOVERY-ACCEPTANCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn map_root<T>(domain: &str, map: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let records: Vec<(String, Value)> = map
        .iter()
        .map(|(key, item)| (key.clone(), item.public_record_value()))
        .collect();
    merkle_root(domain, &records)
}

pub fn map_records<T, F>(map: &BTreeMap<String, T>, record_fn: F) -> BTreeMap<String, Value>
where
    F: Fn(&T) -> Value,
{
    map.iter()
        .map(|(key, item)| (key.clone(), record_fn(item)))
        .collect()
}

pub trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for WalletRecoveryBundle {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for EvidenceCheck {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for AcceptanceCertificate {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
