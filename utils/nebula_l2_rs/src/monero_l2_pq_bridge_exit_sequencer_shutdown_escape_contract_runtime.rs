use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSequencerShutdownEscapeContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SEQUENCER_SHUTDOWN_ESCAPE_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-sequencer-shutdown-escape-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SEQUENCER_SHUTDOWN_ESCAPE_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEQUENCER_SHUTDOWN_ESCAPE_CONTRACT_SUITE: &str =
    "monero-l2-pq-bridge-exit-sequencer-shutdown-escape-contract-v1";
pub const DEFAULT_MIN_FALLBACK_DA_ROOTS: u64 = 3;
pub const DEFAULT_MIN_USER_RECEIPTS: u64 = 2;
pub const DEFAULT_WATCHER_EMERGENCY_QUORUM_WEIGHT: u64 = 7;
pub const DEFAULT_PQ_AUTHORITY_THRESHOLD_WEIGHT: u64 = 5;
pub const DEFAULT_FORCED_EXIT_ACTIVATION_DELAY_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_HANDOFF_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_TRANSCRIPT_DISCLOSURES: u64 = 2;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDataAvailabilityKind {
    L1Calldata,
    MoneroHeaderAnchor,
    WatcherArchive,
    UserReceiptMirror,
    ReleaseFixtureManifest,
}

impl FallbackDataAvailabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L1Calldata => "l1_calldata",
            Self::MoneroHeaderAnchor => "monero_header_anchor",
            Self::WatcherArchive => "watcher_archive",
            Self::UserReceiptMirror => "user_receipt_mirror",
            Self::ReleaseFixtureManifest => "release_fixture_manifest",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownEvidenceKind {
    SequencerHeartbeatExpired,
    BatchPublicationGap,
    DaRootUnavailable,
    WatcherEmergencyQuorum,
    PqAuthorityOverride,
}

impl ShutdownEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerHeartbeatExpired => "sequencer_heartbeat_expired",
            Self::BatchPublicationGap => "batch_publication_gap",
            Self::DaRootUnavailable => "da_root_unavailable",
            Self::WatcherEmergencyQuorum => "watcher_emergency_quorum",
            Self::PqAuthorityOverride => "pq_authority_override",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDisclosureMode {
    CommitmentOnly,
    NullifierAndAmountBand,
    ViewTagWindow,
    SelectivePlaintext,
}

impl ReceiptDisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::NullifierAndAmountBand => "nullifier_and_amount_band",
            Self::ViewTagWindow => "view_tag_window",
            Self::SelectivePlaintext => "selective_plaintext",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedExitLaneStatus {
    Dormant,
    Armed,
    Active,
    HandoffReady,
    Settled,
    Quarantined,
}

impl ForcedExitLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Armed => "armed",
            Self::Active => "active",
            Self::HandoffReady => "handoff_ready",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeContractStatus {
    Observing,
    EmergencyArmed,
    ForcedExitActive,
    HandoffReady,
    Settled,
    Blocked,
}

impl EscapeContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observing => "observing",
            Self::EmergencyArmed => "emergency_armed",
            Self::ForcedExitActive => "forced_exit_active",
            Self::HandoffReady => "handoff_ready",
            Self::Settled => "settled",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementHandoffTarget {
    LiveSettlementExecutionContract,
    TrustMinimizedBridgeExitSpine,
    ForcedExitUserRecoveryPlaybook,
    ManualReleaseRemediationFixture,
}

impl SettlementHandoffTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveSettlementExecutionContract => "live_settlement_execution_contract",
            Self::TrustMinimizedBridgeExitSpine => "trust_minimized_bridge_exit_spine",
            Self::ForcedExitUserRecoveryPlaybook => "forced_exit_user_recovery_playbook",
            Self::ManualReleaseRemediationFixture => "manual_release_remediation_fixture",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub contract_suite: String,
    pub min_fallback_da_roots: u64,
    pub min_user_receipts: u64,
    pub watcher_emergency_quorum_weight: u64,
    pub pq_authority_threshold_weight: u64,
    pub forced_exit_activation_delay_blocks: u64,
    pub settlement_handoff_ttl_blocks: u64,
    pub min_transcript_disclosures: u64,
    pub require_release_remediation_fixture_alignment: bool,
    pub require_live_settlement_handoff: bool,
    pub require_trust_minimized_spine_alignment: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            contract_suite: SEQUENCER_SHUTDOWN_ESCAPE_CONTRACT_SUITE.to_string(),
            min_fallback_da_roots: DEFAULT_MIN_FALLBACK_DA_ROOTS,
            min_user_receipts: DEFAULT_MIN_USER_RECEIPTS,
            watcher_emergency_quorum_weight: DEFAULT_WATCHER_EMERGENCY_QUORUM_WEIGHT,
            pq_authority_threshold_weight: DEFAULT_PQ_AUTHORITY_THRESHOLD_WEIGHT,
            forced_exit_activation_delay_blocks: DEFAULT_FORCED_EXIT_ACTIVATION_DELAY_BLOCKS,
            settlement_handoff_ttl_blocks: DEFAULT_SETTLEMENT_HANDOFF_TTL_BLOCKS,
            min_transcript_disclosures: DEFAULT_MIN_TRANSCRIPT_DISCLOSURES,
            require_release_remediation_fixture_alignment: true,
            require_live_settlement_handoff: true,
            require_trust_minimized_spine_alignment: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "contract_suite": self.contract_suite,
            "min_fallback_da_roots": self.min_fallback_da_roots,
            "min_user_receipts": self.min_user_receipts,
            "watcher_emergency_quorum_weight": self.watcher_emergency_quorum_weight,
            "pq_authority_threshold_weight": self.pq_authority_threshold_weight,
            "forced_exit_activation_delay_blocks": self.forced_exit_activation_delay_blocks,
            "settlement_handoff_ttl_blocks": self.settlement_handoff_ttl_blocks,
            "min_transcript_disclosures": self.min_transcript_disclosures,
            "require_release_remediation_fixture_alignment": self.require_release_remediation_fixture_alignment,
            "require_live_settlement_handoff": self.require_live_settlement_handoff,
            "require_trust_minimized_spine_alignment": self.require_trust_minimized_spine_alignment,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FallbackDataAvailabilityRoot {
    pub root_id: String,
    pub kind: FallbackDataAvailabilityKind,
    pub epoch: u64,
    pub height: u64,
    pub da_root: String,
    pub source_commitment_root: String,
    pub witness_set_root: String,
    pub release_fixture_manifest_root: String,
    pub trust_minimized_spine_root: String,
    pub available: bool,
    pub root: String,
}

impl FallbackDataAvailabilityRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FallbackDataAvailabilityKind,
        epoch: u64,
        height: u64,
        da_root: impl Into<String>,
        source_commitment_root: impl Into<String>,
        witness_set_root: impl Into<String>,
        release_fixture_manifest_root: impl Into<String>,
        trust_minimized_spine_root: impl Into<String>,
        available: bool,
    ) -> Self {
        let da_root = da_root.into();
        let source_commitment_root = source_commitment_root.into();
        let witness_set_root = witness_set_root.into();
        let release_fixture_manifest_root = release_fixture_manifest_root.into();
        let trust_minimized_spine_root = trust_minimized_spine_root.into();
        let root = fallback_da_root(
            kind,
            epoch,
            height,
            &da_root,
            &source_commitment_root,
            &witness_set_root,
            bool_str(available),
        );
        let root_id = fallback_da_root_id(kind, epoch, &root);
        Self {
            root_id,
            kind,
            epoch,
            height,
            da_root,
            source_commitment_root,
            witness_set_root,
            release_fixture_manifest_root,
            trust_minimized_spine_root,
            available,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "kind": self.kind.as_str(),
            "epoch": self.epoch,
            "height": self.height,
            "da_root": self.da_root,
            "source_commitment_root": self.source_commitment_root,
            "witness_set_root": self.witness_set_root,
            "release_fixture_manifest_root": self.release_fixture_manifest_root,
            "trust_minimized_spine_root": self.trust_minimized_spine_root,
            "available": self.available,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserSubmittedReceipt {
    pub receipt_id: String,
    pub user_commitment: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub receipt_root: String,
    pub exit_nullifier_root: String,
    pub private_receipt_scan_root: String,
    pub recovery_playbook_root: String,
    pub accepted_height: u64,
    pub disclosure_mode: ReceiptDisclosureMode,
    pub privacy_budget_bps: u64,
    pub accepted: bool,
    pub root: String,
}

impl UserSubmittedReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_commitment: impl Into<String>,
        release_claim_id: impl Into<String>,
        transfer_id: impl Into<String>,
        receipt_root: impl Into<String>,
        exit_nullifier_root: impl Into<String>,
        private_receipt_scan_root: impl Into<String>,
        recovery_playbook_root: impl Into<String>,
        accepted_height: u64,
        disclosure_mode: ReceiptDisclosureMode,
        privacy_budget_bps: u64,
        accepted: bool,
    ) -> Self {
        let user_commitment = user_commitment.into();
        let release_claim_id = release_claim_id.into();
        let transfer_id = transfer_id.into();
        let receipt_root = receipt_root.into();
        let exit_nullifier_root = exit_nullifier_root.into();
        let private_receipt_scan_root = private_receipt_scan_root.into();
        let recovery_playbook_root = recovery_playbook_root.into();
        let root = user_receipt_root(
            &user_commitment,
            &release_claim_id,
            &transfer_id,
            &receipt_root,
            &exit_nullifier_root,
            disclosure_mode,
            bool_str(accepted),
        );
        let receipt_id = user_receipt_id(&release_claim_id, &root);
        Self {
            receipt_id,
            user_commitment,
            release_claim_id,
            transfer_id,
            receipt_root,
            exit_nullifier_root,
            private_receipt_scan_root,
            recovery_playbook_root,
            accepted_height,
            disclosure_mode,
            privacy_budget_bps,
            accepted,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "user_commitment": self.user_commitment,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "receipt_root": self.receipt_root,
            "exit_nullifier_root": self.exit_nullifier_root,
            "private_receipt_scan_root": self.private_receipt_scan_root,
            "recovery_playbook_root": self.recovery_playbook_root,
            "accepted_height": self.accepted_height,
            "disclosure_mode": self.disclosure_mode.as_str(),
            "privacy_budget_bps": self.privacy_budget_bps,
            "accepted": self.accepted,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherEmergencyVote {
    pub vote_id: String,
    pub watcher_id: String,
    pub evidence_kind: ShutdownEvidenceKind,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub quorum_epoch: u64,
    pub weight: u64,
    pub slashable_bond_root: String,
    pub accepted: bool,
    pub root: String,
}

impl WatcherEmergencyVote {
    pub fn new(
        watcher_id: impl Into<String>,
        evidence_kind: ShutdownEvidenceKind,
        evidence_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        quorum_epoch: u64,
        weight: u64,
        slashable_bond_root: impl Into<String>,
        accepted: bool,
    ) -> Self {
        let watcher_id = watcher_id.into();
        let evidence_root = evidence_root.into();
        let pq_signature_root = pq_signature_root.into();
        let slashable_bond_root = slashable_bond_root.into();
        let root = watcher_vote_root(
            &watcher_id,
            evidence_kind,
            &evidence_root,
            &pq_signature_root,
            quorum_epoch,
            weight,
            bool_str(accepted),
        );
        let vote_id = watcher_vote_id(&watcher_id, &root);
        Self {
            vote_id,
            watcher_id,
            evidence_kind,
            evidence_root,
            pq_signature_root,
            quorum_epoch,
            weight,
            slashable_bond_root,
            accepted,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "watcher_id": self.watcher_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "quorum_epoch": self.quorum_epoch,
            "weight": self.weight,
            "slashable_bond_root": self.slashable_bond_root,
            "accepted": self.accepted,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyPreservingTranscriptDisclosure {
    pub disclosure_id: String,
    pub disclosure_mode: ReceiptDisclosureMode,
    pub transcript_commitment_root: String,
    pub redacted_transcript_root: String,
    pub selective_opening_root: String,
    pub view_tag_window_root: String,
    pub nullifier_set_root: String,
    pub verifier_challenge_root: String,
    pub leakage_budget_bps: u64,
    pub accepted: bool,
    pub root: String,
}

impl PrivacyPreservingTranscriptDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        disclosure_mode: ReceiptDisclosureMode,
        transcript_commitment_root: impl Into<String>,
        redacted_transcript_root: impl Into<String>,
        selective_opening_root: impl Into<String>,
        view_tag_window_root: impl Into<String>,
        nullifier_set_root: impl Into<String>,
        verifier_challenge_root: impl Into<String>,
        leakage_budget_bps: u64,
        accepted: bool,
    ) -> Self {
        let transcript_commitment_root = transcript_commitment_root.into();
        let redacted_transcript_root = redacted_transcript_root.into();
        let selective_opening_root = selective_opening_root.into();
        let view_tag_window_root = view_tag_window_root.into();
        let nullifier_set_root = nullifier_set_root.into();
        let verifier_challenge_root = verifier_challenge_root.into();
        let root = transcript_disclosure_root(
            disclosure_mode,
            &transcript_commitment_root,
            &redacted_transcript_root,
            &selective_opening_root,
            &view_tag_window_root,
            &nullifier_set_root,
            leakage_budget_bps,
            bool_str(accepted),
        );
        let disclosure_id = transcript_disclosure_id(&transcript_commitment_root, &root);
        Self {
            disclosure_id,
            disclosure_mode,
            transcript_commitment_root,
            redacted_transcript_root,
            selective_opening_root,
            view_tag_window_root,
            nullifier_set_root,
            verifier_challenge_root,
            leakage_budget_bps,
            accepted,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "disclosure_mode": self.disclosure_mode.as_str(),
            "transcript_commitment_root": self.transcript_commitment_root,
            "redacted_transcript_root": self.redacted_transcript_root,
            "selective_opening_root": self.selective_opening_root,
            "view_tag_window_root": self.view_tag_window_root,
            "nullifier_set_root": self.nullifier_set_root,
            "verifier_challenge_root": self.verifier_challenge_root,
            "leakage_budget_bps": self.leakage_budget_bps,
            "accepted": self.accepted,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqEmergencyAuthority {
    pub authority_id: String,
    pub authority_set_root: String,
    pub threshold_signature_root: String,
    pub key_epoch: u64,
    pub signer_weight: u64,
    pub threshold_weight: u64,
    pub verification_contract_root: String,
    pub key_manager_root: String,
    pub active: bool,
    pub root: String,
}

impl PqEmergencyAuthority {
    pub fn new(
        authority_set_root: impl Into<String>,
        threshold_signature_root: impl Into<String>,
        key_epoch: u64,
        signer_weight: u64,
        threshold_weight: u64,
        verification_contract_root: impl Into<String>,
        key_manager_root: impl Into<String>,
        active: bool,
    ) -> Self {
        let authority_set_root = authority_set_root.into();
        let threshold_signature_root = threshold_signature_root.into();
        let verification_contract_root = verification_contract_root.into();
        let key_manager_root = key_manager_root.into();
        let root = pq_authority_root(
            &authority_set_root,
            &threshold_signature_root,
            key_epoch,
            signer_weight,
            threshold_weight,
            bool_str(active),
        );
        let authority_id = pq_authority_id(key_epoch, &root);
        Self {
            authority_id,
            authority_set_root,
            threshold_signature_root,
            key_epoch,
            signer_weight,
            threshold_weight,
            verification_contract_root,
            key_manager_root,
            active,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "authority_set_root": self.authority_set_root,
            "threshold_signature_root": self.threshold_signature_root,
            "key_epoch": self.key_epoch,
            "signer_weight": self.signer_weight,
            "threshold_weight": self.threshold_weight,
            "verification_contract_root": self.verification_contract_root,
            "key_manager_root": self.key_manager_root,
            "active": self.active,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitLaneActivation {
    pub activation_id: String,
    pub status: ForcedExitLaneStatus,
    pub release_claim_id: String,
    pub activation_height: u64,
    pub executable_after_height: u64,
    pub fallback_da_bundle_root: String,
    pub user_receipt_bundle_root: String,
    pub watcher_quorum_root: String,
    pub transcript_disclosure_bundle_root: String,
    pub pq_authority_root: String,
    pub forced_exit_playbook_root: String,
    pub root: String,
}

impl ForcedExitLaneActivation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: ForcedExitLaneStatus,
        release_claim_id: impl Into<String>,
        activation_height: u64,
        executable_after_height: u64,
        fallback_da_bundle_root: impl Into<String>,
        user_receipt_bundle_root: impl Into<String>,
        watcher_quorum_root: impl Into<String>,
        transcript_disclosure_bundle_root: impl Into<String>,
        pq_authority_root: impl Into<String>,
        forced_exit_playbook_root: impl Into<String>,
    ) -> Self {
        let release_claim_id = release_claim_id.into();
        let fallback_da_bundle_root = fallback_da_bundle_root.into();
        let user_receipt_bundle_root = user_receipt_bundle_root.into();
        let watcher_quorum_root = watcher_quorum_root.into();
        let transcript_disclosure_bundle_root = transcript_disclosure_bundle_root.into();
        let pq_authority_root = pq_authority_root.into();
        let forced_exit_playbook_root = forced_exit_playbook_root.into();
        let root = forced_exit_lane_root(
            status,
            &release_claim_id,
            activation_height,
            executable_after_height,
            &fallback_da_bundle_root,
            &user_receipt_bundle_root,
            &watcher_quorum_root,
            &pq_authority_root,
        );
        let activation_id = forced_exit_lane_id(&release_claim_id, &root);
        Self {
            activation_id,
            status,
            release_claim_id,
            activation_height,
            executable_after_height,
            fallback_da_bundle_root,
            user_receipt_bundle_root,
            watcher_quorum_root,
            transcript_disclosure_bundle_root,
            pq_authority_root,
            forced_exit_playbook_root,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activation_id": self.activation_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "activation_height": self.activation_height,
            "executable_after_height": self.executable_after_height,
            "fallback_da_bundle_root": self.fallback_da_bundle_root,
            "user_receipt_bundle_root": self.user_receipt_bundle_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "transcript_disclosure_bundle_root": self.transcript_disclosure_bundle_root,
            "pq_authority_root": self.pq_authority_root,
            "forced_exit_playbook_root": self.forced_exit_playbook_root,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementHandoff {
    pub handoff_id: String,
    pub target: SettlementHandoffTarget,
    pub release_claim_id: String,
    pub activation_id: String,
    pub live_settlement_contract_root: String,
    pub trust_minimized_spine_root: String,
    pub remediation_fixture_manifest_root: String,
    pub handoff_payload_root: String,
    pub handoff_receipt_root: String,
    pub expires_at_height: u64,
    pub accepted: bool,
    pub root: String,
}

impl SettlementHandoff {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: SettlementHandoffTarget,
        release_claim_id: impl Into<String>,
        activation_id: impl Into<String>,
        live_settlement_contract_root: impl Into<String>,
        trust_minimized_spine_root: impl Into<String>,
        remediation_fixture_manifest_root: impl Into<String>,
        handoff_payload_root: impl Into<String>,
        handoff_receipt_root: impl Into<String>,
        expires_at_height: u64,
        accepted: bool,
    ) -> Self {
        let release_claim_id = release_claim_id.into();
        let activation_id = activation_id.into();
        let live_settlement_contract_root = live_settlement_contract_root.into();
        let trust_minimized_spine_root = trust_minimized_spine_root.into();
        let remediation_fixture_manifest_root = remediation_fixture_manifest_root.into();
        let handoff_payload_root = handoff_payload_root.into();
        let handoff_receipt_root = handoff_receipt_root.into();
        let root = settlement_handoff_root(
            target,
            &release_claim_id,
            &activation_id,
            &live_settlement_contract_root,
            &trust_minimized_spine_root,
            &handoff_payload_root,
            &handoff_receipt_root,
            bool_str(accepted),
        );
        let handoff_id = settlement_handoff_id(&release_claim_id, &root);
        Self {
            handoff_id,
            target,
            release_claim_id,
            activation_id,
            live_settlement_contract_root,
            trust_minimized_spine_root,
            remediation_fixture_manifest_root,
            handoff_payload_root,
            handoff_receipt_root,
            expires_at_height,
            accepted,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "target": self.target.as_str(),
            "release_claim_id": self.release_claim_id,
            "activation_id": self.activation_id,
            "live_settlement_contract_root": self.live_settlement_contract_root,
            "trust_minimized_spine_root": self.trust_minimized_spine_root,
            "remediation_fixture_manifest_root": self.remediation_fixture_manifest_root,
            "handoff_payload_root": self.handoff_payload_root,
            "handoff_receipt_root": self.handoff_receipt_root,
            "expires_at_height": self.expires_at_height,
            "accepted": self.accepted,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EscapeCounters {
    pub fallback_da_roots: u64,
    pub available_fallback_da_roots: u64,
    pub user_receipts: u64,
    pub accepted_user_receipts: u64,
    pub watcher_votes: u64,
    pub accepted_watcher_votes: u64,
    pub watcher_quorum_weight: u64,
    pub transcript_disclosures: u64,
    pub accepted_transcript_disclosures: u64,
    pub pq_authorities: u64,
    pub active_pq_authorities: u64,
    pub forced_exit_activations: u64,
    pub settlement_handoffs: u64,
    pub accepted_settlement_handoffs: u64,
}

impl EscapeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "fallback_da_roots": self.fallback_da_roots,
            "available_fallback_da_roots": self.available_fallback_da_roots,
            "user_receipts": self.user_receipts,
            "accepted_user_receipts": self.accepted_user_receipts,
            "watcher_votes": self.watcher_votes,
            "accepted_watcher_votes": self.accepted_watcher_votes,
            "watcher_quorum_weight": self.watcher_quorum_weight,
            "transcript_disclosures": self.transcript_disclosures,
            "accepted_transcript_disclosures": self.accepted_transcript_disclosures,
            "pq_authorities": self.pq_authorities,
            "active_pq_authorities": self.active_pq_authorities,
            "forced_exit_activations": self.forced_exit_activations,
            "settlement_handoffs": self.settlement_handoffs,
            "accepted_settlement_handoffs": self.accepted_settlement_handoffs,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EscapeContractReport {
    pub report_id: String,
    pub status: EscapeContractStatus,
    pub config_root: String,
    pub source_alignment_root: String,
    pub fallback_da_bundle_root: String,
    pub user_receipt_bundle_root: String,
    pub watcher_quorum_root: String,
    pub transcript_disclosure_bundle_root: String,
    pub pq_authority_bundle_root: String,
    pub forced_exit_lane_root: String,
    pub settlement_handoff_root: String,
    pub counters_root: String,
    pub report_root: String,
    pub counters: EscapeCounters,
    pub release_claim_id: String,
    pub gate_reason: String,
}

impl EscapeContractReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "config_root": self.config_root,
            "source_alignment_root": self.source_alignment_root,
            "fallback_da_bundle_root": self.fallback_da_bundle_root,
            "user_receipt_bundle_root": self.user_receipt_bundle_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "transcript_disclosure_bundle_root": self.transcript_disclosure_bundle_root,
            "pq_authority_bundle_root": self.pq_authority_bundle_root,
            "forced_exit_lane_root": self.forced_exit_lane_root,
            "settlement_handoff_root": self.settlement_handoff_root,
            "counters_root": self.counters_root,
            "report_root": self.report_root,
            "counters": self.counters.public_record(),
            "release_claim_id": self.release_claim_id,
            "gate_reason": self.gate_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fallback_da_roots: BTreeMap<String, FallbackDataAvailabilityRoot>,
    pub user_receipts: BTreeMap<String, UserSubmittedReceipt>,
    pub watcher_votes: BTreeMap<String, WatcherEmergencyVote>,
    pub transcript_disclosures: BTreeMap<String, PrivacyPreservingTranscriptDisclosure>,
    pub pq_authorities: BTreeMap<String, PqEmergencyAuthority>,
    pub forced_exit_activations: BTreeMap<String, ForcedExitLaneActivation>,
    pub settlement_handoffs: BTreeMap<String, SettlementHandoff>,
    pub reports: BTreeMap<String, EscapeContractReport>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            fallback_da_roots: BTreeMap::new(),
            user_receipts: BTreeMap::new(),
            watcher_votes: BTreeMap::new(),
            transcript_disclosures: BTreeMap::new(),
            pq_authorities: BTreeMap::new(),
            forced_exit_activations: BTreeMap::new(),
            settlement_handoffs: BTreeMap::new(),
            reports: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn insert_fallback_da_root(&mut self, record: FallbackDataAvailabilityRoot) -> Result<()> {
        ensure(
            !record.root_id.is_empty(),
            "fallback da root id is required",
        )?;
        self.fallback_da_roots
            .insert(record.root_id.clone(), record);
        Ok(())
    }

    pub fn insert_user_receipt(&mut self, receipt: UserSubmittedReceipt) -> Result<()> {
        ensure(
            !receipt.receipt_id.is_empty(),
            "user receipt id is required",
        )?;
        self.user_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_watcher_vote(&mut self, vote: WatcherEmergencyVote) -> Result<()> {
        ensure(!vote.vote_id.is_empty(), "watcher vote id is required")?;
        self.watcher_votes.insert(vote.vote_id.clone(), vote);
        Ok(())
    }

    pub fn insert_transcript_disclosure(
        &mut self,
        disclosure: PrivacyPreservingTranscriptDisclosure,
    ) -> Result<()> {
        ensure(
            !disclosure.disclosure_id.is_empty(),
            "transcript disclosure id is required",
        )?;
        self.transcript_disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure);
        Ok(())
    }

    pub fn insert_pq_authority(&mut self, authority: PqEmergencyAuthority) -> Result<()> {
        ensure(
            !authority.authority_id.is_empty(),
            "pq authority id is required",
        )?;
        self.pq_authorities
            .insert(authority.authority_id.clone(), authority);
        Ok(())
    }

    pub fn insert_forced_exit_activation(
        &mut self,
        activation: ForcedExitLaneActivation,
    ) -> Result<()> {
        ensure(
            !activation.activation_id.is_empty(),
            "forced exit activation id is required",
        )?;
        self.forced_exit_activations
            .insert(activation.activation_id.clone(), activation);
        Ok(())
    }

    pub fn insert_settlement_handoff(&mut self, handoff: SettlementHandoff) -> Result<()> {
        ensure(
            !handoff.handoff_id.is_empty(),
            "settlement handoff id is required",
        )?;
        self.settlement_handoffs
            .insert(handoff.handoff_id.clone(), handoff);
        Ok(())
    }

    pub fn counters(&self) -> EscapeCounters {
        let fallback_da_roots = self.fallback_da_roots.len() as u64;
        let available_fallback_da_roots = self
            .fallback_da_roots
            .values()
            .filter(|record| record.available)
            .count() as u64;
        let user_receipts = self.user_receipts.len() as u64;
        let accepted_user_receipts = self
            .user_receipts
            .values()
            .filter(|receipt| receipt.accepted)
            .count() as u64;
        let watcher_votes = self.watcher_votes.len() as u64;
        let accepted_watcher_votes = self
            .watcher_votes
            .values()
            .filter(|vote| vote.accepted)
            .count() as u64;
        let watcher_quorum_weight = self
            .watcher_votes
            .values()
            .filter(|vote| vote.accepted)
            .map(|vote| vote.weight)
            .sum();
        let transcript_disclosures = self.transcript_disclosures.len() as u64;
        let accepted_transcript_disclosures = self
            .transcript_disclosures
            .values()
            .filter(|disclosure| disclosure.accepted)
            .count() as u64;
        let pq_authorities = self.pq_authorities.len() as u64;
        let active_pq_authorities = self
            .pq_authorities
            .values()
            .filter(|authority| authority.active)
            .count() as u64;
        let forced_exit_activations = self.forced_exit_activations.len() as u64;
        let settlement_handoffs = self.settlement_handoffs.len() as u64;
        let accepted_settlement_handoffs = self
            .settlement_handoffs
            .values()
            .filter(|handoff| handoff.accepted)
            .count() as u64;
        EscapeCounters {
            fallback_da_roots,
            available_fallback_da_roots,
            user_receipts,
            accepted_user_receipts,
            watcher_votes,
            accepted_watcher_votes,
            watcher_quorum_weight,
            transcript_disclosures,
            accepted_transcript_disclosures,
            pq_authorities,
            active_pq_authorities,
            forced_exit_activations,
            settlement_handoffs,
            accepted_settlement_handoffs,
        }
    }

    pub fn state_root(&self) -> String {
        merkle_root(&[
            self.config.state_root(),
            collection_root(
                "fallback_da_roots",
                self.fallback_da_roots
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "user_receipts",
                self.user_receipts
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "watcher_votes",
                self.watcher_votes
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "transcript_disclosures",
                self.transcript_disclosures
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "pq_authorities",
                self.pq_authorities
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "forced_exit_activations",
                self.forced_exit_activations
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
            collection_root(
                "settlement_handoffs",
                self.settlement_handoffs
                    .values()
                    .map(|record| record.root.clone())
                    .collect(),
            ),
        ])
    }

    pub fn build_report(
        &mut self,
        release_claim_id: impl Into<String>,
        source_alignment: SourceAlignmentRoots,
    ) -> Result<EscapeContractReport> {
        ensure(
            self.reports.len() < self.config.max_reports,
            "maximum report count reached",
        )?;
        let release_claim_id = release_claim_id.into();
        ensure(!release_claim_id.is_empty(), "release claim id is required")?;
        let counters = self.counters();
        let config_root = self.config.state_root();
        let source_alignment_root = source_alignment.state_root();
        let fallback_da_bundle_root = collection_root(
            "fallback_da_roots",
            self.fallback_da_roots
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let user_receipt_bundle_root = collection_root(
            "user_receipts",
            self.user_receipts
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let watcher_quorum_root = collection_root(
            "watcher_votes",
            self.watcher_votes
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let transcript_disclosure_bundle_root = collection_root(
            "transcript_disclosures",
            self.transcript_disclosures
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let pq_authority_bundle_root = collection_root(
            "pq_authorities",
            self.pq_authorities
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let forced_exit_lane_root = collection_root(
            "forced_exit_activations",
            self.forced_exit_activations
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let settlement_handoff_root = collection_root(
            "settlement_handoffs",
            self.settlement_handoffs
                .values()
                .map(|record| record.root.clone())
                .collect(),
        );
        let counters_root = counters.state_root();
        let (status, gate_reason) = self.evaluate_gate(&counters, &source_alignment);
        let report_root = escape_contract_report_root(
            status,
            &config_root,
            &source_alignment_root,
            &fallback_da_bundle_root,
            &user_receipt_bundle_root,
            &watcher_quorum_root,
            &transcript_disclosure_bundle_root,
            &pq_authority_bundle_root,
            &forced_exit_lane_root,
            &settlement_handoff_root,
            &counters_root,
            &release_claim_id,
        );
        let report_id = escape_contract_report_id(&release_claim_id, &report_root);
        let report = EscapeContractReport {
            report_id: report_id.clone(),
            status,
            config_root,
            source_alignment_root,
            fallback_da_bundle_root,
            user_receipt_bundle_root,
            watcher_quorum_root,
            transcript_disclosure_bundle_root,
            pq_authority_bundle_root,
            forced_exit_lane_root,
            settlement_handoff_root,
            counters_root,
            report_root,
            counters,
            release_claim_id,
            gate_reason,
        };
        self.reports.insert(report_id, report.clone());
        Ok(report)
    }

    pub fn evaluate_gate(
        &self,
        counters: &EscapeCounters,
        source_alignment: &SourceAlignmentRoots,
    ) -> (EscapeContractStatus, String) {
        if counters.available_fallback_da_roots < self.config.min_fallback_da_roots {
            return (
                EscapeContractStatus::Observing,
                "waiting_for_fallback_data_availability_roots".to_string(),
            );
        }
        if counters.accepted_user_receipts < self.config.min_user_receipts {
            return (
                EscapeContractStatus::EmergencyArmed,
                "waiting_for_user_submitted_receipts".to_string(),
            );
        }
        if counters.watcher_quorum_weight < self.config.watcher_emergency_quorum_weight {
            return (
                EscapeContractStatus::EmergencyArmed,
                "waiting_for_watcher_emergency_quorum".to_string(),
            );
        }
        if counters.accepted_transcript_disclosures < self.config.min_transcript_disclosures {
            return (
                EscapeContractStatus::EmergencyArmed,
                "waiting_for_privacy_preserving_transcript_disclosure".to_string(),
            );
        }
        if counters.active_pq_authorities == 0 {
            return (
                EscapeContractStatus::EmergencyArmed,
                "waiting_for_pq_emergency_authority".to_string(),
            );
        }
        if self.config.require_release_remediation_fixture_alignment
            && source_alignment
                .release_remediation_fixture_manifest_root
                .is_empty()
        {
            return (
                EscapeContractStatus::Blocked,
                "release_remediation_fixture_manifest_alignment_missing".to_string(),
            );
        }
        if self.config.require_trust_minimized_spine_alignment
            && source_alignment
                .trust_minimized_bridge_exit_spine_root
                .is_empty()
        {
            return (
                EscapeContractStatus::Blocked,
                "trust_minimized_bridge_exit_spine_alignment_missing".to_string(),
            );
        }
        if counters.forced_exit_activations == 0 {
            return (
                EscapeContractStatus::ForcedExitActive,
                "forced_exit_lane_activation_ready".to_string(),
            );
        }
        if self.config.require_live_settlement_handoff && counters.accepted_settlement_handoffs == 0
        {
            return (
                EscapeContractStatus::HandoffReady,
                "waiting_for_live_settlement_handoff".to_string(),
            );
        }
        (
            EscapeContractStatus::Settled,
            "escape_contract_settled".to_string(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceAlignmentRoots {
    pub forced_exit_user_recovery_playbook_root: String,
    pub release_remediation_fixture_manifest_root: String,
    pub live_settlement_execution_contract_root: String,
    pub trust_minimized_bridge_exit_spine_root: String,
}

impl SourceAlignmentRoots {
    pub fn new(
        forced_exit_user_recovery_playbook_root: impl Into<String>,
        release_remediation_fixture_manifest_root: impl Into<String>,
        live_settlement_execution_contract_root: impl Into<String>,
        trust_minimized_bridge_exit_spine_root: impl Into<String>,
    ) -> Self {
        Self {
            forced_exit_user_recovery_playbook_root: forced_exit_user_recovery_playbook_root.into(),
            release_remediation_fixture_manifest_root: release_remediation_fixture_manifest_root
                .into(),
            live_settlement_execution_contract_root: live_settlement_execution_contract_root.into(),
            trust_minimized_bridge_exit_spine_root: trust_minimized_bridge_exit_spine_root.into(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-DEVNET-PLAYBOOK",
                &[HashPart::Str("forced_exit_user_recovery_playbook")],
                32,
            ),
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-DEVNET-FIXTURE",
                &[HashPart::Str("release_remediation_fixture_manifest")],
                32,
            ),
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-DEVNET-LIVE-SETTLEMENT",
                &[HashPart::Str("live_settlement_execution_contract")],
                32,
            ),
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-DEVNET-SPINE",
                &[HashPart::Str("trust_minimized_bridge_exit_spine")],
                32,
            ),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "forced_exit_user_recovery_playbook_root": self.forced_exit_user_recovery_playbook_root,
            "release_remediation_fixture_manifest_root": self.release_remediation_fixture_manifest_root,
            "live_settlement_execution_contract_root": self.live_settlement_execution_contract_root,
            "trust_minimized_bridge_exit_spine_root": self.trust_minimized_bridge_exit_spine_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source_alignment_roots", &self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

#[allow(clippy::too_many_arguments)]
pub fn fallback_da_root(
    kind: FallbackDataAvailabilityKind,
    epoch: u64,
    height: u64,
    da_root: &str,
    source_commitment_root: &str,
    witness_set_root: &str,
    available: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-FALLBACK-DA-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(height),
            HashPart::Str(da_root),
            HashPart::Str(source_commitment_root),
            HashPart::Str(witness_set_root),
            HashPart::Str(available),
        ],
        32,
    )
}

pub fn fallback_da_root_id(kind: FallbackDataAvailabilityKind, epoch: u64, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-FALLBACK-DA-ROOT-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(epoch),
            HashPart::Str(root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn user_receipt_root(
    user_commitment: &str,
    release_claim_id: &str,
    transfer_id: &str,
    receipt_root: &str,
    exit_nullifier_root: &str,
    disclosure_mode: ReceiptDisclosureMode,
    accepted: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-USER-RECEIPT",
        &[
            HashPart::Str(user_commitment),
            HashPart::Str(release_claim_id),
            HashPart::Str(transfer_id),
            HashPart::Str(receipt_root),
            HashPart::Str(exit_nullifier_root),
            HashPart::Str(disclosure_mode.as_str()),
            HashPart::Str(accepted),
        ],
        32,
    )
}

pub fn user_receipt_id(release_claim_id: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-USER-RECEIPT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn watcher_vote_root(
    watcher_id: &str,
    evidence_kind: ShutdownEvidenceKind,
    evidence_root: &str,
    pq_signature_root: &str,
    quorum_epoch: u64,
    weight: u64,
    accepted: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-WATCHER-VOTE",
        &[
            HashPart::Str(watcher_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(pq_signature_root),
            HashPart::U64(quorum_epoch),
            HashPart::U64(weight),
            HashPart::Str(accepted),
        ],
        32,
    )
}

pub fn watcher_vote_id(watcher_id: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-WATCHER-VOTE-ID",
        &[HashPart::Str(watcher_id), HashPart::Str(root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn transcript_disclosure_root(
    disclosure_mode: ReceiptDisclosureMode,
    transcript_commitment_root: &str,
    redacted_transcript_root: &str,
    selective_opening_root: &str,
    view_tag_window_root: &str,
    nullifier_set_root: &str,
    leakage_budget_bps: u64,
    accepted: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-TRANSCRIPT-DISCLOSURE",
        &[
            HashPart::Str(disclosure_mode.as_str()),
            HashPart::Str(transcript_commitment_root),
            HashPart::Str(redacted_transcript_root),
            HashPart::Str(selective_opening_root),
            HashPart::Str(view_tag_window_root),
            HashPart::Str(nullifier_set_root),
            HashPart::U64(leakage_budget_bps),
            HashPart::Str(accepted),
        ],
        32,
    )
}

pub fn transcript_disclosure_id(transcript_commitment_root: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-TRANSCRIPT-DISCLOSURE-ID",
        &[
            HashPart::Str(transcript_commitment_root),
            HashPart::Str(root),
        ],
        32,
    )
}

pub fn pq_authority_root(
    authority_set_root: &str,
    threshold_signature_root: &str,
    key_epoch: u64,
    signer_weight: u64,
    threshold_weight: u64,
    active: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-PQ-AUTHORITY",
        &[
            HashPart::Str(authority_set_root),
            HashPart::Str(threshold_signature_root),
            HashPart::U64(key_epoch),
            HashPart::U64(signer_weight),
            HashPart::U64(threshold_weight),
            HashPart::Str(active),
        ],
        32,
    )
}

pub fn pq_authority_id(key_epoch: u64, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-PQ-AUTHORITY-ID",
        &[HashPart::U64(key_epoch), HashPart::Str(root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn forced_exit_lane_root(
    status: ForcedExitLaneStatus,
    release_claim_id: &str,
    activation_height: u64,
    executable_after_height: u64,
    fallback_da_bundle_root: &str,
    user_receipt_bundle_root: &str,
    watcher_quorum_root: &str,
    pq_authority_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-FORCED-EXIT-LANE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::U64(activation_height),
            HashPart::U64(executable_after_height),
            HashPart::Str(fallback_da_bundle_root),
            HashPart::Str(user_receipt_bundle_root),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(pq_authority_root),
        ],
        32,
    )
}

pub fn forced_exit_lane_id(release_claim_id: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-FORCED-EXIT-LANE-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn settlement_handoff_root(
    target: SettlementHandoffTarget,
    release_claim_id: &str,
    activation_id: &str,
    live_settlement_contract_root: &str,
    trust_minimized_spine_root: &str,
    handoff_payload_root: &str,
    handoff_receipt_root: &str,
    accepted: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-SETTLEMENT-HANDOFF",
        &[
            HashPart::Str(target.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(activation_id),
            HashPart::Str(live_settlement_contract_root),
            HashPart::Str(trust_minimized_spine_root),
            HashPart::Str(handoff_payload_root),
            HashPart::Str(handoff_receipt_root),
            HashPart::Str(accepted),
        ],
        32,
    )
}

pub fn settlement_handoff_id(release_claim_id: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-SETTLEMENT-HANDOFF-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn escape_contract_report_root(
    status: EscapeContractStatus,
    config_root: &str,
    source_alignment_root: &str,
    fallback_da_bundle_root: &str,
    user_receipt_bundle_root: &str,
    watcher_quorum_root: &str,
    transcript_disclosure_bundle_root: &str,
    pq_authority_bundle_root: &str,
    forced_exit_lane_root: &str,
    settlement_handoff_root: &str,
    counters_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-ESCAPE-CONTRACT-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(config_root),
            HashPart::Str(source_alignment_root),
            HashPart::Str(fallback_da_bundle_root),
            HashPart::Str(user_receipt_bundle_root),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(transcript_disclosure_bundle_root),
            HashPart::Str(pq_authority_bundle_root),
            HashPart::Str(forced_exit_lane_root),
            HashPart::Str(settlement_handoff_root),
            HashPart::Str(counters_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn escape_contract_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-ESCAPE-CONTRACT-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn collection_root(kind: &str, mut roots: Vec<String>) -> String {
    roots.sort();
    let root = merkle_root(&roots);
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-COLLECTION",
        &[HashPart::Str(kind), HashPart::Str(&root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SEQUENCER-SHUTDOWN-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
