use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type BridgeFinalityResult<T> = Result<T, String>;

pub const BRIDGE_FINALITY_PROTOCOL_VERSION: &str = "nebula-bridge-finality-v1";
pub const BRIDGE_FINALITY_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const BRIDGE_FINALITY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const BRIDGE_FINALITY_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 10;
pub const BRIDGE_FINALITY_DEFAULT_SOFT_CONFIRMATION_DEPTH: u64 = 3;
pub const BRIDGE_FINALITY_DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 4;
pub const BRIDGE_FINALITY_DEFAULT_RELEASE_TTL_BLOCKS: u64 = 160;
pub const BRIDGE_FINALITY_DEFAULT_COHORT_MAX_ITEMS: u64 = 32;
pub const BRIDGE_FINALITY_DEFAULT_COHORT_MAX_UNITS: u64 = 2_500_000;
pub const BRIDGE_FINALITY_DEFAULT_INSURANCE_MIN_COVERAGE_BPS: u64 = 10_500;
pub const BRIDGE_FINALITY_DEFAULT_SIGNER_ROTATION_GRACE_BLOCKS: u64 = 20;
pub const BRIDGE_FINALITY_DEFAULT_PAUSE_EVIDENCE_QUORUM: u64 = 2;
pub const BRIDGE_FINALITY_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const BRIDGE_FINALITY_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 24;
pub const BRIDGE_FINALITY_DEFAULT_RECONCILIATION_INTERVAL_BLOCKS: u64 = 12;
pub const BRIDGE_FINALITY_DEFAULT_MAX_DELAYED_QUEUE_DEPTH: u64 = 512;
pub const BRIDGE_FINALITY_MAX_BPS: u64 = 10_000;
pub const BRIDGE_FINALITY_UNBOUNDED_AMOUNT: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositFinalityStatus {
    Observed,
    SoftConfirmed,
    Finalized,
    Disputed,
    Reorged,
}

impl DepositFinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SoftConfirmed => "soft_confirmed",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalReleaseStatus {
    Queued,
    Delayed,
    Ready,
    Cohorted,
    Released,
    Cancelled,
    Expired,
    Paused,
}

impl WithdrawalReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Delayed => "delayed",
            Self::Ready => "ready",
            Self::Cohorted => "cohorted",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalCohortStatus {
    Open,
    Scheduled,
    Releasing,
    Released,
    Cancelled,
    Disputed,
}

impl WithdrawalCohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Scheduled => "scheduled",
            Self::Releasing => "releasing",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceTrancheStatus {
    Active,
    Locked,
    Paying,
    Depleted,
    Retired,
    Expired,
}

impl InsuranceTrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Paying => "paying",
            Self::Depleted => "depleted",
            Self::Retired => "retired",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRotationStatus {
    Proposed,
    Active,
    Grace,
    Retired,
    Revoked,
    Expired,
}

impl SignerRotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyPauseAction {
    Pause,
    Unpause,
}

impl EmergencyPauseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Unpause => "unpause",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyEvidenceStatus {
    Pending,
    Active,
    Superseded,
    Expired,
    Rejected,
}

impl EmergencyEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveReconciliationStatus {
    Balanced,
    Surplus,
    Shortfall,
    InsuredShortfall,
    Disputed,
}

impl ReserveReconciliationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Surplus => "surplus",
            Self::Shortfall => "shortfall",
            Self::InsuredShortfall => "insured_shortfall",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Reclaimed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerSignalKind {
    DepositObserved,
    DepositFinal,
    WithdrawalQueued,
    ReleaseCohortReady,
    ReleaseSubmitted,
    ReserveReconciled,
    PauseEvidence,
    ReorgAlert,
    SignerRotation,
}

impl WatchtowerSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositObserved => "deposit_observed",
            Self::DepositFinal => "deposit_final",
            Self::WithdrawalQueued => "withdrawal_queued",
            Self::ReleaseCohortReady => "release_cohort_ready",
            Self::ReleaseSubmitted => "release_submitted",
            Self::ReserveReconciled => "reserve_reconciled",
            Self::PauseEvidence => "pause_evidence",
            Self::ReorgAlert => "reorg_alert",
            Self::SignerRotation => "signer_rotation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerAttestationStatus {
    Fresh,
    Stale,
    Disputed,
    Slashed,
    Revoked,
}

impl WatchtowerAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFinalityParameters {
    pub protocol_version: String,
    pub monero_finality_depth: u64,
    pub soft_confirmation_depth: u64,
    pub release_delay_blocks: u64,
    pub release_ttl_blocks: u64,
    pub release_cohort_max_items: u64,
    pub release_cohort_max_units: u64,
    pub insurance_min_coverage_bps: u64,
    pub signer_rotation_grace_blocks: u64,
    pub pause_evidence_quorum: u64,
    pub watchtower_quorum: u64,
    pub sponsorship_ttl_blocks: u64,
    pub reserve_reconciliation_interval_blocks: u64,
    pub max_delayed_queue_depth: u64,
}

impl Default for BridgeFinalityParameters {
    fn default() -> Self {
        Self {
            protocol_version: BRIDGE_FINALITY_PROTOCOL_VERSION.to_string(),
            monero_finality_depth: BRIDGE_FINALITY_DEFAULT_MONERO_FINALITY_DEPTH,
            soft_confirmation_depth: BRIDGE_FINALITY_DEFAULT_SOFT_CONFIRMATION_DEPTH,
            release_delay_blocks: BRIDGE_FINALITY_DEFAULT_RELEASE_DELAY_BLOCKS,
            release_ttl_blocks: BRIDGE_FINALITY_DEFAULT_RELEASE_TTL_BLOCKS,
            release_cohort_max_items: BRIDGE_FINALITY_DEFAULT_COHORT_MAX_ITEMS,
            release_cohort_max_units: BRIDGE_FINALITY_DEFAULT_COHORT_MAX_UNITS,
            insurance_min_coverage_bps: BRIDGE_FINALITY_DEFAULT_INSURANCE_MIN_COVERAGE_BPS,
            signer_rotation_grace_blocks: BRIDGE_FINALITY_DEFAULT_SIGNER_ROTATION_GRACE_BLOCKS,
            pause_evidence_quorum: BRIDGE_FINALITY_DEFAULT_PAUSE_EVIDENCE_QUORUM,
            watchtower_quorum: BRIDGE_FINALITY_DEFAULT_WATCHTOWER_QUORUM,
            sponsorship_ttl_blocks: BRIDGE_FINALITY_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            reserve_reconciliation_interval_blocks:
                BRIDGE_FINALITY_DEFAULT_RECONCILIATION_INTERVAL_BLOCKS,
            max_delayed_queue_depth: BRIDGE_FINALITY_DEFAULT_MAX_DELAYED_QUEUE_DEPTH,
        }
    }
}

impl BridgeFinalityParameters {
    pub fn validate(&self) -> BridgeFinalityResult<String> {
        if self.protocol_version != BRIDGE_FINALITY_PROTOCOL_VERSION {
            return Err("bridge finality protocol version mismatch".to_string());
        }
        if self.monero_finality_depth == 0 {
            return Err("bridge finality Monero depth must be positive".to_string());
        }
        if self.soft_confirmation_depth == 0 {
            return Err("bridge finality soft confirmation depth must be positive".to_string());
        }
        if self.soft_confirmation_depth > self.monero_finality_depth {
            return Err("bridge finality soft depth cannot exceed finality depth".to_string());
        }
        if self.release_delay_blocks == 0 {
            return Err("bridge finality release delay must be positive".to_string());
        }
        if self.release_ttl_blocks <= self.release_delay_blocks {
            return Err("bridge finality release ttl must exceed release delay".to_string());
        }
        if self.release_cohort_max_items == 0 {
            return Err("bridge finality cohort item limit must be positive".to_string());
        }
        if self.release_cohort_max_units == 0 {
            return Err("bridge finality cohort unit limit must be positive".to_string());
        }
        if self.insurance_min_coverage_bps < BRIDGE_FINALITY_MAX_BPS {
            return Err(
                "bridge finality insurance coverage floor must be at least 100%".to_string(),
            );
        }
        if self.signer_rotation_grace_blocks == 0 {
            return Err("bridge finality signer rotation grace must be positive".to_string());
        }
        if self.pause_evidence_quorum == 0 {
            return Err("bridge finality pause quorum must be positive".to_string());
        }
        if self.watchtower_quorum == 0 {
            return Err("bridge finality watchtower quorum must be positive".to_string());
        }
        if self.sponsorship_ttl_blocks == 0 {
            return Err("bridge finality sponsorship ttl must be positive".to_string());
        }
        if self.reserve_reconciliation_interval_blocks == 0 {
            return Err("bridge finality reconciliation interval must be positive".to_string());
        }
        if self.max_delayed_queue_depth == 0 {
            return Err("bridge finality delayed queue depth must be positive".to_string());
        }
        Ok(self.parameters_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_finality_parameters",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "monero_finality_depth": self.monero_finality_depth,
            "soft_confirmation_depth": self.soft_confirmation_depth,
            "release_delay_blocks": self.release_delay_blocks,
            "release_ttl_blocks": self.release_ttl_blocks,
            "release_cohort_max_items": self.release_cohort_max_items,
            "release_cohort_max_units": self.release_cohort_max_units,
            "insurance_min_coverage_bps": self.insurance_min_coverage_bps,
            "signer_rotation_grace_blocks": self.signer_rotation_grace_blocks,
            "pause_evidence_quorum": self.pause_evidence_quorum,
            "watchtower_quorum": self.watchtower_quorum,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "reserve_reconciliation_interval_blocks": self.reserve_reconciliation_interval_blocks,
            "max_delayed_queue_depth": self.max_delayed_queue_depth,
        })
    }

    pub fn parameters_root(&self) -> String {
        bridge_finality_payload_root("BRIDGE-FINALITY-PARAMETERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWatchtowerAttestation {
    pub attestation_id: String,
    pub watchtower_label: String,
    pub watchtower_public_key_root: String,
    pub signal_kind: WatchtowerSignalKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub observed_height: u64,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
    pub signer_rotation_id: Option<String>,
    pub signature_root: String,
    pub status: WatchtowerAttestationStatus,
}

impl BridgeWatchtowerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watchtower_label: impl Into<String>,
        watchtower_public_key_root: impl Into<String>,
        signal_kind: WatchtowerSignalKind,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        observed_height: u64,
        reported_at_height: u64,
        expires_at_height: u64,
        signer_rotation_id: Option<String>,
    ) -> BridgeFinalityResult<Self> {
        let watchtower_label = watchtower_label.into();
        let watchtower_public_key_root = watchtower_public_key_root.into();
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let signature_root = bridge_finality_signature_root(
            "BRIDGE-FINALITY-WATCHTOWER-SIGNATURE",
            &watchtower_label,
            &subject_root,
            reported_at_height,
        );
        let mut attestation = Self {
            attestation_id: String::new(),
            watchtower_label,
            watchtower_public_key_root,
            signal_kind,
            subject_kind,
            subject_id,
            subject_root,
            observed_height,
            reported_at_height,
            expires_at_height,
            signer_rotation_id,
            signature_root,
            status: WatchtowerAttestationStatus::Fresh,
        };
        attestation.attestation_id =
            bridge_watchtower_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_watchtower_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "watchtower_label": self.watchtower_label,
            "signal_kind": self.signal_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_watchtower_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "watchtower_label": self.watchtower_label,
            "watchtower_public_key_root": self.watchtower_public_key_root,
            "signal_kind": self.signal_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
            "signer_rotation_id": self.signer_rotation_id,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-WATCHTOWER-ATTESTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.attestation_id == bridge_watchtower_attestation_id(&self.identity_record())
    }

    pub fn is_fresh_at(&self, height: u64) -> bool {
        self.status == WatchtowerAttestationStatus::Fresh && height <= self.expires_at_height
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status == WatchtowerAttestationStatus::Fresh && height > self.expires_at_height {
            self.status = WatchtowerAttestationStatus::Stale;
        }
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.watchtower_label, "bridge watchtower label")?;
        ensure_non_empty(
            &self.watchtower_public_key_root,
            "bridge watchtower public key root",
        )?;
        ensure_non_empty(&self.subject_kind, "bridge watchtower subject kind")?;
        ensure_non_empty(&self.subject_id, "bridge watchtower subject id")?;
        ensure_non_empty(&self.subject_root, "bridge watchtower subject root")?;
        ensure_non_empty(&self.signature_root, "bridge watchtower signature root")?;
        if self.reported_at_height < self.observed_height {
            return Err("bridge watchtower report cannot predate observation".to_string());
        }
        if self.expires_at_height < self.reported_at_height {
            return Err("bridge watchtower attestation expires before report".to_string());
        }
        if !self.verify_id() {
            return Err("bridge watchtower attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositFinalityCertificate {
    pub certificate_id: String,
    pub deposit_id: String,
    pub monero_network: String,
    pub monero_txid_hash: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub output_commitment: String,
    pub recipient_account_commitment: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub observed_at_height: u64,
    pub finalized_at_height: u64,
    pub confirmations: u64,
    pub finality_depth: u64,
    pub output_proof_root: String,
    pub watchtower_attestation_root: String,
    pub reserve_checkpoint_id: Option<String>,
    pub attester_labels: BTreeSet<String>,
    pub status: DepositFinalityStatus,
}

impl DepositFinalityCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deposit_id: impl Into<String>,
        monero_network: impl Into<String>,
        monero_txid_hash: impl Into<String>,
        monero_block_height: u64,
        monero_block_hash: impl Into<String>,
        output_commitment: impl Into<String>,
        recipient_account_commitment: impl Into<String>,
        asset_id: impl Into<String>,
        amount_units: u64,
        observed_at_height: u64,
        confirmations: u64,
        finality_depth: u64,
        output_proof_root: impl Into<String>,
        watchtower_attestation_root: impl Into<String>,
        reserve_checkpoint_id: Option<String>,
        attester_labels: &[String],
    ) -> BridgeFinalityResult<Self> {
        let status = if confirmations >= finality_depth {
            DepositFinalityStatus::Finalized
        } else if confirmations >= BRIDGE_FINALITY_DEFAULT_SOFT_CONFIRMATION_DEPTH {
            DepositFinalityStatus::SoftConfirmed
        } else {
            DepositFinalityStatus::Observed
        };
        let finalized_at_height = if status == DepositFinalityStatus::Finalized {
            observed_at_height.saturating_add(confirmations)
        } else {
            0
        };
        let mut certificate = Self {
            certificate_id: String::new(),
            deposit_id: deposit_id.into(),
            monero_network: monero_network.into(),
            monero_txid_hash: monero_txid_hash.into(),
            monero_block_height,
            monero_block_hash: monero_block_hash.into(),
            output_commitment: output_commitment.into(),
            recipient_account_commitment: recipient_account_commitment.into(),
            asset_id: asset_id.into(),
            amount_units,
            observed_at_height,
            finalized_at_height,
            confirmations,
            finality_depth,
            output_proof_root: output_proof_root.into(),
            watchtower_attestation_root: watchtower_attestation_root.into(),
            reserve_checkpoint_id,
            attester_labels: ordered_string_set(attester_labels),
            status,
        };
        certificate.certificate_id =
            bridge_deposit_finality_certificate_id(&certificate.identity_record());
        certificate.validate()?;
        Ok(certificate)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_deposit_finality_certificate_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "deposit_id": self.deposit_id,
            "monero_network": self.monero_network,
            "monero_txid_hash": self.monero_txid_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "output_commitment": self.output_commitment,
            "recipient_account_commitment": self.recipient_account_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_deposit_finality_certificate",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "certificate_id": self.certificate_id,
            "deposit_id": self.deposit_id,
            "monero_network": self.monero_network,
            "monero_txid_hash": self.monero_txid_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "output_commitment": self.output_commitment,
            "recipient_account_commitment": self.recipient_account_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "observed_at_height": self.observed_at_height,
            "finalized_at_height": self.finalized_at_height,
            "confirmations": self.confirmations,
            "finality_depth": self.finality_depth,
            "output_proof_root": self.output_proof_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "reserve_checkpoint_id": self.reserve_checkpoint_id,
            "attester_root": self.attester_root(),
            "attester_count": self.attester_labels.len() as u64,
            "status": self.status.as_str(),
        })
    }

    pub fn certificate_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-DEPOSIT-CERTIFICATE",
            &self.public_record_without_root(),
        )
    }

    pub fn attester_root(&self) -> String {
        bridge_finality_string_set_root(
            "BRIDGE-FINALITY-DEPOSIT-ATTESTERS",
            &self.attester_labels.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "certificate_root",
            self.certificate_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.certificate_id == bridge_deposit_finality_certificate_id(&self.identity_record())
    }

    pub fn is_final(&self) -> bool {
        self.status == DepositFinalityStatus::Finalized && self.confirmations >= self.finality_depth
    }

    pub fn mark_disputed(&self) -> BridgeFinalityResult<Self> {
        let certificate = Self {
            status: DepositFinalityStatus::Disputed,
            ..self.clone()
        };
        certificate.validate()?;
        Ok(certificate)
    }

    pub fn mark_reorged(&self) -> BridgeFinalityResult<Self> {
        let certificate = Self {
            status: DepositFinalityStatus::Reorged,
            ..self.clone()
        };
        certificate.validate()?;
        Ok(certificate)
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.deposit_id, "deposit finality deposit id")?;
        ensure_non_empty(&self.monero_network, "deposit finality Monero network")?;
        ensure_non_empty(&self.monero_txid_hash, "deposit finality txid hash")?;
        ensure_non_empty(&self.monero_block_hash, "deposit finality block hash")?;
        ensure_non_empty(
            &self.output_commitment,
            "deposit finality output commitment",
        )?;
        ensure_non_empty(
            &self.recipient_account_commitment,
            "deposit finality recipient account commitment",
        )?;
        ensure_non_empty(&self.asset_id, "deposit finality asset id")?;
        ensure_non_empty(
            &self.output_proof_root,
            "deposit finality output proof root",
        )?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "deposit finality watchtower root",
        )?;
        if self.amount_units == 0 {
            return Err("deposit finality amount must be positive".to_string());
        }
        if self.finality_depth == 0 {
            return Err("deposit finality depth must be positive".to_string());
        }
        if self.attester_labels.is_empty() {
            return Err("deposit finality requires at least one attester".to_string());
        }
        if self.status == DepositFinalityStatus::Finalized {
            if self.confirmations < self.finality_depth {
                return Err("finalized deposit lacks finality confirmations".to_string());
            }
            if self.finalized_at_height < self.observed_at_height {
                return Err("deposit finalization cannot predate observation".to_string());
            }
        }
        if !self.verify_id() {
            return Err("deposit finality certificate id mismatch".to_string());
        }
        Ok(self.certificate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedReleaseQueueItem {
    pub queue_id: String,
    pub withdrawal_id: String,
    pub account_commitment: String,
    pub recipient_address_hash: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub lane_id: String,
    pub priority: u64,
    pub requested_at_height: u64,
    pub eligible_at_height: u64,
    pub expires_at_height: u64,
    pub deposit_certificate_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub cohort_id: Option<String>,
    pub fee_budget_units: u64,
    pub status: WithdrawalReleaseStatus,
}

impl DelayedReleaseQueueItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        account_commitment: impl Into<String>,
        recipient_address_hash: impl Into<String>,
        asset_id: impl Into<String>,
        amount_units: u64,
        lane_id: impl Into<String>,
        priority: u64,
        requested_at_height: u64,
        release_delay_blocks: u64,
        release_ttl_blocks: u64,
        deposit_certificate_id: Option<String>,
        fee_budget_units: u64,
    ) -> BridgeFinalityResult<Self> {
        let mut item = Self {
            queue_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            account_commitment: account_commitment.into(),
            recipient_address_hash: recipient_address_hash.into(),
            asset_id: asset_id.into(),
            amount_units,
            lane_id: lane_id.into(),
            priority,
            requested_at_height,
            eligible_at_height: requested_at_height.saturating_add(release_delay_blocks),
            expires_at_height: requested_at_height.saturating_add(release_ttl_blocks),
            deposit_certificate_id,
            sponsorship_id: None,
            cohort_id: None,
            fee_budget_units,
            status: WithdrawalReleaseStatus::Delayed,
        };
        item.queue_id = bridge_delayed_release_queue_id(&item.identity_record());
        item.validate()?;
        Ok(item)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_delayed_release_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "lane_id": self.lane_id,
            "requested_at_height": self.requested_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_delayed_release_queue_item",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "withdrawal_id": self.withdrawal_id,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "lane_id": self.lane_id,
            "priority": self.priority,
            "requested_at_height": self.requested_at_height,
            "eligible_at_height": self.eligible_at_height,
            "expires_at_height": self.expires_at_height,
            "deposit_certificate_id": self.deposit_certificate_id,
            "sponsorship_id": self.sponsorship_id,
            "cohort_id": self.cohort_id,
            "fee_budget_units": self.fee_budget_units,
            "status": self.status.as_str(),
        })
    }

    pub fn queue_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-DELAYED-RELEASE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "queue_item_root",
            self.queue_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.queue_id == bridge_delayed_release_queue_id(&self.identity_record())
    }

    pub fn is_ready_at(&self, height: u64, paused: bool) -> bool {
        !paused
            && matches!(
                self.status,
                WithdrawalReleaseStatus::Queued
                    | WithdrawalReleaseStatus::Delayed
                    | WithdrawalReleaseStatus::Ready
            )
            && height >= self.eligible_at_height
            && height <= self.expires_at_height
    }

    pub fn refresh(&mut self, height: u64, paused: bool) {
        if self.status.is_terminal() || self.status == WithdrawalReleaseStatus::Cohorted {
            return;
        }
        if height > self.expires_at_height {
            self.status = WithdrawalReleaseStatus::Expired;
        } else if paused {
            self.status = WithdrawalReleaseStatus::Paused;
        } else if height >= self.eligible_at_height {
            self.status = WithdrawalReleaseStatus::Ready;
        } else {
            self.status = WithdrawalReleaseStatus::Delayed;
        }
    }

    pub fn with_sponsorship(
        &self,
        sponsorship_id: impl Into<String>,
    ) -> BridgeFinalityResult<Self> {
        let item = Self {
            sponsorship_id: Some(sponsorship_id.into()),
            ..self.clone()
        };
        item.validate()?;
        Ok(item)
    }

    pub fn assign_to_cohort(&self, cohort_id: impl Into<String>) -> BridgeFinalityResult<Self> {
        let item = Self {
            cohort_id: Some(cohort_id.into()),
            status: WithdrawalReleaseStatus::Cohorted,
            ..self.clone()
        };
        item.validate()?;
        Ok(item)
    }

    pub fn mark_released(&self) -> BridgeFinalityResult<Self> {
        let item = Self {
            status: WithdrawalReleaseStatus::Released,
            ..self.clone()
        };
        item.validate()?;
        Ok(item)
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.withdrawal_id, "delayed release withdrawal id")?;
        ensure_non_empty(
            &self.account_commitment,
            "delayed release account commitment",
        )?;
        ensure_non_empty(
            &self.recipient_address_hash,
            "delayed release recipient address hash",
        )?;
        ensure_non_empty(&self.asset_id, "delayed release asset id")?;
        ensure_non_empty(&self.lane_id, "delayed release lane id")?;
        if self.amount_units == 0 {
            return Err("delayed release amount must be positive".to_string());
        }
        if self.eligible_at_height < self.requested_at_height {
            return Err("delayed release eligibility cannot predate request".to_string());
        }
        if self.expires_at_height <= self.eligible_at_height {
            return Err("delayed release expiry must follow eligibility".to_string());
        }
        if self.status == WithdrawalReleaseStatus::Cohorted && self.cohort_id.is_none() {
            return Err("cohorted delayed release requires cohort id".to_string());
        }
        if !self.verify_id() {
            return Err("delayed release queue id mismatch".to_string());
        }
        Ok(self.queue_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReleaseCohort {
    pub cohort_id: String,
    pub cohort_index: u64,
    pub lane_id: String,
    pub asset_id: String,
    pub queue_item_ids: Vec<String>,
    pub queue_root: String,
    pub sponsorship_root: String,
    pub watchtower_attestation_root: String,
    pub signer_rotation_id: Option<String>,
    pub total_amount_units: u64,
    pub scheduled_at_height: u64,
    pub release_after_height: u64,
    pub released_at_height: u64,
    pub release_txid_hash: String,
    pub status: WithdrawalCohortStatus,
}

impl WithdrawalReleaseCohort {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cohort_index: u64,
        lane_id: impl Into<String>,
        asset_id: impl Into<String>,
        queue_item_ids: &[String],
        queue_root: impl Into<String>,
        sponsorship_root: impl Into<String>,
        watchtower_attestation_root: impl Into<String>,
        signer_rotation_id: Option<String>,
        total_amount_units: u64,
        scheduled_at_height: u64,
        release_after_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let mut cohort = Self {
            cohort_id: String::new(),
            cohort_index,
            lane_id: lane_id.into(),
            asset_id: asset_id.into(),
            queue_item_ids: ordered_strings(queue_item_ids),
            queue_root: queue_root.into(),
            sponsorship_root: sponsorship_root.into(),
            watchtower_attestation_root: watchtower_attestation_root.into(),
            signer_rotation_id,
            total_amount_units,
            scheduled_at_height,
            release_after_height,
            released_at_height: 0,
            release_txid_hash: String::new(),
            status: WithdrawalCohortStatus::Scheduled,
        };
        cohort.cohort_id = bridge_withdrawal_release_cohort_id(&cohort.identity_record());
        cohort.validate()?;
        Ok(cohort)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_release_cohort_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "cohort_index": self.cohort_index,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "queue_root": self.queue_root,
            "total_amount_units": self.total_amount_units,
            "scheduled_at_height": self.scheduled_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_release_cohort",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "cohort_id": self.cohort_id,
            "cohort_index": self.cohort_index,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "queue_item_ids": self.queue_item_ids,
            "queue_item_count": self.queue_item_ids.len() as u64,
            "queue_root": self.queue_root,
            "sponsorship_root": self.sponsorship_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "signer_rotation_id": self.signer_rotation_id,
            "total_amount_units": self.total_amount_units,
            "scheduled_at_height": self.scheduled_at_height,
            "release_after_height": self.release_after_height,
            "released_at_height": self.released_at_height,
            "release_txid_hash": self.release_txid_hash,
            "status": self.status.as_str(),
        })
    }

    pub fn cohort_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-WITHDRAWAL-COHORT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "cohort_root",
            self.cohort_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.cohort_id == bridge_withdrawal_release_cohort_id(&self.identity_record())
    }

    pub fn mark_releasing(&self, height: u64) -> BridgeFinalityResult<Self> {
        if height < self.release_after_height {
            return Err("release cohort delay has not elapsed".to_string());
        }
        let cohort = Self {
            status: WithdrawalCohortStatus::Releasing,
            ..self.clone()
        };
        cohort.validate()?;
        Ok(cohort)
    }

    pub fn mark_released(
        &self,
        release_txid_hash: impl Into<String>,
        released_at_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let cohort = Self {
            release_txid_hash: release_txid_hash.into(),
            released_at_height,
            status: WithdrawalCohortStatus::Released,
            ..self.clone()
        };
        cohort.validate()?;
        Ok(cohort)
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.lane_id, "release cohort lane id")?;
        ensure_non_empty(&self.asset_id, "release cohort asset id")?;
        ensure_non_empty(&self.queue_root, "release cohort queue root")?;
        ensure_non_empty(&self.sponsorship_root, "release cohort sponsorship root")?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "release cohort watchtower root",
        )?;
        if self.queue_item_ids.is_empty() {
            return Err("release cohort requires queue items".to_string());
        }
        if self.total_amount_units == 0 {
            return Err("release cohort amount must be positive".to_string());
        }
        if self.release_after_height < self.scheduled_at_height {
            return Err("release cohort release height cannot predate schedule".to_string());
        }
        if self.status == WithdrawalCohortStatus::Released {
            ensure_non_empty(&self.release_txid_hash, "release cohort txid hash")?;
            if self.released_at_height < self.release_after_height {
                return Err("release cohort released before delay elapsed".to_string());
            }
        }
        if !self.verify_id() {
            return Err("release cohort id mismatch".to_string());
        }
        Ok(self.cohort_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgInsuranceTranche {
    pub tranche_id: String,
    pub reserve_checkpoint_id: String,
    pub provider_commitment: String,
    pub asset_id: String,
    pub coverage_units: u64,
    pub locked_units: u64,
    pub paid_units: u64,
    pub deductible_bps: u64,
    pub priority: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
    pub status: InsuranceTrancheStatus,
}

impl ReorgInsuranceTranche {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reserve_checkpoint_id: impl Into<String>,
        provider_label: impl Into<String>,
        asset_id: impl Into<String>,
        coverage_units: u64,
        deductible_bps: u64,
        priority: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        evidence: &Value,
    ) -> BridgeFinalityResult<Self> {
        let provider_label = provider_label.into();
        let evidence_root =
            bridge_finality_payload_root("BRIDGE-FINALITY-INSURANCE-EVIDENCE", evidence);
        let mut tranche = Self {
            tranche_id: String::new(),
            reserve_checkpoint_id: reserve_checkpoint_id.into(),
            provider_commitment: bridge_finality_string_root(
                "BRIDGE-FINALITY-INSURANCE-PROVIDER",
                &provider_label,
            ),
            asset_id: asset_id.into(),
            coverage_units,
            locked_units: 0,
            paid_units: 0,
            deductible_bps,
            priority,
            activated_at_height,
            expires_at_height,
            evidence_root,
            status: InsuranceTrancheStatus::Active,
        };
        tranche.tranche_id = bridge_reorg_insurance_tranche_id(&tranche.identity_record());
        tranche.validate()?;
        Ok(tranche)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_reorg_insurance_tranche_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "reserve_checkpoint_id": self.reserve_checkpoint_id,
            "provider_commitment": self.provider_commitment,
            "asset_id": self.asset_id,
            "coverage_units": self.coverage_units,
            "deductible_bps": self.deductible_bps,
            "priority": self.priority,
            "activated_at_height": self.activated_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_reorg_insurance_tranche",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "tranche_id": self.tranche_id,
            "reserve_checkpoint_id": self.reserve_checkpoint_id,
            "provider_commitment": self.provider_commitment,
            "asset_id": self.asset_id,
            "coverage_units": self.coverage_units,
            "locked_units": self.locked_units,
            "paid_units": self.paid_units,
            "available_units": self.available_units(),
            "deductible_bps": self.deductible_bps,
            "priority": self.priority,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
        })
    }

    pub fn tranche_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-REORG-INSURANCE-TRANCHE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "tranche_root",
            self.tranche_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.tranche_id == bridge_reorg_insurance_tranche_id(&self.identity_record())
    }

    pub fn available_units(&self) -> u64 {
        self.coverage_units
            .saturating_sub(self.locked_units)
            .saturating_sub(self.paid_units)
    }

    pub fn lock_claim(&self, amount_units: u64) -> BridgeFinalityResult<Self> {
        if amount_units > self.available_units() {
            return Err("insurance tranche cannot lock more than available coverage".to_string());
        }
        let tranche = Self {
            locked_units: self.locked_units.saturating_add(amount_units),
            status: InsuranceTrancheStatus::Locked,
            ..self.clone()
        };
        tranche.validate()?;
        Ok(tranche)
    }

    pub fn pay_claim(&self, amount_units: u64) -> BridgeFinalityResult<Self> {
        if amount_units > self.locked_units.saturating_add(self.available_units()) {
            return Err("insurance tranche cannot pay more than covered amount".to_string());
        }
        let paid_units = self.paid_units.saturating_add(amount_units);
        let locked_units = self.locked_units.saturating_sub(amount_units);
        let status = if paid_units >= self.coverage_units {
            InsuranceTrancheStatus::Depleted
        } else {
            InsuranceTrancheStatus::Paying
        };
        let tranche = Self {
            locked_units,
            paid_units,
            status,
            ..self.clone()
        };
        tranche.validate()?;
        Ok(tranche)
    }

    pub fn refresh(&mut self, height: u64) {
        if matches!(
            self.status,
            InsuranceTrancheStatus::Retired | InsuranceTrancheStatus::Depleted
        ) {
            return;
        }
        if height > self.expires_at_height {
            self.status = InsuranceTrancheStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(
            &self.reserve_checkpoint_id,
            "insurance tranche reserve checkpoint id",
        )?;
        ensure_non_empty(&self.provider_commitment, "insurance provider commitment")?;
        ensure_non_empty(&self.asset_id, "insurance tranche asset id")?;
        ensure_non_empty(&self.evidence_root, "insurance tranche evidence root")?;
        ensure_bps(self.deductible_bps, "insurance tranche deductible bps")?;
        if self.coverage_units == 0 {
            return Err("insurance tranche coverage must be positive".to_string());
        }
        if self.paid_units.saturating_add(self.locked_units) > self.coverage_units {
            return Err("insurance tranche locked and paid units exceed coverage".to_string());
        }
        if self.expires_at_height <= self.activated_at_height {
            return Err("insurance tranche expiry must follow activation".to_string());
        }
        if !self.verify_id() {
            return Err("insurance tranche id mismatch".to_string());
        }
        Ok(self.tranche_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumResistantSignerRotation {
    pub rotation_id: String,
    pub signer_set_id: String,
    pub previous_signer_root: String,
    pub next_signer_root: String,
    pub ml_dsa_public_key_root: String,
    pub slh_dsa_public_key_root: String,
    pub kem_public_key_root: String,
    pub proof_of_possession_root: String,
    pub authorization_root: String,
    pub requested_at_height: u64,
    pub activate_at_height: u64,
    pub grace_ends_at_height: u64,
    pub expires_at_height: u64,
    pub status: SignerRotationStatus,
}

impl QuantumResistantSignerRotation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_set_id: impl Into<String>,
        previous_signer_root: impl Into<String>,
        next_signer_root: impl Into<String>,
        ml_dsa_public_key_root: impl Into<String>,
        slh_dsa_public_key_root: impl Into<String>,
        kem_public_key_root: impl Into<String>,
        proof_of_possession_root: impl Into<String>,
        authorization_root: impl Into<String>,
        requested_at_height: u64,
        activate_at_height: u64,
        grace_blocks: u64,
        expires_at_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let mut rotation = Self {
            rotation_id: String::new(),
            signer_set_id: signer_set_id.into(),
            previous_signer_root: previous_signer_root.into(),
            next_signer_root: next_signer_root.into(),
            ml_dsa_public_key_root: ml_dsa_public_key_root.into(),
            slh_dsa_public_key_root: slh_dsa_public_key_root.into(),
            kem_public_key_root: kem_public_key_root.into(),
            proof_of_possession_root: proof_of_possession_root.into(),
            authorization_root: authorization_root.into(),
            requested_at_height,
            activate_at_height,
            grace_ends_at_height: activate_at_height.saturating_add(grace_blocks),
            expires_at_height,
            status: SignerRotationStatus::Proposed,
        };
        rotation.rotation_id = bridge_quantum_signer_rotation_id(&rotation.identity_record());
        rotation.validate()?;
        Ok(rotation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_quantum_signer_rotation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "signer_set_id": self.signer_set_id,
            "previous_signer_root": self.previous_signer_root,
            "next_signer_root": self.next_signer_root,
            "requested_at_height": self.requested_at_height,
            "activate_at_height": self.activate_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_quantum_resistant_signer_rotation",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "signer_set_id": self.signer_set_id,
            "previous_signer_root": self.previous_signer_root,
            "next_signer_root": self.next_signer_root,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "kem_public_key_root": self.kem_public_key_root,
            "proof_of_possession_root": self.proof_of_possession_root,
            "authorization_root": self.authorization_root,
            "requested_at_height": self.requested_at_height,
            "activate_at_height": self.activate_at_height,
            "grace_ends_at_height": self.grace_ends_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn rotation_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-QUANTUM-SIGNER-ROTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "rotation_root",
            self.rotation_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.rotation_id == bridge_quantum_signer_rotation_id(&self.identity_record())
    }

    pub fn refresh(&mut self, height: u64) {
        if matches!(
            self.status,
            SignerRotationStatus::Revoked | SignerRotationStatus::Retired
        ) {
            return;
        }
        self.status = if height < self.activate_at_height {
            SignerRotationStatus::Proposed
        } else if height <= self.grace_ends_at_height {
            SignerRotationStatus::Active
        } else if height <= self.expires_at_height {
            SignerRotationStatus::Grace
        } else {
            SignerRotationStatus::Expired
        };
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.signer_set_id, "signer rotation signer set id")?;
        ensure_non_empty(
            &self.previous_signer_root,
            "signer rotation previous signer root",
        )?;
        ensure_non_empty(&self.next_signer_root, "signer rotation next signer root")?;
        ensure_non_empty(&self.ml_dsa_public_key_root, "signer rotation ML-DSA root")?;
        ensure_non_empty(
            &self.slh_dsa_public_key_root,
            "signer rotation SLH-DSA root",
        )?;
        ensure_non_empty(&self.kem_public_key_root, "signer rotation KEM root")?;
        ensure_non_empty(
            &self.proof_of_possession_root,
            "signer rotation proof of possession root",
        )?;
        ensure_non_empty(
            &self.authorization_root,
            "signer rotation authorization root",
        )?;
        if self.activate_at_height < self.requested_at_height {
            return Err("signer rotation activation cannot predate request".to_string());
        }
        if self.grace_ends_at_height < self.activate_at_height {
            return Err("signer rotation grace cannot predate activation".to_string());
        }
        if self.expires_at_height <= self.grace_ends_at_height {
            return Err("signer rotation expiry must follow grace".to_string());
        }
        if !self.verify_id() {
            return Err("signer rotation id mismatch".to_string());
        }
        Ok(self.rotation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseEvidence {
    pub evidence_id: String,
    pub action: EmergencyPauseAction,
    pub scope: String,
    pub reason_code: String,
    pub evidence_root: String,
    pub quorum_root: String,
    pub watchtower_attestation_root: String,
    pub requested_by: String,
    pub requested_at_height: u64,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub status: EmergencyEvidenceStatus,
}

impl EmergencyPauseEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action: EmergencyPauseAction,
        scope: impl Into<String>,
        reason_code: impl Into<String>,
        evidence: &Value,
        quorum_labels: &[String],
        watchtower_attestation_root: impl Into<String>,
        requested_by: impl Into<String>,
        requested_at_height: u64,
        effective_at_height: u64,
        expires_at_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let quorum_root = bridge_finality_string_set_root(
            "BRIDGE-FINALITY-EMERGENCY-QUORUM",
            &ordered_strings(quorum_labels),
        );
        let mut evidence = Self {
            evidence_id: String::new(),
            action,
            scope: scope.into(),
            reason_code: reason_code.into(),
            evidence_root: bridge_finality_payload_root(
                "BRIDGE-FINALITY-EMERGENCY-EVIDENCE",
                evidence,
            ),
            quorum_root,
            watchtower_attestation_root: watchtower_attestation_root.into(),
            requested_by: requested_by.into(),
            requested_at_height,
            effective_at_height,
            expires_at_height,
            status: EmergencyEvidenceStatus::Pending,
        };
        evidence.evidence_id = bridge_emergency_pause_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_emergency_pause_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "action": self.action.as_str(),
            "scope": self.scope,
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "requested_at_height": self.requested_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_emergency_pause_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "action": self.action.as_str(),
            "scope": self.scope,
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "quorum_root": self.quorum_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "requested_by": self.requested_by,
            "requested_at_height": self.requested_at_height,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn pause_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-EMERGENCY-PAUSE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "pause_evidence_root",
            self.pause_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.evidence_id == bridge_emergency_pause_evidence_id(&self.identity_record())
    }

    pub fn is_effective_at(&self, height: u64) -> bool {
        self.status == EmergencyEvidenceStatus::Active
            && height >= self.effective_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn refresh(&mut self, height: u64) {
        if matches!(
            self.status,
            EmergencyEvidenceStatus::Superseded | EmergencyEvidenceStatus::Rejected
        ) {
            return;
        }
        self.status = if self.expires_at_height != 0 && height > self.expires_at_height {
            EmergencyEvidenceStatus::Expired
        } else if height >= self.effective_at_height {
            EmergencyEvidenceStatus::Active
        } else {
            EmergencyEvidenceStatus::Pending
        };
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.scope, "emergency pause scope")?;
        ensure_non_empty(&self.reason_code, "emergency pause reason code")?;
        ensure_non_empty(&self.evidence_root, "emergency pause evidence root")?;
        ensure_non_empty(&self.quorum_root, "emergency pause quorum root")?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "emergency pause watchtower root",
        )?;
        ensure_non_empty(&self.requested_by, "emergency pause requester")?;
        if self.effective_at_height < self.requested_at_height {
            return Err("emergency pause effective height cannot predate request".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height < self.effective_at_height {
            return Err("emergency pause expiry cannot predate effect".to_string());
        }
        if !self.verify_id() {
            return Err("emergency pause evidence id mismatch".to_string());
        }
        Ok(self.pause_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveReconciliationCheckpoint {
    pub checkpoint_id: String,
    pub sequence: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub reserve_view_root: String,
    pub deposit_certificate_root: String,
    pub withdrawal_queue_root: String,
    pub release_cohort_root: String,
    pub insurance_root: String,
    pub sponsorship_root: String,
    pub observed_reserve_units: u64,
    pub minted_liability_units: u64,
    pub pending_withdrawal_units: u64,
    pub released_unfinalized_units: u64,
    pub sponsored_fee_liability_units: u64,
    pub insurance_coverage_units: u64,
    pub surplus_units: u64,
    pub shortfall_units: u64,
    pub coverage_bps: u64,
    pub recorded_at_height: u64,
    pub status: ReserveReconciliationStatus,
}

impl ReserveReconciliationCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        monero_network: impl Into<String>,
        asset_id: impl Into<String>,
        reserve_view_root: impl Into<String>,
        deposit_certificate_root: impl Into<String>,
        withdrawal_queue_root: impl Into<String>,
        release_cohort_root: impl Into<String>,
        insurance_root: impl Into<String>,
        sponsorship_root: impl Into<String>,
        observed_reserve_units: u64,
        minted_liability_units: u64,
        pending_withdrawal_units: u64,
        released_unfinalized_units: u64,
        sponsored_fee_liability_units: u64,
        insurance_coverage_units: u64,
        recorded_at_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let liability_units = minted_liability_units
            .saturating_add(pending_withdrawal_units)
            .saturating_add(released_unfinalized_units)
            .saturating_add(sponsored_fee_liability_units);
        let insured_reserve_units = observed_reserve_units.saturating_add(insurance_coverage_units);
        let surplus_units = observed_reserve_units.saturating_sub(liability_units);
        let shortfall_units = liability_units.saturating_sub(observed_reserve_units);
        let coverage_bps = coverage_bps(insured_reserve_units, liability_units);
        let status = if shortfall_units == 0 && surplus_units == 0 {
            ReserveReconciliationStatus::Balanced
        } else if shortfall_units == 0 {
            ReserveReconciliationStatus::Surplus
        } else if insured_reserve_units >= liability_units {
            ReserveReconciliationStatus::InsuredShortfall
        } else {
            ReserveReconciliationStatus::Shortfall
        };
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            sequence,
            monero_network: monero_network.into(),
            asset_id: asset_id.into(),
            reserve_view_root: reserve_view_root.into(),
            deposit_certificate_root: deposit_certificate_root.into(),
            withdrawal_queue_root: withdrawal_queue_root.into(),
            release_cohort_root: release_cohort_root.into(),
            insurance_root: insurance_root.into(),
            sponsorship_root: sponsorship_root.into(),
            observed_reserve_units,
            minted_liability_units,
            pending_withdrawal_units,
            released_unfinalized_units,
            sponsored_fee_liability_units,
            insurance_coverage_units,
            surplus_units,
            shortfall_units,
            coverage_bps,
            recorded_at_height,
            status,
        };
        checkpoint.checkpoint_id =
            bridge_reserve_reconciliation_checkpoint_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn liability_units(&self) -> u64 {
        self.minted_liability_units
            .saturating_add(self.pending_withdrawal_units)
            .saturating_add(self.released_unfinalized_units)
            .saturating_add(self.sponsored_fee_liability_units)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_reserve_reconciliation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "reserve_view_root": self.reserve_view_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_reserve_reconciliation_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "reserve_view_root": self.reserve_view_root,
            "deposit_certificate_root": self.deposit_certificate_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "release_cohort_root": self.release_cohort_root,
            "insurance_root": self.insurance_root,
            "sponsorship_root": self.sponsorship_root,
            "observed_reserve_units": self.observed_reserve_units,
            "minted_liability_units": self.minted_liability_units,
            "pending_withdrawal_units": self.pending_withdrawal_units,
            "released_unfinalized_units": self.released_unfinalized_units,
            "sponsored_fee_liability_units": self.sponsored_fee_liability_units,
            "insurance_coverage_units": self.insurance_coverage_units,
            "liability_units": self.liability_units(),
            "surplus_units": self.surplus_units,
            "shortfall_units": self.shortfall_units,
            "coverage_bps": self.coverage_bps,
            "recorded_at_height": self.recorded_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn checkpoint_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-RESERVE-RECONCILIATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "checkpoint_root",
            self.checkpoint_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.checkpoint_id == bridge_reserve_reconciliation_checkpoint_id(&self.identity_record())
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.monero_network, "reserve checkpoint Monero network")?;
        ensure_non_empty(&self.asset_id, "reserve checkpoint asset id")?;
        ensure_non_empty(
            &self.reserve_view_root,
            "reserve checkpoint reserve view root",
        )?;
        ensure_non_empty(
            &self.deposit_certificate_root,
            "reserve checkpoint deposit root",
        )?;
        ensure_non_empty(
            &self.withdrawal_queue_root,
            "reserve checkpoint withdrawal queue root",
        )?;
        ensure_non_empty(&self.release_cohort_root, "reserve checkpoint cohort root")?;
        ensure_non_empty(&self.insurance_root, "reserve checkpoint insurance root")?;
        ensure_non_empty(
            &self.sponsorship_root,
            "reserve checkpoint sponsorship root",
        )?;
        let expected_shortfall = self
            .liability_units()
            .saturating_sub(self.observed_reserve_units);
        let expected_surplus = self
            .observed_reserve_units
            .saturating_sub(self.liability_units());
        if self.shortfall_units != expected_shortfall {
            return Err("reserve checkpoint shortfall mismatch".to_string());
        }
        if self.surplus_units != expected_surplus {
            return Err("reserve checkpoint surplus mismatch".to_string());
        }
        if self.coverage_bps
            != coverage_bps(
                self.observed_reserve_units
                    .saturating_add(self.insurance_coverage_units),
                self.liability_units(),
            )
        {
            return Err("reserve checkpoint coverage bps mismatch".to_string());
        }
        if !self.verify_id() {
            return Err("reserve checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFinalityLowFeeWithdrawalSponsorship {
    pub sponsorship_id: String,
    pub withdrawal_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub settled_fee_units: u64,
    pub sponsor_budget_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub applied_at_height: u64,
    pub status: SponsorshipStatus,
}

impl BridgeFinalityLowFeeWithdrawalSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        sponsor_label: impl Into<String>,
        fee_asset_id: impl Into<String>,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        sponsor_budget_root: impl Into<String>,
        reserved_at_height: u64,
        expires_at_height: u64,
    ) -> BridgeFinalityResult<Self> {
        let sponsor_label = sponsor_label.into();
        let settled_fee_units = gross_fee_units.saturating_sub(sponsored_fee_units);
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            sponsor_commitment: bridge_finality_string_root(
                "BRIDGE-FINALITY-LOW-FEE-SPONSOR",
                &sponsor_label,
            ),
            fee_asset_id: fee_asset_id.into(),
            gross_fee_units,
            sponsored_fee_units,
            settled_fee_units,
            sponsor_budget_root: sponsor_budget_root.into(),
            reserved_at_height,
            expires_at_height,
            applied_at_height: 0,
            status: SponsorshipStatus::Reserved,
        };
        sponsorship.sponsorship_id =
            bridge_low_fee_withdrawal_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_low_fee_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "reserved_at_height": self.reserved_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_low_fee_withdrawal_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "withdrawal_id": self.withdrawal_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "settled_fee_units": self.settled_fee_units,
            "sponsor_budget_root": self.sponsor_budget_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "applied_at_height": self.applied_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        bridge_finality_payload_root(
            "BRIDGE-FINALITY-LOW-FEE-WITHDRAWAL-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.sponsorship_id == bridge_low_fee_withdrawal_sponsorship_id(&self.identity_record())
    }

    pub fn apply_at(&self, height: u64) -> BridgeFinalityResult<Self> {
        if height > self.expires_at_height {
            return Err("cannot apply expired low-fee sponsorship".to_string());
        }
        let sponsorship = Self {
            applied_at_height: height,
            status: SponsorshipStatus::Applied,
            ..self.clone()
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status == SponsorshipStatus::Reserved && height > self.expires_at_height {
            self.status = SponsorshipStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        ensure_non_empty(&self.withdrawal_id, "low-fee sponsorship withdrawal id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "low-fee sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "low-fee sponsorship fee asset id")?;
        ensure_non_empty(&self.sponsor_budget_root, "low-fee sponsorship budget root")?;
        if self.sponsored_fee_units > self.gross_fee_units {
            return Err("low-fee sponsorship exceeds gross fee".to_string());
        }
        if self.settled_fee_units
            != self
                .gross_fee_units
                .saturating_sub(self.sponsored_fee_units)
        {
            return Err("low-fee sponsorship settled fee mismatch".to_string());
        }
        if self.expires_at_height < self.reserved_at_height {
            return Err("low-fee sponsorship expires before reservation".to_string());
        }
        if self.status == SponsorshipStatus::Applied
            && (self.applied_at_height < self.reserved_at_height
                || self.applied_at_height > self.expires_at_height)
        {
            return Err("low-fee sponsorship applied outside reservation window".to_string());
        }
        if !self.verify_id() {
            return Err("low-fee sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFinalityRoots {
    pub parameters_root: String,
    pub deposit_certificate_root: String,
    pub delayed_release_root: String,
    pub release_cohort_root: String,
    pub insurance_tranche_root: String,
    pub signer_rotation_root: String,
    pub emergency_evidence_root: String,
    pub reserve_checkpoint_root: String,
    pub sponsorship_root: String,
    pub watchtower_attestation_root: String,
    pub paused_scope_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl BridgeFinalityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_finality_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "parameters_root": self.parameters_root,
            "deposit_certificate_root": self.deposit_certificate_root,
            "delayed_release_root": self.delayed_release_root,
            "release_cohort_root": self.release_cohort_root,
            "insurance_tranche_root": self.insurance_tranche_root,
            "signer_rotation_root": self.signer_rotation_root,
            "emergency_evidence_root": self.emergency_evidence_root,
            "reserve_checkpoint_root": self.reserve_checkpoint_root,
            "sponsorship_root": self.sponsorship_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "paused_scope_root": self.paused_scope_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn roots_root(&self) -> String {
        bridge_finality_payload_root("BRIDGE-FINALITY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFinalityState {
    pub network: String,
    pub asset_id: String,
    pub operator_label: String,
    pub height: u64,
    pub parameters: BridgeFinalityParameters,
    pub paused_scopes: BTreeSet<String>,
    pub deposit_certificates: BTreeMap<String, DepositFinalityCertificate>,
    pub delayed_releases: BTreeMap<String, DelayedReleaseQueueItem>,
    pub release_cohorts: BTreeMap<String, WithdrawalReleaseCohort>,
    pub insurance_tranches: BTreeMap<String, ReorgInsuranceTranche>,
    pub signer_rotations: BTreeMap<String, QuantumResistantSignerRotation>,
    pub emergency_evidence: BTreeMap<String, EmergencyPauseEvidence>,
    pub reserve_checkpoints: BTreeMap<String, ReserveReconciliationCheckpoint>,
    pub sponsorships: BTreeMap<String, BridgeFinalityLowFeeWithdrawalSponsorship>,
    pub watchtower_attestations: BTreeMap<String, BridgeWatchtowerAttestation>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for BridgeFinalityState {
    fn default() -> Self {
        Self {
            network: BRIDGE_FINALITY_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: BRIDGE_FINALITY_DEVNET_ASSET_ID.to_string(),
            operator_label: "bridge-finality".to_string(),
            height: 0,
            parameters: BridgeFinalityParameters::default(),
            paused_scopes: BTreeSet::new(),
            deposit_certificates: BTreeMap::new(),
            delayed_releases: BTreeMap::new(),
            release_cohorts: BTreeMap::new(),
            insurance_tranches: BTreeMap::new(),
            signer_rotations: BTreeMap::new(),
            emergency_evidence: BTreeMap::new(),
            reserve_checkpoints: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            watchtower_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl BridgeFinalityState {
    pub fn new(
        operator_label: impl Into<String>,
        network: impl Into<String>,
        asset_id: impl Into<String>,
        parameters: BridgeFinalityParameters,
    ) -> BridgeFinalityResult<Self> {
        parameters.validate()?;
        let operator_label = operator_label.into();
        let network = network.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&operator_label, "bridge finality operator label")?;
        ensure_non_empty(&network, "bridge finality network")?;
        ensure_non_empty(&asset_id, "bridge finality asset id")?;
        Ok(Self {
            operator_label,
            network,
            asset_id,
            parameters,
            ..Self::default()
        })
    }

    pub fn devnet(operator_label: &str) -> BridgeFinalityResult<Self> {
        let operator_label = if operator_label.is_empty() {
            "devnet-bridge-finality"
        } else {
            operator_label
        };
        let mut state = Self::new(
            operator_label,
            BRIDGE_FINALITY_DEVNET_MONERO_NETWORK,
            BRIDGE_FINALITY_DEVNET_ASSET_ID,
            BridgeFinalityParameters::default(),
        )?;
        state.set_height(12)?;

        let previous_signer_root = bridge_finality_string_set_root(
            "BRIDGE-FINALITY-DEVNET-PREVIOUS-SIGNERS",
            &[
                "devnet-bridge-signer-a".to_string(),
                "devnet-bridge-signer-b".to_string(),
            ],
        );
        let next_signer_root = bridge_finality_string_set_root(
            "BRIDGE-FINALITY-DEVNET-NEXT-SIGNERS",
            &[
                "devnet-bridge-signer-c".to_string(),
                "devnet-bridge-signer-d".to_string(),
            ],
        );
        let rotation = QuantumResistantSignerRotation::new(
            "devnet-bridge-signers",
            &previous_signer_root,
            &next_signer_root,
            &bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-ML-DSA", "devnet-ml-dsa"),
            &bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-SLH-DSA", "devnet-slh-dsa"),
            &bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-KEM", "devnet-kem"),
            &bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-POP", "devnet-pop"),
            &bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-AUTH", "devnet-auth"),
            10,
            12,
            state.parameters.signer_rotation_grace_blocks,
            240,
        )?;
        let rotation_id = rotation.rotation_id.clone();
        state.apply_signer_rotation(rotation)?;

        let deposit_subject_root = bridge_finality_payload_root(
            "BRIDGE-FINALITY-DEVNET-DEPOSIT-SUBJECT",
            &json!({
                "deposit_id": "devnet-deposit-0",
                "txid_hash": "devnet-monero-deposit-txid-0",
                "amount_units": 100_000_u64,
            }),
        );
        let mut attestation_ids = Vec::new();
        for label in ["devnet-watchtower-a", "devnet-watchtower-b"] {
            let attestation = BridgeWatchtowerAttestation::new(
                label,
                bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-WATCHTOWER-KEY", label),
                WatchtowerSignalKind::DepositFinal,
                "deposit",
                "devnet-deposit-0",
                &deposit_subject_root,
                11,
                12,
                72,
                Some(rotation_id.clone()),
            )?;
            attestation_ids.push(attestation.attestation_id.clone());
            state.apply_watchtower_attestation(attestation)?;
        }
        let deposit_attestation_root = state.attestation_subset_root(&attestation_ids);
        let certificate = DepositFinalityCertificate::new(
            "devnet-deposit-0",
            &state.network,
            "devnet-monero-deposit-txid-0",
            64,
            "devnet-monero-block-hash-64",
            "devnet-output-commitment-0",
            "devnet-account-commitment-0",
            &state.asset_id,
            100_000,
            2,
            state.parameters.monero_finality_depth,
            state.parameters.monero_finality_depth,
            bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-OUTPUT-PROOF", "deposit-0"),
            deposit_attestation_root,
            None,
            &[
                "devnet-watchtower-a".to_string(),
                "devnet-watchtower-b".to_string(),
            ],
        )?;
        let certificate_id = certificate.certificate_id.clone();
        state.apply_deposit_certificate(certificate)?;

        let sponsorship = BridgeFinalityLowFeeWithdrawalSponsorship::new(
            "devnet-withdrawal-0",
            "devnet-fee-sponsor",
            &state.asset_id,
            2_500,
            1_500,
            bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-SPONSOR-BUDGET", "budget-0"),
            state.height,
            state
                .height
                .saturating_add(state.parameters.sponsorship_ttl_blocks),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.apply_sponsorship(sponsorship)?;

        let queue_item = DelayedReleaseQueueItem::new(
            "devnet-withdrawal-0",
            "devnet-account-commitment-0",
            "devnet-recipient-address-hash-0",
            &state.asset_id,
            75_000,
            "devnet-hot-release-lane",
            10,
            state.height,
            state.parameters.release_delay_blocks,
            state.parameters.release_ttl_blocks,
            Some(certificate_id),
            2_500,
        )?
        .with_sponsorship(sponsorship_id)?;
        state.enqueue_delayed_release(queue_item)?;

        let pause = EmergencyPauseEvidence::new(
            EmergencyPauseAction::Pause,
            "withdrawals",
            "devnet-reconciliation-drill",
            &json!({"kind": "devnet_pause_drill", "drill": true}),
            &[
                "devnet-watchtower-a".to_string(),
                "devnet-watchtower-b".to_string(),
            ],
            state.watchtower_attestation_root(),
            operator_label,
            13,
            13,
            15,
        )?;
        state.apply_emergency_evidence(pause)?;
        let unpause = EmergencyPauseEvidence::new(
            EmergencyPauseAction::Unpause,
            "withdrawals",
            "devnet-reconciliation-clear",
            &json!({"kind": "devnet_unpause_drill", "clear": true}),
            &[
                "devnet-watchtower-a".to_string(),
                "devnet-watchtower-b".to_string(),
            ],
            state.watchtower_attestation_root(),
            operator_label,
            16,
            16,
            0,
        )?;
        state.apply_emergency_evidence(unpause)?;

        state.set_height(16)?;
        let cohort = state.form_release_cohort("devnet-hot-release-lane", Some(&rotation_id))?;
        state.release_cohort(&cohort.cohort_id, "devnet-release-txid-0", 20)?;

        let checkpoint = state.record_reserve_reconciliation(
            1,
            bridge_finality_string_root("BRIDGE-FINALITY-DEVNET-RESERVE-VIEW", "reserve-view-0"),
            1_250_000,
            100_000,
            75_000,
            75_000,
            1_500,
            250_000,
        )?;
        let tranche = ReorgInsuranceTranche::new(
            &checkpoint.checkpoint_id,
            "devnet-insurance-provider",
            &state.asset_id,
            250_000,
            500,
            1,
            16,
            240,
            &json!({"kind": "devnet_reorg_insurance", "coverage": "first-loss"}),
        )?;
        state.apply_insurance_tranche(tranche)?;
        state.set_height(20)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> BridgeFinalityResult<String> {
        self.height = height;
        for attestation in self.watchtower_attestations.values_mut() {
            attestation.refresh(height);
        }
        for rotation in self.signer_rotations.values_mut() {
            rotation.refresh(height);
        }
        for evidence in self.emergency_evidence.values_mut() {
            evidence.refresh(height);
        }
        self.refresh_paused_scopes();
        let withdrawals_paused = self.withdrawals_paused();
        for item in self.delayed_releases.values_mut() {
            let lane_paused = withdrawals_paused || self.paused_scopes.contains(&item.lane_id);
            item.refresh(height, lane_paused);
        }
        for cohort in self.release_cohorts.values_mut() {
            if cohort.status == WithdrawalCohortStatus::Scheduled
                && height >= cohort.release_after_height
            {
                cohort.status = WithdrawalCohortStatus::Releasing;
            }
        }
        for tranche in self.insurance_tranches.values_mut() {
            tranche.refresh(height);
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.refresh(height);
        }
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn apply_deposit_certificate(
        &mut self,
        certificate: DepositFinalityCertificate,
    ) -> BridgeFinalityResult<String> {
        let root = certificate.validate()?;
        if certificate.monero_network != self.network {
            return Err("deposit certificate network mismatch".to_string());
        }
        if certificate.asset_id != self.asset_id {
            return Err("deposit certificate asset mismatch".to_string());
        }
        insert_unique_record(
            &mut self.deposit_certificates,
            certificate.certificate_id.clone(),
            certificate.clone(),
            "deposit finality certificate",
        )?;
        self.public_records.insert(
            format!("deposit:{}", certificate.certificate_id),
            certificate.public_record(),
        );
        Ok(root)
    }

    pub fn enqueue_delayed_release(
        &mut self,
        item: DelayedReleaseQueueItem,
    ) -> BridgeFinalityResult<String> {
        let root = item.validate()?;
        if item.asset_id != self.asset_id {
            return Err("delayed release asset mismatch".to_string());
        }
        if self.delayed_releases.len() as u64 >= self.parameters.max_delayed_queue_depth {
            return Err("bridge finality delayed release queue is full".to_string());
        }
        if let Some(certificate_id) = &item.deposit_certificate_id {
            if !self.deposit_certificates.contains_key(certificate_id) {
                return Err("delayed release references unknown deposit certificate".to_string());
            }
        }
        if let Some(sponsorship_id) = &item.sponsorship_id {
            let sponsorship = self
                .sponsorships
                .get(sponsorship_id)
                .ok_or_else(|| "delayed release references unknown sponsorship".to_string())?;
            if sponsorship.withdrawal_id != item.withdrawal_id {
                return Err("delayed release sponsorship withdrawal mismatch".to_string());
            }
        }
        insert_unique_record(
            &mut self.delayed_releases,
            item.queue_id.clone(),
            item.clone(),
            "delayed release queue item",
        )?;
        self.public_records
            .insert(format!("release:{}", item.queue_id), item.public_record());
        Ok(root)
    }

    pub fn apply_release_cohort(
        &mut self,
        cohort: WithdrawalReleaseCohort,
    ) -> BridgeFinalityResult<String> {
        let root = cohort.validate()?;
        if cohort.asset_id != self.asset_id {
            return Err("release cohort asset mismatch".to_string());
        }
        for queue_id in &cohort.queue_item_ids {
            if !self.delayed_releases.contains_key(queue_id) {
                return Err("release cohort references unknown queue item".to_string());
            }
        }
        insert_unique_record(
            &mut self.release_cohorts,
            cohort.cohort_id.clone(),
            cohort.clone(),
            "withdrawal release cohort",
        )?;
        self.public_records.insert(
            format!("cohort:{}", cohort.cohort_id),
            cohort.public_record(),
        );
        Ok(root)
    }

    pub fn apply_insurance_tranche(
        &mut self,
        tranche: ReorgInsuranceTranche,
    ) -> BridgeFinalityResult<String> {
        let root = tranche.validate()?;
        if tranche.asset_id != self.asset_id {
            return Err("insurance tranche asset mismatch".to_string());
        }
        if !self
            .reserve_checkpoints
            .contains_key(&tranche.reserve_checkpoint_id)
        {
            return Err("insurance tranche references unknown reserve checkpoint".to_string());
        }
        insert_unique_record(
            &mut self.insurance_tranches,
            tranche.tranche_id.clone(),
            tranche.clone(),
            "reorg insurance tranche",
        )?;
        self.public_records.insert(
            format!("insurance:{}", tranche.tranche_id),
            tranche.public_record(),
        );
        Ok(root)
    }

    pub fn apply_signer_rotation(
        &mut self,
        rotation: QuantumResistantSignerRotation,
    ) -> BridgeFinalityResult<String> {
        let root = rotation.validate()?;
        insert_unique_record(
            &mut self.signer_rotations,
            rotation.rotation_id.clone(),
            rotation.clone(),
            "quantum-resistant signer rotation",
        )?;
        self.public_records.insert(
            format!("rotation:{}", rotation.rotation_id),
            rotation.public_record(),
        );
        Ok(root)
    }

    pub fn apply_emergency_evidence(
        &mut self,
        mut evidence: EmergencyPauseEvidence,
    ) -> BridgeFinalityResult<String> {
        evidence.refresh(self.height);
        let root = evidence.validate()?;
        insert_unique_record(
            &mut self.emergency_evidence,
            evidence.evidence_id.clone(),
            evidence.clone(),
            "emergency pause evidence",
        )?;
        self.public_records.insert(
            format!("emergency:{}", evidence.evidence_id),
            evidence.public_record(),
        );
        self.refresh_paused_scopes();
        Ok(root)
    }

    pub fn apply_reserve_checkpoint(
        &mut self,
        checkpoint: ReserveReconciliationCheckpoint,
    ) -> BridgeFinalityResult<String> {
        let root = checkpoint.validate()?;
        if checkpoint.monero_network != self.network {
            return Err("reserve checkpoint network mismatch".to_string());
        }
        if checkpoint.asset_id != self.asset_id {
            return Err("reserve checkpoint asset mismatch".to_string());
        }
        insert_unique_record(
            &mut self.reserve_checkpoints,
            checkpoint.checkpoint_id.clone(),
            checkpoint.clone(),
            "reserve reconciliation checkpoint",
        )?;
        self.public_records.insert(
            format!("reserve:{}", checkpoint.checkpoint_id),
            checkpoint.public_record(),
        );
        Ok(root)
    }

    pub fn apply_sponsorship(
        &mut self,
        sponsorship: BridgeFinalityLowFeeWithdrawalSponsorship,
    ) -> BridgeFinalityResult<String> {
        let root = sponsorship.validate()?;
        if sponsorship.fee_asset_id != self.asset_id {
            return Err("low-fee sponsorship asset mismatch".to_string());
        }
        insert_unique_record(
            &mut self.sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship.clone(),
            "low-fee withdrawal sponsorship",
        )?;
        self.public_records.insert(
            format!("sponsorship:{}", sponsorship.sponsorship_id),
            sponsorship.public_record(),
        );
        Ok(root)
    }

    pub fn apply_watchtower_attestation(
        &mut self,
        attestation: BridgeWatchtowerAttestation,
    ) -> BridgeFinalityResult<String> {
        let root = attestation.validate()?;
        if let Some(rotation_id) = &attestation.signer_rotation_id {
            if !self.signer_rotations.contains_key(rotation_id) {
                return Err("watchtower attestation references unknown signer rotation".to_string());
            }
        }
        insert_unique_record(
            &mut self.watchtower_attestations,
            attestation.attestation_id.clone(),
            attestation.clone(),
            "bridge watchtower attestation",
        )?;
        self.public_records.insert(
            format!("watchtower:{}", attestation.attestation_id),
            attestation.public_record(),
        );
        Ok(root)
    }

    pub fn record_watchtower_attestation(
        &mut self,
        watchtower_label: &str,
        signal_kind: WatchtowerSignalKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        ttl_blocks: u64,
    ) -> BridgeFinalityResult<BridgeWatchtowerAttestation> {
        let attestation = BridgeWatchtowerAttestation::new(
            watchtower_label,
            bridge_finality_string_root("BRIDGE-FINALITY-WATCHTOWER-PUBLIC-KEY", watchtower_label),
            signal_kind,
            subject_kind,
            subject_id,
            subject_root,
            self.height,
            self.height,
            self.height.saturating_add(ttl_blocks),
            self.active_signer_rotation_id(),
        )?;
        self.apply_watchtower_attestation(attestation.clone())?;
        Ok(attestation)
    }

    pub fn sponsor_low_fee_withdrawal(
        &mut self,
        withdrawal_id: &str,
        sponsor_label: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        sponsor_budget_root: &str,
    ) -> BridgeFinalityResult<BridgeFinalityLowFeeWithdrawalSponsorship> {
        let sponsorship = BridgeFinalityLowFeeWithdrawalSponsorship::new(
            withdrawal_id,
            sponsor_label,
            &self.asset_id,
            gross_fee_units,
            sponsored_fee_units,
            sponsor_budget_root,
            self.height,
            self.height
                .saturating_add(self.parameters.sponsorship_ttl_blocks),
        )?;
        self.apply_sponsorship(sponsorship.clone())?;
        Ok(sponsorship)
    }

    pub fn record_reserve_reconciliation(
        &mut self,
        sequence: u64,
        reserve_view_root: String,
        observed_reserve_units: u64,
        minted_liability_units: u64,
        pending_withdrawal_units: u64,
        released_unfinalized_units: u64,
        sponsored_fee_liability_units: u64,
        insurance_coverage_units: u64,
    ) -> BridgeFinalityResult<ReserveReconciliationCheckpoint> {
        let checkpoint = ReserveReconciliationCheckpoint::new(
            sequence,
            &self.network,
            &self.asset_id,
            reserve_view_root,
            self.deposit_certificate_root(),
            self.delayed_release_root(),
            self.release_cohort_root(),
            self.insurance_tranche_root(),
            self.sponsorship_root(),
            observed_reserve_units,
            minted_liability_units,
            pending_withdrawal_units,
            released_unfinalized_units,
            sponsored_fee_liability_units,
            insurance_coverage_units,
            self.height,
        )?;
        self.apply_reserve_checkpoint(checkpoint.clone())?;
        Ok(checkpoint)
    }

    pub fn form_release_cohort(
        &mut self,
        lane_id: &str,
        signer_rotation_id: Option<&str>,
    ) -> BridgeFinalityResult<WithdrawalReleaseCohort> {
        if self.withdrawals_paused() || self.paused_scopes.contains(lane_id) {
            return Err("cannot form release cohort while withdrawals are paused".to_string());
        }
        let mut selected = Vec::<DelayedReleaseQueueItem>::new();
        let mut total_amount = 0_u64;
        let max_items = self.parameters.release_cohort_max_items as usize;
        for item in self.delayed_releases.values() {
            if item.lane_id != lane_id || !item.is_ready_at(self.height, false) {
                continue;
            }
            if selected.len() >= max_items {
                break;
            }
            let next_total = total_amount.saturating_add(item.amount_units);
            if next_total > self.parameters.release_cohort_max_units && !selected.is_empty() {
                break;
            }
            total_amount = next_total;
            selected.push(item.clone());
        }
        if selected.is_empty() {
            return Err("no ready delayed releases for cohort".to_string());
        }
        let queue_ids = selected
            .iter()
            .map(|item| item.queue_id.clone())
            .collect::<Vec<_>>();
        let queue_root = bridge_finality_delayed_release_root(&selected);
        let sponsorships = selected
            .iter()
            .filter_map(|item| item.sponsorship_id.as_ref())
            .filter_map(|id| self.sponsorships.get(id))
            .cloned()
            .collect::<Vec<_>>();
        let sponsorship_root = bridge_finality_sponsorship_root(&sponsorships);
        let cohort_index = self.release_cohorts.len() as u64;
        let signer_rotation_id = signer_rotation_id.map(str::to_string);
        if let Some(rotation_id) = &signer_rotation_id {
            if !self.signer_rotations.contains_key(rotation_id) {
                return Err("release cohort references unknown signer rotation".to_string());
            }
        }
        let cohort = WithdrawalReleaseCohort::new(
            cohort_index,
            lane_id,
            &self.asset_id,
            &queue_ids,
            queue_root,
            sponsorship_root,
            self.watchtower_attestation_root(),
            signer_rotation_id,
            total_amount,
            self.height,
            self.height
                .saturating_add(self.parameters.release_delay_blocks),
        )?;
        for queue_id in &queue_ids {
            let item = self
                .delayed_releases
                .get(queue_id)
                .cloned()
                .ok_or_else(|| "release cohort queue item disappeared".to_string())?
                .assign_to_cohort(&cohort.cohort_id)?;
            self.public_records
                .insert(format!("release:{queue_id}"), item.public_record());
            self.delayed_releases.insert(queue_id.clone(), item);
        }
        self.apply_release_cohort(cohort.clone())?;
        Ok(cohort)
    }

    pub fn release_cohort(
        &mut self,
        cohort_id: &str,
        release_txid_hash: &str,
        released_at_height: u64,
    ) -> BridgeFinalityResult<String> {
        let cohort = self
            .release_cohorts
            .get(cohort_id)
            .cloned()
            .ok_or_else(|| "unknown release cohort".to_string())?;
        if self.withdrawals_paused() || self.paused_scopes.contains(&cohort.lane_id) {
            return Err("cannot release cohort while withdrawals are paused".to_string());
        }
        let released = cohort.mark_released(release_txid_hash, released_at_height)?;
        let root = released.cohort_root();
        for queue_id in &released.queue_item_ids {
            let item = self
                .delayed_releases
                .get(queue_id)
                .cloned()
                .ok_or_else(|| "released cohort references unknown queue item".to_string())?
                .mark_released()?;
            if let Some(sponsorship_id) = &item.sponsorship_id {
                if let Some(sponsorship) = self.sponsorships.get(sponsorship_id).cloned() {
                    let sponsorship = sponsorship.apply_at(released_at_height)?;
                    self.public_records.insert(
                        format!("sponsorship:{sponsorship_id}"),
                        sponsorship.public_record(),
                    );
                    self.sponsorships
                        .insert(sponsorship_id.clone(), sponsorship);
                }
            }
            self.public_records
                .insert(format!("release:{queue_id}"), item.public_record());
            self.delayed_releases.insert(queue_id.clone(), item);
        }
        self.public_records
            .insert(format!("cohort:{cohort_id}"), released.public_record());
        self.release_cohorts.insert(cohort_id.to_string(), released);
        Ok(root)
    }

    pub fn active_signer_rotation_id(&self) -> Option<String> {
        self.signer_rotations
            .values()
            .filter(|rotation| {
                matches!(
                    rotation.status,
                    SignerRotationStatus::Active | SignerRotationStatus::Grace
                )
            })
            .max_by_key(|rotation| rotation.activate_at_height)
            .map(|rotation| rotation.rotation_id.clone())
    }

    pub fn withdrawals_paused(&self) -> bool {
        self.paused_scopes.contains("global") || self.paused_scopes.contains("withdrawals")
    }

    pub fn scope_paused(&self, scope: &str) -> bool {
        self.paused_scopes.contains("global") || self.paused_scopes.contains(scope)
    }

    pub fn ready_releases(&self) -> Vec<DelayedReleaseQueueItem> {
        self.delayed_releases
            .values()
            .filter(|item| item.status == WithdrawalReleaseStatus::Ready)
            .cloned()
            .collect()
    }

    pub fn total_certified_deposits(&self) -> u64 {
        self.deposit_certificates
            .values()
            .filter(|certificate| certificate.is_final())
            .fold(0_u64, |total, certificate| {
                total.saturating_add(certificate.amount_units)
            })
    }

    pub fn total_pending_withdrawals(&self) -> u64 {
        self.delayed_releases
            .values()
            .filter(|item| {
                !matches!(
                    item.status,
                    WithdrawalReleaseStatus::Released
                        | WithdrawalReleaseStatus::Cancelled
                        | WithdrawalReleaseStatus::Expired
                )
            })
            .fold(0_u64, |total, item| total.saturating_add(item.amount_units))
    }

    pub fn total_insurance_coverage(&self) -> u64 {
        self.insurance_tranches
            .values()
            .fold(0_u64, |total, tranche| {
                total.saturating_add(tranche.available_units())
            })
    }

    pub fn total_sponsored_fees(&self) -> u64 {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status != SponsorshipStatus::Expired)
            .fold(0_u64, |total, sponsorship| {
                total.saturating_add(sponsorship.sponsored_fee_units)
            })
    }

    pub fn attestation_subset_root(&self, attestation_ids: &[String]) -> String {
        let attestations = ordered_strings(attestation_ids)
            .iter()
            .filter_map(|id| self.watchtower_attestations.get(id))
            .cloned()
            .collect::<Vec<_>>();
        bridge_finality_watchtower_attestation_root(&attestations)
    }

    pub fn parameters_root(&self) -> String {
        self.parameters.parameters_root()
    }

    pub fn deposit_certificate_root(&self) -> String {
        bridge_finality_deposit_certificate_root(
            &self
                .deposit_certificates
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn delayed_release_root(&self) -> String {
        bridge_finality_delayed_release_root(
            &self.delayed_releases.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn release_cohort_root(&self) -> String {
        bridge_finality_release_cohort_root(
            &self.release_cohorts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn insurance_tranche_root(&self) -> String {
        bridge_finality_insurance_tranche_root(
            &self
                .insurance_tranches
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn signer_rotation_root(&self) -> String {
        bridge_finality_signer_rotation_root(
            &self.signer_rotations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn emergency_evidence_root(&self) -> String {
        bridge_finality_emergency_evidence_root(
            &self
                .emergency_evidence
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_checkpoint_root(&self) -> String {
        bridge_finality_reserve_checkpoint_root(
            &self
                .reserve_checkpoints
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        bridge_finality_sponsorship_root(&self.sponsorships.values().cloned().collect::<Vec<_>>())
    }

    pub fn watchtower_attestation_root(&self) -> String {
        bridge_finality_watchtower_attestation_root(
            &self
                .watchtower_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn paused_scope_root(&self) -> String {
        bridge_finality_string_set_root(
            "BRIDGE-FINALITY-PAUSED-SCOPES",
            &self.paused_scopes.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        keyed_value_root(
            "BRIDGE-FINALITY-PUBLIC-RECORDS",
            self.public_records
                .iter()
                .map(|(key, record)| (key.clone(), record.clone()))
                .collect(),
        )
    }

    pub fn roots(&self) -> BridgeFinalityRoots {
        BridgeFinalityRoots {
            parameters_root: self.parameters_root(),
            deposit_certificate_root: self.deposit_certificate_root(),
            delayed_release_root: self.delayed_release_root(),
            release_cohort_root: self.release_cohort_root(),
            insurance_tranche_root: self.insurance_tranche_root(),
            signer_rotation_root: self.signer_rotation_root(),
            emergency_evidence_root: self.emergency_evidence_root(),
            reserve_checkpoint_root: self.reserve_checkpoint_root(),
            sponsorship_root: self.sponsorship_root(),
            watchtower_attestation_root: self.watchtower_attestation_root(),
            paused_scope_root: self.paused_scope_root(),
            public_record_root: self.public_record_root(),
            state_root: self.state_root(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_finality_state",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_FINALITY_PROTOCOL_VERSION,
            "network": self.network,
            "asset_id": self.asset_id,
            "operator_label": self.operator_label,
            "height": self.height,
            "parameters_root": self.parameters_root(),
            "deposit_certificate_root": self.deposit_certificate_root(),
            "delayed_release_root": self.delayed_release_root(),
            "release_cohort_root": self.release_cohort_root(),
            "insurance_tranche_root": self.insurance_tranche_root(),
            "signer_rotation_root": self.signer_rotation_root(),
            "emergency_evidence_root": self.emergency_evidence_root(),
            "reserve_checkpoint_root": self.reserve_checkpoint_root(),
            "sponsorship_root": self.sponsorship_root(),
            "watchtower_attestation_root": self.watchtower_attestation_root(),
            "paused_scope_root": self.paused_scope_root(),
            "public_record_root": self.public_record_root(),
            "deposit_certificate_count": self.deposit_certificates.len() as u64,
            "delayed_release_count": self.delayed_releases.len() as u64,
            "release_cohort_count": self.release_cohorts.len() as u64,
            "insurance_tranche_count": self.insurance_tranches.len() as u64,
            "signer_rotation_count": self.signer_rotations.len() as u64,
            "emergency_evidence_count": self.emergency_evidence.len() as u64,
            "reserve_checkpoint_count": self.reserve_checkpoints.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "watchtower_attestation_count": self.watchtower_attestations.len() as u64,
            "paused_scope_count": self.paused_scopes.len() as u64,
            "ready_release_count": self.ready_releases().len() as u64,
            "total_certified_deposits": self.total_certified_deposits(),
            "total_pending_withdrawals": self.total_pending_withdrawals(),
            "total_insurance_coverage": self.total_insurance_coverage(),
            "total_sponsored_fees": self.total_sponsored_fees(),
            "active_signer_rotation_id": self.active_signer_rotation_id(),
        })
    }

    pub fn state_root(&self) -> String {
        bridge_finality_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "bridge_finality_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> BridgeFinalityResult<String> {
        self.parameters.validate()?;
        ensure_non_empty(&self.network, "bridge finality network")?;
        ensure_non_empty(&self.asset_id, "bridge finality asset id")?;
        ensure_non_empty(&self.operator_label, "bridge finality operator label")?;
        for certificate in self.deposit_certificates.values() {
            certificate.validate()?;
            if certificate.monero_network != self.network {
                return Err("deposit certificate network mismatch".to_string());
            }
            if certificate.asset_id != self.asset_id {
                return Err("deposit certificate asset mismatch".to_string());
            }
        }
        for item in self.delayed_releases.values() {
            item.validate()?;
            if item.asset_id != self.asset_id {
                return Err("delayed release asset mismatch".to_string());
            }
            if let Some(certificate_id) = &item.deposit_certificate_id {
                if !self.deposit_certificates.contains_key(certificate_id) {
                    return Err("delayed release references missing certificate".to_string());
                }
            }
        }
        for cohort in self.release_cohorts.values() {
            cohort.validate()?;
            if cohort.asset_id != self.asset_id {
                return Err("release cohort asset mismatch".to_string());
            }
            for queue_id in &cohort.queue_item_ids {
                let item = self
                    .delayed_releases
                    .get(queue_id)
                    .ok_or_else(|| "release cohort references missing queue item".to_string())?;
                if item.cohort_id.as_deref() != Some(cohort.cohort_id.as_str())
                    && cohort.status != WithdrawalCohortStatus::Cancelled
                {
                    return Err("release cohort queue item assignment mismatch".to_string());
                }
            }
        }
        for tranche in self.insurance_tranches.values() {
            tranche.validate()?;
            if tranche.asset_id != self.asset_id {
                return Err("insurance tranche asset mismatch".to_string());
            }
            if !self
                .reserve_checkpoints
                .contains_key(&tranche.reserve_checkpoint_id)
            {
                return Err("insurance tranche references missing reserve checkpoint".to_string());
            }
        }
        for rotation in self.signer_rotations.values() {
            rotation.validate()?;
        }
        for evidence in self.emergency_evidence.values() {
            evidence.validate()?;
        }
        for checkpoint in self.reserve_checkpoints.values() {
            checkpoint.validate()?;
            if checkpoint.monero_network != self.network {
                return Err("reserve checkpoint network mismatch".to_string());
            }
            if checkpoint.asset_id != self.asset_id {
                return Err("reserve checkpoint asset mismatch".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if sponsorship.fee_asset_id != self.asset_id {
                return Err("sponsorship asset mismatch".to_string());
            }
            if let Some(item) = self
                .delayed_releases
                .values()
                .find(|item| item.withdrawal_id == sponsorship.withdrawal_id)
            {
                if item.sponsorship_id.as_deref() != Some(sponsorship.sponsorship_id.as_str()) {
                    return Err("sponsorship queue item link mismatch".to_string());
                }
            }
        }
        for attestation in self.watchtower_attestations.values() {
            attestation.validate()?;
        }
        Ok(self.state_root())
    }

    fn refresh_paused_scopes(&mut self) {
        let mut scoped_events = self
            .emergency_evidence
            .values()
            .filter(|evidence| evidence.is_effective_at(self.height))
            .map(|evidence| {
                (
                    evidence.effective_at_height,
                    evidence.evidence_id.clone(),
                    evidence.action,
                    evidence.scope.clone(),
                )
            })
            .collect::<Vec<_>>();
        scoped_events.sort();
        let mut paused = BTreeSet::new();
        for (_, _, action, scope) in scoped_events {
            match action {
                EmergencyPauseAction::Pause => {
                    paused.insert(scope);
                }
                EmergencyPauseAction::Unpause => {
                    paused.remove(&scope);
                    if scope == "global" {
                        paused.clear();
                    }
                }
            }
        }
        self.paused_scopes = paused;
    }

    fn refresh_public_records(&mut self) {
        for certificate in self.deposit_certificates.values() {
            self.public_records.insert(
                format!("deposit:{}", certificate.certificate_id),
                certificate.public_record(),
            );
        }
        for item in self.delayed_releases.values() {
            self.public_records
                .insert(format!("release:{}", item.queue_id), item.public_record());
        }
        for cohort in self.release_cohorts.values() {
            self.public_records.insert(
                format!("cohort:{}", cohort.cohort_id),
                cohort.public_record(),
            );
        }
        for tranche in self.insurance_tranches.values() {
            self.public_records.insert(
                format!("insurance:{}", tranche.tranche_id),
                tranche.public_record(),
            );
        }
        for rotation in self.signer_rotations.values() {
            self.public_records.insert(
                format!("rotation:{}", rotation.rotation_id),
                rotation.public_record(),
            );
        }
        for evidence in self.emergency_evidence.values() {
            self.public_records.insert(
                format!("emergency:{}", evidence.evidence_id),
                evidence.public_record(),
            );
        }
        for checkpoint in self.reserve_checkpoints.values() {
            self.public_records.insert(
                format!("reserve:{}", checkpoint.checkpoint_id),
                checkpoint.public_record(),
            );
        }
        for sponsorship in self.sponsorships.values() {
            self.public_records.insert(
                format!("sponsorship:{}", sponsorship.sponsorship_id),
                sponsorship.public_record(),
            );
        }
        for attestation in self.watchtower_attestations.values() {
            self.public_records.insert(
                format!("watchtower:{}", attestation.attestation_id),
                attestation.public_record(),
            );
        }
    }
}

pub fn bridge_deposit_finality_certificate_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-DEPOSIT-CERTIFICATE-ID", record)
}

pub fn bridge_delayed_release_queue_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-DELAYED-RELEASE-ID", record)
}

pub fn bridge_withdrawal_release_cohort_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-WITHDRAWAL-COHORT-ID", record)
}

pub fn bridge_reorg_insurance_tranche_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-REORG-INSURANCE-ID", record)
}

pub fn bridge_quantum_signer_rotation_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-QUANTUM-ROTATION-ID", record)
}

pub fn bridge_emergency_pause_evidence_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-EMERGENCY-EVIDENCE-ID", record)
}

pub fn bridge_reserve_reconciliation_checkpoint_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-RESERVE-CHECKPOINT-ID", record)
}

pub fn bridge_low_fee_withdrawal_sponsorship_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-LOW-FEE-SPONSORSHIP-ID", record)
}

pub fn bridge_watchtower_attestation_id(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-WATCHTOWER-ATTESTATION-ID", record)
}

pub fn bridge_finality_deposit_certificate_root(
    certificates: &[DepositFinalityCertificate],
) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-DEPOSIT-CERTIFICATE-SET",
        certificates
            .iter()
            .map(|certificate| {
                (
                    certificate.certificate_id.clone(),
                    certificate.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_finality_delayed_release_root(releases: &[DelayedReleaseQueueItem]) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-DELAYED-RELEASE-SET",
        releases
            .iter()
            .map(|release| (release.queue_id.clone(), release.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_release_cohort_root(cohorts: &[WithdrawalReleaseCohort]) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-WITHDRAWAL-COHORT-SET",
        cohorts
            .iter()
            .map(|cohort| (cohort.cohort_id.clone(), cohort.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_insurance_tranche_root(tranches: &[ReorgInsuranceTranche]) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-INSURANCE-TRANCHE-SET",
        tranches
            .iter()
            .map(|tranche| (tranche.tranche_id.clone(), tranche.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_signer_rotation_root(
    rotations: &[QuantumResistantSignerRotation],
) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-SIGNER-ROTATION-SET",
        rotations
            .iter()
            .map(|rotation| (rotation.rotation_id.clone(), rotation.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_emergency_evidence_root(evidence: &[EmergencyPauseEvidence]) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-EMERGENCY-EVIDENCE-SET",
        evidence
            .iter()
            .map(|evidence| (evidence.evidence_id.clone(), evidence.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_reserve_checkpoint_root(
    checkpoints: &[ReserveReconciliationCheckpoint],
) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-RESERVE-CHECKPOINT-SET",
        checkpoints
            .iter()
            .map(|checkpoint| (checkpoint.checkpoint_id.clone(), checkpoint.public_record()))
            .collect(),
    )
}

pub fn bridge_finality_sponsorship_root(
    sponsorships: &[BridgeFinalityLowFeeWithdrawalSponsorship],
) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-SPONSORSHIP-SET",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_finality_watchtower_attestation_root(
    attestations: &[BridgeWatchtowerAttestation],
) -> String {
    keyed_record_root(
        "BRIDGE-FINALITY-WATCHTOWER-ATTESTATION-SET",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_finality_state_root_from_record(record: &Value) -> String {
    bridge_finality_payload_root("BRIDGE-FINALITY-STATE", record)
}

pub fn bridge_finality_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn bridge_finality_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn bridge_finality_signature_root(
    domain: &str,
    signer_label: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(BRIDGE_FINALITY_PROTOCOL_VERSION),
            HashPart::Str(signer_label),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn bridge_finality_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = ordered_strings(values)
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn bridge_finality_public_record_root(records: &[Value]) -> String {
    merkle_root(
        "BRIDGE-FINALITY-PUBLIC-RECORDS",
        &records
            .iter()
            .enumerate()
            .map(|(index, record)| json!({"index": index as u64, "record": record}))
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_finality_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn bridge_finality_required_coverage_units(liability_units: u64, coverage_bps: u64) -> u64 {
    liability_units
        .saturating_mul(coverage_bps)
        .div_ceil(BRIDGE_FINALITY_MAX_BPS)
}

pub fn bridge_finality_has_quorum(voters: &[String], quorum: u64) -> bool {
    ordered_string_set(voters).len() as u64 >= quorum
}

fn keyed_record_root(domain: &str, records: Vec<(String, Value)>) -> String {
    keyed_value_root(domain, records)
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(key, record)| json!({"key": key, "record": record}))
            .collect::<Vec<_>>(),
    )
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    record
        .as_object_mut()
        .expect("bridge finality public record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> BridgeFinalityResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ordered_strings(values: &[String]) -> Vec<String> {
    ordered_string_set(values).into_iter().collect()
}

fn ordered_string_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect()
}

fn ensure_non_empty(value: &str, label: &str) -> BridgeFinalityResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> BridgeFinalityResult<()> {
    if value > BRIDGE_FINALITY_MAX_BPS {
        Err(format!("{label} cannot exceed 10000 bps"))
    } else {
        Ok(())
    }
}

fn coverage_bps(covered_units: u64, liability_units: u64) -> u64 {
    if liability_units == 0 {
        BRIDGE_FINALITY_MAX_BPS
    } else {
        covered_units
            .saturating_mul(BRIDGE_FINALITY_MAX_BPS)
            .checked_div(liability_units)
            .unwrap_or(BRIDGE_FINALITY_MAX_BPS)
    }
}
