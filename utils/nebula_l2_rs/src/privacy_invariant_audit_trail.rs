use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivacyInvariantAuditTrailResult<T> = Result<T, String>;

pub const PRIVACY_INVARIANT_AUDIT_TRAIL_PROTOCOL_VERSION: &str =
    "nebula-privacy-invariant-audit-trail-v1";
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEVNET_HEIGHT: u64 = 416;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 144;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_REDACTION_TTL_BLOCKS: u64 = 17_280;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MIN_AUDITOR_WEIGHT: u64 = 7;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 100_000;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MAX_RECEIPT_UNITS: u64 = 5_000;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MIN_ANONYMITY_SET: u64 = 128;
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_COMMITMENT_SCHEME: &str =
    "privacy-invariant-commitment-v1";
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_REDACTION_SCHEME: &str =
    "selective-redaction-merkle-v1";
pub const PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_SIGNATURE_SCHEME: &str = "ML-DSA-65";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySurface {
    ShieldedAsset,
    MoneroViewKey,
    PrivateContract,
    ConfidentialToken,
    PrivateDefi,
    WalletRecovery,
    OracleDisclosure,
}

impl PrivacySurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedAsset => "shielded_asset",
            Self::MoneroViewKey => "monero_view_key",
            Self::PrivateContract => "private_contract",
            Self::ConfidentialToken => "confidential_token",
            Self::PrivateDefi => "private_defi",
            Self::WalletRecovery => "wallet_recovery",
            Self::OracleDisclosure => "oracle_disclosure",
        }
    }

    pub fn default_budget_units(self) -> u64 {
        match self {
            Self::ShieldedAsset => 12_000,
            Self::MoneroViewKey => 18_000,
            Self::PrivateContract => 14_000,
            Self::ConfidentialToken => 11_000,
            Self::PrivateDefi => 16_000,
            Self::WalletRecovery => 9_000,
            Self::OracleDisclosure => 8_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    NoRawSecretMaterial,
    DisclosureScopeBounded,
    PrivacyBudgetConserved,
    AuditorThresholdMet,
    RedactionRootAnchored,
    EpochMonotonicity,
    ReceiptUniqueness,
    OraclePayloadMinimized,
    RecoveryGuardianQuorum,
    DefiPositionAggregation,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRawSecretMaterial => "no_raw_secret_material",
            Self::DisclosureScopeBounded => "disclosure_scope_bounded",
            Self::PrivacyBudgetConserved => "privacy_budget_conserved",
            Self::AuditorThresholdMet => "auditor_threshold_met",
            Self::RedactionRootAnchored => "redaction_root_anchored",
            Self::EpochMonotonicity => "epoch_monotonicity",
            Self::ReceiptUniqueness => "receipt_uniqueness",
            Self::OraclePayloadMinimized => "oracle_payload_minimized",
            Self::RecoveryGuardianQuorum => "recovery_guardian_quorum",
            Self::DefiPositionAggregation => "defi_position_aggregation",
        }
    }

    pub fn severity_weight(self) -> u64 {
        match self {
            Self::NoRawSecretMaterial => 5,
            Self::DisclosureScopeBounded => 4,
            Self::PrivacyBudgetConserved => 5,
            Self::AuditorThresholdMet => 4,
            Self::RedactionRootAnchored => 4,
            Self::EpochMonotonicity => 3,
            Self::ReceiptUniqueness => 3,
            Self::OraclePayloadMinimized => 2,
            Self::RecoveryGuardianQuorum => 4,
            Self::DefiPositionAggregation => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Scheduled,
    Open,
    EvidenceSealed,
    ReceiptsIssued,
    Verified,
    Challenged,
    Remediated,
    Expired,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::EvidenceSealed => "evidence_sealed",
            Self::ReceiptsIssued => "receipts_issued",
            Self::Verified => "verified",
            Self::Challenged => "challenged",
            Self::Remediated => "remediated",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Scheduled
                | Self::Open
                | Self::EvidenceSealed
                | Self::ReceiptsIssued
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Authorized,
    Published,
    Consumed,
    Revoked,
    Disputed,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Authorized => "authorized",
            Self::Published => "published",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn is_spendable(self) -> bool {
        matches!(self, Self::Authorized | Self::Published | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDeltaKind {
    Reserve,
    Spend,
    Refund,
    Slash,
    Rollover,
    EmergencyGrant,
}

impl BudgetDeltaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserve => "reserve",
            Self::Spend => "spend",
            Self::Refund => "refund",
            Self::Slash => "slash",
            Self::Rollover => "rollover",
            Self::EmergencyGrant => "emergency_grant",
        }
    }

    pub fn increases_budget(self) -> bool {
        matches!(self, Self::Refund | Self::Rollover | Self::EmergencyGrant)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorStatus {
    Candidate,
    Active,
    Suspended,
    Slashed,
    Retired,
}

impl AuditorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    EpochOpened,
    EvidenceCommitted,
    ReceiptAuthorized,
    ReceiptPublished,
    BudgetReserved,
    BudgetSpent,
    RedactionAnchored,
    InvariantChecked,
    AuditorAttested,
    ChallengeOpened,
    ChallengeResolved,
}

impl AuditEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochOpened => "epoch_opened",
            Self::EvidenceCommitted => "evidence_committed",
            Self::ReceiptAuthorized => "receipt_authorized",
            Self::ReceiptPublished => "receipt_published",
            Self::BudgetReserved => "budget_reserved",
            Self::BudgetSpent => "budget_spent",
            Self::RedactionAnchored => "redaction_anchored",
            Self::InvariantChecked => "invariant_checked",
            Self::AuditorAttested => "auditor_attested",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
        }
    }

    pub fn mutates_privacy_budget(self) -> bool {
        matches!(self, Self::BudgetReserved | Self::BudgetSpent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Informational,
    Warning,
    ActionRequired,
    Waived,
    Remediated,
    Escalated,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::ActionRequired => "action_required",
            Self::Waived => "waived",
            Self::Remediated => "remediated",
            Self::Escalated => "escalated",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Warning | Self::ActionRequired | Self::Escalated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub epoch_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub min_auditor_weight: u64,
    pub default_privacy_budget_units: u64,
    pub max_receipt_units: u64,
    pub min_anonymity_set: u64,
    pub hash_suite: String,
    pub commitment_scheme: String,
    pub redaction_scheme: String,
    pub signature_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            epoch_blocks: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_EPOCH_BLOCKS,
            disclosure_ttl_blocks: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            redaction_ttl_blocks: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_REDACTION_TTL_BLOCKS,
            min_auditor_weight: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MIN_AUDITOR_WEIGHT,
            default_privacy_budget_units:
                PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_PRIVACY_BUDGET_UNITS,
            max_receipt_units: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MAX_RECEIPT_UNITS,
            min_anonymity_set: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_MIN_ANONYMITY_SET,
            hash_suite: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_HASH_SUITE.to_string(),
            commitment_scheme: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_COMMITMENT_SCHEME.to_string(),
            redaction_scheme: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_REDACTION_SCHEME.to_string(),
            signature_scheme: PRIVACY_INVARIANT_AUDIT_TRAIL_DEFAULT_SIGNATURE_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.chain_id, "config chain id")?;
        ensure_non_zero(self.epoch_blocks, "config epoch blocks")?;
        ensure_non_zero(self.disclosure_ttl_blocks, "config disclosure ttl blocks")?;
        ensure_non_zero(self.redaction_ttl_blocks, "config redaction ttl blocks")?;
        ensure_non_zero(self.min_auditor_weight, "config min auditor weight")?;
        ensure_non_zero(
            self.default_privacy_budget_units,
            "config default privacy budget units",
        )?;
        ensure_non_zero(self.max_receipt_units, "config max receipt units")?;
        ensure_non_zero(self.min_anonymity_set, "config min anonymity set")?;
        ensure_non_empty(&self.hash_suite, "config hash suite")?;
        ensure_non_empty(&self.commitment_scheme, "config commitment scheme")?;
        ensure_non_empty(&self.redaction_scheme, "config redaction scheme")?;
        ensure_non_empty(&self.signature_scheme, "config signature scheme")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "epoch_blocks": self.epoch_blocks.to_string(),
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks.to_string(),
            "redaction_ttl_blocks": self.redaction_ttl_blocks.to_string(),
            "min_auditor_weight": self.min_auditor_weight.to_string(),
            "default_privacy_budget_units": self.default_privacy_budget_units.to_string(),
            "max_receipt_units": self.max_receipt_units.to_string(),
            "min_anonymity_set": self.min_anonymity_set.to_string(),
            "hash_suite": self.hash_suite,
            "commitment_scheme": self.commitment_scheme,
            "redaction_scheme": self.redaction_scheme,
            "signature_scheme": self.signature_scheme,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEpoch {
    pub epoch_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub status: AuditStatus,
    pub surface_budget: BTreeMap<PrivacySurface, u64>,
    pub invariant_set: BTreeSet<InvariantKind>,
    pub anchor_root: String,
}

impl AuditEpoch {
    pub fn new(
        epoch_id: impl Into<String>,
        start_height: u64,
        end_height: u64,
        status: AuditStatus,
        surface_budget: BTreeMap<PrivacySurface, u64>,
        invariant_set: BTreeSet<InvariantKind>,
        anchor_root: impl Into<String>,
    ) -> Self {
        Self {
            epoch_id: epoch_id.into(),
            start_height,
            end_height,
            status,
            surface_budget,
            invariant_set,
            anchor_root: anchor_root.into(),
        }
    }

    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.epoch_id, "audit epoch id")?;
        if self.end_height < self.start_height {
            return Err("audit epoch end height precedes start height".to_string());
        }
        ensure_non_empty(&self.anchor_root, "audit epoch anchor root")?;
        if self.surface_budget.is_empty() {
            return Err("audit epoch must include surface budgets".to_string());
        }
        if self.invariant_set.is_empty() {
            return Err("audit epoch must include invariant set".to_string());
        }
        Ok(())
    }

    pub fn total_budget_units(&self) -> u64 {
        self.surface_budget.values().copied().sum()
    }

    pub fn public_record(&self) -> Value {
        let surface_budget = self
            .surface_budget
            .iter()
            .map(|(surface, units)| {
                json!({
                    "surface": surface.as_str(),
                    "budget_units": units.to_string(),
                })
            })
            .collect::<Vec<_>>();
        let invariants = self
            .invariant_set
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "epoch_id": self.epoch_id,
            "start_height": self.start_height.to_string(),
            "end_height": self.end_height.to_string(),
            "status": self.status.as_str(),
            "surface_budget": surface_budget,
            "invariants": invariants,
            "anchor_root": self.anchor_root,
            "total_budget_units": self.total_budget_units().to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-EPOCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetDelta {
    pub delta_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub kind: BudgetDeltaKind,
    pub units: u64,
    pub subject_commitment: String,
    pub receipt_id: Option<String>,
    pub note: String,
}

impl PrivacyBudgetDelta {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.delta_id, "privacy budget delta id")?;
        ensure_non_empty(&self.epoch_id, "privacy budget delta epoch id")?;
        ensure_non_zero(self.units, "privacy budget delta units")?;
        ensure_non_empty(
            &self.subject_commitment,
            "privacy budget delta subject commitment",
        )?;
        ensure_non_empty(&self.note, "privacy budget delta note")?;
        Ok(())
    }

    pub fn signed_units(&self) -> i128 {
        if self.kind.increases_budget() {
            i128::from(self.units)
        } else {
            -i128::from(self.units)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "delta_id": self.delta_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "kind": self.kind.as_str(),
            "units": self.units.to_string(),
            "signed_units": self.signed_units().to_string(),
            "subject_commitment": self.subject_commitment,
            "receipt_id": self.receipt_id,
            "note": self.note,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-BUDGET-DELTA",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureReceipt {
    pub receipt_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub invariant: InvariantKind,
    pub status: ReceiptStatus,
    pub disclosure_units: u64,
    pub subject_commitment: String,
    pub auditor_commitment: String,
    pub redaction_root: String,
    pub opened_fields_root: String,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureReceipt {
    pub fn validate(&self, config: &Config) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.receipt_id, "selective disclosure receipt id")?;
        ensure_non_empty(&self.epoch_id, "selective disclosure receipt epoch id")?;
        ensure_non_zero(
            self.disclosure_units,
            "selective disclosure receipt disclosure units",
        )?;
        if self.disclosure_units > config.max_receipt_units {
            return Err("selective disclosure receipt exceeds max receipt units".to_string());
        }
        ensure_non_empty(
            &self.subject_commitment,
            "selective disclosure receipt subject commitment",
        )?;
        ensure_non_empty(
            &self.auditor_commitment,
            "selective disclosure receipt auditor commitment",
        )?;
        ensure_non_empty(
            &self.redaction_root,
            "selective disclosure receipt redaction root",
        )?;
        ensure_non_empty(
            &self.opened_fields_root,
            "selective disclosure receipt opened fields root",
        )?;
        ensure_non_zero(
            self.expires_at_height,
            "selective disclosure receipt expires at height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "invariant": self.invariant.as_str(),
            "status": self.status.as_str(),
            "disclosure_units": self.disclosure_units.to_string(),
            "subject_commitment": self.subject_commitment,
            "auditor_commitment": self.auditor_commitment,
            "redaction_root": self.redaction_root,
            "opened_fields_root": self.opened_fields_root,
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-DISCLOSURE-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditorCommitment {
    pub auditor_id: String,
    pub status: AuditorStatus,
    pub weight: u64,
    pub jurisdiction_tag: String,
    pub commitment_root: String,
    pub keyset_root: String,
    pub last_attested_height: u64,
}

impl AuditorCommitment {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.auditor_id, "auditor id")?;
        ensure_non_zero(self.weight, "auditor weight")?;
        ensure_non_empty(&self.jurisdiction_tag, "auditor jurisdiction tag")?;
        ensure_non_empty(&self.commitment_root, "auditor commitment root")?;
        ensure_non_empty(&self.keyset_root, "auditor keyset root")?;
        ensure_non_zero(self.last_attested_height, "auditor last attested height")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auditor_id": self.auditor_id,
            "status": self.status.as_str(),
            "weight": self.weight.to_string(),
            "jurisdiction_tag": self.jurisdiction_tag,
            "commitment_root": self.commitment_root,
            "keyset_root": self.keyset_root,
            "last_attested_height": self.last_attested_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-AUDITOR",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRoot {
    pub redaction_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub source_root: String,
    pub redacted_root: String,
    pub policy_root: String,
    pub retained_field_count: u64,
    pub removed_field_count: u64,
    pub expires_at_height: u64,
}

impl RedactionRoot {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.redaction_id, "redaction id")?;
        ensure_non_empty(&self.epoch_id, "redaction epoch id")?;
        ensure_non_empty(&self.source_root, "redaction source root")?;
        ensure_non_empty(&self.redacted_root, "redaction redacted root")?;
        ensure_non_empty(&self.policy_root, "redaction policy root")?;
        ensure_non_zero(self.retained_field_count, "redaction retained field count")?;
        ensure_non_zero(self.expires_at_height, "redaction expires at height")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "source_root": self.source_root,
            "redacted_root": self.redacted_root,
            "policy_root": self.policy_root,
            "retained_field_count": self.retained_field_count.to_string(),
            "removed_field_count": self.removed_field_count.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-REDACTION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub check_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub invariant: InvariantKind,
    pub passed: bool,
    pub evidence_root: String,
    pub remediation_root: String,
    pub checked_at_height: u64,
}

impl InvariantCheck {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.check_id, "invariant check id")?;
        ensure_non_empty(&self.epoch_id, "invariant check epoch id")?;
        ensure_non_empty(&self.evidence_root, "invariant check evidence root")?;
        ensure_non_empty(&self.remediation_root, "invariant check remediation root")?;
        ensure_non_zero(self.checked_at_height, "invariant check checked at height")?;
        Ok(())
    }

    pub fn risk_score(&self) -> u64 {
        if self.passed {
            0
        } else {
            self.invariant.severity_weight()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "invariant": self.invariant.as_str(),
            "passed": self.passed,
            "evidence_root": self.evidence_root,
            "remediation_root": self.remediation_root,
            "checked_at_height": self.checked_at_height.to_string(),
            "risk_score": self.risk_score().to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-INVARIANT-CHECK",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceCoverage {
    pub surface: PrivacySurface,
    pub epoch_id: String,
    pub lane_id: String,
    pub subject_count: u64,
    pub receipt_count: u64,
    pub redaction_count: u64,
    pub budget_units_reserved: u64,
    pub budget_units_spent: u64,
    pub coverage_root: String,
}

impl SurfaceCoverage {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.epoch_id, "surface coverage epoch id")?;
        ensure_non_empty(&self.lane_id, "surface coverage lane id")?;
        ensure_non_zero(self.subject_count, "surface coverage subject count")?;
        ensure_non_empty(&self.coverage_root, "surface coverage root")?;
        if self.budget_units_spent > self.budget_units_reserved {
            return Err("surface coverage spent budget exceeds reserved budget".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "surface": self.surface.as_str(),
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "subject_count": self.subject_count.to_string(),
            "receipt_count": self.receipt_count.to_string(),
            "redaction_count": self.redaction_count.to_string(),
            "budget_units_reserved": self.budget_units_reserved.to_string(),
            "budget_units_spent": self.budget_units_spent.to_string(),
            "coverage_root": self.coverage_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-SURFACE-COVERAGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTrailEvent {
    pub event_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub kind: AuditEventKind,
    pub related_root: String,
    pub actor_commitment: String,
    pub sequence: u64,
    pub height: u64,
}

impl AuditTrailEvent {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.event_id, "audit trail event id")?;
        ensure_non_empty(&self.epoch_id, "audit trail event epoch id")?;
        ensure_non_empty(&self.related_root, "audit trail event related root")?;
        ensure_non_empty(&self.actor_commitment, "audit trail event actor commitment")?;
        ensure_non_zero(self.sequence, "audit trail event sequence")?;
        ensure_non_zero(self.height, "audit trail event height")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "kind": self.kind.as_str(),
            "mutates_privacy_budget": self.kind.mutates_privacy_budget(),
            "related_root": self.related_root,
            "actor_commitment": self.actor_commitment,
            "sequence": self.sequence.to_string(),
            "height": self.height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-EVENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub finding_id: String,
    pub epoch_id: String,
    pub surface: PrivacySurface,
    pub invariant: InvariantKind,
    pub status: FindingStatus,
    pub severity: u64,
    pub evidence_root: String,
    pub redacted_summary_root: String,
    pub remediation_commitment: String,
    pub opened_at_height: u64,
    pub due_at_height: u64,
}

impl AuditFinding {
    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_empty(&self.finding_id, "audit finding id")?;
        ensure_non_empty(&self.epoch_id, "audit finding epoch id")?;
        ensure_non_zero(self.severity, "audit finding severity")?;
        ensure_non_empty(&self.evidence_root, "audit finding evidence root")?;
        ensure_non_empty(
            &self.redacted_summary_root,
            "audit finding redacted summary root",
        )?;
        ensure_non_empty(
            &self.remediation_commitment,
            "audit finding remediation commitment",
        )?;
        ensure_non_zero(self.opened_at_height, "audit finding opened at height")?;
        ensure_non_zero(self.due_at_height, "audit finding due at height")?;
        if self.due_at_height < self.opened_at_height {
            return Err("audit finding due height precedes opened height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "epoch_id": self.epoch_id,
            "surface": self.surface.as_str(),
            "invariant": self.invariant.as_str(),
            "status": self.status.as_str(),
            "is_open": self.status.is_open(),
            "severity": self.severity.to_string(),
            "evidence_root": self.evidence_root,
            "redacted_summary_root": self.redacted_summary_root,
            "remediation_commitment": self.remediation_commitment,
            "opened_at_height": self.opened_at_height.to_string(),
            "due_at_height": self.due_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-FINDING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub epoch_root: String,
    pub budget_delta_root: String,
    pub receipt_root: String,
    pub auditor_root: String,
    pub redaction_root: String,
    pub invariant_check_root: String,
    pub coverage_root: String,
    pub event_root: String,
    pub finding_root: String,
    pub live_receipt_root: String,
    pub failed_invariant_root: String,
    pub open_finding_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "epoch_root": self.epoch_root,
            "budget_delta_root": self.budget_delta_root,
            "receipt_root": self.receipt_root,
            "auditor_root": self.auditor_root,
            "redaction_root": self.redaction_root,
            "invariant_check_root": self.invariant_check_root,
            "coverage_root": self.coverage_root,
            "event_root": self.event_root,
            "finding_root": self.finding_root,
            "live_receipt_root": self.live_receipt_root,
            "failed_invariant_root": self.failed_invariant_root,
            "open_finding_root": self.open_finding_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub epochs: usize,
    pub live_epochs: usize,
    pub budget_deltas: usize,
    pub receipts: usize,
    pub spendable_receipts: usize,
    pub auditors: usize,
    pub active_auditors: usize,
    pub redactions: usize,
    pub invariant_checks: usize,
    pub failed_invariant_checks: usize,
    pub surface_coverages: usize,
    pub audit_events: usize,
    pub budget_mutating_events: usize,
    pub findings: usize,
    pub open_findings: usize,
    pub total_budget_reserved: u64,
    pub total_budget_spent: u64,
    pub total_auditor_weight: u64,
    pub total_open_finding_severity: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "epochs": self.epochs.to_string(),
            "live_epochs": self.live_epochs.to_string(),
            "budget_deltas": self.budget_deltas.to_string(),
            "receipts": self.receipts.to_string(),
            "spendable_receipts": self.spendable_receipts.to_string(),
            "auditors": self.auditors.to_string(),
            "active_auditors": self.active_auditors.to_string(),
            "redactions": self.redactions.to_string(),
            "invariant_checks": self.invariant_checks.to_string(),
            "failed_invariant_checks": self.failed_invariant_checks.to_string(),
            "surface_coverages": self.surface_coverages.to_string(),
            "audit_events": self.audit_events.to_string(),
            "budget_mutating_events": self.budget_mutating_events.to_string(),
            "findings": self.findings.to_string(),
            "open_findings": self.open_findings.to_string(),
            "total_budget_reserved": self.total_budget_reserved.to_string(),
            "total_budget_spent": self.total_budget_spent.to_string(),
            "total_auditor_weight": self.total_auditor_weight.to_string(),
            "total_open_finding_severity": self.total_open_finding_severity.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub epochs: Vec<AuditEpoch>,
    pub budget_deltas: Vec<PrivacyBudgetDelta>,
    pub receipts: Vec<SelectiveDisclosureReceipt>,
    pub auditors: Vec<AuditorCommitment>,
    pub redactions: Vec<RedactionRoot>,
    pub invariant_checks: Vec<InvariantCheck>,
    pub surface_coverages: Vec<SurfaceCoverage>,
    pub audit_events: Vec<AuditTrailEvent>,
    pub findings: Vec<AuditFinding>,
}

impl State {
    pub fn devnet() -> PrivacyInvariantAuditTrailResult<State> {
        let config = Config::devnet();
        let height = PRIVACY_INVARIANT_AUDIT_TRAIL_DEVNET_HEIGHT;
        let epoch_id = "piat-epoch-0001".to_string();
        let surface_budget = devnet_surface_budget();
        let invariant_set = devnet_invariant_set();
        let anchor_root = synthetic_root("devnet-anchor", &epoch_id, "root");
        let epoch = AuditEpoch::new(
            epoch_id.clone(),
            1,
            config.epoch_blocks,
            AuditStatus::Open,
            surface_budget,
            invariant_set,
            anchor_root,
        );
        let auditors = devnet_auditors(height);
        let redactions = devnet_redactions(&epoch_id, height + config.redaction_ttl_blocks);
        let receipts = devnet_receipts(&epoch_id, height + config.disclosure_ttl_blocks);
        let budget_deltas = devnet_budget_deltas(&epoch_id);
        let invariant_checks = devnet_invariant_checks(&epoch_id, height);
        let surface_coverages = devnet_surface_coverages(&epoch_id);
        let audit_events = devnet_audit_events(&epoch_id, height);
        let findings = devnet_findings(&epoch_id, height);
        let state = State {
            height,
            config,
            epochs: vec![epoch],
            budget_deltas,
            receipts,
            auditors,
            redactions,
            invariant_checks,
            surface_coverages,
            audit_events,
            findings,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_zero(height, "state height")?;
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PrivacyInvariantAuditTrailResult<()> {
        if height < self.height {
            return Err("state height cannot decrease".to_string());
        }
        self.set_height(height)
    }

    pub fn validate(&self) -> PrivacyInvariantAuditTrailResult<()> {
        ensure_non_zero(self.height, "state height")?;
        self.config.validate()?;
        ensure_unique(
            self.epochs.iter().map(|epoch| epoch.epoch_id.as_str()),
            "audit epoch id",
        )?;
        ensure_unique(
            self.budget_deltas
                .iter()
                .map(|delta| delta.delta_id.as_str()),
            "privacy budget delta id",
        )?;
        ensure_unique(
            self.receipts
                .iter()
                .map(|receipt| receipt.receipt_id.as_str()),
            "selective disclosure receipt id",
        )?;
        ensure_unique(
            self.auditors
                .iter()
                .map(|auditor| auditor.auditor_id.as_str()),
            "auditor id",
        )?;
        ensure_unique(
            self.redactions
                .iter()
                .map(|redaction| redaction.redaction_id.as_str()),
            "redaction id",
        )?;
        ensure_unique(
            self.invariant_checks
                .iter()
                .map(|check| check.check_id.as_str()),
            "invariant check id",
        )?;
        ensure_unique(
            self.audit_events
                .iter()
                .map(|event| event.event_id.as_str()),
            "audit trail event id",
        )?;
        ensure_unique(
            self.findings
                .iter()
                .map(|finding| finding.finding_id.as_str()),
            "audit finding id",
        )?;
        for epoch in &self.epochs {
            epoch.validate()?;
        }
        for delta in &self.budget_deltas {
            delta.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate(&self.config)?;
        }
        for auditor in &self.auditors {
            auditor.validate()?;
        }
        for redaction in &self.redactions {
            redaction.validate()?;
        }
        for check in &self.invariant_checks {
            check.validate()?;
        }
        for coverage in &self.surface_coverages {
            coverage.validate()?;
        }
        for event in &self.audit_events {
            event.validate()?;
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.active_auditor_weight() < self.config.min_auditor_weight {
            return Err("active auditor weight below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let epoch_records = self
            .epochs
            .iter()
            .map(AuditEpoch::public_record)
            .collect::<Vec<_>>();
        let budget_delta_records = self
            .budget_deltas
            .iter()
            .map(PrivacyBudgetDelta::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .iter()
            .map(SelectiveDisclosureReceipt::public_record)
            .collect::<Vec<_>>();
        let auditor_records = self
            .auditors
            .iter()
            .map(AuditorCommitment::public_record)
            .collect::<Vec<_>>();
        let redaction_records = self
            .redactions
            .iter()
            .map(RedactionRoot::public_record)
            .collect::<Vec<_>>();
        let invariant_check_records = self
            .invariant_checks
            .iter()
            .map(InvariantCheck::public_record)
            .collect::<Vec<_>>();
        let coverage_records = self
            .surface_coverages
            .iter()
            .map(SurfaceCoverage::public_record)
            .collect::<Vec<_>>();
        let event_records = self
            .audit_events
            .iter()
            .map(AuditTrailEvent::public_record)
            .collect::<Vec<_>>();
        let finding_records = self
            .findings
            .iter()
            .map(AuditFinding::public_record)
            .collect::<Vec<_>>();
        let live_receipt_records = self
            .receipts
            .iter()
            .filter(|receipt| receipt.status.is_spendable())
            .map(SelectiveDisclosureReceipt::public_record)
            .collect::<Vec<_>>();
        let failed_invariant_records = self
            .invariant_checks
            .iter()
            .filter(|check| !check.passed)
            .map(InvariantCheck::public_record)
            .collect::<Vec<_>>();
        let open_finding_records = self
            .findings
            .iter()
            .filter(|finding| finding.status.is_open())
            .map(AuditFinding::public_record)
            .collect::<Vec<_>>();
        let config_root = domain_hash(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-CONFIG",
            &[HashPart::Json(&config_record)],
            32,
        );
        let epoch_root = merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-EPOCHS", &epoch_records);
        let budget_delta_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-BUDGET-DELTAS",
            &budget_delta_records,
        );
        let receipt_root = merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-RECEIPTS", &receipt_records);
        let auditor_root = merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-AUDITORS", &auditor_records);
        let redaction_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-REDACTIONS",
            &redaction_records,
        );
        let invariant_check_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-INVARIANT-CHECKS",
            &invariant_check_records,
        );
        let coverage_root =
            merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-COVERAGE", &coverage_records);
        let event_root = merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-EVENTS", &event_records);
        let finding_root = merkle_root("PRIVACY-INVARIANT-AUDIT-TRAIL-FINDINGS", &finding_records);
        let live_receipt_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-LIVE-RECEIPTS",
            &live_receipt_records,
        );
        let failed_invariant_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-FAILED-INVARIANTS",
            &failed_invariant_records,
        );
        let open_finding_root = merkle_root(
            "PRIVACY-INVARIANT-AUDIT-TRAIL-OPEN-FINDINGS",
            &open_finding_records,
        );
        let state_record = json!({
            "height": self.height.to_string(),
            "config_root": config_root,
            "epoch_root": epoch_root,
            "budget_delta_root": budget_delta_root,
            "receipt_root": receipt_root,
            "auditor_root": auditor_root,
            "redaction_root": redaction_root,
            "invariant_check_root": invariant_check_root,
            "coverage_root": coverage_root,
            "event_root": event_root,
            "finding_root": finding_root,
            "live_receipt_root": live_receipt_root,
            "failed_invariant_root": failed_invariant_root,
            "open_finding_root": open_finding_root,
        });
        let state_root = root_from_record(&state_record);
        Roots {
            config_root,
            epoch_root,
            budget_delta_root,
            receipt_root,
            auditor_root,
            redaction_root,
            invariant_check_root,
            coverage_root,
            event_root,
            finding_root,
            live_receipt_root,
            failed_invariant_root,
            open_finding_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            epochs: self.epochs.len(),
            live_epochs: self
                .epochs
                .iter()
                .filter(|epoch| epoch.status.is_live())
                .count(),
            budget_deltas: self.budget_deltas.len(),
            receipts: self.receipts.len(),
            spendable_receipts: self
                .receipts
                .iter()
                .filter(|receipt| receipt.status.is_spendable())
                .count(),
            auditors: self.auditors.len(),
            active_auditors: self
                .auditors
                .iter()
                .filter(|auditor| auditor.status.can_attest())
                .count(),
            redactions: self.redactions.len(),
            invariant_checks: self.invariant_checks.len(),
            failed_invariant_checks: self
                .invariant_checks
                .iter()
                .filter(|check| !check.passed)
                .count(),
            surface_coverages: self.surface_coverages.len(),
            audit_events: self.audit_events.len(),
            budget_mutating_events: self
                .audit_events
                .iter()
                .filter(|event| event.kind.mutates_privacy_budget())
                .count(),
            findings: self.findings.len(),
            open_findings: self
                .findings
                .iter()
                .filter(|finding| finding.status.is_open())
                .count(),
            total_budget_reserved: self
                .surface_coverages
                .iter()
                .map(|coverage| coverage.budget_units_reserved)
                .sum(),
            total_budget_spent: self
                .surface_coverages
                .iter()
                .map(|coverage| coverage.budget_units_spent)
                .sum(),
            total_auditor_weight: self.active_auditor_weight(),
            total_open_finding_severity: self
                .findings
                .iter()
                .filter(|finding| finding.status.is_open())
                .map(|finding| finding.severity)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "privacy_invariant_audit_trail_protocol_version":
                PRIVACY_INVARIANT_AUDIT_TRAIL_PROTOCOL_VERSION,
            "height": self.height.to_string(),
            "config": self.config.public_record(),
            "epochs": self.epochs.iter().map(AuditEpoch::public_record).collect::<Vec<_>>(),
            "budget_deltas": self
                .budget_deltas
                .iter()
                .map(PrivacyBudgetDelta::public_record)
                .collect::<Vec<_>>(),
            "receipts": self
                .receipts
                .iter()
                .map(SelectiveDisclosureReceipt::public_record)
                .collect::<Vec<_>>(),
            "auditors": self
                .auditors
                .iter()
                .map(AuditorCommitment::public_record)
                .collect::<Vec<_>>(),
            "redactions": self
                .redactions
                .iter()
                .map(RedactionRoot::public_record)
                .collect::<Vec<_>>(),
            "invariant_checks": self
                .invariant_checks
                .iter()
                .map(InvariantCheck::public_record)
                .collect::<Vec<_>>(),
            "surface_coverages": self
                .surface_coverages
                .iter()
                .map(SurfaceCoverage::public_record)
                .collect::<Vec<_>>(),
            "audit_events": self
                .audit_events
                .iter()
                .map(AuditTrailEvent::public_record)
                .collect::<Vec<_>>(),
            "findings": self
                .findings
                .iter()
                .map(AuditFinding::public_record)
                .collect::<Vec<_>>(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn active_auditor_weight(&self) -> u64 {
        self.auditors
            .iter()
            .filter(|auditor| auditor.status.can_attest())
            .map(|auditor| auditor.weight)
            .sum()
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVACY-INVARIANT-AUDIT-TRAIL-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivacyInvariantAuditTrailResult<State> {
    State::devnet()
}

fn devnet_surface_budget() -> BTreeMap<PrivacySurface, u64> {
    [
        PrivacySurface::ShieldedAsset,
        PrivacySurface::MoneroViewKey,
        PrivacySurface::PrivateContract,
        PrivacySurface::ConfidentialToken,
        PrivacySurface::PrivateDefi,
        PrivacySurface::WalletRecovery,
        PrivacySurface::OracleDisclosure,
    ]
    .into_iter()
    .map(|surface| (surface, surface.default_budget_units()))
    .collect()
}

fn devnet_invariant_set() -> BTreeSet<InvariantKind> {
    [
        InvariantKind::NoRawSecretMaterial,
        InvariantKind::DisclosureScopeBounded,
        InvariantKind::PrivacyBudgetConserved,
        InvariantKind::AuditorThresholdMet,
        InvariantKind::RedactionRootAnchored,
        InvariantKind::EpochMonotonicity,
        InvariantKind::ReceiptUniqueness,
        InvariantKind::OraclePayloadMinimized,
        InvariantKind::RecoveryGuardianQuorum,
        InvariantKind::DefiPositionAggregation,
    ]
    .into_iter()
    .collect()
}

fn devnet_auditors(height: u64) -> Vec<AuditorCommitment> {
    ["north", "south", "east", "west"]
        .into_iter()
        .enumerate()
        .map(|(index, region)| {
            let auditor_id = format!("piat-auditor-{region}");
            AuditorCommitment {
                auditor_id: auditor_id.clone(),
                status: AuditorStatus::Active,
                weight: 3,
                jurisdiction_tag: format!("devnet-{region}"),
                commitment_root: synthetic_root("auditor-commitment", &auditor_id, region),
                keyset_root: synthetic_root("auditor-keyset", &auditor_id, region),
                last_attested_height: height.saturating_sub(index as u64),
            }
        })
        .collect()
}

fn devnet_redactions(epoch_id: &str, expires_at_height: u64) -> Vec<RedactionRoot> {
    [
        (PrivacySurface::ShieldedAsset, "note-nullifier-window", 8, 3),
        (PrivacySurface::MoneroViewKey, "viewkey-scope-window", 6, 4),
        (
            PrivacySurface::PrivateContract,
            "contract-calldata-mask",
            9,
            5,
        ),
        (
            PrivacySurface::ConfidentialToken,
            "token-amount-range",
            7,
            4,
        ),
        (PrivacySurface::PrivateDefi, "defi-position-bucket", 8, 6),
        (
            PrivacySurface::WalletRecovery,
            "guardian-quorum-proof",
            5,
            2,
        ),
        (
            PrivacySurface::OracleDisclosure,
            "oracle-feed-minimal",
            4,
            3,
        ),
    ]
    .into_iter()
    .map(|(surface, label, retained, removed)| RedactionRoot {
        redaction_id: format!("redaction-{}-{label}", surface.as_str()),
        epoch_id: epoch_id.to_string(),
        surface,
        source_root: synthetic_root("redaction-source", epoch_id, label),
        redacted_root: synthetic_root("redaction-redacted", epoch_id, label),
        policy_root: synthetic_root("redaction-policy", epoch_id, label),
        retained_field_count: retained,
        removed_field_count: removed,
        expires_at_height,
    })
    .collect()
}

fn devnet_receipts(epoch_id: &str, expires_at_height: u64) -> Vec<SelectiveDisclosureReceipt> {
    [
        (
            "receipt-shielded-asset-supply",
            PrivacySurface::ShieldedAsset,
            InvariantKind::DisclosureScopeBounded,
            850,
        ),
        (
            "receipt-monero-viewkey-reserve",
            PrivacySurface::MoneroViewKey,
            InvariantKind::NoRawSecretMaterial,
            1_250,
        ),
        (
            "receipt-private-contract-selector",
            PrivacySurface::PrivateContract,
            InvariantKind::RedactionRootAnchored,
            640,
        ),
        (
            "receipt-confidential-token-range",
            PrivacySurface::ConfidentialToken,
            InvariantKind::PrivacyBudgetConserved,
            720,
        ),
        (
            "receipt-private-defi-liquidity",
            PrivacySurface::PrivateDefi,
            InvariantKind::DefiPositionAggregation,
            1_100,
        ),
        (
            "receipt-wallet-recovery-guardian",
            PrivacySurface::WalletRecovery,
            InvariantKind::RecoveryGuardianQuorum,
            460,
        ),
        (
            "receipt-oracle-minimized-payload",
            PrivacySurface::OracleDisclosure,
            InvariantKind::OraclePayloadMinimized,
            390,
        ),
    ]
    .into_iter()
    .map(
        |(receipt_id, surface, invariant, disclosure_units)| SelectiveDisclosureReceipt {
            receipt_id: receipt_id.to_string(),
            epoch_id: epoch_id.to_string(),
            surface,
            invariant,
            status: ReceiptStatus::Published,
            disclosure_units,
            subject_commitment: synthetic_root("receipt-subject", epoch_id, receipt_id),
            auditor_commitment: synthetic_root("receipt-auditor", epoch_id, receipt_id),
            redaction_root: synthetic_root("receipt-redaction", epoch_id, receipt_id),
            opened_fields_root: synthetic_root("receipt-opened-fields", epoch_id, receipt_id),
            expires_at_height,
        },
    )
    .collect()
}

fn devnet_budget_deltas(epoch_id: &str) -> Vec<PrivacyBudgetDelta> {
    [
        (
            "delta-shielded-asset-reserve",
            PrivacySurface::ShieldedAsset,
            BudgetDeltaKind::Reserve,
            850,
            "receipt-shielded-asset-supply",
        ),
        (
            "delta-monero-viewkey-reserve",
            PrivacySurface::MoneroViewKey,
            BudgetDeltaKind::Reserve,
            1_250,
            "receipt-monero-viewkey-reserve",
        ),
        (
            "delta-private-contract-spend",
            PrivacySurface::PrivateContract,
            BudgetDeltaKind::Spend,
            640,
            "receipt-private-contract-selector",
        ),
        (
            "delta-confidential-token-spend",
            PrivacySurface::ConfidentialToken,
            BudgetDeltaKind::Spend,
            720,
            "receipt-confidential-token-range",
        ),
        (
            "delta-private-defi-reserve",
            PrivacySurface::PrivateDefi,
            BudgetDeltaKind::Reserve,
            1_100,
            "receipt-private-defi-liquidity",
        ),
        (
            "delta-wallet-recovery-refund",
            PrivacySurface::WalletRecovery,
            BudgetDeltaKind::Refund,
            120,
            "receipt-wallet-recovery-guardian",
        ),
        (
            "delta-oracle-disclosure-spend",
            PrivacySurface::OracleDisclosure,
            BudgetDeltaKind::Spend,
            390,
            "receipt-oracle-minimized-payload",
        ),
    ]
    .into_iter()
    .map(
        |(delta_id, surface, kind, units, receipt_id)| PrivacyBudgetDelta {
            delta_id: delta_id.to_string(),
            epoch_id: epoch_id.to_string(),
            surface,
            kind,
            units,
            subject_commitment: synthetic_root("budget-delta-subject", epoch_id, delta_id),
            receipt_id: Some(receipt_id.to_string()),
            note: format!("devnet privacy budget delta for {}", surface.as_str()),
        },
    )
    .collect()
}

fn devnet_invariant_checks(epoch_id: &str, height: u64) -> Vec<InvariantCheck> {
    [
        (
            "check-shielded-asset-no-raw-secret",
            PrivacySurface::ShieldedAsset,
            InvariantKind::NoRawSecretMaterial,
            true,
        ),
        (
            "check-monero-viewkey-scope",
            PrivacySurface::MoneroViewKey,
            InvariantKind::DisclosureScopeBounded,
            true,
        ),
        (
            "check-private-contract-redaction",
            PrivacySurface::PrivateContract,
            InvariantKind::RedactionRootAnchored,
            true,
        ),
        (
            "check-confidential-token-budget",
            PrivacySurface::ConfidentialToken,
            InvariantKind::PrivacyBudgetConserved,
            true,
        ),
        (
            "check-private-defi-aggregation",
            PrivacySurface::PrivateDefi,
            InvariantKind::DefiPositionAggregation,
            true,
        ),
        (
            "check-wallet-recovery-quorum",
            PrivacySurface::WalletRecovery,
            InvariantKind::RecoveryGuardianQuorum,
            true,
        ),
        (
            "check-oracle-minimized-payload",
            PrivacySurface::OracleDisclosure,
            InvariantKind::OraclePayloadMinimized,
            true,
        ),
    ]
    .into_iter()
    .map(|(check_id, surface, invariant, passed)| InvariantCheck {
        check_id: check_id.to_string(),
        epoch_id: epoch_id.to_string(),
        surface,
        invariant,
        passed,
        evidence_root: synthetic_root("invariant-evidence", epoch_id, check_id),
        remediation_root: synthetic_root("invariant-remediation", epoch_id, check_id),
        checked_at_height: height,
    })
    .collect()
}

fn devnet_surface_coverages(epoch_id: &str) -> Vec<SurfaceCoverage> {
    [
        (
            PrivacySurface::ShieldedAsset,
            "lane:shielded:asset",
            512,
            1,
            1,
            12_000,
            850,
        ),
        (
            PrivacySurface::MoneroViewKey,
            "lane:monero:viewkey",
            384,
            1,
            1,
            18_000,
            1_250,
        ),
        (
            PrivacySurface::PrivateContract,
            "lane:private:contract",
            640,
            1,
            1,
            14_000,
            640,
        ),
        (
            PrivacySurface::ConfidentialToken,
            "lane:confidential:token",
            320,
            1,
            1,
            11_000,
            720,
        ),
        (
            PrivacySurface::PrivateDefi,
            "lane:private:defi",
            256,
            1,
            1,
            16_000,
            1_100,
        ),
        (
            PrivacySurface::WalletRecovery,
            "lane:wallet:recovery",
            192,
            1,
            1,
            9_000,
            340,
        ),
        (
            PrivacySurface::OracleDisclosure,
            "lane:oracle:private",
            144,
            1,
            1,
            8_000,
            390,
        ),
    ]
    .into_iter()
    .map(
        |(
            surface,
            lane_id,
            subject_count,
            receipt_count,
            redaction_count,
            budget_units_reserved,
            budget_units_spent,
        )| SurfaceCoverage {
            surface,
            epoch_id: epoch_id.to_string(),
            lane_id: lane_id.to_string(),
            subject_count,
            receipt_count,
            redaction_count,
            budget_units_reserved,
            budget_units_spent,
            coverage_root: synthetic_root("surface-coverage", epoch_id, lane_id),
        },
    )
    .collect()
}

fn devnet_audit_events(epoch_id: &str, height: u64) -> Vec<AuditTrailEvent> {
    [
        (
            "event-epoch-opened",
            PrivacySurface::ShieldedAsset,
            AuditEventKind::EpochOpened,
            1,
        ),
        (
            "event-shielded-evidence-committed",
            PrivacySurface::ShieldedAsset,
            AuditEventKind::EvidenceCommitted,
            2,
        ),
        (
            "event-monero-receipt-authorized",
            PrivacySurface::MoneroViewKey,
            AuditEventKind::ReceiptAuthorized,
            3,
        ),
        (
            "event-monero-receipt-published",
            PrivacySurface::MoneroViewKey,
            AuditEventKind::ReceiptPublished,
            4,
        ),
        (
            "event-private-contract-budget-reserved",
            PrivacySurface::PrivateContract,
            AuditEventKind::BudgetReserved,
            5,
        ),
        (
            "event-confidential-token-budget-spent",
            PrivacySurface::ConfidentialToken,
            AuditEventKind::BudgetSpent,
            6,
        ),
        (
            "event-private-defi-redaction-anchored",
            PrivacySurface::PrivateDefi,
            AuditEventKind::RedactionAnchored,
            7,
        ),
        (
            "event-wallet-recovery-invariant-checked",
            PrivacySurface::WalletRecovery,
            AuditEventKind::InvariantChecked,
            8,
        ),
        (
            "event-oracle-auditor-attested",
            PrivacySurface::OracleDisclosure,
            AuditEventKind::AuditorAttested,
            9,
        ),
    ]
    .into_iter()
    .map(|(event_id, surface, kind, sequence)| AuditTrailEvent {
        event_id: event_id.to_string(),
        epoch_id: epoch_id.to_string(),
        surface,
        kind,
        related_root: synthetic_root("audit-event-related", epoch_id, event_id),
        actor_commitment: synthetic_root("audit-event-actor", epoch_id, event_id),
        sequence,
        height: height.saturating_sub(9_u64.saturating_sub(sequence)),
    })
    .collect()
}

fn devnet_findings(epoch_id: &str, height: u64) -> Vec<AuditFinding> {
    [
        (
            "finding-shielded-asset-info",
            PrivacySurface::ShieldedAsset,
            InvariantKind::ReceiptUniqueness,
            FindingStatus::Informational,
            1,
        ),
        (
            "finding-monero-viewkey-warning",
            PrivacySurface::MoneroViewKey,
            InvariantKind::DisclosureScopeBounded,
            FindingStatus::Warning,
            2,
        ),
        (
            "finding-private-contract-remediated",
            PrivacySurface::PrivateContract,
            InvariantKind::RedactionRootAnchored,
            FindingStatus::Remediated,
            2,
        ),
        (
            "finding-oracle-action-required",
            PrivacySurface::OracleDisclosure,
            InvariantKind::OraclePayloadMinimized,
            FindingStatus::ActionRequired,
            3,
        ),
    ]
    .into_iter()
    .map(
        |(finding_id, surface, invariant, status, severity)| AuditFinding {
            finding_id: finding_id.to_string(),
            epoch_id: epoch_id.to_string(),
            surface,
            invariant,
            status,
            severity,
            evidence_root: synthetic_root("finding-evidence", epoch_id, finding_id),
            redacted_summary_root: synthetic_root("finding-redacted-summary", epoch_id, finding_id),
            remediation_commitment: synthetic_root("finding-remediation", epoch_id, finding_id),
            opened_at_height: height.saturating_sub(12),
            due_at_height: height + 144,
        },
    )
    .collect()
}

fn synthetic_root(domain: &str, left: &str, right: &str) -> String {
    domain_hash(
        "PRIVACY-INVARIANT-AUDIT-TRAIL-SYNTHETIC-ROOT",
        &[
            HashPart::Str(domain),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivacyInvariantAuditTrailResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_non_zero(value: u64, label: &str) -> PrivacyInvariantAuditTrailResult<()> {
    if value == 0 {
        Err(format!("{label} must be non-zero"))
    } else {
        Ok(())
    }
}

fn ensure_unique<'a, I>(values: I, label: &str) -> PrivacyInvariantAuditTrailResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{label} must be unique: {value}"));
        }
    }
    Ok(())
}
