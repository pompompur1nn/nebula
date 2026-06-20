use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroViewkeySelectiveDisclosureAuditorResult<T> = Result<T, String>;

pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION: &str =
    "nebula-monero-viewkey-selective-disclosure-auditor-v1";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_HEIGHT: u64 = 312;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_CAPSULE_SCHEME: &str =
    "viewkey-capsule-xof-aead-v1";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_RECEIPT_SCHEME: &str =
    "compliance-safe-redacted-receipt-v1";
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_WINDOW_BLOCKS: u64 = 720;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_GRACE_BLOCKS: u64 = 36;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 5;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MIN_AUDITOR_COUNT: u16 = 3;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 10_000;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MAX_TICKET_SCOPE_UNITS: u64 = 2_500;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_SPONSOR_UNIT_PRICE: u64 = 125;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_SPONSOR_BUDGET: u64 = 2_000_000;
pub const MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_RETENTION_BLOCKS: u64 = 17_280;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScopeKind {
    ReserveProof,
    WithdrawalSupport,
    LawfulAudit,
    TaxLotSummary,
    IncidentResponse,
    UserExport,
}

impl DisclosureScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveProof => "reserve_proof",
            Self::WithdrawalSupport => "withdrawal_support",
            Self::LawfulAudit => "lawful_audit",
            Self::TaxLotSummary => "tax_lot_summary",
            Self::IncidentResponse => "incident_response",
            Self::UserExport => "user_export",
        }
    }

    pub fn default_budget_units(self) -> u64 {
        match self {
            Self::ReserveProof => 900,
            Self::WithdrawalSupport => 650,
            Self::LawfulAudit => 1_600,
            Self::TaxLotSummary => 1_200,
            Self::IncidentResponse => 2_000,
            Self::UserExport => 400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureTicketStatus {
    Draft,
    Authorized,
    CapsulePosted,
    CommitteeAccepted,
    Proving,
    Satisfied,
    Revoked,
    Expired,
    Disputed,
}

impl DisclosureTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Authorized => "authorized",
            Self::CapsulePosted => "capsule_posted",
            Self::CommitteeAccepted => "committee_accepted",
            Self::Proving => "proving",
            Self::Satisfied => "satisfied",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::Authorized
                | Self::CapsulePosted
                | Self::CommitteeAccepted
                | Self::Proving
                | Self::Disputed
        )
    }

    pub fn accepts_capsule(self) -> bool {
        matches!(self, Self::Authorized | Self::CapsulePosted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleStatus {
    Sealed,
    Assigned,
    OpenedByCommittee,
    ReceiptIssued,
    Revoked,
    Expired,
}

impl CapsuleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Assigned => "assigned",
            Self::OpenedByCommittee => "opened_by_committee",
            Self::ReceiptIssued => "receipt_issued",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Assigned | Self::OpenedByCommittee
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorStatus {
    Pending,
    Active,
    Suspended,
    Rotating,
    Retired,
}

impl AuditorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
        }
    }

    pub fn can_serve(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWindowStatus {
    Scheduled,
    Open,
    Submitted,
    Verified,
    Challenged,
    Failed,
    Expired,
}

impl ProofWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_complete(self) -> bool {
        matches!(self, Self::Submitted | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    Consumed,
    Exhausted,
    Frozen,
    Revoked,
}

impl BudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Announced,
    Effective,
    Challenged,
    Finalized,
    Cancelled,
}

impl RevocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Effective => "effective",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn blocks_use(self) -> bool {
        matches!(self, Self::Effective | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Issued,
    Anchored,
    Superseded,
    Withdrawn,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Issued => "issued",
            Self::Anchored => "anchored",
            Self::Superseded => "superseded",
            Self::Withdrawn => "withdrawn",
        }
    }

    pub fn is_public(self) -> bool {
        matches!(self, Self::Issued | Self::Anchored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Rebalanced,
    Exhausted,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Rebalanced => "rebalanced",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Offered | Self::Reserved | Self::Applied | Self::Rebalanced
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Config,
    Auditor,
    Committee,
    DisclosureTicket,
    ViewkeyCapsule,
    ProofWindow,
    PrivacyBudget,
    Revocation,
    ComplianceReceipt,
    Sponsorship,
    StateRoot,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Auditor => "auditor",
            Self::Committee => "committee",
            Self::DisclosureTicket => "disclosure_ticket",
            Self::ViewkeyCapsule => "viewkey_capsule",
            Self::ProofWindow => "proof_window",
            Self::PrivacyBudget => "privacy_budget",
            Self::Revocation => "revocation",
            Self::ComplianceReceipt => "compliance_receipt",
            Self::Sponsorship => "sponsorship",
            Self::StateRoot => "state_root",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub pq_kem_scheme: String,
    pub pq_signature_scheme: String,
    pub capsule_scheme: String,
    pub receipt_scheme: String,
    pub default_window_blocks: u64,
    pub grace_blocks: u64,
    pub retention_blocks: u64,
    pub min_committee_weight: u64,
    pub min_auditor_count: u16,
    pub privacy_budget_epoch_blocks: u64,
    pub default_privacy_budget_units: u64,
    pub max_ticket_scope_units: u64,
    pub sponsor_unit_price_piconero: u64,
    pub sponsor_budget_piconero: u64,
    pub created_at_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        let config_id = stable_id(
            "MVSD-CONFIG-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION),
                HashPart::Str(MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_NETWORK),
            ],
        );
        Self {
            config_id,
            protocol_version: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION
                .to_string(),
            monero_network: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_FEE_ASSET_ID
                .to_string(),
            pq_kem_scheme: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PQ_KEM_SCHEME.to_string(),
            pq_signature_scheme: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PQ_SIGNATURE_SCHEME
                .to_string(),
            capsule_scheme: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_CAPSULE_SCHEME.to_string(),
            receipt_scheme: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_RECEIPT_SCHEME.to_string(),
            default_window_blocks:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_WINDOW_BLOCKS,
            grace_blocks: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_GRACE_BLOCKS,
            retention_blocks: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_RETENTION_BLOCKS,
            min_committee_weight:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MIN_COMMITTEE_WEIGHT,
            min_auditor_count:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MIN_AUDITOR_COUNT,
            privacy_budget_epoch_blocks: 1_440,
            default_privacy_budget_units:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_PRIVACY_BUDGET_UNITS,
            max_ticket_scope_units:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_MAX_TICKET_SCOPE_UNITS,
            sponsor_unit_price_piconero:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_SPONSOR_UNIT_PRICE,
            sponsor_budget_piconero:
                MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEFAULT_SPONSOR_BUDGET,
            created_at_height: MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("config_id", &self.config_id)?;
        if self.protocol_version != MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION {
            return Err("config protocol_version mismatch".to_string());
        }
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("pq_kem_scheme", &self.pq_kem_scheme)?;
        ensure_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("capsule_scheme", &self.capsule_scheme)?;
        ensure_non_empty("receipt_scheme", &self.receipt_scheme)?;
        ensure_positive("default_window_blocks", self.default_window_blocks)?;
        ensure_positive("retention_blocks", self.retention_blocks)?;
        ensure_positive("min_committee_weight", self.min_committee_weight)?;
        ensure_positive("min_auditor_count", self.min_auditor_count as u64)?;
        ensure_positive(
            "privacy_budget_epoch_blocks",
            self.privacy_budget_epoch_blocks,
        )?;
        ensure_positive(
            "default_privacy_budget_units",
            self.default_privacy_budget_units,
        )?;
        ensure_positive("max_ticket_scope_units", self.max_ticket_scope_units)?;
        ensure_positive(
            "sponsor_unit_price_piconero",
            self.sponsor_unit_price_piconero,
        )?;
        if self.max_ticket_scope_units > self.default_privacy_budget_units {
            return Err("max_ticket_scope_units exceeds default_privacy_budget_units".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::Config.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "config_id": self.config_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_kem_scheme": self.pq_kem_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "capsule_scheme": self.capsule_scheme,
            "receipt_scheme": self.receipt_scheme,
            "default_window_blocks": self.default_window_blocks,
            "grace_blocks": self.grace_blocks,
            "retention_blocks": self.retention_blocks,
            "min_committee_weight": self.min_committee_weight,
            "min_auditor_count": self.min_auditor_count,
            "privacy_budget_epoch_blocks": self.privacy_budget_epoch_blocks,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "max_ticket_scope_units": self.max_ticket_scope_units,
            "sponsor_unit_price_piconero": self.sponsor_unit_price_piconero,
            "sponsor_budget_piconero": self.sponsor_budget_piconero,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auditor {
    pub auditor_id: String,
    pub operator_commitment: String,
    pub role: String,
    pub status: AuditorStatus,
    pub committee_weight: u64,
    pub pq_public_key_root: String,
    pub disclosure_policy_root: String,
    pub jurisdiction_commitment: String,
    pub stake_commitment: String,
    pub joined_at_height: u64,
    pub last_heartbeat_height: u64,
}

impl Auditor {
    pub fn new(
        label: &str,
        role: &str,
        committee_weight: u64,
        joined_at_height: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ensure_non_empty("auditor label", label)?;
        ensure_non_empty("auditor role", role)?;
        ensure_positive("committee_weight", committee_weight)?;
        let operator_commitment = commitment_for("MVSD-AUDITOR-OPERATOR", label);
        let pq_public_key_root = commitment_for("MVSD-AUDITOR-PQ-PUBLIC-KEY", label);
        let disclosure_policy_root = commitment_for("MVSD-AUDITOR-DISCLOSURE-POLICY", role);
        let jurisdiction_commitment = commitment_for("MVSD-AUDITOR-JURISDICTION", label);
        let stake_commitment = commitment_for("MVSD-AUDITOR-STAKE", label);
        let auditor_id = stable_id(
            "MVSD-AUDITOR-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(role),
                HashPart::Str(&operator_commitment),
            ],
        );
        Ok(Self {
            auditor_id,
            operator_commitment,
            role: role.to_string(),
            status: AuditorStatus::Active,
            committee_weight,
            pq_public_key_root,
            disclosure_policy_root,
            jurisdiction_commitment,
            stake_commitment,
            joined_at_height,
            last_heartbeat_height: joined_at_height,
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("auditor_id", &self.auditor_id)?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("role", &self.role)?;
        ensure_positive("committee_weight", self.committee_weight)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_non_empty("jurisdiction_commitment", &self.jurisdiction_commitment)?;
        ensure_non_empty("stake_commitment", &self.stake_commitment)?;
        if self.last_heartbeat_height < self.joined_at_height {
            return Err(format!(
                "auditor {} heartbeat predates join",
                self.auditor_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::Auditor.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "auditor_id": self.auditor_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role,
            "status": self.status.as_str(),
            "committee_weight": self.committee_weight,
            "pq_public_key_root": self.pq_public_key_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "jurisdiction_commitment": self.jurisdiction_commitment,
            "stake_commitment": self.stake_commitment,
            "joined_at_height": self.joined_at_height,
            "last_heartbeat_height": self.last_heartbeat_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditorCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub member_ids: BTreeSet<String>,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub acceptance_root: String,
    pub scope_allowlist_root: String,
    pub formed_at_height: u64,
    pub expires_at_height: u64,
}

impl AuditorCommittee {
    pub fn new(
        epoch: u64,
        member_ids: BTreeSet<String>,
        threshold_weight: u64,
        total_weight: u64,
        scope_allowlist_root: String,
        formed_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        if member_ids.is_empty() {
            return Err("committee member_ids cannot be empty".to_string());
        }
        ensure_positive("threshold_weight", threshold_weight)?;
        ensure_positive("total_weight", total_weight)?;
        if threshold_weight > total_weight {
            return Err("committee threshold_weight exceeds total_weight".to_string());
        }
        if expires_at_height <= formed_at_height {
            return Err("committee expires_at_height must exceed formed_at_height".to_string());
        }
        let member_root = string_set_root("MVSD-COMMITTEE-MEMBER", &member_ids);
        let acceptance_root = stable_id(
            "MVSD-COMMITTEE-ACCEPTANCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(epoch as i128),
                HashPart::Str(&member_root),
                HashPart::Int(threshold_weight as i128),
            ],
        );
        let committee_id = stable_id(
            "MVSD-COMMITTEE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(epoch as i128),
                HashPart::Str(&member_root),
                HashPart::Str(&acceptance_root),
            ],
        );
        Ok(Self {
            committee_id,
            epoch,
            member_ids,
            threshold_weight,
            total_weight,
            acceptance_root,
            scope_allowlist_root,
            formed_at_height,
            expires_at_height,
        })
    }

    pub fn validate(
        &self,
        auditors: &BTreeMap<String, Auditor>,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_positive("committee threshold_weight", self.threshold_weight)?;
        ensure_positive("committee total_weight", self.total_weight)?;
        ensure_non_empty("acceptance_root", &self.acceptance_root)?;
        ensure_non_empty("scope_allowlist_root", &self.scope_allowlist_root)?;
        if self.member_ids.is_empty() {
            return Err(format!("committee {} has no members", self.committee_id));
        }
        if self.threshold_weight > self.total_weight {
            return Err(format!(
                "committee {} threshold exceeds total weight",
                self.committee_id
            ));
        }
        let mut computed_weight = 0_u64;
        for member_id in &self.member_ids {
            let auditor = auditors.get(member_id).ok_or_else(|| {
                format!(
                    "committee {} references missing auditor {}",
                    self.committee_id, member_id
                )
            })?;
            if !auditor.status.can_serve() {
                return Err(format!(
                    "committee {} includes inactive auditor",
                    self.committee_id
                ));
            }
            computed_weight = computed_weight.saturating_add(auditor.committee_weight);
        }
        if computed_weight != self.total_weight {
            return Err(format!(
                "committee {} total_weight does not match auditors",
                self.committee_id
            ));
        }
        if self.expires_at_height <= self.formed_at_height {
            return Err(format!(
                "committee {} has invalid height range",
                self.committee_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::Committee.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "member_ids": sorted_strings(&self.member_ids),
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "acceptance_root": self.acceptance_root,
            "scope_allowlist_root": self.scope_allowlist_root,
            "formed_at_height": self.formed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureTicket {
    pub ticket_id: String,
    pub subject_commitment: String,
    pub requester_commitment: String,
    pub scope_kind: DisclosureScopeKind,
    pub scope_commitment_root: String,
    pub requested_budget_units: u64,
    pub authorized_budget_units: u64,
    pub committee_id: String,
    pub capsule_id: String,
    pub window_id: String,
    pub status: DisclosureTicketStatus,
    pub policy_root: String,
    pub consent_nullifier: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl DisclosureTicket {
    pub fn new(
        subject_label: &str,
        requester_label: &str,
        scope_kind: DisclosureScopeKind,
        committee_id: &str,
        created_at_height: u64,
        expires_at_height: u64,
        max_ticket_scope_units: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ensure_non_empty("subject_label", subject_label)?;
        ensure_non_empty("requester_label", requester_label)?;
        ensure_non_empty("committee_id", committee_id)?;
        if expires_at_height <= created_at_height {
            return Err("ticket expires_at_height must exceed created_at_height".to_string());
        }
        let requested_budget_units = scope_kind.default_budget_units();
        if requested_budget_units > max_ticket_scope_units {
            return Err("ticket requested budget exceeds configured maximum".to_string());
        }
        let subject_commitment = commitment_for("MVSD-TICKET-SUBJECT", subject_label);
        let requester_commitment = commitment_for("MVSD-TICKET-REQUESTER", requester_label);
        let scope_commitment_root = stable_id(
            "MVSD-TICKET-SCOPE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(scope_kind.as_str()),
                HashPart::Str(&subject_commitment),
                HashPart::Str(&requester_commitment),
            ],
        );
        let consent_nullifier = stable_id(
            "MVSD-TICKET-CONSENT-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&subject_commitment),
                HashPart::Str(scope_kind.as_str()),
                HashPart::Int(created_at_height as i128),
            ],
        );
        let policy_root = stable_id(
            "MVSD-TICKET-POLICY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(scope_kind.as_str()),
                HashPart::Str(&scope_commitment_root),
            ],
        );
        let ticket_id = stable_id(
            "MVSD-TICKET-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&subject_commitment),
                HashPart::Str(&requester_commitment),
                HashPart::Str(&scope_commitment_root),
                HashPart::Str(committee_id),
                HashPart::Int(created_at_height as i128),
            ],
        );
        let capsule_id = stable_id(
            "MVSD-TICKET-CAPSULE-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&ticket_id)],
        );
        let window_id = stable_id(
            "MVSD-TICKET-WINDOW-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&ticket_id)],
        );
        Ok(Self {
            ticket_id,
            subject_commitment,
            requester_commitment,
            scope_kind,
            scope_commitment_root,
            requested_budget_units,
            authorized_budget_units: requested_budget_units,
            committee_id: committee_id.to_string(),
            capsule_id,
            window_id,
            status: DisclosureTicketStatus::Authorized,
            policy_root,
            consent_nullifier,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("subject_commitment", &self.subject_commitment)?;
        ensure_non_empty("requester_commitment", &self.requester_commitment)?;
        ensure_non_empty("scope_commitment_root", &self.scope_commitment_root)?;
        ensure_positive("requested_budget_units", self.requested_budget_units)?;
        ensure_positive("authorized_budget_units", self.authorized_budget_units)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("capsule_id", &self.capsule_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("policy_root", &self.policy_root)?;
        ensure_non_empty("consent_nullifier", &self.consent_nullifier)?;
        if self.authorized_budget_units > self.requested_budget_units {
            return Err(format!("ticket {} over-authorized budget", self.ticket_id));
        }
        if self.expires_at_height <= self.created_at_height {
            return Err(format!(
                "ticket {} has invalid height range",
                self.ticket_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::DisclosureTicket.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "subject_commitment": self.subject_commitment,
            "requester_commitment": self.requester_commitment,
            "scope_kind": self.scope_kind.as_str(),
            "scope_commitment_root": self.scope_commitment_root,
            "requested_budget_units": self.requested_budget_units,
            "authorized_budget_units": self.authorized_budget_units,
            "committee_id": self.committee_id,
            "capsule_id": self.capsule_id,
            "window_id": self.window_id,
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "consent_nullifier": self.consent_nullifier,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedViewkeyCapsule {
    pub capsule_id: String,
    pub ticket_id: String,
    pub owner_viewkey_commitment: String,
    pub encrypted_viewkey_root: String,
    pub committee_recipient_root: String,
    pub aead_associated_data_root: String,
    pub capsule_nonce_commitment: String,
    pub status: CapsuleStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedViewkeyCapsule {
    pub fn for_ticket(
        ticket: &DisclosureTicket,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ticket.validate()?;
        let owner_viewkey_commitment = stable_id(
            "MVSD-CAPSULE-OWNER-VIEWKEY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.subject_commitment),
                HashPart::Str(&ticket.scope_commitment_root),
            ],
        );
        let encrypted_viewkey_root = stable_id(
            "MVSD-CAPSULE-ENCRYPTED-VIEWKEY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&owner_viewkey_commitment),
            ],
        );
        let committee_recipient_root = stable_id(
            "MVSD-CAPSULE-COMMITTEE-RECIPIENTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.committee_id),
                HashPart::Str(&ticket.ticket_id),
            ],
        );
        let aead_associated_data_root = stable_id(
            "MVSD-CAPSULE-AAD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&ticket.policy_root),
                HashPart::Str(&ticket.consent_nullifier),
            ],
        );
        let capsule_nonce_commitment = stable_id(
            "MVSD-CAPSULE-NONCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.capsule_id),
                HashPart::Int(ticket.created_at_height as i128),
            ],
        );
        Ok(Self {
            capsule_id: ticket.capsule_id.clone(),
            ticket_id: ticket.ticket_id.clone(),
            owner_viewkey_commitment,
            encrypted_viewkey_root,
            committee_recipient_root,
            aead_associated_data_root,
            capsule_nonce_commitment,
            status: CapsuleStatus::Assigned,
            posted_at_height: ticket.created_at_height,
            expires_at_height: ticket.expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("capsule_id", &self.capsule_id)?;
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("owner_viewkey_commitment", &self.owner_viewkey_commitment)?;
        ensure_non_empty("encrypted_viewkey_root", &self.encrypted_viewkey_root)?;
        ensure_non_empty("committee_recipient_root", &self.committee_recipient_root)?;
        ensure_non_empty("aead_associated_data_root", &self.aead_associated_data_root)?;
        ensure_non_empty("capsule_nonce_commitment", &self.capsule_nonce_commitment)?;
        if self.expires_at_height <= self.posted_at_height {
            return Err(format!(
                "capsule {} has invalid height range",
                self.capsule_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::ViewkeyCapsule.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "capsule_id": self.capsule_id,
            "ticket_id": self.ticket_id,
            "owner_viewkey_commitment": self.owner_viewkey_commitment,
            "encrypted_viewkey_root": self.encrypted_viewkey_root,
            "committee_recipient_root": self.committee_recipient_root,
            "aead_associated_data_root": self.aead_associated_data_root,
            "capsule_nonce_commitment": self.capsule_nonce_commitment,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfViewWindow {
    pub window_id: String,
    pub ticket_id: String,
    pub capsule_id: String,
    pub committee_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub challenge_deadline_height: u64,
    pub scan_cursor_commitment: String,
    pub output_set_root: String,
    pub proof_transcript_root: String,
    pub status: ProofWindowStatus,
}

impl ProofOfViewWindow {
    pub fn for_ticket(
        ticket: &DisclosureTicket,
        config: &Config,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ticket.validate()?;
        config.validate()?;
        let start_height = ticket.created_at_height;
        let end_height = start_height.saturating_add(config.default_window_blocks);
        let challenge_deadline_height = end_height.saturating_add(config.grace_blocks);
        let scan_cursor_commitment = stable_id(
            "MVSD-WINDOW-SCAN-CURSOR",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Int(start_height as i128),
                HashPart::Int(end_height as i128),
            ],
        );
        let output_set_root = stable_id(
            "MVSD-WINDOW-OUTPUT-SET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.scope_commitment_root),
                HashPart::Str(&scan_cursor_commitment),
            ],
        );
        let proof_transcript_root = stable_id(
            "MVSD-WINDOW-PROOF-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&output_set_root),
            ],
        );
        Ok(Self {
            window_id: ticket.window_id.clone(),
            ticket_id: ticket.ticket_id.clone(),
            capsule_id: ticket.capsule_id.clone(),
            committee_id: ticket.committee_id.clone(),
            start_height,
            end_height,
            challenge_deadline_height,
            scan_cursor_commitment,
            output_set_root,
            proof_transcript_root,
            status: ProofWindowStatus::Open,
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("capsule_id", &self.capsule_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("scan_cursor_commitment", &self.scan_cursor_commitment)?;
        ensure_non_empty("output_set_root", &self.output_set_root)?;
        ensure_non_empty("proof_transcript_root", &self.proof_transcript_root)?;
        if self.end_height <= self.start_height {
            return Err(format!("proof window {} has invalid range", self.window_id));
        }
        if self.challenge_deadline_height < self.end_height {
            return Err(format!(
                "proof window {} challenge deadline predates end",
                self.window_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::ProofWindow.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "ticket_id": self.ticket_id,
            "capsule_id": self.capsule_id,
            "committee_id": self.committee_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "scan_cursor_commitment": self.scan_cursor_commitment,
            "output_set_root": self.output_set_root,
            "proof_transcript_root": self.proof_transcript_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccount {
    pub account_id: String,
    pub subject_commitment: String,
    pub epoch: u64,
    pub allowance_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub ticket_ids: BTreeSet<String>,
    pub status: BudgetStatus,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl PrivacyBudgetAccount {
    pub fn new(
        subject_commitment: &str,
        epoch: u64,
        allowance_units: u64,
        opened_at_height: u64,
        closes_at_height: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ensure_non_empty("subject_commitment", subject_commitment)?;
        ensure_positive("allowance_units", allowance_units)?;
        if closes_at_height <= opened_at_height {
            return Err("budget closes_at_height must exceed opened_at_height".to_string());
        }
        let account_id = stable_id(
            "MVSD-BUDGET-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(subject_commitment),
                HashPart::Int(epoch as i128),
            ],
        );
        Ok(Self {
            account_id,
            subject_commitment: subject_commitment.to_string(),
            epoch,
            allowance_units,
            reserved_units: 0,
            consumed_units: 0,
            ticket_ids: BTreeSet::new(),
            status: BudgetStatus::Open,
            opened_at_height,
            closes_at_height,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.allowance_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn reserve_ticket(
        &mut self,
        ticket: &DisclosureTicket,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ticket.validate()?;
        if !self.status.spendable() {
            return Err(format!("budget {} is not spendable", self.account_id));
        }
        if self.subject_commitment != ticket.subject_commitment {
            return Err(format!("budget {} subject mismatch", self.account_id));
        }
        if ticket.authorized_budget_units > self.available_units() {
            return Err(format!("budget {} has insufficient units", self.account_id));
        }
        self.reserved_units = self
            .reserved_units
            .saturating_add(ticket.authorized_budget_units);
        self.ticket_ids.insert(ticket.ticket_id.clone());
        if self.available_units() == 0 {
            self.status = BudgetStatus::Exhausted;
        } else {
            self.status = BudgetStatus::Reserved;
        }
        Ok(())
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("subject_commitment", &self.subject_commitment)?;
        ensure_positive("allowance_units", self.allowance_units)?;
        if self.reserved_units.saturating_add(self.consumed_units) > self.allowance_units {
            return Err(format!("budget {} over spent", self.account_id));
        }
        if self.closes_at_height <= self.opened_at_height {
            return Err(format!(
                "budget {} has invalid height range",
                self.account_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::PrivacyBudget.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "subject_commitment": self.subject_commitment,
            "epoch": self.epoch,
            "allowance_units": self.allowance_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "ticket_ids": sorted_strings(&self.ticket_ids),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationNullifier {
    pub revocation_id: String,
    pub ticket_id: String,
    pub capsule_id: String,
    pub nullifier: String,
    pub reason_commitment: String,
    pub revoker_commitment: String,
    pub evidence_root: String,
    pub status: RevocationStatus,
    pub announced_at_height: u64,
    pub effective_at_height: u64,
}

impl RevocationNullifier {
    pub fn for_ticket(
        ticket: &DisclosureTicket,
        reason_label: &str,
        revoker_label: &str,
        announced_at_height: u64,
        grace_blocks: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ticket.validate()?;
        ensure_non_empty("reason_label", reason_label)?;
        ensure_non_empty("revoker_label", revoker_label)?;
        let reason_commitment = commitment_for("MVSD-REVOCATION-REASON", reason_label);
        let revoker_commitment = commitment_for("MVSD-REVOCATION-REVOKER", revoker_label);
        let nullifier = stable_id(
            "MVSD-REVOCATION-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&ticket.capsule_id),
                HashPart::Str(&reason_commitment),
            ],
        );
        let revocation_id = stable_id(
            "MVSD-REVOCATION-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&nullifier)],
        );
        let evidence_root = stable_id(
            "MVSD-REVOCATION-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.policy_root),
                HashPart::Str(&revoker_commitment),
            ],
        );
        Ok(Self {
            revocation_id,
            ticket_id: ticket.ticket_id.clone(),
            capsule_id: ticket.capsule_id.clone(),
            nullifier,
            reason_commitment,
            revoker_commitment,
            evidence_root,
            status: RevocationStatus::Announced,
            announced_at_height,
            effective_at_height: announced_at_height.saturating_add(grace_blocks),
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("revocation_id", &self.revocation_id)?;
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("capsule_id", &self.capsule_id)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_non_empty("reason_commitment", &self.reason_commitment)?;
        ensure_non_empty("revoker_commitment", &self.revoker_commitment)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        if self.effective_at_height < self.announced_at_height {
            return Err(format!(
                "revocation {} effective height predates announcement",
                self.revocation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::Revocation.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "revocation_id": self.revocation_id,
            "ticket_id": self.ticket_id,
            "capsule_id": self.capsule_id,
            "nullifier": self.nullifier,
            "reason_commitment": self.reason_commitment,
            "revoker_commitment": self.revoker_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "announced_at_height": self.announced_at_height,
            "effective_at_height": self.effective_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceSafeReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub window_id: String,
    pub committee_id: String,
    pub redacted_subject_root: String,
    pub disclosed_field_root: String,
    pub non_disclosure_salt_root: String,
    pub finding_root: String,
    pub receipt_nullifier: String,
    pub status: ReceiptStatus,
    pub issued_at_height: u64,
    pub retention_until_height: u64,
}

impl ComplianceSafeReceipt {
    pub fn for_window(
        ticket: &DisclosureTicket,
        window: &ProofOfViewWindow,
        retention_blocks: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ticket.validate()?;
        window.validate()?;
        if ticket.window_id != window.window_id {
            return Err("receipt ticket/window mismatch".to_string());
        }
        let redacted_subject_root = stable_id(
            "MVSD-RECEIPT-REDACTED-SUBJECT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.subject_commitment),
                HashPart::Str(&ticket.scope_commitment_root),
            ],
        );
        let disclosed_field_root = stable_id(
            "MVSD-RECEIPT-DISCLOSED-FIELDS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(ticket.scope_kind.as_str()),
                HashPart::Str(&window.output_set_root),
            ],
        );
        let non_disclosure_salt_root = stable_id(
            "MVSD-RECEIPT-NON-DISCLOSURE-SALT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&window.proof_transcript_root),
            ],
        );
        let finding_root = stable_id(
            "MVSD-RECEIPT-FINDING",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&disclosed_field_root),
                HashPart::Str(&non_disclosure_salt_root),
            ],
        );
        let receipt_nullifier = stable_id(
            "MVSD-RECEIPT-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&ticket.consent_nullifier),
                HashPart::Str(&finding_root),
            ],
        );
        let receipt_id = stable_id(
            "MVSD-RECEIPT-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&receipt_nullifier)],
        );
        Ok(Self {
            receipt_id,
            ticket_id: ticket.ticket_id.clone(),
            window_id: window.window_id.clone(),
            committee_id: window.committee_id.clone(),
            redacted_subject_root,
            disclosed_field_root,
            non_disclosure_salt_root,
            finding_root,
            receipt_nullifier,
            status: ReceiptStatus::Issued,
            issued_at_height: window.end_height,
            retention_until_height: window.end_height.saturating_add(retention_blocks),
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("redacted_subject_root", &self.redacted_subject_root)?;
        ensure_non_empty("disclosed_field_root", &self.disclosed_field_root)?;
        ensure_non_empty("non_disclosure_salt_root", &self.non_disclosure_salt_root)?;
        ensure_non_empty("finding_root", &self.finding_root)?;
        ensure_non_empty("receipt_nullifier", &self.receipt_nullifier)?;
        if self.retention_until_height < self.issued_at_height {
            return Err(format!("receipt {} has invalid retention", self.receipt_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::ComplianceReceipt.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "redacted_subject_root": self.redacted_subject_root,
            "disclosed_field_root": self.disclosed_field_root,
            "non_disclosure_salt_root": self.non_disclosure_salt_root,
            "finding_root": self.finding_root,
            "receipt_nullifier": self.receipt_nullifier,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "retention_until_height": self.retention_until_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub ticket_id: String,
    pub fee_asset_id: String,
    pub unit_price_piconero: u64,
    pub max_units: u64,
    pub reserved_piconero: u64,
    pub applied_piconero: u64,
    pub status: SponsorshipStatus,
    pub offer_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorship {
    pub fn for_ticket(
        ticket: &DisclosureTicket,
        sponsor_label: &str,
        fee_asset_id: &str,
        unit_price_piconero: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<Self> {
        ticket.validate()?;
        ensure_non_empty("sponsor_label", sponsor_label)?;
        ensure_non_empty("fee_asset_id", fee_asset_id)?;
        ensure_positive("unit_price_piconero", unit_price_piconero)?;
        if expires_at_height <= opened_at_height {
            return Err("sponsorship expires_at_height must exceed opened_at_height".to_string());
        }
        let sponsor_commitment = commitment_for("MVSD-SPONSOR", sponsor_label);
        let max_units = ticket.authorized_budget_units;
        let reserved_piconero = max_units.saturating_mul(unit_price_piconero);
        let offer_root = stable_id(
            "MVSD-SPONSOR-OFFER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&ticket.ticket_id),
                HashPart::Int(unit_price_piconero as i128),
            ],
        );
        let sponsorship_id = stable_id(
            "MVSD-SPONSORSHIP-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&offer_root)],
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            ticket_id: ticket.ticket_id.clone(),
            fee_asset_id: fee_asset_id.to_string(),
            unit_price_piconero,
            max_units,
            reserved_piconero,
            applied_piconero: 0,
            status: SponsorshipStatus::Reserved,
            offer_root,
            opened_at_height,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        ensure_non_empty("sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("unit_price_piconero", self.unit_price_piconero)?;
        ensure_positive("max_units", self.max_units)?;
        ensure_non_empty("offer_root", &self.offer_root)?;
        if self.applied_piconero > self.reserved_piconero {
            return Err(format!("sponsorship {} over-applied", self.sponsorship_id));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "sponsorship {} has invalid height range",
                self.sponsorship_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": PublicRecordKind::Sponsorship.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "ticket_id": self.ticket_id,
            "fee_asset_id": self.fee_asset_id,
            "unit_price_piconero": self.unit_price_piconero,
            "max_units": self.max_units,
            "reserved_piconero": self.reserved_piconero,
            "applied_piconero": self.applied_piconero,
            "status": self.status.as_str(),
            "offer_root": self.offer_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub auditor_root: String,
    pub committee_root: String,
    pub ticket_root: String,
    pub capsule_root: String,
    pub proof_window_root: String,
    pub privacy_budget_root: String,
    pub revocation_root: String,
    pub receipt_root: String,
    pub sponsorship_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "auditor_root": self.auditor_root,
            "committee_root": self.committee_root,
            "ticket_root": self.ticket_root,
            "capsule_root": self.capsule_root,
            "proof_window_root": self.proof_window_root,
            "privacy_budget_root": self.privacy_budget_root,
            "revocation_root": self.revocation_root,
            "receipt_root": self.receipt_root,
            "sponsorship_root": self.sponsorship_root,
            "public_event_root": self.public_event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub auditors: u64,
    pub active_auditors: u64,
    pub committees: u64,
    pub open_tickets: u64,
    pub satisfied_tickets: u64,
    pub capsules: u64,
    pub live_capsules: u64,
    pub proof_windows: u64,
    pub verified_windows: u64,
    pub privacy_budget_accounts: u64,
    pub total_privacy_allowance_units: u64,
    pub reserved_privacy_units: u64,
    pub consumed_privacy_units: u64,
    pub revocations: u64,
    pub effective_revocations: u64,
    pub receipts: u64,
    pub public_receipts: u64,
    pub sponsorships: u64,
    pub live_sponsorships: u64,
    pub reserved_sponsor_piconero: u64,
    pub applied_sponsor_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "auditors": self.auditors,
            "active_auditors": self.active_auditors,
            "committees": self.committees,
            "open_tickets": self.open_tickets,
            "satisfied_tickets": self.satisfied_tickets,
            "capsules": self.capsules,
            "live_capsules": self.live_capsules,
            "proof_windows": self.proof_windows,
            "verified_windows": self.verified_windows,
            "privacy_budget_accounts": self.privacy_budget_accounts,
            "total_privacy_allowance_units": self.total_privacy_allowance_units,
            "reserved_privacy_units": self.reserved_privacy_units,
            "consumed_privacy_units": self.consumed_privacy_units,
            "revocations": self.revocations,
            "effective_revocations": self.effective_revocations,
            "receipts": self.receipts,
            "public_receipts": self.public_receipts,
            "sponsorships": self.sponsorships,
            "live_sponsorships": self.live_sponsorships,
            "reserved_sponsor_piconero": self.reserved_sponsor_piconero,
            "applied_sponsor_piconero": self.applied_sponsor_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub auditors: BTreeMap<String, Auditor>,
    pub committees: BTreeMap<String, AuditorCommittee>,
    pub disclosure_tickets: BTreeMap<String, DisclosureTicket>,
    pub capsules: BTreeMap<String, EncryptedViewkeyCapsule>,
    pub proof_windows: BTreeMap<String, ProofOfViewWindow>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub revocations: BTreeMap<String, RevocationNullifier>,
    pub receipts: BTreeMap<String, ComplianceSafeReceipt>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub public_events: Vec<Value>,
}

impl State {
    pub fn devnet() -> MoneroViewkeySelectiveDisclosureAuditorResult<State> {
        let config = Config::devnet();
        config.validate()?;
        let height = MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_DEVNET_HEIGHT;

        let mut auditors = BTreeMap::new();
        for (label, role, weight) in [
            ("devnet-auditor-alpha", "reserve_disclosure", 2_u64),
            ("devnet-auditor-beta", "compliance_receipt", 2_u64),
            ("devnet-auditor-gamma", "privacy_budget", 2_u64),
            ("devnet-auditor-delta", "revocation", 1_u64),
        ] {
            let auditor = Auditor::new(label, role, weight, height)?;
            auditors.insert(auditor.auditor_id.clone(), auditor);
        }

        let member_ids = auditors.keys().cloned().collect::<BTreeSet<_>>();
        let total_weight = auditors.values().fold(0_u64, |acc, auditor| {
            acc.saturating_add(auditor.committee_weight)
        });
        let scope_allowlist_root = string_vec_root(
            "MVSD-DEVNET-SCOPE-ALLOWLIST",
            &[
                DisclosureScopeKind::ReserveProof.as_str().to_string(),
                DisclosureScopeKind::WithdrawalSupport.as_str().to_string(),
                DisclosureScopeKind::LawfulAudit.as_str().to_string(),
                DisclosureScopeKind::UserExport.as_str().to_string(),
            ],
        );
        let committee = AuditorCommittee::new(
            0,
            member_ids,
            config.min_committee_weight,
            total_weight,
            scope_allowlist_root,
            height,
            height.saturating_add(config.privacy_budget_epoch_blocks),
        )?;
        let committee_id = committee.committee_id.clone();
        let mut committees = BTreeMap::new();
        committees.insert(committee.committee_id.clone(), committee);

        let ticket = DisclosureTicket::new(
            "devnet-reserve-wallet",
            "devnet-compliance-desk",
            DisclosureScopeKind::ReserveProof,
            &committee_id,
            height,
            height.saturating_add(config.default_window_blocks),
            config.max_ticket_scope_units,
        )?;
        let capsule = EncryptedViewkeyCapsule::for_ticket(&ticket)?;
        let proof_window = ProofOfViewWindow::for_ticket(&ticket, &config)?;
        let receipt =
            ComplianceSafeReceipt::for_window(&ticket, &proof_window, config.retention_blocks)?;
        let sponsorship = LowFeeSponsorship::for_ticket(
            &ticket,
            "devnet-low-fee-sponsor",
            &config.fee_asset_id,
            config.sponsor_unit_price_piconero,
            height,
            height.saturating_add(config.default_window_blocks),
        )?;

        let mut budget = PrivacyBudgetAccount::new(
            &ticket.subject_commitment,
            0,
            config.default_privacy_budget_units,
            height,
            height.saturating_add(config.privacy_budget_epoch_blocks),
        )?;
        budget.reserve_ticket(&ticket)?;

        let mut disclosure_tickets = BTreeMap::new();
        disclosure_tickets.insert(ticket.ticket_id.clone(), ticket);
        let mut capsules = BTreeMap::new();
        capsules.insert(capsule.capsule_id.clone(), capsule);
        let mut proof_windows = BTreeMap::new();
        proof_windows.insert(proof_window.window_id.clone(), proof_window);
        let mut privacy_budgets = BTreeMap::new();
        privacy_budgets.insert(budget.account_id.clone(), budget);
        let mut receipts = BTreeMap::new();
        receipts.insert(receipt.receipt_id.clone(), receipt);
        let mut sponsorships = BTreeMap::new();
        sponsorships.insert(sponsorship.sponsorship_id.clone(), sponsorship);

        let mut state = State {
            height,
            config,
            auditors,
            committees,
            disclosure_tickets,
            capsules,
            proof_windows,
            privacy_budgets,
            revocations: BTreeMap::new(),
            receipts,
            sponsorships,
            public_events: Vec::new(),
        };
        state.rebuild_public_events();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        self.config.validate()?;
        if self.height < self.config.created_at_height {
            return Err("state height predates config height".to_string());
        }
        if self.auditors.is_empty() {
            return Err("state requires at least one auditor".to_string());
        }
        for (id, auditor) in &self.auditors {
            if id != &auditor.auditor_id {
                return Err(format!("auditor map key mismatch for {}", id));
            }
            auditor.validate()?;
        }
        for (id, committee) in &self.committees {
            if id != &committee.committee_id {
                return Err(format!("committee map key mismatch for {}", id));
            }
            committee.validate(&self.auditors)?;
        }
        for (id, ticket) in &self.disclosure_tickets {
            if id != &ticket.ticket_id {
                return Err(format!("ticket map key mismatch for {}", id));
            }
            ticket.validate()?;
            if ticket.authorized_budget_units > self.config.max_ticket_scope_units {
                return Err(format!("ticket {} exceeds max scope units", id));
            }
            if !self.committees.contains_key(&ticket.committee_id) {
                return Err(format!("ticket {} references missing committee", id));
            }
            if !self.capsules.contains_key(&ticket.capsule_id) {
                return Err(format!("ticket {} references missing capsule", id));
            }
            if !self.proof_windows.contains_key(&ticket.window_id) {
                return Err(format!("ticket {} references missing proof window", id));
            }
        }
        for (id, capsule) in &self.capsules {
            if id != &capsule.capsule_id {
                return Err(format!("capsule map key mismatch for {}", id));
            }
            capsule.validate()?;
            if !self.disclosure_tickets.contains_key(&capsule.ticket_id) {
                return Err(format!("capsule {} references missing ticket", id));
            }
        }
        for (id, window) in &self.proof_windows {
            if id != &window.window_id {
                return Err(format!("proof window map key mismatch for {}", id));
            }
            window.validate()?;
            if !self.disclosure_tickets.contains_key(&window.ticket_id) {
                return Err(format!("proof window {} references missing ticket", id));
            }
            if !self.capsules.contains_key(&window.capsule_id) {
                return Err(format!("proof window {} references missing capsule", id));
            }
        }
        for (id, budget) in &self.privacy_budgets {
            if id != &budget.account_id {
                return Err(format!("budget map key mismatch for {}", id));
            }
            budget.validate()?;
            for ticket_id in &budget.ticket_ids {
                if !self.disclosure_tickets.contains_key(ticket_id) {
                    return Err(format!("budget {} references missing ticket", id));
                }
            }
        }
        let mut revocation_nullifiers = BTreeSet::new();
        for (id, revocation) in &self.revocations {
            if id != &revocation.revocation_id {
                return Err(format!("revocation map key mismatch for {}", id));
            }
            revocation.validate()?;
            if !revocation_nullifiers.insert(revocation.nullifier.clone()) {
                return Err(format!(
                    "duplicate revocation nullifier {}",
                    revocation.nullifier
                ));
            }
            if !self.disclosure_tickets.contains_key(&revocation.ticket_id) {
                return Err(format!("revocation {} references missing ticket", id));
            }
        }
        let mut receipt_nullifiers = BTreeSet::new();
        for (id, receipt) in &self.receipts {
            if id != &receipt.receipt_id {
                return Err(format!("receipt map key mismatch for {}", id));
            }
            receipt.validate()?;
            if !receipt_nullifiers.insert(receipt.receipt_nullifier.clone()) {
                return Err(format!(
                    "duplicate receipt nullifier {}",
                    receipt.receipt_nullifier
                ));
            }
            if !self.disclosure_tickets.contains_key(&receipt.ticket_id) {
                return Err(format!("receipt {} references missing ticket", id));
            }
            if !self.proof_windows.contains_key(&receipt.window_id) {
                return Err(format!("receipt {} references missing proof window", id));
            }
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err(format!("sponsorship map key mismatch for {}", id));
            }
            sponsorship.validate()?;
            if !self.disclosure_tickets.contains_key(&sponsorship.ticket_id) {
                return Err(format!("sponsorship {} references missing ticket", id));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        if height < self.config.created_at_height {
            return Err("height cannot be below config creation height".to_string());
        }
        self.height = height;
        self.refresh_time_dependent_statuses();
        self.rebuild_public_events();
        self.validate()
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
        if height < self.height {
            return Err("height update cannot move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let auditor_root = map_record_root(
            "MVSD-AUDITOR-ROOT",
            self.auditors
                .values()
                .map(Auditor::public_record)
                .collect::<Vec<_>>(),
        );
        let committee_root = map_record_root(
            "MVSD-COMMITTEE-ROOT",
            self.committees
                .values()
                .map(AuditorCommittee::public_record)
                .collect::<Vec<_>>(),
        );
        let ticket_root = map_record_root(
            "MVSD-TICKET-ROOT",
            self.disclosure_tickets
                .values()
                .map(DisclosureTicket::public_record)
                .collect::<Vec<_>>(),
        );
        let capsule_root = map_record_root(
            "MVSD-CAPSULE-ROOT",
            self.capsules
                .values()
                .map(EncryptedViewkeyCapsule::public_record)
                .collect::<Vec<_>>(),
        );
        let proof_window_root = map_record_root(
            "MVSD-PROOF-WINDOW-ROOT",
            self.proof_windows
                .values()
                .map(ProofOfViewWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let privacy_budget_root = map_record_root(
            "MVSD-PRIVACY-BUDGET-ROOT",
            self.privacy_budgets
                .values()
                .map(PrivacyBudgetAccount::public_record)
                .collect::<Vec<_>>(),
        );
        let revocation_root = map_record_root(
            "MVSD-REVOCATION-ROOT",
            self.revocations
                .values()
                .map(RevocationNullifier::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = map_record_root(
            "MVSD-RECEIPT-ROOT",
            self.receipts
                .values()
                .map(ComplianceSafeReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = map_record_root(
            "MVSD-SPONSORSHIP-ROOT",
            self.sponsorships
                .values()
                .map(LowFeeSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        let public_event_root =
            map_record_root("MVSD-PUBLIC-EVENT-ROOT", self.public_events.clone());
        let state_root = domain_hash(
            "MVSD-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&auditor_root),
                HashPart::Str(&committee_root),
                HashPart::Str(&ticket_root),
                HashPart::Str(&capsule_root),
                HashPart::Str(&proof_window_root),
                HashPart::Str(&privacy_budget_root),
                HashPart::Str(&revocation_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&sponsorship_root),
                HashPart::Str(&public_event_root),
            ],
            32,
        );
        Roots {
            config_root,
            auditor_root,
            committee_root,
            ticket_root,
            capsule_root,
            proof_window_root,
            privacy_budget_root,
            revocation_root,
            receipt_root,
            sponsorship_root,
            public_event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            auditors: self.auditors.len() as u64,
            active_auditors: self
                .auditors
                .values()
                .filter(|auditor| auditor.status.can_serve())
                .count() as u64,
            committees: self.committees.len() as u64,
            open_tickets: self
                .disclosure_tickets
                .values()
                .filter(|ticket| ticket.status.is_open())
                .count() as u64,
            satisfied_tickets: self
                .disclosure_tickets
                .values()
                .filter(|ticket| ticket.status == DisclosureTicketStatus::Satisfied)
                .count() as u64,
            capsules: self.capsules.len() as u64,
            live_capsules: self
                .capsules
                .values()
                .filter(|capsule| capsule.status.is_live())
                .count() as u64,
            proof_windows: self.proof_windows.len() as u64,
            verified_windows: self
                .proof_windows
                .values()
                .filter(|window| window.status.counts_as_complete())
                .count() as u64,
            privacy_budget_accounts: self.privacy_budgets.len() as u64,
            total_privacy_allowance_units: self
                .privacy_budgets
                .values()
                .fold(0_u64, |acc, budget| {
                    acc.saturating_add(budget.allowance_units)
                }),
            reserved_privacy_units: self.privacy_budgets.values().fold(0_u64, |acc, budget| {
                acc.saturating_add(budget.reserved_units)
            }),
            consumed_privacy_units: self.privacy_budgets.values().fold(0_u64, |acc, budget| {
                acc.saturating_add(budget.consumed_units)
            }),
            revocations: self.revocations.len() as u64,
            effective_revocations: self
                .revocations
                .values()
                .filter(|revocation| revocation.status.blocks_use())
                .count() as u64,
            receipts: self.receipts.len() as u64,
            public_receipts: self
                .receipts
                .values()
                .filter(|receipt| receipt.status.is_public())
                .count() as u64,
            sponsorships: self.sponsorships.len() as u64,
            live_sponsorships: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_live())
                .count() as u64,
            reserved_sponsor_piconero: self.sponsorships.values().fold(0_u64, |acc, sponsor| {
                acc.saturating_add(sponsor.reserved_piconero)
            }),
            applied_sponsor_piconero: self.sponsorships.values().fold(0_u64, |acc, sponsor| {
                acc.saturating_add(sponsor.applied_piconero)
            }),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": PublicRecordKind::StateRoot.as_str(),
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn authorize_ticket(
        &mut self,
        subject_label: &str,
        requester_label: &str,
        scope_kind: DisclosureScopeKind,
        committee_id: &str,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<String> {
        if !self.committees.contains_key(committee_id) {
            return Err("cannot authorize ticket for missing committee".to_string());
        }
        let ticket = DisclosureTicket::new(
            subject_label,
            requester_label,
            scope_kind,
            committee_id,
            self.height,
            self.height
                .saturating_add(self.config.default_window_blocks)
                .saturating_add(self.config.grace_blocks),
            self.config.max_ticket_scope_units,
        )?;
        let ticket_id = ticket.ticket_id.clone();
        let capsule = EncryptedViewkeyCapsule::for_ticket(&ticket)?;
        let window = ProofOfViewWindow::for_ticket(&ticket, &self.config)?;
        self.disclosure_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        self.capsules.insert(capsule.capsule_id.clone(), capsule);
        self.proof_windows.insert(window.window_id.clone(), window);
        self.rebuild_public_events();
        self.validate()?;
        Ok(ticket_id)
    }

    pub fn issue_receipt(
        &mut self,
        ticket_id: &str,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<String> {
        let ticket = self
            .disclosure_tickets
            .get(ticket_id)
            .ok_or_else(|| format!("missing ticket {}", ticket_id))?
            .clone();
        let window = self
            .proof_windows
            .get(&ticket.window_id)
            .ok_or_else(|| format!("missing proof window {}", ticket.window_id))?
            .clone();
        let receipt =
            ComplianceSafeReceipt::for_window(&ticket, &window, self.config.retention_blocks)?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        if let Some(ticket_mut) = self.disclosure_tickets.get_mut(ticket_id) {
            ticket_mut.status = DisclosureTicketStatus::Satisfied;
        }
        if let Some(window_mut) = self.proof_windows.get_mut(&ticket.window_id) {
            window_mut.status = ProofWindowStatus::Verified;
        }
        if let Some(capsule_mut) = self.capsules.get_mut(&ticket.capsule_id) {
            capsule_mut.status = CapsuleStatus::ReceiptIssued;
        }
        self.rebuild_public_events();
        self.validate()?;
        Ok(receipt_id)
    }

    pub fn announce_revocation(
        &mut self,
        ticket_id: &str,
        reason_label: &str,
        revoker_label: &str,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<String> {
        let ticket = self
            .disclosure_tickets
            .get(ticket_id)
            .ok_or_else(|| format!("missing ticket {}", ticket_id))?
            .clone();
        let revocation = RevocationNullifier::for_ticket(
            &ticket,
            reason_label,
            revoker_label,
            self.height,
            self.config.grace_blocks,
        )?;
        let revocation_id = revocation.revocation_id.clone();
        self.revocations
            .insert(revocation.revocation_id.clone(), revocation);
        if let Some(ticket_mut) = self.disclosure_tickets.get_mut(ticket_id) {
            ticket_mut.status = DisclosureTicketStatus::Revoked;
        }
        if let Some(capsule_mut) = self.capsules.get_mut(&ticket.capsule_id) {
            capsule_mut.status = CapsuleStatus::Revoked;
        }
        self.rebuild_public_events();
        self.validate()?;
        Ok(revocation_id)
    }

    pub fn sponsor_ticket(
        &mut self,
        ticket_id: &str,
        sponsor_label: &str,
    ) -> MoneroViewkeySelectiveDisclosureAuditorResult<String> {
        let ticket = self
            .disclosure_tickets
            .get(ticket_id)
            .ok_or_else(|| format!("missing ticket {}", ticket_id))?
            .clone();
        let sponsorship = LowFeeSponsorship::for_ticket(
            &ticket,
            sponsor_label,
            &self.config.fee_asset_id,
            self.config.sponsor_unit_price_piconero,
            self.height,
            self.height
                .saturating_add(self.config.default_window_blocks),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        self.rebuild_public_events();
        self.validate()?;
        Ok(sponsorship_id)
    }

    fn refresh_time_dependent_statuses(&mut self) {
        for ticket in self.disclosure_tickets.values_mut() {
            if ticket.status.is_open() && self.height > ticket.expires_at_height {
                ticket.status = DisclosureTicketStatus::Expired;
            }
        }
        for capsule in self.capsules.values_mut() {
            if capsule.status.is_live() && self.height > capsule.expires_at_height {
                capsule.status = CapsuleStatus::Expired;
            }
        }
        for window in self.proof_windows.values_mut() {
            if matches!(
                window.status,
                ProofWindowStatus::Scheduled | ProofWindowStatus::Open
            ) && self.height > window.challenge_deadline_height
            {
                window.status = ProofWindowStatus::Expired;
            }
        }
        for revocation in self.revocations.values_mut() {
            if revocation.status == RevocationStatus::Announced
                && self.height >= revocation.effective_at_height
            {
                revocation.status = RevocationStatus::Effective;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.is_live() && self.height > sponsorship.expires_at_height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
    }

    fn rebuild_public_events(&mut self) {
        let mut events = Vec::new();
        events.push(public_event(
            PublicRecordKind::Config,
            &self.config.config_id,
            &self.config.root(),
            self.config.created_at_height,
            0,
        ));
        append_events(
            &mut events,
            PublicRecordKind::Auditor,
            self.auditors.values().map(|record| {
                (
                    record.auditor_id.as_str(),
                    record.root(),
                    record.joined_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::Committee,
            self.committees.values().map(|record| {
                (
                    record.committee_id.as_str(),
                    record.root(),
                    record.formed_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::DisclosureTicket,
            self.disclosure_tickets.values().map(|record| {
                (
                    record.ticket_id.as_str(),
                    record.root(),
                    record.created_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::ViewkeyCapsule,
            self.capsules.values().map(|record| {
                (
                    record.capsule_id.as_str(),
                    record.root(),
                    record.posted_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::ProofWindow,
            self.proof_windows.values().map(|record| {
                (
                    record.window_id.as_str(),
                    record.root(),
                    record.start_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::PrivacyBudget,
            self.privacy_budgets.values().map(|record| {
                (
                    record.account_id.as_str(),
                    record.root(),
                    record.opened_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::Revocation,
            self.revocations.values().map(|record| {
                (
                    record.revocation_id.as_str(),
                    record.root(),
                    record.announced_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::ComplianceReceipt,
            self.receipts.values().map(|record| {
                (
                    record.receipt_id.as_str(),
                    record.root(),
                    record.issued_at_height,
                )
            }),
        );
        append_events(
            &mut events,
            PublicRecordKind::Sponsorship,
            self.sponsorships.values().map(|record| {
                (
                    record.sponsorship_id.as_str(),
                    record.root(),
                    record.opened_at_height,
                )
            }),
        );
        self.public_events = events;
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MVSD-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> MoneroViewkeySelectiveDisclosureAuditorResult<State> {
    State::devnet()
}

fn ensure_non_empty(name: &str, value: &str) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(name: &str, value: u64) -> MoneroViewkeySelectiveDisclosureAuditorResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn commitment_for(domain: &str, label: &str) -> String {
    stable_id(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
    )
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect::<Vec<_>>()
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_vec_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    let leaves = sorted
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_record_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by_key(root_from_record);
    merkle_root(domain, &records)
}

fn public_event(
    kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> Value {
    let event_id = stable_id(
        "MVSD-PUBLIC-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
    );
    json!({
        "event_id": event_id,
        "kind": kind.as_str(),
        "chain_id": CHAIN_ID,
        "protocol_version": MONERO_VIEWKEY_SELECTIVE_DISCLOSURE_AUDITOR_PROTOCOL_VERSION,
        "subject_id": subject_id,
        "payload_root": payload_root,
        "emitted_at_height": emitted_at_height,
        "sequence": sequence,
    })
}

fn append_events<'a, I>(events: &mut Vec<Value>, kind: PublicRecordKind, items: I)
where
    I: IntoIterator<Item = (&'a str, String, u64)>,
{
    for (subject_id, root, height) in items {
        let sequence = events.len() as u64;
        events.push(public_event(kind, subject_id, &root, height, sequence));
    }
}
