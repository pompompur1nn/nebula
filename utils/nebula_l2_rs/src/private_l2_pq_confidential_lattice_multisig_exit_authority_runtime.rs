use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialLatticeMultisigExitAuthorityRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_MULTISIG_EXIT_AUTHORITY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lattice-multisig-exit-authority-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_MULTISIG_EXIT_AUTHORITY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const CHAIN_ID: &str = "nebula-private-l2-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-lattice-multisig-exit-authority-public-record-v1";
pub const COMMITTEE_SUITE: &str = "pq-lattice-exit-authority-committee-root-v1";
pub const MANDATE_SUITE: &str = "confidential-monero-exit-mandate-root-v1";
pub const ATTESTATION_SUITE: &str = "ml-dsa-slh-dsa-exit-attestation-root-v1";
pub const APPROVAL_SUITE: &str = "threshold-exit-authority-approval-root-v1";
pub const OBJECTION_SUITE: &str = "watcher-exit-objection-root-v1";
pub const SETTLEMENT_SUITE: &str = "monero-exit-settlement-window-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-exit-authority-rebate-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "exit-authority-redaction-budget-root-v1";
pub const SUMMARY_SUITE: &str = "operator-safe-exit-authority-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_monero_addresses_amounts_key_images_view_keys_spend_keys_or_notes";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 9;
pub const DEFAULT_THRESHOLD_WEIGHT: u64 = 7_000;
pub const DEFAULT_STRONG_THRESHOLD_WEIGHT: u64 = 8_500;
pub const DEFAULT_WATCHER_OBJECTION_WEIGHT: u64 = 2_500;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 2_880;
pub const DEFAULT_EMERGENCY_WINDOW_BLOCKS: u64 = 120;
pub const DEFAULT_MANDATE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_MANDATE: u64 = 128;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 50_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 18;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 65_536;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_COMMITTEES: usize = 65_536;
pub const MAX_MANDATES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_APPROVALS: usize = 2_097_152;
pub const MAX_OBJECTIONS: usize = 1_048_576;
pub const MAX_SETTLEMENT_WINDOWS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    ExitAuthority,
    EmergencyAuthority,
    LiquidityAuthority,
    WatcherAuthority,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitAuthority => "exit_authority",
            Self::EmergencyAuthority => "emergency_authority",
            Self::LiquidityAuthority => "liquidity_authority",
            Self::WatcherAuthority => "watcher_authority",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsa,
    LatticeFence,
}

impl PqScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
            Self::LatticeFence => "lattice_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Candidate,
    Active,
    Degraded,
    Frozen,
    Retired,
}

impl CommitteeStatus {
    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLane {
    RetailWithdrawal,
    LiquidityProvider,
    DefiSettlement,
    EmergencyEscape,
}

impl ExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailWithdrawal => "retail_withdrawal",
            Self::LiquidityProvider => "liquidity_provider",
            Self::DefiSettlement => "defi_settlement",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Draft,
    Open,
    Approved,
    Objected,
    Settling,
    Settled,
    Expired,
    Revoked,
}

impl MandateStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Revoked)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Approved => "approved",
            Self::Objected => "objected",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    MandateIntent,
    ApprovalShare,
    SettlementReady,
    WatcherOverride,
    RedactionReceipt,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MandateIntent => "mandate_intent",
            Self::ApprovalShare => "approval_share",
            Self::SettlementReady => "settlement_ready",
            Self::WatcherOverride => "watcher_override",
            Self::RedactionReceipt => "redaction_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    ThresholdMet,
    StrongThresholdMet,
    BlockedByWatcher,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ThresholdMet => "threshold_met",
            Self::StrongThresholdMet => "strong_threshold_met",
            Self::BlockedByWatcher => "blocked_by_watcher",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectionReason {
    DuplicateNullifierHint,
    DecoySetRegression,
    InvalidMandateRoot,
    SettlementWindowUnsafe,
    RebateAbuse,
    RedactionBudgetExceeded,
    OperatorSafetyHold,
}

impl ObjectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateNullifierHint => "duplicate_nullifier_hint",
            Self::DecoySetRegression => "decoy_set_regression",
            Self::InvalidMandateRoot => "invalid_mandate_root",
            Self::SettlementWindowUnsafe => "settlement_window_unsafe",
            Self::RebateAbuse => "rebate_abuse",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::OperatorSafetyHold => "operator_safety_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Scheduled,
    Open,
    Objected,
    Executable,
    Settled,
    Lapsed,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Objected => "objected",
            Self::Executable => "executable",
            Self::Settled => "settled",
            Self::Lapsed => "lapsed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Accrued,
    Paid,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Accrued => "accrued",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPurpose {
    OperatorSummary,
    WatcherEvidence,
    LowFeeReceipt,
    SettlementReceipt,
    EmergencyDisclosure,
}

impl RedactionPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorSummary => "operator_summary",
            Self::WatcherEvidence => "watcher_evidence",
            Self::LowFeeReceipt => "low_fee_receipt",
            Self::SettlementReceipt => "settlement_receipt",
            Self::EmergencyDisclosure => "emergency_disclosure",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub default_committee_size: u16,
    pub threshold_weight: u64,
    pub strong_threshold_weight: u64,
    pub watcher_objection_weight: u64,
    pub settlement_delay_blocks: u64,
    pub settlement_window_blocks: u64,
    pub emergency_window_blocks: u64,
    pub mandate_ttl_blocks: u64,
    pub max_redaction_units_per_mandate: u64,
    pub redaction_budget_units: u64,
    pub low_fee_rebate_bps: u64,
    pub min_anonymity_set: u64,
    pub require_ml_dsa: bool,
    pub require_slh_dsa: bool,
    pub require_watcher_clearance: bool,
    pub allow_emergency_fast_path: bool,
    pub privacy_boundary: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            default_committee_size: DEFAULT_COMMITTEE_SIZE,
            threshold_weight: DEFAULT_THRESHOLD_WEIGHT,
            strong_threshold_weight: DEFAULT_STRONG_THRESHOLD_WEIGHT,
            watcher_objection_weight: DEFAULT_WATCHER_OBJECTION_WEIGHT,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            emergency_window_blocks: DEFAULT_EMERGENCY_WINDOW_BLOCKS,
            mandate_ttl_blocks: DEFAULT_MANDATE_TTL_BLOCKS,
            max_redaction_units_per_mandate: DEFAULT_MAX_REDACTION_UNITS_PER_MANDATE,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            require_ml_dsa: true,
            require_slh_dsa: true,
            require_watcher_clearance: true,
            allow_emergency_fast_path: true,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.threshold_weight == 0 || self.threshold_weight > MAX_BPS {
            return Err("threshold weight outside basis point range".to_string());
        }
        if self.strong_threshold_weight < self.threshold_weight
            || self.strong_threshold_weight > MAX_BPS
        {
            return Err("strong threshold must be within range and at least threshold".to_string());
        }
        if self.watcher_objection_weight > MAX_BPS {
            return Err("watcher objection weight outside basis point range".to_string());
        }
        if self.low_fee_rebate_bps > MAX_BPS {
            return Err("low fee rebate outside basis point range".to_string());
        }
        if self.settlement_window_blocks <= self.settlement_delay_blocks {
            return Err("settlement window must exceed settlement delay".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "public_record_suite": self.public_record_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_committee_size": self.default_committee_size,
            "threshold_weight": self.threshold_weight,
            "strong_threshold_weight": self.strong_threshold_weight,
            "watcher_objection_weight": self.watcher_objection_weight,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "emergency_window_blocks": self.emergency_window_blocks,
            "mandate_ttl_blocks": self.mandate_ttl_blocks,
            "max_redaction_units_per_mandate": self.max_redaction_units_per_mandate,
            "redaction_budget_units": self.redaction_budget_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_anonymity_set": self.min_anonymity_set,
            "require_ml_dsa": self.require_ml_dsa,
            "require_slh_dsa": self.require_slh_dsa,
            "require_watcher_clearance": self.require_watcher_clearance,
            "allow_emergency_fast_path": self.allow_emergency_fast_path,
            "privacy_boundary": self.privacy_boundary,
        })
    }

    pub fn root(&self) -> String {
        root_from_value("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub committees: u64,
    pub active_committees: u64,
    pub mandates: u64,
    pub open_mandates: u64,
    pub approved_mandates: u64,
    pub objected_mandates: u64,
    pub settled_mandates: u64,
    pub attestations: u64,
    pub ml_dsa_attestations: u64,
    pub slh_dsa_attestations: u64,
    pub approvals: u64,
    pub strong_approvals: u64,
    pub objections: u64,
    pub settlement_windows: u64,
    pub executable_windows: u64,
    pub low_fee_rebates: u64,
    pub paid_rebates: u64,
    pub redaction_budgets: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub operator_summaries: u64,
    pub emergency_fast_paths: u64,
}

impl Counters {
    pub fn recompute(state: &State) -> Self {
        let mut counters = Self::default();
        counters.committees = state.committees.len() as u64;
        counters.active_committees = state
            .committees
            .values()
            .filter(|committee| committee.status.can_authorize())
            .count() as u64;
        counters.mandates = state.mandates.len() as u64;
        counters.open_mandates = state
            .mandates
            .values()
            .filter(|mandate| mandate.status == MandateStatus::Open)
            .count() as u64;
        counters.approved_mandates = state
            .mandates
            .values()
            .filter(|mandate| {
                matches!(
                    mandate.status,
                    MandateStatus::Approved | MandateStatus::Settling | MandateStatus::Settled
                )
            })
            .count() as u64;
        counters.objected_mandates = state
            .mandates
            .values()
            .filter(|mandate| mandate.status == MandateStatus::Objected)
            .count() as u64;
        counters.settled_mandates = state
            .mandates
            .values()
            .filter(|mandate| mandate.status == MandateStatus::Settled)
            .count() as u64;
        counters.attestations = state.attestations.len() as u64;
        counters.ml_dsa_attestations = state
            .attestations
            .values()
            .filter(|attestation| attestation.scheme == PqScheme::MlDsa87)
            .count() as u64;
        counters.slh_dsa_attestations = state
            .attestations
            .values()
            .filter(|attestation| attestation.scheme == PqScheme::SlhDsaShake256f)
            .count() as u64;
        counters.approvals = state.approvals.len() as u64;
        counters.strong_approvals = state
            .approvals
            .values()
            .filter(|approval| approval.status == ApprovalStatus::StrongThresholdMet)
            .count() as u64;
        counters.objections = state.objections.len() as u64;
        counters.settlement_windows = state.settlement_windows.len() as u64;
        counters.executable_windows = state
            .settlement_windows
            .values()
            .filter(|window| window.status == WindowStatus::Executable)
            .count() as u64;
        counters.low_fee_rebates = state.low_fee_rebates.len() as u64;
        counters.paid_rebates = state
            .low_fee_rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Paid)
            .count() as u64;
        counters.redaction_budgets = state.redaction_budgets.len() as u64;
        counters.redaction_units_reserved = state
            .redaction_budgets
            .values()
            .map(|budget| budget.reserved_units)
            .sum();
        counters.redaction_units_spent = state
            .redaction_budgets
            .values()
            .map(|budget| budget.spent_units)
            .sum();
        counters.operator_summaries = state.operator_summaries.len() as u64;
        counters.emergency_fast_paths = state
            .mandates
            .values()
            .filter(|mandate| mandate.lane == ExitLane::EmergencyEscape)
            .count() as u64;
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committees": self.committees,
            "active_committees": self.active_committees,
            "mandates": self.mandates,
            "open_mandates": self.open_mandates,
            "approved_mandates": self.approved_mandates,
            "objected_mandates": self.objected_mandates,
            "settled_mandates": self.settled_mandates,
            "attestations": self.attestations,
            "ml_dsa_attestations": self.ml_dsa_attestations,
            "slh_dsa_attestations": self.slh_dsa_attestations,
            "approvals": self.approvals,
            "strong_approvals": self.strong_approvals,
            "objections": self.objections,
            "settlement_windows": self.settlement_windows,
            "executable_windows": self.executable_windows,
            "low_fee_rebates": self.low_fee_rebates,
            "paid_rebates": self.paid_rebates,
            "redaction_budgets": self.redaction_budgets,
            "redaction_units_reserved": self.redaction_units_reserved,
            "redaction_units_spent": self.redaction_units_spent,
            "operator_summaries": self.operator_summaries,
            "emergency_fast_paths": self.emergency_fast_paths,
        })
    }

    pub fn root(&self) -> String {
        root_from_value("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub committee_root: String,
    pub mandate_root: String,
    pub attestation_root: String,
    pub approval_root: String,
    pub objection_root: String,
    pub settlement_window_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "mandate_root": self.mandate_root,
            "attestation_root": self.attestation_root,
            "approval_root": self.approval_root,
            "objection_root": self.objection_root,
            "settlement_window_root": self.settlement_window_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }

    pub fn root_without_state_root(&self) -> String {
        root_from_value("roots", &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityMember {
    pub member_id: String,
    pub operator_label: String,
    pub role: CommitteeRole,
    pub weight_bps: u64,
    pub ml_dsa_public_key_root: String,
    pub slh_dsa_public_key_root: String,
    pub lattice_policy_root: String,
    pub watcher_bond_root: String,
    pub active_from_l2_height: u64,
    pub active_until_l2_height: u64,
}

impl AuthorityMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "weight_bps": self.weight_bps,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "lattice_policy_root": self.lattice_policy_root,
            "watcher_bond_root": self.watcher_bond_root,
            "active_from_l2_height": self.active_from_l2_height,
            "active_until_l2_height": self.active_until_l2_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_value("authority_member", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub role: CommitteeRole,
    pub status: CommitteeStatus,
    pub threshold_weight: u64,
    pub strong_threshold_weight: u64,
    pub watcher_objection_weight: u64,
    pub members: Vec<AuthorityMember>,
    pub rotation_root: String,
    pub quorum_policy_root: String,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl AuthorityCommittee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "threshold_weight": self.threshold_weight,
            "strong_threshold_weight": self.strong_threshold_weight,
            "watcher_objection_weight": self.watcher_objection_weight,
            "member_roots": self.member_roots(),
            "member_count": self.members.len(),
            "total_weight_bps": self.total_weight(),
            "rotation_root": self.rotation_root,
            "quorum_policy_root": self.quorum_policy_root,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }

    pub fn member_roots(&self) -> Vec<String> {
        self.members.iter().map(AuthorityMember::root).collect()
    }

    pub fn total_weight(&self) -> u64 {
        self.members
            .iter()
            .map(|member| member.weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    pub fn member(&self, member_id: &str) -> Option<&AuthorityMember> {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
    }

    pub fn root(&self) -> String {
        root_from_value(COMMITTEE_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitMandate {
    pub mandate_id: String,
    pub lane: ExitLane,
    pub status: MandateStatus,
    pub committee_id: String,
    pub claimant_commitment_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub fee_commitment_root: String,
    pub nullifier_hint_root: String,
    pub decoy_set_root: String,
    pub l2_burn_receipt_root: String,
    pub monero_settlement_hint_root: String,
    pub redaction_budget_id: String,
    pub low_fee_rebate_id: Option<String>,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub anonymity_set_size: u64,
    pub requires_strong_threshold: bool,
    pub operator_safe_label: String,
}

impl ExitMandate {
    pub fn public_record(&self) -> Value {
        json!({
            "mandate_id": self.mandate_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "claimant_commitment_root": self.claimant_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "nullifier_hint_root": self.nullifier_hint_root,
            "decoy_set_root": self.decoy_set_root,
            "l2_burn_receipt_root": self.l2_burn_receipt_root,
            "monero_settlement_hint_root": self.monero_settlement_hint_root,
            "redaction_budget_id": self.redaction_budget_id,
            "low_fee_rebate_id": self.low_fee_rebate_id,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "anonymity_set_size": self.anonymity_set_size,
            "requires_strong_threshold": self.requires_strong_threshold,
            "operator_safe_label": self.operator_safe_label,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(MANDATE_SUITE, &self.public_record())
    }

    pub fn is_live_at(&self, l2_height: u64) -> bool {
        !self.status.is_terminal()
            && self.created_l2_height <= l2_height
            && l2_height <= self.expires_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub mandate_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub kind: AttestationKind,
    pub scheme: PqScheme,
    pub message_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub verification_key_root: String,
    pub security_bits: u16,
    pub l2_height: u64,
    pub monero_height_hint: u64,
    pub accepted: bool,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "mandate_id": self.mandate_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "kind": self.kind.as_str(),
            "scheme": self.scheme.as_str(),
            "message_root": self.message_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "verification_key_root": self.verification_key_root,
            "security_bits": self.security_bits,
            "l2_height": self.l2_height,
            "monero_height_hint": self.monero_height_hint,
            "accepted": self.accepted,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(ATTESTATION_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThresholdApproval {
    pub approval_id: String,
    pub mandate_id: String,
    pub committee_id: String,
    pub status: ApprovalStatus,
    pub approving_member_ids: Vec<String>,
    pub approving_weight_bps: u64,
    pub required_weight_bps: u64,
    pub ml_dsa_count: u64,
    pub slh_dsa_count: u64,
    pub attestation_roots: Vec<String>,
    pub aggregate_transcript_root: String,
    pub approved_l2_height: u64,
}

impl ThresholdApproval {
    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "mandate_id": self.mandate_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "approving_member_ids": self.approving_member_ids,
            "approving_weight_bps": self.approving_weight_bps,
            "required_weight_bps": self.required_weight_bps,
            "ml_dsa_count": self.ml_dsa_count,
            "slh_dsa_count": self.slh_dsa_count,
            "attestation_roots": self.attestation_roots,
            "aggregate_transcript_root": self.aggregate_transcript_root,
            "approved_l2_height": self.approved_l2_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(APPROVAL_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherObjection {
    pub objection_id: String,
    pub mandate_id: String,
    pub watcher_id: String,
    pub reason: ObjectionReason,
    pub evidence_root: String,
    pub objection_weight_bps: u64,
    pub l2_height: u64,
    pub expires_l2_height: u64,
    pub resolved: bool,
}

impl WatcherObjection {
    pub fn public_record(&self) -> Value {
        json!({
            "objection_id": self.objection_id,
            "mandate_id": self.mandate_id,
            "watcher_id": self.watcher_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "objection_weight_bps": self.objection_weight_bps,
            "l2_height": self.l2_height,
            "expires_l2_height": self.expires_l2_height,
            "resolved": self.resolved,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(OBJECTION_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementWindow {
    pub window_id: String,
    pub mandate_id: String,
    pub approval_id: String,
    pub status: WindowStatus,
    pub opens_l2_height: u64,
    pub closes_l2_height: u64,
    pub monero_anchor_height: u64,
    pub settlement_commitment_root: String,
    pub watcher_clearance_root: String,
    pub operator_execution_root: String,
}

impl SettlementWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "mandate_id": self.mandate_id,
            "approval_id": self.approval_id,
            "status": self.status.as_str(),
            "opens_l2_height": self.opens_l2_height,
            "closes_l2_height": self.closes_l2_height,
            "monero_anchor_height": self.monero_anchor_height,
            "settlement_commitment_root": self.settlement_commitment_root,
            "watcher_clearance_root": self.watcher_clearance_root,
            "operator_execution_root": self.operator_execution_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(SETTLEMENT_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub mandate_id: String,
    pub status: RebateStatus,
    pub fee_class: String,
    pub rebate_bps: u64,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_pool_root: String,
    pub accrued_l2_height: u64,
    pub paid_l2_height: Option<u64>,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "mandate_id": self.mandate_id,
            "status": self.status.as_str(),
            "fee_class": self.fee_class,
            "rebate_bps": self.rebate_bps,
            "fee_commitment_root": self.fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "accrued_l2_height": self.accrued_l2_height,
            "paid_l2_height": self.paid_l2_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(LOW_FEE_REBATE_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub mandate_id: String,
    pub purpose: RedactionPurpose,
    pub allocated_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub receipt_root: String,
    pub expires_l2_height: u64,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.allocated_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "mandate_id": self.mandate_id,
            "purpose": self.purpose.as_str(),
            "allocated_units": self.allocated_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "receipt_root": self.receipt_root,
            "expires_l2_height": self.expires_l2_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(REDACTION_BUDGET_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub mandate_id: String,
    pub lane: ExitLane,
    pub status: MandateStatus,
    pub approval_status: Option<ApprovalStatus>,
    pub window_status: Option<WindowStatus>,
    pub committee_id: String,
    pub public_mandate_root: String,
    pub public_approval_root: Option<String>,
    pub public_window_root: Option<String>,
    pub objection_count: u64,
    pub rebate_status: Option<RebateStatus>,
    pub redaction_units_remaining: u64,
    pub operator_action: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "mandate_id": self.mandate_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "approval_status": self.approval_status.map(ApprovalStatus::as_str),
            "window_status": self.window_status.map(WindowStatus::as_str),
            "committee_id": self.committee_id,
            "public_mandate_root": self.public_mandate_root,
            "public_approval_root": self.public_approval_root,
            "public_window_root": self.public_window_root,
            "objection_count": self.objection_count,
            "rebate_status": self.rebate_status.map(RebateStatus::as_str),
            "redaction_units_remaining": self.redaction_units_remaining,
            "operator_action": self.operator_action,
        })
    }

    pub fn root(&self) -> String {
        root_from_value(SUMMARY_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub committees: BTreeMap<String, AuthorityCommittee>,
    pub mandates: BTreeMap<String, ExitMandate>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub approvals: BTreeMap<String, ThresholdApproval>,
    pub objections: BTreeMap<String, WatcherObjection>,
    pub settlement_windows: BTreeMap<String, SettlementWindow>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            committees: BTreeMap::new(),
            mandates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            approvals: BTreeMap::new(),
            objections: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.seed_devnet();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        root_from_value("state", &self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "privacy_boundary": self.config.privacy_boundary,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record_without_state_root(),
            "operator_safe": {
                "summary_count": self.operator_summaries.len(),
                "summary_root": roots.operator_summary_root,
                "public_record_suite": PUBLIC_RECORD_SUITE,
            },
        })
    }

    pub fn refresh_roots(&mut self) {
        self.counters = Counters::recompute(self);
        self.roots = self.roots_without_state_root();
        self.roots.state_root = self.state_root();
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_len("committees", self.committees.len(), MAX_COMMITTEES)?;
        ensure_len("mandates", self.mandates.len(), MAX_MANDATES)?;
        ensure_len("attestations", self.attestations.len(), MAX_ATTESTATIONS)?;
        ensure_len("approvals", self.approvals.len(), MAX_APPROVALS)?;
        ensure_len("objections", self.objections.len(), MAX_OBJECTIONS)?;
        ensure_len(
            "settlement_windows",
            self.settlement_windows.len(),
            MAX_SETTLEMENT_WINDOWS,
        )?;
        ensure_len("low_fee_rebates", self.low_fee_rebates.len(), MAX_REBATES)?;
        ensure_len(
            "redaction_budgets",
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
        )?;
        ensure_len(
            "operator_summaries",
            self.operator_summaries.len(),
            MAX_SUMMARIES,
        )?;
        for committee in self.committees.values() {
            self.validate_committee(committee)?;
        }
        for mandate in self.mandates.values() {
            self.validate_mandate(mandate)?;
        }
        for approval in self.approvals.values() {
            self.validate_approval(approval)?;
        }
        Ok(())
    }

    pub fn register_committee(&mut self, committee: AuthorityCommittee) -> Result<String> {
        self.validate_committee(&committee)?;
        let committee_id = committee.committee_id.clone();
        if self.committees.contains_key(&committee_id) {
            return Err(format!("committee already exists: {committee_id}"));
        }
        self.committees.insert(committee_id.clone(), committee);
        self.refresh_roots();
        Ok(committee_id)
    }

    pub fn open_mandate(&mut self, mut mandate: ExitMandate) -> Result<String> {
        if mandate.status == MandateStatus::Draft {
            mandate.status = MandateStatus::Open;
        }
        self.validate_mandate(&mandate)?;
        let mandate_id = mandate.mandate_id.clone();
        if self.mandates.contains_key(&mandate_id) {
            return Err(format!("mandate already exists: {mandate_id}"));
        }
        self.mandates.insert(mandate_id.clone(), mandate);
        self.refresh_roots();
        Ok(mandate_id)
    }

    pub fn record_attestation(&mut self, attestation: PqAttestation) -> Result<String> {
        self.validate_attestation(&attestation)?;
        let attestation_id = attestation.attestation_id.clone();
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation already exists: {attestation_id}"));
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn compute_threshold_approval(
        &mut self,
        approval_id: impl Into<String>,
        mandate_id: &str,
        l2_height: u64,
    ) -> Result<String> {
        let mandate = self
            .mandates
            .get(mandate_id)
            .ok_or_else(|| format!("missing mandate: {mandate_id}"))?
            .clone();
        let committee = self
            .committees
            .get(&mandate.committee_id)
            .ok_or_else(|| format!("missing committee: {}", mandate.committee_id))?
            .clone();
        if !committee.status.can_authorize() {
            return Err("committee cannot authorize mandates".to_string());
        }
        let mut member_ids = BTreeSet::new();
        let mut attestation_roots = Vec::new();
        let mut ml_dsa_count = 0_u64;
        let mut slh_dsa_count = 0_u64;
        for attestation in self.attestations.values() {
            if attestation.mandate_id != mandate_id || !attestation.accepted {
                continue;
            }
            if attestation.kind != AttestationKind::ApprovalShare {
                continue;
            }
            if committee.member(&attestation.member_id).is_none() {
                continue;
            }
            member_ids.insert(attestation.member_id.clone());
            attestation_roots.push(attestation.root());
            match attestation.scheme {
                PqScheme::MlDsa87 => ml_dsa_count = ml_dsa_count.saturating_add(1),
                PqScheme::SlhDsaShake256f => slh_dsa_count = slh_dsa_count.saturating_add(1),
                _ => {}
            }
        }
        let approving_weight_bps = member_ids
            .iter()
            .filter_map(|member_id| committee.member(member_id))
            .map(|member| member.weight_bps)
            .sum::<u64>()
            .min(MAX_BPS);
        let required_weight_bps = if mandate.requires_strong_threshold {
            committee.strong_threshold_weight
        } else {
            committee.threshold_weight
        };
        let objection_weight = self.live_objection_weight(mandate_id, l2_height);
        let status = if objection_weight >= committee.watcher_objection_weight {
            ApprovalStatus::BlockedByWatcher
        } else if approving_weight_bps >= committee.strong_threshold_weight {
            ApprovalStatus::StrongThresholdMet
        } else if approving_weight_bps >= required_weight_bps {
            ApprovalStatus::ThresholdMet
        } else {
            ApprovalStatus::Pending
        };
        let approval = ThresholdApproval {
            approval_id: approval_id.into(),
            mandate_id: mandate_id.to_string(),
            committee_id: committee.committee_id.clone(),
            status,
            approving_member_ids: member_ids.into_iter().collect(),
            approving_weight_bps,
            required_weight_bps,
            ml_dsa_count,
            slh_dsa_count,
            attestation_roots,
            aggregate_transcript_root: digest_fields(
                "approval_aggregate",
                &[
                    mandate_id,
                    &approving_weight_bps.to_string(),
                    status.as_str(),
                ],
            ),
            approved_l2_height: l2_height,
        };
        self.validate_approval(&approval)?;
        let approval_id = approval.approval_id.clone();
        self.approvals.insert(approval_id.clone(), approval);
        if let Some(stored_mandate) = self.mandates.get_mut(mandate_id) {
            stored_mandate.status = match status {
                ApprovalStatus::ThresholdMet | ApprovalStatus::StrongThresholdMet => {
                    MandateStatus::Approved
                }
                ApprovalStatus::BlockedByWatcher => MandateStatus::Objected,
                _ => stored_mandate.status,
            };
        }
        self.refresh_roots();
        Ok(approval_id)
    }

    pub fn submit_objection(&mut self, objection: WatcherObjection) -> Result<String> {
        if !self.mandates.contains_key(&objection.mandate_id) {
            return Err(format!("missing mandate: {}", objection.mandate_id));
        }
        if objection.objection_weight_bps > MAX_BPS {
            return Err("objection weight outside basis point range".to_string());
        }
        let objection_id = objection.objection_id.clone();
        if self.objections.contains_key(&objection_id) {
            return Err(format!("objection already exists: {objection_id}"));
        }
        let mandate_id = objection.mandate_id.clone();
        self.objections.insert(objection_id.clone(), objection);
        if let Some(mandate) = self.mandates.get_mut(&mandate_id) {
            mandate.status = MandateStatus::Objected;
        }
        self.refresh_roots();
        Ok(objection_id)
    }

    pub fn schedule_settlement_window(
        &mut self,
        window_id: impl Into<String>,
        mandate_id: &str,
        approval_id: &str,
        current_l2_height: u64,
        monero_anchor_height: u64,
    ) -> Result<String> {
        let mandate = self
            .mandates
            .get(mandate_id)
            .ok_or_else(|| format!("missing mandate: {mandate_id}"))?
            .clone();
        let approval = self
            .approvals
            .get(approval_id)
            .ok_or_else(|| format!("missing approval: {approval_id}"))?
            .clone();
        if approval.mandate_id != mandate_id {
            return Err("approval does not belong to mandate".to_string());
        }
        if !matches!(
            approval.status,
            ApprovalStatus::ThresholdMet | ApprovalStatus::StrongThresholdMet
        ) {
            return Err("approval threshold is not met".to_string());
        }
        let delay = if mandate.lane == ExitLane::EmergencyEscape {
            self.config.emergency_window_blocks
        } else {
            self.config.settlement_delay_blocks
        };
        let opens_l2_height = current_l2_height.saturating_add(delay);
        let closes_l2_height = opens_l2_height.saturating_add(self.config.settlement_window_blocks);
        let window = SettlementWindow {
            window_id: window_id.into(),
            mandate_id: mandate_id.to_string(),
            approval_id: approval_id.to_string(),
            status: WindowStatus::Scheduled,
            opens_l2_height,
            closes_l2_height,
            monero_anchor_height,
            settlement_commitment_root: digest_fields(
                "settlement_commitment",
                &[mandate_id, approval_id, &monero_anchor_height.to_string()],
            ),
            watcher_clearance_root: digest_fields(
                "watcher_clearance",
                &[
                    mandate_id,
                    &self
                        .live_objection_weight(mandate_id, current_l2_height)
                        .to_string(),
                ],
            ),
            operator_execution_root: digest_fields(
                "operator_execution",
                &[mandate_id, approval_id, &opens_l2_height.to_string()],
            ),
        };
        let window_id = window.window_id.clone();
        if self.settlement_windows.contains_key(&window_id) {
            return Err(format!("settlement window already exists: {window_id}"));
        }
        self.settlement_windows.insert(window_id.clone(), window);
        if let Some(stored_mandate) = self.mandates.get_mut(mandate_id) {
            stored_mandate.status = MandateStatus::Settling;
        }
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn mark_window_executable(&mut self, window_id: &str, l2_height: u64) -> Result<()> {
        let window = self
            .settlement_windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing settlement window: {window_id}"))?;
        if l2_height < window.opens_l2_height {
            return Err("settlement window has not opened".to_string());
        }
        if l2_height > window.closes_l2_height {
            window.status = WindowStatus::Lapsed;
            self.refresh_roots();
            return Err("settlement window has lapsed".to_string());
        }
        window.status = WindowStatus::Executable;
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_settled(&mut self, mandate_id: &str, window_id: &str) -> Result<()> {
        let window = self
            .settlement_windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing settlement window: {window_id}"))?;
        if window.mandate_id != mandate_id {
            return Err("settlement window does not belong to mandate".to_string());
        }
        if window.status != WindowStatus::Executable {
            return Err("settlement window is not executable".to_string());
        }
        window.status = WindowStatus::Settled;
        let mandate = self
            .mandates
            .get_mut(mandate_id)
            .ok_or_else(|| format!("missing mandate: {mandate_id}"))?;
        mandate.status = MandateStatus::Settled;
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<String> {
        if rebate.rebate_bps > self.config.low_fee_rebate_bps {
            return Err("rebate exceeds configured low-fee rebate bps".to_string());
        }
        if !self.mandates.contains_key(&rebate.mandate_id) {
            return Err(format!("missing mandate: {}", rebate.mandate_id));
        }
        let rebate_id = rebate.rebate_id.clone();
        if self.low_fee_rebates.contains_key(&rebate_id) {
            return Err(format!("rebate already exists: {rebate_id}"));
        }
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn reserve_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        if budget.allocated_units > self.config.max_redaction_units_per_mandate {
            return Err("budget exceeds per-mandate redaction cap".to_string());
        }
        if !self.mandates.contains_key(&budget.mandate_id) {
            return Err(format!("missing mandate: {}", budget.mandate_id));
        }
        let budget_id = budget.budget_id.clone();
        if self.redaction_budgets.contains_key(&budget_id) {
            return Err(format!("redaction budget already exists: {budget_id}"));
        }
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn operator_safe_summary(&self, mandate_id: &str) -> Result<OperatorSafeSummary> {
        let mandate = self
            .mandates
            .get(mandate_id)
            .ok_or_else(|| format!("missing mandate: {mandate_id}"))?;
        let approval = self
            .approvals
            .values()
            .filter(|approval| approval.mandate_id == mandate_id)
            .max_by_key(|approval| approval.approved_l2_height);
        let window = self
            .settlement_windows
            .values()
            .filter(|window| window.mandate_id == mandate_id)
            .max_by_key(|window| window.opens_l2_height);
        let rebate_status = mandate.low_fee_rebate_id.as_ref().and_then(|rebate_id| {
            self.low_fee_rebates
                .get(rebate_id)
                .map(|rebate| rebate.status)
        });
        let redaction_units_remaining = self
            .redaction_budgets
            .get(&mandate.redaction_budget_id)
            .map(RedactionBudget::remaining_units)
            .unwrap_or_default();
        let objection_count = self
            .objections
            .values()
            .filter(|objection| objection.mandate_id == mandate_id && !objection.resolved)
            .count() as u64;
        let operator_action = match (mandate.status, approval.map(|value| value.status)) {
            (MandateStatus::Open, _) => "collect_pq_attestations",
            (MandateStatus::Approved, _) => "schedule_settlement_window",
            (MandateStatus::Objected, _) => "hold_for_watcher_resolution",
            (MandateStatus::Settling, _) => "monitor_window_and_monero_anchor",
            (MandateStatus::Settled, _) => "archive_operator_record",
            (_, Some(ApprovalStatus::BlockedByWatcher)) => "hold_for_watcher_resolution",
            _ => "no_operator_action",
        }
        .to_string();
        Ok(OperatorSafeSummary {
            summary_id: digest_fields("summary_id", &[mandate_id, mandate.status.as_str()]),
            mandate_id: mandate_id.to_string(),
            lane: mandate.lane,
            status: mandate.status,
            approval_status: approval.map(|value| value.status),
            window_status: window.map(|value| value.status),
            committee_id: mandate.committee_id.clone(),
            public_mandate_root: mandate.root(),
            public_approval_root: approval.map(ThresholdApproval::root),
            public_window_root: window.map(SettlementWindow::root),
            objection_count,
            rebate_status,
            redaction_units_remaining,
            operator_action,
        })
    }

    pub fn refresh_operator_summary(&mut self, mandate_id: &str) -> Result<String> {
        let summary = self.operator_safe_summary(mandate_id)?;
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.refresh_roots();
        Ok(summary_id)
    }

    fn roots_without_state_root(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            committee_root: map_root(COMMITTEE_SUITE, &self.committees, AuthorityCommittee::root),
            mandate_root: map_root(MANDATE_SUITE, &self.mandates, ExitMandate::root),
            attestation_root: map_root(ATTESTATION_SUITE, &self.attestations, PqAttestation::root),
            approval_root: map_root(APPROVAL_SUITE, &self.approvals, ThresholdApproval::root),
            objection_root: map_root(OBJECTION_SUITE, &self.objections, WatcherObjection::root),
            settlement_window_root: map_root(
                SETTLEMENT_SUITE,
                &self.settlement_windows,
                SettlementWindow::root,
            ),
            low_fee_rebate_root: map_root(
                LOW_FEE_REBATE_SUITE,
                &self.low_fee_rebates,
                LowFeeRebate::root,
            ),
            redaction_budget_root: map_root(
                REDACTION_BUDGET_SUITE,
                &self.redaction_budgets,
                RedactionBudget::root,
            ),
            operator_summary_root: map_root(
                SUMMARY_SUITE,
                &self.operator_summaries,
                OperatorSafeSummary::root,
            ),
            counters_root: self.counters.root(),
            state_root: String::new(),
        }
    }

    fn validate_committee(&self, committee: &AuthorityCommittee) -> Result<()> {
        if committee.committee_id.is_empty() {
            return Err("committee id is empty".to_string());
        }
        if committee.members.is_empty() {
            return Err("committee has no members".to_string());
        }
        if committee.threshold_weight == 0 || committee.threshold_weight > MAX_BPS {
            return Err("committee threshold outside basis point range".to_string());
        }
        if committee.strong_threshold_weight < committee.threshold_weight {
            return Err("strong threshold below normal threshold".to_string());
        }
        if committee.total_weight() < committee.threshold_weight {
            return Err("committee total weight below threshold".to_string());
        }
        let mut ids = BTreeSet::new();
        for member in &committee.members {
            if !ids.insert(member.member_id.clone()) {
                return Err(format!("duplicate committee member: {}", member.member_id));
            }
            if member.weight_bps == 0 || member.weight_bps > MAX_BPS {
                return Err(format!("invalid member weight: {}", member.member_id));
            }
        }
        Ok(())
    }

    fn validate_mandate(&self, mandate: &ExitMandate) -> Result<()> {
        if mandate.mandate_id.is_empty() {
            return Err("mandate id is empty".to_string());
        }
        if !self.committees.contains_key(&mandate.committee_id) {
            return Err(format!("missing committee: {}", mandate.committee_id));
        }
        if mandate.anonymity_set_size < self.config.min_anonymity_set {
            return Err("mandate anonymity set below configured minimum".to_string());
        }
        if mandate.created_l2_height > mandate.expires_l2_height {
            return Err("mandate expires before it is created".to_string());
        }
        Ok(())
    }

    fn validate_attestation(&self, attestation: &PqAttestation) -> Result<()> {
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("attestation below configured PQ security bits".to_string());
        }
        let mandate = self
            .mandates
            .get(&attestation.mandate_id)
            .ok_or_else(|| format!("missing mandate: {}", attestation.mandate_id))?;
        if mandate.committee_id != attestation.committee_id {
            return Err("attestation committee does not match mandate committee".to_string());
        }
        let committee = self
            .committees
            .get(&attestation.committee_id)
            .ok_or_else(|| format!("missing committee: {}", attestation.committee_id))?;
        if committee.member(&attestation.member_id).is_none() {
            return Err("attesting member is not in committee".to_string());
        }
        if self.config.require_ml_dsa
            && attestation.kind == AttestationKind::ApprovalShare
            && matches!(attestation.scheme, PqScheme::LatticeFence)
        {
            return Err("approval shares must use concrete PQ signature schemes".to_string());
        }
        Ok(())
    }

    fn validate_approval(&self, approval: &ThresholdApproval) -> Result<()> {
        if approval.approving_weight_bps > MAX_BPS {
            return Err("approval weight outside basis point range".to_string());
        }
        if !self.mandates.contains_key(&approval.mandate_id) {
            return Err(format!("missing mandate: {}", approval.mandate_id));
        }
        if !self.committees.contains_key(&approval.committee_id) {
            return Err(format!("missing committee: {}", approval.committee_id));
        }
        if matches!(
            approval.status,
            ApprovalStatus::ThresholdMet | ApprovalStatus::StrongThresholdMet
        ) && self.config.require_slh_dsa
            && approval.slh_dsa_count == 0
        {
            return Err("threshold approval requires at least one SLH-DSA attestation".to_string());
        }
        if matches!(
            approval.status,
            ApprovalStatus::ThresholdMet | ApprovalStatus::StrongThresholdMet
        ) && self.config.require_ml_dsa
            && approval.ml_dsa_count == 0
        {
            return Err("threshold approval requires at least one ML-DSA attestation".to_string());
        }
        Ok(())
    }

    fn live_objection_weight(&self, mandate_id: &str, l2_height: u64) -> u64 {
        self.objections
            .values()
            .filter(|objection| {
                objection.mandate_id == mandate_id
                    && !objection.resolved
                    && objection.l2_height <= l2_height
                    && l2_height <= objection.expires_l2_height
            })
            .map(|objection| objection.objection_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    fn seed_devnet(&mut self) {
        let committee = devnet_committee();
        let committee_id = committee.committee_id.clone();
        self.committees.insert(committee_id.clone(), committee);

        let budget = devnet_redaction_budget("redact-devnet-exit-001", "mandate-devnet-exit-001");
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());

        let rebate = devnet_low_fee_rebate("rebate-devnet-exit-001", "mandate-devnet-exit-001");
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());

        let mandate = ExitMandate {
            mandate_id: "mandate-devnet-exit-001".to_string(),
            lane: ExitLane::RetailWithdrawal,
            status: MandateStatus::Open,
            committee_id: committee_id.clone(),
            claimant_commitment_root: digest_fields("claimant", &["devnet", "claimant-001"]),
            destination_commitment_root: digest_fields(
                "destination",
                &["monero", "stealth-root-001"],
            ),
            amount_commitment_root: digest_fields("amount", &["pedersen", "amount-root-001"]),
            fee_commitment_root: digest_fields("fee", &["low", "fee-root-001"]),
            nullifier_hint_root: digest_fields("nullifier", &["key-image-hint", "001"]),
            decoy_set_root: digest_fields("decoy_set", &["ringct", "65536", "001"]),
            l2_burn_receipt_root: digest_fields("burn_receipt", &["l2", "burn-001"]),
            monero_settlement_hint_root: digest_fields("settlement_hint", &["xmr", "anchor-001"]),
            redaction_budget_id: budget.budget_id,
            low_fee_rebate_id: Some(rebate.rebate_id),
            created_l2_height: 2_440_000,
            expires_l2_height: 2_444_320,
            anonymity_set_size: 65_536,
            requires_strong_threshold: false,
            operator_safe_label: "retail-exit-low-fee-001".to_string(),
        };
        self.mandates.insert(mandate.mandate_id.clone(), mandate);

        let emergency_budget =
            devnet_redaction_budget("redact-devnet-exit-002", "mandate-devnet-exit-002");
        self.redaction_budgets
            .insert(emergency_budget.budget_id.clone(), emergency_budget.clone());
        let emergency = ExitMandate {
            mandate_id: "mandate-devnet-exit-002".to_string(),
            lane: ExitLane::EmergencyEscape,
            status: MandateStatus::Approved,
            committee_id: committee_id.clone(),
            claimant_commitment_root: digest_fields("claimant", &["devnet", "claimant-002"]),
            destination_commitment_root: digest_fields(
                "destination",
                &["monero", "stealth-root-002"],
            ),
            amount_commitment_root: digest_fields("amount", &["pedersen", "amount-root-002"]),
            fee_commitment_root: digest_fields("fee", &["standard", "fee-root-002"]),
            nullifier_hint_root: digest_fields("nullifier", &["key-image-hint", "002"]),
            decoy_set_root: digest_fields("decoy_set", &["seraphis", "131072", "002"]),
            l2_burn_receipt_root: digest_fields("burn_receipt", &["l2", "burn-002"]),
            monero_settlement_hint_root: digest_fields("settlement_hint", &["xmr", "anchor-002"]),
            redaction_budget_id: emergency_budget.budget_id,
            low_fee_rebate_id: None,
            created_l2_height: 2_440_016,
            expires_l2_height: 2_444_336,
            anonymity_set_size: 131_072,
            requires_strong_threshold: true,
            operator_safe_label: "emergency-exit-strong-threshold-002".to_string(),
        };
        self.mandates
            .insert(emergency.mandate_id.clone(), emergency);

        for (idx, member_id) in ["auth-a", "auth-b", "auth-c", "auth-d", "auth-e"]
            .iter()
            .enumerate()
        {
            let attestation = PqAttestation {
                attestation_id: format!("attest-devnet-exit-001-{idx}"),
                mandate_id: "mandate-devnet-exit-001".to_string(),
                committee_id: committee_id.clone(),
                member_id: (*member_id).to_string(),
                kind: AttestationKind::ApprovalShare,
                scheme: if idx % 2 == 0 {
                    PqScheme::MlDsa87
                } else {
                    PqScheme::SlhDsaShake256f
                },
                message_root: digest_fields(
                    "attestation_message",
                    &["mandate-devnet-exit-001", member_id],
                ),
                signature_root: digest_fields("attestation_signature", &[member_id, "sig-root"]),
                transcript_root: digest_fields(
                    "attestation_transcript",
                    &[member_id, "transcript"],
                ),
                verification_key_root: digest_fields("verification_key", &[member_id, "vk"]),
                security_bits: 256,
                l2_height: 2_440_048 + idx as u64,
                monero_height_hint: 3_812_100 + idx as u64,
                accepted: true,
            };
            self.attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        for (idx, member_id) in [
            "auth-a", "auth-b", "auth-c", "auth-d", "auth-e", "auth-f", "auth-g",
        ]
        .iter()
        .enumerate()
        {
            let attestation = PqAttestation {
                attestation_id: format!("attest-devnet-exit-002-{idx}"),
                mandate_id: "mandate-devnet-exit-002".to_string(),
                committee_id: committee_id.clone(),
                member_id: (*member_id).to_string(),
                kind: AttestationKind::ApprovalShare,
                scheme: if idx % 2 == 0 {
                    PqScheme::MlDsa87
                } else {
                    PqScheme::SlhDsaShake256f
                },
                message_root: digest_fields(
                    "attestation_message",
                    &["mandate-devnet-exit-002", member_id],
                ),
                signature_root: digest_fields("attestation_signature", &[member_id, "sig-root"]),
                transcript_root: digest_fields(
                    "attestation_transcript",
                    &[member_id, "transcript"],
                ),
                verification_key_root: digest_fields("verification_key", &[member_id, "vk"]),
                security_bits: 256,
                l2_height: 2_440_064 + idx as u64,
                monero_height_hint: 3_812_140 + idx as u64,
                accepted: true,
            };
            self.attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        let _ = self.compute_threshold_approval(
            "approval-devnet-exit-001",
            "mandate-devnet-exit-001",
            2_440_080,
        );
        let _ = self.compute_threshold_approval(
            "approval-devnet-exit-002",
            "mandate-devnet-exit-002",
            2_440_096,
        );
        let _ = self.schedule_settlement_window(
            "window-devnet-exit-002",
            "mandate-devnet-exit-002",
            "approval-devnet-exit-002",
            2_440_096,
            3_812_160,
        );
        let objection = WatcherObjection {
            objection_id: "objection-devnet-exit-001".to_string(),
            mandate_id: "mandate-devnet-exit-001".to_string(),
            watcher_id: "watcher-north-001".to_string(),
            reason: ObjectionReason::OperatorSafetyHold,
            evidence_root: digest_fields(
                "objection_evidence",
                &["mandate-devnet-exit-001", "operator-hold"],
            ),
            objection_weight_bps: 1_000,
            l2_height: 2_440_090,
            expires_l2_height: 2_440_810,
            resolved: false,
        };
        self.objections
            .insert(objection.objection_id.clone(), objection);
        let _ = self.refresh_operator_summary("mandate-devnet-exit-001");
        let _ = self.refresh_operator_summary("mandate-devnet-exit-002");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn devnet_committee() -> AuthorityCommittee {
    let members = vec![
        devnet_member(
            "auth-a",
            "authority-alpha",
            1_600,
            CommitteeRole::ExitAuthority,
        ),
        devnet_member(
            "auth-b",
            "authority-beta",
            1_500,
            CommitteeRole::ExitAuthority,
        ),
        devnet_member(
            "auth-c",
            "authority-gamma",
            1_400,
            CommitteeRole::ExitAuthority,
        ),
        devnet_member(
            "auth-d",
            "authority-delta",
            1_300,
            CommitteeRole::ExitAuthority,
        ),
        devnet_member(
            "auth-e",
            "authority-epsilon",
            1_200,
            CommitteeRole::ExitAuthority,
        ),
        devnet_member(
            "auth-f",
            "authority-zeta",
            1_100,
            CommitteeRole::EmergencyAuthority,
        ),
        devnet_member(
            "auth-g",
            "authority-eta",
            900,
            CommitteeRole::WatcherAuthority,
        ),
    ];
    AuthorityCommittee {
        committee_id: "committee-devnet-exit-authority-001".to_string(),
        epoch: 42,
        role: CommitteeRole::ExitAuthority,
        status: CommitteeStatus::Active,
        threshold_weight: DEFAULT_THRESHOLD_WEIGHT,
        strong_threshold_weight: DEFAULT_STRONG_THRESHOLD_WEIGHT,
        watcher_objection_weight: DEFAULT_WATCHER_OBJECTION_WEIGHT,
        members,
        rotation_root: digest_fields("rotation", &["devnet", "committee", "42"]),
        quorum_policy_root: digest_fields("quorum_policy", &["7000", "8500", "2500"]),
        created_l2_height: 2_439_000,
        expires_l2_height: 2_500_000,
    }
}

fn devnet_member(
    member_id: &str,
    operator_label: &str,
    weight_bps: u64,
    role: CommitteeRole,
) -> AuthorityMember {
    AuthorityMember {
        member_id: member_id.to_string(),
        operator_label: operator_label.to_string(),
        role,
        weight_bps,
        ml_dsa_public_key_root: digest_fields("ml_dsa_public_key", &[member_id, "devnet"]),
        slh_dsa_public_key_root: digest_fields("slh_dsa_public_key", &[member_id, "devnet"]),
        lattice_policy_root: digest_fields("lattice_policy", &[member_id, role.as_str()]),
        watcher_bond_root: digest_fields("watcher_bond", &[member_id, "bonded"]),
        active_from_l2_height: 2_439_000,
        active_until_l2_height: 2_500_000,
    }
}

fn devnet_low_fee_rebate(rebate_id: &str, mandate_id: &str) -> LowFeeRebate {
    LowFeeRebate {
        rebate_id: rebate_id.to_string(),
        mandate_id: mandate_id.to_string(),
        status: RebateStatus::Accrued,
        fee_class: "low_fee_exit".to_string(),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        fee_commitment_root: digest_fields("fee_commitment", &[mandate_id, "fee"]),
        rebate_commitment_root: digest_fields("rebate_commitment", &[mandate_id, rebate_id]),
        sponsor_pool_root: digest_fields("sponsor_pool", &["devnet", "exit-authority"]),
        accrued_l2_height: 2_440_024,
        paid_l2_height: None,
    }
}

fn devnet_redaction_budget(budget_id: &str, mandate_id: &str) -> RedactionBudget {
    RedactionBudget {
        budget_id: budget_id.to_string(),
        mandate_id: mandate_id.to_string(),
        purpose: RedactionPurpose::OperatorSummary,
        allocated_units: 64,
        reserved_units: 8,
        spent_units: 4,
        receipt_root: digest_fields("redaction_receipt", &[budget_id, mandate_id]),
        expires_l2_height: 2_444_320,
    }
}

fn ensure_len(name: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        Err(format!("{name} exceeds maximum length {max}"))
    } else {
        Ok(())
    }
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, root_fn: F) -> String
where
    F: Fn(&T) -> String,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "id": key,
                "root": root_fn(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn root_from_value(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(PUBLIC_RECORD_SUITE),
            HashPart::Json(value),
        ],
        32,
    )
}

fn digest_fields(domain: &str, fields: &[&str]) -> String {
    let parts = fields
        .iter()
        .map(|field| HashPart::Str(*field))
        .collect::<Vec<_>>();
    domain_hash(domain, &parts, 32)
}
