use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialOperatorSlashingEvidenceArbitrationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-operator-slashing-evidence-arbitration-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_OPERATOR_SLASHING_EVIDENCE_ARBITRATION_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_EVIDENCE_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const ARBITRATION_SUITE: &str = "confidential-operator-slashing-arbitration-root-v1";
pub const BOND_SUITE: &str = "operator-slashing-bond-escrow-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-slashing-evidence-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BOND_ASSET_ID: &str = "operator-bond-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_EVIDENCE_WINDOW_SLOTS: u64 = 1_024;
pub const DEFAULT_APPEAL_WINDOW_SLOTS: u64 = 512;
pub const DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS: u64 = 10_000_000;
pub const DEFAULT_MAX_CASE_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_SLASH_MINOR_BPS: u64 = 750;
pub const DEFAULT_SLASH_MAJOR_BPS: u64 = 3_000;
pub const DEFAULT_MAX_EVIDENCE_RISK_BPS: u64 = 3_200;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_OPERATORS: usize = 524_288;
pub const MAX_ARBITERS: usize = 262_144;
pub const MAX_EVIDENCE_CASES: usize = 1_048_576;
pub const MAX_EVIDENCE_ITEMS: usize = 4_194_304;
pub const MAX_ARBITRATION_PANELS: usize = 524_288;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_VERDICTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_ITEMS_PER_CASE: usize = 512;
pub const MAX_ARBITERS_PER_PANEL: usize = 21;
pub const DEVNET_EPOCH: u64 = 7_424;
pub const DEVNET_SLOT: u64 = 113;
pub const DEVNET_L2_HEIGHT: u64 = 2_921_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Sequencer,
    Prover,
    BridgeRelayer,
    Watchtower,
    Oracle,
    LiquidityRelay,
    DataAvailabilityRelay,
    WalletGateway,
}

impl OperatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::BridgeRelayer => "bridge_relayer",
            Self::Watchtower => "watchtower",
            Self::Oracle => "oracle",
            Self::LiquidityRelay => "liquidity_relay",
            Self::DataAvailabilityRelay => "data_availability_relay",
            Self::WalletGateway => "wallet_gateway",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Candidate,
    Active,
    Throttled,
    UnderReview,
    Quarantined,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Equivocation,
    Censorship,
    InvalidProof,
    DataWithholding,
    BridgeReserveMismatch,
    OracleManipulation,
    PrivacyLeakage,
    FeeGriefing,
    UnauthorizedKeyUse,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::Censorship => "censorship",
            Self::InvalidProof => "invalid_proof",
            Self::DataWithholding => "data_withholding",
            Self::BridgeReserveMismatch => "bridge_reserve_mismatch",
            Self::OracleManipulation => "oracle_manipulation",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::FeeGriefing => "fee_griefing",
            Self::UnauthorizedKeyUse => "unauthorized_key_use",
        }
    }

    pub fn base_risk_bps(self) -> u64 {
        match self {
            Self::PrivacyLeakage => 3_100,
            Self::BridgeReserveMismatch => 2_900,
            Self::Equivocation => 2_700,
            Self::InvalidProof => 2_500,
            Self::DataWithholding => 2_200,
            Self::OracleManipulation => 2_100,
            Self::Censorship => 1_800,
            Self::UnauthorizedKeyUse => 2_600,
            Self::FeeGriefing => 1_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Submitted,
    EvidenceAttached,
    PanelAssigned,
    Attested,
    Deliberating,
    VerdictPublished,
    Appealed,
    Settled,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Sealed,
    Redacted,
    Attested,
    Accepted,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    EvidenceCommitmentOpened,
    PrivacyBoundaryObserved,
    BondEscrowed,
    PanelQuorumSatisfied,
    ReplayProtectionChecked,
    FeeCapObserved,
    VerdictSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerified => "pq_signature_verified",
            Self::EvidenceCommitmentOpened => "evidence_commitment_opened",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::BondEscrowed => "bond_escrowed",
            Self::PanelQuorumSatisfied => "panel_quorum_satisfied",
            Self::ReplayProtectionChecked => "replay_protection_checked",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::VerdictSafe => "verdict_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    Dismiss,
    Warning,
    Throttle,
    Quarantine,
    MinorSlash,
    MajorSlash,
    RetireOperator,
}

impl VerdictDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::Warning => "warning",
            Self::Throttle => "throttle",
            Self::Quarantine => "quarantine",
            Self::MinorSlash => "minor_slash",
            Self::MajorSlash => "major_slash",
            Self::RetireOperator => "retire_operator",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_evidence_suite: String,
    pub arbitration_suite: String,
    pub bond_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub evidence_window_slots: u64,
    pub appeal_window_slots: u64,
    pub min_operator_bond_micro_units: u64,
    pub min_arbiter_bond_micro_units: u64,
    pub max_case_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub slash_minor_bps: u64,
    pub slash_major_bps: u64,
    pub max_evidence_risk_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_evidence_suite: PQ_EVIDENCE_SUITE.to_string(),
            arbitration_suite: ARBITRATION_SUITE.to_string(),
            bond_suite: BOND_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bond_asset_id: DEFAULT_BOND_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            evidence_window_slots: DEFAULT_EVIDENCE_WINDOW_SLOTS,
            appeal_window_slots: DEFAULT_APPEAL_WINDOW_SLOTS,
            min_operator_bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS,
            min_arbiter_bond_micro_units: DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS,
            max_case_fee_bps: DEFAULT_MAX_CASE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            slash_minor_bps: DEFAULT_SLASH_MINOR_BPS,
            slash_major_bps: DEFAULT_SLASH_MAJOR_BPS,
            max_evidence_risk_bps: DEFAULT_MAX_EVIDENCE_RISK_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_evidence_suite, "pq_evidence_suite")?;
        ensure_non_empty(&self.arbitration_suite, "arbitration_suite")?;
        ensure_non_empty(&self.bond_suite, "bond_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.bond_asset_id, "bond_asset_id")?;
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below configured target".to_string());
        }
        if self.evidence_window_slots == 0 || self.appeal_window_slots == 0 {
            return Err("evidence and appeal windows must be non-zero".to_string());
        }
        if self.min_operator_bond_micro_units == 0 || self.min_arbiter_bond_micro_units == 0 {
            return Err("bond floors must be non-zero".to_string());
        }
        ensure_bps(self.max_case_fee_bps, "max_case_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.slash_minor_bps, "slash_minor_bps")?;
        ensure_bps(self.slash_major_bps, "slash_major_bps")?;
        ensure_bps(self.max_evidence_risk_bps, "max_evidence_risk_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err(
                "strong_attestation_quorum_bps must be >= min_attestation_quorum_bps".to_string(),
            );
        }
        if self.slash_major_bps < self.slash_minor_bps {
            return Err("slash_major_bps must be >= slash_minor_bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub operators: u64,
    pub arbiters: u64,
    pub evidence_cases: u64,
    pub evidence_items: u64,
    pub arbitration_panels: u64,
    pub attestations: u64,
    pub verdicts: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub dismissed_cases: u64,
    pub quarantined_operators: u64,
    pub slashed_operators: u64,
    pub retired_operators: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "operators": self.operators,
            "arbiters": self.arbiters,
            "evidence_cases": self.evidence_cases,
            "evidence_items": self.evidence_items,
            "arbitration_panels": self.arbitration_panels,
            "attestations": self.attestations,
            "verdicts": self.verdicts,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "dismissed_cases": self.dismissed_cases,
            "quarantined_operators": self.quarantined_operators,
            "slashed_operators": self.slashed_operators,
            "retired_operators": self.retired_operators,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub operator_root: String,
    pub arbiter_root: String,
    pub evidence_case_root: String,
    pub evidence_item_root: String,
    pub arbitration_panel_root: String,
    pub attestation_root: String,
    pub verdict_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("operator-slashing-evidence-arbitration:empty-root", &[], 32);
        Self {
            operator_root: empty.clone(),
            arbiter_root: empty.clone(),
            evidence_case_root: empty.clone(),
            evidence_item_root: empty.clone(),
            arbitration_panel_root: empty.clone(),
            attestation_root: empty.clone(),
            verdict_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            operator_summary_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_root": self.operator_root,
            "arbiter_root": self.arbiter_root,
            "evidence_case_root": self.evidence_case_root,
            "evidence_item_root": self.evidence_item_root,
            "arbitration_panel_root": self.arbitration_panel_root,
            "attestation_root": self.attestation_root,
            "verdict_root": self.verdict_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorRecord {
    pub operator_id: String,
    pub role: OperatorRole,
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
    pub status: OperatorStatus,
    pub successful_epochs: u64,
    pub open_cases: u64,
    pub slashed_micro_units: u64,
    pub quarantine_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArbiterRecord {
    pub arbiter_id: String,
    pub arbiter_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
    pub supported_evidence_kinds: BTreeSet<EvidenceKind>,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCase {
    pub case_id: String,
    pub operator_id: String,
    pub reporter_commitment: String,
    pub kind: EvidenceKind,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub risk_bps: u64,
    pub fee_bps: u64,
    pub status: CaseStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceItem {
    pub item_id: String,
    pub case_id: String,
    pub item_index: u64,
    pub commitment_root: String,
    pub redaction_root: String,
    pub pq_signature_root: String,
    pub status: EvidenceStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArbitrationPanel {
    pub panel_id: String,
    pub case_id: String,
    pub arbiter_ids: Vec<String>,
    pub panel_commitment_root: String,
    pub required_quorum_bps: u64,
    pub assigned_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Attestation {
    pub attestation_id: String,
    pub case_id: String,
    pub arbiter_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Verdict {
    pub verdict_id: String,
    pub case_id: String,
    pub panel_id: String,
    pub decision: VerdictDecision,
    pub verdict_root: String,
    pub slashed_micro_units: u64,
    pub appeal_expires_slot: u64,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub case_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub cases: u64,
    pub open_cases: u64,
    pub slashed_operators: u64,
    pub quarantined_operators: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterOperatorRequest {
    pub role: OperatorRole,
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterArbiterRequest {
    pub arbiter_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
    pub supported_evidence_kinds: BTreeSet<EvidenceKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEvidenceCaseRequest {
    pub operator_id: String,
    pub reporter_commitment: String,
    pub kind: EvidenceKind,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub submitted_slot: u64,
    pub risk_bps: u64,
    pub fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddEvidenceItemRequest {
    pub case_id: String,
    pub item_index: u64,
    pub commitment_root: String,
    pub redaction_root: String,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssignPanelRequest {
    pub case_id: String,
    pub arbiter_ids: Vec<String>,
    pub panel_commitment_root: String,
    pub required_quorum_bps: u64,
    pub assigned_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub case_id: String,
    pub arbiter_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishVerdictRequest {
    pub case_id: String,
    pub panel_id: String,
    pub decision: VerdictDecision,
    pub verdict_root: String,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub case_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub operators: BTreeMap<String, OperatorRecord>,
    pub arbiters: BTreeMap<String, ArbiterRecord>,
    pub evidence_cases: BTreeMap<String, EvidenceCase>,
    pub evidence_items: BTreeMap<String, EvidenceItem>,
    pub arbitration_panels: BTreeMap<String, ArbitrationPanel>,
    pub attestations: BTreeMap<String, Attestation>,
    pub verdicts: BTreeMap<String, Verdict>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default slashing arbitration config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            operators: BTreeMap::new(),
            arbiters: BTreeMap::new(),
            evidence_cases: BTreeMap::new(),
            evidence_items: BTreeMap::new(),
            arbitration_panels: BTreeMap::new(),
            attestations: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn register_operator(
        &mut self,
        request: RegisterOperatorRequest,
    ) -> Result<OperatorRecord> {
        ensure_capacity(self.operators.len(), MAX_OPERATORS, "operators")?;
        ensure_non_empty(&request.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        if request.bond_micro_units < self.config.min_operator_bond_micro_units {
            return Err("operator bond below configured minimum".to_string());
        }
        let operator_id = stable_id(
            "operator",
            &[
                HashPart::Str(request.role.as_str()),
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
            ],
        );
        let record = OperatorRecord {
            operator_id: operator_id.clone(),
            role: request.role,
            operator_commitment: request.operator_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            bond_micro_units: request.bond_micro_units,
            status: OperatorStatus::Active,
            successful_epochs: 0,
            open_cases: 0,
            slashed_micro_units: 0,
            quarantine_until_slot: 0,
        };
        self.operators.insert(operator_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_arbiter(&mut self, request: RegisterArbiterRequest) -> Result<ArbiterRecord> {
        ensure_capacity(self.arbiters.len(), MAX_ARBITERS, "arbiters")?;
        ensure_non_empty(&request.arbiter_commitment, "arbiter_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        if request.bond_micro_units < self.config.min_arbiter_bond_micro_units {
            return Err("arbiter bond below configured minimum".to_string());
        }
        if request.supported_evidence_kinds.is_empty() {
            return Err("arbiter must support at least one evidence kind".to_string());
        }
        let arbiter_id = stable_id(
            "arbiter",
            &[
                HashPart::Str(&request.arbiter_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.bond_micro_units),
            ],
        );
        let record = ArbiterRecord {
            arbiter_id: arbiter_id.clone(),
            arbiter_commitment: request.arbiter_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            bond_micro_units: request.bond_micro_units,
            supported_evidence_kinds: request.supported_evidence_kinds,
            active: true,
        };
        self.arbiters.insert(arbiter_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn submit_evidence_case(
        &mut self,
        request: SubmitEvidenceCaseRequest,
    ) -> Result<EvidenceCase> {
        ensure_capacity(
            self.evidence_cases.len(),
            MAX_EVIDENCE_CASES,
            "evidence_cases",
        )?;
        let operator = self
            .operators
            .get(&request.operator_id)
            .ok_or_else(|| "operator not found".to_string())?;
        if operator.status == OperatorStatus::Slashed || operator.status == OperatorStatus::Retired
        {
            return Err("operator is not eligible for a new case".to_string());
        }
        ensure_non_empty(&request.reporter_commitment, "reporter_commitment")?;
        ensure_non_empty(&request.sealed_evidence_root, "sealed_evidence_root")?;
        ensure_non_empty(&request.redacted_evidence_root, "redacted_evidence_root")?;
        ensure_bps(request.risk_bps, "risk_bps")?;
        ensure_bps(request.fee_bps, "fee_bps")?;
        if request.fee_bps > self.config.max_case_fee_bps {
            return Err("case fee exceeds configured cap".to_string());
        }
        let risk_bps = request.risk_bps.max(request.kind.base_risk_bps());
        if risk_bps > self.config.max_evidence_risk_bps {
            return Err("evidence risk exceeds configured bound".to_string());
        }
        let case_id = stable_id(
            "case",
            &[
                HashPart::Str(&request.operator_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.sealed_evidence_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let case = EvidenceCase {
            case_id: case_id.clone(),
            operator_id: request.operator_id.clone(),
            reporter_commitment: request.reporter_commitment,
            kind: request.kind,
            sealed_evidence_root: request.sealed_evidence_root,
            redacted_evidence_root: request.redacted_evidence_root,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.evidence_window_slots,
            risk_bps,
            fee_bps: request.fee_bps,
            status: CaseStatus::Submitted,
        };
        self.evidence_cases.insert(case_id, case.clone());
        if let Some(operator) = self.operators.get_mut(&request.operator_id) {
            operator.status = OperatorStatus::UnderReview;
            operator.open_cases = operator.open_cases.saturating_add(1);
        }
        self.refresh_roots();
        Ok(case)
    }

    pub fn add_evidence_item(&mut self, request: AddEvidenceItemRequest) -> Result<EvidenceItem> {
        ensure_capacity(
            self.evidence_items.len(),
            MAX_EVIDENCE_ITEMS,
            "evidence_items",
        )?;
        self.ensure_case_exists(&request.case_id)?;
        let existing = self
            .evidence_items
            .values()
            .filter(|item| item.case_id == request.case_id)
            .count();
        if existing >= MAX_ITEMS_PER_CASE {
            return Err("case has too many evidence items".to_string());
        }
        ensure_non_empty(&request.commitment_root, "commitment_root")?;
        ensure_non_empty(&request.redaction_root, "redaction_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        let item_id = stable_id(
            "evidence-item",
            &[
                HashPart::Str(&request.case_id),
                HashPart::U64(request.item_index),
                HashPart::Str(&request.commitment_root),
            ],
        );
        let item = EvidenceItem {
            item_id: item_id.clone(),
            case_id: request.case_id.clone(),
            item_index: request.item_index,
            commitment_root: request.commitment_root,
            redaction_root: request.redaction_root,
            pq_signature_root: request.pq_signature_root,
            status: EvidenceStatus::Sealed,
        };
        self.evidence_items.insert(item_id, item.clone());
        if let Some(case) = self.evidence_cases.get_mut(&request.case_id) {
            case.status = CaseStatus::EvidenceAttached;
        }
        self.refresh_roots();
        Ok(item)
    }

    pub fn assign_panel(&mut self, request: AssignPanelRequest) -> Result<ArbitrationPanel> {
        ensure_capacity(
            self.arbitration_panels.len(),
            MAX_ARBITRATION_PANELS,
            "arbitration_panels",
        )?;
        let case = self
            .evidence_cases
            .get(&request.case_id)
            .ok_or_else(|| "case not found".to_string())?;
        if request.arbiter_ids.is_empty() {
            return Err("panel requires at least one arbiter".to_string());
        }
        if request.arbiter_ids.len() > MAX_ARBITERS_PER_PANEL {
            return Err("panel has too many arbiters".to_string());
        }
        ensure_non_empty(&request.panel_commitment_root, "panel_commitment_root")?;
        ensure_bps(request.required_quorum_bps, "required_quorum_bps")?;
        if request.required_quorum_bps < self.config.min_attestation_quorum_bps {
            return Err("panel quorum below configured minimum".to_string());
        }
        for arbiter_id in &request.arbiter_ids {
            let arbiter = self
                .arbiters
                .get(arbiter_id)
                .ok_or_else(|| format!("arbiter not found: {arbiter_id}"))?;
            if !arbiter.active {
                return Err("panel includes inactive arbiter".to_string());
            }
            if !arbiter.supported_evidence_kinds.contains(&case.kind) {
                return Err("panel arbiter does not support evidence kind".to_string());
            }
        }
        let panel_id = stable_id(
            "panel",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Str(&request.panel_commitment_root),
                HashPart::U64(request.assigned_slot),
            ],
        );
        let panel = ArbitrationPanel {
            panel_id: panel_id.clone(),
            case_id: request.case_id.clone(),
            arbiter_ids: request.arbiter_ids,
            panel_commitment_root: request.panel_commitment_root,
            required_quorum_bps: request.required_quorum_bps,
            assigned_slot: request.assigned_slot,
        };
        self.arbitration_panels.insert(panel_id, panel.clone());
        if let Some(case) = self.evidence_cases.get_mut(&request.case_id) {
            case.status = CaseStatus::PanelAssigned;
        }
        self.refresh_roots();
        Ok(panel)
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<Attestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        self.ensure_case_exists(&request.case_id)?;
        self.ensure_arbiter_exists(&request.arbiter_id)?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Str(&request.arbiter_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = Attestation {
            attestation_id: attestation_id.clone(),
            case_id: request.case_id.clone(),
            arbiter_id: request.arbiter_id,
            kind: request.kind,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(case) = self.evidence_cases.get_mut(&request.case_id) {
            case.status = CaseStatus::Attested;
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn publish_verdict(&mut self, request: PublishVerdictRequest) -> Result<Verdict> {
        ensure_capacity(self.verdicts.len(), MAX_VERDICTS, "verdicts")?;
        let case = self
            .evidence_cases
            .get(&request.case_id)
            .ok_or_else(|| "case not found".to_string())?
            .clone();
        let panel = self
            .arbitration_panels
            .get(&request.panel_id)
            .ok_or_else(|| "panel not found".to_string())?;
        if panel.case_id != request.case_id {
            return Err("panel does not match case".to_string());
        }
        if request.published_slot < case.submitted_slot {
            return Err("verdict published before case submission".to_string());
        }
        ensure_non_empty(&request.verdict_root, "verdict_root")?;
        let slashed_micro_units = self.compute_slash(&case.operator_id, request.decision)?;
        let verdict_id = stable_id(
            "verdict",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Str(&request.panel_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(request.published_slot),
            ],
        );
        let verdict = Verdict {
            verdict_id: verdict_id.clone(),
            case_id: request.case_id.clone(),
            panel_id: request.panel_id,
            decision: request.decision,
            verdict_root: request.verdict_root,
            slashed_micro_units,
            appeal_expires_slot: request.published_slot + self.config.appeal_window_slots,
            published_slot: request.published_slot,
        };
        self.verdicts.insert(verdict_id, verdict.clone());
        self.apply_verdict(&request.case_id, request.decision, slashed_micro_units)?;
        self.refresh_roots();
        Ok(verdict)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        self.ensure_case_exists(&request.case_id)?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            case_id: request.case_id,
            asset_id: request.asset_id,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, receipt.clone());
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction_budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.public_fields.is_empty() {
            return Err("redaction budget requires public fields".to_string());
        }
        if request.redacted_fields.is_empty() {
            return Err("redaction budget requires redacted fields".to_string());
        }
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below configured minimum".to_string());
        }
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::U64(request.max_public_bytes),
                HashPart::U64(request.actual_public_bytes),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let open_cases = self
            .evidence_cases
            .values()
            .filter(|case| {
                matches!(
                    case.status,
                    CaseStatus::Submitted
                        | CaseStatus::EvidenceAttached
                        | CaseStatus::PanelAssigned
                        | CaseStatus::Attested
                        | CaseStatus::Deliberating
                )
            })
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[HashPart::U64(self.operator_summaries.len() as u64)],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            cases: self.evidence_cases.len() as u64,
            open_cases,
            slashed_operators: self.counters.slashed_operators,
            quarantined_operators: self.counters.quarantined_operators,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.operators = self.operators.len() as u64;
        self.counters.arbiters = self.arbiters.len() as u64;
        self.counters.evidence_cases = self.evidence_cases.len() as u64;
        self.counters.evidence_items = self.evidence_items.len() as u64;
        self.counters.arbitration_panels = self.arbitration_panels.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.verdicts = self.verdicts.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.operator_root = map_root(
            "operator-slashing-evidence-arbitration:operators",
            &self.operators,
        );
        self.roots.arbiter_root = map_root(
            "operator-slashing-evidence-arbitration:arbiters",
            &self.arbiters,
        );
        self.roots.evidence_case_root = map_root(
            "operator-slashing-evidence-arbitration:evidence-cases",
            &self.evidence_cases,
        );
        self.roots.evidence_item_root = map_root(
            "operator-slashing-evidence-arbitration:evidence-items",
            &self.evidence_items,
        );
        self.roots.arbitration_panel_root = map_root(
            "operator-slashing-evidence-arbitration:arbitration-panels",
            &self.arbitration_panels,
        );
        self.roots.attestation_root = map_root(
            "operator-slashing-evidence-arbitration:attestations",
            &self.attestations,
        );
        self.roots.verdict_root = map_root(
            "operator-slashing-evidence-arbitration:verdicts",
            &self.verdicts,
        );
        self.roots.rebate_root = map_root(
            "operator-slashing-evidence-arbitration:rebates",
            &self.rebates,
        );
        self.roots.redaction_budget_root = map_root(
            "operator-slashing-evidence-arbitration:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "operator-slashing-evidence-arbitration:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_evidence_suite": self.config.pq_evidence_suite,
            "arbitration_suite": self.config.arbitration_suite,
            "bond_suite": self.config.bond_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operators": self.operators,
            "arbiters": self.arbiters,
            "evidence_cases": self.evidence_cases,
            "evidence_items": self.evidence_items,
            "arbitration_panels": self.arbitration_panels,
            "attestations": self.attestations,
            "verdicts": self.verdicts,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
        })
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "operator_root": self.roots.operator_root,
            "arbiter_root": self.roots.arbiter_root,
            "evidence_case_root": self.roots.evidence_case_root,
            "evidence_item_root": self.roots.evidence_item_root,
            "arbitration_panel_root": self.roots.arbitration_panel_root,
            "attestation_root": self.roots.attestation_root,
            "verdict_root": self.roots.verdict_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "operator-slashing-evidence-arbitration:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn compute_slash(&self, operator_id: &str, decision: VerdictDecision) -> Result<u64> {
        let operator = self
            .operators
            .get(operator_id)
            .ok_or_else(|| "operator not found".to_string())?;
        let bps = match decision {
            VerdictDecision::MinorSlash => self.config.slash_minor_bps,
            VerdictDecision::MajorSlash | VerdictDecision::RetireOperator => {
                self.config.slash_major_bps
            }
            _ => 0,
        };
        Ok(operator.bond_micro_units * bps / MAX_BPS)
    }

    fn apply_verdict(
        &mut self,
        case_id: &str,
        decision: VerdictDecision,
        slashed_micro_units: u64,
    ) -> Result<()> {
        let operator_id = self
            .evidence_cases
            .get(case_id)
            .ok_or_else(|| "case not found".to_string())?
            .operator_id
            .clone();
        if let Some(case) = self.evidence_cases.get_mut(case_id) {
            case.status = match decision {
                VerdictDecision::Dismiss => CaseStatus::Rejected,
                _ => CaseStatus::VerdictPublished,
            };
        }
        if let Some(operator) = self.operators.get_mut(&operator_id) {
            operator.open_cases = operator.open_cases.saturating_sub(1);
            match decision {
                VerdictDecision::Dismiss => {
                    operator.status = OperatorStatus::Active;
                    self.counters.dismissed_cases = self.counters.dismissed_cases.saturating_add(1);
                }
                VerdictDecision::Warning => operator.status = OperatorStatus::Active,
                VerdictDecision::Throttle => operator.status = OperatorStatus::Throttled,
                VerdictDecision::Quarantine => {
                    operator.status = OperatorStatus::Quarantined;
                    operator.quarantine_until_slot = DEVNET_SLOT + self.config.appeal_window_slots;
                    self.counters.quarantined_operators =
                        self.counters.quarantined_operators.saturating_add(1);
                }
                VerdictDecision::MinorSlash | VerdictDecision::MajorSlash => {
                    operator.status = OperatorStatus::Slashed;
                    operator.slashed_micro_units = operator
                        .slashed_micro_units
                        .saturating_add(slashed_micro_units);
                    self.counters.slashed_operators =
                        self.counters.slashed_operators.saturating_add(1);
                }
                VerdictDecision::RetireOperator => {
                    operator.status = OperatorStatus::Retired;
                    operator.slashed_micro_units = operator
                        .slashed_micro_units
                        .saturating_add(slashed_micro_units);
                    self.counters.retired_operators =
                        self.counters.retired_operators.saturating_add(1);
                    self.counters.slashed_operators =
                        self.counters.slashed_operators.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    fn ensure_case_exists(&self, case_id: &str) -> Result<()> {
        ensure_non_empty(case_id, "case_id")?;
        if !self.evidence_cases.contains_key(case_id) {
            return Err(format!("case not found: {case_id}"));
        }
        Ok(())
    }

    fn ensure_arbiter_exists(&self, arbiter_id: &str) -> Result<()> {
        ensure_non_empty(arbiter_id, "arbiter_id")?;
        if !self.arbiters.contains_key(arbiter_id) {
            return Err(format!("arbiter not found: {arbiter_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let operator = state
        .register_operator(RegisterOperatorRequest {
            role: OperatorRole::Sequencer,
            operator_commitment: sample_hash("operator", 1),
            pq_verifying_key_root: sample_hash("pq-key", 1),
            bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS * 3,
        })
        .expect("devnet operator registered");
    let arbiter_a = state
        .register_arbiter(RegisterArbiterRequest {
            arbiter_commitment: sample_hash("arbiter", 1),
            pq_verifying_key_root: sample_hash("arbiter-pq-key", 1),
            bond_micro_units: DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS * 2,
            supported_evidence_kinds: [
                EvidenceKind::Equivocation,
                EvidenceKind::Censorship,
                EvidenceKind::PrivacyLeakage,
            ]
            .into_iter()
            .collect(),
        })
        .expect("devnet arbiter a registered");
    let arbiter_b = state
        .register_arbiter(RegisterArbiterRequest {
            arbiter_commitment: sample_hash("arbiter", 2),
            pq_verifying_key_root: sample_hash("arbiter-pq-key", 2),
            bond_micro_units: DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS * 2,
            supported_evidence_kinds: [
                EvidenceKind::Equivocation,
                EvidenceKind::Censorship,
                EvidenceKind::PrivacyLeakage,
            ]
            .into_iter()
            .collect(),
        })
        .expect("devnet arbiter b registered");
    let case = state
        .submit_evidence_case(SubmitEvidenceCaseRequest {
            operator_id: operator.operator_id.clone(),
            reporter_commitment: sample_hash("reporter", 1),
            kind: EvidenceKind::Equivocation,
            sealed_evidence_root: sample_hash("sealed-evidence", 1),
            redacted_evidence_root: sample_hash("redacted-evidence", 1),
            submitted_slot: DEVNET_SLOT,
            risk_bps: 2_200,
            fee_bps: 8,
        })
        .expect("devnet evidence case submitted");
    state
        .add_evidence_item(AddEvidenceItemRequest {
            case_id: case.case_id.clone(),
            item_index: 0,
            commitment_root: sample_hash("commitment", 1),
            redaction_root: sample_hash("redaction", 1),
            pq_signature_root: sample_hash("evidence-signature", 1),
        })
        .expect("devnet evidence item added");
    let panel = state
        .assign_panel(AssignPanelRequest {
            case_id: case.case_id.clone(),
            arbiter_ids: vec![arbiter_a.arbiter_id.clone(), arbiter_b.arbiter_id.clone()],
            panel_commitment_root: sample_hash("panel", 1),
            required_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            assigned_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet panel assigned");
    state
        .record_attestation(RecordAttestationRequest {
            case_id: case.case_id.clone(),
            arbiter_id: arbiter_a.arbiter_id,
            kind: AttestationKind::EvidenceCommitmentOpened,
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 4,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .publish_verdict(PublishVerdictRequest {
            case_id: case.case_id.clone(),
            panel_id: panel.panel_id,
            decision: VerdictDecision::MinorSlash,
            verdict_root: sample_hash("verdict", 1),
            published_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet verdict published");
    state
        .issue_rebate(IssueRebateRequest {
            case_id: case.case_id.clone(),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            amount_micro_units: 900,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 9,
            expires_slot: DEVNET_SLOT + 512,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: case.case_id,
            public_fields: ["case_id", "operator_role", "evidence_kind", "risk_bps"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            redacted_fields: [
                "operator_commitment",
                "reporter_commitment",
                "sealed_evidence_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
            actual_public_bytes: 704,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 8,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .register_operator(RegisterOperatorRequest {
            role: OperatorRole::Oracle,
            operator_commitment: sample_hash("operator", 2),
            pq_verifying_key_root: sample_hash("pq-key", 2),
            bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS * 2,
        })
        .expect("demo operator registered");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!(state.public_record())
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("operator-slashing-evidence-arbitration:{domain}:id"),
        parts,
        24,
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "operator-slashing-evidence-arbitration:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
