use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type MoneroL2PqPrivateSeraphisViewkeyFeeRebateCoordinatorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = MoneroL2PqPrivateSeraphisViewkeyFeeRebateCoordinatorRuntimeResult<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWKEY_FEE_REBATE_COORDINATOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-viewkey-fee-rebate-coordinator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWKEY_FEE_REBATE_COORDINATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COORDINATOR_ID: &str =
    "monero-l2-pq-private-seraphis-viewkey-fee-rebate-coordinator-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "private-seraphis-fee-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_208_640;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_981_120;
pub const DEVNET_EPOCH: u64 = 144;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_SCAN_COHORT_SCHEME: &str = "seraphis-scan-cohort-root-v1";
pub const VIEWKEY_PRIVACY_BUDGET_SCHEME: &str = "seraphis-viewkey-privacy-budget-root-v1";
pub const FEE_REBATE_CLAIM_SCHEME: &str = "private-seraphis-fee-rebate-claim-root-v1";
pub const PQ_COORDINATOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-seraphis-viewkey-fee-rebate-coordinator-v1";
pub const DECOY_SAFETY_SCHEME: &str = "seraphis-decoy-safety-check-root-v1";
pub const SPONSOR_SETTLEMENT_SCHEME: &str = "private-seraphis-sponsor-settlement-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "bounded-seraphis-viewkey-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-seraphis-rebate-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "seraphis-viewkey-fee-rebate-coordinator-public-record-v1";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-SERAPHIS-VIEWKEY-FEE-REBATE-COORDINATOR-STATE";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_DECOYS: u64 = 16;
pub const DEFAULT_MIN_RING_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 16_384;
pub const DEFAULT_MIN_PRIVACY_SCORE_BPS: u64 = 8_900;
pub const DEFAULT_MIN_DECOY_DIVERSITY_BPS: u64 = 8_750;
pub const DEFAULT_REBATE_BPS: u64 = 90;
pub const DEFAULT_SPONSOR_BUFFER_BPS: u64 = 2_500;
pub const DEFAULT_MAX_VIEWKEY_REVEALS_PER_EPOCH: u64 = 3;
pub const DEFAULT_MAX_PUBLIC_HINT_BYTES: u64 = 192;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 4_096;
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 216;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 720;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    WalletBackground,
    MerchantBatch,
    BridgeIngress,
    DexSettlement,
    SponsorRecovery,
    EmergencyPrivacy,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletBackground => "wallet_background",
            Self::MerchantBatch => "merchant_batch",
            Self::BridgeIngress => "bridge_ingress",
            Self::DexSettlement => "dex_settlement",
            Self::SponsorRecovery => "sponsor_recovery",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::SponsorRecovery => 930,
            Self::BridgeIngress => 880,
            Self::DexSettlement => 840,
            Self::MerchantBatch => 790,
            Self::WalletBackground => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Drafted,
    Scheduled,
    Scanning,
    BudgetChecked,
    DecoyChecked,
    Attested,
    RebateOpen,
    Settled,
    Quarantined,
    Expired,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Scheduled => "scheduled",
            Self::Scanning => "scanning",
            Self::BudgetChecked => "budget_checked",
            Self::DecoyChecked => "decoy_checked",
            Self::Attested => "attested",
            Self::RebateOpen => "rebate_open",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Drafted
                | Self::Scheduled
                | Self::Scanning
                | Self::BudgetChecked
                | Self::DecoyChecked
                | Self::Attested
                | Self::RebateOpen
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewkeyScope {
    None,
    ViewTagOnly,
    OutputMembership,
    AmountHint,
    SpendStatusHint,
    CoordinatorAudit,
}

impl ViewkeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ViewTagOnly => "view_tag_only",
            Self::OutputMembership => "output_membership",
            Self::AmountHint => "amount_hint",
            Self::SpendStatusHint => "spend_status_hint",
            Self::CoordinatorAudit => "coordinator_audit",
        }
    }

    pub fn privacy_cost_units(self) -> u64 {
        match self {
            Self::None => 0,
            Self::ViewTagOnly => 8,
            Self::OutputMembership => 64,
            Self::AmountHint => 192,
            Self::SpendStatusHint => 256,
            Self::CoordinatorAudit => 512,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Drafted,
    Reserved,
    Attested,
    DecoySafe,
    Payable,
    Paid,
    Rejected,
    Challenged,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::DecoySafe => "decoy_safe",
            Self::Payable => "payable",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn payable(self) -> bool {
        matches!(self, Self::Payable | Self::Paid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Stale,
    Challenged,
    Revoked,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Stale => "stale",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoySafetyStatus {
    Pending,
    Safe,
    NeedsMoreDecoys,
    AgeTooYoung,
    DiversityWeak,
    Poisoned,
    Quarantined,
}

impl DecoySafetyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Safe => "safe",
            Self::NeedsMoreDecoys => "needs_more_decoys",
            Self::AgeTooYoung => "age_too_young",
            Self::DiversityWeak => "diversity_weak",
            Self::Poisoned => "poisoned",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn blocks_rebate(self) -> bool {
        !matches!(self, Self::Safe)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Reserved,
    Netting,
    Payable,
    Paid,
    Disputed,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Netting => "netting",
            Self::Payable => "payable",
            Self::Paid => "paid",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    ViewkeyFragment,
    ViewTag,
    OutputIndex,
    AmountHint,
    SponsorMemo,
    OperatorNote,
    AttestationPayload,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewkeyFragment => "viewkey_fragment",
            Self::ViewTag => "view_tag",
            Self::OutputIndex => "output_index",
            Self::AmountHint => "amount_hint",
            Self::SponsorMemo => "sponsor_memo",
            Self::OperatorNote => "operator_note",
            Self::AttestationPayload => "attestation_payload",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Sponsor,
    Wallet,
    Auditor,
    Public,
}

impl SummaryAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Sponsor => "sponsor",
            Self::Wallet => "wallet",
            Self::Auditor => "auditor",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub coordinator_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_decoys: u64,
    pub min_ring_age_blocks: u64,
    pub min_cohort_outputs: u64,
    pub min_privacy_score_bps: u64,
    pub min_decoy_diversity_bps: u64,
    pub default_rebate_bps: u64,
    pub sponsor_buffer_bps: u64,
    pub max_viewkey_reveals_per_epoch: u64,
    pub max_public_hint_bytes: u64,
    pub redaction_budget_units: u64,
    pub cohort_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub scan_cohort_scheme: String,
    pub viewkey_budget_scheme: String,
    pub fee_rebate_claim_scheme: String,
    pub pq_attestation_scheme: String,
    pub decoy_safety_scheme: String,
    pub sponsor_settlement_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub hash_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            coordinator_id: DEVNET_COORDINATOR_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_decoys: DEFAULT_MIN_DECOYS,
            min_ring_age_blocks: DEFAULT_MIN_RING_AGE_BLOCKS,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            min_privacy_score_bps: DEFAULT_MIN_PRIVACY_SCORE_BPS,
            min_decoy_diversity_bps: DEFAULT_MIN_DECOY_DIVERSITY_BPS,
            default_rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_buffer_bps: DEFAULT_SPONSOR_BUFFER_BPS,
            max_viewkey_reveals_per_epoch: DEFAULT_MAX_VIEWKEY_REVEALS_PER_EPOCH,
            max_public_hint_bytes: DEFAULT_MAX_PUBLIC_HINT_BYTES,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            scan_cohort_scheme: SERAPHIS_SCAN_COHORT_SCHEME.to_string(),
            viewkey_budget_scheme: VIEWKEY_PRIVACY_BUDGET_SCHEME.to_string(),
            fee_rebate_claim_scheme: FEE_REBATE_CLAIM_SCHEME.to_string(),
            pq_attestation_scheme: PQ_COORDINATOR_ATTESTATION_SCHEME.to_string(),
            decoy_safety_scheme: DECOY_SAFETY_SCHEME.to_string(),
            sponsor_settlement_scheme: SPONSOR_SETTLEMENT_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            hash_suite: HASH_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "coordinator_id": self.coordinator_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_decoys": self.min_decoys,
            "min_ring_age_blocks": self.min_ring_age_blocks,
            "min_cohort_outputs": self.min_cohort_outputs,
            "min_privacy_score_bps": self.min_privacy_score_bps,
            "min_decoy_diversity_bps": self.min_decoy_diversity_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "sponsor_buffer_bps": self.sponsor_buffer_bps,
            "max_viewkey_reveals_per_epoch": self.max_viewkey_reveals_per_epoch,
            "max_public_hint_bytes": self.max_public_hint_bytes,
            "redaction_budget_units": self.redaction_budget_units,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "scan_cohort_scheme": self.scan_cohort_scheme,
            "viewkey_budget_scheme": self.viewkey_budget_scheme,
            "fee_rebate_claim_scheme": self.fee_rebate_claim_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "decoy_safety_scheme": self.decoy_safety_scheme,
            "sponsor_settlement_scheme": self.sponsor_settlement_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "hash_suite": self.hash_suite
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        if self.default_rebate_bps > MAX_BPS {
            return Err("default rebate exceeds MAX_BPS".to_string());
        }
        if self.sponsor_buffer_bps > MAX_BPS {
            return Err("sponsor buffer exceeds MAX_BPS".to_string());
        }
        if self.min_privacy_score_bps > MAX_BPS || self.min_decoy_diversity_bps > MAX_BPS {
            return Err("privacy thresholds exceed MAX_BPS".to_string());
        }
        if self.min_decoys == 0 || self.min_cohort_outputs == 0 {
            return Err("privacy floor must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SeraphisScanCohort {
    pub cohort_id: String,
    pub lane: ScanLane,
    pub status: CohortStatus,
    pub epoch: u64,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub output_count: u64,
    pub scanned_output_count: u64,
    pub wallet_count: u64,
    pub coordinator_hint_root: String,
    pub encrypted_viewkey_hint_root: String,
    pub view_tag_commitment_root: String,
    pub amount_commitment_root: String,
    pub nullifier_set_root: String,
    pub decoy_set_root: String,
    pub privacy_score_bps: u64,
    pub decoy_diversity_bps: u64,
    pub min_ring_age_blocks: u64,
    pub public_hint_bytes: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl SeraphisScanCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "output_count": self.output_count,
            "scanned_output_count": self.scanned_output_count,
            "wallet_count": self.wallet_count,
            "coordinator_hint_root": self.coordinator_hint_root,
            "encrypted_viewkey_hint_root": self.encrypted_viewkey_hint_root,
            "view_tag_commitment_root": self.view_tag_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "nullifier_set_root": self.nullifier_set_root,
            "decoy_set_root": self.decoy_set_root,
            "privacy_score_bps": self.privacy_score_bps,
            "decoy_diversity_bps": self.decoy_diversity_bps,
            "min_ring_age_blocks": self.min_ring_age_blocks,
            "public_hint_bytes": self.public_hint_bytes,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("SERAPHIS-SCAN-COHORT", &self.public_record())
    }

    pub fn privacy_ready(&self, config: &Config) -> bool {
        self.output_count >= config.min_cohort_outputs
            && self.privacy_score_bps >= config.min_privacy_score_bps
            && self.decoy_diversity_bps >= config.min_decoy_diversity_bps
            && self.min_ring_age_blocks >= config.min_ring_age_blocks
            && self.public_hint_bytes <= config.max_public_hint_bytes
    }
}

impl Default for ScanLane {
    fn default() -> Self {
        Self::WalletBackground
    }
}

impl Default for CohortStatus {
    fn default() -> Self {
        Self::Drafted
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ViewkeyPrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub cohort_id: String,
    pub scope: ViewkeyScope,
    pub epoch: u64,
    pub allocated_units: u64,
    pub spent_units: u64,
    pub reveal_count: u64,
    pub max_reveal_count: u64,
    pub redaction_commitment_root: String,
    pub encrypted_audit_path_root: String,
    pub public_hint_bytes: u64,
    pub sponsor_id: String,
    pub expires_at_l2_height: u64,
}

impl ViewkeyPrivacyBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "cohort_id": self.cohort_id,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "allocated_units": self.allocated_units,
            "spent_units": self.spent_units,
            "reveal_count": self.reveal_count,
            "max_reveal_count": self.max_reveal_count,
            "redaction_commitment_root": self.redaction_commitment_root,
            "encrypted_audit_path_root": self.encrypted_audit_path_root,
            "public_hint_bytes": self.public_hint_bytes,
            "sponsor_id": self.sponsor_id,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("VIEWKEY-PRIVACY-BUDGET", &self.public_record())
    }

    pub fn remaining_units(&self) -> u64 {
        self.allocated_units.saturating_sub(self.spent_units)
    }

    pub fn can_spend(&self, config: &Config, scope: ViewkeyScope, units: u64) -> bool {
        self.reveal_count < self.max_reveal_count
            && self.reveal_count < config.max_viewkey_reveals_per_epoch
            && self.remaining_units() >= units.saturating_add(scope.privacy_cost_units())
            && self.public_hint_bytes <= config.max_public_hint_bytes
    }
}

impl Default for ViewkeyScope {
    fn default() -> Self {
        Self::ViewTagOnly
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FeeRebateClaim {
    pub claim_id: String,
    pub claimant_commitment: String,
    pub cohort_id: String,
    pub budget_id: String,
    pub sponsor_id: String,
    pub status: ClaimStatus,
    pub epoch: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub eligible_fee_units: u64,
    pub rebate_bps: u64,
    pub requested_rebate_units: u64,
    pub approved_rebate_units: u64,
    pub proof_commitment: String,
    pub encrypted_claim_payload_root: String,
    pub nullifier: String,
    pub decoy_check_id: String,
    pub attestation_id: String,
    pub settlement_id: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl FeeRebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "claimant_commitment": self.claimant_commitment,
            "cohort_id": self.cohort_id,
            "budget_id": self.budget_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_bps": self.rebate_bps,
            "requested_rebate_units": self.requested_rebate_units,
            "approved_rebate_units": self.approved_rebate_units,
            "proof_commitment": self.proof_commitment,
            "encrypted_claim_payload_root": self.encrypted_claim_payload_root,
            "nullifier": self.nullifier,
            "decoy_check_id": self.decoy_check_id,
            "attestation_id": self.attestation_id,
            "settlement_id": self.settlement_id,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("FEE-REBATE-CLAIM", &self.public_record())
    }

    pub fn computed_rebate_units(&self) -> u64 {
        self.eligible_fee_units.saturating_mul(self.rebate_bps) / MAX_BPS
    }
}

impl Default for ClaimStatus {
    fn default() -> Self {
        Self::Drafted
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PqCoordinatorAttestation {
    pub attestation_id: String,
    pub coordinator_id: String,
    pub cohort_id: String,
    pub claim_id: String,
    pub status: AttestationStatus,
    pub epoch: u64,
    pub pq_security_bits: u16,
    pub signature_scheme: String,
    pub committee_weight_bps: u64,
    pub signed_public_root: String,
    pub signed_private_payload_root: String,
    pub transcript_root: String,
    pub challenge_window_start_l2_height: u64,
    pub challenge_window_end_l2_height: u64,
    pub operator_redaction_root: String,
}

impl PqCoordinatorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "coordinator_id": self.coordinator_id,
            "cohort_id": self.cohort_id,
            "claim_id": self.claim_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "pq_security_bits": self.pq_security_bits,
            "signature_scheme": self.signature_scheme,
            "committee_weight_bps": self.committee_weight_bps,
            "signed_public_root": self.signed_public_root,
            "signed_private_payload_root": self.signed_private_payload_root,
            "transcript_root": self.transcript_root,
            "challenge_window_start_l2_height": self.challenge_window_start_l2_height,
            "challenge_window_end_l2_height": self.challenge_window_end_l2_height,
            "operator_redaction_root": self.operator_redaction_root
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("PQ-COORDINATOR-ATTESTATION", &self.public_record())
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status == AttestationStatus::Accepted
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.committee_weight_bps >= 6_700
    }
}

impl Default for AttestationStatus {
    fn default() -> Self {
        Self::Submitted
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DecoySafetyCheck {
    pub check_id: String,
    pub cohort_id: String,
    pub claim_id: String,
    pub status: DecoySafetyStatus,
    pub decoy_count: u64,
    pub minimum_decoys: u64,
    pub ring_age_blocks: u64,
    pub diversity_bps: u64,
    pub poison_score_bps: u64,
    pub output_overlap_bps: u64,
    pub decoy_set_root: String,
    pub age_histogram_root: String,
    pub wallet_cluster_hint_root: String,
    pub checked_at_monero_height: u64,
    pub checked_at_l2_height: u64,
}

impl DecoySafetyCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "cohort_id": self.cohort_id,
            "claim_id": self.claim_id,
            "status": self.status.as_str(),
            "decoy_count": self.decoy_count,
            "minimum_decoys": self.minimum_decoys,
            "ring_age_blocks": self.ring_age_blocks,
            "diversity_bps": self.diversity_bps,
            "poison_score_bps": self.poison_score_bps,
            "output_overlap_bps": self.output_overlap_bps,
            "decoy_set_root": self.decoy_set_root,
            "age_histogram_root": self.age_histogram_root,
            "wallet_cluster_hint_root": self.wallet_cluster_hint_root,
            "checked_at_monero_height": self.checked_at_monero_height,
            "checked_at_l2_height": self.checked_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("DECOY-SAFETY-CHECK", &self.public_record())
    }

    pub fn evaluate(
        config: &Config,
        decoy_count: u64,
        ring_age_blocks: u64,
        diversity_bps: u64,
        poison_score_bps: u64,
    ) -> DecoySafetyStatus {
        if poison_score_bps > 1_000 {
            DecoySafetyStatus::Poisoned
        } else if decoy_count < config.min_decoys {
            DecoySafetyStatus::NeedsMoreDecoys
        } else if ring_age_blocks < config.min_ring_age_blocks {
            DecoySafetyStatus::AgeTooYoung
        } else if diversity_bps < config.min_decoy_diversity_bps {
            DecoySafetyStatus::DiversityWeak
        } else {
            DecoySafetyStatus::Safe
        }
    }
}

impl Default for DecoySafetyStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SponsorSettlement {
    pub settlement_id: String,
    pub sponsor_id: String,
    pub claim_ids: BTreeSet<String>,
    pub status: SettlementStatus,
    pub epoch: u64,
    pub rebate_asset_id: String,
    pub reserved_units: u64,
    pub payable_units: u64,
    pub paid_units: u64,
    pub buffer_bps: u64,
    pub sponsor_balance_root: String,
    pub payable_root: String,
    pub settlement_receipt_root: String,
    pub opened_at_l2_height: u64,
    pub payable_at_l2_height: u64,
}

impl SponsorSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "claim_ids": self.claim_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "rebate_asset_id": self.rebate_asset_id,
            "reserved_units": self.reserved_units,
            "payable_units": self.payable_units,
            "paid_units": self.paid_units,
            "buffer_bps": self.buffer_bps,
            "sponsor_balance_root": self.sponsor_balance_root,
            "payable_root": self.payable_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "payable_at_l2_height": self.payable_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("SPONSOR-SETTLEMENT", &self.public_record())
    }

    pub fn buffered_reserve(units: u64, buffer_bps: u64) -> u64 {
        units.saturating_add(units.saturating_mul(buffer_bps) / MAX_BPS)
    }
}

impl Default for SettlementStatus {
    fn default() -> Self {
        Self::Reserved
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub redaction_id: String,
    pub operator_id: String,
    pub cohort_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub allocated_units: u64,
    pub spent_units: u64,
    pub max_public_hint_bytes: u64,
    pub public_hint_bytes_used: u64,
    pub redacted_field_count: u64,
    pub transcript_root: String,
    pub redaction_receipt_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "operator_id": self.operator_id,
            "cohort_id": self.cohort_id,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "allocated_units": self.allocated_units,
            "spent_units": self.spent_units,
            "max_public_hint_bytes": self.max_public_hint_bytes,
            "public_hint_bytes_used": self.public_hint_bytes_used,
            "redacted_field_count": self.redacted_field_count,
            "transcript_root": self.transcript_root,
            "redaction_receipt_root": self.redaction_receipt_root
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("REDACTION-BUDGET", &self.public_record())
    }

    pub fn remaining_units(&self) -> u64 {
        self.allocated_units.saturating_sub(self.spent_units)
    }

    pub fn operator_safe(&self) -> bool {
        self.public_hint_bytes_used <= self.max_public_hint_bytes
            && self.spent_units <= self.allocated_units
    }
}

impl Default for RedactionScope {
    fn default() -> Self {
        Self::OperatorNote
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub audience: SummaryAudience,
    pub epoch: u64,
    pub cohort_count: u64,
    pub claim_count: u64,
    pub payable_claim_count: u64,
    pub settled_claim_count: u64,
    pub quarantined_count: u64,
    pub total_rebate_units: u64,
    pub total_reserved_units: u64,
    pub average_privacy_score_bps: u64,
    pub average_decoy_diversity_bps: u64,
    pub public_record_root: String,
    pub redaction_budget_root: String,
    pub sponsor_settlement_root: String,
    pub generated_at_l2_height: u64,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "audience": self.audience.as_str(),
            "epoch": self.epoch,
            "cohort_count": self.cohort_count,
            "claim_count": self.claim_count,
            "payable_claim_count": self.payable_claim_count,
            "settled_claim_count": self.settled_claim_count,
            "quarantined_count": self.quarantined_count,
            "total_rebate_units": self.total_rebate_units,
            "total_reserved_units": self.total_reserved_units,
            "average_privacy_score_bps": self.average_privacy_score_bps,
            "average_decoy_diversity_bps": self.average_decoy_diversity_bps,
            "public_record_root": self.public_record_root,
            "redaction_budget_root": self.redaction_budget_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "generated_at_l2_height": self.generated_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("OPERATOR-SAFE-SUMMARY", &self.public_record())
    }
}

impl Default for SummaryAudience {
    fn default() -> Self {
        Self::Operator
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub cohorts: u64,
    pub live_cohorts: u64,
    pub budgets: u64,
    pub claims: u64,
    pub payable_claims: u64,
    pub paid_claims: u64,
    pub attestations: u64,
    pub accepted_attestations: u64,
    pub decoy_checks: u64,
    pub unsafe_decoy_checks: u64,
    pub sponsor_settlements: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub total_rebate_units: u64,
    pub total_reserved_units: u64,
    pub total_paid_units: u64,
    pub total_public_hint_bytes: u64,
    pub total_redaction_spent_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "cohorts": self.cohorts,
            "live_cohorts": self.live_cohorts,
            "budgets": self.budgets,
            "claims": self.claims,
            "payable_claims": self.payable_claims,
            "paid_claims": self.paid_claims,
            "attestations": self.attestations,
            "accepted_attestations": self.accepted_attestations,
            "decoy_checks": self.decoy_checks,
            "unsafe_decoy_checks": self.unsafe_decoy_checks,
            "sponsor_settlements": self.sponsor_settlements,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "total_rebate_units": self.total_rebate_units,
            "total_reserved_units": self.total_reserved_units,
            "total_paid_units": self.total_paid_units,
            "total_public_hint_bytes": self.total_public_hint_bytes,
            "total_redaction_spent_units": self.total_redaction_spent_units
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub cohort_root: String,
    pub viewkey_budget_root: String,
    pub fee_rebate_claim_root: String,
    pub pq_attestation_root: String,
    pub decoy_safety_root: String,
    pub sponsor_settlement_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "cohort_root": self.cohort_root,
            "viewkey_budget_root": self.viewkey_budget_root,
            "fee_rebate_claim_root": self.fee_rebate_claim_root,
            "pq_attestation_root": self.pq_attestation_root,
            "decoy_safety_root": self.decoy_safety_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub cohorts: BTreeMap<String, SeraphisScanCohort>,
    pub viewkey_budgets: BTreeMap<String, ViewkeyPrivacyBudget>,
    pub fee_rebate_claims: BTreeMap<String, FeeRebateClaim>,
    pub pq_attestations: BTreeMap<String, PqCoordinatorAttestation>,
    pub decoy_safety_checks: BTreeMap<String, DecoySafetyCheck>,
    pub sponsor_settlements: BTreeMap<String, SponsorSettlement>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub operator_public_notes: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            cohorts: BTreeMap::new(),
            viewkey_budgets: BTreeMap::new(),
            fee_rebate_claims: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            decoy_safety_checks: BTreeMap::new(),
            sponsor_settlements: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            operator_public_notes: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn insert_cohort(&mut self, cohort: SeraphisScanCohort) -> Result<String> {
        if cohort.cohort_id.is_empty() {
            return Err("cohort id is required".to_string());
        }
        if !cohort.privacy_ready(&self.config) && cohort.status == CohortStatus::RebateOpen {
            return Err("cohort cannot open rebates before privacy floors pass".to_string());
        }
        let root = cohort.state_root();
        self.cohorts.insert(cohort.cohort_id.clone(), cohort);
        Ok(root)
    }

    pub fn insert_viewkey_budget(&mut self, budget: ViewkeyPrivacyBudget) -> Result<String> {
        if !self.cohorts.contains_key(&budget.cohort_id) {
            return Err("budget references unknown cohort".to_string());
        }
        if budget.public_hint_bytes > self.config.max_public_hint_bytes {
            return Err("budget public hint bytes exceed config limit".to_string());
        }
        let root = budget.state_root();
        self.viewkey_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(root)
    }

    pub fn insert_claim(&mut self, claim: FeeRebateClaim) -> Result<String> {
        if claim.rebate_bps > MAX_BPS {
            return Err("claim rebate bps exceeds MAX_BPS".to_string());
        }
        if !self.cohorts.contains_key(&claim.cohort_id) {
            return Err("claim references unknown cohort".to_string());
        }
        if !self.viewkey_budgets.contains_key(&claim.budget_id) {
            return Err("claim references unknown viewkey budget".to_string());
        }
        if claim.requested_rebate_units > claim.computed_rebate_units() {
            return Err("claim requests more than computed rebate".to_string());
        }
        let root = claim.state_root();
        self.fee_rebate_claims.insert(claim.claim_id.clone(), claim);
        Ok(root)
    }

    pub fn insert_attestation(&mut self, attestation: PqCoordinatorAttestation) -> Result<String> {
        if !self.cohorts.contains_key(&attestation.cohort_id) {
            return Err("attestation references unknown cohort".to_string());
        }
        if !attestation.claim_id.is_empty()
            && !self.fee_rebate_claims.contains_key(&attestation.claim_id)
        {
            return Err("attestation references unknown claim".to_string());
        }
        let root = attestation.state_root();
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(root)
    }

    pub fn insert_decoy_check(&mut self, check: DecoySafetyCheck) -> Result<String> {
        if !self.cohorts.contains_key(&check.cohort_id) {
            return Err("decoy check references unknown cohort".to_string());
        }
        if !check.claim_id.is_empty() && !self.fee_rebate_claims.contains_key(&check.claim_id) {
            return Err("decoy check references unknown claim".to_string());
        }
        let root = check.state_root();
        self.decoy_safety_checks
            .insert(check.check_id.clone(), check);
        Ok(root)
    }

    pub fn insert_sponsor_settlement(&mut self, settlement: SponsorSettlement) -> Result<String> {
        if settlement.buffer_bps > MAX_BPS {
            return Err("settlement buffer exceeds MAX_BPS".to_string());
        }
        for claim_id in &settlement.claim_ids {
            if !self.fee_rebate_claims.contains_key(claim_id) {
                return Err(format!("settlement references unknown claim {claim_id}"));
            }
        }
        let root = settlement.state_root();
        self.sponsor_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(root)
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        if !budget.operator_safe() {
            return Err("redaction budget is not operator safe".to_string());
        }
        if !self.cohorts.contains_key(&budget.cohort_id) {
            return Err("redaction budget references unknown cohort".to_string());
        }
        let root = budget.state_root();
        self.redaction_budgets
            .insert(budget.redaction_id.clone(), budget);
        Ok(root)
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSafeSummary) -> Result<String> {
        let root = summary.state_root();
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        Ok(root)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            cohorts: self.cohorts.len() as u64,
            live_cohorts: self
                .cohorts
                .values()
                .filter(|cohort| cohort.status.live())
                .count() as u64,
            budgets: self.viewkey_budgets.len() as u64,
            claims: self.fee_rebate_claims.len() as u64,
            payable_claims: self
                .fee_rebate_claims
                .values()
                .filter(|claim| claim.status.payable())
                .count() as u64,
            paid_claims: self
                .fee_rebate_claims
                .values()
                .filter(|claim| claim.status == ClaimStatus::Paid)
                .count() as u64,
            attestations: self.pq_attestations.len() as u64,
            accepted_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.accepted(&self.config))
                .count() as u64,
            decoy_checks: self.decoy_safety_checks.len() as u64,
            unsafe_decoy_checks: self
                .decoy_safety_checks
                .values()
                .filter(|check| check.status.blocks_rebate())
                .count() as u64,
            sponsor_settlements: self.sponsor_settlements.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            total_rebate_units: self
                .fee_rebate_claims
                .values()
                .map(|claim| claim.approved_rebate_units)
                .sum(),
            total_reserved_units: self
                .sponsor_settlements
                .values()
                .map(|settlement| settlement.reserved_units)
                .sum(),
            total_paid_units: self
                .sponsor_settlements
                .values()
                .map(|settlement| settlement.paid_units)
                .sum(),
            total_public_hint_bytes: self
                .cohorts
                .values()
                .map(|cohort| cohort.public_hint_bytes)
                .sum::<u64>()
                .saturating_add(
                    self.viewkey_budgets
                        .values()
                        .map(|budget| budget.public_hint_bytes)
                        .sum(),
                ),
            total_redaction_spent_units: self
                .redaction_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let public_records = self.public_records_without_roots();
        Roots {
            config_root: self.config.state_root(),
            cohort_root: map_root("COHORTS", &self.cohorts),
            viewkey_budget_root: map_root("VIEWKEY-BUDGETS", &self.viewkey_budgets),
            fee_rebate_claim_root: map_root("FEE-REBATE-CLAIMS", &self.fee_rebate_claims),
            pq_attestation_root: map_root("PQ-ATTESTATIONS", &self.pq_attestations),
            decoy_safety_root: map_root("DECOY-SAFETY-CHECKS", &self.decoy_safety_checks),
            sponsor_settlement_root: map_root("SPONSOR-SETTLEMENTS", &self.sponsor_settlements),
            redaction_budget_root: map_root("REDACTION-BUDGETS", &self.redaction_budgets),
            operator_summary_root: map_root("OPERATOR-SUMMARIES", &self.operator_summaries),
            counters_root: counters.state_root(),
            public_record_root: runtime_hash("PUBLIC-RECORDS", &public_records),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "coordinator_id": self.config.coordinator_id,
            "epoch": self.config.epoch,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
            "operator_safe_summary": self.operator_safe_summary_record(&roots, &counters),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        runtime_hash(
            "STATE",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "config_root": self.config.state_root(),
                "roots": roots.public_record(),
                "roots_root": roots.state_root(),
                "counters": counters.public_record(),
                "counters_root": counters.state_root()
            }),
        )
    }

    fn operator_safe_summary_record(&self, roots: &Roots, counters: &Counters) -> Value {
        json!({
            "cohort_count": counters.cohorts,
            "live_cohort_count": counters.live_cohorts,
            "claim_count": counters.claims,
            "payable_claim_count": counters.payable_claims,
            "paid_claim_count": counters.paid_claims,
            "unsafe_decoy_check_count": counters.unsafe_decoy_checks,
            "total_rebate_units": counters.total_rebate_units,
            "total_reserved_units": counters.total_reserved_units,
            "total_paid_units": counters.total_paid_units,
            "cohort_root": roots.cohort_root,
            "fee_rebate_claim_root": roots.fee_rebate_claim_root,
            "decoy_safety_root": roots.decoy_safety_root,
            "sponsor_settlement_root": roots.sponsor_settlement_root,
            "redaction_budget_root": roots.redaction_budget_root
        })
    }

    fn public_records_without_roots(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "cohorts": record_map(&self.cohorts),
            "viewkey_budgets": record_map(&self.viewkey_budgets),
            "fee_rebate_claims": record_map(&self.fee_rebate_claims),
            "pq_attestations": record_map(&self.pq_attestations),
            "decoy_safety_checks": record_map(&self.decoy_safety_checks),
            "sponsor_settlements": record_map(&self.sponsor_settlements),
            "redaction_budgets": record_map(&self.redaction_budgets),
            "operator_summaries": record_map(&self.operator_summaries),
            "operator_public_notes": self.operator_public_notes
        })
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone()).expect("default config is valid");

    let cohort = SeraphisScanCohort {
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        lane: ScanLane::WalletBackground,
        status: CohortStatus::RebateOpen,
        epoch: config.epoch,
        monero_start_height: config.monero_height - 216,
        monero_end_height: config.monero_height,
        output_count: 24_576,
        scanned_output_count: 24_576,
        wallet_count: 384,
        coordinator_hint_root: sample_root("coordinator-hints", 1),
        encrypted_viewkey_hint_root: sample_root("encrypted-viewkey-hints", 1),
        view_tag_commitment_root: sample_root("view-tags", 1),
        amount_commitment_root: sample_root("amounts", 1),
        nullifier_set_root: sample_root("nullifiers", 1),
        decoy_set_root: sample_root("decoys", 1),
        privacy_score_bps: 9_350,
        decoy_diversity_bps: 9_180,
        min_ring_age_blocks: 96,
        public_hint_bytes: 96,
        opened_at_l2_height: config.l2_height,
        expires_at_l2_height: config.l2_height + config.cohort_ttl_blocks,
    };
    state.insert_cohort(cohort).expect("devnet cohort inserts");

    let budget = ViewkeyPrivacyBudget {
        budget_id: "devnet-viewkey-budget-001".to_string(),
        owner_commitment: sample_root("owner", 1),
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        scope: ViewkeyScope::OutputMembership,
        epoch: config.epoch,
        allocated_units: config.redaction_budget_units,
        spent_units: 384,
        reveal_count: 1,
        max_reveal_count: config.max_viewkey_reveals_per_epoch,
        redaction_commitment_root: sample_root("budget-redactions", 1),
        encrypted_audit_path_root: sample_root("audit-path", 1),
        public_hint_bytes: 64,
        sponsor_id: "devnet-sponsor-alpha".to_string(),
        expires_at_l2_height: config.l2_height + config.claim_ttl_blocks,
    };
    state
        .insert_viewkey_budget(budget)
        .expect("devnet budget inserts");

    let check_status = DecoySafetyCheck::evaluate(&config, 18, 104, 9_180, 80);
    let check = DecoySafetyCheck {
        check_id: "devnet-decoy-check-001".to_string(),
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        claim_id: String::new(),
        status: check_status,
        decoy_count: 18,
        minimum_decoys: config.min_decoys,
        ring_age_blocks: 104,
        diversity_bps: 9_180,
        poison_score_bps: 80,
        output_overlap_bps: 320,
        decoy_set_root: sample_root("claim-decoys", 1),
        age_histogram_root: sample_root("age-histogram", 1),
        wallet_cluster_hint_root: sample_root("wallet-cluster", 1),
        checked_at_monero_height: config.monero_height,
        checked_at_l2_height: config.l2_height + 4,
    };
    state
        .insert_decoy_check(check)
        .expect("devnet decoy check inserts");

    let claim = FeeRebateClaim {
        claim_id: "devnet-rebate-claim-001".to_string(),
        claimant_commitment: sample_root("claimant", 1),
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        budget_id: "devnet-viewkey-budget-001".to_string(),
        sponsor_id: "devnet-sponsor-alpha".to_string(),
        status: ClaimStatus::Payable,
        epoch: config.epoch,
        fee_asset_id: config.fee_asset_id.clone(),
        rebate_asset_id: config.rebate_asset_id.clone(),
        eligible_fee_units: 12_000_000,
        rebate_bps: config.default_rebate_bps,
        requested_rebate_units: 108_000,
        approved_rebate_units: 108_000,
        proof_commitment: sample_root("claim-proof", 1),
        encrypted_claim_payload_root: sample_root("encrypted-claim", 1),
        nullifier: sample_root("claim-nullifier", 1),
        decoy_check_id: "devnet-decoy-check-001".to_string(),
        attestation_id: "devnet-attestation-001".to_string(),
        settlement_id: "devnet-settlement-001".to_string(),
        opened_at_l2_height: config.l2_height + 8,
        expires_at_l2_height: config.l2_height + config.claim_ttl_blocks,
    };
    state.insert_claim(claim).expect("devnet claim inserts");

    let attestation = PqCoordinatorAttestation {
        attestation_id: "devnet-attestation-001".to_string(),
        coordinator_id: config.coordinator_id.clone(),
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        claim_id: "devnet-rebate-claim-001".to_string(),
        status: AttestationStatus::Accepted,
        epoch: config.epoch,
        pq_security_bits: config.min_pq_security_bits,
        signature_scheme: config.pq_attestation_scheme.clone(),
        committee_weight_bps: 7_200,
        signed_public_root: sample_root("signed-public", 1),
        signed_private_payload_root: sample_root("signed-private", 1),
        transcript_root: sample_root("attestation-transcript", 1),
        challenge_window_start_l2_height: config.l2_height + 8,
        challenge_window_end_l2_height: config.l2_height + config.attestation_ttl_blocks,
        operator_redaction_root: sample_root("operator-redaction", 1),
    };
    state
        .insert_attestation(attestation)
        .expect("devnet attestation inserts");

    let settlement_claims = BTreeSet::from(["devnet-rebate-claim-001".to_string()]);
    let settlement = SponsorSettlement {
        settlement_id: "devnet-settlement-001".to_string(),
        sponsor_id: "devnet-sponsor-alpha".to_string(),
        claim_ids: settlement_claims,
        status: SettlementStatus::Payable,
        epoch: config.epoch,
        rebate_asset_id: config.rebate_asset_id.clone(),
        reserved_units: SponsorSettlement::buffered_reserve(108_000, config.sponsor_buffer_bps),
        payable_units: 108_000,
        paid_units: 0,
        buffer_bps: config.sponsor_buffer_bps,
        sponsor_balance_root: sample_root("sponsor-balance", 1),
        payable_root: sample_root("payable", 1),
        settlement_receipt_root: sample_root("settlement-receipt", 1),
        opened_at_l2_height: config.l2_height + 12,
        payable_at_l2_height: config.l2_height + config.settlement_window_blocks,
    };
    state
        .insert_sponsor_settlement(settlement)
        .expect("devnet settlement inserts");

    let redaction_budget = RedactionBudget {
        redaction_id: "devnet-redaction-budget-001".to_string(),
        operator_id: "devnet-operator-alpha".to_string(),
        cohort_id: "devnet-seraphis-cohort-001".to_string(),
        scope: RedactionScope::AttestationPayload,
        epoch: config.epoch,
        allocated_units: config.redaction_budget_units,
        spent_units: 512,
        max_public_hint_bytes: config.max_public_hint_bytes,
        public_hint_bytes_used: 80,
        redacted_field_count: 7,
        transcript_root: sample_root("redaction-transcript", 1),
        redaction_receipt_root: sample_root("redaction-receipt", 1),
    };
    state
        .insert_redaction_budget(redaction_budget)
        .expect("devnet redaction budget inserts");

    let roots = state.roots();
    let counters = state.counters();
    let summary = OperatorSafeSummary {
        summary_id: "devnet-operator-summary-001".to_string(),
        audience: SummaryAudience::Operator,
        epoch: config.epoch,
        cohort_count: counters.cohorts,
        claim_count: counters.claims,
        payable_claim_count: counters.payable_claims,
        settled_claim_count: counters.paid_claims,
        quarantined_count: counters.unsafe_decoy_checks,
        total_rebate_units: counters.total_rebate_units,
        total_reserved_units: counters.total_reserved_units,
        average_privacy_score_bps: 9_350,
        average_decoy_diversity_bps: 9_180,
        public_record_root: roots.public_record_root,
        redaction_budget_root: roots.redaction_budget_root,
        sponsor_settlement_root: roots.sponsor_settlement_root,
        generated_at_l2_height: config.l2_height + 16,
    };
    state
        .insert_operator_summary(summary)
        .expect("devnet summary inserts");

    state.operator_public_notes.insert(
        "devnet-note-001".to_string(),
        json!({
            "kind": "operator_safe_status",
            "message": "devnet seraphis viewkey fee rebate coordinator has one payable private claim",
            "cohort_root": state.roots().cohort_root
        }),
    );

    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let config = state.config.clone();

    let emergency_cohort = SeraphisScanCohort {
        cohort_id: "demo-seraphis-cohort-emergency-001".to_string(),
        lane: ScanLane::EmergencyPrivacy,
        status: CohortStatus::DecoyChecked,
        epoch: config.epoch,
        monero_start_height: config.monero_height - 432,
        monero_end_height: config.monero_height - 216,
        output_count: 32_768,
        scanned_output_count: 29_400,
        wallet_count: 42,
        coordinator_hint_root: sample_root("demo-coordinator-hints", 2),
        encrypted_viewkey_hint_root: sample_root("demo-encrypted-viewkey-hints", 2),
        view_tag_commitment_root: sample_root("demo-view-tags", 2),
        amount_commitment_root: sample_root("demo-amounts", 2),
        nullifier_set_root: sample_root("demo-nullifiers", 2),
        decoy_set_root: sample_root("demo-decoys", 2),
        privacy_score_bps: 9_610,
        decoy_diversity_bps: 9_440,
        min_ring_age_blocks: 144,
        public_hint_bytes: 88,
        opened_at_l2_height: config.l2_height + 32,
        expires_at_l2_height: config.l2_height + 32 + config.cohort_ttl_blocks,
    };
    state
        .insert_cohort(emergency_cohort)
        .expect("demo emergency cohort inserts");

    let redaction_budget = RedactionBudget {
        redaction_id: "demo-redaction-budget-emergency-001".to_string(),
        operator_id: "devnet-operator-alpha".to_string(),
        cohort_id: "demo-seraphis-cohort-emergency-001".to_string(),
        scope: RedactionScope::ViewkeyFragment,
        epoch: config.epoch,
        allocated_units: config.redaction_budget_units,
        spent_units: 768,
        max_public_hint_bytes: config.max_public_hint_bytes,
        public_hint_bytes_used: 72,
        redacted_field_count: 11,
        transcript_root: sample_root("demo-redaction-transcript", 2),
        redaction_receipt_root: sample_root("demo-redaction-receipt", 2),
    };
    state
        .insert_redaction_budget(redaction_budget)
        .expect("demo redaction budget inserts");

    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn runtime_hash(label: &str, value: &Value) -> String {
    domain_hash(
        &format!("{STATE_ROOT_DOMAIN}:{label}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        &format!("{STATE_ROOT_DOMAIN}:SAMPLE:{label}"),
        &[HashPart::U64(index)],
        32,
    )
}

fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(&format!("{STATE_ROOT_DOMAIN}:{domain}"), &leaves)
}

fn record_map<T: PublicRecord>(map: &BTreeMap<String, T>) -> Value {
    Value::Array(
        map.iter()
            .map(|(key, value)| json!({"key": key, "value": value.public_record()}))
            .collect(),
    )
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for SeraphisScanCohort {
    fn public_record(&self) -> Value {
        SeraphisScanCohort::public_record(self)
    }
}

impl PublicRecord for ViewkeyPrivacyBudget {
    fn public_record(&self) -> Value {
        ViewkeyPrivacyBudget::public_record(self)
    }
}

impl PublicRecord for FeeRebateClaim {
    fn public_record(&self) -> Value {
        FeeRebateClaim::public_record(self)
    }
}

impl PublicRecord for PqCoordinatorAttestation {
    fn public_record(&self) -> Value {
        PqCoordinatorAttestation::public_record(self)
    }
}

impl PublicRecord for DecoySafetyCheck {
    fn public_record(&self) -> Value {
        DecoySafetyCheck::public_record(self)
    }
}

impl PublicRecord for SponsorSettlement {
    fn public_record(&self) -> Value {
        SponsorSettlement::public_record(self)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        RedactionBudget::public_record(self)
    }
}

impl PublicRecord for OperatorSafeSummary {
    fn public_record(&self) -> Value {
        OperatorSafeSummary::public_record(self)
    }
}
