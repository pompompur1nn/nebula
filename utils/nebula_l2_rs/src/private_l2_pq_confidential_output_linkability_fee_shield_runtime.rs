use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialOutputLinkabilityFeeShieldRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_OUTPUT_LINKABILITY_FEE_SHIELD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-output-linkability-fee-shield-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_OUTPUT_LINKABILITY_FEE_SHIELD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-output-fee-shield-attestation-v1";
pub const FEE_COMMITMENT_SCHEME: &str = "confidential-fee-pedersen-range-commitment-root-v1";
pub const OUTPUT_COHORT_SCHEME: &str = "monero-output-cohort-linkability-fee-shield-root-v1";
pub const LINKABILITY_SIGNAL_SCHEME: &str = "output-linkability-regression-signal-root-v1";
pub const DECOY_SET_SCHEME: &str = "decoy-set-preservation-public-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-confidential-output-shield-rebate-root-v1";
pub const SETTLEMENT_SCHEME: &str = "fee-shield-settlement-commitment-root-v1";
pub const REDACTION_SCHEME: &str = "operator-redacted-output-fee-shield-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_RUNTIME_ID: &str =
    "private-l2-pq-confidential-output-linkability-fee-shield-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_734_720;
pub const DEVNET_EPOCH: u64 = 3_469;
pub const MAX_BPS: u16 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_OUTPUTS_PER_COHORT: u64 = 65_536;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_HEALTHY_DECOYS: u16 = 15;
pub const DEFAULT_MAX_LINKABILITY_SCORE_BPS: u16 = 100;
pub const DEFAULT_MAX_FEE_BUCKET_LINKABILITY_BPS: u16 = 75;
pub const DEFAULT_MIN_DECOY_PRESERVATION_BPS: u16 = 9_700;
pub const DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_REBATE_BPS: u16 = 6_000;
pub const DEFAULT_OPERATOR_REDACTION_FIELDS: u16 = 4;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000;
pub const MAX_POLICIES: usize = 262_144;
pub const MAX_COHORTS: usize = 1_048_576;
pub const MAX_SIGNALS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldLane {
    WalletTransfer,
    MerchantPayment,
    BridgeDeposit,
    BridgeWithdrawal,
    DefiSettlement,
    ContractReceipt,
    TokenMintBurn,
    AccountAbstraction,
    ReorgReplay,
    OperatorCanary,
}

impl ShieldLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MerchantPayment => "merchant_payment",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractReceipt => "contract_receipt",
            Self::TokenMintBurn => "token_mint_burn",
            Self::AccountAbstraction => "account_abstraction",
            Self::ReorgReplay => "reorg_replay",
            Self::OperatorCanary => "operator_canary",
        }
    }

    pub fn privacy_weight_bps(self) -> u16 {
        match self {
            Self::WalletTransfer => 10_000,
            Self::MerchantPayment => 9_950,
            Self::BridgeDeposit => 9_800,
            Self::BridgeWithdrawal => 9_750,
            Self::DefiSettlement => 9_700,
            Self::ContractReceipt => 9_650,
            Self::TokenMintBurn => 9_550,
            Self::AccountAbstraction => 9_500,
            Self::ReorgReplay => 9_200,
            Self::OperatorCanary => 9_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Drafted,
    Active,
    Tightening,
    Subsidizing,
    Quarantining,
    Paused,
    Retired,
}

impl PolicyStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Tightening | Self::Subsidizing | Self::Quarantining
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Open,
    Sealed,
    Shielded,
    Watch,
    Quarantined,
    Settled,
    Retired,
}

impl CohortStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Shielded | Self::Watch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkabilitySignalKind {
    DecoyAgeSkew,
    RingIntersection,
    FeeBucketFingerprint,
    TimingCluster,
    ChangeOutputHeuristic,
    BridgeBatchFingerprint,
    ContractReceiptBurst,
    RebateCorrelation,
    OperatorCanaryRegression,
}

impl LinkabilitySignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecoyAgeSkew => "decoy_age_skew",
            Self::RingIntersection => "ring_intersection",
            Self::FeeBucketFingerprint => "fee_bucket_fingerprint",
            Self::TimingCluster => "timing_cluster",
            Self::ChangeOutputHeuristic => "change_output_heuristic",
            Self::BridgeBatchFingerprint => "bridge_batch_fingerprint",
            Self::ContractReceiptBurst => "contract_receipt_burst",
            Self::RebateCorrelation => "rebate_correlation",
            Self::OperatorCanaryRegression => "operator_canary_regression",
        }
    }

    pub fn severe(self) -> bool {
        matches!(
            self,
            Self::RingIntersection
                | Self::FeeBucketFingerprint
                | Self::ChangeOutputHeuristic
                | Self::BridgeBatchFingerprint
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalStatus {
    Observed,
    Attested,
    Mitigating,
    Cleared,
    Quarantined,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqWatcher,
    LatticeBatchVerifier,
    DecoyPreservation,
    ConfidentialFeeCommitment,
    RebateEligibility,
    RedactionCompliance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Drafted,
    Verified,
    Challenged,
    Superseded,
    Expired,
    Revoked,
}

impl AttestationStatus {
    pub fn valid(self) -> bool {
        matches!(self, Self::Verified | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    FeeCommitted,
    DecoyPreserved,
    RebateQueued,
    Settled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Offered,
    Reserved,
    Claimed,
    Settled,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    PublicRoot,
    CohortAggregate,
    FeeBucket,
    RebateAggregate,
    AttestationDigest,
    OperatorAction,
}

impl RedactionClass {
    pub fn unit_cost(self) -> u64 {
        match self {
            Self::PublicRoot => 1,
            Self::CohortAggregate => 3,
            Self::FeeBucket => 5,
            Self::RebateAggregate => 5,
            Self::AttestationDigest => 8,
            Self::OperatorAction => 13,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_outputs_per_cohort: u64,
    pub min_ring_size: u16,
    pub min_healthy_decoys: u16,
    pub max_linkability_score_bps: u16,
    pub max_fee_bucket_linkability_bps: u16,
    pub min_decoy_preservation_bps: u16,
    pub low_fee_cap_micro_units: u64,
    pub rebate_bps: u16,
    pub operator_redaction_fields: u16,
    pub redaction_budget_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_outputs_per_cohort: DEFAULT_MIN_OUTPUTS_PER_COHORT,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_healthy_decoys: DEFAULT_MIN_HEALTHY_DECOYS,
            max_linkability_score_bps: DEFAULT_MAX_LINKABILITY_SCORE_BPS,
            max_fee_bucket_linkability_bps: DEFAULT_MAX_FEE_BUCKET_LINKABILITY_BPS,
            min_decoy_preservation_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            rebate_bps: DEFAULT_REBATE_BPS,
            operator_redaction_fields: DEFAULT_OPERATOR_REDACTION_FIELDS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "invalid protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "invalid schema version"
        );
        ensure!(self.epoch_blocks > 0, "epoch blocks must be non-zero");
        ensure!(
            self.min_pq_security_bits >= 192,
            "pq security floor below 192 bits"
        );
        ensure!(self.min_ring_size > 0, "ring size must be non-zero");
        ensure!(
            self.min_healthy_decoys <= self.min_ring_size,
            "healthy decoys cannot exceed ring size"
        );
        ensure!(
            self.max_linkability_score_bps <= MAX_BPS,
            "linkability score cap exceeds bps"
        );
        ensure!(
            self.max_fee_bucket_linkability_bps <= MAX_BPS,
            "fee bucket score cap exceeds bps"
        );
        ensure!(
            self.min_decoy_preservation_bps <= MAX_BPS,
            "decoy preservation floor exceeds bps"
        );
        ensure!(self.rebate_bps <= MAX_BPS, "rebate exceeds bps");
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "runtime_id": self.runtime_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_outputs_per_cohort": self.min_outputs_per_cohort,
            "min_ring_size": self.min_ring_size,
            "min_healthy_decoys": self.min_healthy_decoys,
            "max_linkability_score_bps": self.max_linkability_score_bps,
            "max_fee_bucket_linkability_bps": self.max_fee_bucket_linkability_bps,
            "min_decoy_preservation_bps": self.min_decoy_preservation_bps,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "rebate_bps": self.rebate_bps,
            "operator_redaction_fields": self.operator_redaction_fields,
            "redaction_budget_units": self.redaction_budget_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_count: u64,
    pub cohort_count: u64,
    pub linkability_signal_count: u64,
    pub pq_attestation_count: u64,
    pub settlement_count: u64,
    pub rebate_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub quarantined_cohort_count: u64,
    pub low_fee_shielded_micro_units: u64,
    pub confidential_fee_committed_micro_units: u64,
    pub rebate_reserved_micro_units: u64,
    pub rebate_settled_micro_units: u64,
    pub redaction_units_spent: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldPolicy {
    pub policy_id: String,
    pub lane: ShieldLane,
    pub status: PolicyStatus,
    pub min_outputs_per_cohort: u64,
    pub min_ring_size: u16,
    pub min_healthy_decoys: u16,
    pub max_linkability_score_bps: u16,
    pub max_fee_bucket_linkability_bps: u16,
    pub min_decoy_preservation_bps: u16,
    pub low_fee_cap_micro_units: u64,
    pub rebate_bps: u16,
    pub pq_security_bits: u16,
    pub effective_height: u64,
    pub expires_height: u64,
    pub policy_commitment: String,
}

impl ShieldPolicy {
    pub fn devnet(policy_id: impl Into<String>, lane: ShieldLane, config: &Config) -> Self {
        let policy_id = policy_id.into();
        let commitment = domain_hash(
            "private-l2-output-linkability-fee-shield:policy",
            &[
                HashPart::Str(&policy_id),
                HashPart::Str(lane.as_str()),
                HashPart::U64(DEVNET_HEIGHT),
            ],
            32,
        );
        Self {
            policy_id,
            lane,
            status: PolicyStatus::Active,
            min_outputs_per_cohort: config.min_outputs_per_cohort,
            min_ring_size: config.min_ring_size,
            min_healthy_decoys: config.min_healthy_decoys,
            max_linkability_score_bps: config.max_linkability_score_bps,
            max_fee_bucket_linkability_bps: config.max_fee_bucket_linkability_bps,
            min_decoy_preservation_bps: config.min_decoy_preservation_bps,
            low_fee_cap_micro_units: config.low_fee_cap_micro_units,
            rebate_bps: config.rebate_bps,
            pq_security_bits: config.min_pq_security_bits,
            effective_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT + (config.epoch_blocks * 8),
            policy_commitment: commitment,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.policy_id.is_empty(), "policy id is empty");
        ensure!(
            self.min_ring_size >= config.min_ring_size,
            "ring floor regressed"
        );
        ensure!(
            self.min_healthy_decoys >= config.min_healthy_decoys,
            "healthy decoy floor regressed"
        );
        ensure!(
            self.max_linkability_score_bps <= config.max_linkability_score_bps,
            "linkability cap loosened"
        );
        ensure!(
            self.max_fee_bucket_linkability_bps <= config.max_fee_bucket_linkability_bps,
            "fee bucket cap loosened"
        );
        ensure!(
            self.min_decoy_preservation_bps >= config.min_decoy_preservation_bps,
            "decoy preservation floor regressed"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "policy pq security too low"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "lane": self.lane,
            "status": self.status,
            "min_outputs_per_cohort": self.min_outputs_per_cohort,
            "min_ring_size": self.min_ring_size,
            "min_healthy_decoys": self.min_healthy_decoys,
            "max_linkability_score_bps": self.max_linkability_score_bps,
            "max_fee_bucket_linkability_bps": self.max_fee_bucket_linkability_bps,
            "min_decoy_preservation_bps": self.min_decoy_preservation_bps,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "rebate_bps": self.rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
            "policy_commitment": self.policy_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub lane: ShieldLane,
    pub status: CohortStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub output_count: u64,
    pub ring_size_floor: u16,
    pub healthy_decoy_floor: u16,
    pub output_commitment_root: String,
    pub fee_bucket_root: String,
    pub decoy_set_root: String,
    pub view_tag_sample_root: String,
    pub cohort_entropy_commitment: String,
}

impl OutputCohort {
    pub fn privacy_floor_bps(&self, config: &Config) -> u16 {
        let output_score = ratio_bps(self.output_count, config.min_outputs_per_cohort);
        let ring_score = ratio_bps(self.ring_size_floor as u64, config.min_ring_size as u64);
        let decoy_score = ratio_bps(
            self.healthy_decoy_floor as u64,
            config.min_healthy_decoys as u64,
        );
        output_score.min(ring_score).min(decoy_score)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "policy_id": self.policy_id,
            "lane": self.lane,
            "status": self.status,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "output_count": self.output_count,
            "ring_size_floor": self.ring_size_floor,
            "healthy_decoy_floor": self.healthy_decoy_floor,
            "output_commitment_root": self.output_commitment_root,
            "fee_bucket_root": self.fee_bucket_root,
            "decoy_set_root": self.decoy_set_root,
            "view_tag_sample_root": self.view_tag_sample_root,
            "cohort_entropy_commitment": self.cohort_entropy_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkabilitySignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub kind: LinkabilitySignalKind,
    pub status: SignalStatus,
    pub score_bps: u16,
    pub fee_bucket_score_bps: u16,
    pub decoy_preservation_bps: u16,
    pub affected_output_commitment_root: String,
    pub evidence_commitment: String,
    pub mitigation_commitment: String,
    pub observed_height: u64,
}

impl LinkabilitySignal {
    pub fn regression(&self, config: &Config) -> bool {
        self.score_bps > config.max_linkability_score_bps
            || self.fee_bucket_score_bps > config.max_fee_bucket_linkability_bps
            || self.decoy_preservation_bps < config.min_decoy_preservation_bps
            || self.kind.severe()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "score_bps": self.score_bps,
            "fee_bucket_score_bps": self.fee_bucket_score_bps,
            "decoy_preservation_bps": self.decoy_preservation_bps,
            "affected_output_commitment_root": self.affected_output_commitment_root,
            "evidence_commitment": self.evidence_commitment,
            "mitigation_commitment": self.mitigation_commitment,
            "observed_height": self.observed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub subject_id: String,
    pub signer_committee_root: String,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub statement_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub not_before_height: u64,
    pub not_after_height: u64,
}

impl PqAttestation {
    pub fn validates_subject(&self, subject_id: &str, config: &Config, height: u64) -> bool {
        self.subject_id == subject_id
            && self.status.valid()
            && self.pq_scheme == PQ_ATTESTATION_SUITE
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.not_before_height <= height
            && height <= self.not_after_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind,
            "status": self.status,
            "subject_id": self.subject_id,
            "signer_committee_root": self.signer_committee_root,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "statement_root": self.statement_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "not_before_height": self.not_before_height,
            "not_after_height": self.not_after_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeShieldSettlement {
    pub settlement_id: String,
    pub cohort_id: String,
    pub status: SettlementStatus,
    pub gross_fee_commitment: String,
    pub net_fee_commitment: String,
    pub fee_range_proof_root: String,
    pub decoy_preservation_root: String,
    pub low_fee_cap_micro_units: u64,
    pub confidential_fee_bucket_count: u64,
    pub settlement_height: u64,
    pub attestation_ids: Vec<String>,
}

impl FeeShieldSettlement {
    pub fn confidential(&self) -> bool {
        !self.gross_fee_commitment.is_empty()
            && !self.net_fee_commitment.is_empty()
            && !self.fee_range_proof_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "gross_fee_commitment": self.gross_fee_commitment,
            "net_fee_commitment": self.net_fee_commitment,
            "fee_range_proof_root": self.fee_range_proof_root,
            "decoy_preservation_root": self.decoy_preservation_root,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "confidential_fee_bucket_count": self.confidential_fee_bucket_count,
            "settlement_height": self.settlement_height,
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub status: RebateStatus,
    pub recipient_class_root: String,
    pub eligibility_root: String,
    pub amount_commitment: String,
    pub reserved_micro_units: u64,
    pub settled_micro_units: u64,
    pub expires_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "status": self.status,
            "recipient_class_root": self.recipient_class_root,
            "eligibility_root": self.eligibility_root,
            "amount_commitment": self.amount_commitment,
            "reserved_micro_units": self.reserved_micro_units,
            "settled_micro_units": self.settled_micro_units,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub class: RedactionClass,
    pub epoch: u64,
    pub allowance_units: u64,
    pub spent_units: u64,
    pub redacted_field_root: String,
    pub disclosure_commitment: String,
}

impl RedactionBudget {
    pub fn spend(&mut self, units: u64) -> Result<()> {
        ensure!(
            self.spent_units.saturating_add(units) <= self.allowance_units,
            "redaction budget exceeded for {}",
            self.budget_id
        );
        self.spent_units += units;
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.allowance_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "class": self.class,
            "epoch": self.epoch,
            "allowance_units": self.allowance_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "redacted_field_root": self.redacted_field_root,
            "disclosure_commitment": self.disclosure_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub cohort_root: String,
    pub signal_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub pq_attestation_root: String,
    pub redacted_fields: BTreeSet<String>,
    pub privacy_floor_bps: u16,
    pub low_fee_cap_micro_units: u64,
    pub generated_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "cohort_root": self.cohort_root,
            "signal_root": self.signal_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "redaction_root": self.redaction_root,
            "pq_attestation_root": self.pq_attestation_root,
            "redacted_field_count": self.redacted_fields.len(),
            "privacy_floor_bps": self.privacy_floor_bps,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "generated_height": self.generated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub output_cohort_root: String,
    pub linkability_signal_root: String,
    pub pq_attestation_root: String,
    pub fee_shield_settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub policies: BTreeMap<String, ShieldPolicy>,
    pub output_cohorts: BTreeMap<String, OutputCohort>,
    pub linkability_signals: BTreeMap<String, LinkabilitySignal>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub fee_shield_settlements: BTreeMap<String, FeeShieldSettlement>,
    pub rebates: BTreeMap<String, Rebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config: config.clone(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            policies: BTreeMap::new(),
            output_cohorts: BTreeMap::new(),
            linkability_signals: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_shield_settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };

        let wallet_policy = ShieldPolicy::devnet(
            "policy-wallet-transfer-low-fee-shield",
            ShieldLane::WalletTransfer,
            &config,
        );
        let bridge_policy = ShieldPolicy::devnet(
            "policy-bridge-withdrawal-decoy-preserve",
            ShieldLane::BridgeWithdrawal,
            &config,
        );
        state
            .policies
            .insert(wallet_policy.policy_id.clone(), wallet_policy);
        state
            .policies
            .insert(bridge_policy.policy_id.clone(), bridge_policy);

        let cohort_id = "cohort-wallet-transfer-3469-a".to_string();
        let output_commitment_root = sample_root("output-commitments", &cohort_id);
        let fee_bucket_root = sample_root("confidential-fee-buckets", &cohort_id);
        let decoy_set_root = sample_root("decoy-set-preservation", &cohort_id);
        let view_tag_sample_root = sample_root("view-tag-samples", &cohort_id);
        let cohort_entropy_commitment = domain_hash(
            "private-l2-output-linkability-fee-shield:cohort-entropy",
            &[HashPart::Str(&cohort_id), HashPart::U64(DEVNET_EPOCH)],
            32,
        );
        state.output_cohorts.insert(
            cohort_id.clone(),
            OutputCohort {
                cohort_id: cohort_id.clone(),
                policy_id: "policy-wallet-transfer-low-fee-shield".to_string(),
                lane: ShieldLane::WalletTransfer,
                status: CohortStatus::Shielded,
                start_height: DEVNET_HEIGHT - DEFAULT_EPOCH_BLOCKS,
                end_height: DEVNET_HEIGHT,
                output_count: DEFAULT_MIN_OUTPUTS_PER_COHORT + 8_192,
                ring_size_floor: DEFAULT_MIN_RING_SIZE,
                healthy_decoy_floor: DEFAULT_MIN_HEALTHY_DECOYS,
                output_commitment_root,
                fee_bucket_root,
                decoy_set_root,
                view_tag_sample_root,
                cohort_entropy_commitment,
            },
        );

        let signal_id = "signal-wallet-fee-bucket-canary-3469".to_string();
        state.linkability_signals.insert(
            signal_id.clone(),
            LinkabilitySignal {
                signal_id: signal_id.clone(),
                cohort_id: cohort_id.clone(),
                kind: LinkabilitySignalKind::FeeBucketFingerprint,
                status: SignalStatus::Mitigating,
                score_bps: 88,
                fee_bucket_score_bps: 61,
                decoy_preservation_bps: 9_812,
                affected_output_commitment_root: sample_root("affected-outputs", &signal_id),
                evidence_commitment: sample_root("redacted-evidence", &signal_id),
                mitigation_commitment: sample_root("fee-bucket-mitigation", &signal_id),
                observed_height: DEVNET_HEIGHT - 12,
            },
        );

        let attestation_id = "pq-attestation-wallet-cohort-3469".to_string();
        state.pq_attestations.insert(
            attestation_id.clone(),
            PqAttestation {
                attestation_id: attestation_id.clone(),
                kind: AttestationKind::ConfidentialFeeCommitment,
                status: AttestationStatus::Verified,
                subject_id: cohort_id.clone(),
                signer_committee_root: sample_root("pq-committee", &attestation_id),
                pq_scheme: PQ_ATTESTATION_SUITE.to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                statement_root: sample_root("pq-statement", &attestation_id),
                transcript_root: sample_root("pq-transcript", &attestation_id),
                signature_root: sample_root("pq-signature", &attestation_id),
                not_before_height: DEVNET_HEIGHT - DEFAULT_EPOCH_BLOCKS,
                not_after_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS,
            },
        );

        let settlement_id = "settlement-wallet-fee-shield-3469".to_string();
        state.fee_shield_settlements.insert(
            settlement_id.clone(),
            FeeShieldSettlement {
                settlement_id: settlement_id.clone(),
                cohort_id: cohort_id.clone(),
                status: SettlementStatus::RebateQueued,
                gross_fee_commitment: sample_root("gross-fee-commitment", &settlement_id),
                net_fee_commitment: sample_root("net-fee-commitment", &settlement_id),
                fee_range_proof_root: sample_root("fee-range-proof", &settlement_id),
                decoy_preservation_root: sample_root("settlement-decoys", &settlement_id),
                low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
                confidential_fee_bucket_count: 128,
                settlement_height: DEVNET_HEIGHT,
                attestation_ids: vec![attestation_id],
            },
        );

        state.rebates.insert(
            "rebate-wallet-low-fee-3469".to_string(),
            Rebate {
                rebate_id: "rebate-wallet-low-fee-3469".to_string(),
                settlement_id: settlement_id.clone(),
                status: RebateStatus::Reserved,
                recipient_class_root: sample_root("rebate-recipient-class", &settlement_id),
                eligibility_root: sample_root("rebate-eligibility", &settlement_id),
                amount_commitment: sample_root("rebate-amount", &settlement_id),
                reserved_micro_units: 1_500_000,
                settled_micro_units: 0,
                expires_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS,
            },
        );

        let mut redacted_fields = BTreeSet::new();
        redacted_fields.insert("fee_bucket_histogram".to_string());
        redacted_fields.insert("output_timing_samples".to_string());
        redacted_fields.insert("rebate_recipient_classes".to_string());
        state.redaction_budgets.insert(
            "redaction-operator-alpha-3469".to_string(),
            RedactionBudget {
                budget_id: "redaction-operator-alpha-3469".to_string(),
                operator_id: "operator-alpha".to_string(),
                class: RedactionClass::OperatorAction,
                epoch: DEVNET_EPOCH,
                allowance_units: DEFAULT_REDACTION_BUDGET_UNITS,
                spent_units: 39,
                redacted_field_root: sample_root("redacted-fields", "operator-alpha"),
                disclosure_commitment: sample_root("operator-disclosure", "operator-alpha"),
            },
        );

        let roots = state.roots();
        state.operator_summaries.insert(
            "summary-operator-alpha-3469".to_string(),
            OperatorSummary {
                summary_id: "summary-operator-alpha-3469".to_string(),
                operator_id: "operator-alpha".to_string(),
                epoch: DEVNET_EPOCH,
                cohort_root: roots.output_cohort_root,
                signal_root: roots.linkability_signal_root,
                settlement_root: roots.fee_shield_settlement_root,
                rebate_root: roots.rebate_root,
                redaction_root: roots.redaction_budget_root,
                pq_attestation_root: roots.pq_attestation_root,
                redacted_fields,
                privacy_floor_bps: 9_812,
                low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
                generated_height: DEVNET_HEIGHT,
            },
        );

        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            policy_count: self.policies.len() as u64,
            cohort_count: self.output_cohorts.len() as u64,
            linkability_signal_count: self.linkability_signals.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            settlement_count: self.fee_shield_settlements.len() as u64,
            rebate_count: self.rebates.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            quarantined_cohort_count: self
                .output_cohorts
                .values()
                .filter(|cohort| cohort.status == CohortStatus::Quarantined)
                .count() as u64,
            low_fee_shielded_micro_units: self
                .fee_shield_settlements
                .values()
                .map(|settlement| settlement.low_fee_cap_micro_units)
                .sum(),
            confidential_fee_committed_micro_units: self
                .fee_shield_settlements
                .values()
                .filter(|settlement| settlement.confidential())
                .map(|settlement| settlement.low_fee_cap_micro_units)
                .sum(),
            rebate_reserved_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.reserved_micro_units)
                .sum(),
            rebate_settled_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.settled_micro_units)
                .sum(),
            redaction_units_spent: self
                .redaction_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
        }
    }

    pub fn add_policy(&mut self, policy: ShieldPolicy) -> Result<()> {
        ensure!(self.policies.len() < MAX_POLICIES, "policy limit reached");
        policy.validate(&self.config)?;
        ensure!(
            !self.policies.contains_key(&policy.policy_id),
            "duplicate policy {}",
            policy.policy_id
        );
        self.policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn add_output_cohort(&mut self, cohort: OutputCohort) -> Result<()> {
        ensure!(
            self.output_cohorts.len() < MAX_COHORTS,
            "cohort limit reached"
        );
        ensure!(
            self.policies.contains_key(&cohort.policy_id),
            "unknown cohort policy {}",
            cohort.policy_id
        );
        ensure!(
            cohort.output_count >= self.config.min_outputs_per_cohort,
            "cohort output floor regressed"
        );
        ensure!(
            cohort.ring_size_floor >= self.config.min_ring_size,
            "cohort ring floor regressed"
        );
        ensure!(
            cohort.healthy_decoy_floor >= self.config.min_healthy_decoys,
            "cohort decoy floor regressed"
        );
        self.output_cohorts.insert(cohort.cohort_id.clone(), cohort);
        Ok(())
    }

    pub fn record_linkability_signal(&mut self, signal: LinkabilitySignal) -> Result<()> {
        ensure!(
            self.linkability_signals.len() < MAX_SIGNALS,
            "linkability signal limit reached"
        );
        ensure!(
            self.output_cohorts.contains_key(&signal.cohort_id),
            "unknown signal cohort {}",
            signal.cohort_id
        );
        ensure!(signal.score_bps <= MAX_BPS, "signal score exceeds bps");
        ensure!(
            signal.fee_bucket_score_bps <= MAX_BPS,
            "fee bucket score exceeds bps"
        );
        ensure!(
            signal.decoy_preservation_bps <= MAX_BPS,
            "decoy preservation exceeds bps"
        );
        if signal.regression(&self.config) {
            if let Some(cohort) = self.output_cohorts.get_mut(&signal.cohort_id) {
                cohort.status = CohortStatus::Watch;
            }
        }
        self.linkability_signals
            .insert(signal.signal_id.clone(), signal);
        Ok(())
    }

    pub fn add_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "pq attestation limit reached"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security too low"
        );
        ensure!(
            attestation.pq_scheme == PQ_ATTESTATION_SUITE,
            "unsupported pq attestation suite"
        );
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn settle_fee_shield(&mut self, settlement: FeeShieldSettlement) -> Result<()> {
        ensure!(
            self.fee_shield_settlements.len() < MAX_SETTLEMENTS,
            "settlement limit reached"
        );
        ensure!(
            self.output_cohorts.contains_key(&settlement.cohort_id),
            "unknown settlement cohort {}",
            settlement.cohort_id
        );
        ensure!(settlement.confidential(), "settlement is not confidential");
        ensure!(
            settlement.low_fee_cap_micro_units <= self.config.low_fee_cap_micro_units,
            "low fee cap exceeded"
        );
        let missing_attestations = settlement
            .attestation_ids
            .iter()
            .filter(|id| {
                self.pq_attestations
                    .get(*id)
                    .map(|attestation| {
                        !attestation.validates_subject(
                            &settlement.cohort_id,
                            &self.config,
                            settlement.settlement_height,
                        )
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            missing_attestations.is_empty(),
            "settlement has invalid attestations {:?}",
            missing_attestations
        );
        self.fee_shield_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(())
    }

    pub fn reserve_rebate(&mut self, rebate: Rebate) -> Result<()> {
        ensure!(self.rebates.len() < MAX_REBATES, "rebate limit reached");
        ensure!(
            self.fee_shield_settlements
                .contains_key(&rebate.settlement_id),
            "unknown rebate settlement {}",
            rebate.settlement_id
        );
        ensure!(
            !rebate.amount_commitment.is_empty(),
            "rebate amount commitment is empty"
        );
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        redaction_class: RedactionClass,
    ) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown redaction budget {budget_id}"))?;
        ensure!(
            budget.class == redaction_class,
            "redaction class mismatch for {}",
            budget_id
        );
        budget.spend(redaction_class.unit_cost())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("config", &[self.config.public_record()]),
            policy_root: records_root(
                "policies",
                self.policies
                    .values()
                    .map(ShieldPolicy::public_record)
                    .collect::<Vec<_>>(),
            ),
            output_cohort_root: records_root(
                "output-cohorts",
                self.output_cohorts
                    .values()
                    .map(OutputCohort::public_record)
                    .collect::<Vec<_>>(),
            ),
            linkability_signal_root: records_root(
                "linkability-signals",
                self.linkability_signals
                    .values()
                    .map(LinkabilitySignal::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: records_root(
                "pq-attestations",
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_shield_settlement_root: records_root(
                "fee-shield-settlements",
                self.fee_shield_settlements
                    .values()
                    .map(FeeShieldSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: records_root(
                "rebates",
                self.rebates
                    .values()
                    .map(Rebate::public_record)
                    .collect::<Vec<_>>(),
            ),
            redaction_budget_root: records_root(
                "redaction-budgets",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect::<Vec<_>>(),
            ),
            operator_summary_root: records_root(
                "operator-summaries",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect::<Vec<_>>(),
            ),
            counters_root: value_root("counters", &[self.counters().public_record()]),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "private-l2-output-linkability-fee-shield:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "fee_commitment_scheme": FEE_COMMITMENT_SCHEME,
            "output_cohort_scheme": OUTPUT_COHORT_SCHEME,
            "linkability_signal_scheme": LINKABILITY_SIGNAL_SCHEME,
            "decoy_set_scheme": DECOY_SET_SCHEME,
            "rebate_scheme": REBATE_SCHEME,
            "settlement_scheme": SETTLEMENT_SCHEME,
            "redaction_scheme": REDACTION_SCHEME,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
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

fn ratio_bps(value: u64, floor: u64) -> u16 {
    if floor == 0 {
        return MAX_BPS;
    }
    (((value.saturating_mul(MAX_BPS as u64)) / floor).min(MAX_BPS as u64)) as u16
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    value_root(domain, &records)
}

fn value_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("private-l2-output-linkability-fee-shield:{domain}"),
        records,
    )
}

fn sample_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("private-l2-output-linkability-fee-shield:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(seed)],
        32,
    )
}
