use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSubaddressOutputRecoveryMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_OUTPUT_RECOVERY_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-subaddress-output-recovery-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_OUTPUT_RECOVERY_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_HEIGHT: u64 = 1_557_760;
pub const DEVNET_EPOCH: u64 = 8_192;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const RECOVERY_COHORT_SCHEME: &str = "private-subaddress-recovery-cohort-root-v1";
pub const OUTPUT_HINT_SCHEME: &str = "ml-kem-1024-encrypted-recovery-output-hint-root-v1";
pub const SEARCH_PROVIDER_SCHEME: &str = "pq-private-subaddress-recovery-provider-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-subaddress-output-recovery-attestation-v1";
pub const DECOY_PROOF_SCHEME: &str = "decoy-preserving-recovery-proof-commitment-root-v1";
pub const SETTLEMENT_SCHEME: &str = "low-fee-private-output-recovery-settlement-root-v1";
pub const REBATE_SCHEME: &str = "recovery-market-fee-rebate-commitment-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "operator-safe-subaddress-output-recovery-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "redacted-subaddress-output-recovery-operator-summary-root-v1";
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_RING_DECOYS: u16 = 32;
pub const DEFAULT_TARGET_RING_DECOYS: u16 = 96;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_RECOVERY_FEE_MICRO_UNITS: u64 = 3_200;
pub const DEFAULT_LOW_FEE_SETTLEMENT_BPS: u16 = 5;
pub const DEFAULT_PROVIDER_REWARD_BPS: u16 = 7_000;
pub const DEFAULT_REBATE_BPS: u16 = 1_500;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u32 = 32;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_RECOVERY_COHORTS: usize = 1_048_576;
pub const MAX_OUTPUT_HINTS: usize = 4_194_304;
pub const MAX_SEARCH_PROVIDERS: usize = 262_144;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_DECOY_PROOFS: usize = 2_097_152;
pub const MAX_SETTLEMENTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    WalletRestore,
    WatchOnlyRepair,
    MobileFastRestore,
    EstateRecovery,
    MerchantResync,
    ReorgRecovery,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WatchOnlyRepair => "watch_only_repair",
            Self::MobileFastRestore => "mobile_fast_restore",
            Self::EstateRecovery => "estate_recovery",
            Self::MerchantResync => "merchant_resync",
            Self::ReorgRecovery => "reorg_recovery",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::ReorgRecovery => 10_000,
            Self::EstateRecovery => 9_400,
            Self::WalletRestore => 9_000,
            Self::MobileFastRestore => 8_300,
            Self::MerchantResync => 7_800,
            Self::WatchOnlyRepair => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Open,
    Sealed,
    Searching,
    Proved,
    Settled,
    Expired,
    Disputed,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Searching => "searching",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Searching | Self::Proved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintKind {
    ViewTagShard,
    SubaddressRange,
    EncryptedPaymentId,
    OutputCommitment,
    SpendableCandidate,
    ReorgRepair,
}

impl HintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagShard => "view_tag_shard",
            Self::SubaddressRange => "subaddress_range",
            Self::EncryptedPaymentId => "encrypted_payment_id",
            Self::OutputCommitment => "output_commitment",
            Self::SpendableCandidate => "spendable_candidate",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Candidate,
    Active,
    RateLimited,
    Slashed,
    Retired,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureValid,
    HintEncryptionValid,
    CohortCoverage,
    OutputDiscoveryCompleteness,
    DecoyPreservation,
    SettlementIntegrity,
    RedactionCompliance,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureValid => "pq_signature_valid",
            Self::HintEncryptionValid => "hint_encryption_valid",
            Self::CohortCoverage => "cohort_coverage",
            Self::OutputDiscoveryCompleteness => "output_discovery_completeness",
            Self::DecoyPreservation => "decoy_preservation",
            Self::SettlementIntegrity => "settlement_integrity",
            Self::RedactionCompliance => "redaction_compliance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Attested,
    RebateReserved,
    Settled,
    Refunded,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Attested => "attested",
            Self::RebateReserved => "rebate_reserved",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    LowFeeSponsored,
    IncompleteSearch,
    MobileRestoreDiscount,
    EstateRecoveryWaiver,
    ReorgRepairCredit,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::IncompleteSearch => "incomplete_search",
            Self::MobileRestoreDiscount => "mobile_restore_discount",
            Self::EstateRecoveryWaiver => "estate_recovery_waiver",
            Self::ReorgRepairCredit => "reorg_repair_credit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub recovery_cohort_scheme: String,
    pub output_hint_scheme: String,
    pub search_provider_scheme: String,
    pub pq_attestation_scheme: String,
    pub decoy_proof_scheme: String,
    pub settlement_scheme: String,
    pub rebate_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub cohort_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_ring_decoys: u16,
    pub target_ring_decoys: u16,
    pub min_pq_security_bits: u16,
    pub max_recovery_fee_micro_units: u64,
    pub low_fee_settlement_bps: u16,
    pub provider_reward_bps: u16,
    pub rebate_bps: u16,
    pub redaction_budget_per_epoch: u32,
    pub require_decoy_preserving_proof: bool,
    pub allow_low_fee_rebates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            recovery_cohort_scheme: RECOVERY_COHORT_SCHEME.to_string(),
            output_hint_scheme: OUTPUT_HINT_SCHEME.to_string(),
            search_provider_scheme: SEARCH_PROVIDER_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            decoy_proof_scheme: DECOY_PROOF_SCHEME.to_string(),
            settlement_scheme: SETTLEMENT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_ring_decoys: DEFAULT_MIN_RING_DECOYS,
            target_ring_decoys: DEFAULT_TARGET_RING_DECOYS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_recovery_fee_micro_units: DEFAULT_MAX_RECOVERY_FEE_MICRO_UNITS,
            low_fee_settlement_bps: DEFAULT_LOW_FEE_SETTLEMENT_BPS,
            provider_reward_bps: DEFAULT_PROVIDER_REWARD_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            require_decoy_preserving_proof: true,
            allow_low_fee_rebates: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "recovery_cohort_scheme": self.recovery_cohort_scheme,
            "output_hint_scheme": self.output_hint_scheme,
            "search_provider_scheme": self.search_provider_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "decoy_proof_scheme": self.decoy_proof_scheme,
            "settlement_scheme": self.settlement_scheme,
            "rebate_scheme": self.rebate_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_ring_decoys": self.min_ring_decoys,
            "target_ring_decoys": self.target_ring_decoys,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_recovery_fee_micro_units": self.max_recovery_fee_micro_units,
            "low_fee_settlement_bps": self.low_fee_settlement_bps,
            "provider_reward_bps": self.provider_reward_bps,
            "rebate_bps": self.rebate_bps,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "require_decoy_preserving_proof": self.require_decoy_preserving_proof,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub recovery_cohorts: u64,
    pub output_hints: u64,
    pub search_providers: u64,
    pub pq_attestations: u64,
    pub decoy_preserving_proofs: u64,
    pub recovery_settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_cohorts": self.recovery_cohorts,
            "output_hints": self.output_hints,
            "search_providers": self.search_providers,
            "pq_attestations": self.pq_attestations,
            "decoy_preserving_proofs": self.decoy_preserving_proofs,
            "recovery_settlements": self.recovery_settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub recovery_cohort_root: String,
    pub output_hint_root: String,
    pub search_provider_root: String,
    pub pq_attestation_root: String,
    pub decoy_preserving_proof_root: String,
    pub recovery_settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub operator_safe_summary_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            recovery_cohort_root: empty_root("recovery-cohorts"),
            output_hint_root: empty_root("output-hints"),
            search_provider_root: empty_root("search-providers"),
            pq_attestation_root: empty_root("pq-attestations"),
            decoy_preserving_proof_root: empty_root("decoy-preserving-proofs"),
            recovery_settlement_root: empty_root("recovery-settlements"),
            rebate_root: empty_root("rebates"),
            redaction_budget_root: empty_root("redaction-budgets"),
            operator_summary_root: empty_root("operator-summaries"),
            public_record_root: empty_root("public-records"),
            operator_safe_summary_root: empty_root("operator-safe-summary"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_cohort_root": self.recovery_cohort_root,
            "output_hint_root": self.output_hint_root,
            "search_provider_root": self.search_provider_root,
            "pq_attestation_root": self.pq_attestation_root,
            "decoy_preserving_proof_root": self.decoy_preserving_proof_root,
            "recovery_settlement_root": self.recovery_settlement_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "public_record_root": self.public_record_root,
            "operator_safe_summary_root": self.operator_safe_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryCohort {
    pub cohort_id: String,
    pub lane: RecoveryLane,
    pub wallet_group_commitment: String,
    pub subaddress_range_commitment: String,
    pub view_tag_prefix_root: String,
    pub request_ciphertext_root: String,
    pub privacy_set_size: u64,
    pub requested_output_count: u32,
    pub min_ring_decoys: u16,
    pub target_ring_decoys: u16,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: CohortStatus,
    pub provider_ids: BTreeSet<String>,
    pub hint_ids: BTreeSet<String>,
}

impl RecoveryCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "view_tag_prefix_root": self.view_tag_prefix_root,
            "request_ciphertext_root": self.request_ciphertext_root,
            "privacy_set_size": self.privacy_set_size,
            "requested_output_count": self.requested_output_count,
            "min_ring_decoys": self.min_ring_decoys,
            "target_ring_decoys": self.target_ring_decoys,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "provider_count": self.provider_ids.len(),
            "hint_count": self.hint_ids.len(),
            "wallet_group_commitment_redacted": true,
            "subaddress_range_commitment_redacted": true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub provider_id: String,
    pub kind: HintKind,
    pub encrypted_hint_root: String,
    pub output_commitment_root: String,
    pub decoy_set_root: String,
    pub hint_count: u32,
    pub false_positive_floor_bps: u16,
    pub monero_height: u64,
    pub expires_height: u64,
}

impl OutputHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "cohort_id": self.cohort_id,
            "provider_id": self.provider_id,
            "kind": self.kind.as_str(),
            "encrypted_hint_root": self.encrypted_hint_root,
            "output_commitment_root": self.output_commitment_root,
            "decoy_set_root": self.decoy_set_root,
            "hint_count": self.hint_count,
            "false_positive_floor_bps": self.false_positive_floor_bps,
            "monero_height": self.monero_height,
            "expires_height": self.expires_height,
            "plaintext_output_indexes_redacted": true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SearchProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub endpoint_commitment: String,
    pub pq_identity_root: String,
    pub supported_lanes: BTreeSet<RecoveryLane>,
    pub status: ProviderStatus,
    pub stake_commitment: String,
    pub max_fee_micro_units: u64,
    pub completed_recoveries: u64,
    pub slash_count: u32,
}

impl SearchProvider {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "endpoint_commitment": self.endpoint_commitment,
            "pq_identity_root": self.pq_identity_root,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "stake_commitment": self.stake_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "completed_recoveries": self.completed_recoveries,
            "slash_count": self.slash_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub cohort_id: String,
    pub provider_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "cohort_id": self.cohort_id,
            "provider_id": self.provider_id,
            "kind": self.kind.as_str(),
            "statement_root": self.statement_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyPreservingRecoveryProof {
    pub proof_id: String,
    pub cohort_id: String,
    pub provider_id: String,
    pub proof_commitment_root: String,
    pub ring_member_commitment_root: String,
    pub decoy_distribution_root: String,
    pub recovered_output_count: u32,
    pub min_ring_decoys: u16,
    pub entropy_floor_bps: u16,
    pub nullifier_fence_root: String,
}

impl DecoyPreservingRecoveryProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "cohort_id": self.cohort_id,
            "provider_id": self.provider_id,
            "proof_commitment_root": self.proof_commitment_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "recovered_output_count": self.recovered_output_count,
            "min_ring_decoys": self.min_ring_decoys,
            "entropy_floor_bps": self.entropy_floor_bps,
            "nullifier_fence_root": self.nullifier_fence_root,
            "spendable_outputs_redacted": true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoverySettlement {
    pub settlement_id: String,
    pub cohort_id: String,
    pub provider_id: String,
    pub proof_id: String,
    pub fee_micro_units: u64,
    pub provider_reward_micro_units: u64,
    pub protocol_fee_micro_units: u64,
    pub settlement_anchor_root: String,
    pub settled_height: u64,
    pub status: SettlementStatus,
}

impl RecoverySettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "cohort_id": self.cohort_id,
            "provider_id": self.provider_id,
            "proof_id": self.proof_id,
            "fee_micro_units": self.fee_micro_units,
            "provider_reward_micro_units": self.provider_reward_micro_units,
            "protocol_fee_micro_units": self.protocol_fee_micro_units,
            "settlement_anchor_root": self.settlement_anchor_root,
            "settled_height": self.settled_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub beneficiary_commitment: String,
    pub reason: RebateReason,
    pub rebate_micro_units: u64,
    pub sponsor_commitment: String,
    pub claimed: bool,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "reason": self.reason.as_str(),
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_commitment": self.sponsor_commitment,
            "claimed": self.claimed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub epoch: u64,
    pub allowance: u32,
    pub spent: u32,
    pub public_reason: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_id": self.subject_id,
            "epoch": self.epoch,
            "allowance": self.allowance,
            "spent": self.spent,
            "remaining": self.allowance.saturating_sub(self.spent),
            "public_reason": self.public_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub cohorts_served: u64,
    pub hints_delivered: u64,
    pub proofs_accepted: u64,
    pub rebates_paid_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub redacted_summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "epoch": self.epoch,
            "cohorts_served": self.cohorts_served,
            "hints_delivered": self.hints_delivered,
            "proofs_accepted": self.proofs_accepted,
            "rebates_paid_micro_units": self.rebates_paid_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "redacted_summary_root": self.redacted_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub recovery_cohorts: BTreeMap<String, RecoveryCohort>,
    pub output_hints: BTreeMap<String, OutputHint>,
    pub search_providers: BTreeMap<String, SearchProvider>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub decoy_preserving_proofs: BTreeMap<String, DecoyPreservingRecoveryProof>,
    pub recovery_settlements: BTreeMap<String, RecoverySettlement>,
    pub rebates: BTreeMap<String, Rebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: Vec<Value>,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            recovery_cohorts: BTreeMap::new(),
            output_hints: BTreeMap::new(),
            search_providers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            decoy_preserving_proofs: BTreeMap::new(),
            recovery_settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: Vec::new(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed("wallet-restore-alpha", RecoveryLane::WalletRestore);
        state.seed("mobile-fast-restore-beta", RecoveryLane::MobileFastRestore);
        state.seed("reorg-recovery-gamma", RecoveryLane::ReorgRecovery);
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn counters(&self) -> Counters {
        Counters {
            recovery_cohorts: self.recovery_cohorts.len() as u64,
            output_hints: self.output_hints.len() as u64,
            search_providers: self.search_providers.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            decoy_preserving_proofs: self.decoy_preserving_proofs.len() as u64,
            recovery_settlements: self.recovery_settlements.len() as u64,
            rebates: self.rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            public_records: self.public_records.len() as u64,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_summary": self.operator_safe_summary(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn register_provider(
        &mut self,
        operator_commitment: String,
        endpoint_commitment: String,
        pq_identity_root: String,
        stake_commitment: String,
        supported_lanes: BTreeSet<RecoveryLane>,
        max_fee_micro_units: u64,
    ) -> Result<String> {
        ensure!(
            self.search_providers.len() < MAX_SEARCH_PROVIDERS,
            "search provider capacity exceeded"
        );
        require_nonempty("operator_commitment", &operator_commitment)?;
        require_nonempty("endpoint_commitment", &endpoint_commitment)?;
        require_nonempty("pq_identity_root", &pq_identity_root)?;
        ensure!(
            !supported_lanes.is_empty(),
            "supported_lanes must not be empty"
        );
        ensure!(
            max_fee_micro_units <= self.config.max_recovery_fee_micro_units,
            "provider fee {max_fee_micro_units} exceeds cap {}",
            self.config.max_recovery_fee_micro_units
        );
        let provider_id = id(
            "search-provider",
            json!([
                &operator_commitment,
                &endpoint_commitment,
                &pq_identity_root
            ]),
        );
        self.search_providers.insert(
            provider_id.clone(),
            SearchProvider {
                provider_id: provider_id.clone(),
                operator_commitment,
                endpoint_commitment,
                pq_identity_root,
                supported_lanes,
                status: ProviderStatus::Active,
                stake_commitment,
                max_fee_micro_units,
                completed_recoveries: 0,
                slash_count: 0,
            },
        );
        self.refresh_roots();
        Ok(provider_id)
    }

    pub fn open_recovery_cohort(
        &mut self,
        lane: RecoveryLane,
        wallet_group_commitment: String,
        subaddress_range_commitment: String,
        view_tag_prefix_root: String,
        request_ciphertext_root: String,
        privacy_set_size: u64,
        requested_output_count: u32,
        monero_start_height: u64,
        monero_end_height: u64,
    ) -> Result<String> {
        ensure!(
            self.recovery_cohorts.len() < MAX_RECOVERY_COHORTS,
            "recovery cohort capacity exceeded"
        );
        require_nonempty("wallet_group_commitment", &wallet_group_commitment)?;
        require_nonempty("subaddress_range_commitment", &subaddress_range_commitment)?;
        require_nonempty("view_tag_prefix_root", &view_tag_prefix_root)?;
        require_nonempty("request_ciphertext_root", &request_ciphertext_root)?;
        ensure!(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set {privacy_set_size} below minimum {}",
            self.config.min_privacy_set_size
        );
        ensure!(
            requested_output_count > 0,
            "requested_output_count must be positive"
        );
        ensure!(
            monero_start_height <= monero_end_height,
            "monero_start_height must be <= monero_end_height"
        );
        let cohort_id = id(
            "recovery-cohort",
            json!([
                lane.as_str(),
                &wallet_group_commitment,
                &subaddress_range_commitment,
                &view_tag_prefix_root,
                monero_start_height,
                monero_end_height
            ]),
        );
        self.recovery_cohorts.insert(
            cohort_id.clone(),
            RecoveryCohort {
                cohort_id: cohort_id.clone(),
                lane,
                wallet_group_commitment,
                subaddress_range_commitment,
                view_tag_prefix_root,
                request_ciphertext_root,
                privacy_set_size,
                requested_output_count,
                min_ring_decoys: self.config.min_ring_decoys,
                target_ring_decoys: self.config.target_ring_decoys,
                monero_start_height,
                monero_end_height,
                opened_height: self.height,
                expires_height: self.height + self.config.cohort_ttl_blocks,
                status: CohortStatus::Open,
                provider_ids: BTreeSet::new(),
                hint_ids: BTreeSet::new(),
            },
        );
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn submit_output_hint(
        &mut self,
        cohort_id: &str,
        provider_id: &str,
        kind: HintKind,
        encrypted_hint_root: String,
        output_commitment_root: String,
        decoy_set_root: String,
        hint_count: u32,
        false_positive_floor_bps: u16,
        monero_height: u64,
    ) -> Result<String> {
        ensure!(
            self.output_hints.len() < MAX_OUTPUT_HINTS,
            "output hint capacity exceeded"
        );
        require_nonempty("encrypted_hint_root", &encrypted_hint_root)?;
        require_nonempty("output_commitment_root", &output_commitment_root)?;
        require_nonempty("decoy_set_root", &decoy_set_root)?;
        ensure!(hint_count > 0, "hint_count must be positive");
        ensure!(
            false_positive_floor_bps <= MAX_BPS,
            "false_positive_floor_bps exceeds MAX_BPS"
        );
        let provider = self
            .search_providers
            .get(provider_id)
            .ok_or_else(|| format!("unknown provider {provider_id}"))?;
        ensure!(
            provider.status == ProviderStatus::Active,
            "provider is not active"
        );
        let cohort = self
            .recovery_cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        ensure!(
            provider.supported_lanes.contains(&cohort.lane),
            "provider does not support lane {}",
            cohort.lane.as_str()
        );
        ensure!(
            monero_height >= cohort.monero_start_height
                && monero_height <= cohort.monero_end_height,
            "hint monero height outside cohort range"
        );
        let hint_id = id(
            "output-hint",
            json!([
                cohort_id,
                provider_id,
                kind.as_str(),
                &encrypted_hint_root,
                monero_height
            ]),
        );
        self.output_hints.insert(
            hint_id.clone(),
            OutputHint {
                hint_id: hint_id.clone(),
                cohort_id: cohort_id.to_string(),
                provider_id: provider_id.to_string(),
                kind,
                encrypted_hint_root,
                output_commitment_root,
                decoy_set_root,
                hint_count,
                false_positive_floor_bps,
                monero_height,
                expires_height: self.height + self.config.hint_ttl_blocks,
            },
        );
        cohort.provider_ids.insert(provider_id.to_string());
        cohort.hint_ids.insert(hint_id.clone());
        cohort.status = CohortStatus::Searching;
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn submit_pq_attestation(
        &mut self,
        cohort_id: &str,
        provider_id: &str,
        kind: AttestationKind,
        statement_root: String,
        pq_signature_root: String,
        pq_security_bits: u16,
    ) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < MAX_PQ_ATTESTATIONS,
            "pq attestation capacity exceeded"
        );
        require_nonempty("statement_root", &statement_root)?;
        require_nonempty("pq_signature_root", &pq_signature_root)?;
        ensure!(
            self.recovery_cohorts.contains_key(cohort_id),
            "unknown cohort {cohort_id}"
        );
        ensure!(
            self.search_providers.contains_key(provider_id),
            "unknown provider {provider_id}"
        );
        ensure!(
            pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits {pq_security_bits} below minimum {}",
            self.config.min_pq_security_bits
        );
        let attestation_id = id(
            "pq-attestation",
            json!([cohort_id, provider_id, kind.as_str(), &statement_root]),
        );
        self.pq_attestations.insert(
            attestation_id.clone(),
            PqAttestation {
                attestation_id: attestation_id.clone(),
                cohort_id: cohort_id.to_string(),
                provider_id: provider_id.to_string(),
                kind,
                statement_root,
                pq_signature_root,
                pq_security_bits,
                attested_height: self.height,
                expires_height: self.height + self.config.attestation_ttl_blocks,
            },
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn submit_decoy_preserving_proof(
        &mut self,
        cohort_id: &str,
        provider_id: &str,
        proof_commitment_root: String,
        ring_member_commitment_root: String,
        decoy_distribution_root: String,
        recovered_output_count: u32,
        min_ring_decoys: u16,
        entropy_floor_bps: u16,
        nullifier_fence_root: String,
    ) -> Result<String> {
        ensure!(
            self.decoy_preserving_proofs.len() < MAX_DECOY_PROOFS,
            "decoy preserving proof capacity exceeded"
        );
        require_nonempty("proof_commitment_root", &proof_commitment_root)?;
        require_nonempty("ring_member_commitment_root", &ring_member_commitment_root)?;
        require_nonempty("decoy_distribution_root", &decoy_distribution_root)?;
        require_nonempty("nullifier_fence_root", &nullifier_fence_root)?;
        let cohort = self
            .recovery_cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        ensure!(
            self.search_providers.contains_key(provider_id),
            "unknown provider {provider_id}"
        );
        ensure!(
            recovered_output_count > 0 && recovered_output_count <= cohort.requested_output_count,
            "recovered output count outside requested range"
        );
        ensure!(
            min_ring_decoys >= self.config.min_ring_decoys,
            "min_ring_decoys below configured floor"
        );
        ensure!(
            entropy_floor_bps <= MAX_BPS,
            "entropy_floor_bps exceeds MAX_BPS"
        );
        let proof_id = id(
            "decoy-proof",
            json!([
                cohort_id,
                provider_id,
                &proof_commitment_root,
                &nullifier_fence_root
            ]),
        );
        self.decoy_preserving_proofs.insert(
            proof_id.clone(),
            DecoyPreservingRecoveryProof {
                proof_id: proof_id.clone(),
                cohort_id: cohort_id.to_string(),
                provider_id: provider_id.to_string(),
                proof_commitment_root,
                ring_member_commitment_root,
                decoy_distribution_root,
                recovered_output_count,
                min_ring_decoys,
                entropy_floor_bps,
                nullifier_fence_root,
            },
        );
        cohort.status = CohortStatus::Proved;
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn settle_recovery(
        &mut self,
        cohort_id: &str,
        provider_id: &str,
        proof_id: &str,
        fee_micro_units: u64,
        settlement_anchor_root: String,
    ) -> Result<String> {
        ensure!(
            self.recovery_settlements.len() < MAX_SETTLEMENTS,
            "recovery settlement capacity exceeded"
        );
        require_nonempty("settlement_anchor_root", &settlement_anchor_root)?;
        ensure!(
            fee_micro_units <= self.config.max_recovery_fee_micro_units,
            "fee {fee_micro_units} exceeds cap {}",
            self.config.max_recovery_fee_micro_units
        );
        let cohort = self
            .recovery_cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        ensure!(
            self.decoy_preserving_proofs.contains_key(proof_id),
            "unknown proof {proof_id}"
        );
        let provider = self
            .search_providers
            .get_mut(provider_id)
            .ok_or_else(|| format!("unknown provider {provider_id}"))?;
        let provider_reward_micro_units =
            fee_micro_units * u64::from(self.config.provider_reward_bps) / u64::from(MAX_BPS);
        let protocol_fee_micro_units = fee_micro_units.saturating_sub(provider_reward_micro_units);
        let settlement_id = id(
            "recovery-settlement",
            json!([cohort_id, provider_id, proof_id, &settlement_anchor_root]),
        );
        self.recovery_settlements.insert(
            settlement_id.clone(),
            RecoverySettlement {
                settlement_id: settlement_id.clone(),
                cohort_id: cohort_id.to_string(),
                provider_id: provider_id.to_string(),
                proof_id: proof_id.to_string(),
                fee_micro_units,
                provider_reward_micro_units,
                protocol_fee_micro_units,
                settlement_anchor_root,
                settled_height: self.height,
                status: SettlementStatus::Settled,
            },
        );
        provider.completed_recoveries = provider.completed_recoveries.saturating_add(1);
        cohort.status = CohortStatus::Settled;
        self.public_records.push(json!({
            "kind": "subaddress_output_recovery_settlement",
            "settlement_id": &settlement_id,
            "cohort_id": cohort_id,
            "provider_id": provider_id,
            "fee_micro_units": fee_micro_units,
            "status": "settled",
        }));
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn reserve_rebate(
        &mut self,
        settlement_id: &str,
        beneficiary_commitment: String,
        sponsor_commitment: String,
        reason: RebateReason,
    ) -> Result<String> {
        ensure!(self.rebates.len() < MAX_REBATES, "rebate capacity exceeded");
        ensure!(self.config.allow_low_fee_rebates, "rebates disabled");
        require_nonempty("beneficiary_commitment", &beneficiary_commitment)?;
        require_nonempty("sponsor_commitment", &sponsor_commitment)?;
        let settlement = self
            .recovery_settlements
            .get(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        let rebate_micro_units =
            settlement.fee_micro_units * u64::from(self.config.rebate_bps) / u64::from(MAX_BPS);
        let rebate_id = id(
            "rebate",
            json!([
                settlement_id,
                &beneficiary_commitment,
                &sponsor_commitment,
                reason.as_str()
            ]),
        );
        self.rebates.insert(
            rebate_id.clone(),
            Rebate {
                rebate_id: rebate_id.clone(),
                settlement_id: settlement_id.to_string(),
                beneficiary_commitment,
                reason,
                rebate_micro_units,
                sponsor_commitment,
                claimed: false,
            },
        );
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        subject_id: String,
        spent: u32,
        public_reason: String,
    ) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded"
        );
        require_nonempty("subject_id", &subject_id)?;
        require_nonempty("public_reason", &public_reason)?;
        ensure!(
            spent <= self.config.redaction_budget_per_epoch,
            "spent redaction budget exceeds allowance"
        );
        let budget_id = id("redaction-budget", json!([&subject_id, self.epoch]));
        self.redaction_budgets.insert(
            budget_id.clone(),
            RedactionBudget {
                budget_id: budget_id.clone(),
                subject_id,
                epoch: self.epoch,
                allowance: self.config.redaction_budget_per_epoch,
                spent,
                public_reason,
            },
        );
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(&mut self, operator_commitment: String) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exceeded"
        );
        require_nonempty("operator_commitment", &operator_commitment)?;
        let provider_ids = self
            .search_providers
            .values()
            .filter(|provider| provider.operator_commitment == operator_commitment)
            .map(|provider| provider.provider_id.clone())
            .collect::<BTreeSet<_>>();
        let cohorts_served = self
            .recovery_cohorts
            .values()
            .filter(|cohort| !cohort.provider_ids.is_disjoint(&provider_ids))
            .count() as u64;
        let hints_delivered = self
            .output_hints
            .values()
            .filter(|hint| provider_ids.contains(&hint.provider_id))
            .map(|hint| u64::from(hint.hint_count))
            .sum::<u64>();
        let proofs_accepted = self
            .decoy_preserving_proofs
            .values()
            .filter(|proof| provider_ids.contains(&proof.provider_id))
            .count() as u64;
        let rebates_paid_micro_units = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_micro_units)
            .sum::<u64>();
        let max_fee_micro_units = self
            .recovery_settlements
            .values()
            .filter(|settlement| provider_ids.contains(&settlement.provider_id))
            .map(|settlement| settlement.fee_micro_units)
            .max()
            .unwrap_or(0);
        let redacted_summary_root = value_root(
            "operator-redacted-summary",
            &json!({
                "operator_commitment": &operator_commitment,
                "epoch": self.epoch,
                "cohorts_served": cohorts_served,
                "hints_delivered": hints_delivered,
                "proofs_accepted": proofs_accepted,
            }),
        );
        let summary_id = id(
            "operator-summary",
            json!([&operator_commitment, self.epoch]),
        );
        self.operator_summaries.insert(
            summary_id.clone(),
            OperatorSummary {
                summary_id: summary_id.clone(),
                operator_commitment,
                epoch: self.epoch,
                cohorts_served,
                hints_delivered,
                proofs_accepted,
                rebates_paid_micro_units,
                max_fee_micro_units,
                redacted_summary_root,
            },
        );
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            recovery_cohort_root: public_map_root(
                "recovery-cohorts",
                &self
                    .recovery_cohorts
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            output_hint_root: public_map_root(
                "output-hints",
                &self
                    .output_hints
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            search_provider_root: public_map_root(
                "search-providers",
                &self
                    .search_providers
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            pq_attestation_root: public_map_root(
                "pq-attestations",
                &self
                    .pq_attestations
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            decoy_preserving_proof_root: public_map_root(
                "decoy-preserving-proofs",
                &self
                    .decoy_preserving_proofs
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            recovery_settlement_root: public_map_root(
                "recovery-settlements",
                &self
                    .recovery_settlements
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            rebate_root: public_map_root(
                "rebates",
                &self
                    .rebates
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            redaction_budget_root: public_map_root(
                "redaction-budgets",
                &self
                    .redaction_budgets
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            operator_summary_root: public_map_root(
                "operator-summaries",
                &self
                    .operator_summaries
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            public_record_root: merkle_root(
                "monero-l2-pq-private-subaddress-output-recovery-market:public-records",
                &self.public_records,
            ),
            operator_safe_summary_root: value_root(
                "operator-safe-summary",
                &self.operator_safe_summary(),
            ),
        };
    }

    fn seed(&mut self, label: &str, lane: RecoveryLane) {
        let mut supported_lanes = BTreeSet::new();
        supported_lanes.insert(lane);
        supported_lanes.insert(RecoveryLane::ReorgRecovery);
        let operator_commitment = devnet_payload_root("operator", label);
        let provider_id = self
            .register_provider(
                operator_commitment.clone(),
                devnet_payload_root("endpoint", label),
                devnet_payload_root("pq-identity", label),
                devnet_payload_root("stake", label),
                supported_lanes,
                lane_fee_cap(lane, &self.config),
            )
            .expect("devnet provider");
        let cohort_id = self
            .open_recovery_cohort(
                lane,
                devnet_payload_root("wallet-group", label),
                devnet_payload_root("subaddress-range", label),
                devnet_payload_root("viewtag-prefix", label),
                devnet_payload_root("request-ciphertext", label),
                self.config.min_privacy_set_size * 2,
                12,
                self.height - 2_000,
                self.height - 8,
            )
            .expect("devnet cohort");
        for kind in [
            HintKind::ViewTagShard,
            HintKind::SubaddressRange,
            HintKind::OutputCommitment,
        ] {
            self.submit_output_hint(
                &cohort_id,
                &provider_id,
                kind,
                devnet_payload_root("encrypted-hint", kind.as_str()),
                devnet_payload_root("output-commitment", label),
                devnet_payload_root("decoy-set", label),
                4,
                8_750,
                self.height - 64,
            )
            .expect("devnet output hint");
        }
        for kind in [
            AttestationKind::PqSignatureValid,
            AttestationKind::HintEncryptionValid,
            AttestationKind::DecoyPreservation,
            AttestationKind::RedactionCompliance,
        ] {
            self.submit_pq_attestation(
                &cohort_id,
                &provider_id,
                kind,
                devnet_payload_root("attestation-statement", kind.as_str()),
                devnet_payload_root("pq-signature", kind.as_str()),
                self.config.min_pq_security_bits,
            )
            .expect("devnet pq attestation");
        }
        let proof_id = self
            .submit_decoy_preserving_proof(
                &cohort_id,
                &provider_id,
                devnet_payload_root("proof-commitment", label),
                devnet_payload_root("ring-member-commitment", label),
                devnet_payload_root("decoy-distribution", label),
                3,
                self.config.target_ring_decoys,
                9_100,
                devnet_payload_root("nullifier-fence", label),
            )
            .expect("devnet decoy proof");
        let settlement_id = self
            .settle_recovery(
                &cohort_id,
                &provider_id,
                &proof_id,
                lane_fee_cap(lane, &self.config),
                devnet_payload_root("settlement-anchor", label),
            )
            .expect("devnet settlement");
        self.reserve_rebate(
            &settlement_id,
            devnet_payload_root("beneficiary", label),
            devnet_payload_root("fee-sponsor", label),
            if lane == RecoveryLane::ReorgRecovery {
                RebateReason::ReorgRepairCredit
            } else {
                RebateReason::LowFeeSponsored
            },
        )
        .expect("devnet rebate");
        self.allocate_redaction_budget(
            cohort_id,
            4,
            "wallet_recovery_assistance_without_plaintext_output_exposure".to_string(),
        )
        .expect("devnet redaction budget");
        self.publish_operator_summary(operator_commitment)
            .expect("devnet operator summary");
    }

    fn operator_safe_summary(&self) -> Value {
        json!({
            "active_providers": self.search_providers.values().filter(|provider| provider.status == ProviderStatus::Active).count(),
            "live_cohorts": self.recovery_cohorts.values().filter(|cohort| cohort.status.live()).count(),
            "settled_recoveries": self.recovery_settlements.values().filter(|settlement| settlement.status == SettlementStatus::Settled).count(),
            "encrypted_output_hints": self.output_hints.len(),
            "decoy_preserving_proofs": self.decoy_preserving_proofs.len(),
            "min_privacy_set_size": self.recovery_cohorts.values().map(|cohort| cohort.privacy_set_size).min().unwrap_or(0),
            "min_ring_decoys_observed": self.decoy_preserving_proofs.values().map(|proof| proof.min_ring_decoys).min().unwrap_or(0),
            "max_recovery_fee_micro_units": self.recovery_settlements.values().map(|settlement| settlement.fee_micro_units).max().unwrap_or(0),
            "rebates_reserved_micro_units": self.rebates.values().map(|rebate| rebate.rebate_micro_units).sum::<u64>(),
            "redaction_budget_spent": self.redaction_budgets.values().map(|budget| budget.spent).sum::<u32>(),
            "plaintext_output_indexes_exposed": false,
            "wallet_group_plaintext_exposed": false,
        })
    }
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    value_root(
        "devnet-payload",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "kind": kind,
            "label": label,
            "height": DEVNET_HEIGHT,
            "epoch": DEVNET_EPOCH,
        }),
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-SUBADDRESS-OUTPUT-RECOVERY-MARKET-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn lane_fee_cap(lane: RecoveryLane, config: &Config) -> u64 {
    let base = match lane {
        RecoveryLane::WalletRestore => 2_400,
        RecoveryLane::WatchOnlyRepair => 1_800,
        RecoveryLane::MobileFastRestore => 1_200,
        RecoveryLane::EstateRecovery => 3_200,
        RecoveryLane::MerchantResync => 2_000,
        RecoveryLane::ReorgRecovery => 2_800,
    };
    base.min(config.max_recovery_fee_micro_units)
}

fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn id(kind: &str, value: Value) -> String {
    domain_hash(
        "monero-l2-pq-private-subaddress-output-recovery-market:id",
        &[HashPart::Str(kind), HashPart::Json(&value)],
        32,
    )
}

fn empty_root(kind: &str) -> String {
    merkle_root(
        &format!("monero-l2-pq-private-subaddress-output-recovery-market:{kind}"),
        &[] as &[Value],
    )
}

fn value_root(kind: &str, value: &Value) -> String {
    domain_hash(
        "monero-l2-pq-private-subaddress-output-recovery-market:root",
        &[HashPart::Str(kind), HashPart::Json(value)],
        32,
    )
}

fn public_map_root(kind: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-subaddress-output-recovery-market:{kind}"),
        &leaves,
    )
}
