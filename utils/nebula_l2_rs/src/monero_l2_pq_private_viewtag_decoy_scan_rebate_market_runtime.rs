use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as raw_domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewtagDecoyScanRebateMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_DECOY_SCAN_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewtag-decoy-scan-rebate-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWTAG_DECOY_SCAN_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_566_720;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCAN_COHORT_SCHEME: &str = "ml-kem-1024-private-viewtag-scan-cohort-root-v1";
pub const VIEWTAG_BUCKET_SCHEME: &str = "encrypted-viewtag-bucket-decoy-preserving-root-v1";
pub const DECOY_SCAN_PROOF_SCHEME: &str = "monero-ring-decoy-scan-preservation-proof-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-viewtag-decoy-scan-rebate-attestation-v1";
pub const REBATE_SETTLEMENT_SCHEME: &str = "low-fee-private-viewtag-scan-rebate-settlement-root-v1";
pub const THROTTLE_SCHEME: &str = "wallet-scan-efficiency-throttle-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "redacted-public-viewtag-scan-summary-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-viewtag-decoy-scan-summary-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_FLOOR: u16 = 32;
pub const DEFAULT_TARGET_DECOY_FLOOR: u16 = 64;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u32 = 32;
pub const DEFAULT_MAX_BUCKET_OUTPUTS: u32 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_SCAN_FEE_MICRO_UNITS: u64 = 3_000;
pub const DEFAULT_REBATE_BPS: u16 = 8_750;
pub const DEFAULT_PROVIDER_FEE_SHARE_BPS: u16 = 1_250;
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u32 = 32;
pub const DEFAULT_MAX_OPERATOR_SUMMARY_FIELDS: u8 = 12;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    WalletRestore,
    WalletIncremental,
    BridgeDeposit,
    BridgeWithdrawal,
    MerchantReceive,
    WatchOnlyAudit,
    ReorgRepair,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WalletIncremental => "wallet_incremental",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceive => "merchant_receive",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
        }
    }

    pub fn default_fee_cap(self) -> u64 {
        match self {
            Self::WalletRestore => 2_500,
            Self::WalletIncremental => 900,
            Self::BridgeDeposit => 2_200,
            Self::BridgeWithdrawal => 3_000,
            Self::MerchantReceive => 1_100,
            Self::WatchOnlyAudit => 1_800,
            Self::ReorgRepair => 2_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Open,
    Sealed,
    Bucketed,
    Attested,
    RebateReady,
    Settled,
    Throttled,
    Expired,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Bucketed => "bucketed",
            Self::Attested => "attested",
            Self::RebateReady => "rebate_ready",
            Self::Settled => "settled",
            Self::Throttled => "throttled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Bucketed | Self::Attested | Self::RebateReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Committed,
    Sealed,
    ProofLinked,
    Attested,
    RebateEligible,
    Settled,
    Challenged,
    Expired,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Sealed => "sealed",
            Self::ProofLinked => "proof_linked",
            Self::Attested => "attested",
            Self::RebateEligible => "rebate_eligible",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn scannable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::ProofLinked | Self::Attested | Self::RebateEligible
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    DecoyFloor,
    RingDistribution,
    ViewtagCompleteness,
    ScanWork,
    ReorgSafety,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecoyFloor => "decoy_floor",
            Self::RingDistribution => "ring_distribution",
            Self::ViewtagCompleteness => "viewtag_completeness",
            Self::ScanWork => "scan_work",
            Self::ReorgSafety => "reorg_safety",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSigner,
    ViewtagPrivacy,
    DecoyPreservation,
    ScanEfficiency,
    RebateIntegrity,
    RedactionCompliance,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSigner => "pq_signer",
            Self::ViewtagPrivacy => "viewtag_privacy",
            Self::DecoyPreservation => "decoy_preservation",
            Self::ScanEfficiency => "scan_efficiency",
            Self::RebateIntegrity => "rebate_integrity",
            Self::RedactionCompliance => "redaction_compliance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Quoted,
    Reserved,
    Attested,
    Settled,
    ClawedBack,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStatus {
    Monitoring,
    SoftLimited,
    HardLimited,
    Released,
    Slashed,
}

impl ThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitoring => "monitoring",
            Self::SoftLimited => "soft_limited",
            Self::HardLimited => "hard_limited",
            Self::Released => "released",
            Self::Slashed => "slashed",
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
    pub scan_cohort_scheme: String,
    pub viewtag_bucket_scheme: String,
    pub decoy_scan_proof_scheme: String,
    pub pq_attestation_scheme: String,
    pub rebate_settlement_scheme: String,
    pub throttle_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_decoy_floor: u16,
    pub target_decoy_floor: u16,
    pub min_bucket_outputs: u32,
    pub max_bucket_outputs: u32,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_scan_fee_micro_units: u64,
    pub rebate_bps: u16,
    pub provider_fee_share_bps: u16,
    pub cohort_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_budget_per_epoch: u32,
    pub max_operator_summary_fields: u8,
    pub allow_low_fee_rebates: bool,
    pub require_decoy_preservation: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            hash_suite: HASH_SUITE.to_string(),
            scan_cohort_scheme: SCAN_COHORT_SCHEME.to_string(),
            viewtag_bucket_scheme: VIEWTAG_BUCKET_SCHEME.to_string(),
            decoy_scan_proof_scheme: DECOY_SCAN_PROOF_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            rebate_settlement_scheme: REBATE_SETTLEMENT_SCHEME.to_string(),
            throttle_scheme: THROTTLE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_decoy_floor: DEFAULT_MIN_DECOY_FLOOR,
            target_decoy_floor: DEFAULT_TARGET_DECOY_FLOOR,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            max_bucket_outputs: DEFAULT_MAX_BUCKET_OUTPUTS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_scan_fee_micro_units: DEFAULT_MAX_SCAN_FEE_MICRO_UNITS,
            rebate_bps: DEFAULT_REBATE_BPS,
            provider_fee_share_bps: DEFAULT_PROVIDER_FEE_SHARE_BPS,
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            max_operator_summary_fields: DEFAULT_MAX_OPERATOR_SUMMARY_FIELDS,
            allow_low_fee_rebates: true,
            require_decoy_preservation: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "scan_cohort_scheme": self.scan_cohort_scheme,
            "viewtag_bucket_scheme": self.viewtag_bucket_scheme,
            "decoy_scan_proof_scheme": self.decoy_scan_proof_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "rebate_settlement_scheme": self.rebate_settlement_scheme,
            "throttle_scheme": self.throttle_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_floor": self.min_decoy_floor,
            "target_decoy_floor": self.target_decoy_floor,
            "min_bucket_outputs": self.min_bucket_outputs,
            "max_bucket_outputs": self.max_bucket_outputs,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_scan_fee_micro_units": self.max_scan_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "provider_fee_share_bps": self.provider_fee_share_bps,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "max_operator_summary_fields": self.max_operator_summary_fields,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
            "require_decoy_preservation": self.require_decoy_preservation,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scan_cohorts: u64,
    pub viewtag_buckets: u64,
    pub decoy_scan_proofs: u64,
    pub pq_attestations: u64,
    pub rebate_settlements: u64,
    pub throttles: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_rebate_micro_units: u64,
    pub preserved_decoy_outputs: u64,
    pub redacted_public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_cohorts": self.scan_cohorts,
            "viewtag_buckets": self.viewtag_buckets,
            "decoy_scan_proofs": self.decoy_scan_proofs,
            "pq_attestations": self.pq_attestations,
            "rebate_settlements": self.rebate_settlements,
            "throttles": self.throttles,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "preserved_decoy_outputs": self.preserved_decoy_outputs,
            "redacted_public_records": self.redacted_public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub scan_cohort_root: String,
    pub viewtag_bucket_root: String,
    pub decoy_scan_proof_root: String,
    pub pq_attestation_root: String,
    pub rebate_settlement_root: String,
    pub throttle_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            scan_cohort_root: empty_root("scan_cohorts"),
            viewtag_bucket_root: empty_root("viewtag_buckets"),
            decoy_scan_proof_root: empty_root("decoy_scan_proofs"),
            pq_attestation_root: empty_root("pq_attestations"),
            rebate_settlement_root: empty_root("rebate_settlements"),
            throttle_root: empty_root("throttles"),
            redaction_budget_root: empty_root("redaction_budgets"),
            operator_summary_root: empty_root("operator_summaries"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "scan_cohort_root": self.scan_cohort_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "decoy_scan_proof_root": self.decoy_scan_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rebate_settlement_root": self.rebate_settlement_root,
            "throttle_root": self.throttle_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanCohort {
    pub cohort_id: String,
    pub lane: ScanLane,
    pub provider_id: String,
    pub wallet_group_commitment: String,
    pub encrypted_viewtag_hint_root: String,
    pub decoy_policy_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub privacy_set_size: u64,
    pub expected_outputs: u32,
    pub fee_cap_micro_units: u64,
    pub status: CohortStatus,
}

impl ScanCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "provider_id": self.provider_id,
            "wallet_group_commitment": self.wallet_group_commitment,
            "encrypted_viewtag_hint_root": self.encrypted_viewtag_hint_root,
            "decoy_policy_root": self.decoy_policy_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "privacy_set_size": self.privacy_set_size,
            "expected_outputs": self.expected_outputs,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.cohort_id.is_empty() {
            return Err("scan cohort id is required".to_string());
        }
        if self.provider_id.is_empty() {
            return Err("scan cohort provider id is required".to_string());
        }
        if self.end_height <= self.start_height {
            return Err("scan cohort height range must be increasing".to_string());
        }
        if self.end_height - self.start_height > config.cohort_ttl_blocks {
            return Err("scan cohort exceeds ttl".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("scan cohort privacy set below minimum".to_string());
        }
        if self.fee_cap_micro_units > config.max_scan_fee_micro_units {
            return Err("scan cohort fee cap exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagBucket {
    pub bucket_id: String,
    pub cohort_id: String,
    pub sealed_viewtag_prefix: String,
    pub encrypted_bucket_root: String,
    pub output_commitment_root: String,
    pub decoy_membership_root: String,
    pub bucket_height: u64,
    pub output_count: u32,
    pub decoy_count: u16,
    pub scan_cost_micro_units: u64,
    pub status: BucketStatus,
}

impl ViewtagBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "cohort_id": self.cohort_id,
            "sealed_viewtag_prefix": self.sealed_viewtag_prefix,
            "encrypted_bucket_root": self.encrypted_bucket_root,
            "output_commitment_root": self.output_commitment_root,
            "decoy_membership_root": self.decoy_membership_root,
            "bucket_height": self.bucket_height,
            "output_count": self.output_count,
            "decoy_count": self.decoy_count,
            "scan_cost_micro_units": self.scan_cost_micro_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.bucket_id.is_empty() || self.cohort_id.is_empty() {
            return Err("viewtag bucket id and cohort id are required".to_string());
        }
        if self.output_count < config.min_bucket_outputs {
            return Err("viewtag bucket output count below minimum".to_string());
        }
        if self.output_count > config.max_bucket_outputs {
            return Err("viewtag bucket output count exceeds maximum".to_string());
        }
        if self.decoy_count < config.min_decoy_floor {
            return Err("viewtag bucket decoy count below floor".to_string());
        }
        if self.scan_cost_micro_units > config.max_scan_fee_micro_units {
            return Err("viewtag bucket scan cost exceeds fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyScanProof {
    pub proof_id: String,
    pub bucket_id: String,
    pub proof_kind: ProofKind,
    pub proof_commitment: String,
    pub ring_distribution_root: String,
    pub preserved_decoy_outputs: u64,
    pub minimum_decoy_count: u16,
    pub false_positive_bps: u16,
    pub proof_height: u64,
}

impl DecoyScanProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "bucket_id": self.bucket_id,
            "proof_kind": self.proof_kind.as_str(),
            "proof_commitment": self.proof_commitment,
            "ring_distribution_root": self.ring_distribution_root,
            "preserved_decoy_outputs": self.preserved_decoy_outputs,
            "minimum_decoy_count": self.minimum_decoy_count,
            "false_positive_bps": self.false_positive_bps,
            "proof_height": self.proof_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.proof_id.is_empty() || self.bucket_id.is_empty() {
            return Err("decoy scan proof id and bucket id are required".to_string());
        }
        if self.minimum_decoy_count < config.min_decoy_floor {
            return Err("decoy scan proof below decoy floor".to_string());
        }
        if self.false_positive_bps > MAX_BPS {
            return Err("decoy scan proof false positive bps exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub signer_commitment: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "signer_commitment": self.signer_commitment,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.attestation_id.is_empty() || self.subject_id.is_empty() {
            return Err("pq attestation id and subject id are required".to_string());
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err("pq attestation security bits below minimum".to_string());
        }
        if self.expires_height <= self.issued_height {
            return Err("pq attestation expiry must be after issue height".to_string());
        }
        if self.expires_height - self.issued_height > config.attestation_ttl_blocks {
            return Err("pq attestation exceeds ttl".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub settlement_id: String,
    pub bucket_id: String,
    pub payer_commitment: String,
    pub provider_id: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub provider_fee_micro_units: u64,
    pub settlement_height: u64,
    pub nullifier: String,
    pub status: SettlementStatus,
}

impl RebateSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "bucket_id": self.bucket_id,
            "payer_commitment": self.payer_commitment,
            "provider_id": self.provider_id,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "provider_fee_micro_units": self.provider_fee_micro_units,
            "settlement_height": self.settlement_height,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.settlement_id.is_empty() || self.bucket_id.is_empty() || self.nullifier.is_empty() {
            return Err("rebate settlement id, bucket id, and nullifier are required".to_string());
        }
        if self.fee_paid_micro_units > config.max_scan_fee_micro_units {
            return Err("rebate settlement fee exceeds maximum".to_string());
        }
        if self.rebate_micro_units > self.fee_paid_micro_units {
            return Err("rebate settlement rebate exceeds paid fee".to_string());
        }
        if self.provider_fee_micro_units > self.fee_paid_micro_units {
            return Err("rebate settlement provider fee exceeds paid fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanThrottle {
    pub throttle_id: String,
    pub provider_id: String,
    pub lane: ScanLane,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_bucket_count: u32,
    pub max_scan_cost_micro_units: u64,
    pub reason_code: String,
    pub status: ThrottleStatus,
}

impl ScanThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "provider_id": self.provider_id,
            "lane": self.lane.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_bucket_count": self.max_bucket_count,
            "max_scan_cost_micro_units": self.max_scan_cost_micro_units,
            "reason_code": self.reason_code,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.throttle_id.is_empty() || self.provider_id.is_empty() {
            return Err("scan throttle id and provider id are required".to_string());
        }
        if self.window_end_height <= self.window_start_height {
            return Err("scan throttle window must be increasing".to_string());
        }
        if self.window_end_height - self.window_start_height > config.throttle_window_blocks {
            return Err("scan throttle window exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub max_public_fields: u8,
    pub remaining_summaries: u32,
    pub redacted_subject_root: String,
    pub disclosure_policy_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "max_public_fields": self.max_public_fields,
            "remaining_summaries": self.remaining_summaries,
            "redacted_subject_root": self.redacted_subject_root,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.budget_id.is_empty() || self.operator_id.is_empty() {
            return Err("redaction budget id and operator id are required".to_string());
        }
        if self.max_public_fields > config.max_operator_summary_fields {
            return Err("redaction budget exceeds public field cap".to_string());
        }
        if self.remaining_summaries > config.redaction_budget_per_epoch {
            return Err("redaction budget exceeds epoch allowance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane: ScanLane,
    pub redacted_cohort_count: u64,
    pub redacted_bucket_count: u64,
    pub settled_rebate_micro_units: u64,
    pub median_fee_micro_units: u64,
    pub privacy_floor_met: bool,
    pub decoy_floor_met: bool,
    pub pq_attested: bool,
    pub redaction_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "redacted_cohort_count": self.redacted_cohort_count,
            "redacted_bucket_count": self.redacted_bucket_count,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "median_fee_micro_units": self.median_fee_micro_units,
            "privacy_floor_met": self.privacy_floor_met,
            "decoy_floor_met": self.decoy_floor_met,
            "pq_attested": self.pq_attested,
            "redaction_root": self.redaction_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.summary_id.is_empty() || self.operator_id.is_empty() {
            return Err("operator summary id and operator id are required".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub scan_cohorts: BTreeMap<String, ScanCohort>,
    pub viewtag_buckets: BTreeMap<String, ViewtagBucket>,
    pub decoy_scan_proofs: BTreeMap<String, DecoyScanProof>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub rebate_settlements: BTreeMap<String, RebateSettlement>,
    pub throttles: BTreeMap<String, ScanThrottle>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub settlement_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            counters,
            roots,
            scan_cohorts: BTreeMap::new(),
            viewtag_buckets: BTreeMap::new(),
            decoy_scan_proofs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            settlement_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet_records();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn add_scan_cohort(&mut self, cohort: ScanCohort) -> Result<()> {
        cohort.validate(&self.config)?;
        if self.scan_cohorts.contains_key(&cohort.cohort_id) {
            return Err("scan cohort already exists".to_string());
        }
        self.scan_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.counters.scan_cohorts = self.scan_cohorts.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_viewtag_bucket(&mut self, bucket: ViewtagBucket) -> Result<()> {
        bucket.validate(&self.config)?;
        if !self.scan_cohorts.contains_key(&bucket.cohort_id) {
            return Err("viewtag bucket cohort is unknown".to_string());
        }
        if self.viewtag_buckets.contains_key(&bucket.bucket_id) {
            return Err("viewtag bucket already exists".to_string());
        }
        self.viewtag_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.counters.viewtag_buckets = self.viewtag_buckets.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_decoy_scan_proof(&mut self, proof: DecoyScanProof) -> Result<()> {
        proof.validate(&self.config)?;
        if !self.viewtag_buckets.contains_key(&proof.bucket_id) {
            return Err("decoy scan proof bucket is unknown".to_string());
        }
        if self.decoy_scan_proofs.contains_key(&proof.proof_id) {
            return Err("decoy scan proof already exists".to_string());
        }
        self.counters.preserved_decoy_outputs = self
            .counters
            .preserved_decoy_outputs
            .saturating_add(proof.preserved_decoy_outputs);
        self.decoy_scan_proofs.insert(proof.proof_id.clone(), proof);
        self.counters.decoy_scan_proofs = self.decoy_scan_proofs.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        attestation.validate(&self.config)?;
        if self
            .pq_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("pq attestation already exists".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_rebate_settlement(&mut self, settlement: RebateSettlement) -> Result<()> {
        settlement.validate(&self.config)?;
        if !self.viewtag_buckets.contains_key(&settlement.bucket_id) {
            return Err("rebate settlement bucket is unknown".to_string());
        }
        if self
            .rebate_settlements
            .contains_key(&settlement.settlement_id)
        {
            return Err("rebate settlement already exists".to_string());
        }
        if self.settlement_nullifiers.contains(&settlement.nullifier) {
            return Err("rebate settlement nullifier already used".to_string());
        }
        self.settlement_nullifiers
            .insert(settlement.nullifier.clone());
        self.counters.settled_rebate_micro_units = self
            .counters
            .settled_rebate_micro_units
            .saturating_add(settlement.rebate_micro_units);
        self.rebate_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.counters.rebate_settlements = self.rebate_settlements.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_throttle(&mut self, throttle: ScanThrottle) -> Result<()> {
        throttle.validate(&self.config)?;
        if self.throttles.contains_key(&throttle.throttle_id) {
            return Err("scan throttle already exists".to_string());
        }
        self.throttles
            .insert(throttle.throttle_id.clone(), throttle);
        self.counters.throttles = self.throttles.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        budget.validate(&self.config)?;
        if self.redaction_budgets.contains_key(&budget.budget_id) {
            return Err("redaction budget already exists".to_string());
        }
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        summary.validate()?;
        if self.operator_summaries.contains_key(&summary.summary_id) {
            return Err("operator summary already exists".to_string());
        }
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.redacted_public_records =
            self.counters.redacted_public_records.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn redacted_operator_summary(&self, operator_id: &str) -> Value {
        let summaries: Vec<Value> = self
            .operator_summaries
            .values()
            .filter(|summary| summary.operator_id == operator_id)
            .map(OperatorSummary::public_record)
            .collect();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "operator_id": operator_id,
            "summary_count": summaries.len(),
            "summaries": summaries,
            "state_root": self.state_root(),
        })
    }

    pub fn wallet_scan_efficiency_bps(&self) -> u64 {
        let outputs: u64 = self
            .viewtag_buckets
            .values()
            .filter(|bucket| bucket.status.scannable())
            .map(|bucket| bucket.output_count as u64)
            .sum();
        let cost: u64 = self
            .viewtag_buckets
            .values()
            .filter(|bucket| bucket.status.scannable())
            .map(|bucket| bucket.scan_cost_micro_units)
            .sum();
        if outputs == 0 || cost == 0 {
            return 0;
        }
        outputs.saturating_mul(10_000) / cost.max(1)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.scan_cohort_root = collection_root(
            "scan_cohorts",
            self.scan_cohorts.values().map(|v| v.public_record()),
        );
        self.roots.viewtag_bucket_root = collection_root(
            "viewtag_buckets",
            self.viewtag_buckets.values().map(|v| v.public_record()),
        );
        self.roots.decoy_scan_proof_root = collection_root(
            "decoy_scan_proofs",
            self.decoy_scan_proofs.values().map(|v| v.public_record()),
        );
        self.roots.pq_attestation_root = collection_root(
            "pq_attestations",
            self.pq_attestations.values().map(|v| v.public_record()),
        );
        self.roots.rebate_settlement_root = collection_root(
            "rebate_settlements",
            self.rebate_settlements.values().map(|v| v.public_record()),
        );
        self.roots.throttle_root = collection_root(
            "throttles",
            self.throttles.values().map(|v| v.public_record()),
        );
        self.roots.redaction_budget_root = collection_root(
            "redaction_budgets",
            self.redaction_budgets.values().map(|v| v.public_record()),
        );
        self.roots.operator_summary_root = collection_root(
            "operator_summaries",
            self.operator_summaries.values().map(|v| v.public_record()),
        );
        self.roots.state_root =
            record_root("roots", &self.roots.public_record_without_state_root());
    }

    fn seed_devnet_records(&mut self) {
        let cohort = ScanCohort {
            cohort_id: "devnet-viewtag-cohort-wallet-restore-0001".to_string(),
            lane: ScanLane::WalletRestore,
            provider_id: "devnet-scan-provider-alpha".to_string(),
            wallet_group_commitment: domain_hash(
                "devnet-wallet-group",
                &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str("alpha")],
            ),
            encrypted_viewtag_hint_root: domain_hash(
                "devnet-encrypted-viewtag-hints",
                &[
                    HashPart::Str(SCAN_COHORT_SCHEME),
                    HashPart::U64(DEVNET_HEIGHT),
                ],
            ),
            decoy_policy_root: domain_hash(
                "devnet-decoy-policy",
                &[HashPart::Str(DECOY_SCAN_PROOF_SCHEME), HashPart::U64(64)],
            ),
            start_height: DEVNET_HEIGHT,
            end_height: DEVNET_HEIGHT + 240,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            expected_outputs: 384,
            fee_cap_micro_units: ScanLane::WalletRestore.default_fee_cap(),
            status: CohortStatus::RebateReady,
        };
        let bucket = ViewtagBucket {
            bucket_id: "devnet-viewtag-bucket-7f-0001".to_string(),
            cohort_id: cohort.cohort_id.clone(),
            sealed_viewtag_prefix: "redacted-prefix-7f".to_string(),
            encrypted_bucket_root: domain_hash(
                "devnet-encrypted-bucket",
                &[HashPart::Str(VIEWTAG_BUCKET_SCHEME), HashPart::Str("7f")],
            ),
            output_commitment_root: domain_hash(
                "devnet-output-commitments",
                &[HashPart::U64(DEVNET_HEIGHT), HashPart::U64(384)],
            ),
            decoy_membership_root: domain_hash(
                "devnet-decoy-memberships",
                &[HashPart::U64(64), HashPart::Str("preserved")],
            ),
            bucket_height: DEVNET_HEIGHT + 12,
            output_count: 384,
            decoy_count: DEFAULT_TARGET_DECOY_FLOOR,
            scan_cost_micro_units: 1_900,
            status: BucketStatus::RebateEligible,
        };
        let proof = DecoyScanProof {
            proof_id: "devnet-decoy-scan-proof-0001".to_string(),
            bucket_id: bucket.bucket_id.clone(),
            proof_kind: ProofKind::DecoyFloor,
            proof_commitment: domain_hash(
                "devnet-decoy-proof",
                &[HashPart::Str(DECOY_SCAN_PROOF_SCHEME), HashPart::U64(1)],
            ),
            ring_distribution_root: domain_hash(
                "devnet-ring-distribution",
                &[HashPart::U64(384), HashPart::U64(64)],
            ),
            preserved_decoy_outputs: 24_576,
            minimum_decoy_count: DEFAULT_TARGET_DECOY_FLOOR,
            false_positive_bps: 34,
            proof_height: DEVNET_HEIGHT + 18,
        };
        let attestation = PqAttestation {
            attestation_id: "devnet-pq-attestation-0001".to_string(),
            subject_id: bucket.bucket_id.clone(),
            kind: AttestationKind::DecoyPreservation,
            signer_commitment: domain_hash(
                "devnet-pq-signer",
                &[HashPart::Str(PQ_ATTESTATION_SCHEME), HashPart::Str("alpha")],
            ),
            signature_root: domain_hash(
                "devnet-pq-signature",
                &[
                    HashPart::Str("ml-dsa-87"),
                    HashPart::Str("slh-dsa-shake-192f"),
                ],
            ),
            transcript_root: domain_hash(
                "devnet-pq-transcript",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&bucket.bucket_id),
                ],
            ),
            security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            issued_height: DEVNET_HEIGHT + 20,
            expires_height: DEVNET_HEIGHT + 620,
        };
        let settlement = RebateSettlement {
            settlement_id: "devnet-rebate-settlement-0001".to_string(),
            bucket_id: bucket.bucket_id.clone(),
            payer_commitment: domain_hash(
                "devnet-rebate-payer",
                &[HashPart::Str("wallet-group-alpha")],
            ),
            provider_id: cohort.provider_id.clone(),
            fee_paid_micro_units: 1_900,
            rebate_micro_units: 1_662,
            provider_fee_micro_units: 238,
            settlement_height: DEVNET_HEIGHT + 24,
            nullifier: domain_hash(
                "devnet-rebate-nullifier",
                &[HashPart::Str(&bucket.bucket_id), HashPart::U64(1)],
            ),
            status: SettlementStatus::Settled,
        };
        let throttle = ScanThrottle {
            throttle_id: "devnet-throttle-provider-alpha-0001".to_string(),
            provider_id: cohort.provider_id.clone(),
            lane: ScanLane::WalletRestore,
            window_start_height: DEVNET_HEIGHT,
            window_end_height: DEVNET_HEIGHT + DEFAULT_THROTTLE_WINDOW_BLOCKS,
            max_bucket_count: 96,
            max_scan_cost_micro_units: 180_000,
            reason_code: "protect-wallet-restore-low-fee-lane".to_string(),
            status: ThrottleStatus::Monitoring,
        };
        let budget = RedactionBudget {
            budget_id: "devnet-redaction-budget-alpha-epoch-0001".to_string(),
            operator_id: "devnet-operator-alpha".to_string(),
            epoch: DEVNET_EPOCH,
            max_public_fields: 10,
            remaining_summaries: DEFAULT_REDACTION_BUDGET_PER_EPOCH - 1,
            redacted_subject_root: domain_hash(
                "devnet-redacted-subjects",
                &[
                    HashPart::Str(REDACTION_BUDGET_SCHEME),
                    HashPart::U64(DEVNET_EPOCH),
                ],
            ),
            disclosure_policy_root: domain_hash(
                "devnet-disclosure-policy",
                &[HashPart::Str("summary-only"), HashPart::U64(10)],
            ),
        };
        let summary = OperatorSummary {
            summary_id: "devnet-operator-summary-alpha-0001".to_string(),
            operator_id: "devnet-operator-alpha".to_string(),
            epoch: DEVNET_EPOCH,
            lane: ScanLane::WalletRestore,
            redacted_cohort_count: 1,
            redacted_bucket_count: 1,
            settled_rebate_micro_units: settlement.rebate_micro_units,
            median_fee_micro_units: settlement.fee_paid_micro_units,
            privacy_floor_met: true,
            decoy_floor_met: true,
            pq_attested: true,
            redaction_root: budget.redacted_subject_root.clone(),
        };

        self.scan_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.viewtag_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.decoy_scan_proofs.insert(proof.proof_id.clone(), proof);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.settlement_nullifiers
            .insert(settlement.nullifier.clone());
        self.rebate_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.throttles
            .insert(throttle.throttle_id.clone(), throttle);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);

        self.counters.scan_cohorts = self.scan_cohorts.len() as u64;
        self.counters.viewtag_buckets = self.viewtag_buckets.len() as u64;
        self.counters.decoy_scan_proofs = self.decoy_scan_proofs.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.rebate_settlements = self.rebate_settlements.len() as u64;
        self.counters.throttles = self.throttles.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.settled_rebate_micro_units = self
            .rebate_settlements
            .values()
            .map(|settlement| settlement.rebate_micro_units)
            .sum();
        self.counters.preserved_decoy_outputs = self
            .decoy_scan_proofs
            .values()
            .map(|proof| proof.preserved_decoy_outputs)
            .sum();
        self.counters.redacted_public_records = self.operator_summaries.len() as u64;
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

fn empty_root(label: &str) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-decoy-scan-rebate-market-empty-root",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
    )
}

fn record_root(label: &str, record: &Value) -> String {
    let canonical = serde_json::to_string(record).unwrap_or_else(|_| "null".to_string());
    domain_hash(
        "monero-l2-pq-private-viewtag-decoy-scan-rebate-market-record-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(&canonical),
        ],
    )
}

fn collection_root<I>(label: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves: Vec<Value> = records
        .into_iter()
        .map(|record| Value::String(record_root(label, &record)))
        .collect();
    if leaves.is_empty() {
        return empty_root(label);
    }
    merkle_root(
        &format!(
            "monero-l2-pq-private-viewtag-decoy-scan-rebate-market-{}",
            label
        ),
        &leaves,
    )
}

fn domain_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    raw_domain_hash(domain, parts, 32)
}
