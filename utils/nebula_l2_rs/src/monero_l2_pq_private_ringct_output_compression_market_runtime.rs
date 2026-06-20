use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingctOutputCompressionMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_RINGCT_OUTPUT_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ringct-output-compression-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RINGCT_OUTPUT_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_420_800;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const COMPRESSION_COHORT_SCHEME: &str = "ringct-output-compression-cohort-root-v1";
pub const OUTPUT_SET_SCHEME: &str = "ringct-compressed-output-set-root-v1";
pub const DECOY_PRESERVATION_AUDIT_SCHEME: &str = "ringct-decoy-preservation-audit-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-ringct-output-compression-attestation-v1";
pub const SETTLEMENT_SCHEME: &str = "low-fee-ringct-compression-market-settlement-root-v1";
pub const REBATE_SCHEME: &str = "wallet-scan-ringct-compression-rebate-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "redacted-ringct-output-compression-operator-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_key_images_output_indices_or_ring_graphs";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 32;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_OUTPUTS_PER_SET: u32 = 64;
pub const DEFAULT_TARGET_OUTPUTS_PER_SET: u32 = 512;
pub const DEFAULT_MAX_OUTPUTS_PER_SET: u32 = 4_096;
pub const DEFAULT_MIN_COMPRESSION_BPS: u64 = 1_500;
pub const DEFAULT_TARGET_COMPRESSION_BPS: u64 = 4_500;
pub const DEFAULT_MIN_DECOY_PRESERVATION_BPS: u64 = 9_400;
pub const DEFAULT_TARGET_DECOY_PRESERVATION_BPS: u64 = 9_850;
pub const DEFAULT_MIN_SCAN_SPEEDUP_BPS: u64 = 2_000;
pub const DEFAULT_TARGET_SCAN_SPEEDUP_BPS: u64 = 6_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_WALLET_FEE_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = 6;
pub const DEFAULT_REBATE_BPS: u64 = 1_600;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_AUDIT_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 128;
pub const MAX_COHORTS: usize = 1_048_576;
pub const MAX_OUTPUT_SETS: usize = 4_194_304;
pub const MAX_DECOY_AUDITS: usize = 2_097_152;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 4_194_304;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_NULLIFIERS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionLane {
    WalletScan,
    BridgeWithdrawal,
    MerchantReceipt,
    DexSettlement,
    MobileSync,
    WatchtowerAudit,
    ReorgRepair,
}

impl CompressionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceipt => "merchant_receipt",
            Self::DexSettlement => "dex_settlement",
            Self::MobileSync => "mobile_sync",
            Self::WatchtowerAudit => "watchtower_audit",
            Self::ReorgRepair => "reorg_repair",
        }
    }

    pub fn fee_cap(self) -> u64 {
        match self {
            Self::WalletScan => 1_400,
            Self::MobileSync => 1_700,
            Self::MerchantReceipt => 1_900,
            Self::BridgeWithdrawal => 4_800,
            Self::DexSettlement => 5_500,
            Self::WatchtowerAudit => 2_800,
            Self::ReorgRepair => 2_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Open,
    Filling,
    Sealed,
    Attested,
    Settling,
    Settled,
    Expired,
    Quarantined,
}

impl CohortStatus {
    pub fn accepts_outputs(self) -> bool {
        matches!(self, Self::Open | Self::Filling)
    }

    pub fn publicly_usable(self) -> bool {
        matches!(self, Self::Attested | Self::Settling | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputSetStatus {
    Submitted,
    Packed,
    DecoyAudited,
    Attested,
    Settled,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Submitted,
    Passed,
    Warning,
    Failed,
    Expired,
}

impl AuditStatus {
    pub fn preserves_decoys(self) -> bool {
        matches!(self, Self::Passed | Self::Warning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CompressionCorrectness,
    DecoySetPreservation,
    WalletScanSurface,
    FeeSettlement,
    RedactedSummary,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompressionCorrectness => "compression_correctness",
            Self::DecoySetPreservation => "decoy_set_preservation",
            Self::WalletScanSurface => "wallet_scan_surface",
            Self::FeeSettlement => "fee_settlement",
            Self::RedactedSummary => "redacted_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Quoted,
    Matched,
    Netting,
    Settled,
    Rebated,
    Refunded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Sponsored,
    Paid,
    Refunded,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub compression_cohort_scheme: String,
    pub output_set_scheme: String,
    pub decoy_preservation_audit_scheme: String,
    pub pq_attestation_scheme: String,
    pub settlement_scheme: String,
    pub rebate_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_privacy_set_size: u64,
    pub min_outputs_per_set: u32,
    pub target_outputs_per_set: u32,
    pub max_outputs_per_set: u32,
    pub min_compression_bps: u64,
    pub target_compression_bps: u64,
    pub min_decoy_preservation_bps: u64,
    pub target_decoy_preservation_bps: u64,
    pub min_scan_speedup_bps: u64,
    pub target_scan_speedup_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_wallet_fee_micro_units: u64,
    pub settlement_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub cohort_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub public_bucket_size: u64,
    pub allow_low_fee_settlement: bool,
    pub require_decoy_audit: bool,
    pub require_pq_attestation: bool,
    pub redact_operator_summaries: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            compression_cohort_scheme: COMPRESSION_COHORT_SCHEME.to_string(),
            output_set_scheme: OUTPUT_SET_SCHEME.to_string(),
            decoy_preservation_audit_scheme: DECOY_PRESERVATION_AUDIT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            settlement_scheme: SETTLEMENT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_outputs_per_set: DEFAULT_MIN_OUTPUTS_PER_SET,
            target_outputs_per_set: DEFAULT_TARGET_OUTPUTS_PER_SET,
            max_outputs_per_set: DEFAULT_MAX_OUTPUTS_PER_SET,
            min_compression_bps: DEFAULT_MIN_COMPRESSION_BPS,
            target_compression_bps: DEFAULT_TARGET_COMPRESSION_BPS,
            min_decoy_preservation_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            target_decoy_preservation_bps: DEFAULT_TARGET_DECOY_PRESERVATION_BPS,
            min_scan_speedup_bps: DEFAULT_MIN_SCAN_SPEEDUP_BPS,
            target_scan_speedup_bps: DEFAULT_TARGET_SCAN_SPEEDUP_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_wallet_fee_micro_units: DEFAULT_MAX_WALLET_FEE_MICRO_UNITS,
            settlement_fee_bps: DEFAULT_SETTLEMENT_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            audit_ttl_blocks: DEFAULT_AUDIT_TTL_BLOCKS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            allow_low_fee_settlement: true,
            require_decoy_audit: true,
            require_pq_attestation: true,
            redact_operator_summaries: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "compression_cohort_scheme": self.compression_cohort_scheme,
            "output_set_scheme": self.output_set_scheme,
            "decoy_preservation_audit_scheme": self.decoy_preservation_audit_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "settlement_scheme": self.settlement_scheme,
            "rebate_scheme": self.rebate_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_outputs_per_set": self.min_outputs_per_set,
            "target_outputs_per_set": self.target_outputs_per_set,
            "max_outputs_per_set": self.max_outputs_per_set,
            "min_compression_bps": self.min_compression_bps,
            "target_compression_bps": self.target_compression_bps,
            "min_decoy_preservation_bps": self.min_decoy_preservation_bps,
            "target_decoy_preservation_bps": self.target_decoy_preservation_bps,
            "min_scan_speedup_bps": self.min_scan_speedup_bps,
            "target_scan_speedup_bps": self.target_scan_speedup_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_wallet_fee_micro_units": self.max_wallet_fee_micro_units,
            "settlement_fee_bps": self.settlement_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "public_bucket_size": self.public_bucket_size,
            "allow_low_fee_settlement": self.allow_low_fee_settlement,
            "require_decoy_audit": self.require_decoy_audit,
            "require_pq_attestation": self.require_pq_attestation,
            "redact_operator_summaries": self.redact_operator_summaries,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub compression_cohorts: u64,
    pub output_sets: u64,
    pub compressed_outputs: u64,
    pub decoy_preservation_audits: u64,
    pub pq_attestations: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub operator_summaries: u64,
    pub nullifiers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "compression_cohorts": self.compression_cohorts,
            "output_sets": self.output_sets,
            "compressed_outputs": self.compressed_outputs,
            "decoy_preservation_audits": self.decoy_preservation_audits,
            "pq_attestations": self.pq_attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "operator_summaries": self.operator_summaries,
            "nullifiers": self.nullifiers,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub compression_cohort_root: String,
    pub output_set_root: String,
    pub decoy_preservation_audit_root: String,
    pub pq_attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            compression_cohort_root: empty_root("compression_cohorts"),
            output_set_root: empty_root("output_sets"),
            decoy_preservation_audit_root: empty_root("decoy_preservation_audits"),
            pq_attestation_root: empty_root("pq_attestations"),
            settlement_root: empty_root("settlements"),
            rebate_root: empty_root("rebates"),
            operator_summary_root: empty_root("operator_summaries"),
            nullifier_root: empty_root("nullifiers"),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&roots.public_record_without_state_root());
        roots
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "compression_cohort_root": self.compression_cohort_root,
            "output_set_root": self.output_set_root,
            "decoy_preservation_audit_root": self.decoy_preservation_audit_root,
            "pq_attestation_root": self.pq_attestation_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionCohortRequest {
    pub operator_id: String,
    pub lane: CompressionLane,
    pub epoch: u64,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub output_commitment_root: String,
    pub ring_member_commitment_root: String,
    pub view_tag_bucket_root: String,
    pub wallet_scan_surface_root: String,
    pub target_outputs: u32,
    pub max_wallet_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionCohort {
    pub id: String,
    pub operator_id: String,
    pub lane: CompressionLane,
    pub status: CohortStatus,
    pub epoch: u64,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub output_commitment_root: String,
    pub ring_member_commitment_root: String,
    pub view_tag_bucket_root: String,
    pub wallet_scan_surface_root: String,
    pub target_outputs: u32,
    pub accepted_outputs: u32,
    pub packed_outputs: u32,
    pub max_wallet_fee_micro_units: u64,
    pub compression_score_bps: u64,
    pub scan_speedup_bps: u64,
    pub expires_at_height: u64,
}

impl CompressionCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "epoch": self.epoch,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "output_commitment_root": self.output_commitment_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "wallet_scan_surface_root": self.wallet_scan_surface_root,
            "target_outputs": self.target_outputs,
            "accepted_outputs": self.accepted_outputs,
            "packed_outputs": self.packed_outputs,
            "max_wallet_fee_micro_units": self.max_wallet_fee_micro_units,
            "compression_score_bps": self.compression_score_bps,
            "scan_speedup_bps": self.scan_speedup_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputSetRequest {
    pub cohort_id: String,
    pub wallet_context_root: String,
    pub compressed_output_root: String,
    pub preimage_commitment_root: String,
    pub scan_hint_root: String,
    pub decoy_distribution_root: String,
    pub nullifier_commitment: String,
    pub output_count: u32,
    pub ring_size: u16,
    pub privacy_set_size: u64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputSet {
    pub id: String,
    pub cohort_id: String,
    pub status: OutputSetStatus,
    pub wallet_context_root: String,
    pub compressed_output_root: String,
    pub preimage_commitment_root: String,
    pub scan_hint_root: String,
    pub decoy_distribution_root: String,
    pub nullifier_commitment: String,
    pub output_count: u32,
    pub ring_size: u16,
    pub privacy_set_size: u64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub compression_bps: u64,
    pub scan_speedup_bps: u64,
}

impl OutputSet {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "wallet_context_root": self.wallet_context_root,
            "compressed_output_root": self.compressed_output_root,
            "preimage_commitment_root": self.preimage_commitment_root,
            "scan_hint_root": self.scan_hint_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "nullifier_commitment": self.nullifier_commitment,
            "output_count": self.output_count,
            "ring_size": self.ring_size,
            "privacy_set_size": self.privacy_set_size,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_bps": self.compression_bps,
            "scan_speedup_bps": self.scan_speedup_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyPreservationAuditRequest {
    pub output_set_id: String,
    pub auditor_id: String,
    pub ring_continuity_root: String,
    pub decoy_age_histogram_root: String,
    pub selection_equivalence_root: String,
    pub linkability_regression_root: String,
    pub preservation_bps: u64,
    pub entropy_bps: u64,
    pub false_positive_risk_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyPreservationAudit {
    pub id: String,
    pub output_set_id: String,
    pub auditor_id: String,
    pub status: AuditStatus,
    pub ring_continuity_root: String,
    pub decoy_age_histogram_root: String,
    pub selection_equivalence_root: String,
    pub linkability_regression_root: String,
    pub preservation_bps: u64,
    pub entropy_bps: u64,
    pub false_positive_risk_bps: u64,
    pub expires_at_height: u64,
}

impl DecoyPreservationAudit {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "output_set_id": self.output_set_id,
            "auditor_id": self.auditor_id,
            "status": self.status,
            "ring_continuity_root": self.ring_continuity_root,
            "decoy_age_histogram_root": self.decoy_age_histogram_root,
            "selection_equivalence_root": self.selection_equivalence_root,
            "linkability_regression_root": self.linkability_regression_root,
            "preservation_bps": self.preservation_bps,
            "entropy_bps": self.entropy_bps,
            "false_positive_risk_bps": self.false_positive_risk_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub output_set_id: String,
    pub operator_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub disclosure_root: String,
    pub pq_security_bits: u16,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub id: String,
    pub output_set_id: String,
    pub operator_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub disclosure_root: String,
    pub pq_security_bits: u16,
    pub accepted: bool,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "output_set_id": self.output_set_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "statement_root": self.statement_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "disclosure_root": self.disclosure_root,
            "pq_security_bits": self.pq_security_bits,
            "accepted": self.accepted,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRequest {
    pub output_set_id: String,
    pub payer_commitment_root: String,
    pub operator_fee_commitment_root: String,
    pub sponsor_commitment_root: String,
    pub settlement_note_root: String,
    pub quoted_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Settlement {
    pub id: String,
    pub output_set_id: String,
    pub status: SettlementStatus,
    pub payer_commitment_root: String,
    pub operator_fee_commitment_root: String,
    pub sponsor_commitment_root: String,
    pub settlement_note_root: String,
    pub quoted_fee_micro_units: u64,
    pub settled_fee_micro_units: u64,
    pub compression_discount_bps: u64,
}

impl Settlement {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "output_set_id": self.output_set_id,
            "status": self.status,
            "payer_commitment_root": self.payer_commitment_root,
            "operator_fee_commitment_root": self.operator_fee_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "settlement_note_root": self.settlement_note_root,
            "quoted_fee_micro_units": self.quoted_fee_micro_units,
            "settled_fee_micro_units": self.settled_fee_micro_units,
            "compression_discount_bps": self.compression_discount_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub id: String,
    pub settlement_id: String,
    pub output_set_id: String,
    pub status: RebateStatus,
    pub recipient_commitment_root: String,
    pub rebate_note_root: String,
    pub rebate_micro_units: u64,
    pub sponsor_cover_bps: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "settlement_id": self.settlement_id,
            "output_set_id": self.output_set_id,
            "status": self.status,
            "recipient_commitment_root": self.recipient_commitment_root,
            "rebate_note_root": self.rebate_note_root,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub operator_id: String,
    pub cohort_id: String,
    pub redacted_output_bucket_root: String,
    pub redacted_fee_bucket_root: String,
    pub redacted_scan_surface_root: String,
    pub public_metrics_root: String,
    pub bucketed_outputs: u64,
    pub bucketed_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub id: String,
    pub operator_id: String,
    pub cohort_id: String,
    pub redacted_output_bucket_root: String,
    pub redacted_fee_bucket_root: String,
    pub redacted_scan_surface_root: String,
    pub public_metrics_root: String,
    pub bucketed_outputs: u64,
    pub bucketed_fee_micro_units: u64,
    pub privacy_boundary: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "operator_id": self.operator_id,
            "cohort_id": self.cohort_id,
            "redacted_output_bucket_root": self.redacted_output_bucket_root,
            "redacted_fee_bucket_root": self.redacted_fee_bucket_root,
            "redacted_scan_surface_root": self.redacted_scan_surface_root,
            "public_metrics_root": self.public_metrics_root,
            "bucketed_outputs": self.bucketed_outputs,
            "bucketed_fee_micro_units": self.bucketed_fee_micro_units,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub compression_cohorts: BTreeMap<String, CompressionCohort>,
    pub output_sets: BTreeMap<String, OutputSet>,
    pub decoy_preservation_audits: BTreeMap<String, DecoyPreservationAudit>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub settlements: BTreeMap<String, Settlement>,
    pub rebates: BTreeMap<String, Rebate>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            compression_cohorts: BTreeMap::new(),
            output_sets: BTreeMap::new(),
            decoy_preservation_audits: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        seed_devnet(&mut state);
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn open_compression_cohort(&mut self, request: CompressionCohortRequest) -> Result<String> {
        ensure!(
            self.compression_cohorts.len() < MAX_COHORTS,
            "compression cohort capacity exhausted"
        );
        ensure!(
            request.monero_start_height <= request.monero_end_height,
            "cohort height range is invalid"
        );
        ensure!(
            request.target_outputs >= self.config.min_outputs_per_set,
            "target outputs below minimum"
        );
        ensure!(
            request.target_outputs <= self.config.max_outputs_per_set,
            "target outputs above maximum"
        );
        ensure!(
            request.max_wallet_fee_micro_units <= self.config.max_wallet_fee_micro_units,
            "wallet fee cap exceeds config maximum"
        );

        let record = json!({
            "operator_id": request.operator_id,
            "lane": request.lane.as_str(),
            "epoch": request.epoch,
            "monero_start_height": request.monero_start_height,
            "monero_end_height": request.monero_end_height,
            "output_commitment_root": request.output_commitment_root,
            "ring_member_commitment_root": request.ring_member_commitment_root,
            "view_tag_bucket_root": request.view_tag_bucket_root,
            "wallet_scan_surface_root": request.wallet_scan_surface_root,
            "target_outputs": request.target_outputs,
        });
        let id = id_from_record("compression_cohort", &record);
        ensure!(
            !self.compression_cohorts.contains_key(&id),
            "compression cohort already exists"
        );

        let cohort = CompressionCohort {
            id: id.clone(),
            operator_id: request.operator_id,
            lane: request.lane,
            status: CohortStatus::Open,
            epoch: request.epoch,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            output_commitment_root: request.output_commitment_root,
            ring_member_commitment_root: request.ring_member_commitment_root,
            view_tag_bucket_root: request.view_tag_bucket_root,
            wallet_scan_surface_root: request.wallet_scan_surface_root,
            target_outputs: request.target_outputs,
            accepted_outputs: 0,
            packed_outputs: 0,
            max_wallet_fee_micro_units: request.max_wallet_fee_micro_units,
            compression_score_bps: 0,
            scan_speedup_bps: 0,
            expires_at_height: request
                .monero_end_height
                .saturating_add(self.config.cohort_ttl_blocks),
        };
        self.compression_cohorts.insert(id.clone(), cohort);
        self.counters.compression_cohorts = self.counters.compression_cohorts.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn submit_output_set(&mut self, request: OutputSetRequest) -> Result<String> {
        ensure!(
            self.output_sets.len() < MAX_OUTPUT_SETS,
            "output set capacity exhausted"
        );
        ensure!(
            self.nullifiers.len() < MAX_NULLIFIERS,
            "nullifier capacity exhausted"
        );
        ensure!(
            !self.nullifiers.contains(&request.nullifier_commitment),
            "output set nullifier already used"
        );
        let cohort = self
            .compression_cohorts
            .get_mut(&request.cohort_id)
            .ok_or_else(|| format!("unknown compression cohort {}", request.cohort_id))?;
        ensure!(
            cohort.status.accepts_outputs(),
            "cohort does not accept outputs"
        );
        ensure!(
            request.output_count >= self.config.min_outputs_per_set,
            "output count below minimum"
        );
        ensure!(
            request.output_count <= self.config.max_outputs_per_set,
            "output count above maximum"
        );
        ensure!(
            request.ring_size >= self.config.min_ring_size,
            "ring size below privacy floor"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set size below floor"
        );
        ensure!(
            request.compressed_bytes < request.uncompressed_bytes,
            "compressed bytes must be lower than uncompressed bytes"
        );

        let compression_bps = compression_bps(request.uncompressed_bytes, request.compressed_bytes);
        ensure!(
            compression_bps >= self.config.min_compression_bps,
            "compression score below minimum"
        );
        let scan_speedup_bps = scan_speedup_bps(request.output_count, compression_bps);
        ensure!(
            scan_speedup_bps >= self.config.min_scan_speedup_bps,
            "wallet scan speedup below minimum"
        );

        let record = json!({
            "cohort_id": request.cohort_id,
            "wallet_context_root": request.wallet_context_root,
            "compressed_output_root": request.compressed_output_root,
            "preimage_commitment_root": request.preimage_commitment_root,
            "scan_hint_root": request.scan_hint_root,
            "decoy_distribution_root": request.decoy_distribution_root,
            "nullifier_commitment": request.nullifier_commitment,
        });
        let id = id_from_record("output_set", &record);
        ensure!(
            !self.output_sets.contains_key(&id),
            "output set already exists"
        );

        let output_set = OutputSet {
            id: id.clone(),
            cohort_id: request.cohort_id,
            status: OutputSetStatus::Packed,
            wallet_context_root: request.wallet_context_root,
            compressed_output_root: request.compressed_output_root,
            preimage_commitment_root: request.preimage_commitment_root,
            scan_hint_root: request.scan_hint_root,
            decoy_distribution_root: request.decoy_distribution_root,
            nullifier_commitment: request.nullifier_commitment.clone(),
            output_count: request.output_count,
            ring_size: request.ring_size,
            privacy_set_size: request.privacy_set_size,
            uncompressed_bytes: request.uncompressed_bytes,
            compressed_bytes: request.compressed_bytes,
            compression_bps,
            scan_speedup_bps,
        };
        cohort.status = CohortStatus::Filling;
        cohort.accepted_outputs = cohort.accepted_outputs.saturating_add(request.output_count);
        cohort.packed_outputs = cohort.packed_outputs.saturating_add(request.output_count);
        cohort.compression_score_bps = weighted_average_bps(
            cohort.compression_score_bps,
            cohort.accepted_outputs.saturating_sub(request.output_count) as u64,
            compression_bps,
            request.output_count as u64,
        );
        cohort.scan_speedup_bps = weighted_average_bps(
            cohort.scan_speedup_bps,
            cohort.accepted_outputs.saturating_sub(request.output_count) as u64,
            scan_speedup_bps,
            request.output_count as u64,
        );
        if cohort.accepted_outputs >= cohort.target_outputs {
            cohort.status = CohortStatus::Sealed;
        }

        self.nullifiers.insert(request.nullifier_commitment);
        self.output_sets.insert(id.clone(), output_set);
        self.counters.output_sets = self.counters.output_sets.saturating_add(1);
        self.counters.compressed_outputs = self
            .counters
            .compressed_outputs
            .saturating_add(request.output_count as u64);
        self.counters.nullifiers = self.counters.nullifiers.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn audit_decoy_preservation(
        &mut self,
        request: DecoyPreservationAuditRequest,
    ) -> Result<String> {
        ensure!(
            self.decoy_preservation_audits.len() < MAX_DECOY_AUDITS,
            "decoy audit capacity exhausted"
        );
        ensure!(
            request.preservation_bps <= MAX_BPS && request.entropy_bps <= MAX_BPS,
            "audit bps out of range"
        );
        ensure!(
            request.false_positive_risk_bps <= MAX_BPS,
            "false positive risk bps out of range"
        );
        let output_set = self
            .output_sets
            .get_mut(&request.output_set_id)
            .ok_or_else(|| format!("unknown output set {}", request.output_set_id))?;
        let status = if request.preservation_bps >= self.config.target_decoy_preservation_bps {
            AuditStatus::Passed
        } else if request.preservation_bps >= self.config.min_decoy_preservation_bps {
            AuditStatus::Warning
        } else {
            AuditStatus::Failed
        };
        ensure!(
            status.preserves_decoys(),
            "decoy preservation below minimum"
        );

        let record = json!({
            "output_set_id": request.output_set_id,
            "auditor_id": request.auditor_id,
            "ring_continuity_root": request.ring_continuity_root,
            "decoy_age_histogram_root": request.decoy_age_histogram_root,
            "selection_equivalence_root": request.selection_equivalence_root,
            "linkability_regression_root": request.linkability_regression_root,
        });
        let id = id_from_record("decoy_preservation_audit", &record);
        ensure!(
            !self.decoy_preservation_audits.contains_key(&id),
            "decoy preservation audit already exists"
        );
        let audit = DecoyPreservationAudit {
            id: id.clone(),
            output_set_id: request.output_set_id,
            auditor_id: request.auditor_id,
            status,
            ring_continuity_root: request.ring_continuity_root,
            decoy_age_histogram_root: request.decoy_age_histogram_root,
            selection_equivalence_root: request.selection_equivalence_root,
            linkability_regression_root: request.linkability_regression_root,
            preservation_bps: request.preservation_bps,
            entropy_bps: request.entropy_bps,
            false_positive_risk_bps: request.false_positive_risk_bps,
            expires_at_height: DEVNET_HEIGHT.saturating_add(self.config.audit_ttl_blocks),
        };
        output_set.status = OutputSetStatus::DecoyAudited;
        self.decoy_preservation_audits.insert(id.clone(), audit);
        self.counters.decoy_preservation_audits =
            self.counters.decoy_preservation_audits.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn attest_output_set(&mut self, request: PqAttestationRequest) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < MAX_PQ_ATTESTATIONS,
            "pq attestation capacity exhausted"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below minimum"
        );
        ensure!(
            request.expires_at_height >= DEVNET_HEIGHT,
            "pq attestation already expired"
        );
        let output_set = self
            .output_sets
            .get_mut(&request.output_set_id)
            .ok_or_else(|| format!("unknown output set {}", request.output_set_id))?;
        if self.config.require_decoy_audit {
            ensure!(
                self.decoy_preservation_audits
                    .values()
                    .any(|audit| audit.output_set_id == request.output_set_id
                        && audit.status.preserves_decoys()),
                "missing successful decoy preservation audit"
            );
        }

        let record = json!({
            "output_set_id": request.output_set_id,
            "operator_id": request.operator_id,
            "kind": request.kind.as_str(),
            "statement_root": request.statement_root,
            "transcript_root": request.transcript_root,
            "pq_signature_root": request.pq_signature_root,
        });
        let id = id_from_record("pq_attestation", &record);
        ensure!(
            !self.pq_attestations.contains_key(&id),
            "pq attestation already exists"
        );
        let attestation = PqAttestation {
            id: id.clone(),
            output_set_id: request.output_set_id.clone(),
            operator_id: request.operator_id,
            kind: request.kind,
            statement_root: request.statement_root,
            transcript_root: request.transcript_root,
            pq_signature_root: request.pq_signature_root,
            disclosure_root: request.disclosure_root,
            pq_security_bits: request.pq_security_bits,
            accepted: true,
            expires_at_height: request.expires_at_height,
        };
        output_set.status = OutputSetStatus::Attested;
        if let Some(cohort) = self.compression_cohorts.get_mut(&output_set.cohort_id) {
            cohort.status = CohortStatus::Attested;
        }
        self.pq_attestations.insert(id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn settle_output_set(&mut self, request: SettlementRequest) -> Result<String> {
        ensure!(
            self.settlements.len() < MAX_SETTLEMENTS,
            "settlement capacity exhausted"
        );
        let output_set = self
            .output_sets
            .get_mut(&request.output_set_id)
            .ok_or_else(|| format!("unknown output set {}", request.output_set_id))?;
        ensure!(
            matches!(output_set.status, OutputSetStatus::Attested),
            "output set must be attested before settlement"
        );
        ensure!(
            request.quoted_fee_micro_units <= self.config.max_wallet_fee_micro_units,
            "quoted fee exceeds wallet maximum"
        );
        if self.config.require_pq_attestation {
            ensure!(
                self.pq_attestations
                    .values()
                    .any(
                        |attestation| attestation.output_set_id == request.output_set_id
                            && attestation.accepted
                    ),
                "missing accepted pq attestation"
            );
        }

        let compression_discount_bps = compression_discount_bps(
            output_set.compression_bps,
            self.config.target_compression_bps,
        );
        let settled_fee_micro_units = request
            .quoted_fee_micro_units
            .saturating_mul(MAX_BPS.saturating_sub(compression_discount_bps))
            / MAX_BPS;
        let record = json!({
            "output_set_id": request.output_set_id,
            "payer_commitment_root": request.payer_commitment_root,
            "operator_fee_commitment_root": request.operator_fee_commitment_root,
            "sponsor_commitment_root": request.sponsor_commitment_root,
            "settlement_note_root": request.settlement_note_root,
        });
        let id = id_from_record("settlement", &record);
        ensure!(
            !self.settlements.contains_key(&id),
            "settlement already exists"
        );
        let settlement = Settlement {
            id: id.clone(),
            output_set_id: request.output_set_id.clone(),
            status: SettlementStatus::Settled,
            payer_commitment_root: request.payer_commitment_root,
            operator_fee_commitment_root: request.operator_fee_commitment_root,
            sponsor_commitment_root: request.sponsor_commitment_root,
            settlement_note_root: request.settlement_note_root,
            quoted_fee_micro_units: request.quoted_fee_micro_units,
            settled_fee_micro_units,
            compression_discount_bps,
        };
        output_set.status = OutputSetStatus::Settled;
        if let Some(cohort) = self.compression_cohorts.get_mut(&output_set.cohort_id) {
            cohort.status = CohortStatus::Settling;
        }
        self.settlements.insert(id.clone(), settlement);
        self.counters.settlements = self.counters.settlements.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn queue_rebate(
        &mut self,
        settlement_id: &str,
        recipient_commitment_root: String,
        rebate_note_root: String,
    ) -> Result<String> {
        ensure!(
            self.rebates.len() < MAX_REBATES,
            "rebate capacity exhausted"
        );
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        ensure!(
            matches!(settlement.status, SettlementStatus::Settled),
            "settlement must be settled before rebate"
        );
        let rebate_micro_units = settlement
            .settled_fee_micro_units
            .saturating_mul(self.config.rebate_bps)
            / MAX_BPS;
        let record = json!({
            "settlement_id": settlement_id,
            "output_set_id": settlement.output_set_id,
            "recipient_commitment_root": recipient_commitment_root,
            "rebate_note_root": rebate_note_root,
        });
        let id = id_from_record("rebate", &record);
        ensure!(!self.rebates.contains_key(&id), "rebate already exists");
        let rebate = Rebate {
            id: id.clone(),
            settlement_id: settlement_id.to_string(),
            output_set_id: settlement.output_set_id.clone(),
            status: RebateStatus::Queued,
            recipient_commitment_root,
            rebate_note_root,
            rebate_micro_units,
            sponsor_cover_bps: self.config.sponsor_cover_bps,
        };
        settlement.status = SettlementStatus::Rebated;
        self.rebates.insert(id.clone(), rebate);
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exhausted"
        );
        ensure!(
            self.compression_cohorts.contains_key(&request.cohort_id),
            "unknown compression cohort"
        );
        let bucketed_outputs =
            bucket_value(request.bucketed_outputs, self.config.public_bucket_size);
        let bucketed_fee_micro_units = bucket_value(
            request.bucketed_fee_micro_units,
            self.config.public_bucket_size,
        );
        let record = json!({
            "operator_id": request.operator_id,
            "cohort_id": request.cohort_id,
            "redacted_output_bucket_root": request.redacted_output_bucket_root,
            "redacted_fee_bucket_root": request.redacted_fee_bucket_root,
            "redacted_scan_surface_root": request.redacted_scan_surface_root,
            "public_metrics_root": request.public_metrics_root,
        });
        let id = id_from_record("operator_summary", &record);
        ensure!(
            !self.operator_summaries.contains_key(&id),
            "operator summary already exists"
        );
        let summary = OperatorSummary {
            id: id.clone(),
            operator_id: request.operator_id,
            cohort_id: request.cohort_id,
            redacted_output_bucket_root: request.redacted_output_bucket_root,
            redacted_fee_bucket_root: request.redacted_fee_bucket_root,
            redacted_scan_surface_root: request.redacted_scan_surface_root,
            public_metrics_root: request.public_metrics_root,
            bucketed_outputs,
            bucketed_fee_micro_units,
            privacy_boundary: self.config.privacy_boundary.clone(),
        };
        self.operator_summaries.insert(id.clone(), summary);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.compression_cohort_root =
            map_root("compression_cohorts", &self.compression_cohorts, |record| {
                record.public_record()
            });
        self.roots.output_set_root = map_root("output_sets", &self.output_sets, |record| {
            record.public_record()
        });
        self.roots.decoy_preservation_audit_root = map_root(
            "decoy_preservation_audits",
            &self.decoy_preservation_audits,
            |record| record.public_record(),
        );
        self.roots.pq_attestation_root =
            map_root("pq_attestations", &self.pq_attestations, |record| {
                record.public_record()
            });
        self.roots.settlement_root = map_root("settlements", &self.settlements, |record| {
            record.public_record()
        });
        self.roots.rebate_root =
            map_root("rebates", &self.rebates, |record| record.public_record());
        self.roots.operator_summary_root =
            map_root("operator_summaries", &self.operator_summaries, |record| {
                record.public_record()
            });
        self.roots.nullifier_root = set_root("nullifiers", &self.nullifiers);
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "privacy_boundary": self.config.privacy_boundary,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
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

fn seed_devnet(state: &mut State) {
    let cohort_id = state
        .open_compression_cohort(CompressionCohortRequest {
            operator_id: "ringct-compression-operator-a".to_string(),
            lane: CompressionLane::WalletScan,
            epoch: DEVNET_EPOCH,
            monero_start_height: DEVNET_HEIGHT,
            monero_end_height: DEVNET_HEIGHT + 120,
            output_commitment_root: deterministic_root("outputs", "wallet-scan-cohort-a"),
            ring_member_commitment_root: deterministic_root("ring_members", "wallet-scan-cohort-a"),
            view_tag_bucket_root: deterministic_root("view_tags", "wallet-scan-cohort-a"),
            wallet_scan_surface_root: deterministic_root("scan_surface", "wallet-scan-cohort-a"),
            target_outputs: 512,
            max_wallet_fee_micro_units: 1_600,
        })
        .expect("devnet cohort");
    let output_set_id = state
        .submit_output_set(OutputSetRequest {
            cohort_id: cohort_id.clone(),
            wallet_context_root: deterministic_root("wallet_context", "wallet-a"),
            compressed_output_root: deterministic_root("compressed_outputs", "wallet-a"),
            preimage_commitment_root: deterministic_root("preimages", "wallet-a"),
            scan_hint_root: deterministic_root("scan_hints", "wallet-a"),
            decoy_distribution_root: deterministic_root("decoy_distribution", "wallet-a"),
            nullifier_commitment: deterministic_root("nullifier", "wallet-a"),
            output_count: 512,
            ring_size: 32,
            privacy_set_size: 131_072,
            uncompressed_bytes: 524_288,
            compressed_bytes: 262_144,
        })
        .expect("devnet output set");
    state
        .audit_decoy_preservation(DecoyPreservationAuditRequest {
            output_set_id: output_set_id.clone(),
            auditor_id: "decoy-preservation-auditor-a".to_string(),
            ring_continuity_root: deterministic_root("ring_continuity", "wallet-a"),
            decoy_age_histogram_root: deterministic_root("decoy_age_histogram", "wallet-a"),
            selection_equivalence_root: deterministic_root("selection_equivalence", "wallet-a"),
            linkability_regression_root: deterministic_root("linkability_regression", "wallet-a"),
            preservation_bps: 9_880,
            entropy_bps: 9_620,
            false_positive_risk_bps: 40,
        })
        .expect("devnet decoy audit");
    state
        .attest_output_set(PqAttestationRequest {
            output_set_id: output_set_id.clone(),
            operator_id: "ringct-compression-operator-a".to_string(),
            kind: AttestationKind::CompressionCorrectness,
            statement_root: deterministic_root("statement", "wallet-a"),
            transcript_root: deterministic_root("transcript", "wallet-a"),
            pq_signature_root: deterministic_root("pq_signature", "wallet-a"),
            disclosure_root: deterministic_root("disclosure", "roots-only"),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        })
        .expect("devnet pq attestation");
    let settlement_id = state
        .settle_output_set(SettlementRequest {
            output_set_id: output_set_id.clone(),
            payer_commitment_root: deterministic_root("payer", "wallet-a"),
            operator_fee_commitment_root: deterministic_root("operator_fee", "wallet-a"),
            sponsor_commitment_root: deterministic_root("sponsor", "wallet-a"),
            settlement_note_root: deterministic_root("settlement_note", "wallet-a"),
            quoted_fee_micro_units: 1_500,
        })
        .expect("devnet settlement");
    state
        .queue_rebate(
            &settlement_id,
            deterministic_root("rebate_recipient", "wallet-a"),
            deterministic_root("rebate_note", "wallet-a"),
        )
        .expect("devnet rebate");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            operator_id: "ringct-compression-operator-a".to_string(),
            cohort_id,
            redacted_output_bucket_root: deterministic_root("redacted_outputs", "operator-a"),
            redacted_fee_bucket_root: deterministic_root("redacted_fees", "operator-a"),
            redacted_scan_surface_root: deterministic_root("redacted_scan_surface", "operator-a"),
            public_metrics_root: deterministic_root("public_metrics", "operator-a"),
            bucketed_outputs: 512,
            bucketed_fee_micro_units: 1_500,
        })
        .expect("devnet operator summary");
    state.refresh_roots();
}

fn compression_bps(uncompressed_bytes: u64, compressed_bytes: u64) -> u64 {
    if uncompressed_bytes == 0 || compressed_bytes >= uncompressed_bytes {
        return 0;
    }
    uncompressed_bytes
        .saturating_sub(compressed_bytes)
        .saturating_mul(MAX_BPS)
        / uncompressed_bytes
}

fn scan_speedup_bps(output_count: u32, compression_bps: u64) -> u64 {
    let density_component = (output_count as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_TARGET_OUTPUTS_PER_SET as u64)
        .min(MAX_BPS);
    (compression_bps.saturating_mul(65) + density_component.saturating_mul(35)) / 100
}

fn compression_discount_bps(compression_bps: u64, target_compression_bps: u64) -> u64 {
    let target_component = compression_bps
        .saturating_mul(2_500)
        .saturating_div(target_compression_bps.max(1))
        .min(2_500);
    target_component
        .saturating_add(DEFAULT_SETTLEMENT_FEE_BPS)
        .min(3_000)
}

fn weighted_average_bps(previous: u64, previous_weight: u64, next: u64, next_weight: u64) -> u64 {
    let total = previous_weight.saturating_add(next_weight);
    if total == 0 {
        return 0;
    }
    previous
        .saturating_mul(previous_weight)
        .saturating_add(next.saturating_mul(next_weight))
        / total
}

fn bucket_value(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        return value;
    }
    value
        .saturating_div(bucket_size)
        .saturating_mul(bucket_size)
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}:root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}:id"),
        &[HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-ringct-output-compression-market:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-ringct-output-compression-market:{domain}"),
        &leaves,
    )
}
