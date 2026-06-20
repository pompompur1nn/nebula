use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateSeraphisClsagDualDecoyAuditRuntimeResult<T>;
pub type MoneroL2PqPrivateSeraphisClsagDualDecoyAuditRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_CLSAG_DUAL_DECOY_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-clsag-dual-decoy-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_CLSAG_DUAL_DECOY_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DUAL_RING_AUDIT_SCHEME: &str = "seraphis-clsag-dual-ring-audit-root-v1";
pub const DUAL_RING_ENTROPY_SCHEME: &str = "seraphis-clsag-dual-ring-entropy-score-root-v1";
pub const DECOY_AGE_DIVERSITY_SCHEME: &str = "seraphis-clsag-decoy-age-diversity-root-v1";
pub const VIEWTAG_STEALTH_PRIVACY_SCHEME: &str =
    "seraphis-viewtag-stealth-note-privacy-check-root-v1";
pub const PQ_MIGRATION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-seraphis-clsag-dual-decoy-migration-root-v1";
pub const FEE_SPONSORED_AUDIT_BATCH_SCHEME: &str =
    "low-fee-seraphis-clsag-fee-sponsored-audit-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-clsag-dual-decoy-audit-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_key_images_viewtags_ring_members_note_secrets_subaddress_indices_or_decoy_samples";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_149_200;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_825_200;
pub const DEVNET_EPOCH: u64 = 17_620;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SCORE: u64 = 10_000;
pub const DEFAULT_MIN_CLSAG_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_SERAPHIS_RING_SIZE: u16 = 32;
pub const DEFAULT_TARGET_CLSAG_RING_SIZE: u16 = 128;
pub const DEFAULT_TARGET_SERAPHIS_RING_SIZE: u16 = 256;
pub const DEFAULT_MIN_DUAL_RING_ENTROPY_BPS: u64 = 9_050;
pub const DEFAULT_TARGET_DUAL_RING_ENTROPY_BPS: u64 = 9_825;
pub const DEFAULT_MIN_CROSS_RING_INDEPENDENCE_BPS: u64 = 9_100;
pub const DEFAULT_TARGET_CROSS_RING_INDEPENDENCE_BPS: u64 = 9_850;
pub const DEFAULT_MAX_SHARED_DECOY_OVERLAP_BPS: u64 = 75;
pub const DEFAULT_MAX_POSITION_CORRELATION_BPS: u64 = 90;
pub const DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS: u64 = 4_100_000;
pub const DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS: u64 = 5_250_000;
pub const DEFAULT_MIN_MIN_ENTROPY_MILLIBITS: u64 = 3_450_000;
pub const DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS: u64 = 4_700_000;
pub const DEFAULT_MIN_EFFECTIVE_DUAL_DECOYS: u64 = 160;
pub const DEFAULT_TARGET_EFFECTIVE_DUAL_DECOYS: u64 = 240;
pub const DEFAULT_MIN_AGE_BUCKETS: u16 = 8;
pub const DEFAULT_TARGET_AGE_BUCKETS: u16 = 40;
pub const DEFAULT_MIN_DECOY_AGE_DIVERSITY_BPS: u64 = 9_000;
pub const DEFAULT_TARGET_DECOY_AGE_DIVERSITY_BPS: u64 = 9_780;
pub const DEFAULT_MAX_RECENT_DECOY_DOMINANCE_BPS: u64 = 1_650;
pub const DEFAULT_MAX_AGE_BUCKET_SKEW_BPS: u64 = 500;
pub const DEFAULT_MIN_VIEWTAG_PRIVACY_BPS: u64 = 9_150;
pub const DEFAULT_TARGET_VIEWTAG_PRIVACY_BPS: u64 = 9_900;
pub const DEFAULT_MAX_VIEWTAG_COLLISION_BPS: u64 = 12;
pub const DEFAULT_MAX_STEALTH_NOTE_LINKAGE_BPS: u64 = 25;
pub const DEFAULT_MIN_STEALTH_NOTE_ROTATION_BPS: u64 = 9_200;
pub const DEFAULT_TARGET_STEALTH_NOTE_ROTATION_BPS: u64 = 9_900;
pub const DEFAULT_MIN_PQ_MIGRATION_SAFETY_BPS: u64 = 9_250;
pub const DEFAULT_TARGET_PQ_MIGRATION_SAFETY_BPS: u64 = 9_900;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_AUDIT_BATCH_OUTPUTS: u64 = 8_192;
pub const DEFAULT_TARGET_AUDIT_BATCH_OUTPUTS: u64 = 65_536;
pub const DEFAULT_MIN_SPONSOR_RESERVE_ATOMS: u64 = 25_000_000_000;
pub const DEFAULT_AUDIT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_SPONSOR_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    ConsolidationShieldingScan,
    MultisigSpendAudit,
    ReorgRepair,
    MigrationDryRun,
}

impl AuditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::ConsolidationShieldingScan => "consolidation_shielding_scan",
            Self::MultisigSpendAudit => "multisig_spend_audit",
            Self::ReorgRepair => "reorg_repair",
            Self::MigrationDryRun => "migration_dry_run",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Observed,
    DualEntropyScored,
    AgeDiversityScored,
    ViewtagStealthChecked,
    PqAttested,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl AuditStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::DualEntropyScored
                | Self::AgeDiversityScored
                | Self::ViewtagStealthChecked
                | Self::PqAttested
                | Self::BatchEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DualRingKind {
    SeraphisPrimaryClsagShadow,
    ClsagPrimarySeraphisShadow,
    BridgeIngressDualRing,
    SwapSettlementDualRing,
    MerchantFlowDualRing,
    ReorgRepairDualRing,
    MigrationCanaryDualRing,
    MultisigDualRing,
}

impl DualRingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeraphisPrimaryClsagShadow => "seraphis_primary_clsag_shadow",
            Self::ClsagPrimarySeraphisShadow => "clsag_primary_seraphis_shadow",
            Self::BridgeIngressDualRing => "bridge_ingress_dual_ring",
            Self::SwapSettlementDualRing => "swap_settlement_dual_ring",
            Self::MerchantFlowDualRing => "merchant_flow_dual_ring",
            Self::ReorgRepairDualRing => "reorg_repair_dual_ring",
            Self::MigrationCanaryDualRing => "migration_canary_dual_ring",
            Self::MultisigDualRing => "multisig_dual_ring",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeBandKind {
    AncientAnchor,
    ColdHistorical,
    WarmHistorical,
    WarmRecent,
    HotRecent,
    MempoolAdjacent,
    BridgeLiquidity,
    SwapSettlement,
    MerchantFlow,
    ReorgRepair,
}

impl AgeBandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AncientAnchor => "ancient_anchor",
            Self::ColdHistorical => "cold_historical",
            Self::WarmHistorical => "warm_historical",
            Self::WarmRecent => "warm_recent",
            Self::HotRecent => "hot_recent",
            Self::MempoolAdjacent => "mempool_adjacent",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::SwapSettlement => "swap_settlement",
            Self::MerchantFlow => "merchant_flow",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewtagCheckKind {
    SeraphisViewtagCollision,
    JamtisCompatibilityScan,
    StealthNoteRotation,
    ViewKeyDisclosureBudget,
    NoteRecoveryBloom,
    SubaddressFanout,
    WalletScanThrottle,
    MigrationShadowScan,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    MlDsaBridgeCommittee,
    MlKemViewkeyWrap,
    SlhDsaEmergencyFallback,
    HybridClsagBinding,
    SeraphisMigrationBurn,
    KeyImageNullifierGuard,
    TranscriptArchive,
    ClassicalFallbackDisablement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    WalletScanRebate,
    BridgeDepositAudit,
    MerchantReceiveAudit,
    SwapSettlementAudit,
    ReorgRepairAudit,
    MigrationCanaryAudit,
    WatchOnlyScanRebate,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_clsag_ring_size: u16,
    pub min_seraphis_ring_size: u16,
    pub target_clsag_ring_size: u16,
    pub target_seraphis_ring_size: u16,
    pub min_dual_ring_entropy_bps: u64,
    pub target_dual_ring_entropy_bps: u64,
    pub min_cross_ring_independence_bps: u64,
    pub target_cross_ring_independence_bps: u64,
    pub max_shared_decoy_overlap_bps: u64,
    pub max_position_correlation_bps: u64,
    pub min_shannon_entropy_millibits: u64,
    pub target_shannon_entropy_millibits: u64,
    pub min_min_entropy_millibits: u64,
    pub target_min_entropy_millibits: u64,
    pub min_effective_dual_decoys: u64,
    pub target_effective_dual_decoys: u64,
    pub min_age_buckets: u16,
    pub target_age_buckets: u16,
    pub min_decoy_age_diversity_bps: u64,
    pub target_decoy_age_diversity_bps: u64,
    pub max_recent_decoy_dominance_bps: u64,
    pub max_age_bucket_skew_bps: u64,
    pub min_viewtag_privacy_bps: u64,
    pub target_viewtag_privacy_bps: u64,
    pub max_viewtag_collision_bps: u64,
    pub max_stealth_note_linkage_bps: u64,
    pub min_stealth_note_rotation_bps: u64,
    pub target_stealth_note_rotation_bps: u64,
    pub min_pq_migration_safety_bps: u64,
    pub target_pq_migration_safety_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_audit_batch_outputs: u64,
    pub target_audit_batch_outputs: u64,
    pub min_sponsor_reserve_atoms: u64,
    pub audit_ttl_blocks: u64,
    pub scan_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_sponsor_rebate_bps: u64,
    pub public_bucket_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_clsag_ring_size: DEFAULT_MIN_CLSAG_RING_SIZE,
            min_seraphis_ring_size: DEFAULT_MIN_SERAPHIS_RING_SIZE,
            target_clsag_ring_size: DEFAULT_TARGET_CLSAG_RING_SIZE,
            target_seraphis_ring_size: DEFAULT_TARGET_SERAPHIS_RING_SIZE,
            min_dual_ring_entropy_bps: DEFAULT_MIN_DUAL_RING_ENTROPY_BPS,
            target_dual_ring_entropy_bps: DEFAULT_TARGET_DUAL_RING_ENTROPY_BPS,
            min_cross_ring_independence_bps: DEFAULT_MIN_CROSS_RING_INDEPENDENCE_BPS,
            target_cross_ring_independence_bps: DEFAULT_TARGET_CROSS_RING_INDEPENDENCE_BPS,
            max_shared_decoy_overlap_bps: DEFAULT_MAX_SHARED_DECOY_OVERLAP_BPS,
            max_position_correlation_bps: DEFAULT_MAX_POSITION_CORRELATION_BPS,
            min_shannon_entropy_millibits: DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS,
            target_shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_min_entropy_millibits: DEFAULT_MIN_MIN_ENTROPY_MILLIBITS,
            target_min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            min_effective_dual_decoys: DEFAULT_MIN_EFFECTIVE_DUAL_DECOYS,
            target_effective_dual_decoys: DEFAULT_TARGET_EFFECTIVE_DUAL_DECOYS,
            min_age_buckets: DEFAULT_MIN_AGE_BUCKETS,
            target_age_buckets: DEFAULT_TARGET_AGE_BUCKETS,
            min_decoy_age_diversity_bps: DEFAULT_MIN_DECOY_AGE_DIVERSITY_BPS,
            target_decoy_age_diversity_bps: DEFAULT_TARGET_DECOY_AGE_DIVERSITY_BPS,
            max_recent_decoy_dominance_bps: DEFAULT_MAX_RECENT_DECOY_DOMINANCE_BPS,
            max_age_bucket_skew_bps: DEFAULT_MAX_AGE_BUCKET_SKEW_BPS,
            min_viewtag_privacy_bps: DEFAULT_MIN_VIEWTAG_PRIVACY_BPS,
            target_viewtag_privacy_bps: DEFAULT_TARGET_VIEWTAG_PRIVACY_BPS,
            max_viewtag_collision_bps: DEFAULT_MAX_VIEWTAG_COLLISION_BPS,
            max_stealth_note_linkage_bps: DEFAULT_MAX_STEALTH_NOTE_LINKAGE_BPS,
            min_stealth_note_rotation_bps: DEFAULT_MIN_STEALTH_NOTE_ROTATION_BPS,
            target_stealth_note_rotation_bps: DEFAULT_TARGET_STEALTH_NOTE_ROTATION_BPS,
            min_pq_migration_safety_bps: DEFAULT_MIN_PQ_MIGRATION_SAFETY_BPS,
            target_pq_migration_safety_bps: DEFAULT_TARGET_PQ_MIGRATION_SAFETY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_audit_batch_outputs: DEFAULT_MIN_AUDIT_BATCH_OUTPUTS,
            target_audit_batch_outputs: DEFAULT_TARGET_AUDIT_BATCH_OUTPUTS,
            min_sponsor_reserve_atoms: DEFAULT_MIN_SPONSOR_RESERVE_ATOMS,
            audit_ttl_blocks: DEFAULT_AUDIT_TTL_BLOCKS,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_sponsor_rebate_bps: DEFAULT_TARGET_SPONSOR_REBATE_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &json!(self))
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Counters {
    pub audits: u64,
    pub dual_ring_entropy_scores: u64,
    pub decoy_age_diversity_reports: u64,
    pub viewtag_stealth_privacy_checks: u64,
    pub pq_migration_attestations: u64,
    pub fee_sponsored_audit_batches: u64,
    pub quarantined_audits: u64,
    pub sealed_audits: u64,
}

impl Counters {
    pub fn state_root(&self) -> String {
        root_from_record("counters", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Roots {
    pub dual_ring_audits_root: String,
    pub dual_ring_entropy_scores_root: String,
    pub decoy_age_diversity_reports_root: String,
    pub viewtag_stealth_privacy_checks_root: String,
    pub pq_migration_attestations_root: String,
    pub fee_sponsored_audit_batches_root: String,
    pub public_records_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            dual_ring_audits_root: empty_root(DUAL_RING_AUDIT_SCHEME),
            dual_ring_entropy_scores_root: empty_root(DUAL_RING_ENTROPY_SCHEME),
            decoy_age_diversity_reports_root: empty_root(DECOY_AGE_DIVERSITY_SCHEME),
            viewtag_stealth_privacy_checks_root: empty_root(VIEWTAG_STEALTH_PRIVACY_SCHEME),
            pq_migration_attestations_root: empty_root(PQ_MIGRATION_ATTESTATION_SCHEME),
            fee_sponsored_audit_batches_root: empty_root(FEE_SPONSORED_AUDIT_BATCH_SCHEME),
            public_records_root: empty_root(PUBLIC_RECORD_SCHEME),
        }
    }
}

impl Roots {
    pub fn state_root(&self) -> String {
        root_from_record("roots", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DualRingAuditInput {
    pub audit_id: String,
    pub lane: AuditLane,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub clsag_ring_size: u16,
    pub seraphis_ring_size: u16,
    pub output_bucket_count: u64,
    pub note_bucket_count: u64,
    pub decoy_family_count: u16,
    pub redacted_clsag_ring_root: String,
    pub redacted_seraphis_ring_root: String,
    pub redacted_dual_decoy_manifest_root: String,
    pub bridge_context_root: String,
    pub operator_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DualRingAudit {
    pub audit_id: String,
    pub lane: AuditLane,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub clsag_ring_size: u16,
    pub seraphis_ring_size: u16,
    pub output_bucket_count: u64,
    pub note_bucket_count: u64,
    pub decoy_family_count: u16,
    pub redacted_clsag_ring_root: String,
    pub redacted_seraphis_ring_root: String,
    pub redacted_dual_decoy_manifest_root: String,
    pub bridge_context_root: String,
    pub operator_policy_root: String,
    pub expires_at_monero_height: u64,
    pub status: AuditStatus,
}

impl DualRingAudit {
    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "audit_id": self.audit_id,
            "lane": self.lane.as_str(),
            "l2_height_bucket": bucket(self.l2_height, config.public_bucket_size),
            "monero_height_bucket": bucket(self.monero_height, config.public_bucket_size),
            "epoch": self.epoch,
            "clsag_ring_size": self.clsag_ring_size,
            "seraphis_ring_size": self.seraphis_ring_size,
            "output_bucket_count": self.output_bucket_count,
            "note_bucket_count": self.note_bucket_count,
            "decoy_family_count": self.decoy_family_count,
            "redacted_clsag_ring_root": self.redacted_clsag_ring_root,
            "redacted_seraphis_ring_root": self.redacted_seraphis_ring_root,
            "redacted_dual_decoy_manifest_root": self.redacted_dual_decoy_manifest_root,
            "bridge_context_root": self.bridge_context_root,
            "operator_policy_root": self.operator_policy_root,
            "expires_at_monero_height_bucket": bucket(self.expires_at_monero_height, config.public_bucket_size),
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(DUAL_RING_AUDIT_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DualRingEntropyInput {
    pub entropy_id: String,
    pub audit_id: String,
    pub ring_kind: DualRingKind,
    pub sampled_dual_rings: u64,
    pub clsag_decoys: u64,
    pub seraphis_decoys: u64,
    pub effective_dual_decoys: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub clsag_entropy_bps: u64,
    pub seraphis_entropy_bps: u64,
    pub cross_ring_independence_bps: u64,
    pub shared_decoy_overlap_bps: u64,
    pub position_correlation_bps: u64,
    pub redacted_entropy_histogram_root: String,
    pub dual_sampler_transcript_root: String,
    pub independence_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DualRingEntropyScore {
    pub entropy_id: String,
    pub audit_id: String,
    pub ring_kind: DualRingKind,
    pub sampled_dual_rings: u64,
    pub clsag_decoys: u64,
    pub seraphis_decoys: u64,
    pub effective_dual_decoys: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub clsag_entropy_bps: u64,
    pub seraphis_entropy_bps: u64,
    pub cross_ring_independence_bps: u64,
    pub shared_decoy_overlap_bps: u64,
    pub position_correlation_bps: u64,
    pub dual_ring_entropy_bps: u64,
    pub redacted_entropy_histogram_root: String,
    pub dual_sampler_transcript_root: String,
    pub independence_witness_root: String,
    pub status: AuditStatus,
}

impl DualRingEntropyScore {
    pub fn public_record(&self) -> Value {
        json!({
            "entropy_id": self.entropy_id,
            "audit_id": self.audit_id,
            "ring_kind": self.ring_kind.as_str(),
            "sampled_dual_rings": self.sampled_dual_rings,
            "clsag_decoys": self.clsag_decoys,
            "seraphis_decoys": self.seraphis_decoys,
            "effective_dual_decoys": self.effective_dual_decoys,
            "shannon_entropy_millibits": self.shannon_entropy_millibits,
            "min_entropy_millibits": self.min_entropy_millibits,
            "clsag_entropy_bps": self.clsag_entropy_bps,
            "seraphis_entropy_bps": self.seraphis_entropy_bps,
            "cross_ring_independence_bps": self.cross_ring_independence_bps,
            "shared_decoy_overlap_bps": self.shared_decoy_overlap_bps,
            "position_correlation_bps": self.position_correlation_bps,
            "dual_ring_entropy_bps": self.dual_ring_entropy_bps,
            "redacted_entropy_histogram_root": self.redacted_entropy_histogram_root,
            "dual_sampler_transcript_root": self.dual_sampler_transcript_root,
            "independence_witness_root": self.independence_witness_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(DUAL_RING_ENTROPY_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DecoyAgeDiversityInput {
    pub diversity_id: String,
    pub audit_id: String,
    pub age_band_kind: AgeBandKind,
    pub scan_window_blocks: u64,
    pub sampled_outputs: u64,
    pub age_bucket_count: u16,
    pub decoy_age_diversity_bps: u64,
    pub recent_decoy_dominance_bps: u64,
    pub age_bucket_skew_bps: u64,
    pub median_decoy_age_blocks: u64,
    pub p90_decoy_age_blocks: u64,
    pub p99_decoy_age_blocks: u64,
    pub redacted_age_histogram_root: String,
    pub age_diversity_witness_root: String,
    pub residual_linkability_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DecoyAgeDiversityReport {
    pub diversity_id: String,
    pub audit_id: String,
    pub age_band_kind: AgeBandKind,
    pub scan_window_blocks: u64,
    pub sampled_outputs: u64,
    pub age_bucket_count: u16,
    pub decoy_age_diversity_bps: u64,
    pub recent_decoy_dominance_bps: u64,
    pub age_bucket_skew_bps: u64,
    pub median_decoy_age_blocks: u64,
    pub p90_decoy_age_blocks: u64,
    pub p99_decoy_age_blocks: u64,
    pub redacted_age_histogram_root: String,
    pub age_diversity_witness_root: String,
    pub residual_linkability_root: String,
    pub status: AuditStatus,
}

impl DecoyAgeDiversityReport {
    pub fn public_record(&self) -> Value {
        json!({
            "diversity_id": self.diversity_id,
            "audit_id": self.audit_id,
            "age_band_kind": self.age_band_kind.as_str(),
            "scan_window_blocks": self.scan_window_blocks,
            "sampled_outputs": self.sampled_outputs,
            "age_bucket_count": self.age_bucket_count,
            "decoy_age_diversity_bps": self.decoy_age_diversity_bps,
            "recent_decoy_dominance_bps": self.recent_decoy_dominance_bps,
            "age_bucket_skew_bps": self.age_bucket_skew_bps,
            "median_decoy_age_blocks": self.median_decoy_age_blocks,
            "p90_decoy_age_blocks": self.p90_decoy_age_blocks,
            "p99_decoy_age_blocks": self.p99_decoy_age_blocks,
            "redacted_age_histogram_root": self.redacted_age_histogram_root,
            "age_diversity_witness_root": self.age_diversity_witness_root,
            "residual_linkability_root": self.residual_linkability_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_AGE_DIVERSITY_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewtagStealthPrivacyInput {
    pub check_id: String,
    pub audit_id: String,
    pub check_kind: ViewtagCheckKind,
    pub scanned_notes: u64,
    pub viewtag_privacy_bps: u64,
    pub viewtag_collision_bps: u64,
    pub stealth_note_linkage_bps: u64,
    pub stealth_note_rotation_bps: u64,
    pub viewkey_disclosure_budget_bps: u64,
    pub false_drop_bps: u64,
    pub redacted_viewtag_bucket_root: String,
    pub stealth_note_commitment_root: String,
    pub scan_transcript_root: String,
    pub privacy_budget_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewtagStealthPrivacyCheck {
    pub check_id: String,
    pub audit_id: String,
    pub check_kind: ViewtagCheckKind,
    pub scanned_notes: u64,
    pub viewtag_privacy_bps: u64,
    pub viewtag_collision_bps: u64,
    pub stealth_note_linkage_bps: u64,
    pub stealth_note_rotation_bps: u64,
    pub viewkey_disclosure_budget_bps: u64,
    pub false_drop_bps: u64,
    pub redacted_viewtag_bucket_root: String,
    pub stealth_note_commitment_root: String,
    pub scan_transcript_root: String,
    pub privacy_budget_root: String,
    pub status: AuditStatus,
}

impl ViewtagStealthPrivacyCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "audit_id": self.audit_id,
            "check_kind": self.check_kind,
            "scanned_notes": self.scanned_notes,
            "viewtag_privacy_bps": self.viewtag_privacy_bps,
            "viewtag_collision_bps": self.viewtag_collision_bps,
            "stealth_note_linkage_bps": self.stealth_note_linkage_bps,
            "stealth_note_rotation_bps": self.stealth_note_rotation_bps,
            "viewkey_disclosure_budget_bps": self.viewkey_disclosure_budget_bps,
            "false_drop_bps": self.false_drop_bps,
            "redacted_viewtag_bucket_root": self.redacted_viewtag_bucket_root,
            "stealth_note_commitment_root": self.stealth_note_commitment_root,
            "scan_transcript_root": self.scan_transcript_root,
            "privacy_budget_root": self.privacy_budget_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(VIEWTAG_STEALTH_PRIVACY_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PqMigrationAttestationInput {
    pub attestation_id: String,
    pub audit_id: String,
    pub attestation_kind: PqAttestationKind,
    pub migration_epoch: u64,
    pub pq_security_bits: u16,
    pub pq_migration_safety_bps: u64,
    pub classical_fallback_disabled: bool,
    pub hybrid_binding_complete: bool,
    pub key_image_nullifier_guard_bps: u64,
    pub transcript_retention_blocks: u64,
    pub clsag_to_seraphis_binding_root: String,
    pub pq_signature_attestation_root: String,
    pub pq_key_ceremony_root: String,
    pub rollback_guard_root: String,
    pub migration_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PqMigrationAttestation {
    pub attestation_id: String,
    pub audit_id: String,
    pub attestation_kind: PqAttestationKind,
    pub migration_epoch: u64,
    pub pq_security_bits: u16,
    pub pq_migration_safety_bps: u64,
    pub classical_fallback_disabled: bool,
    pub hybrid_binding_complete: bool,
    pub key_image_nullifier_guard_bps: u64,
    pub transcript_retention_blocks: u64,
    pub clsag_to_seraphis_binding_root: String,
    pub pq_signature_attestation_root: String,
    pub pq_key_ceremony_root: String,
    pub rollback_guard_root: String,
    pub migration_policy_root: String,
    pub status: AuditStatus,
}

impl PqMigrationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "audit_id": self.audit_id,
            "attestation_kind": self.attestation_kind,
            "migration_epoch": self.migration_epoch,
            "pq_security_bits": self.pq_security_bits,
            "pq_migration_safety_bps": self.pq_migration_safety_bps,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "hybrid_binding_complete": self.hybrid_binding_complete,
            "key_image_nullifier_guard_bps": self.key_image_nullifier_guard_bps,
            "transcript_retention_blocks": self.transcript_retention_blocks,
            "clsag_to_seraphis_binding_root": self.clsag_to_seraphis_binding_root,
            "pq_signature_attestation_root": self.pq_signature_attestation_root,
            "pq_key_ceremony_root": self.pq_key_ceremony_root,
            "rollback_guard_root": self.rollback_guard_root,
            "migration_policy_root": self.migration_policy_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_ATTESTATION_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeeSponsoredAuditBatchInput {
    pub batch_id: String,
    pub audit_id: String,
    pub entropy_id: String,
    pub diversity_id: String,
    pub check_id: String,
    pub attestation_id: String,
    pub sponsor_policy: SponsorPolicy,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub audit_count: u64,
    pub user_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub sponsor_reserve_atoms: u64,
    pub batched_audit_root: String,
    pub sponsor_receipt_root: String,
    pub low_fee_privacy_budget_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeeSponsoredAuditBatch {
    pub batch_id: String,
    pub audit_id: String,
    pub entropy_id: String,
    pub diversity_id: String,
    pub check_id: String,
    pub attestation_id: String,
    pub sponsor_policy: SponsorPolicy,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub audit_count: u64,
    pub user_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub sponsor_reserve_atoms: u64,
    pub batched_audit_root: String,
    pub sponsor_receipt_root: String,
    pub low_fee_privacy_budget_root: String,
    pub status: AuditStatus,
}

impl FeeSponsoredAuditBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "audit_id": self.audit_id,
            "entropy_id": self.entropy_id,
            "diversity_id": self.diversity_id,
            "check_id": self.check_id,
            "attestation_id": self.attestation_id,
            "sponsor_policy": self.sponsor_policy,
            "fee_asset_id": self.fee_asset_id,
            "batch_outputs": self.batch_outputs,
            "audit_count": self.audit_count,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "sponsor_reserve_atoms": self.sponsor_reserve_atoms,
            "batched_audit_root": self.batched_audit_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "low_fee_privacy_budget_root": self.low_fee_privacy_budget_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(FEE_SPONSORED_AUDIT_BATCH_SCHEME, &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub dual_ring_audits: BTreeMap<String, DualRingAudit>,
    pub dual_ring_entropy_scores: BTreeMap<String, DualRingEntropyScore>,
    pub decoy_age_diversity_reports: BTreeMap<String, DecoyAgeDiversityReport>,
    pub viewtag_stealth_privacy_checks: BTreeMap<String, ViewtagStealthPrivacyCheck>,
    pub pq_migration_attestations: BTreeMap<String, PqMigrationAttestation>,
    pub fee_sponsored_audit_batches: BTreeMap<String, FeeSponsoredAuditBatch>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            config,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            counters: Counters::default(),
            roots: Roots::default(),
            dual_ring_audits: BTreeMap::new(),
            dual_ring_entropy_scores: BTreeMap::new(),
            decoy_age_diversity_reports: BTreeMap::new(),
            viewtag_stealth_privacy_checks: BTreeMap::new(),
            pq_migration_attestations: BTreeMap::new(),
            fee_sponsored_audit_batches: BTreeMap::new(),
        }
    }

    pub fn insert_dual_ring_audit(&mut self, input: DualRingAuditInput) -> Result<()> {
        ensure(
            !self.dual_ring_audits.contains_key(&input.audit_id),
            "dual ring audit already exists",
        )?;
        ensure(
            input.clsag_ring_size >= self.config.min_clsag_ring_size,
            "CLSAG ring below minimum",
        )?;
        ensure(
            input.seraphis_ring_size >= self.config.min_seraphis_ring_size,
            "Seraphis ring below minimum",
        )?;
        ensure(
            input.output_bucket_count > 0,
            "output bucket count must be nonzero",
        )?;
        ensure(
            input.note_bucket_count > 0,
            "note bucket count must be nonzero",
        )?;
        ensure(
            input.decoy_family_count > 0,
            "decoy family count must be nonzero",
        )?;
        ensure_root(&input.redacted_clsag_ring_root, "redacted CLSAG ring root")?;
        ensure_root(
            &input.redacted_seraphis_ring_root,
            "redacted Seraphis ring root",
        )?;
        ensure_root(
            &input.redacted_dual_decoy_manifest_root,
            "dual decoy manifest root",
        )?;
        ensure_root(&input.bridge_context_root, "bridge context root")?;
        ensure_root(&input.operator_policy_root, "operator policy root")?;
        let audit = DualRingAudit {
            audit_id: input.audit_id.clone(),
            lane: input.lane,
            l2_height: input.l2_height,
            monero_height: input.monero_height,
            epoch: input.epoch,
            clsag_ring_size: input.clsag_ring_size,
            seraphis_ring_size: input.seraphis_ring_size,
            output_bucket_count: input.output_bucket_count,
            note_bucket_count: input.note_bucket_count,
            decoy_family_count: input.decoy_family_count,
            redacted_clsag_ring_root: input.redacted_clsag_ring_root,
            redacted_seraphis_ring_root: input.redacted_seraphis_ring_root,
            redacted_dual_decoy_manifest_root: input.redacted_dual_decoy_manifest_root,
            bridge_context_root: input.bridge_context_root,
            operator_policy_root: input.operator_policy_root,
            expires_at_monero_height: input.monero_height + self.config.audit_ttl_blocks,
            status: AuditStatus::Observed,
        };
        self.l2_height = self.l2_height.max(audit.l2_height);
        self.monero_height = self.monero_height.max(audit.monero_height);
        self.epoch = self.epoch.max(audit.epoch);
        self.dual_ring_audits.insert(input.audit_id, audit);
        self.counters.audits = self.dual_ring_audits.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_dual_ring_entropy_score(&mut self, input: DualRingEntropyInput) -> Result<()> {
        ensure(
            self.dual_ring_audits.contains_key(&input.audit_id),
            "unknown audit for entropy score",
        )?;
        ensure(
            !self
                .dual_ring_entropy_scores
                .contains_key(&input.entropy_id),
            "dual ring entropy score already exists",
        )?;
        ensure(
            input.sampled_dual_rings > 0,
            "sampled dual rings must be nonzero",
        )?;
        ensure(
            input.effective_dual_decoys >= self.config.min_effective_dual_decoys,
            "effective dual decoys below floor",
        )?;
        ensure(
            input.shannon_entropy_millibits >= self.config.min_shannon_entropy_millibits,
            "Shannon entropy below floor",
        )?;
        ensure(
            input.min_entropy_millibits >= self.config.min_min_entropy_millibits,
            "min entropy below floor",
        )?;
        ensure(
            input.clsag_entropy_bps <= MAX_BPS,
            "CLSAG entropy score above max",
        )?;
        ensure(
            input.seraphis_entropy_bps <= MAX_BPS,
            "Seraphis entropy score above max",
        )?;
        ensure(
            input.cross_ring_independence_bps >= self.config.min_cross_ring_independence_bps,
            "cross ring independence below floor",
        )?;
        ensure(
            input.shared_decoy_overlap_bps <= self.config.max_shared_decoy_overlap_bps,
            "shared decoy overlap too high",
        )?;
        ensure(
            input.position_correlation_bps <= self.config.max_position_correlation_bps,
            "ring position correlation too high",
        )?;
        ensure_root(
            &input.redacted_entropy_histogram_root,
            "redacted entropy histogram root",
        )?;
        ensure_root(
            &input.dual_sampler_transcript_root,
            "dual sampler transcript root",
        )?;
        ensure_root(
            &input.independence_witness_root,
            "independence witness root",
        )?;
        let dual_ring_entropy_bps = dual_ring_entropy_bps(
            input.clsag_entropy_bps,
            input.seraphis_entropy_bps,
            input.cross_ring_independence_bps,
            input.shared_decoy_overlap_bps,
            input.position_correlation_bps,
        );
        ensure(
            dual_ring_entropy_bps >= self.config.min_dual_ring_entropy_bps,
            "dual ring entropy score below floor",
        )?;
        let score = DualRingEntropyScore {
            entropy_id: input.entropy_id.clone(),
            audit_id: input.audit_id,
            ring_kind: input.ring_kind,
            sampled_dual_rings: input.sampled_dual_rings,
            clsag_decoys: input.clsag_decoys,
            seraphis_decoys: input.seraphis_decoys,
            effective_dual_decoys: input.effective_dual_decoys,
            shannon_entropy_millibits: input.shannon_entropy_millibits,
            min_entropy_millibits: input.min_entropy_millibits,
            clsag_entropy_bps: input.clsag_entropy_bps,
            seraphis_entropy_bps: input.seraphis_entropy_bps,
            cross_ring_independence_bps: input.cross_ring_independence_bps,
            shared_decoy_overlap_bps: input.shared_decoy_overlap_bps,
            position_correlation_bps: input.position_correlation_bps,
            dual_ring_entropy_bps,
            redacted_entropy_histogram_root: input.redacted_entropy_histogram_root,
            dual_sampler_transcript_root: input.dual_sampler_transcript_root,
            independence_witness_root: input.independence_witness_root,
            status: AuditStatus::DualEntropyScored,
        };
        self.dual_ring_entropy_scores
            .insert(input.entropy_id, score);
        self.counters.dual_ring_entropy_scores = self.dual_ring_entropy_scores.len() as u64;
        self.refresh_audit_statuses();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_age_diversity_report(
        &mut self,
        input: DecoyAgeDiversityInput,
    ) -> Result<()> {
        ensure(
            self.dual_ring_audits.contains_key(&input.audit_id),
            "unknown audit for decoy age report",
        )?;
        ensure(
            !self
                .decoy_age_diversity_reports
                .contains_key(&input.diversity_id),
            "decoy age diversity report already exists",
        )?;
        ensure(
            input.scan_window_blocks >= self.config.scan_window_blocks / 4,
            "scan window too narrow",
        )?;
        ensure(input.sampled_outputs > 0, "sampled outputs must be nonzero")?;
        ensure(
            input.age_bucket_count >= self.config.min_age_buckets,
            "age bucket count below floor",
        )?;
        ensure(
            input.decoy_age_diversity_bps >= self.config.min_decoy_age_diversity_bps,
            "decoy age diversity below floor",
        )?;
        ensure(
            input.recent_decoy_dominance_bps <= self.config.max_recent_decoy_dominance_bps,
            "recent decoy dominance too high",
        )?;
        ensure(
            input.age_bucket_skew_bps <= self.config.max_age_bucket_skew_bps,
            "age bucket skew too high",
        )?;
        ensure(
            input.p99_decoy_age_blocks >= input.p90_decoy_age_blocks,
            "p99 age below p90",
        )?;
        ensure(
            input.p90_decoy_age_blocks >= input.median_decoy_age_blocks,
            "p90 age below median",
        )?;
        ensure_root(
            &input.redacted_age_histogram_root,
            "redacted age histogram root",
        )?;
        ensure_root(
            &input.age_diversity_witness_root,
            "age diversity witness root",
        )?;
        ensure_root(
            &input.residual_linkability_root,
            "residual linkability root",
        )?;
        let report = DecoyAgeDiversityReport {
            diversity_id: input.diversity_id.clone(),
            audit_id: input.audit_id,
            age_band_kind: input.age_band_kind,
            scan_window_blocks: input.scan_window_blocks,
            sampled_outputs: input.sampled_outputs,
            age_bucket_count: input.age_bucket_count,
            decoy_age_diversity_bps: input.decoy_age_diversity_bps,
            recent_decoy_dominance_bps: input.recent_decoy_dominance_bps,
            age_bucket_skew_bps: input.age_bucket_skew_bps,
            median_decoy_age_blocks: input.median_decoy_age_blocks,
            p90_decoy_age_blocks: input.p90_decoy_age_blocks,
            p99_decoy_age_blocks: input.p99_decoy_age_blocks,
            redacted_age_histogram_root: input.redacted_age_histogram_root,
            age_diversity_witness_root: input.age_diversity_witness_root,
            residual_linkability_root: input.residual_linkability_root,
            status: AuditStatus::AgeDiversityScored,
        };
        self.decoy_age_diversity_reports
            .insert(input.diversity_id, report);
        self.counters.decoy_age_diversity_reports = self.decoy_age_diversity_reports.len() as u64;
        self.refresh_audit_statuses();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_viewtag_stealth_privacy_check(
        &mut self,
        input: ViewtagStealthPrivacyInput,
    ) -> Result<()> {
        ensure(
            self.dual_ring_audits.contains_key(&input.audit_id),
            "unknown audit for viewtag stealth check",
        )?;
        ensure(
            !self
                .viewtag_stealth_privacy_checks
                .contains_key(&input.check_id),
            "viewtag stealth privacy check already exists",
        )?;
        ensure(input.scanned_notes > 0, "scanned notes must be nonzero")?;
        ensure(
            input.viewtag_privacy_bps >= self.config.min_viewtag_privacy_bps,
            "viewtag privacy below floor",
        )?;
        ensure(
            input.viewtag_collision_bps <= self.config.max_viewtag_collision_bps,
            "viewtag collision rate too high",
        )?;
        ensure(
            input.stealth_note_linkage_bps <= self.config.max_stealth_note_linkage_bps,
            "stealth note linkage too high",
        )?;
        ensure(
            input.stealth_note_rotation_bps >= self.config.min_stealth_note_rotation_bps,
            "stealth note rotation below floor",
        )?;
        ensure(
            input.viewkey_disclosure_budget_bps <= MAX_BPS,
            "viewkey disclosure budget above max",
        )?;
        ensure(
            input.false_drop_bps <= self.config.max_viewtag_collision_bps,
            "viewtag false drops too high",
        )?;
        ensure_root(
            &input.redacted_viewtag_bucket_root,
            "redacted viewtag bucket root",
        )?;
        ensure_root(
            &input.stealth_note_commitment_root,
            "stealth note commitment root",
        )?;
        ensure_root(&input.scan_transcript_root, "scan transcript root")?;
        ensure_root(&input.privacy_budget_root, "privacy budget root")?;
        let check = ViewtagStealthPrivacyCheck {
            check_id: input.check_id.clone(),
            audit_id: input.audit_id,
            check_kind: input.check_kind,
            scanned_notes: input.scanned_notes,
            viewtag_privacy_bps: input.viewtag_privacy_bps,
            viewtag_collision_bps: input.viewtag_collision_bps,
            stealth_note_linkage_bps: input.stealth_note_linkage_bps,
            stealth_note_rotation_bps: input.stealth_note_rotation_bps,
            viewkey_disclosure_budget_bps: input.viewkey_disclosure_budget_bps,
            false_drop_bps: input.false_drop_bps,
            redacted_viewtag_bucket_root: input.redacted_viewtag_bucket_root,
            stealth_note_commitment_root: input.stealth_note_commitment_root,
            scan_transcript_root: input.scan_transcript_root,
            privacy_budget_root: input.privacy_budget_root,
            status: AuditStatus::ViewtagStealthChecked,
        };
        self.viewtag_stealth_privacy_checks
            .insert(input.check_id, check);
        self.counters.viewtag_stealth_privacy_checks =
            self.viewtag_stealth_privacy_checks.len() as u64;
        self.refresh_audit_statuses();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_attestation(
        &mut self,
        input: PqMigrationAttestationInput,
    ) -> Result<()> {
        ensure(
            self.dual_ring_audits.contains_key(&input.audit_id),
            "unknown audit for PQ migration attestation",
        )?;
        ensure(
            !self
                .pq_migration_attestations
                .contains_key(&input.attestation_id),
            "PQ migration attestation already exists",
        )?;
        ensure(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ security bits below floor",
        )?;
        ensure(
            input.pq_migration_safety_bps >= self.config.min_pq_migration_safety_bps,
            "PQ migration safety below floor",
        )?;
        ensure(
            input.classical_fallback_disabled,
            "classical fallback must be disabled",
        )?;
        ensure(
            input.hybrid_binding_complete,
            "hybrid CLSAG/Seraphis binding incomplete",
        )?;
        ensure(
            input.key_image_nullifier_guard_bps >= self.config.min_pq_migration_safety_bps,
            "key image nullifier guard below floor",
        )?;
        ensure(
            input.transcript_retention_blocks >= self.config.audit_ttl_blocks,
            "transcript retention shorter than audit TTL",
        )?;
        ensure_root(
            &input.clsag_to_seraphis_binding_root,
            "CLSAG to Seraphis binding root",
        )?;
        ensure_root(
            &input.pq_signature_attestation_root,
            "PQ signature attestation root",
        )?;
        ensure_root(&input.pq_key_ceremony_root, "PQ key ceremony root")?;
        ensure_root(&input.rollback_guard_root, "rollback guard root")?;
        ensure_root(&input.migration_policy_root, "migration policy root")?;
        let attestation = PqMigrationAttestation {
            attestation_id: input.attestation_id.clone(),
            audit_id: input.audit_id,
            attestation_kind: input.attestation_kind,
            migration_epoch: input.migration_epoch,
            pq_security_bits: input.pq_security_bits,
            pq_migration_safety_bps: input.pq_migration_safety_bps,
            classical_fallback_disabled: input.classical_fallback_disabled,
            hybrid_binding_complete: input.hybrid_binding_complete,
            key_image_nullifier_guard_bps: input.key_image_nullifier_guard_bps,
            transcript_retention_blocks: input.transcript_retention_blocks,
            clsag_to_seraphis_binding_root: input.clsag_to_seraphis_binding_root,
            pq_signature_attestation_root: input.pq_signature_attestation_root,
            pq_key_ceremony_root: input.pq_key_ceremony_root,
            rollback_guard_root: input.rollback_guard_root,
            migration_policy_root: input.migration_policy_root,
            status: AuditStatus::PqAttested,
        };
        self.pq_migration_attestations
            .insert(input.attestation_id, attestation);
        self.counters.pq_migration_attestations = self.pq_migration_attestations.len() as u64;
        self.refresh_audit_statuses();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_fee_sponsored_audit_batch(
        &mut self,
        input: FeeSponsoredAuditBatchInput,
    ) -> Result<()> {
        ensure(
            self.dual_ring_audits.contains_key(&input.audit_id),
            "unknown audit for fee sponsored batch",
        )?;
        ensure(
            self.dual_ring_entropy_scores
                .contains_key(&input.entropy_id),
            "unknown entropy score for fee sponsored batch",
        )?;
        ensure(
            self.decoy_age_diversity_reports
                .contains_key(&input.diversity_id),
            "unknown age diversity report for fee sponsored batch",
        )?;
        ensure(
            self.viewtag_stealth_privacy_checks
                .contains_key(&input.check_id),
            "unknown viewtag stealth check for fee sponsored batch",
        )?;
        ensure(
            self.pq_migration_attestations
                .contains_key(&input.attestation_id),
            "unknown PQ attestation for fee sponsored batch",
        )?;
        ensure(
            !self
                .fee_sponsored_audit_batches
                .contains_key(&input.batch_id),
            "fee sponsored audit batch already exists",
        )?;
        ensure(
            input.fee_asset_id == self.config.fee_asset_id,
            "unexpected fee asset",
        )?;
        ensure(
            input.batch_outputs >= self.config.min_audit_batch_outputs,
            "audit batch output count below floor",
        )?;
        ensure(input.audit_count > 0, "audit count must be nonzero")?;
        ensure(
            input.user_fee_bps <= self.config.max_user_fee_bps,
            "user fee above low-fee cap",
        )?;
        ensure(
            input.sponsor_rebate_bps >= self.config.target_sponsor_rebate_bps,
            "sponsor rebate below target",
        )?;
        ensure(
            input.sponsor_reserve_atoms >= self.config.min_sponsor_reserve_atoms,
            "sponsor reserve below minimum",
        )?;
        ensure_root(&input.batched_audit_root, "batched audit root")?;
        ensure_root(&input.sponsor_receipt_root, "sponsor receipt root")?;
        ensure_root(
            &input.low_fee_privacy_budget_root,
            "low fee privacy budget root",
        )?;
        let batch = FeeSponsoredAuditBatch {
            batch_id: input.batch_id.clone(),
            audit_id: input.audit_id,
            entropy_id: input.entropy_id,
            diversity_id: input.diversity_id,
            check_id: input.check_id,
            attestation_id: input.attestation_id,
            sponsor_policy: input.sponsor_policy,
            fee_asset_id: input.fee_asset_id,
            batch_outputs: input.batch_outputs,
            audit_count: input.audit_count,
            user_fee_bps: input.user_fee_bps,
            sponsor_rebate_bps: input.sponsor_rebate_bps,
            sponsor_reserve_atoms: input.sponsor_reserve_atoms,
            batched_audit_root: input.batched_audit_root,
            sponsor_receipt_root: input.sponsor_receipt_root,
            low_fee_privacy_budget_root: input.low_fee_privacy_budget_root,
            status: AuditStatus::BatchEligible,
        };
        self.fee_sponsored_audit_batches
            .insert(input.batch_id, batch);
        self.counters.fee_sponsored_audit_batches = self.fee_sponsored_audit_batches.len() as u64;
        self.refresh_audit_statuses();
        self.refresh_roots();
        Ok(())
    }

    pub fn seal_audit(&mut self, audit_id: &str) -> Result<()> {
        ensure(
            self.audit_has_complete_surface(audit_id),
            "audit cannot be sealed before entropy, age, viewtag, PQ, and batch records exist",
        )?;
        let audit = self
            .dual_ring_audits
            .get_mut(audit_id)
            .ok_or_else(|| "unknown audit to seal".to_string())?;
        audit.status = AuditStatus::Sealed;
        self.counters.sealed_audits = self
            .dual_ring_audits
            .values()
            .filter(|audit| audit.status == AuditStatus::Sealed)
            .count() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_audit(&mut self, audit_id: &str) -> Result<()> {
        let audit = self
            .dual_ring_audits
            .get_mut(audit_id)
            .ok_or_else(|| "unknown audit to quarantine".to_string())?;
        audit.status = AuditStatus::Quarantined;
        self.counters.quarantined_audits = self
            .dual_ring_audits
            .values()
            .filter(|audit| audit.status == AuditStatus::Quarantined)
            .count() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_stale_audits(&mut self, monero_height: u64) -> u64 {
        let mut expired = 0;
        for audit in self.dual_ring_audits.values_mut() {
            if audit.status.public_usable()
                && audit.status != AuditStatus::Sealed
                && audit.expires_at_monero_height <= monero_height
            {
                audit.status = AuditStatus::Expired;
                expired += 1;
            }
        }
        if expired > 0 {
            self.monero_height = self.monero_height.max(monero_height);
            self.refresh_roots();
        }
        expired
    }

    pub fn audit_has_complete_surface(&self, audit_id: &str) -> bool {
        self.dual_ring_entropy_scores
            .values()
            .any(|score| score.audit_id == audit_id)
            && self
                .decoy_age_diversity_reports
                .values()
                .any(|report| report.audit_id == audit_id)
            && self
                .viewtag_stealth_privacy_checks
                .values()
                .any(|check| check.audit_id == audit_id)
            && self
                .pq_migration_attestations
                .values()
                .any(|attestation| attestation.audit_id == audit_id)
            && self
                .fee_sponsored_audit_batches
                .values()
                .any(|batch| batch.audit_id == audit_id)
    }

    pub fn aggregate_dual_ring_entropy_bps(&self) -> u64 {
        weighted_average_bps(
            self.dual_ring_entropy_scores
                .values()
                .map(|score| (score.dual_ring_entropy_bps, score.sampled_dual_rings)),
        )
    }

    pub fn aggregate_age_diversity_bps(&self) -> u64 {
        weighted_average_bps(
            self.decoy_age_diversity_reports
                .values()
                .map(|report| (report.decoy_age_diversity_bps, report.sampled_outputs)),
        )
    }

    pub fn aggregate_viewtag_privacy_bps(&self) -> u64 {
        weighted_average_bps(
            self.viewtag_stealth_privacy_checks
                .values()
                .map(|check| (check.viewtag_privacy_bps, check.scanned_notes)),
        )
    }

    pub fn aggregate_pq_safety_bps(&self) -> u64 {
        weighted_average_bps(
            self.pq_migration_attestations
                .values()
                .map(|attestation| (attestation.pq_migration_safety_bps, 1)),
        )
    }

    pub fn low_fee_coverage_outputs(&self) -> u64 {
        self.fee_sponsored_audit_batches
            .values()
            .map(|batch| batch.batch_outputs)
            .sum()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.dual_ring_audits_root = map_root(
            DUAL_RING_AUDIT_SCHEME,
            self.dual_ring_audits
                .iter()
                .map(|(id, audit)| (id.as_str(), audit.state_root())),
        );
        self.roots.dual_ring_entropy_scores_root = map_root(
            DUAL_RING_ENTROPY_SCHEME,
            self.dual_ring_entropy_scores
                .iter()
                .map(|(id, score)| (id.as_str(), score.state_root())),
        );
        self.roots.decoy_age_diversity_reports_root = map_root(
            DECOY_AGE_DIVERSITY_SCHEME,
            self.decoy_age_diversity_reports
                .iter()
                .map(|(id, report)| (id.as_str(), report.state_root())),
        );
        self.roots.viewtag_stealth_privacy_checks_root = map_root(
            VIEWTAG_STEALTH_PRIVACY_SCHEME,
            self.viewtag_stealth_privacy_checks
                .iter()
                .map(|(id, check)| (id.as_str(), check.state_root())),
        );
        self.roots.pq_migration_attestations_root = map_root(
            PQ_MIGRATION_ATTESTATION_SCHEME,
            self.pq_migration_attestations
                .iter()
                .map(|(id, attestation)| (id.as_str(), attestation.state_root())),
        );
        self.roots.fee_sponsored_audit_batches_root = map_root(
            FEE_SPONSORED_AUDIT_BATCH_SCHEME,
            self.fee_sponsored_audit_batches
                .iter()
                .map(|(id, batch)| (id.as_str(), batch.state_root())),
        );
        self.roots.public_records_root = root_from_record(
            PUBLIC_RECORD_SCHEME,
            &self.public_record_without_record_root(),
        );
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::U64(self.schema_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.state_root()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_record_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "public_records_root".to_string(),
                Value::String(self.roots.public_records_root.clone()),
            );
        }
        record
    }

    fn public_record_without_record_root(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": HASH_SUITE,
            "chain_id": self.chain_id,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "l2_height_bucket": bucket(self.l2_height, self.config.public_bucket_size),
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "epoch": self.epoch,
            "counters": self.counters,
            "roots": {
                "dual_ring_audits_root": self.roots.dual_ring_audits_root,
                "dual_ring_entropy_scores_root": self.roots.dual_ring_entropy_scores_root,
                "decoy_age_diversity_reports_root": self.roots.decoy_age_diversity_reports_root,
                "viewtag_stealth_privacy_checks_root": self.roots.viewtag_stealth_privacy_checks_root,
                "pq_migration_attestations_root": self.roots.pq_migration_attestations_root,
                "fee_sponsored_audit_batches_root": self.roots.fee_sponsored_audit_batches_root,
            },
            "aggregate_scores": {
                "dual_ring_entropy_bps": self.aggregate_dual_ring_entropy_bps(),
                "decoy_age_diversity_bps": self.aggregate_age_diversity_bps(),
                "viewtag_privacy_bps": self.aggregate_viewtag_privacy_bps(),
                "pq_migration_safety_bps": self.aggregate_pq_safety_bps(),
                "low_fee_coverage_outputs": self.low_fee_coverage_outputs(),
            },
            "public_audits": self.dual_ring_audits.values().filter(|audit| audit.status.public_usable()).map(|audit| audit.public_record(&self.config)).collect::<Vec<_>>(),
            "public_dual_ring_entropy_scores": self.dual_ring_entropy_scores.values().filter(|score| score.status.public_usable()).map(DualRingEntropyScore::public_record).collect::<Vec<_>>(),
            "public_decoy_age_diversity_reports": self.decoy_age_diversity_reports.values().filter(|report| report.status.public_usable()).map(DecoyAgeDiversityReport::public_record).collect::<Vec<_>>(),
            "public_viewtag_stealth_privacy_checks": self.viewtag_stealth_privacy_checks.values().filter(|check| check.status.public_usable()).map(ViewtagStealthPrivacyCheck::public_record).collect::<Vec<_>>(),
            "public_pq_migration_attestations": self.pq_migration_attestations.values().filter(|attestation| attestation.status.public_usable()).map(PqMigrationAttestation::public_record).collect::<Vec<_>>(),
            "public_fee_sponsored_audit_batches": self.fee_sponsored_audit_batches.values().filter(|batch| batch.status.public_usable()).map(FeeSponsoredAuditBatch::public_record).collect::<Vec<_>>(),
            "state_root": self.state_root(),
        })
    }

    fn refresh_audit_statuses(&mut self) {
        let ids = self.dual_ring_audits.keys().cloned().collect::<Vec<_>>();
        for audit_id in ids {
            let next = if self
                .fee_sponsored_audit_batches
                .values()
                .any(|batch| batch.audit_id == audit_id)
            {
                Some(AuditStatus::BatchEligible)
            } else if self
                .pq_migration_attestations
                .values()
                .any(|attestation| attestation.audit_id == audit_id)
            {
                Some(AuditStatus::PqAttested)
            } else if self
                .viewtag_stealth_privacy_checks
                .values()
                .any(|check| check.audit_id == audit_id)
            {
                Some(AuditStatus::ViewtagStealthChecked)
            } else if self
                .decoy_age_diversity_reports
                .values()
                .any(|report| report.audit_id == audit_id)
            {
                Some(AuditStatus::AgeDiversityScored)
            } else if self
                .dual_ring_entropy_scores
                .values()
                .any(|score| score.audit_id == audit_id)
            {
                Some(AuditStatus::DualEntropyScored)
            } else {
                None
            };
            if let (Some(status), Some(audit)) = (next, self.dual_ring_audits.get_mut(&audit_id)) {
                if audit.status.public_usable() && audit.status != AuditStatus::Sealed {
                    audit.status = status;
                }
            }
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet());
    let audit_id = "seraphis-clsag-dual-decoy-audit-devnet-0".to_string();
    let entropy_id = "seraphis-clsag-dual-ring-entropy-devnet-0".to_string();
    let diversity_id = "seraphis-clsag-decoy-age-diversity-devnet-0".to_string();
    let check_id = "seraphis-clsag-viewtag-stealth-check-devnet-0".to_string();
    let attestation_id = "seraphis-clsag-pq-migration-attestation-devnet-0".to_string();

    state
        .insert_dual_ring_audit(DualRingAuditInput {
            audit_id: audit_id.clone(),
            lane: AuditLane::BridgeDepositScan,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            clsag_ring_size: DEFAULT_TARGET_CLSAG_RING_SIZE,
            seraphis_ring_size: DEFAULT_TARGET_SERAPHIS_RING_SIZE,
            output_bucket_count: 16_384,
            note_bucket_count: 32_768,
            decoy_family_count: 48,
            redacted_clsag_ring_root: root_from_parts(
                "devnet-redacted-clsag-ring",
                &[HashPart::Str(&audit_id)],
            ),
            redacted_seraphis_ring_root: root_from_parts(
                "devnet-redacted-seraphis-ring",
                &[HashPart::Str(&audit_id)],
            ),
            redacted_dual_decoy_manifest_root: root_from_parts(
                "devnet-redacted-dual-decoy-manifest",
                &[HashPart::Str(&audit_id)],
            ),
            bridge_context_root: root_from_parts(
                "devnet-dual-decoy-bridge-context",
                &[HashPart::Str(&audit_id)],
            ),
            operator_policy_root: root_from_parts(
                "devnet-dual-decoy-operator-policy",
                &[HashPart::Str(&audit_id)],
            ),
        })
        .expect("devnet dual ring audit inserts");

    state
        .insert_dual_ring_entropy_score(DualRingEntropyInput {
            entropy_id: entropy_id.clone(),
            audit_id: audit_id.clone(),
            ring_kind: DualRingKind::BridgeIngressDualRing,
            sampled_dual_rings: 8_192,
            clsag_decoys: 8_192 * DEFAULT_TARGET_CLSAG_RING_SIZE as u64,
            seraphis_decoys: 8_192 * DEFAULT_TARGET_SERAPHIS_RING_SIZE as u64,
            effective_dual_decoys: DEFAULT_TARGET_EFFECTIVE_DUAL_DECOYS,
            shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            clsag_entropy_bps: 9_820,
            seraphis_entropy_bps: 9_870,
            cross_ring_independence_bps: DEFAULT_TARGET_CROSS_RING_INDEPENDENCE_BPS,
            shared_decoy_overlap_bps: 24,
            position_correlation_bps: 36,
            redacted_entropy_histogram_root: root_from_parts(
                "devnet-dual-ring-redacted-entropy-histogram",
                &[HashPart::Str(&entropy_id)],
            ),
            dual_sampler_transcript_root: root_from_parts(
                "devnet-dual-ring-sampler-transcript",
                &[HashPart::Str(&entropy_id)],
            ),
            independence_witness_root: root_from_parts(
                "devnet-dual-ring-independence-witness",
                &[HashPart::Str(&entropy_id)],
            ),
        })
        .expect("devnet dual ring entropy inserts");

    state
        .insert_decoy_age_diversity_report(DecoyAgeDiversityInput {
            diversity_id: diversity_id.clone(),
            audit_id: audit_id.clone(),
            age_band_kind: AgeBandKind::BridgeLiquidity,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            sampled_outputs: 65_536,
            age_bucket_count: DEFAULT_TARGET_AGE_BUCKETS,
            decoy_age_diversity_bps: DEFAULT_TARGET_DECOY_AGE_DIVERSITY_BPS,
            recent_decoy_dominance_bps: 900,
            age_bucket_skew_bps: 180,
            median_decoy_age_blocks: 74_000,
            p90_decoy_age_blocks: 410_000,
            p99_decoy_age_blocks: 1_120_000,
            redacted_age_histogram_root: root_from_parts(
                "devnet-dual-decoy-age-histogram",
                &[HashPart::Str(&diversity_id)],
            ),
            age_diversity_witness_root: root_from_parts(
                "devnet-dual-decoy-age-witness",
                &[HashPart::Str(&diversity_id)],
            ),
            residual_linkability_root: root_from_parts(
                "devnet-dual-decoy-age-residual-linkability",
                &[HashPart::Str(&diversity_id)],
            ),
        })
        .expect("devnet decoy age diversity inserts");

    state
        .insert_viewtag_stealth_privacy_check(ViewtagStealthPrivacyInput {
            check_id: check_id.clone(),
            audit_id: audit_id.clone(),
            check_kind: ViewtagCheckKind::StealthNoteRotation,
            scanned_notes: 98_304,
            viewtag_privacy_bps: DEFAULT_TARGET_VIEWTAG_PRIVACY_BPS,
            viewtag_collision_bps: 4,
            stealth_note_linkage_bps: 7,
            stealth_note_rotation_bps: DEFAULT_TARGET_STEALTH_NOTE_ROTATION_BPS,
            viewkey_disclosure_budget_bps: 35,
            false_drop_bps: 3,
            redacted_viewtag_bucket_root: root_from_parts(
                "devnet-redacted-viewtag-bucket",
                &[HashPart::Str(&check_id)],
            ),
            stealth_note_commitment_root: root_from_parts(
                "devnet-stealth-note-commitment",
                &[HashPart::Str(&check_id)],
            ),
            scan_transcript_root: root_from_parts(
                "devnet-viewtag-stealth-scan-transcript",
                &[HashPart::Str(&check_id)],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-viewtag-stealth-privacy-budget",
                &[HashPart::Str(&check_id)],
            ),
        })
        .expect("devnet viewtag stealth privacy inserts");

    state
        .insert_pq_migration_attestation(PqMigrationAttestationInput {
            attestation_id: attestation_id.clone(),
            audit_id: audit_id.clone(),
            attestation_kind: PqAttestationKind::HybridClsagBinding,
            migration_epoch: DEVNET_EPOCH,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_migration_safety_bps: DEFAULT_TARGET_PQ_MIGRATION_SAFETY_BPS,
            classical_fallback_disabled: true,
            hybrid_binding_complete: true,
            key_image_nullifier_guard_bps: DEFAULT_TARGET_PQ_MIGRATION_SAFETY_BPS,
            transcript_retention_blocks: DEFAULT_AUDIT_TTL_BLOCKS * 2,
            clsag_to_seraphis_binding_root: root_from_parts(
                "devnet-clsag-seraphis-binding",
                &[HashPart::Str(&attestation_id)],
            ),
            pq_signature_attestation_root: root_from_parts(
                "devnet-pq-signature-attestation",
                &[HashPart::Str(&attestation_id)],
            ),
            pq_key_ceremony_root: root_from_parts(
                "devnet-pq-key-ceremony",
                &[HashPart::Str(&attestation_id)],
            ),
            rollback_guard_root: root_from_parts(
                "devnet-pq-rollback-guard",
                &[HashPart::Str(&attestation_id)],
            ),
            migration_policy_root: root_from_parts(
                "devnet-pq-migration-policy",
                &[HashPart::Str(&attestation_id)],
            ),
        })
        .expect("devnet PQ migration attestation inserts");

    state
        .insert_fee_sponsored_audit_batch(FeeSponsoredAuditBatchInput {
            batch_id: "seraphis-clsag-fee-sponsored-audit-batch-devnet-0".to_string(),
            audit_id: audit_id.clone(),
            entropy_id,
            diversity_id,
            check_id,
            attestation_id,
            sponsor_policy: SponsorPolicy::BridgeDepositAudit,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_AUDIT_BATCH_OUTPUTS,
            audit_count: 512,
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_rebate_bps: DEFAULT_TARGET_SPONSOR_REBATE_BPS,
            sponsor_reserve_atoms: DEFAULT_MIN_SPONSOR_RESERVE_ATOMS * 4,
            batched_audit_root: root_from_parts(
                "devnet-fee-sponsored-batched-audit",
                &[HashPart::Str(&audit_id)],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-fee-sponsored-receipt",
                &[HashPart::Str(&audit_id)],
            ),
            low_fee_privacy_budget_root: root_from_parts(
                "devnet-low-fee-privacy-budget",
                &[HashPart::Str(&audit_id)],
            ),
        })
        .expect("devnet fee sponsored audit batch inserts");

    state.seal_audit(&audit_id).expect("devnet audit seals");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_root(root: &str, label: &str) -> Result<()> {
    ensure(!root.trim().is_empty(), &format!("{label} must be present"))?;
    ensure(
        root.len() >= 16,
        &format!("{label} must be a commitment-like root"),
    )
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("SERAPHIS-CLSAG-DUAL-DECOY-AUDIT-{domain}"),
        parts,
        32,
    )
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| {
            json!({
                "id": id,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("SERAPHIS-CLSAG-DUAL-DECOY-AUDIT-{domain}"),
        &leaves,
    )
}

fn weighted_average_bps(entries: impl Iterator<Item = (u64, u64)>) -> u64 {
    let mut weighted_sum = 0_u128;
    let mut total_weight = 0_u128;
    for (score, weight) in entries {
        weighted_sum += score as u128 * weight as u128;
        total_weight += weight as u128;
    }
    if total_weight == 0 {
        0
    } else {
        (weighted_sum / total_weight).min(MAX_SCORE as u128) as u64
    }
}

fn dual_ring_entropy_bps(
    clsag_entropy_bps: u64,
    seraphis_entropy_bps: u64,
    cross_ring_independence_bps: u64,
    shared_decoy_overlap_bps: u64,
    position_correlation_bps: u64,
) -> u64 {
    let base = weighted_average_bps(
        [
            (clsag_entropy_bps, 3),
            (seraphis_entropy_bps, 3),
            (cross_ring_independence_bps, 4),
        ]
        .into_iter(),
    );
    base.saturating_sub(shared_decoy_overlap_bps / 2)
        .saturating_sub(position_correlation_bps / 2)
        .min(MAX_SCORE)
}
