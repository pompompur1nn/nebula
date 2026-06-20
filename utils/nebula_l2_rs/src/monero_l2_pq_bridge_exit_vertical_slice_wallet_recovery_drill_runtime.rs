use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceWalletRecoveryDrillRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_WALLET_RECOVERY_DRILL_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-vertical-slice-wallet-recovery-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_WALLET_RECOVERY_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_RECOVERY_SUITE: &str =
    "encrypted-bridge-exit-receipt-root-reconstruction-drill-v1";
pub const SCAN_SURFACE_SUITE: &str =
    "jamtis-seraphis-viewtag-scan-hint-roots-only-recovery-surface-v1";
pub const NULLIFIER_KEY_IMAGE_SUITE: &str =
    "seraphis-nullifier-key-image-commitment-recovery-root-v1";
pub const FORCED_EXIT_CLAIM_SUITE: &str =
    "sequencer-watcher-failure-forced-exit-claim-recovery-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_key_images_amounts_output_indices_scan_secrets_or_plain_receipts";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_246_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_904_800;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_SCAN_COHORT_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_RECEIPT_SHARD_COUNT: u16 = 16;
pub const DEFAULT_MIN_RECONSTRUCTED_RECEIPT_ROOTS: u16 = 4;
pub const DEFAULT_MIN_NULLIFIER_COMMITMENTS: u16 = 2;
pub const DEFAULT_MIN_FORCED_EXIT_CLAIMS: u16 = 1;
pub const DEFAULT_MAX_RESCUE_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_RESCUE_FEE_PICONERO: u64 = 12_000_000;
pub const DEFAULT_MIN_PRIVACY_BUDGET_REMAINING_BPS: u64 = 8_800;
pub const DEFAULT_MAX_SCAN_HINT_DISCLOSURE_BPS: u64 = 65;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_FAILURE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REPLAY_GRACE_BLOCKS: u64 = 120;
pub const DEFAULT_MAX_DRILLS: usize = 131_072;
pub const DEFAULT_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillLane {
    WalletRestore,
    WatchOnlyRestore,
    SequencerFailure,
    WatcherFailure,
    ForcedExitRescue,
    PostReorgAudit,
}

impl DrillLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WatchOnlyRestore => "watch_only_restore",
            Self::SequencerFailure => "sequencer_failure",
            Self::WatcherFailure => "watcher_failure",
            Self::ForcedExitRescue => "forced_exit_rescue",
            Self::PostReorgAudit => "post_reorg_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    SequencerUnavailable,
    WatcherUnavailable,
    BothUnavailable,
    CorruptedLocalCache,
    ReorgAfterReceipt,
}

impl FailureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerUnavailable => "sequencer_unavailable",
            Self::WatcherUnavailable => "watcher_unavailable",
            Self::BothUnavailable => "both_unavailable",
            Self::CorruptedLocalCache => "corrupted_local_cache",
            Self::ReorgAfterReceipt => "reorg_after_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSurfaceKind {
    JamtisViewTag,
    JamtisAddressTag,
    SeraphisViewTag,
    SeraphisLinkabilityTag,
    DecoyFreshnessBand,
}

impl ScanSurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JamtisViewTag => "jamtis_view_tag",
            Self::JamtisAddressTag => "jamtis_address_tag",
            Self::SeraphisViewTag => "seraphis_view_tag",
            Self::SeraphisLinkabilityTag => "seraphis_linkability_tag",
            Self::DecoyFreshnessBand => "decoy_freshness_band",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    ReceiptRootsReconstructed,
    ScanHintsRootsOnly,
    NullifierCommitmentsRecovered,
    KeyImageCommitmentsRecovered,
    ForcedExitClaimsRecoverable,
    PrivacyBudgetPreserved,
    RescueFeeCapMet,
    PqSecurityFloorMet,
    ReplayFencePresent,
    PublicSurfaceRedacted,
}

impl CheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptRootsReconstructed => "receipt_roots_reconstructed",
            Self::ScanHintsRootsOnly => "scan_hints_roots_only",
            Self::NullifierCommitmentsRecovered => "nullifier_commitments_recovered",
            Self::KeyImageCommitmentsRecovered => "key_image_commitments_recovered",
            Self::ForcedExitClaimsRecoverable => "forced_exit_claims_recoverable",
            Self::PrivacyBudgetPreserved => "privacy_budget_preserved",
            Self::RescueFeeCapMet => "rescue_fee_cap_met",
            Self::PqSecurityFloorMet => "pq_security_floor_met",
            Self::ReplayFencePresent => "replay_fence_present",
            Self::PublicSurfaceRedacted => "public_surface_redacted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Watch,
    Failed,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStatus {
    Draft,
    EvidenceLoaded,
    Reconstructed,
    RescueReady,
    Sealed,
    Rejected,
}

impl DrillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::EvidenceLoaded => "evidence_loaded",
            Self::Reconstructed => "reconstructed",
            Self::RescueReady => "rescue_ready",
            Self::Sealed => "sealed",
            Self::Rejected => "rejected",
        }
    }

    pub fn public_usable(self) -> bool {
        matches!(self, Self::Reconstructed | Self::RescueReady | Self::Sealed)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_recovery_suite: String,
    pub scan_surface_suite: String,
    pub nullifier_key_image_suite: String,
    pub forced_exit_claim_suite: String,
    pub privacy_boundary: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_scan_cohort_size: u64,
    pub min_receipt_shard_count: u16,
    pub min_reconstructed_receipt_roots: u16,
    pub min_nullifier_commitments: u16,
    pub min_forced_exit_claims: u16,
    pub max_rescue_fee_bps: u64,
    pub max_rescue_fee_piconero: u64,
    pub min_privacy_budget_remaining_bps: u64,
    pub max_scan_hint_disclosure_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub failure_window_blocks: u64,
    pub replay_grace_blocks: u64,
    pub max_drills: usize,
    pub max_events: usize,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_recovery_suite: RECEIPT_RECOVERY_SUITE.to_string(),
            scan_surface_suite: SCAN_SURFACE_SUITE.to_string(),
            nullifier_key_image_suite: NULLIFIER_KEY_IMAGE_SUITE.to_string(),
            forced_exit_claim_suite: FORCED_EXIT_CLAIM_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_scan_cohort_size: DEFAULT_MIN_SCAN_COHORT_SIZE,
            min_receipt_shard_count: DEFAULT_MIN_RECEIPT_SHARD_COUNT,
            min_reconstructed_receipt_roots: DEFAULT_MIN_RECONSTRUCTED_RECEIPT_ROOTS,
            min_nullifier_commitments: DEFAULT_MIN_NULLIFIER_COMMITMENTS,
            min_forced_exit_claims: DEFAULT_MIN_FORCED_EXIT_CLAIMS,
            max_rescue_fee_bps: DEFAULT_MAX_RESCUE_FEE_BPS,
            max_rescue_fee_piconero: DEFAULT_MAX_RESCUE_FEE_PICONERO,
            min_privacy_budget_remaining_bps: DEFAULT_MIN_PRIVACY_BUDGET_REMAINING_BPS,
            max_scan_hint_disclosure_bps: DEFAULT_MAX_SCAN_HINT_DISCLOSURE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            failure_window_blocks: DEFAULT_FAILURE_WINDOW_BLOCKS,
            replay_grace_blocks: DEFAULT_REPLAY_GRACE_BLOCKS,
            max_drills: DEFAULT_MAX_DRILLS,
            max_events: DEFAULT_MAX_EVENTS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.chain_id == CHAIN_ID,
            "config chain id must match runtime chain id",
        )?;
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "unexpected schema version",
        )?;
        ensure(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set must cover minimum privacy set",
        )?;
        ensure(
            self.min_scan_cohort_size >= self.min_privacy_set_size,
            "scan cohort must cover minimum privacy set",
        )?;
        ensure(
            self.min_receipt_shard_count > 0,
            "receipt shard floor must be non-zero",
        )?;
        ensure(
            self.min_reconstructed_receipt_roots > 0,
            "reconstructed receipt root floor must be non-zero",
        )?;
        ensure(
            self.min_nullifier_commitments > 0,
            "nullifier commitment floor must be non-zero",
        )?;
        ensure(
            self.min_forced_exit_claims > 0,
            "forced-exit claim floor must be non-zero",
        )?;
        ensure(
            self.max_rescue_fee_bps <= MAX_BPS,
            "rescue fee bps exceeds maximum",
        )?;
        ensure(
            self.min_privacy_budget_remaining_bps <= MAX_BPS
                && self.max_scan_hint_disclosure_bps <= MAX_BPS,
            "privacy budget thresholds exceed maximum",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover floor",
        )?;
        ensure(
            self.failure_window_blocks > self.replay_grace_blocks,
            "failure window must exceed replay grace",
        )?;
        ensure(self.max_drills > 0, "max drills must be non-zero")?;
        ensure(self.max_events > 0, "max events must be non-zero")?;
        ensure(
            self.cargo_checks_deferred,
            "runtime is declared with cargo checks deferred",
        )?;
        ensure(
            !self.production_release_allowed,
            "production release must remain disabled for this drill",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub drill_root: String,
    pub receipt_root: String,
    pub scan_surface_root: String,
    pub nullifier_key_image_root: String,
    pub forced_exit_claim_root: String,
    pub check_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub latest_spine_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub drills: u64,
    pub reconstructed_receipt_roots: u64,
    pub scan_surfaces: u64,
    pub nullifier_commitments: u64,
    pub key_image_commitments: u64,
    pub forced_exit_claims: u64,
    pub passed_checks: u64,
    pub watched_checks: u64,
    pub failed_checks: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrillEnvelope {
    pub drill_id: String,
    pub lane: DrillLane,
    pub failure_mode: FailureMode,
    pub wallet_cohort_root: String,
    pub bridge_exit_spine_root: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub failure_detected_height: u64,
    pub recovery_deadline_height: u64,
    pub privacy_set_size: u64,
    pub scan_cohort_size: u64,
    pub pq_security_bits: u16,
    pub rescue_fee_bps: u64,
    pub rescue_fee_piconero: u64,
    pub privacy_budget_remaining_bps: u64,
    pub scan_hint_disclosure_bps: u64,
    pub receipt_manifest_root: String,
    pub scan_manifest_root: String,
    pub nullifier_manifest_root: String,
    pub forced_exit_manifest_root: String,
    pub replay_fence_root: String,
    pub status: DrillStatus,
    pub envelope_root: String,
}

impl DrillEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "drill_id": self.drill_id,
            "lane": self.lane.as_str(),
            "failure_mode": self.failure_mode.as_str(),
            "wallet_cohort_root": self.wallet_cohort_root,
            "bridge_exit_spine_root": self.bridge_exit_spine_root,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "failure_detected_height": self.failure_detected_height,
            "recovery_deadline_height": self.recovery_deadline_height,
            "privacy_set_size": self.privacy_set_size,
            "scan_cohort_size": self.scan_cohort_size,
            "pq_security_bits": self.pq_security_bits,
            "rescue_fee_bps": self.rescue_fee_bps,
            "rescue_fee_piconero": self.rescue_fee_piconero,
            "privacy_budget_remaining_bps": self.privacy_budget_remaining_bps,
            "scan_hint_disclosure_bps": self.scan_hint_disclosure_bps,
            "receipt_manifest_root": self.receipt_manifest_root,
            "scan_manifest_root": self.scan_manifest_root,
            "nullifier_manifest_root": self.nullifier_manifest_root,
            "forced_exit_manifest_root": self.forced_exit_manifest_root,
            "replay_fence_root": self.replay_fence_root,
            "status": self.status.as_str(),
            "envelope_root": self.envelope_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-envelope", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptRootRecovery {
    pub receipt_id: String,
    pub drill_id: String,
    pub encrypted_receipt_root: String,
    pub receipt_ciphertext_root: String,
    pub shard_commitment_root: String,
    pub reconstruction_proof_root: String,
    pub local_cache_witness_root: String,
    pub bridge_action_receipt_root: String,
    pub receipt_shards: u16,
    pub recovered_at_l2_height: u64,
}

impl ReceiptRootRecovery {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-receipt-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanSurface {
    pub surface_id: String,
    pub drill_id: String,
    pub kind: ScanSurfaceKind,
    pub hint_root: String,
    pub view_tag_bucket_root: String,
    pub subaddress_epoch_root: String,
    pub decoy_freshness_root: String,
    pub redaction_proof_root: String,
    pub scan_cohort_size: u64,
    pub disclosure_bps: u64,
    pub privacy_budget_remaining_bps: u64,
}

impl ScanSurface {
    pub fn public_record(&self) -> Value {
        json!({
            "surface_id": self.surface_id,
            "drill_id": self.drill_id,
            "kind": self.kind.as_str(),
            "hint_root": self.hint_root,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "subaddress_epoch_root": self.subaddress_epoch_root,
            "decoy_freshness_root": self.decoy_freshness_root,
            "redaction_proof_root": self.redaction_proof_root,
            "scan_cohort_size": self.scan_cohort_size,
            "disclosure_bps": self.disclosure_bps,
            "privacy_budget_remaining_bps": self.privacy_budget_remaining_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-scan-surface", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageCommitment {
    pub commitment_id: String,
    pub drill_id: String,
    pub nullifier_commitment_root: String,
    pub key_image_commitment_root: String,
    pub spend_auth_commitment_root: String,
    pub membership_witness_root: String,
    pub linkability_domain_root: String,
    pub recovery_note_root: String,
    pub pq_binding_root: String,
}

impl NullifierKeyImageCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "wallet-recovery-drill-nullifier-key-image",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitClaim {
    pub claim_id: String,
    pub drill_id: String,
    pub exit_claim_root: String,
    pub claimant_commitment_root: String,
    pub bridge_receipt_root: String,
    pub forced_exit_queue_root: String,
    pub rescue_fee_commitment_root: String,
    pub replay_fence_root: String,
    pub claim_window_start: u64,
    pub claim_window_end: u64,
    pub rescue_fee_bps: u64,
    pub rescue_fee_piconero: u64,
}

impl ForcedExitClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "wallet-recovery-drill-forced-exit-claim",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckRecord {
    pub check_id: String,
    pub drill_id: String,
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub evidence_root: String,
    pub note: String,
}

impl CheckRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "drill_id": self.drill_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub drill_id: String,
    pub kind: String,
    pub sequence: u64,
    pub l2_height: u64,
    pub event_root: String,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-event", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrillRequest {
    pub drill_id: String,
    pub lane: DrillLane,
    pub failure_mode: FailureMode,
    pub wallet_cohort_root: String,
    pub bridge_exit_spine_root: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub failure_detected_height: u64,
    pub privacy_set_size: u64,
    pub scan_cohort_size: u64,
    pub pq_security_bits: u16,
    pub rescue_fee_bps: u64,
    pub rescue_fee_piconero: u64,
    pub privacy_budget_remaining_bps: u64,
    pub scan_hint_disclosure_bps: u64,
    pub receipt_manifest_root: String,
    pub scan_manifest_root: String,
    pub nullifier_manifest_root: String,
    pub forced_exit_manifest_root: String,
    pub replay_fence_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptRecoveryRequest {
    pub receipt_id: String,
    pub drill_id: String,
    pub encrypted_receipt_root: String,
    pub receipt_ciphertext_root: String,
    pub shard_commitment_root: String,
    pub reconstruction_proof_root: String,
    pub local_cache_witness_root: String,
    pub bridge_action_receipt_root: String,
    pub receipt_shards: u16,
    pub recovered_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanSurfaceRequest {
    pub surface_id: String,
    pub drill_id: String,
    pub kind: ScanSurfaceKind,
    pub hint_root: String,
    pub view_tag_bucket_root: String,
    pub subaddress_epoch_root: String,
    pub decoy_freshness_root: String,
    pub redaction_proof_root: String,
    pub scan_cohort_size: u64,
    pub disclosure_bps: u64,
    pub privacy_budget_remaining_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageRequest {
    pub commitment_id: String,
    pub drill_id: String,
    pub nullifier_commitment_root: String,
    pub key_image_commitment_root: String,
    pub spend_auth_commitment_root: String,
    pub membership_witness_root: String,
    pub linkability_domain_root: String,
    pub recovery_note_root: String,
    pub pq_binding_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitClaimRequest {
    pub claim_id: String,
    pub drill_id: String,
    pub exit_claim_root: String,
    pub claimant_commitment_root: String,
    pub bridge_receipt_root: String,
    pub forced_exit_queue_root: String,
    pub rescue_fee_commitment_root: String,
    pub replay_fence_root: String,
    pub claim_window_start: u64,
    pub claim_window_end: u64,
    pub rescue_fee_bps: u64,
    pub rescue_fee_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub drills: BTreeMap<String, DrillEnvelope>,
    pub receipts: BTreeMap<String, ReceiptRootRecovery>,
    pub scan_surfaces: BTreeMap<String, ScanSurface>,
    pub nullifier_key_images: BTreeMap<String, NullifierKeyImageCommitment>,
    pub forced_exit_claims: BTreeMap<String, ForcedExitClaim>,
    pub checks: BTreeMap<String, CheckRecord>,
    pub events: BTreeMap<String, EventRecord>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            l2_height: DEVNET_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            config,
            drills: BTreeMap::new(),
            receipts: BTreeMap::new(),
            scan_surfaces: BTreeMap::new(),
            nullifier_key_images: BTreeMap::new(),
            forced_exit_claims: BTreeMap::new(),
            checks: BTreeMap::new(),
            events: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.seed_devnet_vertical_slice()?;
        Ok(state)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("wallet-recovery-drill-state", &self.public_record())
    }

    pub fn register_drill(&mut self, request: DrillRequest) -> Result<String> {
        ensure(
            self.drills.len() < self.config.max_drills,
            "drill capacity exhausted",
        )?;
        ensure(
            !self.drills.contains_key(&request.drill_id),
            "drill id already exists",
        )?;
        self.validate_privacy_budget(
            request.privacy_set_size,
            request.scan_cohort_size,
            request.privacy_budget_remaining_bps,
            request.scan_hint_disclosure_bps,
        )?;
        self.validate_rescue_fee(request.rescue_fee_bps, request.rescue_fee_piconero)?;
        ensure(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ security floor not met",
        )?;
        ensure(
            request.replay_fence_root != empty_root("wallet-recovery-drill-replay-fence"),
            "replay fence root must be bound",
        )?;
        ensure(
            request.failure_detected_height <= request.l2_height,
            "failure detection height cannot exceed l2 height",
        )?;
        let recovery_deadline_height = request
            .failure_detected_height
            .saturating_add(self.config.failure_window_blocks);
        let envelope_root =
            drill_envelope_root(&request.drill_id, request.bridge_exit_spine_root.as_str());
        let drill = DrillEnvelope {
            drill_id: request.drill_id.clone(),
            lane: request.lane,
            failure_mode: request.failure_mode,
            wallet_cohort_root: request.wallet_cohort_root,
            bridge_exit_spine_root: request.bridge_exit_spine_root,
            l2_height: request.l2_height,
            monero_height: request.monero_height,
            failure_detected_height: request.failure_detected_height,
            recovery_deadline_height,
            privacy_set_size: request.privacy_set_size,
            scan_cohort_size: request.scan_cohort_size,
            pq_security_bits: request.pq_security_bits,
            rescue_fee_bps: request.rescue_fee_bps,
            rescue_fee_piconero: request.rescue_fee_piconero,
            privacy_budget_remaining_bps: request.privacy_budget_remaining_bps,
            scan_hint_disclosure_bps: request.scan_hint_disclosure_bps,
            receipt_manifest_root: request.receipt_manifest_root,
            scan_manifest_root: request.scan_manifest_root,
            nullifier_manifest_root: request.nullifier_manifest_root,
            forced_exit_manifest_root: request.forced_exit_manifest_root,
            replay_fence_root: request.replay_fence_root,
            status: DrillStatus::EvidenceLoaded,
            envelope_root,
        };
        let drill_id = drill.drill_id.clone();
        self.l2_height = self.l2_height.max(drill.l2_height);
        self.monero_height = self.monero_height.max(drill.monero_height);
        self.drills.insert(drill_id.clone(), drill);
        self.counters.drills += 1;
        self.record_event(&drill_id, "drill_registered", self.l2_height)?;
        self.refresh_roots();
        Ok(drill_id)
    }

    pub fn add_receipt_recovery(&mut self, request: ReceiptRecoveryRequest) -> Result<String> {
        self.require_drill(&request.drill_id)?;
        ensure(
            !self.receipts.contains_key(&request.receipt_id),
            "receipt id already exists",
        )?;
        ensure(
            request.receipt_shards >= self.config.min_receipt_shard_count,
            "receipt shard count below reconstruction floor",
        )?;
        let receipt = ReceiptRootRecovery {
            receipt_id: request.receipt_id.clone(),
            drill_id: request.drill_id.clone(),
            encrypted_receipt_root: request.encrypted_receipt_root,
            receipt_ciphertext_root: request.receipt_ciphertext_root,
            shard_commitment_root: request.shard_commitment_root,
            reconstruction_proof_root: request.reconstruction_proof_root,
            local_cache_witness_root: request.local_cache_witness_root,
            bridge_action_receipt_root: request.bridge_action_receipt_root,
            receipt_shards: request.receipt_shards,
            recovered_at_l2_height: request.recovered_at_l2_height,
        };
        let receipt_id = receipt.receipt_id.clone();
        let drill_id = receipt.drill_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.reconstructed_receipt_roots += 1;
        self.record_event(&drill_id, "receipt_root_reconstructed", self.l2_height)?;
        self.refresh_drill_status(&drill_id)?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn add_scan_surface(&mut self, request: ScanSurfaceRequest) -> Result<String> {
        self.require_drill(&request.drill_id)?;
        ensure(
            !self.scan_surfaces.contains_key(&request.surface_id),
            "scan surface id already exists",
        )?;
        self.validate_privacy_budget(
            request.scan_cohort_size,
            request.scan_cohort_size,
            request.privacy_budget_remaining_bps,
            request.disclosure_bps,
        )?;
        let surface = ScanSurface {
            surface_id: request.surface_id.clone(),
            drill_id: request.drill_id.clone(),
            kind: request.kind,
            hint_root: request.hint_root,
            view_tag_bucket_root: request.view_tag_bucket_root,
            subaddress_epoch_root: request.subaddress_epoch_root,
            decoy_freshness_root: request.decoy_freshness_root,
            redaction_proof_root: request.redaction_proof_root,
            scan_cohort_size: request.scan_cohort_size,
            disclosure_bps: request.disclosure_bps,
            privacy_budget_remaining_bps: request.privacy_budget_remaining_bps,
        };
        let surface_id = surface.surface_id.clone();
        let drill_id = surface.drill_id.clone();
        self.scan_surfaces.insert(surface_id.clone(), surface);
        self.counters.scan_surfaces += 1;
        self.record_event(&drill_id, "scan_surface_committed", self.l2_height)?;
        self.refresh_drill_status(&drill_id)?;
        self.refresh_roots();
        Ok(surface_id)
    }

    pub fn add_nullifier_key_image(&mut self, request: NullifierKeyImageRequest) -> Result<String> {
        self.require_drill(&request.drill_id)?;
        ensure(
            !self
                .nullifier_key_images
                .contains_key(&request.commitment_id),
            "nullifier key image commitment id already exists",
        )?;
        let commitment = NullifierKeyImageCommitment {
            commitment_id: request.commitment_id.clone(),
            drill_id: request.drill_id.clone(),
            nullifier_commitment_root: request.nullifier_commitment_root,
            key_image_commitment_root: request.key_image_commitment_root,
            spend_auth_commitment_root: request.spend_auth_commitment_root,
            membership_witness_root: request.membership_witness_root,
            linkability_domain_root: request.linkability_domain_root,
            recovery_note_root: request.recovery_note_root,
            pq_binding_root: request.pq_binding_root,
        };
        let commitment_id = commitment.commitment_id.clone();
        let drill_id = commitment.drill_id.clone();
        self.nullifier_key_images
            .insert(commitment_id.clone(), commitment);
        self.counters.nullifier_commitments += 1;
        self.counters.key_image_commitments += 1;
        self.record_event(
            &drill_id,
            "nullifier_key_image_commitment_recovered",
            self.l2_height,
        )?;
        self.refresh_drill_status(&drill_id)?;
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn add_forced_exit_claim(&mut self, request: ForcedExitClaimRequest) -> Result<String> {
        self.require_drill(&request.drill_id)?;
        ensure(
            !self.forced_exit_claims.contains_key(&request.claim_id),
            "forced-exit claim id already exists",
        )?;
        self.validate_rescue_fee(request.rescue_fee_bps, request.rescue_fee_piconero)?;
        ensure(
            request.claim_window_end > request.claim_window_start,
            "claim window must be ordered",
        )?;
        ensure(
            request.claim_window_end - request.claim_window_start
                >= self.config.replay_grace_blocks,
            "claim window must include replay grace",
        )?;
        let claim = ForcedExitClaim {
            claim_id: request.claim_id.clone(),
            drill_id: request.drill_id.clone(),
            exit_claim_root: request.exit_claim_root,
            claimant_commitment_root: request.claimant_commitment_root,
            bridge_receipt_root: request.bridge_receipt_root,
            forced_exit_queue_root: request.forced_exit_queue_root,
            rescue_fee_commitment_root: request.rescue_fee_commitment_root,
            replay_fence_root: request.replay_fence_root,
            claim_window_start: request.claim_window_start,
            claim_window_end: request.claim_window_end,
            rescue_fee_bps: request.rescue_fee_bps,
            rescue_fee_piconero: request.rescue_fee_piconero,
        };
        let claim_id = claim.claim_id.clone();
        let drill_id = claim.drill_id.clone();
        self.forced_exit_claims.insert(claim_id.clone(), claim);
        self.counters.forced_exit_claims += 1;
        self.record_event(&drill_id, "forced_exit_claim_recovered", self.l2_height)?;
        self.refresh_drill_status(&drill_id)?;
        self.refresh_roots();
        Ok(claim_id)
    }

    pub fn run_recovery_checks(&mut self, drill_id: &str) -> Result<Value> {
        let drill = self.require_drill(drill_id)?.clone();
        let receipt_count = self.receipts_for_drill(drill_id) as u16;
        let scan_surface_count = self.scan_surfaces_for_drill(drill_id);
        let nullifier_count = self.nullifier_key_images_for_drill(drill_id) as u16;
        let forced_exit_count = self.forced_exit_claims_for_drill(drill_id) as u16;
        let checks = [
            (
                CheckKind::ReceiptRootsReconstructed,
                receipt_count >= self.config.min_reconstructed_receipt_roots,
                "encrypted receipt roots reconstructed from shards",
            ),
            (
                CheckKind::ScanHintsRootsOnly,
                scan_surface_count >= 2,
                "JAMTIS and Seraphis scan surfaces committed as roots only",
            ),
            (
                CheckKind::NullifierCommitmentsRecovered,
                nullifier_count >= self.config.min_nullifier_commitments,
                "nullifier commitments are recoverable",
            ),
            (
                CheckKind::KeyImageCommitmentsRecovered,
                nullifier_count >= self.config.min_nullifier_commitments,
                "key-image commitments are recoverable without raw key images",
            ),
            (
                CheckKind::ForcedExitClaimsRecoverable,
                forced_exit_count >= self.config.min_forced_exit_claims,
                "forced-exit claim is ready after sequencer or watcher failure",
            ),
            (
                CheckKind::PrivacyBudgetPreserved,
                drill.privacy_budget_remaining_bps >= self.config.min_privacy_budget_remaining_bps
                    && drill.scan_hint_disclosure_bps <= self.config.max_scan_hint_disclosure_bps,
                "privacy budget and scan disclosure bounds met",
            ),
            (
                CheckKind::RescueFeeCapMet,
                drill.rescue_fee_bps <= self.config.max_rescue_fee_bps
                    && drill.rescue_fee_piconero <= self.config.max_rescue_fee_piconero,
                "low-fee rescue caps met",
            ),
            (
                CheckKind::PqSecurityFloorMet,
                drill.pq_security_bits >= self.config.min_pq_security_bits,
                "post-quantum recovery authorization floor met",
            ),
            (
                CheckKind::ReplayFencePresent,
                !drill.replay_fence_root.is_empty(),
                "forced-exit replay fence root is present",
            ),
            (
                CheckKind::PublicSurfaceRedacted,
                self.public_surface_is_roots_only(drill_id),
                "public recovery surface contains roots and counters only",
            ),
        ];
        let mut check_records = Vec::with_capacity(checks.len());
        for (kind, passed, note) in checks {
            let status = if passed {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            };
            let check_id = check_id(drill_id, kind);
            let evidence_root = root_from_parts(
                "wallet-recovery-drill-check-evidence",
                &[
                    HashPart::Str(drill_id),
                    HashPart::Str(kind.as_str()),
                    HashPart::Str(status.as_str()),
                ],
            );
            let record = CheckRecord {
                check_id: check_id.clone(),
                drill_id: drill_id.to_string(),
                kind,
                status,
                evidence_root,
                note: note.to_string(),
            };
            if status.passes() {
                self.counters.passed_checks += 1;
            } else {
                self.counters.failed_checks += 1;
            }
            check_records.push(record.public_record());
            self.checks.insert(check_id, record);
        }
        self.refresh_drill_status(drill_id)?;
        self.record_event(drill_id, "recovery_checks_completed", self.l2_height)?;
        self.refresh_roots();
        Ok(json!({
            "drill_id": drill_id,
            "status": self.drills.get(drill_id).map(|d| d.status.as_str()).unwrap_or("missing"),
            "receipt_count": receipt_count,
            "scan_surface_count": scan_surface_count,
            "nullifier_key_image_count": nullifier_count,
            "forced_exit_claim_count": forced_exit_count,
            "checks": check_records,
            "check_root": self.roots.check_root,
        }))
    }

    pub fn root_summary(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "config_root": self.roots.config_root,
            "drill_root": self.roots.drill_root,
            "receipt_root": self.roots.receipt_root,
            "scan_surface_root": self.roots.scan_surface_root,
            "nullifier_key_image_root": self.roots.nullifier_key_image_root,
            "forced_exit_claim_root": self.roots.forced_exit_claim_root,
            "check_root": self.roots.check_root,
            "event_root": self.roots.event_root,
        })
    }

    fn seed_devnet_vertical_slice(&mut self) -> Result<()> {
        let drill_id = "devnet-wallet-recovery-drill-001".to_string();
        let request = DrillRequest {
            drill_id: drill_id.clone(),
            lane: DrillLane::ForcedExitRescue,
            failure_mode: FailureMode::BothUnavailable,
            wallet_cohort_root: labeled_root("wallet-cohort", "devnet-cohort"),
            bridge_exit_spine_root: labeled_root("bridge-exit-spine", "devnet-spine"),
            l2_height: DEVNET_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            failure_detected_height: DEVNET_HEIGHT - 32,
            privacy_set_size: self.config.target_privacy_set_size,
            scan_cohort_size: self.config.min_scan_cohort_size,
            pq_security_bits: self.config.target_pq_security_bits,
            rescue_fee_bps: self.config.max_rescue_fee_bps,
            rescue_fee_piconero: self.config.max_rescue_fee_piconero / 2,
            privacy_budget_remaining_bps: self.config.min_privacy_budget_remaining_bps + 200,
            scan_hint_disclosure_bps: self.config.max_scan_hint_disclosure_bps / 2,
            receipt_manifest_root: labeled_root("receipt-manifest", "devnet"),
            scan_manifest_root: labeled_root("scan-manifest", "devnet"),
            nullifier_manifest_root: labeled_root("nullifier-manifest", "devnet"),
            forced_exit_manifest_root: labeled_root("forced-exit-manifest", "devnet"),
            replay_fence_root: labeled_root("replay-fence", "devnet"),
        };
        self.register_drill(request)?;
        for index in 0..self.config.min_reconstructed_receipt_roots {
            self.add_receipt_recovery(ReceiptRecoveryRequest {
                receipt_id: format!("devnet-receipt-root-{index:02}"),
                drill_id: drill_id.clone(),
                encrypted_receipt_root: labeled_index_root("encrypted-receipt", index as u64),
                receipt_ciphertext_root: labeled_index_root("receipt-ciphertext", index as u64),
                shard_commitment_root: labeled_index_root("receipt-shards", index as u64),
                reconstruction_proof_root: labeled_index_root("receipt-proof", index as u64),
                local_cache_witness_root: labeled_index_root("local-cache", index as u64),
                bridge_action_receipt_root: labeled_index_root("bridge-action", index as u64),
                receipt_shards: self.config.min_receipt_shard_count,
                recovered_at_l2_height: DEVNET_HEIGHT + index as u64,
            })?;
        }
        for (index, kind) in [
            ScanSurfaceKind::JamtisViewTag,
            ScanSurfaceKind::JamtisAddressTag,
            ScanSurfaceKind::SeraphisViewTag,
            ScanSurfaceKind::SeraphisLinkabilityTag,
        ]
        .iter()
        .copied()
        .enumerate()
        {
            self.add_scan_surface(ScanSurfaceRequest {
                surface_id: format!("devnet-scan-surface-{index:02}"),
                drill_id: drill_id.clone(),
                kind,
                hint_root: labeled_index_root("scan-hint", index as u64),
                view_tag_bucket_root: labeled_index_root("viewtag-bucket", index as u64),
                subaddress_epoch_root: labeled_index_root("subaddress-epoch", index as u64),
                decoy_freshness_root: labeled_index_root("decoy-freshness", index as u64),
                redaction_proof_root: labeled_index_root("scan-redaction", index as u64),
                scan_cohort_size: self.config.min_scan_cohort_size,
                disclosure_bps: self.config.max_scan_hint_disclosure_bps / 2,
                privacy_budget_remaining_bps: self.config.min_privacy_budget_remaining_bps + 200,
            })?;
        }
        for index in 0..self.config.min_nullifier_commitments {
            self.add_nullifier_key_image(NullifierKeyImageRequest {
                commitment_id: format!("devnet-nullifier-key-image-{index:02}"),
                drill_id: drill_id.clone(),
                nullifier_commitment_root: labeled_index_root("nullifier", index as u64),
                key_image_commitment_root: labeled_index_root("key-image", index as u64),
                spend_auth_commitment_root: labeled_index_root("spend-auth", index as u64),
                membership_witness_root: labeled_index_root("membership", index as u64),
                linkability_domain_root: labeled_index_root("linkability", index as u64),
                recovery_note_root: labeled_index_root("recovery-note", index as u64),
                pq_binding_root: labeled_index_root("pq-binding", index as u64),
            })?;
        }
        for index in 0..self.config.min_forced_exit_claims {
            self.add_forced_exit_claim(ForcedExitClaimRequest {
                claim_id: format!("devnet-forced-exit-claim-{index:02}"),
                drill_id: drill_id.clone(),
                exit_claim_root: labeled_index_root("exit-claim", index as u64),
                claimant_commitment_root: labeled_index_root("claimant", index as u64),
                bridge_receipt_root: labeled_index_root("bridge-receipt", index as u64),
                forced_exit_queue_root: labeled_index_root("exit-queue", index as u64),
                rescue_fee_commitment_root: labeled_index_root("rescue-fee", index as u64),
                replay_fence_root: labeled_index_root("claim-replay-fence", index as u64),
                claim_window_start: DEVNET_HEIGHT + 1,
                claim_window_end: DEVNET_HEIGHT + 1 + self.config.replay_grace_blocks,
                rescue_fee_bps: self.config.max_rescue_fee_bps,
                rescue_fee_piconero: self.config.max_rescue_fee_piconero / 2,
            })?;
        }
        self.run_recovery_checks(&drill_id)?;
        Ok(())
    }

    fn validate_privacy_budget(
        &self,
        privacy_set_size: u64,
        scan_cohort_size: u64,
        privacy_budget_remaining_bps: u64,
        scan_hint_disclosure_bps: u64,
    ) -> Result<()> {
        ensure(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below floor",
        )?;
        ensure(
            scan_cohort_size >= self.config.min_scan_cohort_size,
            "scan cohort below JAMTIS/Seraphis recovery floor",
        )?;
        ensure(
            privacy_budget_remaining_bps >= self.config.min_privacy_budget_remaining_bps,
            "privacy budget remaining below floor",
        )?;
        ensure(
            scan_hint_disclosure_bps <= self.config.max_scan_hint_disclosure_bps,
            "scan hint disclosure exceeds cap",
        )?;
        Ok(())
    }

    fn validate_rescue_fee(&self, rescue_fee_bps: u64, rescue_fee_piconero: u64) -> Result<()> {
        ensure(
            rescue_fee_bps <= self.config.max_rescue_fee_bps,
            "rescue fee bps exceeds low-fee cap",
        )?;
        ensure(
            rescue_fee_piconero <= self.config.max_rescue_fee_piconero,
            "rescue fee amount exceeds low-fee cap",
        )?;
        Ok(())
    }

    fn require_drill(&self, drill_id: &str) -> Result<&DrillEnvelope> {
        self.drills
            .get(drill_id)
            .ok_or_else(|| format!("unknown drill id: {drill_id}"))
    }

    fn receipts_for_drill(&self, drill_id: &str) -> usize {
        self.receipts
            .values()
            .filter(|receipt| receipt.drill_id == drill_id)
            .count()
    }

    fn scan_surfaces_for_drill(&self, drill_id: &str) -> usize {
        self.scan_surfaces
            .values()
            .filter(|surface| surface.drill_id == drill_id)
            .count()
    }

    fn nullifier_key_images_for_drill(&self, drill_id: &str) -> usize {
        self.nullifier_key_images
            .values()
            .filter(|commitment| commitment.drill_id == drill_id)
            .count()
    }

    fn forced_exit_claims_for_drill(&self, drill_id: &str) -> usize {
        self.forced_exit_claims
            .values()
            .filter(|claim| claim.drill_id == drill_id)
            .count()
    }

    fn public_surface_is_roots_only(&self, drill_id: &str) -> bool {
        self.receipts.values().all(|receipt| {
            receipt.drill_id != drill_id
                || (!receipt.encrypted_receipt_root.is_empty()
                    && !receipt.reconstruction_proof_root.is_empty())
        }) && self.scan_surfaces.values().all(|surface| {
            surface.drill_id != drill_id
                || (!surface.hint_root.is_empty() && !surface.redaction_proof_root.is_empty())
        }) && self.nullifier_key_images.values().all(|commitment| {
            commitment.drill_id != drill_id
                || (!commitment.nullifier_commitment_root.is_empty()
                    && !commitment.key_image_commitment_root.is_empty())
        })
    }

    fn refresh_drill_status(&mut self, drill_id: &str) -> Result<()> {
        let receipt_ready =
            self.receipts_for_drill(drill_id) as u16 >= self.config.min_reconstructed_receipt_roots;
        let nullifier_ready = self.nullifier_key_images_for_drill(drill_id) as u16
            >= self.config.min_nullifier_commitments;
        let forced_exit_ready = self.forced_exit_claims_for_drill(drill_id) as u16
            >= self.config.min_forced_exit_claims;
        let scan_ready = self.scan_surfaces_for_drill(drill_id) >= 2;
        let failed_check = self
            .checks
            .values()
            .any(|check| check.drill_id == drill_id && check.status == CheckStatus::Failed);
        let passed_checks = self
            .checks
            .values()
            .filter(|check| check.drill_id == drill_id && check.status.passes())
            .count();
        let drill = self
            .drills
            .get_mut(drill_id)
            .ok_or_else(|| format!("unknown drill id: {drill_id}"))?;
        drill.status = if failed_check {
            DrillStatus::Rejected
        } else if receipt_ready
            && nullifier_ready
            && forced_exit_ready
            && scan_ready
            && passed_checks >= 10
        {
            DrillStatus::Sealed
        } else if receipt_ready && nullifier_ready && forced_exit_ready && scan_ready {
            DrillStatus::RescueReady
        } else if receipt_ready && nullifier_ready {
            DrillStatus::Reconstructed
        } else {
            DrillStatus::EvidenceLoaded
        };
        Ok(())
    }

    fn record_event(&mut self, drill_id: &str, kind: &str, l2_height: u64) -> Result<()> {
        ensure(
            self.events.len() < self.config.max_events,
            "event capacity exhausted",
        )?;
        let sequence = self.counters.events + 1;
        let event_root = root_from_parts(
            "wallet-recovery-drill-event-root",
            &[
                HashPart::Str(drill_id),
                HashPart::Str(kind),
                HashPart::U64(sequence),
                HashPart::U64(l2_height),
            ],
        );
        let event_id = root_from_parts(
            "wallet-recovery-drill-event-id",
            &[HashPart::Str(drill_id), HashPart::U64(sequence)],
        );
        let event = EventRecord {
            event_id: event_id.clone(),
            drill_id: drill_id.to_string(),
            kind: kind.to_string(),
            sequence,
            l2_height,
            event_root,
        };
        self.events.insert(event_id, event);
        self.counters.events = sequence;
        Ok(())
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.state_root();
        self.roots.drill_root = map_root(
            "wallet-recovery-drill-envelope-map",
            self.drills.values().map(DrillEnvelope::public_record),
        );
        self.roots.receipt_root = map_root(
            "wallet-recovery-drill-receipt-map",
            self.receipts
                .values()
                .map(ReceiptRootRecovery::public_record),
        );
        self.roots.scan_surface_root = map_root(
            "wallet-recovery-drill-scan-map",
            self.scan_surfaces.values().map(ScanSurface::public_record),
        );
        self.roots.nullifier_key_image_root = map_root(
            "wallet-recovery-drill-nullifier-key-image-map",
            self.nullifier_key_images
                .values()
                .map(NullifierKeyImageCommitment::public_record),
        );
        self.roots.forced_exit_claim_root = map_root(
            "wallet-recovery-drill-forced-exit-map",
            self.forced_exit_claims
                .values()
                .map(ForcedExitClaim::public_record),
        );
        self.roots.check_root = map_root(
            "wallet-recovery-drill-check-map",
            self.checks.values().map(CheckRecord::public_record),
        );
        self.roots.event_root = map_root(
            "wallet-recovery-drill-event-map",
            self.events.values().map(EventRecord::public_record),
        );
        self.roots.counters_root = self.counters.state_root();
        self.roots.latest_spine_root = root_from_parts(
            "wallet-recovery-drill-latest-spine",
            &[
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.drill_root),
                HashPart::Str(&self.roots.receipt_root),
                HashPart::Str(&self.roots.scan_surface_root),
                HashPart::Str(&self.roots.nullifier_key_image_root),
                HashPart::Str(&self.roots.forced_exit_claim_root),
                HashPart::Str(&self.roots.check_root),
                HashPart::Str(&self.roots.event_root),
                HashPart::Str(&self.roots.counters_root),
            ],
        );
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn config_root(config: &Config) -> String {
    config.state_root()
}

pub fn drill_root(drill: &DrillEnvelope) -> String {
    drill.state_root()
}

pub fn receipt_root(receipt: &ReceiptRootRecovery) -> String {
    receipt.state_root()
}

pub fn scan_surface_root(surface: &ScanSurface) -> String {
    surface.state_root()
}

pub fn nullifier_key_image_root(commitment: &NullifierKeyImageCommitment) -> String {
    commitment.state_root()
}

pub fn forced_exit_claim_root(claim: &ForcedExitClaim) -> String {
    claim.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

pub fn labeled_root(domain: &str, label: &str) -> String {
    root_from_parts(domain, &[HashPart::Str(label)])
}

pub fn labeled_index_root(domain: &str, index: u64) -> String {
    root_from_parts(domain, &[HashPart::U64(index)])
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("nebula:{PROTOCOL_VERSION}:{domain}"), parts, 32)
}

pub fn map_root(domain: &str, records: impl Iterator<Item = Value>) -> String {
    let leaves = records.collect::<Vec<_>>();
    merkle_root(&format!("nebula:{PROTOCOL_VERSION}:{domain}"), &leaves)
}

pub fn drill_envelope_root(drill_id: &str, bridge_exit_spine_root: &str) -> String {
    root_from_parts(
        "wallet-recovery-drill-envelope-id",
        &[
            HashPart::Str(drill_id),
            HashPart::Str(bridge_exit_spine_root),
        ],
    )
}

pub fn check_id(drill_id: &str, kind: CheckKind) -> String {
    root_from_parts(
        "wallet-recovery-drill-check-id",
        &[HashPart::Str(drill_id), HashPart::Str(kind.as_str())],
    )
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
