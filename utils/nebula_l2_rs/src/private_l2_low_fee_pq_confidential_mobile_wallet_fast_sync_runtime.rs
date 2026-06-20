use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialMobileWalletFastSyncRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MOBILE_WALLET_FAST_SYNC_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-mobile-wallet-fast-sync-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MOBILE_WALLET_FAST_SYNC_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEW_TAG_ENCRYPTION_SUITE: &str =
    "encrypted-monero-view-tags-ml-kem-1024-chacha20poly1305-root-v1";
pub const PQ_SESSION_ENVELOPE_SUITE: &str =
    "ml-kem-1024+xwing-device-session-envelope-ml-dsa-87-v1";
pub const COMPACT_STATE_DIFF_SUITE: &str =
    "sparse-merkle-confidential-mobile-state-diff-zstd-fec-v1";
pub const SPONSORED_SYNC_BUNDLE_SCHEME: &str =
    "low-fee-sponsored-mobile-wallet-fast-sync-bundle-root-v1";
pub const SUBADDRESS_HINT_SCHEME: &str = "monero-subaddress-hint-commitment-root-v1";
pub const SELECTIVE_DISCLOSURE_AUDIT_SCHEME: &str =
    "viewkey-selective-disclosure-audit-packet-root-v1";
pub const PRECONFIRMATION_CACHE_RECEIPT_SCHEME: &str =
    "private-l2-preconfirmation-cache-receipt-root-v1";
pub const FEE_CAP_POLICY_SCHEME: &str = "mobile-wallet-fast-sync-fee-cap-policy-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_244_160;
pub const DEVNET_EPOCH: u64 = 1_728;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_SYNC_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 216;
pub const DEFAULT_DEVICE_SESSION_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_AUDIT_PACKET_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_MAX_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_MAX_VIEW_TAGS_PER_BUNDLE: u32 = 8_192;
pub const DEFAULT_MAX_DIFF_BYTES: u32 = 196_608;
pub const DEFAULT_MAX_HINTS_PER_BUNDLE: u32 = 256;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_DEVICE_ENVELOPES: usize = 1_048_576;
pub const MAX_VIEW_TAG_BATCHES: usize = 2_097_152;
pub const MAX_STATE_DIFFS: usize = 2_097_152;
pub const MAX_SYNC_BUNDLES: usize = 1_048_576;
pub const MAX_SUBADDRESS_HINTS: usize = 2_097_152;
pub const MAX_AUDIT_PACKETS: usize = 524_288;
pub const MAX_PRECONFIRMATION_RECEIPTS: usize = 2_097_152;
pub const MAX_FEE_CAPS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileSyncLane {
    ForegroundScan,
    BackgroundRefresh,
    MerchantCheckout,
    WatchOnlyAudit,
    RecoveryBootstrap,
    ReorgRepair,
}

impl MobileSyncLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundScan => "foreground_scan",
            Self::BackgroundRefresh => "background_refresh",
            Self::MerchantCheckout => "merchant_checkout",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::RecoveryBootstrap => "recovery_bootstrap",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Draft,
    Sponsored,
    Delivered,
    Receipted,
    Audited,
    Expired,
    Rejected,
}

impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Draft | Self::Sponsored | Self::Delivered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    ViewTagCompleteness,
    SubaddressMembership,
    FeeCapCompliance,
    PreconfirmationInclusion,
    CompactDiffIntegrity,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagCompleteness => "view_tag_completeness",
            Self::SubaddressMembership => "subaddress_membership",
            Self::FeeCapCompliance => "fee_cap_compliance",
            Self::PreconfirmationInclusion => "preconfirmation_inclusion",
            Self::CompactDiffIntegrity => "compact_diff_integrity",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub sync_window_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub device_session_ttl_blocks: u64,
    pub audit_packet_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub max_fee_cap_bps: u64,
    pub max_view_tags_per_bundle: u32,
    pub max_diff_bytes: u32,
    pub max_hints_per_bundle: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            sync_window_blocks: DEFAULT_SYNC_WINDOW_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            device_session_ttl_blocks: DEFAULT_DEVICE_SESSION_TTL_BLOCKS,
            audit_packet_ttl_blocks: DEFAULT_AUDIT_PACKET_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_fee_cap_bps: DEFAULT_MAX_FEE_CAP_BPS,
            max_view_tags_per_bundle: DEFAULT_MAX_VIEW_TAGS_PER_BUNDLE,
            max_diff_bytes: DEFAULT_MAX_DIFF_BYTES,
            max_hints_per_bundle: DEFAULT_MAX_HINTS_PER_BUNDLE,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version: {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure!(!self.l2_network.is_empty(), "l2 network is required");
        ensure!(
            !self.monero_network.is_empty(),
            "monero network is required"
        );
        ensure!(!self.fee_asset_id.is_empty(), "fee asset id is required");
        ensure!(self.sync_window_blocks > 0, "sync window must be nonzero");
        ensure!(self.bundle_ttl_blocks > 0, "bundle ttl must be nonzero");
        ensure!(
            self.device_session_ttl_blocks >= self.bundle_ttl_blocks,
            "device session ttl must cover bundle ttl"
        );
        ensure!(
            self.audit_packet_ttl_blocks >= self.bundle_ttl_blocks,
            "audit packet ttl must cover bundle ttl"
        );
        ensure!(
            self.preconfirmation_ttl_blocks > 0,
            "preconfirmation ttl must be nonzero"
        );
        ensure!(
            self.min_privacy_set_size > 0,
            "min privacy set size must be nonzero"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security bits must not be below minimum"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps exceeds max"
        );
        ensure!(self.max_fee_cap_bps <= MAX_BPS, "fee cap bps exceeds max");
        ensure!(
            self.max_view_tags_per_bundle > 0,
            "max view tags per bundle must be nonzero"
        );
        ensure!(self.max_diff_bytes > 0, "max diff bytes must be nonzero");
        ensure!(
            self.max_hints_per_bundle > 0,
            "max hints per bundle must be nonzero"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "sync_window_blocks": self.sync_window_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "device_session_ttl_blocks": self.device_session_ttl_blocks,
            "audit_packet_ttl_blocks": self.audit_packet_ttl_blocks,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_fee_cap_bps": self.max_fee_cap_bps,
            "max_view_tags_per_bundle": self.max_view_tags_per_bundle,
            "max_diff_bytes": self.max_diff_bytes,
            "max_hints_per_bundle": self.max_hints_per_bundle,
            "hash_suite": HASH_SUITE,
            "view_tag_encryption_suite": VIEW_TAG_ENCRYPTION_SUITE,
            "pq_session_envelope_suite": PQ_SESSION_ENVELOPE_SUITE,
            "compact_state_diff_suite": COMPACT_STATE_DIFF_SUITE,
        })
    }

    pub fn config_id(&self) -> String {
        config_id_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub device_envelopes: u64,
    pub view_tag_batches: u64,
    pub compact_state_diffs: u64,
    pub sponsored_sync_bundles: u64,
    pub subaddress_hints: u64,
    pub audit_packets: u64,
    pub preconfirmation_receipts: u64,
    pub fee_caps: u64,
    pub rejected_requests: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "device_envelopes": self.device_envelopes,
            "view_tag_batches": self.view_tag_batches,
            "compact_state_diffs": self.compact_state_diffs,
            "sponsored_sync_bundles": self.sponsored_sync_bundles,
            "subaddress_hints": self.subaddress_hints,
            "audit_packets": self.audit_packets,
            "preconfirmation_receipts": self.preconfirmation_receipts,
            "fee_caps": self.fee_caps,
            "rejected_requests": self.rejected_requests,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub device_envelope_root: String,
    pub view_tag_batch_root: String,
    pub compact_state_diff_root: String,
    pub sponsored_sync_bundle_root: String,
    pub subaddress_hint_root: String,
    pub audit_packet_root: String,
    pub preconfirmation_receipt_root: String,
    pub fee_cap_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "device_envelope_root": self.device_envelope_root,
            "view_tag_batch_root": self.view_tag_batch_root,
            "compact_state_diff_root": self.compact_state_diff_root,
            "sponsored_sync_bundle_root": self.sponsored_sync_bundle_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "audit_packet_root": self.audit_packet_root,
            "preconfirmation_receipt_root": self.preconfirmation_receipt_root,
            "fee_cap_root": self.fee_cap_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSessionDeviceEnvelope {
    pub envelope_id: String,
    pub wallet_id: String,
    pub device_id: String,
    pub session_epoch: u64,
    pub pq_public_key_root: String,
    pub encrypted_session_root: String,
    pub device_policy_root: String,
    pub attestation_root: String,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
}

impl PqSessionDeviceEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "wallet_id": self.wallet_id,
            "device_id": self.device_id,
            "session_epoch": self.session_epoch,
            "pq_public_key_root": self.pq_public_key_root,
            "encrypted_session_root": self.encrypted_session_root,
            "device_policy_root": self.device_policy_root,
            "attestation_root": self.attestation_root,
            "expires_at_height": self.expires_at_height,
            "pq_security_bits": self.pq_security_bits,
            "suite": PQ_SESSION_ENVELOPE_SUITE,
        })
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(!self.envelope_id.is_empty(), "envelope id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(!self.device_id.is_empty(), "device id is required");
        ensure!(
            self.expires_at_height > height,
            "device envelope must expire in the future"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "device envelope pq security is below minimum"
        );
        ensure!(
            !self.pq_public_key_root.is_empty()
                && !self.encrypted_session_root.is_empty()
                && !self.device_policy_root.is_empty()
                && !self.attestation_root.is_empty(),
            "device envelope roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedViewTagBatch {
    pub batch_id: String,
    pub wallet_id: String,
    pub envelope_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub encrypted_view_tag_root: String,
    pub output_commitment_root: String,
    pub tag_count: u32,
    pub privacy_set_size: u64,
}

impl EncryptedViewTagBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "wallet_id": self.wallet_id,
            "envelope_id": self.envelope_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "encrypted_view_tag_root": self.encrypted_view_tag_root,
            "output_commitment_root": self.output_commitment_root,
            "tag_count": self.tag_count,
            "privacy_set_size": self.privacy_set_size,
            "suite": VIEW_TAG_ENCRYPTION_SUITE,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.batch_id.is_empty(), "view tag batch id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(!self.envelope_id.is_empty(), "envelope id is required");
        ensure!(self.start_height <= self.end_height, "invalid scan range");
        ensure!(
            self.end_height.saturating_sub(self.start_height) <= config.sync_window_blocks,
            "view tag batch exceeds sync window"
        );
        ensure!(self.tag_count > 0, "view tag count must be nonzero");
        ensure!(
            self.tag_count <= config.max_view_tags_per_bundle,
            "view tag count exceeds config max"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "view tag privacy set is too small"
        );
        ensure!(
            !self.encrypted_view_tag_root.is_empty() && !self.output_commitment_root.is_empty(),
            "view tag roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompactStateDiff {
    pub diff_id: String,
    pub wallet_id: String,
    pub base_state_root: String,
    pub diff_root: String,
    pub result_state_root: String,
    pub compressed_bytes: u32,
    pub changed_leaf_count: u32,
    pub nullifier_commitment: String,
}

impl CompactStateDiff {
    pub fn public_record(&self) -> Value {
        json!({
            "diff_id": self.diff_id,
            "wallet_id": self.wallet_id,
            "base_state_root": self.base_state_root,
            "diff_root": self.diff_root,
            "result_state_root": self.result_state_root,
            "compressed_bytes": self.compressed_bytes,
            "changed_leaf_count": self.changed_leaf_count,
            "nullifier_commitment": self.nullifier_commitment,
            "suite": COMPACT_STATE_DIFF_SUITE,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.diff_id.is_empty(), "diff id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(
            self.compressed_bytes > 0 && self.compressed_bytes <= config.max_diff_bytes,
            "compact state diff byte size is outside bounds"
        );
        ensure!(
            self.changed_leaf_count > 0,
            "compact state diff must include changed leaves"
        );
        ensure!(
            !self.base_state_root.is_empty()
                && !self.diff_root.is_empty()
                && !self.result_state_root.is_empty()
                && !self.nullifier_commitment.is_empty(),
            "compact state diff roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroSubaddressHint {
    pub hint_id: String,
    pub wallet_id: String,
    pub subaddress_hint_root: String,
    pub major_index_commitment: String,
    pub minor_index_range_root: String,
    pub payment_id_hint_root: String,
    pub decoy_set_root: String,
}

impl MoneroSubaddressHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "wallet_id": self.wallet_id,
            "subaddress_hint_root": self.subaddress_hint_root,
            "major_index_commitment": self.major_index_commitment,
            "minor_index_range_root": self.minor_index_range_root,
            "payment_id_hint_root": self.payment_id_hint_root,
            "decoy_set_root": self.decoy_set_root,
            "scheme": SUBADDRESS_HINT_SCHEME,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.hint_id.is_empty(), "subaddress hint id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(
            !self.subaddress_hint_root.is_empty()
                && !self.major_index_commitment.is_empty()
                && !self.minor_index_range_root.is_empty()
                && !self.payment_id_hint_root.is_empty()
                && !self.decoy_set_root.is_empty(),
            "subaddress hint roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub fee_cap_id: String,
    pub wallet_id: String,
    pub sponsor_id: String,
    pub max_user_fee_micro_units: u64,
    pub max_fee_cap_bps: u64,
    pub sponsor_cover_bps: u64,
    pub fee_asset_id: String,
    pub policy_root: String,
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "wallet_id": self.wallet_id,
            "sponsor_id": self.sponsor_id,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "max_fee_cap_bps": self.max_fee_cap_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "fee_asset_id": self.fee_asset_id,
            "policy_root": self.policy_root,
            "scheme": FEE_CAP_POLICY_SCHEME,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.fee_cap_id.is_empty(), "fee cap id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(!self.sponsor_id.is_empty(), "sponsor id is required");
        ensure!(
            self.max_user_fee_micro_units <= config.max_user_fee_micro_units,
            "user fee exceeds configured cap"
        );
        ensure!(
            self.max_fee_cap_bps <= config.max_fee_cap_bps,
            "fee cap bps exceeds configured cap"
        );
        ensure!(
            self.sponsor_cover_bps >= config.sponsor_cover_bps && self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps is outside bounds"
        );
        ensure!(
            self.fee_asset_id == config.fee_asset_id,
            "fee cap asset does not match config"
        );
        ensure!(
            !self.policy_root.is_empty(),
            "fee cap policy root is required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredSyncBundle {
    pub bundle_id: String,
    pub wallet_id: String,
    pub sponsor_id: String,
    pub lane: MobileSyncLane,
    pub envelope_id: String,
    pub view_tag_batch_ids: BTreeSet<String>,
    pub state_diff_ids: BTreeSet<String>,
    pub subaddress_hint_ids: BTreeSet<String>,
    pub fee_cap_id: String,
    pub fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub valid_until_height: u64,
    pub status: BundleStatus,
}

impl SponsoredSyncBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "wallet_id": self.wallet_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "envelope_id": self.envelope_id,
            "view_tag_batch_ids": self.view_tag_batch_ids.iter().cloned().collect::<Vec<_>>(),
            "state_diff_ids": self.state_diff_ids.iter().cloned().collect::<Vec<_>>(),
            "subaddress_hint_ids": self.subaddress_hint_ids.iter().cloned().collect::<Vec<_>>(),
            "fee_cap_id": self.fee_cap_id,
            "fee_micro_units": self.fee_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "valid_until_height": self.valid_until_height,
            "status": self.status,
            "scheme": SPONSORED_SYNC_BUNDLE_SCHEME,
        })
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(!self.bundle_id.is_empty(), "bundle id is required");
        ensure!(!self.wallet_id.is_empty(), "wallet id is required");
        ensure!(!self.sponsor_id.is_empty(), "sponsor id is required");
        ensure!(!self.envelope_id.is_empty(), "envelope id is required");
        ensure!(!self.fee_cap_id.is_empty(), "fee cap id is required");
        ensure!(
            !self.view_tag_batch_ids.is_empty() || !self.state_diff_ids.is_empty(),
            "sync bundle must include view tags or state diffs"
        );
        ensure!(
            self.subaddress_hint_ids.len() <= config.max_hints_per_bundle as usize,
            "sync bundle has too many subaddress hints"
        );
        ensure!(
            self.fee_micro_units <= config.max_user_fee_micro_units,
            "sync bundle fee exceeds configured cap"
        );
        ensure!(
            self.sponsor_paid_micro_units >= self.fee_micro_units,
            "sponsor payment must cover user fee"
        );
        ensure!(
            self.valid_until_height > height,
            "sync bundle must expire in the future"
        );
        ensure!(self.status.live(), "sync bundle must be in a live status");
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureAuditPacket {
    pub audit_packet_id: String,
    pub bundle_id: String,
    pub auditor_id: String,
    pub disclosure_scopes: BTreeSet<DisclosureScope>,
    pub disclosed_root: String,
    pub redaction_root: String,
    pub proof_root: String,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureAuditPacket {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_packet_id": self.audit_packet_id,
            "bundle_id": self.bundle_id,
            "auditor_id": self.auditor_id,
            "disclosure_scopes": self.disclosure_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "disclosed_root": self.disclosed_root,
            "redaction_root": self.redaction_root,
            "proof_root": self.proof_root,
            "expires_at_height": self.expires_at_height,
            "scheme": SELECTIVE_DISCLOSURE_AUDIT_SCHEME,
        })
    }

    pub fn validate(&self, height: u64) -> Result<()> {
        ensure!(
            !self.audit_packet_id.is_empty(),
            "audit packet id is required"
        );
        ensure!(!self.bundle_id.is_empty(), "bundle id is required");
        ensure!(!self.auditor_id.is_empty(), "auditor id is required");
        ensure!(
            !self.disclosure_scopes.is_empty(),
            "audit packet requires disclosure scopes"
        );
        ensure!(
            self.expires_at_height > height,
            "audit packet must expire in the future"
        );
        ensure!(
            !self.disclosed_root.is_empty()
                && !self.redaction_root.is_empty()
                && !self.proof_root.is_empty(),
            "audit packet roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationCacheReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub sequencer_id: String,
    pub preconfirmation_height: u64,
    pub cache_root_before: String,
    pub cache_root_after: String,
    pub inclusion_root: String,
    pub fee_receipt_root: String,
}

impl PreconfirmationCacheReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "sequencer_id": self.sequencer_id,
            "preconfirmation_height": self.preconfirmation_height,
            "cache_root_before": self.cache_root_before,
            "cache_root_after": self.cache_root_after,
            "inclusion_root": self.inclusion_root,
            "fee_receipt_root": self.fee_receipt_root,
            "scheme": PRECONFIRMATION_CACHE_RECEIPT_SCHEME,
        })
    }

    pub fn validate(&self, height: u64, ttl_blocks: u64) -> Result<()> {
        ensure!(!self.receipt_id.is_empty(), "receipt id is required");
        ensure!(!self.bundle_id.is_empty(), "bundle id is required");
        ensure!(!self.sequencer_id.is_empty(), "sequencer id is required");
        ensure!(
            self.preconfirmation_height <= height.saturating_add(ttl_blocks),
            "preconfirmation height is outside ttl horizon"
        );
        ensure!(
            !self.cache_root_before.is_empty()
                && !self.cache_root_after.is_empty()
                && !self.inclusion_root.is_empty()
                && !self.fee_receipt_root.is_empty(),
            "preconfirmation receipt roots are required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceEnvelopeRequest {
    pub wallet_id: String,
    pub device_id: String,
    pub session_epoch: u64,
    pub pq_public_key_root: String,
    pub encrypted_session_root: String,
    pub device_policy_root: String,
    pub attestation_root: String,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagBatchRequest {
    pub wallet_id: String,
    pub envelope_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub encrypted_view_tag_root: String,
    pub output_commitment_root: String,
    pub tag_count: u32,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompactStateDiffRequest {
    pub wallet_id: String,
    pub base_state_root: String,
    pub diff_root: String,
    pub result_state_root: String,
    pub compressed_bytes: u32,
    pub changed_leaf_count: u32,
    pub nullifier_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroSubaddressHintRequest {
    pub wallet_id: String,
    pub subaddress_hint_root: String,
    pub major_index_commitment: String,
    pub minor_index_range_root: String,
    pub payment_id_hint_root: String,
    pub decoy_set_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCapRequest {
    pub wallet_id: String,
    pub sponsor_id: String,
    pub max_user_fee_micro_units: u64,
    pub max_fee_cap_bps: u64,
    pub sponsor_cover_bps: u64,
    pub policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredSyncBundleRequest {
    pub wallet_id: String,
    pub sponsor_id: String,
    pub lane: MobileSyncLane,
    pub envelope_id: String,
    pub view_tag_batch_ids: BTreeSet<String>,
    pub state_diff_ids: BTreeSet<String>,
    pub subaddress_hint_ids: BTreeSet<String>,
    pub fee_cap_id: String,
    pub fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureAuditRequest {
    pub bundle_id: String,
    pub auditor_id: String,
    pub disclosure_scopes: BTreeSet<DisclosureScope>,
    pub disclosed_root: String,
    pub redaction_root: String,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationCacheReceiptRequest {
    pub bundle_id: String,
    pub sequencer_id: String,
    pub preconfirmation_height: u64,
    pub cache_root_before: String,
    pub cache_root_after: String,
    pub inclusion_root: String,
    pub fee_receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub device_envelopes: BTreeMap<String, PqSessionDeviceEnvelope>,
    pub view_tag_batches: BTreeMap<String, EncryptedViewTagBatch>,
    pub compact_state_diffs: BTreeMap<String, CompactStateDiff>,
    pub sponsored_sync_bundles: BTreeMap<String, SponsoredSyncBundle>,
    pub subaddress_hints: BTreeMap<String, MoneroSubaddressHint>,
    pub audit_packets: BTreeMap<String, SelectiveDisclosureAuditPacket>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationCacheReceipt>,
    pub fee_caps: BTreeMap<String, FeeCap>,
    pub spent_nullifiers: BTreeSet<String>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            epoch,
            device_envelopes: BTreeMap::new(),
            view_tag_batches: BTreeMap::new(),
            compact_state_diffs: BTreeMap::new(),
            sponsored_sync_bundles: BTreeMap::new(),
            subaddress_hints: BTreeMap::new(),
            audit_packets: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            counters: Counters::default(),
        })
    }

    pub fn devnet() -> Self {
        Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            device_envelopes: BTreeMap::new(),
            view_tag_batches: BTreeMap::new(),
            compact_state_diffs: BTreeMap::new(),
            sponsored_sync_bundles: BTreeMap::new(),
            subaddress_hints: BTreeMap::new(),
            audit_packets: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            counters: Counters::default(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let envelope = state
            .register_device_envelope(DeviceEnvelopeRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                device_id: "ios-secure-enclave-alpha".to_string(),
                session_epoch: DEVNET_EPOCH,
                pq_public_key_root: devnet_payload_root("pq-public-key", "alpha"),
                encrypted_session_root: devnet_payload_root("encrypted-session", "alpha"),
                device_policy_root: devnet_payload_root("device-policy", "alpha"),
                attestation_root: devnet_payload_root("device-attestation", "alpha"),
                pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            })
            .ok();
        let envelope_id = match envelope {
            Some(record) => record.envelope_id,
            None => "devnet-envelope-fallback".to_string(),
        };
        let view_batch = state
            .add_view_tag_batch(ViewTagBatchRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                envelope_id: envelope_id.clone(),
                start_height: DEVNET_HEIGHT.saturating_sub(64),
                end_height: DEVNET_HEIGHT,
                encrypted_view_tag_root: devnet_payload_root("encrypted-view-tags", "alpha"),
                output_commitment_root: devnet_payload_root("output-commitments", "alpha"),
                tag_count: 512,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            })
            .ok();
        let diff = state
            .add_compact_state_diff(CompactStateDiffRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                base_state_root: devnet_payload_root("base-state", "alpha"),
                diff_root: devnet_payload_root("compact-diff", "alpha"),
                result_state_root: devnet_payload_root("result-state", "alpha"),
                compressed_bytes: 24_576,
                changed_leaf_count: 48,
                nullifier_commitment: devnet_payload_root("nullifier", "alpha"),
            })
            .ok();
        let hint = state
            .add_subaddress_hint(MoneroSubaddressHintRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                subaddress_hint_root: devnet_payload_root("subaddress-hint", "alpha"),
                major_index_commitment: devnet_payload_root("major-index", "alpha"),
                minor_index_range_root: devnet_payload_root("minor-range", "alpha"),
                payment_id_hint_root: devnet_payload_root("payment-id", "alpha"),
                decoy_set_root: devnet_payload_root("decoy-set", "alpha"),
            })
            .ok();
        let fee_cap = state
            .add_fee_cap(FeeCapRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                sponsor_id: "devnet-low-fee-sync-sponsor".to_string(),
                max_user_fee_micro_units: 1_250,
                max_fee_cap_bps: 8,
                sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
                policy_root: devnet_payload_root("fee-cap-policy", "alpha"),
            })
            .ok();
        if let (Some(view_batch), Some(diff), Some(hint), Some(fee_cap)) =
            (view_batch, diff, hint, fee_cap)
        {
            let mut view_tag_batch_ids = BTreeSet::new();
            view_tag_batch_ids.insert(view_batch.batch_id);
            let mut state_diff_ids = BTreeSet::new();
            state_diff_ids.insert(diff.diff_id);
            let mut subaddress_hint_ids = BTreeSet::new();
            subaddress_hint_ids.insert(hint.hint_id);
            if let Ok(bundle) = state.add_sponsored_sync_bundle(SponsoredSyncBundleRequest {
                wallet_id: "devnet-mobile-wallet-alpha".to_string(),
                sponsor_id: "devnet-low-fee-sync-sponsor".to_string(),
                lane: MobileSyncLane::ForegroundScan,
                envelope_id,
                view_tag_batch_ids,
                state_diff_ids,
                subaddress_hint_ids,
                fee_cap_id: fee_cap.fee_cap_id,
                fee_micro_units: 1_000,
                sponsor_paid_micro_units: 1_000,
            }) {
                let mut scopes = BTreeSet::new();
                scopes.insert(DisclosureScope::ViewTagCompleteness);
                scopes.insert(DisclosureScope::FeeCapCompliance);
                let _ = state.add_audit_packet(SelectiveDisclosureAuditRequest {
                    bundle_id: bundle.bundle_id.clone(),
                    auditor_id: "devnet-viewkey-auditor".to_string(),
                    disclosure_scopes: scopes,
                    disclosed_root: devnet_payload_root("audit-disclosed", "alpha"),
                    redaction_root: devnet_payload_root("audit-redaction", "alpha"),
                    proof_root: devnet_payload_root("audit-proof", "alpha"),
                });
                let _ = state.add_preconfirmation_receipt(PreconfirmationCacheReceiptRequest {
                    bundle_id: bundle.bundle_id,
                    sequencer_id: "devnet-fast-sync-sequencer".to_string(),
                    preconfirmation_height: DEVNET_HEIGHT.saturating_add(1),
                    cache_root_before: devnet_payload_root("cache-before", "alpha"),
                    cache_root_after: devnet_payload_root("cache-after", "alpha"),
                    inclusion_root: devnet_payload_root("cache-inclusion", "alpha"),
                    fee_receipt_root: devnet_payload_root("fee-receipt", "alpha"),
                });
            }
        }
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.device_envelopes.len() <= MAX_DEVICE_ENVELOPES,
            "too many device envelopes"
        );
        ensure!(
            self.view_tag_batches.len() <= MAX_VIEW_TAG_BATCHES,
            "too many view tag batches"
        );
        ensure!(
            self.compact_state_diffs.len() <= MAX_STATE_DIFFS,
            "too many compact state diffs"
        );
        ensure!(
            self.sponsored_sync_bundles.len() <= MAX_SYNC_BUNDLES,
            "too many sponsored sync bundles"
        );
        ensure!(
            self.subaddress_hints.len() <= MAX_SUBADDRESS_HINTS,
            "too many subaddress hints"
        );
        ensure!(
            self.audit_packets.len() <= MAX_AUDIT_PACKETS,
            "too many audit packets"
        );
        ensure!(
            self.preconfirmation_receipts.len() <= MAX_PRECONFIRMATION_RECEIPTS,
            "too many preconfirmation receipts"
        );
        ensure!(self.fee_caps.len() <= MAX_FEE_CAPS, "too many fee caps");
        for envelope in self.device_envelopes.values() {
            envelope.validate(&self.config, self.height)?;
        }
        for batch in self.view_tag_batches.values() {
            batch.validate(&self.config)?;
            ensure!(
                self.device_envelopes.contains_key(&batch.envelope_id),
                "view tag batch references unknown envelope {}",
                batch.envelope_id
            );
        }
        for diff in self.compact_state_diffs.values() {
            diff.validate(&self.config)?;
        }
        for hint in self.subaddress_hints.values() {
            hint.validate()?;
        }
        for fee_cap in self.fee_caps.values() {
            fee_cap.validate(&self.config)?;
        }
        for bundle in self.sponsored_sync_bundles.values() {
            bundle.validate(&self.config, self.height)?;
            self.validate_bundle_references(bundle)?;
        }
        for packet in self.audit_packets.values() {
            packet.validate(self.height)?;
            ensure!(
                self.sponsored_sync_bundles.contains_key(&packet.bundle_id),
                "audit packet references unknown bundle {}",
                packet.bundle_id
            );
        }
        for receipt in self.preconfirmation_receipts.values() {
            receipt.validate(self.height, self.config.preconfirmation_ttl_blocks)?;
            ensure!(
                self.sponsored_sync_bundles.contains_key(&receipt.bundle_id),
                "receipt references unknown bundle {}",
                receipt.bundle_id
            );
        }
        Ok(())
    }

    pub fn register_device_envelope(
        &mut self,
        request: DeviceEnvelopeRequest,
    ) -> Result<PqSessionDeviceEnvelope> {
        ensure!(
            self.device_envelopes.len() < MAX_DEVICE_ENVELOPES,
            "device envelope capacity reached"
        );
        let envelope = PqSessionDeviceEnvelope {
            envelope_id: device_envelope_id(&request),
            wallet_id: request.wallet_id,
            device_id: request.device_id,
            session_epoch: request.session_epoch,
            pq_public_key_root: request.pq_public_key_root,
            encrypted_session_root: request.encrypted_session_root,
            device_policy_root: request.device_policy_root,
            attestation_root: request.attestation_root,
            expires_at_height: self
                .height
                .saturating_add(self.config.device_session_ttl_blocks),
            pq_security_bits: request.pq_security_bits,
        };
        envelope.validate(&self.config, self.height)?;
        self.device_envelopes
            .insert(envelope.envelope_id.clone(), envelope.clone());
        self.counters.device_envelopes = self.counters.device_envelopes.saturating_add(1);
        Ok(envelope)
    }

    pub fn add_view_tag_batch(
        &mut self,
        request: ViewTagBatchRequest,
    ) -> Result<EncryptedViewTagBatch> {
        ensure!(
            self.view_tag_batches.len() < MAX_VIEW_TAG_BATCHES,
            "view tag batch capacity reached"
        );
        ensure!(
            self.device_envelopes.contains_key(&request.envelope_id),
            "unknown device envelope {}",
            request.envelope_id
        );
        let batch = EncryptedViewTagBatch {
            batch_id: view_tag_batch_id(&request),
            wallet_id: request.wallet_id,
            envelope_id: request.envelope_id,
            start_height: request.start_height,
            end_height: request.end_height,
            encrypted_view_tag_root: request.encrypted_view_tag_root,
            output_commitment_root: request.output_commitment_root,
            tag_count: request.tag_count,
            privacy_set_size: request.privacy_set_size,
        };
        batch.validate(&self.config)?;
        self.view_tag_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.counters.view_tag_batches = self.counters.view_tag_batches.saturating_add(1);
        Ok(batch)
    }

    pub fn add_compact_state_diff(
        &mut self,
        request: CompactStateDiffRequest,
    ) -> Result<CompactStateDiff> {
        ensure!(
            self.compact_state_diffs.len() < MAX_STATE_DIFFS,
            "compact state diff capacity reached"
        );
        ensure!(
            !self
                .spent_nullifiers
                .contains(&request.nullifier_commitment),
            "compact state diff nullifier already used"
        );
        let diff = CompactStateDiff {
            diff_id: compact_state_diff_id(&request),
            wallet_id: request.wallet_id,
            base_state_root: request.base_state_root,
            diff_root: request.diff_root,
            result_state_root: request.result_state_root,
            compressed_bytes: request.compressed_bytes,
            changed_leaf_count: request.changed_leaf_count,
            nullifier_commitment: request.nullifier_commitment,
        };
        diff.validate(&self.config)?;
        self.spent_nullifiers
            .insert(diff.nullifier_commitment.clone());
        self.compact_state_diffs
            .insert(diff.diff_id.clone(), diff.clone());
        self.counters.compact_state_diffs = self.counters.compact_state_diffs.saturating_add(1);
        Ok(diff)
    }

    pub fn add_subaddress_hint(
        &mut self,
        request: MoneroSubaddressHintRequest,
    ) -> Result<MoneroSubaddressHint> {
        ensure!(
            self.subaddress_hints.len() < MAX_SUBADDRESS_HINTS,
            "subaddress hint capacity reached"
        );
        let hint = MoneroSubaddressHint {
            hint_id: subaddress_hint_id(&request),
            wallet_id: request.wallet_id,
            subaddress_hint_root: request.subaddress_hint_root,
            major_index_commitment: request.major_index_commitment,
            minor_index_range_root: request.minor_index_range_root,
            payment_id_hint_root: request.payment_id_hint_root,
            decoy_set_root: request.decoy_set_root,
        };
        hint.validate()?;
        self.subaddress_hints
            .insert(hint.hint_id.clone(), hint.clone());
        self.counters.subaddress_hints = self.counters.subaddress_hints.saturating_add(1);
        Ok(hint)
    }

    pub fn add_fee_cap(&mut self, request: FeeCapRequest) -> Result<FeeCap> {
        ensure!(
            self.fee_caps.len() < MAX_FEE_CAPS,
            "fee cap capacity reached"
        );
        let fee_cap = FeeCap {
            fee_cap_id: fee_cap_id(&request, &self.config.fee_asset_id),
            wallet_id: request.wallet_id,
            sponsor_id: request.sponsor_id,
            max_user_fee_micro_units: request.max_user_fee_micro_units,
            max_fee_cap_bps: request.max_fee_cap_bps,
            sponsor_cover_bps: request.sponsor_cover_bps,
            fee_asset_id: self.config.fee_asset_id.clone(),
            policy_root: request.policy_root,
        };
        fee_cap.validate(&self.config)?;
        self.fee_caps
            .insert(fee_cap.fee_cap_id.clone(), fee_cap.clone());
        self.counters.fee_caps = self.counters.fee_caps.saturating_add(1);
        Ok(fee_cap)
    }

    pub fn add_sponsored_sync_bundle(
        &mut self,
        request: SponsoredSyncBundleRequest,
    ) -> Result<SponsoredSyncBundle> {
        ensure!(
            self.sponsored_sync_bundles.len() < MAX_SYNC_BUNDLES,
            "sponsored sync bundle capacity reached"
        );
        let bundle = SponsoredSyncBundle {
            bundle_id: sync_bundle_id(&request),
            wallet_id: request.wallet_id,
            sponsor_id: request.sponsor_id,
            lane: request.lane,
            envelope_id: request.envelope_id,
            view_tag_batch_ids: request.view_tag_batch_ids,
            state_diff_ids: request.state_diff_ids,
            subaddress_hint_ids: request.subaddress_hint_ids,
            fee_cap_id: request.fee_cap_id,
            fee_micro_units: request.fee_micro_units,
            sponsor_paid_micro_units: request.sponsor_paid_micro_units,
            valid_until_height: self.height.saturating_add(self.config.bundle_ttl_blocks),
            status: BundleStatus::Sponsored,
        };
        bundle.validate(&self.config, self.height)?;
        self.validate_bundle_references(&bundle)?;
        self.sponsored_sync_bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        self.counters.sponsored_sync_bundles =
            self.counters.sponsored_sync_bundles.saturating_add(1);
        Ok(bundle)
    }

    pub fn add_audit_packet(
        &mut self,
        request: SelectiveDisclosureAuditRequest,
    ) -> Result<SelectiveDisclosureAuditPacket> {
        ensure!(
            self.audit_packets.len() < MAX_AUDIT_PACKETS,
            "audit packet capacity reached"
        );
        ensure!(
            self.sponsored_sync_bundles.contains_key(&request.bundle_id),
            "unknown sync bundle {}",
            request.bundle_id
        );
        let packet = SelectiveDisclosureAuditPacket {
            audit_packet_id: audit_packet_id(&request),
            bundle_id: request.bundle_id,
            auditor_id: request.auditor_id,
            disclosure_scopes: request.disclosure_scopes,
            disclosed_root: request.disclosed_root,
            redaction_root: request.redaction_root,
            proof_root: request.proof_root,
            expires_at_height: self
                .height
                .saturating_add(self.config.audit_packet_ttl_blocks),
        };
        packet.validate(self.height)?;
        self.audit_packets
            .insert(packet.audit_packet_id.clone(), packet.clone());
        self.counters.audit_packets = self.counters.audit_packets.saturating_add(1);
        Ok(packet)
    }

    pub fn add_preconfirmation_receipt(
        &mut self,
        request: PreconfirmationCacheReceiptRequest,
    ) -> Result<PreconfirmationCacheReceipt> {
        ensure!(
            self.preconfirmation_receipts.len() < MAX_PRECONFIRMATION_RECEIPTS,
            "preconfirmation receipt capacity reached"
        );
        ensure!(
            self.sponsored_sync_bundles.contains_key(&request.bundle_id),
            "unknown sync bundle {}",
            request.bundle_id
        );
        let receipt = PreconfirmationCacheReceipt {
            receipt_id: preconfirmation_receipt_id(&request),
            bundle_id: request.bundle_id,
            sequencer_id: request.sequencer_id,
            preconfirmation_height: request.preconfirmation_height,
            cache_root_before: request.cache_root_before,
            cache_root_after: request.cache_root_after,
            inclusion_root: request.inclusion_root,
            fee_receipt_root: request.fee_receipt_root,
        };
        receipt.validate(self.height, self.config.preconfirmation_ttl_blocks)?;
        self.preconfirmation_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.counters.preconfirmation_receipts =
            self.counters.preconfirmation_receipts.saturating_add(1);
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let config_root = config_id_from_record(&self.config.public_record());
        let device_records = self
            .device_envelopes
            .values()
            .map(PqSessionDeviceEnvelope::public_record)
            .collect::<Vec<_>>();
        let view_tag_records = self
            .view_tag_batches
            .values()
            .map(EncryptedViewTagBatch::public_record)
            .collect::<Vec<_>>();
        let diff_records = self
            .compact_state_diffs
            .values()
            .map(CompactStateDiff::public_record)
            .collect::<Vec<_>>();
        let bundle_records = self
            .sponsored_sync_bundles
            .values()
            .map(SponsoredSyncBundle::public_record)
            .collect::<Vec<_>>();
        let hint_records = self
            .subaddress_hints
            .values()
            .map(MoneroSubaddressHint::public_record)
            .collect::<Vec<_>>();
        let audit_records = self
            .audit_packets
            .values()
            .map(SelectiveDisclosureAuditPacket::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .preconfirmation_receipts
            .values()
            .map(PreconfirmationCacheReceipt::public_record)
            .collect::<Vec<_>>();
        let fee_cap_records = self
            .fee_caps
            .values()
            .map(FeeCap::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        let mut roots = Roots {
            config_root,
            device_envelope_root: merkle_root("MOBILE-FAST-SYNC-DEVICE-ENVELOPE", &device_records),
            view_tag_batch_root: merkle_root("MOBILE-FAST-SYNC-VIEW-TAG-BATCH", &view_tag_records),
            compact_state_diff_root: merkle_root("MOBILE-FAST-SYNC-COMPACT-DIFF", &diff_records),
            sponsored_sync_bundle_root: merkle_root("MOBILE-FAST-SYNC-BUNDLE", &bundle_records),
            subaddress_hint_root: merkle_root("MOBILE-FAST-SYNC-SUBADDRESS-HINT", &hint_records),
            audit_packet_root: merkle_root("MOBILE-FAST-SYNC-AUDIT-PACKET", &audit_records),
            preconfirmation_receipt_root: merkle_root(
                "MOBILE-FAST-SYNC-PRECONFIRMATION-RECEIPT",
                &receipt_records,
            ),
            fee_cap_root: merkle_root("MOBILE-FAST-SYNC-FEE-CAP", &fee_cap_records),
            nullifier_root: merkle_root("MOBILE-FAST-SYNC-NULLIFIER", &nullifier_records),
            state_root: String::new(),
        };
        roots.state_root = mobile_fast_sync_state_root_from_record(&json!({
            "height": self.height,
            "epoch": self.epoch,
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        }));
        roots
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn validate_bundle_references(&self, bundle: &SponsoredSyncBundle) -> Result<()> {
        ensure!(
            self.device_envelopes.contains_key(&bundle.envelope_id),
            "bundle references unknown envelope {}",
            bundle.envelope_id
        );
        ensure!(
            self.fee_caps.contains_key(&bundle.fee_cap_id),
            "bundle references unknown fee cap {}",
            bundle.fee_cap_id
        );
        for batch_id in &bundle.view_tag_batch_ids {
            ensure!(
                self.view_tag_batches.contains_key(batch_id),
                "bundle references unknown view tag batch {}",
                batch_id
            );
        }
        for diff_id in &bundle.state_diff_ids {
            ensure!(
                self.compact_state_diffs.contains_key(diff_id),
                "bundle references unknown state diff {}",
                diff_id
            );
        }
        for hint_id in &bundle.subaddress_hint_ids {
            ensure!(
                self.subaddress_hints.contains_key(hint_id),
                "bundle references unknown subaddress hint {}",
                hint_id
            );
        }
        Ok(())
    }
}

pub fn config_id_from_record(record: &Value) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-CONFIG-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn mobile_fast_sync_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn device_envelope_id(request: &DeviceEnvelopeRequest) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-DEVICE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_id),
            HashPart::Str(&request.device_id),
            HashPart::U64(request.session_epoch),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.encrypted_session_root),
        ],
        32,
    )
}

pub fn view_tag_batch_id(request: &ViewTagBatchRequest) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-VIEW-TAG-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_id),
            HashPart::Str(&request.envelope_id),
            HashPart::U64(request.start_height),
            HashPart::U64(request.end_height),
            HashPart::Str(&request.encrypted_view_tag_root),
            HashPart::Str(&request.output_commitment_root),
        ],
        32,
    )
}

pub fn compact_state_diff_id(request: &CompactStateDiffRequest) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-COMPACT-STATE-DIFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_id),
            HashPart::Str(&request.base_state_root),
            HashPart::Str(&request.diff_root),
            HashPart::Str(&request.result_state_root),
            HashPart::Str(&request.nullifier_commitment),
        ],
        32,
    )
}

pub fn subaddress_hint_id(request: &MoneroSubaddressHintRequest) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-SUBADDRESS-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_id),
            HashPart::Str(&request.subaddress_hint_root),
            HashPart::Str(&request.major_index_commitment),
            HashPart::Str(&request.minor_index_range_root),
        ],
        32,
    )
}

pub fn fee_cap_id(request: &FeeCapRequest, fee_asset_id: &str) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-FEE-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(fee_asset_id),
            HashPart::U64(request.max_user_fee_micro_units),
            HashPart::U64(request.max_fee_cap_bps),
            HashPart::Str(&request.policy_root),
        ],
        32,
    )
}

pub fn sync_bundle_id(request: &SponsoredSyncBundleRequest) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "wallet_id": request.wallet_id,
        "sponsor_id": request.sponsor_id,
        "lane": request.lane.as_str(),
        "envelope_id": request.envelope_id,
        "view_tag_batch_ids": request.view_tag_batch_ids.iter().cloned().collect::<Vec<_>>(),
        "state_diff_ids": request.state_diff_ids.iter().cloned().collect::<Vec<_>>(),
        "subaddress_hint_ids": request.subaddress_hint_ids.iter().cloned().collect::<Vec<_>>(),
        "fee_cap_id": request.fee_cap_id,
        "fee_micro_units": request.fee_micro_units,
        "sponsor_paid_micro_units": request.sponsor_paid_micro_units,
    });
    domain_hash(
        "MOBILE-FAST-SYNC-SPONSORED-BUNDLE-ID",
        &[HashPart::Json(&record)],
        32,
    )
}

pub fn audit_packet_id(request: &SelectiveDisclosureAuditRequest) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "bundle_id": request.bundle_id,
        "auditor_id": request.auditor_id,
        "disclosure_scopes": request.disclosure_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
        "disclosed_root": request.disclosed_root,
        "redaction_root": request.redaction_root,
        "proof_root": request.proof_root,
    });
    domain_hash(
        "MOBILE-FAST-SYNC-AUDIT-PACKET-ID",
        &[HashPart::Json(&record)],
        32,
    )
}

pub fn preconfirmation_receipt_id(request: &PreconfirmationCacheReceiptRequest) -> String {
    domain_hash(
        "MOBILE-FAST-SYNC-PRECONFIRMATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.bundle_id),
            HashPart::Str(&request.sequencer_id),
            HashPart::U64(request.preconfirmation_height),
            HashPart::Str(&request.cache_root_before),
            HashPart::Str(&request.cache_root_after),
        ],
        32,
    )
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "kind": kind,
        "label": label,
        "height": DEVNET_HEIGHT,
        "epoch": DEVNET_EPOCH,
    });
    domain_hash(
        "MOBILE-FAST-SYNC-DEVNET-PAYLOAD",
        &[HashPart::Json(&record)],
        32,
    )
}

pub fn devnet_config() -> Config {
    Config::default()
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn demo_state() -> State {
    State::demo()
}
