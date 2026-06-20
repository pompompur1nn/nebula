use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateWalletScanAcceleratorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_WALLET_SCAN_ACCELERATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-wallet-scan-accelerator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_WALLET_SCAN_ACCELERATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_331_200;
pub const DEVNET_EPOCH: u64 = 2_048;
pub const VIEW_TAG_WINDOW_SCHEME: &str = "monero-view-tag-private-scan-window-root-v1";
pub const SUBADDRESS_BLOOM_SCHEME: &str = "subaddress-bloom-commitment-root-v1";
pub const ENCRYPTED_OUTPUT_HINT_SCHEME: &str = "ml-kem-1024-encrypted-output-hint-root-v1";
pub const MOBILE_SCAN_SHARD_SCHEME: &str = "mobile-wallet-private-scan-shard-root-v1";
pub const RING_DECOY_FLOOR_SCHEME: &str = "ring-decoy-safety-floor-root-v1";
pub const PQ_WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-private-scan-watcher-attestation-v1";
pub const SCAN_SPONSORSHIP_SCHEME: &str = "low-fee-private-wallet-scan-sponsorship-root-v1";
pub const PRIVATE_TOKEN_RECEIPT_HINT_SCHEME: &str = "private-token-receipt-hint-commitment-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "wallet-scan-nullifier-fence-root-v1";
pub const REDACTION_ROOT_SCHEME: &str = "operator-safe-wallet-scan-redaction-root-v1";
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_SHARD_BLOCKS: u64 = 90;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_RING_DECOYS: u16 = 16;
pub const DEFAULT_TARGET_RING_DECOYS: u16 = 32;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_WALLET_FEE_MICRO_UNITS: u64 = 2_000;
pub const DEFAULT_SPONSOR_COVER_BPS: u16 = 9_500;
pub const DEFAULT_CONTRACT_HINT_FEE_BPS: u16 = 4;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_SCAN_WINDOWS: usize = 1_048_576;
pub const MAX_BLOOM_COMMITMENTS: usize = 2_097_152;
pub const MAX_OUTPUT_HINTS: usize = 4_194_304;
pub const MAX_MOBILE_SHARDS: usize = 1_048_576;
pub const MAX_DECOY_FLOORS: usize = 524_288;
pub const MAX_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SPONSORSHIPS: usize = 1_048_576;
pub const MAX_TOKEN_RECEIPT_HINTS: usize = 2_097_152;
pub const MAX_NULLIFIER_FENCES: usize = 4_194_304;
pub const MAX_REDACTION_ROOTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    ForegroundWallet,
    BackgroundMobile,
    WatchOnlyAudit,
    MerchantCheckout,
    DefiContractReceipt,
    ReorgRepair,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundWallet => "foreground_wallet",
            Self::BackgroundMobile => "background_mobile",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::MerchantCheckout => "merchant_checkout",
            Self::DefiContractReceipt => "defi_contract_receipt",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Draft,
    Open,
    Sealed,
    Attested,
    Sponsored,
    Delivered,
    ReorgLocked,
    Expired,
    Rejected,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Delivered => "delivered",
            Self::ReorgLocked => "reorg_locked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Attested | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ViewTagCompleteness,
    SubaddressBloomIntegrity,
    OutputHintEncryption,
    MobileShardCoverage,
    RingDecoySafety,
    ContractReceiptPrivacy,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagCompleteness => "view_tag_completeness",
            Self::SubaddressBloomIntegrity => "subaddress_bloom_integrity",
            Self::OutputHintEncryption => "output_hint_encryption",
            Self::MobileShardCoverage => "mobile_shard_coverage",
            Self::RingDecoySafety => "ring_decoy_safety",
            Self::ContractReceiptPrivacy => "contract_receipt_privacy",
        }
    }
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
    pub view_tag_window_scheme: String,
    pub subaddress_bloom_scheme: String,
    pub encrypted_output_hint_scheme: String,
    pub mobile_scan_shard_scheme: String,
    pub pq_watcher_attestation_scheme: String,
    pub scan_sponsorship_scheme: String,
    pub private_token_receipt_hint_scheme: String,
    pub scan_window_blocks: u64,
    pub shard_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_ring_decoys: u16,
    pub target_ring_decoys: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_wallet_fee_micro_units: u64,
    pub sponsor_cover_bps: u16,
    pub contract_hint_fee_bps: u16,
    pub allow_low_fee_sponsorship: bool,
    pub allow_contract_receipt_hints: bool,
    pub require_nullifier_fences: bool,
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
            view_tag_window_scheme: VIEW_TAG_WINDOW_SCHEME.to_string(),
            subaddress_bloom_scheme: SUBADDRESS_BLOOM_SCHEME.to_string(),
            encrypted_output_hint_scheme: ENCRYPTED_OUTPUT_HINT_SCHEME.to_string(),
            mobile_scan_shard_scheme: MOBILE_SCAN_SHARD_SCHEME.to_string(),
            pq_watcher_attestation_scheme: PQ_WATCHER_ATTESTATION_SCHEME.to_string(),
            scan_sponsorship_scheme: SCAN_SPONSORSHIP_SCHEME.to_string(),
            private_token_receipt_hint_scheme: PRIVATE_TOKEN_RECEIPT_HINT_SCHEME.to_string(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            shard_blocks: DEFAULT_SHARD_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_ring_decoys: DEFAULT_MIN_RING_DECOYS,
            target_ring_decoys: DEFAULT_TARGET_RING_DECOYS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_wallet_fee_micro_units: DEFAULT_MAX_WALLET_FEE_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            contract_hint_fee_bps: DEFAULT_CONTRACT_HINT_FEE_BPS,
            allow_low_fee_sponsorship: true,
            allow_contract_receipt_hints: true,
            require_nullifier_fences: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id == CHAIN_ID,
            "unsupported chain id {}",
            self.chain_id
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version {}",
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
        ensure!(self.scan_window_blocks > 0, "scan window must be nonzero");
        ensure!(self.shard_blocks > 0, "shard blocks must be nonzero");
        ensure!(
            self.scan_window_blocks >= self.shard_blocks,
            "scan window must cover at least one shard"
        );
        ensure!(
            self.min_privacy_set_size >= 1_024,
            "privacy set is too small for private wallet scanning"
        );
        ensure!(
            self.target_ring_decoys >= self.min_ring_decoys,
            "target ring decoys must cover minimum floor"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below runtime floor"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security must cover minimum"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps exceeds max"
        );
        ensure!(
            self.contract_hint_fee_bps <= MAX_BPS,
            "contract hint fee bps exceeds max"
        );
        Ok(())
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
            "view_tag_window_scheme": self.view_tag_window_scheme,
            "subaddress_bloom_scheme": self.subaddress_bloom_scheme,
            "encrypted_output_hint_scheme": self.encrypted_output_hint_scheme,
            "mobile_scan_shard_scheme": self.mobile_scan_shard_scheme,
            "pq_watcher_attestation_scheme": self.pq_watcher_attestation_scheme,
            "scan_sponsorship_scheme": self.scan_sponsorship_scheme,
            "private_token_receipt_hint_scheme": self.private_token_receipt_hint_scheme,
            "scan_window_blocks": self.scan_window_blocks,
            "shard_blocks": self.shard_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_ring_decoys": self.min_ring_decoys,
            "target_ring_decoys": self.target_ring_decoys,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_wallet_fee_micro_units": self.max_wallet_fee_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "contract_hint_fee_bps": self.contract_hint_fee_bps,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
            "allow_contract_receipt_hints": self.allow_contract_receipt_hints,
            "require_nullifier_fences": self.require_nullifier_fences,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scan_windows: u64,
    pub active_scan_windows: u64,
    pub bloom_commitments: u64,
    pub encrypted_output_hints: u64,
    pub mobile_scan_shards: u64,
    pub ring_decoy_floors: u64,
    pub pq_watcher_attestations: u64,
    pub scan_sponsorships: u64,
    pub private_token_receipt_hints: u64,
    pub nullifier_fences: u64,
    pub redaction_roots: u64,
    pub sponsored_fee_micro_units: u64,
    pub wallet_fee_micro_units: u64,
    pub contract_hint_fee_micro_units: u64,
    pub min_observed_privacy_set_size: u64,
    pub min_observed_ring_decoys: u16,
    pub max_observed_wallet_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_windows": self.scan_windows,
            "active_scan_windows": self.active_scan_windows,
            "bloom_commitments": self.bloom_commitments,
            "encrypted_output_hints": self.encrypted_output_hints,
            "mobile_scan_shards": self.mobile_scan_shards,
            "ring_decoy_floors": self.ring_decoy_floors,
            "pq_watcher_attestations": self.pq_watcher_attestations,
            "scan_sponsorships": self.scan_sponsorships,
            "private_token_receipt_hints": self.private_token_receipt_hints,
            "nullifier_fences": self.nullifier_fences,
            "redaction_roots": self.redaction_roots,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "wallet_fee_micro_units": self.wallet_fee_micro_units,
            "contract_hint_fee_micro_units": self.contract_hint_fee_micro_units,
            "min_observed_privacy_set_size": self.min_observed_privacy_set_size,
            "min_observed_ring_decoys": self.min_observed_ring_decoys,
            "max_observed_wallet_fee_micro_units": self.max_observed_wallet_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub scan_window_root: String,
    pub subaddress_bloom_root: String,
    pub encrypted_output_hint_root: String,
    pub mobile_scan_shard_root: String,
    pub ring_decoy_floor_root: String,
    pub pq_watcher_attestation_root: String,
    pub scan_sponsorship_root: String,
    pub private_token_receipt_hint_root: String,
    pub nullifier_fence_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "scan_window_root": self.scan_window_root,
            "subaddress_bloom_root": self.subaddress_bloom_root,
            "encrypted_output_hint_root": self.encrypted_output_hint_root,
            "mobile_scan_shard_root": self.mobile_scan_shard_root,
            "ring_decoy_floor_root": self.ring_decoy_floor_root,
            "pq_watcher_attestation_root": self.pq_watcher_attestation_root,
            "scan_sponsorship_root": self.scan_sponsorship_root,
            "private_token_receipt_hint_root": self.private_token_receipt_hint_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "redaction_root": self.redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagScanWindowRequest {
    pub wallet_commitment: String,
    pub lane: ScanLane,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_prefix_commitment: String,
    pub output_commitment_root: String,
    pub encrypted_route_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagScanWindow {
    pub window_id: String,
    pub wallet_commitment: String,
    pub lane: ScanLane,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_prefix_commitment: String,
    pub output_commitment_root: String,
    pub encrypted_route_root: String,
    pub privacy_set_size: u64,
    pub status: RecordStatus,
}

impl ViewTagScanWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "wallet_commitment": self.wallet_commitment,
            "lane": self.lane.as_str(),
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "view_tag_prefix_commitment": self.view_tag_prefix_commitment,
            "output_commitment_root": self.output_commitment_root,
            "encrypted_route_root": self.encrypted_route_root,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBloomCommitmentRequest {
    pub window_id: String,
    pub bloom_commitment_root: String,
    pub subaddress_range_commitment: String,
    pub false_positive_rate_micros: u32,
    pub salt_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBloomCommitment {
    pub bloom_id: String,
    pub window_id: String,
    pub bloom_commitment_root: String,
    pub subaddress_range_commitment: String,
    pub false_positive_rate_micros: u32,
    pub salt_commitment: String,
    pub status: RecordStatus,
}

impl SubaddressBloomCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "bloom_id": self.bloom_id,
            "window_id": self.window_id,
            "bloom_commitment_root": self.bloom_commitment_root,
            "subaddress_range_commitment": self.subaddress_range_commitment,
            "false_positive_rate_micros": self.false_positive_rate_micros,
            "salt_commitment": self.salt_commitment,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedOutputHintRequest {
    pub window_id: String,
    pub hint_kind: String,
    pub encrypted_hint_root: String,
    pub output_bucket_root: String,
    pub pq_ciphertext_root: String,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedOutputHint {
    pub hint_id: String,
    pub window_id: String,
    pub hint_kind: String,
    pub encrypted_hint_root: String,
    pub output_bucket_root: String,
    pub pq_ciphertext_root: String,
    pub expires_height: u64,
    pub status: RecordStatus,
}

impl EncryptedOutputHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "window_id": self.window_id,
            "hint_kind": self.hint_kind,
            "encrypted_hint_root": self.encrypted_hint_root,
            "output_bucket_root": self.output_bucket_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileScanShardRequest {
    pub window_id: String,
    pub device_commitment: String,
    pub shard_index: u32,
    pub shard_count: u32,
    pub start_height: u64,
    pub end_height: u64,
    pub compact_scan_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileScanShard {
    pub shard_id: String,
    pub window_id: String,
    pub device_commitment: String,
    pub shard_index: u32,
    pub shard_count: u32,
    pub start_height: u64,
    pub end_height: u64,
    pub compact_scan_root: String,
    pub status: RecordStatus,
}

impl MobileScanShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "window_id": self.window_id,
            "device_commitment": self.device_commitment,
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "compact_scan_root": self.compact_scan_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoySafetyFloor {
    pub floor_id: String,
    pub window_id: String,
    pub min_ring_decoys: u16,
    pub target_ring_decoys: u16,
    pub decoy_selection_root: String,
    pub excluded_output_root: String,
    pub status: RecordStatus,
}

impl RingDecoySafetyFloor {
    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "window_id": self.window_id,
            "min_ring_decoys": self.min_ring_decoys,
            "target_ring_decoys": self.target_ring_decoys,
            "decoy_selection_root": self.decoy_selection_root,
            "excluded_output_root": self.excluded_output_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestationRequest {
    pub window_id: String,
    pub watcher_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub window_id: String,
    pub watcher_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub pq_security_bits: u16,
    pub status: RecordStatus,
}

impl PqWatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "window_id": self.window_id,
            "watcher_id": self.watcher_id,
            "kind": self.kind.as_str(),
            "statement_root": self.statement_root,
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanSponsorship {
    pub sponsorship_id: String,
    pub window_id: String,
    pub sponsor_id: String,
    pub wallet_fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub fee_asset_id: String,
    pub policy_root: String,
    pub status: RecordStatus,
}

impl ScanSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "window_id": self.window_id,
            "sponsor_id": self.sponsor_id,
            "wallet_fee_micro_units": self.wallet_fee_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateTokenReceiptHint {
    pub receipt_hint_id: String,
    pub window_id: String,
    pub contract_id: String,
    pub encrypted_receipt_root: String,
    pub token_commitment_root: String,
    pub contract_call_root: String,
    pub fee_micro_units: u64,
    pub status: RecordStatus,
}

impl PrivateTokenReceiptHint {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_hint_id": self.receipt_hint_id,
            "window_id": self.window_id,
            "contract_id": self.contract_id,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "token_commitment_root": self.token_commitment_root,
            "contract_call_root": self.contract_call_root,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub window_id: String,
    pub nullifier_commitment: String,
    pub fence_kind: String,
    pub redaction_root: String,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "window_id": self.window_id,
            "nullifier_commitment": self.nullifier_commitment,
            "fence_kind": self.fence_kind,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorRedactionRoot {
    pub redaction_id: String,
    pub window_id: String,
    pub operator_id: String,
    pub public_summary_root: String,
    pub redacted_field_root: String,
    pub reason: String,
}

impl OperatorRedactionRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "window_id": self.window_id,
            "operator_id": self.operator_id,
            "public_summary_root": self.public_summary_root,
            "redacted_field_root": self.redacted_field_root,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub scan_windows: BTreeMap<String, ViewTagScanWindow>,
    pub subaddress_blooms: BTreeMap<String, SubaddressBloomCommitment>,
    pub encrypted_output_hints: BTreeMap<String, EncryptedOutputHint>,
    pub mobile_scan_shards: BTreeMap<String, MobileScanShard>,
    pub ring_decoy_floors: BTreeMap<String, RingDecoySafetyFloor>,
    pub pq_watcher_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub scan_sponsorships: BTreeMap<String, ScanSponsorship>,
    pub private_token_receipt_hints: BTreeMap<String, PrivateTokenReceiptHint>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub redaction_roots: BTreeMap<String, OperatorRedactionRoot>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            scan_windows: BTreeMap::new(),
            subaddress_blooms: BTreeMap::new(),
            encrypted_output_hints: BTreeMap::new(),
            mobile_scan_shards: BTreeMap::new(),
            ring_decoy_floors: BTreeMap::new(),
            pq_watcher_attestations: BTreeMap::new(),
            scan_sponsorships: BTreeMap::new(),
            private_token_receipt_hints: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            redaction_roots: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.scan_windows.len() <= MAX_SCAN_WINDOWS,
            "too many scan windows"
        );
        ensure!(
            self.subaddress_blooms.len() <= MAX_BLOOM_COMMITMENTS,
            "too many bloom commitments"
        );
        ensure!(
            self.encrypted_output_hints.len() <= MAX_OUTPUT_HINTS,
            "too many encrypted output hints"
        );
        ensure!(
            self.mobile_scan_shards.len() <= MAX_MOBILE_SHARDS,
            "too many mobile scan shards"
        );
        ensure!(
            self.ring_decoy_floors.len() <= MAX_DECOY_FLOORS,
            "too many ring decoy floors"
        );
        ensure!(
            self.pq_watcher_attestations.len() <= MAX_WATCHER_ATTESTATIONS,
            "too many watcher attestations"
        );
        ensure!(
            self.scan_sponsorships.len() <= MAX_SPONSORSHIPS,
            "too many scan sponsorships"
        );
        ensure!(
            self.private_token_receipt_hints.len() <= MAX_TOKEN_RECEIPT_HINTS,
            "too many private token receipt hints"
        );
        ensure!(
            self.nullifier_fences.len() <= MAX_NULLIFIER_FENCES,
            "too many nullifier fences"
        );
        ensure!(
            self.redaction_roots.len() <= MAX_REDACTION_ROOTS,
            "too many redaction roots"
        );
        for window in self.scan_windows.values() {
            ensure!(
                window.monero_start_height <= window.monero_end_height,
                "window {} has invalid height range",
                window.window_id
            );
            ensure!(
                window.privacy_set_size >= self.config.min_privacy_set_size,
                "window {} privacy set below floor",
                window.window_id
            );
        }
        for shard in self.mobile_scan_shards.values() {
            ensure!(
                self.scan_windows.contains_key(&shard.window_id),
                "shard {} references unknown window",
                shard.shard_id
            );
            ensure!(
                shard.shard_index < shard.shard_count,
                "shard index out of range"
            );
        }
        for hint in self.encrypted_output_hints.values() {
            ensure!(
                self.scan_windows.contains_key(&hint.window_id),
                "hint {} references unknown window",
                hint.hint_id
            );
        }
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let active_scan_windows = self
            .scan_windows
            .values()
            .filter(|window| window.status.active())
            .count() as u64;
        let sponsored_fee_micro_units = self
            .scan_sponsorships
            .values()
            .map(|record| record.sponsor_paid_micro_units)
            .sum();
        let wallet_fee_micro_units = self
            .scan_sponsorships
            .values()
            .map(|record| record.wallet_fee_micro_units)
            .sum();
        let contract_hint_fee_micro_units = self
            .private_token_receipt_hints
            .values()
            .map(|record| record.fee_micro_units)
            .sum();
        let min_observed_privacy_set_size = self
            .scan_windows
            .values()
            .map(|record| record.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size);
        let min_observed_ring_decoys = self
            .ring_decoy_floors
            .values()
            .map(|record| record.min_ring_decoys)
            .min()
            .unwrap_or(self.config.min_ring_decoys);
        let max_observed_wallet_fee_micro_units = self
            .scan_sponsorships
            .values()
            .map(|record| record.wallet_fee_micro_units)
            .max()
            .unwrap_or(0);
        Counters {
            scan_windows: self.scan_windows.len() as u64,
            active_scan_windows,
            bloom_commitments: self.subaddress_blooms.len() as u64,
            encrypted_output_hints: self.encrypted_output_hints.len() as u64,
            mobile_scan_shards: self.mobile_scan_shards.len() as u64,
            ring_decoy_floors: self.ring_decoy_floors.len() as u64,
            pq_watcher_attestations: self.pq_watcher_attestations.len() as u64,
            scan_sponsorships: self.scan_sponsorships.len() as u64,
            private_token_receipt_hints: self.private_token_receipt_hints.len() as u64,
            nullifier_fences: self.nullifier_fences.len() as u64,
            redaction_roots: self.redaction_roots.len() as u64,
            sponsored_fee_micro_units,
            wallet_fee_micro_units,
            contract_hint_fee_micro_units,
            min_observed_privacy_set_size,
            min_observed_ring_decoys,
            max_observed_wallet_fee_micro_units,
        }
    }

    pub fn refresh_roots(&self) -> Roots {
        self.roots()
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let config_root = domain_hash(
            "WALLET-SCAN-ACCELERATOR-CONFIG",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&config_record)],
            32,
        );
        let scan_window_records = self
            .scan_windows
            .values()
            .map(ViewTagScanWindow::public_record)
            .collect::<Vec<_>>();
        let bloom_records = self
            .subaddress_blooms
            .values()
            .map(SubaddressBloomCommitment::public_record)
            .collect::<Vec<_>>();
        let hint_records = self
            .encrypted_output_hints
            .values()
            .map(EncryptedOutputHint::public_record)
            .collect::<Vec<_>>();
        let shard_records = self
            .mobile_scan_shards
            .values()
            .map(MobileScanShard::public_record)
            .collect::<Vec<_>>();
        let floor_records = self
            .ring_decoy_floors
            .values()
            .map(RingDecoySafetyFloor::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .pq_watcher_attestations
            .values()
            .map(PqWatcherAttestation::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .scan_sponsorships
            .values()
            .map(ScanSponsorship::public_record)
            .collect::<Vec<_>>();
        let receipt_hint_records = self
            .private_token_receipt_hints
            .values()
            .map(PrivateTokenReceiptHint::public_record)
            .collect::<Vec<_>>();
        let fence_records = self
            .nullifier_fences
            .values()
            .map(NullifierFence::public_record)
            .collect::<Vec<_>>();
        let redaction_records = self
            .redaction_roots
            .values()
            .map(OperatorRedactionRoot::public_record)
            .collect::<Vec<_>>();
        let operator_summary_records = vec![self.operator_safe_summary()];
        let mut roots = Roots {
            config_root,
            scan_window_root: merkle_root("WALLET-SCAN-ACCELERATOR-WINDOW", &scan_window_records),
            subaddress_bloom_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-SUBADDRESS-BLOOM",
                &bloom_records,
            ),
            encrypted_output_hint_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-OUTPUT-HINT",
                &hint_records,
            ),
            mobile_scan_shard_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-MOBILE-SHARD",
                &shard_records,
            ),
            ring_decoy_floor_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-DECOY-FLOOR",
                &floor_records,
            ),
            pq_watcher_attestation_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-WATCHER-ATTESTATION",
                &attestation_records,
            ),
            scan_sponsorship_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-SPONSORSHIP",
                &sponsorship_records,
            ),
            private_token_receipt_hint_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-TOKEN-RECEIPT-HINT",
                &receipt_hint_records,
            ),
            nullifier_fence_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-NULLIFIER-FENCE",
                &fence_records,
            ),
            redaction_root: merkle_root("WALLET-SCAN-ACCELERATOR-REDACTION", &redaction_records),
            operator_summary_root: merkle_root(
                "WALLET-SCAN-ACCELERATOR-OPERATOR-SUMMARY",
                &operator_summary_records,
            ),
            state_root: String::new(),
        };
        roots.state_root = wallet_scan_accelerator_state_root_from_record(&json!({
            "height": self.height,
            "epoch": self.epoch,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        }));
        roots
    }

    pub fn operator_safe_summary(&self) -> Value {
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "scan_windows": counters.scan_windows,
            "active_scan_windows": counters.active_scan_windows,
            "encrypted_output_hints": counters.encrypted_output_hints,
            "mobile_scan_shards": counters.mobile_scan_shards,
            "pq_watcher_attestations": counters.pq_watcher_attestations,
            "sponsored_fee_micro_units": counters.sponsored_fee_micro_units,
            "wallet_fee_micro_units": counters.wallet_fee_micro_units,
            "contract_hint_fee_micro_units": counters.contract_hint_fee_micro_units,
            "min_observed_privacy_set_size": counters.min_observed_privacy_set_size,
            "min_observed_ring_decoys": counters.min_observed_ring_decoys,
            "max_observed_wallet_fee_micro_units": counters.max_observed_wallet_fee_micro_units,
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
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "operator_safe_summary": self.operator_safe_summary(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn insert_scan_window(&mut self, request: ViewTagScanWindowRequest) -> Result<String> {
        ensure!(
            request.monero_start_height <= request.monero_end_height,
            "invalid scan window height range"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured floor"
        );
        let window_id = view_tag_scan_window_id(&request);
        let record = ViewTagScanWindow {
            window_id: window_id.clone(),
            wallet_commitment: request.wallet_commitment,
            lane: request.lane,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            view_tag_prefix_commitment: request.view_tag_prefix_commitment,
            output_commitment_root: request.output_commitment_root,
            encrypted_route_root: request.encrypted_route_root,
            privacy_set_size: request.privacy_set_size,
            status: RecordStatus::Open,
        };
        self.scan_windows.insert(window_id.clone(), record);
        Ok(window_id)
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let foreground = state
            .insert_scan_window(ViewTagScanWindowRequest {
                wallet_commitment: devnet_payload_root("wallet", "alice-watch-only"),
                lane: ScanLane::ForegroundWallet,
                monero_start_height: DEVNET_HEIGHT - 720,
                monero_end_height: DEVNET_HEIGHT,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "alice-00-af"),
                output_commitment_root: devnet_payload_root("outputs", "alice-window"),
                encrypted_route_root: devnet_payload_root("route", "alice-device-route"),
                privacy_set_size: 131_072,
            })
            .expect("devnet foreground window");
        let background = state
            .insert_scan_window(ViewTagScanWindowRequest {
                wallet_commitment: devnet_payload_root("wallet", "merchant-background"),
                lane: ScanLane::MerchantCheckout,
                monero_start_height: DEVNET_HEIGHT - 360,
                monero_end_height: DEVNET_HEIGHT,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "merchant-17"),
                output_commitment_root: devnet_payload_root("outputs", "merchant-window"),
                encrypted_route_root: devnet_payload_root("route", "merchant-pos-route"),
                privacy_set_size: 98_304,
            })
            .expect("devnet merchant window");
        state.seed_window_support(&foreground, "alice", 0);
        state.seed_window_support(&background, "merchant", 1);
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let contract = state
            .insert_scan_window(ViewTagScanWindowRequest {
                wallet_commitment: devnet_payload_root("wallet", "defi-vault-receipts"),
                lane: ScanLane::DefiContractReceipt,
                monero_start_height: DEVNET_HEIGHT - 180,
                monero_end_height: DEVNET_HEIGHT,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "vault-42"),
                output_commitment_root: devnet_payload_root("outputs", "vault-window"),
                encrypted_route_root: devnet_payload_root("route", "vault-indexer-route"),
                privacy_set_size: 262_144,
            })
            .expect("demo contract window");
        state.seed_window_support(&contract, "vault", 2);
        state
    }

    fn seed_window_support(&mut self, window_id: &str, label: &str, index: u32) {
        let bloom = SubaddressBloomCommitment {
            bloom_id: subaddress_bloom_id(window_id, &devnet_payload_root("bloom", label)),
            window_id: window_id.to_string(),
            bloom_commitment_root: devnet_payload_root("bloom", label),
            subaddress_range_commitment: devnet_payload_root("subaddress-range", label),
            false_positive_rate_micros: 95,
            salt_commitment: devnet_payload_root("salt", label),
            status: RecordStatus::Sealed,
        };
        self.subaddress_blooms.insert(bloom.bloom_id.clone(), bloom);

        for shard_index in 0..4 {
            let shard = MobileScanShard {
                shard_id: mobile_scan_shard_id(window_id, index, shard_index),
                window_id: window_id.to_string(),
                device_commitment: devnet_payload_root("device", label),
                shard_index,
                shard_count: 4,
                start_height: DEVNET_HEIGHT - 720 + u64::from(shard_index) * 90,
                end_height: DEVNET_HEIGHT - 631 + u64::from(shard_index) * 90,
                compact_scan_root: devnet_payload_root(
                    "compact-scan-shard",
                    &format!("{label}-{shard_index}"),
                ),
                status: RecordStatus::Delivered,
            };
            self.mobile_scan_shards
                .insert(shard.shard_id.clone(), shard);
        }

        let hint = EncryptedOutputHint {
            hint_id: encrypted_output_hint_id(
                window_id,
                "view_tag_bucket",
                &devnet_payload_root("hint", label),
            ),
            window_id: window_id.to_string(),
            hint_kind: "view_tag_bucket".to_string(),
            encrypted_hint_root: devnet_payload_root("hint", label),
            output_bucket_root: devnet_payload_root("bucket", label),
            pq_ciphertext_root: devnet_payload_root("pq-ciphertext", label),
            expires_height: DEVNET_HEIGHT + DEFAULT_HINT_TTL_BLOCKS,
            status: RecordStatus::Attested,
        };
        self.encrypted_output_hints
            .insert(hint.hint_id.clone(), hint);

        let floor = RingDecoySafetyFloor {
            floor_id: ring_decoy_floor_id(
                window_id,
                self.config.min_ring_decoys,
                self.config.target_ring_decoys,
            ),
            window_id: window_id.to_string(),
            min_ring_decoys: self.config.min_ring_decoys,
            target_ring_decoys: self.config.target_ring_decoys,
            decoy_selection_root: devnet_payload_root("decoy-selection", label),
            excluded_output_root: devnet_payload_root("excluded-outputs", label),
            status: RecordStatus::Attested,
        };
        self.ring_decoy_floors.insert(floor.floor_id.clone(), floor);

        let attestation = PqWatcherAttestation {
            attestation_id: pq_watcher_attestation_id(
                window_id,
                &format!("watcher-{index}"),
                AttestationKind::RingDecoySafety,
                &devnet_payload_root("watcher-statement", label),
            ),
            window_id: window_id.to_string(),
            watcher_id: format!("watcher-{index}"),
            kind: AttestationKind::RingDecoySafety,
            statement_root: devnet_payload_root("watcher-statement", label),
            public_key_commitment: devnet_payload_root("watcher-pq-key", label),
            signature_commitment: devnet_payload_root("watcher-signature", label),
            pq_security_bits: self.config.target_pq_security_bits,
            status: RecordStatus::Attested,
        };
        self.pq_watcher_attestations
            .insert(attestation.attestation_id.clone(), attestation);

        let sponsorship = ScanSponsorship {
            sponsorship_id: scan_sponsorship_id(window_id, &format!("sponsor-{index}")),
            window_id: window_id.to_string(),
            sponsor_id: format!("sponsor-{index}"),
            wallet_fee_micro_units: 250,
            sponsor_paid_micro_units: 4_750,
            fee_asset_id: self.config.fee_asset_id.clone(),
            policy_root: devnet_payload_root("sponsor-policy", label),
            status: RecordStatus::Sponsored,
        };
        self.scan_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);

        let receipt_hint = PrivateTokenReceiptHint {
            receipt_hint_id: private_token_receipt_hint_id(window_id, &format!("contract-{index}")),
            window_id: window_id.to_string(),
            contract_id: format!("contract-{index}"),
            encrypted_receipt_root: devnet_payload_root("contract-receipt", label),
            token_commitment_root: devnet_payload_root("token-commitment", label),
            contract_call_root: devnet_payload_root("contract-call", label),
            fee_micro_units: 80,
            status: RecordStatus::Delivered,
        };
        self.private_token_receipt_hints
            .insert(receipt_hint.receipt_hint_id.clone(), receipt_hint);

        let nullifier = devnet_payload_root("nullifier", label);
        let fence = NullifierFence {
            fence_id: nullifier_fence_id(window_id, &nullifier, "scan_window"),
            window_id: window_id.to_string(),
            nullifier_commitment: nullifier.clone(),
            fence_kind: "scan_window".to_string(),
            redaction_root: devnet_payload_root("fence-redaction", label),
        };
        self.consumed_nullifiers.insert(nullifier);
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);

        let redaction = OperatorRedactionRoot {
            redaction_id: operator_redaction_id(window_id, &format!("operator-{index}")),
            window_id: window_id.to_string(),
            operator_id: format!("operator-{index}"),
            public_summary_root: devnet_payload_root("public-summary", label),
            redacted_field_root: devnet_payload_root("redacted-fields", label),
            reason: "operator_safe_public_summary".to_string(),
        };
        self.redaction_roots
            .insert(redaction.redaction_id.clone(), redaction);
    }
}

pub fn view_tag_scan_window_id(request: &ViewTagScanWindowRequest) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(request.lane.as_str()),
            HashPart::U64(request.monero_start_height),
            HashPart::U64(request.monero_end_height),
            HashPart::Str(&request.view_tag_prefix_commitment),
            HashPart::Str(&request.output_commitment_root),
        ],
        32,
    )
}

pub fn subaddress_bloom_id(window_id: &str, bloom_commitment_root: &str) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-BLOOM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(bloom_commitment_root),
        ],
        32,
    )
}

pub fn encrypted_output_hint_id(
    window_id: &str,
    hint_kind: &str,
    encrypted_hint_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(hint_kind),
            HashPart::Str(encrypted_hint_root),
        ],
        32,
    )
}

pub fn mobile_scan_shard_id(window_id: &str, window_index: u32, shard_index: u32) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::U64(u64::from(window_index)),
            HashPart::U64(u64::from(shard_index)),
        ],
        32,
    )
}

pub fn ring_decoy_floor_id(
    window_id: &str,
    min_ring_decoys: u16,
    target_ring_decoys: u16,
) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-DECOY-FLOOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::U64(u64::from(min_ring_decoys)),
            HashPart::U64(u64::from(target_ring_decoys)),
        ],
        32,
    )
}

pub fn pq_watcher_attestation_id(
    window_id: &str,
    watcher_id: &str,
    kind: AttestationKind,
    statement_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(watcher_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(statement_root),
        ],
        32,
    )
}

pub fn scan_sponsorship_id(window_id: &str, sponsor_id: &str) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(sponsor_id),
        ],
        32,
    )
}

pub fn private_token_receipt_hint_id(window_id: &str, contract_id: &str) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-PRIVATE-TOKEN-RECEIPT-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(contract_id),
        ],
        32,
    )
}

pub fn nullifier_fence_id(window_id: &str, nullifier_commitment: &str, fence_kind: &str) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(nullifier_commitment),
            HashPart::Str(fence_kind),
        ],
        32,
    )
}

pub fn operator_redaction_id(window_id: &str, operator_id: &str) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-OPERATOR-REDACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(operator_id),
        ],
        32,
    )
}

pub fn wallet_scan_accelerator_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind,
        "label": label,
        "height": DEVNET_HEIGHT,
        "epoch": DEVNET_EPOCH,
    });
    domain_hash(
        "WALLET-SCAN-ACCELERATOR-DEVNET-PAYLOAD",
        &[HashPart::Json(&record)],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn demo_state() -> State {
    State::demo()
}
