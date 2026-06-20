use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateSeraphisJamtisLiquidityMigrationRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = MoneroL2PqPrivateSeraphisJamtisLiquidityMigrationRuntimeResult<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_LIQUIDITY_MIGRATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-jamtis-liquidity-migration-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_LIQUIDITY_MIGRATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str =
    "monero-l2-pq-private-seraphis-jamtis-liquidity-migration-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 1_948_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_744_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_NOTE_BATCH_SCHEME: &str = "seraphis-jamtis-migrated-note-batch-root-v1";
pub const ADDRESS_EPOCH_POLICY_SCHEME: &str = "jamtis-address-epoch-policy-root-v1";
pub const DECOY_PRESERVATION_SCHEME: &str = "seraphis-decoy-preservation-root-v1";
pub const VIEW_KEY_REDACTION_SCHEME: &str = "jamtis-view-key-redaction-root-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-liquidity-migration-watcher-root-v1";
pub const LIQUIDITY_QUOTA_SCHEME: &str = "seraphis-jamtis-liquidity-migration-quota-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "low-fee-seraphis-jamtis-sponsor-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "seraphis-jamtis-liquidity-migration-public-record-v1";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-SERAPHIS-JAMTIS-LIQUIDITY-MIGRATION-STATE";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_DECOY_PRESERVATION_BPS: u64 = 9_200;
pub const DEFAULT_ADDRESS_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_ADDRESS_EPOCH_GRACE_BLOCKS: u64 = 144;
pub const DEFAULT_NOTE_BATCH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_WATCHER_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_QUOTA_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_BATCH_NOTES: u32 = 512;
pub const DEFAULT_MAX_BATCH_LIQUIDITY_UNITS: u64 = 25_000_000_000;
pub const DEFAULT_DAILY_LIQUIDITY_QUOTA_UNITS: u64 = 100_000_000_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 3;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 7;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 2_048;
pub const MAX_NOTE_BATCHES: usize = 1_048_576;
pub const MAX_ADDRESS_POLICIES: usize = 524_288;
pub const MAX_DECOY_SETS: usize = 2_097_152;
pub const MAX_REDACTIONS: usize = 2_097_152;
pub const MAX_WATCHER_ATTESTATIONS: usize = 4_194_304;
pub const MAX_QUOTAS: usize = 524_288;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationLane {
    LowFeeSponsored,
    WalletBatch,
    MerchantLiquidity,
    DefiPool,
    BridgeReserve,
    EmergencyUnwind,
}

impl MigrationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::WalletBatch => "wallet_batch",
            Self::MerchantLiquidity => "merchant_liquidity",
            Self::DefiPool => "defi_pool",
            Self::BridgeReserve => "bridge_reserve",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 1_000,
            Self::BridgeReserve => 950,
            Self::DefiPool => 880,
            Self::MerchantLiquidity => 820,
            Self::WalletBatch => 760,
            Self::LowFeeSponsored => 720,
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFeeSponsored => config.low_fee_target_bps,
            Self::WalletBatch | Self::MerchantLiquidity => config.max_user_fee_bps / 2,
            Self::DefiPool | Self::BridgeReserve => config.max_user_fee_bps,
            Self::EmergencyUnwind => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Drafted,
    AddressEpochChecked,
    DecoysPreserved,
    WatcherAttested,
    QuotaReserved,
    RebateReserved,
    RootAnchored,
    Migrated,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::AddressEpochChecked => "address_epoch_checked",
            Self::DecoysPreserved => "decoys_preserved",
            Self::WatcherAttested => "watcher_attested",
            Self::QuotaReserved => "quota_reserved",
            Self::RebateReserved => "rebate_reserved",
            Self::RootAnchored => "root_anchored",
            Self::Migrated => "migrated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Drafted
                | Self::AddressEpochChecked
                | Self::DecoysPreserved
                | Self::WatcherAttested
                | Self::QuotaReserved
                | Self::RebateReserved
                | Self::RootAnchored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressEpochMode {
    LegacyRingCt,
    JamtisReceiveOnly,
    SeraphisJamtisDual,
    SeraphisOnly,
    RecoveryOnly,
}

impl AddressEpochMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyRingCt => "legacy_ringct",
            Self::JamtisReceiveOnly => "jamtis_receive_only",
            Self::SeraphisJamtisDual => "seraphis_jamtis_dual",
            Self::SeraphisOnly => "seraphis_only",
            Self::RecoveryOnly => "recovery_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    ViewKey,
    ViewTag,
    AddressHint,
    AmountHint,
    WatcherMemo,
    SponsorReceipt,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKey => "view_key",
            Self::ViewTag => "view_tag",
            Self::AddressHint => "address_hint",
            Self::AmountHint => "amount_hint",
            Self::WatcherMemo => "watcher_memo",
            Self::SponsorReceipt => "sponsor_receipt",
        }
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
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub bridge_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub seraphis_note_batch_scheme: String,
    pub address_epoch_policy_scheme: String,
    pub decoy_preservation_scheme: String,
    pub view_key_redaction_scheme: String,
    pub watcher_attestation_scheme: String,
    pub liquidity_quota_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_decoy_preservation_bps: u64,
    pub address_epoch_blocks: u64,
    pub address_epoch_grace_blocks: u64,
    pub note_batch_ttl_blocks: u64,
    pub watcher_ttl_blocks: u64,
    pub quota_window_blocks: u64,
    pub max_batch_notes: u32,
    pub max_batch_liquidity_units: u64,
    pub daily_liquidity_quota_units: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub watcher_quorum_bps: u64,
    pub redaction_budget_units: u64,
    pub allowed_wallet_families: BTreeSet<String>,
}

impl Config {
    pub fn devnet() -> Self {
        let mut allowed_wallet_families = BTreeSet::new();
        allowed_wallet_families.insert("monero-cli".to_string());
        allowed_wallet_families.insert("monero-gui".to_string());
        allowed_wallet_families.insert("seraphis-mobile".to_string());
        allowed_wallet_families.insert("hardware-jamtis-devnet".to_string());
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            seraphis_note_batch_scheme: SERAPHIS_NOTE_BATCH_SCHEME.to_string(),
            address_epoch_policy_scheme: ADDRESS_EPOCH_POLICY_SCHEME.to_string(),
            decoy_preservation_scheme: DECOY_PRESERVATION_SCHEME.to_string(),
            view_key_redaction_scheme: VIEW_KEY_REDACTION_SCHEME.to_string(),
            watcher_attestation_scheme: WATCHER_ATTESTATION_SCHEME.to_string(),
            liquidity_quota_scheme: LIQUIDITY_QUOTA_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_decoy_preservation_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            address_epoch_blocks: DEFAULT_ADDRESS_EPOCH_BLOCKS,
            address_epoch_grace_blocks: DEFAULT_ADDRESS_EPOCH_GRACE_BLOCKS,
            note_batch_ttl_blocks: DEFAULT_NOTE_BATCH_TTL_BLOCKS,
            watcher_ttl_blocks: DEFAULT_WATCHER_TTL_BLOCKS,
            quota_window_blocks: DEFAULT_QUOTA_WINDOW_BLOCKS,
            max_batch_notes: DEFAULT_MAX_BATCH_NOTES,
            max_batch_liquidity_units: DEFAULT_MAX_BATCH_LIQUIDITY_UNITS,
            daily_liquidity_quota_units: DEFAULT_DAILY_LIQUIDITY_QUOTA_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            allowed_wallet_families,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        ensure(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy",
        )?;
        ensure(
            self.min_decoy_preservation_bps <= MAX_BPS,
            "decoy preservation bps above range",
        )?;
        ensure(self.max_user_fee_bps <= MAX_BPS, "user fee bps above range")?;
        ensure(
            self.low_fee_target_bps <= self.max_user_fee_bps,
            "low fee target above max fee",
        )?;
        ensure(
            self.sponsor_rebate_bps <= self.max_user_fee_bps,
            "rebate bps above max fee",
        )?;
        ensure(
            self.watcher_quorum_bps <= MAX_BPS,
            "watcher quorum bps above range",
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub migrated_note_batches: u64,
    pub address_epoch_policies: u64,
    pub decoy_preservations: u64,
    pub view_key_redactions: u64,
    pub watcher_attestations: u64,
    pub liquidity_quotas: u64,
    pub sponsor_rebates: u64,
    pub public_records: u64,
    pub migrated_notes: u64,
    pub liquidity_units_migrated: u64,
    pub redaction_units_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub note_batch_root: String,
    pub address_epoch_policy_root: String,
    pub decoy_preservation_root: String,
    pub view_key_redaction_root: String,
    pub watcher_attestation_root: String,
    pub liquidity_quota_root: String,
    pub low_fee_rebate_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            note_batch_root: empty_root("note-batches"),
            address_epoch_policy_root: empty_root("address-epoch-policies"),
            decoy_preservation_root: empty_root("decoy-preservations"),
            view_key_redaction_root: empty_root("view-key-redactions"),
            watcher_attestation_root: empty_root("watcher-attestations"),
            liquidity_quota_root: empty_root("liquidity-quotas"),
            low_fee_rebate_root: empty_root("low-fee-rebates"),
            public_record_root: empty_root("public-records"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigratedNoteBatch {
    pub batch_id: String,
    pub lane: MigrationLane,
    pub status: BatchStatus,
    pub address_epoch_id: String,
    pub source_ringct_note_root: String,
    pub seraphis_note_root: String,
    pub jamtis_address_commitment_root: String,
    pub nullifier_root: String,
    pub encrypted_amount_root: String,
    pub decoy_set_id: String,
    pub watcher_attestation_id: String,
    pub quota_id: String,
    pub rebate_id: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub note_count: u32,
    pub liquidity_units: u64,
    pub max_fee_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl MigratedNoteBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "address_epoch_id": self.address_epoch_id,
            "source_ringct_note_root": self.source_ringct_note_root,
            "seraphis_note_root": self.seraphis_note_root,
            "jamtis_address_commitment_root": self.jamtis_address_commitment_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_amount_root": self.encrypted_amount_root,
            "decoy_set_id": self.decoy_set_id,
            "watcher_attestation_id": self.watcher_attestation_id,
            "quota_id": self.quota_id,
            "rebate_id": self.rebate_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "note_count": self.note_count,
            "liquidity_units": self.liquidity_units,
            "max_fee_bps": self.max_fee_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressEpochPolicy {
    pub epoch_id: String,
    pub mode: AddressEpochMode,
    pub wallet_family: String,
    pub policy_root: String,
    pub jamtis_prefix_root: String,
    pub minimum_wallet_version: String,
    pub start_height: u64,
    pub enforce_height: u64,
    pub expires_height: u64,
    pub allowed_lanes: BTreeSet<MigrationLane>,
}

impl AddressEpochPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "mode": self.mode.as_str(),
            "wallet_family": self.wallet_family,
            "policy_root": self.policy_root,
            "jamtis_prefix_root": self.jamtis_prefix_root,
            "minimum_wallet_version": self.minimum_wallet_version,
            "start_height": self.start_height,
            "enforce_height": self.enforce_height,
            "expires_height": self.expires_height,
            "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyPreservation {
    pub decoy_set_id: String,
    pub batch_id: String,
    pub legacy_decoy_root: String,
    pub seraphis_decoy_root: String,
    pub age_distribution_root: String,
    pub ring_member_overlap_root: String,
    pub preserved_bps: u64,
    pub minimum_required_bps: u64,
    pub privacy_set_size: u64,
}

impl DecoyPreservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyRedaction {
    pub redaction_id: String,
    pub batch_id: String,
    pub scope: RedactionScope,
    pub redacted_view_key_root: String,
    pub disclosure_policy_root: String,
    pub auditor_commitment: String,
    pub redaction_units: u64,
    pub issued_height: u64,
}

impl ViewKeyRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "batch_id": self.batch_id,
            "scope": self.scope.as_str(),
            "redacted_view_key_root": self.redacted_view_key_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "auditor_commitment": self.auditor_commitment,
            "redaction_units": self.redaction_units,
            "issued_height": self.issued_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub status: AttestationStatus,
    pub watcher_set_root: String,
    pub attested_note_root: String,
    pub attested_quota_root: String,
    pub signature_root: String,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "watcher_set_root": self.watcher_set_root,
            "attested_note_root": self.attested_note_root,
            "attested_quota_root": self.attested_quota_root,
            "signature_root": self.signature_root,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityMigrationQuota {
    pub quota_id: String,
    pub sponsor_commitment: String,
    pub lane: MigrationLane,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_liquidity_units: u64,
    pub reserved_liquidity_units: u64,
    pub migrated_liquidity_units: u64,
    pub quota_root: String,
}

impl LiquidityMigrationQuota {
    pub fn public_record(&self) -> Value {
        json!({
            "quota_id": self.quota_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_liquidity_units": self.max_liquidity_units,
            "reserved_liquidity_units": self.reserved_liquidity_units,
            "migrated_liquidity_units": self.migrated_liquidity_units,
            "quota_root": self.quota_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub rebate_bps: u64,
    pub fee_asset_id: String,
    pub rebate_note_root: String,
    pub sponsor_receipt_root: String,
    pub claimed: bool,
    pub issued_height: u64,
}

impl LowFeeSponsorRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub note_batches: BTreeMap<String, MigratedNoteBatch>,
    pub address_epoch_policies: BTreeMap<String, AddressEpochPolicy>,
    pub decoy_preservations: BTreeMap<String, DecoyPreservation>,
    pub view_key_redactions: BTreeMap<String, ViewKeyRedaction>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub liquidity_quotas: BTreeMap<String, LiquidityMigrationQuota>,
    pub sponsor_rebates: BTreeMap<String, LowFeeSponsorRebate>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64) -> Self {
        Self {
            config,
            l2_height,
            monero_height,
            note_batches: BTreeMap::new(),
            address_epoch_policies: BTreeMap::new(),
            decoy_preservations: BTreeMap::new(),
            view_key_redactions: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            liquidity_quotas: BTreeMap::new(),
            sponsor_rebates: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = state.l2_height;
        let mut allowed_lanes = BTreeSet::new();
        allowed_lanes.insert(MigrationLane::LowFeeSponsored);
        allowed_lanes.insert(MigrationLane::WalletBatch);
        allowed_lanes.insert(MigrationLane::BridgeReserve);
        let policy = AddressEpochPolicy {
            epoch_id: deterministic_id("addr-epoch", &["devnet", "seraphis-jamtis", "001"]),
            mode: AddressEpochMode::SeraphisJamtisDual,
            wallet_family: "seraphis-mobile".to_string(),
            policy_root: fixed_root("devnet-address-epoch-policy"),
            jamtis_prefix_root: fixed_root("devnet-jamtis-prefixes"),
            minimum_wallet_version: "0.20.0.0-seraphis-devnet".to_string(),
            start_height: height,
            enforce_height: height + DEFAULT_ADDRESS_EPOCH_GRACE_BLOCKS,
            expires_height: height + DEFAULT_ADDRESS_EPOCH_BLOCKS,
            allowed_lanes,
        };
        let epoch_id = policy.epoch_id.clone();
        state
            .insert_address_epoch_policy(policy)
            .expect("devnet policy");

        let quota = LiquidityMigrationQuota {
            quota_id: deterministic_id("quota", &["devnet-sponsor", "low-fee", "001"]),
            sponsor_commitment: "devnet-low-fee-sponsor".to_string(),
            lane: MigrationLane::LowFeeSponsored,
            window_start_height: height,
            window_end_height: height + DEFAULT_QUOTA_WINDOW_BLOCKS,
            max_liquidity_units: DEFAULT_DAILY_LIQUIDITY_QUOTA_UNITS,
            reserved_liquidity_units: 15_000_000_000,
            migrated_liquidity_units: 0,
            quota_root: fixed_root("devnet-low-fee-quota"),
        };
        let quota_id = quota.quota_id.clone();
        state.insert_liquidity_quota(quota).expect("devnet quota");

        let batch_id = deterministic_id("note-batch", &["devnet", "alice", "001"]);
        let decoy = DecoyPreservation {
            decoy_set_id: deterministic_id("decoy-set", &[&batch_id, "preserved"]),
            batch_id: batch_id.clone(),
            legacy_decoy_root: fixed_root("devnet-legacy-decoys"),
            seraphis_decoy_root: fixed_root("devnet-seraphis-decoys"),
            age_distribution_root: fixed_root("devnet-decoy-age-distribution"),
            ring_member_overlap_root: fixed_root("devnet-ring-member-overlap"),
            preserved_bps: 9_650,
            minimum_required_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        };
        let decoy_set_id = decoy.decoy_set_id.clone();
        state
            .insert_decoy_preservation(decoy)
            .expect("devnet decoys");

        let attestation = WatcherAttestation {
            attestation_id: deterministic_id("watcher-att", &[&batch_id, "devnet-watchers"]),
            batch_id: batch_id.clone(),
            status: AttestationStatus::Accepted,
            watcher_set_root: fixed_root("devnet-watcher-set"),
            attested_note_root: fixed_root("devnet-seraphis-notes"),
            attested_quota_root: fixed_root("devnet-low-fee-quota"),
            signature_root: fixed_root("devnet-watcher-pq-signatures"),
            quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            submitted_height: height,
            expires_height: height + DEFAULT_WATCHER_TTL_BLOCKS,
        };
        let watcher_attestation_id = attestation.attestation_id.clone();
        state
            .insert_watcher_attestation(attestation)
            .expect("devnet attestation");

        let rebate = LowFeeSponsorRebate {
            rebate_id: deterministic_id("rebate", &[&batch_id, "low-fee"]),
            batch_id: batch_id.clone(),
            sponsor_commitment: "devnet-low-fee-sponsor".to_string(),
            rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_note_root: fixed_root("devnet-rebate-note"),
            sponsor_receipt_root: fixed_root("devnet-sponsor-receipt"),
            claimed: false,
            issued_height: height,
        };
        let rebate_id = rebate.rebate_id.clone();
        state.insert_sponsor_rebate(rebate).expect("devnet rebate");

        let batch = MigratedNoteBatch {
            batch_id: batch_id.clone(),
            lane: MigrationLane::LowFeeSponsored,
            status: BatchStatus::RootAnchored,
            address_epoch_id: epoch_id,
            source_ringct_note_root: fixed_root("devnet-ringct-notes"),
            seraphis_note_root: fixed_root("devnet-seraphis-notes"),
            jamtis_address_commitment_root: fixed_root("devnet-jamtis-address-commitments"),
            nullifier_root: fixed_root("devnet-nullifiers"),
            encrypted_amount_root: fixed_root("devnet-encrypted-amounts"),
            decoy_set_id,
            watcher_attestation_id,
            quota_id,
            rebate_id: Some(rebate_id),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            note_count: 128,
            liquidity_units: 15_000_000_000,
            max_fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            opened_height: height,
            expires_height: height + DEFAULT_NOTE_BATCH_TTL_BLOCKS,
        };
        state.insert_note_batch(batch).expect("devnet batch");

        let redaction = ViewKeyRedaction {
            redaction_id: deterministic_id("redaction", &[&batch_id, "view-key"]),
            batch_id,
            scope: RedactionScope::ViewKey,
            redacted_view_key_root: fixed_root("devnet-redacted-view-key"),
            disclosure_policy_root: fixed_root("devnet-disclosure-policy"),
            auditor_commitment: "auditor:devnet:privacy-root-only".to_string(),
            redaction_units: 8,
            issued_height: height,
        };
        state
            .insert_view_key_redaction(redaction)
            .expect("devnet redaction");
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn insert_note_batch(&mut self, batch: MigratedNoteBatch) -> Result<()> {
        ensure_capacity(self.note_batches.len(), MAX_NOTE_BATCHES, "note batches")?;
        ensure(
            batch.privacy_set_size >= self.config.min_privacy_set_size,
            "batch privacy set below policy",
        )?;
        ensure(
            batch.pq_security_bits >= self.config.min_pq_security_bits,
            "batch pq security below policy",
        )?;
        ensure(
            batch.note_count <= self.config.max_batch_notes,
            "batch note count above policy",
        )?;
        ensure(
            batch.liquidity_units <= self.config.max_batch_liquidity_units,
            "batch liquidity above policy",
        )?;
        self.note_batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_address_epoch_policy(&mut self, policy: AddressEpochPolicy) -> Result<()> {
        ensure_capacity(
            self.address_epoch_policies.len(),
            MAX_ADDRESS_POLICIES,
            "address epoch policies",
        )?;
        ensure(
            self.config
                .allowed_wallet_families
                .contains(&policy.wallet_family),
            "wallet family not allowed",
        )?;
        self.address_epoch_policies
            .insert(policy.epoch_id.clone(), policy);
        Ok(())
    }

    pub fn insert_decoy_preservation(&mut self, decoy: DecoyPreservation) -> Result<()> {
        ensure_capacity(self.decoy_preservations.len(), MAX_DECOY_SETS, "decoy sets")?;
        ensure(
            decoy.preserved_bps >= self.config.min_decoy_preservation_bps,
            "decoy preservation below policy",
        )?;
        self.decoy_preservations
            .insert(decoy.decoy_set_id.clone(), decoy);
        Ok(())
    }

    pub fn insert_view_key_redaction(&mut self, redaction: ViewKeyRedaction) -> Result<()> {
        ensure_capacity(
            self.view_key_redactions.len(),
            MAX_REDACTIONS,
            "view key redactions",
        )?;
        self.view_key_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        Ok(())
    }

    pub fn insert_watcher_attestation(&mut self, attestation: WatcherAttestation) -> Result<()> {
        ensure_capacity(
            self.watcher_attestations.len(),
            MAX_WATCHER_ATTESTATIONS,
            "watcher attestations",
        )?;
        ensure(
            attestation.quorum_bps >= self.config.watcher_quorum_bps,
            "watcher quorum below policy",
        )?;
        ensure(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "watcher pq security below policy",
        )?;
        self.watcher_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_liquidity_quota(&mut self, quota: LiquidityMigrationQuota) -> Result<()> {
        ensure_capacity(self.liquidity_quotas.len(), MAX_QUOTAS, "liquidity quotas")?;
        ensure(
            quota.max_liquidity_units <= self.config.daily_liquidity_quota_units,
            "quota above daily liquidity limit",
        )?;
        ensure(
            quota.reserved_liquidity_units <= quota.max_liquidity_units,
            "reserved liquidity above quota",
        )?;
        self.liquidity_quotas.insert(quota.quota_id.clone(), quota);
        Ok(())
    }

    pub fn insert_sponsor_rebate(&mut self, rebate: LowFeeSponsorRebate) -> Result<()> {
        ensure_capacity(self.sponsor_rebates.len(), MAX_REBATES, "sponsor rebates")?;
        ensure(
            rebate.rebate_bps <= self.config.max_user_fee_bps,
            "rebate bps above max user fee",
        )?;
        self.sponsor_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            migrated_note_batches: self.note_batches.len() as u64,
            address_epoch_policies: self.address_epoch_policies.len() as u64,
            decoy_preservations: self.decoy_preservations.len() as u64,
            view_key_redactions: self.view_key_redactions.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            liquidity_quotas: self.liquidity_quotas.len() as u64,
            sponsor_rebates: self.sponsor_rebates.len() as u64,
            public_records: self.public_record_count(),
            migrated_notes: self
                .note_batches
                .values()
                .filter(|batch| batch.status.live())
                .map(|batch| batch.note_count as u64)
                .sum(),
            liquidity_units_migrated: self
                .note_batches
                .values()
                .filter(|batch| batch.status.live())
                .map(|batch| batch.liquidity_units)
                .sum(),
            redaction_units_consumed: self
                .view_key_redactions
                .values()
                .map(|redaction| redaction.redaction_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            note_batch_root: map_root("note-batches", &self.note_batches, |item| {
                item.public_record()
            }),
            address_epoch_policy_root: map_root(
                "address-epoch-policies",
                &self.address_epoch_policies,
                |item| item.public_record(),
            ),
            decoy_preservation_root: map_root(
                "decoy-preservations",
                &self.decoy_preservations,
                |item| item.public_record(),
            ),
            view_key_redaction_root: map_root(
                "view-key-redactions",
                &self.view_key_redactions,
                |item| item.public_record(),
            ),
            watcher_attestation_root: map_root(
                "watcher-attestations",
                &self.watcher_attestations,
                |item| item.public_record(),
            ),
            liquidity_quota_root: map_root("liquidity-quotas", &self.liquidity_quotas, |item| {
                item.public_record()
            }),
            low_fee_rebate_root: map_root("low-fee-rebates", &self.sponsor_rebates, |item| {
                item.public_record()
            }),
            public_record_root: domain_hash(
                PUBLIC_RECORD_SCHEME,
                &[HashPart::Json(&self.public_records())],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "bridge_id": self.config.bridge_id,
            "asset_id": self.config.asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "hash_suite": self.config.hash_suite,
            "privacy": {
                "view_keys": "redacted",
                "amounts": "encrypted",
                "addresses": "commitment_roots_only",
                "decoys": "preserved_distribution_roots"
            },
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "records": self.public_records()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    fn public_record_count(&self) -> u64 {
        self.note_batches.len() as u64
            + self.address_epoch_policies.len() as u64
            + self.decoy_preservations.len() as u64
            + self.view_key_redactions.len() as u64
            + self.watcher_attestations.len() as u64
            + self.liquidity_quotas.len() as u64
            + self.sponsor_rebates.len() as u64
    }

    fn public_records(&self) -> Value {
        json!({
            "note_batches": map_records(&self.note_batches, |item| item.public_record()),
            "address_epoch_policies": map_records(&self.address_epoch_policies, |item| item.public_record()),
            "decoy_preservations": map_records(&self.decoy_preservations, |item| item.public_record()),
            "view_key_redactions": map_records(&self.view_key_redactions, |item| item.public_record()),
            "watcher_attestations": map_records(&self.watcher_attestations, |item| item.public_record()),
            "liquidity_quotas": map_records(&self.liquidity_quotas, |item| item.public_record()),
            "sponsor_rebates": map_records(&self.sponsor_rebates, |item| item.public_record())
        })
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT)
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

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(STATE_ROOT_DOMAIN, &[HashPart::Json(record)], 32)
}

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-SERAPHIS-JAMTIS-LIQUIDITY-MIGRATION-FIXED",
        &[HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-SERAPHIS-JAMTIS-LIQUIDITY-MIGRATION-ID",
        &[HashPart::Str(prefix), HashPart::Json(&json!(parts))],
        16,
    );
    format!("{prefix}-{root}")
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("monero-l2-pq-private-seraphis-jamtis-liquidity-migration:{label}"),
        &[],
    )
}

fn map_records<T, F>(values: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let mut object = serde_json::Map::new();
    for (key, value) in values {
        object.insert(key.clone(), public_record(value));
    }
    Value::Object(object)
}

fn map_root<T, F>(label: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value)
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-seraphis-jamtis-liquidity-migration:{label}"),
        &leaves,
    )
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current < max {
        Ok(())
    } else {
        Err(format!("{label} capacity exceeded"))
    }
}
