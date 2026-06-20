use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateJamtisSeraphisStealthNoteIndexRuntimeResult<T>;
pub type MoneroL2PqPrivateJamtisSeraphisStealthNoteIndexRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_STEALTH_NOTE_INDEX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-seraphis-stealth-note-index-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_STEALTH_NOTE_INDEX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STEALTH_NOTE_INDEX_SCHEME: &str = "monero-jamtis-seraphis-stealth-note-index-root-v1";
pub const VIEWTAG_SCAN_PRIVACY_SCHEME: &str =
    "view-key-safe-jamtis-seraphis-viewtag-scan-privacy-root-v1";
pub const PQ_MIGRATION_GUARDRAIL_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-seraphis-stealth-note-guardrail-v1";
pub const RING_MEMBER_DECOY_FRESHNESS_SCHEME: &str = "seraphis-ring-member-decoy-freshness-root-v1";
pub const LOW_FEE_WALLET_SYNC_REBATE_SCHEME: &str =
    "low-fee-private-jamtis-seraphis-wallet-sync-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-jamtis-seraphis-stealth-note-index-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_note_indices_or_ring_witnesses";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_096_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_772_000;
pub const DEVNET_EPOCH: u64 = 15_840;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 96;
pub const DEFAULT_MIN_NOTE_COHORT_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_NOTE_COHORT_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_VIEWTAG_PRIVACY_BPS: u64 = 8_800;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 7_800;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_INDEX_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexLane {
    WalletReceive,
    MerchantReceive,
    BridgeWithdrawal,
    SwapSettlement,
    WatchOnlyAudit,
    ReorgRepair,
}

impl IndexLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceive => "wallet_receive",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::SwapSettlement => "swap_settlement",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStatus {
    Draft,
    Indexed,
    ScanPrivate,
    Guarded,
    Fresh,
    RebateEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl IndexStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Indexed
                | Self::ScanPrivate
                | Self::Guarded
                | Self::Fresh
                | Self::RebateEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_note_cohort_outputs: u64,
    pub target_note_cohort_outputs: u64,
    pub min_viewtag_privacy_bps: u64,
    pub min_decoy_freshness_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub scan_window_blocks: u64,
    pub index_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub public_bucket_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_note_cohort_outputs: DEFAULT_MIN_NOTE_COHORT_OUTPUTS,
            target_note_cohort_outputs: DEFAULT_TARGET_NOTE_COHORT_OUTPUTS,
            min_viewtag_privacy_bps: DEFAULT_MIN_VIEWTAG_PRIVACY_BPS,
            min_decoy_freshness_bps: DEFAULT_MIN_DECOY_FRESHNESS_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            index_ttl_blocks: DEFAULT_INDEX_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(self.min_ring_size >= 16, "minimum ring size is too low")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_note_cohort_outputs >= self.min_note_cohort_outputs,
            "target note cohort must cover privacy floor",
        )?;
        ensure(
            self.min_viewtag_privacy_bps <= MAX_BPS && self.min_decoy_freshness_bps <= MAX_BPS,
            "privacy thresholds exceed max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(self.scan_window_blocks > 0, "scan window must be non-zero")?;
        ensure(self.index_ttl_blocks > 0, "index ttl must be non-zero")?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS,
            "maximum user fee bps exceeds bound",
        )?;
        ensure(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate bps must not exceed fee bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "jamtis-seraphis-stealth-note-index-config",
            &self.public_record(),
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
    pub stealth_note_indexes: u64,
    pub viewtag_scan_privacy_windows: u64,
    pub pq_migration_guardrails: u64,
    pub ring_member_decoy_freshness: u64,
    pub low_fee_wallet_sync_rebates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "jamtis-seraphis-stealth-note-index-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub stealth_note_indexes_root: String,
    pub viewtag_scan_privacy_windows_root: String,
    pub pq_migration_guardrails_root: String,
    pub ring_member_decoy_freshness_root: String,
    pub low_fee_wallet_sync_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            stealth_note_indexes_root: empty_root(STEALTH_NOTE_INDEX_SCHEME),
            viewtag_scan_privacy_windows_root: empty_root(VIEWTAG_SCAN_PRIVACY_SCHEME),
            pq_migration_guardrails_root: empty_root(PQ_MIGRATION_GUARDRAIL_SCHEME),
            ring_member_decoy_freshness_root: empty_root(RING_MEMBER_DECOY_FRESHNESS_SCHEME),
            low_fee_wallet_sync_rebates_root: empty_root(LOW_FEE_WALLET_SYNC_REBATE_SCHEME),
            deterministic_state_root: empty_root("jamtis-seraphis-stealth-note-index-state"),
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
pub struct StealthNoteIndex {
    pub index_id: String,
    pub lane: IndexLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub note_count_bucket: u64,
    pub viewtag_bucket_root: String,
    pub jamtis_note_commitment_root: String,
    pub seraphis_membership_root: String,
    pub expires_at_monero_height: u64,
    pub status: IndexStatus,
}

impl StealthNoteIndex {
    pub fn public_record(&self) -> Value {
        json!({
            "index_id": self.index_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "note_count_bucket": self.note_count_bucket,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "jamtis_note_commitment_root": self.jamtis_note_commitment_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(STEALTH_NOTE_INDEX_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanPrivacyWindow {
    pub window_id: String,
    pub index_id: String,
    pub scan_window_blocks: u64,
    pub viewtag_privacy_bps: u64,
    pub redacted_scan_hint_root: String,
    pub wallet_cohort_root: String,
    pub status: IndexStatus,
}

impl ViewtagScanPrivacyWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(VIEWTAG_SCAN_PRIVACY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationGuardrail {
    pub guardrail_id: String,
    pub index_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub attestation_root: String,
    pub status: IndexStatus,
}

impl PqMigrationGuardrail {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_GUARDRAIL_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberDecoyFreshness {
    pub freshness_id: String,
    pub index_id: String,
    pub ring_size: u16,
    pub decoy_freshness_bps: u64,
    pub age_distribution_root: String,
    pub replacement_hint_root: String,
    pub expires_at_monero_height: u64,
    pub status: IndexStatus,
}

impl RingMemberDecoyFreshness {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_MEMBER_DECOY_FRESHNESS_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeWalletSyncRebate {
    pub rebate_id: String,
    pub index_id: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sync_window_root: String,
    pub sponsor_receipt_root: String,
}

impl LowFeeWalletSyncRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_WALLET_SYNC_REBATE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub stealth_note_indexes: BTreeMap<String, StealthNoteIndex>,
    pub viewtag_scan_privacy_windows: BTreeMap<String, ViewtagScanPrivacyWindow>,
    pub pq_migration_guardrails: BTreeMap<String, PqMigrationGuardrail>,
    pub ring_member_decoy_freshness: BTreeMap<String, RingMemberDecoyFreshness>,
    pub low_fee_wallet_sync_rebates: BTreeMap<String, LowFeeWalletSyncRebate>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            config,
            l2_height,
            monero_height,
            epoch,
            stealth_note_indexes: BTreeMap::new(),
            viewtag_scan_privacy_windows: BTreeMap::new(),
            pq_migration_guardrails: BTreeMap::new(),
            ring_member_decoy_freshness: BTreeMap::new(),
            low_fee_wallet_sync_rebates: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::empty(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime": "monero_l2_pq_private_jamtis_seraphis_stealth_note_index_runtime",
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "hash_suite": HASH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "l2_height": bucket(self.l2_height, self.config.public_bucket_size),
            "monero_height": bucket(self.monero_height, self.config.public_bucket_size),
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.deterministic_state_root.clone()
    }

    pub fn insert_stealth_note_index(&mut self, index: StealthNoteIndex) -> Result<()> {
        ensure(
            index.note_count_bucket >= self.config.min_note_cohort_outputs,
            "stealth note index is below note cohort privacy floor",
        )?;
        ensure(
            index.expires_at_monero_height > self.monero_height,
            "stealth note index must expire in the future",
        )?;
        self.stealth_note_indexes
            .insert(index.index_id.clone(), index);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_viewtag_scan_privacy_window(
        &mut self,
        window: ViewtagScanPrivacyWindow,
    ) -> Result<()> {
        ensure(
            self.stealth_note_indexes.contains_key(&window.index_id),
            "viewtag scan privacy window references unknown index",
        )?;
        ensure(
            window.scan_window_blocks <= self.config.scan_window_blocks,
            "viewtag scan privacy window exceeds configured window",
        )?;
        ensure(
            window.viewtag_privacy_bps >= self.config.min_viewtag_privacy_bps,
            "viewtag scan privacy score is below floor",
        )?;
        self.viewtag_scan_privacy_windows
            .insert(window.window_id.clone(), window);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_guardrail(&mut self, guardrail: PqMigrationGuardrail) -> Result<()> {
        ensure(
            self.stealth_note_indexes.contains_key(&guardrail.index_id),
            "PQ migration guardrail references unknown index",
        )?;
        ensure(
            guardrail.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ migration guardrail is below minimum security",
        )?;
        ensure(
            guardrail.classical_fallback_disabled,
            "PQ migration guardrail must disable classical fallback",
        )?;
        self.pq_migration_guardrails
            .insert(guardrail.guardrail_id.clone(), guardrail);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_member_decoy_freshness(
        &mut self,
        freshness: RingMemberDecoyFreshness,
    ) -> Result<()> {
        ensure(
            self.stealth_note_indexes.contains_key(&freshness.index_id),
            "ring-member decoy freshness references unknown index",
        )?;
        ensure(
            freshness.ring_size >= self.config.min_ring_size,
            "ring-member decoy freshness ring size is below minimum",
        )?;
        ensure(
            freshness.decoy_freshness_bps >= self.config.min_decoy_freshness_bps,
            "ring-member decoy freshness is below floor",
        )?;
        self.ring_member_decoy_freshness
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_wallet_sync_rebate(
        &mut self,
        rebate: LowFeeWalletSyncRebate,
    ) -> Result<()> {
        ensure(
            self.stealth_note_indexes.contains_key(&rebate.index_id),
            "wallet sync rebate references unknown index",
        )?;
        ensure(
            rebate.user_fee_bps <= self.config.max_user_fee_bps,
            "wallet sync rebate user fee exceeds low-fee cap",
        )?;
        ensure(
            rebate.rebate_bps <= rebate.user_fee_bps,
            "wallet sync rebate exceeds charged fee",
        )?;
        self.low_fee_wallet_sync_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.stealth_note_indexes = self.stealth_note_indexes.len() as u64;
        self.counters.viewtag_scan_privacy_windows = self.viewtag_scan_privacy_windows.len() as u64;
        self.counters.pq_migration_guardrails = self.pq_migration_guardrails.len() as u64;
        self.counters.ring_member_decoy_freshness = self.ring_member_decoy_freshness.len() as u64;
        self.counters.low_fee_wallet_sync_rebates = self.low_fee_wallet_sync_rebates.len() as u64;

        self.roots.stealth_note_indexes_root = map_root(
            STEALTH_NOTE_INDEX_SCHEME,
            self.stealth_note_indexes
                .iter()
                .map(|(id, index)| (id.as_str(), index.state_root())),
        );
        self.roots.viewtag_scan_privacy_windows_root = map_root(
            VIEWTAG_SCAN_PRIVACY_SCHEME,
            self.viewtag_scan_privacy_windows
                .iter()
                .map(|(id, window)| (id.as_str(), window.state_root())),
        );
        self.roots.pq_migration_guardrails_root = map_root(
            PQ_MIGRATION_GUARDRAIL_SCHEME,
            self.pq_migration_guardrails
                .iter()
                .map(|(id, guardrail)| (id.as_str(), guardrail.state_root())),
        );
        self.roots.ring_member_decoy_freshness_root = map_root(
            RING_MEMBER_DECOY_FRESHNESS_SCHEME,
            self.ring_member_decoy_freshness
                .iter()
                .map(|(id, freshness)| (id.as_str(), freshness.state_root())),
        );
        self.roots.low_fee_wallet_sync_rebates_root = map_root(
            LOW_FEE_WALLET_SYNC_REBATE_SCHEME,
            self.low_fee_wallet_sync_rebates
                .iter()
                .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "jamtis-seraphis-stealth-note-index-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.stealth_note_indexes_root),
                HashPart::Str(&self.roots.viewtag_scan_privacy_windows_root),
                HashPart::Str(&self.roots.pq_migration_guardrails_root),
                HashPart::Str(&self.roots.ring_member_decoy_freshness_root),
                HashPart::Str(&self.roots.low_fee_wallet_sync_rebates_root),
            ],
        )
    }
}

impl Default for State {
    fn default() -> Self {
        State::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("default JAMTIS Seraphis stealth note index config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let index_id = "jamtis-seraphis-stealth-note-index-devnet-0".to_string();

    state
        .insert_stealth_note_index(StealthNoteIndex {
            index_id: index_id.clone(),
            lane: IndexLane::WalletReceive,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            note_count_bucket: DEFAULT_TARGET_NOTE_COHORT_OUTPUTS,
            viewtag_bucket_root: root_from_parts(
                "devnet-stealth-note-viewtag-bucket",
                &[HashPart::Str(&index_id)],
            ),
            jamtis_note_commitment_root: root_from_parts(
                "devnet-jamtis-note-commitment",
                &[HashPart::Str(&index_id)],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-note-membership",
                &[HashPart::Str(&index_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_INDEX_TTL_BLOCKS,
            status: IndexStatus::Indexed,
        })
        .expect("devnet stealth note index inserts");
    state
        .insert_viewtag_scan_privacy_window(ViewtagScanPrivacyWindow {
            window_id: "jamtis-seraphis-viewtag-scan-window-devnet-0".to_string(),
            index_id: index_id.clone(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            viewtag_privacy_bps: 9_120,
            redacted_scan_hint_root: root_from_parts(
                "devnet-redacted-viewtag-scan-hint",
                &[HashPart::Str("0")],
            ),
            wallet_cohort_root: root_from_parts(
                "devnet-wallet-scan-cohort",
                &[HashPart::Str(&index_id)],
            ),
            status: IndexStatus::ScanPrivate,
        })
        .expect("devnet viewtag scan privacy inserts");
    state
        .insert_pq_migration_guardrail(PqMigrationGuardrail {
            guardrail_id: "jamtis-seraphis-stealth-note-pq-guardrail-devnet-0".to_string(),
            index_id: index_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            attestation_root: root_from_parts(
                "devnet-stealth-note-pq-attestation",
                &[HashPart::Str(&index_id)],
            ),
            status: IndexStatus::Guarded,
        })
        .expect("devnet PQ migration guardrail inserts");
    state
        .insert_ring_member_decoy_freshness(RingMemberDecoyFreshness {
            freshness_id: "seraphis-ring-member-decoy-freshness-devnet-0".to_string(),
            index_id: index_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_freshness_bps: 8_940,
            age_distribution_root: root_from_parts(
                "devnet-seraphis-decoy-age-distribution",
                &[HashPart::Str(&index_id)],
            ),
            replacement_hint_root: root_from_parts(
                "devnet-seraphis-decoy-replacement-hint",
                &[HashPart::Str(&index_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_INDEX_TTL_BLOCKS,
            status: IndexStatus::Fresh,
        })
        .expect("devnet ring-member decoy freshness inserts");
    state
        .insert_low_fee_wallet_sync_rebate(LowFeeWalletSyncRebate {
            rebate_id: "jamtis-seraphis-low-fee-wallet-sync-rebate-devnet-0".to_string(),
            index_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sync_window_root: root_from_parts("devnet-wallet-sync-window", &[HashPart::Str("0")]),
            sponsor_receipt_root: root_from_parts(
                "devnet-wallet-sync-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
        })
        .expect("devnet low-fee wallet sync rebate inserts");

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
    domain_hash(domain, parts, 32)
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
    merkle_root(domain, &leaves)
}
