use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateSeraphisJamtisOutputNoteRecoveryCacheRuntimeResult<T>;
pub type MoneroL2PqPrivateSeraphisJamtisOutputNoteRecoveryCacheRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_OUTPUT_NOTE_RECOVERY_CACHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-jamtis-output-note-recovery-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_OUTPUT_NOTE_RECOVERY_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECOVERY_CACHE_SCHEME: &str = "seraphis-jamtis-output-note-recovery-cache-root-v1";
pub const VIEWTAG_PRIVACY_SCHEME: &str =
    "seraphis-jamtis-output-note-recovery-viewtag-privacy-root-v1";
pub const PQ_RECOVERY_COMMITMENT_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-output-note-recovery-commitment-root-v1";
pub const DECOY_FRESHNESS_SCHEME: &str = "seraphis-output-note-recovery-decoy-freshness-root-v1";
pub const LOW_FEE_RECOVERY_REBATE_SCHEME: &str =
    "low-fee-private-seraphis-jamtis-output-note-recovery-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-jamtis-output-note-recovery-cache-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_note_indices_or_recovery_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_104_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_780_000;
pub const DEVNET_EPOCH: u64 = 16_160;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 96;
pub const DEFAULT_MIN_RECOVERY_COHORT_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_VIEWTAG_PRIVACY_BPS: u64 = 8_900;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 7_900;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_VIEWTAG_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    WalletRestore,
    WatchOnlyRestore,
    BridgeWithdrawalRestore,
    MerchantReceiveRestore,
    SwapSettlementRestore,
    ReorgRepair,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WatchOnlyRestore => "watch_only_restore",
            Self::BridgeWithdrawalRestore => "bridge_withdrawal_restore",
            Self::MerchantReceiveRestore => "merchant_receive_restore",
            Self::SwapSettlementRestore => "swap_settlement_restore",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Draft,
    Cached,
    ViewtagPrivate,
    Committed,
    Fresh,
    RebateEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl RecoveryStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Cached
                | Self::ViewtagPrivate
                | Self::Committed
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
    pub min_recovery_cohort_outputs: u64,
    pub target_recovery_cohort_outputs: u64,
    pub min_viewtag_privacy_bps: u64,
    pub min_decoy_freshness_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub recovery_ttl_blocks: u64,
    pub viewtag_window_blocks: u64,
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
            min_recovery_cohort_outputs: DEFAULT_MIN_RECOVERY_COHORT_OUTPUTS,
            target_recovery_cohort_outputs: DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS,
            min_viewtag_privacy_bps: DEFAULT_MIN_VIEWTAG_PRIVACY_BPS,
            min_decoy_freshness_bps: DEFAULT_MIN_DECOY_FRESHNESS_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            recovery_ttl_blocks: DEFAULT_RECOVERY_TTL_BLOCKS,
            viewtag_window_blocks: DEFAULT_VIEWTAG_WINDOW_BLOCKS,
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
            self.target_recovery_cohort_outputs >= self.min_recovery_cohort_outputs,
            "target recovery cohort must cover privacy floor",
        )?;
        ensure(
            self.min_viewtag_privacy_bps <= MAX_BPS && self.min_decoy_freshness_bps <= MAX_BPS,
            "privacy thresholds exceed max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.recovery_ttl_blocks > 0,
            "recovery ttl must be non-zero",
        )?;
        ensure(
            self.viewtag_window_blocks > 0,
            "viewtag window must be non-zero",
        )?;
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
            "seraphis-jamtis-output-note-recovery-cache-config",
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
    pub recovery_cache_entries: u64,
    pub viewtag_privacy_windows: u64,
    pub pq_recovery_commitments: u64,
    pub decoy_freshness_claims: u64,
    pub low_fee_recovery_rebates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "seraphis-jamtis-output-note-recovery-cache-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub recovery_cache_entries_root: String,
    pub viewtag_privacy_windows_root: String,
    pub pq_recovery_commitments_root: String,
    pub decoy_freshness_claims_root: String,
    pub low_fee_recovery_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            recovery_cache_entries_root: empty_root(RECOVERY_CACHE_SCHEME),
            viewtag_privacy_windows_root: empty_root(VIEWTAG_PRIVACY_SCHEME),
            pq_recovery_commitments_root: empty_root(PQ_RECOVERY_COMMITMENT_SCHEME),
            decoy_freshness_claims_root: empty_root(DECOY_FRESHNESS_SCHEME),
            low_fee_recovery_rebates_root: empty_root(LOW_FEE_RECOVERY_REBATE_SCHEME),
            deterministic_state_root: empty_root(
                "seraphis-jamtis-output-note-recovery-cache-state",
            ),
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
pub struct RecoveryCacheEntry {
    pub cache_id: String,
    pub lane: RecoveryLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub recovery_cohort_outputs: u64,
    pub encrypted_note_hint_root: String,
    pub jamtis_recovery_tag_root: String,
    pub seraphis_membership_root: String,
    pub expires_at_monero_height: u64,
    pub status: RecoveryStatus,
}

impl RecoveryCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "cache_id": self.cache_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "recovery_cohort_outputs": self.recovery_cohort_outputs,
            "encrypted_note_hint_root": self.encrypted_note_hint_root,
            "jamtis_recovery_tag_root": self.jamtis_recovery_tag_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(RECOVERY_CACHE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagPrivacyWindow {
    pub window_id: String,
    pub cache_id: String,
    pub viewtag_window_blocks: u64,
    pub viewtag_privacy_bps: u64,
    pub redacted_viewtag_hint_root: String,
    pub recovery_wallet_cohort_root: String,
    pub status: RecoveryStatus,
}

impl ViewtagPrivacyWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(VIEWTAG_PRIVACY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRecoveryCommitment {
    pub commitment_id: String,
    pub cache_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub recovery_commitment_root: String,
    pub attestation_root: String,
    pub status: RecoveryStatus,
}

impl PqRecoveryCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_RECOVERY_COMMITMENT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessClaim {
    pub freshness_id: String,
    pub cache_id: String,
    pub ring_size: u16,
    pub decoy_freshness_bps: u64,
    pub output_age_distribution_root: String,
    pub replacement_decoy_root: String,
    pub expires_at_monero_height: u64,
    pub status: RecoveryStatus,
}

impl DecoyFreshnessClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_FRESHNESS_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRecoveryRebate {
    pub rebate_id: String,
    pub cache_id: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub recovery_window_root: String,
    pub sponsor_receipt_root: String,
}

impl LowFeeRecoveryRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_RECOVERY_REBATE_SCHEME, &self.public_record())
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
    pub recovery_cache_entries: BTreeMap<String, RecoveryCacheEntry>,
    pub viewtag_privacy_windows: BTreeMap<String, ViewtagPrivacyWindow>,
    pub pq_recovery_commitments: BTreeMap<String, PqRecoveryCommitment>,
    pub decoy_freshness_claims: BTreeMap<String, DecoyFreshnessClaim>,
    pub low_fee_recovery_rebates: BTreeMap<String, LowFeeRecoveryRebate>,
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
            recovery_cache_entries: BTreeMap::new(),
            viewtag_privacy_windows: BTreeMap::new(),
            pq_recovery_commitments: BTreeMap::new(),
            decoy_freshness_claims: BTreeMap::new(),
            low_fee_recovery_rebates: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_seraphis_jamtis_output_note_recovery_cache_runtime",
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

    pub fn insert_recovery_cache_entry(&mut self, entry: RecoveryCacheEntry) -> Result<()> {
        ensure(
            entry.recovery_cohort_outputs >= self.config.min_recovery_cohort_outputs,
            "recovery cache entry is below output cohort privacy floor",
        )?;
        ensure(
            entry.expires_at_monero_height > self.monero_height,
            "recovery cache entry must expire in the future",
        )?;
        self.recovery_cache_entries
            .insert(entry.cache_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_viewtag_privacy_window(&mut self, window: ViewtagPrivacyWindow) -> Result<()> {
        ensure(
            self.recovery_cache_entries.contains_key(&window.cache_id),
            "viewtag privacy window references unknown recovery cache entry",
        )?;
        ensure(
            window.viewtag_window_blocks <= self.config.viewtag_window_blocks,
            "viewtag privacy window exceeds configured window",
        )?;
        ensure(
            window.viewtag_privacy_bps >= self.config.min_viewtag_privacy_bps,
            "viewtag privacy score is below floor",
        )?;
        self.viewtag_privacy_windows
            .insert(window.window_id.clone(), window);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_recovery_commitment(
        &mut self,
        commitment: PqRecoveryCommitment,
    ) -> Result<()> {
        ensure(
            self.recovery_cache_entries
                .contains_key(&commitment.cache_id),
            "PQ recovery commitment references unknown recovery cache entry",
        )?;
        ensure(
            commitment.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ recovery commitment is below minimum security",
        )?;
        ensure(
            commitment.classical_fallback_disabled,
            "PQ recovery commitment must disable classical fallback",
        )?;
        self.pq_recovery_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_freshness_claim(&mut self, freshness: DecoyFreshnessClaim) -> Result<()> {
        ensure(
            self.recovery_cache_entries
                .contains_key(&freshness.cache_id),
            "decoy freshness claim references unknown recovery cache entry",
        )?;
        ensure(
            freshness.ring_size >= self.config.min_ring_size,
            "decoy freshness ring size is below minimum",
        )?;
        ensure(
            freshness.decoy_freshness_bps >= self.config.min_decoy_freshness_bps,
            "decoy freshness score is below floor",
        )?;
        ensure(
            freshness.expires_at_monero_height > self.monero_height,
            "decoy freshness claim must expire in the future",
        )?;
        self.decoy_freshness_claims
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_recovery_rebate(&mut self, rebate: LowFeeRecoveryRebate) -> Result<()> {
        ensure(
            self.recovery_cache_entries.contains_key(&rebate.cache_id),
            "recovery rebate references unknown recovery cache entry",
        )?;
        ensure(
            rebate.user_fee_bps <= self.config.max_user_fee_bps,
            "recovery rebate user fee exceeds low-fee cap",
        )?;
        ensure(
            rebate.rebate_bps <= rebate.user_fee_bps,
            "recovery rebate exceeds charged fee",
        )?;
        self.low_fee_recovery_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.recovery_cache_entries = self.recovery_cache_entries.len() as u64;
        self.counters.viewtag_privacy_windows = self.viewtag_privacy_windows.len() as u64;
        self.counters.pq_recovery_commitments = self.pq_recovery_commitments.len() as u64;
        self.counters.decoy_freshness_claims = self.decoy_freshness_claims.len() as u64;
        self.counters.low_fee_recovery_rebates = self.low_fee_recovery_rebates.len() as u64;

        self.roots.recovery_cache_entries_root = map_root(
            RECOVERY_CACHE_SCHEME,
            self.recovery_cache_entries
                .iter()
                .map(|(id, entry)| (id.as_str(), entry.state_root())),
        );
        self.roots.viewtag_privacy_windows_root = map_root(
            VIEWTAG_PRIVACY_SCHEME,
            self.viewtag_privacy_windows
                .iter()
                .map(|(id, window)| (id.as_str(), window.state_root())),
        );
        self.roots.pq_recovery_commitments_root = map_root(
            PQ_RECOVERY_COMMITMENT_SCHEME,
            self.pq_recovery_commitments
                .iter()
                .map(|(id, commitment)| (id.as_str(), commitment.state_root())),
        );
        self.roots.decoy_freshness_claims_root = map_root(
            DECOY_FRESHNESS_SCHEME,
            self.decoy_freshness_claims
                .iter()
                .map(|(id, freshness)| (id.as_str(), freshness.state_root())),
        );
        self.roots.low_fee_recovery_rebates_root = map_root(
            LOW_FEE_RECOVERY_REBATE_SCHEME,
            self.low_fee_recovery_rebates
                .iter()
                .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "seraphis-jamtis-output-note-recovery-cache-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.recovery_cache_entries_root),
                HashPart::Str(&self.roots.viewtag_privacy_windows_root),
                HashPart::Str(&self.roots.pq_recovery_commitments_root),
                HashPart::Str(&self.roots.decoy_freshness_claims_root),
                HashPart::Str(&self.roots.low_fee_recovery_rebates_root),
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
        .expect("default Seraphis JAMTIS output note recovery cache config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let cache_id = "seraphis-jamtis-output-note-recovery-cache-devnet-0".to_string();

    state
        .insert_recovery_cache_entry(RecoveryCacheEntry {
            cache_id: cache_id.clone(),
            lane: RecoveryLane::WalletRestore,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            recovery_cohort_outputs: DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS,
            encrypted_note_hint_root: root_from_parts(
                "devnet-encrypted-output-note-recovery-hint",
                &[HashPart::Str(&cache_id)],
            ),
            jamtis_recovery_tag_root: root_from_parts(
                "devnet-jamtis-output-note-recovery-tag",
                &[HashPart::Str(&cache_id)],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-output-note-membership",
                &[HashPart::Str(&cache_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: RecoveryStatus::Cached,
        })
        .expect("devnet recovery cache entry inserts");
    state
        .insert_viewtag_privacy_window(ViewtagPrivacyWindow {
            window_id: "seraphis-jamtis-output-note-viewtag-privacy-devnet-0".to_string(),
            cache_id: cache_id.clone(),
            viewtag_window_blocks: DEFAULT_VIEWTAG_WINDOW_BLOCKS,
            viewtag_privacy_bps: 9_180,
            redacted_viewtag_hint_root: root_from_parts(
                "devnet-redacted-output-note-viewtag-hint",
                &[HashPart::Str("0")],
            ),
            recovery_wallet_cohort_root: root_from_parts(
                "devnet-recovery-wallet-cohort",
                &[HashPart::Str(&cache_id)],
            ),
            status: RecoveryStatus::ViewtagPrivate,
        })
        .expect("devnet viewtag privacy inserts");
    state
        .insert_pq_recovery_commitment(PqRecoveryCommitment {
            commitment_id: "seraphis-jamtis-output-note-pq-recovery-commitment-devnet-0"
                .to_string(),
            cache_id: cache_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            recovery_commitment_root: root_from_parts(
                "devnet-output-note-pq-recovery-commitment",
                &[HashPart::Str(&cache_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-output-note-pq-recovery-attestation",
                &[HashPart::Str(&cache_id)],
            ),
            status: RecoveryStatus::Committed,
        })
        .expect("devnet PQ recovery commitment inserts");
    state
        .insert_decoy_freshness_claim(DecoyFreshnessClaim {
            freshness_id: "seraphis-output-note-recovery-decoy-freshness-devnet-0".to_string(),
            cache_id: cache_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_freshness_bps: 8_960,
            output_age_distribution_root: root_from_parts(
                "devnet-output-note-recovery-decoy-age-distribution",
                &[HashPart::Str(&cache_id)],
            ),
            replacement_decoy_root: root_from_parts(
                "devnet-output-note-recovery-replacement-decoy",
                &[HashPart::Str(&cache_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: RecoveryStatus::Fresh,
        })
        .expect("devnet decoy freshness inserts");
    state
        .insert_low_fee_recovery_rebate(LowFeeRecoveryRebate {
            rebate_id: "seraphis-jamtis-output-note-low-fee-recovery-rebate-devnet-0".to_string(),
            cache_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            recovery_window_root: root_from_parts(
                "devnet-output-note-recovery-window",
                &[HashPart::Str("0")],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-output-note-recovery-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
        })
        .expect("devnet low-fee recovery rebate inserts");

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
    domain_hash(
        &format!("SERAPHIS-JAMTIS-OUTPUT-NOTE-RECOVERY-CACHE-{domain}"),
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
        &format!("SERAPHIS-JAMTIS-OUTPUT-NOTE-RECOVERY-CACHE-{domain}"),
        &leaves,
    )
}
