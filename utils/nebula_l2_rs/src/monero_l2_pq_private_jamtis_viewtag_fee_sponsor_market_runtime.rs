use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisViewtagFeeSponsorMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_FEE_SPONSOR_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-viewtag-fee-sponsor-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_FEE_SPONSOR_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-l2-pq-private-jamtis-viewtag-fee-sponsor-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_612_800;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const JAMTIS_HINT_SCHEME: &str = "monero-jamtis-routing-hint-commitment-root-v1";
pub const VIEWTAG_SCAN_REBATE_SCHEME: &str = "monero-viewtag-scan-rebate-market-root-v1";
pub const SPONSOR_INTENT_SCHEME: &str = "pq-private-fee-sponsor-intent-root-v1";
pub const PQ_AUTHORIZATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-authorization-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "operator-safe-jamtis-viewtag-privacy-budget-root-v1";
pub const NULLIFIER_GUARD_SCHEME: &str = "jamtis-viewtag-fee-sponsor-nullifier-guard-root-v1";
pub const FEE_MARKET_SCHEME: &str = "low-scan-cost-jamtis-viewtag-fee-market-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-redacted-sponsor-market-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "jamtis-viewtag-fee-sponsor-public-record-root-v1";
pub const STATE_ROOT_DOMAIN: &str = "MONERO-L2-PQ-PRIVATE-JAMTIS-VIEWTAG-FEE-SPONSOR-MARKET-STATE";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_view_keys_key_images_or_wallet_graphs";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_JAMTIS_EPOCH_OUTPUTS: u32 = 512;
pub const DEFAULT_TARGET_JAMTIS_EPOCH_OUTPUTS: u32 = 8_192;
pub const DEFAULT_MIN_VIEWTAG_BUCKET_SIZE: u32 = 64;
pub const DEFAULT_TARGET_VIEWTAG_BUCKET_SIZE: u32 = 1_024;
pub const DEFAULT_MAX_SCAN_FEE_PICONERO: u64 = 3_200;
pub const DEFAULT_TARGET_SCAN_FEE_PICONERO: u64 = 900;
pub const DEFAULT_MAX_SPONSOR_FEE_PICONERO: u64 = 7_500;
pub const DEFAULT_REBATE_BPS: u64 = 8_750;
pub const DEFAULT_SPONSOR_FILL_BPS: u64 = 9_200;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 800;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_AUTHORIZATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_NULLIFIER_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 65_536;
pub const DEFAULT_DAILY_WALLET_CAP_PICONERO: u64 = 150_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingLane {
    WalletIncremental,
    WalletRestore,
    MerchantReceive,
    BridgeDeposit,
    BridgeWithdrawal,
    AtomicSwap,
    WatchOnlyAudit,
    ReorgRepair,
    Emergency,
}

impl RoutingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletIncremental => "wallet_incremental",
            Self::WalletRestore => "wallet_restore",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::AtomicSwap => "atomic_swap",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::ReorgRepair => 960,
            Self::BridgeWithdrawal => 930,
            Self::BridgeDeposit => 900,
            Self::WalletRestore => 860,
            Self::AtomicSwap => 840,
            Self::MerchantReceive => 820,
            Self::WatchOnlyAudit => 780,
            Self::WalletIncremental => 720,
        }
    }

    pub fn scan_fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::WalletIncremental => config.target_scan_fee_piconero,
            Self::WalletRestore | Self::WatchOnlyAudit => config.max_scan_fee_piconero * 8 / 10,
            Self::MerchantReceive | Self::AtomicSwap => config.max_scan_fee_piconero * 9 / 10,
            Self::BridgeDeposit | Self::BridgeWithdrawal | Self::ReorgRepair | Self::Emergency => {
                config.max_scan_fee_piconero
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Draft,
    Committed,
    Bucketed,
    RebateQuoted,
    Sponsored,
    Authorized,
    Anchored,
    Settled,
    Expired,
    Rejected,
}

impl HintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Bucketed => "bucketed",
            Self::RebateQuoted => "rebate_quoted",
            Self::Sponsored => "sponsored",
            Self::Authorized => "authorized",
            Self::Anchored => "anchored",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Bucketed
                | Self::RebateQuoted
                | Self::Sponsored
                | Self::Authorized
                | Self::Anchored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    ScanProved,
    Authorized,
    Settled,
    ClawedBack,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorIntentStatus {
    Open,
    Matched,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Slashed,
}

impl SponsorIntentStatus {
    pub fn accepts_matches(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::PartiallyFilled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Submitted,
    Accepted,
    StrongQuorum,
    WeakPqEvidence,
    Revoked,
    Expired,
    Rejected,
}

impl AuthorizationStatus {
    pub fn counts_for_settlement(self) -> bool {
        matches!(self, Self::Accepted | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    JamtisHint,
    ViewtagBucket,
    ScanWork,
    SponsorMetadata,
    AuthorizationReceipt,
    PublicAudit,
    OperatorSummary,
}

impl BudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JamtisHint => "jamtis_hint",
            Self::ViewtagBucket => "viewtag_bucket",
            Self::ScanWork => "scan_work",
            Self::SponsorMetadata => "sponsor_metadata",
            Self::AuthorizationReceipt => "authorization_receipt",
            Self::PublicAudit => "public_audit",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Spent,
    Settled,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Balanced,
    SponsorHeavy,
    ScanHeavy,
    Throttled,
    Paused,
    EmergencyOnly,
}

impl MarketStatus {
    pub fn accepts_flow(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Balanced | Self::SponsorHeavy | Self::ScanHeavy
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHealth {
    Nominal,
    Watch,
    Backpressure,
    PrivacyBudgetLow,
    PqQuorumWeak,
    Paused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub bridge_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub jamtis_hint_scheme: String,
    pub viewtag_scan_rebate_scheme: String,
    pub sponsor_intent_scheme: String,
    pub pq_authorization_scheme: String,
    pub privacy_budget_scheme: String,
    pub nullifier_guard_scheme: String,
    pub fee_market_scheme: String,
    pub operator_summary_scheme: String,
    pub public_record_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_jamtis_epoch_outputs: u32,
    pub target_jamtis_epoch_outputs: u32,
    pub min_viewtag_bucket_size: u32,
    pub target_viewtag_bucket_size: u32,
    pub max_scan_fee_piconero: u64,
    pub target_scan_fee_piconero: u64,
    pub max_sponsor_fee_piconero: u64,
    pub rebate_bps: u64,
    pub sponsor_fill_bps: u64,
    pub operator_fee_share_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub hint_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub authorization_ttl_blocks: u64,
    pub nullifier_ttl_blocks: u64,
    pub privacy_budget_units: u64,
    pub daily_wallet_cap_piconero: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            jamtis_hint_scheme: JAMTIS_HINT_SCHEME.to_string(),
            viewtag_scan_rebate_scheme: VIEWTAG_SCAN_REBATE_SCHEME.to_string(),
            sponsor_intent_scheme: SPONSOR_INTENT_SCHEME.to_string(),
            pq_authorization_scheme: PQ_AUTHORIZATION_SCHEME.to_string(),
            privacy_budget_scheme: PRIVACY_BUDGET_SCHEME.to_string(),
            nullifier_guard_scheme: NULLIFIER_GUARD_SCHEME.to_string(),
            fee_market_scheme: FEE_MARKET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_jamtis_epoch_outputs: DEFAULT_MIN_JAMTIS_EPOCH_OUTPUTS,
            target_jamtis_epoch_outputs: DEFAULT_TARGET_JAMTIS_EPOCH_OUTPUTS,
            min_viewtag_bucket_size: DEFAULT_MIN_VIEWTAG_BUCKET_SIZE,
            target_viewtag_bucket_size: DEFAULT_TARGET_VIEWTAG_BUCKET_SIZE,
            max_scan_fee_piconero: DEFAULT_MAX_SCAN_FEE_PICONERO,
            target_scan_fee_piconero: DEFAULT_TARGET_SCAN_FEE_PICONERO,
            max_sponsor_fee_piconero: DEFAULT_MAX_SPONSOR_FEE_PICONERO,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_fill_bps: DEFAULT_SPONSOR_FILL_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            authorization_ttl_blocks: DEFAULT_AUTHORIZATION_TTL_BLOCKS,
            nullifier_ttl_blocks: DEFAULT_NULLIFIER_TTL_BLOCKS,
            privacy_budget_units: DEFAULT_PRIVACY_BUDGET_UNITS,
            daily_wallet_cap_piconero: DEFAULT_DAILY_WALLET_CAP_PICONERO,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE / 2 {
            return Err("privacy set size below Monero-compatible floor".to_string());
        }
        if self.min_jamtis_epoch_outputs == 0 || self.min_viewtag_bucket_size == 0 {
            return Err("JAMTIS epoch and viewtag bucket sizes must be non-zero".to_string());
        }
        if self.target_jamtis_epoch_outputs < self.min_jamtis_epoch_outputs {
            return Err("target JAMTIS epoch outputs below minimum".to_string());
        }
        if self.target_viewtag_bucket_size < self.min_viewtag_bucket_size {
            return Err("target viewtag bucket size below minimum".to_string());
        }
        if self.target_scan_fee_piconero > self.max_scan_fee_piconero {
            return Err("target scan fee exceeds configured cap".to_string());
        }
        if self.rebate_bps > MAX_BPS
            || self.sponsor_fill_bps > MAX_BPS
            || self.operator_fee_share_bps > MAX_BPS
        {
            return Err("basis point field exceeds 100%".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security bits below runtime minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub jamtis_hints: u64,
    pub viewtag_rebates: u64,
    pub sponsor_intents: u64,
    pub pq_authorizations: u64,
    pub privacy_budgets: u64,
    pub nullifier_guards: u64,
    pub fee_markets: u64,
    pub operator_summaries: u64,
    pub settled_rebates: u64,
    pub rejected_hints: u64,
    pub replay_attempts_blocked: u64,
    pub redacted_public_records: u64,
    pub total_scan_fee_piconero: u64,
    pub total_rebate_piconero: u64,
    pub total_sponsored_piconero: u64,
}

impl Counters {
    pub fn record_rebate(&mut self, scan_fee: u64, rebate: u64) {
        self.viewtag_rebates = self.viewtag_rebates.saturating_add(1);
        self.total_scan_fee_piconero = self.total_scan_fee_piconero.saturating_add(scan_fee);
        self.total_rebate_piconero = self.total_rebate_piconero.saturating_add(rebate);
    }
    pub fn record_sponsorship(&mut self, sponsored: u64) {
        self.total_sponsored_piconero = self.total_sponsored_piconero.saturating_add(sponsored);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub jamtis_hint_root: String,
    pub viewtag_scan_rebate_root: String,
    pub sponsor_intent_root: String,
    pub pq_authorization_root: String,
    pub privacy_budget_root: String,
    pub nullifier_guard_root: String,
    pub fee_market_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub audit_facet_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JamtisRoutingHint {
    pub hint_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub status: HintStatus,
    pub encrypted_jamtis_hint_commitment: String,
    pub viewtag_bucket_commitment: String,
    pub stealth_output_set_root: String,
    pub sender_blind: String,
    pub recipient_hint_tag: String,
    pub monero_height: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub min_privacy_set_size: u64,
    pub bucket_size: u32,
    pub scan_fee_cap_piconero: u64,
    pub sponsor_intent_id: Option<String>,
    pub nullifier: String,
    pub notes: Vec<String>,
}
impl JamtisRoutingHint {
    pub fn new(
        hint_id: impl Into<String>,
        epoch: u64,
        lane: RoutingLane,
        seed: &str,
        height: u64,
        config: &Config,
    ) -> Self {
        let hint_id = hint_id.into();
        Self {
            encrypted_jamtis_hint_commitment: tagged_commitment("jamtis-hint", &[&hint_id, seed]),
            viewtag_bucket_commitment: tagged_commitment("viewtag-bucket", &[&hint_id, seed]),
            stealth_output_set_root: tagged_commitment("stealth-output-set", &[&hint_id, seed]),
            sender_blind: tagged_commitment("sender-blind", &[&hint_id, seed]),
            recipient_hint_tag: tagged_commitment("recipient-hint-tag", &[&hint_id, seed]),
            expires_at_height: height.saturating_add(config.hint_ttl_blocks),
            min_privacy_set_size: config.min_privacy_set_size,
            bucket_size: config.target_viewtag_bucket_size,
            scan_fee_cap_piconero: lane.scan_fee_cap(config),
            nullifier: tagged_commitment("hint-nullifier", &[&hint_id, seed]),
            hint_id,
            epoch,
            lane,
            status: HintStatus::Committed,
            monero_height: height,
            created_at_height: height,
            sponsor_intent_id: None,
            notes: Vec::new(),
        }
    }
    pub fn commitment(&self) -> String {
        canonical_hash(JAMTIS_HINT_SCHEME, self)
    }
    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height || matches!(self.status, HintStatus::Expired)
    }
    pub fn attach_sponsor(&mut self, sponsor_intent_id: impl Into<String>) {
        self.sponsor_intent_id = Some(sponsor_intent_id.into());
        self.status = HintStatus::Sponsored;
    }
    pub fn mark_authorized(&mut self) {
        self.status = HintStatus::Authorized;
    }
    pub fn privacy_score(&self, config: &Config) -> u64 {
        let set_score =
            self.min_privacy_set_size.saturating_mul(10_000) / config.min_privacy_set_size.max(1);
        let bucket_score =
            self.bucket_size as u64 * 10_000 / config.target_viewtag_bucket_size.max(1) as u64;
        set_score.min(bucket_score).min(10_000)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanRebate {
    pub rebate_id: String,
    pub hint_id: String,
    pub lane: RoutingLane,
    pub status: RebateStatus,
    pub scan_work_commitment: String,
    pub viewtag_bucket_root: String,
    pub encrypted_wallet_cohort_root: String,
    pub scan_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub operator_fee_piconero: u64,
    pub sponsor_intent_id: Option<String>,
    pub authorization_id: Option<String>,
    pub created_at_height: u64,
    pub settled_at_height: Option<u64>,
}
impl ViewtagScanRebate {
    pub fn quote(
        rebate_id: impl Into<String>,
        hint: &JamtisRoutingHint,
        scan_fee_piconero: u64,
        config: &Config,
    ) -> Result<Self> {
        let rebate_id = rebate_id.into();
        if scan_fee_piconero > hint.scan_fee_cap_piconero
            || scan_fee_piconero > config.max_scan_fee_piconero
        {
            return Err("scan fee exceeds privacy-preserving fee cap".to_string());
        }
        let rebate_piconero = scan_fee_piconero.saturating_mul(config.rebate_bps) / MAX_BPS;
        let operator_fee_piconero =
            rebate_piconero.saturating_mul(config.operator_fee_share_bps) / MAX_BPS;
        Ok(Self {
            scan_work_commitment: tagged_commitment("scan-work", &[&rebate_id, &hint.hint_id]),
            viewtag_bucket_root: hint.viewtag_bucket_commitment.clone(),
            encrypted_wallet_cohort_root: tagged_commitment(
                "wallet-cohort",
                &[&rebate_id, &hint.hint_id],
            ),
            rebate_id,
            hint_id: hint.hint_id.clone(),
            lane: hint.lane,
            status: RebateStatus::Quoted,
            scan_fee_piconero,
            rebate_piconero,
            operator_fee_piconero,
            sponsor_intent_id: hint.sponsor_intent_id.clone(),
            authorization_id: None,
            created_at_height: hint.created_at_height,
            settled_at_height: None,
        })
    }
    pub fn reserve(&mut self, sponsor_intent_id: impl Into<String>) {
        self.sponsor_intent_id = Some(sponsor_intent_id.into());
        self.status = RebateStatus::Reserved;
    }
    pub fn authorize(&mut self, authorization_id: impl Into<String>) {
        self.authorization_id = Some(authorization_id.into());
        self.status = RebateStatus::Authorized;
    }
    pub fn settle(&mut self, height: u64) {
        self.status = RebateStatus::Settled;
        self.settled_at_height = Some(height);
    }
    pub fn commitment(&self) -> String {
        canonical_hash(VIEWTAG_SCAN_REBATE_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorIntent {
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub market_id: String,
    pub lane: RoutingLane,
    pub status: SponsorIntentStatus,
    pub max_fee_piconero: u64,
    pub remaining_budget_piconero: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub fill_bps: u64,
    pub allowed_hint_root: String,
    pub authorization_policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub matched_rebate_ids: BTreeSet<String>,
}
impl SponsorIntent {
    pub fn new(
        intent_id: impl Into<String>,
        market_id: impl Into<String>,
        lane: RoutingLane,
        budget: u64,
        seed: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        if budget == 0 || budget > config.daily_wallet_cap_piconero.saturating_mul(64) {
            return Err("sponsor budget outside private market bounds".to_string());
        }
        let intent_id = intent_id.into();
        Ok(Self {
            sponsor_commitment: tagged_commitment("sponsor", &[&intent_id, seed]),
            allowed_hint_root: tagged_commitment("allowed-hints", &[&intent_id, seed]),
            authorization_policy_root: tagged_commitment("auth-policy", &[&intent_id, seed]),
            market_id: market_id.into(),
            lane,
            status: SponsorIntentStatus::Open,
            max_fee_piconero: config.max_sponsor_fee_piconero,
            remaining_budget_piconero: budget,
            min_privacy_set_size: config.min_privacy_set_size,
            min_pq_security_bits: config.min_pq_security_bits,
            fill_bps: config.sponsor_fill_bps,
            created_at_height: height,
            expires_at_height: height.saturating_add(config.intent_ttl_blocks),
            intent_id,
            matched_rebate_ids: BTreeSet::new(),
        })
    }
    pub fn can_cover(&self, rebate: &ViewtagScanRebate, height: u64, config: &Config) -> bool {
        self.status.accepts_matches()
            && height <= self.expires_at_height
            && self.lane == rebate.lane
            && rebate.rebate_piconero <= self.max_fee_piconero
            && self.remaining_budget_piconero >= rebate.rebate_piconero
            && self.min_privacy_set_size >= config.min_privacy_set_size
            && self.min_pq_security_bits >= config.min_pq_security_bits
    }
    pub fn reserve(&mut self, rebate: &ViewtagScanRebate) -> Result<()> {
        if self.remaining_budget_piconero < rebate.rebate_piconero {
            return Err("insufficient private sponsor budget".to_string());
        }
        self.remaining_budget_piconero = self
            .remaining_budget_piconero
            .saturating_sub(rebate.rebate_piconero);
        self.matched_rebate_ids.insert(rebate.rebate_id.clone());
        self.status = if self.remaining_budget_piconero == 0 {
            SponsorIntentStatus::Filled
        } else {
            SponsorIntentStatus::PartiallyFilled
        };
        Ok(())
    }
    pub fn commitment(&self) -> String {
        canonical_hash(SPONSOR_INTENT_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationReceipt {
    pub authorization_id: String,
    pub intent_id: String,
    pub rebate_id: String,
    pub signer_commitment: String,
    pub status: AuthorizationStatus,
    pub pq_scheme: String,
    pub security_bits: u16,
    pub transcript_root: String,
    pub signature_root: String,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub quorum_weight: u64,
}
impl PqAuthorizationReceipt {
    pub fn new(
        authorization_id: impl Into<String>,
        intent: &SponsorIntent,
        rebate: &ViewtagScanRebate,
        seed: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        if intent.min_pq_security_bits < config.min_pq_security_bits {
            return Err("sponsor intent does not satisfy PQ authorization floor".to_string());
        }
        let authorization_id = authorization_id.into();
        Ok(Self {
            signer_commitment: tagged_commitment(
                "pq-signer",
                &[&authorization_id, &intent.intent_id, seed],
            ),
            transcript_root: tagged_commitment(
                "pq-transcript",
                &[&authorization_id, &rebate.rebate_id, seed],
            ),
            signature_root: tagged_commitment(
                "pq-signature",
                &[&authorization_id, &rebate.rebate_id, seed],
            ),
            policy_root: intent.authorization_policy_root.clone(),
            authorization_id,
            intent_id: intent.intent_id.clone(),
            rebate_id: rebate.rebate_id.clone(),
            status: AuthorizationStatus::Accepted,
            pq_scheme: config.pq_authorization_scheme.clone(),
            security_bits: config.target_pq_security_bits,
            created_at_height: height,
            expires_at_height: height.saturating_add(config.authorization_ttl_blocks),
            quorum_weight: 1,
        })
    }
    pub fn strengthen_quorum(&mut self, weight: u64) {
        self.quorum_weight = self.quorum_weight.saturating_add(weight);
        if self.quorum_weight >= 3 {
            self.status = AuthorizationStatus::StrongQuorum;
        }
    }
    pub fn valid_at(&self, height: u64, config: &Config) -> bool {
        self.status.counts_for_settlement()
            && height <= self.expires_at_height
            && self.security_bits >= config.min_pq_security_bits
    }
    pub fn commitment(&self) -> String {
        canonical_hash(PQ_AUTHORIZATION_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub scope: BudgetScope,
    pub epoch: u64,
    pub status: OperatorHealth,
    pub allowance_units: u64,
    pub consumed_units: u64,
    pub redacted_subject_root: String,
    pub auditor_commitment: String,
}
impl PrivacyBudget {
    pub fn new(
        budget_id: impl Into<String>,
        scope: BudgetScope,
        epoch: u64,
        seed: &str,
        config: &Config,
    ) -> Self {
        let budget_id = budget_id.into();
        Self {
            redacted_subject_root: tagged_commitment("budget-subject", &[&budget_id, seed]),
            auditor_commitment: tagged_commitment("budget-auditor", &[&budget_id, seed]),
            budget_id,
            scope,
            epoch,
            status: OperatorHealth::Nominal,
            allowance_units: config.privacy_budget_units,
            consumed_units: 0,
        }
    }
    pub fn consume(&mut self, units: u64) -> Result<()> {
        if self.consumed_units.saturating_add(units) > self.allowance_units {
            self.status = OperatorHealth::PrivacyBudgetLow;
            return Err("privacy budget exhausted".to_string());
        }
        self.consumed_units = self.consumed_units.saturating_add(units);
        if self.remaining_units() < self.allowance_units / 10 {
            self.status = OperatorHealth::PrivacyBudgetLow;
        }
        Ok(())
    }
    pub fn remaining_units(&self) -> u64 {
        self.allowance_units.saturating_sub(self.consumed_units)
    }
    pub fn commitment(&self) -> String {
        canonical_hash(PRIVACY_BUDGET_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierReplayGuard {
    pub nullifier: String,
    pub source_id: String,
    pub status: NullifierStatus,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub replay_count: u64,
    pub guard_root: String,
}
impl NullifierReplayGuard {
    pub fn reserve(
        nullifier: impl Into<String>,
        source_id: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let nullifier = nullifier.into();
        let source_id = source_id.into();
        Self {
            guard_root: tagged_commitment("nullifier-guard", &[&nullifier, &source_id]),
            nullifier,
            source_id,
            status: NullifierStatus::Reserved,
            first_seen_height: height,
            expires_at_height: height.saturating_add(config.nullifier_ttl_blocks),
            replay_count: 0,
        }
    }
    pub fn mark_spent(&mut self) {
        self.status = NullifierStatus::Spent;
    }
    pub fn record_replay(&mut self) {
        self.replay_count = self.replay_count.saturating_add(1);
        self.status = NullifierStatus::Quarantined;
    }
    pub fn active(&self, height: u64) -> bool {
        height <= self.expires_at_height && !matches!(self.status, NullifierStatus::Expired)
    }
    pub fn commitment(&self) -> String {
        canonical_hash(NULLIFIER_GUARD_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeMarket {
    pub market_id: String,
    pub lane: RoutingLane,
    pub status: MarketStatus,
    pub epoch: u64,
    pub base_scan_fee_piconero: u64,
    pub clearing_rebate_bps: u64,
    pub sponsor_liquidity_piconero: u64,
    pub scan_demand_units: u64,
    pub matched_volume_piconero: u64,
    pub jamtis_hint_root: String,
    pub viewtag_bucket_root: String,
}
impl FeeMarket {
    pub fn new(
        market_id: impl Into<String>,
        lane: RoutingLane,
        epoch: u64,
        seed: &str,
        config: &Config,
    ) -> Self {
        let market_id = market_id.into();
        Self {
            jamtis_hint_root: tagged_commitment("market-hints", &[&market_id, seed]),
            viewtag_bucket_root: tagged_commitment("market-viewtags", &[&market_id, seed]),
            market_id,
            lane,
            status: MarketStatus::Open,
            epoch,
            base_scan_fee_piconero: lane
                .scan_fee_cap(config)
                .min(config.target_scan_fee_piconero.saturating_mul(2)),
            clearing_rebate_bps: config.rebate_bps,
            sponsor_liquidity_piconero: 0,
            scan_demand_units: 0,
            matched_volume_piconero: 0,
        }
    }
    pub fn add_liquidity(&mut self, piconero: u64) {
        self.sponsor_liquidity_piconero = self.sponsor_liquidity_piconero.saturating_add(piconero);
        self.rebalance_status();
    }
    pub fn add_scan_demand(&mut self, units: u64) {
        self.scan_demand_units = self.scan_demand_units.saturating_add(units);
        self.rebalance_status();
    }
    pub fn match_volume(&mut self, piconero: u64) {
        self.matched_volume_piconero = self.matched_volume_piconero.saturating_add(piconero);
        self.sponsor_liquidity_piconero = self.sponsor_liquidity_piconero.saturating_sub(piconero);
        self.rebalance_status();
    }
    fn rebalance_status(&mut self) {
        self.status = if self.sponsor_liquidity_piconero == 0 {
            MarketStatus::ScanHeavy
        } else if self.scan_demand_units == 0 {
            MarketStatus::SponsorHeavy
        } else {
            let sponsor_units =
                self.sponsor_liquidity_piconero / self.base_scan_fee_piconero.max(1);
            if sponsor_units.saturating_mul(2) < self.scan_demand_units {
                MarketStatus::ScanHeavy
            } else if sponsor_units > self.scan_demand_units.saturating_mul(2) {
                MarketStatus::SponsorHeavy
            } else {
                MarketStatus::Balanced
            }
        };
    }
    pub fn commitment(&self) -> String {
        canonical_hash(FEE_MARKET_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub health: OperatorHealth,
    pub epoch: u64,
    pub redacted_hint_count: u64,
    pub redacted_rebate_count: u64,
    pub redacted_sponsor_count: u64,
    pub settled_volume_piconero: u64,
    pub replay_attempts_blocked: u64,
    pub pq_authorization_quorum: u64,
    pub privacy_budget_remaining: u64,
    pub public_summary_root: String,
}
impl OperatorSummary {
    pub fn from_state(operator_id: impl Into<String>, state: &State) -> Self {
        let privacy_budget_remaining = state
            .privacy_budgets
            .values()
            .map(PrivacyBudget::remaining_units)
            .sum();
        let pq_authorization_quorum = state
            .pq_authorizations
            .values()
            .filter(|receipt| receipt.status.counts_for_settlement())
            .count() as u64;
        let health = if privacy_budget_remaining < state.config.privacy_budget_units / 4 {
            OperatorHealth::PrivacyBudgetLow
        } else if pq_authorization_quorum == 0 {
            OperatorHealth::PqQuorumWeak
        } else {
            OperatorHealth::Nominal
        };
        let operator_id = operator_id.into();
        Self {
            public_summary_root: tagged_commitment(
                "operator-summary",
                &[&operator_id, &state.epoch.to_string()],
            ),
            operator_id,
            health,
            epoch: state.epoch,
            redacted_hint_count: state.jamtis_hints.len() as u64,
            redacted_rebate_count: state.viewtag_rebates.len() as u64,
            redacted_sponsor_count: state.sponsor_intents.len() as u64,
            settled_volume_piconero: state.counters.total_sponsored_piconero,
            replay_attempts_blocked: state.counters.replay_attempts_blocked,
            pq_authorization_quorum,
            privacy_budget_remaining,
        }
    }
    pub fn commitment(&self) -> String {
        canonical_hash(OPERATOR_SUMMARY_SCHEME, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet01 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet01 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-01-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-01-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-01-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-01-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-01-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet02 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet02 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-02-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-02-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-02-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-02-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-02-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet03 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet03 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-03-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-03-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-03-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-03-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-03-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet04 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet04 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-04-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-04-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-04-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-04-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-04-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet05 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet05 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-05-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-05-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-05-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-05-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-05-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet06 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet06 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-06-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-06-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-06-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-06-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-06-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet07 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet07 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-07-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-07-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-07-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-07-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-07-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet08 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet08 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-08-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-08-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-08-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-08-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-08-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet09 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet09 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-09-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-09-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-09-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-09-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-09-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet10 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet10 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-10-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-10-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-10-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-10-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-10-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet11 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet11 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-11-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-11-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-11-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-11-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-11-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet12 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet12 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-12-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-12-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-12-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-12-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-12-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet13 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet13 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-13-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-13-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-13-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-13-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-13-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPrivacyCostFacet14 {
    pub facet_id: String,
    pub epoch: u64,
    pub lane: RoutingLane,
    pub hint_commitment_root: String,
    pub viewtag_scan_root: String,
    pub sponsor_liquidity_root: String,
    pub pq_authorization_root: String,
    pub nullifier_guard_root: String,
    pub redacted_observation_count: u64,
    pub projected_scan_savings_piconero: u64,
    pub projected_privacy_risk_bps: u64,
}

impl GeneratedPrivacyCostFacet14 {
    pub fn new(facet_id: impl Into<String>, epoch: u64, lane: RoutingLane, seed: &str) -> Self {
        let facet_id = facet_id.into();
        Self {
            hint_commitment_root: tagged_commitment("facet-14-hint", &[&facet_id, seed]),
            viewtag_scan_root: tagged_commitment("facet-14-viewtag", &[&facet_id, seed]),
            sponsor_liquidity_root: tagged_commitment("facet-14-sponsor", &[&facet_id, seed]),
            pq_authorization_root: tagged_commitment("facet-14-pq", &[&facet_id, seed]),
            nullifier_guard_root: tagged_commitment("facet-14-nullifier", &[&facet_id, seed]),
            facet_id,
            epoch,
            lane,
            redacted_observation_count: 0,
            projected_scan_savings_piconero: 0,
            projected_privacy_risk_bps: 0,
        }
    }

    pub fn observe(&mut self, observations: u64, savings_piconero: u64) {
        self.redacted_observation_count =
            self.redacted_observation_count.saturating_add(observations);
        self.projected_scan_savings_piconero = self
            .projected_scan_savings_piconero
            .saturating_add(savings_piconero);
        self.projected_privacy_risk_bps = self.redacted_observation_count.min(MAX_BPS);
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.projected_privacy_risk_bps <= config.operator_fee_share_bps.saturating_mul(2)
            && self.redacted_observation_count <= config.privacy_budget_units
    }

    pub fn commitment(&self) -> String {
        canonical_hash(
            "generated-jamtis-viewtag-fee-sponsor-privacy-cost-facet-root-v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub jamtis_hints: BTreeMap<String, JamtisRoutingHint>,
    pub viewtag_rebates: BTreeMap<String, ViewtagScanRebate>,
    pub sponsor_intents: BTreeMap<String, SponsorIntent>,
    pub pq_authorizations: BTreeMap<String, PqAuthorizationReceipt>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub nullifier_guards: BTreeMap<String, NullifierReplayGuard>,
    pub fee_markets: BTreeMap<String, FeeMarket>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        Self::new(config, DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            jamtis_hints: BTreeMap::new(),
            viewtag_rebates: BTreeMap::new(),
            sponsor_intents: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            nullifier_guards: BTreeMap::new(),
            fee_markets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: Vec::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet_fixture();
        state.recompute_roots();
        state
    }
    pub fn public_record(&self) -> Value {
        public_record(self)
    }
    pub fn state_root(&self) -> String {
        state_root(self)
    }
    pub fn register_fee_market(&mut self, market: FeeMarket) -> Result<()> {
        if self.fee_markets.contains_key(&market.market_id) {
            return Err("fee market already registered".to_string());
        }
        self.counters.fee_markets = self.counters.fee_markets.saturating_add(1);
        self.fee_markets.insert(market.market_id.clone(), market);
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_hint(&mut self, hint: JamtisRoutingHint) -> Result<()> {
        self.config.validate()?;
        if hint.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("JAMTIS hint privacy set below configured floor".to_string());
        }
        if hint.bucket_size < self.config.min_viewtag_bucket_size {
            return Err("viewtag bucket too small for low-linkability scan rebate".to_string());
        }
        self.reserve_nullifier(hint.nullifier.clone(), hint.hint_id.clone())?;
        self.counters.jamtis_hints = self.counters.jamtis_hints.saturating_add(1);
        self.jamtis_hints.insert(hint.hint_id.clone(), hint);
        self.recompute_roots();
        Ok(())
    }
    pub fn quote_rebate(
        &mut self,
        rebate_id: impl Into<String>,
        hint_id: &str,
        scan_fee_piconero: u64,
    ) -> Result<String> {
        let rebate_id = rebate_id.into();
        let hint = self
            .jamtis_hints
            .get(hint_id)
            .ok_or_else(|| "unknown JAMTIS routing hint".to_string())?;
        if hint.expired(self.height) {
            return Err("cannot quote rebate for expired JAMTIS hint".to_string());
        }
        let rebate =
            ViewtagScanRebate::quote(rebate_id.clone(), hint, scan_fee_piconero, &self.config)?;
        self.consume_budget(BudgetScope::ScanWork, 1)?;
        self.counters
            .record_rebate(scan_fee_piconero, rebate.rebate_piconero);
        self.viewtag_rebates.insert(rebate_id.clone(), rebate);
        self.recompute_roots();
        Ok(rebate_id)
    }
    pub fn submit_sponsor_intent(&mut self, intent: SponsorIntent) -> Result<()> {
        if self.sponsor_intents.contains_key(&intent.intent_id) {
            return Err("sponsor intent already exists".to_string());
        }
        if let Some(market) = self.fee_markets.get_mut(&intent.market_id) {
            market.add_liquidity(intent.remaining_budget_piconero);
        }
        self.counters.sponsor_intents = self.counters.sponsor_intents.saturating_add(1);
        self.sponsor_intents
            .insert(intent.intent_id.clone(), intent);
        self.recompute_roots();
        Ok(())
    }
    pub fn match_sponsor(&mut self, rebate_id: &str, intent_id: &str) -> Result<()> {
        let rebate_snapshot = self
            .viewtag_rebates
            .get(rebate_id)
            .ok_or_else(|| "unknown rebate".to_string())?
            .clone();
        let intent = self
            .sponsor_intents
            .get_mut(intent_id)
            .ok_or_else(|| "unknown sponsor intent".to_string())?;
        if !intent.can_cover(&rebate_snapshot, self.height, &self.config) {
            return Err("sponsor intent cannot cover rebate".to_string());
        }
        intent.reserve(&rebate_snapshot)?;
        if let Some(rebate) = self.viewtag_rebates.get_mut(rebate_id) {
            rebate.reserve(intent_id.to_string());
        }
        if let Some(hint) = self.jamtis_hints.get_mut(&rebate_snapshot.hint_id) {
            hint.attach_sponsor(intent_id.to_string());
        }
        if let Some(market) = self.fee_markets.get_mut(&intent.market_id) {
            market.match_volume(rebate_snapshot.rebate_piconero);
        }
        self.counters
            .record_sponsorship(rebate_snapshot.rebate_piconero);
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_authorization(&mut self, receipt: PqAuthorizationReceipt) -> Result<()> {
        if self
            .pq_authorizations
            .contains_key(&receipt.authorization_id)
        {
            return Err("PQ authorization receipt already exists".to_string());
        }
        if !receipt.valid_at(self.height, &self.config) {
            return Err("PQ authorization receipt is not valid at current height".to_string());
        }
        let hint_id = self
            .viewtag_rebates
            .get(&receipt.rebate_id)
            .map(|r| r.hint_id.clone());
        if let Some(rebate) = self.viewtag_rebates.get_mut(&receipt.rebate_id) {
            rebate.authorize(receipt.authorization_id.clone());
        }
        if let Some(hint_id) = hint_id {
            if let Some(hint) = self.jamtis_hints.get_mut(&hint_id) {
                hint.mark_authorized();
            }
        }
        self.counters.pq_authorizations = self.counters.pq_authorizations.saturating_add(1);
        self.pq_authorizations
            .insert(receipt.authorization_id.clone(), receipt);
        self.recompute_roots();
        Ok(())
    }
    pub fn settle_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let authorization_id = self
            .viewtag_rebates
            .get(rebate_id)
            .and_then(|rebate| rebate.authorization_id.clone())
            .ok_or_else(|| "rebate lacks PQ sponsor authorization".to_string())?;
        let authorization = self
            .pq_authorizations
            .get(&authorization_id)
            .ok_or_else(|| "missing PQ authorization receipt".to_string())?;
        if !authorization.valid_at(self.height, &self.config) {
            return Err("PQ sponsor authorization expired or weak".to_string());
        }
        let hint_id = self
            .viewtag_rebates
            .get(rebate_id)
            .map(|rebate| rebate.hint_id.clone())
            .unwrap_or_default();
        if let Some(rebate) = self.viewtag_rebates.get_mut(rebate_id) {
            rebate.settle(self.height);
            self.counters.settled_rebates = self.counters.settled_rebates.saturating_add(1);
        }
        if let Some(hint) = self.jamtis_hints.get_mut(&hint_id) {
            hint.status = HintStatus::Settled;
        }
        if let Some(hint) = self.jamtis_hints.get(&hint_id) {
            if let Some(guard) = self.nullifier_guards.get_mut(&hint.nullifier) {
                guard.status = NullifierStatus::Settled;
            }
        }
        self.recompute_roots();
        Ok(())
    }
    pub fn reserve_nullifier(&mut self, nullifier: String, source_id: String) -> Result<()> {
        if let Some(existing) = self.nullifier_guards.get_mut(&nullifier) {
            if existing.active(self.height) {
                existing.record_replay();
                self.counters.replay_attempts_blocked =
                    self.counters.replay_attempts_blocked.saturating_add(1);
                return Err("nullifier replay blocked".to_string());
            }
        }
        let guard =
            NullifierReplayGuard::reserve(nullifier.clone(), source_id, self.height, &self.config);
        self.counters.nullifier_guards = self.counters.nullifier_guards.saturating_add(1);
        self.nullifier_guards.insert(nullifier, guard);
        Ok(())
    }
    pub fn install_privacy_budget(&mut self, budget: PrivacyBudget) -> Result<()> {
        if self.privacy_budgets.contains_key(&budget.budget_id) {
            return Err("privacy budget already installed".to_string());
        }
        self.counters.privacy_budgets = self.counters.privacy_budgets.saturating_add(1);
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        self.recompute_roots();
        Ok(())
    }
    pub fn consume_budget(&mut self, scope: BudgetScope, units: u64) -> Result<()> {
        if let Some((_, budget)) = self
            .privacy_budgets
            .iter_mut()
            .find(|(_, budget)| budget.scope == scope && budget.epoch == self.epoch)
        {
            budget.consume(units)
        } else {
            let mut budget = PrivacyBudget::new(
                format!("budget-{}-{}", scope.as_str(), self.epoch),
                scope,
                self.epoch,
                "auto",
                &self.config,
            );
            budget.consume(units)?;
            self.install_privacy_budget(budget)
        }
    }
    pub fn publish_operator_summary(&mut self, operator_id: impl Into<String>) -> String {
        let summary = OperatorSummary::from_state(operator_id, self);
        let summary_id = summary.operator_id.clone();
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.recompute_roots();
        summary_id
    }
    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        self.expire_old_records();
        self.recompute_roots();
    }
    pub fn expire_old_records(&mut self) {
        for hint in self.jamtis_hints.values_mut() {
            if hint.expired(self.height) && hint.status.live() {
                hint.status = HintStatus::Expired;
            }
        }
        for intent in self.sponsor_intents.values_mut() {
            if self.height > intent.expires_at_height && intent.status.accepts_matches() {
                intent.status = SponsorIntentStatus::Expired;
            }
        }
        for receipt in self.pq_authorizations.values_mut() {
            if self.height > receipt.expires_at_height && receipt.status.counts_for_settlement() {
                receipt.status = AuthorizationStatus::Expired;
            }
        }
        for guard in self.nullifier_guards.values_mut() {
            if self.height > guard.expires_at_height && guard.status != NullifierStatus::Settled {
                guard.status = NullifierStatus::Expired;
            }
        }
    }
    pub fn recompute_roots(&mut self) {
        self.roots.jamtis_hint_root = map_root(JAMTIS_HINT_SCHEME, &self.jamtis_hints);
        self.roots.viewtag_scan_rebate_root =
            map_root(VIEWTAG_SCAN_REBATE_SCHEME, &self.viewtag_rebates);
        self.roots.sponsor_intent_root = map_root(SPONSOR_INTENT_SCHEME, &self.sponsor_intents);
        self.roots.pq_authorization_root =
            map_root(PQ_AUTHORIZATION_SCHEME, &self.pq_authorizations);
        self.roots.privacy_budget_root = map_root(PRIVACY_BUDGET_SCHEME, &self.privacy_budgets);
        self.roots.nullifier_guard_root = map_root(NULLIFIER_GUARD_SCHEME, &self.nullifier_guards);
        self.roots.fee_market_root = map_root(FEE_MARKET_SCHEME, &self.fee_markets);
        self.roots.operator_summary_root =
            map_root(OPERATOR_SUMMARY_SCHEME, &self.operator_summaries);
        self.roots.public_record_root = list_root(PUBLIC_RECORD_SCHEME, &self.public_records);
        self.roots.audit_facet_root = domain_hash(
            "generated-audit-facet-placeholder",
            &[HashPart::from(self.counters.jamtis_hints.to_string())],
        );
        self.roots.state_root = state_root(self);
    }
    fn seed_devnet_fixture(&mut self) {
        let _ = self.config.validate();
        let lanes = [
            RoutingLane::WalletIncremental,
            RoutingLane::MerchantReceive,
            RoutingLane::BridgeDeposit,
            RoutingLane::BridgeWithdrawal,
            RoutingLane::AtomicSwap,
        ];
        for (idx, lane) in lanes.iter().enumerate() {
            let market_id = format!("jamtis-viewtag-market-{}", lane.as_str());
            let mut market = FeeMarket::new(
                market_id.clone(),
                *lane,
                self.epoch,
                "devnet-market",
                &self.config,
            );
            market.add_scan_demand(128 + idx as u64 * 32);
            let _ = self.register_fee_market(market);
            let hint_id = format!("jamtis-hint-devnet-{idx}");
            let hint = JamtisRoutingHint::new(
                hint_id.clone(),
                self.epoch,
                *lane,
                "devnet-hint",
                self.height + idx as u64,
                &self.config,
            );
            let _ = self.submit_hint(hint);
            let rebate_id = format!("viewtag-rebate-devnet-{idx}");
            let _ = self.quote_rebate(
                rebate_id.clone(),
                &hint_id,
                self.config.target_scan_fee_piconero + idx as u64 * 100,
            );
            let intent_id = format!("sponsor-intent-devnet-{idx}");
            if let Ok(intent) = SponsorIntent::new(
                intent_id.clone(),
                market_id,
                *lane,
                80_000 + idx as u64 * 10_000,
                "devnet-sponsor",
                self.height,
                &self.config,
            ) {
                let _ = self.submit_sponsor_intent(intent);
                let _ = self.match_sponsor(&rebate_id, &intent_id);
                if let (Some(intent), Some(rebate)) = (
                    self.sponsor_intents.get(&intent_id).cloned(),
                    self.viewtag_rebates.get(&rebate_id).cloned(),
                ) {
                    if let Ok(mut auth) = PqAuthorizationReceipt::new(
                        format!("pq-auth-devnet-{idx}"),
                        &intent,
                        &rebate,
                        "devnet-auth",
                        self.height,
                        &self.config,
                    ) {
                        auth.strengthen_quorum(2);
                        let _ = self.submit_authorization(auth);
                        let _ = self.settle_rebate(&rebate_id);
                    }
                }
            }
        }
        for scope in [
            BudgetScope::JamtisHint,
            BudgetScope::ViewtagBucket,
            BudgetScope::ScanWork,
            BudgetScope::SponsorMetadata,
            BudgetScope::AuthorizationReceipt,
            BudgetScope::PublicAudit,
            BudgetScope::OperatorSummary,
        ] {
            let _ = self.install_privacy_budget(PrivacyBudget::new(
                format!("privacy-budget-devnet-{}", scope.as_str()),
                scope,
                self.epoch,
                "devnet-budget",
                &self.config,
            ));
        }
        self.publish_operator_summary("operator-devnet-0");
        self.public_records.push(public_record(self));
        self.counters.redacted_public_records = self.public_records.len() as u64;
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    let mut state = State::devnet();
    state.advance_height(DEVNET_HEIGHT + 12);
    state.publish_operator_summary("operator-demo-1");
    state.public_records.push(public_record(&state));
    state.counters.redacted_public_records = state.public_records.len() as u64;
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.config.protocol_version, "schema_version": state.config.schema_version, "chain_id": state.config.chain_id, "l2_network": state.config.l2_network, "monero_network": state.config.monero_network, "bridge_id": state.config.bridge_id, "fee_asset_id": state.config.fee_asset_id, "privacy_boundary": PRIVACY_BOUNDARY, "height": state.height, "epoch": state.epoch,
        "counters": { "jamtis_hints": state.counters.jamtis_hints, "viewtag_rebates": state.counters.viewtag_rebates, "sponsor_intents": state.counters.sponsor_intents, "pq_authorizations": state.counters.pq_authorizations, "privacy_budgets": state.counters.privacy_budgets, "nullifier_guards": state.counters.nullifier_guards, "fee_markets": state.counters.fee_markets, "operator_summaries": state.counters.operator_summaries, "settled_rebates": state.counters.settled_rebates, "replay_attempts_blocked": state.counters.replay_attempts_blocked, "total_scan_fee_piconero": state.counters.total_scan_fee_piconero, "total_rebate_piconero": state.counters.total_rebate_piconero, "total_sponsored_piconero": state.counters.total_sponsored_piconero },
        "roots": { "jamtis_hint_root": state.roots.jamtis_hint_root, "viewtag_scan_rebate_root": state.roots.viewtag_scan_rebate_root, "sponsor_intent_root": state.roots.sponsor_intent_root, "pq_authorization_root": state.roots.pq_authorization_root, "privacy_budget_root": state.roots.privacy_budget_root, "nullifier_guard_root": state.roots.nullifier_guard_root, "fee_market_root": state.roots.fee_market_root, "operator_summary_root": state.roots.operator_summary_root, "public_record_root": state.roots.public_record_root, "audit_facet_root": state.roots.audit_facet_root, "state_root": state.roots.state_root },
        "market_summary": state.fee_markets.values().map(|market| json!({ "market_id": market.market_id, "lane": market.lane.as_str(), "status": market.status, "epoch": market.epoch, "base_scan_fee_piconero": market.base_scan_fee_piconero, "clearing_rebate_bps": market.clearing_rebate_bps, "sponsor_liquidity_piconero": market.sponsor_liquidity_piconero, "scan_demand_units": market.scan_demand_units, "matched_volume_piconero": market.matched_volume_piconero })).collect::<Vec<_>>(),
        "operator_summaries": state.operator_summaries.values().map(|summary| json!({ "operator_id": summary.operator_id, "health": summary.health, "epoch": summary.epoch, "redacted_hint_count": summary.redacted_hint_count, "redacted_rebate_count": summary.redacted_rebate_count, "redacted_sponsor_count": summary.redacted_sponsor_count, "settled_volume_piconero": summary.settled_volume_piconero, "replay_attempts_blocked": summary.replay_attempts_blocked, "pq_authorization_quorum": summary.pq_authorization_quorum, "privacy_budget_remaining": summary.privacy_budget_remaining, "public_summary_root": summary.public_summary_root })).collect::<Vec<_>>(),
    })
}

pub fn state_root(state: &State) -> String {
    let parts = vec![
        HashPart::from(PROTOCOL_VERSION),
        HashPart::from(state.config.chain_id.as_str()),
        HashPart::from(state.height.to_string()),
        HashPart::from(state.epoch.to_string()),
        HashPart::from(state.roots.jamtis_hint_root.as_str()),
        HashPart::from(state.roots.viewtag_scan_rebate_root.as_str()),
        HashPart::from(state.roots.sponsor_intent_root.as_str()),
        HashPart::from(state.roots.pq_authorization_root.as_str()),
        HashPart::from(state.roots.privacy_budget_root.as_str()),
        HashPart::from(state.roots.nullifier_guard_root.as_str()),
        HashPart::from(state.roots.fee_market_root.as_str()),
        HashPart::from(state.roots.operator_summary_root.as_str()),
        HashPart::from(state.roots.audit_facet_root.as_str()),
        HashPart::from(state.counters.jamtis_hints.to_string()),
        HashPart::from(state.counters.viewtag_rebates.to_string()),
        HashPart::from(state.counters.sponsor_intents.to_string()),
        HashPart::from(state.counters.pq_authorizations.to_string()),
        HashPart::from(state.counters.replay_attempts_blocked.to_string()),
    ];
    domain_hash(STATE_ROOT_DOMAIN, &parts)
}
fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| HashPart::from(format!("{}:{}", key, canonical_hash(domain, value))))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn list_root<T: Serialize>(domain: &str, values: &[T]) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(idx, value)| HashPart::from(format!("{}:{}", idx, canonical_hash(domain, value))))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn canonical_hash<T: Serialize>(domain: &str, value: &T) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    domain_hash(domain, &[HashPart::from(encoded)])
}
fn tagged_commitment(tag: &str, parts: &[&str]) -> String {
    let mut hash_parts = vec![HashPart::from(tag)];
    hash_parts.extend(parts.iter().copied().map(HashPart::from));
    domain_hash("jamtis-viewtag-fee-sponsor-market-commitment", &hash_parts)
}
