use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingDecoyFeeSponsorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RING_DECOY_FEE_SPONSOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ring-decoy-fee-sponsor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RING_DECOY_FEE_SPONSOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_SPONSOR_POOL_SCHEME: &str = "private-ring-decoy-fee-sponsor-pool-root-v1";
pub const DECOY_FEE_COHORT_SCHEME: &str = "decoy-set-fee-cohort-commitment-root-v1";
pub const RING_FRESHNESS_SCHEME: &str = "ring-member-freshness-oracle-root-v1";
pub const VIEWKEY_REDACTION_SCHEME: &str = "operator-safe-viewkey-redaction-budget-root-v1";
pub const PQ_SPONSOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-ring-decoy-fee-sponsor-attestation-v1";
pub const FEE_COUPON_SCHEME: &str = "private-fee-coupon-nullifier-root-v1";
pub const WALLET_CAP_SCHEME: &str = "shielded-wallet-fee-cap-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "ring-decoy-fee-sponsor-public-record-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_view_keys_key_images_ring_members_or_wallet_graphs";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 32;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 8_750;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_WALLET_FEE_BPS: u64 = 4;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_VIEWKEY_REDACTION_UNITS: u64 = 8_192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_WALLET_DAILY_CAP_PICONERO: u64 = 120_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Draft,
    Active,
    Throttled,
    Depleted,
    Frozen,
    Retired,
}

impl SponsorPoolStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Depleted => "depleted",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    WalletTransfer,
    MerchantCheckout,
    BridgeExit,
    AtomicSwap,
    DefiSettlement,
    FastPreconfirmation,
    EmergencyEscape,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MerchantCheckout => "merchant_checkout",
            Self::BridgeExit => "bridge_exit",
            Self::AtomicSwap => "atomic_swap",
            Self::DefiSettlement => "defi_settlement",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Proposed,
    Open,
    Balanced,
    Subsidized,
    FreshnessLimited,
    Paused,
    Retired,
}

impl CohortStatus {
    pub fn accepts_coupons(self) -> bool {
        matches!(self, Self::Open | Self::Balanced | Self::Subsidized)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Balanced => "balanced",
            Self::Subsidized => "subsidized",
            Self::FreshnessLimited => "freshness_limited",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Pending,
    Fresh,
    Watch,
    Stale,
    Quarantined,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    ViewKey,
    WalletPolicy,
    SponsorMetadata,
    CouponSettlement,
    PublicAudit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletCapStatus {
    Open,
    NearCap,
    Capped,
    CoolingDown,
    Suspended,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub private_sponsor_pool_scheme: String,
    pub decoy_fee_cohort_scheme: String,
    pub ring_freshness_scheme: String,
    pub viewkey_redaction_scheme: String,
    pub pq_sponsor_attestation_scheme: String,
    pub fee_coupon_scheme: String,
    pub wallet_cap_scheme: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_decoy_set_size: u64,
    pub min_freshness_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub max_wallet_fee_bps: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub viewkey_redaction_units: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub wallet_daily_cap_piconero: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            private_sponsor_pool_scheme: PRIVATE_SPONSOR_POOL_SCHEME.to_string(),
            decoy_fee_cohort_scheme: DECOY_FEE_COHORT_SCHEME.to_string(),
            ring_freshness_scheme: RING_FRESHNESS_SCHEME.to_string(),
            viewkey_redaction_scheme: VIEWKEY_REDACTION_SCHEME.to_string(),
            pq_sponsor_attestation_scheme: PQ_SPONSOR_ATTESTATION_SCHEME.to_string(),
            fee_coupon_scheme: FEE_COUPON_SCHEME.to_string(),
            wallet_cap_scheme: WALLET_CAP_SCHEME.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            max_wallet_fee_bps: DEFAULT_MAX_WALLET_FEE_BPS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            viewkey_redaction_units: DEFAULT_VIEWKEY_REDACTION_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            wallet_daily_cap_piconero: DEFAULT_WALLET_DAILY_CAP_PICONERO,
        }
    }

    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version",
        )?;
        ensure(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        ensure(
            self.min_ring_size >= 11,
            "minimum ring size below Monero floor",
        )?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size below floor",
        )?;
        ensure(self.min_decoy_set_size > 0, "empty decoy set floor")?;
        ensure(self.min_freshness_bps <= MAX_BPS, "freshness above max bps")?;
        ensure(
            self.max_sponsor_fee_bps <= MAX_BPS,
            "sponsor fee above max bps",
        )?;
        ensure(
            self.max_wallet_fee_bps <= MAX_BPS,
            "wallet fee above max bps",
        )?;
        ensure(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "target pq security below minimum",
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_pools: u64,
    pub decoy_fee_cohorts: u64,
    pub freshness_reports: u64,
    pub viewkey_redactions: u64,
    pub sponsor_attestations: u64,
    pub fee_coupons: u64,
    pub wallet_caps: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub sponsor_pools_root: String,
    pub decoy_fee_cohorts_root: String,
    pub freshness_reports_root: String,
    pub viewkey_redactions_root: String,
    pub sponsor_attestations_root: String,
    pub fee_coupons_root: String,
    pub wallet_caps_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSponsorPool {
    pub pool_id: String,
    pub sponsor_id: String,
    pub status: SponsorPoolStatus,
    pub fee_asset_id: String,
    pub pool_commitment_root: String,
    pub sponsor_policy_root: String,
    pub liquidity_commitment_root: String,
    pub available_fee_budget_piconero: u64,
    pub max_coupon_value_piconero: u64,
    pub max_coupons_per_epoch: u64,
    pub epoch: u64,
    pub expires_at_height: u64,
}

impl PrivateSponsorPool {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoySetFeeCohort {
    pub cohort_id: String,
    pub pool_id: String,
    pub kind: CohortKind,
    pub status: CohortStatus,
    pub ring_size: u16,
    pub decoy_set_size: u64,
    pub decoy_distribution_root: String,
    pub fee_bucket_root: String,
    pub max_user_fee_bps: u64,
    pub sponsor_share_bps: u64,
    pub min_freshness_bps: u64,
    pub active_height: u64,
}

impl DecoySetFeeCohort {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberFreshnessReport {
    pub report_id: String,
    pub cohort_id: String,
    pub oracle_id: String,
    pub status: FreshnessStatus,
    pub ring_member_commitment_root: String,
    pub age_histogram_root: String,
    pub quarantined_member_root: String,
    pub freshness_bps: u64,
    pub sampled_members: u64,
    pub observed_height: u64,
}

impl RingMemberFreshnessReport {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyRedactionBudget {
    pub redaction_id: String,
    pub owner_commitment: String,
    pub scope: RedactionScope,
    pub redacted_viewkey_root: String,
    pub disclosure_policy_root: String,
    pub redaction_nullifier_root: String,
    pub allowance_units: u64,
    pub used_units: u64,
    pub epoch: u64,
}

impl ViewKeyRedactionBudget {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub sponsor_id: String,
    pub pool_id: String,
    pub status: AttestationStatus,
    pub pq_public_key_root: String,
    pub sponsor_attestation_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCoupon {
    pub coupon_id: String,
    pub pool_id: String,
    pub cohort_id: String,
    pub wallet_cap_id: String,
    pub status: CouponStatus,
    pub coupon_nullifier_root: String,
    pub recipient_commitment_root: String,
    pub settlement_batch_root: String,
    pub coupon_value_piconero: u64,
    pub user_fee_bps: u64,
    pub minted_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeCoupon {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCap {
    pub cap_id: String,
    pub wallet_commitment: String,
    pub status: WalletCapStatus,
    pub policy_root: String,
    pub spend_nullifier_root: String,
    pub epoch: u64,
    pub daily_cap_piconero: u64,
    pub consumed_piconero: u64,
    pub max_user_fee_bps: u64,
}

impl WalletCap {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecordEntry {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl PublicRecordEntry {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub sponsor_pools: BTreeMap<String, PrivateSponsorPool>,
    pub decoy_fee_cohorts: BTreeMap<String, DecoySetFeeCohort>,
    pub freshness_reports: BTreeMap<String, RingMemberFreshnessReport>,
    pub viewkey_redactions: BTreeMap<String, ViewKeyRedactionBudget>,
    pub sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub fee_coupons: BTreeMap<String, FeeCoupon>,
    pub wallet_caps: BTreeMap<String, WalletCap>,
    pub public_records: BTreeMap<String, PublicRecordEntry>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            sponsor_pools: BTreeMap::new(),
            decoy_fee_cohorts: BTreeMap::new(),
            freshness_reports: BTreeMap::new(),
            viewkey_redactions: BTreeMap::new(),
            sponsor_attestations: BTreeMap::new(),
            fee_coupons: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet_state()
    }

    pub fn demo() -> Self {
        demo_state()
    }

    pub fn counters(&self) -> Counters {
        Counters {
            sponsor_pools: self.sponsor_pools.len() as u64,
            decoy_fee_cohorts: self.decoy_fee_cohorts.len() as u64,
            freshness_reports: self.freshness_reports.len() as u64,
            viewkey_redactions: self.viewkey_redactions.len() as u64,
            sponsor_attestations: self.sponsor_attestations.len() as u64,
            fee_coupons: self.fee_coupons.len() as u64,
            wallet_caps: self.wallet_caps.len() as u64,
            public_records: self.public_records.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root("RING-DECOY-FEE-SPONSOR-CONFIG", &self.config);
        let counters_root = payload_root("RING-DECOY-FEE-SPONSOR-COUNTERS", &self.counters());
        let sponsor_pools_root = map_root(PRIVATE_SPONSOR_POOL_SCHEME, &self.sponsor_pools);
        let decoy_fee_cohorts_root = map_root(DECOY_FEE_COHORT_SCHEME, &self.decoy_fee_cohorts);
        let freshness_reports_root = map_root(RING_FRESHNESS_SCHEME, &self.freshness_reports);
        let viewkey_redactions_root = map_root(VIEWKEY_REDACTION_SCHEME, &self.viewkey_redactions);
        let sponsor_attestations_root =
            map_root(PQ_SPONSOR_ATTESTATION_SCHEME, &self.sponsor_attestations);
        let fee_coupons_root = map_root(FEE_COUPON_SCHEME, &self.fee_coupons);
        let wallet_caps_root = map_root(WALLET_CAP_SCHEME, &self.wallet_caps);
        let public_records_root = map_root(PUBLIC_RECORD_SCHEME, &self.public_records);
        let state_root = payload_root(
            "RING-DECOY-FEE-SPONSOR-STATE",
            &json!({
                "config_root": config_root,
                "counters_root": counters_root,
                "sponsor_pools_root": sponsor_pools_root,
                "decoy_fee_cohorts_root": decoy_fee_cohorts_root,
                "freshness_reports_root": freshness_reports_root,
                "viewkey_redactions_root": viewkey_redactions_root,
                "sponsor_attestations_root": sponsor_attestations_root,
                "fee_coupons_root": fee_coupons_root,
                "wallet_caps_root": wallet_caps_root,
                "public_records_root": public_records_root,
            }),
        );

        Roots {
            config_root,
            counters_root,
            sponsor_pools_root,
            decoy_fee_cohorts_root,
            freshness_reports_root,
            viewkey_redactions_root,
            sponsor_attestations_root,
            fee_coupons_root,
            wallet_caps_root,
            public_records_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "active_sponsor_pools": self.sponsor_pools.values().filter(|pool| pool.status.usable()).count(),
            "open_decoy_fee_cohorts": self.decoy_fee_cohorts.values().filter(|cohort| cohort.status.accepts_coupons()).count(),
            "accepted_sponsor_attestations": self.sponsor_attestations.values().filter(|attestation| attestation.status.counts_for_quorum()).count(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn insert_public_record(
        &mut self,
        kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
    ) {
        let record_id = deterministic_id("public-record", &[kind, subject_id, &height.to_string()]);
        self.public_records.insert(
            record_id.clone(),
            PublicRecordEntry {
                record_id,
                record_kind: kind.to_string(),
                subject_id: subject_id.to_string(),
                payload_root: payload_root("RING-DECOY-FEE-SPONSOR-PUBLIC-PAYLOAD", payload),
                height,
            },
        );
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

pub fn devnet_state() -> State {
    let mut state = State::new(Config::devnet()).expect("devnet ring decoy fee sponsor config");
    let sponsor_pool = PrivateSponsorPool {
        pool_id: "sponsor-pool-devnet-0".to_string(),
        sponsor_id: "sponsor-ml-dsa-devnet-0".to_string(),
        status: SponsorPoolStatus::Active,
        fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        pool_commitment_root: demo_root("pool-commitment", 0),
        sponsor_policy_root: demo_root("sponsor-policy", 0),
        liquidity_commitment_root: demo_root("liquidity", 0),
        available_fee_budget_piconero: 9_500_000_000,
        max_coupon_value_piconero: 9_000,
        max_coupons_per_epoch: 25_000,
        epoch: 4_672,
        expires_at_height: 2_250_000,
    };
    state
        .sponsor_pools
        .insert(sponsor_pool.pool_id.clone(), sponsor_pool.clone());

    let cohort = DecoySetFeeCohort {
        cohort_id: "decoy-fee-cohort-wallet-devnet-0".to_string(),
        pool_id: sponsor_pool.pool_id.clone(),
        kind: CohortKind::WalletTransfer,
        status: CohortStatus::Balanced,
        ring_size: DEFAULT_TARGET_RING_SIZE,
        decoy_set_size: 131_072,
        decoy_distribution_root: demo_root("decoy-distribution", 0),
        fee_bucket_root: demo_root("fee-bucket", 0),
        max_user_fee_bps: DEFAULT_MAX_WALLET_FEE_BPS,
        sponsor_share_bps: 8_700,
        min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
        active_height: 2_241_360,
    };
    state
        .decoy_fee_cohorts
        .insert(cohort.cohort_id.clone(), cohort.clone());

    let freshness = RingMemberFreshnessReport {
        report_id: "freshness-devnet-0".to_string(),
        cohort_id: cohort.cohort_id.clone(),
        oracle_id: "ring-freshness-oracle-devnet-0".to_string(),
        status: FreshnessStatus::Fresh,
        ring_member_commitment_root: demo_root("ring-members", 0),
        age_histogram_root: demo_root("age-histogram", 0),
        quarantined_member_root: demo_root("quarantine-empty", 0),
        freshness_bps: 9_230,
        sampled_members: 4_096,
        observed_height: 2_241_372,
    };
    state
        .freshness_reports
        .insert(freshness.report_id.clone(), freshness);

    let redaction = ViewKeyRedactionBudget {
        redaction_id: "viewkey-redaction-devnet-0".to_string(),
        owner_commitment: demo_commitment("wallet-owner", 0),
        scope: RedactionScope::ViewKey,
        redacted_viewkey_root: demo_root("redacted-viewkey", 0),
        disclosure_policy_root: demo_root("disclosure-policy", 0),
        redaction_nullifier_root: demo_root("redaction-nullifier", 0),
        allowance_units: DEFAULT_VIEWKEY_REDACTION_UNITS,
        used_units: 384,
        epoch: 4_672,
    };
    state
        .viewkey_redactions
        .insert(redaction.redaction_id.clone(), redaction);

    let attestation = PqSponsorAttestation {
        attestation_id: "pq-sponsor-attestation-devnet-0".to_string(),
        sponsor_id: sponsor_pool.sponsor_id.clone(),
        pool_id: sponsor_pool.pool_id.clone(),
        status: AttestationStatus::StrongQuorum,
        pq_public_key_root: demo_root("pq-public-key", 0),
        sponsor_attestation_root: demo_root("sponsor-attestation", 0),
        signature_root: demo_root("pq-signature", 0),
        security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
        issued_at_height: 2_241_344,
        expires_at_height: 2_241_632,
    };
    state
        .sponsor_attestations
        .insert(attestation.attestation_id.clone(), attestation);

    let wallet_cap = WalletCap {
        cap_id: "wallet-cap-devnet-0".to_string(),
        wallet_commitment: demo_commitment("wallet", 0),
        status: WalletCapStatus::Open,
        policy_root: demo_root("wallet-cap-policy", 0),
        spend_nullifier_root: demo_root("wallet-spend-nullifier", 0),
        epoch: 4_672,
        daily_cap_piconero: DEFAULT_WALLET_DAILY_CAP_PICONERO,
        consumed_piconero: 18_000,
        max_user_fee_bps: DEFAULT_MAX_WALLET_FEE_BPS,
    };
    state
        .wallet_caps
        .insert(wallet_cap.cap_id.clone(), wallet_cap.clone());

    let coupon = FeeCoupon {
        coupon_id: "fee-coupon-devnet-0".to_string(),
        pool_id: sponsor_pool.pool_id,
        cohort_id: cohort.cohort_id,
        wallet_cap_id: wallet_cap.cap_id,
        status: CouponStatus::Reserved,
        coupon_nullifier_root: demo_root("coupon-nullifier", 0),
        recipient_commitment_root: demo_root("coupon-recipient", 0),
        settlement_batch_root: demo_root("coupon-settlement", 0),
        coupon_value_piconero: 4_500,
        user_fee_bps: 3,
        minted_at_height: 2_241_374,
        expires_at_height: 2_244_254,
    };
    state.fee_coupons.insert(coupon.coupon_id.clone(), coupon);
    let devnet_public_payload = state.roots().public_record();
    state.insert_public_record(
        "devnet_snapshot",
        "ring-decoy-fee-sponsor",
        &devnet_public_payload,
        2_241_376,
    );
    state
}

pub fn demo_state() -> State {
    let mut state = devnet_state();
    let pool_id = "sponsor-pool-demo-merchant-1".to_string();
    let cohort_id = "decoy-fee-cohort-merchant-demo-1".to_string();
    state.sponsor_pools.insert(
        pool_id.clone(),
        PrivateSponsorPool {
            pool_id: pool_id.clone(),
            sponsor_id: "merchant-sponsor-demo-1".to_string(),
            status: SponsorPoolStatus::Throttled,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            pool_commitment_root: demo_root("pool-commitment", 1),
            sponsor_policy_root: demo_root("sponsor-policy", 1),
            liquidity_commitment_root: demo_root("liquidity", 1),
            available_fee_budget_piconero: 3_250_000_000,
            max_coupon_value_piconero: 7_500,
            max_coupons_per_epoch: 8_000,
            epoch: 4_672,
            expires_at_height: 2_248_880,
        },
    );
    state.decoy_fee_cohorts.insert(
        cohort_id.clone(),
        DecoySetFeeCohort {
            cohort_id: cohort_id.clone(),
            pool_id: pool_id.clone(),
            kind: CohortKind::MerchantCheckout,
            status: CohortStatus::Subsidized,
            ring_size: 40,
            decoy_set_size: 262_144,
            decoy_distribution_root: demo_root("decoy-distribution", 1),
            fee_bucket_root: demo_root("fee-bucket", 1),
            max_user_fee_bps: 2,
            sponsor_share_bps: 9_250,
            min_freshness_bps: 9_000,
            active_height: 2_241_520,
        },
    );
    state.freshness_reports.insert(
        "freshness-demo-merchant-1".to_string(),
        RingMemberFreshnessReport {
            report_id: "freshness-demo-merchant-1".to_string(),
            cohort_id: cohort_id.clone(),
            oracle_id: "ring-freshness-oracle-demo-1".to_string(),
            status: FreshnessStatus::Watch,
            ring_member_commitment_root: demo_root("ring-members", 1),
            age_histogram_root: demo_root("age-histogram", 1),
            quarantined_member_root: demo_root("quarantine", 1),
            freshness_bps: 8_980,
            sampled_members: 8_192,
            observed_height: 2_241_540,
        },
    );
    state.sponsor_attestations.insert(
        "pq-sponsor-attestation-demo-1".to_string(),
        PqSponsorAttestation {
            attestation_id: "pq-sponsor-attestation-demo-1".to_string(),
            sponsor_id: "merchant-sponsor-demo-1".to_string(),
            pool_id,
            status: AttestationStatus::Quorum,
            pq_public_key_root: demo_root("pq-public-key", 1),
            sponsor_attestation_root: demo_root("sponsor-attestation", 1),
            signature_root: demo_root("pq-signature", 1),
            security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            issued_at_height: 2_241_500,
            expires_at_height: 2_241_788,
        },
    );
    let cap_id = "wallet-cap-demo-merchant-1".to_string();
    state.wallet_caps.insert(
        cap_id.clone(),
        WalletCap {
            cap_id: cap_id.clone(),
            wallet_commitment: demo_commitment("wallet", 1),
            status: WalletCapStatus::NearCap,
            policy_root: demo_root("wallet-cap-policy", 1),
            spend_nullifier_root: demo_root("wallet-spend-nullifier", 1),
            epoch: 4_672,
            daily_cap_piconero: 90_000,
            consumed_piconero: 81_500,
            max_user_fee_bps: 2,
        },
    );
    state.fee_coupons.insert(
        "fee-coupon-demo-merchant-1".to_string(),
        FeeCoupon {
            coupon_id: "fee-coupon-demo-merchant-1".to_string(),
            pool_id: "sponsor-pool-demo-merchant-1".to_string(),
            cohort_id,
            wallet_cap_id: cap_id,
            status: CouponStatus::Applied,
            coupon_nullifier_root: demo_root("coupon-nullifier", 1),
            recipient_commitment_root: demo_root("coupon-recipient", 1),
            settlement_batch_root: demo_root("coupon-settlement", 1),
            coupon_value_piconero: 6_200,
            user_fee_bps: 2,
            minted_at_height: 2_241_544,
            expires_at_height: 2_244_424,
        },
    );
    let demo_public_payload = state.roots().public_record();
    state.insert_public_record(
        "demo_snapshot",
        "merchant-checkout-fee-sponsor",
        &demo_public_payload,
        2_241_548,
    );
    state
}

pub fn payload_root<T: Serialize>(domain: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("runtime value serializes");
    domain_hash(domain, &[HashPart::Json(&value)])
}

pub fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": payload_root(domain, value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn public_records_root(records: &BTreeMap<String, PublicRecordEntry>) -> String {
    map_root(PUBLIC_RECORD_SCHEME, records)
}

pub fn deterministic_id(label: &str, parts: &[&str]) -> String {
    let values = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    domain_hash(label, &[HashPart::Json(&json!(values))])
}

pub fn demo_root(label: &str, index: u64) -> String {
    payload_root(
        "RING-DECOY-FEE-SPONSOR-DEMO-ROOT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

pub fn demo_commitment(label: &str, index: u64) -> String {
    payload_root(
        "RING-DECOY-FEE-SPONSOR-DEMO-COMMITMENT",
        &json!({
            "label": label,
            "index": index,
            "redacted": true,
        }),
    )
}

pub fn record_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serializes")
}

pub fn sorted_tags(tags: &[&str]) -> BTreeSet<String> {
    tags.iter().map(|tag| tag.to_string()).collect()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
