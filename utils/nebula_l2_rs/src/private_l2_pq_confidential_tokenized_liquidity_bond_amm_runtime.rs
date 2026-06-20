use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedLiquidityBondAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_BOND_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-liquidity-bond-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_BOND_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_NAV_ORACLE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-bond-nav-v1";
pub const CONFIDENTIAL_BOND_NOTE_SUITE: &str = "confidential-tokenized-liquidity-bond-note-root-v1";
pub const AMM_QUOTE_LANE_SUITE: &str = "confidential-liquidity-bond-amm-quote-lane-root-v1";
pub const MATURITY_BUCKET_SUITE: &str = "tokenized-liquidity-bond-maturity-bucket-root-v1";
pub const NAV_ATTESTATION_SUITE: &str = "pq-nav-oracle-attestation-root-v1";
pub const REDEMPTION_QUEUE_SUITE: &str = "confidential-liquidity-bond-redemption-queue-root-v1";
pub const LIQUIDITY_HAIRCUT_SUITE: &str = "liquidity-bond-amm-haircut-root-v1";
pub const LOW_FEE_REDEMPTION_REBATE_SUITE: &str =
    "low-fee-confidential-liquidity-bond-redemption-rebate-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-tokenized-liquidity-bond-amm-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_944_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_188_000;
pub const DEVNET_AMM_ID: &str = "private-l2-pq-confidential-tokenized-liquidity-bond-amm-devnet";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-liquidity-bond-amm-devnet";
pub const DEVNET_BOND_ASSET_ID: &str = "dlbond-private-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 4;
pub const DEFAULT_REDEMPTION_QUORUM: u16 = 3;
pub const DEFAULT_NAV_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REDEMPTION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REDEMPTION_FEE_BPS: u64 = 4;
pub const DEFAULT_REBATE_BPS: u64 = 3_000;
pub const DEFAULT_MAX_HAIRCUT_BPS: u64 = 850;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u64 = 10_800;
pub const DEFAULT_MAX_QUOTE_LANES: usize = 512;
pub const DEFAULT_MAX_REDEMPTIONS: usize = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondNoteStatus {
    Minted,
    AmmDeposited,
    Quoted,
    Redeeming,
    Settled,
    Burned,
    Frozen,
}

impl BondNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::AmmDeposited => "amm_deposited",
            Self::Quoted => "quoted",
            Self::Redeeming => "redeeming",
            Self::Settled => "settled",
            Self::Burned => "burned",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteLaneStatus {
    Open,
    Throttled,
    OracleLocked,
    RedemptionOnly,
    Paused,
    Retired,
}

impl QuoteLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::OracleLocked => "oracle_locked",
            Self::RedemptionOnly => "redemption_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaturityBucketStatus {
    Building,
    Active,
    RedemptionWindow,
    Matured,
    Retired,
}

impl MaturityBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Active => "active",
            Self::RedemptionWindow => "redemption_window",
            Self::Matured => "matured",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Hold,
    Reject,
    Challenge,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Challenge => "challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionStatus {
    Sealed,
    NavAttested,
    Queued,
    HaircutApplied,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl RedemptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::NavAttested => "nav_attested",
            Self::Queued => "queued",
            Self::HaircutApplied => "haircut_applied",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_nav_oracle_suite: String,
    pub amm_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub bond_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub redemption_quorum: u16,
    pub nav_ttl_blocks: u64,
    pub redemption_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_redemption_fee_bps: u64,
    pub rebate_bps: u64,
    pub max_haircut_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_quote_lanes: usize,
    pub max_redemptions: usize,
    pub require_confidential_bond_notes: bool,
    pub require_pq_nav_attestations: bool,
    pub allow_low_fee_redemption_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_nav_oracle_suite: PQ_NAV_ORACLE_SUITE.to_string(),
            amm_id: DEVNET_AMM_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            bond_asset_id: DEVNET_BOND_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            redemption_quorum: DEFAULT_REDEMPTION_QUORUM,
            nav_ttl_blocks: DEFAULT_NAV_TTL_BLOCKS,
            redemption_ttl_blocks: DEFAULT_REDEMPTION_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_redemption_fee_bps: DEFAULT_TARGET_REDEMPTION_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            max_haircut_bps: DEFAULT_MAX_HAIRCUT_BPS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            max_quote_lanes: DEFAULT_MAX_QUOTE_LANES,
            max_redemptions: DEFAULT_MAX_REDEMPTIONS,
            require_confidential_bond_notes: true,
            require_pq_nav_attestations: true,
            allow_low_fee_redemption_rebates: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_nav_oracle_suite": self.pq_nav_oracle_suite,
            "amm_id": self.amm_id,
            "replay_domain": self.replay_domain,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "bond_asset_id": self.bond_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "redemption_quorum": self.redemption_quorum,
            "nav_ttl_blocks": self.nav_ttl_blocks,
            "redemption_ttl_blocks": self.redemption_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_redemption_fee_bps": self.target_redemption_fee_bps,
            "rebate_bps": self.rebate_bps,
            "max_haircut_bps": self.max_haircut_bps,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "max_quote_lanes": self.max_quote_lanes,
            "max_redemptions": self.max_redemptions,
            "require_confidential_bond_notes": self.require_confidential_bond_notes,
            "require_pq_nav_attestations": self.require_pq_nav_attestations,
            "allow_low_fee_redemption_rebates": self.allow_low_fee_redemption_rebates,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bond_notes: u64,
    pub quote_lanes: u64,
    pub maturity_buckets: u64,
    pub nav_attestations: u64,
    pub redemption_requests: u64,
    pub liquidity_haircuts: u64,
    pub redemption_rebates: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub bond_notes_root: String,
    pub quote_lanes_root: String,
    pub maturity_buckets_root: String,
    pub nav_attestations_root: String,
    pub redemption_queues_root: String,
    pub liquidity_haircuts_root: String,
    pub redemption_rebates_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: merkle_root("liquidity-bond-amm-empty-config-root-v1", &[]),
            counters_root: merkle_root("liquidity-bond-amm-empty-counters-root-v1", &[]),
            bond_notes_root: merkle_root(CONFIDENTIAL_BOND_NOTE_SUITE, &[]),
            quote_lanes_root: merkle_root(AMM_QUOTE_LANE_SUITE, &[]),
            maturity_buckets_root: merkle_root(MATURITY_BUCKET_SUITE, &[]),
            nav_attestations_root: merkle_root(NAV_ATTESTATION_SUITE, &[]),
            redemption_queues_root: merkle_root(REDEMPTION_QUEUE_SUITE, &[]),
            liquidity_haircuts_root: merkle_root(LIQUIDITY_HAIRCUT_SUITE, &[]),
            redemption_rebates_root: merkle_root(LOW_FEE_REDEMPTION_REBATE_SUITE, &[]),
            nullifier_root: merkle_root("liquidity-bond-amm-empty-nullifier-root-v1", &[]),
            public_records_root: merkle_root(PUBLIC_RECORD_SUITE, &[]),
            state_root: merkle_root("liquidity-bond-amm-empty-state-root-v1", &[]),
        }
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialBondNote {
    pub note_id: String,
    pub bucket_id: String,
    pub owner_commitment: String,
    pub note_commitment: String,
    pub nullifier: String,
    pub encrypted_terms_root: String,
    pub principal_commitment: String,
    pub coupon_commitment: String,
    pub maturity_l2_height: u64,
    pub nav_units: u64,
    pub status: BondNoteStatus,
}

impl ConfidentialBondNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "bucket_id": self.bucket_id,
            "note_commitment": self.note_commitment,
            "nullifier": self.nullifier,
            "encrypted_terms_root": self.encrypted_terms_root,
            "principal_commitment": self.principal_commitment,
            "coupon_commitment": self.coupon_commitment,
            "maturity_l2_height": self.maturity_l2_height,
            "nav_units": self.nav_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmmQuoteLane {
    pub lane_id: String,
    pub bucket_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub reserve_commitment: String,
    pub virtual_liquidity_micro_units: u64,
    pub bid_spread_bps: u64,
    pub ask_spread_bps: u64,
    pub max_trade_micro_units: u64,
    pub quote_ttl_blocks: u64,
    pub status: QuoteLaneStatus,
}

impl AmmQuoteLane {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturityBucket {
    pub bucket_id: String,
    pub label: String,
    pub maturity_l2_height: u64,
    pub duration_days: u64,
    pub target_liquidity_micro_units: u64,
    pub outstanding_nav_units: u64,
    pub coupon_rate_bps: u64,
    pub bucket_inventory_root: String,
    pub status: MaturityBucketStatus,
}

impl MaturityBucket {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqNavOracleAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub lane_id: Option<String>,
    pub oracle_committee_root: String,
    pub nav_per_unit_micro_units: u64,
    pub confidence_bps: u64,
    pub reserve_coverage_bps: u64,
    pub oracle_round: u64,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
}

impl PqNavOracleAttestation {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionRequest {
    pub redemption_id: String,
    pub note_id: String,
    pub bucket_id: String,
    pub owner_commitment: String,
    pub nullifier: String,
    pub encrypted_redemption_root: String,
    pub requested_nav_units: u64,
    pub max_fee_bps: u64,
    pub queued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: RedemptionStatus,
}

impl RedemptionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "redemption_id": self.redemption_id,
            "note_id": self.note_id,
            "bucket_id": self.bucket_id,
            "nullifier": self.nullifier,
            "encrypted_redemption_root": self.encrypted_redemption_root,
            "requested_nav_units": self.requested_nav_units,
            "max_fee_bps": self.max_fee_bps,
            "queued_at_l2_height": self.queued_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityHaircut {
    pub haircut_id: String,
    pub bucket_id: String,
    pub redemption_id: Option<String>,
    pub basis: String,
    pub haircut_bps: u64,
    pub pre_haircut_nav_micro_units: u64,
    pub post_haircut_nav_micro_units: u64,
    pub proof_root: String,
    pub applied_at_l2_height: u64,
}

impl LiquidityHaircut {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRedemptionRebate {
    pub rebate_id: String,
    pub redemption_id: String,
    pub recipient_commitment: String,
    pub fee_asset_id: String,
    pub charged_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_micro_units: u64,
    pub issued_at_l2_height: u64,
}

impl LowFeeRedemptionRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "redemption_id": self.redemption_id,
            "fee_asset_id": self.fee_asset_id,
            "charged_fee_bps": self.charged_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "issued_at_l2_height": self.issued_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_l2_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bond_notes: BTreeMap<String, ConfidentialBondNote>,
    pub quote_lanes: BTreeMap<String, AmmQuoteLane>,
    pub maturity_buckets: BTreeMap<String, MaturityBucket>,
    pub nav_attestations: BTreeMap<String, PqNavOracleAttestation>,
    pub redemption_queue: BTreeMap<String, RedemptionRequest>,
    pub liquidity_haircuts: BTreeMap<String, LiquidityHaircut>,
    pub redemption_rebates: BTreeMap<String, LowFeeRedemptionRebate>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            bond_notes: BTreeMap::new(),
            quote_lanes: BTreeMap::new(),
            maturity_buckets: BTreeMap::new(),
            nav_attestations: BTreeMap::new(),
            redemption_queue: BTreeMap::new(),
            liquidity_haircuts: BTreeMap::new(),
            redemption_rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "operator_view": "operator-safe-roots-and-commitments-only",
            "config": self.config.public_record(),
            "counters": self.counters,
            "roots": self.roots,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn insert_maturity_bucket(&mut self, mut bucket: MaturityBucket) -> Result<String> {
        require_non_empty("bucket label", &bucket.label)?;
        require_root("bucket inventory root", &bucket.bucket_inventory_root)?;
        require(bucket.duration_days > 0, "duration days must be positive")?;
        require(
            bucket.coupon_rate_bps <= MAX_BPS,
            "coupon rate cannot exceed MAX_BPS",
        )?;
        if bucket.bucket_id.is_empty() {
            bucket.bucket_id = deterministic_id(
                "liquidity-bond-amm-maturity-bucket-id-v1",
                &[
                    HashPart::Str(&bucket.label),
                    HashPart::U64(bucket.maturity_l2_height),
                    HashPart::U64(bucket.duration_days),
                ],
            );
        }
        let bucket_id = bucket.bucket_id.clone();
        self.maturity_buckets
            .insert(bucket_id.clone(), bucket.clone());
        self.counters.maturity_buckets = self.maturity_buckets.len() as u64;
        self.emit_public_record(
            "maturity_bucket",
            &bucket_id,
            &bucket.public_record(),
            self.config.l2_height,
        );
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn upsert_quote_lane(&mut self, mut lane: AmmQuoteLane) -> Result<String> {
        require(
            self.quote_lanes.len() < self.config.max_quote_lanes
                || self.quote_lanes.contains_key(&lane.lane_id),
            "max quote lanes exceeded",
        )?;
        require(
            self.maturity_buckets.contains_key(&lane.bucket_id),
            "quote lane bucket not found",
        )?;
        require_root("reserve commitment", &lane.reserve_commitment)?;
        require(lane.bid_spread_bps <= MAX_BPS, "bid spread exceeds MAX_BPS")?;
        require(lane.ask_spread_bps <= MAX_BPS, "ask spread exceeds MAX_BPS")?;
        if lane.lane_id.is_empty() {
            lane.lane_id = deterministic_id(
                "liquidity-bond-amm-quote-lane-id-v1",
                &[
                    HashPart::Str(&lane.bucket_id),
                    HashPart::Str(&lane.base_asset_id),
                    HashPart::Str(&lane.quote_asset_id),
                    HashPart::Str(&lane.reserve_commitment),
                ],
            );
        }
        let lane_id = lane.lane_id.clone();
        self.quote_lanes.insert(lane_id.clone(), lane.clone());
        self.counters.quote_lanes = self.quote_lanes.len() as u64;
        self.emit_public_record(
            "amm_quote_lane",
            &lane_id,
            &lane.public_record(),
            self.config.l2_height,
        );
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn mint_bond_note(&mut self, mut note: ConfidentialBondNote) -> Result<String> {
        require(
            self.maturity_buckets.contains_key(&note.bucket_id),
            "bond note bucket not found",
        )?;
        require_root("owner commitment", &note.owner_commitment)?;
        require_root("note commitment", &note.note_commitment)?;
        require_root("nullifier", &note.nullifier)?;
        require_root("encrypted terms root", &note.encrypted_terms_root)?;
        require(
            !self.consumed_nullifiers.contains(&note.nullifier),
            "bond note nullifier already consumed",
        )?;
        if note.note_id.is_empty() {
            note.note_id = deterministic_id(
                "liquidity-bond-amm-confidential-note-id-v1",
                &[
                    HashPart::Str(&note.bucket_id),
                    HashPart::Str(&note.note_commitment),
                    HashPart::Str(&note.nullifier),
                ],
            );
        }
        let note_id = note.note_id.clone();
        self.bond_notes.insert(note_id.clone(), note.clone());
        self.counters.bond_notes = self.bond_notes.len() as u64;
        self.emit_public_record(
            "confidential_bond_note",
            &note_id,
            &note.public_record(),
            self.config.l2_height,
        );
        self.refresh_roots();
        Ok(note_id)
    }

    pub fn attest_nav(&mut self, mut attestation: PqNavOracleAttestation) -> Result<String> {
        require(
            self.maturity_buckets.contains_key(&attestation.bucket_id),
            "attestation bucket not found",
        )?;
        require_root("oracle committee root", &attestation.oracle_committee_root)?;
        require_root("pq signature root", &attestation.pq_signature_root)?;
        require(
            attestation.confidence_bps <= MAX_BPS,
            "confidence cannot exceed MAX_BPS",
        )?;
        require(
            attestation.reserve_coverage_bps >= self.config.min_liquidity_coverage_bps,
            "reserve coverage below configured minimum",
        )?;
        if attestation.attestation_id.is_empty() {
            attestation.attestation_id = deterministic_id(
                "liquidity-bond-amm-pq-nav-attestation-id-v1",
                &[
                    HashPart::Str(&attestation.bucket_id),
                    HashPart::U64(attestation.oracle_round),
                    HashPart::Str(&attestation.pq_signature_root),
                ],
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        self.nav_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.nav_attestations = self.nav_attestations.len() as u64;
        self.emit_public_record(
            "pq_nav_oracle_attestation",
            &attestation_id,
            &attestation.public_record(),
            attestation.attested_at_l2_height,
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn queue_redemption(&mut self, mut redemption: RedemptionRequest) -> Result<String> {
        require(
            self.redemption_queue.len() < self.config.max_redemptions
                || self
                    .redemption_queue
                    .contains_key(&redemption.redemption_id),
            "max redemptions exceeded",
        )?;
        require(
            self.bond_notes.contains_key(&redemption.note_id),
            "redemption note not found",
        )?;
        require_root("redemption nullifier", &redemption.nullifier)?;
        require_root(
            "encrypted redemption root",
            &redemption.encrypted_redemption_root,
        )?;
        require(
            redemption.max_fee_bps <= self.config.max_user_fee_bps,
            "redemption fee exceeds configured maximum",
        )?;
        require(
            !self.consumed_nullifiers.contains(&redemption.nullifier),
            "redemption nullifier already consumed",
        )?;
        if redemption.redemption_id.is_empty() {
            redemption.redemption_id = deterministic_id(
                "liquidity-bond-amm-redemption-id-v1",
                &[
                    HashPart::Str(&redemption.note_id),
                    HashPart::Str(&redemption.nullifier),
                    HashPart::U64(redemption.queued_at_l2_height),
                ],
            );
        }
        let redemption_id = redemption.redemption_id.clone();
        self.consumed_nullifiers
            .insert(redemption.nullifier.clone());
        self.redemption_queue
            .insert(redemption_id.clone(), redemption.clone());
        self.counters.redemption_requests = self.redemption_queue.len() as u64;
        self.counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        self.emit_public_record(
            "redemption_queue",
            &redemption_id,
            &redemption.public_record(),
            redemption.queued_at_l2_height,
        );
        self.refresh_roots();
        Ok(redemption_id)
    }

    pub fn apply_liquidity_haircut(&mut self, mut haircut: LiquidityHaircut) -> Result<String> {
        require(
            self.maturity_buckets.contains_key(&haircut.bucket_id),
            "haircut bucket not found",
        )?;
        require(
            haircut.haircut_bps <= self.config.max_haircut_bps,
            "haircut exceeds configured maximum",
        )?;
        require_root("haircut proof root", &haircut.proof_root)?;
        if haircut.haircut_id.is_empty() {
            haircut.haircut_id = deterministic_id(
                "liquidity-bond-amm-haircut-id-v1",
                &[
                    HashPart::Str(&haircut.bucket_id),
                    HashPart::Str(haircut.redemption_id.as_deref().unwrap_or("bucket")),
                    HashPart::U64(haircut.applied_at_l2_height),
                    HashPart::Str(&haircut.proof_root),
                ],
            );
        }
        let haircut_id = haircut.haircut_id.clone();
        self.liquidity_haircuts
            .insert(haircut_id.clone(), haircut.clone());
        self.counters.liquidity_haircuts = self.liquidity_haircuts.len() as u64;
        self.emit_public_record(
            "liquidity_haircut",
            &haircut_id,
            &haircut.public_record(),
            haircut.applied_at_l2_height,
        );
        self.refresh_roots();
        Ok(haircut_id)
    }

    pub fn issue_redemption_rebate(
        &mut self,
        mut rebate: LowFeeRedemptionRebate,
    ) -> Result<String> {
        require(
            self.config.allow_low_fee_redemption_rebates,
            "redemption rebates disabled",
        )?;
        require(
            self.redemption_queue.contains_key(&rebate.redemption_id),
            "rebate redemption not found",
        )?;
        require_root("rebate recipient commitment", &rebate.recipient_commitment)?;
        require(
            rebate.target_fee_bps <= rebate.charged_fee_bps,
            "target fee cannot exceed charged fee",
        )?;
        if rebate.rebate_id.is_empty() {
            rebate.rebate_id = deterministic_id(
                "liquidity-bond-amm-redemption-rebate-id-v1",
                &[
                    HashPart::Str(&rebate.redemption_id),
                    HashPart::Str(&rebate.recipient_commitment),
                    HashPart::U64(rebate.issued_at_l2_height),
                ],
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        self.redemption_rebates
            .insert(rebate_id.clone(), rebate.clone());
        self.counters.redemption_rebates = self.redemption_rebates.len() as u64;
        self.emit_public_record(
            "low_fee_redemption_rebate",
            &rebate_id,
            &rebate.public_record(),
            rebate.issued_at_l2_height,
        );
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = merkle_root(
            "liquidity-bond-amm-config-root-v1",
            &[self.config.public_record()],
        );
        self.roots.counters_root = merkle_root(
            "liquidity-bond-amm-counters-root-v1",
            &[stable_record(&self.counters)],
        );
        self.roots.bond_notes_root = merkle_root(
            CONFIDENTIAL_BOND_NOTE_SUITE,
            &values(&self.bond_notes, ConfidentialBondNote::public_record),
        );
        self.roots.quote_lanes_root = merkle_root(
            AMM_QUOTE_LANE_SUITE,
            &values(&self.quote_lanes, AmmQuoteLane::public_record),
        );
        self.roots.maturity_buckets_root = merkle_root(
            MATURITY_BUCKET_SUITE,
            &values(&self.maturity_buckets, MaturityBucket::public_record),
        );
        self.roots.nav_attestations_root = merkle_root(
            NAV_ATTESTATION_SUITE,
            &values(
                &self.nav_attestations,
                PqNavOracleAttestation::public_record,
            ),
        );
        self.roots.redemption_queues_root = merkle_root(
            REDEMPTION_QUEUE_SUITE,
            &values(&self.redemption_queue, RedemptionRequest::public_record),
        );
        self.roots.liquidity_haircuts_root = merkle_root(
            LIQUIDITY_HAIRCUT_SUITE,
            &values(&self.liquidity_haircuts, LiquidityHaircut::public_record),
        );
        self.roots.redemption_rebates_root = merkle_root(
            LOW_FEE_REDEMPTION_REBATE_SUITE,
            &values(
                &self.redemption_rebates,
                LowFeeRedemptionRebate::public_record,
            ),
        );
        self.roots.nullifier_root = merkle_root(
            "confidential-liquidity-bond-amm-consumed-nullifier-root-v1",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root(
            PUBLIC_RECORD_SUITE,
            &values(
                &self.public_records,
                DeterministicPublicRecord::public_record,
            ),
        );
        self.roots.state_root = domain_hash(
            "nebula-private-l2-pq-confidential-tokenized-liquidity-bond-amm-state-root-v1",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.monero_height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.bond_notes_root),
                HashPart::Str(&self.roots.quote_lanes_root),
                HashPart::Str(&self.roots.maturity_buckets_root),
                HashPart::Str(&self.roots.nav_attestations_root),
                HashPart::Str(&self.roots.redemption_queues_root),
                HashPart::Str(&self.roots.liquidity_haircuts_root),
                HashPart::Str(&self.roots.redemption_rebates_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }

    fn emit_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_l2_height: u64,
    ) {
        let payload_root = payload_root(record_kind, payload);
        let record_id = deterministic_id(
            "liquidity-bond-amm-public-record-id-v1",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::U64(emitted_at_l2_height),
            ],
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                record_kind: record_kind.to_string(),
                subject_id: subject_id.to_string(),
                payload_root,
                emitted_at_l2_height,
            },
        );
        self.counters.public_records = self.public_records.len() as u64;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let bucket_id = state
        .insert_maturity_bucket(MaturityBucket {
            bucket_id: String::new(),
            label: "91-day private liquidity bond senior bucket".to_string(),
            maturity_l2_height: DEVNET_L2_HEIGHT + 65_520,
            duration_days: 91,
            target_liquidity_micro_units: 25_000_000_000,
            outstanding_nav_units: 18_250_000,
            coupon_rate_bps: 520,
            bucket_inventory_root: hex_root("bucket-inventory", 1),
            status: MaturityBucketStatus::Active,
        })
        .expect("demo maturity bucket");
    let lane_id = state
        .upsert_quote_lane(AmmQuoteLane {
            lane_id: String::new(),
            bucket_id: bucket_id.clone(),
            base_asset_id: DEVNET_BOND_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            reserve_commitment: hex_root("lane-reserve", 1),
            virtual_liquidity_micro_units: 10_500_000_000,
            bid_spread_bps: 18,
            ask_spread_bps: 22,
            max_trade_micro_units: 750_000_000,
            quote_ttl_blocks: 12,
            status: QuoteLaneStatus::Open,
        })
        .expect("demo quote lane");
    let note_id = state
        .mint_bond_note(ConfidentialBondNote {
            note_id: String::new(),
            bucket_id: bucket_id.clone(),
            owner_commitment: hex_root("note-owner", 1),
            note_commitment: hex_root("note-commitment", 1),
            nullifier: hex_root("note-nullifier", 1),
            encrypted_terms_root: hex_root("note-terms", 1),
            principal_commitment: hex_root("note-principal", 1),
            coupon_commitment: hex_root("note-coupon", 1),
            maturity_l2_height: DEVNET_L2_HEIGHT + 65_520,
            nav_units: 1_250_000,
            status: BondNoteStatus::AmmDeposited,
        })
        .expect("demo bond note");
    state
        .attest_nav(PqNavOracleAttestation {
            attestation_id: String::new(),
            bucket_id: bucket_id.clone(),
            lane_id: Some(lane_id),
            oracle_committee_root: hex_root("oracle-committee", 1),
            nav_per_unit_micro_units: 1_000_640,
            confidence_bps: 9_875,
            reserve_coverage_bps: 11_400,
            oracle_round: 77,
            attested_at_l2_height: DEVNET_L2_HEIGHT + 3,
            expires_at_l2_height: DEVNET_L2_HEIGHT + 3 + DEFAULT_NAV_TTL_BLOCKS,
            verdict: AttestationVerdict::Accept,
            pq_signature_root: hex_root("oracle-signature", 1),
        })
        .expect("demo nav attestation");
    let redemption_id = state
        .queue_redemption(RedemptionRequest {
            redemption_id: String::new(),
            note_id,
            bucket_id: bucket_id.clone(),
            owner_commitment: hex_root("redemption-owner", 1),
            nullifier: hex_root("redemption-nullifier", 1),
            encrypted_redemption_root: hex_root("redemption-payload", 1),
            requested_nav_units: 250_000,
            max_fee_bps: 8,
            queued_at_l2_height: DEVNET_L2_HEIGHT + 6,
            expires_at_l2_height: DEVNET_L2_HEIGHT + 6 + DEFAULT_REDEMPTION_TTL_BLOCKS,
            status: RedemptionStatus::Queued,
        })
        .expect("demo redemption");
    state
        .apply_liquidity_haircut(LiquidityHaircut {
            haircut_id: String::new(),
            bucket_id,
            redemption_id: Some(redemption_id.clone()),
            basis: "same-day-redemption-liquidity-buffer".to_string(),
            haircut_bps: 45,
            pre_haircut_nav_micro_units: 250_160_000_000,
            post_haircut_nav_micro_units: 249_034_280_000,
            proof_root: hex_root("haircut-proof", 1),
            applied_at_l2_height: DEVNET_L2_HEIGHT + 7,
        })
        .expect("demo haircut");
    state
        .issue_redemption_rebate(LowFeeRedemptionRebate {
            rebate_id: String::new(),
            redemption_id,
            recipient_commitment: hex_root("rebate-recipient", 1),
            fee_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            charged_fee_bps: 8,
            target_fee_bps: DEFAULT_TARGET_REDEMPTION_FEE_BPS,
            rebate_micro_units: 300_000,
            issued_at_l2_height: DEVNET_L2_HEIGHT + 8,
        })
        .expect("demo redemption rebate");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn values<T>(map: &BTreeMap<String, T>, record: fn(&T) -> Value) -> Vec<Value> {
    map.values().map(record).collect()
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-liquidity-bond-amm-payload-v1",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn stable_record<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn hex_root(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-liquidity-bond-amm-demo-root-v1",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
