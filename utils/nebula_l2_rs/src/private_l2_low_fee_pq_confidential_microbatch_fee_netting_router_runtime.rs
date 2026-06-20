use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialMicrobatchFeeNettingRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MICROBATCH_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-microbatch-fee-netting-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MICROBATCH_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MICRO_BATCH_SUITE: &str = "private-l2-low-fee-confidential-microbatch-router-v1";
pub const FEE_NETTING_SUITE: &str = "confidential-microbatch-fee-netting-intent-v1";
pub const SPONSOR_RESERVE_SUITE: &str = "confidential-low-fee-sponsor-reserve-v1";
pub const REBATE_COUPON_SUITE: &str = "privacy-preserving-fee-rebate-coupon-v1";
pub const ROUTE_CAP_SUITE: &str = "microbatch-route-cap-and-speed-guard-v1";
pub const PQ_FEE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-fee-attestation-v1";
pub const SETTLEMENT_RECEIPT_SUITE: &str =
    "private-l2-microbatch-fee-netting-settlement-receipt-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "operator-safe-confidential-microbatch-fee-redaction-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "operator-safe-microbatch-fee-netting-router-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_312_640;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_812_480;
pub const DEVNET_EPOCH: u64 = 27_904;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_BATCH_SIZE: u64 = 64;
pub const DEFAULT_TARGET_BATCH_SIZE: u64 = 512;
pub const DEFAULT_MAX_BATCH_SIZE: u64 = 4_096;
pub const DEFAULT_MAX_NETTING_DELAY_MS: u64 = 280;
pub const DEFAULT_TARGET_SETTLEMENT_MS: u64 = 900;
pub const DEFAULT_ROUTE_CAP_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_RESERVE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u128 = 900;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u128 = 2_400;
pub const DEFAULT_TARGET_NET_FEE_MICRO_UNITS: u128 = 420;
pub const DEFAULT_ROUTE_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_PRIVACY_REBATE_BPS: u64 = 700;
pub const DEFAULT_SPEED_REBATE_BPS: u64 = 450;
pub const DEFAULT_OPERATOR_TAKE_BPS: u64 = 220;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_INTENTS: usize = 8_388_608;
pub const DEFAULT_MAX_SPONSOR_RESERVES: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_ROUTE_CAPS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_REDACTIONS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    WalletTransfer,
    SwapSettlement,
    BridgeHop,
    ContractCall,
    OracleCallback,
    LiquidityRebalance,
    EmergencyExit,
}

impl LaneClass {
    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::BridgeHop => 8_700,
            Self::SwapSettlement => 8_200,
            Self::LiquidityRebalance => 7_800,
            Self::OracleCallback => 7_200,
            Self::ContractCall => 6_800,
            Self::WalletTransfer => 6_400,
        }
    }

    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::WalletTransfer => 262_144,
            Self::SwapSettlement => 524_288,
            Self::BridgeHop => 1_048_576,
            Self::ContractCall => 393_216,
            Self::OracleCallback => 262_144,
            Self::LiquidityRebalance => 786_432,
            Self::EmergencyExit => 131_072,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Warming,
    Saturated,
    Settling,
    Throttled,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Warming | Self::Saturated)
    }

    pub fn is_live(self) -> bool {
        !matches!(self, Self::Paused | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Encrypted,
    Queued,
    Netted,
    Sponsored,
    Rebated,
    Attested,
    Settled,
    Expired,
    Rejected,
    Quarantined,
}

impl IntentStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Encrypted
                | Self::Queued
                | Self::Netted
                | Self::Sponsored
                | Self::Rebated
                | Self::Attested
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Rejected | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingMode {
    SameAsset,
    CrossAssetOracleBound,
    SponsorOffset,
    CouponOffset,
    RouteInternalization,
    EmergencyMinimal,
}

impl NettingMode {
    pub fn fee_savings_bps(self) -> u64 {
        match self {
            Self::SameAsset => 1_800,
            Self::CrossAssetOracleBound => 1_250,
            Self::SponsorOffset => 2_400,
            Self::CouponOffset => 1_600,
            Self::RouteInternalization => 2_100,
            Self::EmergencyMinimal => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    None,
    PrivacySetGrowth,
    NewWalletBootstrap,
    MarketMakerFlow,
    BridgeIngress,
    EmergencyExit,
}

impl SponsorPolicy {
    pub fn max_rebate_bps(self) -> u64 {
        match self {
            Self::None => 0,
            Self::PrivacySetGrowth => 1_200,
            Self::NewWalletBootstrap => 2_000,
            Self::MarketMakerFlow => 1_600,
            Self::BridgeIngress => 1_400,
            Self::EmergencyExit => 3_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

impl CouponStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Issued | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Funded,
    Committed,
    Draining,
    Exhausted,
    Frozen,
}

impl ReserveStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Funded | Self::Committed | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Verified,
    RotatingKey,
    Stale,
    Slashed,
}

impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::RotatingKey)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Committed,
    Anchored,
    Final,
    Disputed,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub runtime_mode: RuntimeMode,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_batch_size: u64,
    pub target_batch_size: u64,
    pub max_batch_size: u64,
    pub max_netting_delay_ms: u64,
    pub target_settlement_ms: u64,
    pub route_cap_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub reserve_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub base_fee_micro_units: u128,
    pub max_user_fee_micro_units: u128,
    pub target_net_fee_micro_units: u128,
    pub route_fee_cap_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub privacy_rebate_bps: u64,
    pub speed_rebate_bps: u64,
    pub operator_take_bps: u64,
    pub max_lanes: usize,
    pub max_intents: usize,
    pub max_sponsor_reserves: usize,
    pub max_rebate_coupons: usize,
    pub max_route_caps: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
    pub max_redactions: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runtime_mode: RuntimeMode::Devnet,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: "monero-devnet".to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            target_batch_size: DEFAULT_TARGET_BATCH_SIZE,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_netting_delay_ms: DEFAULT_MAX_NETTING_DELAY_MS,
            target_settlement_ms: DEFAULT_TARGET_SETTLEMENT_MS,
            route_cap_ttl_blocks: DEFAULT_ROUTE_CAP_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            reserve_ttl_blocks: DEFAULT_RESERVE_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            target_net_fee_micro_units: DEFAULT_TARGET_NET_FEE_MICRO_UNITS,
            route_fee_cap_bps: DEFAULT_ROUTE_FEE_CAP_BPS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            privacy_rebate_bps: DEFAULT_PRIVACY_REBATE_BPS,
            speed_rebate_bps: DEFAULT_SPEED_REBATE_BPS,
            operator_take_bps: DEFAULT_OPERATOR_TAKE_BPS,
            max_lanes: DEFAULT_MAX_LANES,
            max_intents: DEFAULT_MAX_INTENTS,
            max_sponsor_reserves: DEFAULT_MAX_SPONSOR_RESERVES,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_route_caps: DEFAULT_MAX_ROUTE_CAPS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_redactions: DEFAULT_MAX_REDACTIONS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor too low"
        );
        ensure!(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set floor too low"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.min_batch_size > 0
                && self.target_batch_size >= self.min_batch_size
                && self.max_batch_size >= self.target_batch_size,
            "invalid batch size range"
        );
        ensure!(
            self.max_netting_delay_ms > 0,
            "netting delay must be positive"
        );
        ensure!(
            self.target_settlement_ms >= self.max_netting_delay_ms,
            "settlement target below netting delay"
        );
        ensure!(
            self.target_net_fee_micro_units <= self.max_user_fee_micro_units,
            "target net fee exceeds user cap"
        );
        for (label, bps) in [
            ("route_fee_cap_bps", self.route_fee_cap_bps),
            ("sponsor_rebate_bps", self.sponsor_rebate_bps),
            ("privacy_rebate_bps", self.privacy_rebate_bps),
            ("speed_rebate_bps", self.speed_rebate_bps),
            ("operator_take_bps", self.operator_take_bps),
        ] {
            ensure!(bps <= MAX_BPS, "{} exceeds bps maximum", label);
        }
        Ok(())
    }

    pub fn effective_rebate_bps(&self, policy: SponsorPolicy, privacy_delta: u64) -> u64 {
        let policy_bps = policy.max_rebate_bps().min(self.sponsor_rebate_bps);
        let privacy_bps = if privacy_delta >= self.target_privacy_set_size / 8 {
            self.privacy_rebate_bps
        } else {
            self.privacy_rebate_bps / 2
        };
        policy_bps
            .saturating_add(privacy_bps)
            .saturating_add(self.speed_rebate_bps)
            .min(MAX_BPS)
    }

    pub fn capped_fee(&self, gross_fee_micro_units: u128) -> u128 {
        gross_fee_micro_units.min(self.max_user_fee_micro_units)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub lanes_retired: u64,
    pub intents_submitted: u64,
    pub intents_netted: u64,
    pub intents_rebated: u64,
    pub intents_attested: u64,
    pub intents_settled: u64,
    pub sponsor_reserves_funded: u64,
    pub sponsor_reserves_debited: u64,
    pub coupons_issued: u64,
    pub coupons_applied: u64,
    pub route_caps_set: u64,
    pub route_caps_hit: u64,
    pub attestations_recorded: u64,
    pub receipts_recorded: u64,
    pub redactions_recorded: u64,
    pub operator_summaries_recorded: u64,
    pub gross_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsor_paid_micro_units: u128,
    pub coupon_rebate_micro_units: u128,
    pub operator_fee_micro_units: u128,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lanes_root: String,
    pub intents_root: String,
    pub sponsor_reserves_root: String,
    pub rebate_coupons_root: String,
    pub route_caps_root: String,
    pub attestations_root: String,
    pub receipts_root: String,
    pub redactions_root: String,
    pub operator_summaries_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = merkle_root(&[]);
        Self {
            config_root: empty.clone(),
            lanes_root: empty.clone(),
            intents_root: empty.clone(),
            sponsor_reserves_root: empty.clone(),
            rebate_coupons_root: empty.clone(),
            route_caps_root: empty.clone(),
            attestations_root: empty.clone(),
            receipts_root: empty.clone(),
            redactions_root: empty.clone(),
            operator_summaries_root: empty.clone(),
            counters_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchLane {
    pub lane_id: String,
    pub class: LaneClass,
    pub status: LaneStatus,
    pub route_id: String,
    pub asset_id: String,
    pub operator_id: String,
    pub encrypted_lane_label: String,
    pub min_batch_size: u64,
    pub target_batch_size: u64,
    pub max_batch_size: u64,
    pub pending_intents: u64,
    pub netted_intents: u64,
    pub settled_intents: u64,
    pub gross_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsor_offset_micro_units: u128,
    pub coupon_offset_micro_units: u128,
    pub route_cap_micro_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_l2_height: u64,
    pub updated_l2_height: u64,
    pub last_netting_ms: u64,
    pub attestation_root: String,
    pub lane_root: String,
}

impl MicrobatchLane {
    pub fn new(
        lane_id: impl Into<String>,
        class: LaneClass,
        route_id: impl Into<String>,
        asset_id: impl Into<String>,
        operator_id: impl Into<String>,
        encrypted_lane_label: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut lane = Self {
            lane_id: lane_id.into(),
            class,
            status: LaneStatus::Open,
            route_id: route_id.into(),
            asset_id: asset_id.into(),
            operator_id: operator_id.into(),
            encrypted_lane_label: encrypted_lane_label.into(),
            min_batch_size: config.min_batch_size,
            target_batch_size: config.target_batch_size,
            max_batch_size: config.max_batch_size,
            pending_intents: 0,
            netted_intents: 0,
            settled_intents: 0,
            gross_fee_micro_units: 0,
            net_fee_micro_units: 0,
            sponsor_offset_micro_units: 0,
            coupon_offset_micro_units: 0,
            route_cap_micro_units: config.max_user_fee_micro_units,
            privacy_set_size: class.privacy_floor().max(config.min_privacy_set_size),
            pq_security_bits: config.min_pq_security_bits,
            opened_l2_height: height,
            updated_l2_height: height,
            last_netting_ms: 0,
            attestation_root: merkle_root(&[]),
            lane_root: String::new(),
        };
        lane.refresh_root();
        lane
    }

    pub fn accepts(&self, config: &Config) -> bool {
        self.status.accepts_intents()
            && self.pending_intents < self.max_batch_size
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.privacy_set_size >= self.class.privacy_floor()
    }

    pub fn load_ratio_bps(&self) -> u64 {
        if self.max_batch_size == 0 {
            return MAX_BPS;
        }
        ((self.pending_intents.saturating_mul(MAX_BPS)) / self.max_batch_size).min(MAX_BPS)
    }

    pub fn effective_fee_micro_units(&self) -> u128 {
        self.gross_fee_micro_units
            .saturating_sub(self.sponsor_offset_micro_units)
            .saturating_sub(self.coupon_offset_micro_units)
            .min(self.route_cap_micro_units)
    }

    pub fn note_intent(&mut self, gross_fee: u128, height: u64) {
        self.pending_intents = self.pending_intents.saturating_add(1);
        self.gross_fee_micro_units = self.gross_fee_micro_units.saturating_add(gross_fee);
        self.updated_l2_height = height;
        if self.pending_intents >= self.target_batch_size {
            self.status = LaneStatus::Saturated;
        }
        self.refresh_root();
    }

    pub fn note_netting(
        &mut self,
        net_fee: u128,
        sponsor_offset: u128,
        coupon_offset: u128,
        netting_ms: u64,
        height: u64,
    ) {
        self.pending_intents = self.pending_intents.saturating_sub(1);
        self.netted_intents = self.netted_intents.saturating_add(1);
        self.net_fee_micro_units = self.net_fee_micro_units.saturating_add(net_fee);
        self.sponsor_offset_micro_units = self
            .sponsor_offset_micro_units
            .saturating_add(sponsor_offset);
        self.coupon_offset_micro_units =
            self.coupon_offset_micro_units.saturating_add(coupon_offset);
        self.last_netting_ms = netting_ms;
        self.updated_l2_height = height;
        if self.pending_intents < self.target_batch_size {
            self.status = LaneStatus::Open;
        }
        self.refresh_root();
    }

    pub fn note_settlement(&mut self, count: u64, height: u64) {
        self.settled_intents = self.settled_intents.saturating_add(count);
        self.netted_intents = self.netted_intents.saturating_sub(count);
        self.updated_l2_height = height;
        self.refresh_root();
    }

    pub fn refresh_root(&mut self) {
        self.lane_root = stable_hash(
            "microbatch_lane",
            &json!({
                "lane_id": self.lane_id,
                "class": self.class,
                "status": self.status,
                "route_id": self.route_id,
                "asset_id": self.asset_id,
                "operator_id": self.operator_id,
                "encrypted_lane_label": self.encrypted_lane_label,
                "min_batch_size": self.min_batch_size,
                "target_batch_size": self.target_batch_size,
                "max_batch_size": self.max_batch_size,
                "pending_intents": self.pending_intents,
                "netted_intents": self.netted_intents,
                "settled_intents": self.settled_intents,
                "gross_fee_micro_units": self.gross_fee_micro_units,
                "net_fee_micro_units": self.net_fee_micro_units,
                "sponsor_offset_micro_units": self.sponsor_offset_micro_units,
                "coupon_offset_micro_units": self.coupon_offset_micro_units,
                "route_cap_micro_units": self.route_cap_micro_units,
                "privacy_set_size": self.privacy_set_size,
                "pq_security_bits": self.pq_security_bits,
                "opened_l2_height": self.opened_l2_height,
                "updated_l2_height": self.updated_l2_height,
                "last_netting_ms": self.last_netting_ms,
                "attestation_root": self.attestation_root,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "class": self.class,
            "status": self.status,
            "route_id": self.route_id,
            "asset_id": self.asset_id,
            "operator_id": self.operator_id,
            "pending_intents": self.pending_intents,
            "netted_intents": self.netted_intents,
            "settled_intents": self.settled_intents,
            "effective_fee_micro_units": self.effective_fee_micro_units(),
            "load_ratio_bps": self.load_ratio_bps(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "updated_l2_height": self.updated_l2_height,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeNettingIntent {
    pub intent_id: String,
    pub lane_id: String,
    pub route_id: String,
    pub encrypted_sender: String,
    pub encrypted_recipient: String,
    pub encrypted_payload_commitment: String,
    pub nullifier_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub gross_fee_micro_units: u128,
    pub max_user_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsor_offset_micro_units: u128,
    pub coupon_offset_micro_units: u128,
    pub mode: NettingMode,
    pub sponsor_policy: SponsorPolicy,
    pub status: IntentStatus,
    pub priority_weight: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_l2_height: u64,
    pub expires_l2_height: u64,
    pub settled_l2_height: Option<u64>,
    pub coupon_id: Option<String>,
    pub sponsor_id: Option<String>,
    pub attestation_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
    pub intent_root: String,
}

impl FeeNettingIntent {
    pub fn new(
        intent_id: impl Into<String>,
        lane_id: impl Into<String>,
        route_id: impl Into<String>,
        encrypted_sender: impl Into<String>,
        encrypted_recipient: impl Into<String>,
        asset_id: impl Into<String>,
        gross_fee_micro_units: u128,
        mode: NettingMode,
        sponsor_policy: SponsorPolicy,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut intent = Self {
            intent_id: intent_id.into(),
            lane_id: lane_id.into(),
            route_id: route_id.into(),
            encrypted_sender: encrypted_sender.into(),
            encrypted_recipient: encrypted_recipient.into(),
            encrypted_payload_commitment: seeded_id("payload", height, gross_fee_micro_units),
            nullifier_commitment: seeded_id("nullifier", height, gross_fee_micro_units),
            asset_id: asset_id.into(),
            amount_commitment: seeded_id("amount", height, gross_fee_micro_units),
            gross_fee_micro_units,
            max_user_fee_micro_units: config.max_user_fee_micro_units,
            net_fee_micro_units: config.capped_fee(gross_fee_micro_units),
            sponsor_offset_micro_units: 0,
            coupon_offset_micro_units: 0,
            mode,
            sponsor_policy,
            status: IntentStatus::Submitted,
            priority_weight: mode.fee_savings_bps().saturating_add(6_000),
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            submitted_l2_height: height,
            expires_l2_height: height.saturating_add(config.intent_ttl_blocks),
            settled_l2_height: None,
            coupon_id: None,
            sponsor_id: None,
            attestation_id: None,
            settlement_receipt_id: None,
            intent_root: String::new(),
        };
        intent.refresh_root();
        intent
    }

    pub fn expired(&self, current_height: u64) -> bool {
        current_height > self.expires_l2_height && !self.status.terminal()
    }

    pub fn apply_netting(&mut self, config: &Config, privacy_delta: u64) {
        let mode_rebate = (self
            .gross_fee_micro_units
            .saturating_mul(self.mode.fee_savings_bps() as u128))
            / MAX_BPS as u128;
        let policy_bps = config.effective_rebate_bps(self.sponsor_policy, privacy_delta);
        let policy_rebate = (self
            .gross_fee_micro_units
            .saturating_mul(policy_bps as u128))
            / MAX_BPS as u128;
        let gross_rebate = mode_rebate.saturating_add(policy_rebate);
        self.net_fee_micro_units = config
            .capped_fee(self.gross_fee_micro_units)
            .saturating_sub(gross_rebate)
            .max(
                config
                    .target_net_fee_micro_units
                    .min(self.gross_fee_micro_units),
            );
        self.sponsor_offset_micro_units = policy_rebate;
        self.status = IntentStatus::Netted;
        self.refresh_root();
    }

    pub fn apply_coupon(&mut self, coupon_id: impl Into<String>, rebate: u128) {
        self.coupon_id = Some(coupon_id.into());
        self.coupon_offset_micro_units = self.coupon_offset_micro_units.saturating_add(rebate);
        self.net_fee_micro_units = self.net_fee_micro_units.saturating_sub(rebate);
        self.status = IntentStatus::Rebated;
        self.refresh_root();
    }

    pub fn attach_sponsor(&mut self, sponsor_id: impl Into<String>, paid: u128) {
        self.sponsor_id = Some(sponsor_id.into());
        self.sponsor_offset_micro_units = self.sponsor_offset_micro_units.saturating_add(paid);
        self.net_fee_micro_units = self.net_fee_micro_units.saturating_sub(paid);
        self.status = IntentStatus::Sponsored;
        self.refresh_root();
    }

    pub fn attest(&mut self, attestation_id: impl Into<String>) {
        self.attestation_id = Some(attestation_id.into());
        self.status = IntentStatus::Attested;
        self.refresh_root();
    }

    pub fn settle(&mut self, receipt_id: impl Into<String>, height: u64) {
        self.settlement_receipt_id = Some(receipt_id.into());
        self.settled_l2_height = Some(height);
        self.status = IntentStatus::Settled;
        self.refresh_root();
    }

    pub fn refresh_root(&mut self) {
        self.intent_root = stable_hash(
            "fee_netting_intent",
            &json!({
                "intent_id": self.intent_id,
                "lane_id": self.lane_id,
                "route_id": self.route_id,
                "encrypted_sender": self.encrypted_sender,
                "encrypted_recipient": self.encrypted_recipient,
                "encrypted_payload_commitment": self.encrypted_payload_commitment,
                "nullifier_commitment": self.nullifier_commitment,
                "asset_id": self.asset_id,
                "amount_commitment": self.amount_commitment,
                "gross_fee_micro_units": self.gross_fee_micro_units,
                "max_user_fee_micro_units": self.max_user_fee_micro_units,
                "net_fee_micro_units": self.net_fee_micro_units,
                "sponsor_offset_micro_units": self.sponsor_offset_micro_units,
                "coupon_offset_micro_units": self.coupon_offset_micro_units,
                "mode": self.mode,
                "sponsor_policy": self.sponsor_policy,
                "status": self.status,
                "priority_weight": self.priority_weight,
                "privacy_set_size": self.privacy_set_size,
                "pq_security_bits": self.pq_security_bits,
                "submitted_l2_height": self.submitted_l2_height,
                "expires_l2_height": self.expires_l2_height,
                "settled_l2_height": self.settled_l2_height,
                "coupon_id": self.coupon_id,
                "sponsor_id": self.sponsor_id,
                "attestation_id": self.attestation_id,
                "settlement_receipt_id": self.settlement_receipt_id,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "route_id": self.route_id,
            "asset_id": self.asset_id,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "net_fee_micro_units": self.net_fee_micro_units,
            "sponsor_offset_micro_units": self.sponsor_offset_micro_units,
            "coupon_offset_micro_units": self.coupon_offset_micro_units,
            "mode": self.mode,
            "sponsor_policy": self.sponsor_policy,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_l2_height": self.submitted_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "settled_l2_height": self.settled_l2_height,
            "coupon_id": self.coupon_id,
            "sponsor_id": self.sponsor_id,
            "attestation_id": self.attestation_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "intent_root": self.intent_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReserve {
    pub sponsor_id: String,
    pub reserve_id: String,
    pub policy: SponsorPolicy,
    pub asset_id: String,
    pub encrypted_owner: String,
    pub total_budget_micro_units: u128,
    pub available_micro_units: u128,
    pub committed_micro_units: u128,
    pub spent_micro_units: u128,
    pub max_per_intent_micro_units: u128,
    pub min_privacy_set_size: u64,
    pub status: ReserveStatus,
    pub funded_l2_height: u64,
    pub expires_l2_height: u64,
    pub reserve_root: String,
}

impl SponsorReserve {
    pub fn new(
        sponsor_id: impl Into<String>,
        reserve_id: impl Into<String>,
        policy: SponsorPolicy,
        encrypted_owner: impl Into<String>,
        budget: u128,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut reserve = Self {
            sponsor_id: sponsor_id.into(),
            reserve_id: reserve_id.into(),
            policy,
            asset_id: config.fee_asset_id.clone(),
            encrypted_owner: encrypted_owner.into(),
            total_budget_micro_units: budget,
            available_micro_units: budget,
            committed_micro_units: 0,
            spent_micro_units: 0,
            max_per_intent_micro_units: config.max_user_fee_micro_units,
            min_privacy_set_size: config.min_privacy_set_size,
            status: ReserveStatus::Funded,
            funded_l2_height: height,
            expires_l2_height: height.saturating_add(config.reserve_ttl_blocks),
            reserve_root: String::new(),
        };
        reserve.refresh_root();
        reserve
    }

    pub fn can_cover(&self, amount: u128, privacy_set_size: u64, height: u64) -> bool {
        self.status.spendable()
            && amount <= self.max_per_intent_micro_units
            && amount <= self.available_micro_units
            && privacy_set_size >= self.min_privacy_set_size
            && height <= self.expires_l2_height
    }

    pub fn commit(&mut self, amount: u128) -> Result<()> {
        ensure!(
            self.status.spendable(),
            "reserve {} not spendable",
            self.reserve_id
        );
        ensure!(
            amount <= self.available_micro_units,
            "reserve {} insufficient",
            self.reserve_id
        );
        self.available_micro_units = self.available_micro_units.saturating_sub(amount);
        self.committed_micro_units = self.committed_micro_units.saturating_add(amount);
        self.status = if self.available_micro_units == 0 {
            ReserveStatus::Draining
        } else {
            ReserveStatus::Committed
        };
        self.refresh_root();
        Ok(())
    }

    pub fn settle(&mut self, amount: u128) {
        let paid = amount.min(self.committed_micro_units);
        self.committed_micro_units = self.committed_micro_units.saturating_sub(paid);
        self.spent_micro_units = self.spent_micro_units.saturating_add(paid);
        if self.available_micro_units == 0 && self.committed_micro_units == 0 {
            self.status = ReserveStatus::Exhausted;
        } else if self.available_micro_units > 0 {
            self.status = ReserveStatus::Funded;
        }
        self.refresh_root();
    }

    pub fn refresh_root(&mut self) {
        self.reserve_root = stable_hash(
            "sponsor_reserve",
            &json!({
                "sponsor_id": self.sponsor_id,
                "reserve_id": self.reserve_id,
                "policy": self.policy,
                "asset_id": self.asset_id,
                "encrypted_owner": self.encrypted_owner,
                "total_budget_micro_units": self.total_budget_micro_units,
                "available_micro_units": self.available_micro_units,
                "committed_micro_units": self.committed_micro_units,
                "spent_micro_units": self.spent_micro_units,
                "max_per_intent_micro_units": self.max_per_intent_micro_units,
                "min_privacy_set_size": self.min_privacy_set_size,
                "status": self.status,
                "funded_l2_height": self.funded_l2_height,
                "expires_l2_height": self.expires_l2_height,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "reserve_id": self.reserve_id,
            "policy": self.policy,
            "asset_id": self.asset_id,
            "available_micro_units": self.available_micro_units,
            "committed_micro_units": self.committed_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "status": self.status,
            "expires_l2_height": self.expires_l2_height,
            "reserve_root": self.reserve_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub issuer_id: String,
    pub encrypted_recipient: String,
    pub lane_class: LaneClass,
    pub asset_id: String,
    pub face_value_micro_units: u128,
    pub remaining_value_micro_units: u128,
    pub min_gross_fee_micro_units: u128,
    pub min_privacy_set_size: u64,
    pub status: CouponStatus,
    pub issued_l2_height: u64,
    pub expires_l2_height: u64,
    pub applied_intents: BTreeSet<String>,
    pub coupon_root: String,
}

impl RebateCoupon {
    pub fn new(
        coupon_id: impl Into<String>,
        issuer_id: impl Into<String>,
        encrypted_recipient: impl Into<String>,
        lane_class: LaneClass,
        face_value_micro_units: u128,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut coupon = Self {
            coupon_id: coupon_id.into(),
            issuer_id: issuer_id.into(),
            encrypted_recipient: encrypted_recipient.into(),
            lane_class,
            asset_id: config.fee_asset_id.clone(),
            face_value_micro_units,
            remaining_value_micro_units: face_value_micro_units,
            min_gross_fee_micro_units: config.target_net_fee_micro_units,
            min_privacy_set_size: lane_class.privacy_floor().max(config.min_privacy_set_size),
            status: CouponStatus::Issued,
            issued_l2_height: height,
            expires_l2_height: height.saturating_add(config.coupon_ttl_blocks),
            applied_intents: BTreeSet::new(),
            coupon_root: String::new(),
        };
        coupon.refresh_root();
        coupon
    }

    pub fn apply(&mut self, intent_id: impl Into<String>, requested: u128, height: u64) -> u128 {
        if !self.status.usable() || height > self.expires_l2_height {
            return 0;
        }
        let rebate = requested.min(self.remaining_value_micro_units);
        self.remaining_value_micro_units = self.remaining_value_micro_units.saturating_sub(rebate);
        self.applied_intents.insert(intent_id.into());
        self.status = if self.remaining_value_micro_units == 0 {
            CouponStatus::Applied
        } else {
            CouponStatus::Reserved
        };
        self.refresh_root();
        rebate
    }

    pub fn settle(&mut self) {
        if self.remaining_value_micro_units == 0 {
            self.status = CouponStatus::Settled;
            self.refresh_root();
        }
    }

    pub fn refresh_root(&mut self) {
        self.coupon_root = stable_hash(
            "rebate_coupon",
            &json!({
                "coupon_id": self.coupon_id,
                "issuer_id": self.issuer_id,
                "encrypted_recipient": self.encrypted_recipient,
                "lane_class": self.lane_class,
                "asset_id": self.asset_id,
                "face_value_micro_units": self.face_value_micro_units,
                "remaining_value_micro_units": self.remaining_value_micro_units,
                "min_gross_fee_micro_units": self.min_gross_fee_micro_units,
                "min_privacy_set_size": self.min_privacy_set_size,
                "status": self.status,
                "issued_l2_height": self.issued_l2_height,
                "expires_l2_height": self.expires_l2_height,
                "applied_intents": self.applied_intents,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "issuer_id": self.issuer_id,
            "lane_class": self.lane_class,
            "asset_id": self.asset_id,
            "remaining_value_micro_units": self.remaining_value_micro_units,
            "status": self.status,
            "expires_l2_height": self.expires_l2_height,
            "applied_intent_count": self.applied_intents.len(),
            "coupon_root": self.coupon_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCap {
    pub cap_id: String,
    pub route_id: String,
    pub lane_class: LaneClass,
    pub asset_id: String,
    pub max_gross_fee_micro_units: u128,
    pub max_net_fee_micro_units: u128,
    pub max_batch_weight: u64,
    pub max_netting_delay_ms: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub active_from_l2_height: u64,
    pub expires_l2_height: u64,
    pub hits: u64,
    pub cap_root: String,
}

impl RouteCap {
    pub fn devnet(
        cap_id: impl Into<String>,
        route_id: impl Into<String>,
        lane_class: LaneClass,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut cap = Self {
            cap_id: cap_id.into(),
            route_id: route_id.into(),
            lane_class,
            asset_id: config.fee_asset_id.clone(),
            max_gross_fee_micro_units: config.max_user_fee_micro_units,
            max_net_fee_micro_units: config.target_net_fee_micro_units,
            max_batch_weight: lane_class
                .default_weight()
                .saturating_mul(config.max_batch_size),
            max_netting_delay_ms: config.max_netting_delay_ms,
            min_privacy_set_size: lane_class.privacy_floor().max(config.min_privacy_set_size),
            min_pq_security_bits: config.min_pq_security_bits,
            active_from_l2_height: height,
            expires_l2_height: height.saturating_add(config.route_cap_ttl_blocks),
            hits: 0,
            cap_root: String::new(),
        };
        cap.refresh_root();
        cap
    }

    pub fn allows(&self, intent: &FeeNettingIntent, netting_delay_ms: u64, height: u64) -> bool {
        self.route_id == intent.route_id
            && self.asset_id == intent.asset_id
            && intent.gross_fee_micro_units <= self.max_gross_fee_micro_units
            && intent.net_fee_micro_units <= self.max_net_fee_micro_units
            && intent.privacy_set_size >= self.min_privacy_set_size
            && intent.pq_security_bits >= self.min_pq_security_bits
            && netting_delay_ms <= self.max_netting_delay_ms
            && height >= self.active_from_l2_height
            && height <= self.expires_l2_height
    }

    pub fn note_hit(&mut self) {
        self.hits = self.hits.saturating_add(1);
        self.refresh_root();
    }

    pub fn refresh_root(&mut self) {
        self.cap_root = stable_hash(
            "route_cap",
            &json!({
                "cap_id": self.cap_id,
                "route_id": self.route_id,
                "lane_class": self.lane_class,
                "asset_id": self.asset_id,
                "max_gross_fee_micro_units": self.max_gross_fee_micro_units,
                "max_net_fee_micro_units": self.max_net_fee_micro_units,
                "max_batch_weight": self.max_batch_weight,
                "max_netting_delay_ms": self.max_netting_delay_ms,
                "min_privacy_set_size": self.min_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits,
                "active_from_l2_height": self.active_from_l2_height,
                "expires_l2_height": self.expires_l2_height,
                "hits": self.hits,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "route_id": self.route_id,
            "lane_class": self.lane_class,
            "asset_id": self.asset_id,
            "max_gross_fee_micro_units": self.max_gross_fee_micro_units,
            "max_net_fee_micro_units": self.max_net_fee_micro_units,
            "max_netting_delay_ms": self.max_netting_delay_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "expires_l2_height": self.expires_l2_height,
            "hits": self.hits,
            "cap_root": self.cap_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqFeeAttestation {
    pub attestation_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub intent_id: String,
    pub fee_vector_commitment: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub net_fee_micro_units: u128,
    pub status: AttestationStatus,
    pub attested_l2_height: u64,
    pub expires_l2_height: u64,
    pub attestation_root: String,
}

impl PqFeeAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        operator_id: impl Into<String>,
        lane_id: impl Into<String>,
        intent: &FeeNettingIntent,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut attestation = Self {
            attestation_id: attestation_id.into(),
            operator_id: operator_id.into(),
            lane_id: lane_id.into(),
            intent_id: intent.intent_id.clone(),
            fee_vector_commitment: stable_hash(
                "fee_vector",
                &json!({
                    "gross": intent.gross_fee_micro_units,
                    "net": intent.net_fee_micro_units,
                    "sponsor": intent.sponsor_offset_micro_units,
                    "coupon": intent.coupon_offset_micro_units,
                }),
            ),
            pq_public_key_commitment: seeded_id(
                "pq_fee_attestation_pk",
                height,
                intent.net_fee_micro_units,
            ),
            signature_commitment: seeded_id(
                "pq_fee_attestation_sig",
                height,
                intent.gross_fee_micro_units,
            ),
            transcript_root: stable_hash("pq_fee_transcript", &intent.public_record()),
            min_pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: intent.privacy_set_size,
            net_fee_micro_units: intent.net_fee_micro_units,
            status: AttestationStatus::Verified,
            attested_l2_height: height,
            expires_l2_height: height.saturating_add(config.attestation_ttl_blocks),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        attestation
    }

    pub fn usable(&self, config: &Config, height: u64) -> bool {
        self.status.usable()
            && self.min_pq_security_bits >= config.min_pq_security_bits
            && self.privacy_set_size >= config.min_privacy_set_size
            && height <= self.expires_l2_height
    }

    pub fn refresh_root(&mut self) {
        self.attestation_root = stable_hash(
            "pq_fee_attestation",
            &json!({
                "attestation_id": self.attestation_id,
                "operator_id": self.operator_id,
                "lane_id": self.lane_id,
                "intent_id": self.intent_id,
                "fee_vector_commitment": self.fee_vector_commitment,
                "pq_public_key_commitment": self.pq_public_key_commitment,
                "signature_commitment": self.signature_commitment,
                "transcript_root": self.transcript_root,
                "min_pq_security_bits": self.min_pq_security_bits,
                "privacy_set_size": self.privacy_set_size,
                "net_fee_micro_units": self.net_fee_micro_units,
                "status": self.status,
                "attested_l2_height": self.attested_l2_height,
                "expires_l2_height": self.expires_l2_height,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "intent_id": self.intent_id,
            "transcript_root": self.transcript_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "net_fee_micro_units": self.net_fee_micro_units,
            "status": self.status,
            "expires_l2_height": self.expires_l2_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub route_id: String,
    pub intent_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub gross_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsor_paid_micro_units: u128,
    pub coupon_rebate_micro_units: u128,
    pub operator_fee_micro_units: u128,
    pub settlement_batch_root: String,
    pub settlement_nullifier_root: String,
    pub status: ReceiptStatus,
    pub settled_l2_height: u64,
    pub expires_l2_height: u64,
    pub receipt_root: String,
}

impl SettlementReceipt {
    pub fn from_intents(
        receipt_id: impl Into<String>,
        lane_id: impl Into<String>,
        route_id: impl Into<String>,
        intents: &[FeeNettingIntent],
        height: u64,
        config: &Config,
    ) -> Self {
        let gross_fee_micro_units = intents
            .iter()
            .map(|intent| intent.gross_fee_micro_units)
            .sum::<u128>();
        let net_fee_micro_units = intents
            .iter()
            .map(|intent| intent.net_fee_micro_units)
            .sum::<u128>();
        let sponsor_paid_micro_units = intents
            .iter()
            .map(|intent| intent.sponsor_offset_micro_units)
            .sum::<u128>();
        let coupon_rebate_micro_units = intents
            .iter()
            .map(|intent| intent.coupon_offset_micro_units)
            .sum::<u128>();
        let operator_fee_micro_units = (net_fee_micro_units
            .saturating_mul(config.operator_take_bps as u128))
            / MAX_BPS as u128;
        let intent_ids = intents
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        let attestation_ids = intents
            .iter()
            .filter_map(|intent| intent.attestation_id.clone())
            .collect::<Vec<_>>();
        let batch_leaves = intents
            .iter()
            .map(|intent| intent.intent_root.clone())
            .collect::<Vec<_>>();
        let nullifier_leaves = intents
            .iter()
            .map(|intent| intent.nullifier_commitment.clone())
            .collect::<Vec<_>>();
        let mut receipt = Self {
            receipt_id: receipt_id.into(),
            lane_id: lane_id.into(),
            route_id: route_id.into(),
            intent_ids,
            attestation_ids,
            gross_fee_micro_units,
            net_fee_micro_units,
            sponsor_paid_micro_units,
            coupon_rebate_micro_units,
            operator_fee_micro_units,
            settlement_batch_root: merkle_root(&batch_leaves),
            settlement_nullifier_root: merkle_root(&nullifier_leaves),
            status: ReceiptStatus::Committed,
            settled_l2_height: height,
            expires_l2_height: height.saturating_add(config.receipt_ttl_blocks),
            receipt_root: String::new(),
        };
        receipt.refresh_root();
        receipt
    }

    pub fn anchor(&mut self) {
        self.status = ReceiptStatus::Anchored;
        self.refresh_root();
    }

    pub fn finalize(&mut self) {
        self.status = ReceiptStatus::Final;
        self.refresh_root();
    }

    pub fn refresh_root(&mut self) {
        self.receipt_root = stable_hash(
            "settlement_receipt",
            &json!({
                "receipt_id": self.receipt_id,
                "lane_id": self.lane_id,
                "route_id": self.route_id,
                "intent_ids": self.intent_ids,
                "attestation_ids": self.attestation_ids,
                "gross_fee_micro_units": self.gross_fee_micro_units,
                "net_fee_micro_units": self.net_fee_micro_units,
                "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
                "coupon_rebate_micro_units": self.coupon_rebate_micro_units,
                "operator_fee_micro_units": self.operator_fee_micro_units,
                "settlement_batch_root": self.settlement_batch_root,
                "settlement_nullifier_root": self.settlement_nullifier_root,
                "status": self.status,
                "settled_l2_height": self.settled_l2_height,
                "expires_l2_height": self.expires_l2_height,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "route_id": self.route_id,
            "intent_count": self.intent_ids.len(),
            "attestation_count": self.attestation_ids.len(),
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "net_fee_micro_units": self.net_fee_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "coupon_rebate_micro_units": self.coupon_rebate_micro_units,
            "operator_fee_micro_units": self.operator_fee_micro_units,
            "settlement_batch_root": self.settlement_batch_root,
            "settlement_nullifier_root": self.settlement_nullifier_root,
            "status": self.status,
            "settled_l2_height": self.settled_l2_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub subject_root: String,
    pub redacted_fields: BTreeSet<String>,
    pub retained_fields: BTreeSet<String>,
    pub privacy_budget_bps: u64,
    pub min_privacy_set_size: u64,
    pub operator_safe_summary: Value,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub redaction_root: String,
}

impl PrivacyRedaction {
    pub fn new(
        redaction_id: impl Into<String>,
        subject_root: impl Into<String>,
        redacted_fields: BTreeSet<String>,
        retained_fields: BTreeSet<String>,
        operator_safe_summary: Value,
        height: u64,
        config: &Config,
    ) -> Self {
        let mut redaction = Self {
            redaction_id: redaction_id.into(),
            subject_root: subject_root.into(),
            redacted_fields,
            retained_fields,
            privacy_budget_bps: config.privacy_rebate_bps.min(MAX_BPS),
            min_privacy_set_size: config.min_privacy_set_size,
            operator_safe_summary,
            created_l2_height: height,
            expires_l2_height: height.saturating_add(config.redaction_epoch_blocks),
            redaction_root: String::new(),
        };
        redaction.refresh_root();
        redaction
    }

    pub fn refresh_root(&mut self) {
        self.redaction_root = stable_hash(
            "privacy_redaction",
            &json!({
                "redaction_id": self.redaction_id,
                "subject_root": self.subject_root,
                "redacted_fields": self.redacted_fields,
                "retained_fields": self.retained_fields,
                "privacy_budget_bps": self.privacy_budget_bps,
                "min_privacy_set_size": self.min_privacy_set_size,
                "operator_safe_summary": self.operator_safe_summary,
                "created_l2_height": self.created_l2_height,
                "expires_l2_height": self.expires_l2_height,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_root": self.subject_root,
            "redacted_fields": self.redacted_fields,
            "retained_fields": self.retained_fields,
            "privacy_budget_bps": self.privacy_budget_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "operator_safe_summary": self.operator_safe_summary,
            "expires_l2_height": self.expires_l2_height,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub l2_height: u64,
    pub lane_count: u64,
    pub live_lane_count: u64,
    pub intent_count: u64,
    pub settled_intent_count: u64,
    pub gross_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsor_paid_micro_units: u128,
    pub coupon_rebate_micro_units: u128,
    pub average_netting_ms: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub public_roots: Roots,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn from_state(
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        state: &State,
    ) -> Self {
        let operator_id = operator_id.into();
        let lanes = state
            .lanes
            .values()
            .filter(|lane| lane.operator_id == operator_id)
            .collect::<Vec<_>>();
        let lane_ids = lanes
            .iter()
            .map(|lane| lane.lane_id.clone())
            .collect::<BTreeSet<_>>();
        let intents = state
            .intents
            .values()
            .filter(|intent| lane_ids.contains(&intent.lane_id))
            .collect::<Vec<_>>();
        let live_lane_count = lanes.iter().filter(|lane| lane.status.is_live()).count() as u64;
        let average_netting_ms = if lanes.is_empty() {
            0
        } else {
            lanes.iter().map(|lane| lane.last_netting_ms).sum::<u64>() / lanes.len() as u64
        };
        let min_privacy_set_size = lanes
            .iter()
            .map(|lane| lane.privacy_set_size)
            .min()
            .unwrap_or(state.config.min_privacy_set_size);
        let min_pq_security_bits = lanes
            .iter()
            .map(|lane| lane.pq_security_bits)
            .min()
            .unwrap_or(state.config.min_pq_security_bits);
        let mut summary = Self {
            summary_id: summary_id.into(),
            operator_id,
            epoch: state.epoch,
            l2_height: state.l2_height,
            lane_count: lanes.len() as u64,
            live_lane_count,
            intent_count: intents.len() as u64,
            settled_intent_count: intents
                .iter()
                .filter(|intent| intent.status == IntentStatus::Settled)
                .count() as u64,
            gross_fee_micro_units: intents
                .iter()
                .map(|intent| intent.gross_fee_micro_units)
                .sum::<u128>(),
            net_fee_micro_units: intents
                .iter()
                .map(|intent| intent.net_fee_micro_units)
                .sum::<u128>(),
            sponsor_paid_micro_units: intents
                .iter()
                .map(|intent| intent.sponsor_offset_micro_units)
                .sum::<u128>(),
            coupon_rebate_micro_units: intents
                .iter()
                .map(|intent| intent.coupon_offset_micro_units)
                .sum::<u128>(),
            average_netting_ms,
            min_privacy_set_size,
            min_pq_security_bits,
            public_roots: state.roots.clone(),
            summary_root: String::new(),
        };
        summary.refresh_root();
        summary
    }

    pub fn refresh_root(&mut self) {
        self.summary_root = stable_hash(
            "operator_summary",
            &json!({
                "summary_id": self.summary_id,
                "operator_id": self.operator_id,
                "epoch": self.epoch,
                "l2_height": self.l2_height,
                "lane_count": self.lane_count,
                "live_lane_count": self.live_lane_count,
                "intent_count": self.intent_count,
                "settled_intent_count": self.settled_intent_count,
                "gross_fee_micro_units": self.gross_fee_micro_units,
                "net_fee_micro_units": self.net_fee_micro_units,
                "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
                "coupon_rebate_micro_units": self.coupon_rebate_micro_units,
                "average_netting_ms": self.average_netting_ms,
                "min_privacy_set_size": self.min_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits,
                "public_roots": self.public_roots,
            }),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "lane_count": self.lane_count,
            "live_lane_count": self.live_lane_count,
            "intent_count": self.intent_count,
            "settled_intent_count": self.settled_intent_count,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "net_fee_micro_units": self.net_fee_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "coupon_rebate_micro_units": self.coupon_rebate_micro_units,
            "average_netting_ms": self.average_netting_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub lanes: BTreeMap<String, MicrobatchLane>,
    pub intents: BTreeMap<String, FeeNettingIntent>,
    pub sponsor_reserves: BTreeMap<String, SponsorReserve>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub attestations: BTreeMap<String, PqFeeAttestation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            l2_height,
            monero_height,
            epoch,
            lanes: BTreeMap::new(),
            intents: BTreeMap::new(),
            sponsor_reserves: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config, DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT, DEVNET_EPOCH)
            .expect("devnet config is valid");
        state
            .install_devnet_fixtures()
            .expect("devnet fixtures are valid");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.submit_intent(
            "intent-demo-wallet-003",
            "lane-wallet-fast",
            "route-wallet-fast",
            "enc-demo-sender-003",
            "enc-demo-recipient-003",
            DEVNET_FEE_ASSET_ID,
            1_650,
            NettingMode::CouponOffset,
            SponsorPolicy::NewWalletBootstrap,
        );
        let _ =
            state.apply_coupon_to_intent("coupon-new-wallet-001", "intent-demo-wallet-003", 380);
        let _ = state.net_intent("intent-demo-wallet-003", 144);
        let _ = state.attest_intent("intent-demo-wallet-003", "att-demo-wallet-003");
        let _ = state.settle_lane(
            "lane-wallet-fast",
            "receipt-demo-wallet-002",
            &["intent-demo-wallet-003"],
        );
        state
    }

    pub fn open_lane(&mut self, lane: MicrobatchLane) -> Result<()> {
        ensure!(
            self.lanes.len() < self.config.max_lanes,
            "lane capacity exceeded"
        );
        ensure!(!self.lanes.contains_key(&lane.lane_id), "lane exists");
        ensure!(
            lane.pq_security_bits >= self.config.min_pq_security_bits,
            "lane pq security below floor"
        );
        ensure!(
            lane.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below floor"
        );
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn set_route_cap(&mut self, cap: RouteCap) -> Result<()> {
        ensure!(
            self.route_caps.len() < self.config.max_route_caps,
            "route cap capacity exceeded"
        );
        self.counters.route_caps_set = self.counters.route_caps_set.saturating_add(1);
        self.route_caps.insert(cap.cap_id.clone(), cap);
        self.refresh_roots();
        Ok(())
    }

    pub fn fund_sponsor_reserve(&mut self, reserve: SponsorReserve) -> Result<()> {
        ensure!(
            self.sponsor_reserves.len() < self.config.max_sponsor_reserves,
            "sponsor reserve capacity exceeded"
        );
        self.counters.sponsor_reserves_funded =
            self.counters.sponsor_reserves_funded.saturating_add(1);
        self.sponsor_reserves
            .insert(reserve.reserve_id.clone(), reserve);
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_coupon(&mut self, coupon: RebateCoupon) -> Result<()> {
        ensure!(
            self.rebate_coupons.len() < self.config.max_rebate_coupons,
            "rebate coupon capacity exceeded"
        );
        self.counters.coupons_issued = self.counters.coupons_issued.saturating_add(1);
        self.rebate_coupons.insert(coupon.coupon_id.clone(), coupon);
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_intent(
        &mut self,
        intent_id: impl Into<String>,
        lane_id: impl Into<String>,
        route_id: impl Into<String>,
        encrypted_sender: impl Into<String>,
        encrypted_recipient: impl Into<String>,
        asset_id: impl Into<String>,
        gross_fee_micro_units: u128,
        mode: NettingMode,
        sponsor_policy: SponsorPolicy,
    ) -> Result<()> {
        ensure!(
            self.intents.len() < self.config.max_intents,
            "intent capacity exceeded"
        );
        let intent_id = intent_id.into();
        ensure!(!self.intents.contains_key(&intent_id), "intent exists");
        let lane_id = lane_id.into();
        let route_id = route_id.into();
        let asset_id = asset_id.into();
        let lane = self
            .lanes
            .get_mut(&lane_id)
            .ok_or_else(|| format!("missing lane {}", lane_id))?;
        ensure!(lane.accepts(&self.config), "lane {} not accepting", lane_id);
        ensure!(
            lane.route_id == route_id,
            "route mismatch for lane {}",
            lane_id
        );
        ensure!(
            lane.asset_id == asset_id,
            "asset mismatch for lane {}",
            lane_id
        );
        let mut intent = FeeNettingIntent::new(
            intent_id,
            lane_id.clone(),
            route_id,
            encrypted_sender,
            encrypted_recipient,
            asset_id,
            gross_fee_micro_units,
            mode,
            sponsor_policy,
            self.l2_height,
            &self.config,
        );
        intent.status = IntentStatus::Encrypted;
        intent.refresh_root();
        lane.note_intent(gross_fee_micro_units, self.l2_height);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.counters.gross_fee_micro_units = self
            .counters
            .gross_fee_micro_units
            .saturating_add(gross_fee_micro_units);
        self.intents.insert(intent.intent_id.clone(), intent);
        self.refresh_roots();
        Ok(())
    }

    pub fn apply_coupon_to_intent(
        &mut self,
        coupon_id: impl AsRef<str>,
        intent_id: impl AsRef<str>,
        requested_rebate: u128,
    ) -> Result<u128> {
        let coupon_id = coupon_id.as_ref();
        let intent_id = intent_id.as_ref();
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("missing intent {}", intent_id))?;
        let coupon = self
            .rebate_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("missing coupon {}", coupon_id))?;
        ensure!(intent.status.active(), "intent not active");
        ensure!(
            coupon.lane_class.privacy_floor() <= intent.privacy_set_size,
            "coupon privacy floor unmet"
        );
        ensure!(
            intent.gross_fee_micro_units >= coupon.min_gross_fee_micro_units,
            "coupon fee floor unmet"
        );
        let rebate = coupon.apply(intent_id.to_string(), requested_rebate, self.l2_height);
        ensure!(rebate > 0, "coupon {} not applicable", coupon_id);
        intent.apply_coupon(coupon_id.to_string(), rebate);
        self.counters.coupons_applied = self.counters.coupons_applied.saturating_add(1);
        self.counters.coupon_rebate_micro_units = self
            .counters
            .coupon_rebate_micro_units
            .saturating_add(rebate);
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn sponsor_intent(
        &mut self,
        reserve_id: impl AsRef<str>,
        intent_id: impl AsRef<str>,
        requested_amount: u128,
    ) -> Result<u128> {
        let reserve_id = reserve_id.as_ref();
        let intent_id = intent_id.as_ref();
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("missing intent {}", intent_id))?;
        let reserve = self
            .sponsor_reserves
            .get_mut(reserve_id)
            .ok_or_else(|| format!("missing reserve {}", reserve_id))?;
        let amount = requested_amount.min(intent.net_fee_micro_units);
        ensure!(
            reserve.can_cover(amount, intent.privacy_set_size, self.l2_height),
            "reserve cannot cover intent"
        );
        reserve.commit(amount)?;
        intent.attach_sponsor(reserve_id.to_string(), amount);
        self.counters.sponsor_reserves_debited =
            self.counters.sponsor_reserves_debited.saturating_add(1);
        self.counters.sponsor_paid_micro_units = self
            .counters
            .sponsor_paid_micro_units
            .saturating_add(amount);
        self.refresh_roots();
        Ok(amount)
    }

    pub fn net_intent(
        &mut self,
        intent_id: impl AsRef<str>,
        observed_netting_ms: u64,
    ) -> Result<()> {
        let intent_id = intent_id.as_ref();
        let privacy_delta = self.config.target_privacy_set_size / 16;
        {
            let intent = self
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| format!("missing intent {}", intent_id))?;
            ensure!(intent.status.active(), "intent not active");
            ensure!(!intent.expired(self.l2_height), "intent expired");
            intent.privacy_set_size = intent
                .privacy_set_size
                .saturating_add(privacy_delta)
                .max(self.config.min_privacy_set_size);
            intent.apply_netting(&self.config, privacy_delta);
        }
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("missing intent {}", intent_id))?
            .clone();
        if let Some(cap_id) = self.find_route_cap(&intent.route_id, intent.lane_id.as_str()) {
            let cap = self
                .route_caps
                .get_mut(&cap_id)
                .ok_or_else(|| format!("missing cap {}", cap_id))?;
            ensure!(
                cap.allows(&intent, observed_netting_ms, self.l2_height),
                "route cap {} blocks intent {}",
                cap_id,
                intent_id
            );
            cap.note_hit();
            self.counters.route_caps_hit = self.counters.route_caps_hit.saturating_add(1);
        }
        let lane = self
            .lanes
            .get_mut(&intent.lane_id)
            .ok_or_else(|| format!("missing lane {}", intent.lane_id))?;
        lane.note_netting(
            intent.net_fee_micro_units,
            intent.sponsor_offset_micro_units,
            intent.coupon_offset_micro_units,
            observed_netting_ms,
            self.l2_height,
        );
        self.counters.intents_netted = self.counters.intents_netted.saturating_add(1);
        self.counters.intents_rebated = self
            .counters
            .intents_rebated
            .saturating_add((intent.coupon_offset_micro_units > 0) as u64);
        self.counters.net_fee_micro_units = self
            .counters
            .net_fee_micro_units
            .saturating_add(intent.net_fee_micro_units);
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_intent(
        &mut self,
        intent_id: impl AsRef<str>,
        attestation_id: impl Into<String>,
    ) -> Result<()> {
        ensure!(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity exceeded"
        );
        let intent_id = intent_id.as_ref();
        let attestation_id = attestation_id.into();
        ensure!(
            !self.attestations.contains_key(&attestation_id),
            "attestation exists"
        );
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("missing intent {}", intent_id))?
            .clone();
        let lane = self
            .lanes
            .get(&intent.lane_id)
            .ok_or_else(|| format!("missing lane {}", intent.lane_id))?;
        let attestation = PqFeeAttestation::new(
            attestation_id.clone(),
            lane.operator_id.clone(),
            lane.lane_id.clone(),
            &intent,
            self.l2_height,
            &self.config,
        );
        ensure!(
            attestation.usable(&self.config, self.l2_height),
            "attestation unusable"
        );
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.attest(attestation_id);
        }
        if let Some(lane) = self.lanes.get_mut(&intent.lane_id) {
            let leaves = self
                .attestations
                .values()
                .filter(|att| att.lane_id == lane.lane_id)
                .map(|att| att.attestation_root.clone())
                .collect::<Vec<_>>();
            lane.attestation_root = merkle_root(&leaves);
            lane.refresh_root();
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.counters.intents_attested = self.counters.intents_attested.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_lane(
        &mut self,
        lane_id: impl AsRef<str>,
        receipt_id: impl Into<String>,
        intent_ids: &[&str],
    ) -> Result<()> {
        ensure!(
            self.settlement_receipts.len() < self.config.max_receipts,
            "receipt capacity exceeded"
        );
        let lane_id = lane_id.as_ref();
        let receipt_id = receipt_id.into();
        ensure!(
            !self.settlement_receipts.contains_key(&receipt_id),
            "receipt exists"
        );
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("missing lane {}", lane_id))?
            .clone();
        let mut intents = Vec::new();
        for intent_id in intent_ids {
            let intent = self
                .intents
                .get(*intent_id)
                .ok_or_else(|| format!("missing intent {}", intent_id))?;
            ensure!(intent.lane_id == lane_id, "intent lane mismatch");
            ensure!(
                matches!(
                    intent.status,
                    IntentStatus::Attested
                        | IntentStatus::Netted
                        | IntentStatus::Rebated
                        | IntentStatus::Sponsored
                ),
                "intent {} not settlement ready",
                intent_id
            );
            intents.push(intent.clone());
        }
        let mut receipt = SettlementReceipt::from_intents(
            receipt_id.clone(),
            lane_id.to_string(),
            lane.route_id.clone(),
            &intents,
            self.l2_height,
            &self.config,
        );
        receipt.anchor();
        for intent in &mut intents {
            intent.settle(receipt_id.clone(), self.l2_height);
            if let Some(current) = self.intents.get_mut(&intent.intent_id) {
                *current = intent.clone();
            }
            if let Some(reserve_id) = &intent.sponsor_id {
                if let Some(reserve) = self.sponsor_reserves.get_mut(reserve_id) {
                    reserve.settle(intent.sponsor_offset_micro_units);
                }
            }
            if let Some(coupon_id) = &intent.coupon_id {
                if let Some(coupon) = self.rebate_coupons.get_mut(coupon_id) {
                    coupon.settle();
                }
            }
        }
        let settled_count = intents.len() as u64;
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.note_settlement(settled_count, self.l2_height);
        }
        self.counters.intents_settled = self.counters.intents_settled.saturating_add(settled_count);
        self.counters.receipts_recorded = self.counters.receipts_recorded.saturating_add(1);
        self.counters.operator_fee_micro_units = self
            .counters
            .operator_fee_micro_units
            .saturating_add(receipt.operator_fee_micro_units);
        self.settlement_receipts.insert(receipt_id, receipt);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_privacy_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        ensure!(
            self.privacy_redactions.len() < self.config.max_redactions,
            "redaction capacity exceeded"
        );
        self.counters.redactions_recorded = self.counters.redactions_recorded.saturating_add(1);
        self.privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_operator_summary(&mut self, operator_id: impl Into<String>) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity exceeded"
        );
        let operator_id = operator_id.into();
        let summary_id = format!("summary-{}-{}", operator_id, self.epoch);
        let summary = OperatorSummary::from_state(summary_id.clone(), operator_id, self);
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries_recorded =
            self.counters.operator_summaries_recorded.saturating_add(1);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = stable_hash("config", &self.config);
        self.roots.counters_root = stable_hash("counters", &self.counters);
        self.roots.lanes_root = merkle_root(
            &self
                .lanes
                .values()
                .map(|lane| lane.lane_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.intents_root = merkle_root(
            &self
                .intents
                .values()
                .map(|intent| intent.intent_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.sponsor_reserves_root = merkle_root(
            &self
                .sponsor_reserves
                .values()
                .map(|reserve| reserve.reserve_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.rebate_coupons_root = merkle_root(
            &self
                .rebate_coupons
                .values()
                .map(|coupon| coupon.coupon_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.route_caps_root = merkle_root(
            &self
                .route_caps
                .values()
                .map(|cap| cap.cap_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.attestations_root = merkle_root(
            &self
                .attestations
                .values()
                .map(|attestation| attestation.attestation_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.receipts_root = merkle_root(
            &self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.receipt_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.redactions_root = merkle_root(
            &self
                .privacy_redactions
                .values()
                .map(|redaction| redaction.redaction_root.clone())
                .collect::<Vec<_>>(),
        );
        self.roots.operator_summaries_root = merkle_root(
            &self
                .operator_summaries
                .values()
                .map(|summary| summary.summary_root.clone())
                .collect::<Vec<_>>(),
        );
        let record = self.public_record_without_roots();
        self.roots.public_record_root = stable_hash("public_record", &record);
        self.roots.state_root = stable_hash(
            "state",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "l2_height": self.l2_height,
                "monero_height": self.monero_height,
                "epoch": self.epoch,
                "roots": self.roots_without_state_root(),
            }),
        );
    }

    fn install_devnet_fixtures(&mut self) -> Result<()> {
        let wallet_lane = MicrobatchLane::new(
            "lane-wallet-fast",
            LaneClass::WalletTransfer,
            "route-wallet-fast",
            self.config.fee_asset_id.clone(),
            "operator-low-fee-001",
            "enc-lane-wallet-fast",
            self.l2_height,
            &self.config,
        );
        let bridge_lane = MicrobatchLane::new(
            "lane-bridge-net",
            LaneClass::BridgeHop,
            "route-bridge-net",
            self.config.fee_asset_id.clone(),
            "operator-low-fee-001",
            "enc-lane-bridge-net",
            self.l2_height,
            &self.config,
        );
        self.open_lane(wallet_lane)?;
        self.open_lane(bridge_lane)?;
        self.set_route_cap(RouteCap::devnet(
            "cap-wallet-fast",
            "route-wallet-fast",
            LaneClass::WalletTransfer,
            self.l2_height,
            &self.config,
        ))?;
        self.set_route_cap(RouteCap::devnet(
            "cap-bridge-net",
            "route-bridge-net",
            LaneClass::BridgeHop,
            self.l2_height,
            &self.config,
        ))?;
        self.fund_sponsor_reserve(SponsorReserve::new(
            "sponsor-privacy-growth",
            "reserve-privacy-growth-001",
            SponsorPolicy::PrivacySetGrowth,
            "enc-sponsor-privacy-growth-owner",
            8_000_000,
            self.l2_height,
            &self.config,
        ))?;
        self.issue_coupon(RebateCoupon::new(
            "coupon-new-wallet-001",
            "issuer-devnet-growth",
            "enc-demo-recipient-003",
            LaneClass::WalletTransfer,
            1_200,
            self.l2_height,
            &self.config,
        ))?;
        self.submit_intent(
            "intent-demo-wallet-001",
            "lane-wallet-fast",
            "route-wallet-fast",
            "enc-demo-sender-001",
            "enc-demo-recipient-001",
            DEVNET_FEE_ASSET_ID,
            1_900,
            NettingMode::SameAsset,
            SponsorPolicy::PrivacySetGrowth,
        )?;
        self.submit_intent(
            "intent-demo-bridge-001",
            "lane-bridge-net",
            "route-bridge-net",
            "enc-demo-sender-002",
            "enc-demo-recipient-002",
            DEVNET_FEE_ASSET_ID,
            2_200,
            NettingMode::SponsorOffset,
            SponsorPolicy::BridgeIngress,
        )?;
        self.sponsor_intent("reserve-privacy-growth-001", "intent-demo-bridge-001", 480)?;
        self.net_intent("intent-demo-wallet-001", 128)?;
        self.net_intent("intent-demo-bridge-001", 186)?;
        self.attest_intent("intent-demo-wallet-001", "att-demo-wallet-001")?;
        self.attest_intent("intent-demo-bridge-001", "att-demo-bridge-001")?;
        self.settle_lane(
            "lane-wallet-fast",
            "receipt-demo-wallet-001",
            &["intent-demo-wallet-001"],
        )?;
        let mut redacted_fields = BTreeSet::new();
        redacted_fields.insert("encrypted_sender".to_string());
        redacted_fields.insert("encrypted_recipient".to_string());
        redacted_fields.insert("amount_commitment".to_string());
        let retained_fields = ["lane_id", "route_id", "net_fee_micro_units", "intent_root"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let subject_root = self
            .intents
            .get("intent-demo-wallet-001")
            .map(|intent| intent.intent_root.clone())
            .unwrap_or_else(|| merkle_root(&[]));
        self.record_privacy_redaction(PrivacyRedaction::new(
            "redaction-demo-wallet-001",
            subject_root,
            redacted_fields,
            retained_fields,
            json!({
                "lane_id": "lane-wallet-fast",
                "route_id": "route-wallet-fast",
                "fee_class": "low_fee_private_transfer",
            }),
            self.l2_height,
            &self.config,
        ))?;
        self.record_operator_summary("operator-low-fee-001")?;
        self.refresh_roots();
        Ok(())
    }

    fn find_route_cap(&self, route_id: &str, lane_id: &str) -> Option<String> {
        let lane_class = self.lanes.get(lane_id).map(|lane| lane.class)?;
        self.route_caps
            .values()
            .find(|cap| cap.route_id == route_id && cap.lane_class == lane_class)
            .map(|cap| cap.cap_id.clone())
    }

    fn public_record_without_roots(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "micro_batch_suite": MICRO_BATCH_SUITE,
            "fee_netting_suite": FEE_NETTING_SUITE,
            "sponsor_reserve_suite": SPONSOR_RESERVE_SUITE,
            "rebate_coupon_suite": REBATE_COUPON_SUITE,
            "route_cap_suite": ROUTE_CAP_SUITE,
            "pq_fee_attestation_suite": PQ_FEE_ATTESTATION_SUITE,
            "settlement_receipt_suite": SETTLEMENT_RECEIPT_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "config": self.config,
            "counters": self.counters,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "lanes": self.lanes.values().map(MicrobatchLane::public_record).collect::<Vec<_>>(),
            "intents": self.intents.values().map(FeeNettingIntent::public_record).collect::<Vec<_>>(),
            "sponsor_reserves": self.sponsor_reserves.values().map(SponsorReserve::public_record).collect::<Vec<_>>(),
            "rebate_coupons": self.rebate_coupons.values().map(RebateCoupon::public_record).collect::<Vec<_>>(),
            "route_caps": self.route_caps.values().map(RouteCap::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqFeeAttestation::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "privacy_redactions": self.privacy_redactions.values().map(PrivacyRedaction::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
        })
    }

    fn roots_without_state_root(&self) -> Value {
        json!({
            "config_root": self.roots.config_root,
            "lanes_root": self.roots.lanes_root,
            "intents_root": self.roots.intents_root,
            "sponsor_reserves_root": self.roots.sponsor_reserves_root,
            "rebate_coupons_root": self.roots.rebate_coupons_root,
            "route_caps_root": self.roots.route_caps_root,
            "attestations_root": self.roots.attestations_root,
            "receipts_root": self.roots.receipts_root,
            "redactions_root": self.roots.redactions_root,
            "operator_summaries_root": self.roots.operator_summaries_root,
            "counters_root": self.roots.counters_root,
            "public_record_root": self.roots.public_record_root,
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    let mut record = state.public_record_without_roots();
    if let Some(object) = record.as_object_mut() {
        object.insert("roots".to_string(), json!(state.roots));
    }
    record
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}

fn stable_hash<T: Serialize>(domain: &str, value: &T) -> String {
    let value =
        serde_json::to_value(value).unwrap_or_else(|_| json!({ "serialization": "failed" }));
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(&value),
        ],
    )
}

fn seeded_id(label: &str, height: u64, value: u128) -> String {
    domain_hash(
        label,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(height as i128),
            HashPart::Int(value as i128),
        ],
    )
}
