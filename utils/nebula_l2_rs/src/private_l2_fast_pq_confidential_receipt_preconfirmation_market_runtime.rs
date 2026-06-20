use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-receipt-preconfirmation-market-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_620_000;
pub const DEVNET_EPOCH: u64 = 2_240;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CREDENTIAL_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-preconfirmation-committee-credentials-v1";
pub const PQ_BID_ENCRYPTION_SUITE: &str = "ml-kem-1024+xwing-encrypted-receipt-bid-envelope-v1";
pub const CONFIDENTIAL_RECEIPT_SUITE: &str =
    "zk-confidential-fast-preconfirmation-receipt-proof-v1";
pub const MONERO_BRIDGE_SUITE: &str = "monero-view-key-confidential-l2-bridge-receipt-bundle-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 8;
pub const DEFAULT_PRECONFIRMATION_TARGET_MS: u64 = 450;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_BATCH_RECEIPTS: usize = 1_024;
pub const DEFAULT_MAX_ACTIVE_BIDS: usize = 131_072;
pub const DEFAULT_MAX_ACTIVE_BUNDLES: usize = 16_384;
pub const DEFAULT_SLASHING_BOND_MICRO_UNITS: u64 = 2_500_000;
pub const DEFAULT_REBATE_BPS: u64 = 600;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:LANES";
const D_CREDENTIALS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:CREDENTIALS";
const D_BONDS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:BONDS";
const D_BIDS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:BIDS";
const D_INTENTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:INTENTS";
const D_CONTRACT_BUNDLES: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:CONTRACT-BUNDLES";
const D_TOKEN_BUNDLES: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:TOKEN-BUNDLES";
const D_BRIDGE_BUNDLES: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:MONERO-BRIDGE-BUNDLES";
const D_ACKS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:SETTLEMENT-ACKS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:FEE-REBATES";
const D_SLASHING: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:SLASHING-EVIDENCE";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:NULLIFIER-FENCES";
const D_PUBLIC_EVENTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:PUBLIC-EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyFeeLaneKind {
    Instant,
    Fast,
    Standard,
    LowFee,
    Sponsored,
    Emergency,
}

impl LatencyFeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }

    pub fn target_ms(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.preconfirmation_target_ms.saturating_div(2).max(1),
            Self::Fast => config.preconfirmation_target_ms,
            Self::Standard => config.preconfirmation_target_ms.saturating_mul(3),
            Self::LowFee => config.preconfirmation_target_ms.saturating_mul(8),
            Self::Sponsored => config.preconfirmation_target_ms.saturating_mul(5),
            Self::Emergency => config.preconfirmation_target_ms.saturating_div(3).max(1),
        }
    }

    pub fn fee_multiplier_bps(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.instant_lane_fee_multiplier_bps,
            Self::Fast => config.fast_lane_fee_multiplier_bps,
            Self::Standard => MAX_BPS,
            Self::LowFee => config.low_fee_lane_multiplier_bps,
            Self::Sponsored => config.sponsored_lane_multiplier_bps,
            Self::Emergency => config.emergency_lane_fee_multiplier_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptClass {
    Intent,
    ContractCall,
    TokenTransfer,
    MoneroBridge,
    DefiSettlement,
    Paymaster,
    Governance,
}

impl ReceiptClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::DefiSettlement => "defi_settlement",
            Self::Paymaster => "paymaster",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRole {
    Sequencer,
    PreconfirmationSigner,
    Watchtower,
    SettlementProver,
    BridgeObserver,
    FeeSponsor,
}

impl CredentialRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::PreconfirmationSigner => "preconfirmation_signer",
            Self::Watchtower => "watchtower",
            Self::SettlementProver => "settlement_prover",
            Self::BridgeObserver => "bridge_observer",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Pending,
    Active,
    Suspended,
    Slashed,
    Retired,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_preconfirm(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidSide {
    User,
    Sequencer,
    Sponsor,
}

impl BidSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Sequencer => "sequencer",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Encrypted,
    Open,
    Matched,
    Bundled,
    Acknowledged,
    Settled,
    Cancelled,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Bundled => "bundled",
            Self::Acknowledged => "acknowledged",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn marketable(self) -> bool {
        matches!(self, Self::Encrypted | Self::Open | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Sealed,
    Preconfirmed,
    SettlementReady,
    Acknowledged,
    Settled,
    Disputed,
    Expired,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::SettlementReady => "settlement_ready",
            Self::Acknowledged => "acknowledged",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentReceiptStatus {
    Registered,
    BidMatched,
    Preconfirmed,
    Fulfilled,
    Reverted,
    Expired,
}

impl IntentReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::BidMatched => "bid_matched",
            Self::Preconfirmed => "preconfirmed",
            Self::Fulfilled => "fulfilled",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Accepted,
    Finalized,
    Rejected,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Posted,
    Locked,
    Releasing,
    Released,
    Slashed,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::Releasing => "releasing",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingOffense {
    DoublePreconfirmation,
    InvalidCredential,
    InvalidBundleRoot,
    ReceiptWithholding,
    SettlementEquivocation,
    BridgeObservationFraud,
    FeeOverclaim,
    NullifierReuse,
}

impl SlashingOffense {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoublePreconfirmation => "double_preconfirmation",
            Self::InvalidCredential => "invalid_credential",
            Self::InvalidBundleRoot => "invalid_bundle_root",
            Self::ReceiptWithholding => "receipt_withholding",
            Self::SettlementEquivocation => "settlement_equivocation",
            Self::BridgeObservationFraud => "bridge_observation_fraud",
            Self::FeeOverclaim => "fee_overclaim",
            Self::NullifierReuse => "nullifier_reuse",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Paid,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_credential_suite: String,
    pub pq_bid_encryption_suite: String,
    pub confidential_receipt_suite: String,
    pub monero_bridge_suite: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_committee_weight: u64,
    pub min_watchtower_weight: u64,
    pub max_active_bids: usize,
    pub max_active_bundles: usize,
    pub max_batch_receipts: usize,
    pub preconfirmation_target_ms: u64,
    pub bid_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub settlement_finality_delay_blocks: u64,
    pub base_fee_micro_units: u64,
    pub instant_lane_fee_multiplier_bps: u64,
    pub fast_lane_fee_multiplier_bps: u64,
    pub low_fee_lane_multiplier_bps: u64,
    pub sponsored_lane_multiplier_bps: u64,
    pub emergency_lane_fee_multiplier_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub settlement_rebate_bps: u64,
    pub slashing_bond_micro_units: u64,
    pub slash_reward_bps: u64,
    pub min_privacy_set_size: u64,
    pub nullifier_window_blocks: u64,
    pub allow_contract_call_bundles: bool,
    pub allow_token_transfer_bundles: bool,
    pub allow_monero_bridge_bundles: bool,
    pub allow_sponsored_fees: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_credential_suite: PQ_CREDENTIAL_SUITE.to_string(),
            pq_bid_encryption_suite: PQ_BID_ENCRYPTION_SUITE.to_string(),
            confidential_receipt_suite: CONFIDENTIAL_RECEIPT_SUITE.to_string(),
            monero_bridge_suite: MONERO_BRIDGE_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight: 3,
            min_watchtower_weight: 2,
            max_active_bids: DEFAULT_MAX_ACTIVE_BIDS,
            max_active_bundles: DEFAULT_MAX_ACTIVE_BUNDLES,
            max_batch_receipts: DEFAULT_MAX_BATCH_RECEIPTS,
            preconfirmation_target_ms: DEFAULT_PRECONFIRMATION_TARGET_MS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            settlement_finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            base_fee_micro_units: 4,
            instant_lane_fee_multiplier_bps: 2_500,
            fast_lane_fee_multiplier_bps: 1_500,
            low_fee_lane_multiplier_bps: 250,
            sponsored_lane_multiplier_bps: 100,
            emergency_lane_fee_multiplier_bps: 5_000,
            low_fee_rebate_bps: DEFAULT_REBATE_BPS,
            settlement_rebate_bps: 250,
            slashing_bond_micro_units: DEFAULT_SLASHING_BOND_MICRO_UNITS,
            slash_reward_bps: 2_000,
            min_privacy_set_size: 65_536,
            nullifier_window_blocks: 128,
            allow_contract_call_bundles: true,
            allow_token_transfer_bundles: true,
            allow_monero_bridge_bundles: true,
            allow_sponsored_fees: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id is required")?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(!self.fee_asset_id.is_empty(), "fee asset id is required")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below policy",
        )?;
        require(
            self.min_committee_weight > 0,
            "committee weight must be positive",
        )?;
        require(
            self.max_active_bids > 0,
            "active bid limit must be positive",
        )?;
        require(
            self.max_active_bundles > 0,
            "active bundle limit must be positive",
        )?;
        require(
            self.max_batch_receipts > 0,
            "max batch receipts must be positive",
        )?;
        require(
            self.preconfirmation_target_ms > 0,
            "target latency must be positive",
        )?;
        require(self.bid_ttl_blocks > 0, "bid ttl must be positive")?;
        require(
            self.receipt_ttl_blocks >= self.bid_ttl_blocks,
            "receipt ttl must cover bids",
        )?;
        require(
            self.settlement_finality_delay_blocks > 0,
            "finality delay must be positive",
        )?;
        require(
            self.instant_lane_fee_multiplier_bps <= MAX_BPS,
            "instant fee multiplier too high",
        )?;
        require(
            self.fast_lane_fee_multiplier_bps <= MAX_BPS,
            "fast fee multiplier too high",
        )?;
        require(
            self.low_fee_lane_multiplier_bps <= MAX_BPS,
            "low fee multiplier too high",
        )?;
        require(
            self.sponsored_lane_multiplier_bps <= MAX_BPS,
            "sponsored multiplier too high",
        )?;
        require(
            self.emergency_lane_fee_multiplier_bps <= MAX_BPS,
            "emergency multiplier too high",
        )?;
        require(
            self.low_fee_rebate_bps <= MAX_BPS,
            "low fee rebate too high",
        )?;
        require(
            self.settlement_rebate_bps <= MAX_BPS,
            "settlement rebate too high",
        )?;
        require(self.slash_reward_bps <= MAX_BPS, "slash reward too high")?;
        require(
            self.slashing_bond_micro_units > 0,
            "slashing bond must be positive",
        )?;
        require(
            self.nullifier_window_blocks > 0,
            "nullifier window must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub ticks: u64,
    pub epochs: u64,
    pub credentials: u64,
    pub latency_lanes: u64,
    pub bonds: u64,
    pub encrypted_bids: u64,
    pub intent_receipts: u64,
    pub contract_bundles: u64,
    pub token_bundles: u64,
    pub monero_bridge_bundles: u64,
    pub settlement_acknowledgements: u64,
    pub fee_rebates: u64,
    pub slashing_evidence: u64,
    pub nullifier_fences: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            ticks: 0,
            epochs: 0,
            credentials: 0,
            latency_lanes: 0,
            bonds: 0,
            encrypted_bids: 0,
            intent_receipts: 0,
            contract_bundles: 0,
            token_bundles: 0,
            monero_bridge_bundles: 0,
            settlement_acknowledgements: 0,
            fee_rebates: 0,
            slashing_evidence: 0,
            nullifier_fences: 0,
            public_events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub latency_lane_root: String,
    pub credential_root: String,
    pub slashing_bond_root: String,
    pub encrypted_bid_root: String,
    pub intent_receipt_root: String,
    pub contract_call_bundle_root: String,
    pub token_transfer_bundle_root: String,
    pub monero_bridge_bundle_root: String,
    pub settlement_acknowledgement_root: String,
    pub fee_rebate_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_fence_root: String,
    pub public_event_root: String,
}

impl Roots {
    pub fn from_state(state: &State) -> Self {
        Self {
            config_root: state.config.root(),
            counters_root: state.counters.root(),
            latency_lane_root: map_root(D_LANES, &state.latency_lanes),
            credential_root: map_root(D_CREDENTIALS, &state.credentials),
            slashing_bond_root: map_root(D_BONDS, &state.slashing_bonds),
            encrypted_bid_root: map_root(D_BIDS, &state.encrypted_bids),
            intent_receipt_root: map_root(D_INTENTS, &state.intent_receipts),
            contract_call_bundle_root: map_root(D_CONTRACT_BUNDLES, &state.contract_call_bundles),
            token_transfer_bundle_root: map_root(D_TOKEN_BUNDLES, &state.token_transfer_bundles),
            monero_bridge_bundle_root: map_root(D_BRIDGE_BUNDLES, &state.monero_bridge_bundles),
            settlement_acknowledgement_root: map_root(D_ACKS, &state.settlement_acknowledgements),
            fee_rebate_root: map_root(D_REBATES, &state.fee_rebates),
            slashing_evidence_root: map_root(D_SLASHING, &state.slashing_evidence),
            nullifier_fence_root: map_root(D_NULLIFIERS, &state.nullifier_fences),
            public_event_root: map_root(D_PUBLIC_EVENTS, &state.public_events),
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyFeeLane {
    pub lane_id: String,
    pub kind: LatencyFeeLaneKind,
    pub fee_asset_id: String,
    pub min_fee_micro_units: u64,
    pub target_preconfirmation_ms: u64,
    pub max_receipts_per_bundle: usize,
    pub max_pending_bids: usize,
    pub rebate_bps: u64,
    pub privacy_set_floor: u64,
    pub accepted_receipt_classes: BTreeSet<ReceiptClass>,
    pub active_bundle_ids: BTreeSet<String>,
    pub sequence: u64,
    pub paused: bool,
}

impl LatencyFeeLane {
    pub fn new(kind: LatencyFeeLaneKind, config: &Config) -> Self {
        let lane_id = prefixed(
            "lane",
            "LATENCY-LANE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::U64(config.preconfirmation_target_ms),
            ],
        );
        let mut accepted_receipt_classes = BTreeSet::new();
        accepted_receipt_classes.insert(ReceiptClass::Intent);
        accepted_receipt_classes.insert(ReceiptClass::ContractCall);
        accepted_receipt_classes.insert(ReceiptClass::TokenTransfer);
        accepted_receipt_classes.insert(ReceiptClass::MoneroBridge);
        accepted_receipt_classes.insert(ReceiptClass::DefiSettlement);
        Self {
            lane_id,
            kind,
            fee_asset_id: config.fee_asset_id.clone(),
            min_fee_micro_units: scaled_fee(
                config.base_fee_micro_units,
                kind.fee_multiplier_bps(config),
            ),
            target_preconfirmation_ms: kind.target_ms(config),
            max_receipts_per_bundle: config.max_batch_receipts,
            max_pending_bids: config.max_active_bids.saturating_div(6).max(1),
            rebate_bps: if kind == LatencyFeeLaneKind::LowFee {
                config.low_fee_rebate_bps
            } else {
                config.settlement_rebate_bps
            },
            privacy_set_floor: config.min_privacy_set_size,
            accepted_receipt_classes,
            active_bundle_ids: BTreeSet::new(),
            sequence: 0,
            paused: false,
        }
    }

    pub fn accepts(&self, class: ReceiptClass) -> bool {
        !self.paused && self.accepted_receipt_classes.contains(&class)
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("LATENCY-FEE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeCredential {
    pub credential_id: String,
    pub operator_id: String,
    pub role: CredentialRole,
    pub lane_ids: BTreeSet<String>,
    pub committee_weight: u64,
    pub pq_verifier_key_commitment: String,
    pub kem_decapsulation_commitment: String,
    pub credential_transcript_root: String,
    pub bond_id: String,
    pub issued_epoch: u64,
    pub expires_epoch: u64,
    pub status: CredentialStatus,
}

impl CommitteeCredential {
    pub fn validate_for_lane(&self, lane_id: &str, epoch: u64) -> Result<()> {
        require(self.status.can_preconfirm(), "credential cannot preconfirm")?;
        require(
            self.lane_ids.contains(lane_id),
            "credential not authorized for lane",
        )?;
        require(self.issued_epoch <= epoch, "credential not active yet")?;
        require(epoch <= self.expires_epoch, "credential expired")
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("COMMITTEE-CREDENTIAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingBond {
    pub bond_id: String,
    pub operator_id: String,
    pub credential_ids: BTreeSet<String>,
    pub asset_id: String,
    pub posted_micro_units: u64,
    pub locked_micro_units: u64,
    pub slashed_micro_units: u64,
    pub release_height: u64,
    pub status: BondStatus,
}

impl SlashingBond {
    pub fn available_micro_units(&self) -> u64 {
        self.posted_micro_units
            .saturating_sub(self.locked_micro_units)
            .saturating_sub(self.slashed_micro_units)
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("SLASHING-BOND", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptBid {
    pub bid_id: String,
    pub lane_id: String,
    pub receipt_class: ReceiptClass,
    pub side: BidSide,
    pub bidder_commitment: String,
    pub sealed_bid_ciphertext_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units_commitment: String,
    pub revealed_fee_micro_units: Option<u64>,
    pub gas_limit: u64,
    pub privacy_set_size: u64,
    pub nullifiers: BTreeSet<String>,
    pub payload_commitment: String,
    pub witness_commitment: String,
    pub credential_id: Option<String>,
    pub matched_bundle_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: BidStatus,
}

impl EncryptedReceiptBid {
    pub fn validate_basic(&self, lane: &LatencyFeeLane, height: u64) -> Result<()> {
        require(
            lane.accepts(self.receipt_class),
            "lane does not accept receipt class",
        )?;
        require(self.fee_asset_id == lane.fee_asset_id, "fee asset mismatch")?;
        require(
            self.privacy_set_size >= lane.privacy_set_floor,
            "privacy set below lane floor",
        )?;
        require(self.created_height <= height, "bid created in future")?;
        require(height <= self.expires_height, "bid expired")?;
        require(
            !self.payload_commitment.is_empty(),
            "payload commitment is required",
        )?;
        require(
            !self.sealed_bid_ciphertext_root.is_empty(),
            "sealed bid root is required",
        )
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("ENCRYPTED-RECEIPT-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntentReceipt {
    pub intent_receipt_id: String,
    pub bid_id: String,
    pub owner_commitment: String,
    pub solver_commitment: String,
    pub lane_id: String,
    pub receipt_class: ReceiptClass,
    pub intent_payload_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub nullifier_root: String,
    pub event_topic_root: String,
    pub max_fee_micro_units: u64,
    pub status: IntentReceiptStatus,
    pub created_height: u64,
    pub preconfirmed_height: Option<u64>,
    pub settlement_ack_id: Option<String>,
}

impl IntentReceipt {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("INTENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallReceiptBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub sequencer_credential_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub contract_ids: BTreeSet<String>,
    pub call_commitment_root: String,
    pub private_event_root: String,
    pub state_diff_root: String,
    pub fee_micro_units: u64,
    pub target_latency_ms: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: BundleStatus,
    pub attestation_root: String,
}

impl ContractCallReceiptBundle {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("CONTRACT-CALL-RECEIPT-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenTransferReceiptBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub sequencer_credential_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub token_ids: BTreeSet<String>,
    pub amount_commitment_root: String,
    pub transfer_note_root: String,
    pub balance_delta_root: String,
    pub fee_micro_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: BundleStatus,
    pub attestation_root: String,
}

impl TokenTransferReceiptBundle {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("TOKEN-TRANSFER-RECEIPT-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeReceiptBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub bridge_observer_credential_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub monero_tx_commitment_root: String,
    pub view_tag_root: String,
    pub ring_member_root: String,
    pub l2_mint_or_burn_commitment_root: String,
    pub bridge_fee_micro_units: u64,
    pub confirmations_observed: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: BundleStatus,
    pub attestation_root: String,
}

impl MoneroBridgeReceiptBundle {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("MONERO-BRIDGE-RECEIPT-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementAcknowledgement {
    pub acknowledgement_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub acknowledged_by_credential_ids: BTreeSet<String>,
    pub settlement_state_root: String,
    pub receipt_root: String,
    pub fee_root: String,
    pub finality_height: u64,
    pub acknowledged_height: u64,
    pub status: SettlementStatus,
}

impl SettlementAcknowledgement {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("SETTLEMENT-ACKNOWLEDGEMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub bid_id: String,
    pub lane_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub reason_code: String,
    pub created_height: u64,
    pub claim_after_height: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub bond_id: String,
    pub credential_id: String,
    pub offense: SlashingOffense,
    pub related_bid_ids: BTreeSet<String>,
    pub related_bundle_ids: BTreeSet<String>,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_micro_units: u64,
    pub reward_micro_units: u64,
    pub created_height: u64,
    pub adjudicated: bool,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub nullifier: String,
    pub first_bid_id: String,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub receipt_class: ReceiptClass,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("NULLIFIER-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub height: u64,
    pub lane_id: String,
    pub kind: String,
    pub subject_id: String,
    pub public_root: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json("PUBLIC-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub latency_lanes: BTreeMap<String, LatencyFeeLane>,
    pub credentials: BTreeMap<String, CommitteeCredential>,
    pub slashing_bonds: BTreeMap<String, SlashingBond>,
    pub encrypted_bids: BTreeMap<String, EncryptedReceiptBid>,
    pub intent_receipts: BTreeMap<String, IntentReceipt>,
    pub contract_call_bundles: BTreeMap<String, ContractCallReceiptBundle>,
    pub token_transfer_bundles: BTreeMap<String, TokenTransferReceiptBundle>,
    pub monero_bridge_bundles: BTreeMap<String, MoneroBridgeReceiptBundle>,
    pub settlement_acknowledgements: BTreeMap<String, SettlementAcknowledgement>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub public_events: BTreeMap<String, PublicEvent>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            epoch,
            counters: Counters::new(),
            latency_lanes: BTreeMap::new(),
            credentials: BTreeMap::new(),
            slashing_bonds: BTreeMap::new(),
            encrypted_bids: BTreeMap::new(),
            intent_receipts: BTreeMap::new(),
            contract_call_bundles: BTreeMap::new(),
            token_transfer_bundles: BTreeMap::new(),
            monero_bridge_bundles: BTreeMap::new(),
            settlement_acknowledgements: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            public_events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)?;
        for kind in [
            LatencyFeeLaneKind::Instant,
            LatencyFeeLaneKind::Fast,
            LatencyFeeLaneKind::Standard,
            LatencyFeeLaneKind::LowFee,
            LatencyFeeLaneKind::Sponsored,
            LatencyFeeLaneKind::Emergency,
        ] {
            state.register_latency_lane(LatencyFeeLane::new(kind, &state.config))?;
        }
        let lane_ids = state.latency_lanes.keys().cloned().collect::<BTreeSet<_>>();
        for idx in 0..4_u64 {
            let operator_id = format!("devnet-preconf-operator-{idx}");
            let bond_id = state.post_slashing_bond(
                operator_id.clone(),
                state.config.slashing_bond_micro_units.saturating_mul(2),
                DEVNET_HEIGHT + 256,
            )?;
            let credential_id = deterministic_id(
                "DEVNET-CREDENTIAL",
                &[
                    HashPart::Str(&operator_id),
                    HashPart::U64(idx),
                    HashPart::U64(DEVNET_EPOCH),
                ],
            );
            let credential = CommitteeCredential {
                credential_id: credential_id.clone(),
                operator_id: operator_id.clone(),
                role: if idx == 3 {
                    CredentialRole::BridgeObserver
                } else {
                    CredentialRole::Sequencer
                },
                lane_ids: lane_ids.clone(),
                committee_weight: 1,
                pq_verifier_key_commitment: deterministic_id(
                    "DEVNET-PQ-VERIFYING-KEY",
                    &[HashPart::Str(&operator_id)],
                ),
                kem_decapsulation_commitment: deterministic_id(
                    "DEVNET-KEM-COMMITMENT",
                    &[HashPart::Str(&operator_id)],
                ),
                credential_transcript_root: deterministic_id(
                    "DEVNET-CREDENTIAL-TRANSCRIPT",
                    &[HashPart::Str(&operator_id), HashPart::Str(&bond_id)],
                ),
                bond_id,
                issued_epoch: DEVNET_EPOCH,
                expires_epoch: DEVNET_EPOCH + 32,
                status: CredentialStatus::Active,
            };
            state.register_credential(credential)?;
        }
        let fast_lane_id = state.lane_id_by_kind(LatencyFeeLaneKind::Fast)?;
        let instant_lane_id = state.lane_id_by_kind(LatencyFeeLaneKind::Instant)?;
        let bridge_lane_id = state.lane_id_by_kind(LatencyFeeLaneKind::Standard)?;
        let bid_a = state.submit_encrypted_bid(EncryptedBidRequest {
            lane_id: fast_lane_id.clone(),
            receipt_class: ReceiptClass::ContractCall,
            side: BidSide::User,
            bidder_commitment: "devnet-user-commitment-a".to_string(),
            sealed_bid_ciphertext_root: deterministic_id(
                "DEVNET-BID-CIPHERTEXT",
                &[HashPart::Str("a")],
            ),
            max_fee_micro_units: Some(18),
            gas_limit: 2_500_000,
            privacy_set_size: 131_072,
            nullifiers: set(["nf-devnet-contract-a"]),
            payload_commitment: deterministic_id("DEVNET-PAYLOAD", &[HashPart::Str("contract-a")]),
            witness_commitment: deterministic_id("DEVNET-WITNESS", &[HashPart::Str("contract-a")]),
            credential_id: None,
        })?;
        let bid_b = state.submit_encrypted_bid(EncryptedBidRequest {
            lane_id: instant_lane_id.clone(),
            receipt_class: ReceiptClass::TokenTransfer,
            side: BidSide::User,
            bidder_commitment: "devnet-user-commitment-b".to_string(),
            sealed_bid_ciphertext_root: deterministic_id(
                "DEVNET-BID-CIPHERTEXT",
                &[HashPart::Str("b")],
            ),
            max_fee_micro_units: Some(12),
            gas_limit: 180_000,
            privacy_set_size: 131_072,
            nullifiers: set(["nf-devnet-token-b"]),
            payload_commitment: deterministic_id("DEVNET-PAYLOAD", &[HashPart::Str("token-b")]),
            witness_commitment: deterministic_id("DEVNET-WITNESS", &[HashPart::Str("token-b")]),
            credential_id: None,
        })?;
        let bid_c = state.submit_encrypted_bid(EncryptedBidRequest {
            lane_id: bridge_lane_id.clone(),
            receipt_class: ReceiptClass::MoneroBridge,
            side: BidSide::User,
            bidder_commitment: "devnet-user-commitment-c".to_string(),
            sealed_bid_ciphertext_root: deterministic_id(
                "DEVNET-BID-CIPHERTEXT",
                &[HashPart::Str("c")],
            ),
            max_fee_micro_units: Some(22),
            gas_limit: 800_000,
            privacy_set_size: 262_144,
            nullifiers: set(["nf-devnet-bridge-c"]),
            payload_commitment: deterministic_id("DEVNET-PAYLOAD", &[HashPart::Str("bridge-c")]),
            witness_commitment: deterministic_id("DEVNET-WITNESS", &[HashPart::Str("bridge-c")]),
            credential_id: None,
        })?;
        let sequencer_credential = state
            .credentials
            .values()
            .find(|credential| credential.role == CredentialRole::Sequencer)
            .map(|credential| credential.credential_id.clone())
            .ok_or_else(|| "devnet sequencer credential missing".to_string())?;
        let bridge_credential = state
            .credentials
            .values()
            .find(|credential| credential.role == CredentialRole::BridgeObserver)
            .map(|credential| credential.credential_id.clone())
            .ok_or_else(|| "devnet bridge credential missing".to_string())?;
        let contract_receipt = state.create_intent_receipt(IntentReceiptRequest {
            bid_id: bid_a,
            owner_commitment: "devnet-owner-a".to_string(),
            solver_commitment: "devnet-solver-a".to_string(),
            pre_state_root: deterministic_id("DEVNET-PRE-STATE", &[HashPart::Str("a")]),
            post_state_root: deterministic_id("DEVNET-POST-STATE", &[HashPart::Str("a")]),
            event_topics: set(["swap", "vault"]),
            max_fee_micro_units: 18,
        })?;
        let token_receipt = state.create_intent_receipt(IntentReceiptRequest {
            bid_id: bid_b,
            owner_commitment: "devnet-owner-b".to_string(),
            solver_commitment: "devnet-solver-b".to_string(),
            pre_state_root: deterministic_id("DEVNET-PRE-STATE", &[HashPart::Str("b")]),
            post_state_root: deterministic_id("DEVNET-POST-STATE", &[HashPart::Str("b")]),
            event_topics: set(["transfer"]),
            max_fee_micro_units: 12,
        })?;
        let bridge_receipt = state.create_intent_receipt(IntentReceiptRequest {
            bid_id: bid_c,
            owner_commitment: "devnet-owner-c".to_string(),
            solver_commitment: "devnet-solver-c".to_string(),
            pre_state_root: deterministic_id("DEVNET-PRE-STATE", &[HashPart::Str("c")]),
            post_state_root: deterministic_id("DEVNET-POST-STATE", &[HashPart::Str("c")]),
            event_topics: set(["monero_bridge"]),
            max_fee_micro_units: 22,
        })?;
        let contract_bundle = state.seal_contract_call_bundle(BundleRequest {
            lane_id: fast_lane_id,
            credential_id: sequencer_credential.clone(),
            receipt_ids: set([contract_receipt.as_str()]),
            subject_ids: set(["devnet-private-vault"]),
            fee_micro_units: 18,
        })?;
        let token_bundle = state.seal_token_transfer_bundle(BundleRequest {
            lane_id: instant_lane_id,
            credential_id: sequencer_credential,
            receipt_ids: set([token_receipt.as_str()]),
            subject_ids: set(["xmr-note-token"]),
            fee_micro_units: 12,
        })?;
        let bridge_bundle = state.seal_monero_bridge_bundle(MoneroBridgeBundleRequest {
            lane_id: bridge_lane_id,
            credential_id: bridge_credential,
            receipt_ids: set([bridge_receipt.as_str()]),
            confirmations_observed: 10,
            bridge_fee_micro_units: 22,
        })?;
        state.acknowledge_settlement(contract_bundle, SettlementStatus::Accepted)?;
        state.acknowledge_settlement(token_bundle, SettlementStatus::Accepted)?;
        state.acknowledge_settlement(bridge_bundle, SettlementStatus::Accepted)?;
        Ok(state)
    }

    pub fn register_latency_lane(&mut self, lane: LatencyFeeLane) -> Result<()> {
        require(
            !self.latency_lanes.contains_key(&lane.lane_id),
            "lane already exists",
        )?;
        require(!lane.fee_asset_id.is_empty(), "lane fee asset is required")?;
        require(
            lane.max_receipts_per_bundle > 0,
            "lane bundle limit must be positive",
        )?;
        require(lane.rebate_bps <= MAX_BPS, "lane rebate too high")?;
        self.counters.latency_lanes = self.counters.latency_lanes.saturating_add(1);
        self.emit_public_event(
            &lane.lane_id,
            "latency_lane_registered",
            &lane.lane_id,
            lane.root(),
        );
        self.latency_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn post_slashing_bond(
        &mut self,
        operator_id: String,
        posted_micro_units: u64,
        release_height: u64,
    ) -> Result<String> {
        require(!operator_id.is_empty(), "operator id is required")?;
        require(
            posted_micro_units >= self.config.slashing_bond_micro_units,
            "posted bond below minimum",
        )?;
        require(
            release_height > self.height,
            "release height must be in future",
        )?;
        let bond_id = prefixed(
            "bond",
            "SLASHING-BOND-ID",
            &[
                HashPart::Str(&operator_id),
                HashPart::U64(posted_micro_units),
                HashPart::U64(release_height),
                HashPart::U64(self.counters.bonds),
            ],
        );
        let bond = SlashingBond {
            bond_id: bond_id.clone(),
            operator_id,
            credential_ids: BTreeSet::new(),
            asset_id: self.config.fee_asset_id.clone(),
            posted_micro_units,
            locked_micro_units: 0,
            slashed_micro_units: 0,
            release_height,
            status: BondStatus::Posted,
        };
        self.counters.bonds = self.counters.bonds.saturating_add(1);
        self.emit_public_event("bond", "slashing_bond_posted", &bond_id, bond.root());
        self.slashing_bonds.insert(bond_id.clone(), bond);
        Ok(bond_id)
    }

    pub fn register_credential(&mut self, credential: CommitteeCredential) -> Result<()> {
        require(
            !self.credentials.contains_key(&credential.credential_id),
            "credential exists",
        )?;
        require(
            !credential.operator_id.is_empty(),
            "operator id is required",
        )?;
        require(
            credential.committee_weight > 0,
            "committee weight must be positive",
        )?;
        require(
            credential.expires_epoch >= credential.issued_epoch,
            "credential epoch range invalid",
        )?;
        require(
            credential
                .lane_ids
                .iter()
                .all(|lane_id| self.latency_lanes.contains_key(lane_id)),
            "credential references unknown lane",
        )?;
        let bond = self
            .slashing_bonds
            .get_mut(&credential.bond_id)
            .ok_or_else(|| "credential bond missing".to_string())?;
        require(
            bond.operator_id == credential.operator_id,
            "credential bond owner mismatch",
        )?;
        require(
            bond.posted_micro_units >= self.config.slashing_bond_micro_units,
            "credential bond below minimum",
        )?;
        bond.credential_ids.insert(credential.credential_id.clone());
        bond.locked_micro_units = bond.locked_micro_units.saturating_add(
            self.config
                .slashing_bond_micro_units
                .min(bond.available_micro_units()),
        );
        bond.status = BondStatus::Locked;
        self.counters.credentials = self.counters.credentials.saturating_add(1);
        self.emit_public_event(
            "credential",
            "committee_credential_registered",
            &credential.credential_id,
            credential.root(),
        );
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    pub fn submit_encrypted_bid(&mut self, request: EncryptedBidRequest) -> Result<String> {
        require(
            self.encrypted_bids.len() < self.config.max_active_bids,
            "active bid limit reached",
        )?;
        let lane = self
            .latency_lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        require(
            lane.accepts(request.receipt_class),
            "lane rejects receipt class",
        )?;
        require(
            request.privacy_set_size >= lane.privacy_set_floor,
            "privacy set too small",
        )?;
        if let Some(credential_id) = &request.credential_id {
            let credential = self
                .credentials
                .get(credential_id)
                .ok_or_else(|| "bid credential missing".to_string())?;
            credential.validate_for_lane(&request.lane_id, self.epoch)?;
        }
        for nullifier in &request.nullifiers {
            if let Some(fence) = self.nullifier_fences.get(nullifier) {
                require(
                    self.height > fence.expires_height,
                    "nullifier fence is active",
                )?;
            }
        }
        let fee_commitment = match request.max_fee_micro_units {
            Some(fee) => deterministic_id(
                "REVEALED-FEE-COMMITMENT",
                &[
                    HashPart::Str(&request.bidder_commitment),
                    HashPart::U64(fee),
                ],
            ),
            None => deterministic_id(
                "SEALED-FEE-COMMITMENT",
                &[HashPart::Str(&request.sealed_bid_ciphertext_root)],
            ),
        };
        let bid_id = prefixed(
            "bid",
            "ENCRYPTED-RECEIPT-BID-ID",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(request.receipt_class.as_str()),
                HashPart::Str(&request.bidder_commitment),
                HashPart::Str(&request.payload_commitment),
                HashPart::U64(self.counters.encrypted_bids),
            ],
        );
        let bid = EncryptedReceiptBid {
            bid_id: bid_id.clone(),
            lane_id: request.lane_id,
            receipt_class: request.receipt_class,
            side: request.side,
            bidder_commitment: request.bidder_commitment,
            sealed_bid_ciphertext_root: request.sealed_bid_ciphertext_root,
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_fee_micro_units_commitment: fee_commitment,
            revealed_fee_micro_units: request.max_fee_micro_units,
            gas_limit: request.gas_limit,
            privacy_set_size: request.privacy_set_size,
            nullifiers: request.nullifiers,
            payload_commitment: request.payload_commitment,
            witness_commitment: request.witness_commitment,
            credential_id: request.credential_id,
            matched_bundle_id: None,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.bid_ttl_blocks),
            status: BidStatus::Encrypted,
        };
        bid.validate_basic(lane, self.height)?;
        self.install_nullifier_fences(&bid)?;
        self.counters.encrypted_bids = self.counters.encrypted_bids.saturating_add(1);
        self.emit_public_event(&bid.lane_id, "encrypted_bid_submitted", &bid_id, bid.root());
        self.encrypted_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn create_intent_receipt(&mut self, request: IntentReceiptRequest) -> Result<String> {
        let bid = self
            .encrypted_bids
            .get_mut(&request.bid_id)
            .ok_or_else(|| "bid missing".to_string())?;
        require(bid.status.marketable(), "bid is not marketable")?;
        require(self.height <= bid.expires_height, "bid expired")?;
        let lane_id = bid.lane_id.clone();
        let receipt_class = bid.receipt_class;
        let event_topic_values = request
            .event_topics
            .iter()
            .map(|topic| json!(topic))
            .collect::<Vec<_>>();
        let event_topic_root = merkle_root_for("INTENT-RECEIPT-EVENT-TOPICS", &event_topic_values);
        let nullifier_values = bid.nullifiers.iter().map(|n| json!(n)).collect::<Vec<_>>();
        let nullifier_root = merkle_root_for("INTENT-RECEIPT-NULLIFIERS", &nullifier_values);
        let intent_receipt_id = prefixed(
            "intent",
            "INTENT-RECEIPT-ID",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.solver_commitment),
                HashPart::U64(self.counters.intent_receipts),
            ],
        );
        bid.status = BidStatus::Matched;
        let receipt = IntentReceipt {
            intent_receipt_id: intent_receipt_id.clone(),
            bid_id: request.bid_id,
            owner_commitment: request.owner_commitment,
            solver_commitment: request.solver_commitment,
            lane_id: lane_id.clone(),
            receipt_class,
            intent_payload_commitment: bid.payload_commitment.clone(),
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            nullifier_root,
            event_topic_root,
            max_fee_micro_units: request.max_fee_micro_units,
            status: IntentReceiptStatus::BidMatched,
            created_height: self.height,
            preconfirmed_height: None,
            settlement_ack_id: None,
        };
        self.counters.intent_receipts = self.counters.intent_receipts.saturating_add(1);
        self.emit_public_event(
            &lane_id,
            "intent_receipt_created",
            &intent_receipt_id,
            receipt.root(),
        );
        self.intent_receipts
            .insert(intent_receipt_id.clone(), receipt);
        Ok(intent_receipt_id)
    }

    pub fn seal_contract_call_bundle(&mut self, request: BundleRequest) -> Result<String> {
        require(
            self.config.allow_contract_call_bundles,
            "contract bundles disabled",
        )?;
        self.validate_bundle_request(&request, ReceiptClass::ContractCall)?;
        let lane = self
            .latency_lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        let bundle_id = prefixed(
            "ccb",
            "CONTRACT-CALL-BUNDLE-ID",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(&request.credential_id),
                HashPart::U64(self.counters.contract_bundles),
            ],
        );
        let receipt_values = values_for_ids(&request.receipt_ids);
        let bundle = ContractCallReceiptBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            sequencer_credential_id: request.credential_id,
            receipt_ids: request.receipt_ids,
            contract_ids: request.subject_ids,
            call_commitment_root: merkle_root_for("CONTRACT-CALL-COMMITMENTS", &receipt_values),
            private_event_root: merkle_root_for("CONTRACT-CALL-PRIVATE-EVENTS", &receipt_values),
            state_diff_root: merkle_root_for("CONTRACT-CALL-STATE-DIFFS", &receipt_values),
            fee_micro_units: request.fee_micro_units,
            target_latency_ms: lane.target_preconfirmation_ms,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
            status: BundleStatus::Preconfirmed,
            attestation_root: deterministic_id(
                "CONTRACT-CALL-BUNDLE-ATTESTATION",
                &[HashPart::Str(&bundle_id)],
            ),
        };
        self.mark_receipts_preconfirmed(&bundle.receipt_ids, &bundle_id)?;
        self.counters.contract_bundles = self.counters.contract_bundles.saturating_add(1);
        self.link_bundle_to_lane(&request.lane_id, &bundle_id)?;
        self.emit_public_event(
            &request.lane_id,
            "contract_call_bundle_sealed",
            &bundle_id,
            bundle.root(),
        );
        self.contract_call_bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn seal_token_transfer_bundle(&mut self, request: BundleRequest) -> Result<String> {
        require(
            self.config.allow_token_transfer_bundles,
            "token bundles disabled",
        )?;
        self.validate_bundle_request(&request, ReceiptClass::TokenTransfer)?;
        let bundle_id = prefixed(
            "ttb",
            "TOKEN-TRANSFER-BUNDLE-ID",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(&request.credential_id),
                HashPart::U64(self.counters.token_bundles),
            ],
        );
        let receipt_values = values_for_ids(&request.receipt_ids);
        let bundle = TokenTransferReceiptBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            sequencer_credential_id: request.credential_id,
            receipt_ids: request.receipt_ids,
            token_ids: request.subject_ids,
            amount_commitment_root: merkle_root_for("TOKEN-AMOUNT-COMMITMENTS", &receipt_values),
            transfer_note_root: merkle_root_for("TOKEN-TRANSFER-NOTES", &receipt_values),
            balance_delta_root: merkle_root_for("TOKEN-BALANCE-DELTAS", &receipt_values),
            fee_micro_units: request.fee_micro_units,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
            status: BundleStatus::Preconfirmed,
            attestation_root: deterministic_id(
                "TOKEN-TRANSFER-BUNDLE-ATTESTATION",
                &[HashPart::Str(&bundle_id)],
            ),
        };
        self.mark_receipts_preconfirmed(&bundle.receipt_ids, &bundle_id)?;
        self.counters.token_bundles = self.counters.token_bundles.saturating_add(1);
        self.link_bundle_to_lane(&request.lane_id, &bundle_id)?;
        self.emit_public_event(
            &request.lane_id,
            "token_transfer_bundle_sealed",
            &bundle_id,
            bundle.root(),
        );
        self.token_transfer_bundles
            .insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn seal_monero_bridge_bundle(
        &mut self,
        request: MoneroBridgeBundleRequest,
    ) -> Result<String> {
        require(
            self.config.allow_monero_bridge_bundles,
            "monero bridge bundles disabled",
        )?;
        let generic = BundleRequest {
            lane_id: request.lane_id.clone(),
            credential_id: request.credential_id.clone(),
            receipt_ids: request.receipt_ids.clone(),
            subject_ids: BTreeSet::new(),
            fee_micro_units: request.bridge_fee_micro_units,
        };
        self.validate_bundle_request(&generic, ReceiptClass::MoneroBridge)?;
        let credential = self
            .credentials
            .get(&request.credential_id)
            .ok_or_else(|| "bridge credential missing".to_string())?;
        require(
            matches!(
                credential.role,
                CredentialRole::BridgeObserver | CredentialRole::Sequencer
            ),
            "credential cannot seal bridge bundle",
        )?;
        let bundle_id = prefixed(
            "mbb",
            "MONERO-BRIDGE-BUNDLE-ID",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(&request.credential_id),
                HashPart::U64(request.confirmations_observed),
                HashPart::U64(self.counters.monero_bridge_bundles),
            ],
        );
        let receipt_values = values_for_ids(&request.receipt_ids);
        let bundle = MoneroBridgeReceiptBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            bridge_observer_credential_id: request.credential_id,
            receipt_ids: request.receipt_ids,
            monero_tx_commitment_root: merkle_root_for("MONERO-TX-COMMITMENTS", &receipt_values),
            view_tag_root: merkle_root_for("MONERO-VIEW-TAGS", &receipt_values),
            ring_member_root: merkle_root_for("MONERO-RING-MEMBERS", &receipt_values),
            l2_mint_or_burn_commitment_root: merkle_root_for(
                "L2-MINT-BURN-COMMITMENTS",
                &receipt_values,
            ),
            bridge_fee_micro_units: request.bridge_fee_micro_units,
            confirmations_observed: request.confirmations_observed,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
            status: BundleStatus::Preconfirmed,
            attestation_root: deterministic_id(
                "MONERO-BRIDGE-BUNDLE-ATTESTATION",
                &[HashPart::Str(&bundle_id)],
            ),
        };
        self.mark_receipts_preconfirmed(&bundle.receipt_ids, &bundle_id)?;
        self.counters.monero_bridge_bundles = self.counters.monero_bridge_bundles.saturating_add(1);
        self.link_bundle_to_lane(&request.lane_id, &bundle_id)?;
        self.emit_public_event(
            &request.lane_id,
            "monero_bridge_bundle_sealed",
            &bundle_id,
            bundle.root(),
        );
        self.monero_bridge_bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn acknowledge_settlement(
        &mut self,
        bundle_id: String,
        status: SettlementStatus,
    ) -> Result<String> {
        let lane_id = self.bundle_lane_id(&bundle_id)?;
        let receipt_ids = self.bundle_receipt_ids(&bundle_id)?;
        let credential_ids = self.bundle_credential_ids(&bundle_id)?;
        let receipt_values = values_for_ids(&receipt_ids);
        let acknowledgement_id = prefixed(
            "ack",
            "SETTLEMENT-ACKNOWLEDGEMENT-ID",
            &[
                HashPart::Str(&bundle_id),
                HashPart::Str(status.as_str()),
                HashPart::U64(self.counters.settlement_acknowledgements),
            ],
        );
        let ack = SettlementAcknowledgement {
            acknowledgement_id: acknowledgement_id.clone(),
            bundle_id: bundle_id.clone(),
            lane_id: lane_id.clone(),
            acknowledged_by_credential_ids: credential_ids,
            settlement_state_root: deterministic_id(
                "SETTLEMENT-STATE",
                &[HashPart::Str(&bundle_id), HashPart::U64(self.height)],
            ),
            receipt_root: merkle_root_for("SETTLEMENT-RECEIPTS", &receipt_values),
            fee_root: deterministic_id("SETTLEMENT-FEES", &[HashPart::Str(&bundle_id)]),
            finality_height: self
                .height
                .saturating_add(self.config.settlement_finality_delay_blocks),
            acknowledged_height: self.height,
            status,
        };
        self.mark_bundle_acknowledged(&bundle_id)?;
        for receipt_id in &receipt_ids {
            if let Some(receipt) = self.intent_receipts.get_mut(receipt_id) {
                receipt.status = IntentReceiptStatus::Fulfilled;
                receipt.settlement_ack_id = Some(acknowledgement_id.clone());
            }
        }
        self.create_rebates_for_receipts(&receipt_ids, &lane_id)?;
        self.counters.settlement_acknowledgements =
            self.counters.settlement_acknowledgements.saturating_add(1);
        self.emit_public_event(
            &lane_id,
            "settlement_acknowledged",
            &acknowledgement_id,
            ack.root(),
        );
        self.settlement_acknowledgements
            .insert(acknowledgement_id.clone(), ack);
        Ok(acknowledgement_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        credential_id: String,
        offense: SlashingOffense,
        related_bid_ids: BTreeSet<String>,
        related_bundle_ids: BTreeSet<String>,
        evidence_root: String,
        reporter_commitment: String,
    ) -> Result<String> {
        require(!evidence_root.is_empty(), "evidence root is required")?;
        let credential = self
            .credentials
            .get_mut(&credential_id)
            .ok_or_else(|| "credential missing".to_string())?;
        let bond_id = credential.bond_id.clone();
        credential.status = CredentialStatus::Slashed;
        let bond = self
            .slashing_bonds
            .get_mut(&bond_id)
            .ok_or_else(|| "slashing bond missing".to_string())?;
        let slash_micro_units = self.config.slashing_bond_micro_units.min(
            bond.posted_micro_units
                .saturating_sub(bond.slashed_micro_units),
        );
        let reward_micro_units = scaled_fee(slash_micro_units, self.config.slash_reward_bps);
        bond.slashed_micro_units = bond.slashed_micro_units.saturating_add(slash_micro_units);
        bond.status = BondStatus::Slashed;
        let evidence_id = prefixed(
            "slash",
            "SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(&credential_id),
                HashPart::Str(offense.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::U64(self.counters.slashing_evidence),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            bond_id,
            credential_id,
            offense,
            related_bid_ids,
            related_bundle_ids,
            evidence_root,
            reporter_commitment,
            slash_micro_units,
            reward_micro_units,
            created_height: self.height,
            adjudicated: true,
        };
        self.counters.slashing_evidence = self.counters.slashing_evidence.saturating_add(1);
        self.emit_public_event(
            "slashing",
            "slashing_evidence_accepted",
            &evidence_id,
            evidence.root(),
        );
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn tick(&mut self, next_height: u64) -> Result<()> {
        require(next_height >= self.height, "height cannot move backwards")?;
        if next_height == self.height {
            self.counters.ticks = self.counters.ticks.saturating_add(1);
            return Ok(());
        }
        self.height = next_height;
        self.counters.ticks = self.counters.ticks.saturating_add(1);
        self.expire_bids();
        self.expire_nullifier_fences();
        self.expire_bundles();
        Ok(())
    }

    pub fn advance_epoch(&mut self, next_epoch: u64) -> Result<()> {
        require(next_epoch >= self.epoch, "epoch cannot move backwards")?;
        if next_epoch > self.epoch {
            self.epoch = next_epoch;
            self.counters.epochs = self.counters.epochs.saturating_add(1);
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots::from_state(self)
    }

    pub fn state_root(&self) -> String {
        self.roots().root()
    }

    pub fn public_state(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_receipt_preconfirmation_market_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root()
        })
    }

    pub fn public_record(&self) -> Value {
        self.public_state()
    }

    pub fn lane_id_by_kind(&self, kind: LatencyFeeLaneKind) -> Result<String> {
        self.latency_lanes
            .values()
            .find(|lane| lane.kind == kind)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "lane kind missing".to_string())
    }

    fn validate_bundle_request(
        &self,
        request: &BundleRequest,
        receipt_class: ReceiptClass,
    ) -> Result<()> {
        require(
            self.contract_call_bundles.len()
                + self.token_transfer_bundles.len()
                + self.monero_bridge_bundles.len()
                < self.config.max_active_bundles,
            "active bundle limit reached",
        )?;
        require(!request.receipt_ids.is_empty(), "bundle requires receipts")?;
        require(
            request.receipt_ids.len() <= self.config.max_batch_receipts,
            "bundle receipt limit exceeded",
        )?;
        let credential = self
            .credentials
            .get(&request.credential_id)
            .ok_or_else(|| "bundle credential missing".to_string())?;
        credential.validate_for_lane(&request.lane_id, self.epoch)?;
        let lane = self
            .latency_lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        require(
            lane.accepts(receipt_class),
            "lane rejects bundle receipt class",
        )?;
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .intent_receipts
                .get(receipt_id)
                .ok_or_else(|| "bundle receipt missing".to_string())?;
            require(
                receipt.lane_id == request.lane_id,
                "bundle receipt lane mismatch",
            )?;
            require(
                receipt.receipt_class == receipt_class,
                "bundle receipt class mismatch",
            )?;
            require(
                matches!(
                    receipt.status,
                    IntentReceiptStatus::BidMatched | IntentReceiptStatus::Registered
                ),
                "receipt is not bundleable",
            )?;
            require(
                self.height
                    <= receipt
                        .created_height
                        .saturating_add(self.config.receipt_ttl_blocks),
                "receipt expired",
            )?;
        }
        Ok(())
    }

    fn mark_receipts_preconfirmed(
        &mut self,
        receipt_ids: &BTreeSet<String>,
        bundle_id: &str,
    ) -> Result<()> {
        for receipt_id in receipt_ids {
            let receipt = self
                .intent_receipts
                .get_mut(receipt_id)
                .ok_or_else(|| "receipt missing".to_string())?;
            receipt.status = IntentReceiptStatus::Preconfirmed;
            receipt.preconfirmed_height = Some(self.height);
            if let Some(bid) = self.encrypted_bids.get_mut(&receipt.bid_id) {
                bid.status = BidStatus::Bundled;
                bid.matched_bundle_id = Some(bundle_id.to_string());
            }
        }
        Ok(())
    }

    fn mark_bundle_acknowledged(&mut self, bundle_id: &str) -> Result<()> {
        if let Some(bundle) = self.contract_call_bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::Acknowledged;
            return Ok(());
        }
        if let Some(bundle) = self.token_transfer_bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::Acknowledged;
            return Ok(());
        }
        if let Some(bundle) = self.monero_bridge_bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::Acknowledged;
            return Ok(());
        }
        Err("bundle missing".to_string())
    }

    fn bundle_lane_id(&self, bundle_id: &str) -> Result<String> {
        if let Some(bundle) = self.contract_call_bundles.get(bundle_id) {
            return Ok(bundle.lane_id.clone());
        }
        if let Some(bundle) = self.token_transfer_bundles.get(bundle_id) {
            return Ok(bundle.lane_id.clone());
        }
        if let Some(bundle) = self.monero_bridge_bundles.get(bundle_id) {
            return Ok(bundle.lane_id.clone());
        }
        Err("bundle missing".to_string())
    }

    fn bundle_receipt_ids(&self, bundle_id: &str) -> Result<BTreeSet<String>> {
        if let Some(bundle) = self.contract_call_bundles.get(bundle_id) {
            return Ok(bundle.receipt_ids.clone());
        }
        if let Some(bundle) = self.token_transfer_bundles.get(bundle_id) {
            return Ok(bundle.receipt_ids.clone());
        }
        if let Some(bundle) = self.monero_bridge_bundles.get(bundle_id) {
            return Ok(bundle.receipt_ids.clone());
        }
        Err("bundle missing".to_string())
    }

    fn bundle_credential_ids(&self, bundle_id: &str) -> Result<BTreeSet<String>> {
        let mut ids = BTreeSet::new();
        if let Some(bundle) = self.contract_call_bundles.get(bundle_id) {
            ids.insert(bundle.sequencer_credential_id.clone());
            return Ok(ids);
        }
        if let Some(bundle) = self.token_transfer_bundles.get(bundle_id) {
            ids.insert(bundle.sequencer_credential_id.clone());
            return Ok(ids);
        }
        if let Some(bundle) = self.monero_bridge_bundles.get(bundle_id) {
            ids.insert(bundle.bridge_observer_credential_id.clone());
            return Ok(ids);
        }
        Err("bundle missing".to_string())
    }

    fn create_rebates_for_receipts(
        &mut self,
        receipt_ids: &BTreeSet<String>,
        lane_id: &str,
    ) -> Result<()> {
        let lane = self
            .latency_lanes
            .get(lane_id)
            .ok_or_else(|| "rebate lane missing".to_string())?;
        let rebate_bps = lane.rebate_bps;
        for receipt_id in receipt_ids {
            let receipt = self
                .intent_receipts
                .get(receipt_id)
                .ok_or_else(|| "rebate receipt missing".to_string())?;
            let bid = self
                .encrypted_bids
                .get_mut(&receipt.bid_id)
                .ok_or_else(|| "rebate bid missing".to_string())?;
            let gross_fee = bid
                .revealed_fee_micro_units
                .unwrap_or(receipt.max_fee_micro_units);
            let rebate_micro_units = scaled_fee(gross_fee, rebate_bps);
            let rebate_id = prefixed(
                "rebate",
                "FEE-REBATE-ID",
                &[
                    HashPart::Str(&bid.bid_id),
                    HashPart::Str(lane_id),
                    HashPart::U64(self.counters.fee_rebates),
                ],
            );
            bid.status = BidStatus::Acknowledged;
            let rebate = FeeRebate {
                rebate_id: rebate_id.clone(),
                bid_id: bid.bid_id.clone(),
                lane_id: lane_id.to_string(),
                beneficiary_commitment: bid.bidder_commitment.clone(),
                asset_id: self.config.fee_asset_id.clone(),
                gross_fee_micro_units: gross_fee,
                rebate_bps,
                rebate_micro_units,
                reason_code: "settlement_acknowledged".to_string(),
                created_height: self.height,
                claim_after_height: self
                    .height
                    .saturating_add(self.config.settlement_finality_delay_blocks),
                status: RebateStatus::Claimable,
            };
            self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
            self.fee_rebates.insert(rebate_id, rebate);
        }
        Ok(())
    }

    fn install_nullifier_fences(&mut self, bid: &EncryptedReceiptBid) -> Result<()> {
        for nullifier in &bid.nullifiers {
            let fence = NullifierFence {
                fence_id: prefixed(
                    "nf",
                    "NULLIFIER-FENCE-ID",
                    &[HashPart::Str(nullifier), HashPart::Str(&bid.bid_id)],
                ),
                nullifier: nullifier.clone(),
                first_bid_id: bid.bid_id.clone(),
                first_seen_height: self.height,
                expires_height: self
                    .height
                    .saturating_add(self.config.nullifier_window_blocks),
                receipt_class: bid.receipt_class,
            };
            self.counters.nullifier_fences = self.counters.nullifier_fences.saturating_add(1);
            self.nullifier_fences.insert(nullifier.clone(), fence);
        }
        Ok(())
    }

    fn link_bundle_to_lane(&mut self, lane_id: &str, bundle_id: &str) -> Result<()> {
        let lane = self
            .latency_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        lane.active_bundle_ids.insert(bundle_id.to_string());
        lane.sequence = lane.sequence.saturating_add(1);
        Ok(())
    }

    fn expire_bids(&mut self) {
        for bid in self.encrypted_bids.values_mut() {
            if bid.status.marketable() && self.height > bid.expires_height {
                bid.status = BidStatus::Expired;
            }
        }
    }

    fn expire_bundles(&mut self) {
        for bundle in self.contract_call_bundles.values_mut() {
            if bundle.status.accepts_receipts() && self.height > bundle.expires_height {
                bundle.status = BundleStatus::Expired;
            }
        }
        for bundle in self.token_transfer_bundles.values_mut() {
            if bundle.status.accepts_receipts() && self.height > bundle.expires_height {
                bundle.status = BundleStatus::Expired;
            }
        }
        for bundle in self.monero_bridge_bundles.values_mut() {
            if bundle.status.accepts_receipts() && self.height > bundle.expires_height {
                bundle.status = BundleStatus::Expired;
            }
        }
    }

    fn expire_nullifier_fences(&mut self) {
        let expired = self
            .nullifier_fences
            .iter()
            .filter(|(_, fence)| self.height > fence.expires_height)
            .map(|(nullifier, _)| nullifier.clone())
            .collect::<Vec<_>>();
        for nullifier in expired {
            self.nullifier_fences.remove(&nullifier);
        }
    }

    fn emit_public_event(
        &mut self,
        lane_id: &str,
        kind: &str,
        subject_id: &str,
        public_root: String,
    ) {
        let event_id = prefixed(
            "event",
            "PUBLIC-EVENT-ID",
            &[
                HashPart::Str(lane_id),
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.public_events),
            ],
        );
        let event = PublicEvent {
            event_id: event_id.clone(),
            height: self.height,
            lane_id: lane_id.to_string(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            public_root,
        };
        self.counters.public_events = self.counters.public_events.saturating_add(1);
        self.public_events.insert(event_id, event);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBidRequest {
    pub lane_id: String,
    pub receipt_class: ReceiptClass,
    pub side: BidSide,
    pub bidder_commitment: String,
    pub sealed_bid_ciphertext_root: String,
    pub max_fee_micro_units: Option<u64>,
    pub gas_limit: u64,
    pub privacy_set_size: u64,
    pub nullifiers: BTreeSet<String>,
    pub payload_commitment: String,
    pub witness_commitment: String,
    pub credential_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntentReceiptRequest {
    pub bid_id: String,
    pub owner_commitment: String,
    pub solver_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub event_topics: BTreeSet<String>,
    pub max_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleRequest {
    pub lane_id: String,
    pub credential_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub subject_ids: BTreeSet<String>,
    pub fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeBundleRequest {
    pub lane_id: String,
    pub credential_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub confirmations_observed: u64,
    pub bridge_fee_micro_units: u64,
}

pub fn private_l2_fast_pq_confidential_receipt_preconfirmation_market_runtime_state_root(
) -> Result<String> {
    Ok(State::devnet()?.state_root())
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn root_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

pub fn collection_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

pub fn deterministic_id<'a>(domain: &str, parts: &[HashPart<'a>]) -> String {
    let mut encoded = Vec::with_capacity(parts.len() + 1);
    encoded.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        encoded.push(hash_part_ref(part));
    }
    domain_hash(
        &format!("PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:{domain}"),
        &encoded,
        32,
    )
}

pub fn latency_lane_root(lanes: &BTreeMap<String, LatencyFeeLane>) -> String {
    map_root(D_LANES, lanes)
}

pub fn credential_root(credentials: &BTreeMap<String, CommitteeCredential>) -> String {
    map_root(D_CREDENTIALS, credentials)
}

pub fn slashing_bond_root(bonds: &BTreeMap<String, SlashingBond>) -> String {
    map_root(D_BONDS, bonds)
}

pub fn encrypted_bid_root(bids: &BTreeMap<String, EncryptedReceiptBid>) -> String {
    map_root(D_BIDS, bids)
}

pub fn intent_receipt_root(receipts: &BTreeMap<String, IntentReceipt>) -> String {
    map_root(D_INTENTS, receipts)
}

pub fn settlement_acknowledgement_root(
    acknowledgements: &BTreeMap<String, SettlementAcknowledgement>,
) -> String {
    map_root(D_ACKS, acknowledgements)
}

pub fn fee_rebate_root(rebates: &BTreeMap<String, FeeRebate>) -> String {
    map_root(D_REBATES, rebates)
}

pub fn public_state_root(state: &State) -> String {
    root_json(D_STATE, &state.public_state())
}

fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    collection_root(domain, values.values().map(to_value))
}

fn merkle_root_for(domain: &str, values: &[Value]) -> String {
    merkle_root(
        &format!("PL2-FAST-PQ-CONF-RECEIPT-PRECONF-MARKET:{domain}"),
        values,
    )
}

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"}))
}

fn prefixed<'a>(prefix: &str, domain: &str, parts: &[HashPart<'a>]) -> String {
    format!("{prefix}-{}", deterministic_id(domain, parts))
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn scaled_fee(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps).saturating_add(MAX_BPS - 1) / MAX_BPS
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn values_for_ids(ids: &BTreeSet<String>) -> Vec<Value> {
    ids.iter().map(|id| json!(id)).collect()
}

fn set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_string).collect()
}
