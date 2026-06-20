use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeePrivateIntentRelayMarketResult<T> = Result<T, String>;

pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_PROTOCOL_VERSION: &str =
    "nebula-low-fee-private-intent-relay-market-v1";
pub const PROTOCOL_VERSION: &str = LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_PROTOCOL_VERSION;
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_SCHEMA_VERSION: u64 = 1;
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_DEVNET_HEIGHT: u64 = 1_296;
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_INTENT_SCHEME: &str =
    "ml-kem-1024+shake256-sealed-private-intent-v1";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_ROUTE_COMMITMENT_SCHEME: &str =
    "threshold-route-commitment+pq-reveal-v1";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_RELAY_BID_SCHEME: &str =
    "sealed-relay-bid+low-fee-v1";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_RECEIPT_SCHEME: &str =
    "batch-inclusion-receipt+availability-attested-v1";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_CENSORSHIP_PROOF_SCHEME: &str =
    "anti-censorship-witness+inclusion-timeout-v1";
pub const LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_REBATE_SCHEME: &str =
    "refund-rebate-nullifier+surplus-return-v1";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 12;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 30;
pub const DEFAULT_REVEAL_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_MAX_RELAY_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_RELAY_FEE_BPS: u64 = 5;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 8_500;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_MIN_RELAY_BOND_UNITS: u64 = 20_000_000_000;
pub const DEFAULT_MIN_SPONSOR_CREDIT_UNITS: u64 = 1_000_000_000;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 180;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 850;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const DEFAULT_MIN_REPUTATION_SCORE: u64 = 6_500;
pub const DEFAULT_MAX_BATCH_SIZE: usize = 512;
pub const DEFAULT_MAX_ROUTE_HINTS: usize = 64;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_RELAYS: usize = 16_384;
pub const MAX_INTENTS: usize = 262_144;
pub const MAX_BIDS: usize = 262_144;
pub const MAX_SPONSORS: usize = 65_536;
pub const MAX_ROUTE_COMMITMENTS: usize = 262_144;
pub const MAX_RECEIPTS: usize = 262_144;
pub const MAX_SLA_RECORDS: usize = 262_144;
pub const MAX_CENSORSHIP_PROOFS: usize = 65_536;
pub const MAX_REBATES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Swap,
    StableSwap,
    MoneroExit,
    BridgeExit,
    ContractCall,
    WalletRecovery,
    LiquidityUnwind,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::StableSwap => "stable_swap",
            Self::MoneroExit => "monero_exit",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::WalletRecovery => "wallet_recovery",
            Self::LiquidityUnwind => "liquidity_unwind",
        }
    }

    pub fn default_lane(self) -> RelayLane {
        match self {
            Self::Swap => RelayLane::PrivateSwap,
            Self::StableSwap => RelayLane::StableLowFee,
            Self::MoneroExit => RelayLane::MoneroExit,
            Self::BridgeExit => RelayLane::BridgeExit,
            Self::ContractCall => RelayLane::PrivateContract,
            Self::WalletRecovery => RelayLane::WalletRecovery,
            Self::LiquidityUnwind => RelayLane::UrgentExit,
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::MoneroExit => 1_250,
            Self::WalletRecovery => 1_150,
            Self::LiquidityUnwind => 1_050,
            Self::ContractCall => 900,
            Self::BridgeExit => 820,
            Self::Swap => 720,
            Self::StableSwap => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLane {
    LowFee,
    StableLowFee,
    PrivateSwap,
    PrivateContract,
    MoneroExit,
    BridgeExit,
    WalletRecovery,
    UrgentExit,
}

impl RelayLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::StableLowFee => "stable_low_fee",
            Self::PrivateSwap => "private_swap",
            Self::PrivateContract => "private_contract",
            Self::MoneroExit => "monero_exit",
            Self::BridgeExit => "bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
            Self::UrgentExit => "urgent_exit",
        }
    }

    pub fn default_fee_cap_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::StableLowFee | Self::WalletRecovery => config.target_relay_fee_bps,
            Self::UrgentExit => config.max_relay_fee_bps.saturating_add(16),
            Self::PrivateSwap | Self::PrivateContract | Self::MoneroExit | Self::BridgeExit => {
                config.max_relay_fee_bps
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStatus {
    Candidate,
    Active,
    Throttled,
    Probation,
    Slashed,
    Retired,
}

impl RelayStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Probation => "probation",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    BidOpen,
    Assigned,
    Revealed,
    Included,
    Refunded,
    Challenged,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::BidOpen => "bid_open",
            Self::Assigned => "assigned",
            Self::Revealed => "revealed",
            Self::Included => "included",
            Self::Refunded => "refunded",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Included | Self::Refunded | Self::Challenged | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Eligible,
    Winner,
    Superseded,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Eligible => "eligible",
            Self::Winner => "winner",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Open,
    Reserved,
    Consumed,
    Refunded,
    Exhausted,
    Revoked,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensorshipProofStatus {
    Submitted,
    EvidenceMatched,
    RelayAnswered,
    Upheld,
    Dismissed,
    Slashed,
}

impl CensorshipProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::EvidenceMatched => "evidence_matched",
            Self::RelayAnswered => "relay_answered",
            Self::Upheld => "upheld",
            Self::Dismissed => "dismissed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub market_id: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub epoch_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_relay_fee_bps: u64,
    pub target_relay_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub slash_bps: u64,
    pub min_relay_bond_units: u64,
    pub min_sponsor_credit_units: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub min_reputation_score: u64,
    pub max_batch_size: usize,
    pub max_route_hints: usize,
    pub max_public_events: usize,
    pub hash_suite: String,
    pub intent_scheme: String,
    pub route_commitment_scheme: String,
    pub relay_bid_scheme: String,
    pub receipt_scheme: String,
    pub censorship_proof_scheme: String,
    pub rebate_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_SCHEMA_VERSION,
            market_id: "nebula-devnet-low-fee-private-intent-relay-market".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            settlement_asset_id: "wxmr-devnet".to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            reveal_ttl_blocks: DEFAULT_REVEAL_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_relay_fee_bps: DEFAULT_MAX_RELAY_FEE_BPS,
            target_relay_fee_bps: DEFAULT_TARGET_RELAY_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            min_relay_bond_units: DEFAULT_MIN_RELAY_BOND_UNITS,
            min_sponsor_credit_units: DEFAULT_MIN_SPONSOR_CREDIT_UNITS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reputation_score: DEFAULT_MIN_REPUTATION_SCORE,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_route_hints: DEFAULT_MAX_ROUTE_HINTS,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
            hash_suite: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_HASH_SUITE.to_string(),
            intent_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_INTENT_SCHEME.to_string(),
            route_commitment_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_ROUTE_COMMITMENT_SCHEME
                .to_string(),
            relay_bid_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_RELAY_BID_SCHEME.to_string(),
            receipt_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_RECEIPT_SCHEME.to_string(),
            censorship_proof_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_CENSORSHIP_PROOF_SCHEME
                .to_string(),
            rebate_scheme: LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_REBATE_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> LowFeePrivateIntentRelayMarketResult<()> {
        require(
            self.protocol_version == LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_PROTOCOL_VERSION,
            "unsupported low-fee private intent relay market protocol version",
        )?;
        require(self.schema_version > 0, "schema version must be non-zero")?;
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("settlement_asset_id", &self.settlement_asset_id)?;
        require(self.epoch_blocks > 0, "epoch blocks must be non-zero")?;
        require(
            self.intent_ttl_blocks >= self.reveal_ttl_blocks,
            "intent ttl must cover reveal ttl",
        )?;
        require(
            self.receipt_ttl_blocks >= self.reveal_ttl_blocks,
            "receipt ttl must cover reveal ttl",
        )?;
        require(
            self.challenge_window_blocks > 0,
            "challenge window must be non-zero",
        )?;
        require(
            self.target_relay_fee_bps <= self.max_relay_fee_bps,
            "target relay fee cannot exceed max relay fee",
        )?;
        require(
            self.max_relay_fee_bps <= MAX_BPS,
            "max relay fee bps exceeds bounds",
        )?;
        require(
            self.rebate_share_bps <= MAX_BPS,
            "rebate share exceeds bounds",
        )?;
        require(self.slash_bps <= MAX_BPS, "slash bps exceeds bounds")?;
        require(
            self.min_relay_bond_units > 0,
            "minimum relay bond must be non-zero",
        )?;
        require(
            self.min_sponsor_credit_units > 0,
            "minimum sponsor credit must be non-zero",
        )?;
        require(
            self.target_latency_ms <= self.hard_latency_ms,
            "target latency cannot exceed hard latency",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "minimum privacy set size must be non-zero",
        )?;
        require(
            self.min_reputation_score <= MAX_BPS,
            "minimum reputation score exceeds bounds",
        )?;
        require(self.max_batch_size > 0, "max batch size must be non-zero")?;
        require(self.max_route_hints > 0, "max route hints must be non-zero")?;
        require(
            self.max_public_events > 0,
            "max public events must be non-zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "market_id": self.market_id,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "target_relay_fee_bps": self.target_relay_fee_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "slash_bps": self.slash_bps,
            "min_relay_bond_units": self.min_relay_bond_units,
            "min_sponsor_credit_units": self.min_sponsor_credit_units,
            "target_latency_ms": self.target_latency_ms,
            "hard_latency_ms": self.hard_latency_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reputation_score": self.min_reputation_score,
            "max_batch_size": self.max_batch_size,
            "max_route_hints": self.max_route_hints,
            "max_public_events": self.max_public_events,
            "hash_suite": self.hash_suite,
            "intent_scheme": self.intent_scheme,
            "route_commitment_scheme": self.route_commitment_scheme,
            "relay_bid_scheme": self.relay_bid_scheme,
            "receipt_scheme": self.receipt_scheme,
            "censorship_proof_scheme": self.censorship_proof_scheme,
            "rebate_scheme": self.rebate_scheme
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRelay {
    pub relay_id: String,
    pub operator_commitment: String,
    pub status: RelayStatus,
    pub supported_lanes: BTreeSet<RelayLane>,
    pub bond_units: u64,
    pub reputation_score: u64,
    pub successful_batches: u64,
    pub missed_slas: u64,
    pub censorship_faults: u64,
    pub median_latency_ms: u64,
    pub max_fee_bps: u64,
    pub admission_root: String,
    pub network_key_root: String,
    pub registered_at_height: u64,
    pub last_active_height: u64,
}

impl PrivateRelay {
    pub fn public_record(&self) -> Value {
        json!({
            "relay_id": self.relay_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "bond_units": self.bond_units,
            "reputation_score": self.reputation_score,
            "successful_batches": self.successful_batches,
            "missed_slas": self.missed_slas,
            "censorship_faults": self.censorship_faults,
            "median_latency_ms": self.median_latency_ms,
            "max_fee_bps": self.max_fee_bps,
            "admission_root": self.admission_root,
            "network_key_root": self.network_key_root,
            "registered_at_height": self.registered_at_height,
            "last_active_height": self.last_active_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-INTENT-RELAY", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedUserIntent {
    pub intent_id: String,
    pub user_commitment: String,
    pub intent_kind: IntentKind,
    pub lane: RelayLane,
    pub status: IntentStatus,
    pub sealed_payload_root: String,
    pub encrypted_witness_root: String,
    pub nullifier_root: String,
    pub fee_cap_bps: u64,
    pub max_fee_units: u64,
    pub sponsor_credit_id: Option<String>,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub assigned_relay_id: Option<String>,
}

impl SealedUserIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "user_commitment": self.user_commitment,
            "intent_kind": self.intent_kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sealed_payload_root": self.sealed_payload_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "nullifier_root": self.nullifier_root,
            "fee_cap_bps": self.fee_cap_bps,
            "max_fee_units": self.max_fee_units,
            "sponsor_credit_id": self.sponsor_credit_id,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "assigned_relay_id": self.assigned_relay_id
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRelayBid {
    pub bid_id: String,
    pub intent_id: String,
    pub relay_id: String,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub route_commitment_id: String,
    pub bid_fee_bps: u64,
    pub max_fee_units: u64,
    pub promised_latency_ms: u64,
    pub reputation_snapshot: u64,
    pub inclusion_bond_units: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRelayBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "intent_id": self.intent_id,
            "relay_id": self.relay_id,
            "status": self.status.as_str(),
            "sealed_bid_root": self.sealed_bid_root,
            "route_commitment_id": self.route_commitment_id,
            "bid_fee_bps": self.bid_fee_bps,
            "max_fee_units": self.max_fee_units,
            "promised_latency_ms": self.promised_latency_ms,
            "reputation_snapshot": self.reputation_snapshot,
            "inclusion_bond_units": self.inclusion_bond_units,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-RELAY-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredFeeCredit {
    pub credit_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub lane: RelayLane,
    pub status: CreditStatus,
    pub original_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub refunded_units: u64,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl SponsoredFeeCredit {
    pub fn available_units(&self) -> u64 {
        self.original_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
            .saturating_sub(self.refunded_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "original_units": self.original_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "refunded_units": self.refunded_units,
            "available_units": self.available_units(),
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-SPONSORED-CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRouteCommitment {
    pub commitment_id: String,
    pub intent_id: String,
    pub relay_id: String,
    pub route_ciphertext_root: String,
    pub route_hint_root: String,
    pub reveal_threshold_root: String,
    pub settlement_call_root: String,
    pub refund_path_root: String,
    pub hop_count_commitment: u64,
    pub privacy_budget_bps: u64,
    pub committed_at_height: u64,
    pub reveal_after_height: u64,
}

impl EncryptedRouteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "intent_id": self.intent_id,
            "relay_id": self.relay_id,
            "route_ciphertext_root": self.route_ciphertext_root,
            "route_hint_root": self.route_hint_root,
            "reveal_threshold_root": self.reveal_threshold_root,
            "settlement_call_root": self.settlement_call_root,
            "refund_path_root": self.refund_path_root,
            "hop_count_commitment": self.hop_count_commitment,
            "privacy_budget_bps": self.privacy_budget_bps,
            "committed_at_height": self.committed_at_height,
            "reveal_after_height": self.reveal_after_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-ROUTE-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchInclusionReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub bid_id: String,
    pub relay_id: String,
    pub included_height: u64,
    pub observed_latency_ms: u64,
    pub charged_fee_units: u64,
    pub sponsor_credit_units: u64,
    pub inclusion_proof_root: String,
    pub batch_merkle_root: String,
    pub availability_attestation_root: String,
}

impl BatchInclusionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "bid_id": self.bid_id,
            "relay_id": self.relay_id,
            "included_height": self.included_height,
            "observed_latency_ms": self.observed_latency_ms,
            "charged_fee_units": self.charged_fee_units,
            "sponsor_credit_units": self.sponsor_credit_units,
            "inclusion_proof_root": self.inclusion_proof_root,
            "batch_merkle_root": self.batch_merkle_root,
            "availability_attestation_root": self.availability_attestation_root
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-BATCH-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySla {
    pub sla_id: String,
    pub relay_id: String,
    pub batch_id: String,
    pub sample_count: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub max_latency_ms: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub met_target_count: u64,
    pub breached_count: u64,
    pub measured_at_height: u64,
}

impl LatencySla {
    pub fn target_met(&self) -> bool {
        self.p95_latency_ms <= self.target_latency_ms && self.max_latency_ms <= self.hard_latency_ms
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sla_id": self.sla_id,
            "relay_id": self.relay_id,
            "batch_id": self.batch_id,
            "sample_count": self.sample_count,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "target_latency_ms": self.target_latency_ms,
            "hard_latency_ms": self.hard_latency_ms,
            "met_target_count": self.met_target_count,
            "breached_count": self.breached_count,
            "target_met": self.target_met(),
            "measured_at_height": self.measured_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-LATENCY-SLA", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiCensorshipProof {
    pub proof_id: String,
    pub intent_id: String,
    pub relay_id: String,
    pub challenger_commitment: String,
    pub status: CensorshipProofStatus,
    pub withheld_payload_root: String,
    pub witness_set_root: String,
    pub relay_response_root: String,
    pub missed_deadline_height: u64,
    pub submitted_at_height: u64,
    pub slash_units: u64,
}

impl AntiCensorshipProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "intent_id": self.intent_id,
            "relay_id": self.relay_id,
            "challenger_commitment": self.challenger_commitment,
            "status": self.status.as_str(),
            "withheld_payload_root": self.withheld_payload_root,
            "witness_set_root": self.witness_set_root,
            "relay_response_root": self.relay_response_root,
            "missed_deadline_height": self.missed_deadline_height,
            "submitted_at_height": self.submitted_at_height,
            "slash_units": self.slash_units
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-CENSORSHIP-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub recipient_commitment: String,
    pub relay_id: String,
    pub reason: String,
    pub rebate_units: u64,
    pub surplus_units: u64,
    pub nullifier_root: String,
    pub issued_at_height: u64,
    pub claim_expires_at_height: u64,
}

impl RefundRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "recipient_commitment": self.recipient_commitment,
            "relay_id": self.relay_id,
            "reason": self.reason,
            "rebate_units": self.rebate_units,
            "surplus_units": self.surplus_units,
            "nullifier_root": self.nullifier_root,
            "issued_at_height": self.issued_at_height,
            "claim_expires_at_height": self.claim_expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-REFUND-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMarketEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PublicMarketEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LOW-FEE-PRIVATE-RELAY-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub relay_root: String,
    pub intent_root: String,
    pub bid_root: String,
    pub sponsor_credit_root: String,
    pub route_commitment_root: String,
    pub receipt_root: String,
    pub latency_sla_root: String,
    pub censorship_proof_root: String,
    pub rebate_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "relay_root": self.relay_root,
            "intent_root": self.intent_root,
            "bid_root": self.bid_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "route_commitment_root": self.route_commitment_root,
            "receipt_root": self.receipt_root,
            "latency_sla_root": self.latency_sla_root,
            "censorship_proof_root": self.censorship_proof_root,
            "rebate_root": self.rebate_root,
            "event_root": self.event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub relays: usize,
    pub active_relays: usize,
    pub sealed_intents: usize,
    pub terminal_intents: usize,
    pub relay_bids: usize,
    pub winning_bids: usize,
    pub sponsor_credits: usize,
    pub route_commitments: usize,
    pub receipts: usize,
    pub latency_slas: usize,
    pub censorship_proofs: usize,
    pub upheld_censorship_proofs: usize,
    pub rebates: usize,
    pub public_events: usize,
    pub total_bond_units: u64,
    pub total_sponsor_credit_units: u64,
    pub total_rebate_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "relays": self.relays,
            "active_relays": self.active_relays,
            "sealed_intents": self.sealed_intents,
            "terminal_intents": self.terminal_intents,
            "relay_bids": self.relay_bids,
            "winning_bids": self.winning_bids,
            "sponsor_credits": self.sponsor_credits,
            "route_commitments": self.route_commitments,
            "receipts": self.receipts,
            "latency_slas": self.latency_slas,
            "censorship_proofs": self.censorship_proofs,
            "upheld_censorship_proofs": self.upheld_censorship_proofs,
            "rebates": self.rebates,
            "public_events": self.public_events,
            "total_bond_units": self.total_bond_units,
            "total_sponsor_credit_units": self.total_sponsor_credit_units,
            "total_rebate_units": self.total_rebate_units
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub relays: BTreeMap<String, PrivateRelay>,
    pub intents: BTreeMap<String, SealedUserIntent>,
    pub relay_bids: BTreeMap<String, PrivateRelayBid>,
    pub sponsor_credits: BTreeMap<String, SponsoredFeeCredit>,
    pub route_commitments: BTreeMap<String, EncryptedRouteCommitment>,
    pub receipts: BTreeMap<String, BatchInclusionReceipt>,
    pub latency_slas: BTreeMap<String, LatencySla>,
    pub censorship_proofs: BTreeMap<String, AntiCensorshipProof>,
    pub rebates: BTreeMap<String, RefundRebate>,
    pub public_events: BTreeMap<String, PublicMarketEvent>,
}

impl State {
    pub fn devnet() -> LowFeePrivateIntentRelayMarketResult<Self> {
        let config = Config::devnet();
        let height = LOW_FEE_PRIVATE_INTENT_RELAY_MARKET_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            config,
            relays: BTreeMap::new(),
            intents: BTreeMap::new(),
            relay_bids: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            route_commitments: BTreeMap::new(),
            receipts: BTreeMap::new(),
            latency_slas: BTreeMap::new(),
            censorship_proofs: BTreeMap::new(),
            rebates: BTreeMap::new(),
            public_events: BTreeMap::new(),
        };

        for index in 0_u64..4 {
            let relay = sample_relay(index, height, &state.config);
            state.relays.insert(relay.relay_id.clone(), relay);
        }

        for index in 0_u64..6 {
            let credit = sample_sponsor_credit(index, height, &state.config);
            state
                .sponsor_credits
                .insert(credit.credit_id.clone(), credit);
        }

        for index in 0_u64..10 {
            let relay_id = format!("relay-devnet-{}", (index % 4) + 1);
            let credit_id = if index % 2 == 0 {
                Some(format!("credit-devnet-{}", (index % 6) + 1))
            } else {
                None
            };
            let intent = sample_intent(index, height, &state.config, &relay_id, credit_id);
            let route = sample_route_commitment(index, height, &intent.intent_id, &relay_id);
            let bid = sample_bid(
                index,
                height,
                &intent.intent_id,
                &relay_id,
                &route.commitment_id,
            );
            state
                .route_commitments
                .insert(route.commitment_id.clone(), route);
            state.relay_bids.insert(bid.bid_id.clone(), bid);
            state.intents.insert(intent.intent_id.clone(), intent);
        }

        for index in 0_u64..5 {
            let receipt = sample_receipt(index, height);
            let sla = sample_sla(
                index,
                height,
                &receipt.relay_id,
                &receipt.batch_id,
                &state.config,
            );
            let rebate = sample_rebate(index, height, &receipt);
            state.receipts.insert(receipt.receipt_id.clone(), receipt);
            state.latency_slas.insert(sla.sla_id.clone(), sla);
            state.rebates.insert(rebate.rebate_id.clone(), rebate);
        }

        let proof = sample_censorship_proof(height, &state.config);
        state
            .censorship_proofs
            .insert(proof.proof_id.clone(), proof);

        for index in 0_u64..8 {
            let event = sample_event(index, height);
            state.public_events.insert(event.event_id.clone(), event);
        }

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeePrivateIntentRelayMarketResult<()> {
        self.config.validate()?;
        require(self.height > 0, "state height must be non-zero")?;
        require(self.relays.len() <= MAX_RELAYS, "too many relays")?;
        require(self.intents.len() <= MAX_INTENTS, "too many intents")?;
        require(self.relay_bids.len() <= MAX_BIDS, "too many relay bids")?;
        require(
            self.sponsor_credits.len() <= MAX_SPONSORS,
            "too many sponsor credits",
        )?;
        require(
            self.route_commitments.len() <= MAX_ROUTE_COMMITMENTS,
            "too many route commitments",
        )?;
        require(self.receipts.len() <= MAX_RECEIPTS, "too many receipts")?;
        require(
            self.latency_slas.len() <= MAX_SLA_RECORDS,
            "too many latency sla records",
        )?;
        require(
            self.censorship_proofs.len() <= MAX_CENSORSHIP_PROOFS,
            "too many censorship proofs",
        )?;
        require(self.rebates.len() <= MAX_REBATES, "too many rebates")?;
        require(
            self.public_events.len() <= self.config.max_public_events,
            "too many public events",
        )?;

        for (relay_id, relay) in &self.relays {
            require(relay_id == &relay.relay_id, "relay key mismatch")?;
            require_non_empty("relay_id", &relay.relay_id)?;
            require_non_empty("operator_commitment", &relay.operator_commitment)?;
            require(
                relay.bond_units >= self.config.min_relay_bond_units,
                "relay bond below configured minimum",
            )?;
            require(
                relay.reputation_score <= MAX_BPS,
                "relay reputation exceeds bounds",
            )?;
            require(relay.max_fee_bps <= MAX_BPS, "relay fee exceeds bounds")?;
            require(
                !relay.supported_lanes.is_empty(),
                "relay must support at least one lane",
            )?;
            require_non_empty("admission_root", &relay.admission_root)?;
            require_non_empty("network_key_root", &relay.network_key_root)?;
            require(
                relay.registered_at_height <= relay.last_active_height,
                "relay activity predates registration",
            )?;
        }

        for (intent_id, intent) in &self.intents {
            require(intent_id == &intent.intent_id, "intent key mismatch")?;
            require_non_empty("intent_id", &intent.intent_id)?;
            require_non_empty("user_commitment", &intent.user_commitment)?;
            require_non_empty("sealed_payload_root", &intent.sealed_payload_root)?;
            require_non_empty("encrypted_witness_root", &intent.encrypted_witness_root)?;
            require_non_empty("nullifier_root", &intent.nullifier_root)?;
            require(
                intent.fee_cap_bps <= MAX_BPS,
                "intent fee cap exceeds bounds",
            )?;
            require(
                intent.privacy_set_size >= self.config.min_privacy_set_size,
                "intent privacy set below configured minimum",
            )?;
            require(
                intent.submitted_at_height < intent.expires_at_height,
                "intent expiration must be after submission",
            )?;
            if let Some(relay_id) = &intent.assigned_relay_id {
                require(
                    self.relays.contains_key(relay_id),
                    "intent references missing relay",
                )?;
            }
            if let Some(credit_id) = &intent.sponsor_credit_id {
                require(
                    self.sponsor_credits.contains_key(credit_id),
                    "intent references missing sponsor credit",
                )?;
            }
        }

        for (bid_id, bid) in &self.relay_bids {
            require(bid_id == &bid.bid_id, "bid key mismatch")?;
            require(
                self.intents.contains_key(&bid.intent_id),
                "bid references missing intent",
            )?;
            require(
                self.relays.contains_key(&bid.relay_id),
                "bid references missing relay",
            )?;
            require(
                self.route_commitments
                    .contains_key(&bid.route_commitment_id),
                "bid references missing route commitment",
            )?;
            require(bid.bid_fee_bps <= MAX_BPS, "bid fee exceeds bounds")?;
            require(
                bid.promised_latency_ms <= self.config.hard_latency_ms,
                "bid latency exceeds hard latency",
            )?;
            require(
                bid.inclusion_bond_units > 0,
                "bid inclusion bond must be non-zero",
            )?;
            require(
                bid.submitted_at_height < bid.expires_at_height,
                "bid expiration must be after submission",
            )?;
        }

        for (credit_id, credit) in &self.sponsor_credits {
            require(
                credit_id == &credit.credit_id,
                "sponsor credit key mismatch",
            )?;
            require_non_empty("sponsor_commitment", &credit.sponsor_commitment)?;
            require_non_empty("beneficiary_commitment", &credit.beneficiary_commitment)?;
            require(
                credit.original_units >= self.config.min_sponsor_credit_units,
                "sponsor credit below configured minimum",
            )?;
            require(
                credit.max_fee_bps <= MAX_BPS,
                "sponsor credit fee cap exceeds bounds",
            )?;
            require(
                credit
                    .reserved_units
                    .saturating_add(credit.consumed_units)
                    .saturating_add(credit.refunded_units)
                    <= credit.original_units,
                "sponsor credit accounting exceeds original units",
            )?;
            require(
                credit.opened_at_height < credit.expires_at_height,
                "sponsor credit expiration must be after open height",
            )?;
            require_non_empty("policy_root", &credit.policy_root)?;
        }

        for (commitment_id, commitment) in &self.route_commitments {
            require(
                commitment_id == &commitment.commitment_id,
                "route commitment key mismatch",
            )?;
            require(
                self.intents.contains_key(&commitment.intent_id),
                "route commitment references missing intent",
            )?;
            require(
                self.relays.contains_key(&commitment.relay_id),
                "route commitment references missing relay",
            )?;
            require_non_empty("route_ciphertext_root", &commitment.route_ciphertext_root)?;
            require_non_empty("route_hint_root", &commitment.route_hint_root)?;
            require(
                commitment.privacy_budget_bps <= MAX_BPS,
                "route privacy budget exceeds bounds",
            )?;
            require(
                commitment.committed_at_height <= commitment.reveal_after_height,
                "route reveal height predates commitment",
            )?;
        }

        for (receipt_id, receipt) in &self.receipts {
            require(receipt_id == &receipt.receipt_id, "receipt key mismatch")?;
            require(
                self.intents.contains_key(&receipt.intent_id),
                "receipt missing intent",
            )?;
            require(
                self.relay_bids.contains_key(&receipt.bid_id),
                "receipt missing bid",
            )?;
            require(
                self.relays.contains_key(&receipt.relay_id),
                "receipt missing relay",
            )?;
            require_non_empty("inclusion_proof_root", &receipt.inclusion_proof_root)?;
            require_non_empty("batch_merkle_root", &receipt.batch_merkle_root)?;
            require_non_empty(
                "availability_attestation_root",
                &receipt.availability_attestation_root,
            )?;
        }

        for (sla_id, sla) in &self.latency_slas {
            require(sla_id == &sla.sla_id, "latency sla key mismatch")?;
            require(self.relays.contains_key(&sla.relay_id), "sla missing relay")?;
            require(sla.sample_count > 0, "sla sample count must be non-zero")?;
            require(
                sla.p50_latency_ms <= sla.p95_latency_ms,
                "sla p50 exceeds p95",
            )?;
            require(
                sla.p95_latency_ms <= sla.max_latency_ms,
                "sla p95 exceeds max",
            )?;
            require(
                sla.target_latency_ms <= sla.hard_latency_ms,
                "sla target exceeds hard latency",
            )?;
        }

        for (proof_id, proof) in &self.censorship_proofs {
            require(proof_id == &proof.proof_id, "censorship proof key mismatch")?;
            require(
                self.intents.contains_key(&proof.intent_id),
                "censorship proof references missing intent",
            )?;
            require(
                self.relays.contains_key(&proof.relay_id),
                "censorship proof references missing relay",
            )?;
            require_non_empty("challenger_commitment", &proof.challenger_commitment)?;
            require_non_empty("withheld_payload_root", &proof.withheld_payload_root)?;
            require_non_empty("witness_set_root", &proof.witness_set_root)?;
        }

        for (rebate_id, rebate) in &self.rebates {
            require(rebate_id == &rebate.rebate_id, "rebate key mismatch")?;
            require(
                self.intents.contains_key(&rebate.intent_id),
                "rebate missing intent",
            )?;
            require(
                self.receipts.contains_key(&rebate.receipt_id),
                "rebate references missing receipt",
            )?;
            require(
                self.relays.contains_key(&rebate.relay_id),
                "rebate missing relay",
            )?;
            require_non_empty("recipient_commitment", &rebate.recipient_commitment)?;
            require_non_empty("reason", &rebate.reason)?;
            require_non_empty("nullifier_root", &rebate.nullifier_root)?;
            require(
                rebate.issued_at_height < rebate.claim_expires_at_height,
                "rebate claim expiration must be after issue height",
            )?;
        }

        for (event_id, event) in &self.public_events {
            require(event_id == &event.event_id, "event key mismatch")?;
            require_non_empty("event_kind", &event.event_kind)?;
            require_non_empty("subject_id", &event.subject_id)?;
            require_non_empty("payload_root", &event.payload_root)?;
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeePrivateIntentRelayMarketResult<()> {
        require(height > 0, "height must be non-zero")?;
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> LowFeePrivateIntentRelayMarketResult<()> {
        require(height >= self.height, "height cannot decrease")?;
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "LOW-FEE-PRIVATE-INTENT-RELAY-CONFIG",
            &self.config.public_record(),
        );
        let relay_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-RELAYS",
            self.relays
                .values()
                .map(PrivateRelay::public_record)
                .collect(),
        );
        let intent_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-INTENTS",
            self.intents
                .values()
                .map(SealedUserIntent::public_record)
                .collect(),
        );
        let bid_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-BIDS",
            self.relay_bids
                .values()
                .map(PrivateRelayBid::public_record)
                .collect(),
        );
        let sponsor_credit_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-SPONSOR-CREDITS",
            self.sponsor_credits
                .values()
                .map(SponsoredFeeCredit::public_record)
                .collect(),
        );
        let route_commitment_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-ROUTE-COMMITMENTS",
            self.route_commitments
                .values()
                .map(EncryptedRouteCommitment::public_record)
                .collect(),
        );
        let receipt_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-RECEIPTS",
            self.receipts
                .values()
                .map(BatchInclusionReceipt::public_record)
                .collect(),
        );
        let latency_sla_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-LATENCY-SLAS",
            self.latency_slas
                .values()
                .map(LatencySla::public_record)
                .collect(),
        );
        let censorship_proof_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-CENSORSHIP-PROOFS",
            self.censorship_proofs
                .values()
                .map(AntiCensorshipProof::public_record)
                .collect(),
        );
        let rebate_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-REBATES",
            self.rebates
                .values()
                .map(RefundRebate::public_record)
                .collect(),
        );
        let event_root = map_root(
            "LOW-FEE-PRIVATE-INTENT-RELAY-EVENTS",
            self.public_events
                .values()
                .map(PublicMarketEvent::public_record)
                .collect(),
        );
        let state_root = domain_hash(
            "LOW-FEE-PRIVATE-INTENT-RELAY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config_root),
                HashPart::Str(&relay_root),
                HashPart::Str(&intent_root),
                HashPart::Str(&bid_root),
                HashPart::Str(&sponsor_credit_root),
                HashPart::Str(&route_commitment_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&latency_sla_root),
                HashPart::Str(&censorship_proof_root),
                HashPart::Str(&rebate_root),
                HashPart::Str(&event_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );

        Roots {
            config_root,
            relay_root,
            intent_root,
            bid_root,
            sponsor_credit_root,
            route_commitment_root,
            receipt_root,
            latency_sla_root,
            censorship_proof_root,
            rebate_root,
            event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            relays: self.relays.len(),
            active_relays: self
                .relays
                .values()
                .filter(|relay| relay.status.accepts_intents())
                .count(),
            sealed_intents: self.intents.len(),
            terminal_intents: self
                .intents
                .values()
                .filter(|intent| intent.status.terminal())
                .count(),
            relay_bids: self.relay_bids.len(),
            winning_bids: self
                .relay_bids
                .values()
                .filter(|bid| bid.status == BidStatus::Winner)
                .count(),
            sponsor_credits: self.sponsor_credits.len(),
            route_commitments: self.route_commitments.len(),
            receipts: self.receipts.len(),
            latency_slas: self.latency_slas.len(),
            censorship_proofs: self.censorship_proofs.len(),
            upheld_censorship_proofs: self
                .censorship_proofs
                .values()
                .filter(|proof| proof.status == CensorshipProofStatus::Upheld)
                .count(),
            rebates: self.rebates.len(),
            public_events: self.public_events.len(),
            total_bond_units: self.relays.values().map(|relay| relay.bond_units).sum(),
            total_sponsor_credit_units: self
                .sponsor_credits
                .values()
                .map(|credit| credit.original_units)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "relays": self.relays.values().map(PrivateRelay::public_record).collect::<Vec<_>>(),
            "intents": self.intents.values().map(SealedUserIntent::public_record).collect::<Vec<_>>(),
            "relay_bids": self.relay_bids.values().map(PrivateRelayBid::public_record).collect::<Vec<_>>(),
            "sponsor_credits": self.sponsor_credits.values().map(SponsoredFeeCredit::public_record).collect::<Vec<_>>(),
            "route_commitments": self.route_commitments.values().map(EncryptedRouteCommitment::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(BatchInclusionReceipt::public_record).collect::<Vec<_>>(),
            "latency_slas": self.latency_slas.values().map(LatencySla::public_record).collect::<Vec<_>>(),
            "censorship_proofs": self.censorship_proofs.values().map(AntiCensorshipProof::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(RefundRebate::public_record).collect::<Vec<_>>(),
            "public_events": self.public_events.values().map(PublicMarketEvent::public_record).collect::<Vec<_>>()
        })
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> LowFeePrivateIntentRelayMarketResult<State> {
    State::devnet()
}

fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn sample_relay(index: u64, height: u64, config: &Config) -> PrivateRelay {
    let relay_number = index + 1;
    let mut supported_lanes = BTreeSet::new();
    supported_lanes.insert(RelayLane::LowFee);
    supported_lanes.insert(RelayLane::PrivateSwap);
    if index % 2 == 0 {
        supported_lanes.insert(RelayLane::MoneroExit);
        supported_lanes.insert(RelayLane::WalletRecovery);
    } else {
        supported_lanes.insert(RelayLane::PrivateContract);
        supported_lanes.insert(RelayLane::BridgeExit);
    }
    PrivateRelay {
        relay_id: format!("relay-devnet-{relay_number}"),
        operator_commitment: short_root("RELAY-OPERATOR", relay_number),
        status: if index == 3 {
            RelayStatus::Probation
        } else {
            RelayStatus::Active
        },
        supported_lanes,
        bond_units: config.min_relay_bond_units + relay_number * 8_000_000_000,
        reputation_score: 8_900_u64.saturating_sub(index * 450),
        successful_batches: 180 + index * 27,
        missed_slas: index,
        censorship_faults: if index == 3 { 1 } else { 0 },
        median_latency_ms: config.target_latency_ms.saturating_add(index * 18),
        max_fee_bps: config.max_relay_fee_bps.saturating_sub(index),
        admission_root: short_root("RELAY-ADMISSION", relay_number),
        network_key_root: short_root("RELAY-NETWORK-KEY", relay_number),
        registered_at_height: height.saturating_sub(640 + index * 40),
        last_active_height: height.saturating_sub(index),
    }
}

fn sample_sponsor_credit(index: u64, height: u64, config: &Config) -> SponsoredFeeCredit {
    let credit_number = index + 1;
    let original_units = config.min_sponsor_credit_units + credit_number * 650_000_000;
    SponsoredFeeCredit {
        credit_id: format!("credit-devnet-{credit_number}"),
        sponsor_commitment: short_root("SPONSOR", credit_number),
        beneficiary_commitment: short_root("BENEFICIARY", credit_number),
        lane: match index % 4 {
            0 => RelayLane::LowFee,
            1 => RelayLane::PrivateSwap,
            2 => RelayLane::MoneroExit,
            _ => RelayLane::PrivateContract,
        },
        status: if index == 5 {
            CreditStatus::Reserved
        } else {
            CreditStatus::Open
        },
        original_units,
        reserved_units: 80_000_000 + index * 5_000_000,
        consumed_units: 42_000_000 + index * 3_000_000,
        refunded_units: 10_000_000 + index * 2_000_000,
        max_fee_bps: config.max_relay_fee_bps,
        opened_at_height: height.saturating_sub(220 + index * 3),
        expires_at_height: height + config.intent_ttl_blocks + 200 + index,
        policy_root: short_root("SPONSOR-POLICY", credit_number),
    }
}

fn sample_intent(
    index: u64,
    height: u64,
    config: &Config,
    relay_id: &str,
    credit_id: Option<String>,
) -> SealedUserIntent {
    let intent_number = index + 1;
    let intent_kind = match index % 7 {
        0 => IntentKind::Swap,
        1 => IntentKind::StableSwap,
        2 => IntentKind::MoneroExit,
        3 => IntentKind::BridgeExit,
        4 => IntentKind::ContractCall,
        5 => IntentKind::WalletRecovery,
        _ => IntentKind::LiquidityUnwind,
    };
    let lane = intent_kind.default_lane();
    let status = match index % 5 {
        0 => IntentStatus::Included,
        1 => IntentStatus::Assigned,
        2 => IntentStatus::BidOpen,
        3 => IntentStatus::Revealed,
        _ => IntentStatus::Sealed,
    };
    SealedUserIntent {
        intent_id: format!("intent-devnet-{intent_number}"),
        user_commitment: short_root("USER-COMMITMENT", intent_number),
        intent_kind,
        lane,
        status,
        sealed_payload_root: short_root("SEALED-INTENT-PAYLOAD", intent_number),
        encrypted_witness_root: short_root("ENCRYPTED-INTENT-WITNESS", intent_number),
        nullifier_root: short_root("INTENT-NULLIFIER", intent_number),
        fee_cap_bps: lane.default_fee_cap_bps(config),
        max_fee_units: 25_000_000 + index * 2_500_000,
        sponsor_credit_id: credit_id,
        privacy_set_size: config.min_privacy_set_size + intent_kind.privacy_weight() / 10 + index,
        submitted_at_height: height.saturating_sub(24 + index),
        expires_at_height: height + config.intent_ttl_blocks + index,
        assigned_relay_id: Some(relay_id.to_string()),
    }
}

fn sample_route_commitment(
    index: u64,
    height: u64,
    intent_id: &str,
    relay_id: &str,
) -> EncryptedRouteCommitment {
    let route_number = index + 1;
    EncryptedRouteCommitment {
        commitment_id: format!("route-commitment-devnet-{route_number}"),
        intent_id: intent_id.to_string(),
        relay_id: relay_id.to_string(),
        route_ciphertext_root: short_root("ROUTE-CIPHERTEXT", route_number),
        route_hint_root: short_root("ROUTE-HINT", route_number),
        reveal_threshold_root: short_root("ROUTE-REVEAL-THRESHOLD", route_number),
        settlement_call_root: short_root("ROUTE-SETTLEMENT-CALL", route_number),
        refund_path_root: short_root("ROUTE-REFUND-PATH", route_number),
        hop_count_commitment: 2 + index % 5,
        privacy_budget_bps: 420 + index * 12,
        committed_at_height: height.saturating_sub(18 + index),
        reveal_after_height: height.saturating_sub(12 + index / 2),
    }
}

fn sample_bid(
    index: u64,
    height: u64,
    intent_id: &str,
    relay_id: &str,
    route_commitment_id: &str,
) -> PrivateRelayBid {
    let bid_number = index + 1;
    PrivateRelayBid {
        bid_id: format!("relay-bid-devnet-{bid_number}"),
        intent_id: intent_id.to_string(),
        relay_id: relay_id.to_string(),
        status: if index < 5 {
            BidStatus::Winner
        } else if index % 2 == 0 {
            BidStatus::Eligible
        } else {
            BidStatus::Sealed
        },
        sealed_bid_root: short_root("SEALED-RELAY-BID", bid_number),
        route_commitment_id: route_commitment_id.to_string(),
        bid_fee_bps: 3 + index % 6,
        max_fee_units: 20_000_000 + index * 1_500_000,
        promised_latency_ms: DEFAULT_TARGET_LATENCY_MS + index * 12,
        reputation_snapshot: 8_600_u64.saturating_sub(index * 120),
        inclusion_bond_units: 2_000_000_000 + index * 250_000_000,
        submitted_at_height: height.saturating_sub(16 + index),
        expires_at_height: height + DEFAULT_INTENT_TTL_BLOCKS,
    }
}

fn sample_receipt(index: u64, height: u64) -> BatchInclusionReceipt {
    let receipt_number = index + 1;
    BatchInclusionReceipt {
        receipt_id: format!("receipt-devnet-{receipt_number}"),
        batch_id: format!("private-relay-batch-devnet-{}", (index / 2) + 1),
        intent_id: format!("intent-devnet-{receipt_number}"),
        bid_id: format!("relay-bid-devnet-{receipt_number}"),
        relay_id: format!("relay-devnet-{}", (index % 4) + 1),
        included_height: height.saturating_sub(index),
        observed_latency_ms: 120 + index * 24,
        charged_fee_units: 4_500_000 + index * 500_000,
        sponsor_credit_units: if index % 2 == 0 { 1_000_000 } else { 0 },
        inclusion_proof_root: short_root("INCLUSION-PROOF", receipt_number),
        batch_merkle_root: short_root("BATCH-MERKLE", receipt_number),
        availability_attestation_root: short_root("AVAILABILITY-ATTESTATION", receipt_number),
    }
}

fn sample_sla(
    index: u64,
    height: u64,
    relay_id: &str,
    batch_id: &str,
    config: &Config,
) -> LatencySla {
    let sla_number = index + 1;
    LatencySla {
        sla_id: format!("sla-devnet-{sla_number}"),
        relay_id: relay_id.to_string(),
        batch_id: batch_id.to_string(),
        sample_count: 24 + index,
        p50_latency_ms: 110 + index * 10,
        p95_latency_ms: 165 + index * 18,
        max_latency_ms: 300 + index * 60,
        target_latency_ms: config.target_latency_ms,
        hard_latency_ms: config.hard_latency_ms,
        met_target_count: 20 + index,
        breached_count: if index == 4 { 2 } else { index % 2 },
        measured_at_height: height.saturating_sub(index),
    }
}

fn sample_censorship_proof(height: u64, config: &Config) -> AntiCensorshipProof {
    AntiCensorshipProof {
        proof_id: "censorship-proof-devnet-1".to_string(),
        intent_id: "intent-devnet-4".to_string(),
        relay_id: "relay-devnet-4".to_string(),
        challenger_commitment: short_root("CENSORSHIP-CHALLENGER", 1),
        status: CensorshipProofStatus::Submitted,
        withheld_payload_root: short_root("WITHHELD-PAYLOAD", 1),
        witness_set_root: short_root("CENSORSHIP-WITNESS-SET", 1),
        relay_response_root: short_root("RELAY-CENSORSHIP-RESPONSE", 1),
        missed_deadline_height: height.saturating_sub(config.challenge_window_blocks / 2),
        submitted_at_height: height,
        slash_units: config.min_relay_bond_units.saturating_mul(config.slash_bps) / MAX_BPS,
    }
}

fn sample_rebate(index: u64, height: u64, receipt: &BatchInclusionReceipt) -> RefundRebate {
    let rebate_number = index + 1;
    RefundRebate {
        rebate_id: format!("rebate-devnet-{rebate_number}"),
        intent_id: receipt.intent_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        recipient_commitment: short_root("REBATE-RECIPIENT", rebate_number),
        relay_id: receipt.relay_id.clone(),
        reason: if index % 2 == 0 {
            "fee_surplus_return".to_string()
        } else {
            "sponsor_credit_refund".to_string()
        },
        rebate_units: 800_000 + index * 120_000,
        surplus_units: 1_100_000 + index * 140_000,
        nullifier_root: short_root("REBATE-NULLIFIER", rebate_number),
        issued_at_height: height.saturating_sub(index),
        claim_expires_at_height: height + DEFAULT_CHALLENGE_WINDOW_BLOCKS + index,
    }
}

fn sample_event(index: u64, height: u64) -> PublicMarketEvent {
    let event_number = index + 1;
    let event_kind = match index % 4 {
        0 => "intent_sealed",
        1 => "relay_bid_won",
        2 => "batch_receipt_posted",
        _ => "refund_rebate_issued",
    };
    PublicMarketEvent {
        event_id: format!("relay-market-event-devnet-{event_number}"),
        event_kind: event_kind.to_string(),
        subject_id: format!("intent-devnet-{}", (index % 10) + 1),
        payload_root: short_root("PUBLIC-EVENT-PAYLOAD", event_number),
        emitted_at_height: height.saturating_sub(index),
        sequence: index,
    }
}

fn short_root(domain: &str, index: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Int(index as i128)],
        32,
    )
}

fn require(condition: bool, message: &str) -> LowFeePrivateIntentRelayMarketResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(field: &str, value: &str) -> LowFeePrivateIntentRelayMarketResult<()> {
    if value.is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}
