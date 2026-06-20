use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateLiquidityBatchAuctionClearinghouseResult<T> = Result<T>;

pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_PROTOCOL_VERSION: &str =
    "nebula-private-liquidity-batch-auction-clearinghouse-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_HEIGHT: u64 = 2_560;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_INTENT_ENCRYPTION_SUITE: &str =
    "ml-kem-1024+threshold-open+sealed-liquidity-intent-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_COMMITMENT_SUITE: &str =
    "solver-sealed-clearing-commitment-shake256-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_RECEIPT_SUITE: &str =
    "zk-confidential-liquidity-settlement-receipt-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-128f-clearing-committee-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_SLASHING_SUITE: &str =
    "fraud-evidence+bond-slash-private-auction-v1";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID: &str = "dxmr-devnet";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS: u64 = 24;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_COMMIT_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_SOLVER_BOND_UNITS: u128 =
    50_000_000_000;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_SPONSOR_BALANCE_UNITS: u128 =
    10_000_000_000;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_LANE_FEE_BPS: u64 = 35;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_SOLVER_REBATE_BPS: u64 = 1_500;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_PROTOCOL_FEE_BPS: u64 = 5;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_BATCH_INTENTS: usize = 768;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_BATCH_NOTIONAL_UNITS: u128 =
    10_000_000_000_000;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_LANES: usize = 128;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_INTENTS: usize = 524_288;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SOLVER_COMMITMENTS: usize = 262_144;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BATCHES: usize = 65_536;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_RECEIPTS: usize = 524_288;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SPONSORS: usize = 32_768;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_ATTESTATIONS: usize = 524_288;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_PUBLIC_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityLaneKind {
    LowFeeSwap,
    MoneroExit,
    StableSwap,
    ContractIntent,
    PerpsHedge,
    LendingRefinance,
    LiquidationBackstop,
    EmergencyUnwind,
}

impl LiquidityLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeSwap => "low_fee_swap",
            Self::MoneroExit => "monero_exit",
            Self::StableSwap => "stable_swap",
            Self::ContractIntent => "contract_intent",
            Self::PerpsHedge => "perps_hedge",
            Self::LendingRefinance => "lending_refinance",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 0,
            Self::LiquidationBackstop => 1,
            Self::MoneroExit => 2,
            Self::PerpsHedge => 3,
            Self::LendingRefinance => 4,
            Self::StableSwap => 5,
            Self::ContractIntent => 6,
            Self::LowFeeSwap => 7,
        }
    }

    pub fn default_fee_bps(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 0,
            Self::LiquidationBackstop => 4,
            Self::MoneroExit => 6,
            Self::PerpsHedge => 8,
            Self::LendingRefinance => 7,
            Self::StableSwap => 5,
            Self::ContractIntent => 9,
            Self::LowFeeSwap => 3,
        }
    }

    pub fn privacy_weight_bps(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 1_400,
            Self::MoneroExit => 1_250,
            Self::LiquidationBackstop => 1_150,
            Self::PerpsHedge => 1_050,
            Self::ContractIntent => 900,
            Self::LendingRefinance => 850,
            Self::StableSwap => 700,
            Self::LowFeeSwap => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    SwapExactIn,
    SwapExactOut,
    AddLiquidity,
    RemoveLiquidity,
    ContractCall,
    MoneroExit,
    Hedge,
    Rebalance,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::ContractCall => "contract_call",
            Self::MoneroExit => "monero_exit",
            Self::Hedge => "hedge",
            Self::Rebalance => "rebalance",
        }
    }

    pub fn default_lane(self) -> LiquidityLaneKind {
        match self {
            Self::SwapExactIn | Self::SwapExactOut => LiquidityLaneKind::LowFeeSwap,
            Self::AddLiquidity | Self::RemoveLiquidity => LiquidityLaneKind::StableSwap,
            Self::ContractCall => LiquidityLaneKind::ContractIntent,
            Self::MoneroExit => LiquidityLaneKind::MoneroExit,
            Self::Hedge => LiquidityLaneKind::PerpsHedge,
            Self::Rebalance => LiquidityLaneKind::LendingRefinance,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Paused,
    Draining,
    Halted,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Halted => "halted",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Queued,
    Committed,
    Included,
    Settled,
    Refunded,
    Cancelled,
    Expired,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Queued => "queued",
            Self::Committed => "committed",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Queued | Self::Committed | Self::Included
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Sealed,
    Bound,
    Selected,
    Settled,
    Slashed,
    Expired,
    Rejected,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Bound => "bound",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Sealed | Self::Bound | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Solving,
    Attested,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solving => "solving",
            Self::Attested => "attested",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Quorum,
    Applied,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Quorum => "quorum",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidClearing,
    SolverEquivocation,
    PrivacyLeak,
    MissingSettlement,
    FeeOvercharge,
    PqSignatureFailure,
    SponsorDefault,
    ChallengeTimeout,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidClearing => "invalid_clearing",
            Self::SolverEquivocation => "solver_equivocation",
            Self::PrivacyLeak => "privacy_leak",
            Self::MissingSettlement => "missing_settlement",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::SponsorDefault => "sponsor_default",
            Self::ChallengeTimeout => "challenge_timeout",
        }
    }

    pub fn default_severity_bps(self) -> u64 {
        match self {
            Self::SolverEquivocation | Self::PrivacyLeak => 10_000,
            Self::InvalidClearing | Self::MissingSettlement => 7_500,
            Self::PqSignatureFailure => 6_000,
            Self::FeeOvercharge => 3_500,
            Self::SponsorDefault => 3_000,
            Self::ChallengeTimeout => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    UnderReview,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub commit_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_solver_bond_units: u128,
    pub min_sponsor_balance_units: u128,
    pub max_lane_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub solver_rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub slash_bps: u64,
    pub max_batch_intents: usize,
    pub max_batch_notional_units: u128,
    pub hash_suite: String,
    pub intent_encryption_suite: String,
    pub solver_commitment_suite: String,
    pub receipt_suite: String,
    pub pq_attestation_suite: String,
    pub slashing_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID
                .to_string(),
            base_asset_id: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID
                .to_string(),
            quote_asset_id: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID
                .to_string(),
            epoch_blocks: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_BATCH_TTL_BLOCKS,
            intent_ttl_blocks:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_INTENT_TTL_BLOCKS,
            commit_ttl_blocks:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_COMMIT_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_RECEIPT_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_solver_bond_units:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_SOLVER_BOND_UNITS,
            min_sponsor_balance_units:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MIN_SPONSOR_BALANCE_UNITS,
            max_lane_fee_bps:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_LANE_FEE_BPS,
            low_fee_target_bps:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_LOW_FEE_TARGET_BPS,
            solver_rebate_bps:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_SOLVER_REBATE_BPS,
            protocol_fee_bps:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_PROTOCOL_FEE_BPS,
            slash_bps: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_SLASH_BPS,
            max_batch_intents:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_BATCH_INTENTS,
            max_batch_notional_units:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEFAULT_MAX_BATCH_NOTIONAL_UNITS,
            hash_suite: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_HASH_SUITE.to_string(),
            intent_encryption_suite:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_INTENT_ENCRYPTION_SUITE.to_string(),
            solver_commitment_suite: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_COMMITMENT_SUITE
                .to_string(),
            receipt_suite: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_RECEIPT_SUITE.to_string(),
            pq_attestation_suite:
                PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_PQ_ATTESTATION_SUITE.to_string(),
            slashing_suite: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_SLASHING_SUITE
                .to_string(),
        }
    }

    pub fn validate(&self) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.fee_asset_id.is_empty()
            || self.base_asset_id.is_empty()
            || self.quote_asset_id.is_empty()
            || self.hash_suite.is_empty()
            || self.intent_encryption_suite.is_empty()
            || self.solver_commitment_suite.is_empty()
            || self.receipt_suite.is_empty()
            || self.pq_attestation_suite.is_empty()
            || self.slashing_suite.is_empty()
        {
            return Err(
                "private liquidity clearinghouse config labels must be populated".to_string(),
            );
        }
        if self.schema_version == 0
            || self.epoch_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.intent_ttl_blocks == 0
            || self.commit_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
            || self.challenge_window_blocks == 0
            || self.min_privacy_set_size == 0
            || self.min_solver_bond_units == 0
            || self.min_sponsor_balance_units == 0
            || self.max_batch_intents == 0
            || self.max_batch_notional_units == 0
        {
            return Err(
                "private liquidity clearinghouse config numeric values must be positive"
                    .to_string(),
            );
        }
        if self.min_pq_security_bits < 192 {
            return Err("private liquidity clearinghouse pq security bits too low".to_string());
        }
        if self.max_lane_fee_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
            || self.low_fee_target_bps > self.max_lane_fee_bps
            || self.solver_rebate_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
            || self.protocol_fee_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
            || self.slash_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity clearinghouse bps config is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "commit_ttl_blocks": self.commit_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_solver_bond_units": self.min_solver_bond_units.to_string(),
            "min_sponsor_balance_units": self.min_sponsor_balance_units.to_string(),
            "max_lane_fee_bps": self.max_lane_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "solver_rebate_bps": self.solver_rebate_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "slash_bps": self.slash_bps,
            "max_batch_intents": self.max_batch_intents,
            "max_batch_notional_units": self.max_batch_notional_units.to_string(),
            "hash_suite": self.hash_suite,
            "intent_encryption_suite": self.intent_encryption_suite,
            "solver_commitment_suite": self.solver_commitment_suite,
            "receipt_suite": self.receipt_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "slashing_suite": self.slashing_suite,
        })
    }

    pub fn config_root(&self) -> String {
        plbac_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_count: u64,
    pub intent_count: u64,
    pub solver_commitment_count: u64,
    pub batch_count: u64,
    pub receipt_count: u64,
    pub sponsor_count: u64,
    pub attestation_count: u64,
    pub challenge_count: u64,
    pub slashed_solver_count: u64,
    pub slashed_sponsor_count: u64,
    pub public_event_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "intent_count": self.intent_count,
            "solver_commitment_count": self.solver_commitment_count,
            "batch_count": self.batch_count,
            "receipt_count": self.receipt_count,
            "sponsor_count": self.sponsor_count,
            "attestation_count": self.attestation_count,
            "challenge_count": self.challenge_count,
            "slashed_solver_count": self.slashed_solver_count,
            "slashed_sponsor_count": self.slashed_sponsor_count,
            "public_event_count": self.public_event_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub intent_root: String,
    pub solver_commitment_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub sponsor_root: String,
    pub attestation_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
    pub solver_bond_root: String,
    pub sponsor_balance_root: String,
    pub public_event_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "intent_root": self.intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "sponsor_root": self.sponsor_root,
            "attestation_root": self.attestation_root,
            "challenge_root": self.challenge_root,
            "nullifier_root": self.nullifier_root,
            "solver_bond_root": self.solver_bond_root,
            "sponsor_balance_root": self.sponsor_balance_root,
            "public_event_root": self.public_event_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionLane {
    pub lane_id: String,
    pub kind: LiquidityLaneKind,
    pub status: LaneStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub sponsor_id: Option<String>,
    pub maker_commitment_root: String,
    pub taker_commitment_root: String,
    pub allowed_contract_root: String,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_batch_intents: usize,
    pub max_batch_notional_units: u128,
    pub opened_height: u64,
    pub last_updated_height: u64,
}

impl AuctionLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        kind: LiquidityLaneKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        fee_asset_id: &str,
        sponsor_id: Option<String>,
        max_fee_bps: u64,
        min_privacy_set_size: u64,
        max_batch_intents: usize,
        max_batch_notional_units: u128,
        height: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if lane_id.is_empty()
            || base_asset_id.is_empty()
            || quote_asset_id.is_empty()
            || fee_asset_id.is_empty()
        {
            return Err("private liquidity lane identifiers must be populated".to_string());
        }
        if max_batch_intents == 0
            || min_privacy_set_size == 0
            || max_batch_notional_units == 0
            || max_fee_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity lane limits are invalid".to_string());
        }
        Ok(Self {
            lane_id: lane_id.to_string(),
            kind,
            status: LaneStatus::Open,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            sponsor_id,
            maker_commitment_root: empty_root("LANE-MAKER-COMMITMENTS"),
            taker_commitment_root: empty_root("LANE-TAKER-COMMITMENTS"),
            allowed_contract_root: empty_root("LANE-ALLOWED-CONTRACTS"),
            max_fee_bps,
            min_privacy_set_size,
            max_batch_intents,
            max_batch_notional_units,
            opened_height: height,
            last_updated_height: height,
        })
    }

    pub fn accepts_intents(&self) -> bool {
        self.status.accepts_intents()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_id": self.sponsor_id,
            "maker_commitment_root": self.maker_commitment_root,
            "taker_commitment_root": self.taker_commitment_root,
            "allowed_contract_root": self.allowed_contract_root,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_batch_intents": self.max_batch_intents,
            "max_batch_notional_units": self.max_batch_notional_units.to_string(),
            "opened_height": self.opened_height,
            "last_updated_height": self.last_updated_height,
            "priority": self.kind.priority(),
            "privacy_weight_bps": self.kind.privacy_weight_bps(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub lane_id: String,
    pub kind: IntentKind,
    pub owner_commitment: String,
    pub encrypted_payload_hash: String,
    pub ciphertext_commitment: String,
    pub nullifier_hash: String,
    pub max_fee_bps: u64,
    pub notional_units: u128,
    pub min_output_commitment: String,
    pub sponsor_id: Option<String>,
    pub arrival_height: u64,
    pub expiry_height: u64,
    pub status: IntentStatus,
    pub privacy_set_size: u64,
    pub hook_contract_commitment: Option<String>,
    pub metadata_root: String,
}

impl EncryptedIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        kind: IntentKind,
        owner_commitment: &str,
        encrypted_payload_hash: &str,
        ciphertext_commitment: &str,
        nullifier_hash: &str,
        max_fee_bps: u64,
        notional_units: u128,
        min_output_commitment: &str,
        sponsor_id: Option<String>,
        privacy_set_size: u64,
        hook_contract_commitment: Option<String>,
        metadata_root: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if lane_id.is_empty()
            || owner_commitment.is_empty()
            || encrypted_payload_hash.is_empty()
            || ciphertext_commitment.is_empty()
            || nullifier_hash.is_empty()
            || min_output_commitment.is_empty()
            || metadata_root.is_empty()
        {
            return Err("private liquidity intent commitments must be populated".to_string());
        }
        if ttl_blocks == 0
            || notional_units == 0
            || privacy_set_size == 0
            || max_fee_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity intent values are invalid".to_string());
        }
        let expiry_height = height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "lane_id": lane_id,
            "kind": kind.as_str(),
            "owner_commitment": owner_commitment,
            "encrypted_payload_hash": encrypted_payload_hash,
            "ciphertext_commitment": ciphertext_commitment,
            "nullifier_hash": nullifier_hash,
            "arrival_height": height,
            "expiry_height": expiry_height,
            "metadata_root": metadata_root,
        });
        Ok(Self {
            intent_id: plbac_hash("INTENT-ID", &[HashPart::Json(&record)]),
            lane_id: lane_id.to_string(),
            kind,
            owner_commitment: owner_commitment.to_string(),
            encrypted_payload_hash: encrypted_payload_hash.to_string(),
            ciphertext_commitment: ciphertext_commitment.to_string(),
            nullifier_hash: nullifier_hash.to_string(),
            max_fee_bps,
            notional_units,
            min_output_commitment: min_output_commitment.to_string(),
            sponsor_id,
            arrival_height: height,
            expiry_height,
            status: IntentStatus::Encrypted,
            privacy_set_size,
            hook_contract_commitment,
            metadata_root: metadata_root.to_string(),
        })
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expiry_height && self.status.live()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "ciphertext_commitment": self.ciphertext_commitment,
            "nullifier_hash": self.nullifier_hash,
            "max_fee_bps": self.max_fee_bps,
            "notional_units": self.notional_units.to_string(),
            "min_output_commitment": self.min_output_commitment,
            "sponsor_id": self.sponsor_id,
            "arrival_height": self.arrival_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "hook_contract_commitment": self.hook_contract_commitment,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub solver_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub sealed_solution_hash: String,
    pub solver_bond_commitment: String,
    pub max_clear_fee_bps: u64,
    pub claimed_surplus_commitment: String,
    pub pq_identity_commitment: String,
    pub commitment_height: u64,
    pub expiry_height: u64,
    pub status: SolverCommitmentStatus,
    pub selected_score: u64,
}

impl SolverCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_id: &str,
        batch_id: &str,
        lane_id: &str,
        sealed_solution_hash: &str,
        solver_bond_commitment: &str,
        max_clear_fee_bps: u64,
        claimed_surplus_commitment: &str,
        pq_identity_commitment: &str,
        selected_score: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if solver_id.is_empty()
            || batch_id.is_empty()
            || lane_id.is_empty()
            || sealed_solution_hash.is_empty()
            || solver_bond_commitment.is_empty()
            || claimed_surplus_commitment.is_empty()
            || pq_identity_commitment.is_empty()
        {
            return Err("private liquidity solver commitment labels must be populated".to_string());
        }
        if ttl_blocks == 0
            || max_clear_fee_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity solver commitment limits are invalid".to_string());
        }
        let expiry_height = height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "solver_id": solver_id,
            "batch_id": batch_id,
            "lane_id": lane_id,
            "sealed_solution_hash": sealed_solution_hash,
            "solver_bond_commitment": solver_bond_commitment,
            "commitment_height": height,
            "expiry_height": expiry_height,
        });
        Ok(Self {
            commitment_id: plbac_hash("SOLVER-COMMITMENT-ID", &[HashPart::Json(&record)]),
            solver_id: solver_id.to_string(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            sealed_solution_hash: sealed_solution_hash.to_string(),
            solver_bond_commitment: solver_bond_commitment.to_string(),
            max_clear_fee_bps,
            claimed_surplus_commitment: claimed_surplus_commitment.to_string(),
            pq_identity_commitment: pq_identity_commitment.to_string(),
            commitment_height: height,
            expiry_height,
            status: SolverCommitmentStatus::Sealed,
            selected_score,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "solver_id": self.solver_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "sealed_solution_hash": self.sealed_solution_hash,
            "solver_bond_commitment": self.solver_bond_commitment,
            "max_clear_fee_bps": self.max_clear_fee_bps,
            "claimed_surplus_commitment": self.claimed_surplus_commitment,
            "pq_identity_commitment": self.pq_identity_commitment,
            "commitment_height": self.commitment_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "selected_score": self.selected_score,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("SOLVER-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub open_height: u64,
    pub seal_height: u64,
    pub settlement_deadline_height: u64,
    pub status: BatchStatus,
    pub intent_ids: BTreeSet<String>,
    pub solver_commitment_ids: BTreeSet<String>,
    pub selected_commitment_id: Option<String>,
    pub clearing_price_commitment: String,
    pub total_notional_units: u128,
    pub protocol_fee_commitment: String,
    pub surplus_commitment: String,
    pub intent_root: String,
    pub solver_commitment_root: String,
    pub settlement_plan_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
}

impl ClearingBatch {
    pub fn new(
        lane_id: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if lane_id.is_empty() || ttl_blocks == 0 {
            return Err("private liquidity clearing batch parameters are invalid".to_string());
        }
        let seal_height = height.saturating_add(ttl_blocks);
        let settlement_deadline_height = seal_height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "lane_id": lane_id,
            "open_height": height,
            "seal_height": seal_height,
        });
        Ok(Self {
            batch_id: plbac_hash("BATCH-ID", &[HashPart::Json(&record)]),
            lane_id: lane_id.to_string(),
            open_height: height,
            seal_height,
            settlement_deadline_height,
            status: BatchStatus::Open,
            intent_ids: BTreeSet::new(),
            solver_commitment_ids: BTreeSet::new(),
            selected_commitment_id: None,
            clearing_price_commitment: empty_root("BATCH-CLEARING-PRICE"),
            total_notional_units: 0,
            protocol_fee_commitment: empty_root("BATCH-PROTOCOL-FEE"),
            surplus_commitment: empty_root("BATCH-SURPLUS"),
            intent_root: empty_root("BATCH-INTENTS"),
            solver_commitment_root: empty_root("BATCH-SOLVER-COMMITMENTS"),
            settlement_plan_root: empty_root("BATCH-SETTLEMENT-PLAN"),
            receipt_root: empty_root("BATCH-RECEIPTS"),
            attestation_root: empty_root("BATCH-ATTESTATIONS"),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.intent_root = set_root("BATCH-INTENT-ID", &self.intent_ids);
        self.solver_commitment_root =
            set_root("BATCH-SOLVER-COMMITMENT-ID", &self.solver_commitment_ids);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "open_height": self.open_height,
            "seal_height": self.seal_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
            "intent_ids": self.intent_ids,
            "solver_commitment_ids": self.solver_commitment_ids,
            "selected_commitment_id": self.selected_commitment_id,
            "clearing_price_commitment": self.clearing_price_commitment,
            "total_notional_units": self.total_notional_units.to_string(),
            "protocol_fee_commitment": self.protocol_fee_commitment,
            "surplus_commitment": self.surplus_commitment,
            "intent_root": self.intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "settlement_plan_root": self.settlement_plan_root,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub lane_id: String,
    pub output_note_commitment: String,
    pub fee_note_commitment: String,
    pub rebate_note_commitment: String,
    pub settlement_nullifier: String,
    pub receipt_proof_root: String,
    pub settled_height: u64,
    pub expiry_height: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        intent_id: &str,
        solver_id: &str,
        lane_id: &str,
        output_note_commitment: &str,
        fee_note_commitment: &str,
        rebate_note_commitment: &str,
        settlement_nullifier: &str,
        receipt_proof_root: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if batch_id.is_empty()
            || intent_id.is_empty()
            || solver_id.is_empty()
            || lane_id.is_empty()
            || output_note_commitment.is_empty()
            || fee_note_commitment.is_empty()
            || rebate_note_commitment.is_empty()
            || settlement_nullifier.is_empty()
            || receipt_proof_root.is_empty()
            || ttl_blocks == 0
        {
            return Err("private liquidity settlement receipt parameters are invalid".to_string());
        }
        let expiry_height = height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "batch_id": batch_id,
            "intent_id": intent_id,
            "solver_id": solver_id,
            "settlement_nullifier": settlement_nullifier,
            "settled_height": height,
        });
        Ok(Self {
            receipt_id: plbac_hash("RECEIPT-ID", &[HashPart::Json(&record)]),
            batch_id: batch_id.to_string(),
            intent_id: intent_id.to_string(),
            solver_id: solver_id.to_string(),
            lane_id: lane_id.to_string(),
            output_note_commitment: output_note_commitment.to_string(),
            fee_note_commitment: fee_note_commitment.to_string(),
            rebate_note_commitment: rebate_note_commitment.to_string(),
            settlement_nullifier: settlement_nullifier.to_string(),
            receipt_proof_root: receipt_proof_root.to_string(),
            settled_height: height,
            expiry_height,
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "lane_id": self.lane_id,
            "output_note_commitment": self.output_note_commitment,
            "fee_note_commitment": self.fee_note_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "settlement_nullifier": self.settlement_nullifier,
            "receipt_proof_root": self.receipt_proof_root,
            "settled_height": self.settled_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySponsorAccount {
    pub sponsor_id: String,
    pub owner_commitment: String,
    pub status: SponsorStatus,
    pub fee_asset_id: String,
    pub balance_commitment: String,
    pub reserved_commitment: String,
    pub spend_nullifier_root: String,
    pub lane_ids: BTreeSet<String>,
    pub max_exposure_units: u128,
    pub fee_discount_bps: u64,
    pub opened_height: u64,
    pub last_updated_height: u64,
}

impl LiquiditySponsorAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        fee_asset_id: &str,
        balance_commitment: &str,
        reserved_commitment: &str,
        max_exposure_units: u128,
        fee_discount_bps: u64,
        height: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if owner_commitment.is_empty()
            || fee_asset_id.is_empty()
            || balance_commitment.is_empty()
            || reserved_commitment.is_empty()
            || max_exposure_units == 0
            || fee_discount_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity sponsor account parameters are invalid".to_string());
        }
        let record = json!({
            "chain_id": CHAIN_ID,
            "owner_commitment": owner_commitment,
            "fee_asset_id": fee_asset_id,
            "height": height,
        });
        Ok(Self {
            sponsor_id: plbac_hash("SPONSOR-ID", &[HashPart::Json(&record)]),
            owner_commitment: owner_commitment.to_string(),
            status: SponsorStatus::Active,
            fee_asset_id: fee_asset_id.to_string(),
            balance_commitment: balance_commitment.to_string(),
            reserved_commitment: reserved_commitment.to_string(),
            spend_nullifier_root: empty_root("SPONSOR-SPEND-NULLIFIERS"),
            lane_ids: BTreeSet::new(),
            max_exposure_units,
            fee_discount_bps,
            opened_height: height,
            last_updated_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "balance_commitment": self.balance_commitment,
            "reserved_commitment": self.reserved_commitment,
            "spend_nullifier_root": self.spend_nullifier_root,
            "lane_ids": self.lane_ids,
            "max_exposure_units": self.max_exposure_units.to_string(),
            "fee_discount_bps": self.fee_discount_bps,
            "opened_height": self.opened_height,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("SPONSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub committee_root: String,
    pub signer_bitmap_commitment: String,
    pub signature_aggregate_commitment: String,
    pub attested_root: String,
    pub security_bits: u16,
    pub quorum_bps: u64,
    pub height: u64,
    pub expiry_height: u64,
    pub status: AttestationStatus,
}

impl PqCommitteeAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        lane_id: &str,
        committee_root: &str,
        signer_bitmap_commitment: &str,
        signature_aggregate_commitment: &str,
        attested_root: &str,
        security_bits: u16,
        quorum_bps: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if batch_id.is_empty()
            || lane_id.is_empty()
            || committee_root.is_empty()
            || signer_bitmap_commitment.is_empty()
            || signature_aggregate_commitment.is_empty()
            || attested_root.is_empty()
            || ttl_blocks == 0
            || quorum_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity pq attestation parameters are invalid".to_string());
        }
        let expiry_height = height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "batch_id": batch_id,
            "lane_id": lane_id,
            "committee_root": committee_root,
            "attested_root": attested_root,
            "height": height,
        });
        Ok(Self {
            attestation_id: plbac_hash("ATTESTATION-ID", &[HashPart::Json(&record)]),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            committee_root: committee_root.to_string(),
            signer_bitmap_commitment: signer_bitmap_commitment.to_string(),
            signature_aggregate_commitment: signature_aggregate_commitment.to_string(),
            attested_root: attested_root.to_string(),
            security_bits,
            quorum_bps,
            height,
            expiry_height,
            status: AttestationStatus::Proposed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "committee_root": self.committee_root,
            "signer_bitmap_commitment": self.signer_bitmap_commitment,
            "signature_aggregate_commitment": self.signature_aggregate_commitment,
            "attested_root": self.attested_root,
            "security_bits": self.security_bits,
            "quorum_bps": self.quorum_bps,
            "height": self.height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub kind: EvidenceKind,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub affected_batch_id: Option<String>,
    pub affected_solver_id: Option<String>,
    pub affected_sponsor_id: Option<String>,
    pub severity_bps: u64,
    pub bond_slash_commitment: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub resolved_height: Option<u64>,
    pub status: ChallengeStatus,
}

impl ChallengeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EvidenceKind,
        target_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        affected_batch_id: Option<String>,
        affected_solver_id: Option<String>,
        affected_sponsor_id: Option<String>,
        severity_bps: u64,
        bond_slash_commitment: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<Self> {
        if target_id.is_empty()
            || challenger_commitment.is_empty()
            || evidence_root.is_empty()
            || bond_slash_commitment.is_empty()
            || ttl_blocks == 0
            || severity_bps > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BPS
        {
            return Err("private liquidity challenge evidence parameters are invalid".to_string());
        }
        let expiry_height = height.saturating_add(ttl_blocks);
        let record = json!({
            "chain_id": CHAIN_ID,
            "kind": kind.as_str(),
            "target_id": target_id,
            "challenger_commitment": challenger_commitment,
            "evidence_root": evidence_root,
            "height": height,
        });
        Ok(Self {
            challenge_id: plbac_hash("CHALLENGE-ID", &[HashPart::Json(&record)]),
            kind,
            target_id: target_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            affected_batch_id,
            affected_solver_id,
            affected_sponsor_id,
            severity_bps,
            bond_slash_commitment: bond_slash_commitment.to_string(),
            opened_height: height,
            expiry_height,
            resolved_height: None,
            status: ChallengeStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "affected_batch_id": self.affected_batch_id,
            "affected_solver_id": self.affected_solver_id,
            "affected_sponsor_id": self.affected_sponsor_id,
            "severity_bps": self.severity_bps,
            "bond_slash_commitment": self.bond_slash_commitment,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "resolved_height": self.resolved_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lanes: BTreeMap<String, AuctionLane>,
    pub encrypted_intents: BTreeMap<String, EncryptedIntent>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub clearing_batches: BTreeMap<String, ClearingBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub sponsor_accounts: BTreeMap<String, LiquiditySponsorAccount>,
    pub pq_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub nullifiers: BTreeSet<String>,
    pub solver_bonds: BTreeMap<String, String>,
    pub sponsor_balances: BTreeMap<String, String>,
    pub public_events: Vec<Value>,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            height: PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            encrypted_intents: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            sponsor_accounts: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            challenges: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            solver_bonds: BTreeMap::new(),
            sponsor_balances: BTreeMap::new(),
            public_events: Vec::new(),
            counters: Counters::default(),
        };
        let _ = state.open_lane(
            LiquidityLaneKind::LowFeeSwap,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID,
            None,
        );
        let _ = state.open_lane(
            LiquidityLaneKind::MoneroExit,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID,
            PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID,
            None,
        );
        state
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        if height < self.height {
            return Err("private liquidity clearinghouse height cannot decrease".to_string());
        }
        self.height = height;
        self.expire_records();
        self.push_event("height_updated", json!({ "height": height }))?;
        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        self.update_height(height)
    }

    pub fn validate(&self) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        self.config.validate()?;
        if self.lanes.len() > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_LANES
            || self.encrypted_intents.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_INTENTS
            || self.solver_commitments.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SOLVER_COMMITMENTS
            || self.clearing_batches.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BATCHES
            || self.settlement_receipts.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_RECEIPTS
            || self.sponsor_accounts.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SPONSORS
            || self.pq_attestations.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_ATTESTATIONS
            || self.challenges.len() > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_CHALLENGES
            || self.public_events.len()
                > PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_PUBLIC_EVENTS
        {
            return Err("private liquidity clearinghouse capacity exceeded".to_string());
        }
        for lane in self.lanes.values() {
            if lane.max_fee_bps > self.config.max_lane_fee_bps
                || lane.min_privacy_set_size < self.config.min_privacy_set_size
                || lane.max_batch_intents > self.config.max_batch_intents
                || lane.max_batch_notional_units > self.config.max_batch_notional_units
            {
                return Err("private liquidity lane violates configured bounds".to_string());
            }
        }
        for intent in self.encrypted_intents.values() {
            if !self.lanes.contains_key(&intent.lane_id) {
                return Err("private liquidity intent references missing lane".to_string());
            }
            if intent.arrival_height > intent.expiry_height {
                return Err("private liquidity intent height window is invalid".to_string());
            }
        }
        for batch in self.clearing_batches.values() {
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err("private liquidity batch references missing lane".to_string());
            }
            if batch.open_height > batch.seal_height
                || batch.seal_height > batch.settlement_deadline_height
            {
                return Err("private liquidity batch height window is invalid".to_string());
            }
        }
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn roots(&self) -> Roots {
        let lane_root = map_root("PLBAC-LANES", &self.lanes);
        let intent_root = map_root("PLBAC-INTENTS", &self.encrypted_intents);
        let solver_commitment_root = map_root("PLBAC-SOLVER-COMMITMENTS", &self.solver_commitments);
        let batch_root = map_root("PLBAC-BATCHES", &self.clearing_batches);
        let receipt_root = map_root("PLBAC-RECEIPTS", &self.settlement_receipts);
        let sponsor_root = map_root("PLBAC-SPONSORS", &self.sponsor_accounts);
        let attestation_root = map_root("PLBAC-ATTESTATIONS", &self.pq_attestations);
        let challenge_root = map_root("PLBAC-CHALLENGES", &self.challenges);
        let nullifier_root = set_root("PLBAC-NULLIFIERS", &self.nullifiers);
        let solver_bond_root = string_map_root("PLBAC-SOLVER-BONDS", &self.solver_bonds);
        let sponsor_balance_root =
            string_map_root("PLBAC-SPONSOR-BALANCES", &self.sponsor_balances);
        let public_event_root = merkle_root("PLBAC-PUBLIC-EVENTS", &self.public_events);
        let counters_record = self.counters.public_record();
        let counters_root = root_from_record("COUNTERS", &counters_record);
        let config_root = self.config.config_root();
        let state_record = json!({
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config_root": config_root,
            "lane_root": lane_root,
            "intent_root": intent_root,
            "solver_commitment_root": solver_commitment_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "sponsor_root": sponsor_root,
            "attestation_root": attestation_root,
            "challenge_root": challenge_root,
            "nullifier_root": nullifier_root,
            "solver_bond_root": solver_bond_root,
            "sponsor_balance_root": sponsor_balance_root,
            "public_event_root": public_event_root,
            "counters_root": counters_root,
        });
        let state_root = root_from_record("STATE", &state_record);
        Roots {
            config_root,
            lane_root,
            intent_root,
            solver_commitment_root,
            batch_root,
            receipt_root,
            sponsor_root,
            attestation_root,
            challenge_root,
            nullifier_root,
            solver_bond_root,
            sponsor_balance_root,
            public_event_root,
            counters_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol": "private_liquidity_batch_auction_clearinghouse",
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters.public_record(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_lane(
        &mut self,
        kind: LiquidityLaneKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        fee_asset_id: &str,
        sponsor_id: Option<String>,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.lanes.len() >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_LANES {
            return Err("private liquidity lane capacity reached".to_string());
        }
        if let Some(id) = sponsor_id.as_ref() {
            if !self.sponsor_accounts.contains_key(id) {
                return Err("private liquidity lane sponsor is unknown".to_string());
            }
        }
        let lane_record = json!({
            "chain_id": self.config.chain_id,
            "kind": kind.as_str(),
            "base_asset_id": base_asset_id,
            "quote_asset_id": quote_asset_id,
            "fee_asset_id": fee_asset_id,
            "height": self.height,
            "ordinal": self.counters.lane_count,
        });
        let lane_id = plbac_hash("LANE-ID", &[HashPart::Json(&lane_record)]);
        let lane = AuctionLane::new(
            &lane_id,
            kind,
            base_asset_id,
            quote_asset_id,
            fee_asset_id,
            sponsor_id.clone(),
            kind.default_fee_bps().min(self.config.max_lane_fee_bps),
            self.config.min_privacy_set_size,
            self.config.max_batch_intents,
            self.config.max_batch_notional_units,
            self.height,
        )?;
        self.lanes.insert(lane_id.clone(), lane);
        if let Some(id) = sponsor_id {
            if let Some(sponsor) = self.sponsor_accounts.get_mut(&id) {
                sponsor.lane_ids.insert(lane_id.clone());
                sponsor.last_updated_height = self.height;
            }
        }
        self.counters.lane_count = self.counters.lane_count.saturating_add(1);
        self.push_event("lane_opened", json!({ "lane_id": lane_id }))?;
        Ok(lane_id)
    }

    pub fn update_lane_status(
        &mut self,
        lane_id: &str,
        status: LaneStatus,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| "private liquidity lane not found".to_string())?;
        lane.status = status;
        lane.last_updated_height = self.height;
        self.push_event(
            "lane_status_updated",
            json!({ "lane_id": lane_id, "status": status.as_str() }),
        )
    }

    pub fn register_sponsor_account(
        &mut self,
        owner_commitment: &str,
        balance_commitment: &str,
        reserved_commitment: &str,
        max_exposure_units: u128,
        fee_discount_bps: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.sponsor_accounts.len() >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SPONSORS
        {
            return Err("private liquidity sponsor capacity reached".to_string());
        }
        if max_exposure_units < self.config.min_sponsor_balance_units {
            return Err(
                "private liquidity sponsor exposure is below configured minimum".to_string(),
            );
        }
        let sponsor = LiquiditySponsorAccount::new(
            owner_commitment,
            &self.config.fee_asset_id,
            balance_commitment,
            reserved_commitment,
            max_exposure_units,
            fee_discount_bps,
            self.height,
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsor_balances
            .insert(sponsor_id.clone(), balance_commitment.to_string());
        self.sponsor_accounts.insert(sponsor_id.clone(), sponsor);
        self.counters.sponsor_count = self.counters.sponsor_count.saturating_add(1);
        self.push_event(
            "sponsor_registered",
            json!({ "sponsor_id": sponsor_id, "max_exposure_units": max_exposure_units.to_string() }),
        )?;
        Ok(sponsor_id)
    }

    pub fn update_sponsor_status(
        &mut self,
        sponsor_id: &str,
        status: SponsorStatus,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        let sponsor = self
            .sponsor_accounts
            .get_mut(sponsor_id)
            .ok_or_else(|| "private liquidity sponsor not found".to_string())?;
        sponsor.status = status;
        sponsor.last_updated_height = self.height;
        self.push_event(
            "sponsor_status_updated",
            json!({ "sponsor_id": sponsor_id, "status": status.as_str() }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_encrypted_intent(
        &mut self,
        lane_id: &str,
        kind: IntentKind,
        owner_commitment: &str,
        encrypted_payload_hash: &str,
        ciphertext_commitment: &str,
        nullifier_hash: &str,
        max_fee_bps: u64,
        notional_units: u128,
        min_output_commitment: &str,
        sponsor_id: Option<String>,
        hook_contract_commitment: Option<String>,
        metadata_root: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.encrypted_intents.len() >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_INTENTS
        {
            return Err("private liquidity intent capacity reached".to_string());
        }
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "private liquidity intent lane not found".to_string())?;
        if !lane.accepts_intents() {
            return Err("private liquidity lane is not accepting intents".to_string());
        }
        if max_fee_bps > lane.max_fee_bps || notional_units > lane.max_batch_notional_units {
            return Err("private liquidity intent exceeds lane limits".to_string());
        }
        if self.nullifiers.contains(nullifier_hash) {
            return Err("private liquidity intent nullifier already used".to_string());
        }
        if let Some(id) = sponsor_id.as_ref() {
            let sponsor = self
                .sponsor_accounts
                .get(id)
                .ok_or_else(|| "private liquidity intent sponsor not found".to_string())?;
            if !sponsor.status.can_sponsor() {
                return Err("private liquidity intent sponsor is unavailable".to_string());
            }
        }
        let intent = EncryptedIntent::new(
            lane_id,
            kind,
            owner_commitment,
            encrypted_payload_hash,
            ciphertext_commitment,
            nullifier_hash,
            max_fee_bps,
            notional_units,
            min_output_commitment,
            sponsor_id,
            lane.min_privacy_set_size,
            hook_contract_commitment,
            metadata_root,
            self.height,
            self.config.intent_ttl_blocks,
        )?;
        let intent_id = intent.intent_id.clone();
        self.nullifiers.insert(nullifier_hash.to_string());
        self.encrypted_intents.insert(intent_id.clone(), intent);
        self.counters.intent_count = self.counters.intent_count.saturating_add(1);
        self.push_event(
            "intent_submitted",
            json!({ "intent_id": intent_id, "lane_id": lane_id, "kind": kind.as_str() }),
        )?;
        Ok(intent_id)
    }

    pub fn open_clearing_batch(
        &mut self,
        lane_id: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.clearing_batches.len() >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_BATCHES
        {
            return Err("private liquidity batch capacity reached".to_string());
        }
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "private liquidity batch lane not found".to_string())?;
        if !lane.accepts_intents() {
            return Err("private liquidity batch lane is not open".to_string());
        }
        let batch = ClearingBatch::new(lane_id, self.height, self.config.batch_ttl_blocks)?;
        let batch_id = batch.batch_id.clone();
        self.clearing_batches.insert(batch_id.clone(), batch);
        self.counters.batch_count = self.counters.batch_count.saturating_add(1);
        self.push_event(
            "batch_opened",
            json!({ "batch_id": batch_id, "lane_id": lane_id }),
        )?;
        Ok(batch_id)
    }

    pub fn queue_intent_into_batch(
        &mut self,
        batch_id: &str,
        intent_id: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        let (lane_id, max_batch_intents, max_batch_notional_units) = {
            let batch = self
                .clearing_batches
                .get(batch_id)
                .ok_or_else(|| "private liquidity batch not found".to_string())?;
            let lane = self
                .lanes
                .get(&batch.lane_id)
                .ok_or_else(|| "private liquidity batch lane not found".to_string())?;
            (
                batch.lane_id.clone(),
                lane.max_batch_intents,
                lane.max_batch_notional_units,
            )
        };
        let intent_notional = {
            let intent = self
                .encrypted_intents
                .get(intent_id)
                .ok_or_else(|| "private liquidity intent not found".to_string())?;
            if intent.lane_id != lane_id {
                return Err("private liquidity intent lane mismatch".to_string());
            }
            if intent.expired_at(self.height) {
                return Err("private liquidity intent is expired".to_string());
            }
            intent.notional_units
        };
        let batch = self
            .clearing_batches
            .get_mut(batch_id)
            .ok_or_else(|| "private liquidity batch not found".to_string())?;
        if !batch.status.accepts_intents() {
            return Err("private liquidity batch is not accepting intents".to_string());
        }
        if batch.intent_ids.len() >= max_batch_intents {
            return Err("private liquidity batch intent capacity reached".to_string());
        }
        let next_notional = batch.total_notional_units.saturating_add(intent_notional);
        if next_notional > max_batch_notional_units {
            return Err("private liquidity batch notional capacity reached".to_string());
        }
        batch.intent_ids.insert(intent_id.to_string());
        batch.total_notional_units = next_notional;
        batch.refresh_roots();
        if let Some(intent) = self.encrypted_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Queued;
        }
        self.push_event(
            "intent_queued",
            json!({ "batch_id": batch_id, "intent_id": intent_id }),
        )
    }

    pub fn seal_batch(
        &mut self,
        batch_id: &str,
        clearing_price_commitment: &str,
        settlement_plan_root: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        if clearing_price_commitment.is_empty() || settlement_plan_root.is_empty() {
            return Err("private liquidity batch seal commitments must be populated".to_string());
        }
        let intent_count = {
            let batch = self
                .clearing_batches
                .get_mut(batch_id)
                .ok_or_else(|| "private liquidity batch not found".to_string())?;
            if batch.intent_ids.len() < self.config.min_privacy_set_size as usize {
                return Err("private liquidity batch privacy set is too small".to_string());
            }
            if self.height > batch.seal_height {
                return Err("private liquidity batch seal window elapsed".to_string());
            }
            batch.status = BatchStatus::Sealed;
            batch.clearing_price_commitment = clearing_price_commitment.to_string();
            batch.settlement_plan_root = settlement_plan_root.to_string();
            batch.intent_ids.len()
        };
        self.push_event(
            "batch_sealed",
            json!({ "batch_id": batch_id, "intent_count": intent_count }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_solver_commitment(
        &mut self,
        batch_id: &str,
        solver_id: &str,
        sealed_solution_hash: &str,
        solver_bond_commitment: &str,
        max_clear_fee_bps: u64,
        claimed_surplus_commitment: &str,
        pq_identity_commitment: &str,
        selected_score: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.solver_commitments.len()
            >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_SOLVER_COMMITMENTS
        {
            return Err("private liquidity solver commitment capacity reached".to_string());
        }
        let lane_id = {
            let batch = self
                .clearing_batches
                .get(batch_id)
                .ok_or_else(|| "private liquidity solver batch not found".to_string())?;
            if !matches!(batch.status, BatchStatus::Sealed | BatchStatus::Solving) {
                return Err(
                    "private liquidity batch is not accepting solver commitments".to_string(),
                );
            }
            batch.lane_id.clone()
        };
        if max_clear_fee_bps > self.config.max_lane_fee_bps {
            return Err("private liquidity solver fee exceeds configured max".to_string());
        }
        let commitment = SolverCommitment::new(
            solver_id,
            batch_id,
            &lane_id,
            sealed_solution_hash,
            solver_bond_commitment,
            max_clear_fee_bps,
            claimed_surplus_commitment,
            pq_identity_commitment,
            selected_score,
            self.height,
            self.config.commit_ttl_blocks,
        )?;
        let commitment_id = commitment.commitment_id.clone();
        self.solver_bonds
            .insert(solver_id.to_string(), solver_bond_commitment.to_string());
        self.solver_commitments
            .insert(commitment_id.clone(), commitment);
        if let Some(batch) = self.clearing_batches.get_mut(batch_id) {
            batch.status = BatchStatus::Solving;
            batch.solver_commitment_ids.insert(commitment_id.clone());
            batch.refresh_roots();
        }
        self.counters.solver_commitment_count =
            self.counters.solver_commitment_count.saturating_add(1);
        self.push_event(
            "solver_commitment_submitted",
            json!({ "batch_id": batch_id, "commitment_id": commitment_id, "solver_id": solver_id }),
        )?;
        Ok(commitment_id)
    }

    pub fn select_solver_commitment(
        &mut self,
        batch_id: &str,
        commitment_id: &str,
        protocol_fee_commitment: &str,
        surplus_commitment: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        if protocol_fee_commitment.is_empty() || surplus_commitment.is_empty() {
            return Err(
                "private liquidity selected solver commitments must be populated".to_string(),
            );
        }
        let commitment = self
            .solver_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "private liquidity solver commitment not found".to_string())?;
        if commitment.batch_id != batch_id || !commitment.status.usable() {
            return Err("private liquidity solver commitment cannot be selected".to_string());
        }
        commitment.status = SolverCommitmentStatus::Selected;
        let batch = self
            .clearing_batches
            .get_mut(batch_id)
            .ok_or_else(|| "private liquidity batch not found".to_string())?;
        if !batch.solver_commitment_ids.contains(commitment_id) {
            return Err("private liquidity batch does not include solver commitment".to_string());
        }
        batch.selected_commitment_id = Some(commitment_id.to_string());
        batch.protocol_fee_commitment = protocol_fee_commitment.to_string();
        batch.surplus_commitment = surplus_commitment.to_string();
        batch.status = BatchStatus::Settling;
        self.push_event(
            "solver_commitment_selected",
            json!({ "batch_id": batch_id, "commitment_id": commitment_id }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publish_settlement_receipt(
        &mut self,
        batch_id: &str,
        intent_id: &str,
        solver_id: &str,
        output_note_commitment: &str,
        fee_note_commitment: &str,
        rebate_note_commitment: &str,
        settlement_nullifier: &str,
        receipt_proof_root: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.settlement_receipts.len()
            >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_RECEIPTS
        {
            return Err("private liquidity settlement receipt capacity reached".to_string());
        }
        if self.nullifiers.contains(settlement_nullifier) {
            return Err("private liquidity settlement nullifier already used".to_string());
        }
        let lane_id = {
            let batch = self
                .clearing_batches
                .get(batch_id)
                .ok_or_else(|| "private liquidity receipt batch not found".to_string())?;
            if !matches!(batch.status, BatchStatus::Settling | BatchStatus::Attested) {
                return Err("private liquidity batch is not settling".to_string());
            }
            if !batch.intent_ids.contains(intent_id) {
                return Err("private liquidity receipt intent not in batch".to_string());
            }
            batch.lane_id.clone()
        };
        let receipt = SettlementReceipt::new(
            batch_id,
            intent_id,
            solver_id,
            &lane_id,
            output_note_commitment,
            fee_note_commitment,
            rebate_note_commitment,
            settlement_nullifier,
            receipt_proof_root,
            self.height,
            self.config.receipt_ttl_blocks,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.nullifiers.insert(settlement_nullifier.to_string());
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        if let Some(intent) = self.encrypted_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Settled;
        }
        let receipt_records = self
            .settlement_receipts
            .values()
            .filter(|receipt| receipt.batch_id == batch_id)
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.clearing_batches.get_mut(batch_id) {
            batch.receipt_root = merkle_root("PLBAC-BATCH-RECEIPTS", &receipt_records);
            if receipt_records.len() == batch.intent_ids.len() {
                batch.status = BatchStatus::Settled;
            }
        }
        self.counters.receipt_count = self.counters.receipt_count.saturating_add(1);
        self.push_event(
            "settlement_receipt_published",
            json!({ "receipt_id": receipt_id, "batch_id": batch_id, "intent_id": intent_id }),
        )?;
        Ok(receipt_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_pq_attestation(
        &mut self,
        batch_id: &str,
        committee_root: &str,
        signer_bitmap_commitment: &str,
        signature_aggregate_commitment: &str,
        attested_root: &str,
        security_bits: u16,
        quorum_bps: u64,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.pq_attestations.len()
            >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_ATTESTATIONS
        {
            return Err("private liquidity pq attestation capacity reached".to_string());
        }
        if security_bits < self.config.min_pq_security_bits {
            return Err("private liquidity pq attestation security is too low".to_string());
        }
        let lane_id = self
            .clearing_batches
            .get(batch_id)
            .map(|batch| batch.lane_id.clone())
            .ok_or_else(|| "private liquidity pq attestation batch not found".to_string())?;
        let mut attestation = PqCommitteeAttestation::new(
            batch_id,
            &lane_id,
            committee_root,
            signer_bitmap_commitment,
            signature_aggregate_commitment,
            attested_root,
            security_bits,
            quorum_bps,
            self.height,
            self.config.challenge_window_blocks,
        )?;
        if quorum_bps >= 6_667 {
            attestation.status = AttestationStatus::Quorum;
        }
        let attestation_id = attestation.attestation_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        let attestation_records = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.batch_id == batch_id)
            .map(PqCommitteeAttestation::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.clearing_batches.get_mut(batch_id) {
            batch.attestation_root = merkle_root("PLBAC-BATCH-ATTESTATIONS", &attestation_records);
            if quorum_bps >= 6_667 {
                batch.status = BatchStatus::Attested;
            }
        }
        self.counters.attestation_count = self.counters.attestation_count.saturating_add(1);
        self.push_event(
            "pq_attestation_submitted",
            json!({ "attestation_id": attestation_id, "batch_id": batch_id }),
        )?;
        Ok(attestation_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_challenge_evidence(
        &mut self,
        kind: EvidenceKind,
        target_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        affected_batch_id: Option<String>,
        affected_solver_id: Option<String>,
        affected_sponsor_id: Option<String>,
        bond_slash_commitment: &str,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<String> {
        if self.challenges.len() >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_CHALLENGES {
            return Err("private liquidity challenge capacity reached".to_string());
        }
        if let Some(batch_id) = affected_batch_id.as_ref() {
            if !self.clearing_batches.contains_key(batch_id) {
                return Err("private liquidity challenge batch not found".to_string());
            }
        }
        let challenge = ChallengeEvidence::new(
            kind,
            target_id,
            challenger_commitment,
            evidence_root,
            affected_batch_id.clone(),
            affected_solver_id.clone(),
            affected_sponsor_id.clone(),
            kind.default_severity_bps(),
            bond_slash_commitment,
            self.height,
            self.config.challenge_window_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if let Some(batch_id) = affected_batch_id {
            if let Some(batch) = self.clearing_batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Challenged;
            }
        }
        self.challenges.insert(challenge_id.clone(), challenge);
        self.counters.challenge_count = self.counters.challenge_count.saturating_add(1);
        self.push_event(
            "challenge_submitted",
            json!({ "challenge_id": challenge_id, "kind": kind.as_str(), "target_id": target_id }),
        )?;
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "private liquidity challenge not found".to_string())?;
        challenge.resolved_height = Some(self.height);
        challenge.status = if accepted {
            ChallengeStatus::Accepted
        } else {
            ChallengeStatus::Rejected
        };
        if accepted {
            if let Some(solver_id) = challenge.affected_solver_id.as_ref() {
                for commitment in self.solver_commitments.values_mut() {
                    if &commitment.solver_id == solver_id {
                        commitment.status = SolverCommitmentStatus::Slashed;
                    }
                }
                self.counters.slashed_solver_count =
                    self.counters.slashed_solver_count.saturating_add(1);
            }
            if let Some(sponsor_id) = challenge.affected_sponsor_id.as_ref() {
                if let Some(sponsor) = self.sponsor_accounts.get_mut(sponsor_id) {
                    sponsor.status = SponsorStatus::Slashed;
                    sponsor.last_updated_height = self.height;
                }
                self.counters.slashed_sponsor_count =
                    self.counters.slashed_sponsor_count.saturating_add(1);
            }
            challenge.status = ChallengeStatus::Slashed;
        }
        self.push_event(
            "challenge_resolved",
            json!({ "challenge_id": challenge_id, "accepted": accepted }),
        )
    }

    fn expire_records(&mut self) {
        for intent in self.encrypted_intents.values_mut() {
            if self.height > intent.expiry_height && intent.status.live() {
                intent.status = IntentStatus::Expired;
            }
        }
        for commitment in self.solver_commitments.values_mut() {
            if self.height > commitment.expiry_height && commitment.status.usable() {
                commitment.status = SolverCommitmentStatus::Expired;
            }
        }
        for batch in self.clearing_batches.values_mut() {
            if self.height > batch.settlement_deadline_height && !batch.status.final_status() {
                batch.status = BatchStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if self.height > attestation.expiry_height
                && matches!(
                    attestation.status,
                    AttestationStatus::Proposed | AttestationStatus::Quorum
                )
            {
                attestation.status = AttestationStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if self.height > challenge.expiry_height
                && matches!(
                    challenge.status,
                    ChallengeStatus::Open | ChallengeStatus::UnderReview
                )
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    fn push_event(
        &mut self,
        event_kind: &str,
        payload: Value,
    ) -> PrivateLiquidityBatchAuctionClearinghouseResult<()> {
        if self.public_events.len()
            >= PRIVATE_LIQUIDITY_BATCH_AUCTION_CLEARINGHOUSE_MAX_PUBLIC_EVENTS
        {
            return Err("private liquidity public event capacity reached".to_string());
        }
        let event = json!({
            "event_kind": event_kind,
            "height": self.height,
            "ordinal": self.counters.public_event_count,
            "payload": payload,
        });
        self.public_events.push(event);
        self.counters.public_event_count = self.counters.public_event_count.saturating_add(1);
        Ok(())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn root_from_record(record_kind: &str, record: &Value) -> String {
    plbac_hash(record_kind, &[HashPart::Json(record)])
}

fn plbac_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-BATCH-AUCTION-CLEARINGHOUSE-{domain}"),
        parts,
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-LIQUIDITY-BATCH-AUCTION-CLEARINGHOUSE-{domain}"),
        &[],
    )
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-LIQUIDITY-BATCH-AUCTION-CLEARINGHOUSE-{domain}"),
        &leaves,
    )
}

fn string_map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-LIQUIDITY-BATCH-AUCTION-CLEARINGHOUSE-{domain}"),
        &leaves,
    )
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for AuctionLane {
    fn public_record(&self) -> Value {
        AuctionLane::public_record(self)
    }
}

impl PublicRecord for EncryptedIntent {
    fn public_record(&self) -> Value {
        EncryptedIntent::public_record(self)
    }
}

impl PublicRecord for SolverCommitment {
    fn public_record(&self) -> Value {
        SolverCommitment::public_record(self)
    }
}

impl PublicRecord for ClearingBatch {
    fn public_record(&self) -> Value {
        ClearingBatch::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for LiquiditySponsorAccount {
    fn public_record(&self) -> Value {
        LiquiditySponsorAccount::public_record(self)
    }
}

impl PublicRecord for PqCommitteeAttestation {
    fn public_record(&self) -> Value {
        PqCommitteeAttestation::public_record(self)
    }
}

impl PublicRecord for ChallengeEvidence {
    fn public_record(&self) -> Value {
        ChallengeEvidence::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": value.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-LIQUIDITY-BATCH-AUCTION-CLEARINGHOUSE-{domain}"),
        &leaves,
    )
}
