use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqFeeRebateAuctionHouseResult<T> = Result<T, String>;

pub const PQ_FEE_REBATE_AUCTION_HOUSE_PROTOCOL_VERSION: &str =
    "nebula-pq-fee-rebate-auction-house-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_SCHEMA_VERSION: u64 = 1;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEVNET_HEIGHT: u64 = 1_728;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_SEALED_BID_SCHEME: &str =
    "ml-kem-1024+shake256-sealed-sponsor-bid-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_BIDDER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-sponsor-attestation-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_ELIGIBILITY_SCHEME: &str =
    "zk-wallet-contract-eligibility-commitment-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_BUCKET_SCHEME: &str =
    "anti-sybil-private-bucket-nullifier-set-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_RECEIPT_SCHEME: &str = "fee-rebate-settlement-receipt-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_CHALLENGE_SCHEME: &str =
    "auction-house-challenge-slash-evidence-v1";
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_EPOCH_BLOCKS: u64 = 24;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_COMMIT_BLOCKS: u64 = 8;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_REVEAL_BLOCKS: u64 = 6;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_SETTLEMENT_BLOCKS: u64 = 36;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_CHALLENGE_BLOCKS: u64 = 48;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MAX_REBATE_BPS: u64 = 9_500;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_SPONSOR_BOND_UNITS: u64 = 25_000_000;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_SLASH_BPS: u64 = 2_000;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 700;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BPS: u64 = 10_000;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EPOCHS: usize = 16_384;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_COMMITMENTS: usize = 262_144;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BIDS: usize = 262_144;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ALLOCATIONS: usize = 262_144;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ATTESTATIONS: usize = 262_144;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BUCKETS: usize = 65_536;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_RECEIPTS: usize = 262_144;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_CHALLENGES: usize = 65_536;
pub const PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EVENTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateLaneKind {
    WalletTransfer,
    ContractCall,
    DefiSwap,
    LiquidityAdd,
    ProofAggregation,
    MoneroBridgeExit,
    WalletRecovery,
    EmergencyExit,
}

impl RebateLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::LiquidityAdd => "liquidity_add",
            Self::ProofAggregation => "proof_aggregation",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::WalletRecovery => 940,
            Self::WalletTransfer => 900,
            Self::MoneroBridgeExit => 820,
            Self::DefiSwap => 760,
            Self::ContractCall => 720,
            Self::LiquidityAdd => 650,
            Self::ProofAggregation => 600,
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyExit => 400,
            Self::WalletRecovery => 500,
            Self::WalletTransfer => 650,
            Self::MoneroBridgeExit => 900,
            Self::DefiSwap => 1_100,
            Self::ContractCall => 1_350,
            Self::LiquidityAdd => 1_500,
            Self::ProofAggregation => 1_800,
        }
    }

    pub fn contract_eligible(self) -> bool {
        matches!(
            self,
            Self::ContractCall | Self::DefiSwap | Self::LiquidityAdd | Self::ProofAggregation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateEpochStatus {
    CommitOpen,
    RevealOpen,
    Clearing,
    Allocating,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl RebateEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Clearing => "clearing",
            Self::Allocating => "allocating",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_commit(self) -> bool {
        matches!(self, Self::CommitOpen)
    }

    pub fn accepts_reveal(self) -> bool {
        matches!(self, Self::RevealOpen | Self::Clearing)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBidStatus {
    Committed,
    Revealed,
    Accepted,
    PartiallyFilled,
    Rejected,
    Slashed,
    Expired,
}

impl SponsorBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Accepted => "accepted",
            Self::PartiallyFilled => "partially_filled",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Revealed | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilitySubjectKind {
    Wallet,
    Contract,
    SmartAccount,
    Paymaster,
    LiquidityVault,
}

impl EligibilitySubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Contract => "contract",
            Self::SmartAccount => "smart_account",
            Self::Paymaster => "paymaster",
            Self::LiquidityVault => "liquidity_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStatus {
    Pending,
    Active,
    Consumed,
    Revoked,
    Expired,
}

impl EligibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBucketStatus {
    Open,
    Sealed,
    Saturated,
    Quarantined,
    Retired,
}

impl PrivacyBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Saturated => "saturated",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn admits(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStatus {
    Reserved,
    Executed,
    Settled,
    Reclaimed,
    Challenged,
    Expired,
}

impl AllocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Reclaimed => "reclaimed",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Final,
    Disputed,
    Reversed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Final => "final",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidReveal,
    DoubleBucketUse,
    IneligibleBeneficiary,
    FeeCapViolation,
    MissingPqAttestation,
    SettlementMismatch,
    Censorship,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidReveal => "invalid_reveal",
            Self::DoubleBucketUse => "double_bucket_use",
            Self::IneligibleBeneficiary => "ineligible_beneficiary",
            Self::FeeCapViolation => "fee_cap_violation",
            Self::MissingPqAttestation => "missing_pq_attestation",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::Censorship => "censorship",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

pub trait PqFeeRebateAuctionHouseRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeRebateAuctionHouseConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub sealed_bid_scheme: String,
    pub bidder_attestation_scheme: String,
    pub eligibility_scheme: String,
    pub privacy_bucket_scheme: String,
    pub receipt_scheme: String,
    pub challenge_scheme: String,
    pub epoch_blocks: u64,
    pub commit_blocks: u64,
    pub reveal_blocks: u64,
    pub settlement_blocks: u64,
    pub challenge_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_rebate_bps: u64,
    pub min_sponsor_bond_units: u64,
    pub slash_bps: u64,
    pub low_fee_target_micro_units: u64,
    pub privacy_policy_root: String,
}

impl PqFeeRebateAuctionHouseConfig {
    pub fn devnet() -> PqFeeRebateAuctionHouseResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PQ_FEE_REBATE_AUCTION_HOUSE_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_FEE_REBATE_AUCTION_HOUSE_SCHEMA_VERSION,
            fee_asset_id: PQ_FEE_REBATE_AUCTION_HOUSE_FEE_ASSET_ID.to_string(),
            rebate_asset_id: PQ_FEE_REBATE_AUCTION_HOUSE_REBATE_ASSET_ID.to_string(),
            hash_suite: PQ_FEE_REBATE_AUCTION_HOUSE_HASH_SUITE.to_string(),
            sealed_bid_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_SEALED_BID_SCHEME.to_string(),
            bidder_attestation_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_BIDDER_ATTESTATION_SCHEME
                .to_string(),
            eligibility_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_ELIGIBILITY_SCHEME.to_string(),
            privacy_bucket_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_BUCKET_SCHEME.to_string(),
            receipt_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_RECEIPT_SCHEME.to_string(),
            challenge_scheme: PQ_FEE_REBATE_AUCTION_HOUSE_CHALLENGE_SCHEME.to_string(),
            epoch_blocks: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_EPOCH_BLOCKS,
            commit_blocks: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_COMMIT_BLOCKS,
            reveal_blocks: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_REVEAL_BLOCKS,
            settlement_blocks: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_SETTLEMENT_BLOCKS,
            challenge_blocks: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_CHALLENGE_BLOCKS,
            min_pq_security_bits: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_rebate_bps: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MAX_REBATE_BPS,
            min_sponsor_bond_units: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_SPONSOR_BOND_UNITS,
            slash_bps: PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_SLASH_BPS,
            low_fee_target_micro_units:
                PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            privacy_policy_root: pq_fee_rebate_string_root(
                "PQ-FEE-REBATE-PRIVACY-POLICY",
                "public-roots-private-beneficiaries-anti-sybil-buckets",
            ),
        };
        config.config_id = pq_fee_rebate_config_id(
            &config.protocol_version,
            config.schema_version,
            &config.fee_asset_id,
            &config.rebate_asset_id,
        );
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.config_id, "pq fee rebate config id")?;
        ensure_non_empty(&self.protocol_version, "pq fee rebate protocol version")?;
        ensure_non_empty(&self.fee_asset_id, "pq fee rebate fee asset")?;
        ensure_non_empty(&self.rebate_asset_id, "pq fee rebate rebate asset")?;
        ensure_non_empty(&self.hash_suite, "pq fee rebate hash suite")?;
        ensure_non_empty(&self.sealed_bid_scheme, "pq fee rebate sealed bid scheme")?;
        ensure_non_empty(
            &self.bidder_attestation_scheme,
            "pq fee rebate bidder attestation scheme",
        )?;
        ensure_non_empty(&self.eligibility_scheme, "pq fee rebate eligibility scheme")?;
        ensure_non_empty(
            &self.privacy_bucket_scheme,
            "pq fee rebate privacy bucket scheme",
        )?;
        ensure_non_empty(&self.receipt_scheme, "pq fee rebate receipt scheme")?;
        ensure_non_empty(&self.challenge_scheme, "pq fee rebate challenge scheme")?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "pq fee rebate privacy policy root",
        )?;
        if self.schema_version == 0 {
            return Err("pq fee rebate schema version must be positive".to_string());
        }
        if self.epoch_blocks == 0
            || self.commit_blocks == 0
            || self.reveal_blocks == 0
            || self.settlement_blocks == 0
            || self.challenge_blocks == 0
        {
            return Err("pq fee rebate timing windows must be positive".to_string());
        }
        if self.commit_blocks.saturating_add(self.reveal_blocks) > self.epoch_blocks {
            return Err("pq fee rebate commit and reveal windows exceed epoch".to_string());
        }
        if self.max_rebate_bps > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BPS {
            return Err("pq fee rebate max rebate exceeds bps cap".to_string());
        }
        if self.slash_bps > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BPS {
            return Err("pq fee rebate slash exceeds bps cap".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("pq fee rebate pq security floor is too low".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("pq fee rebate privacy set size must be positive".to_string());
        }
        let expected = pq_fee_rebate_config_id(
            &self.protocol_version,
            self.schema_version,
            &self.fee_asset_id,
            &self.rebate_asset_id,
        );
        if self.config_id != expected {
            return Err("pq fee rebate config id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for PqFeeRebateAuctionHouseConfig {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fee_rebate_auction_house_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "sealed_bid_scheme": self.sealed_bid_scheme,
            "bidder_attestation_scheme": self.bidder_attestation_scheme,
            "eligibility_scheme": self.eligibility_scheme,
            "privacy_bucket_scheme": self.privacy_bucket_scheme,
            "receipt_scheme": self.receipt_scheme,
            "challenge_scheme": self.challenge_scheme,
            "epoch_blocks": self.epoch_blocks,
            "commit_blocks": self.commit_blocks,
            "reveal_blocks": self.reveal_blocks,
            "settlement_blocks": self.settlement_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_rebate_bps": self.max_rebate_bps,
            "min_sponsor_bond_units": self.min_sponsor_bond_units,
            "slash_bps": self.slash_bps,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebateEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub commit_close_height: u64,
    pub reveal_close_height: u64,
    pub settlement_close_height: u64,
    pub challenge_close_height: u64,
    pub status: RebateEpochStatus,
    pub lane_keys: BTreeSet<String>,
    pub target_fee_micro_units: u64,
    pub total_sponsor_budget_units: u64,
    pub total_allocated_units: u64,
    pub total_settled_rebate_units: u64,
    pub clearing_price_micro_units: u64,
    pub fairness_score_bps: u64,
    pub public_entropy_root: String,
}

impl FeeRebateEpoch {
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        config: &PqFeeRebateAuctionHouseConfig,
        lane_keys: BTreeSet<String>,
        target_fee_micro_units: u64,
        entropy_label: &str,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        if lane_keys.is_empty() {
            return Err("pq fee rebate epoch requires lanes".to_string());
        }
        ensure_non_empty(entropy_label, "pq fee rebate epoch entropy label")?;
        let commit_close_height = start_height.saturating_add(config.commit_blocks);
        let reveal_close_height = commit_close_height.saturating_add(config.reveal_blocks);
        let settlement_close_height = start_height.saturating_add(config.settlement_blocks);
        let challenge_close_height =
            settlement_close_height.saturating_add(config.challenge_blocks);
        let public_entropy_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-EPOCH-ENTROPY", entropy_label);
        let epoch_id = pq_fee_rebate_epoch_id(epoch_index, start_height, &public_entropy_root);
        let epoch = Self {
            epoch_id,
            epoch_index,
            start_height,
            commit_close_height,
            reveal_close_height,
            settlement_close_height,
            challenge_close_height,
            status: RebateEpochStatus::CommitOpen,
            lane_keys,
            target_fee_micro_units,
            total_sponsor_budget_units: 0,
            total_allocated_units: 0,
            total_settled_rebate_units: 0,
            clearing_price_micro_units: 0,
            fairness_score_bps: 0,
            public_entropy_root,
        };
        epoch.validate(config)?;
        Ok(epoch)
    }

    pub fn validate(
        &self,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.epoch_id, "pq fee rebate epoch id")?;
        ensure_non_empty(
            &self.public_entropy_root,
            "pq fee rebate epoch entropy root",
        )?;
        if self.lane_keys.is_empty() {
            return Err("pq fee rebate epoch must reference at least one lane".to_string());
        }
        if self.commit_close_height <= self.start_height {
            return Err("pq fee rebate epoch commit close must follow start".to_string());
        }
        if self.reveal_close_height <= self.commit_close_height {
            return Err("pq fee rebate epoch reveal close must follow commit".to_string());
        }
        if self.settlement_close_height <= self.start_height {
            return Err("pq fee rebate epoch settlement close must follow start".to_string());
        }
        if self.challenge_close_height <= self.settlement_close_height {
            return Err("pq fee rebate epoch challenge close must follow settlement".to_string());
        }
        if self.target_fee_micro_units > config.low_fee_target_micro_units.saturating_mul(8) {
            return Err("pq fee rebate epoch target fee is outside devnet guardrail".to_string());
        }
        let expected = pq_fee_rebate_epoch_id(
            self.epoch_index,
            self.start_height,
            &self.public_entropy_root,
        );
        if self.epoch_id != expected {
            return Err("pq fee rebate epoch id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for FeeRebateEpoch {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-EPOCH", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_rebate_epoch",
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "commit_close_height": self.commit_close_height,
            "reveal_close_height": self.reveal_close_height,
            "settlement_close_height": self.settlement_close_height,
            "challenge_close_height": self.challenge_close_height,
            "status": self.status.as_str(),
            "lane_keys": self.lane_keys.iter().cloned().collect::<Vec<_>>(),
            "target_fee_micro_units": self.target_fee_micro_units,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_allocated_units": self.total_allocated_units,
            "total_settled_rebate_units": self.total_settled_rebate_units,
            "clearing_price_micro_units": self.clearing_price_micro_units,
            "fairness_score_bps": self.fairness_score_bps,
            "public_entropy_root": self.public_entropy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeLane {
    pub lane_id: String,
    pub lane_key: String,
    pub lane_kind: RebateLaneKind,
    pub display_name: String,
    pub fee_cap_micro_units: u64,
    pub target_slots: u64,
    pub priority_weight: u64,
    pub min_privacy_set_size: u64,
    pub contract_calls_allowed: bool,
    pub enabled: bool,
}

impl LowFeeLane {
    pub fn new(
        lane_kind: RebateLaneKind,
        lane_key: &str,
        display_name: &str,
        target_slots: u64,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(lane_key, "pq fee rebate lane key")?;
        ensure_non_empty(display_name, "pq fee rebate lane display name")?;
        if target_slots == 0 {
            return Err("pq fee rebate lane target slots must be positive".to_string());
        }
        let lane_id = pq_fee_rebate_lane_id(lane_key, lane_kind);
        let lane = Self {
            lane_id,
            lane_key: lane_key.to_string(),
            lane_kind,
            display_name: display_name.to_string(),
            fee_cap_micro_units: lane_kind.default_fee_cap_micro_units(),
            target_slots,
            priority_weight: lane_kind.default_priority_weight(),
            min_privacy_set_size: config.min_privacy_set_size,
            contract_calls_allowed: lane_kind.contract_eligible(),
            enabled: true,
        };
        lane.validate(config)?;
        Ok(lane)
    }

    pub fn validate(
        &self,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.lane_id, "pq fee rebate lane id")?;
        ensure_non_empty(&self.lane_key, "pq fee rebate lane key")?;
        ensure_non_empty(&self.display_name, "pq fee rebate lane display name")?;
        if self.fee_cap_micro_units == 0 {
            return Err("pq fee rebate lane fee cap must be positive".to_string());
        }
        if self.target_slots == 0 {
            return Err("pq fee rebate lane target slots must be positive".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("pq fee rebate lane privacy set below config floor".to_string());
        }
        let expected = pq_fee_rebate_lane_id(&self.lane_key, self.lane_kind);
        if self.lane_id != expected {
            return Err("pq fee rebate lane id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for LowFeeLane {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-LOW-FEE-LANE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_lane",
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "lane_kind": self.lane_kind.as_str(),
            "display_name": self.display_name,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "target_slots": self.target_slots,
            "priority_weight": self.priority_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "contract_calls_allowed": self.contract_calls_allowed,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EligibilityCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub subject_kind: EligibilitySubjectKind,
    pub subject_commitment: String,
    pub wallet_commitment_root: String,
    pub contract_commitment_root: String,
    pub lane_key: String,
    pub privacy_bucket_id: String,
    pub nullifier_hash: String,
    pub max_fee_micro_units: u64,
    pub status: EligibilityStatus,
    pub metadata_root: String,
}

impl EligibilityCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        subject_kind: EligibilitySubjectKind,
        subject_label: &str,
        lane_key: &str,
        privacy_bucket_id: &str,
        nullifier_label: &str,
        max_fee_micro_units: u64,
        metadata: &Value,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(epoch_id, "pq fee rebate eligibility epoch")?;
        ensure_non_empty(subject_label, "pq fee rebate eligibility subject")?;
        ensure_non_empty(lane_key, "pq fee rebate eligibility lane")?;
        ensure_non_empty(privacy_bucket_id, "pq fee rebate eligibility bucket")?;
        ensure_non_empty(nullifier_label, "pq fee rebate eligibility nullifier")?;
        if max_fee_micro_units == 0 {
            return Err("pq fee rebate eligibility max fee must be positive".to_string());
        }
        let subject_commitment =
            pq_fee_rebate_subject_commitment(subject_kind, subject_label, epoch_id);
        let wallet_commitment_root = match subject_kind {
            EligibilitySubjectKind::Wallet | EligibilitySubjectKind::SmartAccount => {
                pq_fee_rebate_string_root("PQ-FEE-REBATE-WALLET-COMMITMENT", subject_label)
            }
            _ => pq_fee_rebate_string_root("PQ-FEE-REBATE-EMPTY-WALLET-COMMITMENT", "none"),
        };
        let contract_commitment_root = match subject_kind {
            EligibilitySubjectKind::Contract
            | EligibilitySubjectKind::Paymaster
            | EligibilitySubjectKind::LiquidityVault => {
                pq_fee_rebate_string_root("PQ-FEE-REBATE-CONTRACT-COMMITMENT", subject_label)
            }
            _ => pq_fee_rebate_string_root("PQ-FEE-REBATE-EMPTY-CONTRACT-COMMITMENT", "none"),
        };
        let nullifier_hash =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-ELIGIBILITY-NULLIFIER", nullifier_label);
        let metadata_root =
            pq_fee_rebate_payload_root("PQ-FEE-REBATE-ELIGIBILITY-METADATA", metadata);
        let commitment_id =
            pq_fee_rebate_eligibility_id(epoch_id, &subject_commitment, lane_key, &nullifier_hash);
        let commitment = Self {
            commitment_id,
            epoch_id: epoch_id.to_string(),
            subject_kind,
            subject_commitment,
            wallet_commitment_root,
            contract_commitment_root,
            lane_key: lane_key.to_string(),
            privacy_bucket_id: privacy_bucket_id.to_string(),
            nullifier_hash,
            max_fee_micro_units,
            status: EligibilityStatus::Active,
            metadata_root,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.commitment_id, "pq fee rebate eligibility id")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate eligibility epoch")?;
        ensure_non_empty(
            &self.subject_commitment,
            "pq fee rebate eligibility subject commitment",
        )?;
        ensure_non_empty(
            &self.wallet_commitment_root,
            "pq fee rebate wallet commitment root",
        )?;
        ensure_non_empty(
            &self.contract_commitment_root,
            "pq fee rebate contract commitment root",
        )?;
        ensure_non_empty(&self.lane_key, "pq fee rebate eligibility lane")?;
        ensure_non_empty(&self.privacy_bucket_id, "pq fee rebate eligibility bucket")?;
        ensure_non_empty(&self.nullifier_hash, "pq fee rebate eligibility nullifier")?;
        ensure_non_empty(&self.metadata_root, "pq fee rebate eligibility metadata")?;
        if self.max_fee_micro_units == 0 {
            return Err("pq fee rebate eligibility max fee must be positive".to_string());
        }
        let expected = pq_fee_rebate_eligibility_id(
            &self.epoch_id,
            &self.subject_commitment,
            &self.lane_key,
            &self.nullifier_hash,
        );
        if self.commitment_id != expected {
            return Err("pq fee rebate eligibility id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for EligibilityCommitment {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-ELIGIBILITY", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "eligibility_commitment",
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_commitment": self.subject_commitment,
            "wallet_commitment_root": self.wallet_commitment_root,
            "contract_commitment_root": self.contract_commitment_root,
            "lane_key": self.lane_key,
            "privacy_bucket_id": self.privacy_bucket_id,
            "nullifier_hash": self.nullifier_hash,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqBidderAttestation {
    pub attestation_id: String,
    pub bidder_id: String,
    pub epoch_id: String,
    pub pq_verification_key_root: String,
    pub reserve_commitment_root: String,
    pub signature_transcript_root: String,
    pub supported_lanes: BTreeSet<String>,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
}

impl PqBidderAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bidder_label: &str,
        epoch_id: &str,
        pq_key_label: &str,
        reserve_label: &str,
        transcript_label: &str,
        supported_lanes: BTreeSet<String>,
        security_bits: u16,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(bidder_label, "pq fee rebate bidder label")?;
        ensure_non_empty(epoch_id, "pq fee rebate attestation epoch")?;
        ensure_non_empty(pq_key_label, "pq fee rebate attestation pq key")?;
        ensure_non_empty(reserve_label, "pq fee rebate attestation reserve")?;
        ensure_non_empty(transcript_label, "pq fee rebate attestation transcript")?;
        if supported_lanes.is_empty() {
            return Err("pq fee rebate bidder attestation requires lanes".to_string());
        }
        if valid_until_height <= valid_from_height {
            return Err("pq fee rebate bidder attestation validity is inverted".to_string());
        }
        let bidder_id = pq_fee_rebate_bidder_id(bidder_label);
        let pq_verification_key_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BIDDER-PQ-KEY", pq_key_label);
        let reserve_commitment_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BIDDER-RESERVE", reserve_label);
        let signature_transcript_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BIDDER-TRANSCRIPT", transcript_label);
        let attestation_id = pq_fee_rebate_attestation_id(
            &bidder_id,
            epoch_id,
            &pq_verification_key_root,
            &signature_transcript_root,
        );
        let attestation = Self {
            attestation_id,
            bidder_id,
            epoch_id: epoch_id.to_string(),
            pq_verification_key_root,
            reserve_commitment_root,
            signature_transcript_root,
            supported_lanes,
            security_bits,
            valid_from_height,
            valid_until_height,
            revoked: false,
        };
        attestation.validate(PQ_FEE_REBATE_AUCTION_HOUSE_DEFAULT_MIN_PQ_SECURITY_BITS)?;
        Ok(attestation)
    }

    pub fn validate(&self, min_security_bits: u16) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.attestation_id, "pq fee rebate attestation id")?;
        ensure_non_empty(&self.bidder_id, "pq fee rebate attestation bidder")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate attestation epoch")?;
        ensure_non_empty(
            &self.pq_verification_key_root,
            "pq fee rebate attestation pq key",
        )?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "pq fee rebate attestation reserve",
        )?;
        ensure_non_empty(
            &self.signature_transcript_root,
            "pq fee rebate attestation transcript",
        )?;
        if self.supported_lanes.is_empty() {
            return Err("pq fee rebate attestation must support at least one lane".to_string());
        }
        if self.security_bits < min_security_bits {
            return Err("pq fee rebate attestation below pq security floor".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("pq fee rebate attestation validity is inverted".to_string());
        }
        let expected = pq_fee_rebate_attestation_id(
            &self.bidder_id,
            &self.epoch_id,
            &self.pq_verification_key_root,
            &self.signature_transcript_root,
        );
        if self.attestation_id != expected {
            return Err("pq fee rebate attestation id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for PqBidderAttestation {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-BIDDER-ATTESTATION", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bidder_attestation",
            "attestation_id": self.attestation_id,
            "bidder_id": self.bidder_id,
            "epoch_id": self.epoch_id,
            "pq_verification_key_root": self.pq_verification_key_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "signature_transcript_root": self.signature_transcript_root,
            "supported_lanes": self.supported_lanes.iter().cloned().collect::<Vec<_>>(),
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "revoked": self.revoked,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedSponsorBid {
    pub bid_id: String,
    pub epoch_id: String,
    pub bidder_id: String,
    pub attestation_id: String,
    pub lane_key: String,
    pub sealed_bid_root: String,
    pub reveal_commitment_root: String,
    pub bid_budget_units: u64,
    pub max_rebate_bps: u64,
    pub requested_slots: u64,
    pub sponsor_bond_units: u64,
    pub status: SponsorBidStatus,
    pub reveal_height: Option<u64>,
    pub accepted_units: u64,
}

impl SealedSponsorBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        bidder_id: &str,
        attestation_id: &str,
        lane_key: &str,
        bid_label: &str,
        bid_budget_units: u64,
        max_rebate_bps: u64,
        requested_slots: u64,
        sponsor_bond_units: u64,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(epoch_id, "pq fee rebate bid epoch")?;
        ensure_non_empty(bidder_id, "pq fee rebate bid bidder")?;
        ensure_non_empty(attestation_id, "pq fee rebate bid attestation")?;
        ensure_non_empty(lane_key, "pq fee rebate bid lane")?;
        ensure_non_empty(bid_label, "pq fee rebate bid label")?;
        if bid_budget_units == 0 {
            return Err("pq fee rebate bid budget must be positive".to_string());
        }
        if requested_slots == 0 {
            return Err("pq fee rebate bid requested slots must be positive".to_string());
        }
        if max_rebate_bps > config.max_rebate_bps {
            return Err("pq fee rebate bid rebate exceeds config cap".to_string());
        }
        if sponsor_bond_units < config.min_sponsor_bond_units {
            return Err("pq fee rebate bid sponsor bond below floor".to_string());
        }
        let sealed_bid_root = pq_fee_rebate_string_root("PQ-FEE-REBATE-SEALED-BID", bid_label);
        let reveal_commitment_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BID-REVEAL-COMMITMENT", bid_label);
        let bid_id = pq_fee_rebate_bid_id(epoch_id, bidder_id, lane_key, &sealed_bid_root);
        let bid = Self {
            bid_id,
            epoch_id: epoch_id.to_string(),
            bidder_id: bidder_id.to_string(),
            attestation_id: attestation_id.to_string(),
            lane_key: lane_key.to_string(),
            sealed_bid_root,
            reveal_commitment_root,
            bid_budget_units,
            max_rebate_bps,
            requested_slots,
            sponsor_bond_units,
            status: SponsorBidStatus::Committed,
            reveal_height: None,
            accepted_units: 0,
        };
        bid.validate(config)?;
        Ok(bid)
    }

    pub fn validate(
        &self,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.bid_id, "pq fee rebate bid id")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate bid epoch")?;
        ensure_non_empty(&self.bidder_id, "pq fee rebate bid bidder")?;
        ensure_non_empty(&self.attestation_id, "pq fee rebate bid attestation")?;
        ensure_non_empty(&self.lane_key, "pq fee rebate bid lane")?;
        ensure_non_empty(&self.sealed_bid_root, "pq fee rebate sealed bid root")?;
        ensure_non_empty(
            &self.reveal_commitment_root,
            "pq fee rebate reveal commitment root",
        )?;
        if self.bid_budget_units == 0 {
            return Err("pq fee rebate bid budget must be positive".to_string());
        }
        if self.requested_slots == 0 {
            return Err("pq fee rebate bid requested slots must be positive".to_string());
        }
        if self.max_rebate_bps > config.max_rebate_bps {
            return Err("pq fee rebate bid rebate exceeds config cap".to_string());
        }
        if self.sponsor_bond_units < config.min_sponsor_bond_units {
            return Err("pq fee rebate bid sponsor bond below floor".to_string());
        }
        if self.accepted_units > self.bid_budget_units {
            return Err("pq fee rebate bid accepted units exceed budget".to_string());
        }
        let expected = pq_fee_rebate_bid_id(
            &self.epoch_id,
            &self.bidder_id,
            &self.lane_key,
            &self.sealed_bid_root,
        );
        if self.bid_id != expected {
            return Err("pq fee rebate bid id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for SealedSponsorBid {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-SEALED-SPONSOR-BID", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_sponsor_bid",
            "bid_id": self.bid_id,
            "epoch_id": self.epoch_id,
            "bidder_id": self.bidder_id,
            "attestation_id": self.attestation_id,
            "lane_key": self.lane_key,
            "sealed_bid_root": self.sealed_bid_root,
            "reveal_commitment_root": self.reveal_commitment_root,
            "bid_budget_units": self.bid_budget_units,
            "max_rebate_bps": self.max_rebate_bps,
            "requested_slots": self.requested_slots,
            "sponsor_bond_units": self.sponsor_bond_units,
            "status": self.status.as_str(),
            "reveal_height": self.reveal_height,
            "accepted_units": self.accepted_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiSybilPrivacyBucket {
    pub bucket_id: String,
    pub epoch_id: String,
    pub lane_key: String,
    pub bucket_label_root: String,
    pub nullifier_set_root: String,
    pub member_commitment_root: String,
    pub min_anonymity_set_size: u64,
    pub observed_unique_members: u64,
    pub max_allocations: u64,
    pub consumed_allocations: u64,
    pub status: PrivacyBucketStatus,
}

impl AntiSybilPrivacyBucket {
    pub fn new(
        epoch_id: &str,
        lane_key: &str,
        bucket_label: &str,
        min_anonymity_set_size: u64,
        max_allocations: u64,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(epoch_id, "pq fee rebate bucket epoch")?;
        ensure_non_empty(lane_key, "pq fee rebate bucket lane")?;
        ensure_non_empty(bucket_label, "pq fee rebate bucket label")?;
        if min_anonymity_set_size == 0 {
            return Err("pq fee rebate bucket anonymity set must be positive".to_string());
        }
        if max_allocations == 0 {
            return Err("pq fee rebate bucket max allocations must be positive".to_string());
        }
        let bucket_label_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BUCKET-LABEL", bucket_label);
        let nullifier_set_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BUCKET-NULLIFIERS", bucket_label);
        let member_commitment_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-BUCKET-MEMBERS", bucket_label);
        let bucket_id = pq_fee_rebate_bucket_id(epoch_id, lane_key, &bucket_label_root);
        let bucket = Self {
            bucket_id,
            epoch_id: epoch_id.to_string(),
            lane_key: lane_key.to_string(),
            bucket_label_root,
            nullifier_set_root,
            member_commitment_root,
            min_anonymity_set_size,
            observed_unique_members: min_anonymity_set_size,
            max_allocations,
            consumed_allocations: 0,
            status: PrivacyBucketStatus::Open,
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.bucket_id, "pq fee rebate bucket id")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate bucket epoch")?;
        ensure_non_empty(&self.lane_key, "pq fee rebate bucket lane")?;
        ensure_non_empty(&self.bucket_label_root, "pq fee rebate bucket label root")?;
        ensure_non_empty(
            &self.nullifier_set_root,
            "pq fee rebate bucket nullifier root",
        )?;
        ensure_non_empty(
            &self.member_commitment_root,
            "pq fee rebate bucket member root",
        )?;
        if self.min_anonymity_set_size == 0 {
            return Err("pq fee rebate bucket anonymity set must be positive".to_string());
        }
        if self.observed_unique_members < self.min_anonymity_set_size {
            return Err("pq fee rebate bucket observed members below anonymity floor".to_string());
        }
        if self.max_allocations == 0 {
            return Err("pq fee rebate bucket max allocations must be positive".to_string());
        }
        if self.consumed_allocations > self.max_allocations {
            return Err("pq fee rebate bucket consumed allocations exceed cap".to_string());
        }
        let expected =
            pq_fee_rebate_bucket_id(&self.epoch_id, &self.lane_key, &self.bucket_label_root);
        if self.bucket_id != expected {
            return Err("pq fee rebate bucket id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for AntiSybilPrivacyBucket {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-ANTI-SYBIL-BUCKET", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "anti_sybil_privacy_bucket",
            "bucket_id": self.bucket_id,
            "epoch_id": self.epoch_id,
            "lane_key": self.lane_key,
            "bucket_label_root": self.bucket_label_root,
            "nullifier_set_root": self.nullifier_set_root,
            "member_commitment_root": self.member_commitment_root,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "observed_unique_members": self.observed_unique_members,
            "max_allocations": self.max_allocations,
            "consumed_allocations": self.consumed_allocations,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeLaneAllocation {
    pub allocation_id: String,
    pub epoch_id: String,
    pub lane_key: String,
    pub bid_id: String,
    pub eligibility_commitment_id: String,
    pub privacy_bucket_id: String,
    pub slot_count: u64,
    pub fee_cap_micro_units: u64,
    pub rebate_bps: u64,
    pub reserved_rebate_units: u64,
    pub execution_hint_root: String,
    pub status: AllocationStatus,
}

impl LowFeeLaneAllocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        lane_key: &str,
        bid_id: &str,
        eligibility_commitment_id: &str,
        privacy_bucket_id: &str,
        slot_count: u64,
        fee_cap_micro_units: u64,
        rebate_bps: u64,
        reserved_rebate_units: u64,
        hint_label: &str,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(epoch_id, "pq fee rebate allocation epoch")?;
        ensure_non_empty(lane_key, "pq fee rebate allocation lane")?;
        ensure_non_empty(bid_id, "pq fee rebate allocation bid")?;
        ensure_non_empty(
            eligibility_commitment_id,
            "pq fee rebate allocation eligibility",
        )?;
        ensure_non_empty(privacy_bucket_id, "pq fee rebate allocation bucket")?;
        ensure_non_empty(hint_label, "pq fee rebate allocation hint")?;
        if slot_count == 0 {
            return Err("pq fee rebate allocation slots must be positive".to_string());
        }
        if fee_cap_micro_units == 0 {
            return Err("pq fee rebate allocation fee cap must be positive".to_string());
        }
        if rebate_bps > config.max_rebate_bps {
            return Err("pq fee rebate allocation rebate exceeds cap".to_string());
        }
        let execution_hint_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-EXECUTION-HINT", hint_label);
        let allocation_id = pq_fee_rebate_allocation_id(
            epoch_id,
            lane_key,
            bid_id,
            eligibility_commitment_id,
            &execution_hint_root,
        );
        let allocation = Self {
            allocation_id,
            epoch_id: epoch_id.to_string(),
            lane_key: lane_key.to_string(),
            bid_id: bid_id.to_string(),
            eligibility_commitment_id: eligibility_commitment_id.to_string(),
            privacy_bucket_id: privacy_bucket_id.to_string(),
            slot_count,
            fee_cap_micro_units,
            rebate_bps,
            reserved_rebate_units,
            execution_hint_root,
            status: AllocationStatus::Reserved,
        };
        allocation.validate(config)?;
        Ok(allocation)
    }

    pub fn validate(
        &self,
        config: &PqFeeRebateAuctionHouseConfig,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.allocation_id, "pq fee rebate allocation id")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate allocation epoch")?;
        ensure_non_empty(&self.lane_key, "pq fee rebate allocation lane")?;
        ensure_non_empty(&self.bid_id, "pq fee rebate allocation bid")?;
        ensure_non_empty(
            &self.eligibility_commitment_id,
            "pq fee rebate allocation eligibility",
        )?;
        ensure_non_empty(&self.privacy_bucket_id, "pq fee rebate allocation bucket")?;
        ensure_non_empty(
            &self.execution_hint_root,
            "pq fee rebate allocation execution hint",
        )?;
        if self.slot_count == 0 {
            return Err("pq fee rebate allocation slots must be positive".to_string());
        }
        if self.fee_cap_micro_units == 0 {
            return Err("pq fee rebate allocation fee cap must be positive".to_string());
        }
        if self.rebate_bps > config.max_rebate_bps {
            return Err("pq fee rebate allocation rebate exceeds cap".to_string());
        }
        let expected = pq_fee_rebate_allocation_id(
            &self.epoch_id,
            &self.lane_key,
            &self.bid_id,
            &self.eligibility_commitment_id,
            &self.execution_hint_root,
        );
        if self.allocation_id != expected {
            return Err("pq fee rebate allocation id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for LowFeeLaneAllocation {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-LOW-FEE-ALLOCATION", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_lane_allocation",
            "allocation_id": self.allocation_id,
            "epoch_id": self.epoch_id,
            "lane_key": self.lane_key,
            "bid_id": self.bid_id,
            "eligibility_commitment_id": self.eligibility_commitment_id,
            "privacy_bucket_id": self.privacy_bucket_id,
            "slot_count": self.slot_count,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "rebate_bps": self.rebate_bps,
            "reserved_rebate_units": self.reserved_rebate_units,
            "execution_hint_root": self.execution_hint_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub allocation_id: String,
    pub epoch_id: String,
    pub lane_key: String,
    pub beneficiary_commitment: String,
    pub actual_fee_micro_units: u64,
    pub rebate_paid_units: u64,
    pub settlement_batch_root: String,
    pub execution_trace_root: String,
    pub settled_at_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        allocation_id: &str,
        epoch_id: &str,
        lane_key: &str,
        beneficiary_label: &str,
        actual_fee_micro_units: u64,
        rebate_paid_units: u64,
        batch_label: &str,
        trace_label: &str,
        settled_at_height: u64,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(allocation_id, "pq fee rebate receipt allocation")?;
        ensure_non_empty(epoch_id, "pq fee rebate receipt epoch")?;
        ensure_non_empty(lane_key, "pq fee rebate receipt lane")?;
        ensure_non_empty(beneficiary_label, "pq fee rebate receipt beneficiary")?;
        ensure_non_empty(batch_label, "pq fee rebate receipt batch")?;
        ensure_non_empty(trace_label, "pq fee rebate receipt trace")?;
        if actual_fee_micro_units == 0 {
            return Err("pq fee rebate receipt actual fee must be positive".to_string());
        }
        let beneficiary_commitment =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-RECEIPT-BENEFICIARY", beneficiary_label);
        let settlement_batch_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-SETTLEMENT-BATCH", batch_label);
        let execution_trace_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-EXECUTION-TRACE", trace_label);
        let receipt_id = pq_fee_rebate_receipt_id(
            allocation_id,
            epoch_id,
            &beneficiary_commitment,
            &settlement_batch_root,
        );
        let receipt = Self {
            receipt_id,
            allocation_id: allocation_id.to_string(),
            epoch_id: epoch_id.to_string(),
            lane_key: lane_key.to_string(),
            beneficiary_commitment,
            actual_fee_micro_units,
            rebate_paid_units,
            settlement_batch_root,
            execution_trace_root,
            settled_at_height,
            status: SettlementStatus::Final,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.receipt_id, "pq fee rebate receipt id")?;
        ensure_non_empty(&self.allocation_id, "pq fee rebate receipt allocation")?;
        ensure_non_empty(&self.epoch_id, "pq fee rebate receipt epoch")?;
        ensure_non_empty(&self.lane_key, "pq fee rebate receipt lane")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "pq fee rebate receipt beneficiary",
        )?;
        ensure_non_empty(
            &self.settlement_batch_root,
            "pq fee rebate receipt settlement batch",
        )?;
        ensure_non_empty(
            &self.execution_trace_root,
            "pq fee rebate receipt execution trace",
        )?;
        if self.actual_fee_micro_units == 0 {
            return Err("pq fee rebate receipt actual fee must be positive".to_string());
        }
        let expected = pq_fee_rebate_receipt_id(
            &self.allocation_id,
            &self.epoch_id,
            &self.beneficiary_commitment,
            &self.settlement_batch_root,
        );
        if self.receipt_id != expected {
            return Err("pq fee rebate receipt id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for SettlementReceipt {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-SETTLEMENT-RECEIPT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "receipt_id": self.receipt_id,
            "allocation_id": self.allocation_id,
            "epoch_id": self.epoch_id,
            "lane_key": self.lane_key,
            "beneficiary_commitment": self.beneficiary_commitment,
            "actual_fee_micro_units": self.actual_fee_micro_units,
            "rebate_paid_units": self.rebate_paid_units,
            "settlement_batch_root": self.settlement_batch_root,
            "execution_trace_root": self.execution_trace_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeSlashEvidence {
    pub evidence_id: String,
    pub challenge_kind: ChallengeKind,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub disputed_state_root: String,
    pub slash_units: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub status: ChallengeStatus,
}

impl ChallengeSlashEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: ChallengeKind,
        target_id: &str,
        challenger_label: &str,
        evidence_label: &str,
        disputed_state_root: &str,
        slash_units: u64,
        opened_at_height: u64,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(target_id, "pq fee rebate challenge target")?;
        ensure_non_empty(challenger_label, "pq fee rebate challenge challenger")?;
        ensure_non_empty(evidence_label, "pq fee rebate challenge evidence")?;
        ensure_non_empty(disputed_state_root, "pq fee rebate challenge disputed root")?;
        let challenger_commitment =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-CHALLENGER", challenger_label);
        let evidence_root =
            pq_fee_rebate_string_root("PQ-FEE-REBATE-CHALLENGE-EVIDENCE", evidence_label);
        let evidence_id = pq_fee_rebate_challenge_id(
            challenge_kind,
            target_id,
            &challenger_commitment,
            &evidence_root,
        );
        let evidence = Self {
            evidence_id,
            challenge_kind,
            target_id: target_id.to_string(),
            challenger_commitment,
            evidence_root,
            disputed_state_root: disputed_state_root.to_string(),
            slash_units,
            opened_at_height,
            resolved_at_height: None,
            status: ChallengeStatus::Open,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        ensure_non_empty(&self.evidence_id, "pq fee rebate challenge id")?;
        ensure_non_empty(&self.target_id, "pq fee rebate challenge target")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "pq fee rebate challenge challenger",
        )?;
        ensure_non_empty(&self.evidence_root, "pq fee rebate challenge evidence")?;
        ensure_non_empty(
            &self.disputed_state_root,
            "pq fee rebate challenge disputed state root",
        )?;
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("pq fee rebate challenge resolved before open".to_string());
            }
        }
        let expected = pq_fee_rebate_challenge_id(
            self.challenge_kind,
            &self.target_id,
            &self.challenger_commitment,
            &self.evidence_root,
        );
        if self.evidence_id != expected {
            return Err("pq fee rebate challenge id mismatch".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeRebateAuctionHouseRooted for ChallengeSlashEvidence {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root(
            "PQ-FEE-REBATE-CHALLENGE-SLASH-EVIDENCE",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_slash_evidence",
            "evidence_id": self.evidence_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "disputed_state_root": self.disputed_state_root,
            "slash_units": self.slash_units,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeRebateAuctionHouseEvent {
    pub event_id: String,
    pub height: u64,
    pub event_kind: String,
    pub subject_id: String,
    pub state_root_after: String,
    pub payload_root: String,
}

impl PqFeeRebateAuctionHouseEvent {
    pub fn new(
        height: u64,
        event_kind: &str,
        subject_id: &str,
        state_root_after: &str,
        payload: &Value,
    ) -> PqFeeRebateAuctionHouseResult<Self> {
        ensure_non_empty(event_kind, "pq fee rebate event kind")?;
        ensure_non_empty(subject_id, "pq fee rebate event subject")?;
        ensure_non_empty(state_root_after, "pq fee rebate event state root")?;
        let payload_root = pq_fee_rebate_payload_root("PQ-FEE-REBATE-EVENT-PAYLOAD", payload);
        let event_id = pq_fee_rebate_event_id(
            height,
            event_kind,
            subject_id,
            state_root_after,
            &payload_root,
        );
        Ok(Self {
            event_id,
            height,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            state_root_after: state_root_after.to_string(),
            payload_root,
        })
    }
}

impl PqFeeRebateAuctionHouseRooted for PqFeeRebateAuctionHouseEvent {
    fn root(&self) -> String {
        pq_fee_rebate_payload_root("PQ-FEE-REBATE-EVENT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fee_rebate_auction_house_event",
            "event_id": self.event_id,
            "height": self.height,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "state_root_after": self.state_root_after,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeRebateAuctionHouseRoots {
    pub config_root: String,
    pub epochs_root: String,
    pub lanes_root: String,
    pub eligibility_commitments_root: String,
    pub sealed_bids_root: String,
    pub bidder_attestations_root: String,
    pub privacy_buckets_root: String,
    pub allocations_root: String,
    pub receipts_root: String,
    pub challenges_root: String,
    pub events_root: String,
}

impl PqFeeRebateAuctionHouseRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "epochs_root": self.epochs_root,
            "lanes_root": self.lanes_root,
            "eligibility_commitments_root": self.eligibility_commitments_root,
            "sealed_bids_root": self.sealed_bids_root,
            "bidder_attestations_root": self.bidder_attestations_root,
            "privacy_buckets_root": self.privacy_buckets_root,
            "allocations_root": self.allocations_root,
            "receipts_root": self.receipts_root,
            "challenges_root": self.challenges_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeRebateAuctionHouseCounters {
    pub epoch_count: usize,
    pub lane_count: usize,
    pub eligibility_commitment_count: usize,
    pub sealed_bid_count: usize,
    pub bidder_attestation_count: usize,
    pub privacy_bucket_count: usize,
    pub allocation_count: usize,
    pub receipt_count: usize,
    pub challenge_count: usize,
    pub event_count: usize,
    pub total_sponsor_budget_units: u64,
    pub total_allocated_units: u64,
    pub total_rebate_paid_units: u64,
    pub total_slashed_units: u64,
}

impl PqFeeRebateAuctionHouseCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_count": self.epoch_count,
            "lane_count": self.lane_count,
            "eligibility_commitment_count": self.eligibility_commitment_count,
            "sealed_bid_count": self.sealed_bid_count,
            "bidder_attestation_count": self.bidder_attestation_count,
            "privacy_bucket_count": self.privacy_bucket_count,
            "allocation_count": self.allocation_count,
            "receipt_count": self.receipt_count,
            "challenge_count": self.challenge_count,
            "event_count": self.event_count,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_allocated_units": self.total_allocated_units,
            "total_rebate_paid_units": self.total_rebate_paid_units,
            "total_slashed_units": self.total_slashed_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeRebateAuctionHouseState {
    pub config: PqFeeRebateAuctionHouseConfig,
    pub height: u64,
    pub epochs: BTreeMap<String, FeeRebateEpoch>,
    pub lanes: BTreeMap<String, LowFeeLane>,
    pub eligibility_commitments: BTreeMap<String, EligibilityCommitment>,
    pub sealed_bids: BTreeMap<String, SealedSponsorBid>,
    pub bidder_attestations: BTreeMap<String, PqBidderAttestation>,
    pub privacy_buckets: BTreeMap<String, AntiSybilPrivacyBucket>,
    pub allocations: BTreeMap<String, LowFeeLaneAllocation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, ChallengeSlashEvidence>,
    pub events: Vec<PqFeeRebateAuctionHouseEvent>,
}

impl PqFeeRebateAuctionHouseState {
    pub fn new(config: PqFeeRebateAuctionHouseConfig, height: u64) -> Self {
        Self {
            config,
            height,
            epochs: BTreeMap::new(),
            lanes: BTreeMap::new(),
            eligibility_commitments: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            bidder_attestations: BTreeMap::new(),
            privacy_buckets: BTreeMap::new(),
            allocations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) -> PqFeeRebateAuctionHouseResult<()> {
        if height < self.height {
            return Err(format!(
                "pq fee rebate auction house height cannot move backward from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        Ok(())
    }

    pub fn devnet() -> PqFeeRebateAuctionHouseResult<Self> {
        let config = PqFeeRebateAuctionHouseConfig::devnet()?;
        let mut state = Self::new(config, PQ_FEE_REBATE_AUCTION_HOUSE_DEVNET_HEIGHT);

        let lane_specs = [
            (
                RebateLaneKind::WalletTransfer,
                "devnet_wallet_transfer",
                "Private wallet transfers",
                2_000_u64,
            ),
            (
                RebateLaneKind::ContractCall,
                "devnet_private_contract_call",
                "Private contract calls",
                1_200_u64,
            ),
            (
                RebateLaneKind::DefiSwap,
                "devnet_defi_swap",
                "Low fee DeFi swaps",
                1_500_u64,
            ),
            (
                RebateLaneKind::MoneroBridgeExit,
                "devnet_monero_bridge_exit",
                "Monero bridge exits",
                900_u64,
            ),
            (
                RebateLaneKind::WalletRecovery,
                "devnet_wallet_recovery",
                "PQ wallet recovery",
                400_u64,
            ),
        ];

        for (kind, key, name, slots) in lane_specs {
            state.insert_lane(LowFeeLane::new(kind, key, name, slots, &state.config)?)?;
        }

        let lane_keys = state.lanes.keys().cloned().collect::<BTreeSet<_>>();
        let mut epoch = FeeRebateEpoch::new(
            0,
            state.height,
            &state.config,
            lane_keys,
            state.config.low_fee_target_micro_units,
            "devnet-fee-rebate-epoch-0",
        )?;

        let wallet_bucket = AntiSybilPrivacyBucket::new(
            &epoch.epoch_id,
            "devnet_wallet_transfer",
            "devnet-wallet-privacy-bucket",
            state.config.min_privacy_set_size,
            4_096,
        )?;
        let contract_bucket = AntiSybilPrivacyBucket::new(
            &epoch.epoch_id,
            "devnet_private_contract_call",
            "devnet-contract-privacy-bucket",
            state.config.min_privacy_set_size,
            2_048,
        )?;
        let defi_bucket = AntiSybilPrivacyBucket::new(
            &epoch.epoch_id,
            "devnet_defi_swap",
            "devnet-defi-privacy-bucket",
            state.config.min_privacy_set_size,
            2_048,
        )?;
        let bridge_bucket = AntiSybilPrivacyBucket::new(
            &epoch.epoch_id,
            "devnet_monero_bridge_exit",
            "devnet-bridge-privacy-bucket",
            state.config.min_privacy_set_size,
            1_024,
        )?;
        let recovery_bucket = AntiSybilPrivacyBucket::new(
            &epoch.epoch_id,
            "devnet_wallet_recovery",
            "devnet-recovery-privacy-bucket",
            state.config.min_privacy_set_size,
            512,
        )?;

        let wallet_bucket_id = wallet_bucket.bucket_id.clone();
        let contract_bucket_id = contract_bucket.bucket_id.clone();
        let defi_bucket_id = defi_bucket.bucket_id.clone();
        let bridge_bucket_id = bridge_bucket.bucket_id.clone();
        let recovery_bucket_id = recovery_bucket.bucket_id.clone();

        state.insert_privacy_bucket(wallet_bucket)?;
        state.insert_privacy_bucket(contract_bucket)?;
        state.insert_privacy_bucket(defi_bucket)?;
        state.insert_privacy_bucket(bridge_bucket)?;
        state.insert_privacy_bucket(recovery_bucket)?;

        let eligibility_wallet = EligibilityCommitment::new(
            &epoch.epoch_id,
            EligibilitySubjectKind::Wallet,
            "devnet-wallet-alice",
            "devnet_wallet_transfer",
            &wallet_bucket_id,
            "devnet-wallet-alice-nullifier",
            650,
            &json!({"purpose": "low_fee_private_transfer", "devnet": true}),
        )?;
        let eligibility_contract = EligibilityCommitment::new(
            &epoch.epoch_id,
            EligibilitySubjectKind::Contract,
            "devnet-private-amm-contract",
            "devnet_private_contract_call",
            &contract_bucket_id,
            "devnet-contract-amm-nullifier",
            1_350,
            &json!({"purpose": "contract_call", "ux": "sponsored_private_execution"}),
        )?;
        let eligibility_defi = EligibilityCommitment::new(
            &epoch.epoch_id,
            EligibilitySubjectKind::LiquidityVault,
            "devnet-defi-vault",
            "devnet_defi_swap",
            &defi_bucket_id,
            "devnet-defi-vault-nullifier",
            1_100,
            &json!({"purpose": "defi_swap", "router": "private_amm"}),
        )?;
        let eligibility_bridge = EligibilityCommitment::new(
            &epoch.epoch_id,
            EligibilitySubjectKind::SmartAccount,
            "devnet-monero-exit-wallet",
            "devnet_monero_bridge_exit",
            &bridge_bucket_id,
            "devnet-bridge-exit-nullifier",
            900,
            &json!({"purpose": "monero_bridge_exit", "privacy": "subaddress_commitment"}),
        )?;
        let eligibility_recovery = EligibilityCommitment::new(
            &epoch.epoch_id,
            EligibilitySubjectKind::Wallet,
            "devnet-recovery-wallet",
            "devnet_wallet_recovery",
            &recovery_bucket_id,
            "devnet-recovery-nullifier",
            500,
            &json!({"purpose": "pq_wallet_recovery", "urgency": "high"}),
        )?;

        let eligibility_wallet_id = eligibility_wallet.commitment_id.clone();
        let eligibility_contract_id = eligibility_contract.commitment_id.clone();
        let eligibility_defi_id = eligibility_defi.commitment_id.clone();
        let eligibility_bridge_id = eligibility_bridge.commitment_id.clone();
        let eligibility_recovery_id = eligibility_recovery.commitment_id.clone();

        state.insert_eligibility_commitment(eligibility_wallet)?;
        state.insert_eligibility_commitment(eligibility_contract)?;
        state.insert_eligibility_commitment(eligibility_defi)?;
        state.insert_eligibility_commitment(eligibility_bridge)?;
        state.insert_eligibility_commitment(eligibility_recovery)?;

        let mut sponsor_a_lanes = BTreeSet::new();
        sponsor_a_lanes.insert("devnet_wallet_transfer".to_string());
        sponsor_a_lanes.insert("devnet_defi_swap".to_string());
        sponsor_a_lanes.insert("devnet_monero_bridge_exit".to_string());
        let attestation_a = PqBidderAttestation::new(
            "devnet-sponsor-a",
            &epoch.epoch_id,
            "devnet-sponsor-a-ml-dsa-key",
            "devnet-sponsor-a-reserve",
            "devnet-sponsor-a-transcript",
            sponsor_a_lanes,
            256,
            state.height,
            epoch.challenge_close_height,
        )?;

        let mut sponsor_b_lanes = BTreeSet::new();
        sponsor_b_lanes.insert("devnet_private_contract_call".to_string());
        sponsor_b_lanes.insert("devnet_wallet_recovery".to_string());
        let attestation_b = PqBidderAttestation::new(
            "devnet-sponsor-b",
            &epoch.epoch_id,
            "devnet-sponsor-b-ml-dsa-key",
            "devnet-sponsor-b-reserve",
            "devnet-sponsor-b-transcript",
            sponsor_b_lanes,
            256,
            state.height,
            epoch.challenge_close_height,
        )?;

        let bidder_a = attestation_a.bidder_id.clone();
        let bidder_b = attestation_b.bidder_id.clone();
        let attestation_a_id = attestation_a.attestation_id.clone();
        let attestation_b_id = attestation_b.attestation_id.clone();
        state.insert_bidder_attestation(attestation_a)?;
        state.insert_bidder_attestation(attestation_b)?;

        let bid_wallet = SealedSponsorBid::new(
            &epoch.epoch_id,
            &bidder_a,
            &attestation_a_id,
            "devnet_wallet_transfer",
            "devnet-wallet-transfer-sponsor-bid",
            75_000_000,
            8_500,
            1_500,
            state.config.min_sponsor_bond_units,
            &state.config,
        )?;
        let bid_defi = SealedSponsorBid::new(
            &epoch.epoch_id,
            &bidder_a,
            &attestation_a_id,
            "devnet_defi_swap",
            "devnet-defi-sponsor-bid",
            65_000_000,
            8_000,
            1_100,
            state.config.min_sponsor_bond_units,
            &state.config,
        )?;
        let bid_contract = SealedSponsorBid::new(
            &epoch.epoch_id,
            &bidder_b,
            &attestation_b_id,
            "devnet_private_contract_call",
            "devnet-contract-sponsor-bid",
            60_000_000,
            7_500,
            900,
            state.config.min_sponsor_bond_units,
            &state.config,
        )?;
        let bid_recovery = SealedSponsorBid::new(
            &epoch.epoch_id,
            &bidder_b,
            &attestation_b_id,
            "devnet_wallet_recovery",
            "devnet-recovery-sponsor-bid",
            20_000_000,
            9_000,
            300,
            state.config.min_sponsor_bond_units,
            &state.config,
        )?;

        let bid_wallet_id = bid_wallet.bid_id.clone();
        let bid_defi_id = bid_defi.bid_id.clone();
        let bid_contract_id = bid_contract.bid_id.clone();
        let bid_recovery_id = bid_recovery.bid_id.clone();
        epoch.total_sponsor_budget_units = epoch
            .total_sponsor_budget_units
            .saturating_add(bid_wallet.bid_budget_units)
            .saturating_add(bid_defi.bid_budget_units)
            .saturating_add(bid_contract.bid_budget_units)
            .saturating_add(bid_recovery.bid_budget_units);
        state.insert_sealed_bid(bid_wallet)?;
        state.insert_sealed_bid(bid_defi)?;
        state.insert_sealed_bid(bid_contract)?;
        state.insert_sealed_bid(bid_recovery)?;

        let allocation_wallet = LowFeeLaneAllocation::new(
            &epoch.epoch_id,
            "devnet_wallet_transfer",
            &bid_wallet_id,
            &eligibility_wallet_id,
            &wallet_bucket_id,
            1,
            650,
            8_500,
            420,
            "devnet-wallet-transfer-execution-hint",
            &state.config,
        )?;
        let allocation_contract = LowFeeLaneAllocation::new(
            &epoch.epoch_id,
            "devnet_private_contract_call",
            &bid_contract_id,
            &eligibility_contract_id,
            &contract_bucket_id,
            1,
            1_350,
            7_500,
            900,
            "devnet-contract-execution-hint",
            &state.config,
        )?;
        let allocation_defi = LowFeeLaneAllocation::new(
            &epoch.epoch_id,
            "devnet_defi_swap",
            &bid_defi_id,
            &eligibility_defi_id,
            &defi_bucket_id,
            1,
            1_100,
            8_000,
            760,
            "devnet-defi-execution-hint",
            &state.config,
        )?;
        let allocation_recovery = LowFeeLaneAllocation::new(
            &epoch.epoch_id,
            "devnet_wallet_recovery",
            &bid_recovery_id,
            &eligibility_recovery_id,
            &recovery_bucket_id,
            1,
            500,
            9_000,
            450,
            "devnet-recovery-execution-hint",
            &state.config,
        )?;
        let allocation_bridge = LowFeeLaneAllocation::new(
            &epoch.epoch_id,
            "devnet_monero_bridge_exit",
            &bid_wallet_id,
            &eligibility_bridge_id,
            &bridge_bucket_id,
            1,
            900,
            8_000,
            680,
            "devnet-bridge-exit-execution-hint",
            &state.config,
        )?;

        let allocation_wallet_id = allocation_wallet.allocation_id.clone();
        let allocation_contract_id = allocation_contract.allocation_id.clone();
        let allocation_defi_id = allocation_defi.allocation_id.clone();
        let allocation_recovery_id = allocation_recovery.allocation_id.clone();
        let allocation_bridge_id = allocation_bridge.allocation_id.clone();
        epoch.total_allocated_units = allocation_wallet
            .reserved_rebate_units
            .saturating_add(allocation_contract.reserved_rebate_units)
            .saturating_add(allocation_defi.reserved_rebate_units)
            .saturating_add(allocation_recovery.reserved_rebate_units)
            .saturating_add(allocation_bridge.reserved_rebate_units);
        state.insert_allocation(allocation_wallet)?;
        state.insert_allocation(allocation_contract)?;
        state.insert_allocation(allocation_defi)?;
        state.insert_allocation(allocation_recovery)?;
        state.insert_allocation(allocation_bridge)?;

        let receipt_wallet = SettlementReceipt::new(
            &allocation_wallet_id,
            &epoch.epoch_id,
            "devnet_wallet_transfer",
            "devnet-wallet-alice",
            610,
            390,
            "devnet-settlement-batch-0",
            "devnet-wallet-transfer-trace",
            state.height.saturating_add(12),
        )?;
        let receipt_contract = SettlementReceipt::new(
            &allocation_contract_id,
            &epoch.epoch_id,
            "devnet_private_contract_call",
            "devnet-private-amm-contract",
            1_200,
            820,
            "devnet-settlement-batch-0",
            "devnet-contract-call-trace",
            state.height.saturating_add(13),
        )?;
        let receipt_defi = SettlementReceipt::new(
            &allocation_defi_id,
            &epoch.epoch_id,
            "devnet_defi_swap",
            "devnet-defi-vault",
            980,
            700,
            "devnet-settlement-batch-0",
            "devnet-defi-swap-trace",
            state.height.saturating_add(14),
        )?;
        let receipt_recovery = SettlementReceipt::new(
            &allocation_recovery_id,
            &epoch.epoch_id,
            "devnet_wallet_recovery",
            "devnet-recovery-wallet",
            460,
            430,
            "devnet-settlement-batch-0",
            "devnet-recovery-trace",
            state.height.saturating_add(15),
        )?;
        epoch.total_settled_rebate_units = receipt_wallet
            .rebate_paid_units
            .saturating_add(receipt_contract.rebate_paid_units)
            .saturating_add(receipt_defi.rebate_paid_units)
            .saturating_add(receipt_recovery.rebate_paid_units);
        state.insert_receipt(receipt_wallet)?;
        state.insert_receipt(receipt_contract)?;
        state.insert_receipt(receipt_defi)?;
        state.insert_receipt(receipt_recovery)?;

        epoch.status = RebateEpochStatus::Settling;
        epoch.clearing_price_micro_units = 625;
        epoch.fairness_score_bps = 8_850;
        state.insert_epoch(epoch)?;

        let disputed_root = state.state_root();
        let mut challenge = ChallengeSlashEvidence::new(
            ChallengeKind::FeeCapViolation,
            &allocation_bridge_id,
            "devnet-watchtower-alpha",
            "bridge-exit-fee-cap-sample",
            &disputed_root,
            125_000,
            state.height.saturating_add(18),
        )?;
        challenge.status = ChallengeStatus::Accepted;
        challenge.resolved_at_height = Some(state.height.saturating_add(21));
        state.insert_challenge(challenge)?;

        state.record_event(
            state.height,
            "devnet_initialized",
            "pq_fee_rebate_auction_house",
            &json!({"epochs": state.epochs.len(), "lanes": state.lanes.len()}),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_epoch(&mut self, epoch: FeeRebateEpoch) -> PqFeeRebateAuctionHouseResult<String> {
        if self.epochs.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EPOCHS
            && !self.epochs.contains_key(&epoch.epoch_id)
        {
            return Err("pq fee rebate epoch capacity exceeded".to_string());
        }
        epoch.validate(&self.config)?;
        let epoch_id = epoch.epoch_id.clone();
        self.epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn insert_lane(&mut self, lane: LowFeeLane) -> PqFeeRebateAuctionHouseResult<String> {
        lane.validate(&self.config)?;
        let lane_key = lane.lane_key.clone();
        self.lanes.insert(lane_key.clone(), lane);
        Ok(lane_key)
    }

    pub fn insert_eligibility_commitment(
        &mut self,
        commitment: EligibilityCommitment,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.eligibility_commitments.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_COMMITMENTS
            && !self
                .eligibility_commitments
                .contains_key(&commitment.commitment_id)
        {
            return Err("pq fee rebate eligibility capacity exceeded".to_string());
        }
        if !self.lanes.contains_key(&commitment.lane_key) {
            return Err("pq fee rebate eligibility references unknown lane".to_string());
        }
        if !self
            .privacy_buckets
            .contains_key(&commitment.privacy_bucket_id)
        {
            return Err("pq fee rebate eligibility references unknown bucket".to_string());
        }
        commitment.validate()?;
        let commitment_id = commitment.commitment_id.clone();
        self.eligibility_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_sealed_bid(
        &mut self,
        bid: SealedSponsorBid,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.sealed_bids.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BIDS
            && !self.sealed_bids.contains_key(&bid.bid_id)
        {
            return Err("pq fee rebate sealed bid capacity exceeded".to_string());
        }
        if !self.lanes.contains_key(&bid.lane_key) {
            return Err("pq fee rebate bid references unknown lane".to_string());
        }
        if !self.bidder_attestations.contains_key(&bid.attestation_id) {
            return Err("pq fee rebate bid references unknown attestation".to_string());
        }
        bid.validate(&self.config)?;
        let bid_id = bid.bid_id.clone();
        self.sealed_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn insert_bidder_attestation(
        &mut self,
        attestation: PqBidderAttestation,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.bidder_attestations.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ATTESTATIONS
            && !self
                .bidder_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("pq fee rebate bidder attestation capacity exceeded".to_string());
        }
        for lane_key in &attestation.supported_lanes {
            if !self.lanes.contains_key(lane_key) {
                return Err("pq fee rebate bidder attestation references unknown lane".to_string());
            }
        }
        attestation.validate(self.config.min_pq_security_bits)?;
        let attestation_id = attestation.attestation_id.clone();
        self.bidder_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_privacy_bucket(
        &mut self,
        bucket: AntiSybilPrivacyBucket,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.privacy_buckets.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BUCKETS
            && !self.privacy_buckets.contains_key(&bucket.bucket_id)
        {
            return Err("pq fee rebate privacy bucket capacity exceeded".to_string());
        }
        if !self.lanes.contains_key(&bucket.lane_key) {
            return Err("pq fee rebate privacy bucket references unknown lane".to_string());
        }
        if bucket.min_anonymity_set_size < self.config.min_privacy_set_size {
            return Err(
                "pq fee rebate privacy bucket below configured anonymity floor".to_string(),
            );
        }
        bucket.validate()?;
        let bucket_id = bucket.bucket_id.clone();
        self.privacy_buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    pub fn insert_allocation(
        &mut self,
        allocation: LowFeeLaneAllocation,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.allocations.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ALLOCATIONS
            && !self.allocations.contains_key(&allocation.allocation_id)
        {
            return Err("pq fee rebate allocation capacity exceeded".to_string());
        }
        if !self.lanes.contains_key(&allocation.lane_key) {
            return Err("pq fee rebate allocation references unknown lane".to_string());
        }
        if !self.sealed_bids.contains_key(&allocation.bid_id) {
            return Err("pq fee rebate allocation references unknown bid".to_string());
        }
        if !self
            .eligibility_commitments
            .contains_key(&allocation.eligibility_commitment_id)
        {
            return Err("pq fee rebate allocation references unknown eligibility".to_string());
        }
        if !self
            .privacy_buckets
            .contains_key(&allocation.privacy_bucket_id)
        {
            return Err("pq fee rebate allocation references unknown bucket".to_string());
        }
        allocation.validate(&self.config)?;
        let allocation_id = allocation.allocation_id.clone();
        self.allocations.insert(allocation_id.clone(), allocation);
        Ok(allocation_id)
    }

    pub fn insert_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.receipts.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_RECEIPTS
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("pq fee rebate receipt capacity exceeded".to_string());
        }
        if !self.allocations.contains_key(&receipt.allocation_id) {
            return Err("pq fee rebate receipt references unknown allocation".to_string());
        }
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeSlashEvidence,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.challenges.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_CHALLENGES
            && !self.challenges.contains_key(&challenge.evidence_id)
        {
            return Err("pq fee rebate challenge capacity exceeded".to_string());
        }
        challenge.validate()?;
        let challenge_id = challenge.evidence_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn record_event(
        &mut self,
        height: u64,
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> PqFeeRebateAuctionHouseResult<String> {
        if self.events.len() >= PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EVENTS {
            return Err("pq fee rebate event capacity exceeded".to_string());
        }
        let state_root_after = self.state_root();
        let event = PqFeeRebateAuctionHouseEvent::new(
            height,
            event_kind,
            subject_id,
            &state_root_after,
            payload,
        )?;
        let event_id = event.event_id.clone();
        self.events.push(event);
        Ok(event_id)
    }

    pub fn roots(&self) -> PqFeeRebateAuctionHouseRoots {
        PqFeeRebateAuctionHouseRoots {
            config_root: self.config.root(),
            epochs_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-EPOCHS",
                self.epochs
                    .values()
                    .map(FeeRebateEpoch::public_record)
                    .collect(),
            ),
            lanes_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-LANES",
                self.lanes.values().map(LowFeeLane::public_record).collect(),
            ),
            eligibility_commitments_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-ELIGIBILITY-COMMITMENTS",
                self.eligibility_commitments
                    .values()
                    .map(EligibilityCommitment::public_record)
                    .collect(),
            ),
            sealed_bids_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-SEALED-BIDS",
                self.sealed_bids
                    .values()
                    .map(SealedSponsorBid::public_record)
                    .collect(),
            ),
            bidder_attestations_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-BIDDER-ATTESTATIONS",
                self.bidder_attestations
                    .values()
                    .map(PqBidderAttestation::public_record)
                    .collect(),
            ),
            privacy_buckets_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-PRIVACY-BUCKETS",
                self.privacy_buckets
                    .values()
                    .map(AntiSybilPrivacyBucket::public_record)
                    .collect(),
            ),
            allocations_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-ALLOCATIONS",
                self.allocations
                    .values()
                    .map(LowFeeLaneAllocation::public_record)
                    .collect(),
            ),
            receipts_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-RECEIPTS",
                self.receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            challenges_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-CHALLENGES",
                self.challenges
                    .values()
                    .map(ChallengeSlashEvidence::public_record)
                    .collect(),
            ),
            events_root: pq_fee_rebate_merkle_records(
                "PQ-FEE-REBATE-EVENTS",
                self.events
                    .iter()
                    .map(PqFeeRebateAuctionHouseEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqFeeRebateAuctionHouseCounters {
        let total_sponsor_budget_units = self
            .sealed_bids
            .values()
            .fold(0_u64, |acc, bid| acc.saturating_add(bid.bid_budget_units));
        let total_allocated_units = self.allocations.values().fold(0_u64, |acc, allocation| {
            acc.saturating_add(allocation.reserved_rebate_units)
        });
        let total_rebate_paid_units = self.receipts.values().fold(0_u64, |acc, receipt| {
            acc.saturating_add(receipt.rebate_paid_units)
        });
        let total_slashed_units = self
            .challenges
            .values()
            .filter(|challenge| {
                matches!(
                    challenge.status,
                    ChallengeStatus::Accepted | ChallengeStatus::Slashed
                )
            })
            .fold(0_u64, |acc, challenge| {
                acc.saturating_add(challenge.slash_units)
            });
        PqFeeRebateAuctionHouseCounters {
            epoch_count: self.epochs.len(),
            lane_count: self.lanes.len(),
            eligibility_commitment_count: self.eligibility_commitments.len(),
            sealed_bid_count: self.sealed_bids.len(),
            bidder_attestation_count: self.bidder_attestations.len(),
            privacy_bucket_count: self.privacy_buckets.len(),
            allocation_count: self.allocations.len(),
            receipt_count: self.receipts.len(),
            challenge_count: self.challenges.len(),
            event_count: self.events.len(),
            total_sponsor_budget_units,
            total_allocated_units,
            total_rebate_paid_units,
            total_slashed_units,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_fee_rebate_auction_house_state",
            "height": self.height,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_fee_rebate_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert(
                "pq_fee_rebate_auction_house_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn validate(&self) -> PqFeeRebateAuctionHouseResult<String> {
        self.config.validate()?;
        if self.epochs.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EPOCHS {
            return Err("pq fee rebate state has too many epochs".to_string());
        }
        if self.eligibility_commitments.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_COMMITMENTS {
            return Err("pq fee rebate state has too many eligibility commitments".to_string());
        }
        if self.sealed_bids.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BIDS {
            return Err("pq fee rebate state has too many sealed bids".to_string());
        }
        if self.bidder_attestations.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ATTESTATIONS {
            return Err("pq fee rebate state has too many bidder attestations".to_string());
        }
        if self.privacy_buckets.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_BUCKETS {
            return Err("pq fee rebate state has too many privacy buckets".to_string());
        }
        if self.allocations.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_ALLOCATIONS {
            return Err("pq fee rebate state has too many allocations".to_string());
        }
        if self.receipts.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_RECEIPTS {
            return Err("pq fee rebate state has too many receipts".to_string());
        }
        if self.challenges.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_CHALLENGES {
            return Err("pq fee rebate state has too many challenges".to_string());
        }
        if self.events.len() > PQ_FEE_REBATE_AUCTION_HOUSE_MAX_EVENTS {
            return Err("pq fee rebate state has too many events".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for epoch in self.epochs.values() {
            epoch.validate(&self.config)?;
            for lane_key in &epoch.lane_keys {
                if !self.lanes.contains_key(lane_key) {
                    return Err("pq fee rebate epoch references unknown lane".to_string());
                }
            }
        }
        for bucket in self.privacy_buckets.values() {
            bucket.validate()?;
            if !self.lanes.contains_key(&bucket.lane_key) {
                return Err("pq fee rebate bucket references unknown lane".to_string());
            }
        }
        for commitment in self.eligibility_commitments.values() {
            commitment.validate()?;
            if !self.lanes.contains_key(&commitment.lane_key) {
                return Err("pq fee rebate eligibility references unknown lane".to_string());
            }
            if !self
                .privacy_buckets
                .contains_key(&commitment.privacy_bucket_id)
            {
                return Err("pq fee rebate eligibility references unknown bucket".to_string());
            }
        }
        for attestation in self.bidder_attestations.values() {
            attestation.validate(self.config.min_pq_security_bits)?;
            for lane_key in &attestation.supported_lanes {
                if !self.lanes.contains_key(lane_key) {
                    return Err(
                        "pq fee rebate attestation references unknown supported lane".to_string(),
                    );
                }
            }
        }
        for bid in self.sealed_bids.values() {
            bid.validate(&self.config)?;
            if !self.lanes.contains_key(&bid.lane_key) {
                return Err("pq fee rebate bid references unknown lane".to_string());
            }
            let attestation = self
                .bidder_attestations
                .get(&bid.attestation_id)
                .ok_or_else(|| "pq fee rebate bid references unknown attestation".to_string())?;
            if attestation.bidder_id != bid.bidder_id {
                return Err("pq fee rebate bid bidder does not match attestation".to_string());
            }
            if !attestation.supported_lanes.contains(&bid.lane_key) {
                return Err("pq fee rebate bid lane not supported by attestation".to_string());
            }
        }
        for allocation in self.allocations.values() {
            allocation.validate(&self.config)?;
            if !self.sealed_bids.contains_key(&allocation.bid_id) {
                return Err("pq fee rebate allocation references unknown bid".to_string());
            }
            if !self
                .eligibility_commitments
                .contains_key(&allocation.eligibility_commitment_id)
            {
                return Err("pq fee rebate allocation references unknown eligibility".to_string());
            }
            if !self
                .privacy_buckets
                .contains_key(&allocation.privacy_bucket_id)
            {
                return Err("pq fee rebate allocation references unknown bucket".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.allocations.contains_key(&receipt.allocation_id) {
                return Err("pq fee rebate receipt references unknown allocation".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn pq_fee_rebate_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-FEE-REBATE-AUCTION-HOUSE-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn pq_fee_rebate_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

pub fn pq_fee_rebate_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn pq_fee_rebate_config_id(
    protocol_version: &str,
    schema_version: u64,
    fee_asset_id: &str,
    rebate_asset_id: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(protocol_version),
            HashPart::Int(schema_version as i128),
            HashPart::Str(fee_asset_id),
            HashPart::Str(rebate_asset_id),
        ],
        32,
    )
}

pub fn pq_fee_rebate_epoch_id(
    epoch_index: u64,
    start_height: u64,
    public_entropy_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Str(public_entropy_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_lane_id(lane_key: &str, lane_kind: RebateLaneKind) -> String {
    domain_hash(
        "PQ-FEE-REBATE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_key),
            HashPart::Str(lane_kind.as_str()),
        ],
        32,
    )
}

pub fn pq_fee_rebate_bidder_id(bidder_label: &str) -> String {
    domain_hash(
        "PQ-FEE-REBATE-BIDDER-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(bidder_label)],
        32,
    )
}

pub fn pq_fee_rebate_subject_commitment(
    subject_kind: EligibilitySubjectKind,
    subject_label: &str,
    epoch_id: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-SUBJECT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_label),
            HashPart::Str(epoch_id),
        ],
        32,
    )
}

pub fn pq_fee_rebate_eligibility_id(
    epoch_id: &str,
    subject_commitment: &str,
    lane_key: &str,
    nullifier_hash: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-ELIGIBILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(subject_commitment),
            HashPart::Str(lane_key),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

pub fn pq_fee_rebate_attestation_id(
    bidder_id: &str,
    epoch_id: &str,
    pq_verification_key_root: &str,
    signature_transcript_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bidder_id),
            HashPart::Str(epoch_id),
            HashPart::Str(pq_verification_key_root),
            HashPart::Str(signature_transcript_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_bid_id(
    epoch_id: &str,
    bidder_id: &str,
    lane_key: &str,
    sealed_bid_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(bidder_id),
            HashPart::Str(lane_key),
            HashPart::Str(sealed_bid_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_bucket_id(epoch_id: &str, lane_key: &str, bucket_label_root: &str) -> String {
    domain_hash(
        "PQ-FEE-REBATE-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_key),
            HashPart::Str(bucket_label_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_allocation_id(
    epoch_id: &str,
    lane_key: &str,
    bid_id: &str,
    eligibility_commitment_id: &str,
    execution_hint_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-ALLOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_key),
            HashPart::Str(bid_id),
            HashPart::Str(eligibility_commitment_id),
            HashPart::Str(execution_hint_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_receipt_id(
    allocation_id: &str,
    epoch_id: &str,
    beneficiary_commitment: &str,
    settlement_batch_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(allocation_id),
            HashPart::Str(epoch_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(settlement_batch_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_challenge_id(
    challenge_kind: ChallengeKind,
    target_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn pq_fee_rebate_event_id(
    height: u64,
    event_kind: &str,
    subject_id: &str,
    state_root_after: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-REBATE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(state_root_after),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

fn pq_fee_rebate_merkle_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> PqFeeRebateAuctionHouseResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
