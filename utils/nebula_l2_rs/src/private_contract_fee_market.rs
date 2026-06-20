use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateContractFeeMarketResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_FEE_MARKET_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEVNET_HEIGHT: u64 = 192;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_CONTRACT_FEE_MARKET_DEVNET_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_CONTRACT_FEE_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_FEE_MARKET_PQ_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-fee-policy-v1";
pub const PRIVATE_CONTRACT_FEE_MARKET_PRICE_COMMITMENT_SCHEME: &str =
    "encrypted-contract-fee-price-commitment-v1";
pub const PRIVATE_CONTRACT_FEE_MARKET_DEMAND_BUCKET_SCHEME: &str =
    "shielded-contract-demand-bucket-v1";
pub const PRIVATE_CONTRACT_FEE_MARKET_SPONSOR_BOOK_SCHEME: &str =
    "private-contract-sponsor-book-v1";
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 64;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_160;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 1_200;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MAX_SURGE_BPS: u64 = 4_000;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_TARGET_FILL_BPS: u64 = 7_000;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6_500;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_EMERGENCY_REBATE_BPS: u64 = 9_000;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_LANES: usize = 256;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_EPOCHS: usize = 131_072;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_BUCKETS: usize = 524_288;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_QUOTES: usize = 524_288;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_SPONSORS: usize = 131_072;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_REBATES: usize = 524_288;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_CONTRACT_FEE_MARKET_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractFeeLaneKind {
    PrivateTransfer,
    ShieldedSwap,
    VaultDeposit,
    VaultRedeem,
    LendingAction,
    DerivativesAction,
    GovernanceVote,
    NftMint,
    AccountRecovery,
    MoneroExit,
    EmergencyAction,
}

impl ContractFeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ShieldedSwap => "shielded_swap",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::LendingAction => "lending_action",
            Self::DerivativesAction => "derivatives_action",
            Self::GovernanceVote => "governance_vote",
            Self::NftMint => "nft_mint",
            Self::AccountRecovery => "account_recovery",
            Self::MoneroExit => "monero_exit",
            Self::EmergencyAction => "emergency_action",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyAction => 120,
            Self::AccountRecovery => 110,
            Self::MoneroExit => 100,
            Self::PrivateTransfer => 90,
            Self::ShieldedSwap => 80,
            Self::VaultDeposit | Self::VaultRedeem => 70,
            Self::LendingAction | Self::DerivativesAction => 65,
            Self::GovernanceVote => 55,
            Self::NftMint => 50,
        }
    }

    pub fn default_fee_multiplier_bps(self) -> u64 {
        match self {
            Self::EmergencyAction => 6_000,
            Self::AccountRecovery => 5_000,
            Self::PrivateTransfer => 7_500,
            Self::GovernanceVote => 8_000,
            Self::MoneroExit => 10_000,
            Self::ShieldedSwap => 11_000,
            Self::VaultDeposit | Self::VaultRedeem => 11_500,
            Self::LendingAction | Self::DerivativesAction => 12_500,
            Self::NftMint => 13_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneStatus {
    Draft,
    Active,
    Congested,
    LowFeeOnly,
    EmergencyOnly,
    Paused,
    Retired,
}

impl FeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Congested => "congested",
            Self::LowFeeOnly => "low_fee_only",
            Self::EmergencyOnly => "emergency_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::LowFeeOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemandBucketStatus {
    Open,
    Sealed,
    Priced,
    Expired,
    Disputed,
}

impl DemandBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Priced => "priced",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeQuoteStatus {
    Quoted,
    Reserved,
    Sponsored,
    Consumed,
    Refunded,
    Expired,
    Rejected,
}

impl FeeQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Sponsored => "sponsored",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Quoted | Self::Reserved | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBookStatus {
    Active,
    Replenishing,
    Exhausted,
    Paused,
    Slashed,
    Closed,
}

impl SponsorBookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Replenishing => "replenishing",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Replenishing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateStatus {
    Accruing,
    Claimable,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl FeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractFeeMarketConfig {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub protocol_version: u32,
    pub hash_suite: String,
    pub pq_suite: String,
    pub price_commitment_scheme: String,
    pub demand_bucket_scheme: String,
    pub sponsor_book_scheme: String,
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub base_fee_micro_units: u64,
    pub max_surge_bps: u64,
    pub target_fill_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub emergency_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl PrivateContractFeeMarketConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_CONTRACT_FEE_MARKET_DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: PRIVATE_CONTRACT_FEE_MARKET_DEVNET_REBATE_ASSET_ID.to_string(),
            protocol_version: PRIVATE_CONTRACT_FEE_MARKET_PROTOCOL_VERSION,
            hash_suite: PRIVATE_CONTRACT_FEE_MARKET_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_CONTRACT_FEE_MARKET_PQ_SUITE.to_string(),
            price_commitment_scheme: PRIVATE_CONTRACT_FEE_MARKET_PRICE_COMMITMENT_SCHEME
                .to_string(),
            demand_bucket_scheme: PRIVATE_CONTRACT_FEE_MARKET_DEMAND_BUCKET_SCHEME.to_string(),
            sponsor_book_scheme: PRIVATE_CONTRACT_FEE_MARKET_SPONSOR_BOOK_SCHEME.to_string(),
            epoch_blocks: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_QUOTE_TTL_BLOCKS,
            rebate_ttl_blocks: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_REBATE_TTL_BLOCKS,
            base_fee_micro_units: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_BASE_FEE_MICRO_UNITS,
            max_surge_bps: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MAX_SURGE_BPS,
            target_fill_bps: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_TARGET_FILL_BPS,
            low_fee_rebate_bps: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_LOW_FEE_REBATE_BPS,
            emergency_rebate_bps: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_EMERGENCY_REBATE_BPS,
            min_privacy_set_size: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_CONTRACT_FEE_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "price_commitment_scheme": self.price_commitment_scheme,
            "demand_bucket_scheme": self.demand_bucket_scheme,
            "sponsor_book_scheme": self.sponsor_book_scheme,
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_surge_bps": self.max_surge_bps,
            "target_fill_bps": self.target_fill_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "emergency_rebate_bps": self.emergency_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn validate(&self) -> PrivateContractFeeMarketResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private contract fee market chain id mismatch".to_string());
        }
        if self.epoch_blocks == 0 || self.quote_ttl_blocks == 0 {
            return Err(
                "private contract fee market epoch and quote ttl must be non-zero".to_string(),
            );
        }
        if self.target_fill_bps > PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS {
            return Err(
                "private contract fee market target fill exceeds bps denominator".to_string(),
            );
        }
        if self.low_fee_rebate_bps > PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS
            || self.emergency_rebate_bps > PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS
        {
            return Err("private contract fee market rebate exceeds bps denominator".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("private contract fee market pq security too low".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFeeLane {
    pub lane_id: String,
    pub kind: ContractFeeLaneKind,
    pub status: FeeLaneStatus,
    pub contract_family: String,
    pub base_fee_micro_units: u64,
    pub surge_bps: u64,
    pub priority_weight: u64,
    pub max_batch_units: u64,
    pub sponsor_book_ids: BTreeSet<String>,
    pub policy_root: String,
}

impl ContractFeeLane {
    pub fn devnet(
        lane_id: impl Into<String>,
        kind: ContractFeeLaneKind,
        config: &PrivateContractFeeMarketConfig,
    ) -> Self {
        let lane_id = lane_id.into();
        let base_fee_micro_units = config
            .base_fee_micro_units
            .saturating_mul(kind.default_fee_multiplier_bps())
            / PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS;
        Self {
            policy_root: hash32(
                "private_contract_fee_lane_policy",
                &[HashPart::Str(&lane_id), HashPart::Str(kind.as_str())],
            ),
            contract_family: format!("{}-family", kind.as_str()),
            priority_weight: kind.default_weight(),
            max_batch_units: 100_000 + kind.default_weight().saturating_mul(1_000),
            surge_bps: match kind {
                ContractFeeLaneKind::EmergencyAction | ContractFeeLaneKind::AccountRecovery => 0,
                ContractFeeLaneKind::ShieldedSwap | ContractFeeLaneKind::DerivativesAction => 850,
                _ => 350,
            },
            status: FeeLaneStatus::Active,
            base_fee_micro_units,
            sponsor_book_ids: BTreeSet::new(),
            lane_id,
            kind,
        }
    }

    pub fn current_fee_micro_units(&self) -> u64 {
        self.base_fee_micro_units
            .saturating_mul(PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS.saturating_add(self.surge_bps))
            / PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "contract_family": self.contract_family,
            "base_fee_micro_units": self.base_fee_micro_units,
            "surge_bps": self.surge_bps,
            "current_fee_micro_units": self.current_fee_micro_units(),
            "priority_weight": self.priority_weight,
            "max_batch_units": self.max_batch_units,
            "sponsor_book_ids": self.sponsor_book_ids.iter().cloned().collect::<Vec<_>>(),
            "policy_root": self.policy_root,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateContractFeeMarketConfig,
    ) -> PrivateContractFeeMarketResult<()> {
        if self.lane_id.is_empty() {
            return Err("private contract fee lane id must not be empty".to_string());
        }
        if self.surge_bps > config.max_surge_bps {
            return Err(format!(
                "private contract fee lane {} surge exceeds max",
                self.lane_id
            ));
        }
        if self.base_fee_micro_units == 0 {
            return Err(format!(
                "private contract fee lane {} base fee is zero",
                self.lane_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEpoch {
    pub epoch_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub lane_ids: BTreeSet<String>,
    pub demand_root: String,
    pub quote_root: String,
    pub settlement_root: String,
    pub target_fill_bps: u64,
    pub sealed: bool,
}

impl FeeEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "demand_root": self.demand_root,
            "quote_root": self.quote_root,
            "settlement_root": self.settlement_root,
            "target_fill_bps": self.target_fill_bps,
            "sealed": self.sealed,
        })
    }

    pub fn validate(&self) -> PrivateContractFeeMarketResult<()> {
        if self.epoch_id.is_empty() {
            return Err("private contract fee epoch id must not be empty".to_string());
        }
        if self.start_height >= self.end_height {
            return Err(format!(
                "private contract fee epoch {} invalid range",
                self.epoch_id
            ));
        }
        if self.target_fill_bps > PRIVATE_CONTRACT_FEE_MARKET_MAX_BPS {
            return Err(format!(
                "private contract fee epoch {} fill target invalid",
                self.epoch_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDemandBucket {
    pub bucket_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub status: DemandBucketStatus,
    pub encrypted_demand_root: String,
    pub privacy_bucket: String,
    pub estimated_call_count: u64,
    pub estimated_compute_units: u64,
    pub min_privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl EncryptedDemandBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "encrypted_demand_root": self.encrypted_demand_root,
            "privacy_bucket": self.privacy_bucket,
            "estimated_call_count": self.estimated_call_count,
            "estimated_compute_units": self.estimated_compute_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateContractFeeMarketConfig,
    ) -> PrivateContractFeeMarketResult<()> {
        if self.bucket_id.is_empty() || self.encrypted_demand_root.is_empty() {
            return Err("private contract fee demand bucket ids must not be empty".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "private contract fee demand bucket {} privacy set too small",
                self.bucket_id
            ));
        }
        if self.opened_height >= self.expires_height {
            return Err(format!(
                "private contract fee demand bucket {} invalid expiry",
                self.bucket_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeQuote {
    pub quote_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub status: FeeQuoteStatus,
    pub encrypted_call_commitment: String,
    pub quote_nullifier: String,
    pub max_fee_micro_units: u64,
    pub reserved_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub compute_unit_limit: u64,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PrivateFeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "encrypted_call_commitment": self.encrypted_call_commitment,
            "quote_nullifier": self.quote_nullifier,
            "max_fee_micro_units": self.max_fee_micro_units,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "compute_unit_limit": self.compute_unit_limit,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(&self) -> PrivateContractFeeMarketResult<()> {
        if self.quote_id.is_empty() || self.quote_nullifier.is_empty() {
            return Err("private contract fee quote ids must not be empty".to_string());
        }
        if self.reserved_fee_micro_units > self.max_fee_micro_units {
            return Err(format!(
                "private contract fee quote {} reserves too much",
                self.quote_id
            ));
        }
        if self.sponsored_fee_micro_units > self.reserved_fee_micro_units {
            return Err(format!(
                "private contract fee quote {} sponsorship exceeds reserved fee",
                self.quote_id
            ));
        }
        if self.issued_height >= self.expires_height {
            return Err(format!(
                "private contract fee quote {} invalid expiry",
                self.quote_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorBook {
    pub sponsor_book_id: String,
    pub sponsor_commitment: String,
    pub lane_ids: BTreeSet<String>,
    pub status: SponsorBookStatus,
    pub available_micro_units: u64,
    pub reserved_micro_units: u64,
    pub settled_micro_units: u64,
    pub pq_policy_root: String,
    pub min_pq_security_bits: u16,
}

impl SponsorBook {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_book_id": self.sponsor_book_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "available_micro_units": self.available_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "settled_micro_units": self.settled_micro_units,
            "pq_policy_root": self.pq_policy_root,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateContractFeeMarketConfig,
    ) -> PrivateContractFeeMarketResult<()> {
        if self.sponsor_book_id.is_empty() || self.sponsor_commitment.is_empty() {
            return Err("private contract fee sponsor book ids must not be empty".to_string());
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "private contract fee sponsor book {} pq security too low",
                self.sponsor_book_id
            ));
        }
        if !self.status.spendable() && self.reserved_micro_units > 0 {
            return Err(format!(
                "private contract fee sponsor book {} inactive but reserved",
                self.sponsor_book_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFeeRebate {
    pub rebate_id: String,
    pub quote_id: String,
    pub lane_id: String,
    pub sponsor_book_id: String,
    pub status: FeeRebateStatus,
    pub rebate_note_commitment: String,
    pub claim_nullifier: String,
    pub rebate_micro_units: u64,
    pub accrued_height: u64,
    pub expires_height: u64,
}

impl ContractFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "sponsor_book_id": self.sponsor_book_id,
            "status": self.status.as_str(),
            "rebate_note_commitment": self.rebate_note_commitment,
            "claim_nullifier": self.claim_nullifier,
            "rebate_micro_units": self.rebate_micro_units,
            "accrued_height": self.accrued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(&self) -> PrivateContractFeeMarketResult<()> {
        if self.rebate_id.is_empty() || self.claim_nullifier.is_empty() {
            return Err("private contract fee rebate ids must not be empty".to_string());
        }
        if self.accrued_height >= self.expires_height {
            return Err(format!(
                "private contract fee rebate {} invalid expiry",
                self.rebate_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFeePolicyAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub signer_commitment: String,
    pub fee_policy_root: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
}

impl PqFeePolicyAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "signer_commitment": self.signer_commitment,
            "fee_policy_root": self.fee_policy_root,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "revoked": self.revoked,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateContractFeeMarketConfig,
    ) -> PrivateContractFeeMarketResult<()> {
        if self.attestation_id.is_empty() || self.lane_id.is_empty() {
            return Err("private contract fee attestation ids must not be empty".to_string());
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "private contract fee attestation {} pq security too low",
                self.attestation_id
            ));
        }
        if self.valid_from_height >= self.valid_until_height {
            return Err(format!(
                "private contract fee attestation {} invalid validity",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_height: u64,
    pub event_root: String,
}

impl FeeMarketEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_height": self.event_height,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractFeeMarketRoots {
    pub config_root: String,
    pub lane_root: String,
    pub epoch_root: String,
    pub demand_bucket_root: String,
    pub quote_root: String,
    pub sponsor_book_root: String,
    pub rebate_root: String,
    pub pq_attestation_root: String,
    pub event_root: String,
}

impl PrivateContractFeeMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "epoch_root": self.epoch_root,
            "demand_bucket_root": self.demand_bucket_root,
            "quote_root": self.quote_root,
            "sponsor_book_root": self.sponsor_book_root,
            "rebate_root": self.rebate_root,
            "pq_attestation_root": self.pq_attestation_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        hash32(
            "private_contract_fee_market_roots",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractFeeMarketCounters {
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub epoch_count: u64,
    pub open_epoch_count: u64,
    pub demand_bucket_count: u64,
    pub open_demand_bucket_count: u64,
    pub quote_count: u64,
    pub open_quote_count: u64,
    pub sponsor_book_count: u64,
    pub active_sponsor_book_count: u64,
    pub rebate_count: u64,
    pub claimable_rebate_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub event_count: u64,
    pub total_available_sponsor_micro_units: u64,
    pub total_reserved_fee_micro_units: u64,
    pub total_sponsored_fee_micro_units: u64,
}

impl PrivateContractFeeMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "epoch_count": self.epoch_count,
            "open_epoch_count": self.open_epoch_count,
            "demand_bucket_count": self.demand_bucket_count,
            "open_demand_bucket_count": self.open_demand_bucket_count,
            "quote_count": self.quote_count,
            "open_quote_count": self.open_quote_count,
            "sponsor_book_count": self.sponsor_book_count,
            "active_sponsor_book_count": self.active_sponsor_book_count,
            "rebate_count": self.rebate_count,
            "claimable_rebate_count": self.claimable_rebate_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "event_count": self.event_count,
            "total_available_sponsor_micro_units": self.total_available_sponsor_micro_units,
            "total_reserved_fee_micro_units": self.total_reserved_fee_micro_units,
            "total_sponsored_fee_micro_units": self.total_sponsored_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractFeeMarketState {
    pub config: PrivateContractFeeMarketConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, ContractFeeLane>,
    pub epochs: BTreeMap<String, FeeEpoch>,
    pub demand_buckets: BTreeMap<String, EncryptedDemandBucket>,
    pub quotes: BTreeMap<String, PrivateFeeQuote>,
    pub sponsor_books: BTreeMap<String, SponsorBook>,
    pub rebates: BTreeMap<String, ContractFeeRebate>,
    pub pq_attestations: BTreeMap<String, PqFeePolicyAttestation>,
    pub events: BTreeMap<String, FeeMarketEvent>,
}

impl PrivateContractFeeMarketState {
    pub fn devnet() -> PrivateContractFeeMarketResult<Self> {
        let config = PrivateContractFeeMarketConfig::devnet();
        let height = PRIVATE_CONTRACT_FEE_MARKET_DEVNET_HEIGHT;
        let mut lanes = BTreeMap::new();
        for (lane_id, kind) in [
            (
                "fee-lane-private-transfer",
                ContractFeeLaneKind::PrivateTransfer,
            ),
            ("fee-lane-shielded-swap", ContractFeeLaneKind::ShieldedSwap),
            ("fee-lane-vault-deposit", ContractFeeLaneKind::VaultDeposit),
            ("fee-lane-vault-redeem", ContractFeeLaneKind::VaultRedeem),
            ("fee-lane-lending", ContractFeeLaneKind::LendingAction),
            (
                "fee-lane-derivatives",
                ContractFeeLaneKind::DerivativesAction,
            ),
            ("fee-lane-governance", ContractFeeLaneKind::GovernanceVote),
            ("fee-lane-monero-exit", ContractFeeLaneKind::MoneroExit),
            (
                "fee-lane-account-recovery",
                ContractFeeLaneKind::AccountRecovery,
            ),
            ("fee-lane-emergency", ContractFeeLaneKind::EmergencyAction),
        ] {
            lanes.insert(
                lane_id.to_string(),
                ContractFeeLane::devnet(lane_id, kind, &config),
            );
        }

        let mut sponsor_books = BTreeMap::new();
        let lane_ids = lanes.keys().cloned().collect::<Vec<_>>();
        for index in 0..4 {
            let sponsor_book_id = format!("contract-fee-sponsor-book-{index}");
            let selected_lanes = lane_ids
                .iter()
                .skip(index)
                .step_by(2)
                .cloned()
                .collect::<BTreeSet<_>>();
            for lane_id in &selected_lanes {
                if let Some(lane) = lanes.get_mut(lane_id) {
                    lane.sponsor_book_ids.insert(sponsor_book_id.clone());
                }
            }
            sponsor_books.insert(
                sponsor_book_id.clone(),
                SponsorBook {
                    sponsor_commitment: hash32(
                        "private_contract_fee_sponsor_commitment",
                        &[HashPart::Str(&sponsor_book_id)],
                    ),
                    lane_ids: selected_lanes,
                    status: if index == 3 {
                        SponsorBookStatus::Replenishing
                    } else {
                        SponsorBookStatus::Active
                    },
                    available_micro_units: 600_000 + index as u64 * 275_000,
                    reserved_micro_units: index as u64 * 17_500,
                    settled_micro_units: index as u64 * 44_000,
                    pq_policy_root: hash32(
                        "private_contract_fee_sponsor_pq_policy",
                        &[HashPart::Str(&sponsor_book_id)],
                    ),
                    min_pq_security_bits: config.min_pq_security_bits,
                    sponsor_book_id,
                },
            );
        }

        let mut epochs = BTreeMap::new();
        for index in 0..3 {
            let epoch_id = format!("contract-fee-epoch-{index}");
            let start_height = height.saturating_sub((2 - index) as u64 * config.epoch_blocks);
            let end_height = start_height.saturating_add(config.epoch_blocks - 1);
            epochs.insert(
                epoch_id.clone(),
                FeeEpoch {
                    start_height,
                    end_height,
                    lane_ids: lanes.keys().cloned().collect(),
                    demand_root: hash32(
                        "private_contract_fee_epoch_demand",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    quote_root: hash32(
                        "private_contract_fee_epoch_quotes",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    settlement_root: hash32(
                        "private_contract_fee_epoch_settlement",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    target_fill_bps: config.target_fill_bps,
                    sealed: index < 2,
                    epoch_id,
                },
            );
        }

        let active_epoch_id = "contract-fee-epoch-2".to_string();
        let mut demand_buckets = BTreeMap::new();
        for index in 0..32 {
            let lane_id = lane_ids[index % lane_ids.len()].clone();
            let bucket_id = format!("contract-fee-demand-{index:03}");
            demand_buckets.insert(
                bucket_id.clone(),
                EncryptedDemandBucket {
                    epoch_id: active_epoch_id.clone(),
                    lane_id,
                    status: if index % 5 == 0 {
                        DemandBucketStatus::Sealed
                    } else {
                        DemandBucketStatus::Open
                    },
                    encrypted_demand_root: hash32(
                        "private_contract_fee_encrypted_demand",
                        &[HashPart::Str(&bucket_id)],
                    ),
                    privacy_bucket: format!("bucket-{}", index % 8),
                    estimated_call_count: 5 + index as u64,
                    estimated_compute_units: 25_000 + index as u64 * 1_750,
                    min_privacy_set_size: config.min_privacy_set_size * (1 + (index % 4) as u64),
                    opened_height: height.saturating_sub(index as u64 % 16),
                    expires_height: height.saturating_add(config.quote_ttl_blocks),
                    bucket_id,
                },
            );
        }

        let sponsor_book_ids = sponsor_books.keys().cloned().collect::<Vec<_>>();
        let mut quotes = BTreeMap::new();
        for index in 0..36 {
            let lane_id = lane_ids[index % lane_ids.len()].clone();
            let quote_id = format!("private-contract-fee-quote-{index:03}");
            let lane_fee = lanes
                .get(&lane_id)
                .map(ContractFeeLane::current_fee_micro_units)
                .unwrap_or(config.base_fee_micro_units);
            quotes.insert(
                quote_id.clone(),
                PrivateFeeQuote {
                    epoch_id: active_epoch_id.clone(),
                    lane_id,
                    status: match index % 6 {
                        0 => FeeQuoteStatus::Sponsored,
                        1 | 2 => FeeQuoteStatus::Reserved,
                        3 => FeeQuoteStatus::Consumed,
                        _ => FeeQuoteStatus::Quoted,
                    },
                    encrypted_call_commitment: hash32(
                        "private_contract_fee_call_commitment",
                        &[HashPart::Str(&quote_id)],
                    ),
                    quote_nullifier: hash32(
                        "private_contract_fee_quote_nullifier",
                        &[HashPart::Str(&quote_id)],
                    ),
                    max_fee_micro_units: lane_fee.saturating_mul(4),
                    reserved_fee_micro_units: lane_fee,
                    sponsored_fee_micro_units: if index % 3 == 0 { lane_fee / 2 } else { 0 },
                    compute_unit_limit: 50_000 + index as u64 * 5_000,
                    issued_height: height.saturating_sub(index as u64 % 10),
                    expires_height: height.saturating_add(config.quote_ttl_blocks),
                    quote_id,
                },
            );
        }

        let mut rebates = BTreeMap::new();
        for (index, quote) in quotes
            .values()
            .filter(|quote| quote.sponsored_fee_micro_units > 0)
            .enumerate()
        {
            let rebate_id = format!("private-contract-fee-rebate-{index:03}");
            rebates.insert(
                rebate_id.clone(),
                ContractFeeRebate {
                    quote_id: quote.quote_id.clone(),
                    lane_id: quote.lane_id.clone(),
                    sponsor_book_id: sponsor_book_ids[index % sponsor_book_ids.len()].clone(),
                    status: if index % 4 == 0 {
                        FeeRebateStatus::Batched
                    } else {
                        FeeRebateStatus::Claimable
                    },
                    rebate_note_commitment: hash32(
                        "private_contract_fee_rebate_note",
                        &[HashPart::Str(&rebate_id)],
                    ),
                    claim_nullifier: hash32(
                        "private_contract_fee_rebate_nullifier",
                        &[HashPart::Str(&rebate_id)],
                    ),
                    rebate_micro_units: quote.sponsored_fee_micro_units,
                    accrued_height: height.saturating_sub(index as u64),
                    expires_height: height.saturating_add(config.rebate_ttl_blocks),
                    rebate_id,
                },
            );
        }

        let mut pq_attestations = BTreeMap::new();
        for lane_id in lanes.keys() {
            let attestation_id = format!("contract-fee-pq-policy-{lane_id}");
            pq_attestations.insert(
                attestation_id.clone(),
                PqFeePolicyAttestation {
                    lane_id: lane_id.clone(),
                    signer_commitment: hash32(
                        "private_contract_fee_pq_signer",
                        &[HashPart::Str(lane_id)],
                    ),
                    fee_policy_root: hash32(
                        "private_contract_fee_pq_policy_attested",
                        &[HashPart::Str(lane_id)],
                    ),
                    signature_commitment: hash32(
                        "private_contract_fee_pq_signature",
                        &[HashPart::Str(&attestation_id)],
                    ),
                    security_bits: config.min_pq_security_bits,
                    valid_from_height: height.saturating_sub(config.epoch_blocks),
                    valid_until_height: height.saturating_add(config.epoch_blocks * 8),
                    revoked: false,
                    attestation_id,
                },
            );
        }

        let mut events = BTreeMap::new();
        for (index, subject_id) in [
            "fee-lane-private-transfer",
            "contract-fee-epoch-2",
            "contract-fee-sponsor-book-0",
            "private-contract-fee-quote-000",
        ]
        .iter()
        .enumerate()
        {
            let event_id = format!("private-contract-fee-event-{index:03}");
            events.insert(
                event_id.clone(),
                FeeMarketEvent {
                    event_kind: match index {
                        0 => "lane_opened",
                        1 => "epoch_opened",
                        2 => "sponsor_book_funded",
                        _ => "quote_sponsored",
                    }
                    .to_string(),
                    subject_id: (*subject_id).to_string(),
                    event_height: height.saturating_sub((4 - index) as u64),
                    event_root: hash32(
                        "private_contract_fee_event",
                        &[HashPart::Str(&event_id), HashPart::Str(subject_id)],
                    ),
                    event_id,
                },
            );
        }

        let state = Self {
            config,
            height,
            lanes,
            epochs,
            demand_buckets,
            quotes,
            sponsor_books,
            rebates,
            pq_attestations,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractFeeMarketResult<()> {
        if height < self.height {
            return Err("private contract fee market cannot rewind height".to_string());
        }
        self.height = height;
        for epoch in self.epochs.values_mut() {
            if height > epoch.end_height {
                epoch.sealed = true;
            }
        }
        for bucket in self.demand_buckets.values_mut() {
            if height > bucket.expires_height && bucket.status == DemandBucketStatus::Open {
                bucket.status = DemandBucketStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if height > quote.expires_height && quote.status.open() {
                quote.status = FeeQuoteStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if height > rebate.expires_height && rebate.status == FeeRebateStatus::Claimable {
                rebate.status = FeeRebateStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn roots(&self) -> PrivateContractFeeMarketRoots {
        PrivateContractFeeMarketRoots {
            config_root: value_root("private_contract_fee_config", &self.config.public_record()),
            lane_root: map_root("private_contract_fee_lanes", &self.lanes),
            epoch_root: map_root("private_contract_fee_epochs", &self.epochs),
            demand_bucket_root: map_root(
                "private_contract_fee_demand_buckets",
                &self.demand_buckets,
            ),
            quote_root: map_root("private_contract_fee_quotes", &self.quotes),
            sponsor_book_root: map_root("private_contract_fee_sponsor_books", &self.sponsor_books),
            rebate_root: map_root("private_contract_fee_rebates", &self.rebates),
            pq_attestation_root: map_root(
                "private_contract_fee_pq_attestations",
                &self.pq_attestations,
            ),
            event_root: map_root("private_contract_fee_events", &self.events),
        }
    }

    pub fn counters(&self) -> PrivateContractFeeMarketCounters {
        PrivateContractFeeMarketCounters {
            lane_count: self.lanes.len() as u64,
            active_lane_count: self
                .lanes
                .values()
                .filter(|lane| lane.status.accepts_quotes())
                .count() as u64,
            epoch_count: self.epochs.len() as u64,
            open_epoch_count: self.epochs.values().filter(|epoch| !epoch.sealed).count() as u64,
            demand_bucket_count: self.demand_buckets.len() as u64,
            open_demand_bucket_count: self
                .demand_buckets
                .values()
                .filter(|bucket| bucket.status == DemandBucketStatus::Open)
                .count() as u64,
            quote_count: self.quotes.len() as u64,
            open_quote_count: self
                .quotes
                .values()
                .filter(|quote| quote.status.open())
                .count() as u64,
            sponsor_book_count: self.sponsor_books.len() as u64,
            active_sponsor_book_count: self
                .sponsor_books
                .values()
                .filter(|book| book.status.spendable())
                .count() as u64,
            rebate_count: self.rebates.len() as u64,
            claimable_rebate_count: self
                .rebates
                .values()
                .filter(|rebate| rebate.status == FeeRebateStatus::Claimable)
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    !attestation.revoked && self.height <= attestation.valid_until_height
                })
                .count() as u64,
            event_count: self.events.len() as u64,
            total_available_sponsor_micro_units: self
                .sponsor_books
                .values()
                .map(|book| book.available_micro_units)
                .sum(),
            total_reserved_fee_micro_units: self
                .quotes
                .values()
                .map(|quote| quote.reserved_fee_micro_units)
                .sum(),
            total_sponsored_fee_micro_units: self
                .quotes
                .values()
                .map(|quote| quote.sponsored_fee_micro_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_fee_market",
            "protocol_version": PRIVATE_CONTRACT_FEE_MARKET_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_lane_ids": self.active_lane_ids(),
            "open_quote_ids": self.open_quote_ids(),
            "claimable_rebate_ids": self.claimable_rebate_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_fee_market_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateContractFeeMarketResult<()> {
        self.config.validate()?;
        if self.lanes.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_LANES {
            return Err("private contract fee market lane limit exceeded".to_string());
        }
        if self.epochs.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_EPOCHS {
            return Err("private contract fee market epoch limit exceeded".to_string());
        }
        if self.demand_buckets.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_BUCKETS {
            return Err("private contract fee market demand bucket limit exceeded".to_string());
        }
        if self.quotes.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_QUOTES {
            return Err("private contract fee market quote limit exceeded".to_string());
        }
        if self.sponsor_books.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_SPONSORS {
            return Err("private contract fee market sponsor book limit exceeded".to_string());
        }
        if self.rebates.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_REBATES {
            return Err("private contract fee market rebate limit exceeded".to_string());
        }
        if self.pq_attestations.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_ATTESTATIONS {
            return Err("private contract fee market attestation limit exceeded".to_string());
        }
        if self.events.len() > PRIVATE_CONTRACT_FEE_MARKET_MAX_EVENTS {
            return Err("private contract fee market event limit exceeded".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
            for sponsor_book_id in &lane.sponsor_book_ids {
                if !self.sponsor_books.contains_key(sponsor_book_id) {
                    return Err(format!(
                        "private contract fee lane {} references missing sponsor book {}",
                        lane.lane_id, sponsor_book_id
                    ));
                }
            }
        }
        for epoch in self.epochs.values() {
            epoch.validate()?;
            for lane_id in &epoch.lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(format!(
                        "private contract fee epoch {} references missing lane {}",
                        epoch.epoch_id, lane_id
                    ));
                }
            }
        }
        for bucket in self.demand_buckets.values() {
            bucket.validate(&self.config)?;
            if !self.epochs.contains_key(&bucket.epoch_id)
                || !self.lanes.contains_key(&bucket.lane_id)
            {
                return Err(format!(
                    "private contract fee demand bucket {} has dangling reference",
                    bucket.bucket_id
                ));
            }
        }
        let mut quote_nullifiers = BTreeSet::new();
        for quote in self.quotes.values() {
            quote.validate()?;
            if !self.epochs.contains_key(&quote.epoch_id)
                || !self.lanes.contains_key(&quote.lane_id)
            {
                return Err(format!(
                    "private contract fee quote {} has dangling reference",
                    quote.quote_id
                ));
            }
            if !quote_nullifiers.insert(quote.quote_nullifier.clone()) {
                return Err(format!(
                    "private contract fee duplicate quote nullifier {}",
                    quote.quote_nullifier
                ));
            }
        }
        for book in self.sponsor_books.values() {
            book.validate(&self.config)?;
            for lane_id in &book.lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(format!(
                        "private contract fee sponsor book {} references missing lane {}",
                        book.sponsor_book_id, lane_id
                    ));
                }
            }
        }
        let mut rebate_nullifiers = BTreeSet::new();
        for rebate in self.rebates.values() {
            rebate.validate()?;
            if !self.quotes.contains_key(&rebate.quote_id)
                || !self.lanes.contains_key(&rebate.lane_id)
                || !self.sponsor_books.contains_key(&rebate.sponsor_book_id)
            {
                return Err(format!(
                    "private contract fee rebate {} has dangling reference",
                    rebate.rebate_id
                ));
            }
            if !rebate_nullifiers.insert(rebate.claim_nullifier.clone()) {
                return Err(format!(
                    "private contract fee duplicate rebate nullifier {}",
                    rebate.claim_nullifier
                ));
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config)?;
            if !self.lanes.contains_key(&attestation.lane_id) {
                return Err(format!(
                    "private contract fee attestation {} references missing lane",
                    attestation.attestation_id
                ));
            }
        }
        Ok(())
    }

    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.status.accepts_quotes())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn open_quote_ids(&self) -> Vec<String> {
        self.quotes
            .values()
            .filter(|quote| quote.status.open())
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn claimable_rebate_ids(&self) -> Vec<String> {
        self.rebates
            .values()
            .filter(|rebate| rebate.status == FeeRebateStatus::Claimable)
            .map(|rebate| rebate.rebate_id.clone())
            .collect()
    }
}

pub fn private_contract_fee_market_state_root_from_record(record: &Value) -> String {
    hash32(
        "private_contract_fee_market_state",
        &[HashPart::Json(record)],
    )
}

fn value_root(label: &str, value: &Value) -> String {
    hash32(label, &[HashPart::Json(value)])
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let value = json!(map);
    hash32(label, &[HashPart::Json(&value)])
}

fn hash32(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
