use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeCrossDomainGasVaultResult<T> = Result<T, String>;

pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_PROTOCOL_VERSION: &str =
    "nebula-low-fee-cross-domain-gas-vault-v1";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_SCHEMA_VERSION: u64 = 1;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_COMMITMENT_SCHEME: &str =
    "blinded-gas-note-nullifier-vault-v1";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_RECEIPT_SCHEME: &str =
    "zk-settlement-receipt-range-proof-v1";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_INSURANCE_SCHEME: &str =
    "fee-volatility-insurance-bucket-v1";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_FEE_ASSET_ID: &str = "dxmr-devnet";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_DEPOSIT_TTL_BLOCKS: u64 = 2_880;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_CREDIT_TTL_BLOCKS: u64 = 1_440;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 4_320;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_SLIPPAGE_BPS: u64 = 250;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 35;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MIN_PRIVACY_SET: u64 = 32;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_BATCH_ITEMS: u64 = 512;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS: u64 = 6_500;
pub const LOW_FEE_CROSS_DOMAIN_GAS_VAULT_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasDomain {
    NebulaL2,
    MoneroExit,
    AppRollup,
    PrivateContract,
    ProofMarket,
    WalletRecovery,
}

impl GasDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NebulaL2 => "nebula_l2",
            Self::MoneroExit => "monero_exit",
            Self::AppRollup => "app_rollup",
            Self::PrivateContract => "private_contract",
            Self::ProofMarket => "proof_market",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn default_rollup_id(self) -> &'static str {
        match self {
            Self::NebulaL2 => "rollup:nebula:l2",
            Self::MoneroExit => "rollup:monero:exit",
            Self::AppRollup => "rollup:app:sealed",
            Self::PrivateContract => "rollup:contract:private",
            Self::ProofMarket => "rollup:proof:market",
            Self::WalletRecovery => "rollup:wallet:recovery",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::WalletRecovery => 650,
            Self::MoneroExit => 900,
            Self::NebulaL2 => 1_000,
            Self::AppRollup => 1_450,
            Self::PrivateContract => 1_900,
            Self::ProofMarket => 2_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasDepositStatus {
    Pending,
    Active,
    PartiallySpent,
    Spent,
    Refunded,
    Expired,
    Slashed,
}

impl GasDepositStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::PartiallySpent => "partially_spent",
            Self::Spent => "spent",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::PartiallySpent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorLaneStatus {
    Active,
    Throttled,
    Paused,
    Exhausted,
    Draining,
    Closed,
}

impl SponsorLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }

    pub fn can_route(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Reserved,
    Routed,
    Settled,
    Rebalanced,
    Cancelled,
    Expired,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Routed => "routed",
            Self::Settled => "settled",
            Self::Rebalanced => "rebalanced",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Reserved | Self::Routed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyRouteStatus {
    Available,
    Reserved,
    Claimed,
    Finalized,
    Disputed,
    Expired,
}

impl SubsidyRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Claimed => "claimed",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Available | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceStatus {
    Open,
    Reserved,
    Claimed,
    Paid,
    Denied,
    Expired,
}

impl InsuranceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Claimed => "claimed",
            Self::Paid => "paid",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Claimed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Posted,
    Proven,
    Finalized,
    Challenged,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Proven => "proven",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Reversed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub gas_asset_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub deposit_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_slippage_bps: u64,
    pub insurance_premium_bps: u64,
    pub min_privacy_set: u64,
    pub max_batch_items: u64,
    pub max_sponsor_exposure_bps: u64,
    pub commitment_scheme: String,
    pub receipt_scheme: String,
    pub insurance_scheme: String,
    pub hash_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_L2_NETWORK.to_string(),
            monero_network: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_MONERO_NETWORK.to_string(),
            gas_asset_id: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_EPOCH_BLOCKS,
            deposit_ttl_blocks: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_DEPOSIT_TTL_BLOCKS,
            credit_ttl_blocks: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_CREDIT_TTL_BLOCKS,
            receipt_ttl_blocks: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_slippage_bps: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_SLIPPAGE_BPS,
            insurance_premium_bps: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_INSURANCE_PREMIUM_BPS,
            min_privacy_set: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MIN_PRIVACY_SET,
            max_batch_items: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_BATCH_ITEMS,
            max_sponsor_exposure_bps:
                LOW_FEE_CROSS_DOMAIN_GAS_VAULT_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS,
            commitment_scheme: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_COMMITMENT_SCHEME.to_string(),
            receipt_scheme: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_RECEIPT_SCHEME.to_string(),
            insurance_scheme: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_INSURANCE_SCHEME.to_string(),
            hash_suite: LOW_FEE_CROSS_DOMAIN_GAS_VAULT_HASH_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        require_non_empty("config.protocol_version", &self.protocol_version)?;
        require_non_empty("config.chain_id", &self.chain_id)?;
        require_non_empty("config.l2_network", &self.l2_network)?;
        require_non_empty("config.monero_network", &self.monero_network)?;
        require_non_empty("config.gas_asset_id", &self.gas_asset_id)?;
        require_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("config.commitment_scheme", &self.commitment_scheme)?;
        require_non_empty("config.receipt_scheme", &self.receipt_scheme)?;
        require_non_empty("config.insurance_scheme", &self.insurance_scheme)?;
        require_non_empty("config.hash_suite", &self.hash_suite)?;
        require_positive("config.epoch_blocks", self.epoch_blocks)?;
        require_positive("config.deposit_ttl_blocks", self.deposit_ttl_blocks)?;
        require_positive("config.credit_ttl_blocks", self.credit_ttl_blocks)?;
        require_positive("config.receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        require_positive("config.min_privacy_set", self.min_privacy_set)?;
        require_positive("config.max_batch_items", self.max_batch_items)?;
        require_bps("config.max_slippage_bps", self.max_slippage_bps)?;
        require_bps("config.insurance_premium_bps", self.insurance_premium_bps)?;
        require_bps(
            "config.max_sponsor_exposure_bps",
            self.max_sponsor_exposure_bps,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "gas_asset_id": self.gas_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "deposit_ttl_blocks": self.deposit_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_slippage_bps": self.max_slippage_bps,
            "insurance_premium_bps": self.insurance_premium_bps,
            "min_privacy_set": self.min_privacy_set,
            "max_batch_items": self.max_batch_items,
            "max_sponsor_exposure_bps": self.max_sponsor_exposure_bps,
            "commitment_scheme": self.commitment_scheme,
            "receipt_scheme": self.receipt_scheme,
            "insurance_scheme": self.insurance_scheme,
            "hash_suite": self.hash_suite,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasDeposit {
    pub deposit_id: String,
    pub note_commitment: String,
    pub owner_commitment_root: String,
    pub source_domain: GasDomain,
    pub target_domain: GasDomain,
    pub asset_id: String,
    pub amount_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub refund_units: u64,
    pub min_privacy_set: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: GasDepositStatus,
    pub nullifier_root: String,
    pub metadata_root: String,
}

impl PrivateGasDeposit {
    pub fn available_units(&self) -> u64 {
        self.amount_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.refund_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "note_commitment": self.note_commitment,
            "owner_commitment_root": self.owner_commitment_root,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "refund_units": self.refund_units,
            "available_units": self.available_units(),
            "min_privacy_set": self.min_privacy_set,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "nullifier_root": self.nullifier_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEPOSIT-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorLane {
    pub lane_id: String,
    pub sponsor_id: String,
    pub lane_domain: GasDomain,
    pub display_name: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub max_fee_micro_units: u64,
    pub max_slippage_bps: u64,
    pub priority_weight: u64,
    pub exposure_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: SponsorLaneStatus,
    pub policy_root: String,
    pub allowlist_root: String,
}

impl SponsorLane {
    pub fn remaining_budget_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.spent_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "lane_domain": self.lane_domain.as_str(),
            "display_name": self.display_name,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "reserved_units": self.reserved_units,
            "remaining_budget_units": self.remaining_budget_units(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_slippage_bps": self.max_slippage_bps,
            "priority_weight": self.priority_weight,
            "exposure_bps": self.exposure_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "allowlist_root": self.allowlist_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SPONSOR-LANE-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupCredit {
    pub credit_id: String,
    pub deposit_id: String,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub source_domain: GasDomain,
    pub target_domain: GasDomain,
    pub sponsor_lane_id: Option<String>,
    pub gas_units: u64,
    pub fee_quote_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub slippage_cap_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: CreditStatus,
    pub routing_commitment_root: String,
    pub witness_root: String,
}

impl CrossRollupCredit {
    pub fn has_sponsor(&self) -> bool {
        self.sponsor_lane_id.is_some()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "deposit_id": self.deposit_id,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "sponsor_lane_id": self.sponsor_lane_id,
            "gas_units": self.gas_units,
            "fee_quote_micro_units": self.fee_quote_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "slippage_cap_bps": self.slippage_cap_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "routing_commitment_root": self.routing_commitment_root,
            "witness_root": self.witness_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CREDIT-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitSubsidyRoute {
    pub route_id: String,
    pub credit_id: String,
    pub sponsor_lane_id: String,
    pub monero_network: String,
    pub exit_lane_id: String,
    pub subsidy_units: u64,
    pub max_exit_fee_micro_units: u64,
    pub privacy_floor_bps: u64,
    pub ring_size_floor: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SubsidyRouteStatus,
    pub reserve_proof_root: String,
    pub payout_commitment_root: String,
}

impl MoneroExitSubsidyRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "credit_id": self.credit_id,
            "sponsor_lane_id": self.sponsor_lane_id,
            "monero_network": self.monero_network,
            "exit_lane_id": self.exit_lane_id,
            "subsidy_units": self.subsidy_units,
            "max_exit_fee_micro_units": self.max_exit_fee_micro_units,
            "privacy_floor_bps": self.privacy_floor_bps,
            "ring_size_floor": self.ring_size_floor,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "reserve_proof_root": self.reserve_proof_root,
            "payout_commitment_root": self.payout_commitment_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SUBSIDY-ROUTE-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlippageCap {
    pub cap_id: String,
    pub domain: GasDomain,
    pub rollup_id: String,
    pub max_quote_micro_units: u64,
    pub max_slippage_bps: u64,
    pub oracle_commitment_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl SlippageCap {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "domain": self.domain.as_str(),
            "rollup_id": self.rollup_id,
            "max_quote_micro_units": self.max_quote_micro_units,
            "max_slippage_bps": self.max_slippage_bps,
            "oracle_commitment_root": self.oracle_commitment_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SLIPPAGE-CAP-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeInsurancePolicy {
    pub policy_id: String,
    pub credit_id: String,
    pub underwriter_id: String,
    pub covered_units: u64,
    pub premium_units: u64,
    pub deductible_units: u64,
    pub trigger_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: InsuranceStatus,
    pub trigger_oracle_root: String,
    pub collateral_root: String,
}

impl FeeInsurancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "credit_id": self.credit_id,
            "underwriter_id": self.underwriter_id,
            "covered_units": self.covered_units,
            "premium_units": self.premium_units,
            "deductible_units": self.deductible_units,
            "trigger_bps": self.trigger_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "trigger_oracle_root": self.trigger_oracle_root,
            "collateral_root": self.collateral_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-INSURANCE-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub credit_id: String,
    pub deposit_id: String,
    pub route_id: Option<String>,
    pub policy_id: Option<String>,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub settled_gas_units: u64,
    pub charged_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub insured_fee_micro_units: u64,
    pub settlement_height: u64,
    pub status: ReceiptStatus,
    pub execution_root: String,
    pub fee_breakdown_root: String,
    pub proof_root: String,
}

impl SettlementReceipt {
    pub fn total_offset_micro_units(&self) -> u64 {
        self.sponsored_fee_micro_units
            .saturating_add(self.insured_fee_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "credit_id": self.credit_id,
            "deposit_id": self.deposit_id,
            "route_id": self.route_id,
            "policy_id": self.policy_id,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "settled_gas_units": self.settled_gas_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "insured_fee_micro_units": self.insured_fee_micro_units,
            "total_offset_micro_units": self.total_offset_micro_units(),
            "settlement_height": self.settlement_height,
            "status": self.status.as_str(),
            "execution_root": self.execution_root,
            "fee_breakdown_root": self.fee_breakdown_root,
            "proof_root": self.proof_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-RECEIPT-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub deposit_root: String,
    pub sponsor_lane_root: String,
    pub cross_rollup_credit_root: String,
    pub monero_subsidy_route_root: String,
    pub slippage_cap_root: String,
    pub fee_insurance_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub aggregate_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "deposit_root": self.deposit_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "cross_rollup_credit_root": self.cross_rollup_credit_root,
            "monero_subsidy_route_root": self.monero_subsidy_route_root,
            "slippage_cap_root": self.slippage_cap_root,
            "fee_insurance_root": self.fee_insurance_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "aggregate_root": self.aggregate_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub deposits: u64,
    pub active_deposits: u64,
    pub sponsor_lanes: u64,
    pub routable_sponsor_lanes: u64,
    pub cross_rollup_credits: u64,
    pub open_credits: u64,
    pub monero_subsidy_routes: u64,
    pub usable_subsidy_routes: u64,
    pub slippage_caps: u64,
    pub fee_insurance_policies: u64,
    pub active_insurance_policies: u64,
    pub settlement_receipts: u64,
    pub finalized_receipts: u64,
    pub nullifiers: u64,
    pub total_deposit_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_sponsored_micro_units: u64,
    pub total_insured_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "deposits": self.deposits,
            "active_deposits": self.active_deposits,
            "sponsor_lanes": self.sponsor_lanes,
            "routable_sponsor_lanes": self.routable_sponsor_lanes,
            "cross_rollup_credits": self.cross_rollup_credits,
            "open_credits": self.open_credits,
            "monero_subsidy_routes": self.monero_subsidy_routes,
            "usable_subsidy_routes": self.usable_subsidy_routes,
            "slippage_caps": self.slippage_caps,
            "fee_insurance_policies": self.fee_insurance_policies,
            "active_insurance_policies": self.active_insurance_policies,
            "settlement_receipts": self.settlement_receipts,
            "finalized_receipts": self.finalized_receipts,
            "nullifiers": self.nullifiers,
            "total_deposit_units": self.total_deposit_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_sponsored_micro_units": self.total_sponsored_micro_units,
            "total_insured_micro_units": self.total_insured_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub deposits: BTreeMap<String, PrivateGasDeposit>,
    pub sponsor_lanes: BTreeMap<String, SponsorLane>,
    pub cross_rollup_credits: BTreeMap<String, CrossRollupCredit>,
    pub monero_subsidy_routes: BTreeMap<String, MoneroExitSubsidyRoute>,
    pub slippage_caps: BTreeMap<String, SlippageCap>,
    pub fee_insurance_policies: BTreeMap<String, FeeInsurancePolicy>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> LowFeeCrossDomainGasVaultResult<State> {
        let config = Config::default();
        let height = 320;
        let epoch = height / config.epoch_blocks;
        let mut state = Self {
            config,
            height,
            epoch,
            deposits: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            cross_rollup_credits: BTreeMap::new(),
            monero_subsidy_routes: BTreeMap::new(),
            slippage_caps: BTreeMap::new(),
            fee_insurance_policies: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        self.config.validate()?;
        self.validate_height()?;
        self.validate_deposits()?;
        self.validate_sponsor_lanes()?;
        self.validate_credits()?;
        self.validate_subsidy_routes()?;
        self.validate_slippage_caps()?;
        self.validate_insurance()?;
        self.validate_receipts()?;
        self.validate_nullifiers()?;
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeCrossDomainGasVaultResult<()> {
        self.height = height;
        self.epoch = height / self.config.epoch_blocks;
        self.validate_height()
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeCrossDomainGasVaultResult<()> {
        if height < self.height {
            return Err("height update cannot move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let config_root = record_hash("LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CONFIG", &config_record);
        let deposit_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEPOSITS",
            &map_records(&self.deposits, PrivateGasDeposit::public_record),
        );
        let sponsor_lane_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SPONSOR-LANES",
            &map_records(&self.sponsor_lanes, SponsorLane::public_record),
        );
        let cross_rollup_credit_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CROSS-ROLLUP-CREDITS",
            &map_records(&self.cross_rollup_credits, CrossRollupCredit::public_record),
        );
        let monero_subsidy_route_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-MONERO-SUBSIDY-ROUTES",
            &map_records(
                &self.monero_subsidy_routes,
                MoneroExitSubsidyRoute::public_record,
            ),
        );
        let slippage_cap_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SLIPPAGE-CAPS",
            &map_records(&self.slippage_caps, SlippageCap::public_record),
        );
        let fee_insurance_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-FEE-INSURANCE",
            &map_records(
                &self.fee_insurance_policies,
                FeeInsurancePolicy::public_record,
            ),
        );
        let settlement_receipt_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SETTLEMENT-RECEIPTS",
            &map_records(&self.settlement_receipts, SettlementReceipt::public_record),
        );
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let nullifier_root = merkle_root(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CONSUMED-NULLIFIERS",
            &nullifier_records,
        );
        let aggregate_record = json!({
            "config_root": config_root,
            "deposit_root": deposit_root,
            "sponsor_lane_root": sponsor_lane_root,
            "cross_rollup_credit_root": cross_rollup_credit_root,
            "monero_subsidy_route_root": monero_subsidy_route_root,
            "slippage_cap_root": slippage_cap_root,
            "fee_insurance_root": fee_insurance_root,
            "settlement_receipt_root": settlement_receipt_root,
            "nullifier_root": nullifier_root,
        });
        let aggregate_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-AGGREGATE-ROOT",
            &aggregate_record,
        );
        let state_record = json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "aggregate_root": aggregate_root,
        });
        let state_root = record_hash("LOW-FEE-CROSS-DOMAIN-GAS-VAULT-STATE-ROOT", &state_record);
        Roots {
            config_root: string_field(&aggregate_record, "config_root"),
            deposit_root: string_field(&aggregate_record, "deposit_root"),
            sponsor_lane_root: string_field(&aggregate_record, "sponsor_lane_root"),
            cross_rollup_credit_root: string_field(&aggregate_record, "cross_rollup_credit_root"),
            monero_subsidy_route_root: string_field(&aggregate_record, "monero_subsidy_route_root"),
            slippage_cap_root: string_field(&aggregate_record, "slippage_cap_root"),
            fee_insurance_root: string_field(&aggregate_record, "fee_insurance_root"),
            settlement_receipt_root: string_field(&aggregate_record, "settlement_receipt_root"),
            nullifier_root: string_field(&aggregate_record, "nullifier_root"),
            aggregate_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            deposits: self.deposits.len() as u64,
            sponsor_lanes: self.sponsor_lanes.len() as u64,
            cross_rollup_credits: self.cross_rollup_credits.len() as u64,
            monero_subsidy_routes: self.monero_subsidy_routes.len() as u64,
            slippage_caps: self.slippage_caps.len() as u64,
            fee_insurance_policies: self.fee_insurance_policies.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            nullifiers: self.consumed_nullifiers.len() as u64,
            ..Counters::default()
        };
        for deposit in self.deposits.values() {
            if deposit.status.spendable() {
                counters.active_deposits = counters.active_deposits.saturating_add(1);
            }
            counters.total_deposit_units = counters
                .total_deposit_units
                .saturating_add(deposit.amount_units);
            counters.total_reserved_units = counters
                .total_reserved_units
                .saturating_add(deposit.reserved_units);
            counters.total_spent_units = counters
                .total_spent_units
                .saturating_add(deposit.spent_units);
        }
        for lane in self.sponsor_lanes.values() {
            if lane.status.can_route() {
                counters.routable_sponsor_lanes = counters.routable_sponsor_lanes.saturating_add(1);
            }
        }
        for credit in self.cross_rollup_credits.values() {
            if credit.status.open() {
                counters.open_credits = counters.open_credits.saturating_add(1);
            }
        }
        for route in self.monero_subsidy_routes.values() {
            if route.status.usable() {
                counters.usable_subsidy_routes = counters.usable_subsidy_routes.saturating_add(1);
            }
        }
        for policy in self.fee_insurance_policies.values() {
            if policy.status.active() {
                counters.active_insurance_policies =
                    counters.active_insurance_policies.saturating_add(1);
            }
        }
        for receipt in self.settlement_receipts.values() {
            if receipt.status == ReceiptStatus::Finalized {
                counters.finalized_receipts = counters.finalized_receipts.saturating_add(1);
            }
            counters.total_sponsored_micro_units = counters
                .total_sponsored_micro_units
                .saturating_add(receipt.sponsored_fee_micro_units);
            counters.total_insured_micro_units = counters
                .total_insured_micro_units
                .saturating_add(receipt.insured_fee_micro_units);
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "deposits": map_records(&self.deposits, PrivateGasDeposit::public_record),
            "sponsor_lanes": map_records(&self.sponsor_lanes, SponsorLane::public_record),
            "cross_rollup_credits": map_records(
                &self.cross_rollup_credits,
                CrossRollupCredit::public_record
            ),
            "monero_subsidy_routes": map_records(
                &self.monero_subsidy_routes,
                MoneroExitSubsidyRoute::public_record
            ),
            "slippage_caps": map_records(&self.slippage_caps, SlippageCap::public_record),
            "fee_insurance_policies": map_records(
                &self.fee_insurance_policies,
                FeeInsurancePolicy::public_record
            ),
            "settlement_receipts": map_records(
                &self.settlement_receipts,
                SettlementReceipt::public_record
            ),
            "consumed_nullifiers": self.consumed_nullifiers.iter().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn add_private_deposit(
        &mut self,
        note_commitment: &str,
        owner_commitment_root: &str,
        source_domain: GasDomain,
        target_domain: GasDomain,
        amount_units: u64,
        nullifier_root: &str,
        metadata: &Value,
    ) -> LowFeeCrossDomainGasVaultResult<String> {
        require_non_empty("deposit.note_commitment", note_commitment)?;
        require_non_empty("deposit.owner_commitment_root", owner_commitment_root)?;
        require_non_empty("deposit.nullifier_root", nullifier_root)?;
        require_positive("deposit.amount_units", amount_units)?;
        let metadata_root =
            record_hash("LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEPOSIT-METADATA", metadata);
        let deposit_id = make_deposit_id(
            note_commitment,
            owner_commitment_root,
            source_domain,
            target_domain,
            self.height,
            self.deposits.len() as u64,
        );
        let deposit = PrivateGasDeposit {
            deposit_id: deposit_id.clone(),
            note_commitment: note_commitment.to_string(),
            owner_commitment_root: owner_commitment_root.to_string(),
            source_domain,
            target_domain,
            asset_id: self.config.gas_asset_id.clone(),
            amount_units,
            reserved_units: 0,
            spent_units: 0,
            refund_units: 0,
            min_privacy_set: self.config.min_privacy_set,
            opened_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.deposit_ttl_blocks),
            status: GasDepositStatus::Active,
            nullifier_root: nullifier_root.to_string(),
            metadata_root,
        };
        self.deposits.insert(deposit_id.clone(), deposit);
        self.validate_deposits()?;
        Ok(deposit_id)
    }

    pub fn reserve_cross_rollup_credit(
        &mut self,
        deposit_id: &str,
        target_domain: GasDomain,
        gas_units: u64,
        fee_quote_micro_units: u64,
        sponsor_lane_id: Option<String>,
    ) -> LowFeeCrossDomainGasVaultResult<String> {
        require_non_empty("credit.deposit_id", deposit_id)?;
        require_positive("credit.gas_units", gas_units)?;
        require_positive("credit.fee_quote_micro_units", fee_quote_micro_units)?;
        let deposit = self
            .deposits
            .get_mut(deposit_id)
            .ok_or_else(|| format!("unknown deposit id {deposit_id}"))?;
        if !deposit.status.spendable() {
            return Err(format!("deposit {deposit_id} is not spendable"));
        }
        if deposit.available_units() < gas_units {
            return Err(format!(
                "deposit {deposit_id} has insufficient available units"
            ));
        }
        if let Some(lane_id) = sponsor_lane_id.as_deref() {
            let lane = self
                .sponsor_lanes
                .get(lane_id)
                .ok_or_else(|| format!("unknown sponsor lane id {lane_id}"))?;
            if !lane.status.can_route() {
                return Err(format!("sponsor lane {lane_id} cannot route credits"));
            }
            if lane.max_fee_micro_units < fee_quote_micro_units {
                return Err(format!("sponsor lane {lane_id} fee cap is below quote"));
            }
        }
        let source_domain = deposit.target_domain;
        let source_rollup_id = source_domain.default_rollup_id().to_string();
        let target_rollup_id = target_domain.default_rollup_id().to_string();
        let credit_id = make_credit_id(
            deposit_id,
            &source_rollup_id,
            &target_rollup_id,
            gas_units,
            self.height,
            self.cross_rollup_credits.len() as u64,
        );
        deposit.reserved_units = deposit.reserved_units.saturating_add(gas_units);
        if deposit.spent_units > 0 {
            deposit.status = GasDepositStatus::PartiallySpent;
        }
        let routing_payload = json!({
            "deposit_id": deposit_id,
            "source_rollup_id": source_rollup_id,
            "target_rollup_id": target_rollup_id,
            "sponsor_lane_id": sponsor_lane_id,
            "gas_units": gas_units,
        });
        let routing_commitment_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CREDIT-ROUTING",
            &routing_payload,
        );
        let witness_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CREDIT-WITNESS",
            &json!({
                "credit_id": credit_id,
                "height": self.height,
                "deposit_root": deposit.record_root(),
            }),
        );
        let max_fee_micro_units =
            quote_with_slippage(fee_quote_micro_units, self.config.max_slippage_bps);
        let credit = CrossRollupCredit {
            credit_id: credit_id.clone(),
            deposit_id: deposit_id.to_string(),
            source_rollup_id,
            target_rollup_id,
            source_domain,
            target_domain,
            sponsor_lane_id,
            gas_units,
            fee_quote_micro_units,
            max_fee_micro_units,
            slippage_cap_bps: self.config.max_slippage_bps,
            issued_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.credit_ttl_blocks),
            status: CreditStatus::Reserved,
            routing_commitment_root,
            witness_root,
        };
        self.cross_rollup_credits.insert(credit_id.clone(), credit);
        self.validate_deposits()?;
        self.validate_credits()?;
        Ok(credit_id)
    }

    pub fn settle_credit(
        &mut self,
        credit_id: &str,
        charged_fee_micro_units: u64,
        execution: &Value,
    ) -> LowFeeCrossDomainGasVaultResult<String> {
        require_non_empty("receipt.credit_id", credit_id)?;
        let credit = self
            .cross_rollup_credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown credit id {credit_id}"))?;
        if !credit.status.open() {
            return Err(format!("credit {credit_id} is not open"));
        }
        if charged_fee_micro_units > credit.max_fee_micro_units {
            return Err(format!("credit {credit_id} exceeds max fee slippage cap"));
        }
        let deposit = self
            .deposits
            .get_mut(&credit.deposit_id)
            .ok_or_else(|| format!("credit {credit_id} references missing deposit"))?;
        if deposit.reserved_units < credit.gas_units {
            return Err(format!(
                "deposit {} has inconsistent reservation",
                deposit.deposit_id
            ));
        }
        deposit.reserved_units = deposit.reserved_units.saturating_sub(credit.gas_units);
        deposit.spent_units = deposit.spent_units.saturating_add(credit.gas_units);
        if deposit.available_units() == 0 && deposit.reserved_units == 0 {
            deposit.status = GasDepositStatus::Spent;
        } else {
            deposit.status = GasDepositStatus::PartiallySpent;
        }
        let route_id = self
            .monero_subsidy_routes
            .values()
            .find(|route| {
                route.credit_id == credit_id && route.status == SubsidyRouteStatus::Claimed
            })
            .map(|route| route.route_id.clone());
        let policy_id = self
            .fee_insurance_policies
            .values()
            .find(|policy| policy.credit_id == credit_id && policy.status.active())
            .map(|policy| policy.policy_id.clone());
        let sponsored_fee_micro_units = if route_id.is_some() {
            charged_fee_micro_units.min(credit.fee_quote_micro_units)
        } else {
            0
        };
        let insured_fee_micro_units = if policy_id.is_some() {
            charged_fee_micro_units.saturating_sub(credit.fee_quote_micro_units)
        } else {
            0
        };
        let execution_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-RECEIPT-EXECUTION",
            execution,
        );
        let fee_breakdown = json!({
            "charged_fee_micro_units": charged_fee_micro_units,
            "sponsored_fee_micro_units": sponsored_fee_micro_units,
            "insured_fee_micro_units": insured_fee_micro_units,
        });
        let fee_breakdown_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-RECEIPT-FEE-BREAKDOWN",
            &fee_breakdown,
        );
        let proof_payload = json!({
            "credit_id": credit_id,
            "execution_root": execution_root,
            "fee_breakdown_root": fee_breakdown_root,
            "height": self.height,
        });
        let proof_root = record_hash(
            "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-RECEIPT-PROOF",
            &proof_payload,
        );
        let receipt_id = make_receipt_id(
            credit_id,
            &credit.deposit_id,
            &execution_root,
            self.height,
            self.settlement_receipts.len() as u64,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            credit_id: credit_id.to_string(),
            deposit_id: credit.deposit_id.clone(),
            route_id,
            policy_id,
            source_rollup_id: credit.source_rollup_id.clone(),
            target_rollup_id: credit.target_rollup_id.clone(),
            settled_gas_units: credit.gas_units,
            charged_fee_micro_units,
            sponsored_fee_micro_units,
            insured_fee_micro_units,
            settlement_height: self.height,
            status: ReceiptStatus::Finalized,
            execution_root,
            fee_breakdown_root,
            proof_root,
        };
        credit.status = CreditStatus::Settled;
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.validate()?;
        Ok(receipt_id)
    }

    fn seed_devnet_records(&mut self) -> LowFeeCrossDomainGasVaultResult<()> {
        for domain in [
            GasDomain::NebulaL2,
            GasDomain::MoneroExit,
            GasDomain::AppRollup,
            GasDomain::PrivateContract,
            GasDomain::ProofMarket,
            GasDomain::WalletRecovery,
        ] {
            let lane_id = make_lane_id(
                "devnet-sponsor",
                domain,
                self.height,
                self.sponsor_lanes.len() as u64,
            );
            let policy_root = record_hash(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-SPONSOR-POLICY",
                &json!({
                    "lane_domain": domain.as_str(),
                    "max_fee_micro_units": domain.default_fee_cap_micro_units(),
                    "max_slippage_bps": self.config.max_slippage_bps,
                }),
            );
            let allowlist_root = merkle_root(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-SPONSOR-ALLOWLIST",
                &[json!(domain.default_rollup_id())],
            );
            let lane = SponsorLane {
                lane_id: lane_id.clone(),
                sponsor_id: "devnet-sponsor".to_string(),
                lane_domain: domain,
                display_name: format!("devnet {}", domain.as_str()),
                budget_units: 1_000_000,
                spent_units: 0,
                reserved_units: 0,
                max_fee_micro_units: domain.default_fee_cap_micro_units(),
                max_slippage_bps: self.config.max_slippage_bps,
                priority_weight: 100_u64.saturating_sub(self.sponsor_lanes.len() as u64),
                exposure_bps: 1_500,
                valid_from_height: self.height,
                valid_until_height: self.height.saturating_add(self.config.epoch_blocks),
                status: SponsorLaneStatus::Active,
                policy_root,
                allowlist_root,
            };
            self.sponsor_lanes.insert(lane_id, lane);

            let cap_id = make_slippage_cap_id(
                domain,
                domain.default_rollup_id(),
                self.height,
                self.slippage_caps.len() as u64,
            );
            let cap = SlippageCap {
                cap_id: cap_id.clone(),
                domain,
                rollup_id: domain.default_rollup_id().to_string(),
                max_quote_micro_units: domain.default_fee_cap_micro_units(),
                max_slippage_bps: self.config.max_slippage_bps,
                oracle_commitment_root: record_hash(
                    "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-ORACLE",
                    &json!({
                        "domain": domain.as_str(),
                        "rollup_id": domain.default_rollup_id(),
                        "height": self.height,
                    }),
                ),
                valid_from_height: self.height,
                valid_until_height: self.height.saturating_add(self.config.epoch_blocks),
            };
            self.slippage_caps.insert(cap_id, cap);
        }

        let deposit_metadata = json!({
            "memo": "devnet private gas deposit",
            "privacy_pool": "devnet-gas-notes",
        });
        let deposit_id = self.add_private_deposit(
            "note:devnet:gas:0001",
            &record_hash(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-OWNER",
                &json!({"owner": "devnet-wallet"}),
            ),
            GasDomain::NebulaL2,
            GasDomain::MoneroExit,
            250_000,
            &record_hash(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-NULLIFIER-ROOT",
                &json!({"set": "devnet"}),
            ),
            &deposit_metadata,
        )?;
        let sponsor_lane_id = self
            .sponsor_lanes
            .values()
            .find(|lane| lane.lane_domain == GasDomain::MoneroExit)
            .map(|lane| lane.lane_id.clone());
        let credit_id = self.reserve_cross_rollup_credit(
            &deposit_id,
            GasDomain::MoneroExit,
            25_000,
            875,
            sponsor_lane_id.clone(),
        )?;
        if let Some(lane_id) = sponsor_lane_id {
            let route_id = make_subsidy_route_id(
                &credit_id,
                &lane_id,
                self.config.monero_network.as_str(),
                self.height,
                self.monero_subsidy_routes.len() as u64,
            );
            let route = MoneroExitSubsidyRoute {
                route_id: route_id.clone(),
                credit_id: credit_id.clone(),
                sponsor_lane_id: lane_id,
                monero_network: self.config.monero_network.clone(),
                exit_lane_id: "devnet-wallet-exit".to_string(),
                subsidy_units: 875,
                max_exit_fee_micro_units: 1_000,
                privacy_floor_bps: 9_500,
                ring_size_floor: 16,
                reserved_at_height: self.height,
                expires_at_height: self.height.saturating_add(self.config.credit_ttl_blocks),
                status: SubsidyRouteStatus::Claimed,
                reserve_proof_root: record_hash(
                    "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-RESERVE-PROOF",
                    &json!({"route_id": route_id}),
                ),
                payout_commitment_root: record_hash(
                    "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-PAYOUT",
                    &json!({"credit_id": credit_id}),
                ),
            };
            self.monero_subsidy_routes.insert(route_id, route);
        }
        let policy_id = make_insurance_policy_id(
            &credit_id,
            "devnet-underwriter",
            self.height,
            self.fee_insurance_policies.len() as u64,
        );
        let policy = FeeInsurancePolicy {
            policy_id: policy_id.clone(),
            credit_id: credit_id.clone(),
            underwriter_id: "devnet-underwriter".to_string(),
            covered_units: 25_000,
            premium_units: 88,
            deductible_units: 25,
            trigger_bps: 300,
            opened_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
            status: InsuranceStatus::Reserved,
            trigger_oracle_root: record_hash(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-INSURANCE-ORACLE",
                &json!({"credit_id": credit_id, "trigger_bps": 300}),
            ),
            collateral_root: record_hash(
                "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEVNET-INSURANCE-COLLATERAL",
                &json!({"underwriter_id": "devnet-underwriter"}),
            ),
        };
        self.fee_insurance_policies.insert(policy_id, policy);
        let receipt_id = self.settle_credit(
            &credit_id,
            900,
            &json!({
                "monero_exit_batch": "devnet-batch-0001",
                "settlement_adapter": "monero-settlement-adapter",
            }),
        )?;
        let nullifier = make_nullifier("devnet-nullifier", &receipt_id, self.height);
        self.consumed_nullifiers.insert(nullifier);
        Ok(())
    }

    fn validate_height(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        if self.config.epoch_blocks == 0 {
            return Err("config epoch_blocks cannot be zero".to_string());
        }
        let expected_epoch = self.height / self.config.epoch_blocks;
        if self.epoch != expected_epoch {
            return Err(format!(
                "epoch {} does not match height {} and epoch_blocks {}",
                self.epoch, self.height, self.config.epoch_blocks
            ));
        }
        Ok(())
    }

    fn validate_deposits(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        let mut note_commitments = BTreeSet::new();
        for (deposit_id, deposit) in &self.deposits {
            require_key_match("deposit", deposit_id, &deposit.deposit_id)?;
            require_non_empty("deposit.note_commitment", &deposit.note_commitment)?;
            require_non_empty(
                "deposit.owner_commitment_root",
                &deposit.owner_commitment_root,
            )?;
            require_non_empty("deposit.asset_id", &deposit.asset_id)?;
            require_non_empty("deposit.nullifier_root", &deposit.nullifier_root)?;
            require_non_empty("deposit.metadata_root", &deposit.metadata_root)?;
            require_positive("deposit.amount_units", deposit.amount_units)?;
            require_positive("deposit.min_privacy_set", deposit.min_privacy_set)?;
            require_height_window(
                "deposit height window",
                deposit.opened_at_height,
                deposit.expires_at_height,
            )?;
            let accounted = deposit
                .reserved_units
                .saturating_add(deposit.spent_units)
                .saturating_add(deposit.refund_units);
            if accounted > deposit.amount_units {
                return Err(format!(
                    "deposit {deposit_id} accounts for more than amount"
                ));
            }
            if deposit.status.spendable() && deposit.expires_at_height <= self.height {
                return Err(format!("deposit {deposit_id} is spendable after expiry"));
            }
            if !note_commitments.insert(deposit.note_commitment.clone()) {
                return Err(format!(
                    "duplicate private gas note commitment {}",
                    deposit.note_commitment
                ));
            }
        }
        Ok(())
    }

    fn validate_sponsor_lanes(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (lane_id, lane) in &self.sponsor_lanes {
            require_key_match("sponsor lane", lane_id, &lane.lane_id)?;
            require_non_empty("sponsor_lane.sponsor_id", &lane.sponsor_id)?;
            require_non_empty("sponsor_lane.display_name", &lane.display_name)?;
            require_non_empty("sponsor_lane.policy_root", &lane.policy_root)?;
            require_non_empty("sponsor_lane.allowlist_root", &lane.allowlist_root)?;
            require_positive("sponsor_lane.budget_units", lane.budget_units)?;
            require_positive("sponsor_lane.max_fee_micro_units", lane.max_fee_micro_units)?;
            require_positive("sponsor_lane.priority_weight", lane.priority_weight)?;
            require_bps("sponsor_lane.max_slippage_bps", lane.max_slippage_bps)?;
            require_bps("sponsor_lane.exposure_bps", lane.exposure_bps)?;
            require_height_window(
                "sponsor lane height window",
                lane.valid_from_height,
                lane.valid_until_height,
            )?;
            let accounted = lane.spent_units.saturating_add(lane.reserved_units);
            if accounted > lane.budget_units {
                return Err(format!("sponsor lane {lane_id} over-accounts budget"));
            }
            if lane.exposure_bps > self.config.max_sponsor_exposure_bps {
                return Err(format!(
                    "sponsor lane {lane_id} exceeds sponsor exposure cap"
                ));
            }
        }
        Ok(())
    }

    fn validate_credits(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (credit_id, credit) in &self.cross_rollup_credits {
            require_key_match("cross-rollup credit", credit_id, &credit.credit_id)?;
            require_non_empty("credit.deposit_id", &credit.deposit_id)?;
            require_non_empty("credit.source_rollup_id", &credit.source_rollup_id)?;
            require_non_empty("credit.target_rollup_id", &credit.target_rollup_id)?;
            require_non_empty(
                "credit.routing_commitment_root",
                &credit.routing_commitment_root,
            )?;
            require_non_empty("credit.witness_root", &credit.witness_root)?;
            require_positive("credit.gas_units", credit.gas_units)?;
            require_positive("credit.fee_quote_micro_units", credit.fee_quote_micro_units)?;
            require_positive("credit.max_fee_micro_units", credit.max_fee_micro_units)?;
            require_bps("credit.slippage_cap_bps", credit.slippage_cap_bps)?;
            require_height_window(
                "credit height window",
                credit.issued_at_height,
                credit.expires_at_height,
            )?;
            if !self.deposits.contains_key(&credit.deposit_id) {
                return Err(format!(
                    "credit {credit_id} references missing deposit {}",
                    credit.deposit_id
                ));
            }
            if let Some(lane_id) = credit.sponsor_lane_id.as_deref() {
                if !self.sponsor_lanes.contains_key(lane_id) {
                    return Err(format!(
                        "credit {credit_id} references missing sponsor lane {lane_id}"
                    ));
                }
            }
            if credit.fee_quote_micro_units > credit.max_fee_micro_units {
                return Err(format!("credit {credit_id} quote exceeds max fee"));
            }
        }
        Ok(())
    }

    fn validate_subsidy_routes(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (route_id, route) in &self.monero_subsidy_routes {
            require_key_match("monero subsidy route", route_id, &route.route_id)?;
            require_non_empty("subsidy_route.credit_id", &route.credit_id)?;
            require_non_empty("subsidy_route.sponsor_lane_id", &route.sponsor_lane_id)?;
            require_non_empty("subsidy_route.monero_network", &route.monero_network)?;
            require_non_empty("subsidy_route.exit_lane_id", &route.exit_lane_id)?;
            require_non_empty(
                "subsidy_route.reserve_proof_root",
                &route.reserve_proof_root,
            )?;
            require_non_empty(
                "subsidy_route.payout_commitment_root",
                &route.payout_commitment_root,
            )?;
            require_positive("subsidy_route.subsidy_units", route.subsidy_units)?;
            require_positive(
                "subsidy_route.max_exit_fee_micro_units",
                route.max_exit_fee_micro_units,
            )?;
            require_positive("subsidy_route.ring_size_floor", route.ring_size_floor)?;
            require_bps("subsidy_route.privacy_floor_bps", route.privacy_floor_bps)?;
            require_height_window(
                "subsidy route height window",
                route.reserved_at_height,
                route.expires_at_height,
            )?;
            if !self.cross_rollup_credits.contains_key(&route.credit_id) {
                return Err(format!(
                    "subsidy route {route_id} references missing credit {}",
                    route.credit_id
                ));
            }
            if !self.sponsor_lanes.contains_key(&route.sponsor_lane_id) {
                return Err(format!(
                    "subsidy route {route_id} references missing sponsor lane {}",
                    route.sponsor_lane_id
                ));
            }
        }
        Ok(())
    }

    fn validate_slippage_caps(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (cap_id, cap) in &self.slippage_caps {
            require_key_match("slippage cap", cap_id, &cap.cap_id)?;
            require_non_empty("slippage_cap.rollup_id", &cap.rollup_id)?;
            require_non_empty(
                "slippage_cap.oracle_commitment_root",
                &cap.oracle_commitment_root,
            )?;
            require_positive(
                "slippage_cap.max_quote_micro_units",
                cap.max_quote_micro_units,
            )?;
            require_bps("slippage_cap.max_slippage_bps", cap.max_slippage_bps)?;
            require_height_window(
                "slippage cap height window",
                cap.valid_from_height,
                cap.valid_until_height,
            )?;
        }
        Ok(())
    }

    fn validate_insurance(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (policy_id, policy) in &self.fee_insurance_policies {
            require_key_match("fee insurance policy", policy_id, &policy.policy_id)?;
            require_non_empty("insurance.credit_id", &policy.credit_id)?;
            require_non_empty("insurance.underwriter_id", &policy.underwriter_id)?;
            require_non_empty("insurance.trigger_oracle_root", &policy.trigger_oracle_root)?;
            require_non_empty("insurance.collateral_root", &policy.collateral_root)?;
            require_positive("insurance.covered_units", policy.covered_units)?;
            require_positive("insurance.trigger_bps", policy.trigger_bps)?;
            require_bps("insurance.trigger_bps", policy.trigger_bps)?;
            require_height_window(
                "insurance height window",
                policy.opened_at_height,
                policy.expires_at_height,
            )?;
            if !self.cross_rollup_credits.contains_key(&policy.credit_id) {
                return Err(format!(
                    "insurance policy {policy_id} references missing credit {}",
                    policy.credit_id
                ));
            }
        }
        Ok(())
    }

    fn validate_receipts(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for (receipt_id, receipt) in &self.settlement_receipts {
            require_key_match("settlement receipt", receipt_id, &receipt.receipt_id)?;
            require_non_empty("receipt.credit_id", &receipt.credit_id)?;
            require_non_empty("receipt.deposit_id", &receipt.deposit_id)?;
            require_non_empty("receipt.source_rollup_id", &receipt.source_rollup_id)?;
            require_non_empty("receipt.target_rollup_id", &receipt.target_rollup_id)?;
            require_non_empty("receipt.execution_root", &receipt.execution_root)?;
            require_non_empty("receipt.fee_breakdown_root", &receipt.fee_breakdown_root)?;
            require_non_empty("receipt.proof_root", &receipt.proof_root)?;
            require_positive("receipt.settled_gas_units", receipt.settled_gas_units)?;
            if !self.cross_rollup_credits.contains_key(&receipt.credit_id) {
                return Err(format!(
                    "receipt {receipt_id} references missing credit {}",
                    receipt.credit_id
                ));
            }
            if !self.deposits.contains_key(&receipt.deposit_id) {
                return Err(format!(
                    "receipt {receipt_id} references missing deposit {}",
                    receipt.deposit_id
                ));
            }
            if let Some(route_id) = receipt.route_id.as_deref() {
                if !self.monero_subsidy_routes.contains_key(route_id) {
                    return Err(format!(
                        "receipt {receipt_id} references missing subsidy route {route_id}"
                    ));
                }
            }
            if let Some(policy_id) = receipt.policy_id.as_deref() {
                if !self.fee_insurance_policies.contains_key(policy_id) {
                    return Err(format!(
                        "receipt {receipt_id} references missing insurance policy {policy_id}"
                    ));
                }
            }
            if receipt.total_offset_micro_units() > receipt.charged_fee_micro_units {
                return Err(format!(
                    "receipt {receipt_id} offsets more than charged fee"
                ));
            }
        }
        Ok(())
    }

    fn validate_nullifiers(&self) -> LowFeeCrossDomainGasVaultResult<()> {
        for nullifier in &self.consumed_nullifiers {
            require_non_empty("consumed_nullifier", nullifier)?;
        }
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    record_hash("LOW-FEE-CROSS-DOMAIN-GAS-VAULT-ROOT-FROM-RECORD", record)
}

pub fn devnet() -> LowFeeCrossDomainGasVaultResult<State> {
    State::devnet()
}

fn require_non_empty(label: &str, value: &str) -> LowFeeCrossDomainGasVaultResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_positive(label: &str, value: u64) -> LowFeeCrossDomainGasVaultResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> LowFeeCrossDomainGasVaultResult<()> {
    if value > LOW_FEE_CROSS_DOMAIN_GAS_VAULT_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}

fn require_height_window(label: &str, start: u64, end: u64) -> LowFeeCrossDomainGasVaultResult<()> {
    if end <= start {
        return Err(format!("{label} end must be after start"));
    }
    Ok(())
}

fn require_key_match(label: &str, key: &str, id: &str) -> LowFeeCrossDomainGasVaultResult<()> {
    if key != id {
        return Err(format!("{label} map key does not match record id"));
    }
    Ok(())
}

fn quote_with_slippage(quote: u64, slippage_bps: u64) -> u64 {
    let premium = quote
        .saturating_mul(slippage_bps)
        .saturating_add(LOW_FEE_CROSS_DOMAIN_GAS_VAULT_MAX_BPS - 1)
        / LOW_FEE_CROSS_DOMAIN_GAS_VAULT_MAX_BPS;
    quote.saturating_add(premium)
}

fn string_field(record: &Value, key: &str) -> String {
    match record.get(key).and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn map_records<T, F>(records: &BTreeMap<String, T>, to_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(to_record).collect::<Vec<_>>()
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_CROSS_DOMAIN_GAS_VAULT_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn make_deposit_id(
    note_commitment: &str,
    owner_commitment_root: &str,
    source_domain: GasDomain,
    target_domain: GasDomain,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-DEPOSIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(note_commitment),
            HashPart::Str(owner_commitment_root),
            HashPart::Str(source_domain.as_str()),
            HashPart::Str(target_domain.as_str()),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_lane_id(sponsor_id: &str, domain: GasDomain, height: u64, sequence: u64) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SPONSOR-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(domain.as_str()),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_credit_id(
    deposit_id: &str,
    source_rollup_id: &str,
    target_rollup_id: &str,
    gas_units: u64,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(deposit_id),
            HashPart::Str(source_rollup_id),
            HashPart::Str(target_rollup_id),
            HashPart::Int(gas_units as i128),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_subsidy_route_id(
    credit_id: &str,
    sponsor_lane_id: &str,
    monero_network: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SUBSIDY-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(credit_id),
            HashPart::Str(sponsor_lane_id),
            HashPart::Str(monero_network),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_slippage_cap_id(domain: GasDomain, rollup_id: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-SLIPPAGE-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(rollup_id),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_insurance_policy_id(
    credit_id: &str,
    underwriter_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-INSURANCE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(credit_id),
            HashPart::Str(underwriter_id),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_receipt_id(
    credit_id: &str,
    deposit_id: &str,
    execution_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(credit_id),
            HashPart::Str(deposit_id),
            HashPart::Str(execution_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn make_nullifier(label: &str, receipt_id: &str, height: u64) -> String {
    domain_hash(
        "LOW-FEE-CROSS-DOMAIN-GAS-VAULT-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(receipt_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}
