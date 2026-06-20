use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkContractFeeRebateSequencerMarketResult<T> = Result<T, String>;

pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_PROTOCOL_VERSION: &str =
    "nebula-zk-contract-fee-rebate-sequencer-market-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_SCHEMA_VERSION: u64 = 1;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_ORDER_SCHEME: &str =
    "sealed-private-contract-rebate-order-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_QUOTE_SCHEME: &str =
    "pq-sequencer-rebate-quote-commitment-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_SPONSORSHIP_SCHEME: &str =
    "contract-gas-sponsorship-vault-note-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_ELIGIBILITY_PROOF_SCHEME: &str =
    "zk-contract-rebate-eligibility-proof-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_NULLIFIER_SCHEME: &str =
    "anti-sybil-contract-rebate-nullifier-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_RECEIPT_SCHEME: &str =
    "low-fee-lane-rebate-settlement-receipt-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_CHALLENGE_SCHEME: &str =
    "rebate-sequencer-market-challenge-window-v1";
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEVNET_HEIGHT: u64 = 3_456;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 60;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_ORDER_TTL_BLOCKS: u64 = 24;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_SETTLEMENT_BLOCKS: u64 = 18;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_CHALLENGE_BLOCKS: u64 = 48;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MAX_REBATE_BPS: u64 = 9_500;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_SPONSOR_BOND_UNITS: u64 = 5_000_000;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 700;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS: u64 = 10_000;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_RECORDS: usize = 262_144;
pub const ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_CHALLENGES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallClass {
    PaymasterSponsored,
    PrivateDefiSwap,
    PrivateLiquidityAdd,
    OracleUpdate,
    ProofAggregation,
    WalletRecovery,
    MoneroBridgeExit,
    EmergencyCircuit,
}

impl ContractCallClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PaymasterSponsored => "paymaster_sponsored",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::PrivateLiquidityAdd => "private_liquidity_add",
            Self::OracleUpdate => "oracle_update",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::EmergencyCircuit => "emergency_circuit",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCircuit => 1_000,
            Self::WalletRecovery => 940,
            Self::MoneroBridgeExit => 850,
            Self::PaymasterSponsored => 820,
            Self::PrivateDefiSwap => 760,
            Self::PrivateLiquidityAdd => 700,
            Self::ProofAggregation => 640,
            Self::OracleUpdate => 580,
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyCircuit => 350,
            Self::WalletRecovery => 500,
            Self::MoneroBridgeExit => 850,
            Self::PaymasterSponsored => 950,
            Self::PrivateDefiSwap => 1_150,
            Self::PrivateLiquidityAdd => 1_350,
            Self::ProofAggregation => 1_600,
            Self::OracleUpdate => 1_900,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    Eligible,
    Quoted,
    Reserved,
    Settled,
    Rejected,
    Expired,
    Challenged,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Eligible => "eligible",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Eligible | Self::Quoted | Self::Reserved | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Accepted,
    Filled,
    Expired,
    Cancelled,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Open | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Reserved,
    Exhausted,
    Paused,
    Slashed,
    Closed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStatus {
    Pending,
    Verified,
    Consumed,
    Revoked,
    Expired,
}

impl EligibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Included,
    RebateCredited,
    Finalized,
    Disputed,
    Reversed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Included => "included",
            Self::RebateCredited => "rebate_credited",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }

    pub fn finalizable(self) -> bool {
        matches!(self, Self::RebateCredited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub settlement_blocks: u64,
    pub challenge_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_rebate_bps: u64,
    pub min_sponsor_bond_units: u64,
    pub low_fee_target_micro_units: u64,
    pub slash_bps: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub order_scheme: String,
    pub quote_scheme: String,
    pub sponsorship_scheme: String,
    pub eligibility_proof_scheme: String,
    pub nullifier_scheme: String,
    pub receipt_scheme: String,
    pub challenge_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_QUOTE_TTL_BLOCKS,
            order_ttl_blocks: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_ORDER_TTL_BLOCKS,
            settlement_blocks: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_SETTLEMENT_BLOCKS,
            challenge_blocks: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_CHALLENGE_BLOCKS,
            min_privacy_set_size:
                ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_rebate_bps: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MAX_REBATE_BPS,
            min_sponsor_bond_units:
                ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MIN_SPONSOR_BOND_UNITS,
            low_fee_target_micro_units:
                ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            slash_bps: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_SLASH_BPS,
            fee_asset_id: "piconero-devnet".to_string(),
            rebate_asset_id: "wxmr-devnet".to_string(),
            hash_suite: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_HASH_SUITE.to_string(),
            order_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_ORDER_SCHEME.to_string(),
            quote_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_QUOTE_SCHEME.to_string(),
            sponsorship_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_SPONSORSHIP_SCHEME
                .to_string(),
            eligibility_proof_scheme:
                ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_ELIGIBILITY_PROOF_SCHEME.to_string(),
            nullifier_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_NULLIFIER_SCHEME.to_string(),
            receipt_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_RECEIPT_SCHEME.to_string(),
            challenge_scheme: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_CHALLENGE_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        if self.epoch_blocks == 0
            || self.quote_ttl_blocks == 0
            || self.order_ttl_blocks == 0
            || self.settlement_blocks == 0
            || self.challenge_blocks == 0
        {
            return Err("zk contract fee rebate market windows must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("zk contract fee rebate market privacy set must be positive".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("zk contract fee rebate market pq security must be positive".to_string());
        }
        if self.max_rebate_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS
            || self.slash_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS
        {
            return Err("zk contract fee rebate market bps exceeds max".to_string());
        }
        if self.min_sponsor_bond_units == 0 || self.low_fee_target_micro_units == 0 {
            return Err(
                "zk contract fee rebate market fee parameters must be positive".to_string(),
            );
        }
        for (label, value) in [
            ("fee asset", self.fee_asset_id.as_str()),
            ("rebate asset", self.rebate_asset_id.as_str()),
            ("hash suite", self.hash_suite.as_str()),
            ("order scheme", self.order_scheme.as_str()),
            ("quote scheme", self.quote_scheme.as_str()),
            ("sponsorship scheme", self.sponsorship_scheme.as_str()),
            (
                "eligibility proof scheme",
                self.eligibility_proof_scheme.as_str(),
            ),
            ("nullifier scheme", self.nullifier_scheme.as_str()),
            ("receipt scheme", self.receipt_scheme.as_str()),
            ("challenge scheme", self.challenge_scheme.as_str()),
        ] {
            if value.is_empty() {
                return Err(format!(
                    "zk contract fee rebate market {label} cannot be empty"
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "settlement_blocks": self.settlement_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_rebate_bps": self.max_rebate_bps,
            "min_sponsor_bond_units": self.min_sponsor_bond_units,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "slash_bps": self.slash_bps,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "order_scheme": self.order_scheme,
            "quote_scheme": self.quote_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "eligibility_proof_scheme": self.eligibility_proof_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "receipt_scheme": self.receipt_scheme,
            "challenge_scheme": self.challenge_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePolicy {
    pub lane_id: String,
    pub call_class: ContractCallClass,
    pub fee_cap_micro_units: u64,
    pub priority_weight: u64,
    pub max_gas_units: u64,
    pub max_rebate_bps: u64,
    pub requires_sponsorship: bool,
}

impl LanePolicy {
    pub fn new(call_class: ContractCallClass, lane_label: &str, max_gas_units: u64) -> Self {
        let lane_id = lane_policy_id(call_class, lane_label);
        Self {
            lane_id,
            call_class,
            fee_cap_micro_units: call_class.default_fee_cap_micro_units(),
            priority_weight: call_class.default_priority_weight(),
            max_gas_units,
            max_rebate_bps: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEFAULT_MAX_REBATE_BPS,
            requires_sponsorship: true,
        }
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        if self.lane_id.is_empty() {
            return Err("lane policy id cannot be empty".to_string());
        }
        if self.fee_cap_micro_units == 0 || self.priority_weight == 0 || self.max_gas_units == 0 {
            return Err("lane policy numeric fields must be positive".to_string());
        }
        if self.max_rebate_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS {
            return Err("lane policy rebate bps exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "call_class": self.call_class.as_str(),
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "priority_weight": self.priority_weight,
            "max_gas_units": self.max_gas_units,
            "max_rebate_bps": self.max_rebate_bps,
            "requires_sponsorship": self.requires_sponsorship,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRebateOrder {
    pub order_id: String,
    pub lane_id: String,
    pub call_class: ContractCallClass,
    pub sealed_call_commitment: String,
    pub wallet_commitment: String,
    pub contract_commitment: String,
    pub gas_limit: u64,
    pub max_fee_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub eligibility_proof_id: String,
    pub anti_sybil_nullifier: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: OrderStatus,
}

impl PrivateRebateOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        call_class: ContractCallClass,
        sealed_call_commitment: &str,
        wallet_commitment: &str,
        contract_commitment: &str,
        gas_limit: u64,
        max_fee_micro_units: u64,
        requested_rebate_bps: u64,
        eligibility_proof_id: &str,
        anti_sybil_nullifier: &str,
        metadata: &Value,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let metadata_root = metadata_root(metadata);
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let order_id = private_rebate_order_id(
            lane_id,
            call_class,
            sealed_call_commitment,
            wallet_commitment,
            contract_commitment,
            gas_limit,
            max_fee_micro_units,
            requested_rebate_bps,
            eligibility_proof_id,
            anti_sybil_nullifier,
            &metadata_root,
            created_at_height,
            expires_at_height,
        );
        let order = Self {
            order_id,
            lane_id: lane_id.to_string(),
            call_class,
            sealed_call_commitment: sealed_call_commitment.to_string(),
            wallet_commitment: wallet_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            gas_limit,
            max_fee_micro_units,
            requested_rebate_bps,
            eligibility_proof_id: eligibility_proof_id.to_string(),
            anti_sybil_nullifier: anti_sybil_nullifier.to_string(),
            metadata_root,
            created_at_height,
            expires_at_height,
            status: OrderStatus::Sealed,
        };
        order.validate()?;
        Ok(order)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("order id", &self.order_id)?;
        validate_id("lane id", &self.lane_id)?;
        validate_id("sealed call commitment", &self.sealed_call_commitment)?;
        validate_id("wallet commitment", &self.wallet_commitment)?;
        validate_id("contract commitment", &self.contract_commitment)?;
        validate_id("eligibility proof id", &self.eligibility_proof_id)?;
        validate_id("anti sybil nullifier", &self.anti_sybil_nullifier)?;
        validate_id("metadata root", &self.metadata_root)?;
        if self.gas_limit == 0 || self.max_fee_micro_units == 0 {
            return Err("private rebate order gas and fee fields must be positive".to_string());
        }
        if self.requested_rebate_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS {
            return Err("private rebate order rebate bps exceeds max".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("private rebate order expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "lane_id": self.lane_id,
            "call_class": self.call_class.as_str(),
            "sealed_call_commitment": self.sealed_call_commitment,
            "wallet_commitment": self.wallet_commitment,
            "contract_commitment": self.contract_commitment,
            "gas_limit": self.gas_limit,
            "max_fee_micro_units": self.max_fee_micro_units,
            "requested_rebate_bps": self.requested_rebate_bps,
            "eligibility_proof_id": self.eligibility_proof_id,
            "anti_sybil_nullifier": self.anti_sybil_nullifier,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerQuote {
    pub quote_id: String,
    pub sequencer_id: String,
    pub lane_id: String,
    pub order_id: String,
    pub quote_commitment: String,
    pub fee_micro_units: u64,
    pub rebate_bps: u64,
    pub sponsored_gas_units: u64,
    pub bond_units: u64,
    pub quote_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuoteStatus,
}

impl SequencerQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequencer_id: &str,
        lane_id: &str,
        order_id: &str,
        quote_commitment: &str,
        fee_micro_units: u64,
        rebate_bps: u64,
        sponsored_gas_units: u64,
        bond_units: u64,
        metadata: &Value,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let quote_root = metadata_root(metadata);
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let quote_id = sequencer_quote_id(
            sequencer_id,
            lane_id,
            order_id,
            quote_commitment,
            fee_micro_units,
            rebate_bps,
            sponsored_gas_units,
            bond_units,
            &quote_root,
            opened_at_height,
            expires_at_height,
        );
        let quote = Self {
            quote_id,
            sequencer_id: sequencer_id.to_string(),
            lane_id: lane_id.to_string(),
            order_id: order_id.to_string(),
            quote_commitment: quote_commitment.to_string(),
            fee_micro_units,
            rebate_bps,
            sponsored_gas_units,
            bond_units,
            quote_root,
            opened_at_height,
            expires_at_height,
            status: QuoteStatus::Open,
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("quote id", &self.quote_id)?;
        validate_id("sequencer id", &self.sequencer_id)?;
        validate_id("lane id", &self.lane_id)?;
        validate_id("order id", &self.order_id)?;
        validate_id("quote commitment", &self.quote_commitment)?;
        validate_id("quote root", &self.quote_root)?;
        if self.fee_micro_units == 0
            || self.sponsored_gas_units == 0
            || self.bond_units == 0
            || self.expires_at_height <= self.opened_at_height
        {
            return Err("sequencer quote numeric fields are invalid".to_string());
        }
        if self.rebate_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS {
            return Err("sequencer quote rebate bps exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "sequencer_id": self.sequencer_id,
            "lane_id": self.lane_id,
            "order_id": self.order_id,
            "quote_commitment": self.quote_commitment,
            "fee_micro_units": self.fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "sponsored_gas_units": self.sponsored_gas_units,
            "bond_units": self.bond_units,
            "quote_root": self.quote_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractGasSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub contract_commitment: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_rebate_bps: u64,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl ContractGasSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        contract_commitment: &str,
        lane_id: &str,
        budget_units: u64,
        max_rebate_bps: u64,
        policy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let policy_root = metadata_root(policy);
        let sponsorship_id = contract_gas_sponsorship_id(
            sponsor_id,
            contract_commitment,
            lane_id,
            budget_units,
            max_rebate_bps,
            &policy_root,
            opened_at_height,
            expires_at_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            contract_commitment: contract_commitment.to_string(),
            lane_id: lane_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_rebate_bps,
            policy_root,
            opened_at_height,
            expires_at_height,
            status: SponsorshipStatus::Active,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("sponsorship id", &self.sponsorship_id)?;
        validate_id("sponsor id", &self.sponsor_id)?;
        validate_id("contract commitment", &self.contract_commitment)?;
        validate_id("lane id", &self.lane_id)?;
        validate_id("policy root", &self.policy_root)?;
        if self.budget_units == 0 {
            return Err("contract gas sponsorship budget must be positive".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("contract gas sponsorship over-reserved budget".to_string());
        }
        if self.max_rebate_bps > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS {
            return Err("contract gas sponsorship rebate bps exceeds max".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("contract gas sponsorship expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "contract_commitment": self.contract_commitment,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "max_rebate_bps": self.max_rebate_bps,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkEligibilityProof {
    pub proof_id: String,
    pub subject_commitment: String,
    pub contract_commitment: String,
    pub lane_id: String,
    pub proof_system: String,
    pub verifying_key_root: String,
    pub public_input_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub anti_sybil_nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: EligibilityStatus,
}

impl ZkEligibilityProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_commitment: &str,
        contract_commitment: &str,
        lane_id: &str,
        proof_system: &str,
        verifying_key_root: &str,
        public_inputs: &Value,
        privacy_set_size: u64,
        pq_security_bits: u16,
        anti_sybil_nullifier: &str,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let public_input_root = metadata_root(public_inputs);
        let proof_id = zk_eligibility_proof_id(
            subject_commitment,
            contract_commitment,
            lane_id,
            proof_system,
            verifying_key_root,
            &public_input_root,
            privacy_set_size,
            pq_security_bits,
            anti_sybil_nullifier,
            opened_at_height,
            expires_at_height,
        );
        let proof = Self {
            proof_id,
            subject_commitment: subject_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            lane_id: lane_id.to_string(),
            proof_system: proof_system.to_string(),
            verifying_key_root: verifying_key_root.to_string(),
            public_input_root,
            privacy_set_size,
            pq_security_bits,
            anti_sybil_nullifier: anti_sybil_nullifier.to_string(),
            opened_at_height,
            expires_at_height,
            status: EligibilityStatus::Verified,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("proof id", &self.proof_id)?;
        validate_id("subject commitment", &self.subject_commitment)?;
        validate_id("contract commitment", &self.contract_commitment)?;
        validate_id("lane id", &self.lane_id)?;
        validate_id("proof system", &self.proof_system)?;
        validate_id("verifying key root", &self.verifying_key_root)?;
        validate_id("public input root", &self.public_input_root)?;
        validate_id("anti sybil nullifier", &self.anti_sybil_nullifier)?;
        if self.privacy_set_size == 0 || self.pq_security_bits == 0 {
            return Err(
                "zk eligibility proof privacy and security fields must be positive".to_string(),
            );
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("zk eligibility proof expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "subject_commitment": self.subject_commitment,
            "contract_commitment": self.contract_commitment,
            "lane_id": self.lane_id,
            "proof_system": self.proof_system,
            "verifying_key_root": self.verifying_key_root,
            "public_input_root": self.public_input_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "anti_sybil_nullifier": self.anti_sybil_nullifier,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub nullifier: String,
    pub order_id: String,
    pub proof_id: String,
    pub epoch: u64,
    pub first_seen_height: u64,
    pub consumed: bool,
}

impl NullifierEntry {
    pub fn new(
        nullifier: &str,
        order_id: &str,
        proof_id: &str,
        epoch: u64,
        first_seen_height: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let entry = Self {
            nullifier: nullifier.to_string(),
            order_id: order_id.to_string(),
            proof_id: proof_id.to_string(),
            epoch,
            first_seen_height,
            consumed: false,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("nullifier", &self.nullifier)?;
        validate_id("order id", &self.order_id)?;
        validate_id("proof id", &self.proof_id)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "order_id": self.order_id,
            "proof_id": self.proof_id,
            "epoch": self.epoch,
            "first_seen_height": self.first_seen_height,
            "consumed": self.consumed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub order_id: String,
    pub quote_id: String,
    pub sponsorship_id: String,
    pub lane_id: String,
    pub sequencer_id: String,
    pub inclusion_root: String,
    pub execution_root: String,
    pub rebate_commitment: String,
    pub gas_used: u64,
    pub fee_paid_micro_units: u64,
    pub rebate_paid_units: u64,
    pub settled_at_height: u64,
    pub challenge_deadline_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: &str,
        quote_id: &str,
        sponsorship_id: &str,
        lane_id: &str,
        sequencer_id: &str,
        inclusion_root: &str,
        execution_root: &str,
        rebate_commitment: &str,
        gas_used: u64,
        fee_paid_micro_units: u64,
        rebate_paid_units: u64,
        settled_at_height: u64,
        challenge_blocks: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let challenge_deadline_height = settled_at_height.saturating_add(challenge_blocks);
        let receipt_id = settlement_receipt_id(
            order_id,
            quote_id,
            sponsorship_id,
            lane_id,
            sequencer_id,
            inclusion_root,
            execution_root,
            rebate_commitment,
            gas_used,
            fee_paid_micro_units,
            rebate_paid_units,
            settled_at_height,
            challenge_deadline_height,
        );
        let receipt = Self {
            receipt_id,
            order_id: order_id.to_string(),
            quote_id: quote_id.to_string(),
            sponsorship_id: sponsorship_id.to_string(),
            lane_id: lane_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            inclusion_root: inclusion_root.to_string(),
            execution_root: execution_root.to_string(),
            rebate_commitment: rebate_commitment.to_string(),
            gas_used,
            fee_paid_micro_units,
            rebate_paid_units,
            settled_at_height,
            challenge_deadline_height,
            status: SettlementStatus::RebateCredited,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("receipt id", &self.receipt_id)?;
        validate_id("order id", &self.order_id)?;
        validate_id("quote id", &self.quote_id)?;
        validate_id("sponsorship id", &self.sponsorship_id)?;
        validate_id("lane id", &self.lane_id)?;
        validate_id("sequencer id", &self.sequencer_id)?;
        validate_id("inclusion root", &self.inclusion_root)?;
        validate_id("execution root", &self.execution_root)?;
        validate_id("rebate commitment", &self.rebate_commitment)?;
        if self.gas_used == 0 || self.fee_paid_micro_units == 0 {
            return Err("settlement receipt gas and fee fields must be positive".to_string());
        }
        if self.challenge_deadline_height <= self.settled_at_height {
            return Err(
                "settlement receipt challenge deadline must be after settlement".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "order_id": self.order_id,
            "quote_id": self.quote_id,
            "sponsorship_id": self.sponsorship_id,
            "lane_id": self.lane_id,
            "sequencer_id": self.sequencer_id,
            "inclusion_root": self.inclusion_root,
            "execution_root": self.execution_root,
            "rebate_commitment": self.rebate_commitment,
            "gas_used": self.gas_used,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_paid_units": self.rebate_paid_units,
            "settled_at_height": self.settled_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub slash_hint_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChallengeStatus,
}

impl Challenge {
    pub fn new(
        receipt_id: &str,
        challenger_commitment: &str,
        evidence: &Value,
        slash_hint_units: u64,
        opened_at_height: u64,
        challenge_blocks: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<Self> {
        let evidence_root = metadata_root(evidence);
        let expires_at_height = opened_at_height.saturating_add(challenge_blocks);
        let challenge_id = challenge_id(
            receipt_id,
            challenger_commitment,
            &evidence_root,
            slash_hint_units,
            opened_at_height,
            expires_at_height,
        );
        let challenge = Self {
            challenge_id,
            receipt_id: receipt_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root,
            slash_hint_units,
            opened_at_height,
            expires_at_height,
            status: ChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("challenge id", &self.challenge_id)?;
        validate_id("receipt id", &self.receipt_id)?;
        validate_id("challenger commitment", &self.challenger_commitment)?;
        validate_id("evidence root", &self.evidence_root)?;
        if self.slash_hint_units == 0 {
            return Err("challenge slash hint must be positive".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "slash_hint_units": self.slash_hint_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_policy_root: String,
    pub private_order_root: String,
    pub quote_root: String,
    pub sponsorship_root: String,
    pub eligibility_proof_root: String,
    pub nullifier_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub sequencer_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_policies: usize,
    pub private_orders: usize,
    pub sequencer_quotes: usize,
    pub sponsorships: usize,
    pub eligibility_proofs: usize,
    pub nullifiers: usize,
    pub receipts: usize,
    pub challenges: usize,
    pub sequencers: usize,
    pub active_orders: usize,
    pub open_quotes: usize,
    pub open_challenges: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub lane_policies: BTreeMap<String, LanePolicy>,
    pub private_orders: BTreeMap<String, PrivateRebateOrder>,
    pub sequencer_quotes: BTreeMap<String, SequencerQuote>,
    pub sponsorships: BTreeMap<String, ContractGasSponsorship>,
    pub eligibility_proofs: BTreeMap<String, ZkEligibilityProof>,
    pub nullifiers: BTreeMap<String, NullifierEntry>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, Challenge>,
    pub sequencers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> ZkContractFeeRebateSequencerMarketResult<State> {
        let config = Config::devnet();
        let mut state = Self {
            config,
            height: ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_DEVNET_HEIGHT,
            epoch: 0,
            lane_policies: BTreeMap::new(),
            private_orders: BTreeMap::new(),
            sequencer_quotes: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            eligibility_proofs: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            sequencers: BTreeSet::new(),
        };
        state.epoch = state.height / state.config.epoch_blocks;
        state.install_devnet_lanes()?;
        state.install_devnet_market()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        self.config.validate()?;
        if self.config.epoch_blocks == 0 {
            return Err("zk contract fee rebate market epoch blocks cannot be zero".to_string());
        }
        if self.epoch != self.height / self.config.epoch_blocks {
            return Err("zk contract fee rebate market epoch does not match height".to_string());
        }
        validate_len("lane policies", self.lane_policies.len())?;
        validate_len("private orders", self.private_orders.len())?;
        validate_len("sequencer quotes", self.sequencer_quotes.len())?;
        validate_len("sponsorships", self.sponsorships.len())?;
        validate_len("eligibility proofs", self.eligibility_proofs.len())?;
        validate_len("nullifiers", self.nullifiers.len())?;
        validate_len("receipts", self.receipts.len())?;
        if self.challenges.len() > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_CHALLENGES {
            return Err("zk contract fee rebate market too many challenges".to_string());
        }

        for (id, policy) in &self.lane_policies {
            if id != &policy.lane_id {
                return Err("lane policy map key mismatch".to_string());
            }
            policy.validate()?;
        }
        for (id, proof) in &self.eligibility_proofs {
            if id != &proof.proof_id {
                return Err("eligibility proof map key mismatch".to_string());
            }
            proof.validate()?;
            if proof.privacy_set_size < self.config.min_privacy_set_size {
                return Err("eligibility proof privacy set below config minimum".to_string());
            }
            if proof.pq_security_bits < self.config.min_pq_security_bits {
                return Err("eligibility proof pq security below config minimum".to_string());
            }
            if !self.lane_policies.contains_key(&proof.lane_id) {
                return Err("eligibility proof references unknown lane".to_string());
            }
        }
        for (id, order) in &self.private_orders {
            if id != &order.order_id {
                return Err("private order map key mismatch".to_string());
            }
            order.validate()?;
            let policy = self
                .lane_policies
                .get(&order.lane_id)
                .ok_or_else(|| "private order references unknown lane".to_string())?;
            if order.call_class != policy.call_class {
                return Err("private order call class does not match lane".to_string());
            }
            if order.gas_limit > policy.max_gas_units {
                return Err("private order gas exceeds lane max".to_string());
            }
            if order.max_fee_micro_units > policy.fee_cap_micro_units {
                return Err("private order fee exceeds lane cap".to_string());
            }
            if order.requested_rebate_bps > policy.max_rebate_bps
                || order.requested_rebate_bps > self.config.max_rebate_bps
            {
                return Err("private order requested rebate exceeds policy".to_string());
            }
            let proof = self
                .eligibility_proofs
                .get(&order.eligibility_proof_id)
                .ok_or_else(|| "private order references unknown proof".to_string())?;
            if proof.anti_sybil_nullifier != order.anti_sybil_nullifier {
                return Err("private order nullifier does not match proof".to_string());
            }
        }
        let mut seen_nullifiers = BTreeSet::new();
        for (id, nullifier) in &self.nullifiers {
            if id != &nullifier.nullifier {
                return Err("nullifier map key mismatch".to_string());
            }
            nullifier.validate()?;
            if !seen_nullifiers.insert(id.clone()) {
                return Err("duplicate nullifier".to_string());
            }
            if !self.private_orders.contains_key(&nullifier.order_id) {
                return Err("nullifier references unknown order".to_string());
            }
            if !self.eligibility_proofs.contains_key(&nullifier.proof_id) {
                return Err("nullifier references unknown proof".to_string());
            }
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            if sponsorship.budget_units < self.config.min_sponsor_bond_units {
                return Err("sponsorship budget below minimum bond".to_string());
            }
            if !self.lane_policies.contains_key(&sponsorship.lane_id) {
                return Err("sponsorship references unknown lane".to_string());
            }
        }
        for (id, quote) in &self.sequencer_quotes {
            if id != &quote.quote_id {
                return Err("sequencer quote map key mismatch".to_string());
            }
            quote.validate()?;
            if !self.sequencers.contains(&quote.sequencer_id) {
                return Err("sequencer quote references unknown sequencer".to_string());
            }
            if !self.private_orders.contains_key(&quote.order_id) {
                return Err("sequencer quote references unknown order".to_string());
            }
            if quote.rebate_bps > self.config.max_rebate_bps {
                return Err("sequencer quote rebate exceeds config max".to_string());
            }
        }
        for (id, receipt) in &self.receipts {
            if id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.private_orders.contains_key(&receipt.order_id) {
                return Err("receipt references unknown order".to_string());
            }
            if !self.sequencer_quotes.contains_key(&receipt.quote_id) {
                return Err("receipt references unknown quote".to_string());
            }
            if !self.sponsorships.contains_key(&receipt.sponsorship_id) {
                return Err("receipt references unknown sponsorship".to_string());
            }
        }
        for (id, challenge) in &self.challenges {
            if id != &challenge.challenge_id {
                return Err("challenge map key mismatch".to_string());
            }
            challenge.validate()?;
            if !self.receipts.contains_key(&challenge.receipt_id) {
                return Err("challenge references unknown receipt".to_string());
            }
        }
        for sequencer in &self.sequencers {
            validate_id("sequencer id", sequencer)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkContractFeeRebateSequencerMarketResult<()> {
        self.height = height;
        self.epoch = height / self.config.epoch_blocks;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> ZkContractFeeRebateSequencerMarketResult<()> {
        if height < self.height {
            return Err("zk contract fee rebate market height cannot decrease".to_string());
        }
        self.set_height(height)?;
        self.expire_records();
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.config_root();
        let lane_policy_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-LANE-POLICY",
            &self
                .lane_policies
                .values()
                .map(LanePolicy::public_record)
                .collect::<Vec<_>>(),
        );
        let private_order_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-PRIVATE-ORDER",
            &self
                .private_orders
                .values()
                .map(PrivateRebateOrder::public_record)
                .collect::<Vec<_>>(),
        );
        let quote_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-QUOTE",
            &self
                .sequencer_quotes
                .values()
                .map(SequencerQuote::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-SPONSORSHIP",
            &self
                .sponsorships
                .values()
                .map(ContractGasSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        let eligibility_proof_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-ELIGIBILITY-PROOF",
            &self
                .eligibility_proofs
                .values()
                .map(ZkEligibilityProof::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-NULLIFIER",
            &self
                .nullifiers
                .values()
                .map(NullifierEntry::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-RECEIPT",
            &self
                .receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let challenge_root = map_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-CHALLENGE",
            &self
                .challenges
                .values()
                .map(Challenge::public_record)
                .collect::<Vec<_>>(),
        );
        let sequencer_root = string_set_root(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-SEQUENCER",
            &self.sequencers,
        );
        let state_root = domain_hash(
            "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&lane_policy_root),
                HashPart::Str(&private_order_root),
                HashPart::Str(&quote_root),
                HashPart::Str(&sponsorship_root),
                HashPart::Str(&eligibility_proof_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&challenge_root),
                HashPart::Str(&sequencer_root),
            ],
            32,
        );
        Roots {
            config_root,
            lane_policy_root,
            private_order_root,
            quote_root,
            sponsorship_root,
            eligibility_proof_root,
            nullifier_root,
            receipt_root,
            challenge_root,
            sequencer_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lane_policies: self.lane_policies.len(),
            private_orders: self.private_orders.len(),
            sequencer_quotes: self.sequencer_quotes.len(),
            sponsorships: self.sponsorships.len(),
            eligibility_proofs: self.eligibility_proofs.len(),
            nullifiers: self.nullifiers.len(),
            receipts: self.receipts.len(),
            challenges: self.challenges.len(),
            sequencers: self.sequencers.len(),
            active_orders: self
                .private_orders
                .values()
                .filter(|order| order.status.active())
                .count(),
            open_quotes: self
                .sequencer_quotes
                .values()
                .filter(|quote| quote.status.usable())
                .count(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol": ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_PROTOCOL_VERSION,
            "schema_version": ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots,
            "counters": counters,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn register_sequencer(
        &mut self,
        sequencer_id: &str,
    ) -> ZkContractFeeRebateSequencerMarketResult<()> {
        validate_id("sequencer id", sequencer_id)?;
        self.sequencers.insert(sequencer_id.to_string());
        self.validate()
    }

    pub fn upsert_lane_policy(
        &mut self,
        policy: LanePolicy,
    ) -> ZkContractFeeRebateSequencerMarketResult<()> {
        policy.validate()?;
        self.lane_policies.insert(policy.lane_id.clone(), policy);
        self.validate()
    }

    pub fn submit_eligibility_proof(
        &mut self,
        proof: ZkEligibilityProof,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        proof.validate()?;
        if proof.privacy_set_size < self.config.min_privacy_set_size {
            return Err("eligibility proof privacy set below config minimum".to_string());
        }
        if proof.pq_security_bits < self.config.min_pq_security_bits {
            return Err("eligibility proof pq security below config minimum".to_string());
        }
        if proof.expires_at_height <= self.height {
            return Err("eligibility proof already expired".to_string());
        }
        if !self.lane_policies.contains_key(&proof.lane_id) {
            return Err("eligibility proof lane is unknown".to_string());
        }
        let proof_id = proof.proof_id.clone();
        self.eligibility_proofs.insert(proof_id.clone(), proof);
        self.validate()?;
        Ok(proof_id)
    }

    pub fn submit_private_order(
        &mut self,
        order: PrivateRebateOrder,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        order.validate()?;
        if order.expires_at_height <= self.height {
            return Err("private rebate order already expired".to_string());
        }
        if self.nullifiers.contains_key(&order.anti_sybil_nullifier) {
            return Err("anti-sybil nullifier already seen".to_string());
        }
        let proof = self
            .eligibility_proofs
            .get(&order.eligibility_proof_id)
            .ok_or_else(|| "private order eligibility proof is unknown".to_string())?;
        if !proof.status.usable() {
            return Err("private order eligibility proof is not usable".to_string());
        }
        if proof.anti_sybil_nullifier != order.anti_sybil_nullifier {
            return Err("private order proof nullifier mismatch".to_string());
        }
        let order_id = order.order_id.clone();
        let nullifier = NullifierEntry::new(
            &order.anti_sybil_nullifier,
            &order.order_id,
            &order.eligibility_proof_id,
            self.epoch,
            self.height,
        )?;
        self.nullifiers
            .insert(nullifier.nullifier.clone(), nullifier);
        self.private_orders.insert(order_id.clone(), order);
        self.validate()?;
        Ok(order_id)
    }

    pub fn submit_sequencer_quote(
        &mut self,
        quote: SequencerQuote,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        quote.validate()?;
        if quote.expires_at_height <= self.height {
            return Err("sequencer quote already expired".to_string());
        }
        if !self.sequencers.contains(&quote.sequencer_id) {
            return Err("sequencer quote sequencer is not registered".to_string());
        }
        let order = self
            .private_orders
            .get_mut(&quote.order_id)
            .ok_or_else(|| "sequencer quote order is unknown".to_string())?;
        if !order.status.active() {
            return Err("sequencer quote order is not active".to_string());
        }
        if quote.fee_micro_units > order.max_fee_micro_units {
            return Err("sequencer quote fee exceeds order cap".to_string());
        }
        if quote.rebate_bps < order.requested_rebate_bps {
            return Err("sequencer quote rebate below order request".to_string());
        }
        order.status = OrderStatus::Quoted;
        let quote_id = quote.quote_id.clone();
        self.sequencer_quotes.insert(quote_id.clone(), quote);
        self.validate()?;
        Ok(quote_id)
    }

    pub fn open_sponsorship(
        &mut self,
        sponsorship: ContractGasSponsorship,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        sponsorship.validate()?;
        if sponsorship.expires_at_height <= self.height {
            return Err("contract gas sponsorship already expired".to_string());
        }
        if sponsorship.budget_units < self.config.min_sponsor_bond_units {
            return Err("contract gas sponsorship below minimum bond".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.validate()?;
        Ok(sponsorship_id)
    }

    pub fn reserve_quote_with_sponsorship(
        &mut self,
        order_id: &str,
        quote_id: &str,
        sponsorship_id: &str,
    ) -> ZkContractFeeRebateSequencerMarketResult<()> {
        let quote = self
            .sequencer_quotes
            .get_mut(quote_id)
            .ok_or_else(|| "reserve quote references unknown quote".to_string())?;
        if quote.order_id != order_id {
            return Err("reserve quote order mismatch".to_string());
        }
        if !quote.status.usable() {
            return Err("reserve quote is not usable".to_string());
        }
        let order = self
            .private_orders
            .get_mut(order_id)
            .ok_or_else(|| "reserve quote references unknown order".to_string())?;
        if !order.status.active() {
            return Err("reserve quote order is not active".to_string());
        }
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "reserve quote references unknown sponsorship".to_string())?;
        if !sponsorship.status.spendable() {
            return Err("reserve quote sponsorship is not spendable".to_string());
        }
        if sponsorship.lane_id != order.lane_id {
            return Err("reserve quote sponsorship lane mismatch".to_string());
        }
        if sponsorship.available_units() < quote.fee_micro_units {
            return Err("reserve quote sponsorship has insufficient budget".to_string());
        }
        sponsorship.reserved_units = sponsorship
            .reserved_units
            .saturating_add(quote.fee_micro_units);
        sponsorship.status = SponsorshipStatus::Reserved;
        quote.status = QuoteStatus::Accepted;
        order.status = OrderStatus::Reserved;
        self.validate()
    }

    pub fn settle_low_fee_lane(
        &mut self,
        order_id: &str,
        quote_id: &str,
        sponsorship_id: &str,
        inclusion_root: &str,
        execution_root: &str,
        rebate_commitment: &str,
        gas_used: u64,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        let order = self
            .private_orders
            .get(order_id)
            .ok_or_else(|| "settlement order is unknown".to_string())?
            .clone();
        let quote = self
            .sequencer_quotes
            .get(quote_id)
            .ok_or_else(|| "settlement quote is unknown".to_string())?
            .clone();
        if quote.order_id != order.order_id {
            return Err("settlement quote order mismatch".to_string());
        }
        if gas_used == 0 || gas_used > order.gas_limit || gas_used > quote.sponsored_gas_units {
            return Err("settlement gas is outside order or quote bounds".to_string());
        }
        let rebate_paid_units = mul_bps(quote.fee_micro_units, quote.rebate_bps);
        let receipt = SettlementReceipt::new(
            &order.order_id,
            &quote.quote_id,
            sponsorship_id,
            &order.lane_id,
            &quote.sequencer_id,
            inclusion_root,
            execution_root,
            rebate_commitment,
            gas_used,
            quote.fee_micro_units,
            rebate_paid_units,
            self.height,
            self.config.challenge_blocks,
        )?;

        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "settlement sponsorship is unknown".to_string())?;
        if sponsorship.reserved_units < quote.fee_micro_units {
            return Err("settlement sponsorship reservation is insufficient".to_string());
        }
        sponsorship.reserved_units = sponsorship
            .reserved_units
            .saturating_sub(quote.fee_micro_units);
        sponsorship.spent_units = sponsorship
            .spent_units
            .saturating_add(quote.fee_micro_units);
        if sponsorship.available_units() == 0 {
            sponsorship.status = SponsorshipStatus::Exhausted;
        } else {
            sponsorship.status = SponsorshipStatus::Active;
        }
        if let Some(stored_order) = self.private_orders.get_mut(order_id) {
            stored_order.status = OrderStatus::Settled;
        }
        if let Some(stored_quote) = self.sequencer_quotes.get_mut(quote_id) {
            stored_quote.status = QuoteStatus::Filled;
        }
        if let Some(nullifier) = self.nullifiers.get_mut(&order.anti_sybil_nullifier) {
            nullifier.consumed = true;
        }
        if let Some(proof) = self.eligibility_proofs.get_mut(&order.eligibility_proof_id) {
            proof.status = EligibilityStatus::Consumed;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        self.validate()?;
        Ok(receipt_id)
    }

    pub fn open_challenge(
        &mut self,
        challenge: Challenge,
    ) -> ZkContractFeeRebateSequencerMarketResult<String> {
        challenge.validate()?;
        let receipt = self
            .receipts
            .get_mut(&challenge.receipt_id)
            .ok_or_else(|| "challenge receipt is unknown".to_string())?;
        if self.height > receipt.challenge_deadline_height {
            return Err("challenge window is closed".to_string());
        }
        receipt.status = SettlementStatus::Disputed;
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        self.validate()?;
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
    ) -> ZkContractFeeRebateSequencerMarketResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "resolve challenge id is unknown".to_string())?;
        if challenge.status != ChallengeStatus::Open {
            return Err("challenge is not open".to_string());
        }
        challenge.status = if accepted {
            ChallengeStatus::Accepted
        } else {
            ChallengeStatus::Rejected
        };
        if let Some(receipt) = self.receipts.get_mut(&challenge.receipt_id) {
            receipt.status = if accepted {
                SettlementStatus::Reversed
            } else {
                SettlementStatus::Finalized
            };
        }
        self.validate()
    }

    fn install_devnet_lanes(&mut self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        for (class, label, gas) in [
            (
                ContractCallClass::PaymasterSponsored,
                "private_paymaster_contract_call",
                450_000,
            ),
            (
                ContractCallClass::PrivateDefiSwap,
                "sealed_defi_swap_low_fee_lane",
                700_000,
            ),
            (
                ContractCallClass::ProofAggregation,
                "recursive_proof_aggregation_rebate_lane",
                1_250_000,
            ),
            (
                ContractCallClass::MoneroBridgeExit,
                "monero_bridge_exit_contract_rebate_lane",
                550_000,
            ),
            (
                ContractCallClass::EmergencyCircuit,
                "emergency_circuit_contract_lane",
                300_000,
            ),
        ] {
            self.upsert_lane_policy(LanePolicy::new(class, label, gas))?;
        }
        Ok(())
    }

    fn install_devnet_market(&mut self) -> ZkContractFeeRebateSequencerMarketResult<()> {
        let sequencer_id = deterministic_label_hash("sequencer", "devnet-alpha");
        self.register_sequencer(&sequencer_id)?;
        let lane_id = lane_policy_id(
            ContractCallClass::PaymasterSponsored,
            "private_paymaster_contract_call",
        );
        let contract_commitment = deterministic_label_hash("contract", "paymaster-router");
        let wallet_commitment = deterministic_label_hash("wallet", "alice-private-wallet");
        let nullifier = nullifier_id(
            &wallet_commitment,
            &contract_commitment,
            &lane_id,
            self.epoch,
        );
        let proof = ZkEligibilityProof::new(
            &wallet_commitment,
            &contract_commitment,
            &lane_id,
            ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_ELIGIBILITY_PROOF_SCHEME,
            &deterministic_label_hash("vk", "contract-rebate-devnet"),
            &json!({
                "lane_id": lane_id,
                "contract_commitment": contract_commitment,
                "fee_asset_id": self.config.fee_asset_id,
                "rebate_asset_id": self.config.rebate_asset_id,
            }),
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
            &nullifier,
            self.height,
            self.height.saturating_add(self.config.epoch_blocks),
        )?;
        let proof_id = self.submit_eligibility_proof(proof)?;
        let order = PrivateRebateOrder::new(
            &lane_id,
            ContractCallClass::PaymasterSponsored,
            &deterministic_label_hash("sealed-call", "alice-paymaster-call"),
            &wallet_commitment,
            &contract_commitment,
            280_000,
            850,
            6_500,
            &proof_id,
            &nullifier,
            &json!({"purpose": "devnet seeded private contract gas rebate"}),
            self.height,
            self.config.order_ttl_blocks,
        )?;
        let order_id = self.submit_private_order(order)?;
        let quote = SequencerQuote::new(
            &sequencer_id,
            &lane_id,
            &order_id,
            &deterministic_label_hash("quote-commitment", "devnet-alpha-quote"),
            700,
            7_000,
            300_000,
            self.config.min_sponsor_bond_units,
            &json!({"latency_target_ms": 500, "lane": "low_fee_private_contract"}),
            self.height,
            self.config.quote_ttl_blocks,
        )?;
        let quote_id = self.submit_sequencer_quote(quote)?;
        let sponsorship = ContractGasSponsorship::new(
            &deterministic_label_hash("sponsor", "devnet-foundation"),
            &contract_commitment,
            &lane_id,
            self.config.min_sponsor_bond_units.saturating_mul(4),
            8_000,
            &json!({"allow_contract": contract_commitment, "lane_id": lane_id}),
            self.height,
            self.height
                .saturating_add(self.config.epoch_blocks.saturating_mul(4)),
        )?;
        let sponsorship_id = self.open_sponsorship(sponsorship)?;
        self.reserve_quote_with_sponsorship(&order_id, &quote_id, &sponsorship_id)?;
        Ok(())
    }

    fn expire_records(&mut self) {
        for order in self.private_orders.values_mut() {
            if order.status.active() && self.height > order.expires_at_height {
                order.status = OrderStatus::Expired;
            }
        }
        for quote in self.sequencer_quotes.values_mut() {
            if quote.status.usable() && self.height > quote.expires_at_height {
                quote.status = QuoteStatus::Expired;
            }
        }
        for proof in self.eligibility_proofs.values_mut() {
            if proof.status.usable() && self.height > proof.expires_at_height {
                proof.status = EligibilityStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.spendable() && self.height > sponsorship.expires_at_height {
                sponsorship.status = SponsorshipStatus::Closed;
            }
        }
        for receipt in self.receipts.values_mut() {
            if receipt.status.finalizable() && self.height > receipt.challenge_deadline_height {
                receipt.status = SettlementStatus::Finalized;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open
                && self.height > challenge.expires_at_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkContractFeeRebateSequencerMarketResult<State> {
    State::devnet()
}

pub fn lane_policy_id(call_class: ContractCallClass, lane_label: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_class.as_str()),
            HashPart::Str(lane_label),
        ],
        32,
    )
}

pub fn nullifier_id(
    subject_commitment: &str,
    contract_commitment: &str,
    lane_id: &str,
    epoch: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_rebate_order_id(
    lane_id: &str,
    call_class: ContractCallClass,
    sealed_call_commitment: &str,
    wallet_commitment: &str,
    contract_commitment: &str,
    gas_limit: u64,
    max_fee_micro_units: u64,
    requested_rebate_bps: u64,
    eligibility_proof_id: &str,
    anti_sybil_nullifier: &str,
    metadata_root: &str,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-PRIVATE-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(call_class.as_str()),
            HashPart::Str(sealed_call_commitment),
            HashPart::Str(wallet_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Int(gas_limit as i128),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Int(requested_rebate_bps as i128),
            HashPart::Str(eligibility_proof_id),
            HashPart::Str(anti_sybil_nullifier),
            HashPart::Str(metadata_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sequencer_quote_id(
    sequencer_id: &str,
    lane_id: &str,
    order_id: &str,
    quote_commitment: &str,
    fee_micro_units: u64,
    rebate_bps: u64,
    sponsored_gas_units: u64,
    bond_units: u64,
    quote_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sequencer_id),
            HashPart::Str(lane_id),
            HashPart::Str(order_id),
            HashPart::Str(quote_commitment),
            HashPart::Int(fee_micro_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Int(sponsored_gas_units as i128),
            HashPart::Int(bond_units as i128),
            HashPart::Str(quote_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn contract_gas_sponsorship_id(
    sponsor_id: &str,
    contract_commitment: &str,
    lane_id: &str,
    budget_units: u64,
    max_rebate_bps: u64,
    policy_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(budget_units as i128),
            HashPart::Int(max_rebate_bps as i128),
            HashPart::Str(policy_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_eligibility_proof_id(
    subject_commitment: &str,
    contract_commitment: &str,
    lane_id: &str,
    proof_system: &str,
    verifying_key_root: &str,
    public_input_root: &str,
    privacy_set_size: u64,
    pq_security_bits: u16,
    anti_sybil_nullifier: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-ELIGIBILITY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(proof_system),
            HashPart::Str(verifying_key_root),
            HashPart::Str(public_input_root),
            HashPart::Int(privacy_set_size as i128),
            HashPart::Int(pq_security_bits as i128),
            HashPart::Str(anti_sybil_nullifier),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn settlement_receipt_id(
    order_id: &str,
    quote_id: &str,
    sponsorship_id: &str,
    lane_id: &str,
    sequencer_id: &str,
    inclusion_root: &str,
    execution_root: &str,
    rebate_commitment: &str,
    gas_used: u64,
    fee_paid_micro_units: u64,
    rebate_paid_units: u64,
    settled_at_height: u64,
    challenge_deadline_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(order_id),
            HashPart::Str(quote_id),
            HashPart::Str(sponsorship_id),
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(inclusion_root),
            HashPart::Str(execution_root),
            HashPart::Str(rebate_commitment),
            HashPart::Int(gas_used as i128),
            HashPart::Int(fee_paid_micro_units as i128),
            HashPart::Int(rebate_paid_units as i128),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(challenge_deadline_height as i128),
        ],
        32,
    )
}

pub fn challenge_id(
    receipt_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    slash_hint_units: u64,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(slash_hint_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn deterministic_label_hash(kind: &str, label: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn metadata_root(metadata: &Value) -> String {
    domain_hash(
        "ZK-CONTRACT-FEE-REBATE-SEQUENCER-MARKET-METADATA",
        &[HashPart::Json(metadata)],
        32,
    )
}

fn map_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn validate_id(label: &str, value: &str) -> ZkContractFeeRebateSequencerMarketResult<()> {
    if value.is_empty() {
        return Err(format!(
            "zk contract fee rebate market {label} cannot be empty"
        ));
    }
    Ok(())
}

fn validate_len(label: &str, len: usize) -> ZkContractFeeRebateSequencerMarketResult<()> {
    if len > ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_RECORDS {
        return Err(format!("zk contract fee rebate market too many {label}"));
    }
    Ok(())
}

fn mul_bps(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps) / ZK_CONTRACT_FEE_REBATE_SEQUENCER_MARKET_MAX_BPS
}
