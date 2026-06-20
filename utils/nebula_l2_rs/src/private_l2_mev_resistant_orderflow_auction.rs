use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2MevResistantOrderflowAuctionResult<T> = Result<T, String>;

pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_PROTOCOL_VERSION: &str =
    "nebula-private-l2-mev-resistant-orderflow-auction-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SEALED_INTENT_SCHEME: &str =
    "ml-kem-1024+zk-sealed-private-l2-intent-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_ORDERFLOW_BUNDLE_SCHEME: &str =
    "threshold-encrypted-private-orderflow-bundle-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SOLVER_COMMITMENT_SCHEME: &str =
    "commit-reveal-solver-route-commitment-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-private-orderflow-auth-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_ANTI_CENSORSHIP_SCHEME: &str =
    "inclusion-list+encrypted-mempool-anti-censorship-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_REBATE_SCHEME: &str =
    "low-fee-private-execution-rebate-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SETTLEMENT_SCHEME: &str =
    "zk-pq-private-auction-settlement-receipt-v1";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEVNET_HEIGHT: u64 = 175_000;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEVNET_RUNTIME: &str =
    "devnet-private-l2-mev-resistant-orderflow-auction-runtime";
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_INTENTS_PER_AUCTION: usize = 768;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_SOLVER_COMMITMENTS: usize = 128;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_ROUTE_STEPS: usize = 2_048;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_PRIVACY_SET: u64 = 80;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_SURPLUS_REBATE_BPS: u64 = 6_000;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_CENSORSHIP_BOND_MICRO_UNITS: u64 =
    250_000;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 =
    75_000_000;
pub const PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    PrivateDefiSwap,
    ConfidentialTokenTransfer,
    ConfidentialTokenMint,
    ConfidentialContractCall,
    ConfidentialContractBatch,
    LiquidityProvision,
    PrivateBridgeExit,
    PrivateMoneroExit,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::ConfidentialTokenMint => "confidential_token_mint",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::ConfidentialContractBatch => "confidential_contract_batch",
            Self::LiquidityProvision => "liquidity_provision",
            Self::PrivateBridgeExit => "private_bridge_exit",
            Self::PrivateMoneroExit => "private_monero_exit",
        }
    }

    pub fn default_domain(self) -> ExecutionDomain {
        match self {
            Self::PrivateDefiSwap | Self::LiquidityProvision => ExecutionDomain::PrivateDefi,
            Self::ConfidentialTokenTransfer | Self::ConfidentialTokenMint => {
                ExecutionDomain::ConfidentialTokens
            }
            Self::ConfidentialContractCall | Self::ConfidentialContractBatch => {
                ExecutionDomain::PrivateContracts
            }
            Self::PrivateBridgeExit | Self::PrivateMoneroExit => ExecutionDomain::PrivateExit,
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::PrivateMoneroExit => 980,
            Self::PrivateBridgeExit => 920,
            Self::PrivateDefiSwap => 880,
            Self::LiquidityProvision => 820,
            Self::ConfidentialContractBatch => 760,
            Self::ConfidentialContractCall => 700,
            Self::ConfidentialTokenMint => 640,
            Self::ConfidentialTokenTransfer => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDomain {
    PrivateDefi,
    ConfidentialTokens,
    PrivateContracts,
    PrivateExit,
    RebateSettlement,
}

impl ExecutionDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDefi => "private_defi",
            Self::ConfidentialTokens => "confidential_tokens",
            Self::PrivateContracts => "private_contracts",
            Self::PrivateExit => "private_exit",
            Self::RebateSettlement => "rebate_settlement",
        }
    }

    pub fn ordering_rank(self) -> u64 {
        match self {
            Self::PrivateExit => 0,
            Self::PrivateDefi => 1,
            Self::PrivateContracts => 2,
            Self::ConfidentialTokens => 3,
            Self::RebateSettlement => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Admitted,
    Bundled,
    Auctioned,
    Settled,
    Deferred,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Bundled => "bundled",
            Self::Auctioned => "auctioned",
            Self::Settled => "settled",
            Self::Deferred => "deferred",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Admitted | Self::Bundled | Self::Deferred
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Encrypted,
    Committed,
    Auctioned,
    Settled,
    Expired,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Encrypted => "encrypted",
            Self::Committed => "committed",
            Self::Auctioned => "auctioned",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Committed,
    Solved,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Solved => "solved",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStepKind {
    PoolSwap,
    PrivateTokenTransfer,
    ContractInvoke,
    LiquidityAdd,
    LiquidityRemove,
    BridgeExit,
    MoneroExit,
    RebateCredit,
}

impl RouteStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolSwap => "pool_swap",
            Self::PrivateTokenTransfer => "private_token_transfer",
            Self::ContractInvoke => "contract_invoke",
            Self::LiquidityAdd => "liquidity_add",
            Self::LiquidityRemove => "liquidity_remove",
            Self::BridgeExit => "bridge_exit",
            Self::MoneroExit => "monero_exit",
            Self::RebateCredit => "rebate_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_intent_scheme: String,
    pub orderflow_bundle_scheme: String,
    pub solver_commitment_scheme: String,
    pub pq_auth_scheme: String,
    pub anti_censorship_scheme: String,
    pub rebate_scheme: String,
    pub settlement_scheme: String,
    pub auction_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_intents_per_auction: usize,
    pub max_solver_commitments: usize,
    pub max_route_steps: usize,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub max_solver_fee_bps: u64,
    pub censorship_bond_micro_units: u64,
    pub rebate_budget_micro_units: u64,
    pub require_pq_authorization: bool,
    pub require_threshold_encryption: bool,
    pub require_anti_censorship_commitment: bool,
    pub enable_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_HASH_SUITE.to_string(),
            sealed_intent_scheme: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SEALED_INTENT_SCHEME
                .to_string(),
            orderflow_bundle_scheme:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_ORDERFLOW_BUNDLE_SCHEME.to_string(),
            solver_commitment_scheme:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SOLVER_COMMITMENT_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_PQ_AUTH_SCHEME.to_string(),
            anti_censorship_scheme:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_ANTI_CENSORSHIP_SCHEME.to_string(),
            rebate_scheme: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_REBATE_SCHEME.to_string(),
            settlement_scheme: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SETTLEMENT_SCHEME
                .to_string(),
            auction_window_blocks:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_AUCTION_WINDOW_BLOCKS,
            intent_ttl_blocks: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_INTENT_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_intents_per_auction:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_INTENTS_PER_AUCTION,
            max_solver_commitments:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_SOLVER_COMMITMENTS,
            max_route_steps: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_ROUTE_STEPS,
            min_privacy_set: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_USER_FEE_BPS,
            min_surplus_rebate_bps:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MIN_SURPLUS_REBATE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_MAX_SOLVER_FEE_BPS,
            censorship_bond_micro_units:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_CENSORSHIP_BOND_MICRO_UNITS,
            rebate_budget_micro_units:
                PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            require_pq_authorization: true,
            require_threshold_encryption: true,
            require_anti_censorship_commitment: true,
            enable_low_fee_rebates: true,
        }
    }

    pub fn validate(&self) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
        ensure_eq(
            &self.chain_id,
            CHAIN_ID,
            "private orderflow auction chain id",
        )?;
        ensure_eq(
            &self.protocol_version,
            PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_PROTOCOL_VERSION,
            "private orderflow auction protocol version",
        )?;
        if self.schema_version != PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_SCHEMA_VERSION {
            return Err("private orderflow auction schema version mismatch".to_string());
        }
        if self.auction_window_blocks == 0 || self.intent_ttl_blocks == 0 {
            return Err("private orderflow auction windows must be non-zero".to_string());
        }
        if self.max_intents_per_auction == 0 || self.max_solver_commitments == 0 {
            return Err("private orderflow auction capacities must be non-zero".to_string());
        }
        if self.min_surplus_rebate_bps > PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS {
            return Err("private orderflow auction rebate bps exceeds max bps".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS
            || self.max_solver_fee_bps > PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS
        {
            return Err("private orderflow auction fee bps exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "orderflow_bundle_scheme": self.orderflow_bundle_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "anti_censorship_scheme": self.anti_censorship_scheme,
            "rebate_scheme": self.rebate_scheme,
            "settlement_scheme": self.settlement_scheme,
            "auction_window_blocks": self.auction_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_intents_per_auction": self.max_intents_per_auction,
            "max_solver_commitments": self.max_solver_commitments,
            "max_route_steps": self.max_route_steps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_surplus_rebate_bps": self.min_surplus_rebate_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "censorship_bond_micro_units": self.censorship_bond_micro_units,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "require_pq_authorization": self.require_pq_authorization,
            "require_threshold_encryption": self.require_threshold_encryption,
            "require_anti_censorship_commitment": self.require_anti_censorship_commitment,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_bundle_nonce: u64,
    pub next_auction_nonce: u64,
    pub next_route_nonce: u64,
    pub intents_submitted: u64,
    pub intents_admitted: u64,
    pub intents_deferred: u64,
    pub intents_rejected: u64,
    pub intents_auctioned: u64,
    pub intents_settled: u64,
    pub bundles_encrypted: u64,
    pub solver_commitments_recorded: u64,
    pub auctions_run: u64,
    pub auctions_settled: u64,
    pub receipts_published: u64,
    pub low_fee_rebates_micro_units: u64,
    pub solver_fees_micro_units: u64,
    pub surplus_returned_micro_units: u64,
    pub censorship_bonds_locked_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_intent_nonce": self.next_intent_nonce,
            "next_bundle_nonce": self.next_bundle_nonce,
            "next_auction_nonce": self.next_auction_nonce,
            "next_route_nonce": self.next_route_nonce,
            "intents_submitted": self.intents_submitted,
            "intents_admitted": self.intents_admitted,
            "intents_deferred": self.intents_deferred,
            "intents_rejected": self.intents_rejected,
            "intents_auctioned": self.intents_auctioned,
            "intents_settled": self.intents_settled,
            "bundles_encrypted": self.bundles_encrypted,
            "solver_commitments_recorded": self.solver_commitments_recorded,
            "auctions_run": self.auctions_run,
            "auctions_settled": self.auctions_settled,
            "receipts_published": self.receipts_published,
            "low_fee_rebates_micro_units": self.low_fee_rebates_micro_units,
            "solver_fees_micro_units": self.solver_fees_micro_units,
            "surplus_returned_micro_units": self.surplus_returned_micro_units,
            "censorship_bonds_locked_micro_units": self.censorship_bonds_locked_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitOrderflowRequest {
    pub intent_kind: IntentKind,
    pub execution_domain: Option<ExecutionDomain>,
    pub account_commitment: String,
    pub source_asset_commitment: String,
    pub target_asset_commitment: String,
    pub sealed_intent_root: String,
    pub encrypted_payload_root: String,
    pub encrypted_orderflow_root: String,
    pub nullifier_root: String,
    pub refund_commitment: String,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub estimated_value_micro_units: u64,
    pub estimated_weight: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_authorization_root: String,
    pub anti_censorship_commitment_root: String,
    pub inclusion_list_root: String,
    pub low_fee_rebate_commitment: Option<String>,
    pub expires_at_height: u64,
    pub submitted_at_height: u64,
    pub relay_hint: Option<String>,
}

impl SubmitOrderflowRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
        validate_root(&self.account_commitment, "account commitment")?;
        validate_root(&self.source_asset_commitment, "source asset commitment")?;
        validate_root(&self.target_asset_commitment, "target asset commitment")?;
        validate_root(&self.sealed_intent_root, "sealed intent root")?;
        validate_root(&self.encrypted_payload_root, "encrypted payload root")?;
        validate_root(&self.encrypted_orderflow_root, "encrypted orderflow root")?;
        validate_root(&self.nullifier_root, "nullifier root")?;
        validate_root(&self.refund_commitment, "refund commitment")?;
        if config.require_pq_authorization {
            validate_root(&self.pq_authorization_root, "pq authorization root")?;
        }
        if config.require_anti_censorship_commitment {
            validate_root(
                &self.anti_censorship_commitment_root,
                "anti-censorship commitment root",
            )?;
            validate_root(&self.inclusion_list_root, "inclusion list root")?;
        }
        if let Some(root) = &self.low_fee_rebate_commitment {
            validate_root(root, "low-fee rebate commitment")?;
        }
        if self.estimated_weight == 0 || self.estimated_value_micro_units == 0 {
            return Err(
                "private orderflow estimated value and weight must be non-zero".to_string(),
            );
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("private orderflow privacy set is below configured floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("private orderflow pq security bits below configured floor".to_string());
        }
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("private orderflow user fee exceeds configured cap".to_string());
        }
        if self.max_solver_fee_bps > config.max_solver_fee_bps {
            return Err("private orderflow solver fee exceeds configured cap".to_string());
        }
        if self.min_surplus_rebate_bps < config.min_surplus_rebate_bps {
            return Err("private orderflow surplus rebate is below configured floor".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("private orderflow expiry must be after submission height".to_string());
        }
        if self.expires_at_height
            > self
                .submitted_at_height
                .saturating_add(config.intent_ttl_blocks)
        {
            return Err("private orderflow expiry exceeds configured ttl".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitmentRequest {
    pub solver_id: String,
    pub solver_stake_root: String,
    pub route_commitment_root: String,
    pub execution_trace_commitment_root: String,
    pub surplus_commitment_root: String,
    pub pq_authorization_root: String,
    pub censorship_bond_root: String,
    pub bid_fee_micro_units: u64,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub reveal_deadline_height: u64,
}

impl SolverCommitmentRequest {
    pub fn validate(
        &self,
        config: &Config,
        auction_height: u64,
    ) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
        if self.solver_id.trim().is_empty() {
            return Err("private orderflow solver id must not be empty".to_string());
        }
        validate_root(&self.solver_stake_root, "solver stake root")?;
        validate_root(&self.route_commitment_root, "route commitment root")?;
        validate_root(
            &self.execution_trace_commitment_root,
            "execution trace commitment root",
        )?;
        validate_root(&self.surplus_commitment_root, "surplus commitment root")?;
        validate_root(&self.pq_authorization_root, "solver pq authorization root")?;
        validate_root(&self.censorship_bond_root, "censorship bond root")?;
        if self.solver_fee_bps > config.max_solver_fee_bps {
            return Err("private orderflow solver fee bps exceeds cap".to_string());
        }
        if self.reveal_deadline_height <= auction_height {
            return Err(
                "private orderflow solver reveal deadline must be after auction height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAuctionRequest {
    pub auctioneer_id: String,
    pub intent_ids: Vec<String>,
    pub solver_commitments: Vec<SolverCommitmentRequest>,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub decryption_share_root: String,
    pub fairness_witness_root: String,
    pub anti_censorship_root: String,
    pub bundle_ciphertext_root: String,
    pub route_witness_root: String,
    pub auction_proof_root: String,
    pub low_fee_rebate_pool_root: String,
}

impl RunAuctionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
        if self.auctioneer_id.trim().is_empty() {
            return Err("private orderflow auctioneer id must not be empty".to_string());
        }
        if self.intent_ids.is_empty() {
            return Err("private orderflow auction requires at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_auction {
            return Err("private orderflow auction exceeds max intents".to_string());
        }
        let unique = self.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.intent_ids.len() {
            return Err("private orderflow auction cannot include duplicate intents".to_string());
        }
        if self.solver_commitments.is_empty() {
            return Err("private orderflow auction requires solver commitments".to_string());
        }
        if self.solver_commitments.len() > config.max_solver_commitments {
            return Err("private orderflow auction exceeds max solver commitments".to_string());
        }
        if self.sealed_at_height <= self.opened_at_height {
            return Err(
                "private orderflow auction seal height must be after open height".to_string(),
            );
        }
        if self.sealed_at_height
            > self
                .opened_at_height
                .saturating_add(config.auction_window_blocks)
        {
            return Err("private orderflow auction window exceeds configured limit".to_string());
        }
        validate_root(&self.decryption_share_root, "decryption share root")?;
        validate_root(&self.fairness_witness_root, "fairness witness root")?;
        validate_root(&self.anti_censorship_root, "auction anti-censorship root")?;
        validate_root(&self.bundle_ciphertext_root, "bundle ciphertext root")?;
        validate_root(&self.route_witness_root, "route witness root")?;
        validate_root(&self.auction_proof_root, "auction proof root")?;
        validate_root(&self.low_fee_rebate_pool_root, "low fee rebate pool root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleAuctionRequest {
    pub auction_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub aggregate_pq_authorization_root: String,
    pub executed_route_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub rebate_distribution_root: String,
    pub solver_payment_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettleAuctionRequest {
    pub fn validate(&self) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
        validate_root(&self.auction_id, "auction id")?;
        validate_root(&self.settlement_tx_root, "settlement tx root")?;
        validate_root(&self.settlement_proof_root, "settlement proof root")?;
        validate_root(&self.settlement_witness_root, "settlement witness root")?;
        validate_root(
            &self.aggregate_pq_authorization_root,
            "aggregate pq authorization root",
        )?;
        validate_root(&self.executed_route_root, "executed route root")?;
        validate_root(&self.spent_nullifier_root, "spent nullifier root")?;
        validate_root(&self.output_commitment_root, "output commitment root")?;
        validate_root(&self.rebate_distribution_root, "rebate distribution root")?;
        validate_root(&self.solver_payment_root, "solver payment root")?;
        validate_root(&self.state_transition_root, "state transition root")?;
        validate_root(&self.runtime_state_root_after, "runtime state root after")?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err(
                    "private orderflow finality height cannot precede settlement".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPrivateIntent {
    pub intent_id: String,
    pub intent_nonce: u64,
    pub status: IntentStatus,
    pub intent_kind: IntentKind,
    pub execution_domain: ExecutionDomain,
    pub account_commitment: String,
    pub source_asset_commitment: String,
    pub target_asset_commitment: String,
    pub sealed_intent_root: String,
    pub encrypted_payload_root: String,
    pub encrypted_orderflow_root: String,
    pub nullifier_root: String,
    pub refund_commitment: String,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub estimated_value_micro_units: u64,
    pub estimated_weight: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_authorization_root: String,
    pub anti_censorship_commitment_root: String,
    pub inclusion_list_root: String,
    pub low_fee_rebate_commitment: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub relay_hint: Option<String>,
    pub bundle_id: Option<String>,
    pub auction_id: Option<String>,
}

impl SealedPrivateIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "intent_nonce": self.intent_nonce,
            "status": self.status.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "execution_domain": self.execution_domain.as_str(),
            "account_commitment": self.account_commitment,
            "source_asset_commitment": self.source_asset_commitment,
            "target_asset_commitment": self.target_asset_commitment,
            "sealed_intent_root": self.sealed_intent_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "nullifier_root": self.nullifier_root,
            "refund_commitment": self.refund_commitment,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_surplus_rebate_bps": self.min_surplus_rebate_bps,
            "estimated_value_micro_units": self.estimated_value_micro_units,
            "estimated_weight": self.estimated_weight,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "pq_authorization_root": self.pq_authorization_root,
            "anti_censorship_commitment_root": self.anti_censorship_commitment_root,
            "inclusion_list_root": self.inclusion_list_root,
            "low_fee_rebate_commitment": self.low_fee_rebate_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "relay_hint": self.relay_hint,
            "bundle_id": self.bundle_id,
            "auction_id": self.auction_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrderflowBundle {
    pub bundle_id: String,
    pub bundle_nonce: u64,
    pub status: BundleStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub encrypted_orderflow_root: String,
    pub ciphertext_root: String,
    pub decryption_share_root: String,
    pub anti_censorship_root: String,
    pub inclusion_list_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_nullifier_root: String,
    pub low_fee_rebate_pool_root: String,
    pub privacy_set_size: u64,
    pub total_estimated_value_micro_units: u64,
    pub total_estimated_weight: u64,
}

impl EncryptedOrderflowBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "bundle_nonce": self.bundle_nonce,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "intent_ids": self.intent_ids,
            "intent_root": self.intent_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "ciphertext_root": self.ciphertext_root,
            "decryption_share_root": self.decryption_share_root,
            "anti_censorship_root": self.anti_censorship_root,
            "inclusion_list_root": self.inclusion_list_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "low_fee_rebate_pool_root": self.low_fee_rebate_pool_root,
            "privacy_set_size": self.privacy_set_size,
            "total_estimated_value_micro_units": self.total_estimated_value_micro_units,
            "total_estimated_weight": self.total_estimated_weight,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-BUNDLE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub solver_stake_root: String,
    pub route_commitment_root: String,
    pub execution_trace_commitment_root: String,
    pub surplus_commitment_root: String,
    pub pq_authorization_root: String,
    pub censorship_bond_root: String,
    pub bid_fee_micro_units: u64,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub score: u128,
}

impl SolverCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "solver_stake_root": self.solver_stake_root,
            "route_commitment_root": self.route_commitment_root,
            "execution_trace_commitment_root": self.execution_trace_commitment_root,
            "surplus_commitment_root": self.surplus_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "censorship_bond_root": self.censorship_bond_root,
            "bid_fee_micro_units": self.bid_fee_micro_units,
            "expected_surplus_micro_units": self.expected_surplus_micro_units,
            "solver_fee_bps": self.solver_fee_bps,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "score": self.score.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinningRouteStep {
    pub step_id: String,
    pub step_index: u64,
    pub step_kind: RouteStepKind,
    pub execution_domain: ExecutionDomain,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub pool_or_contract_root: String,
    pub execution_proof_root: String,
    pub fee_micro_units: u64,
    pub surplus_micro_units: u64,
}

impl WinningRouteStep {
    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "step_index": self.step_index,
            "step_kind": self.step_kind.as_str(),
            "execution_domain": self.execution_domain.as_str(),
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "pool_or_contract_root": self.pool_or_contract_root,
            "execution_proof_root": self.execution_proof_root,
            "fee_micro_units": self.fee_micro_units,
            "surplus_micro_units": self.surplus_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinningRoute {
    pub route_id: String,
    pub route_nonce: u64,
    pub auction_id: String,
    pub winning_solver_id: String,
    pub winning_commitment_id: String,
    pub route_commitment_root: String,
    pub route_step_root: String,
    pub execution_trace_root: String,
    pub fairness_witness_root: String,
    pub route_witness_root: String,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_micro_units: u64,
    pub user_rebate_micro_units: u64,
    pub protocol_fee_micro_units: u64,
    pub step_ids: Vec<String>,
}

impl WinningRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "route_nonce": self.route_nonce,
            "auction_id": self.auction_id,
            "winning_solver_id": self.winning_solver_id,
            "winning_commitment_id": self.winning_commitment_id,
            "route_commitment_root": self.route_commitment_root,
            "route_step_root": self.route_step_root,
            "execution_trace_root": self.execution_trace_root,
            "fairness_witness_root": self.fairness_witness_root,
            "route_witness_root": self.route_witness_root,
            "expected_surplus_micro_units": self.expected_surplus_micro_units,
            "solver_fee_micro_units": self.solver_fee_micro_units,
            "user_rebate_micro_units": self.user_rebate_micro_units,
            "protocol_fee_micro_units": self.protocol_fee_micro_units,
            "step_ids": self.step_ids,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-WINNING-ROUTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuction {
    pub auction_id: String,
    pub auction_nonce: u64,
    pub status: AuctionStatus,
    pub auctioneer_id: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
    pub bundle_id: String,
    pub bundle_root: String,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub solver_commitment_root: String,
    pub winning_commitment_id: String,
    pub winning_solver_id: String,
    pub winning_route_id: String,
    pub winning_route_root: String,
    pub decryption_share_root: String,
    pub fairness_witness_root: String,
    pub anti_censorship_root: String,
    pub auction_proof_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_nullifier_root: String,
    pub low_fee_rebate_pool_root: String,
    pub total_estimated_value_micro_units: u64,
    pub total_estimated_weight: u64,
    pub user_rebate_micro_units: u64,
    pub solver_fee_micro_units: u64,
    pub protocol_fee_micro_units: u64,
}

impl BatchAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "auction_nonce": self.auction_nonce,
            "status": self.status.as_str(),
            "auctioneer_id": self.auctioneer_id,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "bundle_id": self.bundle_id,
            "bundle_root": self.bundle_root,
            "intent_ids": self.intent_ids,
            "intent_root": self.intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "winning_commitment_id": self.winning_commitment_id,
            "winning_solver_id": self.winning_solver_id,
            "winning_route_id": self.winning_route_id,
            "winning_route_root": self.winning_route_root,
            "decryption_share_root": self.decryption_share_root,
            "fairness_witness_root": self.fairness_witness_root,
            "anti_censorship_root": self.anti_censorship_root,
            "auction_proof_root": self.auction_proof_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "low_fee_rebate_pool_root": self.low_fee_rebate_pool_root,
            "total_estimated_value_micro_units": self.total_estimated_value_micro_units,
            "total_estimated_weight": self.total_estimated_weight,
            "user_rebate_micro_units": self.user_rebate_micro_units,
            "solver_fee_micro_units": self.solver_fee_micro_units,
            "protocol_fee_micro_units": self.protocol_fee_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub status: ReceiptStatus,
    pub auction_root: String,
    pub winning_route_root: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub aggregate_pq_authorization_root: String,
    pub executed_route_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub rebate_distribution_root: String,
    pub solver_payment_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_before: String,
    pub runtime_state_root_after: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "auction_root": self.auction_root,
            "winning_route_root": self.winning_route_root,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "settlement_witness_root": self.settlement_witness_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "executed_route_root": self.executed_route_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "solver_payment_root": self.solver_payment_root,
            "state_transition_root": self.state_transition_root,
            "runtime_state_root_before": self.runtime_state_root_before,
            "runtime_state_root_after": self.runtime_state_root_after,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub rebate_budget_remaining_micro_units: u64,
    pub sealed_intents: BTreeMap<String, SealedPrivateIntent>,
    pub pending_queue: BTreeSet<String>,
    pub encrypted_bundles: BTreeMap<String, EncryptedOrderflowBundle>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub route_steps: BTreeMap<String, WinningRouteStep>,
    pub winning_routes: BTreeMap<String, WinningRoute>,
    pub auctions: BTreeMap<String, BatchAuction>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub anti_censorship_commitments: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let runtime_root = domain_hash(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-DEVNET-RUNTIME",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEVNET_RUNTIME),
            ],
            32,
        );
        Self {
            rebate_budget_remaining_micro_units: config.rebate_budget_micro_units,
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_DEVNET_HEIGHT,
            runtime_root,
            sealed_intents: BTreeMap::new(),
            pending_queue: BTreeSet::new(),
            encrypted_bundles: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            route_steps: BTreeMap::new(),
            winning_routes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            anti_censorship_commitments: BTreeSet::new(),
        }
    }

    pub fn submit_orderflow(
        &mut self,
        request: SubmitOrderflowRequest,
    ) -> PrivateL2MevResistantOrderflowAuctionResult<SealedPrivateIntent> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.current_height = self.current_height.max(request.submitted_at_height);
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
            || self
                .sealed_intents
                .values()
                .any(|intent| intent.nullifier_root == request.nullifier_root)
        {
            self.counters.intents_rejected += 1;
            return Err("private orderflow nullifier root already pending or consumed".to_string());
        }
        if self
            .anti_censorship_commitments
            .contains(&request.anti_censorship_commitment_root)
        {
            self.counters.intents_rejected += 1;
            return Err(
                "private orderflow anti-censorship commitment already observed".to_string(),
            );
        }

        let intent_nonce = self.counters.next_intent_nonce;
        let execution_domain = request
            .execution_domain
            .unwrap_or_else(|| request.intent_kind.default_domain());
        let intent_id = private_intent_id(
            intent_nonce,
            &request.account_commitment,
            &request.sealed_intent_root,
            &request.nullifier_root,
        );
        if self.sealed_intents.contains_key(&intent_id) {
            self.counters.intents_rejected += 1;
            return Err(format!("duplicate private orderflow intent {intent_id}"));
        }

        let status = if request.privacy_set_size >= self.config.min_privacy_set {
            IntentStatus::Admitted
        } else {
            IntentStatus::Deferred
        };
        let intent = SealedPrivateIntent {
            intent_id: intent_id.clone(),
            intent_nonce,
            status,
            intent_kind: request.intent_kind,
            execution_domain,
            account_commitment: request.account_commitment,
            source_asset_commitment: request.source_asset_commitment,
            target_asset_commitment: request.target_asset_commitment,
            sealed_intent_root: request.sealed_intent_root,
            encrypted_payload_root: request.encrypted_payload_root,
            encrypted_orderflow_root: request.encrypted_orderflow_root,
            nullifier_root: request.nullifier_root,
            refund_commitment: request.refund_commitment,
            max_user_fee_bps: request.max_user_fee_bps,
            max_solver_fee_bps: request.max_solver_fee_bps,
            min_surplus_rebate_bps: request.min_surplus_rebate_bps,
            estimated_value_micro_units: request.estimated_value_micro_units,
            estimated_weight: request.estimated_weight,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            pq_authorization_root: request.pq_authorization_root,
            anti_censorship_commitment_root: request.anti_censorship_commitment_root,
            inclusion_list_root: request.inclusion_list_root,
            low_fee_rebate_commitment: request.low_fee_rebate_commitment,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            relay_hint: request.relay_hint,
            bundle_id: None,
            auction_id: None,
        };

        self.counters.next_intent_nonce += 1;
        self.counters.intents_submitted += 1;
        if intent.status == IntentStatus::Admitted {
            self.pending_queue.insert(intent_id.clone());
            self.counters.intents_admitted += 1;
        } else {
            self.counters.intents_deferred += 1;
        }
        self.anti_censorship_commitments
            .insert(intent.anti_censorship_commitment_root.clone());
        self.sealed_intents.insert(intent_id, intent.clone());
        Ok(intent)
    }

    pub fn run_auction(
        &mut self,
        request: RunAuctionRequest,
    ) -> PrivateL2MevResistantOrderflowAuctionResult<BatchAuction> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.current_height = self.current_height.max(request.sealed_at_height);

        let mut selected = Vec::with_capacity(request.intent_ids.len());
        for intent_id in &request.intent_ids {
            let intent = self
                .sealed_intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| format!("unknown private orderflow intent id {intent_id}"))?;
            if !intent.status.live() {
                return Err(format!("private orderflow intent {intent_id} is not live"));
            }
            if intent.expires_at_height < request.sealed_at_height {
                return Err(format!(
                    "private orderflow intent {intent_id} expired before auction sealing"
                ));
            }
            selected.push(intent);
        }

        let auction_nonce = self.counters.next_auction_nonce;
        let bundle_nonce = self.counters.next_bundle_nonce;
        let auction_id =
            batch_auction_id(auction_nonce, &request.intent_ids, request.sealed_at_height);
        let intent_records = selected
            .iter()
            .map(SealedPrivateIntent::public_record)
            .collect::<Vec<_>>();
        let intent_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-INTENT",
            &intent_records,
        );
        let pq_auth_records = selected
            .iter()
            .map(|intent| json!(intent.pq_authorization_root))
            .collect::<Vec<_>>();
        let aggregate_pq_authorization_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-PQ-AUTH",
            &pq_auth_records,
        );
        let nullifier_records = selected
            .iter()
            .map(|intent| json!(intent.nullifier_root))
            .collect::<Vec<_>>();
        let aggregate_nullifier_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-NULLIFIER",
            &nullifier_records,
        );
        let encrypted_orderflow_records = selected
            .iter()
            .map(|intent| json!(intent.encrypted_orderflow_root))
            .collect::<Vec<_>>();
        let encrypted_orderflow_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ENCRYPTED-ORDERFLOW",
            &encrypted_orderflow_records,
        );
        let inclusion_records = selected
            .iter()
            .map(|intent| json!(intent.inclusion_list_root))
            .collect::<Vec<_>>();
        let inclusion_list_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-INCLUSION-LIST",
            &inclusion_records,
        );
        let privacy_set_size = selected
            .iter()
            .map(|intent| intent.privacy_set_size)
            .min()
            .unwrap_or_default();
        let total_estimated_value_micro_units = selected
            .iter()
            .map(|intent| intent.estimated_value_micro_units)
            .sum::<u64>();
        let total_estimated_weight = selected
            .iter()
            .map(|intent| intent.estimated_weight)
            .sum::<u64>();

        let bundle_id = encrypted_orderflow_bundle_id(bundle_nonce, &intent_root, &auction_id);
        let bundle = EncryptedOrderflowBundle {
            bundle_id: bundle_id.clone(),
            bundle_nonce,
            status: BundleStatus::Auctioned,
            opened_at_height: request.opened_at_height,
            sealed_at_height: request.sealed_at_height,
            intent_ids: request.intent_ids.clone(),
            intent_root: intent_root.clone(),
            encrypted_orderflow_root,
            ciphertext_root: request.bundle_ciphertext_root.clone(),
            decryption_share_root: request.decryption_share_root.clone(),
            anti_censorship_root: request.anti_censorship_root.clone(),
            inclusion_list_root,
            aggregate_pq_authorization_root: aggregate_pq_authorization_root.clone(),
            aggregate_nullifier_root: aggregate_nullifier_root.clone(),
            low_fee_rebate_pool_root: request.low_fee_rebate_pool_root.clone(),
            privacy_set_size,
            total_estimated_value_micro_units,
            total_estimated_weight,
        };
        let bundle_root = bundle.state_root();

        let mut solver_commitments = Vec::with_capacity(request.solver_commitments.len());
        let mut solver_ids = BTreeSet::new();
        for solver_request in &request.solver_commitments {
            solver_request.validate(&self.config, request.sealed_at_height)?;
            if !solver_ids.insert(solver_request.solver_id.clone()) {
                return Err(
                    "private orderflow auction cannot include duplicate solver ids".to_string(),
                );
            }
            let score = solver_score(solver_request);
            let commitment_id = solver_commitment_id(
                &auction_id,
                &solver_request.solver_id,
                &solver_request.route_commitment_root,
                score,
            );
            solver_commitments.push(SolverCommitment {
                commitment_id,
                auction_id: auction_id.clone(),
                solver_id: solver_request.solver_id.clone(),
                solver_stake_root: solver_request.solver_stake_root.clone(),
                route_commitment_root: solver_request.route_commitment_root.clone(),
                execution_trace_commitment_root: solver_request
                    .execution_trace_commitment_root
                    .clone(),
                surplus_commitment_root: solver_request.surplus_commitment_root.clone(),
                pq_authorization_root: solver_request.pq_authorization_root.clone(),
                censorship_bond_root: solver_request.censorship_bond_root.clone(),
                bid_fee_micro_units: solver_request.bid_fee_micro_units,
                expected_surplus_micro_units: solver_request.expected_surplus_micro_units,
                solver_fee_bps: solver_request.solver_fee_bps,
                committed_at_height: request.sealed_at_height,
                reveal_deadline_height: solver_request.reveal_deadline_height,
                score,
            });
        }
        solver_commitments.sort_by_key(|commitment| {
            (
                u128::MAX.saturating_sub(commitment.score),
                commitment.bid_fee_micro_units,
                commitment.solver_fee_bps,
                commitment.solver_id.clone(),
            )
        });
        let winning_commitment = solver_commitments.first().cloned().ok_or_else(|| {
            "private orderflow auction has no valid solver commitments".to_string()
        })?;
        let solver_commitment_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-SOLVER-COMMITMENT",
            &solver_commitments
                .iter()
                .map(SolverCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let route_nonce = self.counters.next_route_nonce;
        let route_steps = derive_route_steps(
            &auction_id,
            &winning_commitment,
            &selected,
            &request.auction_proof_root,
            route_nonce,
            self.config.max_route_steps,
        )?;
        let route_step_root = merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ROUTE-STEP",
            &route_steps
                .iter()
                .map(WinningRouteStep::public_record)
                .collect::<Vec<_>>(),
        );
        let step_ids = route_steps
            .iter()
            .map(|step| step.step_id.clone())
            .collect::<Vec<_>>();
        let solver_fee_micro_units = winning_commitment
            .expected_surplus_micro_units
            .saturating_mul(winning_commitment.solver_fee_bps)
            / PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS;
        let desired_rebate = winning_commitment
            .expected_surplus_micro_units
            .saturating_mul(self.config.min_surplus_rebate_bps)
            / PRIVATE_L2_MEV_RESISTANT_ORDERFLOW_AUCTION_MAX_BPS;
        let user_rebate_micro_units = if self.config.enable_low_fee_rebates {
            desired_rebate.min(self.rebate_budget_remaining_micro_units)
        } else {
            0
        };
        let protocol_fee_micro_units = winning_commitment
            .expected_surplus_micro_units
            .saturating_sub(solver_fee_micro_units)
            .saturating_sub(user_rebate_micro_units);
        let route_id = winning_route_id(
            route_nonce,
            &auction_id,
            &winning_commitment.commitment_id,
            &route_step_root,
        );
        let winning_route = WinningRoute {
            route_id: route_id.clone(),
            route_nonce,
            auction_id: auction_id.clone(),
            winning_solver_id: winning_commitment.solver_id.clone(),
            winning_commitment_id: winning_commitment.commitment_id.clone(),
            route_commitment_root: winning_commitment.route_commitment_root.clone(),
            route_step_root,
            execution_trace_root: winning_commitment.execution_trace_commitment_root.clone(),
            fairness_witness_root: request.fairness_witness_root.clone(),
            route_witness_root: request.route_witness_root.clone(),
            expected_surplus_micro_units: winning_commitment.expected_surplus_micro_units,
            solver_fee_micro_units,
            user_rebate_micro_units,
            protocol_fee_micro_units,
            step_ids,
        };
        let winning_route_root = winning_route.state_root();

        let auction = BatchAuction {
            auction_id: auction_id.clone(),
            auction_nonce,
            status: AuctionStatus::SettlementReady,
            auctioneer_id: request.auctioneer_id,
            opened_at_height: request.opened_at_height,
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request
                .sealed_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            bundle_id: bundle_id.clone(),
            bundle_root,
            intent_ids: request.intent_ids.clone(),
            intent_root,
            solver_commitment_root,
            winning_commitment_id: winning_commitment.commitment_id.clone(),
            winning_solver_id: winning_commitment.solver_id.clone(),
            winning_route_id: route_id.clone(),
            winning_route_root,
            decryption_share_root: request.decryption_share_root,
            fairness_witness_root: request.fairness_witness_root,
            anti_censorship_root: request.anti_censorship_root,
            auction_proof_root: request.auction_proof_root,
            aggregate_pq_authorization_root,
            aggregate_nullifier_root,
            low_fee_rebate_pool_root: request.low_fee_rebate_pool_root,
            total_estimated_value_micro_units,
            total_estimated_weight,
            user_rebate_micro_units,
            solver_fee_micro_units,
            protocol_fee_micro_units,
        };

        for intent_id in &auction.intent_ids {
            self.pending_queue.remove(intent_id);
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Auctioned;
                intent.bundle_id = Some(bundle_id.clone());
                intent.auction_id = Some(auction_id.clone());
            }
        }
        for commitment in solver_commitments {
            self.solver_commitments
                .insert(commitment.commitment_id.clone(), commitment);
        }
        for step in route_steps {
            self.route_steps.insert(step.step_id.clone(), step);
        }
        self.rebate_budget_remaining_micro_units = self
            .rebate_budget_remaining_micro_units
            .saturating_sub(user_rebate_micro_units);
        self.encrypted_bundles.insert(bundle_id, bundle);
        self.winning_routes.insert(route_id, winning_route);
        self.auctions.insert(auction_id, auction.clone());
        self.counters.next_auction_nonce += 1;
        self.counters.next_bundle_nonce += 1;
        self.counters.next_route_nonce += 1;
        self.counters.bundles_encrypted += 1;
        self.counters.auctions_run += 1;
        self.counters.intents_auctioned += auction.intent_ids.len() as u64;
        self.counters.solver_commitments_recorded += request.solver_commitments.len() as u64;
        self.counters.low_fee_rebates_micro_units = self
            .counters
            .low_fee_rebates_micro_units
            .saturating_add(user_rebate_micro_units);
        self.counters.solver_fees_micro_units = self
            .counters
            .solver_fees_micro_units
            .saturating_add(solver_fee_micro_units);
        self.counters.surplus_returned_micro_units = self
            .counters
            .surplus_returned_micro_units
            .saturating_add(user_rebate_micro_units);
        self.counters.censorship_bonds_locked_micro_units = self
            .counters
            .censorship_bonds_locked_micro_units
            .saturating_add(
                self.config
                    .censorship_bond_micro_units
                    .saturating_mul(request.solver_commitments.len() as u64),
            );
        Ok(auction)
    }

    pub fn settle_auction(
        &mut self,
        request: SettleAuctionRequest,
    ) -> PrivateL2MevResistantOrderflowAuctionResult<SettlementReceipt> {
        self.config.validate()?;
        request.validate()?;
        let state_root_before = self.state_root();
        let runtime_state_root_before = self.runtime_root.clone();
        let auction = self
            .auctions
            .get(&request.auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown private orderflow auction {}", request.auction_id))?;
        if !auction.status.can_settle() {
            return Err("private orderflow auction is not settlement ready".to_string());
        }
        if request.settled_at_height > auction.settlement_deadline_height {
            return Err("private orderflow auction settlement deadline elapsed".to_string());
        }
        if request.aggregate_pq_authorization_root != auction.aggregate_pq_authorization_root {
            return Err("private orderflow auction pq authorization root mismatch".to_string());
        }
        if request.executed_route_root != auction.winning_route_root {
            return Err("private orderflow auction executed route root mismatch".to_string());
        }
        if request.spent_nullifier_root != auction.aggregate_nullifier_root {
            return Err("private orderflow auction nullifier root mismatch".to_string());
        }

        for intent_id in &auction.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                self.consumed_nullifier_roots
                    .insert(intent.nullifier_root.clone());
            }
        }
        if let Some(bundle) = self.encrypted_bundles.get_mut(&auction.bundle_id) {
            bundle.status = BundleStatus::Settled;
        }
        if let Some(stored_auction) = self.auctions.get_mut(&request.auction_id) {
            stored_auction.status = AuctionStatus::Settled;
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.auctions_settled += 1;
        self.counters.intents_settled += auction.intent_ids.len() as u64;
        self.counters.receipts_published += 1;
        let state_root_after = self.state_root();
        let receipt_id = settlement_receipt_id(
            &request.auction_id,
            &request.settlement_tx_root,
            &request.settlement_proof_root,
            request.settled_at_height,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            auction_id: request.auction_id,
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            auction_root: auction.state_root(),
            winning_route_root: auction.winning_route_root,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            settlement_witness_root: request.settlement_witness_root,
            aggregate_pq_authorization_root: request.aggregate_pq_authorization_root,
            executed_route_root: request.executed_route_root,
            spent_nullifier_root: request.spent_nullifier_root,
            output_commitment_root: request.output_commitment_root,
            rebate_distribution_root: request.rebate_distribution_root,
            solver_payment_root: request.solver_payment_root,
            state_transition_root: request.state_transition_root,
            runtime_state_root_before,
            runtime_state_root_after: request.runtime_state_root_after,
            state_root_before,
            state_root_after,
            settled_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "rebate_budget_remaining_micro_units": self.rebate_budget_remaining_micro_units,
            "sealed_intent_root": self.sealed_intent_root(),
            "pending_queue_root": self.pending_queue_root(),
            "encrypted_bundle_root": self.encrypted_bundle_root(),
            "solver_commitment_root": self.solver_commitment_root(),
            "route_step_root": self.route_step_root(),
            "winning_route_root": self.winning_route_root(),
            "auction_root": self.auction_root(),
            "receipt_root": self.receipt_root(),
            "consumed_nullifier_root": self.consumed_nullifier_root(),
            "anti_censorship_commitment_root": self.anti_censorship_commitment_root(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Int(self.current_height as i128),
                HashPart::Str(&self.runtime_root),
                HashPart::Int(self.rebate_budget_remaining_micro_units as i128),
                HashPart::Str(&self.sealed_intent_root()),
                HashPart::Str(&self.pending_queue_root()),
                HashPart::Str(&self.encrypted_bundle_root()),
                HashPart::Str(&self.solver_commitment_root()),
                HashPart::Str(&self.route_step_root()),
                HashPart::Str(&self.winning_route_root()),
                HashPart::Str(&self.auction_root()),
                HashPart::Str(&self.receipt_root()),
                HashPart::Str(&self.consumed_nullifier_root()),
                HashPart::Str(&self.anti_censorship_commitment_root()),
            ],
            32,
        )
    }

    pub fn sealed_intent_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-SEALED-INTENT",
            &self
                .sealed_intents
                .values()
                .map(SealedPrivateIntent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pending_queue_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-PENDING-QUEUE",
            &self
                .pending_queue
                .iter()
                .map(|id| json!(id))
                .collect::<Vec<_>>(),
        )
    }

    pub fn encrypted_bundle_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-BUNDLE",
            &self
                .encrypted_bundles
                .values()
                .map(EncryptedOrderflowBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn solver_commitment_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-SOLVER-COMMITMENT",
            &self
                .solver_commitments
                .values()
                .map(SolverCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn route_step_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-ROUTE-STEP",
            &self
                .route_steps
                .values()
                .map(WinningRouteStep::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn winning_route_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-WINNING-ROUTE",
            &self
                .winning_routes
                .values()
                .map(WinningRoute::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-AUCTION",
            &self
                .auctions
                .values()
                .map(BatchAuction::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-RECEIPT",
            &self
                .receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-CONSUMED-NULLIFIER",
            &self
                .consumed_nullifier_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn anti_censorship_commitment_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE-ANTI-CENSORSHIP",
            &self
                .anti_censorship_commitments
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }
}

fn derive_route_steps(
    auction_id: &str,
    winning_commitment: &SolverCommitment,
    intents: &[SealedPrivateIntent],
    proof_root: &str,
    route_nonce: u64,
    max_route_steps: usize,
) -> PrivateL2MevResistantOrderflowAuctionResult<Vec<WinningRouteStep>> {
    if intents.len() > max_route_steps {
        return Err("private orderflow route exceeds max route steps".to_string());
    }
    let mut steps = Vec::with_capacity(intents.len());
    for (index, intent) in intents.iter().enumerate() {
        let step_kind = match intent.intent_kind {
            IntentKind::PrivateDefiSwap => RouteStepKind::PoolSwap,
            IntentKind::ConfidentialTokenTransfer | IntentKind::ConfidentialTokenMint => {
                RouteStepKind::PrivateTokenTransfer
            }
            IntentKind::ConfidentialContractCall | IntentKind::ConfidentialContractBatch => {
                RouteStepKind::ContractInvoke
            }
            IntentKind::LiquidityProvision => RouteStepKind::LiquidityAdd,
            IntentKind::PrivateBridgeExit => RouteStepKind::BridgeExit,
            IntentKind::PrivateMoneroExit => RouteStepKind::MoneroExit,
        };
        let surplus_share = winning_commitment
            .expected_surplus_micro_units
            .saturating_mul(intent.estimated_value_micro_units)
            / intents
                .iter()
                .map(|candidate| candidate.estimated_value_micro_units)
                .sum::<u64>()
                .max(1);
        let fee_micro_units = winning_commitment
            .bid_fee_micro_units
            .saturating_mul(intent.estimated_weight)
            / intents
                .iter()
                .map(|candidate| candidate.estimated_weight)
                .sum::<u64>()
                .max(1);
        let step_id = route_step_id(
            auction_id,
            &intent.intent_id,
            route_nonce,
            index as u64,
            step_kind,
        );
        steps.push(WinningRouteStep {
            step_id,
            step_index: index as u64,
            step_kind,
            execution_domain: intent.execution_domain,
            input_commitment_root: intent.source_asset_commitment.clone(),
            output_commitment_root: intent.target_asset_commitment.clone(),
            pool_or_contract_root: intent.encrypted_payload_root.clone(),
            execution_proof_root: payload_root(
                "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ROUTE-STEP-PROOF",
                &json!({
                    "auction_id": auction_id,
                    "intent_id": intent.intent_id,
                    "route_commitment_root": winning_commitment.route_commitment_root,
                    "proof_root": proof_root,
                    "step_index": index,
                }),
            ),
            fee_micro_units,
            surplus_micro_units: surplus_share,
        });
    }
    Ok(steps)
}

fn solver_score(request: &SolverCommitmentRequest) -> u128 {
    let surplus = request.expected_surplus_micro_units as u128;
    let bid_penalty = request.bid_fee_micro_units as u128;
    let fee_penalty = request.solver_fee_bps as u128 * 1_000;
    surplus
        .saturating_mul(1_000_000)
        .saturating_sub(bid_penalty)
        .saturating_sub(fee_penalty)
}

fn private_intent_id(
    intent_nonce: u64,
    account_commitment: &str,
    sealed_intent_root: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(intent_nonce as i128),
            HashPart::Str(account_commitment),
            HashPart::Str(sealed_intent_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

fn encrypted_orderflow_bundle_id(bundle_nonce: u64, intent_root: &str, auction_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(bundle_nonce as i128),
            HashPart::Str(intent_root),
            HashPart::Str(auction_id),
        ],
        32,
    )
}

fn batch_auction_id(auction_nonce: u64, intent_ids: &[String], sealed_at_height: u64) -> String {
    let intent_root = merkle_root(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ID-INTENT",
        &intent_ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(auction_nonce as i128),
            HashPart::Str(&intent_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}

fn solver_commitment_id(
    auction_id: &str,
    solver_id: &str,
    route_commitment_root: &str,
    score: u128,
) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(route_commitment_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

fn winning_route_id(
    route_nonce: u64,
    auction_id: &str,
    winning_commitment_id: &str,
    route_step_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-WINNING-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(route_nonce as i128),
            HashPart::Str(auction_id),
            HashPart::Str(winning_commitment_id),
            HashPart::Str(route_step_root),
        ],
        32,
    )
}

fn route_step_id(
    auction_id: &str,
    intent_id: &str,
    route_nonce: u64,
    step_index: u64,
    step_kind: RouteStepKind,
) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-ROUTE-STEP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(intent_id),
            HashPart::Int(route_nonce as i128),
            HashPart::Int(step_index as i128),
            HashPart::Str(step_kind.as_str()),
        ],
        32,
    )
}

fn settlement_receipt_id(
    auction_id: &str,
    settlement_tx_root: &str,
    settlement_proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(settlement_proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn private_l2_mev_resistant_orderflow_auction_payload_root(
    domain: &str,
    record: &Value,
) -> String {
    payload_root(domain, record)
}

pub fn private_l2_mev_resistant_orderflow_auction_state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-MEV-RESISTANT-ORDERFLOW-AUCTION-STATE", record)
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn validate_root(value: &str, label: &str) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> PrivateL2MevResistantOrderflowAuctionResult<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
