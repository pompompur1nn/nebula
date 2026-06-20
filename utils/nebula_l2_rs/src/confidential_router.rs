use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialRouterResult<T> = Result<T, String>;

pub const CONFIDENTIAL_ROUTER_PROTOCOL_VERSION: u64 = 1;
pub const CONFIDENTIAL_ROUTER_ENCRYPTION_SCHEME: &str =
    "nebula-confidential-route-intent-devnet-v1";
pub const CONFIDENTIAL_ROUTER_RFQ_SCHEME: &str = "nebula-private-rfq-devnet-v1";
pub const CONFIDENTIAL_ROUTER_COMMITMENT_SCHEME: &str = "nebula-shake256-commitment-devnet-v1";
pub const CONFIDENTIAL_ROUTER_ORDERING_POLICY: &str = "commit-reveal-batch-auction-anti-mev-v1";
pub const CONFIDENTIAL_ROUTER_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const CONFIDENTIAL_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 2;
pub const CONFIDENTIAL_ROUTER_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 6;
pub const CONFIDENTIAL_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const CONFIDENTIAL_ROUTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const CONFIDENTIAL_ROUTER_DEFAULT_PRIVACY_EPOCH_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_ROUTER_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 350_000;
pub const CONFIDENTIAL_ROUTER_DEFAULT_LOW_FEE_LANE: &str = "confidential_swap";
pub const CONFIDENTIAL_ROUTER_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_ROUTER_DEFAULT_MARKET_LABEL: &str = "devnet-confidential-router";
pub const CONFIDENTIAL_ROUTER_DEVNET_HEIGHT: u64 = 64;
pub const CONFIDENTIAL_ROUTER_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_ROUTER_MAX_ROUTE_LEGS: usize = 32;
pub const CONFIDENTIAL_ROUTER_MAX_BATCH_INTENTS: usize = 512;
pub const CONFIDENTIAL_ROUTER_MIN_SOLVER_BOND_UNITS: u64 = 1_000;

pub const CONFIDENTIAL_ROUTER_STATUS_ACTIVE: &str = "active";
pub const CONFIDENTIAL_ROUTER_STATUS_OPEN: &str = "open";
pub const CONFIDENTIAL_ROUTER_STATUS_COLLECTING: &str = "collecting";
pub const CONFIDENTIAL_ROUTER_STATUS_REVEALING: &str = "revealing";
pub const CONFIDENTIAL_ROUTER_STATUS_RESERVED: &str = "reserved";
pub const CONFIDENTIAL_ROUTER_STATUS_ACCEPTED: &str = "accepted";
pub const CONFIDENTIAL_ROUTER_STATUS_SETTLED: &str = "settled";
pub const CONFIDENTIAL_ROUTER_STATUS_RELEASED: &str = "released";
pub const CONFIDENTIAL_ROUTER_STATUS_EXPIRED: &str = "expired";
pub const CONFIDENTIAL_ROUTER_STATUS_REJECTED: &str = "rejected";
pub const CONFIDENTIAL_ROUTER_STATUS_PAUSED: &str = "paused";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentKind {
    ExactInputSwap,
    ExactOutputSwap,
    MintThenSwap,
    CollateralizedBorrow,
    RepayWithSwap,
    ChannelRoutedSwap,
    LiquidationProtected,
    Rebalance,
}

impl RouteIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactInputSwap => "exact_input_swap",
            Self::ExactOutputSwap => "exact_output_swap",
            Self::MintThenSwap => "mint_then_swap",
            Self::CollateralizedBorrow => "collateralized_borrow",
            Self::RepayWithSwap => "repay_with_swap",
            Self::ChannelRoutedSwap => "channel_routed_swap",
            Self::LiquidationProtected => "liquidation_protected",
            Self::Rebalance => "rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLegKind {
    AmmSwap,
    RfqFill,
    TokenFactoryMint,
    TokenFactoryBurn,
    TokenFactoryRedeem,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingLiquidation,
    StateChannelOpen,
    StateChannelUpdate,
    StateChannelClose,
    BridgeTransfer,
    FeeSponsor,
    Settlement,
}

impl RouteLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmSwap => "amm_swap",
            Self::RfqFill => "rfq_fill",
            Self::TokenFactoryMint => "token_factory_mint",
            Self::TokenFactoryBurn => "token_factory_burn",
            Self::TokenFactoryRedeem => "token_factory_redeem",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingLiquidation => "lending_liquidation",
            Self::StateChannelOpen => "state_channel_open",
            Self::StateChannelUpdate => "state_channel_update",
            Self::StateChannelClose => "state_channel_close",
            Self::BridgeTransfer => "bridge_transfer",
            Self::FeeSponsor => "fee_sponsor",
            Self::Settlement => "settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingPrivacyClass {
    Shielded,
    Encrypted,
    CommitmentOnly,
    ReceiptOnly,
}

impl RoutingPrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::Encrypted => "encrypted",
            Self::CommitmentOnly => "commitment_only",
            Self::ReceiptOnly => "receipt_only",
        }
    }

    pub fn is_private(self) -> bool {
        matches!(self, Self::Shielded | Self::Encrypted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorshipMode {
    UserPaid,
    Paymaster,
    SolverRebate,
    ProtocolSubsidy,
    ThirdPartySponsor,
}

impl FeeSponsorshipMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPaid => "user_paid",
            Self::Paymaster => "paymaster",
            Self::SolverRebate => "solver_rebate",
            Self::ProtocolSubsidy => "protocol_subsidy",
            Self::ThirdPartySponsor => "third_party_sponsor",
        }
    }

    pub fn requires_sponsor(self) -> bool {
        !matches!(self, Self::UserPaid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouterConfig {
    pub config_id: String,
    pub protocol_version: u64,
    pub encryption_scheme: String,
    pub rfq_scheme: String,
    pub commitment_scheme: String,
    pub ordering_policy: String,
    pub default_auction_window_blocks: u64,
    pub default_reveal_delay_blocks: u64,
    pub default_reveal_window_blocks: u64,
    pub default_settlement_ttl_blocks: u64,
    pub default_intent_ttl_blocks: u64,
    pub default_privacy_epoch_blocks: u64,
    pub default_privacy_budget_units: u64,
    pub max_route_legs: usize,
    pub max_batch_intents: usize,
    pub max_slippage_bps: u64,
    pub min_solver_bond_units: u64,
    pub default_low_fee_lane: String,
    pub default_fee_asset_id: String,
}

impl Default for ConfidentialRouterConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            encryption_scheme: CONFIDENTIAL_ROUTER_ENCRYPTION_SCHEME.to_string(),
            rfq_scheme: CONFIDENTIAL_ROUTER_RFQ_SCHEME.to_string(),
            commitment_scheme: CONFIDENTIAL_ROUTER_COMMITMENT_SCHEME.to_string(),
            ordering_policy: CONFIDENTIAL_ROUTER_ORDERING_POLICY.to_string(),
            default_auction_window_blocks: CONFIDENTIAL_ROUTER_DEFAULT_AUCTION_WINDOW_BLOCKS,
            default_reveal_delay_blocks: CONFIDENTIAL_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS,
            default_reveal_window_blocks: CONFIDENTIAL_ROUTER_DEFAULT_REVEAL_WINDOW_BLOCKS,
            default_settlement_ttl_blocks: CONFIDENTIAL_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            default_intent_ttl_blocks: CONFIDENTIAL_ROUTER_DEFAULT_INTENT_TTL_BLOCKS,
            default_privacy_epoch_blocks: CONFIDENTIAL_ROUTER_DEFAULT_PRIVACY_EPOCH_BLOCKS,
            default_privacy_budget_units: CONFIDENTIAL_ROUTER_DEFAULT_PRIVACY_BUDGET_UNITS,
            max_route_legs: CONFIDENTIAL_ROUTER_MAX_ROUTE_LEGS,
            max_batch_intents: CONFIDENTIAL_ROUTER_MAX_BATCH_INTENTS,
            max_slippage_bps: CONFIDENTIAL_ROUTER_MAX_BPS,
            min_solver_bond_units: CONFIDENTIAL_ROUTER_MIN_SOLVER_BOND_UNITS,
            default_low_fee_lane: CONFIDENTIAL_ROUTER_DEFAULT_LOW_FEE_LANE.to_string(),
            default_fee_asset_id: CONFIDENTIAL_ROUTER_DEFAULT_FEE_ASSET_ID.to_string(),
        };
        config.config_id = confidential_router_config_id(&config.public_record_without_id());
        config
    }
}

impl ConfidentialRouterConfig {
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "confidential_router_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "encryption_scheme": self.encryption_scheme,
            "rfq_scheme": self.rfq_scheme,
            "commitment_scheme": self.commitment_scheme,
            "ordering_policy": self.ordering_policy,
            "default_auction_window_blocks": self.default_auction_window_blocks,
            "default_reveal_delay_blocks": self.default_reveal_delay_blocks,
            "default_reveal_window_blocks": self.default_reveal_window_blocks,
            "default_settlement_ttl_blocks": self.default_settlement_ttl_blocks,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_privacy_epoch_blocks": self.default_privacy_epoch_blocks,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "max_route_legs": self.max_route_legs,
            "max_batch_intents": self.max_batch_intents,
            "max_slippage_bps": self.max_slippage_bps,
            "min_solver_bond_units": self.min_solver_bond_units,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_fee_asset_id": self.default_fee_asset_id,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record
            .as_object_mut()
            .expect("confidential router config record object")
            .insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        record
    }

    pub fn config_root(&self) -> String {
        confidential_router_payload_root("config", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.config_id, "confidential router config id")?;
        ensure_non_empty(
            &self.encryption_scheme,
            "confidential router encryption scheme",
        )?;
        ensure_non_empty(&self.rfq_scheme, "confidential router rfq scheme")?;
        ensure_non_empty(
            &self.commitment_scheme,
            "confidential router commitment scheme",
        )?;
        ensure_non_empty(&self.ordering_policy, "confidential router ordering policy")?;
        ensure_non_empty(
            &self.default_low_fee_lane,
            "confidential router low fee lane",
        )?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "confidential router fee asset id",
        )?;
        if self.default_auction_window_blocks == 0 {
            return Err("confidential router auction window must be positive".to_string());
        }
        if self.default_reveal_window_blocks == 0 {
            return Err("confidential router reveal window must be positive".to_string());
        }
        if self.default_intent_ttl_blocks == 0 {
            return Err("confidential router intent ttl must be positive".to_string());
        }
        if self.default_privacy_epoch_blocks == 0 {
            return Err("confidential router privacy epoch must be positive".to_string());
        }
        if self.default_privacy_budget_units == 0 {
            return Err("confidential router privacy budget must be positive".to_string());
        }
        if self.max_route_legs == 0 {
            return Err("confidential router max route legs must be positive".to_string());
        }
        if self.max_batch_intents == 0 {
            return Err("confidential router max batch intents must be positive".to_string());
        }
        ensure_bps(self.max_slippage_bps, "confidential router max slippage")?;
        let expected_id = confidential_router_config_id(&self.public_record_without_id());
        if self.config_id != expected_id {
            return Err("confidential router config id mismatch".to_string());
        }
        Ok(self.config_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRouteIntent {
    pub intent_id: String,
    pub intent_kind: RouteIntentKind,
    pub owner_commitment: String,
    pub session_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub max_slippage_bps: u64,
    pub route_policy_root: String,
    pub encrypted_payload_root: String,
    pub fee_sponsorship_id: String,
    pub privacy_budget_id: String,
    pub submission_height: u64,
    pub deadline_height: u64,
    pub nonce: u64,
    pub encryption_scheme: String,
    pub status: String,
}

impl EncryptedRouteIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        session_label: &str,
        intent_kind: RouteIntentKind,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        max_slippage_bps: u64,
        route_policy: &Value,
        encrypted_payload: &Value,
        fee_sponsorship_id: impl Into<String>,
        privacy_budget_id: impl Into<String>,
        submission_height: u64,
        deadline_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(owner_label, "route intent owner label")?;
        ensure_non_empty(session_label, "route intent session label")?;
        ensure_non_empty(asset_in_id, "route intent asset in")?;
        ensure_non_empty(asset_out_id, "route intent asset out")?;
        ensure_positive(amount_in, "route intent amount in")?;
        ensure_positive(min_amount_out, "route intent min amount out")?;
        ensure_bps(max_slippage_bps, "route intent max slippage")?;
        if deadline_height <= submission_height {
            return Err("route intent deadline must be after submission".to_string());
        }
        let fee_sponsorship_id = fee_sponsorship_id.into();
        let privacy_budget_id = privacy_budget_id.into();
        ensure_non_empty(&privacy_budget_id, "route intent privacy budget id")?;

        let owner_commitment = confidential_router_account_commitment(owner_label);
        let session_commitment = confidential_router_session_commitment(session_label, nonce);
        let asset_in_commitment = confidential_router_asset_commitment(asset_in_id);
        let asset_out_commitment = confidential_router_asset_commitment(asset_out_id);
        let amount_in_commitment = confidential_router_amount_commitment(
            amount_in,
            &confidential_router_blinding(owner_label, nonce, "amount_in"),
        );
        let min_amount_out_commitment = confidential_router_amount_commitment(
            min_amount_out,
            &confidential_router_blinding(owner_label, nonce, "min_amount_out"),
        );
        let route_policy_root = confidential_router_payload_root("route_policy", route_policy);
        let encrypted_payload_root =
            confidential_router_payload_root("encrypted_route_intent", encrypted_payload);
        let intent_id = confidential_router_intent_id(
            intent_kind,
            &owner_commitment,
            &session_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &min_amount_out_commitment,
            max_slippage_bps,
            &route_policy_root,
            &privacy_budget_id,
            submission_height,
            deadline_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            intent_kind,
            owner_commitment,
            session_commitment,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            min_amount_out_commitment,
            max_slippage_bps,
            route_policy_root,
            encrypted_payload_root,
            fee_sponsorship_id,
            privacy_budget_id,
            submission_height,
            deadline_height,
            nonce,
            encryption_scheme: CONFIDENTIAL_ROUTER_ENCRYPTION_SCHEME.to_string(),
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "confidential_router_encrypted_route_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "session_commitment": self.session_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "max_slippage_bps": self.max_slippage_bps,
            "route_policy_root": self.route_policy_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "fee_sponsorship_id": self.fee_sponsorship_id,
            "privacy_budget_id": self.privacy_budget_id,
            "submission_height": self.submission_height,
            "deadline_height": self.deadline_height,
            "nonce": self.nonce,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": CONFIDENTIAL_ROUTER_COMMITMENT_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("route intent public record object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("route_intent_record", &self.public_record())
    }

    pub fn mark_settled(&mut self) {
        self.status = CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string();
    }

    pub fn mark_expired(&mut self) {
        self.status = CONFIDENTIAL_ROUTER_STATUS_EXPIRED.to_string();
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.intent_id, "route intent id")?;
        ensure_non_empty(&self.owner_commitment, "route intent owner commitment")?;
        ensure_non_empty(&self.session_commitment, "route intent session commitment")?;
        ensure_non_empty(
            &self.asset_in_commitment,
            "route intent asset in commitment",
        )?;
        ensure_non_empty(
            &self.asset_out_commitment,
            "route intent asset out commitment",
        )?;
        ensure_non_empty(&self.amount_in_commitment, "route intent amount commitment")?;
        ensure_non_empty(
            &self.min_amount_out_commitment,
            "route intent min amount commitment",
        )?;
        ensure_non_empty(&self.route_policy_root, "route intent route policy root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "route intent encrypted payload root",
        )?;
        ensure_non_empty(&self.privacy_budget_id, "route intent privacy budget id")?;
        ensure_non_empty(&self.encryption_scheme, "route intent encryption scheme")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_ACCEPTED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        ensure_bps(self.max_slippage_bps, "route intent max slippage")?;
        if self.deadline_height <= self.submission_height {
            return Err("route intent deadline must be after submission".to_string());
        }
        let expected_id = confidential_router_intent_id(
            self.intent_kind,
            &self.owner_commitment,
            &self.session_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_in_commitment,
            &self.min_amount_out_commitment,
            self.max_slippage_bps,
            &self.route_policy_root,
            &self.privacy_budget_id,
            self.submission_height,
            self.deadline_height,
            self.nonce,
        );
        if self.intent_id != expected_id {
            return Err("route intent id mismatch".to_string());
        }
        Ok(self.intent_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouteLeg {
    pub leg_id: String,
    pub route_id: String,
    pub intent_id: String,
    pub leg_index: u16,
    pub leg_kind: RouteLegKind,
    pub privacy_class: RoutingPrivacyClass,
    pub venue_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub fee_commitment: String,
    pub leg_payload_root: String,
    pub dependency_root: String,
    pub created_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl ConfidentialRouteLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: impl Into<String>,
        intent_id: impl Into<String>,
        leg_index: u16,
        leg_kind: RouteLegKind,
        privacy_class: RoutingPrivacyClass,
        venue_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        fee_units: u64,
        leg_payload: &Value,
        dependencies: &[String],
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        let route_id = route_id.into();
        let intent_id = intent_id.into();
        ensure_non_empty(&route_id, "route leg route id")?;
        ensure_non_empty(&intent_id, "route leg intent id")?;
        ensure_non_empty(venue_label, "route leg venue label")?;
        ensure_non_empty(asset_in_id, "route leg asset in")?;
        ensure_non_empty(asset_out_id, "route leg asset out")?;
        ensure_positive(amount_in, "route leg amount in")?;
        ensure_distinct_strings(dependencies, "route leg dependencies")?;

        let venue_commitment = confidential_router_venue_commitment(venue_label);
        let asset_in_commitment = confidential_router_asset_commitment(asset_in_id);
        let asset_out_commitment = confidential_router_asset_commitment(asset_out_id);
        let amount_in_commitment = confidential_router_amount_commitment(
            amount_in,
            &confidential_router_blinding(venue_label, nonce, "leg_amount_in"),
        );
        let min_amount_out_commitment = confidential_router_amount_commitment(
            min_amount_out,
            &confidential_router_blinding(venue_label, nonce, "leg_min_amount_out"),
        );
        let fee_commitment = confidential_router_amount_commitment(
            fee_units,
            &confidential_router_blinding(venue_label, nonce, "leg_fee"),
        );
        let leg_payload_root = confidential_router_payload_root("route_leg_payload", leg_payload);
        let dependency_root =
            confidential_router_string_set_root("route_leg_dependency", dependencies);
        let leg_id = confidential_router_route_leg_id(
            &route_id,
            &intent_id,
            leg_index,
            leg_kind,
            privacy_class,
            &venue_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &min_amount_out_commitment,
            &fee_commitment,
            &leg_payload_root,
            &dependency_root,
            nonce,
        );
        let leg = Self {
            leg_id,
            route_id,
            intent_id,
            leg_index,
            leg_kind,
            privacy_class,
            venue_commitment,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            min_amount_out_commitment,
            fee_commitment,
            leg_payload_root,
            dependency_root,
            created_at_height,
            nonce,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        leg.validate()?;
        Ok(leg)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn token_factory_leg(
        route_id: impl Into<String>,
        intent_id: impl Into<String>,
        leg_index: u16,
        operation: &str,
        token_factory_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        fee_units: u64,
        metadata: &Value,
        dependencies: &[String],
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(operation, "token factory route leg operation")?;
        let leg_kind = match operation {
            "mint" => RouteLegKind::TokenFactoryMint,
            "burn" => RouteLegKind::TokenFactoryBurn,
            "redeem" => RouteLegKind::TokenFactoryRedeem,
            _ => return Err("token factory route leg operation is unsupported".to_string()),
        };
        let payload = json!({
            "module": "token_factory",
            "operation": operation,
            "metadata": metadata,
        });
        Self::new(
            route_id,
            intent_id,
            leg_index,
            leg_kind,
            RoutingPrivacyClass::Encrypted,
            token_factory_label,
            asset_in_id,
            asset_out_id,
            amount_in,
            min_amount_out,
            fee_units,
            &payload,
            dependencies,
            created_at_height,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn lending_leg(
        route_id: impl Into<String>,
        intent_id: impl Into<String>,
        leg_index: u16,
        operation: &str,
        market_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        fee_units: u64,
        metadata: &Value,
        dependencies: &[String],
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(operation, "lending route leg operation")?;
        let leg_kind = match operation {
            "supply" => RouteLegKind::LendingSupply,
            "borrow" => RouteLegKind::LendingBorrow,
            "repay" => RouteLegKind::LendingRepay,
            "liquidate" => RouteLegKind::LendingLiquidation,
            _ => return Err("lending route leg operation is unsupported".to_string()),
        };
        let payload = json!({
            "module": "lending_market",
            "operation": operation,
            "metadata": metadata,
        });
        Self::new(
            route_id,
            intent_id,
            leg_index,
            leg_kind,
            RoutingPrivacyClass::Shielded,
            market_label,
            asset_in_id,
            asset_out_id,
            amount_in,
            min_amount_out,
            fee_units,
            &payload,
            dependencies,
            created_at_height,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn state_channel_leg(
        route_id: impl Into<String>,
        intent_id: impl Into<String>,
        leg_index: u16,
        operation: &str,
        channel_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        fee_units: u64,
        metadata: &Value,
        dependencies: &[String],
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(operation, "state channel route leg operation")?;
        let leg_kind = match operation {
            "open" => RouteLegKind::StateChannelOpen,
            "update" => RouteLegKind::StateChannelUpdate,
            "close" => RouteLegKind::StateChannelClose,
            _ => return Err("state channel route leg operation is unsupported".to_string()),
        };
        let payload = json!({
            "module": "state_channels",
            "operation": operation,
            "metadata": metadata,
        });
        Self::new(
            route_id,
            intent_id,
            leg_index,
            leg_kind,
            RoutingPrivacyClass::Encrypted,
            channel_label,
            asset_in_id,
            asset_out_id,
            amount_in,
            min_amount_out,
            fee_units,
            &payload,
            dependencies,
            created_at_height,
            nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_route_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "leg_index": self.leg_index,
            "leg_kind": self.leg_kind.as_str(),
            "privacy_class": self.privacy_class.as_str(),
            "venue_commitment": self.venue_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "fee_commitment": self.fee_commitment,
            "leg_payload_root": self.leg_payload_root,
            "dependency_root": self.dependency_root,
            "created_at_height": self.created_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("route_leg_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.leg_id, "route leg id")?;
        ensure_non_empty(&self.route_id, "route leg route id")?;
        ensure_non_empty(&self.intent_id, "route leg intent id")?;
        ensure_non_empty(&self.venue_commitment, "route leg venue commitment")?;
        ensure_non_empty(&self.asset_in_commitment, "route leg asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "route leg asset out commitment")?;
        ensure_non_empty(&self.amount_in_commitment, "route leg amount commitment")?;
        ensure_non_empty(
            &self.min_amount_out_commitment,
            "route leg min amount commitment",
        )?;
        ensure_non_empty(&self.fee_commitment, "route leg fee commitment")?;
        ensure_non_empty(&self.leg_payload_root, "route leg payload root")?;
        ensure_non_empty(&self.dependency_root, "route leg dependency root")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_ACCEPTED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        let expected_id = confidential_router_route_leg_id(
            &self.route_id,
            &self.intent_id,
            self.leg_index,
            self.leg_kind,
            self.privacy_class,
            &self.venue_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_in_commitment,
            &self.min_amount_out_commitment,
            &self.fee_commitment,
            &self.leg_payload_root,
            &self.dependency_root,
            self.nonce,
        );
        if self.leg_id != expected_id {
            return Err("route leg id mismatch".to_string());
        }
        Ok(self.leg_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRfqQuote {
    pub quote_id: String,
    pub auction_id: String,
    pub intent_id: String,
    pub solver_commitment_id: String,
    pub solver_commitment: String,
    pub asset_pair_commitment: String,
    pub input_amount_commitment: String,
    pub output_amount_commitment: String,
    pub fee_commitment: String,
    pub price_commitment: String,
    pub route_leg_root: String,
    pub encrypted_quote_root: String,
    pub validity_start_height: u64,
    pub expires_height: u64,
    pub quote_nonce: u64,
    pub status: String,
}

impl PrivateRfqQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        intent_id: impl Into<String>,
        solver_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        input_amount: u64,
        output_amount: u64,
        fee_units: u64,
        price_numerator: u64,
        price_denominator: u64,
        route_legs: &[ConfidentialRouteLeg],
        encrypted_quote: &Value,
        validity_start_height: u64,
        expires_height: u64,
        quote_nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        let auction_id = auction_id.into();
        let intent_id = intent_id.into();
        ensure_non_empty(&auction_id, "rfq quote auction id")?;
        ensure_non_empty(&intent_id, "rfq quote intent id")?;
        ensure_non_empty(solver_label, "rfq quote solver label")?;
        ensure_non_empty(asset_in_id, "rfq quote asset in")?;
        ensure_non_empty(asset_out_id, "rfq quote asset out")?;
        ensure_positive(input_amount, "rfq quote input amount")?;
        ensure_positive(output_amount, "rfq quote output amount")?;
        ensure_positive(price_denominator, "rfq quote price denominator")?;
        if expires_height <= validity_start_height {
            return Err("rfq quote expiry must be after validity start".to_string());
        }
        if route_legs.is_empty() {
            return Err("rfq quote requires at least one route leg".to_string());
        }
        ensure_route_leg_count(route_legs.len())?;

        let solver_commitment = confidential_router_solver_commitment(solver_label);
        let asset_pair_commitment =
            confidential_router_asset_pair_commitment(asset_in_id, asset_out_id);
        let input_amount_commitment = confidential_router_amount_commitment(
            input_amount,
            &confidential_router_blinding(solver_label, quote_nonce, "quote_input"),
        );
        let output_amount_commitment = confidential_router_amount_commitment(
            output_amount,
            &confidential_router_blinding(solver_label, quote_nonce, "quote_output"),
        );
        let fee_commitment = confidential_router_amount_commitment(
            fee_units,
            &confidential_router_blinding(solver_label, quote_nonce, "quote_fee"),
        );
        let price_commitment = confidential_router_price_commitment(
            price_numerator,
            price_denominator,
            &confidential_router_blinding(solver_label, quote_nonce, "quote_price"),
        );
        let route_leg_root = confidential_router_route_leg_root(route_legs);
        let encrypted_quote_root =
            confidential_router_payload_root("encrypted_rfq_quote", encrypted_quote);
        let quote_id = confidential_router_rfq_quote_id(
            &auction_id,
            &intent_id,
            &solver_commitment,
            &asset_pair_commitment,
            &input_amount_commitment,
            &output_amount_commitment,
            &fee_commitment,
            &price_commitment,
            &route_leg_root,
            validity_start_height,
            expires_height,
            quote_nonce,
        );
        let quote = Self {
            quote_id,
            auction_id,
            intent_id,
            solver_commitment_id: String::new(),
            solver_commitment,
            asset_pair_commitment,
            input_amount_commitment,
            output_amount_commitment,
            fee_commitment,
            price_commitment,
            route_leg_root,
            encrypted_quote_root,
            validity_start_height,
            expires_height,
            quote_nonce,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn bind_solver_commitment(
        &mut self,
        solver_commitment_id: impl Into<String>,
    ) -> ConfidentialRouterResult<()> {
        let solver_commitment_id = solver_commitment_id.into();
        ensure_non_empty(&solver_commitment_id, "rfq quote solver commitment id")?;
        self.solver_commitment_id = solver_commitment_id;
        Ok(())
    }

    pub fn commitment_record(&self) -> Value {
        json!({
            "kind": "confidential_router_rfq_quote_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "intent_id": self.intent_id,
            "solver_commitment": self.solver_commitment,
            "asset_pair_commitment": self.asset_pair_commitment,
            "input_amount_commitment": self.input_amount_commitment,
            "output_amount_commitment": self.output_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "price_commitment": self.price_commitment,
            "route_leg_root": self.route_leg_root,
            "encrypted_quote_root": self.encrypted_quote_root,
            "validity_start_height": self.validity_start_height,
            "expires_height": self.expires_height,
            "quote_nonce": self.quote_nonce,
            "rfq_scheme": CONFIDENTIAL_ROUTER_RFQ_SCHEME,
            "commitment_scheme": CONFIDENTIAL_ROUTER_COMMITMENT_SCHEME,
        })
    }

    pub fn quote_commitment_root(&self) -> String {
        confidential_router_payload_root("rfq_quote_commitment", &self.commitment_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.commitment_record();
        let object = record
            .as_object_mut()
            .expect("rfq quote public record object");
        object.insert(
            "solver_commitment_id".to_string(),
            Value::String(self.solver_commitment_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("rfq_quote_record", &self.public_record())
    }

    pub fn mark_settled(&mut self) {
        self.status = CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string();
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.quote_id, "rfq quote id")?;
        ensure_non_empty(&self.auction_id, "rfq quote auction id")?;
        ensure_non_empty(&self.intent_id, "rfq quote intent id")?;
        ensure_non_empty(&self.solver_commitment, "rfq quote solver commitment")?;
        ensure_non_empty(
            &self.asset_pair_commitment,
            "rfq quote asset pair commitment",
        )?;
        ensure_non_empty(
            &self.input_amount_commitment,
            "rfq quote input amount commitment",
        )?;
        ensure_non_empty(
            &self.output_amount_commitment,
            "rfq quote output amount commitment",
        )?;
        ensure_non_empty(&self.fee_commitment, "rfq quote fee commitment")?;
        ensure_non_empty(&self.price_commitment, "rfq quote price commitment")?;
        ensure_non_empty(&self.route_leg_root, "rfq quote route leg root")?;
        ensure_non_empty(&self.encrypted_quote_root, "rfq quote encrypted root")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_ACCEPTED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        if self.expires_height <= self.validity_start_height {
            return Err("rfq quote expiry must be after validity start".to_string());
        }
        let expected_id = confidential_router_rfq_quote_id(
            &self.auction_id,
            &self.intent_id,
            &self.solver_commitment,
            &self.asset_pair_commitment,
            &self.input_amount_commitment,
            &self.output_amount_commitment,
            &self.fee_commitment,
            &self.price_commitment,
            &self.route_leg_root,
            self.validity_start_height,
            self.expires_height,
            self.quote_nonce,
        );
        if self.quote_id != expected_id {
            return Err("rfq quote id mismatch".to_string());
        }
        Ok(self.quote_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverRouteCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub quote_commitment_root: String,
    pub route_plan_root: String,
    pub route_leg_root: String,
    pub collateral_asset_commitment: String,
    pub bond_amount_commitment: String,
    pub fee_rebate_commitment: String,
    pub batch_hint_root: String,
    pub commit_height: u64,
    pub reveal_deadline_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl SolverRouteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        solver_label: &str,
        quote_commitment_root: impl Into<String>,
        route_plan: &Value,
        route_legs: &[ConfidentialRouteLeg],
        collateral_asset_id: &str,
        bond_amount: u64,
        fee_rebate_units: u64,
        batch_hint: &Value,
        commit_height: u64,
        reveal_deadline_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        let auction_id = auction_id.into();
        let quote_commitment_root = quote_commitment_root.into();
        ensure_non_empty(&auction_id, "solver route commitment auction id")?;
        ensure_non_empty(solver_label, "solver route commitment solver label")?;
        ensure_non_empty(&quote_commitment_root, "solver route commitment quote root")?;
        ensure_non_empty(
            collateral_asset_id,
            "solver route commitment collateral asset",
        )?;
        ensure_positive(bond_amount, "solver route commitment bond amount")?;
        if reveal_deadline_height <= commit_height {
            return Err("solver route commitment reveal deadline must be after commit".to_string());
        }
        ensure_route_leg_count(route_legs.len())?;

        let solver_commitment = confidential_router_solver_commitment(solver_label);
        let route_plan_root = confidential_router_payload_root("solver_route_plan", route_plan);
        let route_leg_root = confidential_router_route_leg_root(route_legs);
        let collateral_asset_commitment = confidential_router_asset_commitment(collateral_asset_id);
        let bond_amount_commitment = confidential_router_amount_commitment(
            bond_amount,
            &confidential_router_blinding(solver_label, nonce, "solver_bond"),
        );
        let fee_rebate_commitment = confidential_router_amount_commitment(
            fee_rebate_units,
            &confidential_router_blinding(solver_label, nonce, "fee_rebate"),
        );
        let batch_hint_root = confidential_router_payload_root("solver_batch_hint", batch_hint);
        let commitment_id = confidential_router_solver_route_commitment_id(
            &auction_id,
            &solver_commitment,
            &quote_commitment_root,
            &route_plan_root,
            &route_leg_root,
            &collateral_asset_commitment,
            &bond_amount_commitment,
            &fee_rebate_commitment,
            commit_height,
            reveal_deadline_height,
            nonce,
        );
        let commitment = Self {
            commitment_id,
            auction_id,
            solver_commitment,
            quote_commitment_root,
            route_plan_root,
            route_leg_root,
            collateral_asset_commitment,
            bond_amount_commitment,
            fee_rebate_commitment,
            batch_hint_root,
            commit_height,
            reveal_deadline_height,
            nonce,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_solver_route_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "quote_commitment_root": self.quote_commitment_root,
            "route_plan_root": self.route_plan_root,
            "route_leg_root": self.route_leg_root,
            "collateral_asset_commitment": self.collateral_asset_commitment,
            "bond_amount_commitment": self.bond_amount_commitment,
            "fee_rebate_commitment": self.fee_rebate_commitment,
            "batch_hint_root": self.batch_hint_root,
            "commit_height": self.commit_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "nonce": self.nonce,
            "ordering_policy": CONFIDENTIAL_ROUTER_ORDERING_POLICY,
            "commitment_scheme": CONFIDENTIAL_ROUTER_COMMITMENT_SCHEME,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("solver_route_commitment_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.commitment_id, "solver route commitment id")?;
        ensure_non_empty(&self.auction_id, "solver route commitment auction id")?;
        ensure_non_empty(
            &self.solver_commitment,
            "solver route commitment solver commitment",
        )?;
        ensure_non_empty(
            &self.quote_commitment_root,
            "solver route commitment quote root",
        )?;
        ensure_non_empty(&self.route_plan_root, "solver route commitment plan root")?;
        ensure_non_empty(&self.route_leg_root, "solver route commitment leg root")?;
        ensure_non_empty(
            &self.collateral_asset_commitment,
            "solver route commitment collateral commitment",
        )?;
        ensure_non_empty(
            &self.bond_amount_commitment,
            "solver route commitment bond commitment",
        )?;
        ensure_non_empty(
            &self.fee_rebate_commitment,
            "solver route commitment rebate commitment",
        )?;
        ensure_non_empty(
            &self.batch_hint_root,
            "solver route commitment batch hint root",
        )?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_ACCEPTED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        if self.reveal_deadline_height <= self.commit_height {
            return Err("solver route commitment reveal deadline must be after commit".to_string());
        }
        let expected_id = confidential_router_solver_route_commitment_id(
            &self.auction_id,
            &self.solver_commitment,
            &self.quote_commitment_root,
            &self.route_plan_root,
            &self.route_leg_root,
            &self.collateral_asset_commitment,
            &self.bond_amount_commitment,
            &self.fee_rebate_commitment,
            self.commit_height,
            self.reveal_deadline_height,
            self.nonce,
        );
        if self.commitment_id != expected_id {
            return Err("solver route commitment id mismatch".to_string());
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBatchAuction {
    pub auction_id: String,
    pub market_commitment: String,
    pub intent_root: String,
    pub rfq_quote_root: String,
    pub solver_commitment_root: String,
    pub route_leg_root: String,
    pub privacy_budget_root: String,
    pub fee_sponsorship_root: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub settlement_deadline_height: u64,
    pub ordering_seed: String,
    pub max_intents: usize,
    pub nonce: u64,
    pub status: String,
}

impl ConfidentialBatchAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_label: &str,
        intent_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        fee_sponsorship_root: impl Into<String>,
        start_height: u64,
        auction_window_blocks: u64,
        reveal_delay_blocks: u64,
        reveal_window_blocks: u64,
        settlement_ttl_blocks: u64,
        max_intents: usize,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(market_label, "batch auction market label")?;
        let intent_root = intent_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        let fee_sponsorship_root = fee_sponsorship_root.into();
        ensure_non_empty(&intent_root, "batch auction intent root")?;
        ensure_non_empty(&privacy_budget_root, "batch auction privacy budget root")?;
        ensure_non_empty(&fee_sponsorship_root, "batch auction fee sponsorship root")?;
        ensure_positive(auction_window_blocks, "batch auction window")?;
        ensure_positive(reveal_window_blocks, "batch auction reveal window")?;
        ensure_positive(settlement_ttl_blocks, "batch auction settlement ttl")?;
        if max_intents == 0 || max_intents > CONFIDENTIAL_ROUTER_MAX_BATCH_INTENTS {
            return Err("batch auction max intents is out of range".to_string());
        }

        let market_commitment = confidential_router_market_commitment(market_label);
        let commit_end_height = start_height
            .checked_add(auction_window_blocks)
            .ok_or_else(|| "batch auction commit end height overflow".to_string())?;
        let reveal_start_height = commit_end_height
            .checked_add(reveal_delay_blocks)
            .ok_or_else(|| "batch auction reveal start height overflow".to_string())?;
        let reveal_end_height = reveal_start_height
            .checked_add(reveal_window_blocks)
            .ok_or_else(|| "batch auction reveal end height overflow".to_string())?;
        let settlement_deadline_height = reveal_end_height
            .checked_add(settlement_ttl_blocks)
            .ok_or_else(|| "batch auction settlement deadline overflow".to_string())?;
        let ordering_seed =
            confidential_router_ordering_seed(market_label, start_height, &intent_root, nonce);
        let rfq_quote_root = confidential_router_rfq_quote_root(&[]);
        let solver_commitment_root = confidential_router_solver_route_commitment_root(&[]);
        let route_leg_root = confidential_router_route_leg_root(&[]);
        let auction_id = confidential_router_batch_auction_id(
            &market_commitment,
            &intent_root,
            start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            &ordering_seed,
            nonce,
        );
        let auction = Self {
            auction_id,
            market_commitment,
            intent_root,
            rfq_quote_root,
            solver_commitment_root,
            route_leg_root,
            privacy_budget_root,
            fee_sponsorship_root,
            commit_start_height: start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            settlement_deadline_height,
            ordering_seed,
            max_intents,
            nonce,
            status: CONFIDENTIAL_ROUTER_STATUS_COLLECTING.to_string(),
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn update_roots(
        &mut self,
        rfq_quote_root: impl Into<String>,
        solver_commitment_root: impl Into<String>,
        route_leg_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        fee_sponsorship_root: impl Into<String>,
    ) -> ConfidentialRouterResult<()> {
        self.rfq_quote_root = rfq_quote_root.into();
        self.solver_commitment_root = solver_commitment_root.into();
        self.route_leg_root = route_leg_root.into();
        self.privacy_budget_root = privacy_budget_root.into();
        self.fee_sponsorship_root = fee_sponsorship_root.into();
        self.validate()?;
        Ok(())
    }

    pub fn phase_at_height(&self, height: u64) -> &'static str {
        if height < self.commit_start_height {
            "pending"
        } else if height <= self.commit_end_height {
            "collecting"
        } else if height < self.reveal_start_height {
            "sealed"
        } else if height <= self.reveal_end_height {
            "revealing"
        } else if height <= self.settlement_deadline_height {
            "settling"
        } else {
            "expired"
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_batch_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "market_commitment": self.market_commitment,
            "intent_root": self.intent_root,
            "rfq_quote_root": self.rfq_quote_root,
            "solver_commitment_root": self.solver_commitment_root,
            "route_leg_root": self.route_leg_root,
            "privacy_budget_root": self.privacy_budget_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "ordering_seed": self.ordering_seed,
            "ordering_policy": CONFIDENTIAL_ROUTER_ORDERING_POLICY,
            "max_intents": self.max_intents,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("batch_auction_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.auction_id, "batch auction id")?;
        ensure_non_empty(&self.market_commitment, "batch auction market commitment")?;
        ensure_non_empty(&self.intent_root, "batch auction intent root")?;
        ensure_non_empty(&self.rfq_quote_root, "batch auction quote root")?;
        ensure_non_empty(
            &self.solver_commitment_root,
            "batch auction solver commitment root",
        )?;
        ensure_non_empty(&self.route_leg_root, "batch auction route leg root")?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "batch auction privacy budget root",
        )?;
        ensure_non_empty(
            &self.fee_sponsorship_root,
            "batch auction fee sponsorship root",
        )?;
        ensure_non_empty(&self.ordering_seed, "batch auction ordering seed")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_COLLECTING,
                CONFIDENTIAL_ROUTER_STATUS_REVEALING,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_PAUSED,
            ],
        )?;
        if self.commit_start_height >= self.commit_end_height {
            return Err("batch auction commit window is invalid".to_string());
        }
        if self.commit_end_height > self.reveal_start_height {
            return Err("batch auction reveal start cannot precede commit end".to_string());
        }
        if self.reveal_start_height >= self.reveal_end_height {
            return Err("batch auction reveal window is invalid".to_string());
        }
        if self.reveal_end_height >= self.settlement_deadline_height {
            return Err("batch auction settlement deadline is invalid".to_string());
        }
        if self.max_intents == 0 || self.max_intents > CONFIDENTIAL_ROUTER_MAX_BATCH_INTENTS {
            return Err("batch auction max intents is out of range".to_string());
        }
        let expected_id = confidential_router_batch_auction_id(
            &self.market_commitment,
            &self.intent_root,
            self.commit_start_height,
            self.commit_end_height,
            self.reveal_start_height,
            self.reveal_end_height,
            &self.ordering_seed,
            self.nonce,
        );
        if self.auction_id != expected_id {
            return Err("batch auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiMevBatchOrder {
    pub batch_order_id: String,
    pub auction_id: String,
    pub batch_height: u64,
    pub ordering_seed: String,
    pub ordered_intent_ids: Vec<String>,
    pub ordered_solver_commitment_ids: Vec<String>,
    pub ordered_quote_ids: Vec<String>,
    pub intent_order_root: String,
    pub solver_order_root: String,
    pub quote_order_root: String,
    pub tie_breaker_root: String,
    pub status: String,
}

impl AntiMevBatchOrder {
    pub fn new(
        auction_id: impl Into<String>,
        batch_height: u64,
        ordering_seed: impl Into<String>,
        intent_ids: &[String],
        solver_commitment_ids: &[String],
        quote_ids: &[String],
    ) -> ConfidentialRouterResult<Self> {
        let auction_id = auction_id.into();
        let ordering_seed = ordering_seed.into();
        ensure_non_empty(&auction_id, "anti mev batch order auction id")?;
        ensure_non_empty(&ordering_seed, "anti mev batch order seed")?;
        ensure_distinct_strings(intent_ids, "anti mev batch order intents")?;
        ensure_distinct_strings(
            solver_commitment_ids,
            "anti mev batch order solver commitments",
        )?;
        ensure_distinct_strings(quote_ids, "anti mev batch order quotes")?;
        if intent_ids.len() > CONFIDENTIAL_ROUTER_MAX_BATCH_INTENTS {
            return Err("anti mev batch order has too many intents".to_string());
        }

        let ordered_intent_ids =
            confidential_router_anti_mev_order(&auction_id, &ordering_seed, intent_ids);
        let ordered_solver_commitment_ids =
            confidential_router_anti_mev_order(&auction_id, &ordering_seed, solver_commitment_ids);
        let ordered_quote_ids =
            confidential_router_anti_mev_order(&auction_id, &ordering_seed, quote_ids);
        let intent_order_root =
            confidential_router_ordered_string_root("batch_order_intent", &ordered_intent_ids);
        let solver_order_root = confidential_router_ordered_string_root(
            "batch_order_solver",
            &ordered_solver_commitment_ids,
        );
        let quote_order_root =
            confidential_router_ordered_string_root("batch_order_quote", &ordered_quote_ids);
        let tie_breaker_root = confidential_router_tie_breaker_root(
            &auction_id,
            &ordering_seed,
            &ordered_intent_ids,
            &ordered_solver_commitment_ids,
            &ordered_quote_ids,
        );
        let batch_order_id = confidential_router_batch_order_id(
            &auction_id,
            batch_height,
            &ordering_seed,
            &intent_order_root,
            &solver_order_root,
            &quote_order_root,
            &tie_breaker_root,
        );
        let order = Self {
            batch_order_id,
            auction_id,
            batch_height,
            ordering_seed,
            ordered_intent_ids,
            ordered_solver_commitment_ids,
            ordered_quote_ids,
            intent_order_root,
            solver_order_root,
            quote_order_root,
            tie_breaker_root,
            status: CONFIDENTIAL_ROUTER_STATUS_ACCEPTED.to_string(),
        };
        order.validate()?;
        Ok(order)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_anti_mev_batch_order",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "batch_order_id": self.batch_order_id,
            "auction_id": self.auction_id,
            "batch_height": self.batch_height,
            "ordering_seed": self.ordering_seed,
            "ordering_policy": CONFIDENTIAL_ROUTER_ORDERING_POLICY,
            "ordered_intent_ids": self.ordered_intent_ids,
            "ordered_solver_commitment_ids": self.ordered_solver_commitment_ids,
            "ordered_quote_ids": self.ordered_quote_ids,
            "intent_order_root": self.intent_order_root,
            "solver_order_root": self.solver_order_root,
            "quote_order_root": self.quote_order_root,
            "tie_breaker_root": self.tie_breaker_root,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("anti_mev_batch_order_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.batch_order_id, "anti mev batch order id")?;
        ensure_non_empty(&self.auction_id, "anti mev batch order auction id")?;
        ensure_non_empty(&self.ordering_seed, "anti mev batch order seed")?;
        ensure_non_empty(&self.intent_order_root, "anti mev batch order intent root")?;
        ensure_non_empty(&self.solver_order_root, "anti mev batch order solver root")?;
        ensure_non_empty(&self.quote_order_root, "anti mev batch order quote root")?;
        ensure_non_empty(
            &self.tie_breaker_root,
            "anti mev batch order tie breaker root",
        )?;
        ensure_distinct_strings(&self.ordered_intent_ids, "anti mev batch order intents")?;
        ensure_distinct_strings(
            &self.ordered_solver_commitment_ids,
            "anti mev batch order solver commitments",
        )?;
        ensure_distinct_strings(&self.ordered_quote_ids, "anti mev batch order quotes")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACCEPTED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        let expected_id = confidential_router_batch_order_id(
            &self.auction_id,
            self.batch_height,
            &self.ordering_seed,
            &self.intent_order_root,
            &self.solver_order_root,
            &self.quote_order_root,
            &self.tie_breaker_root,
        );
        if self.batch_order_id != expected_id {
            return Err("anti mev batch order id mismatch".to_string());
        }
        Ok(self.batch_order_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlippageGuard {
    pub guard_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub max_slippage_bps: u64,
    pub expected_amount_out_commitment: String,
    pub min_amount_out_commitment: String,
    pub oracle_guard_root: String,
    pub twap_guard_root: String,
    pub created_at_height: u64,
    pub expires_height: u64,
    pub status: String,
}

impl SlippageGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        quote_id: impl Into<String>,
        expected_amount_out: u64,
        min_amount_out: u64,
        max_slippage_bps: u64,
        oracle_guard: &Value,
        twap_guard: &Value,
        created_at_height: u64,
        expires_height: u64,
        blinding_label: &str,
    ) -> ConfidentialRouterResult<Self> {
        let intent_id = intent_id.into();
        let quote_id = quote_id.into();
        ensure_non_empty(&intent_id, "slippage guard intent id")?;
        ensure_non_empty(&quote_id, "slippage guard quote id")?;
        ensure_positive(expected_amount_out, "slippage guard expected output")?;
        ensure_positive(min_amount_out, "slippage guard minimum output")?;
        ensure_bps(max_slippage_bps, "slippage guard max slippage")?;
        ensure_non_empty(blinding_label, "slippage guard blinding label")?;
        if min_amount_out > expected_amount_out {
            return Err("slippage guard minimum output exceeds expected output".to_string());
        }
        if expires_height <= created_at_height {
            return Err("slippage guard expiry must be after creation".to_string());
        }
        let expected_amount_out_commitment = confidential_router_amount_commitment(
            expected_amount_out,
            &confidential_router_blinding(blinding_label, created_at_height, "expected_out"),
        );
        let min_amount_out_commitment = confidential_router_amount_commitment(
            min_amount_out,
            &confidential_router_blinding(blinding_label, created_at_height, "min_out"),
        );
        let oracle_guard_root =
            confidential_router_payload_root("slippage_oracle_guard", oracle_guard);
        let twap_guard_root = confidential_router_payload_root("slippage_twap_guard", twap_guard);
        let guard_id = confidential_router_slippage_guard_id(
            &intent_id,
            &quote_id,
            max_slippage_bps,
            &expected_amount_out_commitment,
            &min_amount_out_commitment,
            &oracle_guard_root,
            &twap_guard_root,
            created_at_height,
            expires_height,
        );
        let guard = Self {
            guard_id,
            intent_id,
            quote_id,
            max_slippage_bps,
            expected_amount_out_commitment,
            min_amount_out_commitment,
            oracle_guard_root,
            twap_guard_root,
            created_at_height,
            expires_height,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_slippage_guard",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "guard_id": self.guard_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "max_slippage_bps": self.max_slippage_bps,
            "expected_amount_out_commitment": self.expected_amount_out_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "oracle_guard_root": self.oracle_guard_root,
            "twap_guard_root": self.twap_guard_root,
            "created_at_height": self.created_at_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("slippage_guard_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.guard_id, "slippage guard id")?;
        ensure_non_empty(&self.intent_id, "slippage guard intent id")?;
        ensure_non_empty(&self.quote_id, "slippage guard quote id")?;
        ensure_non_empty(
            &self.expected_amount_out_commitment,
            "slippage guard expected output commitment",
        )?;
        ensure_non_empty(
            &self.min_amount_out_commitment,
            "slippage guard min output commitment",
        )?;
        ensure_non_empty(&self.oracle_guard_root, "slippage guard oracle root")?;
        ensure_non_empty(&self.twap_guard_root, "slippage guard twap root")?;
        ensure_bps(self.max_slippage_bps, "slippage guard max slippage")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        if self.expires_height <= self.created_at_height {
            return Err("slippage guard expiry must be after creation".to_string());
        }
        let expected_id = confidential_router_slippage_guard_id(
            &self.intent_id,
            &self.quote_id,
            self.max_slippage_bps,
            &self.expected_amount_out_commitment,
            &self.min_amount_out_commitment,
            &self.oracle_guard_root,
            &self.twap_guard_root,
            self.created_at_height,
            self.expires_height,
        );
        if self.guard_id != expected_id {
            return Err("slippage guard id mismatch".to_string());
        }
        Ok(self.guard_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub sponsored_object_id: String,
    pub mode: FeeSponsorshipMode,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub paymaster_policy_root: String,
    pub starts_at_height: u64,
    pub expires_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl FeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        mode: FeeSponsorshipMode,
        low_fee_lane: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        paymaster_policy: &Value,
        starts_at_height: u64,
        expires_height: u64,
        nonce: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(sponsor_label, "fee sponsorship sponsor label")?;
        ensure_non_empty(low_fee_lane, "fee sponsorship low fee lane")?;
        ensure_non_empty(fee_asset_id, "fee sponsorship fee asset id")?;
        ensure_positive(max_fee_units, "fee sponsorship max fee")?;
        if expires_height <= starts_at_height {
            return Err("fee sponsorship expiry must be after start".to_string());
        }
        if mode.requires_sponsor() && sponsor_label == "user" {
            return Err("fee sponsorship mode requires a sponsor".to_string());
        }
        let sponsor_commitment = confidential_router_account_commitment(sponsor_label);
        let paymaster_policy_root =
            confidential_router_payload_root("fee_sponsorship_policy", paymaster_policy);
        let sponsorship_id = confidential_router_fee_sponsorship_id(
            &sponsor_commitment,
            mode,
            low_fee_lane,
            fee_asset_id,
            max_fee_units,
            &paymaster_policy_root,
            starts_at_height,
            expires_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            sponsored_object_id: String::new(),
            mode,
            low_fee_lane: low_fee_lane.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            reserved_fee_units: 0,
            spent_fee_units: 0,
            paymaster_policy_root,
            starts_at_height,
            expires_height,
            nonce,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn bind_object(
        &mut self,
        sponsored_object_id: impl Into<String>,
    ) -> ConfidentialRouterResult<()> {
        let sponsored_object_id = sponsored_object_id.into();
        ensure_non_empty(&sponsored_object_id, "fee sponsorship object id")?;
        self.sponsored_object_id = sponsored_object_id;
        Ok(())
    }

    pub fn available_fee_units(&self) -> u64 {
        self.max_fee_units
            .saturating_sub(self.reserved_fee_units)
            .saturating_sub(self.spent_fee_units)
    }

    pub fn reserve(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "fee sponsorship reservation")?;
        if self.available_fee_units() < units {
            return Err("fee sponsorship has insufficient available units".to_string());
        }
        self.reserved_fee_units = self
            .reserved_fee_units
            .checked_add(units)
            .ok_or_else(|| "fee sponsorship reservation overflow".to_string())?;
        self.status = CONFIDENTIAL_ROUTER_STATUS_RESERVED.to_string();
        Ok(())
    }

    pub fn spend_reserved(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "fee sponsorship spend")?;
        if self.reserved_fee_units < units {
            return Err("fee sponsorship reserved units are insufficient".to_string());
        }
        self.reserved_fee_units -= units;
        self.spent_fee_units = self
            .spent_fee_units
            .checked_add(units)
            .ok_or_else(|| "fee sponsorship spend overflow".to_string())?;
        self.status = CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string();
        Ok(())
    }

    pub fn release_reserved(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "fee sponsorship release")?;
        if self.reserved_fee_units < units {
            return Err("fee sponsorship reserved units are insufficient".to_string());
        }
        self.reserved_fee_units -= units;
        self.status = if self.reserved_fee_units == 0 {
            CONFIDENTIAL_ROUTER_STATUS_RELEASED.to_string()
        } else {
            CONFIDENTIAL_ROUTER_STATUS_RESERVED.to_string()
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsored_object_id": self.sponsored_object_id,
            "mode": self.mode.as_str(),
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "available_fee_units": self.available_fee_units(),
            "paymaster_policy_root": self.paymaster_policy_root,
            "starts_at_height": self.starts_at_height,
            "expires_height": self.expires_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("fee_sponsorship_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.sponsorship_id, "fee sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "fee sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.low_fee_lane, "fee sponsorship low fee lane")?;
        ensure_non_empty(&self.fee_asset_id, "fee sponsorship fee asset")?;
        ensure_non_empty(&self.paymaster_policy_root, "fee sponsorship policy root")?;
        ensure_positive(self.max_fee_units, "fee sponsorship max fee")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_RESERVED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_RELEASED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        if self.expires_height <= self.starts_at_height {
            return Err("fee sponsorship expiry must be after start".to_string());
        }
        if self.reserved_fee_units.saturating_add(self.spent_fee_units) > self.max_fee_units {
            return Err("fee sponsorship spent plus reserved exceeds maximum".to_string());
        }
        let expected_id = confidential_router_fee_sponsorship_id(
            &self.sponsor_commitment,
            self.mode,
            &self.low_fee_lane,
            &self.fee_asset_id,
            self.max_fee_units,
            &self.paymaster_policy_root,
            self.starts_at_height,
            self.expires_height,
            self.nonce,
        );
        if self.sponsorship_id != expected_id {
            return Err("fee sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub privacy_class: RoutingPrivacyClass,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub audit_root: String,
    pub status: String,
}

impl PrivacyBudget {
    pub fn new(
        owner_label: &str,
        privacy_class: RoutingPrivacyClass,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        total_units: u64,
        audit_policy: &Value,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(owner_label, "privacy budget owner label")?;
        ensure_positive(total_units, "privacy budget total units")?;
        if end_height <= start_height {
            return Err("privacy budget end height must be after start".to_string());
        }
        let owner_commitment = confidential_router_account_commitment(owner_label);
        let audit_root = confidential_router_payload_root("privacy_budget_audit", audit_policy);
        let budget_id = confidential_router_privacy_budget_id(
            &owner_commitment,
            privacy_class,
            epoch_index,
            start_height,
            end_height,
            total_units,
            &audit_root,
        );
        let budget = Self {
            budget_id,
            owner_commitment,
            privacy_class,
            epoch_index,
            start_height,
            end_height,
            total_units,
            reserved_units: 0,
            consumed_units: 0,
            audit_root,
            status: CONFIDENTIAL_ROUTER_STATUS_ACTIVE.to_string(),
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn reserve(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "privacy budget reservation units")?;
        if self.available_units() < units {
            return Err("privacy budget has insufficient units".to_string());
        }
        self.reserved_units = self
            .reserved_units
            .checked_add(units)
            .ok_or_else(|| "privacy budget reservation overflow".to_string())?;
        Ok(())
    }

    pub fn consume_reserved(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "privacy budget consumed units")?;
        if self.reserved_units < units {
            return Err("privacy budget reserved units are insufficient".to_string());
        }
        self.reserved_units -= units;
        self.consumed_units = self
            .consumed_units
            .checked_add(units)
            .ok_or_else(|| "privacy budget consumption overflow".to_string())?;
        Ok(())
    }

    pub fn release_reserved(&mut self, units: u64) -> ConfidentialRouterResult<()> {
        ensure_positive(units, "privacy budget release units")?;
        if self.reserved_units < units {
            return Err("privacy budget reserved units are insufficient".to_string());
        }
        self.reserved_units -= units;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "privacy_class": self.privacy_class.as_str(),
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "audit_root": self.audit_root,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("privacy_budget_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.budget_id, "privacy budget id")?;
        ensure_non_empty(&self.owner_commitment, "privacy budget owner commitment")?;
        ensure_non_empty(&self.audit_root, "privacy budget audit root")?;
        ensure_positive(self.total_units, "privacy budget total units")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_ACTIVE,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
                CONFIDENTIAL_ROUTER_STATUS_PAUSED,
            ],
        )?;
        if self.end_height <= self.start_height {
            return Err("privacy budget end height must be after start".to_string());
        }
        if self.reserved_units.saturating_add(self.consumed_units) > self.total_units {
            return Err("privacy budget reserved plus consumed exceeds total".to_string());
        }
        let expected_id = confidential_router_privacy_budget_id(
            &self.owner_commitment,
            self.privacy_class,
            self.epoch_index,
            self.start_height,
            self.end_height,
            self.total_units,
            &self.audit_root,
        );
        if self.budget_id != expected_id {
            return Err("privacy budget id mismatch".to_string());
        }
        Ok(self.budget_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetReservation {
    pub reservation_id: String,
    pub budget_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub units: u64,
    pub reserved_at_height: u64,
    pub expires_height: u64,
    pub consumed_at_height: u64,
    pub status: String,
}

impl PrivacyBudgetReservation {
    pub fn new(
        budget_id: impl Into<String>,
        object_kind: &str,
        object_id: &str,
        units: u64,
        reserved_at_height: u64,
        expires_height: u64,
    ) -> ConfidentialRouterResult<Self> {
        let budget_id = budget_id.into();
        ensure_non_empty(&budget_id, "privacy budget reservation budget id")?;
        ensure_non_empty(object_kind, "privacy budget reservation object kind")?;
        ensure_non_empty(object_id, "privacy budget reservation object id")?;
        ensure_positive(units, "privacy budget reservation units")?;
        if expires_height <= reserved_at_height {
            return Err("privacy budget reservation expiry must be after reservation".to_string());
        }
        let reservation_id = confidential_router_privacy_budget_reservation_id(
            &budget_id,
            object_kind,
            object_id,
            units,
            reserved_at_height,
            expires_height,
        );
        let reservation = Self {
            reservation_id,
            budget_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            units,
            reserved_at_height,
            expires_height,
            consumed_at_height: 0,
            status: CONFIDENTIAL_ROUTER_STATUS_RESERVED.to_string(),
        };
        reservation.validate()?;
        Ok(reservation)
    }

    pub fn mark_consumed(&mut self, height: u64) -> ConfidentialRouterResult<()> {
        if height < self.reserved_at_height {
            return Err("privacy budget consumption cannot precede reservation".to_string());
        }
        self.consumed_at_height = height;
        self.status = CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string();
        Ok(())
    }

    pub fn mark_released(&mut self, height: u64) -> ConfidentialRouterResult<()> {
        if height < self.reserved_at_height {
            return Err("privacy budget release cannot precede reservation".to_string());
        }
        self.consumed_at_height = height;
        self.status = CONFIDENTIAL_ROUTER_STATUS_RELEASED.to_string();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_privacy_budget_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "budget_id": self.budget_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "units": self.units,
            "reserved_at_height": self.reserved_at_height,
            "expires_height": self.expires_height,
            "consumed_at_height": self.consumed_at_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("privacy_budget_reservation_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.reservation_id, "privacy budget reservation id")?;
        ensure_non_empty(&self.budget_id, "privacy budget reservation budget id")?;
        ensure_non_empty(&self.object_kind, "privacy budget reservation object kind")?;
        ensure_non_empty(&self.object_id, "privacy budget reservation object id")?;
        ensure_positive(self.units, "privacy budget reservation units")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_RESERVED,
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_RELEASED,
                CONFIDENTIAL_ROUTER_STATUS_EXPIRED,
            ],
        )?;
        if self.expires_height <= self.reserved_at_height {
            return Err("privacy budget reservation expiry must be after reservation".to_string());
        }
        let expected_id = confidential_router_privacy_budget_reservation_id(
            &self.budget_id,
            &self.object_kind,
            &self.object_id,
            self.units,
            self.reserved_at_height,
            self.expires_height,
        );
        if self.reservation_id != expected_id {
            return Err("privacy budget reservation id mismatch".to_string());
        }
        Ok(self.reservation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub batch_order_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub solver_commitment_id: String,
    pub route_root: String,
    pub route_leg_receipt_root: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub fee_receipt_root: String,
    pub sponsorship_receipt_root: String,
    pub privacy_budget_receipt_root: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub surplus_commitment: String,
    pub slippage_bps: u64,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub status: String,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        batch_order_id: impl Into<String>,
        intent_id: impl Into<String>,
        quote_id: impl Into<String>,
        solver_commitment_id: impl Into<String>,
        route_legs: &[ConfidentialRouteLeg],
        route_leg_receipts: &[Value],
        input_nullifiers: &[String],
        output_commitments: &[String],
        fee_receipts: &[Value],
        sponsorship_receipts: &[Value],
        privacy_budget_receipts: &[Value],
        amount_in: u64,
        amount_out: u64,
        surplus_units: u64,
        slippage_bps: u64,
        settlement_height: u64,
        finality_height: u64,
        blinding_label: &str,
    ) -> ConfidentialRouterResult<Self> {
        let auction_id = auction_id.into();
        let batch_order_id = batch_order_id.into();
        let intent_id = intent_id.into();
        let quote_id = quote_id.into();
        let solver_commitment_id = solver_commitment_id.into();
        ensure_non_empty(&auction_id, "settlement receipt auction id")?;
        ensure_non_empty(&batch_order_id, "settlement receipt batch order id")?;
        ensure_non_empty(&intent_id, "settlement receipt intent id")?;
        ensure_non_empty(&quote_id, "settlement receipt quote id")?;
        ensure_non_empty(
            &solver_commitment_id,
            "settlement receipt solver commitment id",
        )?;
        ensure_non_empty(blinding_label, "settlement receipt blinding label")?;
        ensure_route_leg_count(route_legs.len())?;
        ensure_bps(slippage_bps, "settlement receipt slippage")?;
        ensure_positive(amount_in, "settlement receipt amount in")?;
        ensure_positive(amount_out, "settlement receipt amount out")?;
        if finality_height < settlement_height {
            return Err("settlement receipt finality height cannot precede settlement".to_string());
        }

        let route_root = confidential_router_route_leg_root(route_legs);
        let route_leg_receipt_root =
            merkle_root("CONFIDENTIAL-ROUTER-ROUTE-LEG-RECEIPT", route_leg_receipts);
        let input_nullifier_root =
            confidential_router_string_set_root("settlement_input_nullifier", input_nullifiers);
        let output_commitment_root =
            confidential_router_string_set_root("settlement_output_commitment", output_commitments);
        let fee_receipt_root = merkle_root("CONFIDENTIAL-ROUTER-FEE-RECEIPT", fee_receipts);
        let sponsorship_receipt_root = merkle_root(
            "CONFIDENTIAL-ROUTER-SPONSORSHIP-RECEIPT",
            sponsorship_receipts,
        );
        let privacy_budget_receipt_root = merkle_root(
            "CONFIDENTIAL-ROUTER-PRIVACY-BUDGET-RECEIPT",
            privacy_budget_receipts,
        );
        let amount_in_commitment = confidential_router_amount_commitment(
            amount_in,
            &confidential_router_blinding(blinding_label, settlement_height, "receipt_in"),
        );
        let amount_out_commitment = confidential_router_amount_commitment(
            amount_out,
            &confidential_router_blinding(blinding_label, settlement_height, "receipt_out"),
        );
        let surplus_commitment = confidential_router_amount_commitment(
            surplus_units,
            &confidential_router_blinding(blinding_label, settlement_height, "receipt_surplus"),
        );
        let receipt_id = confidential_router_settlement_receipt_id(
            &auction_id,
            &batch_order_id,
            &intent_id,
            &quote_id,
            &solver_commitment_id,
            &route_root,
            &input_nullifier_root,
            &output_commitment_root,
            &fee_receipt_root,
            &sponsorship_receipt_root,
            &privacy_budget_receipt_root,
            &amount_in_commitment,
            &amount_out_commitment,
            settlement_height,
        );
        let receipt = Self {
            receipt_id,
            auction_id,
            batch_order_id,
            intent_id,
            quote_id,
            solver_commitment_id,
            route_root,
            route_leg_receipt_root,
            input_nullifier_root,
            output_commitment_root,
            fee_receipt_root,
            sponsorship_receipt_root,
            privacy_budget_receipt_root,
            amount_in_commitment,
            amount_out_commitment,
            surplus_commitment,
            slippage_bps,
            settlement_height,
            finality_height,
            status: CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "batch_order_id": self.batch_order_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "solver_commitment_id": self.solver_commitment_id,
            "route_root": self.route_root,
            "route_leg_receipt_root": self.route_leg_receipt_root,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "sponsorship_receipt_root": self.sponsorship_receipt_root,
            "privacy_budget_receipt_root": self.privacy_budget_receipt_root,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "surplus_commitment": self.surplus_commitment,
            "slippage_bps": self.slippage_bps,
            "settlement_height": self.settlement_height,
            "finality_height": self.finality_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        confidential_router_payload_root("settlement_receipt_record", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.receipt_id, "settlement receipt id")?;
        ensure_non_empty(&self.auction_id, "settlement receipt auction id")?;
        ensure_non_empty(&self.batch_order_id, "settlement receipt batch order id")?;
        ensure_non_empty(&self.intent_id, "settlement receipt intent id")?;
        ensure_non_empty(&self.quote_id, "settlement receipt quote id")?;
        ensure_non_empty(
            &self.solver_commitment_id,
            "settlement receipt solver commitment id",
        )?;
        ensure_non_empty(&self.route_root, "settlement receipt route root")?;
        ensure_non_empty(
            &self.route_leg_receipt_root,
            "settlement receipt leg receipt root",
        )?;
        ensure_non_empty(
            &self.input_nullifier_root,
            "settlement receipt nullifier root",
        )?;
        ensure_non_empty(
            &self.output_commitment_root,
            "settlement receipt output root",
        )?;
        ensure_non_empty(&self.fee_receipt_root, "settlement receipt fee root")?;
        ensure_non_empty(
            &self.sponsorship_receipt_root,
            "settlement receipt sponsorship root",
        )?;
        ensure_non_empty(
            &self.privacy_budget_receipt_root,
            "settlement receipt privacy budget root",
        )?;
        ensure_non_empty(
            &self.amount_in_commitment,
            "settlement receipt amount in commitment",
        )?;
        ensure_non_empty(
            &self.amount_out_commitment,
            "settlement receipt amount out commitment",
        )?;
        ensure_non_empty(
            &self.surplus_commitment,
            "settlement receipt surplus commitment",
        )?;
        ensure_bps(self.slippage_bps, "settlement receipt slippage")?;
        ensure_status(
            &self.status,
            &[
                CONFIDENTIAL_ROUTER_STATUS_SETTLED,
                CONFIDENTIAL_ROUTER_STATUS_REJECTED,
            ],
        )?;
        if self.finality_height < self.settlement_height {
            return Err("settlement receipt finality height cannot precede settlement".to_string());
        }
        let expected_id = confidential_router_settlement_receipt_id(
            &self.auction_id,
            &self.batch_order_id,
            &self.intent_id,
            &self.quote_id,
            &self.solver_commitment_id,
            &self.route_root,
            &self.input_nullifier_root,
            &self.output_commitment_root,
            &self.fee_receipt_root,
            &self.sponsorship_receipt_root,
            &self.privacy_budget_receipt_root,
            &self.amount_in_commitment,
            &self.amount_out_commitment,
            self.settlement_height,
        );
        if self.receipt_id != expected_id {
            return Err("settlement receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouterPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub record_root: String,
    pub recorded_at_height: u64,
    pub payload: Value,
}

impl ConfidentialRouterPublicRecord {
    pub fn new(
        object_kind: &str,
        object_id: &str,
        payload: &Value,
        recorded_at_height: u64,
    ) -> ConfidentialRouterResult<Self> {
        ensure_non_empty(object_kind, "public record object kind")?;
        ensure_non_empty(object_id, "public record object id")?;
        let record_root = confidential_router_payload_root("public_record_payload", payload);
        let record_id = confidential_router_public_record_id(
            object_kind,
            object_id,
            &record_root,
            recorded_at_height,
        );
        let record = Self {
            record_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            record_root,
            recorded_at_height,
            payload: payload.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "record_root": self.record_root,
            "recorded_at_height": self.recorded_at_height,
            "payload": self.payload,
        })
    }

    pub fn validate(&self) -> ConfidentialRouterResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.object_kind, "public record object kind")?;
        ensure_non_empty(&self.object_id, "public record object id")?;
        ensure_non_empty(&self.record_root, "public record root")?;
        let expected_root =
            confidential_router_payload_root("public_record_payload", &self.payload);
        if self.record_root != expected_root {
            return Err("public record root mismatch".to_string());
        }
        let expected_id = confidential_router_public_record_id(
            &self.object_kind,
            &self.object_id,
            &self.record_root,
            self.recorded_at_height,
        );
        if self.record_id != expected_id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouterStateRoots {
    pub config_root: String,
    pub encrypted_intent_root: String,
    pub route_leg_root: String,
    pub rfq_quote_root: String,
    pub solver_commitment_root: String,
    pub batch_auction_root: String,
    pub batch_order_root: String,
    pub slippage_guard_root: String,
    pub fee_sponsorship_root: String,
    pub privacy_budget_root: String,
    pub privacy_budget_reservation_root: String,
    pub settlement_receipt_root: String,
    pub public_record_root: String,
}

impl ConfidentialRouterStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_router_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "route_leg_root": self.route_leg_root,
            "rfq_quote_root": self.rfq_quote_root,
            "solver_commitment_root": self.solver_commitment_root,
            "batch_auction_root": self.batch_auction_root,
            "batch_order_root": self.batch_order_root,
            "slippage_guard_root": self.slippage_guard_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "privacy_budget_root": self.privacy_budget_root,
            "privacy_budget_reservation_root": self.privacy_budget_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_router_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouterState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialRouterConfig,
    pub encrypted_intents: BTreeMap<String, EncryptedRouteIntent>,
    pub route_legs: BTreeMap<String, ConfidentialRouteLeg>,
    pub rfq_quotes: BTreeMap<String, PrivateRfqQuote>,
    pub solver_commitments: BTreeMap<String, SolverRouteCommitment>,
    pub batch_auctions: BTreeMap<String, ConfidentialBatchAuction>,
    pub batch_orders: BTreeMap<String, AntiMevBatchOrder>,
    pub slippage_guards: BTreeMap<String, SlippageGuard>,
    pub fee_sponsorships: BTreeMap<String, FeeSponsorship>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub privacy_budget_reservations: BTreeMap<String, PrivacyBudgetReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub public_records: BTreeMap<String, ConfidentialRouterPublicRecord>,
}

impl Default for ConfidentialRouterState {
    fn default() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialRouterConfig::default(),
            encrypted_intents: BTreeMap::new(),
            route_legs: BTreeMap::new(),
            rfq_quotes: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            batch_auctions: BTreeMap::new(),
            batch_orders: BTreeMap::new(),
            slippage_guards: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            privacy_budget_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl ConfidentialRouterState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: ConfidentialRouterConfig) -> ConfidentialRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> ConfidentialRouterResult<Self> {
        let mut state = Self::new();
        state.set_height(CONFIDENTIAL_ROUTER_DEVNET_HEIGHT);

        let budget = PrivacyBudget::new(
            "devnet-alice-router",
            RoutingPrivacyClass::Shielded,
            0,
            0,
            state.config.default_privacy_epoch_blocks,
            state.config.default_privacy_budget_units,
            &json!({
                "mode": "devnet",
                "disclosure": "aggregate_only",
                "view_key_policy": "devnet-auditor-threshold"
            }),
        )?;
        let budget_id = budget.budget_id.clone();
        state.insert_privacy_budget(budget)?;

        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let default_fee_asset_id = state.config.default_fee_asset_id.clone();
        let default_settlement_ttl_blocks = state.config.default_settlement_ttl_blocks;
        let sponsorship_nonce = state.next_nonce();
        let mut sponsorship = FeeSponsorship::new(
            "devnet-router-paymaster",
            FeeSponsorshipMode::Paymaster,
            &default_low_fee_lane,
            &default_fee_asset_id,
            180_000,
            &json!({
                "policy": "low_fee_confidential_swap",
                "max_fee_per_route": 60_000_u64,
                "solver_rebate": true
            }),
            state.height,
            state.height + default_settlement_ttl_blocks,
            sponsorship_nonce,
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();

        let route_policy = json!({
            "max_legs": 6_u64,
            "allowed_modules": [
                "private_rfq",
                "token_factory",
                "lending_market",
                "state_channels"
            ],
            "anti_mev": CONFIDENTIAL_ROUTER_ORDERING_POLICY,
            "fee_lane": state.config.default_low_fee_lane,
        });
        let encrypted_payload = json!({
            "intent": "swap_and_supply",
            "asset_in": "wxmr-devnet",
            "asset_out": "usdd-devnet",
            "amount_in": 42_000_000_u64,
            "min_amount_out": 7_520_000_000_u64,
            "recipient": "devnet-alice-shielded-note",
            "memo": "devnet confidential router fixture"
        });
        let intent = EncryptedRouteIntent::new(
            "devnet-alice-router",
            "devnet-alice-session-1",
            RouteIntentKind::CollateralizedBorrow,
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000,
            7_520_000_000,
            75,
            &route_policy,
            &encrypted_payload,
            &sponsorship_id,
            &budget_id,
            state.height,
            state.height + state.config.default_intent_ttl_blocks,
            state.next_nonce(),
        )?;
        let intent_id = intent.intent_id.clone();
        sponsorship.bind_object(&intent_id)?;
        state.insert_fee_sponsorship(sponsorship)?;
        state.insert_encrypted_intent(intent)?;

        let route_id = confidential_router_route_id(&intent_id, "devnet-route", state.height, 1);
        let channel_open_leg = ConfidentialRouteLeg::state_channel_leg(
            &route_id,
            &intent_id,
            0,
            "open",
            "devnet-private-rfq-channel",
            "wxmr-devnet",
            "wxmr-devnet",
            42_000_000,
            42_000_000,
            8_000,
            &json!({
                "counterparty": "devnet-solver-1",
                "challenge_window_blocks": 48_u64
            }),
            &[],
            state.height,
            state.next_nonce(),
        )?;
        let channel_open_id = channel_open_leg.leg_id.clone();
        state.insert_route_leg(channel_open_leg)?;

        let rfq_leg = ConfidentialRouteLeg::new(
            &route_id,
            &intent_id,
            1,
            RouteLegKind::RfqFill,
            RoutingPrivacyClass::Shielded,
            "devnet-solver-rfq-vault",
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000,
            7_560_000_000,
            15_000,
            &json!({
                "module": "private_rfq",
                "pair": "wxmr/usdd",
                "settlement": "atomic_note_swap"
            }),
            std::slice::from_ref(&channel_open_id),
            state.height,
            state.next_nonce(),
        )?;
        let rfq_leg_id = rfq_leg.leg_id.clone();
        state.insert_route_leg(rfq_leg)?;

        let token_factory_leg = ConfidentialRouteLeg::token_factory_leg(
            &route_id,
            &intent_id,
            2,
            "mint",
            "devnet-token-factory",
            "usdd-devnet",
            "router-receipt-devnet",
            7_560_000_000,
            7_560_000_000,
            5_000,
            &json!({
                "receipt_asset": "router-receipt-devnet",
                "confidentiality": "commitment_only"
            }),
            std::slice::from_ref(&rfq_leg_id),
            state.height,
            state.next_nonce(),
        )?;
        let token_leg_id = token_factory_leg.leg_id.clone();
        state.insert_route_leg(token_factory_leg)?;

        let lending_leg = ConfidentialRouteLeg::lending_leg(
            &route_id,
            &intent_id,
            3,
            "supply",
            "devnet-wxmr-usdd-lending",
            "usdd-devnet",
            "ausdd-devnet",
            7_540_000_000,
            7_500_000_000,
            12_000,
            &json!({
                "market": "private_usdd_supply",
                "health_bucket": "core"
            }),
            std::slice::from_ref(&token_leg_id),
            state.height,
            state.next_nonce(),
        )?;
        let lending_leg_id = lending_leg.leg_id.clone();
        state.insert_route_leg(lending_leg)?;

        let channel_update_leg = ConfidentialRouteLeg::state_channel_leg(
            &route_id,
            &intent_id,
            4,
            "update",
            "devnet-private-rfq-channel",
            "ausdd-devnet",
            "ausdd-devnet",
            7_500_000_000,
            7_500_000_000,
            4_000,
            &json!({
                "update_kind": "settlement_commitment",
                "watchtower": "devnet-watchtower-a"
            }),
            std::slice::from_ref(&lending_leg_id),
            state.height,
            state.next_nonce(),
        )?;
        state.insert_route_leg(channel_update_leg)?;

        let mut auction = ConfidentialBatchAuction::new(
            CONFIDENTIAL_ROUTER_DEFAULT_MARKET_LABEL,
            state.encrypted_intent_root(),
            state.privacy_budget_root(),
            state.fee_sponsorship_root(),
            state.height,
            state.config.default_auction_window_blocks,
            state.config.default_reveal_delay_blocks,
            state.config.default_reveal_window_blocks,
            state.config.default_settlement_ttl_blocks,
            state.config.max_batch_intents,
            state.next_nonce(),
        )?;
        let auction_id = auction.auction_id.clone();
        auction.update_roots(
            state.rfq_quote_root(),
            state.solver_commitment_root(),
            state.route_leg_root(),
            state.privacy_budget_root(),
            state.fee_sponsorship_root(),
        )?;
        state.insert_batch_auction(auction)?;

        let route_legs = state
            .route_legs
            .values()
            .filter(|leg| leg.intent_id == intent_id)
            .cloned()
            .collect::<Vec<_>>();
        let mut quote = PrivateRfqQuote::new(
            &auction_id,
            &intent_id,
            "devnet-solver-1",
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000,
            7_560_000_000,
            44_000,
            180_000_000,
            1,
            &route_legs,
            &json!({
                "solver": "devnet-solver-1",
                "fill": "sealed",
                "price": "180000000/1",
                "route_id": route_id
            }),
            state.height,
            state.height + state.config.default_auction_window_blocks,
            state.next_nonce(),
        )?;
        let quote_commitment_root = quote.quote_commitment_root();
        let solver = SolverRouteCommitment::new(
            &auction_id,
            "devnet-solver-1",
            quote_commitment_root,
            &json!({
                "route": "rfq-token_factory-lending-state_channel",
                "privacy": "shielded",
                "execution": "batch_auction"
            }),
            &route_legs,
            "wxmr-devnet",
            1_250_000,
            8_000,
            &json!({
                "preferred_batch": "devnet-confidential-router",
                "max_intents": 64_u64
            }),
            state.height + 1,
            state.height
                + state.config.default_auction_window_blocks
                + state.config.default_reveal_delay_blocks,
            state.next_nonce(),
        )?;
        let solver_id = solver.commitment_id.clone();
        quote.bind_solver_commitment(&solver_id)?;
        let quote_id = quote.quote_id.clone();
        state.insert_solver_commitment(solver)?;
        state.insert_rfq_quote(quote)?;
        state.refresh_auction_roots(&auction_id)?;

        let guard = SlippageGuard::new(
            &intent_id,
            &quote_id,
            7_560_000_000,
            7_520_000_000,
            75,
            &json!({
                "oracle": "devnet-median-wxmr-usdd",
                "max_staleness_blocks": 12_u64
            }),
            &json!({
                "twap": "devnet-amm-wxmr-usdd-30m",
                "max_deviation_bps": 50_u64
            }),
            state.height,
            state.height + state.config.default_settlement_ttl_blocks,
            "devnet-slippage",
        )?;
        state.insert_slippage_guard(guard)?;

        let batch_order = AntiMevBatchOrder::new(
            &auction_id,
            state.height + state.config.default_auction_window_blocks + 1,
            state
                .batch_auctions
                .get(&auction_id)
                .expect("devnet auction")
                .ordering_seed
                .clone(),
            std::slice::from_ref(&intent_id),
            std::slice::from_ref(&solver_id),
            std::slice::from_ref(&quote_id),
        )?;
        let batch_order_id = batch_order.batch_order_id.clone();
        state.insert_batch_order(batch_order)?;

        let reservation = state.reserve_privacy_budget(
            &budget_id,
            "encrypted_route_intent",
            &intent_id,
            32_000,
            state.height + state.config.default_settlement_ttl_blocks,
        )?;
        state.reserve_fee_sponsorship(&sponsorship_id, 44_000)?;
        let settlement_height = state.height + state.config.default_auction_window_blocks + 2;
        state.consume_privacy_budget(&reservation.reservation_id, settlement_height)?;
        state.spend_fee_sponsorship(&sponsorship_id, 44_000)?;

        let receipt = SettlementReceipt::new(
            &auction_id,
            &batch_order_id,
            &intent_id,
            &quote_id,
            &solver_id,
            &route_legs,
            &[
                json!({"leg": "state_channel_open", "status": "settled"}),
                json!({"leg": "rfq_fill", "status": "settled"}),
                json!({"leg": "token_factory_mint", "status": "settled"}),
                json!({"leg": "lending_supply", "status": "settled"}),
                json!({"leg": "state_channel_update", "status": "settled"}),
            ],
            &[confidential_router_nullifier("devnet-alice-input", 1)],
            &[confidential_router_note_commitment(
                "devnet-alice-output",
                1,
            )],
            &[json!({
                "fee_asset": state.config.default_fee_asset_id,
                "fee_units": 44_000_u64,
                "sponsored": true
            })],
            &[json!({
                "sponsorship_id": sponsorship_id,
                "spent_units": 44_000_u64
            })],
            &[json!({
                "reservation_id": reservation.reservation_id,
                "consumed_units": 32_000_u64
            })],
            42_000_000,
            7_520_000_000,
            40_000_000,
            52,
            settlement_height,
            settlement_height + 6,
            "devnet-settlement",
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_settlement_receipt(receipt)?;

        if let Some(intent) = state.encrypted_intents.get_mut(&intent_id) {
            intent.mark_settled();
        }
        if let Some(quote) = state.rfq_quotes.get_mut(&quote_id) {
            quote.mark_settled();
        }
        if let Some(auction) = state.batch_auctions.get_mut(&auction_id) {
            auction.status = CONFIDENTIAL_ROUTER_STATUS_SETTLED.to_string();
        }

        for (object_kind, object_id, payload) in [
            (
                "encrypted_route_intent",
                intent_id.as_str(),
                state.encrypted_intents[&intent_id].public_record(),
            ),
            (
                "batch_auction",
                auction_id.as_str(),
                state.batch_auctions[&auction_id].public_record(),
            ),
            (
                "solver_commitment",
                solver_id.as_str(),
                state.solver_commitments[&solver_id].public_record(),
            ),
            (
                "rfq_quote",
                quote_id.as_str(),
                state.rfq_quotes[&quote_id].public_record(),
            ),
            (
                "settlement_receipt",
                receipt_id.as_str(),
                state.settlement_receipts[&receipt_id].public_record(),
            ),
        ] {
            state.publish_public_record(object_kind, object_id, &payload)?;
        }

        state.validate_all()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> ConfidentialRouterResult<u64> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "confidential router height overflow".to_string())?;
        Ok(self.height)
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }

    pub fn insert_encrypted_intent(
        &mut self,
        intent: EncryptedRouteIntent,
    ) -> ConfidentialRouterResult<()> {
        intent.validate()?;
        if !self.privacy_budgets.contains_key(&intent.privacy_budget_id) {
            return Err("encrypted route intent references unknown privacy budget".to_string());
        }
        if !intent.fee_sponsorship_id.is_empty()
            && !self
                .fee_sponsorships
                .contains_key(&intent.fee_sponsorship_id)
        {
            return Err("encrypted route intent references unknown fee sponsorship".to_string());
        }
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    pub fn insert_route_leg(&mut self, leg: ConfidentialRouteLeg) -> ConfidentialRouterResult<()> {
        leg.validate()?;
        if !self.encrypted_intents.contains_key(&leg.intent_id) {
            return Err("route leg references unknown intent".to_string());
        }
        self.route_legs.insert(leg.leg_id.clone(), leg);
        Ok(())
    }

    pub fn insert_rfq_quote(&mut self, quote: PrivateRfqQuote) -> ConfidentialRouterResult<()> {
        quote.validate()?;
        if !self.encrypted_intents.contains_key(&quote.intent_id) {
            return Err("rfq quote references unknown intent".to_string());
        }
        if !self.batch_auctions.contains_key(&quote.auction_id) {
            return Err("rfq quote references unknown auction".to_string());
        }
        if !quote.solver_commitment_id.is_empty()
            && !self
                .solver_commitments
                .contains_key(&quote.solver_commitment_id)
        {
            return Err("rfq quote references unknown solver commitment".to_string());
        }
        self.rfq_quotes.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: SolverRouteCommitment,
    ) -> ConfidentialRouterResult<()> {
        commitment.validate()?;
        if !self.batch_auctions.contains_key(&commitment.auction_id) {
            return Err("solver commitment references unknown auction".to_string());
        }
        self.solver_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_batch_auction(
        &mut self,
        auction: ConfidentialBatchAuction,
    ) -> ConfidentialRouterResult<()> {
        auction.validate()?;
        self.batch_auctions
            .insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_batch_order(&mut self, order: AntiMevBatchOrder) -> ConfidentialRouterResult<()> {
        order.validate()?;
        if !self.batch_auctions.contains_key(&order.auction_id) {
            return Err("anti mev batch order references unknown auction".to_string());
        }
        for intent_id in &order.ordered_intent_ids {
            if !self.encrypted_intents.contains_key(intent_id) {
                return Err("anti mev batch order references unknown intent".to_string());
            }
        }
        for solver_id in &order.ordered_solver_commitment_ids {
            if !self.solver_commitments.contains_key(solver_id) {
                return Err("anti mev batch order references unknown solver commitment".to_string());
            }
        }
        for quote_id in &order.ordered_quote_ids {
            if !self.rfq_quotes.contains_key(quote_id) {
                return Err("anti mev batch order references unknown quote".to_string());
            }
        }
        self.batch_orders
            .insert(order.batch_order_id.clone(), order);
        Ok(())
    }

    pub fn insert_slippage_guard(&mut self, guard: SlippageGuard) -> ConfidentialRouterResult<()> {
        guard.validate()?;
        if !self.encrypted_intents.contains_key(&guard.intent_id) {
            return Err("slippage guard references unknown intent".to_string());
        }
        if !self.rfq_quotes.contains_key(&guard.quote_id) {
            return Err("slippage guard references unknown quote".to_string());
        }
        self.slippage_guards.insert(guard.guard_id.clone(), guard);
        Ok(())
    }

    pub fn insert_fee_sponsorship(
        &mut self,
        sponsorship: FeeSponsorship,
    ) -> ConfidentialRouterResult<()> {
        sponsorship.validate()?;
        self.fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_privacy_budget(&mut self, budget: PrivacyBudget) -> ConfidentialRouterResult<()> {
        budget.validate()?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_privacy_budget_reservation(
        &mut self,
        reservation: PrivacyBudgetReservation,
    ) -> ConfidentialRouterResult<()> {
        reservation.validate()?;
        if !self.privacy_budgets.contains_key(&reservation.budget_id) {
            return Err("privacy budget reservation references unknown budget".to_string());
        }
        self.privacy_budget_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> ConfidentialRouterResult<()> {
        receipt.validate()?;
        if !self.batch_auctions.contains_key(&receipt.auction_id) {
            return Err("settlement receipt references unknown auction".to_string());
        }
        if !self.batch_orders.contains_key(&receipt.batch_order_id) {
            return Err("settlement receipt references unknown batch order".to_string());
        }
        if !self.encrypted_intents.contains_key(&receipt.intent_id) {
            return Err("settlement receipt references unknown intent".to_string());
        }
        if !self.rfq_quotes.contains_key(&receipt.quote_id) {
            return Err("settlement receipt references unknown quote".to_string());
        }
        if !self
            .solver_commitments
            .contains_key(&receipt.solver_commitment_id)
        {
            return Err("settlement receipt references unknown solver commitment".to_string());
        }
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn reserve_privacy_budget(
        &mut self,
        budget_id: &str,
        object_kind: &str,
        object_id: &str,
        units: u64,
        expires_height: u64,
    ) -> ConfidentialRouterResult<PrivacyBudgetReservation> {
        if !self.privacy_budgets.contains_key(budget_id) {
            return Err("unknown privacy budget".to_string());
        }
        let reservation = PrivacyBudgetReservation::new(
            budget_id,
            object_kind,
            object_id,
            units,
            self.height,
            expires_height,
        )?;
        self.privacy_budgets
            .get_mut(budget_id)
            .expect("privacy budget checked")
            .reserve(units)?;
        self.insert_privacy_budget_reservation(reservation.clone())?;
        Ok(reservation)
    }

    pub fn consume_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> ConfidentialRouterResult<()> {
        let (budget_id, units) = {
            let reservation = self
                .privacy_budget_reservations
                .get(reservation_id)
                .ok_or_else(|| "unknown privacy budget reservation".to_string())?;
            (reservation.budget_id.clone(), reservation.units)
        };
        self.privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?
            .consume_reserved(units)?;
        self.privacy_budget_reservations
            .get_mut(reservation_id)
            .expect("privacy budget reservation checked")
            .mark_consumed(height)?;
        Ok(())
    }

    pub fn release_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> ConfidentialRouterResult<()> {
        let (budget_id, units) = {
            let reservation = self
                .privacy_budget_reservations
                .get(reservation_id)
                .ok_or_else(|| "unknown privacy budget reservation".to_string())?;
            (reservation.budget_id.clone(), reservation.units)
        };
        self.privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?
            .release_reserved(units)?;
        self.privacy_budget_reservations
            .get_mut(reservation_id)
            .expect("privacy budget reservation checked")
            .mark_released(height)?;
        Ok(())
    }

    pub fn reserve_fee_sponsorship(
        &mut self,
        sponsorship_id: &str,
        units: u64,
    ) -> ConfidentialRouterResult<()> {
        self.fee_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown fee sponsorship".to_string())?
            .reserve(units)
    }

    pub fn spend_fee_sponsorship(
        &mut self,
        sponsorship_id: &str,
        units: u64,
    ) -> ConfidentialRouterResult<()> {
        self.fee_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown fee sponsorship".to_string())?
            .spend_reserved(units)
    }

    pub fn refresh_auction_roots(&mut self, auction_id: &str) -> ConfidentialRouterResult<()> {
        let quotes = self
            .rfq_quotes
            .values()
            .filter(|quote| quote.auction_id == auction_id)
            .cloned()
            .collect::<Vec<_>>();
        let solvers = self
            .solver_commitments
            .values()
            .filter(|solver| solver.auction_id == auction_id)
            .cloned()
            .collect::<Vec<_>>();
        let route_legs = self.route_legs.values().cloned().collect::<Vec<_>>();
        let rfq_quote_root = confidential_router_rfq_quote_root(&quotes);
        let solver_commitment_root = confidential_router_solver_route_commitment_root(&solvers);
        let route_leg_root = confidential_router_route_leg_root(&route_legs);
        let privacy_budget_root = self.privacy_budget_root();
        let fee_sponsorship_root = self.fee_sponsorship_root();
        let auction = self
            .batch_auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown batch auction".to_string())?;
        auction.update_roots(
            rfq_quote_root,
            solver_commitment_root,
            route_leg_root,
            privacy_budget_root,
            fee_sponsorship_root,
        )
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: &Value,
    ) -> ConfidentialRouterResult<ConfidentialRouterPublicRecord> {
        let record =
            ConfidentialRouterPublicRecord::new(object_kind, object_id, payload, self.height)?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn encrypted_intent_root(&self) -> String {
        confidential_router_encrypted_intent_root(
            &self.encrypted_intents.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn route_leg_root(&self) -> String {
        confidential_router_route_leg_root(&self.route_legs.values().cloned().collect::<Vec<_>>())
    }

    pub fn rfq_quote_root(&self) -> String {
        confidential_router_rfq_quote_root(&self.rfq_quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn solver_commitment_root(&self) -> String {
        confidential_router_solver_route_commitment_root(
            &self
                .solver_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_auction_root(&self) -> String {
        confidential_router_batch_auction_root(
            &self.batch_auctions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn batch_order_root(&self) -> String {
        confidential_router_batch_order_root(
            &self.batch_orders.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn slippage_guard_root(&self) -> String {
        confidential_router_slippage_guard_root(
            &self.slippage_guards.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn fee_sponsorship_root(&self) -> String {
        confidential_router_fee_sponsorship_root(
            &self.fee_sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn privacy_budget_root(&self) -> String {
        confidential_router_privacy_budget_root(
            &self.privacy_budgets.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn privacy_budget_reservation_root(&self) -> String {
        confidential_router_privacy_budget_reservation_root(
            &self
                .privacy_budget_reservations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        confidential_router_settlement_receipt_root(
            &self
                .settlement_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        confidential_router_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> ConfidentialRouterStateRoots {
        ConfidentialRouterStateRoots {
            config_root: self.config.config_root(),
            encrypted_intent_root: self.encrypted_intent_root(),
            route_leg_root: self.route_leg_root(),
            rfq_quote_root: self.rfq_quote_root(),
            solver_commitment_root: self.solver_commitment_root(),
            batch_auction_root: self.batch_auction_root(),
            batch_order_root: self.batch_order_root(),
            slippage_guard_root: self.slippage_guard_root(),
            fee_sponsorship_root: self.fee_sponsorship_root(),
            privacy_budget_root: self.privacy_budget_root(),
            privacy_budget_reservation_root: self.privacy_budget_reservation_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "confidential_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config_id": self.config.config_id,
            "encrypted_intent_count": self.encrypted_intents.len(),
            "route_leg_count": self.route_legs.len(),
            "rfq_quote_count": self.rfq_quotes.len(),
            "solver_commitment_count": self.solver_commitments.len(),
            "batch_auction_count": self.batch_auctions.len(),
            "batch_order_count": self.batch_orders.len(),
            "slippage_guard_count": self.slippage_guards.len(),
            "fee_sponsorship_count": self.fee_sponsorships.len(),
            "privacy_budget_count": self.privacy_budgets.len(),
            "privacy_budget_reservation_count": self.privacy_budget_reservations.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
            "public_record_count": self.public_records.len(),
            "roots": roots.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        confidential_router_state_root_from_record(&self.public_record())
    }

    pub fn validate_all(&self) -> ConfidentialRouterResult<String> {
        self.config.validate()?;
        for budget in self.privacy_budgets.values() {
            budget.validate()?;
        }
        for sponsorship in self.fee_sponsorships.values() {
            sponsorship.validate()?;
        }
        for intent in self.encrypted_intents.values() {
            intent.validate()?;
            if !self.privacy_budgets.contains_key(&intent.privacy_budget_id) {
                return Err("state intent references unknown privacy budget".to_string());
            }
            if !intent.fee_sponsorship_id.is_empty()
                && !self
                    .fee_sponsorships
                    .contains_key(&intent.fee_sponsorship_id)
            {
                return Err("state intent references unknown fee sponsorship".to_string());
            }
        }
        let mut route_indexes = BTreeSet::new();
        for leg in self.route_legs.values() {
            leg.validate()?;
            if !self.encrypted_intents.contains_key(&leg.intent_id) {
                return Err("state route leg references unknown intent".to_string());
            }
            if !route_indexes.insert((leg.route_id.clone(), leg.leg_index)) {
                return Err("state route contains duplicate leg index".to_string());
            }
        }
        for auction in self.batch_auctions.values() {
            auction.validate()?;
        }
        for solver in self.solver_commitments.values() {
            solver.validate()?;
            if !self.batch_auctions.contains_key(&solver.auction_id) {
                return Err("state solver commitment references unknown auction".to_string());
            }
        }
        for quote in self.rfq_quotes.values() {
            quote.validate()?;
            if !self.encrypted_intents.contains_key(&quote.intent_id) {
                return Err("state quote references unknown intent".to_string());
            }
            if !self.batch_auctions.contains_key(&quote.auction_id) {
                return Err("state quote references unknown auction".to_string());
            }
            if !quote.solver_commitment_id.is_empty()
                && !self
                    .solver_commitments
                    .contains_key(&quote.solver_commitment_id)
            {
                return Err("state quote references unknown solver commitment".to_string());
            }
        }
        for guard in self.slippage_guards.values() {
            guard.validate()?;
            if !self.encrypted_intents.contains_key(&guard.intent_id) {
                return Err("state slippage guard references unknown intent".to_string());
            }
            if !self.rfq_quotes.contains_key(&guard.quote_id) {
                return Err("state slippage guard references unknown quote".to_string());
            }
        }
        for reservation in self.privacy_budget_reservations.values() {
            reservation.validate()?;
            if !self.privacy_budgets.contains_key(&reservation.budget_id) {
                return Err("state privacy reservation references unknown budget".to_string());
            }
        }
        for order in self.batch_orders.values() {
            order.validate()?;
            if !self.batch_auctions.contains_key(&order.auction_id) {
                return Err("state batch order references unknown auction".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.batch_auctions.contains_key(&receipt.auction_id) {
                return Err("state settlement receipt references unknown auction".to_string());
            }
            if !self.batch_orders.contains_key(&receipt.batch_order_id) {
                return Err("state settlement receipt references unknown batch order".to_string());
            }
            if !self.encrypted_intents.contains_key(&receipt.intent_id) {
                return Err("state settlement receipt references unknown intent".to_string());
            }
            if !self.rfq_quotes.contains_key(&receipt.quote_id) {
                return Err("state settlement receipt references unknown quote".to_string());
            }
            if !self
                .solver_commitments
                .contains_key(&receipt.solver_commitment_id)
            {
                return Err(
                    "state settlement receipt references unknown solver commitment".to_string(),
                );
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn confidential_router_account_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ACCOUNT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_router_session_commitment(label: &str, nonce: u64) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-SESSION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_solver_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-SOLVER",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_router_market_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-MARKET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_router_venue_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-VENUE",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_router_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ASSET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn confidential_router_asset_pair_commitment(asset_in_id: &str, asset_out_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ASSET-PAIR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
        ],
        32,
    )
}

pub fn confidential_router_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-AMOUNT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_router_price_commitment(
    numerator: u64,
    denominator: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-PRICE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(numerator as i128),
            HashPart::Int(denominator as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_router_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn confidential_router_config_id(config_record_without_id: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(config_record_without_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_intent_id(
    intent_kind: RouteIntentKind,
    owner_commitment: &str,
    session_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    min_amount_out_commitment: &str,
    max_slippage_bps: u64,
    route_policy_root: &str,
    privacy_budget_id: &str,
    submission_height: u64,
    deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(session_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(min_amount_out_commitment),
            HashPart::Int(max_slippage_bps as i128),
            HashPart::Str(route_policy_root),
            HashPart::Str(privacy_budget_id),
            HashPart::Int(submission_height as i128),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_route_id(
    intent_id: &str,
    route_label: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(route_label),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_route_leg_id(
    route_id: &str,
    intent_id: &str,
    leg_index: u16,
    leg_kind: RouteLegKind,
    privacy_class: RoutingPrivacyClass,
    venue_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    min_amount_out_commitment: &str,
    fee_commitment: &str,
    leg_payload_root: &str,
    dependency_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ROUTE-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(intent_id),
            HashPart::Int(leg_index as i128),
            HashPart::Str(leg_kind.as_str()),
            HashPart::Str(privacy_class.as_str()),
            HashPart::Str(venue_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(min_amount_out_commitment),
            HashPart::Str(fee_commitment),
            HashPart::Str(leg_payload_root),
            HashPart::Str(dependency_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_rfq_quote_id(
    auction_id: &str,
    intent_id: &str,
    solver_commitment: &str,
    asset_pair_commitment: &str,
    input_amount_commitment: &str,
    output_amount_commitment: &str,
    fee_commitment: &str,
    price_commitment: &str,
    route_leg_root: &str,
    validity_start_height: u64,
    expires_height: u64,
    quote_nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-RFQ-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(intent_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(asset_pair_commitment),
            HashPart::Str(input_amount_commitment),
            HashPart::Str(output_amount_commitment),
            HashPart::Str(fee_commitment),
            HashPart::Str(price_commitment),
            HashPart::Str(route_leg_root),
            HashPart::Int(validity_start_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Int(quote_nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_solver_route_commitment_id(
    auction_id: &str,
    solver_commitment: &str,
    quote_commitment_root: &str,
    route_plan_root: &str,
    route_leg_root: &str,
    collateral_asset_commitment: &str,
    bond_amount_commitment: &str,
    fee_rebate_commitment: &str,
    commit_height: u64,
    reveal_deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-SOLVER-ROUTE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(quote_commitment_root),
            HashPart::Str(route_plan_root),
            HashPart::Str(route_leg_root),
            HashPart::Str(collateral_asset_commitment),
            HashPart::Str(bond_amount_commitment),
            HashPart::Str(fee_rebate_commitment),
            HashPart::Int(commit_height as i128),
            HashPart::Int(reveal_deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_batch_auction_id(
    market_commitment: &str,
    intent_root: &str,
    commit_start_height: u64,
    commit_end_height: u64,
    reveal_start_height: u64,
    reveal_end_height: u64,
    ordering_seed: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-BATCH-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_commitment),
            HashPart::Str(intent_root),
            HashPart::Int(commit_start_height as i128),
            HashPart::Int(commit_end_height as i128),
            HashPart::Int(reveal_start_height as i128),
            HashPart::Int(reveal_end_height as i128),
            HashPart::Str(ordering_seed),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_ordering_seed(
    market_label: &str,
    height: u64,
    intent_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_label),
            HashPart::Int(height as i128),
            HashPart::Str(intent_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_mev_order_key(
    auction_id: &str,
    ordering_seed: &str,
    object_id: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-MEV-ORDER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(ordering_seed),
            HashPart::Str(object_id),
        ],
        32,
    )
}

pub fn confidential_router_anti_mev_order(
    auction_id: &str,
    ordering_seed: &str,
    object_ids: &[String],
) -> Vec<String> {
    let mut keyed = object_ids
        .iter()
        .map(|object_id| {
            (
                confidential_router_mev_order_key(auction_id, ordering_seed, object_id),
                object_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    keyed.sort();
    keyed.into_iter().map(|(_, object_id)| object_id).collect()
}

pub fn confidential_router_tie_breaker_root(
    auction_id: &str,
    ordering_seed: &str,
    intent_ids: &[String],
    solver_commitment_ids: &[String],
    quote_ids: &[String],
) -> String {
    let mut leaves = Vec::new();
    for object_id in intent_ids {
        leaves.push(json!({
            "object_kind": "intent",
            "object_id": object_id,
            "order_key": confidential_router_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in solver_commitment_ids {
        leaves.push(json!({
            "object_kind": "solver_commitment",
            "object_id": object_id,
            "order_key": confidential_router_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in quote_ids {
        leaves.push(json!({
            "object_kind": "rfq_quote",
            "object_id": object_id,
            "order_key": confidential_router_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    merkle_root("CONFIDENTIAL-ROUTER-TIE-BREAKER", &leaves)
}

pub fn confidential_router_batch_order_id(
    auction_id: &str,
    batch_height: u64,
    ordering_seed: &str,
    intent_order_root: &str,
    solver_order_root: &str,
    quote_order_root: &str,
    tie_breaker_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-BATCH-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Int(batch_height as i128),
            HashPart::Str(ordering_seed),
            HashPart::Str(intent_order_root),
            HashPart::Str(solver_order_root),
            HashPart::Str(quote_order_root),
            HashPart::Str(tie_breaker_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_slippage_guard_id(
    intent_id: &str,
    quote_id: &str,
    max_slippage_bps: u64,
    expected_amount_out_commitment: &str,
    min_amount_out_commitment: &str,
    oracle_guard_root: &str,
    twap_guard_root: &str,
    created_at_height: u64,
    expires_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-SLIPPAGE-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Int(max_slippage_bps as i128),
            HashPart::Str(expected_amount_out_commitment),
            HashPart::Str(min_amount_out_commitment),
            HashPart::Str(oracle_guard_root),
            HashPart::Str(twap_guard_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_fee_sponsorship_id(
    sponsor_commitment: &str,
    mode: FeeSponsorshipMode,
    low_fee_lane: &str,
    fee_asset_id: &str,
    max_fee_units: u64,
    paymaster_policy_root: &str,
    starts_at_height: u64,
    expires_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Str(low_fee_lane),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Str(paymaster_policy_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_privacy_budget_id(
    owner_commitment: &str,
    privacy_class: RoutingPrivacyClass,
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    total_units: u64,
    audit_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(privacy_class.as_str()),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Int(total_units as i128),
            HashPart::Str(audit_root),
        ],
        32,
    )
}

pub fn confidential_router_privacy_budget_reservation_id(
    budget_id: &str,
    object_kind: &str,
    object_id: &str,
    units: u64,
    reserved_at_height: u64,
    expires_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-PRIVACY-BUDGET-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(budget_id),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(units as i128),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_router_settlement_receipt_id(
    auction_id: &str,
    batch_order_id: &str,
    intent_id: &str,
    quote_id: &str,
    solver_commitment_id: &str,
    route_root: &str,
    input_nullifier_root: &str,
    output_commitment_root: &str,
    fee_receipt_root: &str,
    sponsorship_receipt_root: &str,
    privacy_budget_receipt_root: &str,
    amount_in_commitment: &str,
    amount_out_commitment: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(batch_order_id),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(solver_commitment_id),
            HashPart::Str(route_root),
            HashPart::Str(input_nullifier_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(sponsorship_receipt_root),
            HashPart::Str(privacy_budget_receipt_root),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_commitment),
            HashPart::Int(settlement_height as i128),
        ],
        32,
    )
}

pub fn confidential_router_public_record_id(
    object_kind: &str,
    object_id: &str,
    record_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(record_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_router_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn confidential_router_blinding(label: &str, nonce: u64, purpose: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn confidential_router_nullifier(label: &str, nonce: u64) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_note_commitment(label: &str, nonce: u64) -> String {
    domain_hash(
        "CONFIDENTIAL-ROUTER-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_router_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    let leaves = ordered.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(
        &format!("CONFIDENTIAL-ROUTER-{}", domain.to_ascii_uppercase()),
        &leaves,
    )
}

pub fn confidential_router_ordered_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| json!({"index": index, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "CONFIDENTIAL-ROUTER-ORDERED-{}",
            domain.to_ascii_uppercase()
        ),
        &leaves,
    )
}

pub fn confidential_router_encrypted_intent_root(intents: &[EncryptedRouteIntent]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-ENCRYPTED-INTENT",
        &intents
            .iter()
            .map(EncryptedRouteIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_route_leg_root(route_legs: &[ConfidentialRouteLeg]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-ROUTE-LEG",
        &route_legs
            .iter()
            .map(ConfidentialRouteLeg::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_rfq_quote_root(quotes: &[PrivateRfqQuote]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-RFQ-QUOTE",
        &quotes
            .iter()
            .map(PrivateRfqQuote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_solver_route_commitment_root(
    commitments: &[SolverRouteCommitment],
) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-SOLVER-ROUTE-COMMITMENT",
        &commitments
            .iter()
            .map(SolverRouteCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_batch_auction_root(auctions: &[ConfidentialBatchAuction]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-BATCH-AUCTION",
        &auctions
            .iter()
            .map(ConfidentialBatchAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_batch_order_root(orders: &[AntiMevBatchOrder]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-BATCH-ORDER",
        &orders
            .iter()
            .map(AntiMevBatchOrder::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_slippage_guard_root(guards: &[SlippageGuard]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-SLIPPAGE-GUARD",
        &guards
            .iter()
            .map(SlippageGuard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_fee_sponsorship_root(sponsorships: &[FeeSponsorship]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-FEE-SPONSORSHIP",
        &sponsorships
            .iter()
            .map(FeeSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_privacy_budget_root(budgets: &[PrivacyBudget]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-PRIVACY-BUDGET",
        &budgets
            .iter()
            .map(PrivacyBudget::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_privacy_budget_reservation_root(
    reservations: &[PrivacyBudgetReservation],
) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-PRIVACY-BUDGET-RESERVATION",
        &reservations
            .iter()
            .map(PrivacyBudgetReservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_settlement_receipt_root(receipts: &[SettlementReceipt]) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-SETTLEMENT-RECEIPT",
        &receipts
            .iter()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_public_record_root(
    records: &[ConfidentialRouterPublicRecord],
) -> String {
    merkle_root(
        "CONFIDENTIAL-ROUTER-PUBLIC-RECORD",
        &records
            .iter()
            .map(ConfidentialRouterPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_router_validate_non_empty(
    value: &str,
    field: &str,
) -> ConfidentialRouterResult<()> {
    ensure_non_empty(value, field)
}

pub fn confidential_router_validate_positive(
    value: u64,
    field: &str,
) -> ConfidentialRouterResult<()> {
    ensure_positive(value, field)
}

pub fn confidential_router_validate_bps(value: u64, field: &str) -> ConfidentialRouterResult<()> {
    ensure_bps(value, field)
}

pub fn confidential_router_validate_status(
    status: &str,
    allowed: &[&str],
) -> ConfidentialRouterResult<()> {
    ensure_status(status, allowed)
}

pub fn confidential_router_validate_distinct_strings(
    values: &[String],
    field: &str,
) -> ConfidentialRouterResult<()> {
    ensure_distinct_strings(values, field)
}

pub fn confidential_router_validate_route_leg_count(count: usize) -> ConfidentialRouterResult<()> {
    ensure_route_leg_count(count)
}

fn ensure_non_empty(value: &str, field: &str) -> ConfidentialRouterResult<()> {
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    Ok(())
}

fn ensure_positive(value: u64, field: &str) -> ConfidentialRouterResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, field: &str) -> ConfidentialRouterResult<()> {
    if value > CONFIDENTIAL_ROUTER_MAX_BPS {
        return Err(format!("{field} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_status(status: &str, allowed: &[&str]) -> ConfidentialRouterResult<()> {
    if allowed.iter().any(|allowed| allowed == &status) {
        Ok(())
    } else {
        Err(format!("status {status} is invalid"))
    }
}

fn ensure_distinct_strings(values: &[String], field: &str) -> ConfidentialRouterResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} contains an empty value"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_route_leg_count(count: usize) -> ConfidentialRouterResult<()> {
    if count == 0 {
        return Err("route requires at least one leg".to_string());
    }
    if count > CONFIDENTIAL_ROUTER_MAX_ROUTE_LEGS {
        return Err("route has too many legs".to_string());
    }
    Ok(())
}
