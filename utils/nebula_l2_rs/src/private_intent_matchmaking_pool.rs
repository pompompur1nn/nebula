use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateIntentMatchmakingPoolResult<T> = Result<T, String>;

pub const PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION: &str =
    "nebula-private-intent-matchmaking-pool-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-threshold-intent-envelope-devnet-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-private-defi-intent-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-solver-authorization-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_RECEIPT_SCHEME: &str =
    "zk-settlement-receipt-nullifier-devnet-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_AUCTION_POLICY: &str =
    "sealed-uniform-clearing-batch-auction-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY: &str =
    "commit-reveal-threshold-decrypt-no-backrun-v1";
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 16;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 720;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 250_000;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6_500;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_SURPLUS_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS: u64 = 10_000;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_INTENTS: usize = 16_384;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVERS: usize = 512;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_AUCTIONS: usize = 2_048;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVER_COMMITMENTS: usize = 16_384;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_MATCHES: usize = 32_768;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_RECEIPTS: usize = 65_536;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_REBATES: usize = 32_768;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEVNET_HEIGHT: u64 = 240;
pub const PRIVATE_INTENT_MATCHMAKING_POOL_DEVNET_LOW_FEE_LANE: &str = "devnet-private-defi-low-fee";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateIntentKind {
    SwapExactIn,
    SwapExactOut,
    LendSupply,
    LendBorrow,
    LendRepay,
    LendWithdraw,
    BridgeIn,
    BridgeOut,
    Composite,
    Custom(String),
}

impl PrivateIntentKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::SwapExactOut => "swap_exact_out".to_string(),
            Self::LendSupply => "lend_supply".to_string(),
            Self::LendBorrow => "lend_borrow".to_string(),
            Self::LendRepay => "lend_repay".to_string(),
            Self::LendWithdraw => "lend_withdraw".to_string(),
            Self::BridgeIn => "bridge_in".to_string(),
            Self::BridgeOut => "bridge_out".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_swap(&self) -> bool {
        matches!(self, Self::SwapExactIn | Self::SwapExactOut)
    }

    pub fn is_lend(&self) -> bool {
        matches!(
            self,
            Self::LendSupply | Self::LendBorrow | Self::LendRepay | Self::LendWithdraw
        )
    }

    pub fn is_bridge(&self) -> bool {
        matches!(self, Self::BridgeIn | Self::BridgeOut)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentVisibilityClass {
    FullyShielded,
    AmountBucketed,
    RouteHinted,
    SolverScoped,
}

impl IntentVisibilityClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AmountBucketed => "amount_bucketed",
            Self::RouteHinted => "route_hinted",
            Self::SolverScoped => "solver_scoped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Eligible,
    Matched,
    PartiallySettled,
    Settled,
    Cancelled,
    Expired,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Eligible => "eligible",
            Self::Matched => "matched",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn active(&self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Eligible | Self::Matched | Self::PartiallySettled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Collecting,
    CommitClosed,
    Revealing,
    Cleared,
    Settling,
    Settled,
    Expired,
    Challenged,
}

impl AuctionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::CommitClosed => "commit_closed",
            Self::Revealing => "revealing",
            Self::Cleared => "cleared",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(&self) -> bool {
        matches!(
            self,
            Self::Collecting
                | Self::CommitClosed
                | Self::Revealing
                | Self::Cleared
                | Self::Settling
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverAuthorizationStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl SolverAuthorizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Submitted,
    Selected,
    Revealed,
    Settled,
    Slashed,
    Expired,
    Rejected,
}

impl SolverCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Selected => "selected",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    Proposed,
    Cleared,
    ReceiptIssued,
    Finalized,
    Challenged,
    Voided,
}

impl MatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Cleared => "cleared",
            Self::ReceiptIssued => "receipt_issued",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Voided => "voided",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PendingDelay,
    Published,
    Final,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingDelay => "pending_delay",
            Self::Published => "published",
            Self::Final => "final",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentMatchmakingPoolConfig {
    pub pool_id: String,
    pub operator_committee_root: String,
    pub threshold_key_epoch_root: String,
    pub auction_window_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub solver_auth_ttl_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub min_solver_bond_units: u64,
    pub low_fee_rebate_bps: u64,
    pub surplus_rebate_bps: u64,
    pub max_batch_intents: usize,
    pub max_solver_commitments_per_auction: usize,
    pub default_low_fee_lane: String,
    pub mev_policy_root: String,
}

impl Default for PrivateIntentMatchmakingPoolConfig {
    fn default() -> Self {
        Self {
            pool_id: private_intent_matchmaking_pool_string_root("pool", "default-private-defi"),
            operator_committee_root: private_intent_matchmaking_pool_string_root(
                "committee",
                "default-devnet-committee",
            ),
            threshold_key_epoch_root: private_intent_matchmaking_pool_string_root(
                "threshold-key-epoch",
                "epoch-0",
            ),
            auction_window_blocks: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_AUCTION_WINDOW_BLOCKS,
            reveal_delay_blocks: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_REVEAL_DELAY_BLOCKS,
            settlement_window_blocks:
                PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            intent_ttl_blocks: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_INTENT_TTL_BLOCKS,
            solver_auth_ttl_blocks: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_AUTH_TTL_BLOCKS,
            receipt_delay_blocks: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_RECEIPT_DELAY_BLOCKS,
            min_solver_bond_units: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_MIN_SOLVER_BOND_UNITS,
            low_fee_rebate_bps: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_LOW_FEE_REBATE_BPS,
            surplus_rebate_bps: PRIVATE_INTENT_MATCHMAKING_POOL_DEFAULT_SURPLUS_REBATE_BPS,
            max_batch_intents: 256,
            max_solver_commitments_per_auction: 64,
            default_low_fee_lane: PRIVATE_INTENT_MATCHMAKING_POOL_DEVNET_LOW_FEE_LANE.to_string(),
            mev_policy_root: private_intent_matchmaking_pool_payload_root(
                "DEFAULT-MEV-POLICY",
                &json!({
                    "policy": PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY,
                    "same_solver_backrun": false,
                    "batch_only": true,
                    "uniform_clearing": true
                }),
            ),
        }
    }
}

impl PrivateIntentMatchmakingPoolConfig {
    pub fn devnet() -> Self {
        Self {
            pool_id: private_intent_matchmaking_pool_string_root("pool", "devnet-private-defi"),
            operator_committee_root: private_intent_matchmaking_pool_payload_root(
                "DEVNET-OPERATOR-COMMITTEE",
                &json!({
                    "members": ["devnet-sequencer-a", "devnet-sequencer-b", "devnet-watchtower-c"],
                    "threshold": 2
                }),
            ),
            threshold_key_epoch_root: private_intent_matchmaking_pool_payload_root(
                "DEVNET-THRESHOLD-KEY-EPOCH",
                &json!({
                    "epoch": 3,
                    "scheme": PRIVATE_INTENT_MATCHMAKING_POOL_ENCRYPTION_SCHEME,
                    "shares": 5,
                    "threshold": 3
                }),
            ),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "operator_committee_root": self.operator_committee_root,
            "threshold_key_epoch_root": self.threshold_key_epoch_root,
            "auction_window_blocks": self.auction_window_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "solver_auth_ttl_blocks": self.solver_auth_ttl_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "min_solver_bond_units": self.min_solver_bond_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "surplus_rebate_bps": self.surplus_rebate_bps,
            "max_batch_intents": self.max_batch_intents,
            "max_solver_commitments_per_auction": self.max_solver_commitments_per_auction,
            "default_low_fee_lane": self.default_low_fee_lane,
            "mev_policy_root": self.mev_policy_root,
            "auction_policy": PRIVATE_INTENT_MATCHMAKING_POOL_AUCTION_POLICY,
            "mev_policy": PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY,
        })
    }

    pub fn state_root(&self) -> String {
        private_intent_matchmaking_pool_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.pool_id, "config pool id")?;
        ensure_non_empty(
            &self.operator_committee_root,
            "config operator committee root",
        )?;
        ensure_non_empty(&self.threshold_key_epoch_root, "config threshold key root")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default low fee lane")?;
        ensure_non_empty(&self.mev_policy_root, "config mev policy root")?;
        if self.auction_window_blocks == 0 {
            return Err("config auction window must be positive".to_string());
        }
        if self.settlement_window_blocks == 0 {
            return Err("config settlement window must be positive".to_string());
        }
        if self.intent_ttl_blocks <= self.auction_window_blocks {
            return Err("config intent ttl must cover auction window".to_string());
        }
        if self.low_fee_rebate_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("config low fee rebate bps exceeds limit".to_string());
        }
        if self.surplus_rebate_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("config surplus rebate bps exceeds limit".to_string());
        }
        if self.max_batch_intents == 0 {
            return Err("config max batch intents must be positive".to_string());
        }
        if self.max_solver_commitments_per_auction == 0 {
            return Err("config max solver commitments must be positive".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDefiIntent {
    pub intent_id: String,
    pub intent_kind: PrivateIntentKind,
    pub visibility_class: IntentVisibilityClass,
    pub owner_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub collateral_commitment: String,
    pub route_hint_root: String,
    pub allowed_solver_root: String,
    pub encrypted_payload_root: String,
    pub public_metadata_root: String,
    pub fee_commitment_root: String,
    pub low_fee_lane: String,
    pub low_fee_eligible: bool,
    pub max_slippage_bps: u64,
    pub partial_fill_min_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: IntentStatus,
}

impl EncryptedDefiIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        intent_kind: PrivateIntentKind,
        visibility_class: IntentVisibilityClass,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_units: u64,
        limit_price_numerator: u64,
        limit_price_denominator: u64,
        collateral_units: u64,
        route_hints: &[String],
        allowed_solvers: &[String],
        encrypted_payload: &Value,
        public_metadata: &Value,
        fee_metadata: &Value,
        low_fee_lane: impl Into<String>,
        low_fee_eligible: bool,
        max_slippage_bps: u64,
        partial_fill_min_bps: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(owner_label, "intent owner")?;
        ensure_non_empty(asset_in_id, "intent asset in")?;
        ensure_non_empty(asset_out_id, "intent asset out")?;
        if amount_units == 0 {
            return Err("intent amount must be positive".to_string());
        }
        if limit_price_denominator == 0 {
            return Err("intent price denominator cannot be zero".to_string());
        }
        if max_slippage_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("intent slippage bps exceeds limit".to_string());
        }
        if partial_fill_min_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("intent partial fill bps exceeds limit".to_string());
        }
        if expires_at_height <= submitted_at_height {
            return Err("intent expiry must be after submission".to_string());
        }
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&low_fee_lane, "intent low fee lane")?;

        let owner_commitment = private_intent_matchmaking_pool_owner_commitment(owner_label);
        let asset_in_commitment = private_intent_matchmaking_pool_asset_commitment(asset_in_id);
        let asset_out_commitment = private_intent_matchmaking_pool_asset_commitment(asset_out_id);
        let amount_blinding =
            private_intent_matchmaking_pool_blinding(owner_label, nonce, "amount");
        let price_blinding = private_intent_matchmaking_pool_blinding(owner_label, nonce, "price");
        let collateral_blinding =
            private_intent_matchmaking_pool_blinding(owner_label, nonce, "collateral");
        let amount_commitment =
            private_intent_matchmaking_pool_amount_commitment(amount_units, &amount_blinding);
        let limit_price_commitment = private_intent_matchmaking_pool_price_commitment(
            limit_price_numerator,
            limit_price_denominator,
            &price_blinding,
        );
        let collateral_commitment = private_intent_matchmaking_pool_amount_commitment(
            collateral_units,
            &collateral_blinding,
        );
        let route_hint_root =
            private_intent_matchmaking_pool_string_set_root("INTENT-ROUTE-HINTS", route_hints);
        let allowed_solver_root = private_intent_matchmaking_pool_string_set_root(
            "INTENT-ALLOWED-SOLVERS",
            allowed_solvers,
        );
        let encrypted_payload_root = private_intent_matchmaking_pool_payload_root(
            "INTENT-ENCRYPTED-PAYLOAD",
            encrypted_payload,
        );
        let public_metadata_root =
            private_intent_matchmaking_pool_payload_root("INTENT-PUBLIC-METADATA", public_metadata);
        let fee_commitment_root =
            private_intent_matchmaking_pool_payload_root("INTENT-FEE-METADATA", fee_metadata);
        let intent_id = private_intent_matchmaking_pool_intent_id(
            intent_kind.as_str().as_str(),
            visibility_class.as_str(),
            &owner_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_commitment,
            &limit_price_commitment,
            &route_hint_root,
            expires_at_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            intent_kind,
            visibility_class,
            owner_commitment,
            asset_in_commitment,
            asset_out_commitment,
            amount_commitment,
            limit_price_commitment,
            collateral_commitment,
            route_hint_root,
            allowed_solver_root,
            encrypted_payload_root,
            public_metadata_root,
            fee_commitment_root,
            low_fee_lane,
            low_fee_eligible,
            max_slippage_bps,
            partial_fill_min_bps,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: IntentStatus::Submitted,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_encrypted_defi_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "visibility_class": self.visibility_class.as_str(),
            "owner_commitment": self.owner_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "collateral_commitment": self.collateral_commitment,
            "route_hint_root": self.route_hint_root,
            "allowed_solver_root": self.allowed_solver_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "public_metadata_root": self.public_metadata_root,
            "fee_commitment_root": self.fee_commitment_root,
            "low_fee_lane": self.low_fee_lane,
            "low_fee_eligible": self.low_fee_eligible,
            "max_slippage_bps": self.max_slippage_bps,
            "partial_fill_min_bps": self.partial_fill_min_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "encryption_scheme": PRIVATE_INTENT_MATCHMAKING_POOL_ENCRYPTION_SCHEME,
            "commitment_scheme": PRIVATE_INTENT_MATCHMAKING_POOL_COMMITMENT_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.intent_id, "intent id")?;
        ensure_non_empty(&self.owner_commitment, "intent owner commitment")?;
        ensure_non_empty(&self.asset_in_commitment, "intent asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "intent asset out commitment")?;
        ensure_non_empty(&self.amount_commitment, "intent amount commitment")?;
        ensure_non_empty(&self.limit_price_commitment, "intent price commitment")?;
        ensure_non_empty(&self.collateral_commitment, "intent collateral commitment")?;
        ensure_non_empty(&self.route_hint_root, "intent route hint root")?;
        ensure_non_empty(&self.allowed_solver_root, "intent allowed solver root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "intent encrypted payload root",
        )?;
        ensure_non_empty(&self.public_metadata_root, "intent public metadata root")?;
        ensure_non_empty(&self.fee_commitment_root, "intent fee root")?;
        ensure_non_empty(&self.low_fee_lane, "intent low fee lane")?;
        if self.max_slippage_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("intent slippage bps exceeds limit".to_string());
        }
        if self.partial_fill_min_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("intent partial fill bps exceeds limit".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("intent expiry must be after submission".to_string());
        }
        let id = private_intent_matchmaking_pool_intent_id(
            self.intent_kind.as_str().as_str(),
            self.visibility_class.as_str(),
            &self.owner_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_commitment,
            &self.limit_price_commitment,
            &self.route_hint_root,
            self.expires_at_height,
            self.nonce,
        );
        if self.intent_id != id {
            return Err("intent id mismatch".to_string());
        }
        Ok(self.intent_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAuthorization {
    pub authorization_id: String,
    pub solver_id: String,
    pub operator_commitment: String,
    pub auth_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub scope_root: String,
    pub policy_root: String,
    pub aggregate_signature_root: String,
    pub bond_units: u64,
    pub quality_score_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SolverAuthorizationStatus,
}

impl PqSolverAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_id: &str,
        operator_label: &str,
        auth_public_key: &str,
        kem_public_key: &str,
        scopes: &[String],
        policy: &Value,
        aggregate_signature: &Value,
        bond_units: u64,
        quality_score_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(solver_id, "solver auth solver id")?;
        ensure_non_empty(operator_label, "solver auth operator")?;
        ensure_non_empty(auth_public_key, "solver auth public key")?;
        ensure_non_empty(kem_public_key, "solver auth kem key")?;
        if bond_units == 0 {
            return Err("solver auth bond must be positive".to_string());
        }
        if quality_score_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("solver auth quality score exceeds limit".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("solver auth expiry must be after issue height".to_string());
        }
        let operator_commitment = private_intent_matchmaking_pool_owner_commitment(operator_label);
        let auth_public_key_commitment =
            private_intent_matchmaking_pool_string_root("solver-auth-key", auth_public_key);
        let kem_public_key_commitment =
            private_intent_matchmaking_pool_string_root("solver-kem-key", kem_public_key);
        let scope_root =
            private_intent_matchmaking_pool_string_set_root("SOLVER-AUTH-SCOPES", scopes);
        let policy_root =
            private_intent_matchmaking_pool_payload_root("SOLVER-AUTH-POLICY", policy);
        let aggregate_signature_root = private_intent_matchmaking_pool_payload_root(
            "SOLVER-AUTH-AGGREGATE-SIGNATURE",
            aggregate_signature,
        );
        let authorization_id = private_intent_matchmaking_pool_solver_authorization_id(
            solver_id,
            &operator_commitment,
            &auth_public_key_commitment,
            &kem_public_key_commitment,
            &scope_root,
            issued_at_height,
            nonce,
        );
        let authorization = Self {
            authorization_id,
            solver_id: solver_id.to_string(),
            operator_commitment,
            auth_public_key_commitment,
            kem_public_key_commitment,
            scope_root,
            policy_root,
            aggregate_signature_root,
            bond_units,
            quality_score_bps,
            issued_at_height,
            expires_at_height,
            nonce,
            status: SolverAuthorizationStatus::Active,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_pq_solver_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "auth_public_key_commitment": self.auth_public_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "scope_root": self.scope_root,
            "policy_root": self.policy_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "bond_units": self.bond_units,
            "quality_score_bps": self.quality_score_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "pq_auth_scheme": PRIVATE_INTENT_MATCHMAKING_POOL_PQ_AUTH_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.authorization_id, "solver auth id")?;
        ensure_non_empty(&self.solver_id, "solver auth solver id")?;
        ensure_non_empty(&self.operator_commitment, "solver auth operator commitment")?;
        ensure_non_empty(
            &self.auth_public_key_commitment,
            "solver auth public key root",
        )?;
        ensure_non_empty(&self.kem_public_key_commitment, "solver auth kem key root")?;
        ensure_non_empty(&self.scope_root, "solver auth scope root")?;
        ensure_non_empty(&self.policy_root, "solver auth policy root")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "solver auth aggregate signature root",
        )?;
        if self.bond_units == 0 {
            return Err("solver auth bond must be positive".to_string());
        }
        if self.quality_score_bps > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_BPS {
            return Err("solver auth quality score exceeds limit".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("solver auth expiry must be after issue height".to_string());
        }
        let id = private_intent_matchmaking_pool_solver_authorization_id(
            &self.solver_id,
            &self.operator_commitment,
            &self.auth_public_key_commitment,
            &self.kem_public_key_commitment,
            &self.scope_root,
            self.issued_at_height,
            self.nonce,
        );
        if self.authorization_id != id {
            return Err("solver auth id mismatch".to_string());
        }
        Ok(self.authorization_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchAuction {
    pub auction_id: String,
    pub pool_id: String,
    pub intent_root: String,
    pub solver_authorization_root: String,
    pub mev_policy_root: String,
    pub low_fee_lane: String,
    pub collect_start_height: u64,
    pub collect_end_height: u64,
    pub reveal_start_height: u64,
    pub settlement_deadline_height: u64,
    pub challenge_deadline_height: u64,
    pub ordering_seed: String,
    pub clearing_policy_root: String,
    pub max_batch_intents: usize,
    pub status: AuctionStatus,
}

impl PrivateBatchAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        intent_root: impl Into<String>,
        solver_authorization_root: impl Into<String>,
        mev_policy_root: impl Into<String>,
        low_fee_lane: impl Into<String>,
        collect_start_height: u64,
        collect_end_height: u64,
        reveal_start_height: u64,
        settlement_deadline_height: u64,
        challenge_deadline_height: u64,
        ordering_seed: impl Into<String>,
        clearing_policy: &Value,
        max_batch_intents: usize,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(pool_id, "auction pool id")?;
        let intent_root = intent_root.into();
        let solver_authorization_root = solver_authorization_root.into();
        let mev_policy_root = mev_policy_root.into();
        let low_fee_lane = low_fee_lane.into();
        let ordering_seed = ordering_seed.into();
        ensure_non_empty(&intent_root, "auction intent root")?;
        ensure_non_empty(&solver_authorization_root, "auction solver auth root")?;
        ensure_non_empty(&mev_policy_root, "auction mev policy root")?;
        ensure_non_empty(&low_fee_lane, "auction low fee lane")?;
        ensure_non_empty(&ordering_seed, "auction ordering seed")?;
        if max_batch_intents == 0 {
            return Err("auction max batch intents must be positive".to_string());
        }
        validate_height_window(collect_start_height, collect_end_height, "auction collect")?;
        validate_height_window(collect_end_height, reveal_start_height, "auction reveal")?;
        validate_height_window(
            reveal_start_height,
            settlement_deadline_height,
            "auction settlement",
        )?;
        validate_height_window(
            settlement_deadline_height,
            challenge_deadline_height,
            "auction challenge",
        )?;
        let clearing_policy_root = private_intent_matchmaking_pool_payload_root(
            "AUCTION-CLEARING-POLICY",
            clearing_policy,
        );
        let auction_id = private_intent_matchmaking_pool_auction_id(
            pool_id,
            &intent_root,
            &solver_authorization_root,
            &mev_policy_root,
            collect_start_height,
            collect_end_height,
            &ordering_seed,
        );
        let auction = Self {
            auction_id,
            pool_id: pool_id.to_string(),
            intent_root,
            solver_authorization_root,
            mev_policy_root,
            low_fee_lane,
            collect_start_height,
            collect_end_height,
            reveal_start_height,
            settlement_deadline_height,
            challenge_deadline_height,
            ordering_seed,
            clearing_policy_root,
            max_batch_intents,
            status: AuctionStatus::Collecting,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_batch_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "pool_id": self.pool_id,
            "intent_root": self.intent_root,
            "solver_authorization_root": self.solver_authorization_root,
            "mev_policy_root": self.mev_policy_root,
            "low_fee_lane": self.low_fee_lane,
            "collect_start_height": self.collect_start_height,
            "collect_end_height": self.collect_end_height,
            "reveal_start_height": self.reveal_start_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "ordering_seed": self.ordering_seed,
            "clearing_policy_root": self.clearing_policy_root,
            "max_batch_intents": self.max_batch_intents,
            "status": self.status.as_str(),
            "auction_policy": PRIVATE_INTENT_MATCHMAKING_POOL_AUCTION_POLICY,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.pool_id, "auction pool id")?;
        ensure_non_empty(&self.intent_root, "auction intent root")?;
        ensure_non_empty(&self.solver_authorization_root, "auction auth root")?;
        ensure_non_empty(&self.mev_policy_root, "auction mev policy root")?;
        ensure_non_empty(&self.low_fee_lane, "auction low fee lane")?;
        ensure_non_empty(&self.ordering_seed, "auction ordering seed")?;
        ensure_non_empty(&self.clearing_policy_root, "auction clearing policy root")?;
        if self.max_batch_intents == 0 {
            return Err("auction max batch intents must be positive".to_string());
        }
        validate_height_window(
            self.collect_start_height,
            self.collect_end_height,
            "auction collect",
        )?;
        validate_height_window(
            self.collect_end_height,
            self.reveal_start_height,
            "auction reveal",
        )?;
        validate_height_window(
            self.reveal_start_height,
            self.settlement_deadline_height,
            "auction settlement",
        )?;
        validate_height_window(
            self.settlement_deadline_height,
            self.challenge_deadline_height,
            "auction challenge",
        )?;
        let id = private_intent_matchmaking_pool_auction_id(
            &self.pool_id,
            &self.intent_root,
            &self.solver_authorization_root,
            &self.mev_policy_root,
            self.collect_start_height,
            self.collect_end_height,
            &self.ordering_seed,
        );
        if self.auction_id != id {
            return Err("auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverMatchCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub authorization_id: String,
    pub intent_commitment_root: String,
    pub quote_commitment_root: String,
    pub surplus_commitment_root: String,
    pub sealed_solution_root: String,
    pub anti_mev_proof_root: String,
    pub bond_units: u64,
    pub submitted_at_height: u64,
    pub reveal_after_height: u64,
    pub nonce: u64,
    pub status: SolverCommitmentStatus,
}

impl SolverMatchCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        solver_id: &str,
        authorization_id: &str,
        intent_ids: &[String],
        quote_payload: &Value,
        surplus_payload: &Value,
        sealed_solution: &Value,
        anti_mev_proof: &Value,
        bond_units: u64,
        submitted_at_height: u64,
        reveal_after_height: u64,
        nonce: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(auction_id, "solver commitment auction")?;
        ensure_non_empty(solver_id, "solver commitment solver")?;
        ensure_non_empty(authorization_id, "solver commitment auth")?;
        if intent_ids.is_empty() {
            return Err("solver commitment needs at least one intent".to_string());
        }
        if bond_units == 0 {
            return Err("solver commitment bond must be positive".to_string());
        }
        if reveal_after_height <= submitted_at_height {
            return Err("solver commitment reveal height must follow submission".to_string());
        }
        let intent_commitment_root = private_intent_matchmaking_pool_string_set_root(
            "SOLVER-COMMITMENT-INTENTS",
            intent_ids,
        );
        let quote_commitment_root =
            private_intent_matchmaking_pool_payload_root("SOLVER-COMMITMENT-QUOTE", quote_payload);
        let surplus_commitment_root = private_intent_matchmaking_pool_payload_root(
            "SOLVER-COMMITMENT-SURPLUS",
            surplus_payload,
        );
        let sealed_solution_root = private_intent_matchmaking_pool_payload_root(
            "SOLVER-COMMITMENT-SEALED-SOLUTION",
            sealed_solution,
        );
        let anti_mev_proof_root = private_intent_matchmaking_pool_payload_root(
            "SOLVER-COMMITMENT-ANTI-MEV",
            anti_mev_proof,
        );
        let commitment_id = private_intent_matchmaking_pool_solver_commitment_id(
            auction_id,
            solver_id,
            authorization_id,
            &intent_commitment_root,
            &quote_commitment_root,
            &sealed_solution_root,
            submitted_at_height,
            nonce,
        );
        let commitment = Self {
            commitment_id,
            auction_id: auction_id.to_string(),
            solver_id: solver_id.to_string(),
            authorization_id: authorization_id.to_string(),
            intent_commitment_root,
            quote_commitment_root,
            surplus_commitment_root,
            sealed_solution_root,
            anti_mev_proof_root,
            bond_units,
            submitted_at_height,
            reveal_after_height,
            nonce,
            status: SolverCommitmentStatus::Submitted,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_solver_match_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "authorization_id": self.authorization_id,
            "intent_commitment_root": self.intent_commitment_root,
            "quote_commitment_root": self.quote_commitment_root,
            "surplus_commitment_root": self.surplus_commitment_root,
            "sealed_solution_root": self.sealed_solution_root,
            "anti_mev_proof_root": self.anti_mev_proof_root,
            "bond_units": self.bond_units,
            "submitted_at_height": self.submitted_at_height,
            "reveal_after_height": self.reveal_after_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "commitment_scheme": PRIVATE_INTENT_MATCHMAKING_POOL_COMMITMENT_SCHEME,
            "mev_policy": PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.commitment_id, "solver commitment id")?;
        ensure_non_empty(&self.auction_id, "solver commitment auction")?;
        ensure_non_empty(&self.solver_id, "solver commitment solver")?;
        ensure_non_empty(&self.authorization_id, "solver commitment auth")?;
        ensure_non_empty(
            &self.intent_commitment_root,
            "solver commitment intent root",
        )?;
        ensure_non_empty(&self.quote_commitment_root, "solver commitment quote root")?;
        ensure_non_empty(
            &self.surplus_commitment_root,
            "solver commitment surplus root",
        )?;
        ensure_non_empty(
            &self.sealed_solution_root,
            "solver commitment solution root",
        )?;
        ensure_non_empty(&self.anti_mev_proof_root, "solver commitment anti mev root")?;
        if self.bond_units == 0 {
            return Err("solver commitment bond must be positive".to_string());
        }
        validate_height_window(
            self.submitted_at_height,
            self.reveal_after_height,
            "solver commitment reveal",
        )?;
        let id = private_intent_matchmaking_pool_solver_commitment_id(
            &self.auction_id,
            &self.solver_id,
            &self.authorization_id,
            &self.intent_commitment_root,
            &self.quote_commitment_root,
            &self.sealed_solution_root,
            self.submitted_at_height,
            self.nonce,
        );
        if self.commitment_id != id {
            return Err("solver commitment id mismatch".to_string());
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevResistantMatch {
    pub match_id: String,
    pub auction_id: String,
    pub solver_commitment_id: String,
    pub intent_root: String,
    pub fill_root: String,
    pub clearing_price_root: String,
    pub surplus_root: String,
    pub anti_sandwich_root: String,
    pub nullifier_root: String,
    pub matched_notional_units: u64,
    pub solver_fee_units: u64,
    pub user_surplus_units: u64,
    pub matched_at_height: u64,
    pub sequence: u64,
    pub status: MatchStatus,
}

impl MevResistantMatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        solver_commitment_id: &str,
        intent_ids: &[String],
        fills: &[Value],
        clearing_prices: &[Value],
        surplus: &[Value],
        anti_sandwich_proof: &Value,
        nullifiers: &[String],
        matched_notional_units: u64,
        solver_fee_units: u64,
        user_surplus_units: u64,
        matched_at_height: u64,
        sequence: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(auction_id, "match auction")?;
        ensure_non_empty(solver_commitment_id, "match solver commitment")?;
        if intent_ids.is_empty() {
            return Err("match needs at least one intent".to_string());
        }
        if matched_notional_units == 0 {
            return Err("match notional must be positive".to_string());
        }
        let intent_root =
            private_intent_matchmaking_pool_string_set_root("MATCH-INTENTS", intent_ids);
        let fill_root = private_intent_matchmaking_pool_value_root("MATCH-FILLS", fills);
        let clearing_price_root =
            private_intent_matchmaking_pool_value_root("MATCH-CLEARING-PRICES", clearing_prices);
        let surplus_root = private_intent_matchmaking_pool_value_root("MATCH-SURPLUS", surplus);
        let anti_sandwich_root = private_intent_matchmaking_pool_payload_root(
            "MATCH-ANTI-SANDWICH",
            anti_sandwich_proof,
        );
        let nullifier_root =
            private_intent_matchmaking_pool_string_set_root("MATCH-NULLIFIERS", nullifiers);
        let match_id = private_intent_matchmaking_pool_match_id(
            auction_id,
            solver_commitment_id,
            &intent_root,
            &fill_root,
            &clearing_price_root,
            &nullifier_root,
            matched_at_height,
            sequence,
        );
        let matched = Self {
            match_id,
            auction_id: auction_id.to_string(),
            solver_commitment_id: solver_commitment_id.to_string(),
            intent_root,
            fill_root,
            clearing_price_root,
            surplus_root,
            anti_sandwich_root,
            nullifier_root,
            matched_notional_units,
            solver_fee_units,
            user_surplus_units,
            matched_at_height,
            sequence,
            status: MatchStatus::Proposed,
        };
        matched.validate()?;
        Ok(matched)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_mev_resistant_match",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "match_id": self.match_id,
            "auction_id": self.auction_id,
            "solver_commitment_id": self.solver_commitment_id,
            "intent_root": self.intent_root,
            "fill_root": self.fill_root,
            "clearing_price_root": self.clearing_price_root,
            "surplus_root": self.surplus_root,
            "anti_sandwich_root": self.anti_sandwich_root,
            "nullifier_root": self.nullifier_root,
            "matched_notional_units": self.matched_notional_units,
            "solver_fee_units": self.solver_fee_units,
            "user_surplus_units": self.user_surplus_units,
            "matched_at_height": self.matched_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "mev_policy": PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.match_id, "match id")?;
        ensure_non_empty(&self.auction_id, "match auction")?;
        ensure_non_empty(&self.solver_commitment_id, "match solver commitment")?;
        ensure_non_empty(&self.intent_root, "match intent root")?;
        ensure_non_empty(&self.fill_root, "match fill root")?;
        ensure_non_empty(&self.clearing_price_root, "match clearing root")?;
        ensure_non_empty(&self.surplus_root, "match surplus root")?;
        ensure_non_empty(&self.anti_sandwich_root, "match anti sandwich root")?;
        ensure_non_empty(&self.nullifier_root, "match nullifier root")?;
        if self.matched_notional_units == 0 {
            return Err("match notional must be positive".to_string());
        }
        let id = private_intent_matchmaking_pool_match_id(
            &self.auction_id,
            &self.solver_commitment_id,
            &self.intent_root,
            &self.fill_root,
            &self.clearing_price_root,
            &self.nullifier_root,
            self.matched_at_height,
            self.sequence,
        );
        if self.match_id != id {
            return Err("match id mismatch".to_string());
        }
        Ok(self.match_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub match_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_commitment: String,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub sponsor_pool_root: String,
    pub proof_root: String,
    pub issued_at_height: u64,
    pub claim_deadline_height: u64,
    pub status: ReceiptStatus,
}

impl LowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        match_id: &str,
        beneficiary_label: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        rebate_units: u64,
        sponsor_pool: &Value,
        proof: &Value,
        issued_at_height: u64,
        claim_deadline_height: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(match_id, "rebate match")?;
        ensure_non_empty(beneficiary_label, "rebate beneficiary")?;
        ensure_non_empty(fee_asset_id, "rebate fee asset")?;
        if gross_fee_units == 0 {
            return Err("rebate gross fee must be positive".to_string());
        }
        if rebate_units > gross_fee_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        validate_height_window(issued_at_height, claim_deadline_height, "rebate claim")?;
        let beneficiary_commitment =
            private_intent_matchmaking_pool_owner_commitment(beneficiary_label);
        let fee_asset_commitment = private_intent_matchmaking_pool_asset_commitment(fee_asset_id);
        let sponsor_pool_root = private_intent_matchmaking_pool_payload_root(
            "LOW-FEE-REBATE-SPONSOR-POOL",
            sponsor_pool,
        );
        let proof_root =
            private_intent_matchmaking_pool_payload_root("LOW-FEE-REBATE-PROOF", proof);
        let rebate_id = private_intent_matchmaking_pool_rebate_id(
            match_id,
            &beneficiary_commitment,
            &fee_asset_commitment,
            gross_fee_units,
            rebate_units,
            issued_at_height,
        );
        let rebate = Self {
            rebate_id,
            match_id: match_id.to_string(),
            beneficiary_commitment,
            fee_asset_commitment,
            gross_fee_units,
            rebate_units,
            sponsor_pool_root,
            proof_root,
            issued_at_height,
            claim_deadline_height,
            status: ReceiptStatus::PendingDelay,
        };
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_low_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "match_id": self.match_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_commitment": self.fee_asset_commitment,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "sponsor_pool_root": self.sponsor_pool_root,
            "proof_root": self.proof_root,
            "issued_at_height": self.issued_at_height,
            "claim_deadline_height": self.claim_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.rebate_id, "rebate id")?;
        ensure_non_empty(&self.match_id, "rebate match")?;
        ensure_non_empty(&self.beneficiary_commitment, "rebate beneficiary")?;
        ensure_non_empty(&self.fee_asset_commitment, "rebate fee asset")?;
        ensure_non_empty(&self.sponsor_pool_root, "rebate sponsor pool")?;
        ensure_non_empty(&self.proof_root, "rebate proof")?;
        if self.gross_fee_units == 0 {
            return Err("rebate gross fee must be positive".to_string());
        }
        if self.rebate_units > self.gross_fee_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        validate_height_window(
            self.issued_at_height,
            self.claim_deadline_height,
            "rebate claim",
        )?;
        let id = private_intent_matchmaking_pool_rebate_id(
            &self.match_id,
            &self.beneficiary_commitment,
            &self.fee_asset_commitment,
            self.gross_fee_units,
            self.rebate_units,
            self.issued_at_height,
        );
        if self.rebate_id != id {
            return Err("rebate id mismatch".to_string());
        }
        Ok(self.rebate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub match_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub receipt_nullifier: String,
    pub output_note_root: String,
    pub settlement_proof_root: String,
    pub privacy_audit_root: String,
    pub rebate_root: String,
    pub published_at_height: u64,
    pub final_at_height: u64,
    pub sequence: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        match_id: &str,
        auction_id: &str,
        solver_id: &str,
        receipt_secret: &str,
        output_notes: &[Value],
        settlement_proof: &Value,
        privacy_audit: &Value,
        rebate_ids: &[String],
        published_at_height: u64,
        final_at_height: u64,
        sequence: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(match_id, "receipt match")?;
        ensure_non_empty(auction_id, "receipt auction")?;
        ensure_non_empty(solver_id, "receipt solver")?;
        ensure_non_empty(receipt_secret, "receipt secret")?;
        validate_height_window(published_at_height, final_at_height, "receipt final")?;
        let receipt_nullifier = private_intent_matchmaking_pool_receipt_nullifier(
            match_id,
            solver_id,
            receipt_secret,
            sequence,
        );
        let output_note_root = private_intent_matchmaking_pool_value_root(
            "SETTLEMENT-RECEIPT-OUTPUT-NOTES",
            output_notes,
        );
        let settlement_proof_root = private_intent_matchmaking_pool_payload_root(
            "SETTLEMENT-RECEIPT-PROOF",
            settlement_proof,
        );
        let privacy_audit_root = private_intent_matchmaking_pool_payload_root(
            "SETTLEMENT-RECEIPT-PRIVACY-AUDIT",
            privacy_audit,
        );
        let rebate_root = private_intent_matchmaking_pool_string_set_root(
            "SETTLEMENT-RECEIPT-REBATES",
            rebate_ids,
        );
        let receipt_id = private_intent_matchmaking_pool_receipt_id(
            match_id,
            auction_id,
            solver_id,
            &receipt_nullifier,
            &output_note_root,
            &settlement_proof_root,
            published_at_height,
            sequence,
        );
        let receipt = Self {
            receipt_id,
            match_id: match_id.to_string(),
            auction_id: auction_id.to_string(),
            solver_id: solver_id.to_string(),
            receipt_nullifier,
            output_note_root,
            settlement_proof_root,
            privacy_audit_root,
            rebate_root,
            published_at_height,
            final_at_height,
            sequence,
            status: ReceiptStatus::Published,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "match_id": self.match_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "receipt_nullifier": self.receipt_nullifier,
            "output_note_root": self.output_note_root,
            "settlement_proof_root": self.settlement_proof_root,
            "privacy_audit_root": self.privacy_audit_root,
            "rebate_root": self.rebate_root,
            "published_at_height": self.published_at_height,
            "final_at_height": self.final_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "receipt_scheme": PRIVATE_INTENT_MATCHMAKING_POOL_RECEIPT_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.match_id, "receipt match")?;
        ensure_non_empty(&self.auction_id, "receipt auction")?;
        ensure_non_empty(&self.solver_id, "receipt solver")?;
        ensure_non_empty(&self.receipt_nullifier, "receipt nullifier")?;
        ensure_non_empty(&self.output_note_root, "receipt output notes")?;
        ensure_non_empty(&self.settlement_proof_root, "receipt proof")?;
        ensure_non_empty(&self.privacy_audit_root, "receipt audit")?;
        ensure_non_empty(&self.rebate_root, "receipt rebates")?;
        validate_height_window(
            self.published_at_height,
            self.final_at_height,
            "receipt final",
        )?;
        let id = private_intent_matchmaking_pool_receipt_id(
            &self.match_id,
            &self.auction_id,
            &self.solver_id,
            &self.receipt_nullifier,
            &self.output_note_root,
            &self.settlement_proof_root,
            self.published_at_height,
            self.sequence,
        );
        if self.receipt_id != id {
            return Err("receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentPoolPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PrivateIntentPoolPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject")?;
        let payload_root =
            private_intent_matchmaking_pool_payload_root("PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = private_intent_matchmaking_pool_public_record_id(
            record_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let id = private_intent_matchmaking_pool_public_record_id(
            &self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentMatchmakingPoolCounters {
    pub encrypted_intent_count: u64,
    pub active_intent_count: u64,
    pub swap_intent_count: u64,
    pub lend_intent_count: u64,
    pub bridge_intent_count: u64,
    pub solver_authorization_count: u64,
    pub active_solver_authorization_count: u64,
    pub batch_auction_count: u64,
    pub live_batch_auction_count: u64,
    pub solver_commitment_count: u64,
    pub selected_solver_commitment_count: u64,
    pub mev_resistant_match_count: u64,
    pub cleared_match_count: u64,
    pub settlement_receipt_count: u64,
    pub published_receipt_count: u64,
    pub low_fee_rebate_count: u64,
    pub pending_rebate_count: u64,
    pub gross_fee_units: u64,
    pub low_fee_rebate_units: u64,
    pub user_surplus_units: u64,
    pub matched_notional_units: u64,
    pub public_record_count: u64,
}

impl PrivateIntentMatchmakingPoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "encrypted_intent_count": self.encrypted_intent_count,
            "active_intent_count": self.active_intent_count,
            "swap_intent_count": self.swap_intent_count,
            "lend_intent_count": self.lend_intent_count,
            "bridge_intent_count": self.bridge_intent_count,
            "solver_authorization_count": self.solver_authorization_count,
            "active_solver_authorization_count": self.active_solver_authorization_count,
            "batch_auction_count": self.batch_auction_count,
            "live_batch_auction_count": self.live_batch_auction_count,
            "solver_commitment_count": self.solver_commitment_count,
            "selected_solver_commitment_count": self.selected_solver_commitment_count,
            "mev_resistant_match_count": self.mev_resistant_match_count,
            "cleared_match_count": self.cleared_match_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "published_receipt_count": self.published_receipt_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "pending_rebate_count": self.pending_rebate_count,
            "gross_fee_units": self.gross_fee_units,
            "low_fee_rebate_units": self.low_fee_rebate_units,
            "user_surplus_units": self.user_surplus_units,
            "matched_notional_units": self.matched_notional_units,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentMatchmakingPoolRoots {
    pub config_root: String,
    pub encrypted_intent_root: String,
    pub solver_authorization_root: String,
    pub batch_auction_root: String,
    pub solver_commitment_root: String,
    pub mev_resistant_match_root: String,
    pub settlement_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub public_record_root: String,
}

impl PrivateIntentMatchmakingPoolRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_matchmaking_pool_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "solver_authorization_root": self.solver_authorization_root,
            "batch_auction_root": self.batch_auction_root,
            "solver_commitment_root": self.solver_commitment_root,
            "mev_resistant_match_root": self.mev_resistant_match_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_intent_matchmaking_pool_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentMatchmakingPoolState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateIntentMatchmakingPoolConfig,
    pub encrypted_intents: BTreeMap<String, EncryptedDefiIntent>,
    pub solver_authorizations: BTreeMap<String, PqSolverAuthorization>,
    pub batch_auctions: BTreeMap<String, PrivateBatchAuction>,
    pub solver_commitments: BTreeMap<String, SolverMatchCommitment>,
    pub mev_resistant_matches: BTreeMap<String, MevResistantMatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub public_records: BTreeMap<String, PrivateIntentPoolPublicRecord>,
}

impl Default for PrivateIntentMatchmakingPoolState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateIntentMatchmakingPoolState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateIntentMatchmakingPoolConfig::default(),
            encrypted_intents: BTreeMap::new(),
            solver_authorizations: BTreeMap::new(),
            batch_auctions: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            mev_resistant_matches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: PrivateIntentMatchmakingPoolConfig,
    ) -> PrivateIntentMatchmakingPoolResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateIntentMatchmakingPoolResult<Self> {
        let mut state = Self::with_config(PrivateIntentMatchmakingPoolConfig::devnet())?;
        state.set_height(PRIVATE_INTENT_MATCHMAKING_POOL_DEVNET_HEIGHT);

        let solver = PqSolverAuthorization::new(
            "devnet-solver-alpha",
            "devnet-solver-alpha-operator",
            "ml-dsa-87-devnet-solver-alpha-auth-key",
            "ml-kem-1024-devnet-solver-alpha-routing-key",
            &[
                "swap".to_string(),
                "lend".to_string(),
                "bridge".to_string(),
                "low_fee_rebate".to_string(),
            ],
            &json!({
                "max_batch_intents": 64,
                "allowed_lanes": [state.config.default_low_fee_lane.clone()],
                "anti_mev": PRIVATE_INTENT_MATCHMAKING_POOL_MEV_POLICY
            }),
            &json!({"threshold": "2-of-3", "signature": "devnet-solver-alpha-aggregate-sig"}),
            1_000_000,
            920,
            state.height.saturating_sub(12),
            state
                .height
                .saturating_add(state.config.solver_auth_ttl_blocks),
            state.next_nonce(),
        )?;
        let solver_auth_id = solver.authorization_id.clone();
        let solver_id = solver.solver_id.clone();
        state.insert_solver_authorization(solver)?;

        let swap_intent = EncryptedDefiIntent::new(
            "devnet-alice-private-swap",
            PrivateIntentKind::SwapExactIn,
            IntentVisibilityClass::SolverScoped,
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000_000,
            180_000_000_000,
            1_000_000,
            0,
            &["devnet-route-wxmr-usdd-direct".to_string()],
            std::slice::from_ref(&solver_id),
            &json!({
                "intent": "swap_exact_in",
                "amount_bucket": "40-45 wxmr",
                "recipient_note": "alice-output-note"
            }),
            &json!({"lane": "private_defi", "batch_only": true}),
            &json!({"fee_asset": "usdd-devnet", "max_fee_bucket": "low"}),
            state.config.default_low_fee_lane.clone(),
            true,
            60,
            8_000,
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let swap_intent_id = swap_intent.intent_id.clone();
        state.insert_encrypted_intent(swap_intent)?;

        let lend_intent = EncryptedDefiIntent::new(
            "devnet-bob-private-borrow",
            PrivateIntentKind::LendBorrow,
            IntentVisibilityClass::AmountBucketed,
            "wxmr-collateral-devnet",
            "usdd-devnet",
            125_000_000_000,
            18_000_000_000,
            1,
            125_000_000_000,
            &["devnet-lending-market-wxmr-usdd".to_string()],
            std::slice::from_ref(&solver_id),
            &json!({
                "intent": "lend_borrow",
                "collateral_bucket": "100-150 wxmr",
                "borrow_bucket": "18k usdd"
            }),
            &json!({"health_factor_bucket": "safe", "oracle": "devnet-median"}),
            &json!({"fee_asset": "usdd-devnet", "rebate": false}),
            state.config.default_low_fee_lane.clone(),
            false,
            0,
            10_000,
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let lend_intent_id = lend_intent.intent_id.clone();
        state.insert_encrypted_intent(lend_intent)?;

        let bridge_intent = EncryptedDefiIntent::new(
            "devnet-dana-private-bridge",
            PrivateIntentKind::BridgeOut,
            IntentVisibilityClass::RouteHinted,
            "usdd-devnet",
            "xmr-mainnet-bridge-note",
            1_250_000_000,
            1_240_000_000,
            1_000_000_000,
            0,
            &["devnet-fast-exit-monero-vault".to_string()],
            std::slice::from_ref(&solver_id),
            &json!({
                "intent": "bridge_out",
                "destination": "monero",
                "recipient": "stealth-address-commitment"
            }),
            &json!({"bridge_route": "fast_exit", "withdrawal_order_privacy": true}),
            &json!({"fee_asset": "usdd-devnet", "rebate": false}),
            state.config.default_low_fee_lane.clone(),
            false,
            80,
            10_000,
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let bridge_intent_id = bridge_intent.intent_id.clone();
        state.insert_encrypted_intent(bridge_intent)?;

        let ordering_seed = private_intent_matchmaking_pool_ordering_seed(
            &state.config.pool_id,
            state.height,
            &state.encrypted_intent_root(),
        );
        let auction = PrivateBatchAuction::new(
            &state.config.pool_id,
            state.encrypted_intent_root(),
            state.solver_authorization_root(),
            state.config.mev_policy_root.clone(),
            state.config.default_low_fee_lane.clone(),
            state.height,
            state
                .height
                .saturating_add(state.config.auction_window_blocks),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.reveal_delay_blocks),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.reveal_delay_blocks)
                .saturating_add(state.config.settlement_window_blocks),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.reveal_delay_blocks)
                .saturating_add(state.config.settlement_window_blocks)
                .saturating_add(state.config.challenge_window_blocks),
            ordering_seed,
            &json!({
                "clearing": "uniform",
                "tie_break": "commitment_lexicographic",
                "same_solver_backrun": false
            }),
            state.config.max_batch_intents,
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_batch_auction(auction)?;

        let commitment = SolverMatchCommitment::new(
            &auction_id,
            &solver_id,
            &solver_auth_id,
            &[
                swap_intent_id.clone(),
                lend_intent_id.clone(),
                bridge_intent_id.clone(),
            ],
            &json!({
                "swap_price": "180 usdd/wxmr",
                "lend_rate_bucket": "devnet-low",
                "bridge_fee_bucket": "fast-exit"
            }),
            &json!({"user_surplus_units": 22_000_000, "rebate_basis": "low_fee"}),
            &json!({"encrypted_solution": "devnet-alpha-sealed-solution"}),
            &json!({"no_same_solver_backrun": true, "uniform_clearing": true}),
            1_000_000,
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.reveal_delay_blocks),
            state.next_nonce(),
        )?;
        let commitment_id = commitment.commitment_id.clone();
        state.insert_solver_commitment(commitment)?;

        let matched = MevResistantMatch::new(
            &auction_id,
            &commitment_id,
            &[
                swap_intent_id.clone(),
                lend_intent_id.clone(),
                bridge_intent_id.clone(),
            ],
            &[
                json!({"intent": swap_intent_id, "fill": "swap_exact_in", "amount_bucket": "42 wxmr"}),
                json!({"intent": lend_intent_id, "fill": "private_borrow", "borrow_bucket": "18k usdd"}),
                json!({"intent": bridge_intent_id, "fill": "bridge_out", "amount_bucket": "1250 usdd"}),
            ],
            &[
                json!({"pair": "wxmr/usdd", "clearing": "180"}),
                json!({"market": "lend-wxmr-usdd", "rate_bucket": "low"}),
            ],
            &[json!({"surplus_bucket": "22 usdd", "rebate_bucket": "low_fee"})],
            &json!({"batch_only": true, "front_run_window": "sealed"}),
            &[
                "devnet-nullifier-swap".to_string(),
                "devnet-nullifier-lend".to_string(),
                "devnet-nullifier-bridge".to_string(),
            ],
            26_750_000_000,
            120_000,
            22_000_000,
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.reveal_delay_blocks)
                .saturating_add(1),
            state.next_nonce(),
        )?;
        let match_id = matched.match_id.clone();
        state.insert_mev_resistant_match(matched)?;

        let rebate = LowFeeRebate::new(
            &match_id,
            "devnet-alice-private-swap",
            "usdd-devnet",
            120_000,
            78_000,
            &json!({"sponsor": "devnet-low-fee-sponsor", "lane": state.config.default_low_fee_lane}),
            &json!({"eligible": true, "basis_bps": state.config.low_fee_rebate_bps}),
            state.height.saturating_add(32),
            state.height.saturating_add(720),
        )?;
        let rebate_id = rebate.rebate_id.clone();
        state.insert_low_fee_rebate(rebate)?;

        let receipt = SettlementReceipt::new(
            &match_id,
            &auction_id,
            &solver_id,
            "devnet-private-receipt-secret-alpha",
            &[
                json!({"note": "alice-swap-output", "asset": "usdd-devnet"}),
                json!({"note": "bob-borrow-output", "asset": "usdd-devnet"}),
                json!({"note": "dana-bridge-output", "asset": "monero-note"}),
            ],
            &json!({"proof": "devnet-zk-settlement-proof", "recursive": true}),
            &json!({"leakage": "receipt-delay", "receipt_delay_blocks": state.config.receipt_delay_blocks}),
            std::slice::from_ref(&rebate_id),
            state
                .height
                .saturating_add(state.config.receipt_delay_blocks),
            state
                .height
                .saturating_add(state.config.receipt_delay_blocks)
                .saturating_add(state.config.challenge_window_blocks),
            state.next_nonce(),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_settlement_receipt(receipt)?;

        for (kind, subject, record) in [
            (
                "solver_authorization",
                solver_auth_id.as_str(),
                state.solver_authorizations[&solver_auth_id].public_record(),
            ),
            (
                "batch_auction",
                auction_id.as_str(),
                state.batch_auctions[&auction_id].public_record(),
            ),
            (
                "solver_commitment",
                commitment_id.as_str(),
                state.solver_commitments[&commitment_id].public_record(),
            ),
            (
                "mev_resistant_match",
                match_id.as_str(),
                state.mev_resistant_matches[&match_id].public_record(),
            ),
            (
                "settlement_receipt",
                receipt_id.as_str(),
                state.settlement_receipts[&receipt_id].public_record(),
            ),
        ] {
            state.publish_public_record(kind, subject, &record)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_encrypted_intent(
        &mut self,
        intent: EncryptedDefiIntent,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        intent.validate()?;
        if self.encrypted_intents.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_INTENTS {
            return Err("encrypted intent capacity reached".to_string());
        }
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    pub fn insert_solver_authorization(
        &mut self,
        authorization: PqSolverAuthorization,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        authorization.validate()?;
        if authorization.bond_units < self.config.min_solver_bond_units {
            return Err("solver authorization bond below config minimum".to_string());
        }
        if self.solver_authorizations.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVERS {
            return Err("solver authorization capacity reached".to_string());
        }
        self.solver_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(())
    }

    pub fn insert_batch_auction(
        &mut self,
        auction: PrivateBatchAuction,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        auction.validate()?;
        if self.batch_auctions.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_AUCTIONS {
            return Err("batch auction capacity reached".to_string());
        }
        self.batch_auctions
            .insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: SolverMatchCommitment,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        commitment.validate()?;
        if !self.batch_auctions.contains_key(&commitment.auction_id) {
            return Err("solver commitment references unknown auction".to_string());
        }
        let auth = self
            .solver_authorizations
            .get(&commitment.authorization_id)
            .ok_or_else(|| "solver commitment references unknown auth".to_string())?;
        if auth.solver_id != commitment.solver_id {
            return Err("solver commitment auth solver mismatch".to_string());
        }
        if !auth.status.usable() {
            return Err("solver commitment auth is not active".to_string());
        }
        if self.solver_commitments.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVER_COMMITMENTS {
            return Err("solver commitment capacity reached".to_string());
        }
        self.solver_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_mev_resistant_match(
        &mut self,
        matched: MevResistantMatch,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        matched.validate()?;
        if !self.batch_auctions.contains_key(&matched.auction_id) {
            return Err("match references unknown auction".to_string());
        }
        if !self
            .solver_commitments
            .contains_key(&matched.solver_commitment_id)
        {
            return Err("match references unknown solver commitment".to_string());
        }
        if self.mev_resistant_matches.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_MATCHES {
            return Err("match capacity reached".to_string());
        }
        self.mev_resistant_matches
            .insert(matched.match_id.clone(), matched);
        Ok(())
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        receipt.validate()?;
        if !self.mev_resistant_matches.contains_key(&receipt.match_id) {
            return Err("receipt references unknown match".to_string());
        }
        if self.settlement_receipts.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_RECEIPTS {
            return Err("receipt capacity reached".to_string());
        }
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_low_fee_rebate(
        &mut self,
        rebate: LowFeeRebate,
    ) -> PrivateIntentMatchmakingPoolResult<()> {
        rebate.validate()?;
        if !self.mev_resistant_matches.contains_key(&rebate.match_id) {
            return Err("rebate references unknown match".to_string());
        }
        if self.low_fee_rebates.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_REBATES {
            return Err("rebate capacity reached".to_string());
        }
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> PrivateIntentMatchmakingPoolResult<PrivateIntentPoolPublicRecord> {
        if self.public_records.len() >= PRIVATE_INTENT_MATCHMAKING_POOL_MAX_PUBLIC_RECORDS {
            return Err("public record capacity reached".to_string());
        }
        let record = PrivateIntentPoolPublicRecord::new(
            record_kind,
            subject_id,
            payload,
            self.height,
            self.public_records.len() as u64,
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn encrypted_intent_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "ENCRYPTED-INTENTS",
            self.encrypted_intents
                .values()
                .map(EncryptedDefiIntent::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn solver_authorization_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "SOLVER-AUTHORIZATIONS",
            self.solver_authorizations
                .values()
                .map(PqSolverAuthorization::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn batch_auction_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "BATCH-AUCTIONS",
            self.batch_auctions
                .values()
                .map(PrivateBatchAuction::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn solver_commitment_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "SOLVER-COMMITMENTS",
            self.solver_commitments
                .values()
                .map(SolverMatchCommitment::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn mev_resistant_match_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "MEV-RESISTANT-MATCHES",
            self.mev_resistant_matches
                .values()
                .map(MevResistantMatch::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn low_fee_rebate_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "LOW-FEE-REBATES",
            self.low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_intent_matchmaking_pool_object_root(
            "PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(PrivateIntentPoolPublicRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn roots(&self) -> PrivateIntentMatchmakingPoolRoots {
        PrivateIntentMatchmakingPoolRoots {
            config_root: self.config.state_root(),
            encrypted_intent_root: self.encrypted_intent_root(),
            solver_authorization_root: self.solver_authorization_root(),
            batch_auction_root: self.batch_auction_root(),
            solver_commitment_root: self.solver_commitment_root(),
            mev_resistant_match_root: self.mev_resistant_match_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            low_fee_rebate_root: self.low_fee_rebate_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> PrivateIntentMatchmakingPoolCounters {
        PrivateIntentMatchmakingPoolCounters {
            encrypted_intent_count: self.encrypted_intents.len() as u64,
            active_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.status.active())
                .count() as u64,
            swap_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_swap())
                .count() as u64,
            lend_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_lend())
                .count() as u64,
            bridge_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_bridge())
                .count() as u64,
            solver_authorization_count: self.solver_authorizations.len() as u64,
            active_solver_authorization_count: self
                .solver_authorizations
                .values()
                .filter(|authorization| authorization.status.usable())
                .count() as u64,
            batch_auction_count: self.batch_auctions.len() as u64,
            live_batch_auction_count: self
                .batch_auctions
                .values()
                .filter(|auction| auction.status.live())
                .count() as u64,
            solver_commitment_count: self.solver_commitments.len() as u64,
            selected_solver_commitment_count: self
                .solver_commitments
                .values()
                .filter(|commitment| {
                    matches!(
                        commitment.status,
                        SolverCommitmentStatus::Selected
                            | SolverCommitmentStatus::Revealed
                            | SolverCommitmentStatus::Settled
                    )
                })
                .count() as u64,
            mev_resistant_match_count: self.mev_resistant_matches.len() as u64,
            cleared_match_count: self
                .mev_resistant_matches
                .values()
                .filter(|matched| {
                    matches!(
                        matched.status,
                        MatchStatus::Cleared | MatchStatus::ReceiptIssued | MatchStatus::Finalized
                    )
                })
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            published_receipt_count: self
                .settlement_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ReceiptStatus::Published | ReceiptStatus::Final
                    )
                })
                .count() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            pending_rebate_count: self
                .low_fee_rebates
                .values()
                .filter(|rebate| matches!(rebate.status, ReceiptStatus::PendingDelay))
                .count() as u64,
            gross_fee_units: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.gross_fee_units)
                .sum(),
            low_fee_rebate_units: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
            user_surplus_units: self
                .mev_resistant_matches
                .values()
                .map(|matched| matched.user_surplus_units)
                .sum(),
            matched_notional_units: self
                .mev_resistant_matches
                .values()
                .map(|matched| matched.matched_notional_units)
                .sum(),
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_intent_matchmaking_pool_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root()
    }

    pub fn validate(&self) -> PrivateIntentMatchmakingPoolResult<String> {
        self.config.validate()?;
        if self.encrypted_intents.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_INTENTS {
            return Err("encrypted intent capacity exceeded".to_string());
        }
        if self.solver_authorizations.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVERS {
            return Err("solver authorization capacity exceeded".to_string());
        }
        if self.batch_auctions.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_AUCTIONS {
            return Err("batch auction capacity exceeded".to_string());
        }
        if self.solver_commitments.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_SOLVER_COMMITMENTS {
            return Err("solver commitment capacity exceeded".to_string());
        }
        if self.mev_resistant_matches.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_MATCHES {
            return Err("match capacity exceeded".to_string());
        }
        if self.settlement_receipts.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_RECEIPTS {
            return Err("receipt capacity exceeded".to_string());
        }
        if self.low_fee_rebates.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_REBATES {
            return Err("rebate capacity exceeded".to_string());
        }
        if self.public_records.len() > PRIVATE_INTENT_MATCHMAKING_POOL_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }
        let mut solver_ids = BTreeSet::new();
        for authorization in self.solver_authorizations.values() {
            authorization.validate()?;
            solver_ids.insert(authorization.solver_id.clone());
        }
        for intent in self.encrypted_intents.values() {
            intent.validate()?;
            if self.height > intent.expires_at_height && intent.status.active() {
                return Err("active intent is past expiry".to_string());
            }
        }
        for auction in self.batch_auctions.values() {
            auction.validate()?;
            if auction.max_batch_intents > self.config.max_batch_intents {
                return Err("auction max batch intents exceeds config".to_string());
            }
        }
        for commitment in self.solver_commitments.values() {
            commitment.validate()?;
            if !self.batch_auctions.contains_key(&commitment.auction_id) {
                return Err("solver commitment references unknown auction".to_string());
            }
            if !self
                .solver_authorizations
                .contains_key(&commitment.authorization_id)
            {
                return Err("solver commitment references unknown auth".to_string());
            }
            if !solver_ids.contains(&commitment.solver_id) {
                return Err("solver commitment references unknown solver".to_string());
            }
        }
        for matched in self.mev_resistant_matches.values() {
            matched.validate()?;
            if !self.batch_auctions.contains_key(&matched.auction_id) {
                return Err("match references unknown auction".to_string());
            }
            if !self
                .solver_commitments
                .contains_key(&matched.solver_commitment_id)
            {
                return Err("match references unknown solver commitment".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.mev_resistant_matches.contains_key(&receipt.match_id) {
                return Err("receipt references unknown match".to_string());
            }
        }
        for rebate in self.low_fee_rebates.values() {
            rebate.validate()?;
            if !self.mev_resistant_matches.contains_key(&rebate.match_id) {
                return Err("rebate references unknown match".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_intent_matchmaking_pool_owner_commitment(owner_label: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-OWNER",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(owner_label)],
        32,
    )
}

pub fn private_intent_matchmaking_pool_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-ASSET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn private_intent_matchmaking_pool_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-AMOUNT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_price_commitment(
    numerator: u64,
    denominator: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-PRICE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(numerator as i128),
            HashPart::Int(denominator as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_blinding(label: &str, nonce: u64, purpose: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_record_root(domain: &str, payload: &Value) -> String {
    private_intent_matchmaking_pool_payload_root(domain, payload)
}

pub fn private_intent_matchmaking_pool_object_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-INTENT-MATCHMAKING-POOL-{domain}"),
        records,
    )
}

pub fn private_intent_matchmaking_pool_value_root(domain: &str, values: &[Value]) -> String {
    merkle_root(&format!("PRIVATE-INTENT-MATCHMAKING-POOL-{domain}"), values)
}

pub fn private_intent_matchmaking_pool_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-INTENT-MATCHMAKING-POOL-{domain}"),
        &leaves,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_intent_id(
    intent_kind: &str,
    visibility_class: &str,
    owner_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_commitment: &str,
    limit_price_commitment: &str,
    route_hint_root: &str,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-INTENT-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_kind),
            HashPart::Str(visibility_class),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(limit_price_commitment),
            HashPart::Str(route_hint_root),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_solver_authorization_id(
    solver_id: &str,
    operator_commitment: &str,
    auth_public_key_commitment: &str,
    kem_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-SOLVER-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(operator_commitment),
            HashPart::Str(auth_public_key_commitment),
            HashPart::Str(kem_public_key_commitment),
            HashPart::Str(scope_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_auction_id(
    pool_id: &str,
    intent_root: &str,
    solver_authorization_root: &str,
    mev_policy_root: &str,
    collect_start_height: u64,
    collect_end_height: u64,
    ordering_seed: &str,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-AUCTION-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(intent_root),
            HashPart::Str(solver_authorization_root),
            HashPart::Str(mev_policy_root),
            HashPart::Int(collect_start_height as i128),
            HashPart::Int(collect_end_height as i128),
            HashPart::Str(ordering_seed),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_solver_commitment_id(
    auction_id: &str,
    solver_id: &str,
    authorization_id: &str,
    intent_commitment_root: &str,
    quote_commitment_root: &str,
    sealed_solution_root: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(authorization_id),
            HashPart::Str(intent_commitment_root),
            HashPart::Str(quote_commitment_root),
            HashPart::Str(sealed_solution_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_match_id(
    auction_id: &str,
    solver_commitment_id: &str,
    intent_root: &str,
    fill_root: &str,
    clearing_price_root: &str,
    nullifier_root: &str,
    matched_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-MATCH-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment_id),
            HashPart::Str(intent_root),
            HashPart::Str(fill_root),
            HashPart::Str(clearing_price_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(matched_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_rebate_id(
    match_id: &str,
    beneficiary_commitment: &str,
    fee_asset_commitment: &str,
    gross_fee_units: u64,
    rebate_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-REBATE-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(match_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(fee_asset_commitment),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(rebate_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_receipt_nullifier(
    match_id: &str,
    solver_id: &str,
    receipt_secret: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-RECEIPT-NULLIFIER",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(match_id),
            HashPart::Str(solver_id),
            HashPart::Str(receipt_secret),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_matchmaking_pool_receipt_id(
    match_id: &str,
    auction_id: &str,
    solver_id: &str,
    receipt_nullifier: &str,
    output_note_root: &str,
    settlement_proof_root: &str,
    published_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(match_id),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(receipt_nullifier),
            HashPart::Str(output_note_root),
            HashPart::Str(settlement_proof_root),
            HashPart::Int(published_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_ordering_seed(
    pool_id: &str,
    height: u64,
    intent_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-ORDERING-SEED",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(height as i128),
            HashPart::Str(intent_root),
        ],
        32,
    )
}

pub fn private_intent_matchmaking_pool_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-INTENT-MATCHMAKING-POOL-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_INTENT_MATCHMAKING_POOL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateIntentMatchmakingPoolResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateIntentMatchmakingPoolResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}
