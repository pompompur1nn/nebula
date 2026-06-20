use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type IntentSettlementResult<T> = Result<T, String>;

pub const INTENT_SETTLEMENT_PROTOCOL_VERSION: u64 = 1;
pub const INTENT_SETTLEMENT_ENCRYPTION_SCHEME: &str = "devnet-sealed-defi-intent-v1";
pub const INTENT_SETTLEMENT_COMMITMENT_SCHEME: &str = "devnet-shake256-intent-commitment-v1";
pub const INTENT_SETTLEMENT_PARTIAL_FILL_NOTE_SCHEME: &str = "devnet-private-partial-fill-note-v1";
pub const INTENT_SETTLEMENT_MEV_COMMITMENT_SCHEME: &str = "commit-reveal-mev-shield-v1";
pub const INTENT_SETTLEMENT_PQ_ATTESTATION_SCHEME: &str = "ml-dsa-87-solver-attestation-v1";
pub const INTENT_SETTLEMENT_AUCTION_POLICY: &str = "uniform-clearing-batch-auction";
pub const INTENT_SETTLEMENT_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const INTENT_SETTLEMENT_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 16;
pub const INTENT_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const INTENT_SETTLEMENT_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const INTENT_SETTLEMENT_DEFAULT_BRIDGE_EXIT_TTL_BLOCKS: u64 = 720;
pub const INTENT_SETTLEMENT_DEFAULT_MEV_REVEAL_DELAY_BLOCKS: u64 = 2;
pub const INTENT_SETTLEMENT_DEFAULT_LOW_FEE_REBATE_CAP_BPS: u64 = 7_500;
pub const INTENT_SETTLEMENT_DEFAULT_MIN_PARTIAL_FILL_BPS: u64 = 2_500;
pub const INTENT_SETTLEMENT_DEFAULT_MAX_BUNDLE_INTENTS: usize = 256;
pub const INTENT_SETTLEMENT_DEFAULT_MAX_GROUP_LEGS: usize = 512;
pub const INTENT_SETTLEMENT_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 100_000;
pub const INTENT_SETTLEMENT_DEVNET_HEIGHT: u64 = 144;
pub const INTENT_SETTLEMENT_DEVNET_FEE_ASSET_ID: &str = "usdd-devnet";
pub const INTENT_SETTLEMENT_DEVNET_LOW_FEE_LANE: &str = "private-defi-intents";
pub const INTENT_SETTLEMENT_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const INTENT_SETTLEMENT_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDomain {
    Token,
    Swap,
    Lending,
    Perp,
    Bridge,
    Composite,
    Custom(String),
}

impl SettlementDomain {
    pub fn as_str(&self) -> String {
        match self {
            Self::Token => "token".to_string(),
            Self::Swap => "swap".to_string(),
            Self::Lending => "lending".to_string(),
            Self::Perp => "perp".to_string(),
            Self::Bridge => "bridge".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    TokenTransfer,
    TokenRedeem,
    SwapExactIn,
    SwapExactOut,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingWithdraw,
    PerpOpen,
    PerpClose,
    PerpFunding,
    BridgeExit,
    Composite,
    Custom(String),
}

impl IntentKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::TokenTransfer => "token_transfer".to_string(),
            Self::TokenRedeem => "token_redeem".to_string(),
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::SwapExactOut => "swap_exact_out".to_string(),
            Self::LendingSupply => "lending_supply".to_string(),
            Self::LendingBorrow => "lending_borrow".to_string(),
            Self::LendingRepay => "lending_repay".to_string(),
            Self::LendingWithdraw => "lending_withdraw".to_string(),
            Self::PerpOpen => "perp_open".to_string(),
            Self::PerpClose => "perp_close".to_string(),
            Self::PerpFunding => "perp_funding".to_string(),
            Self::BridgeExit => "bridge_exit".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_swap(&self) -> bool {
        matches!(self, Self::SwapExactIn | Self::SwapExactOut)
    }

    pub fn is_lending(&self) -> bool {
        matches!(
            self,
            Self::LendingSupply | Self::LendingBorrow | Self::LendingRepay | Self::LendingWithdraw
        )
    }

    pub fn is_perp(&self) -> bool {
        matches!(self, Self::PerpOpen | Self::PerpClose | Self::PerpFunding)
    }

    pub fn is_bridge_exit(&self) -> bool {
        matches!(self, Self::BridgeExit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Pending,
    Matched,
    PartiallyFilled,
    Filled,
    Expired,
    Cancelled,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Matched => "matched",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(self, Self::Pending | Self::Matched | Self::PartiallyFilled)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Collecting,
    Clearing,
    Cleared,
    Settled,
    Challenged,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBundleStatus {
    Proposed,
    Selected,
    Settled,
    Challenged,
    Slashed,
    Expired,
}

impl SolverBundleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingPriceStatus {
    Proposed,
    Cleared,
    Finalized,
    Challenged,
}

impl ClearingPriceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Cleared => "cleared",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementGroupStatus {
    Pending,
    Executing,
    Settled,
    Failed,
    Challenged,
    Reverted,
}

impl SettlementGroupStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Challenged => "challenged",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Issued,
    Consumed,
    Expired,
    Challenged,
}

impl RebateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn counts_as_pending(&self) -> bool {
        matches!(self, Self::Pending | Self::Issued)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialFillStatus {
    Pending,
    Spendable,
    Spent,
    Refunded,
    Challenged,
}

impl PartialFillStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Spendable => "spendable",
            Self::Spent => "spent",
            Self::Refunded => "refunded",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MevCommitmentStatus {
    Committed,
    Revealed,
    Used,
    Expired,
    Challenged,
}

impl MevCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(self, Self::Committed | Self::Revealed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRouteStatus {
    Proposed,
    Locked,
    Submitted,
    Exited,
    Expired,
    Challenged,
}

impl BridgeRouteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Locked => "locked",
            Self::Submitted => "submitted",
            Self::Exited => "exited",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Active,
    Expired,
    Revoked,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    InvalidClearingPrice,
    InsufficientOutput,
    MissingBridgeExit,
    LendingHealthViolation,
    PerpMarginViolation,
    NullifierConflict,
    MevCommitmentMismatch,
    SolverTimeout,
    Custom(String),
}

impl FailureKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::InvalidClearingPrice => "invalid_clearing_price".to_string(),
            Self::InsufficientOutput => "insufficient_output".to_string(),
            Self::MissingBridgeExit => "missing_bridge_exit".to_string(),
            Self::LendingHealthViolation => "lending_health_violation".to_string(),
            Self::PerpMarginViolation => "perp_margin_violation".to_string(),
            Self::NullifierConflict => "nullifier_conflict".to_string(),
            Self::MevCommitmentMismatch => "mev_commitment_mismatch".to_string(),
            Self::SolverTimeout => "solver_timeout".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Responded,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Responded => "responded",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    BundleEquivocation,
    InvalidPqAttestation,
    DoubleSpendNullifier,
    WithheldBridgeProof,
    InvalidPartialFill,
    PriceManipulation,
    Custom(String),
}

impl SlashingEvidenceKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::BundleEquivocation => "bundle_equivocation".to_string(),
            Self::InvalidPqAttestation => "invalid_pq_attestation".to_string(),
            Self::DoubleSpendNullifier => "double_spend_nullifier".to_string(),
            Self::WithheldBridgeProof => "withheld_bridge_proof".to_string(),
            Self::InvalidPartialFill => "invalid_partial_fill".to_string(),
            Self::PriceManipulation => "price_manipulation".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Pending,
    Proven,
    Rejected,
    Applied,
    Expired,
}

impl SlashingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proven => "proven",
            Self::Rejected => "rejected",
            Self::Applied => "applied",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_pending(&self) -> bool {
        matches!(self, Self::Pending | Self::Proven)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementConfig {
    pub auction_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub bridge_exit_ttl_blocks: u64,
    pub mev_reveal_delay_blocks: u64,
    pub min_partial_fill_bps: u64,
    pub low_fee_rebate_cap_bps: u64,
    pub max_bundle_intents: usize,
    pub max_settlement_group_legs: usize,
    pub min_solver_bond_units: u64,
    pub default_fee_asset_id: String,
    pub default_low_fee_lane: String,
    pub settlement_oracle_root: String,
    pub risk_committee_root: String,
    pub pq_attestation_scheme: String,
    pub encryption_scheme: String,
    pub commitment_scheme: String,
    pub partial_fill_note_scheme: String,
    pub auction_policy: String,
}

impl Default for IntentSettlementConfig {
    fn default() -> Self {
        Self {
            auction_window_blocks: INTENT_SETTLEMENT_DEFAULT_AUCTION_WINDOW_BLOCKS,
            settlement_window_blocks: INTENT_SETTLEMENT_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks: INTENT_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            intent_ttl_blocks: INTENT_SETTLEMENT_DEFAULT_INTENT_TTL_BLOCKS,
            bridge_exit_ttl_blocks: INTENT_SETTLEMENT_DEFAULT_BRIDGE_EXIT_TTL_BLOCKS,
            mev_reveal_delay_blocks: INTENT_SETTLEMENT_DEFAULT_MEV_REVEAL_DELAY_BLOCKS,
            min_partial_fill_bps: INTENT_SETTLEMENT_DEFAULT_MIN_PARTIAL_FILL_BPS,
            low_fee_rebate_cap_bps: INTENT_SETTLEMENT_DEFAULT_LOW_FEE_REBATE_CAP_BPS,
            max_bundle_intents: INTENT_SETTLEMENT_DEFAULT_MAX_BUNDLE_INTENTS,
            max_settlement_group_legs: INTENT_SETTLEMENT_DEFAULT_MAX_GROUP_LEGS,
            min_solver_bond_units: INTENT_SETTLEMENT_DEFAULT_MIN_SOLVER_BOND_UNITS,
            default_fee_asset_id: INTENT_SETTLEMENT_DEVNET_FEE_ASSET_ID.to_string(),
            default_low_fee_lane: INTENT_SETTLEMENT_DEVNET_LOW_FEE_LANE.to_string(),
            settlement_oracle_root: intent_settlement_string_root(
                "INTENT-SETTLEMENT-DEFAULT-ORACLE",
                "devnet-private-defi-oracle",
            ),
            risk_committee_root: intent_settlement_string_set_root(
                "INTENT-SETTLEMENT-DEFAULT-RISK-COMMITTEE",
                &[
                    "devnet-risk-committee-1".to_string(),
                    "devnet-risk-committee-2".to_string(),
                    "devnet-risk-committee-3".to_string(),
                ],
            ),
            pq_attestation_scheme: INTENT_SETTLEMENT_PQ_ATTESTATION_SCHEME.to_string(),
            encryption_scheme: INTENT_SETTLEMENT_ENCRYPTION_SCHEME.to_string(),
            commitment_scheme: INTENT_SETTLEMENT_COMMITMENT_SCHEME.to_string(),
            partial_fill_note_scheme: INTENT_SETTLEMENT_PARTIAL_FILL_NOTE_SCHEME.to_string(),
            auction_policy: INTENT_SETTLEMENT_AUCTION_POLICY.to_string(),
        }
    }
}

impl IntentSettlementConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        if self.auction_window_blocks == 0 {
            return Err("intent settlement auction window must be positive".to_string());
        }
        if self.settlement_window_blocks == 0 {
            return Err("intent settlement settlement window must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("intent settlement challenge window must be positive".to_string());
        }
        if self.intent_ttl_blocks <= self.auction_window_blocks {
            return Err("intent settlement ttl must cover auction window".to_string());
        }
        if self.bridge_exit_ttl_blocks < self.challenge_window_blocks {
            return Err("bridge exit ttl must cover challenge window".to_string());
        }
        ensure_bps(self.min_partial_fill_bps, "min partial fill bps")?;
        ensure_bps(self.low_fee_rebate_cap_bps, "low fee rebate cap bps")?;
        if self.min_partial_fill_bps == 0 {
            return Err("min partial fill bps must be positive".to_string());
        }
        if self.max_bundle_intents == 0 {
            return Err("max bundle intents must be positive".to_string());
        }
        if self.max_settlement_group_legs == 0 {
            return Err("max settlement group legs must be positive".to_string());
        }
        if self.min_solver_bond_units == 0 {
            return Err("min solver bond units must be positive".to_string());
        }
        ensure_non_empty(&self.default_fee_asset_id, "default fee asset id")?;
        ensure_non_empty(&self.default_low_fee_lane, "default low fee lane")?;
        ensure_non_empty(&self.settlement_oracle_root, "settlement oracle root")?;
        ensure_non_empty(&self.risk_committee_root, "risk committee root")?;
        ensure_non_empty(&self.pq_attestation_scheme, "pq attestation scheme")?;
        ensure_non_empty(&self.encryption_scheme, "encryption scheme")?;
        ensure_non_empty(&self.commitment_scheme, "commitment scheme")?;
        ensure_non_empty(&self.partial_fill_note_scheme, "partial fill note scheme")?;
        ensure_non_empty(&self.auction_policy, "auction policy")?;
        Ok(self.config_root())
    }

    pub fn config_root(&self) -> String {
        intent_settlement_payload_root("INTENT-SETTLEMENT-CONFIG", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_config",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "auction_window_blocks": self.auction_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "bridge_exit_ttl_blocks": self.bridge_exit_ttl_blocks,
            "mev_reveal_delay_blocks": self.mev_reveal_delay_blocks,
            "min_partial_fill_bps": self.min_partial_fill_bps,
            "low_fee_rebate_cap_bps": self.low_fee_rebate_cap_bps,
            "max_bundle_intents": self.max_bundle_intents as u64,
            "max_settlement_group_legs": self.max_settlement_group_legs as u64,
            "min_solver_bond_units": self.min_solver_bond_units,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "settlement_oracle_root": self.settlement_oracle_root,
            "risk_committee_root": self.risk_committee_root,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": self.commitment_scheme,
            "partial_fill_note_scheme": self.partial_fill_note_scheme,
            "auction_policy": self.auction_policy,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDefiIntent {
    pub intent_id: String,
    pub intent_kind: IntentKind,
    pub settlement_domains: Vec<SettlementDomain>,
    pub owner_commitment: String,
    pub input_asset_commitment: String,
    pub output_asset_commitment: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub limit_price_commitment: String,
    pub collateral_commitment: String,
    pub leverage_commitment: String,
    pub solver_whitelist_root: String,
    pub route_hint_root: String,
    pub mev_policy_root: String,
    pub public_metadata_root: String,
    pub encrypted_payload_root: String,
    pub encryption_scheme: String,
    pub max_slippage_bps: u64,
    pub min_fill_bps: u64,
    pub allow_partial_fill: bool,
    pub low_fee_lane_id: String,
    pub submitted_at_height: u64,
    pub deadline_height: u64,
    pub nonce: u64,
    pub status: IntentStatus,
}

impl EncryptedDefiIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        intent_kind: IntentKind,
        settlement_domains: Vec<SettlementDomain>,
        input_asset_id: &str,
        output_asset_id: &str,
        amount_in_units: u64,
        min_amount_out_units: u64,
        limit_price_numerator: u64,
        limit_price_denominator: u64,
        collateral_units: u64,
        leverage_bps: u64,
        max_slippage_bps: u64,
        min_fill_bps: u64,
        allow_partial_fill: bool,
        low_fee_lane_id: impl Into<String>,
        submitted_at_height: u64,
        deadline_height: u64,
        nonce: u64,
        encrypted_payload: &Value,
        solver_whitelist: &[String],
        route_hints: &[String],
        mev_policy: &Value,
        public_metadata: &Value,
    ) -> IntentSettlementResult<Self> {
        ensure_non_empty(owner_label, "intent owner label")?;
        ensure_non_empty(input_asset_id, "intent input asset id")?;
        ensure_non_empty(output_asset_id, "intent output asset id")?;
        ensure_positive(amount_in_units, "intent amount in")?;
        ensure_positive(min_amount_out_units, "intent min amount out")?;
        if limit_price_denominator == 0 {
            return Err("intent limit price denominator cannot be zero".to_string());
        }
        ensure_bps(max_slippage_bps, "intent max slippage bps")?;
        ensure_bps(min_fill_bps, "intent min fill bps")?;
        if min_fill_bps == 0 {
            return Err("intent min fill bps must be positive".to_string());
        }
        if deadline_height <= submitted_at_height {
            return Err("intent deadline must be after submission".to_string());
        }
        if settlement_domains.is_empty() {
            return Err("intent requires at least one settlement domain".to_string());
        }
        let low_fee_lane_id = low_fee_lane_id.into();
        ensure_non_empty(&low_fee_lane_id, "intent low fee lane id")?;

        let owner_commitment = intent_settlement_account_commitment(owner_label);
        let input_asset_commitment = intent_settlement_asset_commitment(input_asset_id);
        let output_asset_commitment = intent_settlement_asset_commitment(output_asset_id);
        let amount_in_commitment = intent_settlement_amount_commitment(
            amount_in_units,
            &intent_settlement_blinding(owner_label, nonce, "amount_in"),
        );
        let min_amount_out_commitment = intent_settlement_amount_commitment(
            min_amount_out_units,
            &intent_settlement_blinding(owner_label, nonce, "min_amount_out"),
        );
        let limit_price_commitment = intent_settlement_price_commitment(
            limit_price_numerator,
            limit_price_denominator,
            &intent_settlement_blinding(owner_label, nonce, "limit_price"),
        );
        let collateral_commitment = intent_settlement_amount_commitment(
            collateral_units,
            &intent_settlement_blinding(owner_label, nonce, "collateral"),
        );
        let leverage_commitment = intent_settlement_amount_commitment(
            leverage_bps,
            &intent_settlement_blinding(owner_label, nonce, "leverage"),
        );
        let solver_whitelist_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-SOLVER-WHITELIST",
            solver_whitelist,
        );
        let route_hint_root =
            intent_settlement_string_set_root("INTENT-SETTLEMENT-INTENT-ROUTE-HINTS", route_hints);
        let mev_policy_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-MEV-POLICY", mev_policy);
        let public_metadata_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-INTENT-METADATA", public_metadata);
        let encrypted_payload_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-ENCRYPTED-INTENT", encrypted_payload);
        let intent_id = intent_settlement_intent_id(
            &intent_kind,
            &owner_commitment,
            &input_asset_commitment,
            &output_asset_commitment,
            &amount_in_commitment,
            &min_amount_out_commitment,
            &limit_price_commitment,
            submitted_at_height,
            deadline_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            intent_kind,
            settlement_domains,
            owner_commitment,
            input_asset_commitment,
            output_asset_commitment,
            amount_in_commitment,
            min_amount_out_commitment,
            limit_price_commitment,
            collateral_commitment,
            leverage_commitment,
            solver_whitelist_root,
            route_hint_root,
            mev_policy_root,
            public_metadata_root,
            encrypted_payload_root,
            encryption_scheme: INTENT_SETTLEMENT_ENCRYPTION_SCHEME.to_string(),
            max_slippage_bps,
            min_fill_bps,
            allow_partial_fill,
            low_fee_lane_id,
            submitted_at_height,
            deadline_height,
            nonce,
            status: IntentStatus::Pending,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_as_active() && self.deadline_height >= height
    }

    pub fn public_record(&self) -> Value {
        let domains = self
            .settlement_domains
            .iter()
            .map(SettlementDomain::as_str)
            .collect::<Vec<_>>();
        json!({
            "kind": "intent_settlement_encrypted_defi_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "settlement_domains": domains,
            "owner_commitment": self.owner_commitment,
            "input_asset_commitment": self.input_asset_commitment,
            "output_asset_commitment": self.output_asset_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "collateral_commitment": self.collateral_commitment,
            "leverage_commitment": self.leverage_commitment,
            "solver_whitelist_root": self.solver_whitelist_root,
            "route_hint_root": self.route_hint_root,
            "mev_policy_root": self.mev_policy_root,
            "public_metadata_root": self.public_metadata_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": INTENT_SETTLEMENT_COMMITMENT_SCHEME,
            "max_slippage_bps": self.max_slippage_bps,
            "min_fill_bps": self.min_fill_bps,
            "allow_partial_fill": self.allow_partial_fill,
            "low_fee_lane_id": self.low_fee_lane_id,
            "submitted_at_height": self.submitted_at_height,
            "deadline_height": self.deadline_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.intent_id, "intent id")?;
        ensure_non_empty(&self.owner_commitment, "intent owner commitment")?;
        ensure_non_empty(
            &self.input_asset_commitment,
            "intent input asset commitment",
        )?;
        ensure_non_empty(
            &self.output_asset_commitment,
            "intent output asset commitment",
        )?;
        ensure_non_empty(&self.amount_in_commitment, "intent amount in commitment")?;
        ensure_non_empty(
            &self.min_amount_out_commitment,
            "intent min amount out commitment",
        )?;
        ensure_non_empty(
            &self.limit_price_commitment,
            "intent limit price commitment",
        )?;
        ensure_non_empty(&self.collateral_commitment, "intent collateral commitment")?;
        ensure_non_empty(&self.leverage_commitment, "intent leverage commitment")?;
        ensure_non_empty(&self.solver_whitelist_root, "intent solver whitelist root")?;
        ensure_non_empty(&self.route_hint_root, "intent route hint root")?;
        ensure_non_empty(&self.mev_policy_root, "intent mev policy root")?;
        ensure_non_empty(&self.public_metadata_root, "intent metadata root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "intent encrypted payload root",
        )?;
        ensure_non_empty(&self.encryption_scheme, "intent encryption scheme")?;
        ensure_non_empty(&self.low_fee_lane_id, "intent low fee lane id")?;
        if self.settlement_domains.is_empty() {
            return Err("intent requires settlement domains".to_string());
        }
        ensure_unique_strings(
            &self
                .settlement_domains
                .iter()
                .map(SettlementDomain::as_str)
                .collect::<Vec<_>>(),
            "intent settlement domains",
        )?;
        ensure_bps(self.max_slippage_bps, "intent max slippage bps")?;
        ensure_bps(self.min_fill_bps, "intent min fill bps")?;
        if self.min_fill_bps == 0 {
            return Err("intent min fill bps must be positive".to_string());
        }
        if self.deadline_height <= self.submitted_at_height {
            return Err("intent deadline must be after submission".to_string());
        }
        let expected_id = intent_settlement_intent_id(
            &self.intent_kind,
            &self.owner_commitment,
            &self.input_asset_commitment,
            &self.output_asset_commitment,
            &self.amount_in_commitment,
            &self.min_amount_out_commitment,
            &self.limit_price_commitment,
            self.submitted_at_height,
            self.deadline_height,
            self.nonce,
        );
        if self.intent_id != expected_id {
            return Err("intent id mismatch".to_string());
        }
        Ok(self.intent_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevProtectionCommitment {
    pub commitment_id: String,
    pub intent_id: String,
    pub owner_commitment: String,
    pub batch_salt_commitment: String,
    pub encrypted_preference_root: String,
    pub anti_sandwich_root: String,
    pub replay_domain_root: String,
    pub protected_mempool_root: String,
    pub commit_height: u64,
    pub reveal_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: MevCommitmentStatus,
}

impl MevProtectionCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        batch_salt_label: &str,
        encrypted_preferences: &Value,
        anti_sandwich_policy: &Value,
        replay_domain: &Value,
        protected_mempool: &Value,
        commit_height: u64,
        reveal_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let intent_id = intent_id.into();
        let owner_commitment = owner_commitment.into();
        ensure_non_empty(&intent_id, "mev commitment intent id")?;
        ensure_non_empty(&owner_commitment, "mev commitment owner commitment")?;
        ensure_non_empty(batch_salt_label, "mev commitment batch salt label")?;
        if reveal_height < commit_height {
            return Err("mev reveal height cannot precede commit height".to_string());
        }
        if expires_at_height <= reveal_height {
            return Err("mev commitment expiry must be after reveal height".to_string());
        }
        let batch_salt_commitment =
            intent_settlement_string_root("INTENT-SETTLEMENT-BATCH-SALT", batch_salt_label);
        let encrypted_preference_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-MEV-PREFERENCES",
            encrypted_preferences,
        );
        let anti_sandwich_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-ANTI-SANDWICH", anti_sandwich_policy);
        let replay_domain_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-REPLAY-DOMAIN", replay_domain);
        let protected_mempool_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-PROTECTED-MEMPOOL",
            protected_mempool,
        );
        let commitment_id = intent_settlement_mev_commitment_id(
            &intent_id,
            &owner_commitment,
            &batch_salt_commitment,
            &encrypted_preference_root,
            commit_height,
            nonce,
        );
        let commitment = Self {
            commitment_id,
            intent_id,
            owner_commitment,
            batch_salt_commitment,
            encrypted_preference_root,
            anti_sandwich_root,
            replay_domain_root,
            protected_mempool_root,
            commit_height,
            reveal_height,
            expires_at_height,
            nonce,
            status: MevCommitmentStatus::Committed,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_as_active() && self.expires_at_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_mev_protection_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "batch_salt_commitment": self.batch_salt_commitment,
            "encrypted_preference_root": self.encrypted_preference_root,
            "anti_sandwich_root": self.anti_sandwich_root,
            "replay_domain_root": self.replay_domain_root,
            "protected_mempool_root": self.protected_mempool_root,
            "scheme": INTENT_SETTLEMENT_MEV_COMMITMENT_SCHEME,
            "commit_height": self.commit_height,
            "reveal_height": self.reveal_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.commitment_id, "mev commitment id")?;
        ensure_non_empty(&self.intent_id, "mev commitment intent id")?;
        ensure_non_empty(&self.owner_commitment, "mev commitment owner")?;
        ensure_non_empty(&self.batch_salt_commitment, "mev commitment salt")?;
        ensure_non_empty(&self.encrypted_preference_root, "mev preference root")?;
        ensure_non_empty(&self.anti_sandwich_root, "anti sandwich root")?;
        ensure_non_empty(&self.replay_domain_root, "replay domain root")?;
        ensure_non_empty(&self.protected_mempool_root, "protected mempool root")?;
        if self.reveal_height < self.commit_height {
            return Err("mev reveal height cannot precede commit height".to_string());
        }
        if self.expires_at_height <= self.reveal_height {
            return Err("mev commitment expiry must be after reveal".to_string());
        }
        let expected_id = intent_settlement_mev_commitment_id(
            &self.intent_id,
            &self.owner_commitment,
            &self.batch_salt_commitment,
            &self.encrypted_preference_root,
            self.commit_height,
            self.nonce,
        );
        if self.commitment_id != expected_id {
            return Err("mev commitment id mismatch".to_string());
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalRouteHint {
    pub route_hint_id: String,
    pub intent_id: String,
    pub source_domain: String,
    pub destination_domain: String,
    pub remote_chain_id: String,
    pub bridge_adapter_commitment: String,
    pub liquidity_provider_commitment: String,
    pub withdraw_asset_commitment: String,
    pub min_exit_amount_commitment: String,
    pub exit_recipient_commitment: String,
    pub remote_address_commitment: String,
    pub fee_quote_commitment: String,
    pub route_ciphertext_root: String,
    pub withdrawal_proof_root: String,
    pub max_bridge_fee_bps: u64,
    pub estimated_exit_blocks: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: BridgeRouteStatus,
}

impl BridgeWithdrawalRouteHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        source_domain: &str,
        destination_domain: &str,
        remote_chain_id: &str,
        bridge_adapter_label: &str,
        liquidity_provider_label: &str,
        withdraw_asset_id: &str,
        min_exit_amount_units: u64,
        exit_recipient_label: &str,
        remote_address_label: &str,
        max_bridge_fee_bps: u64,
        estimated_exit_blocks: u64,
        route_ciphertext: &Value,
        withdrawal_proof: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let intent_id = intent_id.into();
        ensure_non_empty(&intent_id, "bridge route intent id")?;
        ensure_non_empty(source_domain, "bridge route source domain")?;
        ensure_non_empty(destination_domain, "bridge route destination domain")?;
        ensure_non_empty(remote_chain_id, "bridge route remote chain id")?;
        ensure_non_empty(bridge_adapter_label, "bridge route adapter label")?;
        ensure_non_empty(liquidity_provider_label, "bridge route liquidity provider")?;
        ensure_non_empty(withdraw_asset_id, "bridge route withdraw asset")?;
        ensure_positive(min_exit_amount_units, "bridge route min exit amount")?;
        ensure_non_empty(exit_recipient_label, "bridge route recipient label")?;
        ensure_non_empty(remote_address_label, "bridge route remote address")?;
        ensure_bps(max_bridge_fee_bps, "bridge route max fee bps")?;
        if estimated_exit_blocks == 0 {
            return Err("bridge route estimated exit blocks must be positive".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("bridge route expiry must be after creation".to_string());
        }
        let bridge_adapter_commitment = intent_settlement_account_commitment(bridge_adapter_label);
        let liquidity_provider_commitment =
            intent_settlement_account_commitment(liquidity_provider_label);
        let withdraw_asset_commitment = intent_settlement_asset_commitment(withdraw_asset_id);
        let min_exit_amount_commitment = intent_settlement_amount_commitment(
            min_exit_amount_units,
            &intent_settlement_blinding(exit_recipient_label, nonce, "bridge_min_exit"),
        );
        let exit_recipient_commitment = intent_settlement_account_commitment(exit_recipient_label);
        let remote_address_commitment =
            intent_settlement_string_root("INTENT-SETTLEMENT-REMOTE-ADDRESS", remote_address_label);
        let fee_quote_commitment = intent_settlement_amount_commitment(
            max_bridge_fee_bps,
            &intent_settlement_blinding(bridge_adapter_label, nonce, "bridge_fee_quote"),
        );
        let route_ciphertext_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-BRIDGE-ROUTE-CIPHERTEXT",
            route_ciphertext,
        );
        let withdrawal_proof_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-BRIDGE-WITHDRAWAL-PROOF",
            withdrawal_proof,
        );
        let route_hint_id = intent_settlement_bridge_route_hint_id(
            &intent_id,
            source_domain,
            destination_domain,
            remote_chain_id,
            &bridge_adapter_commitment,
            &exit_recipient_commitment,
            created_at_height,
            nonce,
        );
        let hint = Self {
            route_hint_id,
            intent_id,
            source_domain: source_domain.to_string(),
            destination_domain: destination_domain.to_string(),
            remote_chain_id: remote_chain_id.to_string(),
            bridge_adapter_commitment,
            liquidity_provider_commitment,
            withdraw_asset_commitment,
            min_exit_amount_commitment,
            exit_recipient_commitment,
            remote_address_commitment,
            fee_quote_commitment,
            route_ciphertext_root,
            withdrawal_proof_root,
            max_bridge_fee_bps,
            estimated_exit_blocks,
            created_at_height,
            expires_at_height,
            nonce,
            status: BridgeRouteStatus::Proposed,
        };
        hint.validate()?;
        Ok(hint)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            BridgeRouteStatus::Proposed | BridgeRouteStatus::Locked | BridgeRouteStatus::Submitted
        ) && self.expires_at_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_bridge_withdrawal_route_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "route_hint_id": self.route_hint_id,
            "intent_id": self.intent_id,
            "source_domain": self.source_domain,
            "destination_domain": self.destination_domain,
            "remote_chain_id": self.remote_chain_id,
            "bridge_adapter_commitment": self.bridge_adapter_commitment,
            "liquidity_provider_commitment": self.liquidity_provider_commitment,
            "withdraw_asset_commitment": self.withdraw_asset_commitment,
            "min_exit_amount_commitment": self.min_exit_amount_commitment,
            "exit_recipient_commitment": self.exit_recipient_commitment,
            "remote_address_commitment": self.remote_address_commitment,
            "fee_quote_commitment": self.fee_quote_commitment,
            "route_ciphertext_root": self.route_ciphertext_root,
            "withdrawal_proof_root": self.withdrawal_proof_root,
            "max_bridge_fee_bps": self.max_bridge_fee_bps,
            "estimated_exit_blocks": self.estimated_exit_blocks,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.route_hint_id, "bridge route hint id")?;
        ensure_non_empty(&self.intent_id, "bridge route intent id")?;
        ensure_non_empty(&self.source_domain, "bridge route source")?;
        ensure_non_empty(&self.destination_domain, "bridge route destination")?;
        ensure_non_empty(&self.remote_chain_id, "bridge route remote chain")?;
        ensure_non_empty(&self.bridge_adapter_commitment, "bridge adapter commitment")?;
        ensure_non_empty(
            &self.liquidity_provider_commitment,
            "bridge liquidity provider commitment",
        )?;
        ensure_non_empty(&self.withdraw_asset_commitment, "bridge withdraw asset")?;
        ensure_non_empty(&self.min_exit_amount_commitment, "bridge min exit amount")?;
        ensure_non_empty(&self.exit_recipient_commitment, "bridge exit recipient")?;
        ensure_non_empty(&self.remote_address_commitment, "bridge remote address")?;
        ensure_non_empty(&self.fee_quote_commitment, "bridge fee quote")?;
        ensure_non_empty(&self.route_ciphertext_root, "bridge route ciphertext")?;
        ensure_non_empty(&self.withdrawal_proof_root, "bridge withdrawal proof")?;
        ensure_bps(self.max_bridge_fee_bps, "bridge route max fee bps")?;
        if self.estimated_exit_blocks == 0 {
            return Err("bridge route estimated exit blocks must be positive".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("bridge route expiry must be after creation".to_string());
        }
        let expected_id = intent_settlement_bridge_route_hint_id(
            &self.intent_id,
            &self.source_domain,
            &self.destination_domain,
            &self.remote_chain_id,
            &self.bridge_adapter_commitment,
            &self.exit_recipient_commitment,
            self.created_at_height,
            self.nonce,
        );
        if self.route_hint_id != expected_id {
            return Err("bridge route hint id mismatch".to_string());
        }
        Ok(self.route_hint_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverPqAttestation {
    pub attestation_id: String,
    pub solver_commitment: String,
    pub solver_operator_commitment: String,
    pub scheme: String,
    pub committee_root: String,
    pub public_key_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub capability_root: String,
    pub bond_commitment: String,
    pub risk_score_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub nonce: u64,
    pub status: AttestationStatus,
}

impl SolverPqAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_label: &str,
        solver_operator_label: &str,
        committee_members: &[String],
        public_keys: &[String],
        transcript: &Value,
        signature_payload: &Value,
        capabilities: &[String],
        bond_units: u64,
        risk_score_bps: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        ensure_non_empty(solver_label, "solver attestation solver label")?;
        ensure_non_empty(solver_operator_label, "solver attestation operator label")?;
        if committee_members.is_empty() {
            return Err("solver attestation requires committee members".to_string());
        }
        if public_keys.is_empty() {
            return Err("solver attestation requires public keys".to_string());
        }
        if capabilities.is_empty() {
            return Err("solver attestation requires capabilities".to_string());
        }
        ensure_positive(bond_units, "solver attestation bond units")?;
        ensure_bps(risk_score_bps, "solver attestation risk score bps")?;
        if valid_until_height <= valid_from_height {
            return Err("solver attestation validity window is empty".to_string());
        }
        let solver_commitment = intent_settlement_solver_commitment(solver_label);
        let solver_operator_commitment =
            intent_settlement_account_commitment(solver_operator_label);
        let committee_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-SOLVER-COMMITTEE",
            committee_members,
        );
        let public_key_root =
            intent_settlement_string_set_root("INTENT-SETTLEMENT-SOLVER-PUBLIC-KEYS", public_keys);
        let transcript_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-SOLVER-TRANSCRIPT", transcript);
        let signature_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-SOLVER-SIGNATURE", signature_payload);
        let capability_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-SOLVER-CAPABILITIES",
            capabilities,
        );
        let bond_commitment = intent_settlement_amount_commitment(
            bond_units,
            &intent_settlement_blinding(solver_label, nonce, "solver_bond"),
        );
        let scheme = INTENT_SETTLEMENT_PQ_ATTESTATION_SCHEME.to_string();
        let attestation_id = intent_settlement_pq_attestation_id(
            &solver_commitment,
            &scheme,
            &committee_root,
            &transcript_root,
            valid_from_height,
            nonce,
        );
        let attestation = Self {
            attestation_id,
            solver_commitment,
            solver_operator_commitment,
            scheme,
            committee_root,
            public_key_root,
            transcript_root,
            signature_root,
            capability_root,
            bond_commitment,
            risk_score_bps,
            valid_from_height,
            valid_until_height,
            nonce,
            status: AttestationStatus::Active,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_as_active()
            && self.valid_from_height <= height
            && self.valid_until_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_pq_solver_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "solver_commitment": self.solver_commitment,
            "solver_operator_commitment": self.solver_operator_commitment,
            "scheme": self.scheme,
            "committee_root": self.committee_root,
            "public_key_root": self.public_key_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "capability_root": self.capability_root,
            "bond_commitment": self.bond_commitment,
            "risk_score_bps": self.risk_score_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.attestation_id, "solver attestation id")?;
        ensure_non_empty(&self.solver_commitment, "solver commitment")?;
        ensure_non_empty(&self.solver_operator_commitment, "solver operator")?;
        ensure_non_empty(&self.scheme, "solver attestation scheme")?;
        ensure_non_empty(&self.committee_root, "solver committee root")?;
        ensure_non_empty(&self.public_key_root, "solver public key root")?;
        ensure_non_empty(&self.transcript_root, "solver transcript root")?;
        ensure_non_empty(&self.signature_root, "solver signature root")?;
        ensure_non_empty(&self.capability_root, "solver capability root")?;
        ensure_non_empty(&self.bond_commitment, "solver bond commitment")?;
        ensure_bps(self.risk_score_bps, "solver risk score bps")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("solver attestation validity window is empty".to_string());
        }
        let expected_id = intent_settlement_pq_attestation_id(
            &self.solver_commitment,
            &self.scheme,
            &self.committee_root,
            &self.transcript_root,
            self.valid_from_height,
            self.nonce,
        );
        if self.attestation_id != expected_id {
            return Err("solver attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuction {
    pub auction_id: String,
    pub market_id: String,
    pub auction_domain: SettlementDomain,
    pub intent_root: String,
    pub route_hint_root: String,
    pub mev_commitment_root: String,
    pub bridge_hint_root: String,
    pub solver_bundle_root: String,
    pub clearing_price_root: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub settle_height: u64,
    pub challenge_deadline_height: u64,
    pub clearing_seed: String,
    pub uniform_price_policy_root: String,
    pub status: AuctionStatus,
}

impl BatchAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        auction_domain: SettlementDomain,
        intent_root: impl Into<String>,
        route_hint_root: impl Into<String>,
        mev_commitment_root: impl Into<String>,
        bridge_hint_root: impl Into<String>,
        commit_start_height: u64,
        commit_end_height: u64,
        settle_height: u64,
        challenge_deadline_height: u64,
        clearing_seed_label: &str,
        uniform_price_policy: &Value,
    ) -> IntentSettlementResult<Self> {
        ensure_non_empty(market_id, "batch auction market id")?;
        if commit_end_height <= commit_start_height {
            return Err("batch auction commit end must be after start".to_string());
        }
        if settle_height < commit_end_height {
            return Err("batch auction settle height must follow commit end".to_string());
        }
        if challenge_deadline_height <= settle_height {
            return Err("batch auction challenge deadline must follow settle height".to_string());
        }
        ensure_non_empty(clearing_seed_label, "batch auction clearing seed")?;
        let intent_root = intent_root.into();
        let route_hint_root = route_hint_root.into();
        let mev_commitment_root = mev_commitment_root.into();
        let bridge_hint_root = bridge_hint_root.into();
        ensure_non_empty(&intent_root, "batch auction intent root")?;
        ensure_non_empty(&route_hint_root, "batch auction route hint root")?;
        ensure_non_empty(&mev_commitment_root, "batch auction mev root")?;
        ensure_non_empty(&bridge_hint_root, "batch auction bridge hint root")?;
        let clearing_seed =
            intent_settlement_string_root("INTENT-SETTLEMENT-CLEARING-SEED", clearing_seed_label);
        let uniform_price_policy_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-UNIFORM-PRICE-POLICY",
            uniform_price_policy,
        );
        let auction_id = intent_settlement_batch_auction_id(
            market_id,
            &auction_domain,
            &intent_root,
            commit_start_height,
            &clearing_seed,
        );
        let auction = Self {
            auction_id,
            market_id: market_id.to_string(),
            auction_domain,
            intent_root,
            route_hint_root,
            mev_commitment_root,
            bridge_hint_root,
            solver_bundle_root: merkle_root("INTENT-SETTLEMENT-EMPTY-SOLVER-BUNDLES", &[]),
            clearing_price_root: merkle_root("INTENT-SETTLEMENT-EMPTY-CLEARING-PRICES", &[]),
            commit_start_height,
            commit_end_height,
            settle_height,
            challenge_deadline_height,
            clearing_seed,
            uniform_price_policy_root,
            status: AuctionStatus::Collecting,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        matches!(self.status, AuctionStatus::Collecting)
            && self.commit_start_height <= height
            && self.commit_end_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_batch_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "auction_domain": self.auction_domain.as_str(),
            "intent_root": self.intent_root,
            "route_hint_root": self.route_hint_root,
            "mev_commitment_root": self.mev_commitment_root,
            "bridge_hint_root": self.bridge_hint_root,
            "solver_bundle_root": self.solver_bundle_root,
            "clearing_price_root": self.clearing_price_root,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "settle_height": self.settle_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "clearing_seed": self.clearing_seed,
            "uniform_price_policy_root": self.uniform_price_policy_root,
            "auction_policy": INTENT_SETTLEMENT_AUCTION_POLICY,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.auction_id, "batch auction id")?;
        ensure_non_empty(&self.market_id, "batch auction market id")?;
        ensure_non_empty(&self.intent_root, "batch auction intent root")?;
        ensure_non_empty(&self.route_hint_root, "batch auction route hint root")?;
        ensure_non_empty(&self.mev_commitment_root, "batch auction mev root")?;
        ensure_non_empty(&self.bridge_hint_root, "batch auction bridge hint root")?;
        ensure_non_empty(&self.solver_bundle_root, "batch auction bundle root")?;
        ensure_non_empty(
            &self.clearing_price_root,
            "batch auction clearing price root",
        )?;
        ensure_non_empty(&self.clearing_seed, "batch auction clearing seed")?;
        ensure_non_empty(
            &self.uniform_price_policy_root,
            "batch auction uniform price policy root",
        )?;
        if self.commit_end_height <= self.commit_start_height {
            return Err("batch auction commit end must be after start".to_string());
        }
        if self.settle_height < self.commit_end_height {
            return Err("batch auction settle height must follow commit end".to_string());
        }
        if self.challenge_deadline_height <= self.settle_height {
            return Err("batch auction challenge deadline must follow settle height".to_string());
        }
        let expected_id = intent_settlement_batch_auction_id(
            &self.market_id,
            &self.auction_domain,
            &self.intent_root,
            self.commit_start_height,
            &self.clearing_seed,
        );
        if self.auction_id != expected_id {
            return Err("batch auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuctionClearingPrice {
    pub clearing_price_id: String,
    pub auction_id: String,
    pub pair_commitment: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub price_numerator: u64,
    pub price_denominator: u64,
    pub notional_cleared_units: u64,
    pub surplus_commitment: String,
    pub solver_fee_bps: u64,
    pub price_proof_root: String,
    pub cleared_at_height: u64,
    pub nonce: u64,
    pub status: ClearingPriceStatus,
}

impl BatchAuctionClearingPrice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        base_asset_id: &str,
        quote_asset_id: &str,
        price_numerator: u64,
        price_denominator: u64,
        notional_cleared_units: u64,
        surplus_units: u64,
        solver_fee_bps: u64,
        price_proof: &Value,
        cleared_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let auction_id = auction_id.into();
        ensure_non_empty(&auction_id, "clearing price auction id")?;
        ensure_non_empty(base_asset_id, "clearing price base asset")?;
        ensure_non_empty(quote_asset_id, "clearing price quote asset")?;
        ensure_positive(price_numerator, "clearing price numerator")?;
        if price_denominator == 0 {
            return Err("clearing price denominator cannot be zero".to_string());
        }
        ensure_bps(solver_fee_bps, "clearing price solver fee bps")?;
        let base_asset_commitment = intent_settlement_asset_commitment(base_asset_id);
        let quote_asset_commitment = intent_settlement_asset_commitment(quote_asset_id);
        let pair_commitment =
            intent_settlement_asset_pair_commitment(base_asset_id, quote_asset_id);
        let surplus_commitment = intent_settlement_amount_commitment(
            surplus_units,
            &intent_settlement_blinding(base_asset_id, nonce, "clearing_surplus"),
        );
        let price_proof_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-CLEARING-PRICE-PROOF", price_proof);
        let clearing_price_id = intent_settlement_clearing_price_id(
            &auction_id,
            &pair_commitment,
            price_numerator,
            price_denominator,
            cleared_at_height,
            nonce,
        );
        let price = Self {
            clearing_price_id,
            auction_id,
            pair_commitment,
            base_asset_commitment,
            quote_asset_commitment,
            price_numerator,
            price_denominator,
            notional_cleared_units,
            surplus_commitment,
            solver_fee_bps,
            price_proof_root,
            cleared_at_height,
            nonce,
            status: ClearingPriceStatus::Cleared,
        };
        price.validate()?;
        Ok(price)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_batch_auction_clearing_price",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "clearing_price_id": self.clearing_price_id,
            "auction_id": self.auction_id,
            "pair_commitment": self.pair_commitment,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "price_numerator": self.price_numerator,
            "price_denominator": self.price_denominator,
            "price_scale": INTENT_SETTLEMENT_PRICE_SCALE,
            "notional_cleared_units": self.notional_cleared_units,
            "surplus_commitment": self.surplus_commitment,
            "solver_fee_bps": self.solver_fee_bps,
            "price_proof_root": self.price_proof_root,
            "cleared_at_height": self.cleared_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.clearing_price_id, "clearing price id")?;
        ensure_non_empty(&self.auction_id, "clearing price auction id")?;
        ensure_non_empty(&self.pair_commitment, "clearing price pair")?;
        ensure_non_empty(&self.base_asset_commitment, "clearing price base asset")?;
        ensure_non_empty(&self.quote_asset_commitment, "clearing price quote asset")?;
        ensure_positive(self.price_numerator, "clearing price numerator")?;
        if self.price_denominator == 0 {
            return Err("clearing price denominator cannot be zero".to_string());
        }
        ensure_non_empty(&self.surplus_commitment, "clearing price surplus")?;
        ensure_bps(self.solver_fee_bps, "clearing price solver fee bps")?;
        ensure_non_empty(&self.price_proof_root, "clearing price proof root")?;
        let expected_id = intent_settlement_clearing_price_id(
            &self.auction_id,
            &self.pair_commitment,
            self.price_numerator,
            self.price_denominator,
            self.cleared_at_height,
            self.nonce,
        );
        if self.clearing_price_id != expected_id {
            return Err("clearing price id mismatch".to_string());
        }
        Ok(self.clearing_price_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBundleLeg {
    pub leg_id: String,
    pub intent_id: String,
    pub domain: SettlementDomain,
    pub input_note_root: String,
    pub output_note_root: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_upper_bound: u64,
    pub amount_out_lower_bound: u64,
    pub clearing_price_id: String,
    pub route_hint_id: String,
    pub bridge_hint_id: String,
    pub partial_fill_bps: u64,
    pub fee_units: u64,
    pub rebate_id: String,
    pub execution_payload_root: String,
    pub nonce: u64,
}

impl SolverBundleLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        domain: SettlementDomain,
        input_note_root: impl Into<String>,
        output_note_root: impl Into<String>,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_upper_bound: u64,
        amount_out_lower_bound: u64,
        clearing_price_id: impl Into<String>,
        route_hint_id: impl Into<String>,
        bridge_hint_id: impl Into<String>,
        partial_fill_bps: u64,
        fee_units: u64,
        rebate_id: impl Into<String>,
        execution_payload: &Value,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let intent_id = intent_id.into();
        let input_note_root = input_note_root.into();
        let output_note_root = output_note_root.into();
        let clearing_price_id = clearing_price_id.into();
        let route_hint_id = route_hint_id.into();
        let bridge_hint_id = bridge_hint_id.into();
        let rebate_id = rebate_id.into();
        ensure_non_empty(&intent_id, "bundle leg intent id")?;
        ensure_non_empty(&input_note_root, "bundle leg input note root")?;
        ensure_non_empty(&output_note_root, "bundle leg output note root")?;
        ensure_non_empty(asset_in_id, "bundle leg asset in")?;
        ensure_non_empty(asset_out_id, "bundle leg asset out")?;
        ensure_positive(amount_in_upper_bound, "bundle leg amount in upper bound")?;
        ensure_positive(amount_out_lower_bound, "bundle leg amount out lower bound")?;
        ensure_bps(partial_fill_bps, "bundle leg partial fill bps")?;
        if partial_fill_bps == 0 {
            return Err("bundle leg partial fill bps must be positive".to_string());
        }
        let asset_in_commitment = intent_settlement_asset_commitment(asset_in_id);
        let asset_out_commitment = intent_settlement_asset_commitment(asset_out_id);
        let execution_payload_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-LEG-EXECUTION-PAYLOAD",
            execution_payload,
        );
        let leg_id = intent_settlement_bundle_leg_id(
            &intent_id,
            &domain,
            &asset_in_commitment,
            &asset_out_commitment,
            amount_in_upper_bound,
            amount_out_lower_bound,
            nonce,
        );
        let leg = Self {
            leg_id,
            intent_id,
            domain,
            input_note_root,
            output_note_root,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_upper_bound,
            amount_out_lower_bound,
            clearing_price_id,
            route_hint_id,
            bridge_hint_id,
            partial_fill_bps,
            fee_units,
            rebate_id,
            execution_payload_root,
            nonce,
        };
        leg.validate()?;
        Ok(leg)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_solver_bundle_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "intent_id": self.intent_id,
            "domain": self.domain.as_str(),
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_upper_bound": self.amount_in_upper_bound,
            "amount_out_lower_bound": self.amount_out_lower_bound,
            "clearing_price_id": self.clearing_price_id,
            "route_hint_id": self.route_hint_id,
            "bridge_hint_id": self.bridge_hint_id,
            "partial_fill_bps": self.partial_fill_bps,
            "fee_units": self.fee_units,
            "rebate_id": self.rebate_id,
            "execution_payload_root": self.execution_payload_root,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.leg_id, "bundle leg id")?;
        ensure_non_empty(&self.intent_id, "bundle leg intent id")?;
        ensure_non_empty(&self.input_note_root, "bundle leg input note root")?;
        ensure_non_empty(&self.output_note_root, "bundle leg output note root")?;
        ensure_non_empty(&self.asset_in_commitment, "bundle leg asset in")?;
        ensure_non_empty(&self.asset_out_commitment, "bundle leg asset out")?;
        ensure_positive(self.amount_in_upper_bound, "bundle leg amount in")?;
        ensure_positive(self.amount_out_lower_bound, "bundle leg amount out")?;
        ensure_bps(self.partial_fill_bps, "bundle leg partial fill bps")?;
        if self.partial_fill_bps == 0 {
            return Err("bundle leg partial fill bps must be positive".to_string());
        }
        ensure_non_empty(&self.execution_payload_root, "bundle leg execution payload")?;
        let expected_id = intent_settlement_bundle_leg_id(
            &self.intent_id,
            &self.domain,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            self.amount_in_upper_bound,
            self.amount_out_lower_bound,
            self.nonce,
        );
        if self.leg_id != expected_id {
            return Err("bundle leg id mismatch".to_string());
        }
        Ok(self.leg_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBundle {
    pub bundle_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub pq_attestation_id: String,
    pub leg_root: String,
    pub intent_root: String,
    pub mev_commitment_root: String,
    pub bridge_hint_root: String,
    pub expected_surplus_commitment: String,
    pub solver_bond_units: u64,
    pub max_gas_units: u64,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub legs: Vec<SolverBundleLeg>,
    pub status: SolverBundleStatus,
}

impl SolverBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        solver_label: &str,
        pq_attestation_id: impl Into<String>,
        legs: Vec<SolverBundleLeg>,
        mev_commitment_ids: &[String],
        bridge_hint_ids: &[String],
        expected_surplus_units: u64,
        solver_bond_units: u64,
        max_gas_units: u64,
        proposed_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let auction_id = auction_id.into();
        let pq_attestation_id = pq_attestation_id.into();
        ensure_non_empty(&auction_id, "solver bundle auction id")?;
        ensure_non_empty(solver_label, "solver bundle solver label")?;
        ensure_non_empty(&pq_attestation_id, "solver bundle pq attestation id")?;
        if legs.is_empty() {
            return Err("solver bundle requires at least one leg".to_string());
        }
        if expires_at_height <= proposed_at_height {
            return Err("solver bundle expiry must be after proposal".to_string());
        }
        ensure_positive(solver_bond_units, "solver bundle bond units")?;
        ensure_positive(max_gas_units, "solver bundle max gas units")?;
        for leg in &legs {
            leg.validate()?;
        }
        let solver_commitment = intent_settlement_solver_commitment(solver_label);
        let leg_root = intent_settlement_bundle_leg_root(&legs);
        let intent_ids = legs
            .iter()
            .map(|leg| leg.intent_id.clone())
            .collect::<Vec<_>>();
        let intent_root =
            intent_settlement_string_set_root("INTENT-SETTLEMENT-BUNDLE-INTENTS", &intent_ids);
        let mev_commitment_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-BUNDLE-MEV-COMMITMENTS",
            mev_commitment_ids,
        );
        let bridge_hint_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-BUNDLE-BRIDGE-HINTS",
            bridge_hint_ids,
        );
        let expected_surplus_commitment = intent_settlement_amount_commitment(
            expected_surplus_units,
            &intent_settlement_blinding(solver_label, nonce, "expected_surplus"),
        );
        let bundle_id = intent_settlement_solver_bundle_id(
            &auction_id,
            &solver_commitment,
            &leg_root,
            proposed_at_height,
            nonce,
        );
        let bundle = Self {
            bundle_id,
            auction_id,
            solver_commitment,
            pq_attestation_id,
            leg_root,
            intent_root,
            mev_commitment_root,
            bridge_hint_root,
            expected_surplus_commitment,
            solver_bond_units,
            max_gas_units,
            proposed_at_height,
            expires_at_height,
            nonce,
            legs,
            status: SolverBundleStatus::Proposed,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn intent_ids(&self) -> Vec<String> {
        self.legs
            .iter()
            .map(|leg| leg.intent_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            SolverBundleStatus::Proposed | SolverBundleStatus::Selected
        ) && self.expires_at_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_solver_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "pq_attestation_id": self.pq_attestation_id,
            "leg_root": self.leg_root,
            "intent_root": self.intent_root,
            "mev_commitment_root": self.mev_commitment_root,
            "bridge_hint_root": self.bridge_hint_root,
            "expected_surplus_commitment": self.expected_surplus_commitment,
            "solver_bond_units": self.solver_bond_units,
            "max_gas_units": self.max_gas_units,
            "proposed_at_height": self.proposed_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "leg_count": self.legs.len() as u64,
            "legs": self.legs.iter().map(SolverBundleLeg::public_record).collect::<Vec<_>>(),
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.bundle_id, "solver bundle id")?;
        ensure_non_empty(&self.auction_id, "solver bundle auction id")?;
        ensure_non_empty(&self.solver_commitment, "solver bundle solver commitment")?;
        ensure_non_empty(&self.pq_attestation_id, "solver bundle pq attestation")?;
        ensure_non_empty(&self.leg_root, "solver bundle leg root")?;
        ensure_non_empty(&self.intent_root, "solver bundle intent root")?;
        ensure_non_empty(&self.mev_commitment_root, "solver bundle mev root")?;
        ensure_non_empty(&self.bridge_hint_root, "solver bundle bridge root")?;
        ensure_non_empty(
            &self.expected_surplus_commitment,
            "solver bundle expected surplus",
        )?;
        ensure_positive(self.solver_bond_units, "solver bundle bond")?;
        ensure_positive(self.max_gas_units, "solver bundle max gas")?;
        if self.legs.is_empty() {
            return Err("solver bundle requires legs".to_string());
        }
        if self.expires_at_height <= self.proposed_at_height {
            return Err("solver bundle expiry must be after proposal".to_string());
        }
        for leg in &self.legs {
            leg.validate()?;
        }
        let expected_leg_root = intent_settlement_bundle_leg_root(&self.legs);
        if self.leg_root != expected_leg_root {
            return Err("solver bundle leg root mismatch".to_string());
        }
        let expected_intent_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-BUNDLE-INTENTS",
            &self.intent_ids(),
        );
        if self.intent_root != expected_intent_root {
            return Err("solver bundle intent root mismatch".to_string());
        }
        let expected_id = intent_settlement_solver_bundle_id(
            &self.auction_id,
            &self.solver_commitment,
            &self.leg_root,
            self.proposed_at_height,
            self.nonce,
        );
        if self.bundle_id != expected_id {
            return Err("solver bundle id mismatch".to_string());
        }
        Ok(self.bundle_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub subject_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub credit_note_commitment: String,
    pub proof_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: RebateStatus,
}

impl LowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        sponsor_label: &str,
        recipient_label: &str,
        subject_id: impl Into<String>,
        fee_asset_id: &str,
        gross_fee_units: u64,
        rebate_units: u64,
        proof: &Value,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let subject_id = subject_id.into();
        ensure_non_empty(lane_id, "rebate lane id")?;
        ensure_non_empty(sponsor_label, "rebate sponsor label")?;
        ensure_non_empty(recipient_label, "rebate recipient label")?;
        ensure_non_empty(&subject_id, "rebate subject id")?;
        ensure_non_empty(fee_asset_id, "rebate fee asset id")?;
        ensure_positive(gross_fee_units, "rebate gross fee units")?;
        if rebate_units > gross_fee_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("rebate expiry must be after issuance".to_string());
        }
        let rebate_bps = rebate_units
            .saturating_mul(INTENT_SETTLEMENT_MAX_BPS)
            .checked_div(gross_fee_units)
            .unwrap_or(0);
        ensure_bps(rebate_bps, "rebate bps")?;
        let sponsor_commitment = intent_settlement_account_commitment(sponsor_label);
        let recipient_commitment = intent_settlement_account_commitment(recipient_label);
        let credit_note_commitment = intent_settlement_amount_commitment(
            rebate_units,
            &intent_settlement_blinding(recipient_label, nonce, "rebate_credit"),
        );
        let proof_root = intent_settlement_payload_root("INTENT-SETTLEMENT-REBATE-PROOF", proof);
        let rebate_id = intent_settlement_low_fee_rebate_id(
            lane_id,
            &recipient_commitment,
            &subject_id,
            rebate_units,
            issued_at_height,
            nonce,
        );
        let rebate = Self {
            rebate_id,
            lane_id: lane_id.to_string(),
            sponsor_commitment,
            recipient_commitment,
            subject_id,
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            rebate_units,
            rebate_bps,
            credit_note_commitment,
            proof_root,
            issued_at_height,
            expires_at_height,
            nonce,
            status: RebateStatus::Issued,
        };
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.counts_as_pending() && self.expires_at_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_low_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "recipient_commitment": self.recipient_commitment,
            "subject_id": self.subject_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "credit_note_commitment": self.credit_note_commitment,
            "proof_root": self.proof_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.rebate_id, "rebate id")?;
        ensure_non_empty(&self.lane_id, "rebate lane")?;
        ensure_non_empty(&self.sponsor_commitment, "rebate sponsor")?;
        ensure_non_empty(&self.recipient_commitment, "rebate recipient")?;
        ensure_non_empty(&self.subject_id, "rebate subject")?;
        ensure_non_empty(&self.fee_asset_id, "rebate fee asset")?;
        ensure_positive(self.gross_fee_units, "rebate gross fee")?;
        if self.rebate_units > self.gross_fee_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        ensure_bps(self.rebate_bps, "rebate bps")?;
        ensure_non_empty(&self.credit_note_commitment, "rebate credit note")?;
        ensure_non_empty(&self.proof_root, "rebate proof root")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("rebate expiry must be after issuance".to_string());
        }
        let expected_id = intent_settlement_low_fee_rebate_id(
            &self.lane_id,
            &self.recipient_commitment,
            &self.subject_id,
            self.rebate_units,
            self.issued_at_height,
            self.nonce,
        );
        if self.rebate_id != expected_id {
            return Err("rebate id mismatch".to_string());
        }
        Ok(self.rebate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePartialFillNote {
    pub note_id: String,
    pub intent_id: String,
    pub group_id: String,
    pub bundle_id: String,
    pub owner_commitment: String,
    pub input_nullifier: String,
    pub output_commitment: String,
    pub fill_amount_commitment: String,
    pub refund_amount_commitment: String,
    pub clearing_price_id: String,
    pub partial_fill_bps: u64,
    pub fee_units: u64,
    pub rebate_id: String,
    pub encrypted_note_root: String,
    pub created_at_height: u64,
    pub unlock_height: u64,
    pub nonce: u64,
    pub status: PartialFillStatus,
}

impl PrivatePartialFillNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        group_id: impl Into<String>,
        bundle_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        input_nullifier_label: &str,
        output_note_label: &str,
        fill_amount_units: u64,
        refund_amount_units: u64,
        clearing_price_id: impl Into<String>,
        partial_fill_bps: u64,
        fee_units: u64,
        rebate_id: impl Into<String>,
        encrypted_note: &Value,
        created_at_height: u64,
        unlock_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let intent_id = intent_id.into();
        let group_id = group_id.into();
        let bundle_id = bundle_id.into();
        let owner_commitment = owner_commitment.into();
        let clearing_price_id = clearing_price_id.into();
        let rebate_id = rebate_id.into();
        ensure_non_empty(&intent_id, "partial fill intent id")?;
        ensure_non_empty(&group_id, "partial fill group id")?;
        ensure_non_empty(&bundle_id, "partial fill bundle id")?;
        ensure_non_empty(&owner_commitment, "partial fill owner")?;
        ensure_non_empty(input_nullifier_label, "partial fill input nullifier")?;
        ensure_non_empty(output_note_label, "partial fill output note")?;
        ensure_positive(fill_amount_units, "partial fill amount")?;
        ensure_bps(partial_fill_bps, "partial fill bps")?;
        if partial_fill_bps == 0 {
            return Err("partial fill bps must be positive".to_string());
        }
        if unlock_height < created_at_height {
            return Err("partial fill unlock cannot precede creation".to_string());
        }
        let input_nullifier = intent_settlement_string_root(
            "INTENT-SETTLEMENT-PARTIAL-FILL-NULLIFIER",
            input_nullifier_label,
        );
        let output_commitment = intent_settlement_string_root(
            "INTENT-SETTLEMENT-PARTIAL-FILL-OUTPUT",
            output_note_label,
        );
        let fill_amount_commitment = intent_settlement_amount_commitment(
            fill_amount_units,
            &intent_settlement_blinding(output_note_label, nonce, "fill_amount"),
        );
        let refund_amount_commitment = intent_settlement_amount_commitment(
            refund_amount_units,
            &intent_settlement_blinding(output_note_label, nonce, "refund_amount"),
        );
        let encrypted_note_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-PARTIAL-FILL-NOTE", encrypted_note);
        let note_id = intent_settlement_partial_fill_note_id(
            &intent_id,
            &group_id,
            &output_commitment,
            &fill_amount_commitment,
            created_at_height,
            nonce,
        );
        let note = Self {
            note_id,
            intent_id,
            group_id,
            bundle_id,
            owner_commitment,
            input_nullifier,
            output_commitment,
            fill_amount_commitment,
            refund_amount_commitment,
            clearing_price_id,
            partial_fill_bps,
            fee_units,
            rebate_id,
            encrypted_note_root,
            created_at_height,
            unlock_height,
            nonce,
            status: PartialFillStatus::Spendable,
        };
        note.validate()?;
        Ok(note)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_private_partial_fill_note",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "note_id": self.note_id,
            "intent_id": self.intent_id,
            "group_id": self.group_id,
            "bundle_id": self.bundle_id,
            "owner_commitment": self.owner_commitment,
            "input_nullifier": self.input_nullifier,
            "output_commitment": self.output_commitment,
            "fill_amount_commitment": self.fill_amount_commitment,
            "refund_amount_commitment": self.refund_amount_commitment,
            "clearing_price_id": self.clearing_price_id,
            "partial_fill_bps": self.partial_fill_bps,
            "fee_units": self.fee_units,
            "rebate_id": self.rebate_id,
            "encrypted_note_root": self.encrypted_note_root,
            "partial_fill_note_scheme": INTENT_SETTLEMENT_PARTIAL_FILL_NOTE_SCHEME,
            "created_at_height": self.created_at_height,
            "unlock_height": self.unlock_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.note_id, "partial fill note id")?;
        ensure_non_empty(&self.intent_id, "partial fill intent id")?;
        ensure_non_empty(&self.group_id, "partial fill group id")?;
        ensure_non_empty(&self.bundle_id, "partial fill bundle id")?;
        ensure_non_empty(&self.owner_commitment, "partial fill owner")?;
        ensure_non_empty(&self.input_nullifier, "partial fill input nullifier")?;
        ensure_non_empty(&self.output_commitment, "partial fill output commitment")?;
        ensure_non_empty(&self.fill_amount_commitment, "partial fill amount")?;
        ensure_non_empty(&self.refund_amount_commitment, "partial fill refund")?;
        ensure_bps(self.partial_fill_bps, "partial fill bps")?;
        if self.partial_fill_bps == 0 {
            return Err("partial fill bps must be positive".to_string());
        }
        ensure_non_empty(
            &self.encrypted_note_root,
            "partial fill encrypted note root",
        )?;
        if self.unlock_height < self.created_at_height {
            return Err("partial fill unlock cannot precede creation".to_string());
        }
        let expected_id = intent_settlement_partial_fill_note_id(
            &self.intent_id,
            &self.group_id,
            &self.output_commitment,
            &self.fill_amount_commitment,
            self.created_at_height,
            self.nonce,
        );
        if self.note_id != expected_id {
            return Err("partial fill note id mismatch".to_string());
        }
        Ok(self.note_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSettlementGroup {
    pub group_id: String,
    pub auction_id: String,
    pub bundle_id: String,
    pub solver_commitment: String,
    pub pq_attestation_id: String,
    pub clearing_price_root: String,
    pub intent_root: String,
    pub leg_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub partial_fill_note_root: String,
    pub bridge_exit_root: String,
    pub lending_effect_root: String,
    pub perp_effect_root: String,
    pub token_delta_root: String,
    pub rebate_root: String,
    pub mev_commitment_root: String,
    pub leg_count: u64,
    pub total_input_upper_bound_units: u64,
    pub total_output_lower_bound_units: u64,
    pub total_fee_units: u64,
    pub total_rebate_units: u64,
    pub execution_height: u64,
    pub challenge_deadline_height: u64,
    pub nonce: u64,
    pub status: SettlementGroupStatus,
}

impl AtomicSettlementGroup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        bundle_id: impl Into<String>,
        solver_commitment: impl Into<String>,
        pq_attestation_id: impl Into<String>,
        legs: &[SolverBundleLeg],
        clearing_prices: &[BatchAuctionClearingPrice],
        partial_fill_notes: &[PrivatePartialFillNote],
        rebates: &[LowFeeRebate],
        bridge_effects: &[Value],
        lending_effects: &[Value],
        perp_effects: &[Value],
        token_deltas: &[Value],
        mev_commitment_ids: &[String],
        execution_height: u64,
        challenge_deadline_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let auction_id = auction_id.into();
        let bundle_id = bundle_id.into();
        let solver_commitment = solver_commitment.into();
        let pq_attestation_id = pq_attestation_id.into();
        ensure_non_empty(&auction_id, "settlement group auction id")?;
        ensure_non_empty(&bundle_id, "settlement group bundle id")?;
        ensure_non_empty(&solver_commitment, "settlement group solver commitment")?;
        ensure_non_empty(&pq_attestation_id, "settlement group pq attestation")?;
        if legs.is_empty() {
            return Err("settlement group requires legs".to_string());
        }
        if clearing_prices.is_empty() {
            return Err("settlement group requires clearing prices".to_string());
        }
        if challenge_deadline_height <= execution_height {
            return Err("settlement group challenge deadline must follow execution".to_string());
        }
        let clearing_price_root = intent_settlement_clearing_price_root(clearing_prices);
        let intent_ids = legs
            .iter()
            .map(|leg| leg.intent_id.clone())
            .collect::<Vec<_>>();
        let intent_root =
            intent_settlement_string_set_root("INTENT-SETTLEMENT-GROUP-INTENTS", &intent_ids);
        let leg_root = intent_settlement_bundle_leg_root(legs);
        let input_note_root = merkle_root(
            "INTENT-SETTLEMENT-GROUP-INPUT-NOTES",
            &legs
                .iter()
                .map(|leg| Value::String(leg.input_note_root.clone()))
                .collect::<Vec<_>>(),
        );
        let output_note_root = merkle_root(
            "INTENT-SETTLEMENT-GROUP-OUTPUT-NOTES",
            &legs
                .iter()
                .map(|leg| Value::String(leg.output_note_root.clone()))
                .collect::<Vec<_>>(),
        );
        let partial_fill_note_root = intent_settlement_partial_fill_note_root(partial_fill_notes);
        let bridge_exit_root = merkle_root("INTENT-SETTLEMENT-GROUP-BRIDGE-EXITS", bridge_effects);
        let lending_effect_root =
            merkle_root("INTENT-SETTLEMENT-GROUP-LENDING-EFFECTS", lending_effects);
        let perp_effect_root = merkle_root("INTENT-SETTLEMENT-GROUP-PERP-EFFECTS", perp_effects);
        let token_delta_root = merkle_root("INTENT-SETTLEMENT-GROUP-TOKEN-DELTAS", token_deltas);
        let rebate_root = intent_settlement_low_fee_rebate_root(rebates);
        let mev_commitment_root = intent_settlement_string_set_root(
            "INTENT-SETTLEMENT-GROUP-MEV-COMMITMENTS",
            mev_commitment_ids,
        );
        let total_input_upper_bound_units = legs.iter().fold(0_u64, |total, leg| {
            total.saturating_add(leg.amount_in_upper_bound)
        });
        let total_output_lower_bound_units = legs.iter().fold(0_u64, |total, leg| {
            total.saturating_add(leg.amount_out_lower_bound)
        });
        let total_fee_units = legs
            .iter()
            .fold(0_u64, |total, leg| total.saturating_add(leg.fee_units));
        let total_rebate_units = rebates.iter().fold(0_u64, |total, rebate| {
            total.saturating_add(rebate.rebate_units)
        });
        let group_id = intent_settlement_group_id(
            &auction_id,
            &bundle_id,
            &solver_commitment,
            &clearing_price_root,
            execution_height,
            nonce,
        );
        let group = Self {
            group_id,
            auction_id,
            bundle_id,
            solver_commitment,
            pq_attestation_id,
            clearing_price_root,
            intent_root,
            leg_root,
            input_note_root,
            output_note_root,
            partial_fill_note_root,
            bridge_exit_root,
            lending_effect_root,
            perp_effect_root,
            token_delta_root,
            rebate_root,
            mev_commitment_root,
            leg_count: legs.len() as u64,
            total_input_upper_bound_units,
            total_output_lower_bound_units,
            total_fee_units,
            total_rebate_units,
            execution_height,
            challenge_deadline_height,
            nonce,
            status: SettlementGroupStatus::Settled,
        };
        group.validate()?;
        Ok(group)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_atomic_settlement_group",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "group_id": self.group_id,
            "auction_id": self.auction_id,
            "bundle_id": self.bundle_id,
            "solver_commitment": self.solver_commitment,
            "pq_attestation_id": self.pq_attestation_id,
            "clearing_price_root": self.clearing_price_root,
            "intent_root": self.intent_root,
            "leg_root": self.leg_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "partial_fill_note_root": self.partial_fill_note_root,
            "bridge_exit_root": self.bridge_exit_root,
            "lending_effect_root": self.lending_effect_root,
            "perp_effect_root": self.perp_effect_root,
            "token_delta_root": self.token_delta_root,
            "rebate_root": self.rebate_root,
            "mev_commitment_root": self.mev_commitment_root,
            "leg_count": self.leg_count,
            "total_input_upper_bound_units": self.total_input_upper_bound_units,
            "total_output_lower_bound_units": self.total_output_lower_bound_units,
            "total_fee_units": self.total_fee_units,
            "total_rebate_units": self.total_rebate_units,
            "execution_height": self.execution_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.group_id, "settlement group id")?;
        ensure_non_empty(&self.auction_id, "settlement group auction")?;
        ensure_non_empty(&self.bundle_id, "settlement group bundle")?;
        ensure_non_empty(&self.solver_commitment, "settlement group solver")?;
        ensure_non_empty(&self.pq_attestation_id, "settlement group attestation")?;
        ensure_non_empty(&self.clearing_price_root, "settlement group clearing root")?;
        ensure_non_empty(&self.intent_root, "settlement group intent root")?;
        ensure_non_empty(&self.leg_root, "settlement group leg root")?;
        ensure_non_empty(&self.input_note_root, "settlement group input notes")?;
        ensure_non_empty(&self.output_note_root, "settlement group output notes")?;
        ensure_non_empty(
            &self.partial_fill_note_root,
            "settlement group partial fill notes",
        )?;
        ensure_non_empty(&self.bridge_exit_root, "settlement group bridge exits")?;
        ensure_non_empty(
            &self.lending_effect_root,
            "settlement group lending effects",
        )?;
        ensure_non_empty(&self.perp_effect_root, "settlement group perp effects")?;
        ensure_non_empty(&self.token_delta_root, "settlement group token deltas")?;
        ensure_non_empty(&self.rebate_root, "settlement group rebate root")?;
        ensure_non_empty(&self.mev_commitment_root, "settlement group mev root")?;
        if self.leg_count == 0 {
            return Err("settlement group requires legs".to_string());
        }
        if self.challenge_deadline_height <= self.execution_height {
            return Err("settlement group challenge deadline must follow execution".to_string());
        }
        let expected_id = intent_settlement_group_id(
            &self.auction_id,
            &self.bundle_id,
            &self.solver_commitment,
            &self.clearing_price_root,
            self.execution_height,
            self.nonce,
        );
        if self.group_id != expected_id {
            return Err("settlement group id mismatch".to_string());
        }
        Ok(self.group_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedSettlementChallenge {
    pub challenge_id: String,
    pub group_id: String,
    pub bundle_id: String,
    pub challenger_commitment: String,
    pub failure_kind: FailureKind,
    pub expected_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub resolved_at_height: u64,
    pub slash_recommendation_bps: u64,
    pub nonce: u64,
    pub status: ChallengeStatus,
}

impl FailedSettlementChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: impl Into<String>,
        bundle_id: impl Into<String>,
        challenger_label: &str,
        failure_kind: FailureKind,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        evidence: &Value,
        opened_at_height: u64,
        response_deadline_height: u64,
        slash_recommendation_bps: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let group_id = group_id.into();
        let bundle_id = bundle_id.into();
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        ensure_non_empty(&group_id, "challenge group id")?;
        ensure_non_empty(&bundle_id, "challenge bundle id")?;
        ensure_non_empty(challenger_label, "challenge challenger label")?;
        ensure_non_empty(&expected_root, "challenge expected root")?;
        ensure_non_empty(&observed_root, "challenge observed root")?;
        if response_deadline_height <= opened_at_height {
            return Err("challenge response deadline must follow open height".to_string());
        }
        ensure_bps(
            slash_recommendation_bps,
            "challenge slash recommendation bps",
        )?;
        let challenger_commitment = intent_settlement_account_commitment(challenger_label);
        let evidence_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-FAILED-CHALLENGE-EVIDENCE", evidence);
        let challenge_id = intent_settlement_failed_challenge_id(
            &group_id,
            &bundle_id,
            &challenger_commitment,
            &failure_kind,
            opened_at_height,
            nonce,
        );
        let challenge = Self {
            challenge_id,
            group_id,
            bundle_id,
            challenger_commitment,
            failure_kind,
            expected_root,
            observed_root,
            evidence_root,
            opened_at_height,
            response_deadline_height,
            resolved_at_height: 0,
            slash_recommendation_bps,
            nonce,
            status: ChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            ChallengeStatus::Open | ChallengeStatus::Responded
        ) && self.response_deadline_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_failed_settlement_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "group_id": self.group_id,
            "bundle_id": self.bundle_id,
            "challenger_commitment": self.challenger_commitment,
            "failure_kind": self.failure_kind.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "slash_recommendation_bps": self.slash_recommendation_bps,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.group_id, "challenge group")?;
        ensure_non_empty(&self.bundle_id, "challenge bundle")?;
        ensure_non_empty(&self.challenger_commitment, "challenge challenger")?;
        ensure_non_empty(&self.expected_root, "challenge expected root")?;
        ensure_non_empty(&self.observed_root, "challenge observed root")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        if self.response_deadline_height <= self.opened_at_height {
            return Err("challenge response deadline must follow open height".to_string());
        }
        if self.resolved_at_height != 0 && self.resolved_at_height < self.opened_at_height {
            return Err("challenge resolved height cannot precede open height".to_string());
        }
        ensure_bps(
            self.slash_recommendation_bps,
            "challenge slash recommendation bps",
        )?;
        let expected_id = intent_settlement_failed_challenge_id(
            &self.group_id,
            &self.bundle_id,
            &self.challenger_commitment,
            &self.failure_kind,
            self.opened_at_height,
            self.nonce,
        );
        if self.challenge_id != expected_id {
            return Err("failed challenge id mismatch".to_string());
        }
        Ok(self.challenge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub solver_commitment: String,
    pub bundle_id: String,
    pub attestation_id: String,
    pub challenge_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub first_statement_root: String,
    pub second_statement_root: String,
    pub equivocation_root: String,
    pub reporter_commitment: String,
    pub bond_units: u64,
    pub slash_units: u64,
    pub created_at_height: u64,
    pub nonce: u64,
    pub status: SlashingStatus,
}

impl SlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_label: &str,
        bundle_id: impl Into<String>,
        attestation_id: impl Into<String>,
        challenge_id: impl Into<String>,
        evidence_kind: SlashingEvidenceKind,
        first_statement: &Value,
        second_statement: &Value,
        reporter_label: &str,
        bond_units: u64,
        slash_units: u64,
        created_at_height: u64,
        nonce: u64,
    ) -> IntentSettlementResult<Self> {
        let bundle_id = bundle_id.into();
        let attestation_id = attestation_id.into();
        let challenge_id = challenge_id.into();
        ensure_non_empty(solver_label, "slashing solver label")?;
        ensure_non_empty(&bundle_id, "slashing bundle id")?;
        ensure_non_empty(&attestation_id, "slashing attestation id")?;
        ensure_non_empty(&challenge_id, "slashing challenge id")?;
        ensure_non_empty(reporter_label, "slashing reporter label")?;
        ensure_positive(bond_units, "slashing bond units")?;
        if slash_units > bond_units {
            return Err("slash units cannot exceed bond units".to_string());
        }
        let solver_commitment = intent_settlement_solver_commitment(solver_label);
        let first_statement_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-SLASH-FIRST-STATEMENT",
            first_statement,
        );
        let second_statement_root = intent_settlement_payload_root(
            "INTENT-SETTLEMENT-SLASH-SECOND-STATEMENT",
            second_statement,
        );
        let equivocation_root = intent_settlement_equivocation_root(
            &solver_commitment,
            &bundle_id,
            &first_statement_root,
            &second_statement_root,
        );
        let reporter_commitment = intent_settlement_account_commitment(reporter_label);
        let evidence_id = intent_settlement_slashing_evidence_id(
            &solver_commitment,
            &bundle_id,
            &attestation_id,
            &challenge_id,
            &evidence_kind,
            created_at_height,
            nonce,
        );
        let evidence = Self {
            evidence_id,
            solver_commitment,
            bundle_id,
            attestation_id,
            challenge_id,
            evidence_kind,
            first_statement_root,
            second_statement_root,
            equivocation_root,
            reporter_commitment,
            bond_units,
            slash_units,
            created_at_height,
            nonce,
            status: SlashingStatus::Pending,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "solver_commitment": self.solver_commitment,
            "bundle_id": self.bundle_id,
            "attestation_id": self.attestation_id,
            "challenge_id": self.challenge_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "first_statement_root": self.first_statement_root,
            "second_statement_root": self.second_statement_root,
            "equivocation_root": self.equivocation_root,
            "reporter_commitment": self.reporter_commitment,
            "bond_units": self.bond_units,
            "slash_units": self.slash_units,
            "created_at_height": self.created_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.solver_commitment, "slashing solver")?;
        ensure_non_empty(&self.bundle_id, "slashing bundle")?;
        ensure_non_empty(&self.attestation_id, "slashing attestation")?;
        ensure_non_empty(&self.challenge_id, "slashing challenge")?;
        ensure_non_empty(&self.first_statement_root, "slashing first statement")?;
        ensure_non_empty(&self.second_statement_root, "slashing second statement")?;
        ensure_non_empty(&self.equivocation_root, "slashing equivocation root")?;
        ensure_non_empty(&self.reporter_commitment, "slashing reporter")?;
        ensure_positive(self.bond_units, "slashing bond units")?;
        if self.slash_units > self.bond_units {
            return Err("slash units cannot exceed bond".to_string());
        }
        let expected_equivocation = intent_settlement_equivocation_root(
            &self.solver_commitment,
            &self.bundle_id,
            &self.first_statement_root,
            &self.second_statement_root,
        );
        if self.equivocation_root != expected_equivocation {
            return Err("slashing equivocation root mismatch".to_string());
        }
        let expected_id = intent_settlement_slashing_evidence_id(
            &self.solver_commitment,
            &self.bundle_id,
            &self.attestation_id,
            &self.challenge_id,
            &self.evidence_kind,
            self.created_at_height,
            self.nonce,
        );
        if self.evidence_id != expected_id {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl IntentSettlementPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> IntentSettlementResult<Self> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject")?;
        let payload_root =
            intent_settlement_payload_root("INTENT-SETTLEMENT-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = intent_settlement_public_record_id(
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
            "kind": "intent_settlement_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let expected_id = intent_settlement_public_record_id(
            &self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected_id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementCounters {
    pub encrypted_intent_count: u64,
    pub active_intent_count: u64,
    pub swap_intent_count: u64,
    pub lending_intent_count: u64,
    pub perp_intent_count: u64,
    pub bridge_exit_intent_count: u64,
    pub batch_auction_count: u64,
    pub live_auction_count: u64,
    pub solver_bundle_count: u64,
    pub selected_bundle_count: u64,
    pub clearing_price_count: u64,
    pub settlement_group_count: u64,
    pub settled_group_count: u64,
    pub failed_group_count: u64,
    pub low_fee_rebate_count: u64,
    pub pending_rebate_count: u64,
    pub partial_fill_note_count: u64,
    pub mev_commitment_count: u64,
    pub active_mev_commitment_count: u64,
    pub bridge_route_hint_count: u64,
    pub live_bridge_route_hint_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub failed_challenge_count: u64,
    pub open_challenge_count: u64,
    pub slashing_evidence_count: u64,
    pub pending_slash_units: u64,
    pub gross_fee_units: u64,
    pub total_rebate_units: u64,
    pub notional_cleared_units: u64,
}

impl IntentSettlementCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "encrypted_intent_count": self.encrypted_intent_count,
            "active_intent_count": self.active_intent_count,
            "swap_intent_count": self.swap_intent_count,
            "lending_intent_count": self.lending_intent_count,
            "perp_intent_count": self.perp_intent_count,
            "bridge_exit_intent_count": self.bridge_exit_intent_count,
            "batch_auction_count": self.batch_auction_count,
            "live_auction_count": self.live_auction_count,
            "solver_bundle_count": self.solver_bundle_count,
            "selected_bundle_count": self.selected_bundle_count,
            "clearing_price_count": self.clearing_price_count,
            "settlement_group_count": self.settlement_group_count,
            "settled_group_count": self.settled_group_count,
            "failed_group_count": self.failed_group_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "pending_rebate_count": self.pending_rebate_count,
            "partial_fill_note_count": self.partial_fill_note_count,
            "mev_commitment_count": self.mev_commitment_count,
            "active_mev_commitment_count": self.active_mev_commitment_count,
            "bridge_route_hint_count": self.bridge_route_hint_count,
            "live_bridge_route_hint_count": self.live_bridge_route_hint_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "failed_challenge_count": self.failed_challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "pending_slash_units": self.pending_slash_units,
            "gross_fee_units": self.gross_fee_units,
            "total_rebate_units": self.total_rebate_units,
            "notional_cleared_units": self.notional_cleared_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementRoots {
    pub config_root: String,
    pub encrypted_intent_root: String,
    pub batch_auction_root: String,
    pub solver_bundle_root: String,
    pub clearing_price_root: String,
    pub settlement_group_root: String,
    pub low_fee_rebate_root: String,
    pub partial_fill_note_root: String,
    pub mev_commitment_root: String,
    pub bridge_route_hint_root: String,
    pub pq_attestation_root: String,
    pub failed_challenge_root: String,
    pub slashing_evidence_root: String,
    pub public_record_root: String,
}

impl IntentSettlementRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "batch_auction_root": self.batch_auction_root,
            "solver_bundle_root": self.solver_bundle_root,
            "clearing_price_root": self.clearing_price_root,
            "settlement_group_root": self.settlement_group_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "partial_fill_note_root": self.partial_fill_note_root,
            "mev_commitment_root": self.mev_commitment_root,
            "bridge_route_hint_root": self.bridge_route_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "failed_challenge_root": self.failed_challenge_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        intent_settlement_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementState {
    pub height: u64,
    pub nonce: u64,
    pub config: IntentSettlementConfig,
    pub encrypted_intents: BTreeMap<String, EncryptedDefiIntent>,
    pub batch_auctions: BTreeMap<String, BatchAuction>,
    pub solver_bundles: BTreeMap<String, SolverBundle>,
    pub clearing_prices: BTreeMap<String, BatchAuctionClearingPrice>,
    pub settlement_groups: BTreeMap<String, AtomicSettlementGroup>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub partial_fill_notes: BTreeMap<String, PrivatePartialFillNote>,
    pub mev_commitments: BTreeMap<String, MevProtectionCommitment>,
    pub bridge_route_hints: BTreeMap<String, BridgeWithdrawalRouteHint>,
    pub pq_attestations: BTreeMap<String, SolverPqAttestation>,
    pub failed_challenges: BTreeMap<String, FailedSettlementChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: BTreeMap<String, IntentSettlementPublicRecord>,
}

impl Default for IntentSettlementState {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentSettlementState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: IntentSettlementConfig::default(),
            encrypted_intents: BTreeMap::new(),
            batch_auctions: BTreeMap::new(),
            solver_bundles: BTreeMap::new(),
            clearing_prices: BTreeMap::new(),
            settlement_groups: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            partial_fill_notes: BTreeMap::new(),
            mev_commitments: BTreeMap::new(),
            bridge_route_hints: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            failed_challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: IntentSettlementConfig) -> IntentSettlementResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> IntentSettlementResult<Self> {
        let mut state = Self::with_config(IntentSettlementConfig::devnet())?;
        state.set_height(INTENT_SETTLEMENT_DEVNET_HEIGHT);

        let solver_attestation = SolverPqAttestation::new(
            "devnet-solver-1",
            "devnet-solver-operator-1",
            &[
                "ml-dsa-risk-member-1".to_string(),
                "ml-dsa-risk-member-2".to_string(),
                "slh-dsa-risk-member-3".to_string(),
            ],
            &[
                "ml-dsa-solver-public-key-1".to_string(),
                "kem-solver-routing-key-1".to_string(),
            ],
            &json!({
                "solver": "devnet-solver-1",
                "scope": "private-defi-intents",
                "max_bundle_intents": 32
            }),
            &json!({
                "aggregate_signature": "devnet-solver-attestation-sig-root",
                "threshold": "2-of-3"
            }),
            &[
                "swap".to_string(),
                "lending".to_string(),
                "perp".to_string(),
                "bridge_exit".to_string(),
                "low_fee_rebate".to_string(),
            ],
            1_500_000,
            850,
            state.height.saturating_sub(12),
            state.height.saturating_add(7_200),
            state.next_nonce(),
        )?;
        let attestation_id = solver_attestation.attestation_id.clone();
        let solver_commitment = solver_attestation.solver_commitment.clone();
        state.insert_pq_attestation(solver_attestation)?;

        let swap_intent = EncryptedDefiIntent::new(
            "devnet-alice-private-intents",
            IntentKind::SwapExactIn,
            vec![SettlementDomain::Token, SettlementDomain::Swap],
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000_000,
            7_500_000_000_000,
            179 * INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            0,
            0,
            60,
            8_000,
            true,
            state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
            &json!({
                "intent": "swap_exact_in",
                "asset_in": "wxmr",
                "asset_out": "usdd",
                "amount_bucket": "40-45 wxmr",
                "recipient": "alice-private-output"
            }),
            &["devnet-solver-1".to_string()],
            &["devnet-router-direct-wxmr-usdd".to_string()],
            &json!({"priority": "anti-sandwich", "batch_only": true}),
            &json!({"wallet": "alice", "lane": "private_defi"}),
        )?;
        let swap_intent_id = swap_intent.intent_id.clone();
        let swap_owner_commitment = swap_intent.owner_commitment.clone();
        state.insert_encrypted_intent(swap_intent)?;

        let borrow_intent = EncryptedDefiIntent::new(
            "devnet-bob-private-borrower",
            IntentKind::LendingBorrow,
            vec![SettlementDomain::Lending, SettlementDomain::Token],
            "wxmr-collateral-devnet",
            "usdd-devnet",
            125_000_000_000,
            18_000_000_000,
            145 * INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            125_000_000_000,
            250,
            0,
            10_000,
            false,
            state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
            &json!({
                "intent": "private_borrow",
                "collateral_bucket": "100-150 wxmr",
                "borrow_bucket": "15k-20k usdd"
            }),
            &["devnet-solver-1".to_string()],
            &["devnet-lending-market-wxmr-usdd".to_string()],
            &json!({"oracle_guard": "bounded-health-bucket"}),
            &json!({"wallet": "bob", "lane": "private_lending"}),
        )?;
        let borrow_intent_id = borrow_intent.intent_id.clone();
        let borrow_owner_commitment = borrow_intent.owner_commitment.clone();
        state.insert_encrypted_intent(borrow_intent)?;

        let perp_intent = EncryptedDefiIntent::new(
            "devnet-caro-private-perp",
            IntentKind::PerpOpen,
            vec![SettlementDomain::Perp, SettlementDomain::Token],
            "usdd-devnet",
            "wxmr-perp-devnet",
            3_600_000_000,
            1_000_000,
            180 * INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            3_600_000_000,
            3_000,
            75,
            10_000,
            false,
            state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
            &json!({
                "intent": "perp_open_long",
                "market": "wxmr-usdd",
                "leverage": "3x",
                "margin_bucket": "3k-4k usdd"
            }),
            &["devnet-solver-1".to_string()],
            &["devnet-perp-vault-wxmr-usdd".to_string()],
            &json!({"funding_guard": "oracle_freshness_12_blocks"}),
            &json!({"wallet": "caro", "lane": "private_perps"}),
        )?;
        let perp_intent_id = perp_intent.intent_id.clone();
        let perp_owner_commitment = perp_intent.owner_commitment.clone();
        state.insert_encrypted_intent(perp_intent)?;

        let bridge_intent = EncryptedDefiIntent::new(
            "devnet-dana-bridge-exit",
            IntentKind::BridgeExit,
            vec![SettlementDomain::Bridge, SettlementDomain::Token],
            "usdd-devnet",
            "usdd-monero-exit",
            1_250_000_000,
            1_240_000_000,
            INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            0,
            0,
            80,
            10_000,
            false,
            state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
            &json!({
                "intent": "bridge_exit",
                "destination": "monero-devnet",
                "recipient": "dana-stealth-address-commitment"
            }),
            &["devnet-solver-1".to_string()],
            &["devnet-fast-exit-liquidity".to_string()],
            &json!({"bridge_mev": "no-reorder-withdrawals"}),
            &json!({"wallet": "dana", "lane": "private_bridge"}),
        )?;
        let bridge_intent_id = bridge_intent.intent_id.clone();
        let bridge_owner_commitment = bridge_intent.owner_commitment.clone();
        state.insert_encrypted_intent(bridge_intent)?;

        let swap_mev = MevProtectionCommitment::new(
            &swap_intent_id,
            &swap_owner_commitment,
            "alice-swap-batch-salt",
            &json!({"preference": "uniform_price_only", "max_delay_blocks": 8}),
            &json!({"sandwich_bound_bps": 0, "private_mempool": true}),
            &json!({"chain_id": CHAIN_ID, "domain": "devnet-intent-auction"}),
            &json!({"relay": "devnet-threshold-relay", "sealed": true}),
            state.height,
            state
                .height
                .saturating_add(state.config.mev_reveal_delay_blocks),
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let swap_mev_id = swap_mev.commitment_id.clone();
        state.insert_mev_commitment(swap_mev)?;

        let bridge_hint = BridgeWithdrawalRouteHint::new(
            &bridge_intent_id,
            "nebula-l2-devnet",
            "monero-devnet",
            "monero-devnet",
            "devnet-fast-exit-adapter",
            "devnet-bridge-liquidity-provider",
            "usdd-devnet",
            1_240_000_000,
            "dana-stealth-address",
            "44AFFq5k-devnet-dana",
            120,
            20,
            &json!({
                "route": "fast-exit-then-finalize",
                "liquidity": "pre-funded-monero-vault",
                "proof": "withdrawal-note-nullifier"
            }),
            &json!({"exit_circuit": "monero-exit-devnet", "view_tag": "dana-view-tag"}),
            state.height,
            state
                .height
                .saturating_add(state.config.bridge_exit_ttl_blocks),
            state.next_nonce(),
        )?;
        let bridge_hint_id = bridge_hint.route_hint_id.clone();
        state.insert_bridge_route_hint(bridge_hint)?;

        let auction = BatchAuction::new(
            "devnet-private-defi-market",
            SettlementDomain::Composite,
            state.encrypted_intent_root(),
            state.bridge_route_hint_root(),
            state.mev_commitment_root(),
            state.bridge_route_hint_root(),
            state.height,
            state
                .height
                .saturating_add(state.config.auction_window_blocks),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.settlement_window_blocks),
            state
                .height
                .saturating_add(state.config.auction_window_blocks)
                .saturating_add(state.config.settlement_window_blocks)
                .saturating_add(state.config.challenge_window_blocks),
            "devnet-private-defi-market-seed",
            &json!({"clearing": "uniform", "tie_break": "lexicographic_commitment"}),
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_batch_auction(auction)?;

        let xmr_usdd_price = BatchAuctionClearingPrice::new(
            &auction_id,
            "wxmr-devnet",
            "usdd-devnet",
            180 * INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            7_560_000_000_000,
            28_000_000,
            20,
            &json!({"oracle": "devnet-median", "samples": 5, "bounded": true}),
            state
                .height
                .saturating_add(state.config.auction_window_blocks),
            state.next_nonce(),
        )?;
        let xmr_usdd_price_id = xmr_usdd_price.clearing_price_id.clone();
        state.insert_clearing_price(xmr_usdd_price)?;

        let usdd_xmr_price = BatchAuctionClearingPrice::new(
            &auction_id,
            "usdd-devnet",
            "wxmr-devnet",
            INTENT_SETTLEMENT_PRICE_SCALE,
            180 * INTENT_SETTLEMENT_PRICE_SCALE,
            125_000_000_000,
            9_000_000,
            18,
            &json!({"oracle": "devnet-inverse-median", "samples": 5}),
            state
                .height
                .saturating_add(state.config.auction_window_blocks),
            state.next_nonce(),
        )?;
        let usdd_xmr_price_id = usdd_xmr_price.clearing_price_id.clone();
        state.insert_clearing_price(usdd_xmr_price)?;

        let perp_price = BatchAuctionClearingPrice::new(
            &auction_id,
            "wxmr-perp-devnet",
            "usdd-devnet",
            181 * INTENT_SETTLEMENT_PRICE_SCALE,
            INTENT_SETTLEMENT_PRICE_SCALE,
            3_600_000_000,
            4_000_000,
            25,
            &json!({"oracle": "devnet-perp-index", "funding_interval": 24}),
            state
                .height
                .saturating_add(state.config.auction_window_blocks),
            state.next_nonce(),
        )?;
        let perp_price_id = perp_price.clearing_price_id.clone();
        state.insert_clearing_price(perp_price)?;

        let legs = vec![
            SolverBundleLeg::new(
                &swap_intent_id,
                SettlementDomain::Swap,
                intent_settlement_string_root("DEVNET-INPUT-NOTE", "alice-wxmr-input"),
                intent_settlement_string_root("DEVNET-OUTPUT-NOTE", "alice-usdd-output"),
                "wxmr-devnet",
                "usdd-devnet",
                42_000_000_000,
                7_560_000_000_000,
                &xmr_usdd_price_id,
                "devnet-router-direct-wxmr-usdd",
                "",
                8_500,
                24_000,
                "",
                &json!({"route": "cfmm-private-pool", "pool": "wxmr-usdd-devnet"}),
                state.next_nonce(),
            )?,
            SolverBundleLeg::new(
                &borrow_intent_id,
                SettlementDomain::Lending,
                intent_settlement_string_root("DEVNET-INPUT-NOTE", "bob-wxmr-collateral"),
                intent_settlement_string_root("DEVNET-OUTPUT-NOTE", "bob-usdd-debt-note"),
                "wxmr-collateral-devnet",
                "usdd-devnet",
                125_000_000_000,
                18_000_000_000,
                &usdd_xmr_price_id,
                "devnet-lending-market-wxmr-usdd",
                "",
                10_000,
                19_000,
                "",
                &json!({"lending": "borrow", "health_bucket": "healthy"}),
                state.next_nonce(),
            )?,
            SolverBundleLeg::new(
                &perp_intent_id,
                SettlementDomain::Perp,
                intent_settlement_string_root("DEVNET-INPUT-NOTE", "caro-usdd-margin"),
                intent_settlement_string_root("DEVNET-OUTPUT-NOTE", "caro-perp-position"),
                "usdd-devnet",
                "wxmr-perp-devnet",
                3_600_000_000,
                1_000_000,
                &perp_price_id,
                "devnet-perp-vault-wxmr-usdd",
                "",
                10_000,
                16_000,
                "",
                &json!({"perp": "open_long", "leverage_bps": 3000}),
                state.next_nonce(),
            )?,
            SolverBundleLeg::new(
                &bridge_intent_id,
                SettlementDomain::Bridge,
                intent_settlement_string_root("DEVNET-INPUT-NOTE", "dana-usdd-l2"),
                intent_settlement_string_root("DEVNET-OUTPUT-NOTE", "dana-monero-exit"),
                "usdd-devnet",
                "usdd-monero-exit",
                1_250_000_000,
                1_240_000_000,
                &usdd_xmr_price_id,
                "devnet-fast-exit-liquidity",
                &bridge_hint_id,
                10_000,
                11_000,
                "",
                &json!({"bridge_exit": "fast_exit", "adapter": "devnet-fast-exit"}),
                state.next_nonce(),
            )?,
        ];

        let mut bundle = SolverBundle::new(
            &auction_id,
            "devnet-solver-1",
            &attestation_id,
            legs.clone(),
            std::slice::from_ref(&swap_mev_id),
            std::slice::from_ref(&bridge_hint_id),
            41_000_000,
            1_500_000,
            950_000,
            state.height.saturating_add(2),
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        bundle.status = SolverBundleStatus::Selected;
        let bundle_id = bundle.bundle_id.clone();
        state.insert_solver_bundle(bundle)?;
        state.refresh_auction_roots();

        let execution_height = state
            .height
            .saturating_add(state.config.auction_window_blocks)
            .saturating_add(2);
        let group_nonce = state.next_nonce();
        let clearing_prices = state.clearing_prices.values().cloned().collect::<Vec<_>>();
        let clearing_price_root = intent_settlement_clearing_price_root(&clearing_prices);
        let group_id = intent_settlement_group_id(
            &auction_id,
            &bundle_id,
            &solver_commitment,
            &clearing_price_root,
            execution_height,
            group_nonce,
        );

        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let default_fee_asset_id = state.config.default_fee_asset_id.clone();
        let rebate_swap_nonce = state.next_nonce();
        let rebate_swap = LowFeeRebate::new(
            &default_low_fee_lane,
            "devnet-foundation-paymaster",
            "devnet-alice-private-intents",
            &group_id,
            &default_fee_asset_id,
            24_000,
            14_000,
            &json!({"lane": "private_defi", "reason": "small_private_swap"}),
            execution_height,
            execution_height.saturating_add(240),
            rebate_swap_nonce,
        )?;
        let rebate_borrow_nonce = state.next_nonce();
        let rebate_borrow = LowFeeRebate::new(
            &default_low_fee_lane,
            "devnet-foundation-paymaster",
            "devnet-bob-private-borrower",
            &group_id,
            &default_fee_asset_id,
            19_000,
            9_500,
            &json!({"lane": "private_lending", "reason": "new_private_borrow"}),
            execution_height,
            execution_height.saturating_add(240),
            rebate_borrow_nonce,
        )?;
        let rebate_swap_id = rebate_swap.rebate_id.clone();
        let rebate_borrow_id = rebate_borrow.rebate_id.clone();
        state.insert_low_fee_rebate(rebate_swap)?;
        state.insert_low_fee_rebate(rebate_borrow)?;

        let partial_swap = PrivatePartialFillNote::new(
            &swap_intent_id,
            &group_id,
            &bundle_id,
            &swap_owner_commitment,
            "alice-wxmr-input-nullifier",
            "alice-usdd-partial-output",
            35_700_000_000,
            6_300_000_000,
            &xmr_usdd_price_id,
            8_500,
            24_000,
            &rebate_swap_id,
            &json!({"ciphertext": "alice-partial-fill-note", "view_tag": "alice-view"}),
            execution_height,
            execution_height,
            state.next_nonce(),
        )?;
        let partial_borrow = PrivatePartialFillNote::new(
            &borrow_intent_id,
            &group_id,
            &bundle_id,
            &borrow_owner_commitment,
            "bob-collateral-nullifier",
            "bob-private-debt-note",
            18_000_000_000,
            0,
            &usdd_xmr_price_id,
            10_000,
            19_000,
            &rebate_borrow_id,
            &json!({"ciphertext": "bob-debt-note", "health_bucket": "healthy"}),
            execution_height,
            execution_height,
            state.next_nonce(),
        )?;
        let partial_perp = PrivatePartialFillNote::new(
            &perp_intent_id,
            &group_id,
            &bundle_id,
            &perp_owner_commitment,
            "caro-margin-nullifier",
            "caro-perp-position-note",
            3_600_000_000,
            0,
            &perp_price_id,
            10_000,
            16_000,
            "",
            &json!({"ciphertext": "caro-perp-position", "side": "long"}),
            execution_height,
            execution_height,
            state.next_nonce(),
        )?;
        let partial_bridge = PrivatePartialFillNote::new(
            &bridge_intent_id,
            &group_id,
            &bundle_id,
            &bridge_owner_commitment,
            "dana-usdd-nullifier",
            "dana-monero-exit-note",
            1_240_000_000,
            10_000_000,
            &usdd_xmr_price_id,
            10_000,
            11_000,
            "",
            &json!({"ciphertext": "dana-bridge-exit-note", "remote": "monero-devnet"}),
            execution_height,
            execution_height.saturating_add(20),
            state.next_nonce(),
        )?;
        state.insert_partial_fill_note(partial_swap)?;
        state.insert_partial_fill_note(partial_borrow)?;
        state.insert_partial_fill_note(partial_perp)?;
        state.insert_partial_fill_note(partial_bridge)?;

        let partial_notes = state
            .partial_fill_notes
            .values()
            .filter(|note| note.group_id == group_id)
            .cloned()
            .collect::<Vec<_>>();
        let rebates = state
            .low_fee_rebates
            .values()
            .filter(|rebate| rebate.subject_id == group_id)
            .cloned()
            .collect::<Vec<_>>();
        let group = AtomicSettlementGroup::new(
            &auction_id,
            &bundle_id,
            &solver_commitment,
            &attestation_id,
            &legs,
            &clearing_prices,
            &partial_notes,
            &rebates,
            &[json!({
                "intent_id": bridge_intent_id,
                "route_hint_id": bridge_hint_id,
                "exit_status": "submitted",
                "min_exit_amount": 1_240_000_000_u64
            })],
            &[json!({
                "intent_id": borrow_intent_id,
                "market": "wxmr-usdd",
                "health_bucket": "healthy"
            })],
            &[json!({
                "intent_id": perp_intent_id,
                "market": "wxmr-usdd-perp",
                "initial_margin_bps": 3333
            })],
            &[json!({
                "bundle_id": bundle_id,
                "token_delta": "netted-private-notes"
            })],
            std::slice::from_ref(&swap_mev_id),
            execution_height,
            execution_height.saturating_add(state.config.challenge_window_blocks),
            group_nonce,
        )?;
        state.insert_settlement_group(group)?;

        let challenge = FailedSettlementChallenge::new(
            &group_id,
            &bundle_id,
            "devnet-watchtower-1",
            FailureKind::MissingBridgeExit,
            intent_settlement_string_root("DEVNET-EXPECTED-BRIDGE-EXIT", "dana-exit-finalized"),
            intent_settlement_string_root("DEVNET-OBSERVED-BRIDGE-EXIT", "dana-exit-submitted"),
            &json!({
                "route_hint_id": bridge_hint_id,
                "observation": "exit pending finality",
                "challenge": "watchtower keeps challenge window warm"
            }),
            execution_height.saturating_add(1),
            execution_height.saturating_add(state.config.challenge_window_blocks),
            750,
            state.next_nonce(),
        )?;
        let challenge_id = challenge.challenge_id.clone();
        state.insert_failed_challenge(challenge)?;

        let slashing = SlashingEvidence::new(
            "devnet-solver-1",
            &bundle_id,
            &attestation_id,
            &challenge_id,
            SlashingEvidenceKind::WithheldBridgeProof,
            &json!({"bundle_id": bundle_id, "claim": "bridge_exit_finalized"}),
            &json!({"bundle_id": bundle_id, "claim": "bridge_exit_submitted"}),
            "devnet-watchtower-1",
            1_500_000,
            75_000,
            execution_height.saturating_add(1),
            state.next_nonce(),
        )?;
        state.insert_slashing_evidence(slashing)?;

        for (record_kind, subject_id, payload) in [
            (
                "encrypted_intent",
                swap_intent_id.as_str(),
                state.encrypted_intents[&swap_intent_id].public_record(),
            ),
            (
                "solver_bundle",
                bundle_id.as_str(),
                state.solver_bundles[&bundle_id].public_record(),
            ),
            (
                "settlement_group",
                group_id.as_str(),
                state.settlement_groups[&group_id].public_record(),
            ),
            (
                "failed_challenge",
                challenge_id.as_str(),
                state.failed_challenges[&challenge_id].public_record(),
            ),
        ] {
            state.publish_public_record(record_kind, subject_id, &payload)?;
        }

        state.refresh_auction_roots();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for intent in self.encrypted_intents.values_mut() {
            if intent.deadline_height < height && intent.status.counts_as_active() {
                intent.status = IntentStatus::Expired;
            }
        }
        for commitment in self.mev_commitments.values_mut() {
            if commitment.expires_at_height < height
                && commitment.status == MevCommitmentStatus::Committed
            {
                commitment.status = MevCommitmentStatus::Expired;
            }
        }
        for hint in self.bridge_route_hints.values_mut() {
            if hint.expires_at_height < height && hint.status == BridgeRouteStatus::Proposed {
                hint.status = BridgeRouteStatus::Expired;
            }
        }
        for rebate in self.low_fee_rebates.values_mut() {
            if rebate.expires_at_height < height && rebate.status.counts_as_pending() {
                rebate.status = RebateStatus::Expired;
            }
        }
        for challenge in self.failed_challenges.values_mut() {
            if challenge.response_deadline_height < height
                && challenge.status == ChallengeStatus::Open
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_encrypted_intent(
        &mut self,
        intent: EncryptedDefiIntent,
    ) -> IntentSettlementResult<()> {
        intent.validate()?;
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    pub fn insert_mev_commitment(
        &mut self,
        commitment: MevProtectionCommitment,
    ) -> IntentSettlementResult<()> {
        commitment.validate()?;
        if !self.encrypted_intents.contains_key(&commitment.intent_id) {
            return Err("mev commitment references missing intent".to_string());
        }
        self.mev_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_bridge_route_hint(
        &mut self,
        hint: BridgeWithdrawalRouteHint,
    ) -> IntentSettlementResult<()> {
        hint.validate()?;
        if !self.encrypted_intents.contains_key(&hint.intent_id) {
            return Err("bridge route hint references missing intent".to_string());
        }
        self.bridge_route_hints
            .insert(hint.route_hint_id.clone(), hint);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: SolverPqAttestation,
    ) -> IntentSettlementResult<()> {
        attestation.validate()?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_batch_auction(&mut self, auction: BatchAuction) -> IntentSettlementResult<()> {
        auction.validate()?;
        self.batch_auctions
            .insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_clearing_price(
        &mut self,
        price: BatchAuctionClearingPrice,
    ) -> IntentSettlementResult<()> {
        price.validate()?;
        if !self.batch_auctions.contains_key(&price.auction_id) {
            return Err("clearing price references missing auction".to_string());
        }
        self.clearing_prices
            .insert(price.clearing_price_id.clone(), price);
        Ok(())
    }

    pub fn insert_solver_bundle(&mut self, bundle: SolverBundle) -> IntentSettlementResult<()> {
        bundle.validate()?;
        if !self.batch_auctions.contains_key(&bundle.auction_id) {
            return Err("solver bundle references missing auction".to_string());
        }
        if !self.pq_attestations.contains_key(&bundle.pq_attestation_id) {
            return Err("solver bundle references missing pq attestation".to_string());
        }
        if bundle.legs.len() > self.config.max_bundle_intents {
            return Err("solver bundle exceeds max bundle intents".to_string());
        }
        if bundle.solver_bond_units < self.config.min_solver_bond_units {
            return Err("solver bundle bond is below configured minimum".to_string());
        }
        for leg in &bundle.legs {
            if !self.encrypted_intents.contains_key(&leg.intent_id) {
                return Err("solver bundle leg references missing intent".to_string());
            }
            if !leg.clearing_price_id.is_empty()
                && !self.clearing_prices.contains_key(&leg.clearing_price_id)
            {
                return Err("solver bundle leg references missing clearing price".to_string());
            }
            if !leg.bridge_hint_id.is_empty()
                && !self.bridge_route_hints.contains_key(&leg.bridge_hint_id)
            {
                return Err("solver bundle leg references missing bridge hint".to_string());
            }
        }
        self.solver_bundles.insert(bundle.bundle_id.clone(), bundle);
        Ok(())
    }

    pub fn insert_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> IntentSettlementResult<()> {
        rebate.validate()?;
        if rebate.rebate_bps > self.config.low_fee_rebate_cap_bps {
            return Err("low fee rebate exceeds configured cap".to_string());
        }
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_partial_fill_note(
        &mut self,
        note: PrivatePartialFillNote,
    ) -> IntentSettlementResult<()> {
        note.validate()?;
        if !self.encrypted_intents.contains_key(&note.intent_id) {
            return Err("partial fill note references missing intent".to_string());
        }
        if !self.solver_bundles.contains_key(&note.bundle_id) {
            return Err("partial fill note references missing bundle".to_string());
        }
        if !note.clearing_price_id.is_empty()
            && !self.clearing_prices.contains_key(&note.clearing_price_id)
        {
            return Err("partial fill note references missing clearing price".to_string());
        }
        if !note.rebate_id.is_empty() && !self.low_fee_rebates.contains_key(&note.rebate_id) {
            return Err("partial fill note references missing rebate".to_string());
        }
        self.partial_fill_notes.insert(note.note_id.clone(), note);
        Ok(())
    }

    pub fn insert_settlement_group(
        &mut self,
        group: AtomicSettlementGroup,
    ) -> IntentSettlementResult<()> {
        group.validate()?;
        if !self.batch_auctions.contains_key(&group.auction_id) {
            return Err("settlement group references missing auction".to_string());
        }
        if !self.solver_bundles.contains_key(&group.bundle_id) {
            return Err("settlement group references missing bundle".to_string());
        }
        if !self.pq_attestations.contains_key(&group.pq_attestation_id) {
            return Err("settlement group references missing pq attestation".to_string());
        }
        if group.leg_count as usize > self.config.max_settlement_group_legs {
            return Err("settlement group exceeds configured leg cap".to_string());
        }
        self.settlement_groups.insert(group.group_id.clone(), group);
        Ok(())
    }

    pub fn insert_failed_challenge(
        &mut self,
        challenge: FailedSettlementChallenge,
    ) -> IntentSettlementResult<()> {
        challenge.validate()?;
        if !self.settlement_groups.contains_key(&challenge.group_id) {
            return Err("failed challenge references missing settlement group".to_string());
        }
        if !self.solver_bundles.contains_key(&challenge.bundle_id) {
            return Err("failed challenge references missing solver bundle".to_string());
        }
        self.failed_challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> IntentSettlementResult<()> {
        evidence.validate()?;
        if !self.solver_bundles.contains_key(&evidence.bundle_id) {
            return Err("slashing evidence references missing bundle".to_string());
        }
        if !self.pq_attestations.contains_key(&evidence.attestation_id) {
            return Err("slashing evidence references missing pq attestation".to_string());
        }
        if !self.failed_challenges.contains_key(&evidence.challenge_id) {
            return Err("slashing evidence references missing challenge".to_string());
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> IntentSettlementResult<IntentSettlementPublicRecord> {
        let record = IntentSettlementPublicRecord::new(
            record_kind,
            subject_id,
            payload,
            self.height,
            self.next_nonce(),
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn refresh_auction_roots(&mut self) {
        let auction_ids = self.batch_auctions.keys().cloned().collect::<Vec<_>>();
        for auction_id in auction_ids {
            let solver_bundle_root = intent_settlement_solver_bundle_root(
                &self
                    .solver_bundles
                    .values()
                    .filter(|bundle| bundle.auction_id == auction_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let clearing_price_root = intent_settlement_clearing_price_root(
                &self
                    .clearing_prices
                    .values()
                    .filter(|price| price.auction_id == auction_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(auction) = self.batch_auctions.get_mut(&auction_id) {
                auction.solver_bundle_root = solver_bundle_root;
                auction.clearing_price_root = clearing_price_root;
                if !self.solver_bundles.is_empty() && !self.clearing_prices.is_empty() {
                    auction.status = AuctionStatus::Cleared;
                }
            }
        }
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn encrypted_intent_root(&self) -> String {
        intent_settlement_encrypted_intent_root(
            &self.encrypted_intents.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn batch_auction_root(&self) -> String {
        intent_settlement_batch_auction_root(
            &self.batch_auctions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn solver_bundle_root(&self) -> String {
        intent_settlement_solver_bundle_root(
            &self.solver_bundles.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn clearing_price_root(&self) -> String {
        intent_settlement_clearing_price_root(
            &self.clearing_prices.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn settlement_group_root(&self) -> String {
        intent_settlement_group_root(&self.settlement_groups.values().cloned().collect::<Vec<_>>())
    }

    pub fn low_fee_rebate_root(&self) -> String {
        intent_settlement_low_fee_rebate_root(
            &self.low_fee_rebates.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn partial_fill_note_root(&self) -> String {
        intent_settlement_partial_fill_note_root(
            &self
                .partial_fill_notes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn mev_commitment_root(&self) -> String {
        intent_settlement_mev_commitment_root(
            &self.mev_commitments.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn bridge_route_hint_root(&self) -> String {
        intent_settlement_bridge_route_hint_root(
            &self
                .bridge_route_hints
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        intent_settlement_pq_attestation_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn failed_challenge_root(&self) -> String {
        intent_settlement_failed_challenge_root(
            &self.failed_challenges.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn slashing_evidence_root(&self) -> String {
        intent_settlement_slashing_evidence_root(
            &self.slashing_evidence.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        intent_settlement_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> IntentSettlementRoots {
        IntentSettlementRoots {
            config_root: self.config_root(),
            encrypted_intent_root: self.encrypted_intent_root(),
            batch_auction_root: self.batch_auction_root(),
            solver_bundle_root: self.solver_bundle_root(),
            clearing_price_root: self.clearing_price_root(),
            settlement_group_root: self.settlement_group_root(),
            low_fee_rebate_root: self.low_fee_rebate_root(),
            partial_fill_note_root: self.partial_fill_note_root(),
            mev_commitment_root: self.mev_commitment_root(),
            bridge_route_hint_root: self.bridge_route_hint_root(),
            pq_attestation_root: self.pq_attestation_root(),
            failed_challenge_root: self.failed_challenge_root(),
            slashing_evidence_root: self.slashing_evidence_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> IntentSettlementCounters {
        IntentSettlementCounters {
            encrypted_intent_count: self.encrypted_intents.len() as u64,
            active_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.is_active_at(self.height))
                .count() as u64,
            swap_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_swap())
                .count() as u64,
            lending_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_lending())
                .count() as u64,
            perp_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_perp())
                .count() as u64,
            bridge_exit_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.intent_kind.is_bridge_exit())
                .count() as u64,
            batch_auction_count: self.batch_auctions.len() as u64,
            live_auction_count: self
                .batch_auctions
                .values()
                .filter(|auction| auction.accepts_height(self.height))
                .count() as u64,
            solver_bundle_count: self.solver_bundles.len() as u64,
            selected_bundle_count: self
                .solver_bundles
                .values()
                .filter(|bundle| {
                    matches!(
                        bundle.status,
                        SolverBundleStatus::Selected | SolverBundleStatus::Settled
                    )
                })
                .count() as u64,
            clearing_price_count: self.clearing_prices.len() as u64,
            settlement_group_count: self.settlement_groups.len() as u64,
            settled_group_count: self
                .settlement_groups
                .values()
                .filter(|group| group.status == SettlementGroupStatus::Settled)
                .count() as u64,
            failed_group_count: self
                .settlement_groups
                .values()
                .filter(|group| {
                    matches!(
                        group.status,
                        SettlementGroupStatus::Failed
                            | SettlementGroupStatus::Challenged
                            | SettlementGroupStatus::Reverted
                    )
                })
                .count() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            pending_rebate_count: self
                .low_fee_rebates
                .values()
                .filter(|rebate| rebate.is_live_at(self.height))
                .count() as u64,
            partial_fill_note_count: self.partial_fill_notes.len() as u64,
            mev_commitment_count: self.mev_commitments.len() as u64,
            active_mev_commitment_count: self
                .mev_commitments
                .values()
                .filter(|commitment| commitment.is_active_at(self.height))
                .count() as u64,
            bridge_route_hint_count: self.bridge_route_hints.len() as u64,
            live_bridge_route_hint_count: self
                .bridge_route_hints
                .values()
                .filter(|hint| hint.is_live_at(self.height))
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.is_active_at(self.height))
                .count() as u64,
            failed_challenge_count: self.failed_challenges.len() as u64,
            open_challenge_count: self
                .failed_challenges
                .values()
                .filter(|challenge| challenge.is_open_at(self.height))
                .count() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            pending_slash_units: self.pending_slash_units(),
            gross_fee_units: self.gross_fee_units(),
            total_rebate_units: self.total_rebate_units(),
            notional_cleared_units: self.notional_cleared_units(),
        }
    }

    pub fn pending_slash_units(&self) -> u64 {
        self.slashing_evidence
            .values()
            .filter(|evidence| evidence.status.counts_as_pending())
            .fold(0_u64, |total, evidence| {
                total.saturating_add(evidence.slash_units)
            })
    }

    pub fn gross_fee_units(&self) -> u64 {
        self.settlement_groups.values().fold(0_u64, |total, group| {
            total.saturating_add(group.total_fee_units)
        })
    }

    pub fn total_rebate_units(&self) -> u64 {
        self.low_fee_rebates.values().fold(0_u64, |total, rebate| {
            total.saturating_add(rebate.rebate_units)
        })
    }

    pub fn notional_cleared_units(&self) -> u64 {
        self.clearing_prices.values().fold(0_u64, |total, price| {
            total.saturating_add(price.notional_cleared_units)
        })
    }

    pub fn state_root(&self) -> String {
        intent_settlement_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("intent settlement state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> IntentSettlementResult<String> {
        self.config.validate()?;
        for (id, intent) in &self.encrypted_intents {
            if id != &intent.intent_id {
                return Err("state intent key does not match intent id".to_string());
            }
            intent.validate()?;
        }
        for (id, commitment) in &self.mev_commitments {
            if id != &commitment.commitment_id {
                return Err("state mev key does not match commitment id".to_string());
            }
            commitment.validate()?;
            if !self.encrypted_intents.contains_key(&commitment.intent_id) {
                return Err("state mev commitment references missing intent".to_string());
            }
        }
        for (id, hint) in &self.bridge_route_hints {
            if id != &hint.route_hint_id {
                return Err("state bridge route key does not match hint id".to_string());
            }
            hint.validate()?;
            if !self.encrypted_intents.contains_key(&hint.intent_id) {
                return Err("state bridge route references missing intent".to_string());
            }
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err("state pq key does not match attestation id".to_string());
            }
            attestation.validate()?;
        }
        for (id, auction) in &self.batch_auctions {
            if id != &auction.auction_id {
                return Err("state auction key does not match auction id".to_string());
            }
            auction.validate()?;
        }
        for (id, price) in &self.clearing_prices {
            if id != &price.clearing_price_id {
                return Err("state clearing price key does not match id".to_string());
            }
            price.validate()?;
            if !self.batch_auctions.contains_key(&price.auction_id) {
                return Err("state clearing price references missing auction".to_string());
            }
        }
        for (id, bundle) in &self.solver_bundles {
            if id != &bundle.bundle_id {
                return Err("state solver bundle key does not match id".to_string());
            }
            bundle.validate()?;
            if !self.batch_auctions.contains_key(&bundle.auction_id) {
                return Err("state solver bundle references missing auction".to_string());
            }
            if !self.pq_attestations.contains_key(&bundle.pq_attestation_id) {
                return Err("state solver bundle references missing attestation".to_string());
            }
            if bundle.solver_bond_units < self.config.min_solver_bond_units {
                return Err("state solver bundle bond below minimum".to_string());
            }
            if bundle.legs.len() > self.config.max_bundle_intents {
                return Err("state solver bundle exceeds max intents".to_string());
            }
            for leg in &bundle.legs {
                if !self.encrypted_intents.contains_key(&leg.intent_id) {
                    return Err("state bundle leg references missing intent".to_string());
                }
                if !leg.clearing_price_id.is_empty()
                    && !self.clearing_prices.contains_key(&leg.clearing_price_id)
                {
                    return Err("state bundle leg references missing price".to_string());
                }
                if !leg.bridge_hint_id.is_empty()
                    && !self.bridge_route_hints.contains_key(&leg.bridge_hint_id)
                {
                    return Err("state bundle leg references missing bridge hint".to_string());
                }
            }
        }
        for (id, rebate) in &self.low_fee_rebates {
            if id != &rebate.rebate_id {
                return Err("state rebate key does not match id".to_string());
            }
            rebate.validate()?;
            if rebate.rebate_bps > self.config.low_fee_rebate_cap_bps {
                return Err("state rebate exceeds configured cap".to_string());
            }
            if !self.subject_exists(&rebate.subject_id) {
                return Err("state rebate references unknown subject".to_string());
            }
        }
        for (id, note) in &self.partial_fill_notes {
            if id != &note.note_id {
                return Err("state partial fill key does not match note id".to_string());
            }
            note.validate()?;
            if !self.encrypted_intents.contains_key(&note.intent_id) {
                return Err("state partial fill references missing intent".to_string());
            }
            if !self.solver_bundles.contains_key(&note.bundle_id) {
                return Err("state partial fill references missing bundle".to_string());
            }
            if !self.settlement_groups.contains_key(&note.group_id) {
                return Err("state partial fill references missing group".to_string());
            }
            if !note.clearing_price_id.is_empty()
                && !self.clearing_prices.contains_key(&note.clearing_price_id)
            {
                return Err("state partial fill references missing price".to_string());
            }
            if !note.rebate_id.is_empty() && !self.low_fee_rebates.contains_key(&note.rebate_id) {
                return Err("state partial fill references missing rebate".to_string());
            }
        }
        for (id, group) in &self.settlement_groups {
            if id != &group.group_id {
                return Err("state settlement group key does not match group id".to_string());
            }
            group.validate()?;
            if !self.batch_auctions.contains_key(&group.auction_id) {
                return Err("state settlement group references missing auction".to_string());
            }
            if !self.solver_bundles.contains_key(&group.bundle_id) {
                return Err("state settlement group references missing bundle".to_string());
            }
            if !self.pq_attestations.contains_key(&group.pq_attestation_id) {
                return Err("state settlement group references missing attestation".to_string());
            }
            if group.leg_count as usize > self.config.max_settlement_group_legs {
                return Err("state settlement group exceeds max legs".to_string());
            }
        }
        for (id, challenge) in &self.failed_challenges {
            if id != &challenge.challenge_id {
                return Err("state challenge key does not match challenge id".to_string());
            }
            challenge.validate()?;
            if !self.settlement_groups.contains_key(&challenge.group_id) {
                return Err("state challenge references missing group".to_string());
            }
            if !self.solver_bundles.contains_key(&challenge.bundle_id) {
                return Err("state challenge references missing bundle".to_string());
            }
        }
        for (id, evidence) in &self.slashing_evidence {
            if id != &evidence.evidence_id {
                return Err("state slashing key does not match evidence id".to_string());
            }
            evidence.validate()?;
            if !self.solver_bundles.contains_key(&evidence.bundle_id) {
                return Err("state slashing references missing bundle".to_string());
            }
            if !self.pq_attestations.contains_key(&evidence.attestation_id) {
                return Err("state slashing references missing attestation".to_string());
            }
            if !self.failed_challenges.contains_key(&evidence.challenge_id) {
                return Err("state slashing references missing challenge".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
            if !self.subject_exists(&record.subject_id) {
                return Err("state public record references unknown subject".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn subject_exists(&self, subject_id: &str) -> bool {
        self.encrypted_intents.contains_key(subject_id)
            || self.batch_auctions.contains_key(subject_id)
            || self.solver_bundles.contains_key(subject_id)
            || self.clearing_prices.contains_key(subject_id)
            || self.settlement_groups.contains_key(subject_id)
            || self.low_fee_rebates.contains_key(subject_id)
            || self.partial_fill_notes.contains_key(subject_id)
            || self.mev_commitments.contains_key(subject_id)
            || self.bridge_route_hints.contains_key(subject_id)
            || self.pq_attestations.contains_key(subject_id)
            || self.failed_challenges.contains_key(subject_id)
            || self.slashing_evidence.contains_key(subject_id)
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "intent_settlement_state",
            "chain_id": CHAIN_ID,
            "protocol_version": INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }
}

pub fn intent_settlement_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn intent_settlement_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn intent_settlement_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn intent_settlement_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn intent_settlement_account_commitment(label: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn intent_settlement_solver_commitment(label: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-SOLVER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn intent_settlement_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn intent_settlement_asset_pair_commitment(asset_a: &str, asset_b: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-ASSET-PAIR-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_a),
            HashPart::Str(asset_b),
        ],
        32,
    )
}

pub fn intent_settlement_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn intent_settlement_price_commitment(
    numerator: u64,
    denominator: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-PRICE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(numerator as i128),
            HashPart::Int(denominator as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn intent_settlement_blinding(label: &str, nonce: u64, field: &str) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(field),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn intent_settlement_intent_id(
    intent_kind: &IntentKind,
    owner_commitment: &str,
    input_asset_commitment: &str,
    output_asset_commitment: &str,
    amount_in_commitment: &str,
    min_amount_out_commitment: &str,
    limit_price_commitment: &str,
    submitted_at_height: u64,
    deadline_height: u64,
    nonce: u64,
) -> String {
    let kind = intent_kind.as_str();
    domain_hash(
        "INTENT-SETTLEMENT-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&kind),
            HashPart::Str(owner_commitment),
            HashPart::Str(input_asset_commitment),
            HashPart::Str(output_asset_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(min_amount_out_commitment),
            HashPart::Str(limit_price_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_mev_commitment_id(
    intent_id: &str,
    owner_commitment: &str,
    batch_salt_commitment: &str,
    encrypted_preference_root: &str,
    commit_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-MEV-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(batch_salt_commitment),
            HashPart::Str(encrypted_preference_root),
            HashPart::Int(commit_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn intent_settlement_bridge_route_hint_id(
    intent_id: &str,
    source_domain: &str,
    destination_domain: &str,
    remote_chain_id: &str,
    bridge_adapter_commitment: &str,
    exit_recipient_commitment: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-BRIDGE-ROUTE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(source_domain),
            HashPart::Str(destination_domain),
            HashPart::Str(remote_chain_id),
            HashPart::Str(bridge_adapter_commitment),
            HashPart::Str(exit_recipient_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_pq_attestation_id(
    solver_commitment: &str,
    scheme: &str,
    committee_root: &str,
    transcript_root: &str,
    valid_from_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_commitment),
            HashPart::Str(scheme),
            HashPart::Str(committee_root),
            HashPart::Str(transcript_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_batch_auction_id(
    market_id: &str,
    auction_domain: &SettlementDomain,
    intent_root: &str,
    commit_start_height: u64,
    clearing_seed: &str,
) -> String {
    let auction_domain = auction_domain.as_str();
    domain_hash(
        "INTENT-SETTLEMENT-BATCH-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(&auction_domain),
            HashPart::Str(intent_root),
            HashPart::Int(commit_start_height as i128),
            HashPart::Str(clearing_seed),
        ],
        32,
    )
}

pub fn intent_settlement_clearing_price_id(
    auction_id: &str,
    pair_commitment: &str,
    price_numerator: u64,
    price_denominator: u64,
    cleared_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-CLEARING-PRICE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(pair_commitment),
            HashPart::Int(price_numerator as i128),
            HashPart::Int(price_denominator as i128),
            HashPart::Int(cleared_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_bundle_leg_id(
    intent_id: &str,
    domain: &SettlementDomain,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_upper_bound: u64,
    amount_out_lower_bound: u64,
    nonce: u64,
) -> String {
    let domain = domain.as_str();
    domain_hash(
        "INTENT-SETTLEMENT-BUNDLE-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(&domain),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Int(amount_in_upper_bound as i128),
            HashPart::Int(amount_out_lower_bound as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_solver_bundle_id(
    auction_id: &str,
    solver_commitment: &str,
    leg_root: &str,
    proposed_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-SOLVER-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(leg_root),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_low_fee_rebate_id(
    lane_id: &str,
    recipient_commitment: &str,
    subject_id: &str,
    rebate_units: u64,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(subject_id),
            HashPart::Int(rebate_units as i128),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_partial_fill_note_id(
    intent_id: &str,
    group_id: &str,
    output_commitment: &str,
    fill_amount_commitment: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-PARTIAL-FILL-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(group_id),
            HashPart::Str(output_commitment),
            HashPart::Str(fill_amount_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_group_id(
    auction_id: &str,
    bundle_id: &str,
    solver_commitment: &str,
    clearing_price_root: &str,
    execution_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-GROUP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bundle_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(clearing_price_root),
            HashPart::Int(execution_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_failed_challenge_id(
    group_id: &str,
    bundle_id: &str,
    challenger_commitment: &str,
    failure_kind: &FailureKind,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    let failure_kind = failure_kind.as_str();
    domain_hash(
        "INTENT-SETTLEMENT-FAILED-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(group_id),
            HashPart::Str(bundle_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(&failure_kind),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_equivocation_root(
    solver_commitment: &str,
    bundle_id: &str,
    first_statement_root: &str,
    second_statement_root: &str,
) -> String {
    let ordered = if first_statement_root <= second_statement_root {
        (first_statement_root, second_statement_root)
    } else {
        (second_statement_root, first_statement_root)
    };
    domain_hash(
        "INTENT-SETTLEMENT-EQUIVOCATION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_commitment),
            HashPart::Str(bundle_id),
            HashPart::Str(ordered.0),
            HashPart::Str(ordered.1),
        ],
        32,
    )
}

pub fn intent_settlement_slashing_evidence_id(
    solver_commitment: &str,
    bundle_id: &str,
    attestation_id: &str,
    challenge_id: &str,
    evidence_kind: &SlashingEvidenceKind,
    created_at_height: u64,
    nonce: u64,
) -> String {
    let evidence_kind = evidence_kind.as_str();
    domain_hash(
        "INTENT-SETTLEMENT-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_commitment),
            HashPart::Str(bundle_id),
            HashPart::Str(attestation_id),
            HashPart::Str(challenge_id),
            HashPart::Str(&evidence_kind),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "INTENT-SETTLEMENT-PUBLIC-RECORD-ID",
        &[
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

pub fn intent_settlement_encrypted_intent_root(items: &[EncryptedDefiIntent]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-ENCRYPTED-INTENT",
        &items
            .iter()
            .map(EncryptedDefiIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_mev_commitment_root(items: &[MevProtectionCommitment]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-MEV-COMMITMENT",
        &items
            .iter()
            .map(MevProtectionCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_bridge_route_hint_root(items: &[BridgeWithdrawalRouteHint]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-BRIDGE-ROUTE-HINT",
        &items
            .iter()
            .map(BridgeWithdrawalRouteHint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_pq_attestation_root(items: &[SolverPqAttestation]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-PQ-ATTESTATION",
        &items
            .iter()
            .map(SolverPqAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_batch_auction_root(items: &[BatchAuction]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-BATCH-AUCTION",
        &items
            .iter()
            .map(BatchAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_clearing_price_root(items: &[BatchAuctionClearingPrice]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-CLEARING-PRICE",
        &items
            .iter()
            .map(BatchAuctionClearingPrice::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_bundle_leg_root(items: &[SolverBundleLeg]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-BUNDLE-LEG",
        &items
            .iter()
            .map(SolverBundleLeg::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_solver_bundle_root(items: &[SolverBundle]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-SOLVER-BUNDLE",
        &items
            .iter()
            .map(SolverBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_low_fee_rebate_root(items: &[LowFeeRebate]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-LOW-FEE-REBATE",
        &items
            .iter()
            .map(LowFeeRebate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_partial_fill_note_root(items: &[PrivatePartialFillNote]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-PARTIAL-FILL-NOTE",
        &items
            .iter()
            .map(PrivatePartialFillNote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_group_root(items: &[AtomicSettlementGroup]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-GROUP",
        &items
            .iter()
            .map(AtomicSettlementGroup::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_failed_challenge_root(items: &[FailedSettlementChallenge]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-FAILED-CHALLENGE",
        &items
            .iter()
            .map(FailedSettlementChallenge::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_slashing_evidence_root(items: &[SlashingEvidence]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-SLASHING-EVIDENCE",
        &items
            .iter()
            .map(SlashingEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_public_record_root(items: &[IntentSettlementPublicRecord]) -> String {
    merkle_root(
        "INTENT-SETTLEMENT-PUBLIC-RECORD",
        &items
            .iter()
            .map(IntentSettlementPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, field: &str) -> IntentSettlementResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} is required"));
    }
    Ok(())
}

fn ensure_positive(value: u64, field: &str) -> IntentSettlementResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, field: &str) -> IntentSettlementResult<()> {
    if value > INTENT_SETTLEMENT_MAX_BPS {
        return Err(format!("{field} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], field: &str) -> IntentSettlementResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{field} contains duplicate values"));
    }
    Ok(())
}
