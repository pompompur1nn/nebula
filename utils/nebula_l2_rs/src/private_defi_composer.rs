use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDefiComposerResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION: &str = "nebula-private-defi-composer-v1";
pub const PRIVATE_DEFI_COMPOSER_ENCRYPTION_SCHEME: &str = "ml-kem-threshold-sealed-defi-v1";
pub const PRIVATE_DEFI_COMPOSER_COMMITMENT_SCHEME: &str = "shake256-route-commitment-v1";
pub const PRIVATE_DEFI_COMPOSER_PQ_USER_AUTH_SCHEME: &str = "ml-dsa-87-user-authorization-v1";
pub const PRIVATE_DEFI_COMPOSER_PQ_OPERATOR_AUTH_SCHEME: &str =
    "ml-dsa-87-operator-authorization-v1";
pub const PRIVATE_DEFI_COMPOSER_RECEIPT_SCHEME: &str = "private-defi-settlement-receipt-v1";
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_CANCELLATION_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 720;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_SLIPPAGE_BPS: u64 = 80;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 120;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MIN_FILL_BPS: u64 = 7_500;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6_500;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_LEGS_PER_INTENT: usize = 16;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_CALLS_PER_INTENT: usize = 24;
pub const PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_SOLVERS_PER_INTENT: usize = 8;
pub const PRIVATE_DEFI_COMPOSER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_COMPOSER_MAX_INTENTS: usize = 16_384;
pub const PRIVATE_DEFI_COMPOSER_MAX_LEGS: usize = 131_072;
pub const PRIVATE_DEFI_COMPOSER_MAX_ROUTES: usize = 32_768;
pub const PRIVATE_DEFI_COMPOSER_MAX_TOKEN_COMPOSITIONS: usize = 32_768;
pub const PRIVATE_DEFI_COMPOSER_MAX_CONTRACT_CALLS: usize = 65_536;
pub const PRIVATE_DEFI_COMPOSER_MAX_BUDGETS: usize = 32_768;
pub const PRIVATE_DEFI_COMPOSER_MAX_SPONSORSHIPS: usize = 8_192;
pub const PRIVATE_DEFI_COMPOSER_MAX_MEV_COMMITMENTS: usize = 65_536;
pub const PRIVATE_DEFI_COMPOSER_MAX_AUTHORIZATIONS: usize = 65_536;
pub const PRIVATE_DEFI_COMPOSER_MAX_RECEIPTS: usize = 65_536;
pub const PRIVATE_DEFI_COMPOSER_MAX_SCORECARDS: usize = 16_384;
pub const PRIVATE_DEFI_COMPOSER_MAX_CANCELLATIONS: usize = 16_384;
pub const PRIVATE_DEFI_COMPOSER_DEVNET_HEIGHT: u64 = 288;
pub const PRIVATE_DEFI_COMPOSER_DEVNET_LOW_FEE_LANE: &str = "private-defi-composer-devnet";
pub const PRIVATE_DEFI_COMPOSER_DEVNET_FEE_ASSET_ID: &str = "usdd-devnet";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiLegKind {
    SwapExactIn,
    SwapExactOut,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingWithdraw,
    OptionMint,
    OptionExercise,
    OptionClose,
    PerpOpen,
    PerpClose,
    PerpAdjustMargin,
    PerpFunding,
    TokenTransfer,
    TokenApprove,
    TokenMint,
    TokenBurn,
    ContractCall,
    BridgeExit,
    Custom(String),
}

impl PrivateDefiLegKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::SwapExactOut => "swap_exact_out".to_string(),
            Self::LendingSupply => "lending_supply".to_string(),
            Self::LendingBorrow => "lending_borrow".to_string(),
            Self::LendingRepay => "lending_repay".to_string(),
            Self::LendingWithdraw => "lending_withdraw".to_string(),
            Self::OptionMint => "option_mint".to_string(),
            Self::OptionExercise => "option_exercise".to_string(),
            Self::OptionClose => "option_close".to_string(),
            Self::PerpOpen => "perp_open".to_string(),
            Self::PerpClose => "perp_close".to_string(),
            Self::PerpAdjustMargin => "perp_adjust_margin".to_string(),
            Self::PerpFunding => "perp_funding".to_string(),
            Self::TokenTransfer => "token_transfer".to_string(),
            Self::TokenApprove => "token_approve".to_string(),
            Self::TokenMint => "token_mint".to_string(),
            Self::TokenBurn => "token_burn".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::BridgeExit => "bridge_exit".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn route_family(&self) -> PrivateDefiRouteKind {
        match self {
            Self::SwapExactIn | Self::SwapExactOut => PrivateDefiRouteKind::PrivateSwap,
            Self::LendingSupply
            | Self::LendingBorrow
            | Self::LendingRepay
            | Self::LendingWithdraw => PrivateDefiRouteKind::PrivateLending,
            Self::OptionMint | Self::OptionExercise | Self::OptionClose => {
                PrivateDefiRouteKind::PrivateOptions
            }
            Self::PerpOpen | Self::PerpClose | Self::PerpAdjustMargin | Self::PerpFunding => {
                PrivateDefiRouteKind::PrivatePerps
            }
            Self::TokenTransfer | Self::TokenApprove | Self::TokenMint | Self::TokenBurn => {
                PrivateDefiRouteKind::TokenComposition
            }
            Self::ContractCall => PrivateDefiRouteKind::SmartContractCall,
            Self::BridgeExit => PrivateDefiRouteKind::BridgeExit,
            Self::Custom(value) => PrivateDefiRouteKind::Custom(value.clone()),
        }
    }

    pub fn requires_contract_call(&self) -> bool {
        matches!(
            self,
            Self::ContractCall
                | Self::OptionMint
                | Self::OptionExercise
                | Self::OptionClose
                | Self::PerpOpen
                | Self::PerpClose
                | Self::PerpAdjustMargin
                | Self::PerpFunding
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiRouteKind {
    PrivateSwap,
    PrivateLending,
    PrivateOptions,
    PrivatePerps,
    TokenComposition,
    SmartContractCall,
    BridgeExit,
    Composite,
    Custom(String),
}

impl PrivateDefiRouteKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::PrivateSwap => "private_swap".to_string(),
            Self::PrivateLending => "private_lending".to_string(),
            Self::PrivateOptions => "private_options".to_string(),
            Self::PrivatePerps => "private_perps".to_string(),
            Self::TokenComposition => "token_composition".to_string(),
            Self::SmartContractCall => "smart_contract_call".to_string(),
            Self::BridgeExit => "bridge_exit".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_private_market(&self) -> bool {
        matches!(
            self,
            Self::PrivateSwap | Self::PrivateLending | Self::PrivateOptions | Self::PrivatePerps
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiIntentStatus {
    Draft,
    Sealed,
    Admitted,
    Routed,
    PartiallySettled,
    Settled,
    CancelRequested,
    Cancelled,
    Expired,
    Failed,
}

impl PrivateDefiIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Routed => "routed",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::CancelRequested => "cancel_requested",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::Routed | Self::PartiallySettled
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Expired | Self::Failed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiRouteStatus {
    Proposed,
    Committed,
    Selected,
    Executing,
    Settled,
    Rejected,
    Expired,
    Cancelled,
}

impl PrivateDefiRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::Selected => "selected",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Committed | Self::Selected | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiLegStatus {
    Pending,
    Locked,
    Executed,
    Skipped,
    Reverted,
    Cancelled,
}

impl PrivateDefiLegStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Locked => "locked",
            Self::Executed => "executed",
            Self::Skipped => "skipped",
            Self::Reverted => "reverted",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetTier {
    Standard,
    High,
    Maximum,
    Emergency,
}

impl PrivacyBudgetTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::High => "high",
            Self::Maximum => "maximum",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Settled,
    Exhausted,
    Revoked,
    Expired,
}

impl LowFeeSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MevCommitmentStatus {
    Committed,
    Revealed,
    Enforced,
    Disputed,
    Slashed,
    Expired,
}

impl MevCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Enforced => "enforced",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Committed | Self::Revealed | Self::Enforced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationRole {
    User,
    Operator,
    Solver,
    Sponsor,
    ContractDelegate,
    EmergencyCouncil,
}

impl PqAuthorizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Operator => "operator",
            Self::Solver => "solver",
            Self::Sponsor => "sponsor",
            Self::ContractDelegate => "contract_delegate",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl PqAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Settled,
    Releasable,
    Disputed,
    Reverted,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Releasable => "releasable",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverScoreGrade {
    Unknown,
    Watch,
    Standard,
    Preferred,
    Quarantined,
    Slashed,
}

impl SolverScoreGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Watch => "watch",
            Self::Standard => "standard",
            Self::Preferred => "preferred",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyCancellationStatus {
    Requested,
    Authorized,
    Enqueued,
    Executed,
    Rejected,
    Expired,
}

impl EmergencyCancellationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::Enqueued => "enqueued",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Requested | Self::Authorized | Self::Enqueued)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiComposerConfig {
    pub protocol_version: String,
    pub encryption_scheme: String,
    pub commitment_scheme: String,
    pub pq_user_auth_scheme: String,
    pub pq_operator_auth_scheme: String,
    pub receipt_scheme: String,
    pub default_intent_ttl_blocks: u64,
    pub default_route_ttl_blocks: u64,
    pub default_auth_ttl_blocks: u64,
    pub default_cancellation_ttl_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub default_max_slippage_bps: u64,
    pub default_max_price_impact_bps: u64,
    pub default_min_fill_bps: u64,
    pub default_low_fee_rebate_bps: u64,
    pub max_legs_per_intent: usize,
    pub max_calls_per_intent: usize,
    pub max_solvers_per_intent: usize,
    pub default_low_fee_lane: String,
    pub default_fee_asset_id: String,
    pub emergency_council_root: String,
}

impl Default for PrivateDefiComposerConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION.to_string(),
            encryption_scheme: PRIVATE_DEFI_COMPOSER_ENCRYPTION_SCHEME.to_string(),
            commitment_scheme: PRIVATE_DEFI_COMPOSER_COMMITMENT_SCHEME.to_string(),
            pq_user_auth_scheme: PRIVATE_DEFI_COMPOSER_PQ_USER_AUTH_SCHEME.to_string(),
            pq_operator_auth_scheme: PRIVATE_DEFI_COMPOSER_PQ_OPERATOR_AUTH_SCHEME.to_string(),
            receipt_scheme: PRIVATE_DEFI_COMPOSER_RECEIPT_SCHEME.to_string(),
            default_intent_ttl_blocks: PRIVATE_DEFI_COMPOSER_DEFAULT_INTENT_TTL_BLOCKS,
            default_route_ttl_blocks: PRIVATE_DEFI_COMPOSER_DEFAULT_ROUTE_TTL_BLOCKS,
            default_auth_ttl_blocks: PRIVATE_DEFI_COMPOSER_DEFAULT_AUTH_TTL_BLOCKS,
            default_cancellation_ttl_blocks: PRIVATE_DEFI_COMPOSER_DEFAULT_CANCELLATION_TTL_BLOCKS,
            receipt_delay_blocks: PRIVATE_DEFI_COMPOSER_DEFAULT_RECEIPT_DELAY_BLOCKS,
            default_max_slippage_bps: PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_SLIPPAGE_BPS,
            default_max_price_impact_bps: PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_PRICE_IMPACT_BPS,
            default_min_fill_bps: PRIVATE_DEFI_COMPOSER_DEFAULT_MIN_FILL_BPS,
            default_low_fee_rebate_bps: PRIVATE_DEFI_COMPOSER_DEFAULT_LOW_FEE_REBATE_BPS,
            max_legs_per_intent: PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_LEGS_PER_INTENT,
            max_calls_per_intent: PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_CALLS_PER_INTENT,
            max_solvers_per_intent: PRIVATE_DEFI_COMPOSER_DEFAULT_MAX_SOLVERS_PER_INTENT,
            default_low_fee_lane: PRIVATE_DEFI_COMPOSER_DEVNET_LOW_FEE_LANE.to_string(),
            default_fee_asset_id: PRIVATE_DEFI_COMPOSER_DEVNET_FEE_ASSET_ID.to_string(),
            emergency_council_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-COMPOSER-DEVNET-EMERGENCY-COUNCIL",
                &json!({
                    "threshold": "2-of-3",
                    "members": [
                        "devnet-private-defi-council-a",
                        "devnet-private-defi-council-b",
                        "devnet-private-defi-council-c"
                    ]
                }),
            ),
        }
    }
}

impl PrivateDefiComposerConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.protocol_version, "composer protocol version")?;
        ensure_non_empty(&self.encryption_scheme, "composer encryption scheme")?;
        ensure_non_empty(&self.commitment_scheme, "composer commitment scheme")?;
        ensure_non_empty(&self.pq_user_auth_scheme, "composer pq user auth scheme")?;
        ensure_non_empty(
            &self.pq_operator_auth_scheme,
            "composer pq operator auth scheme",
        )?;
        ensure_non_empty(&self.receipt_scheme, "composer receipt scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "composer low fee lane")?;
        ensure_non_empty(&self.default_fee_asset_id, "composer fee asset id")?;
        ensure_non_empty(
            &self.emergency_council_root,
            "composer emergency council root",
        )?;
        validate_non_zero(self.default_intent_ttl_blocks, "composer intent ttl")?;
        validate_non_zero(self.default_route_ttl_blocks, "composer route ttl")?;
        validate_non_zero(self.default_auth_ttl_blocks, "composer auth ttl")?;
        validate_non_zero(
            self.default_cancellation_ttl_blocks,
            "composer cancellation ttl",
        )?;
        validate_bps("composer max slippage bps", self.default_max_slippage_bps)?;
        validate_bps(
            "composer max price impact bps",
            self.default_max_price_impact_bps,
        )?;
        validate_bps("composer min fill bps", self.default_min_fill_bps)?;
        validate_bps(
            "composer low fee rebate bps",
            self.default_low_fee_rebate_bps,
        )?;
        validate_non_zero_usize(self.max_legs_per_intent, "composer max legs per intent")?;
        validate_non_zero_usize(self.max_calls_per_intent, "composer max calls per intent")?;
        validate_non_zero_usize(
            self.max_solvers_per_intent,
            "composer max solvers per intent",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_composer_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": self.commitment_scheme,
            "pq_user_auth_scheme": self.pq_user_auth_scheme,
            "pq_operator_auth_scheme": self.pq_operator_auth_scheme,
            "receipt_scheme": self.receipt_scheme,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_route_ttl_blocks": self.default_route_ttl_blocks,
            "default_auth_ttl_blocks": self.default_auth_ttl_blocks,
            "default_cancellation_ttl_blocks": self.default_cancellation_ttl_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "default_max_slippage_bps": self.default_max_slippage_bps,
            "default_max_price_impact_bps": self.default_max_price_impact_bps,
            "default_min_fill_bps": self.default_min_fill_bps,
            "default_low_fee_rebate_bps": self.default_low_fee_rebate_bps,
            "max_legs_per_intent": self.max_legs_per_intent,
            "max_calls_per_intent": self.max_calls_per_intent,
            "max_solvers_per_intent": self.max_solvers_per_intent,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_fee_asset_id": self.default_fee_asset_id,
            "emergency_council_root": self.emergency_council_root,
        })
    }

    pub fn config_root(&self) -> String {
        private_defi_composer_payload_root("PRIVATE-DEFI-COMPOSER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDefiPayload {
    pub payload_root: String,
    pub ciphertext_root: String,
    pub aad_root: String,
    pub key_epoch_id: String,
    pub recipient_commitment_root: String,
    pub payload_size_bytes: u64,
    pub encryption_scheme: String,
}

impl EncryptedDefiPayload {
    pub fn new(
        payload: &Value,
        aad: &Value,
        key_epoch_id: impl Into<String>,
        recipient_commitments: &[String],
        payload_size_bytes: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let key_epoch_id = key_epoch_id.into();
        ensure_non_empty(&key_epoch_id, "encrypted payload key epoch id")?;
        validate_non_zero(payload_size_bytes, "encrypted payload size")?;
        let recipient_records = recipient_commitments
            .iter()
            .map(|recipient| json!({ "recipient_commitment": recipient }))
            .collect::<Vec<_>>();
        Ok(Self {
            payload_root: private_defi_composer_payload_root("PRIVATE-DEFI-PAYLOAD", payload),
            ciphertext_root: private_defi_composer_payload_root("PRIVATE-DEFI-CIPHERTEXT", payload),
            aad_root: private_defi_composer_payload_root("PRIVATE-DEFI-AAD", aad),
            key_epoch_id,
            recipient_commitment_root: merkle_root(
                "PRIVATE-DEFI-RECIPIENT-COMMITMENTS",
                &recipient_records,
            ),
            payload_size_bytes,
            encryption_scheme: PRIVATE_DEFI_COMPOSER_ENCRYPTION_SCHEME.to_string(),
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.payload_root, "encrypted payload root")?;
        ensure_non_empty(&self.ciphertext_root, "encrypted ciphertext root")?;
        ensure_non_empty(&self.aad_root, "encrypted aad root")?;
        ensure_non_empty(&self.key_epoch_id, "encrypted key epoch id")?;
        ensure_non_empty(
            &self.recipient_commitment_root,
            "encrypted recipient commitment root",
        )?;
        validate_non_zero(self.payload_size_bytes, "encrypted payload size")?;
        ensure_non_empty(&self.encryption_scheme, "encrypted scheme")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_defi_payload",
            "chain_id": CHAIN_ID,
            "payload_root": self.payload_root,
            "ciphertext_root": self.ciphertext_root,
            "aad_root": self.aad_root,
            "key_epoch_id": self.key_epoch_id,
            "recipient_commitment_root": self.recipient_commitment_root,
            "payload_size_bytes": self.payload_size_bytes,
            "encryption_scheme": self.encryption_scheme,
        })
    }

    pub fn payload_commitment(&self) -> String {
        private_defi_composer_payload_root(
            "PRIVATE-DEFI-ENCRYPTED-PAYLOAD-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub route_kind: PrivateDefiRouteKind,
    pub max_slippage_bps: u64,
    pub max_price_impact_bps: u64,
    pub min_fill_bps: u64,
    pub max_solver_disclosure_bps: u64,
    pub anonymity_set_min: u64,
    pub timing_noise_blocks: u64,
    pub route_reveal_delay_blocks: u64,
    pub secret_share_budget_units: u64,
    pub privacy_tier: PrivacyBudgetTier,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateDefiBudget {
    pub fn new(
        owner_commitment: impl Into<String>,
        route_kind: PrivateDefiRouteKind,
        max_slippage_bps: u64,
        max_price_impact_bps: u64,
        min_fill_bps: u64,
        anonymity_set_min: u64,
        timing_noise_blocks: u64,
        route_reveal_delay_blocks: u64,
        privacy_tier: PrivacyBudgetTier,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let owner_commitment = owner_commitment.into();
        ensure_non_empty(&owner_commitment, "budget owner commitment")?;
        validate_bps("budget max slippage bps", max_slippage_bps)?;
        validate_bps("budget max price impact bps", max_price_impact_bps)?;
        validate_bps("budget min fill bps", min_fill_bps)?;
        validate_height_window(created_at_height, expires_at_height, "budget")?;
        let budget_id = private_defi_budget_id(
            &owner_commitment,
            &route_kind,
            created_at_height,
            expires_at_height,
            nonce,
        );
        let max_solver_disclosure_bps = match privacy_tier {
            PrivacyBudgetTier::Standard => 2_500,
            PrivacyBudgetTier::High => 1_000,
            PrivacyBudgetTier::Maximum => 250,
            PrivacyBudgetTier::Emergency => 10_000,
        };
        let secret_share_budget_units = anonymity_set_min
            .saturating_mul(1_000)
            .saturating_add(timing_noise_blocks.saturating_mul(100))
            .saturating_add(route_reveal_delay_blocks.saturating_mul(50));
        Ok(Self {
            budget_id,
            owner_commitment,
            route_kind,
            max_slippage_bps,
            max_price_impact_bps,
            min_fill_bps,
            max_solver_disclosure_bps,
            anonymity_set_min,
            timing_noise_blocks,
            route_reveal_delay_blocks,
            secret_share_budget_units,
            privacy_tier,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.created_at_height <= height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.budget_id, "budget id")?;
        ensure_non_empty(&self.owner_commitment, "budget owner commitment")?;
        validate_bps("budget max slippage bps", self.max_slippage_bps)?;
        validate_bps("budget max price impact bps", self.max_price_impact_bps)?;
        validate_bps("budget min fill bps", self.min_fill_bps)?;
        validate_bps(
            "budget max solver disclosure bps",
            self.max_solver_disclosure_bps,
        )?;
        validate_height_window(self.created_at_height, self.expires_at_height, "budget")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_budget",
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "route_kind": self.route_kind.as_str(),
            "max_slippage_bps": self.max_slippage_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "min_fill_bps": self.min_fill_bps,
            "max_solver_disclosure_bps": self.max_solver_disclosure_bps,
            "anonymity_set_min": self.anonymity_set_min,
            "timing_noise_blocks": self.timing_noise_blocks,
            "route_reveal_delay_blocks": self.route_reveal_delay_blocks,
            "secret_share_budget_units": self.secret_share_budget_units,
            "privacy_tier": self.privacy_tier.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn budget_root(&self) -> String {
        private_defi_composer_payload_root("PRIVATE-DEFI-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiContractCall {
    pub call_id: String,
    pub intent_id: String,
    pub contract_commitment: String,
    pub entrypoint_selector: String,
    pub calldata_root: String,
    pub return_data_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub token_delta_root: String,
    pub capability_root: String,
    pub max_gas_units: u64,
    pub value_commitment: String,
    pub allow_reentrancy: bool,
    pub created_at_height: u64,
}

impl PrivateDefiContractCall {
    pub fn new(
        intent_id: impl Into<String>,
        contract_commitment: impl Into<String>,
        entrypoint_selector: impl Into<String>,
        calldata: &Value,
        expected_return: &Value,
        access_sets: &Value,
        token_delta: &Value,
        capability: &Value,
        max_gas_units: u64,
        value_commitment: impl Into<String>,
        allow_reentrancy: bool,
        created_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let contract_commitment = contract_commitment.into();
        let entrypoint_selector = entrypoint_selector.into();
        let value_commitment = value_commitment.into();
        ensure_non_empty(&intent_id, "contract call intent id")?;
        ensure_non_empty(&contract_commitment, "contract call contract commitment")?;
        ensure_non_empty(&entrypoint_selector, "contract call entrypoint selector")?;
        ensure_non_empty(&value_commitment, "contract call value commitment")?;
        validate_non_zero(max_gas_units, "contract call max gas units")?;
        let calldata_root = private_defi_composer_payload_root("PRIVATE-DEFI-CALLDATA", calldata);
        let call_id = private_defi_contract_call_id(
            &intent_id,
            &contract_commitment,
            &entrypoint_selector,
            &calldata_root,
            nonce,
        );
        Ok(Self {
            call_id,
            intent_id,
            contract_commitment,
            entrypoint_selector,
            calldata_root,
            return_data_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-RETURN-DATA",
                expected_return,
            ),
            read_set_root: private_defi_composer_payload_root("PRIVATE-DEFI-READ-SET", access_sets),
            write_set_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-WRITE-SET",
                access_sets,
            ),
            token_delta_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-TOKEN-DELTA",
                token_delta,
            ),
            capability_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-CALL-CAPABILITY",
                capability,
            ),
            max_gas_units,
            value_commitment,
            allow_reentrancy,
            created_at_height,
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.call_id, "contract call id")?;
        ensure_non_empty(&self.intent_id, "contract call intent id")?;
        ensure_non_empty(
            &self.contract_commitment,
            "contract call contract commitment",
        )?;
        ensure_non_empty(
            &self.entrypoint_selector,
            "contract call entrypoint selector",
        )?;
        ensure_non_empty(&self.calldata_root, "contract call calldata root")?;
        ensure_non_empty(&self.return_data_root, "contract call return data root")?;
        ensure_non_empty(&self.read_set_root, "contract call read set root")?;
        ensure_non_empty(&self.write_set_root, "contract call write set root")?;
        ensure_non_empty(&self.token_delta_root, "contract call token delta root")?;
        ensure_non_empty(&self.capability_root, "contract call capability root")?;
        ensure_non_empty(&self.value_commitment, "contract call value commitment")?;
        validate_non_zero(self.max_gas_units, "contract call max gas units")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_contract_call",
            "chain_id": CHAIN_ID,
            "call_id": self.call_id,
            "intent_id": self.intent_id,
            "contract_commitment": self.contract_commitment,
            "entrypoint_selector": self.entrypoint_selector,
            "calldata_root": self.calldata_root,
            "return_data_root": self.return_data_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "token_delta_root": self.token_delta_root,
            "capability_root": self.capability_root,
            "max_gas_units": self.max_gas_units,
            "value_commitment": self.value_commitment,
            "allow_reentrancy": self.allow_reentrancy,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiTokenComposition {
    pub composition_id: String,
    pub intent_id: String,
    pub asset_in_root: String,
    pub asset_out_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub token_call_root: String,
    pub conservation_proof_root: String,
    pub supply_delta_commitment: String,
    pub created_at_height: u64,
}

impl PrivateDefiTokenComposition {
    pub fn new(
        intent_id: impl Into<String>,
        assets_in: &[String],
        assets_out: &[String],
        input_notes: &[String],
        output_notes: &[String],
        token_calls: &[Value],
        conservation_proof: &Value,
        supply_delta_commitment: impl Into<String>,
        created_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let supply_delta_commitment = supply_delta_commitment.into();
        ensure_non_empty(&intent_id, "token composition intent id")?;
        ensure_non_empty(&supply_delta_commitment, "token composition supply delta")?;
        validate_non_empty_slice(assets_in, "token composition input assets")?;
        validate_non_empty_slice(assets_out, "token composition output assets")?;
        validate_non_empty_slice(input_notes, "token composition input notes")?;
        validate_non_empty_slice(output_notes, "token composition output notes")?;
        let asset_in_root = string_merkle_root("PRIVATE-DEFI-TOKEN-ASSET-IN", assets_in);
        let asset_out_root = string_merkle_root("PRIVATE-DEFI-TOKEN-ASSET-OUT", assets_out);
        let input_note_root = string_merkle_root("PRIVATE-DEFI-TOKEN-INPUT-NOTES", input_notes);
        let output_note_root = string_merkle_root("PRIVATE-DEFI-TOKEN-OUTPUT-NOTES", output_notes);
        let token_call_root = merkle_root("PRIVATE-DEFI-TOKEN-CALLS", token_calls);
        let conservation_proof_root = private_defi_composer_payload_root(
            "PRIVATE-DEFI-CONSERVATION-PROOF",
            conservation_proof,
        );
        let composition_id = private_defi_token_composition_id(
            &intent_id,
            &asset_in_root,
            &asset_out_root,
            &conservation_proof_root,
            nonce,
        );
        Ok(Self {
            composition_id,
            intent_id,
            asset_in_root,
            asset_out_root,
            input_note_root,
            output_note_root,
            token_call_root,
            conservation_proof_root,
            supply_delta_commitment,
            created_at_height,
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.composition_id, "token composition id")?;
        ensure_non_empty(&self.intent_id, "token composition intent id")?;
        ensure_non_empty(&self.asset_in_root, "token composition asset in root")?;
        ensure_non_empty(&self.asset_out_root, "token composition asset out root")?;
        ensure_non_empty(&self.input_note_root, "token composition input note root")?;
        ensure_non_empty(&self.output_note_root, "token composition output note root")?;
        ensure_non_empty(&self.token_call_root, "token composition token call root")?;
        ensure_non_empty(
            &self.conservation_proof_root,
            "token composition conservation proof root",
        )?;
        ensure_non_empty(
            &self.supply_delta_commitment,
            "token composition supply delta commitment",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_token_composition",
            "chain_id": CHAIN_ID,
            "composition_id": self.composition_id,
            "intent_id": self.intent_id,
            "asset_in_root": self.asset_in_root,
            "asset_out_root": self.asset_out_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "token_call_root": self.token_call_root,
            "conservation_proof_root": self.conservation_proof_root,
            "supply_delta_commitment": self.supply_delta_commitment,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiRouteLeg {
    pub leg_id: String,
    pub intent_id: String,
    pub sequence: u64,
    pub leg_kind: PrivateDefiLegKind,
    pub route_kind: PrivateDefiRouteKind,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub venue_commitment: String,
    pub market_commitment: String,
    pub budget_id: String,
    pub contract_call_id: Option<String>,
    pub token_composition_id: Option<String>,
    pub dependency_leg_ids: Vec<String>,
    pub route_hint_root: String,
    pub leg_proof_root: String,
    pub status: PrivateDefiLegStatus,
}

impl PrivateDefiRouteLeg {
    pub fn new(
        intent_id: impl Into<String>,
        sequence: u64,
        leg_kind: PrivateDefiLegKind,
        input_asset_id: impl Into<String>,
        output_asset_id: impl Into<String>,
        input_commitment: impl Into<String>,
        output_commitment: impl Into<String>,
        venue_commitment: impl Into<String>,
        market_commitment: impl Into<String>,
        budget_id: impl Into<String>,
        contract_call_id: Option<String>,
        token_composition_id: Option<String>,
        dependency_leg_ids: Vec<String>,
        route_hint: &Value,
        leg_proof: &Value,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let input_asset_id = input_asset_id.into();
        let output_asset_id = output_asset_id.into();
        let input_commitment = input_commitment.into();
        let output_commitment = output_commitment.into();
        let venue_commitment = venue_commitment.into();
        let market_commitment = market_commitment.into();
        let budget_id = budget_id.into();
        ensure_non_empty(&intent_id, "route leg intent id")?;
        ensure_non_empty(&input_asset_id, "route leg input asset")?;
        ensure_non_empty(&output_asset_id, "route leg output asset")?;
        ensure_non_empty(&input_commitment, "route leg input commitment")?;
        ensure_non_empty(&output_commitment, "route leg output commitment")?;
        ensure_non_empty(&venue_commitment, "route leg venue commitment")?;
        ensure_non_empty(&market_commitment, "route leg market commitment")?;
        ensure_non_empty(&budget_id, "route leg budget id")?;
        let route_kind = leg_kind.route_family();
        let route_hint_root =
            private_defi_composer_payload_root("PRIVATE-DEFI-ROUTE-HINT", route_hint);
        let leg_id = private_defi_leg_id(&intent_id, sequence, &leg_kind, &route_hint_root, nonce);
        Ok(Self {
            leg_id,
            intent_id,
            sequence,
            leg_kind,
            route_kind,
            input_asset_id,
            output_asset_id,
            input_commitment,
            output_commitment,
            venue_commitment,
            market_commitment,
            budget_id,
            contract_call_id,
            token_composition_id,
            dependency_leg_ids,
            route_hint_root,
            leg_proof_root: private_defi_composer_payload_root("PRIVATE-DEFI-LEG-PROOF", leg_proof),
            status: PrivateDefiLegStatus::Pending,
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.leg_id, "route leg id")?;
        ensure_non_empty(&self.intent_id, "route leg intent id")?;
        ensure_non_empty(&self.input_asset_id, "route leg input asset")?;
        ensure_non_empty(&self.output_asset_id, "route leg output asset")?;
        ensure_non_empty(&self.input_commitment, "route leg input commitment")?;
        ensure_non_empty(&self.output_commitment, "route leg output commitment")?;
        ensure_non_empty(&self.venue_commitment, "route leg venue commitment")?;
        ensure_non_empty(&self.market_commitment, "route leg market commitment")?;
        ensure_non_empty(&self.budget_id, "route leg budget id")?;
        ensure_non_empty(&self.route_hint_root, "route leg hint root")?;
        ensure_non_empty(&self.leg_proof_root, "route leg proof root")?;
        validate_unique_strings(&self.dependency_leg_ids, "route leg dependency ids")?;
        if self.leg_kind.requires_contract_call() && self.contract_call_id.is_none() {
            return Err("route leg requires a contract call id".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_route_leg",
            "chain_id": CHAIN_ID,
            "leg_id": self.leg_id,
            "intent_id": self.intent_id,
            "sequence": self.sequence,
            "leg_kind": self.leg_kind.as_str(),
            "route_kind": self.route_kind.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "venue_commitment": self.venue_commitment,
            "market_commitment": self.market_commitment,
            "budget_id": self.budget_id,
            "contract_call_id": self.contract_call_id,
            "token_composition_id": self.token_composition_id,
            "dependency_leg_ids": self.dependency_leg_ids,
            "route_hint_root": self.route_hint_root,
            "leg_proof_root": self.leg_proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn leg_root(&self) -> String {
        private_defi_composer_payload_root("PRIVATE-DEFI-ROUTE-LEG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiRoute {
    pub route_id: String,
    pub intent_id: String,
    pub solver_commitment: String,
    pub route_kind: PrivateDefiRouteKind,
    pub leg_ids: Vec<String>,
    pub leg_root: String,
    pub route_commitment_root: String,
    pub price_commitment_root: String,
    pub expected_output_root: String,
    pub fee_commitment_root: String,
    pub mev_commitment_id: Option<String>,
    pub authorization_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateDefiRouteStatus,
}

impl PrivateDefiRoute {
    pub fn new(
        intent_id: impl Into<String>,
        solver_commitment: impl Into<String>,
        route_kind: PrivateDefiRouteKind,
        leg_ids: Vec<String>,
        route_commitment: &Value,
        price_commitment: &Value,
        expected_output: &Value,
        fee_commitment: &Value,
        mev_commitment_id: Option<String>,
        authorization_id: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let solver_commitment = solver_commitment.into();
        let authorization_id = authorization_id.into();
        ensure_non_empty(&intent_id, "route intent id")?;
        ensure_non_empty(&solver_commitment, "route solver commitment")?;
        ensure_non_empty(&authorization_id, "route authorization id")?;
        validate_non_empty_slice(&leg_ids, "route leg ids")?;
        validate_unique_strings(&leg_ids, "route leg ids")?;
        validate_height_window(created_at_height, expires_at_height, "route")?;
        let leg_root = string_merkle_root("PRIVATE-DEFI-ROUTE-LEG-IDS", &leg_ids);
        let route_commitment_root =
            private_defi_composer_payload_root("PRIVATE-DEFI-ROUTE-COMMITMENT", route_commitment);
        let route_id = private_defi_route_id(
            &intent_id,
            &solver_commitment,
            &leg_root,
            &route_commitment_root,
            nonce,
        );
        Ok(Self {
            route_id,
            intent_id,
            solver_commitment,
            route_kind,
            leg_ids,
            leg_root,
            route_commitment_root,
            price_commitment_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-PRICE-COMMITMENT",
                price_commitment,
            ),
            expected_output_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-EXPECTED-OUTPUT",
                expected_output,
            ),
            fee_commitment_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-FEE-COMMITMENT",
                fee_commitment,
            ),
            mev_commitment_id,
            authorization_id,
            created_at_height,
            expires_at_height,
            status: PrivateDefiRouteStatus::Proposed,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.active() && self.created_at_height <= height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.intent_id, "route intent id")?;
        ensure_non_empty(&self.solver_commitment, "route solver commitment")?;
        validate_non_empty_slice(&self.leg_ids, "route leg ids")?;
        validate_unique_strings(&self.leg_ids, "route leg ids")?;
        ensure_non_empty(&self.leg_root, "route leg root")?;
        ensure_non_empty(&self.route_commitment_root, "route commitment root")?;
        ensure_non_empty(&self.price_commitment_root, "route price commitment root")?;
        ensure_non_empty(&self.expected_output_root, "route expected output root")?;
        ensure_non_empty(&self.fee_commitment_root, "route fee commitment root")?;
        ensure_non_empty(&self.authorization_id, "route authorization id")?;
        validate_height_window(self.created_at_height, self.expires_at_height, "route")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_route",
            "chain_id": CHAIN_ID,
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "solver_commitment": self.solver_commitment,
            "route_kind": self.route_kind.as_str(),
            "leg_ids": self.leg_ids,
            "leg_root": self.leg_root,
            "route_commitment_root": self.route_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "expected_output_root": self.expected_output_root,
            "fee_commitment_root": self.fee_commitment_root,
            "mev_commitment_id": self.mev_commitment_id,
            "authorization_id": self.authorization_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub applied_rebate_units: u64,
    pub rebate_bps: u64,
    pub max_priority_fee_micro_units: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeSponsorshipStatus,
}

impl LowFeeSponsorship {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        lane_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        rebate_bps: u64,
        max_priority_fee_micro_units: u64,
        valid_from_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let lane_id = lane_id.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sponsor_commitment, "sponsorship sponsor commitment")?;
        ensure_non_empty(
            &beneficiary_commitment,
            "sponsorship beneficiary commitment",
        )?;
        ensure_non_empty(&lane_id, "sponsorship lane id")?;
        ensure_non_empty(&fee_asset_id, "sponsorship fee asset id")?;
        validate_non_zero(max_fee_units, "sponsorship max fee units")?;
        validate_bps("sponsorship rebate bps", rebate_bps)?;
        validate_height_window(valid_from_height, expires_at_height, "sponsorship")?;
        Ok(Self {
            sponsorship_id: private_defi_sponsorship_id(
                &sponsor_commitment,
                &beneficiary_commitment,
                &lane_id,
                &fee_asset_id,
                nonce,
            ),
            sponsor_commitment,
            beneficiary_commitment,
            lane_id,
            fee_asset_id,
            max_fee_units,
            reserved_fee_units: 0,
            applied_rebate_units: 0,
            rebate_bps,
            max_priority_fee_micro_units,
            valid_from_height,
            expires_at_height,
            status: LowFeeSponsorshipStatus::Offered,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.live() && self.valid_from_height <= height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary commitment",
        )?;
        ensure_non_empty(&self.lane_id, "sponsorship lane id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset id")?;
        validate_non_zero(self.max_fee_units, "sponsorship max fee units")?;
        validate_bps("sponsorship rebate bps", self.rebate_bps)?;
        validate_height_window(
            self.valid_from_height,
            self.expires_at_height,
            "sponsorship",
        )?;
        if self.reserved_fee_units > self.max_fee_units {
            return Err("sponsorship reserved fee exceeds max fee".to_string());
        }
        if self.applied_rebate_units > self.max_fee_units {
            return Err("sponsorship applied rebate exceeds max fee".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_rebate_units": self.applied_rebate_units,
            "rebate_bps": self.rebate_bps,
            "max_priority_fee_micro_units": self.max_priority_fee_micro_units,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevSafeRouteCommitment {
    pub commitment_id: String,
    pub intent_id: String,
    pub route_id: Option<String>,
    pub route_commitment_root: String,
    pub sealed_order_root: String,
    pub solver_set_root: String,
    pub no_sandwich_proof_root: String,
    pub batch_binding_root: String,
    pub salt_commitment: String,
    pub reveal_after_height: u64,
    pub expires_at_height: u64,
    pub status: MevCommitmentStatus,
}

impl MevSafeRouteCommitment {
    pub fn new(
        intent_id: impl Into<String>,
        route_id: Option<String>,
        route_commitment: &Value,
        sealed_order: &Value,
        allowed_solvers: &[String],
        no_sandwich_proof: &Value,
        batch_binding: &Value,
        salt_commitment: impl Into<String>,
        reveal_after_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let salt_commitment = salt_commitment.into();
        ensure_non_empty(&intent_id, "mev commitment intent id")?;
        ensure_non_empty(&salt_commitment, "mev commitment salt")?;
        validate_non_empty_slice(allowed_solvers, "mev commitment allowed solvers")?;
        validate_height_window(reveal_after_height, expires_at_height, "mev commitment")?;
        let route_commitment_root = private_defi_composer_payload_root(
            "PRIVATE-DEFI-MEV-ROUTE-COMMITMENT",
            route_commitment,
        );
        Ok(Self {
            commitment_id: private_defi_mev_commitment_id(
                &intent_id,
                &route_commitment_root,
                &salt_commitment,
                reveal_after_height,
                nonce,
            ),
            intent_id,
            route_id,
            route_commitment_root,
            sealed_order_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-MEV-SEALED-ORDER",
                sealed_order,
            ),
            solver_set_root: string_merkle_root("PRIVATE-DEFI-MEV-SOLVER-SET", allowed_solvers),
            no_sandwich_proof_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-NO-SANDWICH-PROOF",
                no_sandwich_proof,
            ),
            batch_binding_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-BATCH-BINDING",
                batch_binding,
            ),
            salt_commitment,
            reveal_after_height,
            expires_at_height,
            status: MevCommitmentStatus::Committed,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.active() && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.commitment_id, "mev commitment id")?;
        ensure_non_empty(&self.intent_id, "mev commitment intent id")?;
        ensure_non_empty(&self.route_commitment_root, "mev route commitment root")?;
        ensure_non_empty(&self.sealed_order_root, "mev sealed order root")?;
        ensure_non_empty(&self.solver_set_root, "mev solver set root")?;
        ensure_non_empty(&self.no_sandwich_proof_root, "mev no sandwich proof root")?;
        ensure_non_empty(&self.batch_binding_root, "mev batch binding root")?;
        ensure_non_empty(&self.salt_commitment, "mev salt commitment")?;
        validate_height_window(
            self.reveal_after_height,
            self.expires_at_height,
            "mev commitment",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mev_safe_route_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "intent_id": self.intent_id,
            "route_id": self.route_id,
            "route_commitment_root": self.route_commitment_root,
            "sealed_order_root": self.sealed_order_root,
            "solver_set_root": self.solver_set_root,
            "no_sandwich_proof_root": self.no_sandwich_proof_root,
            "batch_binding_root": self.batch_binding_root,
            "salt_commitment": self.salt_commitment,
            "reveal_after_height": self.reveal_after_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorization {
    pub authorization_id: String,
    pub subject_commitment: String,
    pub role: PqAuthorizationRole,
    pub pq_key_root: String,
    pub capability_root: String,
    pub signature_root: String,
    pub delegation_root: String,
    pub nonce_commitment: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: PqAuthorizationStatus,
}

impl PqAuthorization {
    pub fn new(
        subject_commitment: impl Into<String>,
        role: PqAuthorizationRole,
        pq_keys: &[String],
        capabilities: &[String],
        signature: &Value,
        delegation: &Value,
        nonce_commitment: impl Into<String>,
        valid_from_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let subject_commitment = subject_commitment.into();
        let nonce_commitment = nonce_commitment.into();
        ensure_non_empty(&subject_commitment, "pq authorization subject commitment")?;
        ensure_non_empty(&nonce_commitment, "pq authorization nonce commitment")?;
        validate_non_empty_slice(pq_keys, "pq authorization keys")?;
        validate_non_empty_slice(capabilities, "pq authorization capabilities")?;
        validate_height_window(valid_from_height, expires_at_height, "pq authorization")?;
        let pq_key_root = string_merkle_root("PRIVATE-DEFI-PQ-AUTH-KEYS", pq_keys);
        let capability_root = string_merkle_root("PRIVATE-DEFI-PQ-AUTH-CAPABILITIES", capabilities);
        Ok(Self {
            authorization_id: private_defi_pq_authorization_id(
                &subject_commitment,
                role,
                &pq_key_root,
                &capability_root,
                valid_from_height,
                nonce,
            ),
            subject_commitment,
            role,
            pq_key_root,
            capability_root,
            signature_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-PQ-AUTH-SIGNATURE",
                signature,
            ),
            delegation_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-PQ-AUTH-DELEGATION",
                delegation,
            ),
            nonce_commitment,
            valid_from_height,
            expires_at_height,
            status: PqAuthorizationStatus::Active,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.active() && self.valid_from_height <= height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.authorization_id, "pq authorization id")?;
        ensure_non_empty(
            &self.subject_commitment,
            "pq authorization subject commitment",
        )?;
        ensure_non_empty(&self.pq_key_root, "pq authorization key root")?;
        ensure_non_empty(&self.capability_root, "pq authorization capability root")?;
        ensure_non_empty(&self.signature_root, "pq authorization signature root")?;
        ensure_non_empty(&self.delegation_root, "pq authorization delegation root")?;
        ensure_non_empty(&self.nonce_commitment, "pq authorization nonce commitment")?;
        validate_height_window(
            self.valid_from_height,
            self.expires_at_height,
            "pq authorization",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authorization",
            "chain_id": CHAIN_ID,
            "authorization_id": self.authorization_id,
            "subject_commitment": self.subject_commitment,
            "role": self.role.as_str(),
            "pq_key_root": self.pq_key_root,
            "capability_root": self.capability_root,
            "signature_root": self.signature_root,
            "delegation_root": self.delegation_root,
            "nonce_commitment": self.nonce_commitment,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMultiLegDefiIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub account_nullifier: String,
    pub encrypted_payload: EncryptedDefiPayload,
    pub leg_ids: Vec<String>,
    pub route_kind: PrivateDefiRouteKind,
    pub budget_id: String,
    pub user_authorization_id: String,
    pub sponsorship_id: Option<String>,
    pub mev_commitment_id: Option<String>,
    pub preferred_solver_root: String,
    pub token_composition_root: String,
    pub contract_call_root: String,
    pub cancel_authority_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateDefiIntentStatus,
}

impl EncryptedMultiLegDefiIntent {
    pub fn new(
        owner_commitment: impl Into<String>,
        account_nullifier: impl Into<String>,
        encrypted_payload: EncryptedDefiPayload,
        leg_ids: Vec<String>,
        route_kind: PrivateDefiRouteKind,
        budget_id: impl Into<String>,
        user_authorization_id: impl Into<String>,
        sponsorship_id: Option<String>,
        mev_commitment_id: Option<String>,
        preferred_solvers: &[String],
        token_compositions: &[String],
        contract_calls: &[String],
        cancel_authorities: &[String],
        metadata: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let owner_commitment = owner_commitment.into();
        let account_nullifier = account_nullifier.into();
        let budget_id = budget_id.into();
        let user_authorization_id = user_authorization_id.into();
        ensure_non_empty(&owner_commitment, "intent owner commitment")?;
        ensure_non_empty(&account_nullifier, "intent account nullifier")?;
        ensure_non_empty(&budget_id, "intent budget id")?;
        ensure_non_empty(&user_authorization_id, "intent user authorization id")?;
        encrypted_payload.validate()?;
        validate_non_empty_slice(&leg_ids, "intent leg ids")?;
        validate_unique_strings(&leg_ids, "intent leg ids")?;
        validate_non_empty_slice(preferred_solvers, "intent preferred solvers")?;
        validate_non_empty_slice(cancel_authorities, "intent cancel authorities")?;
        validate_height_window(created_at_height, expires_at_height, "intent")?;
        let metadata_root =
            private_defi_composer_payload_root("PRIVATE-DEFI-INTENT-METADATA", metadata);
        let intent_id = private_defi_intent_id(
            &owner_commitment,
            &account_nullifier,
            &encrypted_payload.payload_commitment(),
            &metadata_root,
            created_at_height,
            nonce,
        );
        Ok(Self {
            intent_id,
            owner_commitment,
            account_nullifier,
            encrypted_payload,
            leg_ids,
            route_kind,
            budget_id,
            user_authorization_id,
            sponsorship_id,
            mev_commitment_id,
            preferred_solver_root: string_merkle_root(
                "PRIVATE-DEFI-INTENT-PREFERRED-SOLVERS",
                preferred_solvers,
            ),
            token_composition_root: string_merkle_root(
                "PRIVATE-DEFI-INTENT-TOKEN-COMPOSITIONS",
                token_compositions,
            ),
            contract_call_root: string_merkle_root(
                "PRIVATE-DEFI-INTENT-CONTRACT-CALLS",
                contract_calls,
            ),
            cancel_authority_root: string_merkle_root(
                "PRIVATE-DEFI-INTENT-CANCEL-AUTHORITIES",
                cancel_authorities,
            ),
            metadata_root,
            created_at_height,
            expires_at_height,
            status: PrivateDefiIntentStatus::Sealed,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.active() && self.created_at_height <= height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.intent_id, "intent id")?;
        ensure_non_empty(&self.owner_commitment, "intent owner commitment")?;
        ensure_non_empty(&self.account_nullifier, "intent account nullifier")?;
        self.encrypted_payload.validate()?;
        validate_non_empty_slice(&self.leg_ids, "intent leg ids")?;
        validate_unique_strings(&self.leg_ids, "intent leg ids")?;
        ensure_non_empty(&self.budget_id, "intent budget id")?;
        ensure_non_empty(&self.user_authorization_id, "intent user authorization id")?;
        ensure_non_empty(&self.preferred_solver_root, "intent preferred solver root")?;
        ensure_non_empty(
            &self.token_composition_root,
            "intent token composition root",
        )?;
        ensure_non_empty(&self.contract_call_root, "intent contract call root")?;
        ensure_non_empty(&self.cancel_authority_root, "intent cancel authority root")?;
        ensure_non_empty(&self.metadata_root, "intent metadata root")?;
        validate_height_window(self.created_at_height, self.expires_at_height, "intent")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_multi_leg_defi_intent",
            "chain_id": CHAIN_ID,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "account_nullifier": self.account_nullifier,
            "encrypted_payload": self.encrypted_payload.public_record(),
            "leg_ids": self.leg_ids,
            "route_kind": self.route_kind.as_str(),
            "budget_id": self.budget_id,
            "user_authorization_id": self.user_authorization_id,
            "sponsorship_id": self.sponsorship_id,
            "mev_commitment_id": self.mev_commitment_id,
            "preferred_solver_root": self.preferred_solver_root,
            "token_composition_root": self.token_composition_root,
            "contract_call_root": self.contract_call_root,
            "cancel_authority_root": self.cancel_authority_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub route_id: String,
    pub solver_commitment: String,
    pub settlement_root: String,
    pub consumed_nullifier_root: String,
    pub output_note_root: String,
    pub contract_effect_root: String,
    pub fee_asset_id: String,
    pub fee_paid_units: u64,
    pub rebate_units: u64,
    pub surplus_returned_units: u64,
    pub settled_at_height: u64,
    pub public_release_height: u64,
    pub status: SettlementReceiptStatus,
}

impl SettlementReceipt {
    pub fn new(
        intent_id: impl Into<String>,
        route_id: impl Into<String>,
        solver_commitment: impl Into<String>,
        settlement: &Value,
        consumed_nullifiers: &[String],
        output_notes: &[String],
        contract_effects: &Value,
        fee_asset_id: impl Into<String>,
        fee_paid_units: u64,
        rebate_units: u64,
        surplus_returned_units: u64,
        settled_at_height: u64,
        public_release_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let route_id = route_id.into();
        let solver_commitment = solver_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&intent_id, "settlement receipt intent id")?;
        ensure_non_empty(&route_id, "settlement receipt route id")?;
        ensure_non_empty(&solver_commitment, "settlement receipt solver commitment")?;
        ensure_non_empty(&fee_asset_id, "settlement receipt fee asset id")?;
        validate_non_empty_slice(consumed_nullifiers, "settlement consumed nullifiers")?;
        validate_non_empty_slice(output_notes, "settlement output notes")?;
        if public_release_height < settled_at_height {
            return Err("settlement receipt release height is before settlement".to_string());
        }
        let settlement_root =
            private_defi_composer_payload_root("PRIVATE-DEFI-SETTLEMENT", settlement);
        Ok(Self {
            receipt_id: private_defi_settlement_receipt_id(
                &intent_id,
                &route_id,
                &solver_commitment,
                &settlement_root,
                nonce,
            ),
            intent_id,
            route_id,
            solver_commitment,
            settlement_root,
            consumed_nullifier_root: string_merkle_root(
                "PRIVATE-DEFI-CONSUMED-NULLIFIERS",
                consumed_nullifiers,
            ),
            output_note_root: string_merkle_root("PRIVATE-DEFI-OUTPUT-NOTES", output_notes),
            contract_effect_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-CONTRACT-EFFECTS",
                contract_effects,
            ),
            fee_asset_id,
            fee_paid_units,
            rebate_units,
            surplus_returned_units,
            settled_at_height,
            public_release_height,
            status: SettlementReceiptStatus::Settled,
        })
    }

    pub fn releasable_at(&self, height: u64) -> bool {
        self.public_release_height <= height
            && matches!(
                self.status,
                SettlementReceiptStatus::Settled | SettlementReceiptStatus::Releasable
            )
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.receipt_id, "settlement receipt id")?;
        ensure_non_empty(&self.intent_id, "settlement receipt intent id")?;
        ensure_non_empty(&self.route_id, "settlement receipt route id")?;
        ensure_non_empty(
            &self.solver_commitment,
            "settlement receipt solver commitment",
        )?;
        ensure_non_empty(&self.settlement_root, "settlement receipt settlement root")?;
        ensure_non_empty(
            &self.consumed_nullifier_root,
            "settlement receipt consumed nullifier root",
        )?;
        ensure_non_empty(
            &self.output_note_root,
            "settlement receipt output note root",
        )?;
        ensure_non_empty(
            &self.contract_effect_root,
            "settlement receipt contract effect root",
        )?;
        ensure_non_empty(&self.fee_asset_id, "settlement receipt fee asset id")?;
        if self.public_release_height < self.settled_at_height {
            return Err("settlement receipt release height is before settlement".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "route_id": self.route_id,
            "solver_commitment": self.solver_commitment,
            "settlement_root": self.settlement_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "output_note_root": self.output_note_root,
            "contract_effect_root": self.contract_effect_root,
            "fee_asset_id": self.fee_asset_id,
            "fee_paid_units": self.fee_paid_units,
            "rebate_units": self.rebate_units,
            "surplus_returned_units": self.surplus_returned_units,
            "settled_at_height": self.settled_at_height,
            "public_release_height": self.public_release_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverScorecard {
    pub scorecard_id: String,
    pub solver_commitment: String,
    pub supported_route_root: String,
    pub successful_routes: u64,
    pub failed_routes: u64,
    pub disputed_routes: u64,
    pub surplus_return_bps: u64,
    pub privacy_preservation_bps: u64,
    pub latency_score_bps: u64,
    pub fee_score_bps: u64,
    pub reliability_score_bps: u64,
    pub composite_score_bps: u64,
    pub slashing_events: u64,
    pub bonded_units: u64,
    pub grade: SolverScoreGrade,
    pub updated_at_height: u64,
}

impl SolverScorecard {
    pub fn new(
        solver_commitment: impl Into<String>,
        supported_routes: &[PrivateDefiRouteKind],
        successful_routes: u64,
        failed_routes: u64,
        disputed_routes: u64,
        surplus_return_bps: u64,
        privacy_preservation_bps: u64,
        latency_score_bps: u64,
        fee_score_bps: u64,
        slashing_events: u64,
        bonded_units: u64,
        updated_at_height: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let solver_commitment = solver_commitment.into();
        ensure_non_empty(&solver_commitment, "solver scorecard solver commitment")?;
        if supported_routes.is_empty() {
            return Err("solver scorecard requires supported routes".to_string());
        }
        validate_bps("solver surplus return bps", surplus_return_bps)?;
        validate_bps("solver privacy preservation bps", privacy_preservation_bps)?;
        validate_bps("solver latency score bps", latency_score_bps)?;
        validate_bps("solver fee score bps", fee_score_bps)?;
        let reliability_score_bps =
            derive_reliability_bps(successful_routes, failed_routes, disputed_routes);
        let composite_score_bps = weighted_average_bps(&[
            (surplus_return_bps, 25),
            (privacy_preservation_bps, 30),
            (latency_score_bps, 15),
            (fee_score_bps, 15),
            (reliability_score_bps, 15),
        ]);
        let grade = if slashing_events > 0 {
            SolverScoreGrade::Slashed
        } else if composite_score_bps >= 8_500 {
            SolverScoreGrade::Preferred
        } else if composite_score_bps >= 6_500 {
            SolverScoreGrade::Standard
        } else if composite_score_bps >= 4_000 {
            SolverScoreGrade::Watch
        } else {
            SolverScoreGrade::Quarantined
        };
        let supported_route_records = supported_routes
            .iter()
            .map(|route| json!({ "route_kind": route.as_str() }))
            .collect::<Vec<_>>();
        Ok(Self {
            scorecard_id: private_defi_scorecard_id(&solver_commitment, updated_at_height),
            solver_commitment,
            supported_route_root: merkle_root(
                "PRIVATE-DEFI-SOLVER-SUPPORTED-ROUTES",
                &supported_route_records,
            ),
            successful_routes,
            failed_routes,
            disputed_routes,
            surplus_return_bps,
            privacy_preservation_bps,
            latency_score_bps,
            fee_score_bps,
            reliability_score_bps,
            composite_score_bps,
            slashing_events,
            bonded_units,
            grade,
            updated_at_height,
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.scorecard_id, "solver scorecard id")?;
        ensure_non_empty(
            &self.solver_commitment,
            "solver scorecard solver commitment",
        )?;
        ensure_non_empty(
            &self.supported_route_root,
            "solver scorecard supported route root",
        )?;
        validate_bps("solver surplus return bps", self.surplus_return_bps)?;
        validate_bps(
            "solver privacy preservation bps",
            self.privacy_preservation_bps,
        )?;
        validate_bps("solver latency score bps", self.latency_score_bps)?;
        validate_bps("solver fee score bps", self.fee_score_bps)?;
        validate_bps("solver reliability score bps", self.reliability_score_bps)?;
        validate_bps("solver composite score bps", self.composite_score_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_scorecard",
            "chain_id": CHAIN_ID,
            "scorecard_id": self.scorecard_id,
            "solver_commitment": self.solver_commitment,
            "supported_route_root": self.supported_route_root,
            "successful_routes": self.successful_routes,
            "failed_routes": self.failed_routes,
            "disputed_routes": self.disputed_routes,
            "surplus_return_bps": self.surplus_return_bps,
            "privacy_preservation_bps": self.privacy_preservation_bps,
            "latency_score_bps": self.latency_score_bps,
            "fee_score_bps": self.fee_score_bps,
            "reliability_score_bps": self.reliability_score_bps,
            "composite_score_bps": self.composite_score_bps,
            "slashing_events": self.slashing_events,
            "bonded_units": self.bonded_units,
            "grade": self.grade.as_str(),
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCancellation {
    pub cancellation_id: String,
    pub intent_id: String,
    pub requester_commitment: String,
    pub authorization_id: String,
    pub cancellation_nullifier: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub requested_at_height: u64,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub status: EmergencyCancellationStatus,
}

impl EmergencyCancellation {
    pub fn new(
        intent_id: impl Into<String>,
        requester_commitment: impl Into<String>,
        authorization_id: impl Into<String>,
        cancellation_nullifier: impl Into<String>,
        reason: &Value,
        evidence: &Value,
        requested_at_height: u64,
        effective_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateDefiComposerResult<Self> {
        let intent_id = intent_id.into();
        let requester_commitment = requester_commitment.into();
        let authorization_id = authorization_id.into();
        let cancellation_nullifier = cancellation_nullifier.into();
        ensure_non_empty(&intent_id, "cancellation intent id")?;
        ensure_non_empty(&requester_commitment, "cancellation requester commitment")?;
        ensure_non_empty(&authorization_id, "cancellation authorization id")?;
        ensure_non_empty(&cancellation_nullifier, "cancellation nullifier")?;
        if effective_at_height < requested_at_height {
            return Err("cancellation effective height before request".to_string());
        }
        validate_height_window(effective_at_height, expires_at_height, "cancellation")?;
        Ok(Self {
            cancellation_id: private_defi_cancellation_id(
                &intent_id,
                &requester_commitment,
                &cancellation_nullifier,
                nonce,
            ),
            intent_id,
            requester_commitment,
            authorization_id,
            cancellation_nullifier,
            reason_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-CANCELLATION-REASON",
                reason,
            ),
            evidence_root: private_defi_composer_payload_root(
                "PRIVATE-DEFI-CANCELLATION-EVIDENCE",
                evidence,
            ),
            requested_at_height,
            effective_at_height,
            expires_at_height,
            status: EmergencyCancellationStatus::Requested,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.active()
            && self.requested_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<()> {
        ensure_non_empty(&self.cancellation_id, "cancellation id")?;
        ensure_non_empty(&self.intent_id, "cancellation intent id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "cancellation requester commitment",
        )?;
        ensure_non_empty(&self.authorization_id, "cancellation authorization id")?;
        ensure_non_empty(&self.cancellation_nullifier, "cancellation nullifier")?;
        ensure_non_empty(&self.reason_root, "cancellation reason root")?;
        ensure_non_empty(&self.evidence_root, "cancellation evidence root")?;
        if self.effective_at_height < self.requested_at_height {
            return Err("cancellation effective height before request".to_string());
        }
        validate_height_window(
            self.effective_at_height,
            self.expires_at_height,
            "cancellation",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_cancellation",
            "chain_id": CHAIN_ID,
            "cancellation_id": self.cancellation_id,
            "intent_id": self.intent_id,
            "requester_commitment": self.requester_commitment,
            "authorization_id": self.authorization_id,
            "cancellation_nullifier": self.cancellation_nullifier,
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "requested_at_height": self.requested_at_height,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiComposerRoots {
    pub config_root: String,
    pub intent_root: String,
    pub route_leg_root: String,
    pub route_root: String,
    pub token_composition_root: String,
    pub contract_call_root: String,
    pub budget_root: String,
    pub sponsorship_root: String,
    pub mev_commitment_root: String,
    pub pq_authorization_root: String,
    pub settlement_receipt_root: String,
    pub solver_scorecard_root: String,
    pub emergency_cancellation_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PrivateDefiComposerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_composer_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "route_leg_root": self.route_leg_root,
            "route_root": self.route_root,
            "token_composition_root": self.token_composition_root,
            "contract_call_root": self.contract_call_root,
            "budget_root": self.budget_root,
            "sponsorship_root": self.sponsorship_root,
            "mev_commitment_root": self.mev_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "solver_scorecard_root": self.solver_scorecard_root,
            "emergency_cancellation_root": self.emergency_cancellation_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiComposerCounters {
    pub height: u64,
    pub intent_count: u64,
    pub active_intent_count: u64,
    pub settled_intent_count: u64,
    pub cancelled_intent_count: u64,
    pub swap_intent_count: u64,
    pub lending_intent_count: u64,
    pub options_intent_count: u64,
    pub perps_intent_count: u64,
    pub route_leg_count: u64,
    pub route_count: u64,
    pub live_route_count: u64,
    pub token_composition_count: u64,
    pub contract_call_count: u64,
    pub budget_count: u64,
    pub live_budget_count: u64,
    pub sponsorship_count: u64,
    pub live_sponsorship_count: u64,
    pub total_sponsored_fee_units: u64,
    pub total_rebate_units: u64,
    pub mev_commitment_count: u64,
    pub active_mev_commitment_count: u64,
    pub pq_authorization_count: u64,
    pub active_pq_authorization_count: u64,
    pub settlement_receipt_count: u64,
    pub releasable_receipt_count: u64,
    pub solver_scorecard_count: u64,
    pub preferred_solver_count: u64,
    pub emergency_cancellation_count: u64,
    pub active_cancellation_count: u64,
    pub total_fee_paid_units: u64,
    pub total_surplus_returned_units: u64,
    pub public_record_count: u64,
}

impl PrivateDefiComposerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_composer_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION,
            "height": self.height,
            "intent_count": self.intent_count,
            "active_intent_count": self.active_intent_count,
            "settled_intent_count": self.settled_intent_count,
            "cancelled_intent_count": self.cancelled_intent_count,
            "swap_intent_count": self.swap_intent_count,
            "lending_intent_count": self.lending_intent_count,
            "options_intent_count": self.options_intent_count,
            "perps_intent_count": self.perps_intent_count,
            "route_leg_count": self.route_leg_count,
            "route_count": self.route_count,
            "live_route_count": self.live_route_count,
            "token_composition_count": self.token_composition_count,
            "contract_call_count": self.contract_call_count,
            "budget_count": self.budget_count,
            "live_budget_count": self.live_budget_count,
            "sponsorship_count": self.sponsorship_count,
            "live_sponsorship_count": self.live_sponsorship_count,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_rebate_units": self.total_rebate_units,
            "mev_commitment_count": self.mev_commitment_count,
            "active_mev_commitment_count": self.active_mev_commitment_count,
            "pq_authorization_count": self.pq_authorization_count,
            "active_pq_authorization_count": self.active_pq_authorization_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "releasable_receipt_count": self.releasable_receipt_count,
            "solver_scorecard_count": self.solver_scorecard_count,
            "preferred_solver_count": self.preferred_solver_count,
            "emergency_cancellation_count": self.emergency_cancellation_count,
            "active_cancellation_count": self.active_cancellation_count,
            "total_fee_paid_units": self.total_fee_paid_units,
            "total_surplus_returned_units": self.total_surplus_returned_units,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiComposerState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateDefiComposerConfig,
    pub encrypted_intents: BTreeMap<String, EncryptedMultiLegDefiIntent>,
    pub route_legs: BTreeMap<String, PrivateDefiRouteLeg>,
    pub routes: BTreeMap<String, PrivateDefiRoute>,
    pub token_compositions: BTreeMap<String, PrivateDefiTokenComposition>,
    pub contract_calls: BTreeMap<String, PrivateDefiContractCall>,
    pub budgets: BTreeMap<String, PrivateDefiBudget>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub mev_commitments: BTreeMap<String, MevSafeRouteCommitment>,
    pub pq_authorizations: BTreeMap<String, PqAuthorization>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub solver_scorecards: BTreeMap<String, SolverScorecard>,
    pub emergency_cancellations: BTreeMap<String, EmergencyCancellation>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for PrivateDefiComposerState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateDefiComposerState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateDefiComposerConfig::default(),
            encrypted_intents: BTreeMap::new(),
            route_legs: BTreeMap::new(),
            routes: BTreeMap::new(),
            token_compositions: BTreeMap::new(),
            contract_calls: BTreeMap::new(),
            budgets: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            mev_commitments: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            solver_scorecards: BTreeMap::new(),
            emergency_cancellations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: PrivateDefiComposerConfig) -> PrivateDefiComposerResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateDefiComposerResult<Self> {
        let mut state = Self::with_config(PrivateDefiComposerConfig::devnet())?;
        state.set_height(PRIVATE_DEFI_COMPOSER_DEVNET_HEIGHT);

        let user_auth = PqAuthorization::new(
            "devnet-alice-private-defi-account",
            PqAuthorizationRole::User,
            &[
                "alice-ml-dsa-87-spend-key".to_string(),
                "alice-ml-kem-1024-view-key".to_string(),
            ],
            &[
                "compose_swap".to_string(),
                "compose_lending".to_string(),
                "compose_options".to_string(),
                "compose_perps".to_string(),
                "emergency_cancel_own_intent".to_string(),
            ],
            &json!({"signature": "devnet-alice-pq-auth-signature"}),
            &json!({"delegation": "wallet-session-devnet"}),
            "alice-auth-nonce-commitment",
            state.height.saturating_sub(4),
            state
                .height
                .saturating_add(state.config.default_auth_ttl_blocks),
            state.next_nonce(),
        )?;
        let user_auth_id = user_auth.authorization_id.clone();
        state.insert_pq_authorization(user_auth)?;

        let solver_auth = PqAuthorization::new(
            "devnet-solver-private-defi-operator",
            PqAuthorizationRole::Solver,
            &[
                "solver-ml-dsa-87-operator-key".to_string(),
                "solver-ml-kem-1024-route-key".to_string(),
            ],
            &[
                "solve_private_swap".to_string(),
                "solve_private_lending".to_string(),
                "solve_private_options".to_string(),
                "solve_private_perps".to_string(),
                "sponsor_low_fee_routes".to_string(),
            ],
            &json!({"signature": "devnet-solver-pq-auth-signature"}),
            &json!({"operator": "devnet-solver-1", "bond": 1_500_000_u64}),
            "solver-auth-nonce-commitment",
            state.height.saturating_sub(8),
            state
                .height
                .saturating_add(state.config.default_auth_ttl_blocks),
            state.next_nonce(),
        )?;
        let solver_auth_id = solver_auth.authorization_id.clone();
        state.insert_pq_authorization(solver_auth)?;

        let swap_budget = PrivateDefiBudget::new(
            "devnet-alice-private-defi-account",
            PrivateDefiRouteKind::Composite,
            state.config.default_max_slippage_bps,
            state.config.default_max_price_impact_bps,
            state.config.default_min_fill_bps,
            4_096,
            3,
            2,
            PrivacyBudgetTier::High,
            state.height,
            state
                .height
                .saturating_add(state.config.default_intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let budget_id = swap_budget.budget_id.clone();
        state.insert_budget(swap_budget)?;

        let sponsorship = LowFeeSponsorship::new(
            "devnet-private-defi-sponsor",
            "devnet-alice-private-defi-account",
            state.config.default_low_fee_lane.clone(),
            state.config.default_fee_asset_id.clone(),
            75_000,
            state.config.default_low_fee_rebate_bps,
            2_000,
            state.height,
            state
                .height
                .saturating_add(state.config.default_intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_sponsorship(sponsorship)?;

        let call = PrivateDefiContractCall::new(
            "pending-devnet-intent",
            "devnet-confidential-options-vault",
            "mint_protected_call",
            &json!({
                "underlying": "wxmr-devnet",
                "strike_commitment": "alice-strike-commitment",
                "expiry_bucket": "weekly"
            }),
            &json!({"option_note": "alice-option-note"}),
            &json!({
                "read": ["oracle-wxmr-usdd"],
                "write": ["options-vault-private-position"]
            }),
            &json!({"premium_asset": "usdd-devnet", "premium_bucket": "low"}),
            &json!({"capability": "private-option-mint"}),
            240_000,
            "alice-option-premium-value-commitment",
            false,
            state.height,
            state.next_nonce(),
        )?;
        let call_id = call.call_id.clone();
        state.insert_contract_call(call)?;

        let token_composition = PrivateDefiTokenComposition::new(
            "pending-devnet-intent",
            &["wxmr-devnet".to_string(), "usdd-devnet".to_string()],
            &["usdd-devnet".to_string(), "option-note-devnet".to_string()],
            &[
                "alice-wxmr-input-note-root".to_string(),
                "alice-usdd-input-note-root".to_string(),
            ],
            &[
                "alice-usdd-output-note-root".to_string(),
                "alice-option-output-note-root".to_string(),
            ],
            &[
                json!({"kind": "swap_note", "amount": "bucketed"}),
                json!({"kind": "mint_option_note", "call_id": call_id.clone()}),
            ],
            &json!({"proof": "devnet-token-conservation-proof"}),
            "devnet-net-zero-public-supply-delta",
            state.height,
            state.next_nonce(),
        )?;
        let token_composition_id = token_composition.composition_id.clone();
        state.insert_token_composition(token_composition)?;

        let swap_leg = PrivateDefiRouteLeg::new(
            "pending-devnet-intent",
            0,
            PrivateDefiLegKind::SwapExactIn,
            "wxmr-devnet",
            "usdd-devnet",
            "alice-wxmr-input-commitment",
            "alice-usdd-output-commitment",
            "devnet-private-dex-venue",
            "wxmr-usdd-private-pool",
            budget_id.clone(),
            None,
            Some(token_composition_id.clone()),
            Vec::new(),
            &json!({"pool": "wxmr-usdd", "curve": "confidential-cfmm"}),
            &json!({"swap_validity": "devnet-swap-proof"}),
            state.next_nonce(),
        )?;
        let swap_leg_id = swap_leg.leg_id.clone();
        state.insert_route_leg(swap_leg)?;

        let lend_leg = PrivateDefiRouteLeg::new(
            "pending-devnet-intent",
            1,
            PrivateDefiLegKind::LendingSupply,
            "wxmr-devnet",
            "cwxmr-devnet",
            "alice-wxmr-collateral-commitment",
            "alice-cwxmr-note-commitment",
            "devnet-confidential-lending-venue",
            "wxmr-collateral-market",
            budget_id.clone(),
            None,
            Some(token_composition_id.clone()),
            vec![swap_leg_id.clone()],
            &json!({"market": "wxmr-supply", "health_bucket": "safe"}),
            &json!({"lending_validity": "devnet-lending-proof"}),
            state.next_nonce(),
        )?;
        let lend_leg_id = lend_leg.leg_id.clone();
        state.insert_route_leg(lend_leg)?;

        let option_leg = PrivateDefiRouteLeg::new(
            "pending-devnet-intent",
            2,
            PrivateDefiLegKind::OptionMint,
            "usdd-devnet",
            "option-note-devnet",
            "alice-usdd-premium-commitment",
            "alice-option-note-commitment",
            "devnet-confidential-options-venue",
            "wxmr-usdd-weekly-call",
            budget_id.clone(),
            Some(call_id.clone()),
            Some(token_composition_id.clone()),
            vec![swap_leg_id.clone(), lend_leg_id.clone()],
            &json!({"option": "covered-call", "expiry": "weekly"}),
            &json!({"option_validity": "devnet-option-proof"}),
            state.next_nonce(),
        )?;
        let option_leg_id = option_leg.leg_id.clone();
        state.insert_route_leg(option_leg)?;

        let perp_leg = PrivateDefiRouteLeg::new(
            "pending-devnet-intent",
            3,
            PrivateDefiLegKind::PerpOpen,
            "usdd-devnet",
            "perp-position-note-devnet",
            "alice-usdd-margin-commitment",
            "alice-perp-position-commitment",
            "devnet-confidential-perps-venue",
            "wxmr-usdd-perp-market",
            budget_id.clone(),
            Some(call_id.clone()),
            Some(token_composition_id.clone()),
            vec![swap_leg_id.clone()],
            &json!({"side": "long", "leverage_bucket": "2x-3x"}),
            &json!({"perp_validity": "devnet-perp-proof"}),
            state.next_nonce(),
        )?;
        let perp_leg_id = perp_leg.leg_id.clone();
        state.insert_route_leg(perp_leg)?;

        let devnet_leg_ids = vec![
            swap_leg_id.clone(),
            lend_leg_id.clone(),
            option_leg_id.clone(),
            perp_leg_id.clone(),
        ];

        let intent_payload = EncryptedDefiPayload::new(
            &json!({
                "intent": "multi-leg-private-defi-compose",
                "legs": ["swap", "lending_supply", "option_mint", "perp_open"],
                "privacy": "high",
                "wallet": "alice"
            }),
            &json!({"chain_id": CHAIN_ID, "lane": PRIVATE_DEFI_COMPOSER_DEVNET_LOW_FEE_LANE}),
            "devnet-threshold-key-epoch-1",
            &[
                "devnet-alice-private-defi-account".to_string(),
                "devnet-solver-private-defi-operator".to_string(),
            ],
            12_288,
        )?;
        let intent = EncryptedMultiLegDefiIntent::new(
            "devnet-alice-private-defi-account",
            "alice-private-defi-account-nullifier",
            intent_payload,
            devnet_leg_ids.clone(),
            PrivateDefiRouteKind::Composite,
            budget_id.clone(),
            user_auth_id.clone(),
            Some(sponsorship_id.clone()),
            None,
            &["devnet-solver-private-defi-operator".to_string()],
            &[token_composition_id.clone()],
            &[call_id.clone()],
            &[
                "devnet-alice-private-defi-account".to_string(),
                state.config.emergency_council_root.clone(),
            ],
            &json!({"devnet_case": "private_composable_defi"}),
            state.height,
            state
                .height
                .saturating_add(state.config.default_intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let intent_id = intent.intent_id.clone();
        state.rekey_pending_intent_refs("pending-devnet-intent", &intent_id);
        state.insert_encrypted_intent(intent)?;

        let mev_commitment = MevSafeRouteCommitment::new(
            intent_id.clone(),
            None,
            &json!({
                "legs": devnet_leg_ids.clone(),
                "solver": "devnet-solver-private-defi-operator"
            }),
            &json!({"sealed_order": "devnet-mev-safe-sealed-order"}),
            &["devnet-solver-private-defi-operator".to_string()],
            &json!({"no_sandwich": true, "batch_only": true}),
            &json!({"batch": "devnet-private-defi-batch-1"}),
            "alice-route-salt-commitment",
            state.height.saturating_add(2),
            state
                .height
                .saturating_add(state.config.default_route_ttl_blocks),
            state.next_nonce(),
        )?;
        let mev_commitment_id = mev_commitment.commitment_id.clone();
        state.insert_mev_commitment(mev_commitment)?;

        let route = PrivateDefiRoute::new(
            intent_id.clone(),
            "devnet-solver-private-defi-operator",
            PrivateDefiRouteKind::Composite,
            devnet_leg_ids.clone(),
            &json!({"path": "dex+lending+options+perps", "mev_safe": true}),
            &json!({"clearing": "batch-uniform-private"}),
            &json!({"expected": "bucketed-private-surplus"}),
            &json!({"fee": "low-fee-sponsored"}),
            Some(mev_commitment_id.clone()),
            solver_auth_id.clone(),
            state.height,
            state
                .height
                .saturating_add(state.config.default_route_ttl_blocks),
            state.next_nonce(),
        )?;
        let route_id = route.route_id.clone();
        state.insert_route(route)?;

        let receipt = SettlementReceipt::new(
            intent_id.clone(),
            route_id,
            "devnet-solver-private-defi-operator",
            &json!({"settlement": "devnet-composite-settlement-root"}),
            &["alice-input-nullifier-root".to_string()],
            &[
                "alice-usdd-output-root".to_string(),
                "alice-option-output-root".to_string(),
                "alice-perp-output-root".to_string(),
            ],
            &json!({"effects": "private-contract-effects-root"}),
            state.config.default_fee_asset_id.clone(),
            38_000,
            24_700,
            11_000,
            state.height.saturating_add(6),
            state
                .height
                .saturating_add(state.config.receipt_delay_blocks),
            state.next_nonce(),
        )?;
        state.insert_settlement_receipt(receipt)?;

        let scorecard = SolverScorecard::new(
            "devnet-solver-private-defi-operator",
            &[
                PrivateDefiRouteKind::PrivateSwap,
                PrivateDefiRouteKind::PrivateLending,
                PrivateDefiRouteKind::PrivateOptions,
                PrivateDefiRouteKind::PrivatePerps,
                PrivateDefiRouteKind::Composite,
            ],
            128,
            3,
            1,
            8_800,
            9_400,
            8_200,
            8_700,
            0,
            1_500_000,
            state.height,
        )?;
        state.insert_solver_scorecard(scorecard)?;

        let cancellation = EmergencyCancellation::new(
            intent_id,
            "devnet-alice-private-defi-account",
            user_auth_id,
            "alice-emergency-cancel-nullifier",
            &json!({"reason": "wallet-requested-emergency-cancel"}),
            &json!({"wallet": "alice", "proof": "devnet-cancel-proof"}),
            state.height.saturating_add(1),
            state.height.saturating_add(2),
            state
                .height
                .saturating_add(state.config.default_cancellation_ttl_blocks),
            state.next_nonce(),
        )?;
        state.insert_emergency_cancellation(cancellation)?;
        state.capture_public_record("devnet-private-defi-composer-snapshot");
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        let current = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        current
    }

    pub fn insert_encrypted_intent(
        &mut self,
        intent: EncryptedMultiLegDefiIntent,
    ) -> PrivateDefiComposerResult<String> {
        intent.validate()?;
        if intent.leg_ids.len() > self.config.max_legs_per_intent {
            return Err("intent exceeds max legs per intent".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.encrypted_intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn insert_route_leg(
        &mut self,
        leg: PrivateDefiRouteLeg,
    ) -> PrivateDefiComposerResult<String> {
        leg.validate()?;
        let leg_id = leg.leg_id.clone();
        self.route_legs.insert(leg_id.clone(), leg);
        Ok(leg_id)
    }

    pub fn insert_route(&mut self, route: PrivateDefiRoute) -> PrivateDefiComposerResult<String> {
        route.validate()?;
        let route_id = route.route_id.clone();
        self.routes.insert(route_id.clone(), route);
        Ok(route_id)
    }

    pub fn insert_token_composition(
        &mut self,
        composition: PrivateDefiTokenComposition,
    ) -> PrivateDefiComposerResult<String> {
        composition.validate()?;
        let composition_id = composition.composition_id.clone();
        self.token_compositions
            .insert(composition_id.clone(), composition);
        Ok(composition_id)
    }

    pub fn insert_contract_call(
        &mut self,
        call: PrivateDefiContractCall,
    ) -> PrivateDefiComposerResult<String> {
        call.validate()?;
        let call_id = call.call_id.clone();
        self.contract_calls.insert(call_id.clone(), call);
        Ok(call_id)
    }

    pub fn insert_budget(
        &mut self,
        budget: PrivateDefiBudget,
    ) -> PrivateDefiComposerResult<String> {
        budget.validate()?;
        let budget_id = budget.budget_id.clone();
        self.budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorship,
    ) -> PrivateDefiComposerResult<String> {
        sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_mev_commitment(
        &mut self,
        commitment: MevSafeRouteCommitment,
    ) -> PrivateDefiComposerResult<String> {
        commitment.validate()?;
        let commitment_id = commitment.commitment_id.clone();
        self.mev_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqAuthorization,
    ) -> PrivateDefiComposerResult<String> {
        authorization.validate()?;
        let authorization_id = authorization.authorization_id.clone();
        self.pq_authorizations
            .insert(authorization_id.clone(), authorization);
        Ok(authorization_id)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateDefiComposerResult<String> {
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_solver_scorecard(
        &mut self,
        scorecard: SolverScorecard,
    ) -> PrivateDefiComposerResult<String> {
        scorecard.validate()?;
        let scorecard_id = scorecard.scorecard_id.clone();
        self.solver_scorecards
            .insert(scorecard_id.clone(), scorecard);
        Ok(scorecard_id)
    }

    pub fn insert_emergency_cancellation(
        &mut self,
        cancellation: EmergencyCancellation,
    ) -> PrivateDefiComposerResult<String> {
        cancellation.validate()?;
        let cancellation_id = cancellation.cancellation_id.clone();
        self.emergency_cancellations
            .insert(cancellation_id.clone(), cancellation);
        Ok(cancellation_id)
    }

    pub fn capture_public_record(&mut self, label: impl Into<String>) -> String {
        let label = label.into();
        let record = json!({
            "kind": "private_defi_composer_public_record",
            "chain_id": CHAIN_ID,
            "label": label,
            "height": self.height,
            "roots": self.roots_without_public_records().public_record(),
            "counters": self.counters().public_record(),
        });
        let record_id = domain_hash(
            "PRIVATE-DEFI-COMPOSER-PUBLIC-RECORD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&label),
                HashPart::Json(&record),
                HashPart::Int(self.public_records.len() as i128),
            ],
            32,
        );
        self.public_records.insert(record_id.clone(), record);
        record_id
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn intent_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-INTENTS",
            self.encrypted_intents
                .values()
                .map(EncryptedMultiLegDefiIntent::public_record)
                .collect(),
        )
    }

    pub fn route_leg_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-ROUTE-LEGS",
            self.route_legs
                .values()
                .map(PrivateDefiRouteLeg::public_record)
                .collect(),
        )
    }

    pub fn route_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-ROUTES",
            self.routes
                .values()
                .map(PrivateDefiRoute::public_record)
                .collect(),
        )
    }

    pub fn token_composition_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-TOKEN-COMPOSITIONS",
            self.token_compositions
                .values()
                .map(PrivateDefiTokenComposition::public_record)
                .collect(),
        )
    }

    pub fn contract_call_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-CONTRACT-CALLS",
            self.contract_calls
                .values()
                .map(PrivateDefiContractCall::public_record)
                .collect(),
        )
    }

    pub fn budget_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-BUDGETS",
            self.budgets
                .values()
                .map(PrivateDefiBudget::public_record)
                .collect(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-SPONSORSHIPS",
            self.sponsorships
                .values()
                .map(LowFeeSponsorship::public_record)
                .collect(),
        )
    }

    pub fn mev_commitment_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-MEV-COMMITMENTS",
            self.mev_commitments
                .values()
                .map(MevSafeRouteCommitment::public_record)
                .collect(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-PQ-AUTHORIZATIONS",
            self.pq_authorizations
                .values()
                .map(PqAuthorization::public_record)
                .collect(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        )
    }

    pub fn solver_scorecard_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-SOLVER-SCORECARDS",
            self.solver_scorecards
                .values()
                .map(SolverScorecard::public_record)
                .collect(),
        )
    }

    pub fn emergency_cancellation_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-EMERGENCY-CANCELLATIONS",
            self.emergency_cancellations
                .values()
                .map(EmergencyCancellation::public_record)
                .collect(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_defi_composer_map_root(
            "PRIVATE-DEFI-COMPOSER-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        )
    }

    pub fn roots(&self) -> PrivateDefiComposerRoots {
        let mut roots = self.roots_without_public_records();
        roots.public_record_root = self.public_record_root();
        let state_record = self.state_record_from_roots(&roots);
        roots.state_root = private_defi_composer_state_root_from_record(&state_record);
        roots
    }

    pub fn counters(&self) -> PrivateDefiComposerCounters {
        let mut counters = PrivateDefiComposerCounters {
            height: self.height,
            intent_count: self.encrypted_intents.len() as u64,
            route_leg_count: self.route_legs.len() as u64,
            route_count: self.routes.len() as u64,
            token_composition_count: self.token_compositions.len() as u64,
            contract_call_count: self.contract_calls.len() as u64,
            budget_count: self.budgets.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            mev_commitment_count: self.mev_commitments.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            solver_scorecard_count: self.solver_scorecards.len() as u64,
            emergency_cancellation_count: self.emergency_cancellations.len() as u64,
            public_record_count: self.public_records.len() as u64,
            ..PrivateDefiComposerCounters::default()
        };
        for intent in self.encrypted_intents.values() {
            if intent.is_live_at(self.height) {
                counters.active_intent_count = counters.active_intent_count.saturating_add(1);
            }
            if intent.status == PrivateDefiIntentStatus::Settled {
                counters.settled_intent_count = counters.settled_intent_count.saturating_add(1);
            }
            if intent.status == PrivateDefiIntentStatus::Cancelled {
                counters.cancelled_intent_count = counters.cancelled_intent_count.saturating_add(1);
            }
            match &intent.route_kind {
                PrivateDefiRouteKind::PrivateSwap => {
                    counters.swap_intent_count = counters.swap_intent_count.saturating_add(1);
                }
                PrivateDefiRouteKind::PrivateLending => {
                    counters.lending_intent_count = counters.lending_intent_count.saturating_add(1);
                }
                PrivateDefiRouteKind::PrivateOptions => {
                    counters.options_intent_count = counters.options_intent_count.saturating_add(1);
                }
                PrivateDefiRouteKind::PrivatePerps => {
                    counters.perps_intent_count = counters.perps_intent_count.saturating_add(1);
                }
                _ => {}
            }
        }
        for route in self.routes.values() {
            if route.is_live_at(self.height) {
                counters.live_route_count = counters.live_route_count.saturating_add(1);
            }
        }
        for budget in self.budgets.values() {
            if budget.is_live_at(self.height) {
                counters.live_budget_count = counters.live_budget_count.saturating_add(1);
            }
        }
        for sponsorship in self.sponsorships.values() {
            if sponsorship.is_live_at(self.height) {
                counters.live_sponsorship_count = counters.live_sponsorship_count.saturating_add(1);
            }
            counters.total_sponsored_fee_units = counters
                .total_sponsored_fee_units
                .saturating_add(sponsorship.max_fee_units);
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(sponsorship.applied_rebate_units);
        }
        for commitment in self.mev_commitments.values() {
            if commitment.is_active_at(self.height) {
                counters.active_mev_commitment_count =
                    counters.active_mev_commitment_count.saturating_add(1);
            }
        }
        for authorization in self.pq_authorizations.values() {
            if authorization.is_live_at(self.height) {
                counters.active_pq_authorization_count =
                    counters.active_pq_authorization_count.saturating_add(1);
            }
        }
        for receipt in self.settlement_receipts.values() {
            if receipt.releasable_at(self.height) {
                counters.releasable_receipt_count =
                    counters.releasable_receipt_count.saturating_add(1);
            }
            counters.total_fee_paid_units = counters
                .total_fee_paid_units
                .saturating_add(receipt.fee_paid_units);
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(receipt.rebate_units);
            counters.total_surplus_returned_units = counters
                .total_surplus_returned_units
                .saturating_add(receipt.surplus_returned_units);
        }
        for scorecard in self.solver_scorecards.values() {
            if scorecard.grade == SolverScoreGrade::Preferred {
                counters.preferred_solver_count = counters.preferred_solver_count.saturating_add(1);
            }
        }
        for cancellation in self.emergency_cancellations.values() {
            if cancellation.is_live_at(self.height) {
                counters.active_cancellation_count =
                    counters.active_cancellation_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_defi_composer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "encrypted_intents": self.encrypted_intents.values().map(EncryptedMultiLegDefiIntent::public_record).collect::<Vec<_>>(),
            "route_legs": self.route_legs.values().map(PrivateDefiRouteLeg::public_record).collect::<Vec<_>>(),
            "routes": self.routes.values().map(PrivateDefiRoute::public_record).collect::<Vec<_>>(),
            "token_compositions": self.token_compositions.values().map(PrivateDefiTokenComposition::public_record).collect::<Vec<_>>(),
            "contract_calls": self.contract_calls.values().map(PrivateDefiContractCall::public_record).collect::<Vec<_>>(),
            "budgets": self.budgets.values().map(PrivateDefiBudget::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeSponsorship::public_record).collect::<Vec<_>>(),
            "mev_commitments": self.mev_commitments.values().map(MevSafeRouteCommitment::public_record).collect::<Vec<_>>(),
            "pq_authorizations": self.pq_authorizations.values().map(PqAuthorization::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "solver_scorecards": self.solver_scorecards.values().map(SolverScorecard::public_record).collect::<Vec<_>>(),
            "emergency_cancellations": self.emergency_cancellations.values().map(EmergencyCancellation::public_record).collect::<Vec<_>>(),
            "public_record_count": self.public_records.len(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> PrivateDefiComposerResult<String> {
        self.config.validate()?;
        validate_map_len(
            self.encrypted_intents.len(),
            PRIVATE_DEFI_COMPOSER_MAX_INTENTS,
            "composer intents",
        )?;
        validate_map_len(
            self.route_legs.len(),
            PRIVATE_DEFI_COMPOSER_MAX_LEGS,
            "composer route legs",
        )?;
        validate_map_len(
            self.routes.len(),
            PRIVATE_DEFI_COMPOSER_MAX_ROUTES,
            "composer routes",
        )?;
        validate_map_len(
            self.token_compositions.len(),
            PRIVATE_DEFI_COMPOSER_MAX_TOKEN_COMPOSITIONS,
            "composer token compositions",
        )?;
        validate_map_len(
            self.contract_calls.len(),
            PRIVATE_DEFI_COMPOSER_MAX_CONTRACT_CALLS,
            "composer contract calls",
        )?;
        validate_map_len(
            self.budgets.len(),
            PRIVATE_DEFI_COMPOSER_MAX_BUDGETS,
            "composer budgets",
        )?;
        validate_map_len(
            self.sponsorships.len(),
            PRIVATE_DEFI_COMPOSER_MAX_SPONSORSHIPS,
            "composer sponsorships",
        )?;
        validate_map_len(
            self.mev_commitments.len(),
            PRIVATE_DEFI_COMPOSER_MAX_MEV_COMMITMENTS,
            "composer mev commitments",
        )?;
        validate_map_len(
            self.pq_authorizations.len(),
            PRIVATE_DEFI_COMPOSER_MAX_AUTHORIZATIONS,
            "composer pq authorizations",
        )?;
        validate_map_len(
            self.settlement_receipts.len(),
            PRIVATE_DEFI_COMPOSER_MAX_RECEIPTS,
            "composer settlement receipts",
        )?;
        validate_map_len(
            self.solver_scorecards.len(),
            PRIVATE_DEFI_COMPOSER_MAX_SCORECARDS,
            "composer solver scorecards",
        )?;
        validate_map_len(
            self.emergency_cancellations.len(),
            PRIVATE_DEFI_COMPOSER_MAX_CANCELLATIONS,
            "composer emergency cancellations",
        )?;

        for (id, budget) in &self.budgets {
            if id != &budget.budget_id {
                return Err("composer budget key does not match budget id".to_string());
            }
            budget.validate()?;
        }
        for (id, authorization) in &self.pq_authorizations {
            if id != &authorization.authorization_id {
                return Err(
                    "composer authorization key does not match authorization id".to_string()
                );
            }
            authorization.validate()?;
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("composer sponsorship key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
        }
        for (id, call) in &self.contract_calls {
            if id != &call.call_id {
                return Err("composer contract call key does not match call id".to_string());
            }
            call.validate()?;
        }
        for (id, composition) in &self.token_compositions {
            if id != &composition.composition_id {
                return Err(
                    "composer token composition key does not match composition id".to_string(),
                );
            }
            composition.validate()?;
        }
        for (id, leg) in &self.route_legs {
            if id != &leg.leg_id {
                return Err("composer route leg key does not match leg id".to_string());
            }
            leg.validate()?;
            if !self.budgets.contains_key(&leg.budget_id) {
                return Err("composer route leg references missing budget".to_string());
            }
            if let Some(call_id) = &leg.contract_call_id {
                if !self.contract_calls.contains_key(call_id) {
                    return Err("composer route leg references missing contract call".to_string());
                }
            }
            if let Some(composition_id) = &leg.token_composition_id {
                if !self.token_compositions.contains_key(composition_id) {
                    return Err(
                        "composer route leg references missing token composition".to_string()
                    );
                }
            }
            for dependency in &leg.dependency_leg_ids {
                if !self.route_legs.contains_key(dependency) {
                    return Err("composer route leg references missing dependency".to_string());
                }
            }
        }
        for (id, intent) in &self.encrypted_intents {
            if id != &intent.intent_id {
                return Err("composer intent key does not match intent id".to_string());
            }
            intent.validate()?;
            if intent.leg_ids.len() > self.config.max_legs_per_intent {
                return Err("composer intent exceeds configured leg cap".to_string());
            }
            if !self.budgets.contains_key(&intent.budget_id) {
                return Err("composer intent references missing budget".to_string());
            }
            if !self
                .pq_authorizations
                .contains_key(&intent.user_authorization_id)
            {
                return Err("composer intent references missing user authorization".to_string());
            }
            if let Some(sponsorship_id) = &intent.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err("composer intent references missing sponsorship".to_string());
                }
            }
            if let Some(commitment_id) = &intent.mev_commitment_id {
                if !self.mev_commitments.contains_key(commitment_id) {
                    return Err("composer intent references missing mev commitment".to_string());
                }
            }
            for leg_id in &intent.leg_ids {
                match self.route_legs.get(leg_id) {
                    Some(leg) if leg.intent_id == intent.intent_id => {}
                    Some(_) => return Err("composer intent references foreign leg".to_string()),
                    None => return Err("composer intent references missing leg".to_string()),
                }
            }
        }
        for (id, commitment) in &self.mev_commitments {
            if id != &commitment.commitment_id {
                return Err("composer mev key does not match commitment id".to_string());
            }
            commitment.validate()?;
            if !self.encrypted_intents.contains_key(&commitment.intent_id) {
                return Err("composer mev commitment references missing intent".to_string());
            }
            if let Some(route_id) = &commitment.route_id {
                if !self.routes.contains_key(route_id) {
                    return Err("composer mev commitment references missing route".to_string());
                }
            }
        }
        for (id, route) in &self.routes {
            if id != &route.route_id {
                return Err("composer route key does not match route id".to_string());
            }
            route.validate()?;
            if !self.encrypted_intents.contains_key(&route.intent_id) {
                return Err("composer route references missing intent".to_string());
            }
            if !self.pq_authorizations.contains_key(&route.authorization_id) {
                return Err("composer route references missing authorization".to_string());
            }
            if let Some(commitment_id) = &route.mev_commitment_id {
                if !self.mev_commitments.contains_key(commitment_id) {
                    return Err("composer route references missing mev commitment".to_string());
                }
            }
            for leg_id in &route.leg_ids {
                match self.route_legs.get(leg_id) {
                    Some(leg) if leg.intent_id == route.intent_id => {}
                    Some(_) => return Err("composer route references foreign leg".to_string()),
                    None => return Err("composer route references missing leg".to_string()),
                }
            }
        }
        for (id, receipt) in &self.settlement_receipts {
            if id != &receipt.receipt_id {
                return Err("composer receipt key does not match receipt id".to_string());
            }
            receipt.validate()?;
            if !self.encrypted_intents.contains_key(&receipt.intent_id) {
                return Err("composer receipt references missing intent".to_string());
            }
            if !self.routes.contains_key(&receipt.route_id) {
                return Err("composer receipt references missing route".to_string());
            }
        }
        for (id, scorecard) in &self.solver_scorecards {
            if id != &scorecard.scorecard_id {
                return Err("composer scorecard key does not match scorecard id".to_string());
            }
            scorecard.validate()?;
        }
        for (id, cancellation) in &self.emergency_cancellations {
            if id != &cancellation.cancellation_id {
                return Err("composer cancellation key does not match cancellation id".to_string());
            }
            cancellation.validate()?;
            if !self.encrypted_intents.contains_key(&cancellation.intent_id) {
                return Err("composer cancellation references missing intent".to_string());
            }
            if !self
                .pq_authorizations
                .contains_key(&cancellation.authorization_id)
            {
                return Err("composer cancellation references missing authorization".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn roots_without_public_records(&self) -> PrivateDefiComposerRoots {
        let mut roots = PrivateDefiComposerRoots {
            config_root: self.config_root(),
            intent_root: self.intent_root(),
            route_leg_root: self.route_leg_root(),
            route_root: self.route_root(),
            token_composition_root: self.token_composition_root(),
            contract_call_root: self.contract_call_root(),
            budget_root: self.budget_root(),
            sponsorship_root: self.sponsorship_root(),
            mev_commitment_root: self.mev_commitment_root(),
            pq_authorization_root: self.pq_authorization_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            solver_scorecard_root: self.solver_scorecard_root(),
            emergency_cancellation_root: self.emergency_cancellation_root(),
            public_record_root: merkle_root("PRIVATE-DEFI-COMPOSER-PUBLIC-RECORDS", &[]),
            state_root: String::new(),
        };
        let state_record = self.state_record_from_roots(&roots);
        roots.state_root = private_defi_composer_state_root_from_record(&state_record);
        roots
    }

    fn state_record_from_roots(&self, roots: &PrivateDefiComposerRoots) -> Value {
        json!({
            "kind": "private_defi_composer_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_COMPOSER_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config_root": roots.config_root,
            "intent_root": roots.intent_root,
            "route_leg_root": roots.route_leg_root,
            "route_root": roots.route_root,
            "token_composition_root": roots.token_composition_root,
            "contract_call_root": roots.contract_call_root,
            "budget_root": roots.budget_root,
            "sponsorship_root": roots.sponsorship_root,
            "mev_commitment_root": roots.mev_commitment_root,
            "pq_authorization_root": roots.pq_authorization_root,
            "settlement_receipt_root": roots.settlement_receipt_root,
            "solver_scorecard_root": roots.solver_scorecard_root,
            "emergency_cancellation_root": roots.emergency_cancellation_root,
            "public_record_root": roots.public_record_root,
            "counters": self.counters().public_record(),
        })
    }

    fn rekey_pending_intent_refs(&mut self, old_intent_id: &str, new_intent_id: &str) {
        for leg in self.route_legs.values_mut() {
            if leg.intent_id == old_intent_id {
                leg.intent_id = new_intent_id.to_string();
            }
        }
        for call in self.contract_calls.values_mut() {
            if call.intent_id == old_intent_id {
                call.intent_id = new_intent_id.to_string();
            }
        }
        for composition in self.token_compositions.values_mut() {
            if composition.intent_id == old_intent_id {
                composition.intent_id = new_intent_id.to_string();
            }
        }
    }
}

pub fn private_defi_composer_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DEFI-COMPOSER-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_defi_composer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_defi_composer_map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn private_defi_intent_id(
    owner_commitment: &str,
    account_nullifier: &str,
    encrypted_payload_root: &str,
    metadata_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(account_nullifier),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(metadata_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_leg_id(
    intent_id: &str,
    sequence: u64,
    leg_kind: &PrivateDefiLegKind,
    route_hint_root: &str,
    nonce: u64,
) -> String {
    let leg_kind = leg_kind.as_str();
    domain_hash(
        "PRIVATE-DEFI-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(&leg_kind),
            HashPart::Str(route_hint_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_route_id(
    intent_id: &str,
    solver_commitment: &str,
    leg_root: &str,
    route_commitment_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(leg_root),
            HashPart::Str(route_commitment_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_budget_id(
    owner_commitment: &str,
    route_kind: &PrivateDefiRouteKind,
    created_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    let route_kind = route_kind.as_str();
    domain_hash(
        "PRIVATE-DEFI-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(&route_kind),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_contract_call_id(
    intent_id: &str,
    contract_commitment: &str,
    entrypoint_selector: &str,
    calldata_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-CONTRACT-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(entrypoint_selector),
            HashPart::Str(calldata_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_token_composition_id(
    intent_id: &str,
    asset_in_root: &str,
    asset_out_root: &str,
    conservation_proof_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-TOKEN-COMPOSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(asset_in_root),
            HashPart::Str(asset_out_root),
            HashPart::Str(conservation_proof_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    lane_id: &str,
    fee_asset_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_mev_commitment_id(
    intent_id: &str,
    route_commitment_root: &str,
    salt_commitment: &str,
    reveal_after_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-MEV-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(route_commitment_root),
            HashPart::Str(salt_commitment),
            HashPart::Int(reveal_after_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_pq_authorization_id(
    subject_commitment: &str,
    role: PqAuthorizationRole,
    pq_key_root: &str,
    capability_root: &str,
    valid_from_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(role.as_str()),
            HashPart::Str(pq_key_root),
            HashPart::Str(capability_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_settlement_receipt_id(
    intent_id: &str,
    route_id: &str,
    solver_commitment: &str,
    settlement_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(route_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(settlement_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_defi_scorecard_id(solver_commitment: &str, updated_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-DEFI-SOLVER-SCORECARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_commitment),
            HashPart::Int(updated_at_height as i128),
        ],
        32,
    )
}

pub fn private_defi_cancellation_id(
    intent_id: &str,
    requester_commitment: &str,
    cancellation_nullifier: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-CANCELLATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(cancellation_nullifier),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateDefiComposerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn validate_non_zero(value: u64, label: &str) -> PrivateDefiComposerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn validate_non_zero_usize(value: usize, label: &str) -> PrivateDefiComposerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn validate_bps(label: &str, value: u64) -> PrivateDefiComposerResult<()> {
    if value > PRIVATE_DEFI_COMPOSER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn validate_height_window(start: u64, end: u64, label: &str) -> PrivateDefiComposerResult<()> {
    if end < start {
        return Err(format!("{label} end height is before start height"));
    }
    Ok(())
}

fn validate_map_len(count: usize, max: usize, label: &str) -> PrivateDefiComposerResult<()> {
    if count > max {
        return Err(format!("{label} exceeds max entries"));
    }
    Ok(())
}

fn validate_non_empty_slice<T>(values: &[T], label: &str) -> PrivateDefiComposerResult<()> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn validate_unique_strings(values: &[String], label: &str) -> PrivateDefiComposerResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn string_merkle_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn derive_reliability_bps(successes: u64, failures: u64, disputes: u64) -> u64 {
    let total = successes
        .saturating_add(failures)
        .saturating_add(disputes.saturating_mul(2));
    if total == 0 {
        return 0;
    }
    successes
        .saturating_mul(PRIVATE_DEFI_COMPOSER_MAX_BPS)
        .saturating_div(total)
}

fn weighted_average_bps(values: &[(u64, u64)]) -> u64 {
    let mut weighted_total = 0_u64;
    let mut weight_total = 0_u64;
    for (value, weight) in values {
        weighted_total = weighted_total.saturating_add((*value).saturating_mul(*weight));
        weight_total = weight_total.saturating_add(*weight);
    }
    if weight_total == 0 {
        return 0;
    }
    weighted_total.saturating_div(weight_total)
}
