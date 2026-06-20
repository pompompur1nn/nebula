use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractComposabilityBusResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION: &str =
    "nebula-private-contract-composability-bus-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+shake256-composable-call-bundle-devnet-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-composable-authorization-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_LOCK_SCHEME: &str =
    "shake256-private-contract-dependency-lock-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_RECEIPT_SCHEME: &str =
    "zk-private-composability-budget-receipt-devnet-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_CALLBACK_SCHEME: &str =
    "encrypted-private-contract-callback-v1";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEVNET_LOW_FEE_LANE: &str =
    "devnet-private-contract-composability";
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_LOCK_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALL_LEGS: usize = 32;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALLBACKS: usize = 64;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 25_000;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 125_000;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_FEE_UNITS: u64 = 15_000;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_BUNDLES: usize = 65_536;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_AUTHORIZATIONS: usize = 16_384;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_DEPENDENCY_LOCKS: usize = 131_072;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_SPONSORSHIPS: usize = 65_536;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_PRIVACY_RECEIPTS: usize = 131_072;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_CALLBACK_RECEIPTS: usize = 131_072;
pub const PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_PUBLIC_RECORDS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposableCallKind {
    ShieldedContract,
    PrivateTokenTransfer,
    PrivateTokenMint,
    PrivateTokenBurn,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingWithdraw,
    PerpOpen,
    PerpClose,
    PerpAdjustMargin,
    PerpFundingSettle,
    AmmSwapExactIn,
    AmmSwapExactOut,
    AmmAddLiquidity,
    AmmRemoveLiquidity,
    CallbackInvoke,
    Settlement,
    Custom(String),
}

impl ComposableCallKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedContract => "shielded_contract".to_string(),
            Self::PrivateTokenTransfer => "private_token_transfer".to_string(),
            Self::PrivateTokenMint => "private_token_mint".to_string(),
            Self::PrivateTokenBurn => "private_token_burn".to_string(),
            Self::LendingSupply => "lending_supply".to_string(),
            Self::LendingBorrow => "lending_borrow".to_string(),
            Self::LendingRepay => "lending_repay".to_string(),
            Self::LendingWithdraw => "lending_withdraw".to_string(),
            Self::PerpOpen => "perp_open".to_string(),
            Self::PerpClose => "perp_close".to_string(),
            Self::PerpAdjustMargin => "perp_adjust_margin".to_string(),
            Self::PerpFundingSettle => "perp_funding_settle".to_string(),
            Self::AmmSwapExactIn => "amm_swap_exact_in".to_string(),
            Self::AmmSwapExactOut => "amm_swap_exact_out".to_string(),
            Self::AmmAddLiquidity => "amm_add_liquidity".to_string(),
            Self::AmmRemoveLiquidity => "amm_remove_liquidity".to_string(),
            Self::CallbackInvoke => "callback_invoke".to_string(),
            Self::Settlement => "settlement".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_lending(&self) -> bool {
        matches!(
            self,
            Self::LendingSupply | Self::LendingBorrow | Self::LendingRepay | Self::LendingWithdraw
        )
    }

    pub fn is_perp(&self) -> bool {
        matches!(
            self,
            Self::PerpOpen | Self::PerpClose | Self::PerpAdjustMargin | Self::PerpFundingSettle
        )
    }

    pub fn is_amm(&self) -> bool {
        matches!(
            self,
            Self::AmmSwapExactIn
                | Self::AmmSwapExactOut
                | Self::AmmAddLiquidity
                | Self::AmmRemoveLiquidity
        )
    }

    pub fn is_token(&self) -> bool {
        matches!(
            self,
            Self::PrivateTokenTransfer | Self::PrivateTokenMint | Self::PrivateTokenBurn
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Draft,
    Submitted,
    Authorized,
    Locked,
    Executing,
    Settled,
    Reverted,
    Expired,
    Rejected,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::Locked => "locked",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Authorized | Self::Locked | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
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
pub enum DependencyLockStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Conflicted,
}

impl DependencyLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Conflicted => "conflicted",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Final,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Final => "final",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Scheduled,
    Delivered,
    Acknowledged,
    Reverted,
    Expired,
}

impl CallbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetCategory {
    CallGraph,
    AssetFlow,
    Timing,
    Counterparty,
    Callback,
    PublicDisclosure,
}

impl PrivacyBudgetCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallGraph => "call_graph",
            Self::AssetFlow => "asset_flow",
            Self::Timing => "timing",
            Self::Counterparty => "counterparty",
            Self::Callback => "callback",
            Self::PublicDisclosure => "public_disclosure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractComposabilityBusConfig {
    pub bus_id: String,
    pub operator_committee_root: String,
    pub callback_router_root: String,
    pub dependency_oracle_root: String,
    pub bundle_ttl_blocks: u64,
    pub auth_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub max_call_legs: usize,
    pub max_callbacks: usize,
    pub min_privacy_set_size: u64,
    pub default_privacy_budget_units: u64,
    pub sponsor_budget_units: u64,
    pub max_fee_units: u64,
    pub max_disclosure_bps: u64,
    pub default_low_fee_lane: String,
}

impl Default for PrivateContractComposabilityBusConfig {
    fn default() -> Self {
        Self {
            bus_id: private_contract_composability_bus_string_root("bus", "default"),
            operator_committee_root: private_contract_composability_bus_string_root(
                "operator-committee",
                "default-devnet-composability-committee",
            ),
            callback_router_root: private_contract_composability_bus_string_root(
                "callback-router",
                "default-private-callback-router",
            ),
            dependency_oracle_root: private_contract_composability_bus_string_root(
                "dependency-oracle",
                "default-private-dependency-oracle",
            ),
            bundle_ttl_blocks: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_BUNDLE_TTL_BLOCKS,
            auth_ttl_blocks: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_AUTH_TTL_BLOCKS,
            lock_ttl_blocks: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_LOCK_TTL_BLOCKS,
            callback_ttl_blocks: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_CALLBACK_TTL_BLOCKS,
            max_call_legs: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALL_LEGS,
            max_callbacks: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALLBACKS,
            min_privacy_set_size: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            default_privacy_budget_units:
                PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_PRIVACY_BUDGET_UNITS,
            sponsor_budget_units: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_fee_units: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_FEE_UNITS,
            max_disclosure_bps: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_DISCLOSURE_BPS,
            default_low_fee_lane: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEVNET_LOW_FEE_LANE
                .to_string(),
        }
    }
}

impl PrivateContractComposabilityBusConfig {
    pub fn devnet() -> Self {
        Self {
            bus_id: private_contract_composability_bus_string_root("bus", "devnet"),
            operator_committee_root: private_contract_composability_bus_payload_root(
                "DEVNET-COMPOSABILITY-COMMITTEE",
                &json!({
                    "members": [
                        "devnet-composability-sequencer-a",
                        "devnet-private-solver-b",
                        "devnet-callback-watcher-c"
                    ],
                    "threshold": 2
                }),
            ),
            callback_router_root: private_contract_composability_bus_payload_root(
                "DEVNET-CALLBACK-ROUTER",
                &json!({
                    "encrypted_callbacks": true,
                    "acknowledgements": true,
                    "max_callbacks": PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALLBACKS
                }),
            ),
            dependency_oracle_root: private_contract_composability_bus_payload_root(
                "DEVNET-DEPENDENCY-ORACLE",
                &json!({
                    "lock_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_LOCK_SCHEME,
                    "state_slot_locks": true,
                    "nullifier_locks": true,
                    "amm_reserve_locks": true
                }),
            ),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composability_bus_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "bus_id": self.bus_id,
            "operator_committee_root": self.operator_committee_root,
            "callback_router_root": self.callback_router_root,
            "dependency_oracle_root": self.dependency_oracle_root,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "callback_ttl_blocks": self.callback_ttl_blocks,
            "max_call_legs": self.max_call_legs,
            "max_callbacks": self.max_callbacks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_fee_units": self.max_fee_units,
            "max_disclosure_bps": self.max_disclosure_bps,
            "default_low_fee_lane": self.default_low_fee_lane,
            "encryption_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_ENCRYPTION_SCHEME,
            "pq_auth_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PQ_AUTH_SCHEME,
            "lock_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_LOCK_SCHEME,
            "receipt_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_RECEIPT_SCHEME,
            "callback_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_CALLBACK_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.bus_id, "config bus id")?;
        ensure_non_empty(
            &self.operator_committee_root,
            "config operator committee root",
        )?;
        ensure_non_empty(&self.callback_router_root, "config callback router root")?;
        ensure_non_empty(
            &self.dependency_oracle_root,
            "config dependency oracle root",
        )?;
        ensure_non_empty(&self.default_low_fee_lane, "config low fee lane")?;
        ensure_positive(self.bundle_ttl_blocks, "config bundle ttl")?;
        ensure_positive(self.auth_ttl_blocks, "config auth ttl")?;
        ensure_positive(self.lock_ttl_blocks, "config lock ttl")?;
        ensure_positive(self.callback_ttl_blocks, "config callback ttl")?;
        ensure_positive_usize(self.max_call_legs, "config max call legs")?;
        ensure_positive_usize(self.max_callbacks, "config max callbacks")?;
        ensure_positive(self.min_privacy_set_size, "config privacy set")?;
        ensure_positive(
            self.default_privacy_budget_units,
            "config default privacy budget",
        )?;
        ensure_positive(self.sponsor_budget_units, "config sponsor budget")?;
        ensure_positive(self.max_fee_units, "config max fee")?;
        ensure_bps(self.max_disclosure_bps, "config max disclosure")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBundleAuthorization {
    pub authorization_id: String,
    pub controller_commitment: String,
    pub auth_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub scope_root: String,
    pub policy_root: String,
    pub signature_root: String,
    pub privacy_budget_units: u64,
    pub max_fee_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: AuthorizationStatus,
}

impl PqBundleAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        controller_label: &str,
        auth_public_key: &str,
        kem_public_key: &str,
        scopes: &[String],
        policy: &Value,
        signature_payload: &Value,
        privacy_budget_units: u64,
        max_fee_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        ensure_non_empty(controller_label, "authorization controller")?;
        ensure_non_empty(auth_public_key, "authorization auth public key")?;
        ensure_non_empty(kem_public_key, "authorization kem public key")?;
        ensure_string_set(scopes, "authorization scopes")?;
        ensure_positive(privacy_budget_units, "authorization privacy budget")?;
        ensure_positive(max_fee_units, "authorization max fee")?;
        validate_height_window(issued_at_height, expires_at_height, "authorization")?;

        let controller_commitment =
            private_contract_composability_bus_account_commitment(controller_label);
        let auth_public_key_commitment =
            private_contract_composability_bus_string_root("auth-public-key", auth_public_key);
        let kem_public_key_commitment =
            private_contract_composability_bus_string_root("kem-public-key", kem_public_key);
        let scope_root = private_contract_composability_bus_string_set_root("AUTH-SCOPES", scopes);
        let policy_root = private_contract_composability_bus_payload_root("AUTH-POLICY", policy);
        let signature_root =
            private_contract_composability_bus_payload_root("PQ-AUTH-SIGNATURE", signature_payload);
        let authorization_id = private_contract_composability_bus_authorization_id(
            &controller_commitment,
            &auth_public_key_commitment,
            &kem_public_key_commitment,
            &scope_root,
            issued_at_height,
            nonce,
        );
        let authorization = Self {
            authorization_id,
            controller_commitment,
            auth_public_key_commitment,
            kem_public_key_commitment,
            scope_root,
            policy_root,
            signature_root,
            privacy_budget_units,
            max_fee_units,
            issued_at_height,
            expires_at_height,
            nonce,
            status: AuthorizationStatus::Active,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composability_pq_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "controller_commitment": self.controller_commitment,
            "auth_public_key_commitment": self.auth_public_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "scope_root": self.scope_root,
            "policy_root": self.policy_root,
            "signature_root": self.signature_root,
            "privacy_budget_units": self.privacy_budget_units,
            "max_fee_units": self.max_fee_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "pq_auth_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PQ_AUTH_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("PQ-AUTHORIZATION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.authorization_id, "authorization id")?;
        ensure_non_empty(
            &self.controller_commitment,
            "authorization controller commitment",
        )?;
        ensure_non_empty(
            &self.auth_public_key_commitment,
            "authorization auth key commitment",
        )?;
        ensure_non_empty(
            &self.kem_public_key_commitment,
            "authorization kem key commitment",
        )?;
        ensure_non_empty(&self.scope_root, "authorization scope root")?;
        ensure_non_empty(&self.policy_root, "authorization policy root")?;
        ensure_non_empty(&self.signature_root, "authorization signature root")?;
        ensure_positive(self.privacy_budget_units, "authorization privacy budget")?;
        ensure_positive(self.max_fee_units, "authorization max fee")?;
        validate_height_window(
            self.issued_at_height,
            self.expires_at_height,
            "authorization",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposableCallLeg {
    pub leg_id: String,
    pub leg_index: u64,
    pub call_kind: ComposableCallKind,
    pub contract_id: String,
    pub selector: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub callback_root: String,
    pub dependency_root: String,
    pub proof_root: String,
    pub fee_units: u64,
    pub privacy_cost_units: u64,
    pub nonce: u64,
}

impl ComposableCallLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        leg_index: u64,
        call_kind: ComposableCallKind,
        contract_id: impl Into<String>,
        selector: impl Into<String>,
        asset_in_commitment: impl Into<String>,
        asset_out_commitment: impl Into<String>,
        amount_in_commitment: impl Into<String>,
        amount_out_commitment: impl Into<String>,
        state_reads: &[String],
        state_writes: &[String],
        callback_payload: &Value,
        dependencies: &[String],
        proof_payload: &Value,
        fee_units: u64,
        privacy_cost_units: u64,
        nonce: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let contract_id = contract_id.into();
        let selector = selector.into();
        let asset_in_commitment = asset_in_commitment.into();
        let asset_out_commitment = asset_out_commitment.into();
        let amount_in_commitment = amount_in_commitment.into();
        let amount_out_commitment = amount_out_commitment.into();
        ensure_non_empty(&contract_id, "call leg contract id")?;
        ensure_non_empty(&selector, "call leg selector")?;
        ensure_non_empty(&asset_in_commitment, "call leg asset in commitment")?;
        ensure_non_empty(&asset_out_commitment, "call leg asset out commitment")?;
        ensure_non_empty(&amount_in_commitment, "call leg amount in commitment")?;
        ensure_non_empty(&amount_out_commitment, "call leg amount out commitment")?;
        ensure_string_set(state_reads, "call leg state reads")?;
        ensure_string_set(state_writes, "call leg state writes")?;
        ensure_string_set(dependencies, "call leg dependencies")?;
        ensure_positive(privacy_cost_units, "call leg privacy cost")?;

        let state_read_root =
            private_contract_composability_bus_string_set_root("CALL-STATE-READS", state_reads);
        let state_write_root =
            private_contract_composability_bus_string_set_root("CALL-STATE-WRITES", state_writes);
        let callback_root =
            private_contract_composability_bus_payload_root("CALL-CALLBACK", callback_payload);
        let dependency_root =
            private_contract_composability_bus_string_set_root("CALL-DEPENDENCIES", dependencies);
        let proof_root =
            private_contract_composability_bus_payload_root("CALL-PROOF", proof_payload);
        let leg_id = private_contract_composability_bus_call_leg_id(
            leg_index,
            &call_kind,
            &contract_id,
            &selector,
            &state_read_root,
            &state_write_root,
            &dependency_root,
            nonce,
        );
        let leg = Self {
            leg_id,
            leg_index,
            call_kind,
            contract_id,
            selector,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            amount_out_commitment,
            state_read_root,
            state_write_root,
            callback_root,
            dependency_root,
            proof_root,
            fee_units,
            privacy_cost_units,
            nonce,
        };
        leg.validate()?;
        Ok(leg)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composable_call_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "leg_index": self.leg_index,
            "call_kind": self.call_kind.as_str(),
            "contract_id": self.contract_id,
            "selector": self.selector,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "callback_root": self.callback_root,
            "dependency_root": self.dependency_root,
            "proof_root": self.proof_root,
            "fee_units": self.fee_units,
            "privacy_cost_units": self.privacy_cost_units,
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("CALL-LEG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.leg_id, "call leg id")?;
        ensure_non_empty(&self.contract_id, "call leg contract id")?;
        ensure_non_empty(&self.selector, "call leg selector")?;
        ensure_non_empty(&self.asset_in_commitment, "call leg asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "call leg asset out commitment")?;
        ensure_non_empty(&self.amount_in_commitment, "call leg amount in commitment")?;
        ensure_non_empty(
            &self.amount_out_commitment,
            "call leg amount out commitment",
        )?;
        ensure_non_empty(&self.state_read_root, "call leg state read root")?;
        ensure_non_empty(&self.state_write_root, "call leg state write root")?;
        ensure_non_empty(&self.callback_root, "call leg callback root")?;
        ensure_non_empty(&self.dependency_root, "call leg dependency root")?;
        ensure_non_empty(&self.proof_root, "call leg proof root")?;
        ensure_positive(self.privacy_cost_units, "call leg privacy cost")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCallBundle {
    pub bundle_id: String,
    pub authorization_id: String,
    pub owner_commitment: String,
    pub solver_commitment: String,
    pub call_graph_root: String,
    pub encrypted_payload_root: String,
    pub leg_root: String,
    pub dependency_lock_root: String,
    pub callback_plan_root: String,
    pub fee_asset_commitment: String,
    pub max_fee_units: u64,
    pub sponsor_id: String,
    pub low_fee_lane: String,
    pub privacy_budget_units: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: BundleStatus,
}

impl EncryptedCallBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: impl Into<String>,
        owner_label: &str,
        solver_label: &str,
        legs: &[ComposableCallLeg],
        encrypted_payload: &Value,
        dependency_locks: &[String],
        callback_plan: &Value,
        fee_asset_id: &str,
        max_fee_units: u64,
        sponsor_id: impl Into<String>,
        low_fee_lane: impl Into<String>,
        privacy_budget_units: u64,
        privacy_set_size: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let authorization_id = authorization_id.into();
        let sponsor_id = sponsor_id.into();
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&authorization_id, "bundle authorization id")?;
        ensure_non_empty(owner_label, "bundle owner")?;
        ensure_non_empty(solver_label, "bundle solver")?;
        ensure_call_leg_count(legs.len())?;
        ensure_string_set(dependency_locks, "bundle dependency locks")?;
        ensure_non_empty(fee_asset_id, "bundle fee asset")?;
        ensure_non_empty(&low_fee_lane, "bundle low fee lane")?;
        ensure_positive(max_fee_units, "bundle max fee")?;
        ensure_positive(privacy_budget_units, "bundle privacy budget")?;
        ensure_positive(privacy_set_size, "bundle privacy set")?;
        validate_height_window(submitted_at_height, expires_at_height, "bundle")?;

        let owner_commitment = private_contract_composability_bus_account_commitment(owner_label);
        let solver_commitment = private_contract_composability_bus_account_commitment(solver_label);
        let call_graph_root = private_contract_composability_bus_call_graph_root(legs);
        let encrypted_payload_root = private_contract_composability_bus_payload_root(
            "ENCRYPTED-CALL-BUNDLE",
            encrypted_payload,
        );
        let leg_root = private_contract_composability_bus_call_leg_root(legs);
        let dependency_lock_root = private_contract_composability_bus_string_set_root(
            "BUNDLE-DEPENDENCY-LOCKS",
            dependency_locks,
        );
        let callback_plan_root =
            private_contract_composability_bus_payload_root("BUNDLE-CALLBACK-PLAN", callback_plan);
        let fee_asset_commitment =
            private_contract_composability_bus_asset_commitment(fee_asset_id);
        let bundle_id = private_contract_composability_bus_bundle_id(
            &authorization_id,
            &owner_commitment,
            &solver_commitment,
            &call_graph_root,
            &encrypted_payload_root,
            submitted_at_height,
            nonce,
        );
        let bundle = Self {
            bundle_id,
            authorization_id,
            owner_commitment,
            solver_commitment,
            call_graph_root,
            encrypted_payload_root,
            leg_root,
            dependency_lock_root,
            callback_plan_root,
            fee_asset_commitment,
            max_fee_units,
            sponsor_id,
            low_fee_lane,
            privacy_budget_units,
            privacy_set_size,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: BundleStatus::Submitted,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_encrypted_call_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "authorization_id": self.authorization_id,
            "owner_commitment": self.owner_commitment,
            "solver_commitment": self.solver_commitment,
            "call_graph_root": self.call_graph_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "leg_root": self.leg_root,
            "dependency_lock_root": self.dependency_lock_root,
            "callback_plan_root": self.callback_plan_root,
            "fee_asset_commitment": self.fee_asset_commitment,
            "max_fee_units": self.max_fee_units,
            "sponsor_id": self.sponsor_id,
            "low_fee_lane": self.low_fee_lane,
            "privacy_budget_units": self.privacy_budget_units,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "encryption_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_ENCRYPTION_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root(
            "ENCRYPTED-CALL-BUNDLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.bundle_id, "bundle id")?;
        ensure_non_empty(&self.authorization_id, "bundle authorization id")?;
        ensure_non_empty(&self.owner_commitment, "bundle owner commitment")?;
        ensure_non_empty(&self.solver_commitment, "bundle solver commitment")?;
        ensure_non_empty(&self.call_graph_root, "bundle call graph root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "bundle encrypted payload root",
        )?;
        ensure_non_empty(&self.leg_root, "bundle leg root")?;
        ensure_non_empty(&self.dependency_lock_root, "bundle dependency lock root")?;
        ensure_non_empty(&self.callback_plan_root, "bundle callback plan root")?;
        ensure_non_empty(&self.fee_asset_commitment, "bundle fee asset commitment")?;
        ensure_non_empty(&self.low_fee_lane, "bundle low fee lane")?;
        ensure_positive(self.max_fee_units, "bundle max fee")?;
        ensure_positive(self.privacy_budget_units, "bundle privacy budget")?;
        ensure_positive(self.privacy_set_size, "bundle privacy set")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "bundle")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyLock {
    pub lock_id: String,
    pub bundle_id: String,
    pub contract_id: String,
    pub slot_commitment: String,
    pub read_root: String,
    pub write_root: String,
    pub nullifier_root: String,
    pub lock_order: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: DependencyLockStatus,
}

impl DependencyLock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        contract_id: impl Into<String>,
        slot_commitment: impl Into<String>,
        read_set: &[String],
        write_set: &[String],
        nullifiers: &[String],
        lock_order: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let bundle_id = bundle_id.into();
        let contract_id = contract_id.into();
        let slot_commitment = slot_commitment.into();
        ensure_non_empty(&bundle_id, "dependency lock bundle id")?;
        ensure_non_empty(&contract_id, "dependency lock contract id")?;
        ensure_non_empty(&slot_commitment, "dependency lock slot commitment")?;
        ensure_string_set(read_set, "dependency lock read set")?;
        ensure_string_set(write_set, "dependency lock write set")?;
        ensure_string_set(nullifiers, "dependency lock nullifiers")?;
        validate_height_window(opened_at_height, expires_at_height, "dependency lock")?;

        let read_root = private_contract_composability_bus_string_set_root("LOCK-READS", read_set);
        let write_root =
            private_contract_composability_bus_string_set_root("LOCK-WRITES", write_set);
        let nullifier_root =
            private_contract_composability_bus_string_set_root("LOCK-NULLIFIERS", nullifiers);
        let lock_id = private_contract_composability_bus_dependency_lock_id(
            &bundle_id,
            &contract_id,
            &slot_commitment,
            &read_root,
            &write_root,
            lock_order,
            opened_at_height,
            nonce,
        );
        let lock = Self {
            lock_id,
            bundle_id,
            contract_id,
            slot_commitment,
            read_root,
            write_root,
            nullifier_root,
            lock_order,
            opened_at_height,
            expires_at_height,
            nonce,
            status: DependencyLockStatus::Reserved,
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_dependency_lock",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "lock_id": self.lock_id,
            "bundle_id": self.bundle_id,
            "contract_id": self.contract_id,
            "slot_commitment": self.slot_commitment,
            "read_root": self.read_root,
            "write_root": self.write_root,
            "nullifier_root": self.nullifier_root,
            "lock_order": self.lock_order,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "lock_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_LOCK_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("DEPENDENCY-LOCK", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.lock_id, "dependency lock id")?;
        ensure_non_empty(&self.bundle_id, "dependency lock bundle id")?;
        ensure_non_empty(&self.contract_id, "dependency lock contract id")?;
        ensure_non_empty(&self.slot_commitment, "dependency lock slot commitment")?;
        ensure_non_empty(&self.read_root, "dependency lock read root")?;
        ensure_non_empty(&self.write_root, "dependency lock write root")?;
        ensure_non_empty(&self.nullifier_root, "dependency lock nullifier root")?;
        validate_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "dependency lock",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBundleSponsorship {
    pub sponsorship_id: String,
    pub bundle_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_commitment: String,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub privacy_rebate_units: u64,
    pub low_fee_lane: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeBundleSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        sponsor_label: &str,
        fee_asset_id: &str,
        reserved_fee_units: u64,
        privacy_rebate_units: u64,
        low_fee_lane: impl Into<String>,
        policy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let bundle_id = bundle_id.into();
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&bundle_id, "sponsorship bundle id")?;
        ensure_non_empty(sponsor_label, "sponsorship sponsor")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&low_fee_lane, "sponsorship low fee lane")?;
        ensure_positive(reserved_fee_units, "sponsorship reserved fee")?;
        validate_height_window(opened_at_height, expires_at_height, "sponsorship")?;

        let sponsor_commitment =
            private_contract_composability_bus_account_commitment(sponsor_label);
        let fee_asset_commitment =
            private_contract_composability_bus_asset_commitment(fee_asset_id);
        let policy_root =
            private_contract_composability_bus_payload_root("SPONSORSHIP-POLICY", policy);
        let sponsorship_id = private_contract_composability_bus_sponsorship_id(
            &bundle_id,
            &sponsor_commitment,
            &fee_asset_commitment,
            reserved_fee_units,
            &low_fee_lane,
            opened_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            bundle_id,
            sponsor_commitment,
            fee_asset_commitment,
            reserved_fee_units,
            spent_fee_units: 0,
            privacy_rebate_units,
            low_fee_lane,
            policy_root,
            opened_at_height,
            expires_at_height,
            nonce,
            status: SponsorshipStatus::Offered,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_low_fee_bundle_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "bundle_id": self.bundle_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_commitment": self.fee_asset_commitment,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "privacy_rebate_units": self.privacy_rebate_units,
            "low_fee_lane": self.low_fee_lane,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("LOW-FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.bundle_id, "sponsorship bundle id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor commitment")?;
        ensure_non_empty(
            &self.fee_asset_commitment,
            "sponsorship fee asset commitment",
        )?;
        ensure_non_empty(&self.low_fee_lane, "sponsorship low fee lane")?;
        ensure_non_empty(&self.policy_root, "sponsorship policy root")?;
        ensure_positive(self.reserved_fee_units, "sponsorship reserved fee")?;
        if self.spent_fee_units > self.reserved_fee_units {
            return Err("sponsorship spent fee exceeds reserve".to_string());
        }
        validate_height_window(self.opened_at_height, self.expires_at_height, "sponsorship")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub category: PrivacyBudgetCategory,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub disclosure_bps: u64,
    pub privacy_set_size: u64,
    pub proof_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
    pub status: ReceiptStatus,
}

impl PrivacyBudgetReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        category: PrivacyBudgetCategory,
        spent_units: u64,
        remaining_units: u64,
        disclosure_bps: u64,
        privacy_set_size: u64,
        proof: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let bundle_id = bundle_id.into();
        ensure_non_empty(&bundle_id, "privacy receipt bundle id")?;
        ensure_positive(spent_units, "privacy receipt spent units")?;
        ensure_bps(disclosure_bps, "privacy receipt disclosure")?;
        ensure_positive(privacy_set_size, "privacy receipt privacy set")?;

        let proof_root =
            private_contract_composability_bus_payload_root("PRIVACY-BUDGET-PROOF", proof);
        let receipt_id = private_contract_composability_bus_privacy_receipt_id(
            &bundle_id,
            category,
            spent_units,
            remaining_units,
            disclosure_bps,
            &proof_root,
            emitted_at_height,
            sequence,
        );
        let receipt = Self {
            receipt_id,
            bundle_id,
            category,
            spent_units,
            remaining_units,
            disclosure_bps,
            privacy_set_size,
            proof_root,
            emitted_at_height,
            sequence,
            status: ReceiptStatus::Published,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_privacy_budget_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "category": self.category.as_str(),
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "disclosure_bps": self.disclosure_bps,
            "privacy_set_size": self.privacy_set_size,
            "proof_root": self.proof_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "receipt_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_RECEIPT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root(
            "PRIVACY-BUDGET-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.receipt_id, "privacy receipt id")?;
        ensure_non_empty(&self.bundle_id, "privacy receipt bundle id")?;
        ensure_positive(self.spent_units, "privacy receipt spent units")?;
        ensure_bps(self.disclosure_bps, "privacy receipt disclosure")?;
        ensure_positive(self.privacy_set_size, "privacy receipt privacy set")?;
        ensure_non_empty(&self.proof_root, "privacy receipt proof root")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallbackReceipt {
    pub callback_id: String,
    pub bundle_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub selector: String,
    pub encrypted_payload_root: String,
    pub ack_root: String,
    pub scheduled_at_height: u64,
    pub expires_at_height: u64,
    pub delivered_at_height: u64,
    pub sequence: u64,
    pub status: CallbackStatus,
}

impl ContractCallbackReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        source_contract_id: impl Into<String>,
        target_contract_id: impl Into<String>,
        selector: impl Into<String>,
        encrypted_payload: &Value,
        ack_payload: &Value,
        scheduled_at_height: u64,
        expires_at_height: u64,
        sequence: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let bundle_id = bundle_id.into();
        let source_contract_id = source_contract_id.into();
        let target_contract_id = target_contract_id.into();
        let selector = selector.into();
        ensure_non_empty(&bundle_id, "callback bundle id")?;
        ensure_non_empty(&source_contract_id, "callback source contract")?;
        ensure_non_empty(&target_contract_id, "callback target contract")?;
        ensure_non_empty(&selector, "callback selector")?;
        validate_height_window(scheduled_at_height, expires_at_height, "callback")?;

        let encrypted_payload_root = private_contract_composability_bus_payload_root(
            "CALLBACK-ENCRYPTED-PAYLOAD",
            encrypted_payload,
        );
        let ack_root = private_contract_composability_bus_payload_root("CALLBACK-ACK", ack_payload);
        let callback_id = private_contract_composability_bus_callback_id(
            &bundle_id,
            &source_contract_id,
            &target_contract_id,
            &selector,
            &encrypted_payload_root,
            scheduled_at_height,
            sequence,
        );
        let callback = Self {
            callback_id,
            bundle_id,
            source_contract_id,
            target_contract_id,
            selector,
            encrypted_payload_root,
            ack_root,
            scheduled_at_height,
            expires_at_height,
            delivered_at_height: 0,
            sequence,
            status: CallbackStatus::Scheduled,
        };
        callback.validate()?;
        Ok(callback)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_callback_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "callback_id": self.callback_id,
            "bundle_id": self.bundle_id,
            "source_contract_id": self.source_contract_id,
            "target_contract_id": self.target_contract_id,
            "selector": self.selector,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ack_root": self.ack_root,
            "scheduled_at_height": self.scheduled_at_height,
            "expires_at_height": self.expires_at_height,
            "delivered_at_height": self.delivered_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "callback_scheme": PRIVATE_CONTRACT_COMPOSABILITY_BUS_CALLBACK_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("CALLBACK-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.callback_id, "callback id")?;
        ensure_non_empty(&self.bundle_id, "callback bundle id")?;
        ensure_non_empty(&self.source_contract_id, "callback source contract")?;
        ensure_non_empty(&self.target_contract_id, "callback target contract")?;
        ensure_non_empty(&self.selector, "callback selector")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "callback encrypted payload root",
        )?;
        ensure_non_empty(&self.ack_root, "callback ack root")?;
        validate_height_window(self.scheduled_at_height, self.expires_at_height, "callback")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposabilityPublicRecord {
    pub public_record_id: String,
    pub subject_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub disclosure_bps: u64,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl ComposabilityPublicRecord {
    pub fn new(
        subject_id: impl Into<String>,
        record_kind: impl Into<String>,
        payload: &Value,
        disclosure_bps: u64,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateContractComposabilityBusResult<Self> {
        let subject_id = subject_id.into();
        let record_kind = record_kind.into();
        ensure_non_empty(&subject_id, "public record subject id")?;
        ensure_non_empty(&record_kind, "public record kind")?;
        ensure_bps(disclosure_bps, "public record disclosure")?;

        let payload_root =
            private_contract_composability_bus_payload_root("PUBLIC-RECORD-PAYLOAD", payload);
        let public_record_id = private_contract_composability_bus_public_record_id(
            &subject_id,
            &record_kind,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            public_record_id,
            subject_id,
            record_kind,
            payload_root,
            disclosure_bps,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composability_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "public_record_id": self.public_record_id,
            "subject_id": self.subject_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "disclosure_bps": self.disclosure_bps,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        ensure_non_empty(&self.public_record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        ensure_bps(self.disclosure_bps, "public record disclosure")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractComposabilityBusRoots {
    pub config_root: String,
    pub authorization_root: String,
    pub bundle_root: String,
    pub call_leg_root: String,
    pub dependency_lock_root: String,
    pub sponsorship_root: String,
    pub privacy_receipt_root: String,
    pub callback_receipt_root: String,
    pub public_record_root: String,
    pub active_bundle_root: String,
}

impl PrivateContractComposabilityBusRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composability_bus_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "authorization_root": self.authorization_root,
            "bundle_root": self.bundle_root,
            "call_leg_root": self.call_leg_root,
            "dependency_lock_root": self.dependency_lock_root,
            "sponsorship_root": self.sponsorship_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "callback_receipt_root": self.callback_receipt_root,
            "public_record_root": self.public_record_root,
            "active_bundle_root": self.active_bundle_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractComposabilityBusCounters {
    pub authorization_count: u64,
    pub active_authorization_count: u64,
    pub bundle_count: u64,
    pub active_bundle_count: u64,
    pub token_leg_count: u64,
    pub lending_leg_count: u64,
    pub perp_leg_count: u64,
    pub amm_leg_count: u64,
    pub call_leg_count: u64,
    pub live_dependency_lock_count: u64,
    pub sponsorship_count: u64,
    pub usable_sponsorship_count: u64,
    pub privacy_receipt_count: u64,
    pub callback_receipt_count: u64,
    pub public_record_count: u64,
    pub aggregate_max_fee_units: u64,
    pub aggregate_spent_fee_units: u64,
    pub aggregate_privacy_spent_units: u64,
    pub aggregate_privacy_remaining_units: u64,
}

impl PrivateContractComposabilityBusCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_composability_bus_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "authorization_count": self.authorization_count,
            "active_authorization_count": self.active_authorization_count,
            "bundle_count": self.bundle_count,
            "active_bundle_count": self.active_bundle_count,
            "token_leg_count": self.token_leg_count,
            "lending_leg_count": self.lending_leg_count,
            "perp_leg_count": self.perp_leg_count,
            "amm_leg_count": self.amm_leg_count,
            "call_leg_count": self.call_leg_count,
            "live_dependency_lock_count": self.live_dependency_lock_count,
            "sponsorship_count": self.sponsorship_count,
            "usable_sponsorship_count": self.usable_sponsorship_count,
            "privacy_receipt_count": self.privacy_receipt_count,
            "callback_receipt_count": self.callback_receipt_count,
            "public_record_count": self.public_record_count,
            "aggregate_max_fee_units": self.aggregate_max_fee_units,
            "aggregate_spent_fee_units": self.aggregate_spent_fee_units,
            "aggregate_privacy_spent_units": self.aggregate_privacy_spent_units,
            "aggregate_privacy_remaining_units": self.aggregate_privacy_remaining_units,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractComposabilityBusState {
    pub config: PrivateContractComposabilityBusConfig,
    pub height: u64,
    pub nonce: u64,
    pub authorizations: BTreeMap<String, PqBundleAuthorization>,
    pub bundles: BTreeMap<String, EncryptedCallBundle>,
    pub call_legs: BTreeMap<String, ComposableCallLeg>,
    pub dependency_locks: BTreeMap<String, DependencyLock>,
    pub sponsorships: BTreeMap<String, LowFeeBundleSponsorship>,
    pub privacy_receipts: BTreeMap<String, PrivacyBudgetReceipt>,
    pub callback_receipts: BTreeMap<String, ContractCallbackReceipt>,
    pub public_records: BTreeMap<String, ComposabilityPublicRecord>,
}

impl Default for PrivateContractComposabilityBusState {
    fn default() -> Self {
        Self::new(PrivateContractComposabilityBusConfig::default())
    }
}

impl PrivateContractComposabilityBusState {
    pub fn new(config: PrivateContractComposabilityBusConfig) -> Self {
        Self {
            config,
            height: PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEVNET_HEIGHT,
            nonce: 0,
            authorizations: BTreeMap::new(),
            bundles: BTreeMap::new(),
            call_legs: BTreeMap::new(),
            dependency_locks: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            privacy_receipts: BTreeMap::new(),
            callback_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(PrivateContractComposabilityBusConfig::devnet())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractComposabilityBusResult<String> {
        self.height = height;
        self.validate()
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqBundleAuthorization,
    ) -> PrivateContractComposabilityBusResult<String> {
        authorization.validate()?;
        let id = authorization.authorization_id.clone();
        insert_unique(
            &mut self.authorizations,
            id.clone(),
            authorization,
            "authorization",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_call_leg(
        &mut self,
        call_leg: ComposableCallLeg,
    ) -> PrivateContractComposabilityBusResult<String> {
        call_leg.validate()?;
        let id = call_leg.leg_id.clone();
        insert_unique(&mut self.call_legs, id.clone(), call_leg, "call leg")?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_bundle(
        &mut self,
        bundle: EncryptedCallBundle,
    ) -> PrivateContractComposabilityBusResult<String> {
        bundle.validate()?;
        if !self.authorizations.contains_key(&bundle.authorization_id) {
            return Err("bundle references unknown authorization".to_string());
        }
        let id = bundle.bundle_id.clone();
        insert_unique(&mut self.bundles, id.clone(), bundle, "bundle")?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_dependency_lock(
        &mut self,
        lock: DependencyLock,
    ) -> PrivateContractComposabilityBusResult<String> {
        lock.validate()?;
        if !self.bundles.contains_key(&lock.bundle_id) {
            return Err("dependency lock references unknown bundle".to_string());
        }
        let id = lock.lock_id.clone();
        insert_unique(
            &mut self.dependency_locks,
            id.clone(),
            lock,
            "dependency lock",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeBundleSponsorship,
    ) -> PrivateContractComposabilityBusResult<String> {
        sponsorship.validate()?;
        if !self.bundles.contains_key(&sponsorship.bundle_id) {
            return Err("sponsorship references unknown bundle".to_string());
        }
        let id = sponsorship.sponsorship_id.clone();
        insert_unique(
            &mut self.sponsorships,
            id.clone(),
            sponsorship,
            "sponsorship",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_privacy_receipt(
        &mut self,
        receipt: PrivacyBudgetReceipt,
    ) -> PrivateContractComposabilityBusResult<String> {
        receipt.validate()?;
        if !self.bundles.contains_key(&receipt.bundle_id) {
            return Err("privacy receipt references unknown bundle".to_string());
        }
        let id = receipt.receipt_id.clone();
        insert_unique(
            &mut self.privacy_receipts,
            id.clone(),
            receipt,
            "privacy receipt",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn insert_callback_receipt(
        &mut self,
        receipt: ContractCallbackReceipt,
    ) -> PrivateContractComposabilityBusResult<String> {
        receipt.validate()?;
        if !self.bundles.contains_key(&receipt.bundle_id) {
            return Err("callback receipt references unknown bundle".to_string());
        }
        let id = receipt.callback_id.clone();
        insert_unique(
            &mut self.callback_receipts,
            id.clone(),
            receipt,
            "callback receipt",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn publish_public_record(
        &mut self,
        subject_id: &str,
        record_kind: &str,
        payload: &Value,
        disclosure_bps: u64,
    ) -> PrivateContractComposabilityBusResult<String> {
        let sequence = self.public_records.len() as u64;
        let record = ComposabilityPublicRecord::new(
            subject_id,
            record_kind,
            payload,
            disclosure_bps,
            self.height,
            sequence,
        )?;
        let id = record.public_record_id.clone();
        insert_unique(
            &mut self.public_records,
            id.clone(),
            record,
            "public record",
        )?;
        self.validate()?;
        Ok(id)
    }

    pub fn active_bundle_ids(&self) -> Vec<String> {
        self.bundles
            .values()
            .filter(|bundle| bundle.status.active())
            .map(|bundle| bundle.bundle_id.clone())
            .collect()
    }

    pub fn roots(&self) -> PrivateContractComposabilityBusRoots {
        PrivateContractComposabilityBusRoots {
            config_root: self.config.state_root(),
            authorization_root: private_contract_composability_bus_collection_root(
                "AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(PqBundleAuthorization::public_record)
                    .collect(),
            ),
            bundle_root: private_contract_composability_bus_collection_root(
                "BUNDLES",
                self.bundles
                    .values()
                    .map(EncryptedCallBundle::public_record)
                    .collect(),
            ),
            call_leg_root: private_contract_composability_bus_collection_root(
                "CALL-LEGS",
                self.call_legs
                    .values()
                    .map(ComposableCallLeg::public_record)
                    .collect(),
            ),
            dependency_lock_root: private_contract_composability_bus_collection_root(
                "DEPENDENCY-LOCKS",
                self.dependency_locks
                    .values()
                    .map(DependencyLock::public_record)
                    .collect(),
            ),
            sponsorship_root: private_contract_composability_bus_collection_root(
                "SPONSORSHIPS",
                self.sponsorships
                    .values()
                    .map(LowFeeBundleSponsorship::public_record)
                    .collect(),
            ),
            privacy_receipt_root: private_contract_composability_bus_collection_root(
                "PRIVACY-RECEIPTS",
                self.privacy_receipts
                    .values()
                    .map(PrivacyBudgetReceipt::public_record)
                    .collect(),
            ),
            callback_receipt_root: private_contract_composability_bus_collection_root(
                "CALLBACK-RECEIPTS",
                self.callback_receipts
                    .values()
                    .map(ContractCallbackReceipt::public_record)
                    .collect(),
            ),
            public_record_root: private_contract_composability_bus_collection_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(ComposabilityPublicRecord::public_record)
                    .collect(),
            ),
            active_bundle_root: private_contract_composability_bus_payload_root(
                "ACTIVE-BUNDLES",
                &json!(self.active_bundle_ids()),
            ),
        }
    }

    pub fn counters(&self) -> PrivateContractComposabilityBusCounters {
        PrivateContractComposabilityBusCounters {
            authorization_count: self.authorizations.len() as u64,
            active_authorization_count: self
                .authorizations
                .values()
                .filter(|authorization| authorization.status.usable())
                .count() as u64,
            bundle_count: self.bundles.len() as u64,
            active_bundle_count: self
                .bundles
                .values()
                .filter(|bundle| bundle.status.active())
                .count() as u64,
            token_leg_count: self
                .call_legs
                .values()
                .filter(|leg| leg.call_kind.is_token())
                .count() as u64,
            lending_leg_count: self
                .call_legs
                .values()
                .filter(|leg| leg.call_kind.is_lending())
                .count() as u64,
            perp_leg_count: self
                .call_legs
                .values()
                .filter(|leg| leg.call_kind.is_perp())
                .count() as u64,
            amm_leg_count: self
                .call_legs
                .values()
                .filter(|leg| leg.call_kind.is_amm())
                .count() as u64,
            call_leg_count: self.call_legs.len() as u64,
            live_dependency_lock_count: self
                .dependency_locks
                .values()
                .filter(|lock| lock.status.live())
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            usable_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.usable())
                .count() as u64,
            privacy_receipt_count: self.privacy_receipts.len() as u64,
            callback_receipt_count: self.callback_receipts.len() as u64,
            public_record_count: self.public_records.len() as u64,
            aggregate_max_fee_units: self
                .bundles
                .values()
                .map(|bundle| bundle.max_fee_units)
                .sum(),
            aggregate_spent_fee_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_fee_units)
                .sum(),
            aggregate_privacy_spent_units: self
                .privacy_receipts
                .values()
                .map(|receipt| receipt.spent_units)
                .sum(),
            aggregate_privacy_remaining_units: self
                .privacy_receipts
                .values()
                .map(|receipt| receipt.remaining_units)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_contract_composability_bus_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
            "active_bundle_ids": self.active_bundle_ids(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_contract_composability_bus_record_root(
            "STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> PrivateContractComposabilityBusResult<String> {
        self.config.validate()?;
        if self.authorizations.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_AUTHORIZATIONS {
            return Err("authorization capacity exceeded".to_string());
        }
        if self.bundles.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_BUNDLES {
            return Err("bundle capacity exceeded".to_string());
        }
        if self.dependency_locks.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_DEPENDENCY_LOCKS {
            return Err("dependency lock capacity exceeded".to_string());
        }
        if self.sponsorships.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity exceeded".to_string());
        }
        if self.privacy_receipts.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_PRIVACY_RECEIPTS {
            return Err("privacy receipt capacity exceeded".to_string());
        }
        if self.callback_receipts.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_CALLBACK_RECEIPTS {
            return Err("callback receipt capacity exceeded".to_string());
        }
        if self.public_records.len() > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }

        for authorization in self.authorizations.values() {
            authorization.validate()?;
            if authorization.status.usable() && authorization.expires_at_height < self.height {
                return Err("active authorization expired before bus height".to_string());
            }
            if authorization.max_fee_units > self.config.max_fee_units {
                return Err("authorization max fee exceeds config".to_string());
            }
        }

        for leg in self.call_legs.values() {
            leg.validate()?;
        }

        for bundle in self.bundles.values() {
            bundle.validate()?;
            let authorization = self
                .authorizations
                .get(&bundle.authorization_id)
                .ok_or_else(|| "bundle references unknown authorization".to_string())?;
            if !authorization.status.usable() {
                return Err("bundle authorization is not usable".to_string());
            }
            if bundle.max_fee_units > authorization.max_fee_units {
                return Err("bundle max fee exceeds authorization".to_string());
            }
            if bundle.privacy_budget_units > authorization.privacy_budget_units {
                return Err("bundle privacy budget exceeds authorization".to_string());
            }
            if bundle.privacy_set_size < self.config.min_privacy_set_size {
                return Err("bundle privacy set below configured floor".to_string());
            }
            if bundle.status.active() && bundle.expires_at_height < self.height {
                return Err("active bundle expired before bus height".to_string());
            }
        }

        let mut live_lock_keys = BTreeSet::new();
        for lock in self.dependency_locks.values() {
            lock.validate()?;
            if !self.bundles.contains_key(&lock.bundle_id) {
                return Err("dependency lock references unknown bundle".to_string());
            }
            if lock.status.live() && lock.expires_at_height < self.height {
                return Err("live dependency lock expired before bus height".to_string());
            }
            if lock.status.live() {
                let lock_key = (
                    lock.contract_id.clone(),
                    lock.slot_commitment.clone(),
                    lock.write_root.clone(),
                    lock.nullifier_root.clone(),
                );
                if !live_lock_keys.insert(lock_key) {
                    return Err("conflicting live dependency lock".to_string());
                }
            }
        }

        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.bundles.contains_key(&sponsorship.bundle_id) {
                return Err("sponsorship references unknown bundle".to_string());
            }
            if sponsorship.reserved_fee_units > self.config.sponsor_budget_units {
                return Err("sponsorship exceeds configured sponsor budget".to_string());
            }
            if sponsorship.status.usable() && sponsorship.expires_at_height < self.height {
                return Err("usable sponsorship expired before bus height".to_string());
            }
        }

        for receipt in self.privacy_receipts.values() {
            receipt.validate()?;
            if !self.bundles.contains_key(&receipt.bundle_id) {
                return Err("privacy receipt references unknown bundle".to_string());
            }
            if receipt.disclosure_bps > self.config.max_disclosure_bps {
                return Err("privacy receipt disclosure exceeds config".to_string());
            }
            if receipt.privacy_set_size < self.config.min_privacy_set_size {
                return Err("privacy receipt set below configured floor".to_string());
            }
        }

        for callback in self.callback_receipts.values() {
            callback.validate()?;
            if !self.bundles.contains_key(&callback.bundle_id) {
                return Err("callback receipt references unknown bundle".to_string());
            }
            if callback.status == CallbackStatus::Scheduled
                && callback.expires_at_height < self.height
            {
                return Err("scheduled callback expired before bus height".to_string());
            }
        }

        for record in self.public_records.values() {
            record.validate()?;
            if record.disclosure_bps > self.config.max_disclosure_bps {
                return Err("public record disclosure exceeds config".to_string());
            }
        }

        Ok(self.state_root())
    }
}

pub fn private_contract_composability_bus_account_commitment(account_label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-ACCOUNT",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
        ],
        32,
    )
}

pub fn private_contract_composability_bus_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-ASSET",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_id),
        ],
        32,
    )
}

pub fn private_contract_composability_bus_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-STRING",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_contract_composability_bus_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_contract_composability_bus_record_root(domain: &str, payload: &Value) -> String {
    private_contract_composability_bus_payload_root(domain, payload)
}

pub fn private_contract_composability_bus_collection_root(
    domain: &str,
    records: Vec<Value>,
) -> String {
    merkle_root(
        &format!("PRIVATE-CONTRACT-COMPOSABILITY-BUS-{domain}"),
        &records,
    )
}

pub fn private_contract_composability_bus_string_set_root(
    domain: &str,
    values: &[String],
) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-CONTRACT-COMPOSABILITY-BUS-{domain}"),
        &leaves,
    )
}

pub fn private_contract_composability_bus_call_leg_root(legs: &[ComposableCallLeg]) -> String {
    private_contract_composability_bus_collection_root(
        "CALL-LEG-PLAN",
        legs.iter()
            .map(ComposableCallLeg::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_contract_composability_bus_call_graph_root(legs: &[ComposableCallLeg]) -> String {
    let records = legs
        .iter()
        .map(|leg| {
            json!({
                "leg_id": leg.leg_id,
                "leg_index": leg.leg_index,
                "call_kind": leg.call_kind.as_str(),
                "contract_id": leg.contract_id,
                "selector": leg.selector,
                "dependency_root": leg.dependency_root,
                "callback_root": leg.callback_root,
            })
        })
        .collect::<Vec<_>>();
    private_contract_composability_bus_collection_root("CALL-GRAPH", records)
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_authorization_id(
    controller_commitment: &str,
    auth_public_key_commitment: &str,
    kem_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(controller_commitment),
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
pub fn private_contract_composability_bus_call_leg_id(
    leg_index: u64,
    call_kind: &ComposableCallKind,
    contract_id: &str,
    selector: &str,
    state_read_root: &str,
    state_write_root: &str,
    dependency_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-CALL-LEG-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(leg_index as i128),
            HashPart::Str(&call_kind.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(state_read_root),
            HashPart::Str(state_write_root),
            HashPart::Str(dependency_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_bundle_id(
    authorization_id: &str,
    owner_commitment: &str,
    solver_commitment: &str,
    call_graph_root: &str,
    encrypted_payload_root: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-BUNDLE-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(authorization_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(solver_commitment),
            HashPart::Str(call_graph_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_dependency_lock_id(
    bundle_id: &str,
    contract_id: &str,
    slot_commitment: &str,
    read_root: &str,
    write_root: &str,
    lock_order: u64,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-DEPENDENCY-LOCK-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(contract_id),
            HashPart::Str(slot_commitment),
            HashPart::Str(read_root),
            HashPart::Str(write_root),
            HashPart::Int(lock_order as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_sponsorship_id(
    bundle_id: &str,
    sponsor_commitment: &str,
    fee_asset_commitment: &str,
    reserved_fee_units: u64,
    low_fee_lane: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-SPONSORSHIP-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_commitment),
            HashPart::Int(reserved_fee_units as i128),
            HashPart::Str(low_fee_lane),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_privacy_receipt_id(
    bundle_id: &str,
    category: PrivacyBudgetCategory,
    spent_units: u64,
    remaining_units: u64,
    disclosure_bps: u64,
    proof_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-PRIVACY-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(category.as_str()),
            HashPart::Int(spent_units as i128),
            HashPart::Int(remaining_units as i128),
            HashPart::Int(disclosure_bps as i128),
            HashPart::Str(proof_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_composability_bus_callback_id(
    bundle_id: &str,
    source_contract_id: &str,
    target_contract_id: &str,
    selector: &str,
    encrypted_payload_root: &str,
    scheduled_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-CALLBACK-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(source_contract_id),
            HashPart::Str(target_contract_id),
            HashPart::Str(selector),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(scheduled_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_contract_composability_bus_public_record_id(
    subject_id: &str,
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-COMPOSABILITY-BUS-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_CONTRACT_COMPOSABILITY_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateContractComposabilityBusResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateContractComposabilityBusResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_positive_usize(value: usize, label: &str) -> PrivateContractComposabilityBusResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateContractComposabilityBusResult<()> {
    if value > PRIVATE_CONTRACT_COMPOSABILITY_BUS_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_distinct_strings(
    values: &[String],
    label: &str,
) -> PrivateContractComposabilityBusResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateContractComposabilityBusResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    ensure_distinct_strings(values, label)
}

fn ensure_call_leg_count(count: usize) -> PrivateContractComposabilityBusResult<()> {
    if count == 0 {
        return Err("bundle requires at least one call leg".to_string());
    }
    if count > PRIVATE_CONTRACT_COMPOSABILITY_BUS_DEFAULT_MAX_CALL_LEGS {
        return Err("bundle has too many call legs".to_string());
    }
    Ok(())
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateContractComposabilityBusResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivateContractComposabilityBusResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, record);
    Ok(())
}
