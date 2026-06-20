use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialDefiVaultRouterResult<T> = Result<T, String>;

pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-confidential-defi-vault-router-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-threshold-vault-route-envelope-devnet-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-vault-route-commitment-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-vault-router-authorization-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_RECEIPT_SCHEME: &str =
    "zk-slippage-risk-receipt-devnet-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_BATCHING_POLICY: &str =
    "low-fee-private-vault-route-batch-v1";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 48;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 10;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MAX_SLIPPAGE_BPS: u64 = 85;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MAX_RISK_BPS: u64 = 2_500;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MIN_AUTH_BOND_UNITS: u64 = 500_000;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_SPONSOR_REBATE_BPS: u64 = 6_500;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEVNET_HEIGHT: u64 = 384;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_DEVNET_LOW_FEE_LANE: &str =
    "devnet-confidential-vault-routes";
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_LEGS: usize = 32;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_COMMITMENTS: usize = 16_384;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_AUTHORIZATIONS: usize = 512;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_FEE_SPONSORSHIPS: usize = 8_192;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_BATCHES: usize = 2_048;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_RECEIPTS: usize = 65_536;
pub const CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_PUBLIC_RECORDS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouteKind {
    Swap,
    LendSupply,
    LendBorrow,
    LendRepay,
    LendWithdraw,
    PerpOpen,
    PerpClose,
    PerpAdjustMargin,
    PerpFundingHedge,
    Composite,
    Custom(String),
}

impl VaultRouteKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Swap => "swap".to_string(),
            Self::LendSupply => "lend_supply".to_string(),
            Self::LendBorrow => "lend_borrow".to_string(),
            Self::LendRepay => "lend_repay".to_string(),
            Self::LendWithdraw => "lend_withdraw".to_string(),
            Self::PerpOpen => "perp_open".to_string(),
            Self::PerpClose => "perp_close".to_string(),
            Self::PerpAdjustMargin => "perp_adjust_margin".to_string(),
            Self::PerpFundingHedge => "perp_funding_hedge".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_swap(&self) -> bool {
        matches!(self, Self::Swap)
    }

    pub fn is_lending(&self) -> bool {
        matches!(
            self,
            Self::LendSupply | Self::LendBorrow | Self::LendRepay | Self::LendWithdraw
        )
    }

    pub fn is_perp(&self) -> bool {
        matches!(
            self,
            Self::PerpOpen | Self::PerpClose | Self::PerpAdjustMargin | Self::PerpFundingHedge
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultLegKind {
    SwapAmm,
    SwapRfq,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingWithdraw,
    PerpOpen,
    PerpClose,
    PerpFunding,
    CollateralMove,
    FeeSponsor,
    Settlement,
}

impl VaultLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapAmm => "swap_amm",
            Self::SwapRfq => "swap_rfq",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingWithdraw => "lending_withdraw",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::PerpFunding => "perp_funding",
            Self::CollateralMove => "collateral_move",
            Self::FeeSponsor => "fee_sponsor",
            Self::Settlement => "settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouteStatus {
    Submitted,
    Authorized,
    Batched,
    Executing,
    Settled,
    Expired,
    Rejected,
    Challenged,
}

impl VaultRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::Batched => "batched",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Authorized | Self::Batched | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl PqAuthorizationStatus {
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
pub enum SponsorshipStatus {
    Open,
    Reserved,
    Spent,
    Released,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeBatchStatus {
    Collecting,
    Sealed,
    Executing,
    Settled,
    Expired,
    Challenged,
}

impl LowFeeBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Collecting | Self::Sealed | Self::Executing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PendingDelay,
    Published,
    Final,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingDelay => "pending_delay",
            Self::Published => "published",
            Self::Final => "final",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDefiVaultRouterConfig {
    pub router_id: String,
    pub operator_committee_root: String,
    pub threshold_key_epoch_root: String,
    pub risk_oracle_root: String,
    pub route_ttl_blocks: u64,
    pub pq_auth_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub max_route_legs: usize,
    pub max_batch_routes: usize,
    pub max_slippage_bps: u64,
    pub max_risk_bps: u64,
    pub min_authorization_bond_units: u64,
    pub sponsor_rebate_bps: u64,
    pub default_low_fee_lane: String,
}

impl Default for ConfidentialDefiVaultRouterConfig {
    fn default() -> Self {
        Self {
            router_id: confidential_defi_vault_router_string_root("router", "default-vault-router"),
            operator_committee_root: confidential_defi_vault_router_string_root(
                "operator-committee",
                "default-devnet-committee",
            ),
            threshold_key_epoch_root: confidential_defi_vault_router_string_root(
                "threshold-key-epoch",
                "epoch-0",
            ),
            risk_oracle_root: confidential_defi_vault_router_string_root(
                "risk-oracle",
                "default-private-risk-oracle",
            ),
            route_ttl_blocks: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            pq_auth_ttl_blocks: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_AUTH_TTL_BLOCKS,
            batch_window_blocks: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_BATCH_WINDOW_BLOCKS,
            receipt_delay_blocks: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_RECEIPT_DELAY_BLOCKS,
            max_route_legs: CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_LEGS,
            max_batch_routes: 256,
            max_slippage_bps: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MAX_SLIPPAGE_BPS,
            max_risk_bps: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MAX_RISK_BPS,
            min_authorization_bond_units:
                CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_MIN_AUTH_BOND_UNITS,
            sponsor_rebate_bps: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEFAULT_SPONSOR_REBATE_BPS,
            default_low_fee_lane: CONFIDENTIAL_DEFI_VAULT_ROUTER_DEVNET_LOW_FEE_LANE.to_string(),
        }
    }
}

impl ConfidentialDefiVaultRouterConfig {
    pub fn devnet() -> Self {
        Self {
            router_id: confidential_defi_vault_router_string_root("router", "devnet-vault-router"),
            operator_committee_root: confidential_defi_vault_router_payload_root(
                "DEVNET-VAULT-ROUTER-COMMITTEE",
                &json!({
                    "members": ["devnet-sequencer-a", "devnet-risk-watchtower-b", "devnet-vault-operator-c"],
                    "threshold": 2
                }),
            ),
            threshold_key_epoch_root: confidential_defi_vault_router_payload_root(
                "DEVNET-VAULT-ROUTER-THRESHOLD-KEY",
                &json!({
                    "epoch": 5,
                    "scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_ENCRYPTION_SCHEME,
                    "shares": 7,
                    "threshold": 4
                }),
            ),
            risk_oracle_root: confidential_defi_vault_router_payload_root(
                "DEVNET-VAULT-ROUTER-RISK-ORACLE",
                &json!({
                    "oracles": ["devnet-median-wxmr-usdd", "devnet-perp-funding-index"],
                    "risk_receipts": true,
                    "private_buckets": true
                }),
            ),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_config",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "router_id": self.router_id,
            "operator_committee_root": self.operator_committee_root,
            "threshold_key_epoch_root": self.threshold_key_epoch_root,
            "risk_oracle_root": self.risk_oracle_root,
            "route_ttl_blocks": self.route_ttl_blocks,
            "pq_auth_ttl_blocks": self.pq_auth_ttl_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "max_route_legs": self.max_route_legs,
            "max_batch_routes": self.max_batch_routes,
            "max_slippage_bps": self.max_slippage_bps,
            "max_risk_bps": self.max_risk_bps,
            "min_authorization_bond_units": self.min_authorization_bond_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "default_low_fee_lane": self.default_low_fee_lane,
            "encryption_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_ENCRYPTION_SCHEME,
            "commitment_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_COMMITMENT_SCHEME,
            "pq_auth_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_PQ_AUTH_SCHEME,
            "receipt_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_RECEIPT_SCHEME,
            "batching_policy": CONFIDENTIAL_DEFI_VAULT_ROUTER_BATCHING_POLICY,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.router_id, "config router id")?;
        ensure_non_empty(
            &self.operator_committee_root,
            "config operator committee root",
        )?;
        ensure_non_empty(&self.threshold_key_epoch_root, "config threshold key root")?;
        ensure_non_empty(&self.risk_oracle_root, "config risk oracle root")?;
        ensure_non_empty(&self.default_low_fee_lane, "config low fee lane")?;
        ensure_positive(self.route_ttl_blocks, "config route ttl")?;
        ensure_positive(self.pq_auth_ttl_blocks, "config pq auth ttl")?;
        ensure_positive(self.batch_window_blocks, "config batch window")?;
        ensure_positive(self.receipt_delay_blocks, "config receipt delay")?;
        if self.max_route_legs == 0 {
            return Err("config max route legs must be positive".to_string());
        }
        if self.max_batch_routes == 0 {
            return Err("config max batch routes must be positive".to_string());
        }
        ensure_bps(self.max_slippage_bps, "config max slippage")?;
        ensure_bps(self.max_risk_bps, "config max risk")?;
        ensure_bps(self.sponsor_rebate_bps, "config sponsor rebate")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVaultRouterAuthorization {
    pub authorization_id: String,
    pub solver_id: String,
    pub operator_commitment: String,
    pub auth_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub scope_root: String,
    pub policy_root: String,
    pub signature_root: String,
    pub bond_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PqAuthorizationStatus,
}

impl PqVaultRouterAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_id: impl Into<String>,
        operator_label: &str,
        auth_public_key: &str,
        kem_public_key: &str,
        scopes: &[String],
        policy: &Value,
        signature_payload: &Value,
        bond_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        let solver_id = solver_id.into();
        ensure_non_empty(&solver_id, "authorization solver id")?;
        ensure_non_empty(operator_label, "authorization operator")?;
        ensure_non_empty(auth_public_key, "authorization auth public key")?;
        ensure_non_empty(kem_public_key, "authorization kem public key")?;
        ensure_string_set(scopes, "authorization scopes")?;
        ensure_positive(bond_units, "authorization bond")?;
        validate_height_window(issued_at_height, expires_at_height, "authorization")?;

        let operator_commitment = confidential_defi_vault_router_account_commitment(operator_label);
        let auth_public_key_commitment =
            confidential_defi_vault_router_string_root("auth-public-key", auth_public_key);
        let kem_public_key_commitment =
            confidential_defi_vault_router_string_root("kem-public-key", kem_public_key);
        let scope_root = confidential_defi_vault_router_string_set_root("AUTH-SCOPES", scopes);
        let policy_root = confidential_defi_vault_router_payload_root("AUTH-POLICY", policy);
        let signature_root =
            confidential_defi_vault_router_payload_root("PQ-AUTH-SIGNATURE", signature_payload);
        let authorization_id = confidential_defi_vault_router_authorization_id(
            &solver_id,
            &operator_commitment,
            &auth_public_key_commitment,
            &kem_public_key_commitment,
            &scope_root,
            issued_at_height,
            nonce,
        );
        let authorization = Self {
            authorization_id,
            solver_id,
            operator_commitment,
            auth_public_key_commitment,
            kem_public_key_commitment,
            scope_root,
            policy_root,
            signature_root,
            bond_units,
            issued_at_height,
            expires_at_height,
            nonce,
            status: PqAuthorizationStatus::Active,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_pq_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "auth_public_key_commitment": self.auth_public_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "scope_root": self.scope_root,
            "policy_root": self.policy_root,
            "signature_root": self.signature_root,
            "bond_units": self.bond_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "pq_auth_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_PQ_AUTH_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("PQ-AUTHORIZATION", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.authorization_id, "authorization id")?;
        ensure_non_empty(&self.solver_id, "authorization solver id")?;
        ensure_non_empty(
            &self.operator_commitment,
            "authorization operator commitment",
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
        ensure_positive(self.bond_units, "authorization bond")?;
        validate_height_window(
            self.issued_at_height,
            self.expires_at_height,
            "authorization",
        )?;
        let computed = confidential_defi_vault_router_authorization_id(
            &self.solver_id,
            &self.operator_commitment,
            &self.auth_public_key_commitment,
            &self.kem_public_key_commitment,
            &self.scope_root,
            self.issued_at_height,
            self.nonce,
        );
        if self.authorization_id != computed {
            return Err("authorization id mismatch".to_string());
        }
        Ok(self.authorization_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedVaultRouteCommitment {
    pub route_id: String,
    pub route_kind: VaultRouteKind,
    pub owner_commitment: String,
    pub vault_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub notional_commitment: String,
    pub min_output_commitment: String,
    pub collateral_commitment: String,
    pub route_plan_root: String,
    pub encrypted_payload_root: String,
    pub authorization_id: String,
    pub sponsorship_id: String,
    pub allowed_solver_root: String,
    pub max_slippage_bps: u64,
    pub max_risk_bps: u64,
    pub low_fee_lane: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: VaultRouteStatus,
}

impl EncryptedVaultRouteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        vault_label: &str,
        route_kind: VaultRouteKind,
        asset_in_id: &str,
        asset_out_id: &str,
        notional_units: u64,
        min_output_units: u64,
        collateral_units: u64,
        route_plan: &[VaultRouteLeg],
        encrypted_payload: &Value,
        authorization_id: impl Into<String>,
        sponsorship_id: impl Into<String>,
        allowed_solvers: &[String],
        max_slippage_bps: u64,
        max_risk_bps: u64,
        low_fee_lane: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        ensure_non_empty(owner_label, "route owner")?;
        ensure_non_empty(vault_label, "route vault")?;
        ensure_non_empty(asset_in_id, "route asset in")?;
        ensure_non_empty(asset_out_id, "route asset out")?;
        ensure_positive(notional_units, "route notional")?;
        ensure_bps(max_slippage_bps, "route max slippage")?;
        ensure_bps(max_risk_bps, "route max risk")?;
        validate_height_window(submitted_at_height, expires_at_height, "route")?;
        ensure_route_leg_count(route_plan.len())?;
        ensure_string_set(allowed_solvers, "route allowed solvers")?;
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&low_fee_lane, "route low fee lane")?;
        let authorization_id = authorization_id.into();
        ensure_non_empty(&authorization_id, "route authorization id")?;
        let sponsorship_id = sponsorship_id.into();

        let owner_commitment = confidential_defi_vault_router_account_commitment(owner_label);
        let vault_commitment = confidential_defi_vault_router_account_commitment(vault_label);
        let asset_in_commitment = confidential_defi_vault_router_asset_commitment(asset_in_id);
        let asset_out_commitment = confidential_defi_vault_router_asset_commitment(asset_out_id);
        let notional_commitment = confidential_defi_vault_router_amount_commitment(
            notional_units,
            &confidential_defi_vault_router_blinding(owner_label, nonce, "notional"),
        );
        let min_output_commitment = confidential_defi_vault_router_amount_commitment(
            min_output_units,
            &confidential_defi_vault_router_blinding(owner_label, nonce, "min-output"),
        );
        let collateral_commitment = confidential_defi_vault_router_amount_commitment(
            collateral_units,
            &confidential_defi_vault_router_blinding(owner_label, nonce, "collateral"),
        );
        let route_plan_root = confidential_defi_vault_router_route_leg_root(route_plan);
        let encrypted_payload_root = confidential_defi_vault_router_payload_root(
            "ENCRYPTED-ROUTE-PAYLOAD",
            encrypted_payload,
        );
        let allowed_solver_root =
            confidential_defi_vault_router_string_set_root("ALLOWED-SOLVERS", allowed_solvers);
        let route_id = confidential_defi_vault_router_route_id(
            &route_kind.as_str(),
            &owner_commitment,
            &vault_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &notional_commitment,
            &min_output_commitment,
            &collateral_commitment,
            &route_plan_root,
            &authorization_id,
            submitted_at_height,
            expires_at_height,
            nonce,
        );
        let route = Self {
            route_id,
            route_kind,
            owner_commitment,
            vault_commitment,
            asset_in_commitment,
            asset_out_commitment,
            notional_commitment,
            min_output_commitment,
            collateral_commitment,
            route_plan_root,
            encrypted_payload_root,
            authorization_id,
            sponsorship_id,
            allowed_solver_root,
            max_slippage_bps,
            max_risk_bps,
            low_fee_lane,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: VaultRouteStatus::Submitted,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn mark_batched(&mut self) {
        self.status = VaultRouteStatus::Batched;
    }

    pub fn mark_settled(&mut self) {
        self.status = VaultRouteStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_encrypted_route",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "vault_commitment": self.vault_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "notional_commitment": self.notional_commitment,
            "min_output_commitment": self.min_output_commitment,
            "collateral_commitment": self.collateral_commitment,
            "route_plan_root": self.route_plan_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "authorization_id": self.authorization_id,
            "sponsorship_id": self.sponsorship_id,
            "allowed_solver_root": self.allowed_solver_root,
            "max_slippage_bps": self.max_slippage_bps,
            "max_risk_bps": self.max_risk_bps,
            "low_fee_lane": self.low_fee_lane,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "encryption_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_ENCRYPTION_SCHEME,
            "commitment_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_COMMITMENT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("ENCRYPTED-ROUTE", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.owner_commitment, "route owner commitment")?;
        ensure_non_empty(&self.vault_commitment, "route vault commitment")?;
        ensure_non_empty(&self.asset_in_commitment, "route asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "route asset out commitment")?;
        ensure_non_empty(&self.notional_commitment, "route notional commitment")?;
        ensure_non_empty(&self.min_output_commitment, "route min output commitment")?;
        ensure_non_empty(&self.collateral_commitment, "route collateral commitment")?;
        ensure_non_empty(&self.route_plan_root, "route plan root")?;
        ensure_non_empty(&self.encrypted_payload_root, "route encrypted payload root")?;
        ensure_non_empty(&self.authorization_id, "route authorization id")?;
        ensure_non_empty(&self.allowed_solver_root, "route allowed solver root")?;
        ensure_non_empty(&self.low_fee_lane, "route low fee lane")?;
        ensure_bps(self.max_slippage_bps, "route max slippage")?;
        ensure_bps(self.max_risk_bps, "route max risk")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "route")?;
        let computed = confidential_defi_vault_router_route_id(
            &self.route_kind.as_str(),
            &self.owner_commitment,
            &self.vault_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.notional_commitment,
            &self.min_output_commitment,
            &self.collateral_commitment,
            &self.route_plan_root,
            &self.authorization_id,
            self.submitted_at_height,
            self.expires_at_height,
            self.nonce,
        );
        if self.route_id != computed {
            return Err("route id mismatch".to_string());
        }
        Ok(self.route_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRouteLeg {
    pub leg_id: String,
    pub route_id_hint: String,
    pub leg_index: u64,
    pub leg_kind: VaultLegKind,
    pub venue_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub fee_commitment: String,
    pub risk_bucket_root: String,
    pub encrypted_leg_root: String,
    pub dependency_root: String,
    pub nonce: u64,
}

impl VaultRouteLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id_hint: impl Into<String>,
        leg_index: u64,
        leg_kind: VaultLegKind,
        venue_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_units: u64,
        amount_out_units: u64,
        fee_units: u64,
        risk_payload: &Value,
        encrypted_leg_payload: &Value,
        dependencies: &[String],
        nonce: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        let route_id_hint = route_id_hint.into();
        ensure_non_empty(&route_id_hint, "route leg route hint")?;
        ensure_non_empty(venue_label, "route leg venue")?;
        ensure_non_empty(asset_in_id, "route leg asset in")?;
        ensure_non_empty(asset_out_id, "route leg asset out")?;
        ensure_positive(amount_in_units, "route leg amount in")?;
        ensure_positive(amount_out_units, "route leg amount out")?;
        ensure_distinct_strings(dependencies, "route leg dependencies")?;

        let venue_commitment = confidential_defi_vault_router_string_root("venue", venue_label);
        let asset_in_commitment = confidential_defi_vault_router_asset_commitment(asset_in_id);
        let asset_out_commitment = confidential_defi_vault_router_asset_commitment(asset_out_id);
        let amount_in_commitment = confidential_defi_vault_router_amount_commitment(
            amount_in_units,
            &confidential_defi_vault_router_blinding(venue_label, nonce, "amount-in"),
        );
        let amount_out_commitment = confidential_defi_vault_router_amount_commitment(
            amount_out_units,
            &confidential_defi_vault_router_blinding(venue_label, nonce, "amount-out"),
        );
        let fee_commitment = confidential_defi_vault_router_amount_commitment(
            fee_units,
            &confidential_defi_vault_router_blinding(venue_label, nonce, "fee"),
        );
        let risk_bucket_root =
            confidential_defi_vault_router_payload_root("LEG-RISK", risk_payload);
        let encrypted_leg_root =
            confidential_defi_vault_router_payload_root("ENCRYPTED-LEG", encrypted_leg_payload);
        let dependency_root =
            confidential_defi_vault_router_string_set_root("LEG-DEPENDENCIES", dependencies);
        let leg_id = confidential_defi_vault_router_leg_id(
            &route_id_hint,
            leg_index,
            leg_kind,
            &venue_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &amount_out_commitment,
            &fee_commitment,
            &risk_bucket_root,
            &dependency_root,
            nonce,
        );
        let leg = Self {
            leg_id,
            route_id_hint,
            leg_index,
            leg_kind,
            venue_commitment,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            amount_out_commitment,
            fee_commitment,
            risk_bucket_root,
            encrypted_leg_root,
            dependency_root,
            nonce,
        };
        leg.validate()?;
        Ok(leg)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_route_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "route_id_hint": self.route_id_hint,
            "leg_index": self.leg_index,
            "leg_kind": self.leg_kind.as_str(),
            "venue_commitment": self.venue_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "fee_commitment": self.fee_commitment,
            "risk_bucket_root": self.risk_bucket_root,
            "encrypted_leg_root": self.encrypted_leg_root,
            "dependency_root": self.dependency_root,
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("ROUTE-LEG", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.leg_id, "route leg id")?;
        ensure_non_empty(&self.route_id_hint, "route leg route hint")?;
        ensure_non_empty(&self.venue_commitment, "route leg venue commitment")?;
        ensure_non_empty(&self.asset_in_commitment, "route leg asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "route leg asset out commitment")?;
        ensure_non_empty(&self.amount_in_commitment, "route leg amount in commitment")?;
        ensure_non_empty(
            &self.amount_out_commitment,
            "route leg amount out commitment",
        )?;
        ensure_non_empty(&self.fee_commitment, "route leg fee commitment")?;
        ensure_non_empty(&self.risk_bucket_root, "route leg risk root")?;
        ensure_non_empty(&self.encrypted_leg_root, "route leg encrypted root")?;
        ensure_non_empty(&self.dependency_root, "route leg dependency root")?;
        let computed = confidential_defi_vault_router_leg_id(
            &self.route_id_hint,
            self.leg_index,
            self.leg_kind,
            &self.venue_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_in_commitment,
            &self.amount_out_commitment,
            &self.fee_commitment,
            &self.risk_bucket_root,
            &self.dependency_root,
            self.nonce,
        );
        if self.leg_id != computed {
            return Err("route leg id mismatch".to_string());
        }
        Ok(self.leg_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub route_id: String,
    pub fee_asset_commitment: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub rebate_bps: u64,
    pub low_fee_lane: String,
    pub policy_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl VaultFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        route_id: impl Into<String>,
        fee_asset_id: &str,
        max_fee_units: u64,
        rebate_bps: u64,
        low_fee_lane: impl Into<String>,
        policy: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        ensure_non_empty(sponsor_label, "fee sponsorship sponsor")?;
        let route_id = route_id.into();
        ensure_non_empty(&route_id, "fee sponsorship route id")?;
        ensure_non_empty(fee_asset_id, "fee sponsorship asset")?;
        ensure_positive(max_fee_units, "fee sponsorship max fee")?;
        ensure_bps(rebate_bps, "fee sponsorship rebate")?;
        validate_height_window(starts_at_height, expires_at_height, "fee sponsorship")?;
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&low_fee_lane, "fee sponsorship low fee lane")?;

        let sponsor_commitment = confidential_defi_vault_router_account_commitment(sponsor_label);
        let fee_asset_commitment = confidential_defi_vault_router_asset_commitment(fee_asset_id);
        let policy_root = confidential_defi_vault_router_payload_root("FEE-SPONSOR-POLICY", policy);
        let sponsorship_id = confidential_defi_vault_router_sponsorship_id(
            &sponsor_commitment,
            &route_id,
            &fee_asset_commitment,
            max_fee_units,
            rebate_bps,
            &low_fee_lane,
            &policy_root,
            starts_at_height,
            expires_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            route_id,
            fee_asset_commitment,
            max_fee_units,
            reserved_fee_units: 0,
            spent_fee_units: 0,
            rebate_bps,
            low_fee_lane,
            policy_root,
            starts_at_height,
            expires_at_height,
            nonce,
            status: SponsorshipStatus::Open,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn reserve(&mut self, units: u64) -> ConfidentialDefiVaultRouterResult<()> {
        ensure_positive(units, "fee sponsorship reservation")?;
        let next = self
            .reserved_fee_units
            .checked_add(units)
            .ok_or_else(|| "fee sponsorship reservation overflow".to_string())?;
        if next > self.max_fee_units {
            return Err("fee sponsorship capacity exceeded".to_string());
        }
        self.reserved_fee_units = next;
        self.status = SponsorshipStatus::Reserved;
        Ok(())
    }

    pub fn spend_reserved(&mut self, units: u64) -> ConfidentialDefiVaultRouterResult<()> {
        ensure_positive(units, "fee sponsorship spend")?;
        if units > self.reserved_fee_units {
            return Err("fee sponsorship spend exceeds reserved amount".to_string());
        }
        self.reserved_fee_units -= units;
        self.spent_fee_units = self
            .spent_fee_units
            .checked_add(units)
            .ok_or_else(|| "fee sponsorship spend overflow".to_string())?;
        self.status = SponsorshipStatus::Spent;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "route_id": self.route_id,
            "fee_asset_commitment": self.fee_asset_commitment,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "rebate_bps": self.rebate_bps,
            "low_fee_lane": self.low_fee_lane,
            "policy_root": self.policy_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.sponsorship_id, "fee sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "fee sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.route_id, "fee sponsorship route id")?;
        ensure_non_empty(
            &self.fee_asset_commitment,
            "fee sponsorship asset commitment",
        )?;
        ensure_positive(self.max_fee_units, "fee sponsorship max fee")?;
        ensure_bps(self.rebate_bps, "fee sponsorship rebate")?;
        ensure_non_empty(&self.low_fee_lane, "fee sponsorship low fee lane")?;
        ensure_non_empty(&self.policy_root, "fee sponsorship policy root")?;
        validate_height_window(
            self.starts_at_height,
            self.expires_at_height,
            "fee sponsorship",
        )?;
        if self.reserved_fee_units > self.max_fee_units {
            return Err("fee sponsorship reserved amount exceeds max fee".to_string());
        }
        if self.spent_fee_units > self.max_fee_units {
            return Err("fee sponsorship spent amount exceeds max fee".to_string());
        }
        let computed = confidential_defi_vault_router_sponsorship_id(
            &self.sponsor_commitment,
            &self.route_id,
            &self.fee_asset_commitment,
            self.max_fee_units,
            self.rebate_bps,
            &self.low_fee_lane,
            &self.policy_root,
            self.starts_at_height,
            self.expires_at_height,
            self.nonce,
        );
        if self.sponsorship_id != computed {
            return Err("fee sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeVaultRouteBatch {
    pub batch_id: String,
    pub low_fee_lane: String,
    pub route_root: String,
    pub authorization_root: String,
    pub sponsorship_root: String,
    pub ordering_seed: String,
    pub route_ids: Vec<String>,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub max_routes: usize,
    pub aggregate_fee_units: u64,
    pub status: LowFeeBatchStatus,
}

impl LowFeeVaultRouteBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        low_fee_lane: impl Into<String>,
        route_ids: &[String],
        route_root: impl Into<String>,
        authorization_root: impl Into<String>,
        sponsorship_root: impl Into<String>,
        opened_at_height: u64,
        closes_at_height: u64,
        max_routes: usize,
        aggregate_fee_units: u64,
        nonce: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&low_fee_lane, "batch low fee lane")?;
        ensure_string_set(route_ids, "batch routes")?;
        let route_root = route_root.into();
        let authorization_root = authorization_root.into();
        let sponsorship_root = sponsorship_root.into();
        ensure_non_empty(&route_root, "batch route root")?;
        ensure_non_empty(&authorization_root, "batch authorization root")?;
        ensure_non_empty(&sponsorship_root, "batch sponsorship root")?;
        validate_height_window(opened_at_height, closes_at_height, "batch")?;
        if max_routes == 0 {
            return Err("batch max routes must be positive".to_string());
        }
        if route_ids.len() > max_routes {
            return Err("batch route count exceeds maximum".to_string());
        }
        let ordering_seed = confidential_defi_vault_router_ordering_seed(
            &low_fee_lane,
            opened_at_height,
            &route_root,
            nonce,
        );
        let batch_id = confidential_defi_vault_router_batch_id(
            &low_fee_lane,
            &route_root,
            &authorization_root,
            &sponsorship_root,
            &ordering_seed,
            opened_at_height,
            closes_at_height,
            nonce,
        );
        let batch = Self {
            batch_id,
            low_fee_lane,
            route_root,
            authorization_root,
            sponsorship_root,
            ordering_seed,
            route_ids: route_ids.to_vec(),
            opened_at_height,
            closes_at_height,
            max_routes,
            aggregate_fee_units,
            status: LowFeeBatchStatus::Collecting,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_low_fee_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "low_fee_lane": self.low_fee_lane,
            "route_root": self.route_root,
            "authorization_root": self.authorization_root,
            "sponsorship_root": self.sponsorship_root,
            "ordering_seed": self.ordering_seed,
            "route_ids": self.route_ids,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "max_routes": self.max_routes,
            "aggregate_fee_units": self.aggregate_fee_units,
            "status": self.status.as_str(),
            "batching_policy": CONFIDENTIAL_DEFI_VAULT_ROUTER_BATCHING_POLICY,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("LOW-FEE-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.batch_id, "batch id")?;
        ensure_non_empty(&self.low_fee_lane, "batch low fee lane")?;
        ensure_non_empty(&self.route_root, "batch route root")?;
        ensure_non_empty(&self.authorization_root, "batch authorization root")?;
        ensure_non_empty(&self.sponsorship_root, "batch sponsorship root")?;
        ensure_non_empty(&self.ordering_seed, "batch ordering seed")?;
        ensure_string_set(&self.route_ids, "batch routes")?;
        validate_height_window(self.opened_at_height, self.closes_at_height, "batch")?;
        if self.max_routes == 0 {
            return Err("batch max routes must be positive".to_string());
        }
        if self.route_ids.len() > self.max_routes {
            return Err("batch route count exceeds maximum".to_string());
        }
        Ok(self.batch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRouteRiskReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub batch_id: String,
    pub solver_id: String,
    pub route_leg_root: String,
    pub slippage_receipt_root: String,
    pub risk_receipt_root: String,
    pub fee_receipt_root: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub realized_slippage_bps: u64,
    pub realized_risk_bps: u64,
    pub sponsored_fee_units: u64,
    pub settled_at_height: u64,
    pub publish_at_height: u64,
    pub sequence: u64,
    pub status: ReceiptStatus,
}

impl VaultRouteRiskReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        batch_id: &str,
        solver_id: &str,
        route_legs: &[VaultRouteLeg],
        slippage_payload: &Value,
        risk_payload: &Value,
        fee_payload: &Value,
        input_nullifiers: &[String],
        output_commitments: &[String],
        realized_slippage_bps: u64,
        realized_risk_bps: u64,
        sponsored_fee_units: u64,
        settled_at_height: u64,
        publish_at_height: u64,
        sequence: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        ensure_non_empty(route_id, "receipt route id")?;
        ensure_non_empty(batch_id, "receipt batch id")?;
        ensure_non_empty(solver_id, "receipt solver id")?;
        ensure_route_leg_count(route_legs.len())?;
        ensure_string_set(input_nullifiers, "receipt input nullifiers")?;
        ensure_string_set(output_commitments, "receipt output commitments")?;
        ensure_bps(realized_slippage_bps, "receipt realized slippage")?;
        ensure_bps(realized_risk_bps, "receipt realized risk")?;
        if publish_at_height < settled_at_height {
            return Err("receipt publish height cannot precede settlement".to_string());
        }

        let route_leg_root = confidential_defi_vault_router_route_leg_root(route_legs);
        let slippage_receipt_root =
            confidential_defi_vault_router_payload_root("SLIPPAGE-RECEIPT", slippage_payload);
        let risk_receipt_root =
            confidential_defi_vault_router_payload_root("RISK-RECEIPT", risk_payload);
        let fee_receipt_root =
            confidential_defi_vault_router_payload_root("FEE-RECEIPT", fee_payload);
        let input_nullifier_root =
            confidential_defi_vault_router_string_set_root("INPUT-NULLIFIERS", input_nullifiers);
        let output_commitment_root = confidential_defi_vault_router_string_set_root(
            "OUTPUT-COMMITMENTS",
            output_commitments,
        );
        let receipt_id = confidential_defi_vault_router_receipt_id(
            route_id,
            batch_id,
            solver_id,
            &route_leg_root,
            &slippage_receipt_root,
            &risk_receipt_root,
            &fee_receipt_root,
            &input_nullifier_root,
            &output_commitment_root,
            settled_at_height,
            sequence,
        );
        let receipt = Self {
            receipt_id,
            route_id: route_id.to_string(),
            batch_id: batch_id.to_string(),
            solver_id: solver_id.to_string(),
            route_leg_root,
            slippage_receipt_root,
            risk_receipt_root,
            fee_receipt_root,
            input_nullifier_root,
            output_commitment_root,
            realized_slippage_bps,
            realized_risk_bps,
            sponsored_fee_units,
            settled_at_height,
            publish_at_height,
            sequence,
            status: ReceiptStatus::PendingDelay,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_risk_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "route_leg_root": self.route_leg_root,
            "slippage_receipt_root": self.slippage_receipt_root,
            "risk_receipt_root": self.risk_receipt_root,
            "fee_receipt_root": self.fee_receipt_root,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "realized_slippage_bps": self.realized_slippage_bps,
            "realized_risk_bps": self.realized_risk_bps,
            "sponsored_fee_units": self.sponsored_fee_units,
            "settled_at_height": self.settled_at_height,
            "publish_at_height": self.publish_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "receipt_scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_RECEIPT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_record_root("RISK-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.route_id, "receipt route id")?;
        ensure_non_empty(&self.batch_id, "receipt batch id")?;
        ensure_non_empty(&self.solver_id, "receipt solver id")?;
        ensure_non_empty(&self.route_leg_root, "receipt route leg root")?;
        ensure_non_empty(&self.slippage_receipt_root, "receipt slippage root")?;
        ensure_non_empty(&self.risk_receipt_root, "receipt risk root")?;
        ensure_non_empty(&self.fee_receipt_root, "receipt fee root")?;
        ensure_non_empty(&self.input_nullifier_root, "receipt input nullifier root")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "receipt output commitment root",
        )?;
        ensure_bps(self.realized_slippage_bps, "receipt realized slippage")?;
        ensure_bps(self.realized_risk_bps, "receipt realized risk")?;
        if self.publish_at_height < self.settled_at_height {
            return Err("receipt publish height cannot precede settlement".to_string());
        }
        let computed = confidential_defi_vault_router_receipt_id(
            &self.route_id,
            &self.batch_id,
            &self.solver_id,
            &self.route_leg_root,
            &self.slippage_receipt_root,
            &self.risk_receipt_root,
            &self.fee_receipt_root,
            &self.input_nullifier_root,
            &self.output_commitment_root,
            self.settled_at_height,
            self.sequence,
        );
        if self.receipt_id != computed {
            return Err("receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialVaultRouterPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
    pub payload: Value,
}

impl ConfidentialVaultRouterPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject")?;
        let payload_root = confidential_defi_vault_router_payload_root("PUBLIC-RECORD", payload);
        let record_id = confidential_defi_vault_router_public_record_id(
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
            payload: payload.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "payload": self.payload,
        })
    }

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let computed_root =
            confidential_defi_vault_router_payload_root("PUBLIC-RECORD", &self.payload);
        if self.payload_root != computed_root {
            return Err("public record payload root mismatch".to_string());
        }
        let computed = confidential_defi_vault_router_public_record_id(
            &self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != computed {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDefiVaultRouterCounters {
    pub route_commitment_count: u64,
    pub active_route_count: u64,
    pub swap_route_count: u64,
    pub lending_route_count: u64,
    pub perp_route_count: u64,
    pub route_leg_count: u64,
    pub pq_authorization_count: u64,
    pub active_pq_authorization_count: u64,
    pub fee_sponsorship_count: u64,
    pub open_fee_sponsorship_count: u64,
    pub low_fee_batch_count: u64,
    pub live_low_fee_batch_count: u64,
    pub risk_receipt_count: u64,
    pub published_receipt_count: u64,
    pub sponsored_fee_units: u64,
    pub reserved_fee_units: u64,
    pub aggregate_batch_fee_units: u64,
    pub public_record_count: u64,
}

impl ConfidentialDefiVaultRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "route_commitment_count": self.route_commitment_count,
            "active_route_count": self.active_route_count,
            "swap_route_count": self.swap_route_count,
            "lending_route_count": self.lending_route_count,
            "perp_route_count": self.perp_route_count,
            "route_leg_count": self.route_leg_count,
            "pq_authorization_count": self.pq_authorization_count,
            "active_pq_authorization_count": self.active_pq_authorization_count,
            "fee_sponsorship_count": self.fee_sponsorship_count,
            "open_fee_sponsorship_count": self.open_fee_sponsorship_count,
            "low_fee_batch_count": self.low_fee_batch_count,
            "live_low_fee_batch_count": self.live_low_fee_batch_count,
            "risk_receipt_count": self.risk_receipt_count,
            "published_receipt_count": self.published_receipt_count,
            "sponsored_fee_units": self.sponsored_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "aggregate_batch_fee_units": self.aggregate_batch_fee_units,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDefiVaultRouterRoots {
    pub config_root: String,
    pub route_commitment_root: String,
    pub route_leg_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsorship_root: String,
    pub low_fee_batch_root: String,
    pub risk_receipt_root: String,
    pub public_record_root: String,
}

impl ConfidentialDefiVaultRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_defi_vault_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "route_commitment_root": self.route_commitment_root,
            "route_leg_root": self.route_leg_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "risk_receipt_root": self.risk_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_defi_vault_router_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDefiVaultRouterState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialDefiVaultRouterConfig,
    pub route_commitments: BTreeMap<String, EncryptedVaultRouteCommitment>,
    pub route_legs: BTreeMap<String, VaultRouteLeg>,
    pub pq_authorizations: BTreeMap<String, PqVaultRouterAuthorization>,
    pub fee_sponsorships: BTreeMap<String, VaultFeeSponsorship>,
    pub low_fee_batches: BTreeMap<String, LowFeeVaultRouteBatch>,
    pub risk_receipts: BTreeMap<String, VaultRouteRiskReceipt>,
    pub public_records: BTreeMap<String, ConfidentialVaultRouterPublicRecord>,
}

impl Default for ConfidentialDefiVaultRouterState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialDefiVaultRouterState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialDefiVaultRouterConfig::default(),
            route_commitments: BTreeMap::new(),
            route_legs: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            risk_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: ConfidentialDefiVaultRouterConfig,
    ) -> ConfidentialDefiVaultRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ConfidentialDefiVaultRouterResult<Self> {
        let mut state = Self::with_config(ConfidentialDefiVaultRouterConfig::devnet())?;
        state.set_height(CONFIDENTIAL_DEFI_VAULT_ROUTER_DEVNET_HEIGHT);

        let authorization = PqVaultRouterAuthorization::new(
            "devnet-vault-solver-alpha",
            "devnet-vault-operator-alpha",
            "ml-dsa-87-devnet-vault-solver-auth-key",
            "ml-kem-1024-devnet-vault-route-key",
            &[
                "swap".to_string(),
                "lending".to_string(),
                "perps".to_string(),
                "fee_sponsor".to_string(),
            ],
            &json!({
                "max_route_legs": 8,
                "allowed_lanes": [state.config.default_low_fee_lane.clone()],
                "risk_limit_bps": state.config.max_risk_bps
            }),
            &json!({
                "scheme": CONFIDENTIAL_DEFI_VAULT_ROUTER_PQ_AUTH_SCHEME,
                "signature": "devnet-vault-solver-alpha-pq-signature"
            }),
            1_250_000,
            state.height.saturating_sub(12),
            state.height.saturating_add(state.config.pq_auth_ttl_blocks),
            state.next_nonce(),
        )?;
        let authorization_id = authorization.authorization_id.clone();
        let solver_id = authorization.solver_id.clone();
        state.insert_pq_authorization(authorization)?;

        let route_hint = confidential_defi_vault_router_string_root("route-hint", "devnet-route-0");
        let swap_leg = VaultRouteLeg::new(
            &route_hint,
            0,
            VaultLegKind::SwapRfq,
            "devnet-private-rfq-vault",
            "wxmr-devnet",
            "usdd-devnet",
            42_000_000,
            7_560_000_000,
            42_000,
            &json!({"price_bucket": "180-usdd", "twap_guard_bps": 50}),
            &json!({"sealed_quote": "devnet-solver-alpha-rfq"}),
            &[],
            state.next_nonce(),
        )?;
        let swap_leg_id = swap_leg.leg_id.clone();
        let lend_leg = VaultRouteLeg::new(
            &route_hint,
            1,
            VaultLegKind::LendingSupply,
            "devnet-private-usdd-vault",
            "usdd-devnet",
            "ausdd-devnet",
            7_540_000_000,
            7_520_000_000,
            20_000,
            &json!({"health_bucket": "safe", "ltv_bucket": "low"}),
            &json!({"supply_note": "devnet-alice-ausdd-note"}),
            std::slice::from_ref(&swap_leg_id),
            state.next_nonce(),
        )?;
        let lend_leg_id = lend_leg.leg_id.clone();
        let perp_leg = VaultRouteLeg::new(
            &route_hint,
            2,
            VaultLegKind::PerpFunding,
            "devnet-private-perp-vault",
            "ausdd-devnet",
            "funding-hedge-devnet",
            1_000_000_000,
            998_000_000,
            12_000,
            &json!({"funding_bucket": "positive-low", "margin_bucket": "conservative"}),
            &json!({"hedge_commitment": "devnet-private-perp-funding-hedge"}),
            std::slice::from_ref(&lend_leg_id),
            state.next_nonce(),
        )?;
        let route_plan = vec![swap_leg.clone(), lend_leg.clone(), perp_leg.clone()];
        state.insert_route_leg(swap_leg)?;
        state.insert_route_leg(lend_leg)?;
        state.insert_route_leg(perp_leg)?;

        let route = EncryptedVaultRouteCommitment::new(
            "devnet-alice-vault-router",
            "devnet-alice-private-defi-vault",
            VaultRouteKind::Composite,
            "wxmr-devnet",
            "funding-hedge-devnet",
            42_000_000,
            998_000_000,
            7_520_000_000,
            &route_plan,
            &json!({
                "intent": "swap_supply_and_hedge",
                "recipient_note": "devnet-alice-vault-output-note",
                "route_confidentiality": "threshold_encrypted"
            }),
            &authorization_id,
            "",
            std::slice::from_ref(&solver_id),
            75,
            1_800,
            state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.route_ttl_blocks),
            state.next_nonce(),
        )?;
        let route_id = route.route_id.clone();
        state.insert_route_commitment(route)?;

        let sponsorship = VaultFeeSponsorship::new(
            "devnet-vault-paymaster",
            &route_id,
            "usdd-devnet",
            100_000,
            state.config.sponsor_rebate_bps,
            state.config.default_low_fee_lane.clone(),
            &json!({
                "paymaster": "devnet-low-fee-vault-paymaster",
                "sponsor_private_routes": true,
                "max_realized_risk_bps": state.config.max_risk_bps
            }),
            state.height,
            state.height.saturating_add(state.config.route_ttl_blocks),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_fee_sponsorship(sponsorship)?;
        state.reserve_fee_sponsorship(&sponsorship_id, 74_000)?;

        if let Some(route) = state.route_commitments.get_mut(&route_id) {
            route.sponsorship_id = sponsorship_id.clone();
            route.status = VaultRouteStatus::Authorized;
        }

        let batch = LowFeeVaultRouteBatch::new(
            state.config.default_low_fee_lane.clone(),
            std::slice::from_ref(&route_id),
            state.route_commitment_root(),
            state.pq_authorization_root(),
            state.fee_sponsorship_root(),
            state.height,
            state
                .height
                .saturating_add(state.config.batch_window_blocks),
            state.config.max_batch_routes,
            74_000,
            state.next_nonce(),
        )?;
        let batch_id = batch.batch_id.clone();
        state.insert_low_fee_batch(batch)?;
        if let Some(route) = state.route_commitments.get_mut(&route_id) {
            route.mark_batched();
        }

        state.spend_fee_sponsorship(&sponsorship_id, 74_000)?;
        let receipt = VaultRouteRiskReceipt::new(
            &route_id,
            &batch_id,
            &solver_id,
            &route_plan,
            &json!({
                "max_slippage_bps": 75,
                "realized_slippage_bps": 52,
                "min_output_satisfied": true
            }),
            &json!({
                "max_risk_bps": 1800,
                "realized_risk_bps": 1420,
                "oracle_root": state.config.risk_oracle_root
            }),
            &json!({
                "sponsorship_id": sponsorship_id,
                "fee_units": 74000,
                "rebate_bps": state.config.sponsor_rebate_bps
            }),
            &["devnet-alice-wxmr-nullifier".to_string()],
            &[
                "devnet-alice-ausdd-output".to_string(),
                "devnet-alice-hedge-output".to_string(),
            ],
            52,
            1_420,
            74_000,
            state
                .height
                .saturating_add(state.config.batch_window_blocks + 2),
            state
                .height
                .saturating_add(state.config.batch_window_blocks + 2)
                .saturating_add(state.config.receipt_delay_blocks),
            state.next_nonce(),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_risk_receipt(receipt)?;
        if let Some(route) = state.route_commitments.get_mut(&route_id) {
            route.mark_settled();
        }
        if let Some(batch) = state.low_fee_batches.get_mut(&batch_id) {
            batch.status = LowFeeBatchStatus::Settled;
        }

        for (kind, subject, payload) in [
            (
                "pq_authorization",
                authorization_id.as_str(),
                state
                    .pq_authorizations
                    .get(&authorization_id)
                    .ok_or_else(|| "devnet authorization missing".to_string())?
                    .public_record(),
            ),
            (
                "encrypted_route",
                route_id.as_str(),
                state
                    .route_commitments
                    .get(&route_id)
                    .ok_or_else(|| "devnet route missing".to_string())?
                    .public_record(),
            ),
            (
                "fee_sponsorship",
                sponsorship_id.as_str(),
                state
                    .fee_sponsorships
                    .get(&sponsorship_id)
                    .ok_or_else(|| "devnet sponsorship missing".to_string())?
                    .public_record(),
            ),
            (
                "low_fee_batch",
                batch_id.as_str(),
                state
                    .low_fee_batches
                    .get(&batch_id)
                    .ok_or_else(|| "devnet batch missing".to_string())?
                    .public_record(),
            ),
            (
                "risk_receipt",
                receipt_id.as_str(),
                state
                    .risk_receipts
                    .get(&receipt_id)
                    .ok_or_else(|| "devnet receipt missing".to_string())?
                    .public_record(),
            ),
        ] {
            state.publish_public_record(kind, subject, &payload)?;
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

    pub fn insert_route_commitment(
        &mut self,
        route: EncryptedVaultRouteCommitment,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        route.validate()?;
        if self.route_commitments.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_COMMITMENTS {
            return Err("route commitment capacity reached".to_string());
        }
        if !self.pq_authorizations.contains_key(&route.authorization_id) {
            return Err("route commitment references unknown authorization".to_string());
        }
        if !route.sponsorship_id.is_empty()
            && !self.fee_sponsorships.contains_key(&route.sponsorship_id)
        {
            return Err("route commitment references unknown fee sponsorship".to_string());
        }
        self.route_commitments.insert(route.route_id.clone(), route);
        Ok(())
    }

    pub fn insert_route_leg(
        &mut self,
        leg: VaultRouteLeg,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        leg.validate()?;
        if self.route_legs.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_COMMITMENTS {
            return Err("route leg capacity reached".to_string());
        }
        self.route_legs.insert(leg.leg_id.clone(), leg);
        Ok(())
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqVaultRouterAuthorization,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        authorization.validate()?;
        if authorization.bond_units < self.config.min_authorization_bond_units {
            return Err("authorization bond below config minimum".to_string());
        }
        if self.pq_authorizations.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_AUTHORIZATIONS {
            return Err("authorization capacity reached".to_string());
        }
        self.pq_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(())
    }

    pub fn insert_fee_sponsorship(
        &mut self,
        sponsorship: VaultFeeSponsorship,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        sponsorship.validate()?;
        if self.fee_sponsorships.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_FEE_SPONSORSHIPS {
            return Err("fee sponsorship capacity reached".to_string());
        }
        self.fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_low_fee_batch(
        &mut self,
        batch: LowFeeVaultRouteBatch,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        batch.validate()?;
        if self.low_fee_batches.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_BATCHES {
            return Err("low fee batch capacity reached".to_string());
        }
        for route_id in &batch.route_ids {
            if !self.route_commitments.contains_key(route_id) {
                return Err("low fee batch references unknown route".to_string());
            }
        }
        self.low_fee_batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_risk_receipt(
        &mut self,
        receipt: VaultRouteRiskReceipt,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        receipt.validate()?;
        if self.risk_receipts.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_RECEIPTS {
            return Err("risk receipt capacity reached".to_string());
        }
        if !self.route_commitments.contains_key(&receipt.route_id) {
            return Err("risk receipt references unknown route".to_string());
        }
        if !self.low_fee_batches.contains_key(&receipt.batch_id) {
            return Err("risk receipt references unknown batch".to_string());
        }
        self.risk_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn reserve_fee_sponsorship(
        &mut self,
        sponsorship_id: &str,
        units: u64,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        self.fee_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown fee sponsorship".to_string())?
            .reserve(units)
    }

    pub fn spend_fee_sponsorship(
        &mut self,
        sponsorship_id: &str,
        units: u64,
    ) -> ConfidentialDefiVaultRouterResult<()> {
        self.fee_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown fee sponsorship".to_string())?
            .spend_reserved(units)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> ConfidentialDefiVaultRouterResult<ConfidentialVaultRouterPublicRecord> {
        if self.public_records.len() >= CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_PUBLIC_RECORDS {
            return Err("public record capacity reached".to_string());
        }
        let record = ConfidentialVaultRouterPublicRecord::new(
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

    pub fn route_commitment_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "ROUTE-COMMITMENTS",
            self.route_commitments
                .values()
                .map(EncryptedVaultRouteCommitment::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn route_leg_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "ROUTE-LEGS",
            self.route_legs
                .values()
                .map(VaultRouteLeg::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "PQ-AUTHORIZATIONS",
            self.pq_authorizations
                .values()
                .map(PqVaultRouterAuthorization::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn fee_sponsorship_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "FEE-SPONSORSHIPS",
            self.fee_sponsorships
                .values()
                .map(VaultFeeSponsorship::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn low_fee_batch_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "LOW-FEE-BATCHES",
            self.low_fee_batches
                .values()
                .map(LowFeeVaultRouteBatch::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn risk_receipt_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "RISK-RECEIPTS",
            self.risk_receipts
                .values()
                .map(VaultRouteRiskReceipt::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn public_record_root(&self) -> String {
        confidential_defi_vault_router_object_root(
            "PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(ConfidentialVaultRouterPublicRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    pub fn roots(&self) -> ConfidentialDefiVaultRouterRoots {
        ConfidentialDefiVaultRouterRoots {
            config_root: self.config.state_root(),
            route_commitment_root: self.route_commitment_root(),
            route_leg_root: self.route_leg_root(),
            pq_authorization_root: self.pq_authorization_root(),
            fee_sponsorship_root: self.fee_sponsorship_root(),
            low_fee_batch_root: self.low_fee_batch_root(),
            risk_receipt_root: self.risk_receipt_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> ConfidentialDefiVaultRouterCounters {
        ConfidentialDefiVaultRouterCounters {
            route_commitment_count: self.route_commitments.len() as u64,
            active_route_count: self
                .route_commitments
                .values()
                .filter(|route| route.status.active())
                .count() as u64,
            swap_route_count: self
                .route_commitments
                .values()
                .filter(|route| route.route_kind.is_swap())
                .count() as u64,
            lending_route_count: self
                .route_commitments
                .values()
                .filter(|route| route.route_kind.is_lending())
                .count() as u64,
            perp_route_count: self
                .route_commitments
                .values()
                .filter(|route| route.route_kind.is_perp())
                .count() as u64,
            route_leg_count: self.route_legs.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            active_pq_authorization_count: self
                .pq_authorizations
                .values()
                .filter(|authorization| authorization.status.usable())
                .count() as u64,
            fee_sponsorship_count: self.fee_sponsorships.len() as u64,
            open_fee_sponsorship_count: self
                .fee_sponsorships
                .values()
                .filter(|sponsorship| {
                    matches!(
                        sponsorship.status,
                        SponsorshipStatus::Open | SponsorshipStatus::Reserved
                    )
                })
                .count() as u64,
            low_fee_batch_count: self.low_fee_batches.len() as u64,
            live_low_fee_batch_count: self
                .low_fee_batches
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            risk_receipt_count: self.risk_receipts.len() as u64,
            published_receipt_count: self
                .risk_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ReceiptStatus::Published | ReceiptStatus::Final
                    )
                })
                .count() as u64,
            sponsored_fee_units: self
                .fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_fee_units)
                .sum(),
            reserved_fee_units: self
                .fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_fee_units)
                .sum(),
            aggregate_batch_fee_units: self
                .low_fee_batches
                .values()
                .map(|batch| batch.aggregate_fee_units)
                .sum(),
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "confidential_defi_vault_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION,
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

    pub fn validate(&self) -> ConfidentialDefiVaultRouterResult<String> {
        self.config.validate()?;
        if self.route_commitments.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_COMMITMENTS {
            return Err("route commitment capacity exceeded".to_string());
        }
        if self.pq_authorizations.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_AUTHORIZATIONS {
            return Err("authorization capacity exceeded".to_string());
        }
        if self.fee_sponsorships.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_FEE_SPONSORSHIPS {
            return Err("fee sponsorship capacity exceeded".to_string());
        }
        if self.low_fee_batches.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_BATCHES {
            return Err("low fee batch capacity exceeded".to_string());
        }
        if self.risk_receipts.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_RECEIPTS {
            return Err("risk receipt capacity exceeded".to_string());
        }
        if self.public_records.len() > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }
        for authorization in self.pq_authorizations.values() {
            authorization.validate()?;
        }
        for leg in self.route_legs.values() {
            leg.validate()?;
        }
        for sponsorship in self.fee_sponsorships.values() {
            sponsorship.validate()?;
            if !self.route_commitments.contains_key(&sponsorship.route_id) {
                return Err("fee sponsorship references unknown route".to_string());
            }
        }
        for route in self.route_commitments.values() {
            route.validate()?;
            if !self.pq_authorizations.contains_key(&route.authorization_id) {
                return Err("route references unknown authorization".to_string());
            }
            if !route.sponsorship_id.is_empty()
                && !self.fee_sponsorships.contains_key(&route.sponsorship_id)
            {
                return Err("route references unknown fee sponsorship".to_string());
            }
            if self.height > route.expires_at_height && route.status.active() {
                return Err("active route is past expiry".to_string());
            }
            if route.max_slippage_bps > self.config.max_slippage_bps {
                return Err("route slippage exceeds config".to_string());
            }
            if route.max_risk_bps > self.config.max_risk_bps {
                return Err("route risk exceeds config".to_string());
            }
        }
        for batch in self.low_fee_batches.values() {
            batch.validate()?;
            if batch.max_routes > self.config.max_batch_routes {
                return Err("batch max routes exceeds config".to_string());
            }
            for route_id in &batch.route_ids {
                if !self.route_commitments.contains_key(route_id) {
                    return Err("batch references unknown route".to_string());
                }
            }
        }
        for receipt in self.risk_receipts.values() {
            receipt.validate()?;
            if !self.route_commitments.contains_key(&receipt.route_id) {
                return Err("receipt references unknown route".to_string());
            }
            if !self.low_fee_batches.contains_key(&receipt.batch_id) {
                return Err("receipt references unknown batch".to_string());
            }
            if receipt.realized_slippage_bps > self.config.max_slippage_bps {
                return Err("receipt slippage exceeds config".to_string());
            }
            if receipt.realized_risk_bps > self.config.max_risk_bps {
                return Err("receipt risk exceeds config".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn confidential_defi_vault_router_account_commitment(account_label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-ACCOUNT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(account_label)],
        32,
    )
}

pub fn confidential_defi_vault_router_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-ASSET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn confidential_defi_vault_router_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-AMOUNT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_blinding(label: &str, nonce: u64, purpose: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_record_root(domain: &str, payload: &Value) -> String {
    confidential_defi_vault_router_payload_root(domain, payload)
}

pub fn confidential_defi_vault_router_object_root(domain: &str, records: &[Value]) -> String {
    merkle_root(&format!("CONFIDENTIAL-DEFI-VAULT-ROUTER-{domain}"), records)
}

pub fn confidential_defi_vault_router_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(&format!("CONFIDENTIAL-DEFI-VAULT-ROUTER-{domain}"), &leaves)
}

pub fn confidential_defi_vault_router_route_leg_root(route_legs: &[VaultRouteLeg]) -> String {
    confidential_defi_vault_router_object_root(
        "ROUTE-LEG-PLAN",
        &route_legs
            .iter()
            .map(VaultRouteLeg::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_defi_vault_router_authorization_id(
    solver_id: &str,
    operator_commitment: &str,
    auth_public_key_commitment: &str,
    kem_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-AUTHORIZATION-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
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
pub fn confidential_defi_vault_router_route_id(
    route_kind: &str,
    owner_commitment: &str,
    vault_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    notional_commitment: &str,
    min_output_commitment: &str,
    collateral_commitment: &str,
    route_plan_root: &str,
    authorization_id: &str,
    submitted_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-ROUTE-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_kind),
            HashPart::Str(owner_commitment),
            HashPart::Str(vault_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(notional_commitment),
            HashPart::Str(min_output_commitment),
            HashPart::Str(collateral_commitment),
            HashPart::Str(route_plan_root),
            HashPart::Str(authorization_id),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_defi_vault_router_leg_id(
    route_id_hint: &str,
    leg_index: u64,
    leg_kind: VaultLegKind,
    venue_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    amount_out_commitment: &str,
    fee_commitment: &str,
    risk_bucket_root: &str,
    dependency_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-LEG-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id_hint),
            HashPart::Int(leg_index as i128),
            HashPart::Str(leg_kind.as_str()),
            HashPart::Str(venue_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_commitment),
            HashPart::Str(fee_commitment),
            HashPart::Str(risk_bucket_root),
            HashPart::Str(dependency_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_defi_vault_router_sponsorship_id(
    sponsor_commitment: &str,
    route_id: &str,
    fee_asset_commitment: &str,
    max_fee_units: u64,
    rebate_bps: u64,
    low_fee_lane: &str,
    policy_root: &str,
    starts_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-SPONSORSHIP-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(route_id),
            HashPart::Str(fee_asset_commitment),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Str(low_fee_lane),
            HashPart::Str(policy_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_defi_vault_router_batch_id(
    low_fee_lane: &str,
    route_root: &str,
    authorization_root: &str,
    sponsorship_root: &str,
    ordering_seed: &str,
    opened_at_height: u64,
    closes_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-BATCH-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(low_fee_lane),
            HashPart::Str(route_root),
            HashPart::Str(authorization_root),
            HashPart::Str(sponsorship_root),
            HashPart::Str(ordering_seed),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(closes_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_ordering_seed(
    low_fee_lane: &str,
    height: u64,
    route_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-ORDERING-SEED",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(low_fee_lane),
            HashPart::Int(height as i128),
            HashPart::Str(route_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_defi_vault_router_receipt_id(
    route_id: &str,
    batch_id: &str,
    solver_id: &str,
    route_leg_root: &str,
    slippage_receipt_root: &str,
    risk_receipt_root: &str,
    fee_receipt_root: &str,
    input_nullifier_root: &str,
    output_commitment_root: &str,
    settled_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-RECEIPT-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(batch_id),
            HashPart::Str(solver_id),
            HashPart::Str(route_leg_root),
            HashPart::Str(slippage_receipt_root),
            HashPart::Str(risk_receipt_root),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(input_nullifier_root),
            HashPart::Str(output_commitment_root),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn confidential_defi_vault_router_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
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

pub fn confidential_defi_vault_router_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-DEFI-VAULT-ROUTER-STATE-ROOT",
        &[
            HashPart::Str(CONFIDENTIAL_DEFI_VAULT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialDefiVaultRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> ConfidentialDefiVaultRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialDefiVaultRouterResult<()> {
    if value > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_distinct_strings(
    values: &[String],
    label: &str,
) -> ConfidentialDefiVaultRouterResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> ConfidentialDefiVaultRouterResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    ensure_distinct_strings(values, label)
}

fn ensure_route_leg_count(count: usize) -> ConfidentialDefiVaultRouterResult<()> {
    if count == 0 {
        return Err("route requires at least one leg".to_string());
    }
    if count > CONFIDENTIAL_DEFI_VAULT_ROUTER_MAX_ROUTE_LEGS {
        return Err("route has too many legs".to_string());
    }
    Ok(())
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> ConfidentialDefiVaultRouterResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}
