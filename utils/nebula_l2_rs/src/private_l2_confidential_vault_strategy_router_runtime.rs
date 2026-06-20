use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-vault-strategy-router-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-vault-strategy-router-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_VAULT_SCHEME: &str =
    "private-l2-confidential-vault-strategy-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEPOSIT_SCHEME: &str =
    "shielded-vault-strategy-deposit-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBALANCE_SCHEME: &str =
    "private-vault-strategy-rebalance-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RISK_SCHEME: &str =
    "pq-confidential-vault-strategy-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-vault-strategy-reservation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RECEIPT_SCHEME: &str =
    "private-vault-strategy-settlement-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBATE_SCHEME: &str =
    "private-vault-strategy-fee-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEVNET_HEIGHT: u64 = 668_000;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_VAULTS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_DEPOSITS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_REBALANCES: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_DEPOSITS: usize =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    8_192;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_DEPOSIT_TTL_BLOCKS: u64 =
    36;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS: u64 =
    24;
pub const PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStrategyKind {
    StableYield,
    LendingLoop,
    LiquidityProvision,
    DeltaNeutral,
    PerpetualBasis,
    MoneroReserveYield,
    TreasuryBills,
}

impl VaultStrategyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableYield => "stable_yield",
            Self::LendingLoop => "lending_loop",
            Self::LiquidityProvision => "liquidity_provision",
            Self::DeltaNeutral => "delta_neutral",
            Self::PerpetualBasis => "perpetual_basis",
            Self::MoneroReserveYield => "monero_reserve_yield",
            Self::TreasuryBills => "treasury_bills",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    Rebalancing,
    SettlementOnly,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::SettlementOnly => "settlement_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositNoteStatus {
    Submitted,
    Accepted,
    Reserved,
    Batched,
    Settled,
    Withdrawn,
    Expired,
    Rejected,
}

impl DepositNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Pending,
    LowRisk,
    MediumRisk,
    HighRisk,
    Halt,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::LowRisk => "low_risk",
            Self::MediumRisk => "medium_risk",
            Self::HighRisk => "high_risk",
            Self::Halt => "halt",
        }
    }

    pub fn allows_rebalance(self) -> bool {
        matches!(self, Self::LowRisk | Self::MediumRisk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceStatus {
    Built,
    RiskApproved,
    Executed,
    Settled,
    Rejected,
}

impl RebalanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::RiskApproved => "risk_approved",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Finalized,
    Rebated,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub router_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub pq_auth_suite: String,
    pub hash_suite: String,
    pub max_vaults: usize,
    pub max_deposits: usize,
    pub max_risk_attestations: usize,
    pub max_reservations: usize,
    pub max_rebalances: usize,
    pub max_receipts: usize,
    pub max_batch_deposits: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub deposit_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub current_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            router_id: "devnet-confidential-vault-strategy-router".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            collateral_asset_id: "wxmr-devnet".to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_HASH_SUITE
                .to_string(),
            max_vaults: PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_VAULTS,
            max_deposits:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_DEPOSITS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_rebalances:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_REBALANCES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_deposits:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_DEPOSITS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            deposit_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_DEPOSIT_TTL_BLOCKS,
            rebalance_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS,
            current_height: PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require(
            self.protocol_version
                == PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION,
            "unsupported confidential vault strategy router protocol version",
        )?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("router_id", &self.router_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require(self.max_vaults > 0, "max_vaults must be positive")?;
        require(self.max_deposits > 0, "max_deposits must be positive")?;
        require(
            self.max_risk_attestations > 0,
            "max_risk_attestations must be positive",
        )?;
        require(
            self.max_reservations > 0,
            "max_reservations must be positive",
        )?;
        require(self.max_rebalances > 0, "max_rebalances must be positive")?;
        require(self.max_receipts > 0, "max_receipts must be positive")?;
        require(
            self.max_batch_deposits > 0,
            "max_batch_deposits must be positive",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover per-deposit privacy floor",
        )?;
        require(
            self.min_pq_security_bits
                >= PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "PQ security floor is too low",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate cannot exceed user fee cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "router_id": self.router_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "pq_auth_suite": self.pq_auth_suite,
            "hash_suite": self.hash_suite,
            "max_vaults": self.max_vaults,
            "max_deposits": self.max_deposits,
            "max_risk_attestations": self.max_risk_attestations,
            "max_reservations": self.max_reservations,
            "max_rebalances": self.max_rebalances,
            "max_receipts": self.max_receipts,
            "max_batch_deposits": self.max_batch_deposits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "deposit_ttl_blocks": self.deposit_ttl_blocks,
            "rebalance_ttl_blocks": self.rebalance_ttl_blocks,
            "current_height": self.current_height,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub next_vault: u64,
    pub next_deposit: u64,
    pub next_risk_attestation: u64,
    pub next_reservation: u64,
    pub next_rebalance: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_vault": self.next_vault,
            "next_deposit": self.next_deposit,
            "next_risk_attestation": self.next_risk_attestation,
            "next_reservation": self.next_reservation,
            "next_rebalance": self.next_rebalance,
            "next_receipt": self.next_receipt,
            "next_rebate": self.next_rebate,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenStrategyVaultRequest {
    pub strategy_kind: VaultStrategyKind,
    pub vault_commitment: String,
    pub manager_commitment: String,
    pub asset_commitment_root: String,
    pub strategy_policy_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_manager_key_root: String,
    pub metadata_root: String,
}

impl OpenStrategyVaultRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("vault_commitment", &self.vault_commitment)?;
        require_non_empty("manager_commitment", &self.manager_commitment)?;
        require_root("asset_commitment_root", &self.asset_commitment_root)?;
        require_root("strategy_policy_root", &self.strategy_policy_root)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "vault fee exceeds low-fee cap",
        )?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "vault privacy set is too small",
        )?;
        require_root("pq_manager_key_root", &self.pq_manager_key_root)?;
        require_root("metadata_root", &self.metadata_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "strategy_kind": self.strategy_kind.as_str(),
            "vault_commitment": self.vault_commitment,
            "manager_commitment": self.manager_commitment,
            "asset_commitment_root": self.asset_commitment_root,
            "strategy_policy_root": self.strategy_policy_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_manager_key_root": self.pq_manager_key_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitShieldedVaultDepositRequest {
    pub vault_id: String,
    pub depositor_commitment: String,
    pub asset_note_root: String,
    pub deposit_nullifier: String,
    pub encrypted_amount_root: String,
    pub share_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub expires_at_height: u64,
}

impl SubmitShieldedVaultDepositRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("depositor_commitment", &self.depositor_commitment)?;
        require_root("asset_note_root", &self.asset_note_root)?;
        require_root("deposit_nullifier", &self.deposit_nullifier)?;
        require_root("encrypted_amount_root", &self.encrypted_amount_root)?;
        require_root("share_commitment_root", &self.share_commitment_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "deposit fee exceeds low-fee cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "deposit privacy set is too small",
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require(
            self.expires_at_height > config.current_height,
            "deposit must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "depositor_commitment": self.depositor_commitment,
            "asset_note_root": self.asset_note_root,
            "deposit_nullifier": self.deposit_nullifier,
            "encrypted_amount_root": self.encrypted_amount_root,
            "share_commitment_root": self.share_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestVaultRiskRequest {
    pub vault_id: String,
    pub strategy_exposure_root: String,
    pub nav_commitment_root: String,
    pub liquidity_risk_root: String,
    pub oracle_risk_root: String,
    pub verdict: RiskVerdict,
    pub pq_attestation_root: String,
    pub pq_security_bits: u16,
}

impl AttestVaultRiskRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_root("strategy_exposure_root", &self.strategy_exposure_root)?;
        require_root("nav_commitment_root", &self.nav_commitment_root)?;
        require_root("liquidity_risk_root", &self.liquidity_risk_root)?;
        require_root("oracle_risk_root", &self.oracle_risk_root)?;
        require_root("pq_attestation_root", &self.pq_attestation_root)?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "risk attestation PQ security is too low",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "strategy_exposure_root": self.strategy_exposure_root,
            "nav_commitment_root": self.nav_commitment_root,
            "liquidity_risk_root": self.liquidity_risk_root,
            "oracle_risk_root": self.oracle_risk_root,
            "verdict": self.verdict.as_str(),
            "pq_attestation_root": self.pq_attestation_root,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveLowFeeVaultRouteRequest {
    pub deposit_note_id: String,
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub reservation_nullifier: String,
    pub reserved_fee_bps: u64,
    pub rebate_bps: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeVaultRouteRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("deposit_note_id", &self.deposit_note_id)?;
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("reservation_nullifier", &self.reservation_nullifier)?;
        require_bps("reserved_fee_bps", self.reserved_fee_bps)?;
        require(
            self.reserved_fee_bps <= config.max_user_fee_bps,
            "reserved fee exceeds low-fee cap",
        )?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= self.reserved_fee_bps,
            "rebate cannot exceed reserved fee",
        )?;
        require(
            self.expires_at_height > config.current_height,
            "reservation must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deposit_note_id": self.deposit_note_id,
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reservation_nullifier": self.reservation_nullifier,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_bps": self.rebate_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildPrivateRebalanceRequest {
    pub vault_id: String,
    pub deposit_note_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub risk_attestation_ids: Vec<String>,
    pub target_strategy_root: String,
    pub old_position_root: String,
    pub new_position_root: String,
    pub rebalance_proof_root: String,
    pub batch_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
}

impl BuildPrivateRebalanceRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require(
            !self.deposit_note_ids.is_empty(),
            "rebalance needs deposits",
        )?;
        require(
            self.deposit_note_ids.len() <= config.max_batch_deposits,
            "rebalance includes too many deposits",
        )?;
        require_unique("deposit_note_ids", &self.deposit_note_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_unique("risk_attestation_ids", &self.risk_attestation_ids)?;
        require_root("target_strategy_root", &self.target_strategy_root)?;
        require_root("old_position_root", &self.old_position_root)?;
        require_root("new_position_root", &self.new_position_root)?;
        require_root("rebalance_proof_root", &self.rebalance_proof_root)?;
        require(
            self.batch_privacy_set_size >= config.batch_privacy_set_size,
            "rebalance privacy set is too small",
        )?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "rebalance fee exceeds low-fee cap",
        )?;
        require(
            self.expires_at_height > config.current_height,
            "rebalance must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "deposit_note_ids": self.deposit_note_ids,
            "reservation_ids": self.reservation_ids,
            "risk_attestation_ids": self.risk_attestation_ids,
            "target_strategy_root": self.target_strategy_root,
            "old_position_root": self.old_position_root,
            "new_position_root": self.new_position_root,
            "rebalance_proof_root": self.rebalance_proof_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishVaultSettlementReceiptRequest {
    pub rebalance_id: String,
    pub settlement_root: String,
    pub nav_update_root: String,
    pub share_update_root: String,
    pub recursive_proof_root: String,
    pub pq_signature_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl PublishVaultSettlementReceiptRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("rebalance_id", &self.rebalance_id)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_root("nav_update_root", &self.nav_update_root)?;
        require_root("share_update_root", &self.share_update_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_bps("settled_fee_bps", self.settled_fee_bps)?;
        require(
            self.settled_fee_bps <= config.max_user_fee_bps,
            "settled fee exceeds low-fee cap",
        )?;
        require(
            self.settled_at_height >= config.current_height,
            "settlement height cannot be behind current height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebalance_id": self.rebalance_id,
            "settlement_root": self.settlement_root,
            "nav_update_root": self.nav_update_root,
            "share_update_root": self.share_update_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishVaultRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_nullifier_root: String,
    pub rebate_bps: u64,
    pub published_at_height: u64,
}

impl PublishVaultRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require(
            !self.reservation_ids.is_empty(),
            "rebate needs reservations",
        )?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("rebate_pool_root", &self.rebate_pool_root)?;
        require_root("rebate_nullifier_root", &self.rebate_nullifier_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= config.max_user_fee_bps,
            "rebate exceeds fee cap",
        )?;
        require(
            self.published_at_height >= config.current_height,
            "rebate height cannot be behind current height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_ids": self.reservation_ids,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_nullifier_root": self.rebate_nullifier_root,
            "rebate_bps": self.rebate_bps,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrategyVaultRecord {
    pub vault_id: String,
    pub request: OpenStrategyVaultRequest,
    pub status: VaultStatus,
    pub opened_at_height: u64,
    pub vault_root: String,
}

impl StrategyVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "vault_root": self.vault_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedVaultDepositRecord {
    pub deposit_note_id: String,
    pub request: SubmitShieldedVaultDepositRequest,
    pub status: DepositNoteStatus,
    pub accepted_at_height: u64,
    pub deposit_root: String,
}

impl ShieldedVaultDepositRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_note_id": self.deposit_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height,
            "deposit_root": self.deposit_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultRiskAttestationRecord {
    pub risk_attestation_id: String,
    pub request: AttestVaultRiskRequest,
    pub accepted_at_height: u64,
    pub risk_root: String,
}

impl VaultRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_attestation_id": self.risk_attestation_id,
            "request": self.request.public_record(),
            "accepted_at_height": self.accepted_at_height,
            "risk_root": self.risk_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeVaultRouteReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeVaultRouteRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl LowFeeVaultRouteReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateVaultRebalanceRecord {
    pub rebalance_id: String,
    pub request: BuildPrivateRebalanceRequest,
    pub status: RebalanceStatus,
    pub built_at_height: u64,
    pub rebalance_root: String,
}

impl PrivateVaultRebalanceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebalance_id": self.rebalance_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "rebalance_root": self.rebalance_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultSettlementReceiptRecord {
    pub receipt_id: String,
    pub request: PublishVaultSettlementReceiptRequest,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

impl VaultSettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultRebateReceiptRecord {
    pub rebate_id: String,
    pub request: PublishVaultRebateRequest,
    pub status: ReceiptStatus,
    pub rebate_root: String,
}

impl VaultRebateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub vault_root: String,
    pub deposit_root: String,
    pub risk_root: String,
    pub reservation_root: String,
    pub rebalance_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "deposit_root": self.deposit_root,
            "risk_root": self.risk_root,
            "reservation_root": self.reservation_root,
            "rebalance_root": self.rebalance_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub vaults: BTreeMap<String, StrategyVaultRecord>,
    pub deposits: BTreeMap<String, ShieldedVaultDepositRecord>,
    pub risk_attestations: BTreeMap<String, VaultRiskAttestationRecord>,
    pub reservations: BTreeMap<String, LowFeeVaultRouteReservationRecord>,
    pub rebalances: BTreeMap<String, PrivateVaultRebalanceRecord>,
    pub receipts: BTreeMap<String, VaultSettlementReceiptRecord>,
    pub rebates: BTreeMap<String, VaultRebateReceiptRecord>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            deposits: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            rebalances: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
        })
    }

    pub fn open_strategy_vault(
        &mut self,
        request: OpenStrategyVaultRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<StrategyVaultRecord> {
        request.validate(&self.config)?;
        require(
            self.vaults.len() < self.config.max_vaults,
            "vault capacity exhausted",
        )?;
        let sequence = self.counters.next_vault;
        self.counters.next_vault = self.counters.next_vault.saturating_add(1);
        let vault_id = strategy_vault_id(&request, sequence);
        let vault_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_VAULT_SCHEME,
            &json!({"vault_id": vault_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = StrategyVaultRecord {
            vault_id: vault_id.clone(),
            request,
            status: VaultStatus::Active,
            opened_at_height: self.config.current_height,
            vault_root,
        };
        self.vaults.insert(vault_id, record.clone());
        Ok(record)
    }

    pub fn submit_shielded_deposit(
        &mut self,
        request: SubmitShieldedVaultDepositRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<ShieldedVaultDepositRecord> {
        request.validate(&self.config)?;
        require(
            self.deposits.len() < self.config.max_deposits,
            "deposit capacity exhausted",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "deposit references unknown vault",
        )?;
        let sequence = self.counters.next_deposit;
        self.counters.next_deposit = self.counters.next_deposit.saturating_add(1);
        let deposit_note_id = shielded_vault_deposit_id(&request, sequence);
        let deposit_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEPOSIT_SCHEME,
            &json!({"deposit_note_id": deposit_note_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = ShieldedVaultDepositRecord {
            deposit_note_id: deposit_note_id.clone(),
            request,
            status: DepositNoteStatus::Accepted,
            accepted_at_height: self.config.current_height,
            deposit_root,
        };
        self.deposits.insert(deposit_note_id, record.clone());
        Ok(record)
    }

    pub fn attest_vault_risk(
        &mut self,
        request: AttestVaultRiskRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<VaultRiskAttestationRecord> {
        request.validate(&self.config)?;
        require(
            self.risk_attestations.len() < self.config.max_risk_attestations,
            "risk attestation capacity exhausted",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "risk attestation references unknown vault",
        )?;
        let sequence = self.counters.next_risk_attestation;
        self.counters.next_risk_attestation = self.counters.next_risk_attestation.saturating_add(1);
        let risk_attestation_id = vault_risk_attestation_id(&request, sequence);
        let risk_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RISK_SCHEME,
            &json!({"risk_attestation_id": risk_attestation_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(vault) = self.vaults.get_mut(&request.vault_id) {
            vault.status = if request.verdict.allows_rebalance() {
                VaultStatus::Active
            } else {
                VaultStatus::Paused
            };
        }
        let record = VaultRiskAttestationRecord {
            risk_attestation_id: risk_attestation_id.clone(),
            request,
            accepted_at_height: self.config.current_height,
            risk_root,
        };
        self.risk_attestations
            .insert(risk_attestation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_route(
        &mut self,
        request: ReserveLowFeeVaultRouteRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<LowFeeVaultRouteReservationRecord>
    {
        request.validate(&self.config)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "reservation capacity exhausted",
        )?;
        require(
            self.deposits.contains_key(&request.deposit_note_id),
            "reservation references unknown deposit note",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "reservation references unknown vault",
        )?;
        let sequence = self.counters.next_reservation;
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        let reservation_id = low_fee_vault_route_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RESERVATION_SCHEME,
            &json!({"reservation_id": reservation_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(deposit) = self.deposits.get_mut(&request.deposit_note_id) {
            deposit.status = DepositNoteStatus::Reserved;
        }
        let record = LowFeeVaultRouteReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
            reservation_root,
        };
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_private_rebalance(
        &mut self,
        request: BuildPrivateRebalanceRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<PrivateVaultRebalanceRecord> {
        request.validate(&self.config)?;
        require(
            self.rebalances.len() < self.config.max_rebalances,
            "rebalance capacity exhausted",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "rebalance references unknown vault",
        )?;
        for deposit_note_id in &request.deposit_note_ids {
            require(
                self.deposits.contains_key(deposit_note_id),
                "rebalance references unknown deposit note",
            )?;
        }
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "rebalance references unknown reservation",
            )?;
        }
        for risk_attestation_id in &request.risk_attestation_ids {
            let risk = self
                .risk_attestations
                .get(risk_attestation_id)
                .ok_or_else(|| "rebalance references unknown risk attestation".to_string())?;
            require(
                risk.request.verdict.allows_rebalance(),
                "risk attestation does not allow rebalance",
            )?;
        }
        let sequence = self.counters.next_rebalance;
        self.counters.next_rebalance = self.counters.next_rebalance.saturating_add(1);
        let rebalance_id = private_rebalance_id(&request, sequence);
        let rebalance_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBALANCE_SCHEME,
            &json!({"rebalance_id": rebalance_id, "sequence": sequence, "request": request.public_record()}),
        );
        for deposit_note_id in &request.deposit_note_ids {
            if let Some(deposit) = self.deposits.get_mut(deposit_note_id) {
                deposit.status = DepositNoteStatus::Batched;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Matched;
            }
        }
        if let Some(vault) = self.vaults.get_mut(&request.vault_id) {
            vault.status = VaultStatus::Rebalancing;
        }
        let record = PrivateVaultRebalanceRecord {
            rebalance_id: rebalance_id.clone(),
            request,
            status: RebalanceStatus::RiskApproved,
            built_at_height: self.config.current_height,
            rebalance_root,
        };
        self.rebalances.insert(rebalance_id, record.clone());
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishVaultSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<VaultSettlementReceiptRecord> {
        request.validate(&self.config)?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "settlement receipt capacity exhausted",
        )?;
        let rebalance = self
            .rebalances
            .get(&request.rebalance_id)
            .ok_or_else(|| "receipt references unknown rebalance".to_string())?;
        let deposit_note_ids = rebalance.request.deposit_note_ids.clone();
        let reservation_ids = rebalance.request.reservation_ids.clone();
        let vault_id = rebalance.request.vault_id.clone();
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        let receipt_id = vault_settlement_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RECEIPT_SCHEME,
            &json!({"receipt_id": receipt_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(rebalance) = self.rebalances.get_mut(&request.rebalance_id) {
            rebalance.status = RebalanceStatus::Settled;
        }
        for deposit_note_id in deposit_note_ids {
            if let Some(deposit) = self.deposits.get_mut(&deposit_note_id) {
                deposit.status = DepositNoteStatus::Settled;
            }
        }
        for reservation_id in reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(&reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        if let Some(vault) = self.vaults.get_mut(&vault_id) {
            vault.status = VaultStatus::Active;
        }
        let record = VaultSettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishVaultRebateRequest,
    ) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<VaultRebateReceiptRecord> {
        request.validate(&self.config)?;
        require(
            self.rebates.len() < self.config.max_receipts,
            "rebate capacity exhausted",
        )?;
        require(
            self.receipts.contains_key(&request.receipt_id),
            "rebate references unknown receipt",
        )?;
        let sequence = self.counters.next_rebate;
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        let rebate_id = vault_rebate_id(&request, sequence);
        let rebate_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBATE_SCHEME,
            &json!({"rebate_id": rebate_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(receipt) = self.receipts.get_mut(&request.receipt_id) {
            receipt.status = ReceiptStatus::Rebated;
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Rebated;
            }
        }
        let record = VaultRebateReceiptRecord {
            rebate_id: rebate_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            rebate_root,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            vault_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_VAULT_SCHEME,
                &self
                    .vaults
                    .values()
                    .map(StrategyVaultRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            deposit_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_DEPOSIT_SCHEME,
                &self
                    .deposits
                    .values()
                    .map(ShieldedVaultDepositRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            risk_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RISK_SCHEME,
                &self
                    .risk_attestations
                    .values()
                    .map(VaultRiskAttestationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            reservation_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RESERVATION_SCHEME,
                &self
                    .reservations
                    .values()
                    .map(LowFeeVaultRouteReservationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebalance_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBALANCE_SCHEME,
                &self
                    .rebalances
                    .values()
                    .map(PrivateVaultRebalanceRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_RECEIPT_SCHEME,
                &self
                    .receipts
                    .values()
                    .map(VaultSettlementReceiptRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_REBATE_SCHEME,
                &self
                    .rebates
                    .values()
                    .map(VaultRebateReceiptRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "vault_count": self.vaults.len(),
            "deposit_count": self.deposits.len(),
            "risk_attestation_count": self.risk_attestations.len(),
            "reservation_count": self.reservations.len(),
            "rebalance_count": self.rebalances.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn strategy_vault_id(request: &OpenStrategyVaultRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-STRATEGY-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(request.strategy_kind.as_str()),
            HashPart::Str(&request.vault_commitment),
            HashPart::Str(&request.manager_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn shielded_vault_deposit_id(
    request: &SubmitShieldedVaultDepositRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-DEPOSIT-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.depositor_commitment),
            HashPart::Str(&request.deposit_nullifier),
            HashPart::Str(&request.asset_note_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn vault_risk_attestation_id(request: &AttestVaultRiskRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.vault_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn low_fee_vault_route_reservation_id(
    request: &ReserveLowFeeVaultRouteRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-ROUTE-RESERVATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.deposit_note_id),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn private_rebalance_id(request: &BuildPrivateRebalanceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-REBALANCE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.vault_id),
            HashPart::Json(&json!(request.deposit_note_ids)),
            HashPart::Str(&request.target_strategy_root),
            HashPart::Str(&request.new_position_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn vault_settlement_receipt_id(
    request: &PublishVaultSettlementReceiptRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.rebalance_id),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn vault_rebate_id(request: &PublishVaultRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-REBATE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(request.reservation_ids)),
            HashPart::Str(&request.rebate_pool_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-STRATEGY-RECORD-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VAULT-STRATEGY-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a commitment/root"),
    )
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_VAULT_STRATEGY_ROUTER_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2ConfidentialVaultStrategyRouterRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}
