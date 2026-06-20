use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialCreditVaultRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-credit-vault-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-credit-vault-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_VAULT_SCHEME: &str =
    "private-l2-confidential-credit-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_COLLATERAL_SCHEME: &str =
    "shielded-confidential-credit-collateral-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_CREDIT_LINE_SCHEME: &str =
    "confidential-credit-line-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RISK_SCHEME: &str =
    "pq-confidential-credit-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-confidential-drawdown-reservation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_LIQUIDATION_SCHEME: &str =
    "private-confidential-credit-liquidation-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RECEIPT_SCHEME: &str =
    "private-confidential-credit-settlement-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_REBATE_SCHEME: &str =
    "private-confidential-credit-fee-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 701_000;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_VAULTS: usize = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_CREDIT_LINES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_LIQUIDATION_BATCHES: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_BATCH_CREDIT_LINES: usize =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_INTEREST_RATE_BPS: u64 = 2_400;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS: u64 =
    15_000;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS: u64 =
    12_500;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_DRAWDOWN_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditVaultKind {
    MoneroBacked,
    StableCredit,
    CrossMargin,
    IsolatedBorrow,
    RevolvingCredit,
    InstitutionalVault,
}

impl CreditVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBacked => "monero_backed",
            Self::StableCredit => "stable_credit",
            Self::CrossMargin => "cross_margin",
            Self::IsolatedBorrow => "isolated_borrow",
            Self::RevolvingCredit => "revolving_credit",
            Self::InstitutionalVault => "institutional_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DrawdownOnly,
    LiquidationOnly,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DrawdownOnly => "drawdown_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_credit_flow(self) -> bool {
        matches!(self, Self::Active | Self::DrawdownOnly)
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(self, Self::Active | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralNoteStatus {
    Submitted,
    Accepted,
    Encumbered,
    Released,
    LiquidationPending,
    Liquidated,
    Expired,
    Rejected,
}

impl CollateralNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Encumbered => "encumbered",
            Self::Released => "released",
            Self::LiquidationPending => "liquidation_pending",
            Self::Liquidated => "liquidated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_open_credit(self) -> bool {
        matches!(self, Self::Accepted | Self::Encumbered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditLineStatus {
    Pending,
    Open,
    Reserved,
    Drawn,
    RepaymentOnly,
    LiquidationPending,
    Settled,
    Closed,
    Rejected,
}

impl CreditLineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Drawn => "drawn",
            Self::RepaymentOnly => "repayment_only",
            Self::LiquidationPending => "liquidation_pending",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Open | Self::Reserved | Self::Drawn | Self::RepaymentOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    DrawdownBlocked,
    Liquidatable,
    Rejected,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::DrawdownBlocked => "drawdown_blocked",
            Self::Liquidatable => "liquidatable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_drawdown(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(self, Self::ReduceOnly | Self::Liquidatable)
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
pub enum LiquidationBatchStatus {
    Built,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl LiquidationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
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
pub enum ReceiptKind {
    VaultRegistered,
    CollateralSubmitted,
    CreditLineOpened,
    DrawdownReserved,
    RiskAttested,
    LiquidationSettled,
    RebatePublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultRegistered => "vault_registered",
            Self::CollateralSubmitted => "collateral_submitted",
            Self::CreditLineOpened => "credit_line_opened",
            Self::DrawdownReserved => "drawdown_reserved",
            Self::RiskAttested => "risk_attested",
            Self::LiquidationSettled => "liquidation_settled",
            Self::RebatePublished => "rebate_published",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub collateral_asset_id: String,
    pub credit_asset_id: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_vaults: usize,
    pub max_collateral_notes: usize,
    pub max_credit_lines: usize,
    pub max_risk_attestations: usize,
    pub max_reservations: usize,
    pub max_liquidation_batches: usize,
    pub max_receipts: usize,
    pub max_batch_credit_lines: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_interest_rate_bps: u64,
    pub min_collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub target_rebate_bps: u64,
    pub collateral_note_ttl_blocks: u64,
    pub drawdown_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            collateral_asset_id: "wxmr-devnet".to_string(),
            credit_asset_id: "zusd-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            low_fee_lane: "devnet-private-l2-credit-vault-low-fee".to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PQ_AUTH_SUITE.to_string(),
            max_vaults: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_VAULTS,
            max_collateral_notes:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES,
            max_credit_lines: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_CREDIT_LINES,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_reservations: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_liquidation_batches:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_LIQUIDATION_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_credit_lines:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_BATCH_CREDIT_LINES,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_interest_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MAX_INTEREST_RATE_BPS,
            min_collateral_factor_bps:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS,
            liquidation_threshold_bps:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            collateral_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            drawdown_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_DRAWDOWN_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require(
            self.protocol_version == PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PROTOCOL_VERSION,
            "unsupported confidential credit vault protocol version",
        )?;
        require(self.schema_version > 0, "schema version must be positive")?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        require_non_empty("credit_asset_id", &self.credit_asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("low_fee_lane", &self.low_fee_lane)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require(self.max_vaults > 0, "max_vaults must be positive")?;
        require(
            self.max_collateral_notes > 0,
            "max_collateral_notes must be positive",
        )?;
        require(
            self.max_credit_lines > 0,
            "max_credit_lines must be positive",
        )?;
        require(
            self.max_risk_attestations > 0,
            "max_risk_attestations must be positive",
        )?;
        require(
            self.max_reservations > 0,
            "max_reservations must be positive",
        )?;
        require(
            self.max_liquidation_batches > 0,
            "max_liquidation_batches must be positive",
        )?;
        require(self.max_receipts > 0, "max_receipts must be positive")?;
        require(
            self.max_batch_credit_lines > 0,
            "max_batch_credit_lines must be positive",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover individual privacy floor",
        )?;
        require(
            self.min_pq_security_bits
                >= PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "PQ security floor is too low",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("max_interest_rate_bps", self.max_interest_rate_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate cannot exceed user fee cap",
        )?;
        require(
            self.min_collateral_factor_bps > PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_MAX_BPS,
            "collateral factor must exceed full debt coverage",
        )?;
        require(
            self.liquidation_threshold_bps > PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_MAX_BPS
                && self.liquidation_threshold_bps <= self.min_collateral_factor_bps,
            "liquidation threshold must be over 100% and below collateral factor",
        )?;
        require(
            self.collateral_note_ttl_blocks > 0
                && self.drawdown_ttl_blocks > 0
                && self.settlement_ttl_blocks > 0,
            "runtime TTLs must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "collateral_asset_id": self.collateral_asset_id,
            "credit_asset_id": self.credit_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "max_vaults": self.max_vaults,
            "max_collateral_notes": self.max_collateral_notes,
            "max_credit_lines": self.max_credit_lines,
            "max_risk_attestations": self.max_risk_attestations,
            "max_reservations": self.max_reservations,
            "max_liquidation_batches": self.max_liquidation_batches,
            "max_receipts": self.max_receipts,
            "max_batch_credit_lines": self.max_batch_credit_lines,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "min_collateral_factor_bps": self.min_collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "collateral_note_ttl_blocks": self.collateral_note_ttl_blocks,
            "drawdown_ttl_blocks": self.drawdown_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_vault: u64,
    pub next_collateral_note: u64,
    pub next_credit_line: u64,
    pub next_risk_attestation: u64,
    pub next_reservation: u64,
    pub next_liquidation_batch: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_vault": self.next_vault,
            "next_collateral_note": self.next_collateral_note,
            "next_credit_line": self.next_credit_line,
            "next_risk_attestation": self.next_risk_attestation,
            "next_reservation": self.next_reservation,
            "next_liquidation_batch": self.next_liquidation_batch,
            "next_receipt": self.next_receipt,
            "next_rebate": self.next_rebate,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterShieldedCreditVaultRequest {
    pub vault_kind: CreditVaultKind,
    pub vault_commitment: String,
    pub operator_commitment: String,
    pub collateral_asset_root: String,
    pub credit_asset_root: String,
    pub reserve_note_root: String,
    pub interest_model_root: String,
    pub oracle_root: String,
    pub risk_policy_root: String,
    pub privacy_policy_root: String,
    pub pq_authority_root: String,
    pub low_fee_sponsor_root: String,
    pub vault_nullifier: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl RegisterShieldedCreditVaultRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_commitment", &self.vault_commitment)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_root("collateral_asset_root", &self.collateral_asset_root)?;
        require_root("credit_asset_root", &self.credit_asset_root)?;
        require_root("reserve_note_root", &self.reserve_note_root)?;
        require_root("interest_model_root", &self.interest_model_root)?;
        require_root("risk_policy_root", &self.risk_policy_root)?;
        require_root("privacy_policy_root", &self.privacy_policy_root)?;
        require_root("pq_authority_root", &self.pq_authority_root)?;
        require_root("vault_nullifier", &self.vault_nullifier)?;
        if config.require_oracle_bound {
            require_root("oracle_root", &self.oracle_root)?;
        }
        if config.require_low_fee_sponsor {
            require_root("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.min_privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require_bps("max_interest_rate_bps", self.max_interest_rate_bps)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_interest_rate_bps <= config.max_interest_rate_bps,
            "vault interest rate exceeds policy",
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "vault fee exceeds low-fee cap",
        )?;
        require(
            self.collateral_factor_bps >= config.min_collateral_factor_bps,
            "vault collateral factor below configured minimum",
        )?;
        require(
            self.liquidation_threshold_bps >= config.liquidation_threshold_bps
                && self.liquidation_threshold_bps <= self.collateral_factor_bps,
            "vault liquidation threshold is outside policy",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_kind": self.vault_kind.as_str(),
            "vault_commitment": self.vault_commitment,
            "operator_commitment": self.operator_commitment,
            "collateral_asset_root": self.collateral_asset_root,
            "credit_asset_root": self.credit_asset_root,
            "reserve_note_root": self.reserve_note_root,
            "interest_model_root": self.interest_model_root,
            "oracle_root": self.oracle_root,
            "risk_policy_root": self.risk_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "vault_nullifier": self.vault_nullifier,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitShieldedCollateralNoteRequest {
    pub vault_id: String,
    pub owner_commitment: String,
    pub collateral_note_root: String,
    pub amount_commitment_root: String,
    pub custody_lock_root: String,
    pub range_proof_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub note_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitShieldedCollateralNoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_root("collateral_note_root", &self.collateral_note_root)?;
        require_root("amount_commitment_root", &self.amount_commitment_root)?;
        require_root("custody_lock_root", &self.custody_lock_root)?;
        require_root("range_proof_root", &self.range_proof_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_root("note_nullifier", &self.note_nullifier)?;
        if config.require_low_fee_sponsor {
            require_root("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "collateral note fee exceeds low-fee cap",
        )?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "collateral note expiry must follow submission height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "collateral_note_root": self.collateral_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "custody_lock_root": self.custody_lock_root,
            "range_proof_root": self.range_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "note_nullifier": self.note_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenConfidentialCreditLineRequest {
    pub vault_id: String,
    pub collateral_note_id: String,
    pub borrower_commitment: String,
    pub credit_note_root: String,
    pub credit_limit_commitment_root: String,
    pub collateral_position_root: String,
    pub health_factor_commitment_root: String,
    pub oracle_bound_root: String,
    pub repayment_schedule_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub credit_nullifier: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenConfidentialCreditLineRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("collateral_note_id", &self.collateral_note_id)?;
        require_non_empty("borrower_commitment", &self.borrower_commitment)?;
        require_root("credit_note_root", &self.credit_note_root)?;
        require_root(
            "credit_limit_commitment_root",
            &self.credit_limit_commitment_root,
        )?;
        require_root("collateral_position_root", &self.collateral_position_root)?;
        require_root(
            "health_factor_commitment_root",
            &self.health_factor_commitment_root,
        )?;
        require_root("repayment_schedule_root", &self.repayment_schedule_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_root("credit_nullifier", &self.credit_nullifier)?;
        if config.require_oracle_bound {
            require_root("oracle_bound_root", &self.oracle_bound_root)?;
        }
        if config.require_low_fee_sponsor {
            require_root("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.collateral_factor_bps >= config.min_collateral_factor_bps,
            "credit line collateral factor below configured minimum",
        )?;
        require(
            self.max_interest_rate_bps <= config.max_interest_rate_bps
                && self.max_fee_bps <= config.max_user_fee_bps,
            "credit line rate or fee exceeds policy",
        )?;
        require(
            self.expires_at_height > self.opened_at_height,
            "credit line expiry must follow open height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "collateral_note_id": self.collateral_note_id,
            "borrower_commitment": self.borrower_commitment,
            "credit_note_root": self.credit_note_root,
            "credit_limit_commitment_root": self.credit_limit_commitment_root,
            "collateral_position_root": self.collateral_position_root,
            "health_factor_commitment_root": self.health_factor_commitment_root,
            "oracle_bound_root": self.oracle_bound_root,
            "repayment_schedule_root": self.repayment_schedule_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "credit_nullifier": self.credit_nullifier,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeDrawdownRequest {
    pub vault_id: String,
    pub credit_line_id: String,
    pub borrower_commitment: String,
    pub drawdown_note_root: String,
    pub reservation_nullifier: String,
    pub fee_budget_commitment_root: String,
    pub route_policy_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeDrawdownRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("credit_line_id", &self.credit_line_id)?;
        require_non_empty("borrower_commitment", &self.borrower_commitment)?;
        require_root("drawdown_note_root", &self.drawdown_note_root)?;
        require_root("reservation_nullifier", &self.reservation_nullifier)?;
        require_root(
            "fee_budget_commitment_root",
            &self.fee_budget_commitment_root,
        )?;
        require_root("route_policy_root", &self.route_policy_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "drawdown reservation fee exceeds low-fee cap",
        )?;
        require(
            self.expires_at_height > self.reserved_at_height,
            "drawdown reservation expiry must follow reservation height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "credit_line_id": self.credit_line_id,
            "borrower_commitment": self.borrower_commitment,
            "drawdown_note_root": self.drawdown_note_root,
            "reservation_nullifier": self.reservation_nullifier,
            "fee_budget_commitment_root": self.fee_budget_commitment_root,
            "route_policy_root": self.route_policy_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestCreditRiskRequest {
    pub vault_id: String,
    pub credit_line_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub risk_score_bps: u64,
    pub health_factor_bps: u64,
    pub exposure_commitment_root: String,
    pub oracle_root: String,
    pub proof_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestCreditRiskRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("credit_line_id", &self.credit_line_id)?;
        require_non_empty("attestor_commitment", &self.attestor_commitment)?;
        require_root("exposure_commitment_root", &self.exposure_commitment_root)?;
        require_root("oracle_root", &self.oracle_root)?;
        require_root("proof_root", &self.proof_root)?;
        require_root("pq_attestation_root", &self.pq_attestation_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_root("attestation_nullifier", &self.attestation_nullifier)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require_bps("risk_score_bps", self.risk_score_bps)?;
        require(
            !self.verdict.allows_drawdown()
                || self.health_factor_bps >= config.min_collateral_factor_bps,
            "drawdown-allowing attestation has insufficient health",
        )?;
        require(
            !self.verdict.allows_liquidation()
                || self.health_factor_bps <= config.liquidation_threshold_bps,
            "liquidation verdict requires health below threshold",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "credit_line_id": self.credit_line_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "health_factor_bps": self.health_factor_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "oracle_root": self.oracle_root,
            "proof_root": self.proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPrivateLiquidationBatchRequest {
    pub vault_id: String,
    pub credit_line_ids: Vec<String>,
    pub risk_attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_credit_root: String,
    pub auction_clearing_root: String,
    pub liquidation_proof_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildPrivateLiquidationBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require(
            !self.credit_line_ids.is_empty(),
            "liquidation batch must include credit lines",
        )?;
        require(
            self.credit_line_ids.len() <= config.max_batch_credit_lines,
            "liquidation batch exceeds credit line limit",
        )?;
        require_unique("credit_line_ids", &self.credit_line_ids)?;
        require_unique("risk_attestation_ids", &self.risk_attestation_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_non_empty("liquidator_commitment", &self.liquidator_commitment)?;
        require_root("seized_collateral_root", &self.seized_collateral_root)?;
        require_root("repaid_credit_root", &self.repaid_credit_root)?;
        require_root("auction_clearing_root", &self.auction_clearing_root)?;
        require_root("liquidation_proof_root", &self.liquidation_proof_root)?;
        require_root(
            "recursive_batch_proof_root",
            &self.recursive_batch_proof_root,
        )?;
        require_root(
            "pq_batch_authorization_root",
            &self.pq_batch_authorization_root,
        )?;
        if config.require_low_fee_sponsor {
            require_root("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        require(
            self.privacy_set_size >= config.batch_privacy_set_size,
            "liquidation batch privacy set is too small",
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "liquidation batch fee exceeds low-fee cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "credit_line_ids": self.credit_line_ids,
            "risk_attestation_ids": self.risk_attestation_ids,
            "reservation_ids": self.reservation_ids,
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_credit_root": self.repaid_credit_root,
            "auction_clearing_root": self.auction_clearing_root,
            "liquidation_proof_root": self.liquidation_proof_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl PublishSettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("settlement_tx_root", &self.settlement_tx_root)?;
        require_root("settlement_proof_root", &self.settlement_proof_root)?;
        require_root("account_delta_root", &self.account_delta_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("output_note_root", &self.output_note_root)?;
        require_root("pq_settlement_root", &self.pq_settlement_root)?;
        require_root("state_root_after", &self.state_root_after)?;
        if config.require_low_fee_sponsor {
            require_root(
                "low_fee_sponsor_receipt_root",
                &self.low_fee_sponsor_receipt_root,
            )?;
        }
        require(
            self.settled_fee_bps <= config.max_user_fee_bps,
            "settlement fee exceeds low-fee cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishFeeRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_output_root: String,
    pub rebate_proof_root: String,
    pub pq_rebate_authorization_root: String,
    pub target_rebate_bps: u64,
    pub published_at_height: u64,
}

impl PublishFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require(
            !self.reservation_ids.is_empty(),
            "rebate must include reservations",
        )?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("rebate_pool_root", &self.rebate_pool_root)?;
        require_root("rebate_output_root", &self.rebate_output_root)?;
        require_root("rebate_proof_root", &self.rebate_proof_root)?;
        require_root(
            "pq_rebate_authorization_root",
            &self.pq_rebate_authorization_root,
        )?;
        require(
            self.target_rebate_bps <= config.max_user_fee_bps,
            "rebate exceeds user fee cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_ids": self.reservation_ids,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_output_root": self.rebate_output_root,
            "rebate_proof_root": self.rebate_proof_root,
            "pq_rebate_authorization_root": self.pq_rebate_authorization_root,
            "target_rebate_bps": self.target_rebate_bps,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCreditVaultRecord {
    pub vault_id: String,
    pub request: RegisterShieldedCreditVaultRequest,
    pub status: VaultStatus,
    pub latest_state_root: String,
    pub collateral_note_ids: Vec<String>,
    pub credit_line_ids: Vec<String>,
    pub liquidation_batch_ids: Vec<String>,
}

impl ShieldedCreditVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "latest_state_root": self.latest_state_root,
            "collateral_note_ids": self.collateral_note_ids,
            "credit_line_ids": self.credit_line_ids,
            "liquidation_batch_ids": self.liquidation_batch_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCollateralNoteRecord {
    pub collateral_note_id: String,
    pub request: SubmitShieldedCollateralNoteRequest,
    pub status: CollateralNoteStatus,
    pub note_root: String,
}

impl ShieldedCollateralNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "collateral_note_id": self.collateral_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "note_root": self.note_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCreditLineRecord {
    pub credit_line_id: String,
    pub request: OpenConfidentialCreditLineRequest,
    pub status: CreditLineStatus,
    pub credit_line_root: String,
}

impl ConfidentialCreditLineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_line_id": self.credit_line_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "credit_line_root": self.credit_line_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestationRecord {
    pub risk_attestation_id: String,
    pub request: AttestCreditRiskRequest,
    pub risk_root: String,
}

impl PqRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_attestation_id": self.risk_attestation_id,
            "request": self.request.public_record(),
            "risk_root": self.risk_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDrawdownReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeDrawdownRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl LowFeeDrawdownReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationBatchRecord {
    pub liquidation_batch_id: String,
    pub request: BuildPrivateLiquidationBatchRequest,
    pub status: LiquidationBatchStatus,
    pub settlement_deadline_height: u64,
    pub liquidation_root: String,
}

impl PrivateLiquidationBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_batch_id": self.liquidation_batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "settlement_deadline_height": self.settlement_deadline_height,
            "liquidation_root": self.liquidation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: PublishSettlementReceiptRequest,
    pub receipt_root: String,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub request: PublishFeeRebateRequest,
    pub rebate_root: String,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub vault_root: String,
    pub collateral_note_root: String,
    pub credit_line_root: String,
    pub risk_attestation_root: String,
    pub reservation_root: String,
    pub liquidation_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "collateral_note_root": self.collateral_note_root,
            "credit_line_root": self.credit_line_root,
            "risk_attestation_root": self.risk_attestation_root,
            "reservation_root": self.reservation_root,
            "liquidation_batch_root": self.liquidation_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub vaults: BTreeMap<String, ShieldedCreditVaultRecord>,
    pub collateral_notes: BTreeMap<String, ShieldedCollateralNoteRecord>,
    pub credit_lines: BTreeMap<String, ConfidentialCreditLineRecord>,
    pub risk_attestations: BTreeMap<String, PqRiskAttestationRecord>,
    pub reservations: BTreeMap<String, LowFeeDrawdownReservationRecord>,
    pub liquidation_batches: BTreeMap<String, PrivateLiquidationBatchRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height,
            vaults: BTreeMap::new(),
            collateral_notes: BTreeMap::new(),
            credit_lines: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            liquidation_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn register_vault(
        &mut self,
        request: RegisterShieldedCreditVaultRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<ShieldedCreditVaultRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.vaults.len() < self.config.max_vaults,
            "credit vault capacity exhausted",
        )?;
        self.consume_nullifier(&request.vault_nullifier)?;
        let sequence = self.counters.next_vault;
        self.counters.next_vault = self.counters.next_vault.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let vault_id = credit_vault_id(&request, sequence);
        let latest_state_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_VAULT_SCHEME,
            &json!({"vault_id": vault_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = ShieldedCreditVaultRecord {
            vault_id: vault_id.clone(),
            request,
            status: VaultStatus::Active,
            latest_state_root,
            collateral_note_ids: Vec::new(),
            credit_line_ids: Vec::new(),
            liquidation_batch_ids: Vec::new(),
        };
        self.vaults.insert(vault_id, record.clone());
        Ok(record)
    }

    pub fn submit_collateral_note(
        &mut self,
        request: SubmitShieldedCollateralNoteRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<ShieldedCollateralNoteRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.collateral_notes.len() < self.config.max_collateral_notes,
            "collateral note capacity exhausted",
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "collateral note references unknown vault".to_string())?;
        require(
            vault.status.accepts_credit_flow(),
            "vault is not accepting collateral notes",
        )?;
        self.consume_nullifier(&request.note_nullifier)?;
        let sequence = self.counters.next_collateral_note;
        self.counters.next_collateral_note = self.counters.next_collateral_note.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let collateral_note_id = shielded_collateral_note_id(&request, sequence);
        let note_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_COLLATERAL_SCHEME,
            &json!({"collateral_note_id": collateral_note_id, "sequence": sequence, "request": request.public_record()}),
        );
        let vault_id = request.vault_id.clone();
        let record = ShieldedCollateralNoteRecord {
            collateral_note_id: collateral_note_id.clone(),
            request,
            status: CollateralNoteStatus::Accepted,
            note_root,
        };
        if let Some(vault) = self.vaults.get_mut(&vault_id) {
            vault.collateral_note_ids.push(collateral_note_id.clone());
        }
        self.collateral_notes
            .insert(collateral_note_id, record.clone());
        Ok(record)
    }

    pub fn open_credit_line(
        &mut self,
        request: OpenConfidentialCreditLineRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<ConfidentialCreditLineRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.credit_lines.len() < self.config.max_credit_lines,
            "credit line capacity exhausted",
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "credit line references unknown vault".to_string())?;
        require(
            vault.status.accepts_credit_flow(),
            "vault is not accepting credit lines",
        )?;
        let collateral = self
            .collateral_notes
            .get(&request.collateral_note_id)
            .ok_or_else(|| "credit line references unknown collateral note".to_string())?;
        require(
            collateral.request.vault_id == request.vault_id,
            "collateral note belongs to another vault",
        )?;
        require(
            collateral.status.can_open_credit(),
            "collateral note cannot open credit",
        )?;
        self.consume_nullifier(&request.credit_nullifier)?;
        let sequence = self.counters.next_credit_line;
        self.counters.next_credit_line = self.counters.next_credit_line.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let credit_line_id = confidential_credit_line_id(&request, sequence);
        let credit_line_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_CREDIT_LINE_SCHEME,
            &json!({"credit_line_id": credit_line_id, "sequence": sequence, "request": request.public_record()}),
        );
        let vault_id = request.vault_id.clone();
        let collateral_note_id = request.collateral_note_id.clone();
        let record = ConfidentialCreditLineRecord {
            credit_line_id: credit_line_id.clone(),
            request,
            status: CreditLineStatus::Open,
            credit_line_root,
        };
        if let Some(collateral) = self.collateral_notes.get_mut(&collateral_note_id) {
            collateral.status = CollateralNoteStatus::Encumbered;
        }
        if let Some(vault) = self.vaults.get_mut(&vault_id) {
            vault.credit_line_ids.push(credit_line_id.clone());
        }
        self.credit_lines.insert(credit_line_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_drawdown(
        &mut self,
        request: ReserveLowFeeDrawdownRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<LowFeeDrawdownReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "drawdown reservation capacity exhausted",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "reservation references unknown vault",
        )?;
        let credit_line = self
            .credit_lines
            .get(&request.credit_line_id)
            .ok_or_else(|| "reservation references unknown credit line".to_string())?;
        require(
            credit_line.request.vault_id == request.vault_id,
            "reservation credit line belongs to another vault",
        )?;
        require(
            matches!(
                credit_line.status,
                CreditLineStatus::Open | CreditLineStatus::Drawn
            ),
            "credit line is not eligible for drawdown reservation",
        )?;
        self.consume_nullifier(&request.reservation_nullifier)?;
        let sequence = self.counters.next_reservation;
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id = low_fee_drawdown_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RESERVATION_SCHEME,
            &json!({"reservation_id": reservation_id, "sequence": sequence, "request": request.public_record()}),
        );
        let credit_line_id = request.credit_line_id.clone();
        let record = LowFeeDrawdownReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
            reservation_root,
        };
        if let Some(credit_line) = self.credit_lines.get_mut(&credit_line_id) {
            credit_line.status = CreditLineStatus::Reserved;
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn attest_risk(
        &mut self,
        request: AttestCreditRiskRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<PqRiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.risk_attestations.len() < self.config.max_risk_attestations,
            "risk attestation capacity exhausted",
        )?;
        require(
            self.vaults.contains_key(&request.vault_id),
            "risk attestation references unknown vault",
        )?;
        let credit_line = self
            .credit_lines
            .get(&request.credit_line_id)
            .ok_or_else(|| "risk attestation references unknown credit line".to_string())?;
        require(
            credit_line.request.vault_id == request.vault_id,
            "risk attestation credit line belongs to another vault",
        )?;
        require(
            credit_line.status.live(),
            "risk attestation cannot target a closed credit line",
        )?;
        let collateral_note_id = credit_line.request.collateral_note_id.clone();
        self.consume_nullifier(&request.attestation_nullifier)?;
        let sequence = self.counters.next_risk_attestation;
        self.counters.next_risk_attestation = self.counters.next_risk_attestation.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let risk_attestation_id = credit_risk_attestation_id(&request, sequence);
        let risk_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RISK_SCHEME,
            &json!({"risk_attestation_id": risk_attestation_id, "sequence": sequence, "request": request.public_record()}),
        );
        let credit_line_id = request.credit_line_id.clone();
        let record = PqRiskAttestationRecord {
            risk_attestation_id: risk_attestation_id.clone(),
            request,
            risk_root,
        };
        if let Some(credit_line) = self.credit_lines.get_mut(&credit_line_id) {
            credit_line.status = if record.request.verdict.allows_liquidation() {
                CreditLineStatus::LiquidationPending
            } else if record.request.verdict.allows_drawdown() {
                CreditLineStatus::Open
            } else if record.request.verdict == RiskVerdict::ReduceOnly {
                CreditLineStatus::RepaymentOnly
            } else {
                CreditLineStatus::Rejected
            };
        }
        if record.request.verdict.allows_liquidation() {
            if let Some(collateral) = self.collateral_notes.get_mut(&collateral_note_id) {
                collateral.status = CollateralNoteStatus::LiquidationPending;
            }
        }
        self.risk_attestations
            .insert(risk_attestation_id, record.clone());
        Ok(record)
    }

    pub fn build_private_liquidation_batch(
        &mut self,
        request: BuildPrivateLiquidationBatchRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<PrivateLiquidationBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.liquidation_batches.len() < self.config.max_liquidation_batches,
            "liquidation batch capacity exhausted",
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "liquidation batch references unknown vault".to_string())?;
        require(
            vault.status.accepts_liquidations(),
            "vault is not accepting liquidations",
        )?;
        for credit_line_id in &request.credit_line_ids {
            let credit_line = self
                .credit_lines
                .get(credit_line_id)
                .ok_or_else(|| format!("unknown credit line {credit_line_id}"))?;
            require(
                credit_line.request.vault_id == request.vault_id,
                "liquidation credit line belongs to another vault",
            )?;
            require(
                credit_line.status == CreditLineStatus::LiquidationPending,
                "liquidation requires liquidation-pending credit lines",
            )?;
        }
        for risk_attestation_id in &request.risk_attestation_ids {
            let attestation = self
                .risk_attestations
                .get(risk_attestation_id)
                .ok_or_else(|| "liquidation references unknown risk attestation".to_string())?;
            require(
                attestation.request.verdict.allows_liquidation(),
                "risk attestation does not allow liquidation",
            )?;
        }
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "liquidation references unknown reservation",
            )?;
        }
        let sequence = self.counters.next_liquidation_batch;
        self.counters.next_liquidation_batch =
            self.counters.next_liquidation_batch.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let liquidation_batch_id = private_liquidation_batch_id(&request, sequence);
        let liquidation_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_LIQUIDATION_SCHEME,
            &json!({"liquidation_batch_id": liquidation_batch_id, "sequence": sequence, "request": request.public_record()}),
        );
        for credit_line_id in &request.credit_line_ids {
            if let Some(credit_line) = self.credit_lines.get_mut(credit_line_id) {
                credit_line.status = CreditLineStatus::LiquidationPending;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Matched;
            }
        }
        if let Some(vault) = self.vaults.get_mut(&request.vault_id) {
            vault
                .liquidation_batch_ids
                .push(liquidation_batch_id.clone());
            vault.status = VaultStatus::LiquidationOnly;
        }
        let record = PrivateLiquidationBatchRecord {
            liquidation_batch_id: liquidation_batch_id.clone(),
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            request,
            status: LiquidationBatchStatus::SettlementReady,
            liquidation_root,
        };
        self.liquidation_batches
            .insert(liquidation_batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.settlement_receipts.len() < self.config.max_receipts,
            "settlement receipt capacity exhausted",
        )?;
        if request.receipt_kind == ReceiptKind::LiquidationSettled {
            let batch = self
                .liquidation_batches
                .get(&request.subject_id)
                .ok_or_else(|| "receipt references unknown liquidation batch".to_string())?
                .clone();
            require(
                batch.status.can_settle(),
                "liquidation batch is not settlement-ready",
            )?;
            require(
                request.settled_at_height <= batch.settlement_deadline_height,
                "liquidation settlement deadline elapsed",
            )?;
            for credit_line_id in &batch.request.credit_line_ids {
                if let Some(credit_line) = self.credit_lines.get_mut(credit_line_id) {
                    credit_line.status = CreditLineStatus::Settled;
                    let collateral_note_id = credit_line.request.collateral_note_id.clone();
                    if let Some(collateral) = self.collateral_notes.get_mut(&collateral_note_id) {
                        collateral.status = CollateralNoteStatus::Liquidated;
                    }
                }
            }
            for reservation_id in &batch.request.reservation_ids {
                if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                    reservation.status = ReservationStatus::Consumed;
                }
            }
            if let Some(stored_batch) = self.liquidation_batches.get_mut(&request.subject_id) {
                stored_batch.status = LiquidationBatchStatus::Settled;
            }
            if let Some(vault) = self.vaults.get_mut(&batch.request.vault_id) {
                vault.status = VaultStatus::Active;
                vault.latest_state_root = request.state_root_after.clone();
            }
        }
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RECEIPT_SCHEME,
            &json!({"receipt_id": receipt_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.settlement_receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishFeeRebateRequest,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<FeeRebateRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.rebates.len() < self.config.max_receipts,
            "rebate capacity exhausted",
        )?;
        require(
            self.settlement_receipts.contains_key(&request.receipt_id),
            "rebate references unknown settlement receipt",
        )?;
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "rebate references unknown reservation",
            )?;
        }
        let sequence = self.counters.next_rebate;
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        self.current_height = self.current_height.max(request.published_at_height);
        let rebate_id = fee_rebate_id(&request, sequence);
        let rebate_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_REBATE_SCHEME,
            &json!({"rebate_id": rebate_id, "sequence": sequence, "request": request.public_record()}),
        );
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Rebated;
            }
        }
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            rebate_root,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let vault_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_VAULT_SCHEME,
            &self
                .vaults
                .values()
                .map(ShieldedCreditVaultRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let collateral_note_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_COLLATERAL_SCHEME,
            &self
                .collateral_notes
                .values()
                .map(ShieldedCollateralNoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let credit_line_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_CREDIT_LINE_SCHEME,
            &self
                .credit_lines
                .values()
                .map(ConfidentialCreditLineRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RISK_SCHEME,
            &self
                .risk_attestations
                .values()
                .map(PqRiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RESERVATION_SCHEME,
            &self
                .reservations
                .values()
                .map(LowFeeDrawdownReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidation_batch_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_LIQUIDATION_SCHEME,
            &self
                .liquidation_batches
                .values()
                .map(PrivateLiquidationBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_RECEIPT_SCHEME,
            &self
                .settlement_receipts
                .values()
                .map(SettlementReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_REBATE_SCHEME,
            &self
                .rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CREDIT-VAULT-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = state_root_from_record(&json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "current_height": self.current_height,
            "vault_root": vault_root,
            "collateral_note_root": collateral_note_root,
            "credit_line_root": credit_line_root,
            "risk_attestation_root": risk_attestation_root,
            "reservation_root": reservation_root,
            "liquidation_batch_root": liquidation_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
            "counters": self.counters.public_record(),
        }));
        Roots {
            vault_root,
            collateral_note_root,
            credit_line_root,
            risk_attestation_root,
            reservation_root,
            liquidation_batch_root,
            settlement_receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "vault_ids": self.vaults.keys().cloned().collect::<Vec<_>>(),
            "collateral_note_ids": self.collateral_notes.keys().cloned().collect::<Vec<_>>(),
            "credit_line_ids": self.credit_lines.keys().cloned().collect::<Vec<_>>(),
            "risk_attestation_ids": self.risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "liquidation_batch_ids": self.liquidation_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "rebate_ids": self.rebates.keys().cloned().collect::<Vec<_>>(),
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
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-CREDIT-VAULT-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        require(
            self.consumed_nullifiers.insert(nullifier_hash),
            "confidential credit vault nullifier replay detected",
        )?;
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn credit_vault_id(request: &RegisterShieldedCreditVaultRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-VAULT-ID",
        &[
            HashPart::Str(request.vault_kind.as_str()),
            HashPart::Str(&request.vault_commitment),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.vault_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn shielded_collateral_note_id(
    request: &SubmitShieldedCollateralNoteRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-COLLATERAL-NOTE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.collateral_note_root),
            HashPart::Str(&request.note_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn confidential_credit_line_id(
    request: &OpenConfidentialCreditLineRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-LINE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.collateral_note_id),
            HashPart::Str(&request.borrower_commitment),
            HashPart::Str(&request.credit_note_root),
            HashPart::Str(&request.credit_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn low_fee_drawdown_reservation_id(
    request: &ReserveLowFeeDrawdownRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-DRAWDOWN-RESERVATION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.credit_line_id),
            HashPart::Str(&request.drawdown_note_root),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn credit_risk_attestation_id(request: &AttestCreditRiskRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.credit_line_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn private_liquidation_batch_id(
    request: &BuildPrivateLiquidationBatchRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-LIQUIDATION-BATCH-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Json(&json!(request.credit_line_ids)),
            HashPart::Str(&request.seized_collateral_root),
            HashPart::Str(&request.repaid_credit_root),
            HashPart::Str(&request.recursive_batch_proof_root),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.state_root_after),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn fee_rebate_id(request: &PublishFeeRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-CREDIT-FEE-REBATE-ID",
        &[
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(request.reservation_ids)),
            HashPart::Str(&request.rebate_pool_root),
            HashPart::Str(&request.rebate_output_root),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-CREDIT-VAULT-STATE-ROOT", record)
}

fn require(condition: bool, message: &str) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a commitment/root"),
    )
}

fn require_bps(label: &str, value: u64) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_CREDIT_VAULT_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2ConfidentialCreditVaultRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}
