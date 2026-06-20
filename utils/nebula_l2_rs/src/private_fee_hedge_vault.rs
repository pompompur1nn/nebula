use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateFeeHedgeVaultResult<T> = Result<T, String>;

pub const PRIVATE_FEE_HEDGE_VAULT_PROTOCOL_VERSION: &str = "nebula-private-fee-hedge-vault-v1";
pub const PRIVATE_FEE_HEDGE_VAULT_SCHEMA_VERSION: &str = "private-fee-hedge-vault-state-v1";
pub const PRIVATE_FEE_HEDGE_VAULT_DEVNET_LABEL: &str = "devnet-private-fee-hedge-vault";
pub const PRIVATE_FEE_HEDGE_VAULT_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PRIVATE_FEE_HEDGE_VAULT_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-fee-hedge-attestation";
pub const PRIVATE_FEE_HEDGE_VAULT_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PRIVATE_FEE_HEDGE_VAULT_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_FEE_HEDGE_VAULT_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_FEE_HEDGE_VAULT_DEFAULT_MAX_DISCOUNT_BPS: u64 = 8_000;
pub const PRIVATE_FEE_HEDGE_VAULT_DEFAULT_TARGET_RESERVE_BPS: u64 = 11_000;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_VAULTS: usize = 1_024;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_POLICIES: usize = 2_048;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_LOCKS: usize = 32_768;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_SETTLEMENTS: usize = 32_768;
pub const PRIVATE_FEE_HEDGE_VAULT_MAX_ORACLE_QUOTES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeHedgeLane {
    PrivateTransfer,
    ContractCall,
    MoneroExit,
    AmmSwap,
    Lending,
    Perps,
    ProofAggregation,
    WalletRecovery,
}

impl FeeHedgeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::MoneroExit => "monero_exit",
            Self::AmmSwap => "amm_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::MoneroExit => 9,
            Self::PrivateTransfer | Self::ContractCall => 8,
            Self::AmmSwap | Self::Lending | Self::Perps => 7,
            Self::ProofAggregation => 6,
            Self::WalletRecovery => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeVaultStatus {
    Active,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl HedgeVaultStatus {
    pub fn can_quote(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgePolicyStatus {
    Active,
    Saturated,
    Suspended,
    Expired,
}

impl HedgePolicyStatus {
    pub fn accepts_locks(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeLockStatus {
    Open,
    Matched,
    Settled,
    Expired,
    Challenged,
}

impl HedgeLockStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Challenged)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeSettlementStatus {
    Pending,
    Accepted,
    Rejected,
    Finalized,
}

impl HedgeSettlementStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Finalized => "finalized",
        }
    }
}

pub trait PrivateFeeHedgeRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFeeHedgeVaultConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub commitment_scheme: String,
    pub pq_attestation_scheme: String,
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_discount_bps: u64,
    pub target_reserve_bps: u64,
    pub privacy_policy_root: String,
}

impl PrivateFeeHedgeVaultConfig {
    pub fn devnet() -> PrivateFeeHedgeVaultResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_FEE_HEDGE_VAULT_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_FEE_HEDGE_VAULT_SCHEMA_VERSION.to_string(),
            commitment_scheme: PRIVATE_FEE_HEDGE_VAULT_COMMITMENT_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_FEE_HEDGE_VAULT_PQ_ATTESTATION_SCHEME.to_string(),
            epoch_blocks: PRIVATE_FEE_HEDGE_VAULT_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: PRIVATE_FEE_HEDGE_VAULT_DEFAULT_QUOTE_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_FEE_HEDGE_VAULT_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_discount_bps: PRIVATE_FEE_HEDGE_VAULT_DEFAULT_MAX_DISCOUNT_BPS,
            target_reserve_bps: PRIVATE_FEE_HEDGE_VAULT_DEFAULT_TARGET_RESERVE_BPS,
            privacy_policy_root: private_fee_hedge_string_root(
                "PRIVATE-FEE-HEDGE-PRIVACY-POLICY",
                "quote-roots-and-settlement-receipts-only",
            ),
        };
        config.config_id =
            private_fee_hedge_config_id(&config.protocol_version, &config.schema_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.config_id, "private fee hedge config id")?;
        ensure_non_empty(&self.protocol_version, "private fee hedge protocol version")?;
        ensure_non_empty(&self.schema_version, "private fee hedge schema version")?;
        ensure_non_empty(
            &self.commitment_scheme,
            "private fee hedge commitment scheme",
        )?;
        ensure_non_empty(&self.pq_attestation_scheme, "private fee hedge pq scheme")?;
        ensure_non_empty(&self.privacy_policy_root, "private fee hedge privacy root")?;
        if self.epoch_blocks == 0 || self.quote_ttl_blocks == 0 || self.settlement_ttl_blocks == 0 {
            return Err("private fee hedge timing values must be positive".to_string());
        }
        if self.max_discount_bps > PRIVATE_FEE_HEDGE_VAULT_MAX_BPS {
            return Err("private fee hedge max discount exceeds bps cap".to_string());
        }
        if self.target_reserve_bps < PRIVATE_FEE_HEDGE_VAULT_MAX_BPS {
            return Err(
                "private fee hedge target reserve must be at least fully collateralized"
                    .to_string(),
            );
        }
        let expected = private_fee_hedge_config_id(&self.protocol_version, &self.schema_version);
        if self.config_id != expected {
            return Err("private fee hedge config id does not match protocol".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for PrivateFeeHedgeVaultConfig {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_hedge_vault_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "commitment_scheme": self.commitment_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_discount_bps": self.max_discount_bps,
            "target_reserve_bps": self.target_reserve_bps,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HedgeSponsorVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub reserve_asset_id: String,
    pub reserve_commitment_root: String,
    pub pq_attestation_key_root: String,
    pub status: HedgeVaultStatus,
    pub available_units: u64,
    pub locked_units: u64,
    pub opened_height: u64,
}

impl HedgeSponsorVault {
    pub fn new(
        sponsor_label: &str,
        reserve_asset_id: &str,
        reserve_label: &str,
        pq_key_label: &str,
        available_units: u64,
        opened_height: u64,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(sponsor_label, "private fee hedge sponsor label")?;
        ensure_non_empty(reserve_asset_id, "private fee hedge reserve asset")?;
        ensure_non_empty(reserve_label, "private fee hedge reserve label")?;
        ensure_non_empty(pq_key_label, "private fee hedge pq key label")?;
        if available_units == 0 {
            return Err("private fee hedge vault available units must be positive".to_string());
        }
        let sponsor_commitment =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-SPONSOR", sponsor_label);
        let reserve_commitment_root =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-RESERVE", reserve_label);
        let pq_attestation_key_root =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-PQ-KEY", pq_key_label);
        let vault_id = hedge_sponsor_vault_id(
            &sponsor_commitment,
            reserve_asset_id,
            &reserve_commitment_root,
            &pq_attestation_key_root,
        );
        let vault = Self {
            vault_id,
            sponsor_commitment,
            reserve_asset_id: reserve_asset_id.to_string(),
            reserve_commitment_root,
            pq_attestation_key_root,
            status: HedgeVaultStatus::Active,
            available_units,
            locked_units: 0,
            opened_height,
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn reserve(&mut self, units: u64) -> PrivateFeeHedgeVaultResult<String> {
        if !self.status.can_quote() {
            return Err("private fee hedge vault cannot quote".to_string());
        }
        if units == 0 {
            return Err("private fee hedge reserve units must be positive".to_string());
        }
        if self.available_units < units {
            return Err("private fee hedge vault has insufficient available units".to_string());
        }
        self.available_units -= units;
        self.locked_units = self.locked_units.saturating_add(units);
        Ok(self.root())
    }

    pub fn settle(&mut self, units: u64) -> PrivateFeeHedgeVaultResult<String> {
        if units > self.locked_units {
            return Err("private fee hedge settlement exceeds locked units".to_string());
        }
        self.locked_units -= units;
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.vault_id, "private fee hedge vault id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "private fee hedge sponsor commitment",
        )?;
        ensure_non_empty(&self.reserve_asset_id, "private fee hedge reserve asset")?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "private fee hedge reserve commitment root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_key_root,
            "private fee hedge pq attestation root",
        )?;
        let expected = hedge_sponsor_vault_id(
            &self.sponsor_commitment,
            &self.reserve_asset_id,
            &self.reserve_commitment_root,
            &self.pq_attestation_key_root,
        );
        if self.vault_id != expected {
            return Err("private fee hedge vault id does not match commitments".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for HedgeSponsorVault {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-VAULT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "hedge_sponsor_vault",
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "pq_attestation_key_root": self.pq_attestation_key_root,
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "locked_units": self.locked_units,
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeHedgePolicy {
    pub policy_id: String,
    pub vault_id: String,
    pub lane: FeeHedgeLane,
    pub status: HedgePolicyStatus,
    pub max_fee_units: u64,
    pub discount_bps: u64,
    pub quote_floor_units: u64,
    pub policy_commitment_root: String,
    pub start_height: u64,
    pub end_height: u64,
}

impl FeeHedgePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        lane: FeeHedgeLane,
        max_fee_units: u64,
        discount_bps: u64,
        quote_floor_units: u64,
        policy_label: &str,
        start_height: u64,
        epoch_blocks: u64,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(vault_id, "private fee hedge policy vault id")?;
        ensure_non_empty(policy_label, "private fee hedge policy label")?;
        if max_fee_units == 0 || quote_floor_units == 0 {
            return Err("private fee hedge policy fee bounds must be positive".to_string());
        }
        if quote_floor_units > max_fee_units {
            return Err("private fee hedge quote floor exceeds max fee".to_string());
        }
        if discount_bps > PRIVATE_FEE_HEDGE_VAULT_MAX_BPS {
            return Err("private fee hedge policy discount exceeds bps cap".to_string());
        }
        if epoch_blocks == 0 {
            return Err("private fee hedge policy epoch blocks must be positive".to_string());
        }
        let end_height = start_height.saturating_add(epoch_blocks);
        let policy_commitment_root =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-POLICY", policy_label);
        let policy_id = fee_hedge_policy_id(
            vault_id,
            lane,
            max_fee_units,
            discount_bps,
            &policy_commitment_root,
            start_height,
        );
        let policy = Self {
            policy_id,
            vault_id: vault_id.to_string(),
            lane,
            status: HedgePolicyStatus::Active,
            max_fee_units,
            discount_bps,
            quote_floor_units,
            policy_commitment_root,
            start_height,
            end_height,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn hedge_units_for_quote(&self, gross_fee_units: u64) -> u64 {
        let capped = gross_fee_units
            .min(self.max_fee_units)
            .max(self.quote_floor_units);
        capped.saturating_mul(self.discount_bps) / PRIVATE_FEE_HEDGE_VAULT_MAX_BPS
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.policy_id, "private fee hedge policy id")?;
        ensure_non_empty(&self.vault_id, "private fee hedge policy vault id")?;
        ensure_non_empty(
            &self.policy_commitment_root,
            "private fee hedge policy commitment root",
        )?;
        if self.max_fee_units == 0 || self.quote_floor_units == 0 {
            return Err("private fee hedge policy fee bounds must be positive".to_string());
        }
        if self.quote_floor_units > self.max_fee_units {
            return Err("private fee hedge quote floor exceeds max fee".to_string());
        }
        if self.discount_bps > PRIVATE_FEE_HEDGE_VAULT_MAX_BPS {
            return Err("private fee hedge policy discount exceeds bps cap".to_string());
        }
        if self.end_height <= self.start_height {
            return Err("private fee hedge policy end height must exceed start".to_string());
        }
        let expected = fee_hedge_policy_id(
            &self.vault_id,
            self.lane,
            self.max_fee_units,
            self.discount_bps,
            &self.policy_commitment_root,
            self.start_height,
        );
        if self.policy_id != expected {
            return Err("private fee hedge policy id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for FeeHedgePolicy {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-POLICY", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_hedge_policy",
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "status": self.status.as_str(),
            "max_fee_units": self.max_fee_units,
            "discount_bps": self.discount_bps,
            "quote_floor_units": self.quote_floor_units,
            "policy_commitment_root": self.policy_commitment_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeOracleQuote {
    pub quote_id: String,
    pub lane: FeeHedgeLane,
    pub gross_fee_units: u64,
    pub volatility_bps: u64,
    pub oracle_attestation_root: String,
    pub pq_signature_root: String,
    pub observed_height: u64,
    pub expires_height: u64,
}

impl FeeOracleQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: FeeHedgeLane,
        gross_fee_units: u64,
        volatility_bps: u64,
        oracle_attestation_root: &str,
        pq_signature_root: &str,
        observed_height: u64,
        ttl_blocks: u64,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(
            oracle_attestation_root,
            "private fee hedge oracle attestation root",
        )?;
        ensure_non_empty(pq_signature_root, "private fee hedge pq signature root")?;
        if gross_fee_units == 0 {
            return Err("private fee hedge gross fee must be positive".to_string());
        }
        if volatility_bps > PRIVATE_FEE_HEDGE_VAULT_MAX_BPS {
            return Err("private fee hedge volatility exceeds bps cap".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private fee hedge quote ttl must be positive".to_string());
        }
        let expires_height = observed_height.saturating_add(ttl_blocks);
        let quote_id = fee_oracle_quote_id(
            lane,
            gross_fee_units,
            volatility_bps,
            oracle_attestation_root,
            pq_signature_root,
            observed_height,
        );
        let quote = Self {
            quote_id,
            lane,
            gross_fee_units,
            volatility_bps,
            oracle_attestation_root: oracle_attestation_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            observed_height,
            expires_height,
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.quote_id, "private fee hedge quote id")?;
        ensure_non_empty(
            &self.oracle_attestation_root,
            "private fee hedge oracle attestation root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "private fee hedge pq signature root",
        )?;
        if self.gross_fee_units == 0 {
            return Err("private fee hedge gross fee must be positive".to_string());
        }
        if self.expires_height <= self.observed_height {
            return Err("private fee hedge quote expiry must exceed observation".to_string());
        }
        let expected = fee_oracle_quote_id(
            self.lane,
            self.gross_fee_units,
            self.volatility_bps,
            &self.oracle_attestation_root,
            &self.pq_signature_root,
            self.observed_height,
        );
        if self.quote_id != expected {
            return Err("private fee hedge quote id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for FeeOracleQuote {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-ORACLE-QUOTE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_oracle_quote",
            "quote_id": self.quote_id,
            "lane": self.lane.as_str(),
            "gross_fee_units": self.gross_fee_units,
            "volatility_bps": self.volatility_bps,
            "oracle_attestation_root": self.oracle_attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeHedgeLock {
    pub lock_id: String,
    pub policy_id: String,
    pub quote_id: String,
    pub beneficiary_commitment: String,
    pub transaction_commitment: String,
    pub nullifier_commitment: String,
    pub status: HedgeLockStatus,
    pub gross_fee_units: u64,
    pub hedged_fee_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl FeeHedgeLock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &FeeHedgePolicy,
        quote: &FeeOracleQuote,
        beneficiary_label: &str,
        transaction_label: &str,
        nullifier_label: &str,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(beneficiary_label, "private fee hedge beneficiary")?;
        ensure_non_empty(transaction_label, "private fee hedge transaction")?;
        ensure_non_empty(nullifier_label, "private fee hedge nullifier")?;
        if policy.lane != quote.lane {
            return Err("private fee hedge policy lane does not match quote lane".to_string());
        }
        if !policy.status.accepts_locks() {
            return Err("private fee hedge policy is not accepting locks".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private fee hedge lock ttl must be positive".to_string());
        }
        let beneficiary_commitment =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-BENEFICIARY", beneficiary_label);
        let transaction_commitment =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-TX", transaction_label);
        let nullifier_commitment =
            private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-NULLIFIER", nullifier_label);
        let hedged_fee_units = policy.hedge_units_for_quote(quote.gross_fee_units);
        let expires_height = opened_height.saturating_add(ttl_blocks);
        let lock_id = fee_hedge_lock_id(
            &policy.policy_id,
            &quote.quote_id,
            &beneficiary_commitment,
            &transaction_commitment,
            &nullifier_commitment,
        );
        let lock = Self {
            lock_id,
            policy_id: policy.policy_id.clone(),
            quote_id: quote.quote_id.clone(),
            beneficiary_commitment,
            transaction_commitment,
            nullifier_commitment,
            status: HedgeLockStatus::Open,
            gross_fee_units: quote.gross_fee_units,
            hedged_fee_units,
            opened_height,
            expires_height,
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn mark_matched(&mut self) -> PrivateFeeHedgeVaultResult<String> {
        if self.status != HedgeLockStatus::Open {
            return Err("private fee hedge lock can only match from open".to_string());
        }
        self.status = HedgeLockStatus::Matched;
        Ok(self.root())
    }

    pub fn mark_settled(&mut self) -> PrivateFeeHedgeVaultResult<String> {
        if !self.status.open() {
            return Err("private fee hedge lock is not open".to_string());
        }
        self.status = HedgeLockStatus::Settled;
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.lock_id, "private fee hedge lock id")?;
        ensure_non_empty(&self.policy_id, "private fee hedge lock policy id")?;
        ensure_non_empty(&self.quote_id, "private fee hedge lock quote id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "private fee hedge lock beneficiary commitment",
        )?;
        ensure_non_empty(
            &self.transaction_commitment,
            "private fee hedge lock transaction commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "private fee hedge lock nullifier commitment",
        )?;
        if self.gross_fee_units == 0 || self.hedged_fee_units == 0 {
            return Err("private fee hedge lock fee units must be positive".to_string());
        }
        if self.hedged_fee_units > self.gross_fee_units {
            return Err("private fee hedge lock hedge exceeds gross fee".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("private fee hedge lock expiry must exceed open height".to_string());
        }
        let expected = fee_hedge_lock_id(
            &self.policy_id,
            &self.quote_id,
            &self.beneficiary_commitment,
            &self.transaction_commitment,
            &self.nullifier_commitment,
        );
        if self.lock_id != expected {
            return Err("private fee hedge lock id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for FeeHedgeLock {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-LOCK", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_hedge_lock",
            "lock_id": self.lock_id,
            "policy_id": self.policy_id,
            "quote_id": self.quote_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "transaction_commitment": self.transaction_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "status": self.status.as_str(),
            "gross_fee_units": self.gross_fee_units,
            "hedged_fee_units": self.hedged_fee_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeHedgeSettlement {
    pub settlement_id: String,
    pub lock_id: String,
    pub vault_id: String,
    pub settlement_root: String,
    pub fee_receipt_root: String,
    pub pq_attestation_root: String,
    pub status: HedgeSettlementStatus,
    pub settled_units: u64,
    pub opened_height: u64,
    pub finalized_height: Option<u64>,
}

impl FeeHedgeSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lock_id: &str,
        vault_id: &str,
        settlement_root: &str,
        fee_receipt_root: &str,
        pq_attestation_root: &str,
        settled_units: u64,
        opened_height: u64,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(lock_id, "private fee hedge settlement lock id")?;
        ensure_non_empty(vault_id, "private fee hedge settlement vault id")?;
        ensure_non_empty(settlement_root, "private fee hedge settlement root")?;
        ensure_non_empty(fee_receipt_root, "private fee hedge receipt root")?;
        ensure_non_empty(
            pq_attestation_root,
            "private fee hedge settlement pq attestation",
        )?;
        if settled_units == 0 {
            return Err("private fee hedge settlement units must be positive".to_string());
        }
        let settlement_id = fee_hedge_settlement_id(
            lock_id,
            vault_id,
            settlement_root,
            fee_receipt_root,
            pq_attestation_root,
            opened_height,
        );
        let settlement = Self {
            settlement_id,
            lock_id: lock_id.to_string(),
            vault_id: vault_id.to_string(),
            settlement_root: settlement_root.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            status: HedgeSettlementStatus::Pending,
            settled_units,
            opened_height,
            finalized_height: None,
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn accept(&mut self) -> PrivateFeeHedgeVaultResult<String> {
        if self.status != HedgeSettlementStatus::Pending {
            return Err("private fee hedge settlement can only accept from pending".to_string());
        }
        self.status = HedgeSettlementStatus::Accepted;
        Ok(self.root())
    }

    pub fn finalize(&mut self, height: u64) -> PrivateFeeHedgeVaultResult<String> {
        if !self.status.active() {
            return Err("private fee hedge settlement is not active".to_string());
        }
        if height < self.opened_height {
            return Err("private fee hedge finalization height is before open height".to_string());
        }
        self.status = HedgeSettlementStatus::Finalized;
        self.finalized_height = Some(height);
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.settlement_id, "private fee hedge settlement id")?;
        ensure_non_empty(&self.lock_id, "private fee hedge settlement lock id")?;
        ensure_non_empty(&self.vault_id, "private fee hedge settlement vault id")?;
        ensure_non_empty(&self.settlement_root, "private fee hedge settlement root")?;
        ensure_non_empty(
            &self.fee_receipt_root,
            "private fee hedge settlement receipt root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "private fee hedge settlement attestation root",
        )?;
        if self.settled_units == 0 {
            return Err("private fee hedge settlement units must be positive".to_string());
        }
        if let Some(finalized_height) = self.finalized_height {
            if finalized_height < self.opened_height {
                return Err("private fee hedge finalized height is before open height".to_string());
            }
        }
        let expected = fee_hedge_settlement_id(
            &self.lock_id,
            &self.vault_id,
            &self.settlement_root,
            &self.fee_receipt_root,
            &self.pq_attestation_root,
            self.opened_height,
        );
        if self.settlement_id != expected {
            return Err("private fee hedge settlement id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateFeeHedgeRooted for FeeHedgeSettlement {
    fn root(&self) -> String {
        private_fee_hedge_payload_root("PRIVATE-FEE-HEDGE-SETTLEMENT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_hedge_settlement",
            "settlement_id": self.settlement_id,
            "lock_id": self.lock_id,
            "vault_id": self.vault_id,
            "settlement_root": self.settlement_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
            "settled_units": self.settled_units,
            "opened_height": self.opened_height,
            "finalized_height": self.finalized_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFeeHedgeVaultRoots {
    pub config_root: String,
    pub vault_root: String,
    pub policy_root: String,
    pub quote_root: String,
    pub lock_root: String,
    pub settlement_root: String,
    pub nullifier_root: String,
    pub lane_exposure_root: String,
    pub state_root: String,
}

impl PrivateFeeHedgeVaultRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "policy_root": self.policy_root,
            "quote_root": self.quote_root,
            "lock_root": self.lock_root,
            "settlement_root": self.settlement_root,
            "nullifier_root": self.nullifier_root,
            "lane_exposure_root": self.lane_exposure_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFeeHedgeVaultCounters {
    pub height: u64,
    pub vault_count: u64,
    pub active_vault_count: u64,
    pub policy_count: u64,
    pub active_policy_count: u64,
    pub quote_count: u64,
    pub lock_count: u64,
    pub open_lock_count: u64,
    pub settlement_count: u64,
    pub active_settlement_count: u64,
    pub spent_nullifier_count: u64,
    pub total_available_units: u64,
    pub total_locked_units: u64,
}

impl PrivateFeeHedgeVaultCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "vault_count": self.vault_count,
            "active_vault_count": self.active_vault_count,
            "policy_count": self.policy_count,
            "active_policy_count": self.active_policy_count,
            "quote_count": self.quote_count,
            "lock_count": self.lock_count,
            "open_lock_count": self.open_lock_count,
            "settlement_count": self.settlement_count,
            "active_settlement_count": self.active_settlement_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "total_available_units": self.total_available_units,
            "total_locked_units": self.total_locked_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFeeHedgeVaultState {
    pub height: u64,
    pub label: String,
    pub config: PrivateFeeHedgeVaultConfig,
    pub vaults: BTreeMap<String, HedgeSponsorVault>,
    pub policies: BTreeMap<String, FeeHedgePolicy>,
    pub quotes: BTreeMap<String, FeeOracleQuote>,
    pub locks: BTreeMap<String, FeeHedgeLock>,
    pub settlements: BTreeMap<String, FeeHedgeSettlement>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PrivateFeeHedgeVaultState {
    pub fn new(
        label: &str,
        config: PrivateFeeHedgeVaultConfig,
    ) -> PrivateFeeHedgeVaultResult<Self> {
        ensure_non_empty(label, "private fee hedge vault label")?;
        config.validate()?;
        let state = Self {
            height: 0,
            label: label.to_string(),
            config,
            vaults: BTreeMap::new(),
            policies: BTreeMap::new(),
            quotes: BTreeMap::new(),
            locks: BTreeMap::new(),
            settlements: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PrivateFeeHedgeVaultResult<Self> {
        let config = PrivateFeeHedgeVaultConfig::devnet()?;
        let mut state = Self::new(PRIVATE_FEE_HEDGE_VAULT_DEVNET_LABEL, config)?;
        state.set_height(72)?;
        let vault = HedgeSponsorVault::new(
            "devnet-hedge-sponsor",
            "piconero-devnet",
            "fee-hedge-reserve",
            "fee-hedge-pq-key",
            5_000_000,
            64,
        )?;
        let vault_id = vault.vault_id.clone();
        state.add_vault(vault)?;
        let policy = FeeHedgePolicy::new(
            &vault_id,
            FeeHedgeLane::ContractCall,
            8_000,
            7_000,
            1_000,
            "contract-call-low-fee-hedge",
            64,
            state.config.epoch_blocks,
        )?;
        let policy_id = policy.policy_id.clone();
        state.add_policy(policy)?;
        let quote = FeeOracleQuote::new(
            FeeHedgeLane::ContractCall,
            4_000,
            1_200,
            &private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-DEVNET-ORACLE", "fee-quote"),
            &private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-DEVNET-PQ-SIG", "oracle-sig"),
            68,
            state.config.quote_ttl_blocks,
        )?;
        let quote_id = quote.quote_id.clone();
        state.add_quote(quote)?;
        let lock = state.open_lock(
            &policy_id,
            &quote_id,
            "devnet-beneficiary",
            "devnet-contract-call",
            "devnet-hedge-nullifier",
            70,
        )?;
        let mut settlement = FeeHedgeSettlement::new(
            &lock.lock_id,
            &vault_id,
            &private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-DEVNET-SETTLEMENT", "settlement"),
            &private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-DEVNET-RECEIPT", "receipt"),
            &private_fee_hedge_string_root("PRIVATE-FEE-HEDGE-DEVNET-ATTESTATION", "attestation"),
            lock.hedged_fee_units,
            71,
        )?;
        settlement.accept()?;
        state.add_settlement(settlement)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateFeeHedgeVaultResult<String> {
        self.height = height;
        self.validate()
    }

    pub fn add_vault(&mut self, vault: HedgeSponsorVault) -> PrivateFeeHedgeVaultResult<String> {
        if self.vaults.len() >= PRIVATE_FEE_HEDGE_VAULT_MAX_VAULTS {
            return Err("private fee hedge vault limit reached".to_string());
        }
        vault.validate()?;
        let root = vault.root();
        self.vaults.insert(vault.vault_id.clone(), vault);
        Ok(root)
    }

    pub fn add_policy(&mut self, policy: FeeHedgePolicy) -> PrivateFeeHedgeVaultResult<String> {
        if self.policies.len() >= PRIVATE_FEE_HEDGE_VAULT_MAX_POLICIES {
            return Err("private fee hedge policy limit reached".to_string());
        }
        if !self.vaults.contains_key(&policy.vault_id) {
            return Err("private fee hedge policy references unknown vault".to_string());
        }
        if policy.discount_bps > self.config.max_discount_bps {
            return Err("private fee hedge policy exceeds configured discount".to_string());
        }
        policy.validate()?;
        let root = policy.root();
        self.policies.insert(policy.policy_id.clone(), policy);
        Ok(root)
    }

    pub fn add_quote(&mut self, quote: FeeOracleQuote) -> PrivateFeeHedgeVaultResult<String> {
        if self.quotes.len() >= PRIVATE_FEE_HEDGE_VAULT_MAX_ORACLE_QUOTES {
            return Err("private fee hedge oracle quote limit reached".to_string());
        }
        quote.validate()?;
        let root = quote.root();
        self.quotes.insert(quote.quote_id.clone(), quote);
        Ok(root)
    }

    pub fn open_lock(
        &mut self,
        policy_id: &str,
        quote_id: &str,
        beneficiary_label: &str,
        transaction_label: &str,
        nullifier_label: &str,
        opened_height: u64,
    ) -> PrivateFeeHedgeVaultResult<FeeHedgeLock> {
        if self.locks.len() >= PRIVATE_FEE_HEDGE_VAULT_MAX_LOCKS {
            return Err("private fee hedge lock limit reached".to_string());
        }
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| "private fee hedge lock references unknown policy".to_string())?;
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| "private fee hedge lock references unknown quote".to_string())?;
        if self
            .spent_nullifiers
            .contains(&private_fee_hedge_string_root(
                "PRIVATE-FEE-HEDGE-NULLIFIER",
                nullifier_label,
            ))
        {
            return Err("private fee hedge nullifier already spent".to_string());
        }
        let mut lock = FeeHedgeLock::new(
            policy,
            quote,
            beneficiary_label,
            transaction_label,
            nullifier_label,
            opened_height,
            self.config.quote_ttl_blocks,
        )?;
        let vault = self
            .vaults
            .get_mut(&policy.vault_id)
            .ok_or_else(|| "private fee hedge policy vault is missing".to_string())?;
        vault.reserve(lock.hedged_fee_units)?;
        lock.mark_matched()?;
        self.locks.insert(lock.lock_id.clone(), lock.clone());
        Ok(lock)
    }

    pub fn add_settlement(
        &mut self,
        mut settlement: FeeHedgeSettlement,
    ) -> PrivateFeeHedgeVaultResult<String> {
        if self.settlements.len() >= PRIVATE_FEE_HEDGE_VAULT_MAX_SETTLEMENTS {
            return Err("private fee hedge settlement limit reached".to_string());
        }
        let lock = self
            .locks
            .get_mut(&settlement.lock_id)
            .ok_or_else(|| "private fee hedge settlement references unknown lock".to_string())?;
        if self.spent_nullifiers.contains(&lock.nullifier_commitment) {
            return Err("private fee hedge settlement nullifier already spent".to_string());
        }
        let vault = self
            .vaults
            .get_mut(&settlement.vault_id)
            .ok_or_else(|| "private fee hedge settlement references unknown vault".to_string())?;
        if settlement.settled_units > lock.hedged_fee_units {
            return Err("private fee hedge settlement exceeds lock hedge".to_string());
        }
        settlement.validate()?;
        settlement.finalize(self.height.max(settlement.opened_height))?;
        lock.mark_settled()?;
        vault.settle(settlement.settled_units)?;
        self.spent_nullifiers
            .insert(lock.nullifier_commitment.clone());
        let root = settlement.root();
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(root)
    }

    pub fn active_vault_ids(&self) -> Vec<String> {
        self.vaults
            .values()
            .filter(|vault| vault.status.can_quote())
            .map(|vault| vault.vault_id.clone())
            .collect()
    }

    pub fn active_policy_ids(&self) -> Vec<String> {
        self.policies
            .values()
            .filter(|policy| policy.status.accepts_locks())
            .map(|policy| policy.policy_id.clone())
            .collect()
    }

    pub fn open_lock_ids(&self) -> Vec<String> {
        self.locks
            .values()
            .filter(|lock| lock.status.open())
            .map(|lock| lock.lock_id.clone())
            .collect()
    }

    pub fn lane_exposure_map(&self) -> BTreeMap<String, u64> {
        let mut exposure = BTreeMap::new();
        for lock in self.locks.values() {
            if let Some(policy) = self.policies.get(&lock.policy_id) {
                *exposure
                    .entry(policy.lane.as_str().to_string())
                    .or_insert(0) += lock.hedged_fee_units;
            }
        }
        exposure
    }

    pub fn roots(&self) -> PrivateFeeHedgeVaultRoots {
        let config_root = self.config.root();
        let vault_root = private_fee_hedge_map_root("PRIVATE-FEE-HEDGE-VAULTS", &self.vaults);
        let policy_root = private_fee_hedge_map_root("PRIVATE-FEE-HEDGE-POLICIES", &self.policies);
        let quote_root = private_fee_hedge_map_root("PRIVATE-FEE-HEDGE-QUOTES", &self.quotes);
        let lock_root = private_fee_hedge_map_root("PRIVATE-FEE-HEDGE-LOCKS", &self.locks);
        let settlement_root =
            private_fee_hedge_map_root("PRIVATE-FEE-HEDGE-SETTLEMENTS", &self.settlements);
        let nullifier_root = merkle_root(
            "PRIVATE-FEE-HEDGE-SPENT-NULLIFIERS",
            &self
                .spent_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier_commitment": nullifier }))
                .collect::<Vec<_>>(),
        );
        let lane_exposure_root = private_fee_hedge_payload_root(
            "PRIVATE-FEE-HEDGE-LANE-EXPOSURE",
            &json!(self.lane_exposure_map()),
        );
        let state_root = domain_hash(
            "PRIVATE-FEE-HEDGE-VAULT-STATE-ROOT",
            &[
                HashPart::Str(&self.label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&vault_root),
                HashPart::Str(&policy_root),
                HashPart::Str(&quote_root),
                HashPart::Str(&lock_root),
                HashPart::Str(&settlement_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&lane_exposure_root),
            ],
            32,
        );
        PrivateFeeHedgeVaultRoots {
            config_root,
            vault_root,
            policy_root,
            quote_root,
            lock_root,
            settlement_root,
            nullifier_root,
            lane_exposure_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateFeeHedgeVaultCounters {
        PrivateFeeHedgeVaultCounters {
            height: self.height,
            vault_count: self.vaults.len() as u64,
            active_vault_count: self
                .vaults
                .values()
                .filter(|vault| vault.status.can_quote())
                .count() as u64,
            policy_count: self.policies.len() as u64,
            active_policy_count: self
                .policies
                .values()
                .filter(|policy| policy.status.accepts_locks())
                .count() as u64,
            quote_count: self.quotes.len() as u64,
            lock_count: self.locks.len() as u64,
            open_lock_count: self
                .locks
                .values()
                .filter(|lock| lock.status.open())
                .count() as u64,
            settlement_count: self.settlements.len() as u64,
            active_settlement_count: self
                .settlements
                .values()
                .filter(|settlement| settlement.status.active())
                .count() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
            total_available_units: self
                .vaults
                .values()
                .map(|vault| vault.available_units)
                .sum(),
            total_locked_units: self.vaults.values().map(|vault| vault.locked_units).sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_hedge_vault_state",
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_vault_ids": self.active_vault_ids(),
            "active_policy_ids": self.active_policy_ids(),
            "open_lock_ids": self.open_lock_ids(),
            "lane_exposure_map": self.lane_exposure_map(),
        })
    }

    pub fn validate(&self) -> PrivateFeeHedgeVaultResult<String> {
        ensure_non_empty(&self.label, "private fee hedge vault label")?;
        self.config.validate()?;
        if self.vaults.len() > PRIVATE_FEE_HEDGE_VAULT_MAX_VAULTS {
            return Err("private fee hedge state has too many vaults".to_string());
        }
        if self.policies.len() > PRIVATE_FEE_HEDGE_VAULT_MAX_POLICIES {
            return Err("private fee hedge state has too many policies".to_string());
        }
        if self.locks.len() > PRIVATE_FEE_HEDGE_VAULT_MAX_LOCKS {
            return Err("private fee hedge state has too many locks".to_string());
        }
        if self.settlements.len() > PRIVATE_FEE_HEDGE_VAULT_MAX_SETTLEMENTS {
            return Err("private fee hedge state has too many settlements".to_string());
        }
        if self.quotes.len() > PRIVATE_FEE_HEDGE_VAULT_MAX_ORACLE_QUOTES {
            return Err("private fee hedge state has too many quotes".to_string());
        }
        for vault in self.vaults.values() {
            vault.validate()?;
        }
        for policy in self.policies.values() {
            policy.validate()?;
            if !self.vaults.contains_key(&policy.vault_id) {
                return Err("private fee hedge policy references missing vault".to_string());
            }
        }
        for quote in self.quotes.values() {
            quote.validate()?;
        }
        for lock in self.locks.values() {
            lock.validate()?;
            if !self.policies.contains_key(&lock.policy_id) {
                return Err("private fee hedge lock references missing policy".to_string());
            }
            if !self.quotes.contains_key(&lock.quote_id) {
                return Err("private fee hedge lock references missing quote".to_string());
            }
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.locks.contains_key(&settlement.lock_id) {
                return Err("private fee hedge settlement references missing lock".to_string());
            }
            if !self.vaults.contains_key(&settlement.vault_id) {
                return Err("private fee hedge settlement references missing vault".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_fee_hedge_vault_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-VAULT-STATE-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_fee_hedge_config_id(protocol_version: &str, schema_version: &str) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-CONFIG-ID",
        &[
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
        ],
        24,
    )
}

pub fn hedge_sponsor_vault_id(
    sponsor_commitment: &str,
    reserve_asset_id: &str,
    reserve_commitment_root: &str,
    pq_attestation_key_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-VAULT-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(reserve_commitment_root),
            HashPart::Str(pq_attestation_key_root),
        ],
        24,
    )
}

pub fn fee_hedge_policy_id(
    vault_id: &str,
    lane: FeeHedgeLane,
    max_fee_units: u64,
    discount_bps: u64,
    policy_commitment_root: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-POLICY-ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(discount_bps as i128),
            HashPart::Str(policy_commitment_root),
            HashPart::Int(start_height as i128),
        ],
        24,
    )
}

pub fn fee_oracle_quote_id(
    lane: FeeHedgeLane,
    gross_fee_units: u64,
    volatility_bps: u64,
    oracle_attestation_root: &str,
    pq_signature_root: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-ORACLE-QUOTE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(volatility_bps as i128),
            HashPart::Str(oracle_attestation_root),
            HashPart::Str(pq_signature_root),
            HashPart::Int(observed_height as i128),
        ],
        24,
    )
}

pub fn fee_hedge_lock_id(
    policy_id: &str,
    quote_id: &str,
    beneficiary_commitment: &str,
    transaction_commitment: &str,
    nullifier_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-LOCK-ID",
        &[
            HashPart::Str(policy_id),
            HashPart::Str(quote_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(transaction_commitment),
            HashPart::Str(nullifier_commitment),
        ],
        24,
    )
}

pub fn fee_hedge_settlement_id(
    lock_id: &str,
    vault_id: &str,
    settlement_root: &str,
    fee_receipt_root: &str,
    pq_attestation_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-FEE-HEDGE-SETTLEMENT-ID",
        &[
            HashPart::Str(lock_id),
            HashPart::Str(vault_id),
            HashPart::Str(settlement_root),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(opened_height as i128),
        ],
        24,
    )
}

fn private_fee_hedge_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn private_fee_hedge_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn private_fee_hedge_map_root<T: PrivateFeeHedgeRooted>(
    domain: &str,
    map: &BTreeMap<String, T>,
) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "root": value.root() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateFeeHedgeVaultResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
