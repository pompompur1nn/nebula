use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeePrivateSettlementNettingResult<T> = Result<T, String>;

pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION: &str =
    "nebula-low-fee-private-settlement-netting-v1";
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_SCHEMA_VERSION: u64 = 1;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-private-settlement-netting-v1";
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_RECEIPT_SCHEME: &str =
    "zk-private-batch-receipt-range-proof-v1";
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_AUTH_TTL_BLOCKS: u64 = 1_440;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_BATCH_ITEMS: u64 = 512;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_LANE_PRIVACY_BPS: u64 = 3_500;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_ACCOUNT_PRIVACY_BPS: u64 = 1_500;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS: u64 = 6_000;
pub const LOW_FEE_PRIVATE_SETTLEMENT_NETTING_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSettlementFlowKind {
    TokenTransfer,
    BridgeExit,
    AmmFill,
    ContractCall,
}

impl PrivateSettlementFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::AmmFill => "amm_fill",
            Self::ContractCall => "contract_call",
        }
    }

    pub fn default_lane_key(self) -> &'static str {
        match self {
            Self::TokenTransfer => "lane:private:settlement:transfer",
            Self::BridgeExit => "lane:private:settlement:bridge_exit",
            Self::AmmFill => "lane:private:settlement:amm_fill",
            Self::ContractCall => "lane:private:settlement:contract_call",
        }
    }

    pub fn default_privacy_cost_bps(self) -> u64 {
        match self {
            Self::TokenTransfer => 80,
            Self::BridgeExit => 140,
            Self::AmmFill => 180,
            Self::ContractCall => 220,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementIntentStatus {
    Pending,
    Netted,
    Settled,
    Rejected,
    Expired,
}

impl SettlementIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingBatchStatus {
    Open,
    Authorized,
    Posted,
    Settled,
    Disputed,
    Expired,
}

impl NettingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Authorized => "authorized",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn final_for_receipts(self) -> bool {
        matches!(self, Self::Posted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementSponsorStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SettlementSponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSettlementAuthorizationStatus {
    Active,
    Used,
    Revoked,
    Expired,
}

impl PqSettlementAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Used => "used",
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
pub enum BatchReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
}

impl BatchReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePrivateSettlementNettingConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub authorization_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_batch_items: u64,
    pub max_lane_privacy_bps: u64,
    pub max_account_privacy_bps: u64,
    pub max_sponsor_exposure_bps: u64,
    pub pq_authorization_scheme: String,
    pub receipt_scheme: String,
}

impl Default for LowFeePrivateSettlementNettingConfig {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_EPOCH_BLOCKS,
            batch_ttl_blocks: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_BATCH_TTL_BLOCKS,
            authorization_ttl_blocks: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_AUTH_TTL_BLOCKS,
            min_pq_security_bits: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_items: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_BATCH_ITEMS,
            max_lane_privacy_bps: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_LANE_PRIVACY_BPS,
            max_account_privacy_bps:
                LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_ACCOUNT_PRIVACY_BPS,
            max_sponsor_exposure_bps:
                LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS,
            pq_authorization_scheme: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PQ_AUTH_SCHEME.to_string(),
            receipt_scheme: LOW_FEE_PRIVATE_SETTLEMENT_NETTING_RECEIPT_SCHEME.to_string(),
        }
    }
}

impl LowFeePrivateSettlementNettingConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 240,
            batch_ttl_blocks: 12,
            authorization_ttl_blocks: 720,
            max_batch_items: 128,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_private_settlement_netting_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "authorization_ttl_blocks": self.authorization_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_items": self.max_batch_items,
            "max_lane_privacy_bps": self.max_lane_privacy_bps,
            "max_account_privacy_bps": self.max_account_privacy_bps,
            "max_sponsor_exposure_bps": self.max_sponsor_exposure_bps,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "receipt_scheme": self.receipt_scheme,
            "hash_suite": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_HASH_SUITE,
        })
    }

    pub fn config_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-NETTING-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
        )?;
        if self.schema_version != LOW_FEE_PRIVATE_SETTLEMENT_NETTING_SCHEMA_VERSION {
            return Err("schema version mismatch".to_string());
        }
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("batch ttl blocks", self.batch_ttl_blocks)?;
        ensure_positive("authorization ttl blocks", self.authorization_ttl_blocks)?;
        if self.min_pq_security_bits
            < LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("minimum pq security bits below policy floor".to_string());
        }
        ensure_positive("max batch items", self.max_batch_items)?;
        ensure_bps("max lane privacy bps", self.max_lane_privacy_bps)?;
        ensure_bps("max account privacy bps", self.max_account_privacy_bps)?;
        ensure_bps("max sponsor exposure bps", self.max_sponsor_exposure_bps)?;
        ensure_eq(
            "pq authorization scheme",
            &self.pq_authorization_scheme,
            LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PQ_AUTH_SCHEME,
        )?;
        ensure_eq(
            "receipt scheme",
            &self.receipt_scheme,
            LOW_FEE_PRIVATE_SETTLEMENT_NETTING_RECEIPT_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetEnvelope {
    pub lane_key: String,
    pub account_commitment: String,
    pub contract_commitment: Option<String>,
    pub budget_nullifier: String,
    pub budget_cost_bps: u64,
    pub disclosure_root: String,
}

impl PrivacyBudgetEnvelope {
    pub fn new(
        lane_key: &str,
        account_commitment: &str,
        contract_commitment: Option<String>,
        budget_nullifier: &str,
        budget_cost_bps: u64,
        disclosure_root: &str,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("account commitment", account_commitment)?;
        ensure_non_empty("budget nullifier", budget_nullifier)?;
        ensure_non_empty("disclosure root", disclosure_root)?;
        ensure_bps("budget cost bps", budget_cost_bps)?;
        Ok(Self {
            lane_key: lane_key.to_string(),
            account_commitment: account_commitment.to_string(),
            contract_commitment,
            budget_nullifier: budget_nullifier.to_string(),
            budget_cost_bps,
            disclosure_root: disclosure_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_envelope",
            "lane_key": self.lane_key,
            "account_commitment": self.account_commitment,
            "contract_commitment": self.contract_commitment,
            "budget_nullifier": self.budget_nullifier,
            "budget_cost_bps": self.budget_cost_bps,
            "disclosure_root": self.disclosure_root,
        })
    }

    pub fn envelope_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-PRIVACY-BUDGET-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("account commitment", &self.account_commitment)?;
        if let Some(contract_commitment) = &self.contract_commitment {
            ensure_non_empty("contract commitment", contract_commitment)?;
        }
        ensure_non_empty("budget nullifier", &self.budget_nullifier)?;
        ensure_bps("budget cost bps", self.budget_cost_bps)?;
        ensure_non_empty("disclosure root", &self.disclosure_root)?;
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetWindow {
    pub lane_key: String,
    pub epoch_index: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub max_lane_budget_bps: u64,
    pub spent_lane_budget_bps: u64,
    pub reserved_lane_budget_bps: u64,
    pub account_spent_bps: BTreeMap<String, u64>,
    pub account_reserved_bps: BTreeMap<String, u64>,
    pub contract_spent_bps: BTreeMap<String, u64>,
    pub contract_reserved_bps: BTreeMap<String, u64>,
}

impl PrivacyBudgetWindow {
    pub fn new(
        lane_key: &str,
        epoch_index: u64,
        epoch_start_height: u64,
        epoch_blocks: u64,
        max_lane_budget_bps: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("lane key", lane_key)?;
        ensure_positive("epoch blocks", epoch_blocks)?;
        ensure_bps("max lane budget bps", max_lane_budget_bps)?;
        Ok(Self {
            lane_key: lane_key.to_string(),
            epoch_index,
            epoch_start_height,
            epoch_end_height: epoch_start_height.saturating_add(epoch_blocks),
            max_lane_budget_bps,
            spent_lane_budget_bps: 0,
            reserved_lane_budget_bps: 0,
            account_spent_bps: BTreeMap::new(),
            account_reserved_bps: BTreeMap::new(),
            contract_spent_bps: BTreeMap::new(),
            contract_reserved_bps: BTreeMap::new(),
        })
    }

    pub fn window_id(&self) -> String {
        privacy_budget_window_id(&self.lane_key, self.epoch_index)
    }

    pub fn available_lane_budget_bps(&self) -> u64 {
        self.max_lane_budget_bps
            .saturating_sub(self.spent_lane_budget_bps)
            .saturating_sub(self.reserved_lane_budget_bps)
    }

    pub fn reserve(
        &mut self,
        envelope: &PrivacyBudgetEnvelope,
        max_account_budget_bps: u64,
    ) -> LowFeePrivateSettlementNettingResult<()> {
        envelope.validate()?;
        if envelope.lane_key != self.lane_key {
            return Err("privacy budget envelope lane mismatch".to_string());
        }
        if envelope.budget_cost_bps > self.available_lane_budget_bps() {
            return Err("lane privacy budget exhausted".to_string());
        }
        let account_reserved =
            map_u64_or_zero(&self.account_reserved_bps, &envelope.account_commitment);
        let account_spent = map_u64_or_zero(&self.account_spent_bps, &envelope.account_commitment);
        if account_spent
            .saturating_add(account_reserved)
            .saturating_add(envelope.budget_cost_bps)
            > max_account_budget_bps
        {
            return Err("account privacy budget exhausted".to_string());
        }
        self.reserved_lane_budget_bps = self
            .reserved_lane_budget_bps
            .saturating_add(envelope.budget_cost_bps);
        self.account_reserved_bps.insert(
            envelope.account_commitment.clone(),
            account_reserved.saturating_add(envelope.budget_cost_bps),
        );
        if let Some(contract_commitment) = &envelope.contract_commitment {
            let contract_reserved =
                map_u64_or_zero(&self.contract_reserved_bps, contract_commitment);
            self.contract_reserved_bps.insert(
                contract_commitment.clone(),
                contract_reserved.saturating_add(envelope.budget_cost_bps),
            );
        }
        Ok(())
    }

    pub fn spend(&mut self, envelope: &PrivacyBudgetEnvelope) {
        self.reserved_lane_budget_bps = self
            .reserved_lane_budget_bps
            .saturating_sub(envelope.budget_cost_bps);
        self.spent_lane_budget_bps = self
            .spent_lane_budget_bps
            .saturating_add(envelope.budget_cost_bps);
        spend_budget_map(
            &mut self.account_reserved_bps,
            &mut self.account_spent_bps,
            &envelope.account_commitment,
            envelope.budget_cost_bps,
        );
        if let Some(contract_commitment) = &envelope.contract_commitment {
            spend_budget_map(
                &mut self.contract_reserved_bps,
                &mut self.contract_spent_bps,
                contract_commitment,
                envelope.budget_cost_bps,
            );
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_window",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "window_id": self.window_id(),
            "lane_key": self.lane_key,
            "epoch_index": self.epoch_index,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "max_lane_budget_bps": self.max_lane_budget_bps,
            "spent_lane_budget_bps": self.spent_lane_budget_bps,
            "reserved_lane_budget_bps": self.reserved_lane_budget_bps,
            "available_lane_budget_bps": self.available_lane_budget_bps(),
            "account_spent_root": low_fee_private_settlement_netting_u64_map_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-ACCOUNT-SPENT",
                &self.account_spent_bps,
            ),
            "account_reserved_root": low_fee_private_settlement_netting_u64_map_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-ACCOUNT-RESERVED",
                &self.account_reserved_bps,
            ),
            "contract_spent_root": low_fee_private_settlement_netting_u64_map_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-CONTRACT-SPENT",
                &self.contract_spent_bps,
            ),
            "contract_reserved_root": low_fee_private_settlement_netting_u64_map_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-CONTRACT-RESERVED",
                &self.contract_reserved_bps,
            ),
        })
    }

    pub fn window_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-PRIVACY-BUDGET-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_bps("max lane budget bps", self.max_lane_budget_bps)?;
        ensure_bps("spent lane budget bps", self.spent_lane_budget_bps)?;
        ensure_bps("reserved lane budget bps", self.reserved_lane_budget_bps)?;
        ensure_height_order(
            "privacy budget window",
            self.epoch_start_height,
            self.epoch_end_height,
        )?;
        if self
            .spent_lane_budget_bps
            .saturating_add(self.reserved_lane_budget_bps)
            > self.max_lane_budget_bps
        {
            return Err("privacy budget window overspent".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementSponsorAccount {
    pub sponsor_id: String,
    pub sponsor_label: String,
    pub operator_commitment: String,
    pub treasury_commitment: String,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub reimbursed_units: u64,
    pub max_exposure_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub status: SettlementSponsorStatus,
}

impl SettlementSponsorAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        operator_commitment: &str,
        treasury_commitment: &str,
        fee_asset_id: &str,
        total_budget_units: u64,
        max_exposure_bps: u64,
        opened_at_height: u64,
        account_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("sponsor label", sponsor_label)?;
        ensure_non_empty("operator commitment", operator_commitment)?;
        ensure_non_empty("treasury commitment", treasury_commitment)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("total sponsor budget units", total_budget_units)?;
        ensure_bps("max exposure bps", max_exposure_bps)?;
        let sponsor_id = settlement_sponsor_account_id(
            sponsor_label,
            operator_commitment,
            treasury_commitment,
            fee_asset_id,
            account_nonce,
        );
        Ok(Self {
            sponsor_id,
            sponsor_label: sponsor_label.to_string(),
            operator_commitment: operator_commitment.to_string(),
            treasury_commitment: treasury_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            total_budget_units,
            reserved_units: 0,
            spent_units: 0,
            reimbursed_units: 0,
            max_exposure_bps,
            opened_at_height,
            updated_at_height: opened_at_height,
            status: SettlementSponsorStatus::Active,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(
        &mut self,
        amount_units: u64,
        height: u64,
    ) -> LowFeePrivateSettlementNettingResult<()> {
        if !self.status.can_spend() {
            return Err("sponsor account cannot spend".to_string());
        }
        if amount_units > self.available_units() {
            return Err("sponsor budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(amount_units);
        self.updated_at_height = height;
        Ok(())
    }

    pub fn spend_reserved(&mut self, amount_units: u64, height: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(amount_units);
        self.spent_units = self.spent_units.saturating_add(amount_units);
        self.updated_at_height = height;
        if self.available_units() == 0 {
            self.status = SettlementSponsorStatus::Exhausted;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_sponsor_account",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_label": self.sponsor_label,
            "operator_commitment": self.operator_commitment,
            "treasury_commitment": self.treasury_commitment,
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "reimbursed_units": self.reimbursed_units,
            "available_units": self.available_units(),
            "max_exposure_bps": self.max_exposure_bps,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsor_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-SPONSOR-ACCOUNT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("sponsor label", &self.sponsor_label)?;
        ensure_non_empty("operator commitment", &self.operator_commitment)?;
        ensure_non_empty("treasury commitment", &self.treasury_commitment)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("total sponsor budget units", self.total_budget_units)?;
        ensure_bps("max exposure bps", self.max_exposure_bps)?;
        if self.reserved_units.saturating_add(self.spent_units) > self.total_budget_units {
            return Err("sponsor account overspent".to_string());
        }
        Ok(self.sponsor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSettlementAuthorization {
    pub authorization_id: String,
    pub authorizer_commitment: String,
    pub signer_key_id: String,
    pub public_key_root: String,
    pub scope_root: String,
    pub max_batch_items: u64,
    pub max_fee_units: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub signature_commitment: String,
    pub status: PqSettlementAuthorizationStatus,
}

impl PqSettlementAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorizer_commitment: &str,
        signer_key_id: &str,
        public_key_root: &str,
        scope_root: &str,
        max_batch_items: u64,
        max_fee_units: u64,
        valid_from_height: u64,
        ttl_blocks: u64,
        security_bits: u16,
        signature_commitment: &str,
        authorization_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("authorizer commitment", authorizer_commitment)?;
        ensure_non_empty("signer key id", signer_key_id)?;
        ensure_non_empty("public key root", public_key_root)?;
        ensure_non_empty("scope root", scope_root)?;
        ensure_positive("max batch items", max_batch_items)?;
        ensure_positive("max fee units", max_fee_units)?;
        ensure_positive("authorization ttl blocks", ttl_blocks)?;
        ensure_non_empty("signature commitment", signature_commitment)?;
        if security_bits < LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security below policy floor".to_string());
        }
        let expires_at_height = valid_from_height.saturating_add(ttl_blocks);
        let authorization_id = pq_settlement_authorization_id(
            authorizer_commitment,
            signer_key_id,
            scope_root,
            valid_from_height,
            authorization_nonce,
        );
        Ok(Self {
            authorization_id,
            authorizer_commitment: authorizer_commitment.to_string(),
            signer_key_id: signer_key_id.to_string(),
            public_key_root: public_key_root.to_string(),
            scope_root: scope_root.to_string(),
            max_batch_items,
            max_fee_units,
            valid_from_height,
            expires_at_height,
            security_bits,
            signature_commitment: signature_commitment.to_string(),
            status: PqSettlementAuthorizationStatus::Active,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.usable() && height >= self.valid_from_height && height <= self.expires_at_height
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == PqSettlementAuthorizationStatus::Active && height > self.expires_at_height
        {
            self.status = PqSettlementAuthorizationStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_settlement_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "scheme": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PQ_AUTH_SCHEME,
            "authorization_id": self.authorization_id,
            "authorizer_commitment": self.authorizer_commitment,
            "signer_key_id": self.signer_key_id,
            "public_key_root": self.public_key_root,
            "scope_root": self.scope_root,
            "max_batch_items": self.max_batch_items,
            "max_fee_units": self.max_fee_units,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
            "signature_commitment": self.signature_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn authorization_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-PQ-AUTHORIZATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("authorization id", &self.authorization_id)?;
        ensure_non_empty("authorizer commitment", &self.authorizer_commitment)?;
        ensure_non_empty("signer key id", &self.signer_key_id)?;
        ensure_non_empty("public key root", &self.public_key_root)?;
        ensure_non_empty("scope root", &self.scope_root)?;
        ensure_positive("max batch items", self.max_batch_items)?;
        ensure_positive("max fee units", self.max_fee_units)?;
        ensure_height_order(
            "pq settlement authorization",
            self.valid_from_height,
            self.expires_at_height,
        )?;
        if self.security_bits < LOW_FEE_PRIVATE_SETTLEMENT_NETTING_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security below policy floor".to_string());
        }
        ensure_non_empty("signature commitment", &self.signature_commitment)?;
        Ok(self.authorization_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementIntent {
    pub intent_id: String,
    pub flow_kind: PrivateSettlementFlowKind,
    pub lane_key: String,
    pub payer_commitment: String,
    pub receiver_commitment: String,
    pub debit_asset_id: String,
    pub credit_asset_id: String,
    pub debit_amount_units: u64,
    pub min_credit_amount_units: u64,
    pub route_or_call_root: String,
    pub bridge_exit_root: Option<String>,
    pub amm_fill_root: Option<String>,
    pub contract_call_root: Option<String>,
    pub privacy_budget: PrivacyBudgetEnvelope,
    pub sponsor_id: String,
    pub authorization_id: String,
    pub fee_asset_id: String,
    pub sponsored_fee_units: u64,
    pub nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub intent_nonce: u64,
    pub status: SettlementIntentStatus,
}

impl PrivateSettlementIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flow_kind: PrivateSettlementFlowKind,
        payer_commitment: &str,
        receiver_commitment: &str,
        debit_asset_id: &str,
        credit_asset_id: &str,
        debit_amount_units: u64,
        min_credit_amount_units: u64,
        route_or_call_root: &str,
        bridge_exit_root: Option<String>,
        amm_fill_root: Option<String>,
        contract_call_root: Option<String>,
        privacy_budget: PrivacyBudgetEnvelope,
        sponsor_id: &str,
        authorization_id: &str,
        fee_asset_id: &str,
        sponsored_fee_units: u64,
        nullifier: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        intent_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("payer commitment", payer_commitment)?;
        ensure_non_empty("receiver commitment", receiver_commitment)?;
        ensure_non_empty("debit asset id", debit_asset_id)?;
        ensure_non_empty("credit asset id", credit_asset_id)?;
        ensure_positive("debit amount units", debit_amount_units)?;
        ensure_positive("minimum credit amount units", min_credit_amount_units)?;
        ensure_non_empty("route or call root", route_or_call_root)?;
        privacy_budget.validate()?;
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("authorization id", authorization_id)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("sponsored fee units", sponsored_fee_units)?;
        ensure_non_empty("nullifier", nullifier)?;
        ensure_positive("ttl blocks", ttl_blocks)?;
        let lane_key = flow_kind.default_lane_key().to_string();
        if privacy_budget.lane_key != lane_key {
            return Err("privacy budget lane does not match flow kind".to_string());
        }
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let intent_id = private_settlement_intent_id(
            flow_kind,
            payer_commitment,
            nullifier,
            route_or_call_root,
            opened_at_height,
            intent_nonce,
        );
        Ok(Self {
            intent_id,
            flow_kind,
            lane_key,
            payer_commitment: payer_commitment.to_string(),
            receiver_commitment: receiver_commitment.to_string(),
            debit_asset_id: debit_asset_id.to_string(),
            credit_asset_id: credit_asset_id.to_string(),
            debit_amount_units,
            min_credit_amount_units,
            route_or_call_root: route_or_call_root.to_string(),
            bridge_exit_root,
            amm_fill_root,
            contract_call_root,
            privacy_budget,
            sponsor_id: sponsor_id.to_string(),
            authorization_id: authorization_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            sponsored_fee_units,
            nullifier: nullifier.to_string(),
            opened_at_height,
            expires_at_height,
            intent_nonce,
            status: SettlementIntentStatus::Pending,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == SettlementIntentStatus::Pending && height > self.expires_at_height {
            self.status = SettlementIntentStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_settlement_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "flow_kind": self.flow_kind.as_str(),
            "lane_key": self.lane_key,
            "payer_commitment": self.payer_commitment,
            "receiver_commitment": self.receiver_commitment,
            "debit_asset_id": self.debit_asset_id,
            "credit_asset_id": self.credit_asset_id,
            "debit_amount_units": self.debit_amount_units,
            "min_credit_amount_units": self.min_credit_amount_units,
            "route_or_call_root": self.route_or_call_root,
            "bridge_exit_root": self.bridge_exit_root,
            "amm_fill_root": self.amm_fill_root,
            "contract_call_root": self.contract_call_root,
            "privacy_budget": self.privacy_budget.public_record(),
            "privacy_budget_root": self.privacy_budget.envelope_root(),
            "sponsor_id": self.sponsor_id,
            "authorization_id": self.authorization_id,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee_units": self.sponsored_fee_units,
            "nullifier": self.nullifier,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "intent_nonce": self.intent_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-INTENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("intent id", &self.intent_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("payer commitment", &self.payer_commitment)?;
        ensure_non_empty("receiver commitment", &self.receiver_commitment)?;
        ensure_non_empty("debit asset id", &self.debit_asset_id)?;
        ensure_non_empty("credit asset id", &self.credit_asset_id)?;
        ensure_positive("debit amount units", self.debit_amount_units)?;
        ensure_positive("minimum credit amount units", self.min_credit_amount_units)?;
        ensure_non_empty("route or call root", &self.route_or_call_root)?;
        self.privacy_budget.validate()?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("authorization id", &self.authorization_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("sponsored fee units", self.sponsored_fee_units)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_height_order(
            "private settlement intent",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        if self.privacy_budget.lane_key != self.lane_key {
            return Err("intent privacy budget lane mismatch".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementNetPosition {
    pub position_id: String,
    pub batch_id: String,
    pub asset_id: String,
    pub debit_units: u64,
    pub credit_units: u64,
    pub net_direction: String,
    pub net_units: u64,
    pub participant_root: String,
}

impl SettlementNetPosition {
    pub fn new(
        batch_id: &str,
        asset_id: &str,
        debit_units: u64,
        credit_units: u64,
        participant_root: &str,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("asset id", asset_id)?;
        ensure_non_empty("participant root", participant_root)?;
        let (net_direction, net_units) = if debit_units >= credit_units {
            (
                "debit".to_string(),
                debit_units.saturating_sub(credit_units),
            )
        } else {
            (
                "credit".to_string(),
                credit_units.saturating_sub(debit_units),
            )
        };
        Ok(Self {
            position_id: settlement_net_position_id(batch_id, asset_id, debit_units, credit_units),
            batch_id: batch_id.to_string(),
            asset_id: asset_id.to_string(),
            debit_units,
            credit_units,
            net_direction,
            net_units,
            participant_root: participant_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_net_position",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "batch_id": self.batch_id,
            "asset_id": self.asset_id,
            "debit_units": self.debit_units,
            "credit_units": self.credit_units,
            "net_direction": self.net_direction,
            "net_units": self.net_units,
            "participant_root": self.participant_root,
        })
    }

    pub fn position_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-NET-POSITION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("position id", &self.position_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("asset id", &self.asset_id)?;
        ensure_non_empty("net direction", &self.net_direction)?;
        ensure_non_empty("participant root", &self.participant_root)?;
        if self.net_direction != "debit" && self.net_direction != "credit" {
            return Err("net position direction is invalid".to_string());
        }
        Ok(self.position_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementBatch {
    pub batch_id: String,
    pub intent_ids: BTreeSet<String>,
    pub net_position_ids: BTreeSet<String>,
    pub sponsor_ids: BTreeSet<String>,
    pub authorization_id: String,
    pub intent_root: String,
    pub net_position_root: String,
    pub privacy_budget_root: String,
    pub sponsor_debit_root: String,
    pub posted_call_root: String,
    pub total_sponsored_fee_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub posted_at_height: Option<u64>,
    pub status: NettingBatchStatus,
}

impl PrivateSettlementBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_ids: BTreeSet<String>,
        sponsor_ids: BTreeSet<String>,
        authorization_id: &str,
        intent_root: &str,
        net_position_root: &str,
        privacy_budget_root: &str,
        sponsor_debit_root: &str,
        posted_call_root: &str,
        total_sponsored_fee_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
        batch_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        if intent_ids.is_empty() {
            return Err("batch requires at least one intent".to_string());
        }
        ensure_non_empty("authorization id", authorization_id)?;
        ensure_non_empty("intent root", intent_root)?;
        ensure_non_empty("net position root", net_position_root)?;
        ensure_non_empty("privacy budget root", privacy_budget_root)?;
        ensure_non_empty("sponsor debit root", sponsor_debit_root)?;
        ensure_non_empty("posted call root", posted_call_root)?;
        ensure_positive("total sponsored fee units", total_sponsored_fee_units)?;
        ensure_positive("batch ttl blocks", ttl_blocks)?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let batch_id = private_settlement_batch_id(
            intent_root,
            net_position_root,
            authorization_id,
            opened_at_height,
            batch_nonce,
        );
        Ok(Self {
            batch_id,
            intent_ids,
            net_position_ids: BTreeSet::new(),
            sponsor_ids,
            authorization_id: authorization_id.to_string(),
            intent_root: intent_root.to_string(),
            net_position_root: net_position_root.to_string(),
            privacy_budget_root: privacy_budget_root.to_string(),
            sponsor_debit_root: sponsor_debit_root.to_string(),
            posted_call_root: posted_call_root.to_string(),
            total_sponsored_fee_units,
            opened_at_height,
            expires_at_height,
            posted_at_height: None,
            status: NettingBatchStatus::Open,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == NettingBatchStatus::Open && height > self.expires_at_height {
            self.status = NettingBatchStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_settlement_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "intent_root": self.intent_root,
            "net_position_root": self.net_position_root,
            "privacy_budget_root": self.privacy_budget_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "posted_call_root": self.posted_call_root,
            "intent_ids_root": low_fee_private_settlement_netting_string_set_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-INTENT-IDS",
                &self.intent_ids,
            ),
            "net_position_ids_root": low_fee_private_settlement_netting_string_set_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-NET-POSITION-IDS",
                &self.net_position_ids,
            ),
            "sponsor_ids_root": low_fee_private_settlement_netting_string_set_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-SPONSOR-IDS",
                &self.sponsor_ids,
            ),
            "authorization_id": self.authorization_id,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "posted_at_height": self.posted_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-BATCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("batch id", &self.batch_id)?;
        if self.intent_ids.is_empty() {
            return Err("batch requires at least one intent".to_string());
        }
        ensure_non_empty("authorization id", &self.authorization_id)?;
        ensure_non_empty("intent root", &self.intent_root)?;
        ensure_non_empty("net position root", &self.net_position_root)?;
        ensure_non_empty("privacy budget root", &self.privacy_budget_root)?;
        ensure_non_empty("sponsor debit root", &self.sponsor_debit_root)?;
        ensure_non_empty("posted call root", &self.posted_call_root)?;
        ensure_positive("total sponsored fee units", self.total_sponsored_fee_units)?;
        ensure_height_order(
            "private settlement batch",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub authorization_id: String,
    pub settlement_state_root: String,
    pub intent_root: String,
    pub net_position_root: String,
    pub sponsor_debit_root: String,
    pub privacy_budget_root: String,
    pub receipt_proof_root: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub status: BatchReceiptStatus,
}

impl BatchSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        authorization_id: &str,
        settlement_state_root: &str,
        intent_root: &str,
        net_position_root: &str,
        sponsor_debit_root: &str,
        privacy_budget_root: &str,
        receipt_proof_root: &str,
        published_at_height: u64,
        receipt_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("authorization id", authorization_id)?;
        ensure_non_empty("settlement state root", settlement_state_root)?;
        ensure_non_empty("intent root", intent_root)?;
        ensure_non_empty("net position root", net_position_root)?;
        ensure_non_empty("sponsor debit root", sponsor_debit_root)?;
        ensure_non_empty("privacy budget root", privacy_budget_root)?;
        ensure_non_empty("receipt proof root", receipt_proof_root)?;
        Ok(Self {
            receipt_id: batch_settlement_receipt_id(batch_id, settlement_state_root, receipt_nonce),
            batch_id: batch_id.to_string(),
            authorization_id: authorization_id.to_string(),
            settlement_state_root: settlement_state_root.to_string(),
            intent_root: intent_root.to_string(),
            net_position_root: net_position_root.to_string(),
            sponsor_debit_root: sponsor_debit_root.to_string(),
            privacy_budget_root: privacy_budget_root.to_string(),
            receipt_proof_root: receipt_proof_root.to_string(),
            published_at_height,
            finalized_at_height: None,
            status: BatchReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "scheme": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_RECEIPT_SCHEME,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "authorization_id": self.authorization_id,
            "settlement_state_root": self.settlement_state_root,
            "intent_root": self.intent_root,
            "net_position_root": self.net_position_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "privacy_budget_root": self.privacy_budget_root,
            "receipt_proof_root": self.receipt_proof_root,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("authorization id", &self.authorization_id)?;
        ensure_non_empty("settlement state root", &self.settlement_state_root)?;
        ensure_non_empty("intent root", &self.intent_root)?;
        ensure_non_empty("net position root", &self.net_position_root)?;
        ensure_non_empty("sponsor debit root", &self.sponsor_debit_root)?;
        ensure_non_empty("privacy budget root", &self.privacy_budget_root)?;
        ensure_non_empty("receipt proof root", &self.receipt_proof_root)?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePrivateSettlementNettingRoots {
    pub config_root: String,
    pub privacy_budget_window_root: String,
    pub sponsor_account_root: String,
    pub authorization_root: String,
    pub intent_root: String,
    pub batch_root: String,
    pub net_position_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
}

impl LowFeePrivateSettlementNettingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "privacy_budget_window_root": self.privacy_budget_window_root,
            "sponsor_account_root": self.sponsor_account_root,
            "authorization_root": self.authorization_root,
            "intent_root": self.intent_root,
            "batch_root": self.batch_root,
            "net_position_root": self.net_position_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn roots_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-NETTING-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePrivateSettlementNettingCounters {
    pub privacy_budget_window_count: u64,
    pub sponsor_account_count: u64,
    pub active_sponsor_account_count: u64,
    pub authorization_count: u64,
    pub active_authorization_count: u64,
    pub pending_intent_count: u64,
    pub netted_intent_count: u64,
    pub settled_intent_count: u64,
    pub batch_count: u64,
    pub open_batch_count: u64,
    pub net_position_count: u64,
    pub receipt_count: u64,
    pub total_sponsored_fee_units: u64,
    pub reserved_sponsored_fee_units: u64,
    pub spent_sponsored_fee_units: u64,
    pub spent_privacy_budget_bps: u64,
    pub reserved_privacy_budget_bps: u64,
}

impl LowFeePrivateSettlementNettingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_budget_window_count": self.privacy_budget_window_count,
            "sponsor_account_count": self.sponsor_account_count,
            "active_sponsor_account_count": self.active_sponsor_account_count,
            "authorization_count": self.authorization_count,
            "active_authorization_count": self.active_authorization_count,
            "pending_intent_count": self.pending_intent_count,
            "netted_intent_count": self.netted_intent_count,
            "settled_intent_count": self.settled_intent_count,
            "batch_count": self.batch_count,
            "open_batch_count": self.open_batch_count,
            "net_position_count": self.net_position_count,
            "receipt_count": self.receipt_count,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "reserved_sponsored_fee_units": self.reserved_sponsored_fee_units,
            "spent_sponsored_fee_units": self.spent_sponsored_fee_units,
            "spent_privacy_budget_bps": self.spent_privacy_budget_bps,
            "reserved_privacy_budget_bps": self.reserved_privacy_budget_bps,
        })
    }

    pub fn counters_root(&self) -> String {
        low_fee_private_settlement_netting_payload_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-NETTING-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePrivateSettlementNettingState {
    pub height: u64,
    pub config: LowFeePrivateSettlementNettingConfig,
    pub privacy_budget_windows: BTreeMap<String, PrivacyBudgetWindow>,
    pub sponsor_accounts: BTreeMap<String, SettlementSponsorAccount>,
    pub authorizations: BTreeMap<String, PqSettlementAuthorization>,
    pub intents: BTreeMap<String, PrivateSettlementIntent>,
    pub batches: BTreeMap<String, PrivateSettlementBatch>,
    pub net_positions: BTreeMap<String, SettlementNetPosition>,
    pub receipts: BTreeMap<String, BatchSettlementReceipt>,
    pub nullifier_index: BTreeMap<String, String>,
}

impl Default for LowFeePrivateSettlementNettingState {
    fn default() -> Self {
        Self::new(LowFeePrivateSettlementNettingConfig::default())
    }
}

impl LowFeePrivateSettlementNettingState {
    pub fn new(config: LowFeePrivateSettlementNettingConfig) -> Self {
        Self {
            height: 0,
            config,
            privacy_budget_windows: BTreeMap::new(),
            sponsor_accounts: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            intents: BTreeMap::new(),
            batches: BTreeMap::new(),
            net_positions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
        }
    }

    pub fn devnet() -> LowFeePrivateSettlementNettingResult<Self> {
        let config = LowFeePrivateSettlementNettingConfig::devnet();
        config.validate()?;
        let mut state = Self::new(config);
        state.set_height(192)?;

        for flow_kind in [
            PrivateSettlementFlowKind::TokenTransfer,
            PrivateSettlementFlowKind::BridgeExit,
            PrivateSettlementFlowKind::AmmFill,
            PrivateSettlementFlowKind::ContractCall,
        ] {
            let window = PrivacyBudgetWindow::new(
                flow_kind.default_lane_key(),
                0,
                0,
                state.config.epoch_blocks,
                state.config.max_lane_privacy_bps,
            )?;
            state.insert_privacy_budget_window(window)?;
        }

        let sponsor = SettlementSponsorAccount::new(
            "devnet-private-netting-sponsor",
            "devnet-operator-commitment",
            "devnet-sponsor-treasury-commitment",
            &state.config.fee_asset_id,
            2_000_000,
            state.config.max_sponsor_exposure_bps,
            state.height,
            0,
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor_account(sponsor)?;

        let authorization = PqSettlementAuthorization::new(
            "devnet-settlement-authorizer",
            "devnet-ml-dsa-87-key",
            &low_fee_private_settlement_netting_string_root("DEVNET-PQ-PUBLIC-KEY", "operator"),
            &low_fee_private_settlement_netting_string_root(
                "DEVNET-PQ-SCOPE",
                "all-private-settlement",
            ),
            state.config.max_batch_items,
            100_000,
            state.height,
            state.config.authorization_ttl_blocks,
            state.config.min_pq_security_bits,
            &low_fee_private_settlement_netting_string_root("DEVNET-PQ-SIGNATURE", "authorization"),
            0,
        )?;
        let authorization_id = authorization.authorization_id.clone();
        state.insert_authorization(authorization)?;

        let transfer_budget = PrivacyBudgetEnvelope::new(
            PrivateSettlementFlowKind::TokenTransfer.default_lane_key(),
            "devnet-private-account-a",
            None,
            &low_fee_private_settlement_netting_string_root("DEVNET-BUDGET-NULLIFIER", "a"),
            PrivateSettlementFlowKind::TokenTransfer.default_privacy_cost_bps(),
            &low_fee_private_settlement_netting_string_root("DEVNET-DISCLOSURE", "transfer"),
        )?;
        let transfer_intent = PrivateSettlementIntent::new(
            PrivateSettlementFlowKind::TokenTransfer,
            "devnet-private-account-a",
            "devnet-private-account-b",
            "wxmr-devnet",
            "wxmr-devnet",
            25_000,
            25_000,
            &low_fee_private_settlement_netting_string_root("DEVNET-ROUTE", "transfer"),
            None,
            None,
            None,
            transfer_budget,
            &sponsor_id,
            &authorization_id,
            &state.config.fee_asset_id,
            75,
            &low_fee_private_settlement_netting_string_root("DEVNET-NULLIFIER", "transfer-a"),
            state.height,
            state.config.batch_ttl_blocks,
            0,
        )?;
        state.insert_intent(transfer_intent)?;

        let amm_budget = PrivacyBudgetEnvelope::new(
            PrivateSettlementFlowKind::AmmFill.default_lane_key(),
            "devnet-private-account-c",
            Some("devnet-private-amm-contract".to_string()),
            &low_fee_private_settlement_netting_string_root("DEVNET-BUDGET-NULLIFIER", "swap"),
            PrivateSettlementFlowKind::AmmFill.default_privacy_cost_bps(),
            &low_fee_private_settlement_netting_string_root("DEVNET-DISCLOSURE", "amm-fill"),
        )?;
        let amm_intent = PrivateSettlementIntent::new(
            PrivateSettlementFlowKind::AmmFill,
            "devnet-private-account-c",
            "devnet-private-account-c",
            "wxmr-devnet",
            "dusd-devnet",
            15_000,
            39_000,
            &low_fee_private_settlement_netting_string_root("DEVNET-ROUTE", "amm-wxmr-dusd"),
            None,
            Some(low_fee_private_settlement_netting_string_root(
                "DEVNET-AMM-FILL",
                "fill-0",
            )),
            None,
            amm_budget,
            &sponsor_id,
            &authorization_id,
            &state.config.fee_asset_id,
            110,
            &low_fee_private_settlement_netting_string_root("DEVNET-NULLIFIER", "amm-c"),
            state.height,
            state.config.batch_ttl_blocks,
            1,
        )?;
        state.insert_intent(amm_intent)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> LowFeePrivateSettlementNettingResult<String> {
        self.height = height;
        for authorization in self.authorizations.values_mut() {
            authorization.set_height(height);
        }
        for intent in self.intents.values_mut() {
            intent.set_height(height);
        }
        for batch in self.batches.values_mut() {
            batch.set_height(height);
        }
        Ok(self.state_root())
    }

    pub fn insert_privacy_budget_window(
        &mut self,
        window: PrivacyBudgetWindow,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        window.validate()?;
        let window_id = window.window_id();
        self.privacy_budget_windows
            .insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn insert_sponsor_account(
        &mut self,
        sponsor: SettlementSponsorAccount,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        sponsor.validate()?;
        if sponsor.fee_asset_id != self.config.fee_asset_id {
            return Err("sponsor fee asset mismatch".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsor_accounts.insert(sponsor_id.clone(), sponsor);
        Ok(sponsor_id)
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqSettlementAuthorization,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        authorization.validate()?;
        if authorization.security_bits < self.config.min_pq_security_bits {
            return Err("authorization below configured pq security floor".to_string());
        }
        let authorization_id = authorization.authorization_id.clone();
        self.authorizations
            .insert(authorization_id.clone(), authorization);
        Ok(authorization_id)
    }

    pub fn insert_intent(
        &mut self,
        intent: PrivateSettlementIntent,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        intent.validate()?;
        if intent.fee_asset_id != self.config.fee_asset_id {
            return Err("intent fee asset mismatch".to_string());
        }
        if self.nullifier_index.contains_key(&intent.nullifier) {
            return Err("private settlement intent nullifier replay".to_string());
        }
        let authorization = self
            .authorizations
            .get(&intent.authorization_id)
            .ok_or_else(|| "intent references unknown pq authorization".to_string())?;
        if !authorization.is_live_at(self.height) {
            return Err("intent pq authorization is not live".to_string());
        }
        let sponsor = self
            .sponsor_accounts
            .get_mut(&intent.sponsor_id)
            .ok_or_else(|| "intent references unknown sponsor".to_string())?;
        sponsor.reserve(intent.sponsored_fee_units, self.height)?;
        let window_id = privacy_budget_window_id(
            &intent.lane_key,
            current_epoch(self.height, self.config.epoch_blocks),
        );
        let window = self
            .privacy_budget_windows
            .get_mut(&window_id)
            .ok_or_else(|| "intent references missing privacy budget window".to_string())?;
        window.reserve(&intent.privacy_budget, self.config.max_account_privacy_bps)?;
        let intent_id = intent.intent_id.clone();
        self.nullifier_index
            .insert(intent.nullifier.clone(), intent_id.clone());
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn build_batch(
        &mut self,
        requested_intent_ids: BTreeSet<String>,
        authorization_id: &str,
        posted_call_root: &str,
        batch_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        if requested_intent_ids.is_empty() {
            return Err("batch requires at least one intent".to_string());
        }
        if requested_intent_ids.len() as u64 > self.config.max_batch_items {
            return Err("batch exceeds configured item limit".to_string());
        }
        ensure_non_empty("authorization id", authorization_id)?;
        ensure_non_empty("posted call root", posted_call_root)?;
        let authorization = self
            .authorizations
            .get(authorization_id)
            .ok_or_else(|| "batch references unknown pq authorization".to_string())?;
        if !authorization.is_live_at(self.height) {
            return Err("batch pq authorization is not live".to_string());
        }
        if requested_intent_ids.len() as u64 > authorization.max_batch_items {
            return Err("batch exceeds pq authorization item limit".to_string());
        }

        let mut intent_records = Vec::new();
        let mut sponsor_ids = BTreeSet::new();
        let mut sponsor_debits = BTreeMap::<String, u64>::new();
        let mut privacy_records = Vec::new();
        let mut totals = BTreeMap::<String, (u64, u64, BTreeSet<String>)>::new();
        let mut total_sponsored_fee_units = 0_u64;

        for intent_id in &requested_intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "batch references unknown intent".to_string())?;
            if !intent.status.batchable() {
                return Err("batch references non-batchable intent".to_string());
            }
            if intent.authorization_id != authorization_id {
                return Err("batch intent authorization mismatch".to_string());
            }
            if intent.expires_at_height < self.height {
                return Err("batch references expired intent".to_string());
            }
            total_sponsored_fee_units =
                total_sponsored_fee_units.saturating_add(intent.sponsored_fee_units);
            if total_sponsored_fee_units > authorization.max_fee_units {
                return Err("batch exceeds pq authorization fee limit".to_string());
            }
            sponsor_ids.insert(intent.sponsor_id.clone());
            let sponsor_total = map_u64_or_zero(&sponsor_debits, &intent.sponsor_id)
                .saturating_add(intent.sponsored_fee_units);
            sponsor_debits.insert(intent.sponsor_id.clone(), sponsor_total);
            privacy_records.push(intent.privacy_budget.public_record());
            add_position_delta(
                &mut totals,
                &intent.debit_asset_id,
                intent.debit_amount_units,
                0,
                &intent.payer_commitment,
            );
            add_position_delta(
                &mut totals,
                &intent.credit_asset_id,
                0,
                intent.min_credit_amount_units,
                &intent.receiver_commitment,
            );
            intent_records.push(intent.public_record());
        }

        let intent_root = low_fee_private_settlement_netting_record_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-INTENT-SET",
            intent_records,
        );
        let privacy_budget_root = low_fee_private_settlement_netting_record_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-PRIVACY-BUDGET-SET",
            privacy_records,
        );
        let sponsor_debit_root = low_fee_private_settlement_netting_u64_map_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-SPONSOR-DEBITS",
            &sponsor_debits,
        );
        let pending_net_position_root = low_fee_private_settlement_netting_string_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-PENDING-NET-POSITION-ROOT",
            &intent_root,
        );

        let mut batch = PrivateSettlementBatch::new(
            requested_intent_ids.clone(),
            sponsor_ids,
            authorization_id,
            &intent_root,
            &pending_net_position_root,
            &privacy_budget_root,
            &sponsor_debit_root,
            posted_call_root,
            total_sponsored_fee_units,
            self.height,
            self.config.batch_ttl_blocks,
            batch_nonce,
        )?;
        let batch_id = batch.batch_id.clone();

        let mut position_records = Vec::new();
        for (asset_id, (debit_units, credit_units, participants)) in totals {
            let participant_root = low_fee_private_settlement_netting_string_set_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-NET-POSITION-PARTICIPANTS",
                &participants,
            );
            let position = SettlementNetPosition::new(
                &batch_id,
                &asset_id,
                debit_units,
                credit_units,
                &participant_root,
            )?;
            let position_id = position.position_id.clone();
            position_records.push(position.public_record());
            batch.net_position_ids.insert(position_id.clone());
            self.net_positions.insert(position_id, position);
        }
        batch.net_position_root = low_fee_private_settlement_netting_record_root(
            "LOW-FEE-PRIVATE-SETTLEMENT-NET-POSITION-SET",
            position_records,
        );
        batch.status = NettingBatchStatus::Authorized;

        for intent_id in &requested_intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = SettlementIntentStatus::Netted;
                let window_id = privacy_budget_window_id(
                    &intent.lane_key,
                    current_epoch(self.height, self.config.epoch_blocks),
                );
                if let Some(window) = self.privacy_budget_windows.get_mut(&window_id) {
                    window.spend(&intent.privacy_budget);
                }
            }
        }
        for (sponsor_id, amount_units) in sponsor_debits {
            if let Some(sponsor) = self.sponsor_accounts.get_mut(&sponsor_id) {
                sponsor.spend_reserved(amount_units, self.height);
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        batch_id: &str,
        settlement_state_root: &str,
        receipt_proof_root: &str,
        receipt_nonce: u64,
    ) -> LowFeePrivateSettlementNettingResult<String> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("settlement state root", settlement_state_root)?;
        ensure_non_empty("receipt proof root", receipt_proof_root)?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "receipt references unknown batch".to_string())?;
        if !batch.status.final_for_receipts() && batch.status != NettingBatchStatus::Authorized {
            return Err("batch is not receipt-ready".to_string());
        }
        batch.status = NettingBatchStatus::Posted;
        batch.posted_at_height = Some(self.height);
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = SettlementIntentStatus::Settled;
            }
        }
        let receipt = BatchSettlementReceipt::new(
            &batch.batch_id,
            &batch.authorization_id,
            settlement_state_root,
            &batch.intent_root,
            &batch.net_position_root,
            &batch.sponsor_debit_root,
            &batch.privacy_budget_root,
            receipt_proof_root,
            self.height,
            receipt_nonce,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> LowFeePrivateSettlementNettingRoots {
        LowFeePrivateSettlementNettingRoots {
            config_root: self.config.config_root(),
            privacy_budget_window_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-PRIVACY-BUDGET-WINDOW-SET",
                self.privacy_budget_windows
                    .values()
                    .map(PrivacyBudgetWindow::public_record)
                    .collect(),
            ),
            sponsor_account_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-SPONSOR-ACCOUNT-SET",
                self.sponsor_accounts
                    .values()
                    .map(SettlementSponsorAccount::public_record)
                    .collect(),
            ),
            authorization_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-PQ-AUTHORIZATION-SET",
                self.authorizations
                    .values()
                    .map(PqSettlementAuthorization::public_record)
                    .collect(),
            ),
            intent_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-INTENT-SET",
                self.intents
                    .values()
                    .map(PrivateSettlementIntent::public_record)
                    .collect(),
            ),
            batch_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-SET",
                self.batches
                    .values()
                    .map(PrivateSettlementBatch::public_record)
                    .collect(),
            ),
            net_position_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-NET-POSITION-SET",
                self.net_positions
                    .values()
                    .map(SettlementNetPosition::public_record)
                    .collect(),
            ),
            receipt_root: low_fee_private_settlement_netting_record_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-RECEIPT-SET",
                self.receipts
                    .values()
                    .map(BatchSettlementReceipt::public_record)
                    .collect(),
            ),
            nullifier_root: low_fee_private_settlement_netting_string_map_root(
                "LOW-FEE-PRIVATE-SETTLEMENT-NULLIFIER-INDEX",
                &self.nullifier_index,
            ),
        }
    }

    pub fn counters(&self) -> LowFeePrivateSettlementNettingCounters {
        LowFeePrivateSettlementNettingCounters {
            privacy_budget_window_count: self.privacy_budget_windows.len() as u64,
            sponsor_account_count: self.sponsor_accounts.len() as u64,
            active_sponsor_account_count: self
                .sponsor_accounts
                .values()
                .filter(|sponsor| sponsor.status == SettlementSponsorStatus::Active)
                .count() as u64,
            authorization_count: self.authorizations.len() as u64,
            active_authorization_count: self
                .authorizations
                .values()
                .filter(|authorization| authorization.is_live_at(self.height))
                .count() as u64,
            pending_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status == SettlementIntentStatus::Pending)
                .count() as u64,
            netted_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status == SettlementIntentStatus::Netted)
                .count() as u64,
            settled_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status == SettlementIntentStatus::Settled)
                .count() as u64,
            batch_count: self.batches.len() as u64,
            open_batch_count: self
                .batches
                .values()
                .filter(|batch| {
                    batch.status == NettingBatchStatus::Open
                        || batch.status == NettingBatchStatus::Authorized
                })
                .count() as u64,
            net_position_count: self.net_positions.len() as u64,
            receipt_count: self.receipts.len() as u64,
            total_sponsored_fee_units: self
                .sponsor_accounts
                .values()
                .map(|sponsor| sponsor.total_budget_units)
                .sum(),
            reserved_sponsored_fee_units: self
                .sponsor_accounts
                .values()
                .map(|sponsor| sponsor.reserved_units)
                .sum(),
            spent_sponsored_fee_units: self
                .sponsor_accounts
                .values()
                .map(|sponsor| sponsor.spent_units)
                .sum(),
            spent_privacy_budget_bps: self
                .privacy_budget_windows
                .values()
                .map(|window| window.spent_lane_budget_bps)
                .sum(),
            reserved_privacy_budget_bps: self
                .privacy_budget_windows
                .values()
                .map(|window| window.reserved_lane_budget_bps)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "low_fee_private_settlement_netting_state",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION,
            "schema_version": LOW_FEE_PRIVATE_SETTLEMENT_NETTING_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_private_settlement_netting_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "low_fee_private_settlement_netting_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn validate(&self) -> LowFeePrivateSettlementNettingResult<String> {
        self.config.validate()?;
        for (window_id, window) in &self.privacy_budget_windows {
            if window_id != &window.window_id() {
                return Err("privacy budget window map key mismatch".to_string());
            }
            window.validate()?;
        }
        for (sponsor_id, sponsor) in &self.sponsor_accounts {
            if sponsor_id != &sponsor.sponsor_id {
                return Err("sponsor account map key mismatch".to_string());
            }
            sponsor.validate()?;
        }
        for (authorization_id, authorization) in &self.authorizations {
            if authorization_id != &authorization.authorization_id {
                return Err("pq authorization map key mismatch".to_string());
            }
            authorization.validate()?;
        }
        for (intent_id, intent) in &self.intents {
            if intent_id != &intent.intent_id {
                return Err("intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !self.sponsor_accounts.contains_key(&intent.sponsor_id) {
                return Err("intent sponsor missing".to_string());
            }
            if !self.authorizations.contains_key(&intent.authorization_id) {
                return Err("intent authorization missing".to_string());
            }
        }
        for (batch_id, batch) in &self.batches {
            if batch_id != &batch.batch_id {
                return Err("batch map key mismatch".to_string());
            }
            batch.validate()?;
            if !self.authorizations.contains_key(&batch.authorization_id) {
                return Err("batch authorization missing".to_string());
            }
            for intent_id in &batch.intent_ids {
                if !self.intents.contains_key(intent_id) {
                    return Err("batch intent missing".to_string());
                }
            }
            for position_id in &batch.net_position_ids {
                if !self.net_positions.contains_key(position_id) {
                    return Err("batch net position missing".to_string());
                }
            }
        }
        for (position_id, position) in &self.net_positions {
            if position_id != &position.position_id {
                return Err("net position map key mismatch".to_string());
            }
            position.validate()?;
            if !self.batches.contains_key(&position.batch_id) {
                return Err("net position batch missing".to_string());
            }
        }
        for (receipt_id, receipt) in &self.receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("receipt batch missing".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn low_fee_private_settlement_netting_state_root_from_record(record: &Value) -> String {
    low_fee_private_settlement_netting_payload_root(
        "LOW-FEE-PRIVATE-SETTLEMENT-NETTING-STATE",
        record,
    )
}

pub fn low_fee_private_settlement_netting_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn low_fee_private_settlement_netting_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_PRIVATE_SETTLEMENT_NETTING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_settlement_intent_id(
    flow_kind: PrivateSettlementFlowKind,
    payer_commitment: &str,
    nullifier: &str,
    route_or_call_root: &str,
    opened_at_height: u64,
    intent_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(flow_kind.as_str()),
            HashPart::Str(payer_commitment),
            HashPart::Str(nullifier),
            HashPart::Str(route_or_call_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(intent_nonce as i128),
        ],
        20,
    )
}

pub fn private_settlement_batch_id(
    intent_root: &str,
    net_position_root: &str,
    authorization_id: &str,
    opened_at_height: u64,
    batch_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_root),
            HashPart::Str(net_position_root),
            HashPart::Str(authorization_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(batch_nonce as i128),
        ],
        20,
    )
}

pub fn settlement_net_position_id(
    batch_id: &str,
    asset_id: &str,
    debit_units: u64,
    credit_units: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-NET-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(asset_id),
            HashPart::Int(debit_units as i128),
            HashPart::Int(credit_units as i128),
        ],
        20,
    )
}

pub fn settlement_sponsor_account_id(
    sponsor_label: &str,
    operator_commitment: &str,
    treasury_commitment: &str,
    fee_asset_id: &str,
    account_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-SPONSOR-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(operator_commitment),
            HashPart::Str(treasury_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(account_nonce as i128),
        ],
        20,
    )
}

pub fn pq_settlement_authorization_id(
    authorizer_commitment: &str,
    signer_key_id: &str,
    scope_root: &str,
    valid_from_height: u64,
    authorization_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(authorizer_commitment),
            HashPart::Str(signer_key_id),
            HashPart::Str(scope_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(authorization_nonce as i128),
        ],
        20,
    )
}

pub fn batch_settlement_receipt_id(
    batch_id: &str,
    settlement_state_root: &str,
    receipt_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-BATCH-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_state_root),
            HashPart::Int(receipt_nonce as i128),
        ],
        20,
    )
}

pub fn privacy_budget_window_id(lane_key: &str, epoch_index: u64) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-SETTLEMENT-PRIVACY-BUDGET-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_key),
            HashPart::Int(epoch_index as i128),
        ],
        20,
    )
}

pub fn low_fee_private_settlement_netting_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn low_fee_private_settlement_netting_string_set_root(
    domain: &str,
    values: &BTreeSet<String>,
) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn low_fee_private_settlement_netting_string_map_root(
    domain: &str,
    values: &BTreeMap<String, String>,
) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn low_fee_private_settlement_netting_u64_map_root(
    domain: &str,
    values: &BTreeMap<String, u64>,
) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn current_epoch(height: u64, epoch_blocks: u64) -> u64 {
    if epoch_blocks == 0 {
        0
    } else {
        height.saturating_div(epoch_blocks)
    }
}

fn add_position_delta(
    totals: &mut BTreeMap<String, (u64, u64, BTreeSet<String>)>,
    asset_id: &str,
    debit_units: u64,
    credit_units: u64,
    participant_commitment: &str,
) {
    let entry = totals
        .entry(asset_id.to_string())
        .or_insert((0, 0, BTreeSet::new()));
    entry.0 = entry.0.saturating_add(debit_units);
    entry.1 = entry.1.saturating_add(credit_units);
    entry.2.insert(participant_commitment.to_string());
}

fn spend_budget_map(
    reserved: &mut BTreeMap<String, u64>,
    spent: &mut BTreeMap<String, u64>,
    key: &str,
    amount: u64,
) {
    let reserved_units = map_u64_or_zero(reserved, key).saturating_sub(amount);
    if reserved_units == 0 {
        reserved.remove(key);
    } else {
        reserved.insert(key.to_string(), reserved_units);
    }
    let spent_units = map_u64_or_zero(spent, key).saturating_add(amount);
    spent.insert(key.to_string(), spent_units);
}

fn map_u64_or_zero(values: &BTreeMap<String, u64>, key: &str) -> u64 {
    match values.get(key) {
        Some(value) => *value,
        None => 0,
    }
}

fn ensure_non_empty(label: &str, value: &str) -> LowFeePrivateSettlementNettingResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> LowFeePrivateSettlementNettingResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> LowFeePrivateSettlementNettingResult<()> {
    if value > LOW_FEE_PRIVATE_SETTLEMENT_NETTING_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_height_order(
    label: &str,
    start: u64,
    end: u64,
) -> LowFeePrivateSettlementNettingResult<()> {
    if end < start {
        return Err(format!("{label} ends before it starts"));
    }
    Ok(())
}

fn ensure_eq(
    label: &str,
    actual: &str,
    required: &str,
) -> LowFeePrivateSettlementNettingResult<()> {
    if actual != required {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}
