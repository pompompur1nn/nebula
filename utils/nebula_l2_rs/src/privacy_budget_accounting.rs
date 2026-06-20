use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivacyBudgetAccountingResult<T> = Result<T, String>;

pub const PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION: &str = "nebula-privacy-budget-accounting-v1";
pub const PRIVACY_BUDGET_ACCOUNTING_SCHEMA_VERSION: u64 = 1;
pub const PRIVACY_BUDGET_ACCOUNTING_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVACY_BUDGET_ACCOUNTING_PQ_AUTH_SCHEME: &str = "ML-DSA-65";
pub const PRIVACY_BUDGET_ACCOUNTING_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 96;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 7_200;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 1_440;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_ACCOUNT_BPS: u64 = 2_500;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_CONTRACT_BPS: u64 = 1_500;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_LANE_BPS: u64 = 3_500;
pub const PRIVACY_BUDGET_ACCOUNTING_DEFAULT_REBATE_BPS: u64 = 8_000;
pub const PRIVACY_BUDGET_ACCOUNTING_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyBudgetDomain {
    PrivateTransfer,
    PrivateSwap,
    PrivateLending,
    PrivatePerps,
    PrivateStablecoin,
    MoneroBridge,
    ContractDeployment,
    ProofMarket,
    Governance,
    Audit,
}

impl PrivacyBudgetDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractDeployment => "contract_deployment",
            Self::ProofMarket => "proof_market",
            Self::Governance => "governance",
            Self::Audit => "audit",
        }
    }

    pub fn default_lane_key(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "lane:privacy:transfer",
            Self::PrivateSwap => "lane:defi:swap",
            Self::PrivateLending => "lane:defi:lending",
            Self::PrivatePerps => "lane:defi:perps",
            Self::PrivateStablecoin => "lane:defi:stablecoin",
            Self::MoneroBridge => "lane:bridge:monero",
            Self::ContractDeployment => "lane:contracts:deploy",
            Self::ProofMarket => "lane:proofs:recursive",
            Self::Governance => "lane:governance:private",
            Self::Audit => "lane:audit:selective",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyBudgetClass {
    Metadata,
    Counterparty,
    AmountRange,
    RouteHint,
    LiquidityPosition,
    ContractSelector,
    WitnessShape,
    AuditFinding,
    EmergencyDisclosure,
}

impl PrivacyBudgetClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Counterparty => "counterparty",
            Self::AmountRange => "amount_range",
            Self::RouteHint => "route_hint",
            Self::LiquidityPosition => "liquidity_position",
            Self::ContractSelector => "contract_selector",
            Self::WitnessShape => "witness_shape",
            Self::AuditFinding => "audit_finding",
            Self::EmergencyDisclosure => "emergency_disclosure",
        }
    }

    pub fn default_weight_bps(&self) -> u64 {
        match self {
            Self::Metadata => 50,
            Self::Counterparty => 400,
            Self::AmountRange => 250,
            Self::RouteHint => 150,
            Self::LiquidityPosition => 450,
            Self::ContractSelector => 125,
            Self::WitnessShape => 175,
            Self::AuditFinding => 300,
            Self::EmergencyDisclosure => 1_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BudgetStatus {
    Active,
    Paused,
    Exhausted,
    Quarantined,
    Expired,
}

impl BudgetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DisclosureTicketStatus {
    Requested,
    Authorized,
    Spent,
    Rejected,
    Expired,
    Revoked,
}

impl DisclosureTicketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::Spent => "spent",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Requested | Self::Authorized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeeShieldGrantStatus {
    Open,
    Reserved,
    Settled,
    Exhausted,
    Expired,
    Revoked,
}

impl FeeShieldGrantStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(&self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditDisclosureStatus {
    Pending,
    Published,
    Challenged,
    Sealed,
    Expired,
}

impl AuditDisclosureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Sealed => "sealed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyBudgetActionKind {
    ThrottleLane,
    PauseAccount,
    PauseContract,
    RequireAudit,
    RotateViewKey,
    ReduceRebate,
    EscalateToGovernance,
}

impl PrivacyBudgetActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ThrottleLane => "throttle_lane",
            Self::PauseAccount => "pause_account",
            Self::PauseContract => "pause_contract",
            Self::RequireAudit => "require_audit",
            Self::RotateViewKey => "rotate_view_key",
            Self::ReduceRebate => "reduce_rebate",
            Self::EscalateToGovernance => "escalate_to_governance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyBudgetActionStatus {
    Open,
    Applied,
    Dismissed,
    Expired,
}

impl PrivacyBudgetActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Applied => "applied",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccountingConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub max_account_budget_bps: u64,
    pub max_contract_budget_bps: u64,
    pub max_lane_budget_bps: u64,
    pub default_rebate_bps: u64,
    pub pq_auth_scheme: String,
    pub pq_backup_scheme: String,
}

impl Default for PrivacyBudgetAccountingConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVACY_BUDGET_ACCOUNTING_SCHEMA_VERSION,
            fee_asset_id: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_FEE_ASSET_ID.to_string(),
            epoch_blocks: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_EPOCH_BLOCKS,
            disclosure_ttl_blocks: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            audit_ttl_blocks: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_AUDIT_TTL_BLOCKS,
            sponsor_ttl_blocks: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_SPONSOR_TTL_BLOCKS,
            max_account_budget_bps: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_ACCOUNT_BPS,
            max_contract_budget_bps: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_CONTRACT_BPS,
            max_lane_budget_bps: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_MAX_LANE_BPS,
            default_rebate_bps: PRIVACY_BUDGET_ACCOUNTING_DEFAULT_REBATE_BPS,
            pq_auth_scheme: PRIVACY_BUDGET_ACCOUNTING_PQ_AUTH_SCHEME.to_string(),
            pq_backup_scheme: PRIVACY_BUDGET_ACCOUNTING_PQ_BACKUP_SCHEME.to_string(),
        }
    }
}

impl PrivacyBudgetAccountingConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_accounting_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "max_account_budget_bps": self.max_account_budget_bps,
            "max_contract_budget_bps": self.max_contract_budget_bps,
            "max_lane_budget_bps": self.max_lane_budget_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "hash_suite": PRIVACY_BUDGET_ACCOUNTING_HASH_SUITE,
        })
    }

    pub fn config_root(&self) -> String {
        privacy_budget_payload_root("PRIVACY-BUDGET-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        if self.protocol_version != PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION {
            return Err("privacy budget protocol version mismatch".to_string());
        }
        if self.schema_version != PRIVACY_BUDGET_ACCOUNTING_SCHEMA_VERSION {
            return Err("privacy budget schema version mismatch".to_string());
        }
        ensure_nonempty("fee asset id", &self.fee_asset_id)?;
        ensure_nonzero("epoch blocks", self.epoch_blocks)?;
        ensure_nonzero("disclosure ttl blocks", self.disclosure_ttl_blocks)?;
        ensure_nonzero("audit ttl blocks", self.audit_ttl_blocks)?;
        ensure_nonzero("sponsor ttl blocks", self.sponsor_ttl_blocks)?;
        ensure_bps("max account budget bps", self.max_account_budget_bps)?;
        ensure_bps("max contract budget bps", self.max_contract_budget_bps)?;
        ensure_bps("max lane budget bps", self.max_lane_budget_bps)?;
        ensure_bps("default rebate bps", self.default_rebate_bps)?;
        ensure_nonempty("pq auth scheme", &self.pq_auth_scheme)?;
        ensure_nonempty("pq backup scheme", &self.pq_backup_scheme)?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetLane {
    pub lane_id: String,
    pub domain: PrivacyBudgetDomain,
    pub lane_key: String,
    pub epoch_index: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub max_budget_bps: u64,
    pub spent_budget_bps: u64,
    pub reserved_budget_bps: u64,
    pub low_fee_quota_units: u64,
    pub spent_low_fee_units: u64,
    pub account_ids: BTreeSet<String>,
    pub contract_ids: BTreeSet<String>,
    pub status: BudgetStatus,
}

impl PrivacyBudgetLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: PrivacyBudgetDomain,
        lane_key: &str,
        epoch_index: u64,
        epoch_start_height: u64,
        epoch_blocks: u64,
        max_budget_bps: u64,
        low_fee_quota_units: u64,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("lane key", lane_key)?;
        ensure_nonzero("epoch blocks", epoch_blocks)?;
        ensure_bps("lane max budget bps", max_budget_bps)?;
        let epoch_end_height = epoch_start_height.saturating_add(epoch_blocks);
        let lane_id = privacy_budget_lane_id(&domain, lane_key, epoch_index);
        Ok(Self {
            lane_id,
            domain,
            lane_key: lane_key.to_string(),
            epoch_index,
            epoch_start_height,
            epoch_end_height,
            max_budget_bps,
            spent_budget_bps: 0,
            reserved_budget_bps: 0,
            low_fee_quota_units,
            spent_low_fee_units: 0,
            account_ids: BTreeSet::new(),
            contract_ids: BTreeSet::new(),
            status: BudgetStatus::Active,
        })
    }

    pub fn available_budget_bps(&self) -> u64 {
        self.max_budget_bps
            .saturating_sub(self.spent_budget_bps)
            .saturating_sub(self.reserved_budget_bps)
    }

    pub fn available_low_fee_units(&self) -> u64 {
        self.low_fee_quota_units
            .saturating_sub(self.spent_low_fee_units)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == BudgetStatus::Active
            && height >= self.epoch_start_height
            && height <= self.epoch_end_height
    }

    pub fn reserve_budget(&mut self, budget_bps: u64) -> PrivacyBudgetAccountingResult<()> {
        ensure_bps("reserved lane budget bps", budget_bps)?;
        if budget_bps > self.available_budget_bps() {
            return Err("lane privacy budget exhausted".to_string());
        }
        self.reserved_budget_bps = self.reserved_budget_bps.saturating_add(budget_bps);
        Ok(())
    }

    pub fn spend_budget(&mut self, budget_bps: u64) -> PrivacyBudgetAccountingResult<()> {
        ensure_bps("spent lane budget bps", budget_bps)?;
        if budget_bps
            > self
                .available_budget_bps()
                .saturating_add(self.reserved_budget_bps)
        {
            return Err("lane privacy budget spend exceeds cap".to_string());
        }
        self.reserved_budget_bps = self.reserved_budget_bps.saturating_sub(budget_bps);
        self.spent_budget_bps = self.spent_budget_bps.saturating_add(budget_bps);
        if self.spent_budget_bps >= self.max_budget_bps {
            self.status = BudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "domain": self.domain.as_str(),
            "lane_key": self.lane_key,
            "epoch_index": self.epoch_index,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "max_budget_bps": self.max_budget_bps,
            "spent_budget_bps": self.spent_budget_bps,
            "reserved_budget_bps": self.reserved_budget_bps,
            "available_budget_bps": self.available_budget_bps(),
            "low_fee_quota_units": self.low_fee_quota_units,
            "spent_low_fee_units": self.spent_low_fee_units,
            "available_low_fee_units": self.available_low_fee_units(),
            "account_root": privacy_budget_string_set_root("PRIVACY-BUDGET-LANE-ACCOUNTS", &self.account_ids),
            "contract_root": privacy_budget_string_set_root("PRIVACY-BUDGET-LANE-CONTRACTS", &self.contract_ids),
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        privacy_budget_payload_root("PRIVACY-BUDGET-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("lane key", &self.lane_key)?;
        ensure_bps("lane max budget bps", self.max_budget_bps)?;
        ensure_bps("lane spent budget bps", self.spent_budget_bps)?;
        ensure_bps("lane reserved budget bps", self.reserved_budget_bps)?;
        if self.epoch_end_height < self.epoch_start_height {
            return Err("privacy budget lane epoch ends before it starts".to_string());
        }
        if self
            .spent_budget_bps
            .saturating_add(self.reserved_budget_bps)
            > self.max_budget_bps
        {
            return Err("privacy budget lane overspent".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPrivacyBudget {
    pub account_budget_id: String,
    pub account_commitment: String,
    pub lane_id: String,
    pub epoch_index: u64,
    pub max_budget_bps: u64,
    pub spent_budget_bps: u64,
    pub reserved_budget_bps: u64,
    pub nullifier_root: String,
    pub pq_owner_root: String,
    pub view_key_rotation_root: String,
    pub status: BudgetStatus,
}

impl AccountPrivacyBudget {
    pub fn new(
        account_commitment: &str,
        lane_id: &str,
        epoch_index: u64,
        max_budget_bps: u64,
        nullifier_root: &str,
        pq_owner_root: &str,
        view_key_rotation_root: &str,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("account commitment", account_commitment)?;
        ensure_nonempty("lane id", lane_id)?;
        ensure_bps("account max budget bps", max_budget_bps)?;
        ensure_nonempty("nullifier root", nullifier_root)?;
        ensure_nonempty("pq owner root", pq_owner_root)?;
        ensure_nonempty("view key rotation root", view_key_rotation_root)?;
        Ok(Self {
            account_budget_id: account_privacy_budget_id(account_commitment, lane_id, epoch_index),
            account_commitment: account_commitment.to_string(),
            lane_id: lane_id.to_string(),
            epoch_index,
            max_budget_bps,
            spent_budget_bps: 0,
            reserved_budget_bps: 0,
            nullifier_root: nullifier_root.to_string(),
            pq_owner_root: pq_owner_root.to_string(),
            view_key_rotation_root: view_key_rotation_root.to_string(),
            status: BudgetStatus::Active,
        })
    }

    pub fn available_budget_bps(&self) -> u64 {
        self.max_budget_bps
            .saturating_sub(self.spent_budget_bps)
            .saturating_sub(self.reserved_budget_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "account_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "account_budget_id": self.account_budget_id,
            "account_commitment": self.account_commitment,
            "lane_id": self.lane_id,
            "epoch_index": self.epoch_index,
            "max_budget_bps": self.max_budget_bps,
            "spent_budget_bps": self.spent_budget_bps,
            "reserved_budget_bps": self.reserved_budget_bps,
            "available_budget_bps": self.available_budget_bps(),
            "nullifier_root": self.nullifier_root,
            "pq_owner_root": self.pq_owner_root,
            "view_key_rotation_root": self.view_key_rotation_root,
            "status": self.status.as_str(),
        })
    }

    pub fn budget_root(&self) -> String {
        privacy_budget_payload_root("ACCOUNT-PRIVACY-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("account budget id", &self.account_budget_id)?;
        ensure_nonempty("account commitment", &self.account_commitment)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_bps("account max budget bps", self.max_budget_bps)?;
        ensure_bps("account spent budget bps", self.spent_budget_bps)?;
        ensure_bps("account reserved budget bps", self.reserved_budget_bps)?;
        if self
            .spent_budget_bps
            .saturating_add(self.reserved_budget_bps)
            > self.max_budget_bps
        {
            return Err("account privacy budget overspent".to_string());
        }
        Ok(self.budget_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPrivacyBudget {
    pub contract_budget_id: String,
    pub contract_commitment: String,
    pub lane_id: String,
    pub namespace_root: String,
    pub selector_root: String,
    pub epoch_index: u64,
    pub max_budget_bps: u64,
    pub spent_budget_bps: u64,
    pub reserved_budget_bps: u64,
    pub audit_required: bool,
    pub status: BudgetStatus,
}

impl ContractPrivacyBudget {
    pub fn new(
        contract_commitment: &str,
        lane_id: &str,
        namespace_root: &str,
        selector_root: &str,
        epoch_index: u64,
        max_budget_bps: u64,
        audit_required: bool,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("contract commitment", contract_commitment)?;
        ensure_nonempty("lane id", lane_id)?;
        ensure_nonempty("namespace root", namespace_root)?;
        ensure_nonempty("selector root", selector_root)?;
        ensure_bps("contract max budget bps", max_budget_bps)?;
        Ok(Self {
            contract_budget_id: contract_privacy_budget_id(
                contract_commitment,
                lane_id,
                epoch_index,
            ),
            contract_commitment: contract_commitment.to_string(),
            lane_id: lane_id.to_string(),
            namespace_root: namespace_root.to_string(),
            selector_root: selector_root.to_string(),
            epoch_index,
            max_budget_bps,
            spent_budget_bps: 0,
            reserved_budget_bps: 0,
            audit_required,
            status: BudgetStatus::Active,
        })
    }

    pub fn available_budget_bps(&self) -> u64 {
        self.max_budget_bps
            .saturating_sub(self.spent_budget_bps)
            .saturating_sub(self.reserved_budget_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "contract_budget_id": self.contract_budget_id,
            "contract_commitment": self.contract_commitment,
            "lane_id": self.lane_id,
            "namespace_root": self.namespace_root,
            "selector_root": self.selector_root,
            "epoch_index": self.epoch_index,
            "max_budget_bps": self.max_budget_bps,
            "spent_budget_bps": self.spent_budget_bps,
            "reserved_budget_bps": self.reserved_budget_bps,
            "available_budget_bps": self.available_budget_bps(),
            "audit_required": self.audit_required,
            "status": self.status.as_str(),
        })
    }

    pub fn budget_root(&self) -> String {
        privacy_budget_payload_root("CONTRACT-PRIVACY-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("contract budget id", &self.contract_budget_id)?;
        ensure_nonempty("contract commitment", &self.contract_commitment)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_bps("contract max budget bps", self.max_budget_bps)?;
        ensure_bps("contract spent budget bps", self.spent_budget_bps)?;
        ensure_bps("contract reserved budget bps", self.reserved_budget_bps)?;
        if self
            .spent_budget_bps
            .saturating_add(self.reserved_budget_bps)
            > self.max_budget_bps
        {
            return Err("contract privacy budget overspent".to_string());
        }
        Ok(self.budget_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub account_budget_id: String,
    pub contract_budget_id: Option<String>,
    pub budget_class: PrivacyBudgetClass,
    pub requested_budget_bps: u64,
    pub authorized_budget_bps: u64,
    pub purpose_root: String,
    pub subject_root: String,
    pub encrypted_payload_root: String,
    pub pq_authorization_root: String,
    pub nullifier_hash: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub status: DisclosureTicketStatus,
}

impl DisclosureTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        account_budget_id: &str,
        contract_budget_id: Option<String>,
        budget_class: PrivacyBudgetClass,
        requested_budget_bps: u64,
        purpose_root: &str,
        subject_root: &str,
        encrypted_payload_root: &str,
        pq_authorization_root: &str,
        nullifier_hash: &str,
        requested_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("lane id", lane_id)?;
        ensure_nonempty("account budget id", account_budget_id)?;
        ensure_bps("requested budget bps", requested_budget_bps)?;
        ensure_nonempty("purpose root", purpose_root)?;
        ensure_nonempty("subject root", subject_root)?;
        ensure_nonempty("encrypted payload root", encrypted_payload_root)?;
        ensure_nonempty("pq authorization root", pq_authorization_root)?;
        ensure_nonempty("nullifier hash", nullifier_hash)?;
        ensure_nonzero("ticket ttl blocks", ttl_blocks)?;
        let expires_at_height = requested_at_height.saturating_add(ttl_blocks);
        let ticket_id = disclosure_ticket_id(
            lane_id,
            account_budget_id,
            contract_budget_id.as_deref().unwrap_or("none"),
            nullifier_hash,
        );
        Ok(Self {
            ticket_id,
            lane_id: lane_id.to_string(),
            account_budget_id: account_budget_id.to_string(),
            contract_budget_id,
            budget_class,
            requested_budget_bps,
            authorized_budget_bps: 0,
            purpose_root: purpose_root.to_string(),
            subject_root: subject_root.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            pq_authorization_root: pq_authorization_root.to_string(),
            nullifier_hash: nullifier_hash.to_string(),
            requested_at_height,
            expires_at_height,
            status: DisclosureTicketStatus::Requested,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_live() && height > self.expires_at_height {
            self.status = DisclosureTicketStatus::Expired;
        }
    }

    pub fn authorize(&mut self, budget_bps: u64) -> PrivacyBudgetAccountingResult<()> {
        ensure_bps("authorized disclosure budget bps", budget_bps)?;
        if budget_bps > self.requested_budget_bps {
            return Err("authorized disclosure budget exceeds request".to_string());
        }
        self.authorized_budget_bps = budget_bps;
        self.status = DisclosureTicketStatus::Authorized;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "disclosure_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "account_budget_id": self.account_budget_id,
            "contract_budget_id": self.contract_budget_id,
            "budget_class": self.budget_class.as_str(),
            "requested_budget_bps": self.requested_budget_bps,
            "authorized_budget_bps": self.authorized_budget_bps,
            "purpose_root": self.purpose_root,
            "subject_root": self.subject_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier_hash": self.nullifier_hash,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        privacy_budget_payload_root("DISCLOSURE-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("ticket id", &self.ticket_id)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("account budget id", &self.account_budget_id)?;
        ensure_bps("requested budget bps", self.requested_budget_bps)?;
        ensure_bps("authorized budget bps", self.authorized_budget_bps)?;
        if self.authorized_budget_bps > self.requested_budget_bps {
            return Err("disclosure ticket authorized budget exceeds request".to_string());
        }
        if self.expires_at_height < self.requested_at_height {
            return Err("disclosure ticket expires before request".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeShieldGrant {
    pub grant_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_disclosure_bps: u64,
    pub rebate_bps: u64,
    pub eligibility_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: FeeShieldGrantStatus,
}

impl FeeShieldGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        lane_id: &str,
        fee_asset_id: &str,
        budget_units: u64,
        max_disclosure_bps: u64,
        rebate_bps: u64,
        eligibility_root: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("sponsor commitment", sponsor_commitment)?;
        ensure_nonempty("lane id", lane_id)?;
        ensure_nonempty("fee asset id", fee_asset_id)?;
        ensure_nonzero("fee shield budget units", budget_units)?;
        ensure_bps("fee shield max disclosure bps", max_disclosure_bps)?;
        ensure_bps("fee shield rebate bps", rebate_bps)?;
        ensure_nonempty("eligibility root", eligibility_root)?;
        ensure_nonzero("fee shield ttl blocks", ttl_blocks)?;
        Ok(Self {
            grant_id: fee_shield_grant_id(sponsor_commitment, lane_id, created_at_height),
            sponsor_commitment: sponsor_commitment.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_disclosure_bps,
            rebate_bps,
            eligibility_root: eligibility_root.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: FeeShieldGrantStatus::Open,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.spendable() && height > self.expires_at_height {
            self.status = FeeShieldGrantStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_shield_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_disclosure_bps": self.max_disclosure_bps,
            "rebate_bps": self.rebate_bps,
            "eligibility_root": self.eligibility_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn grant_root(&self) -> String {
        privacy_budget_payload_root("FEE-SHIELD-GRANT", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("fee shield grant id", &self.grant_id)?;
        ensure_nonempty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("fee asset id", &self.fee_asset_id)?;
        ensure_nonzero("fee shield budget units", self.budget_units)?;
        ensure_bps("fee shield max disclosure bps", self.max_disclosure_bps)?;
        ensure_bps("fee shield rebate bps", self.rebate_bps)?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("fee shield grant overspent".to_string());
        }
        Ok(self.grant_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDisclosure {
    pub audit_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub auditor_commitment: String,
    pub disclosure_root: String,
    pub finding_root: String,
    pub pq_signature_root: String,
    pub disclosure_budget_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: AuditDisclosureStatus,
}

impl AuditDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        subject_id: &str,
        subject_root: &str,
        auditor_commitment: &str,
        disclosure_root: &str,
        finding_root: &str,
        pq_signature_root: &str,
        disclosure_budget_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("lane id", lane_id)?;
        ensure_nonempty("subject id", subject_id)?;
        ensure_nonempty("subject root", subject_root)?;
        ensure_nonempty("auditor commitment", auditor_commitment)?;
        ensure_nonempty("disclosure root", disclosure_root)?;
        ensure_nonempty("finding root", finding_root)?;
        ensure_nonempty("pq signature root", pq_signature_root)?;
        ensure_bps("audit disclosure budget bps", disclosure_budget_bps)?;
        ensure_nonzero("audit ttl blocks", ttl_blocks)?;
        Ok(Self {
            audit_id: audit_disclosure_id(
                lane_id,
                subject_id,
                auditor_commitment,
                opened_at_height,
            ),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            auditor_commitment: auditor_commitment.to_string(),
            disclosure_root: disclosure_root.to_string(),
            finding_root: finding_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            disclosure_budget_bps,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: AuditDisclosureStatus::Pending,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            AuditDisclosureStatus::Pending | AuditDisclosureStatus::Published
        ) && height > self.expires_at_height
        {
            self.status = AuditDisclosureStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "auditor_commitment": self.auditor_commitment,
            "disclosure_root": self.disclosure_root,
            "finding_root": self.finding_root,
            "pq_signature_root": self.pq_signature_root,
            "disclosure_budget_bps": self.disclosure_budget_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn disclosure_state_root(&self) -> String {
        privacy_budget_payload_root("AUDIT-DISCLOSURE", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("audit disclosure id", &self.audit_id)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("subject id", &self.subject_id)?;
        ensure_nonempty("subject root", &self.subject_root)?;
        ensure_bps("audit disclosure budget bps", self.disclosure_budget_bps)?;
        if self.expires_at_height < self.opened_at_height {
            return Err("audit disclosure expires before opening".to_string());
        }
        Ok(self.disclosure_state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAction {
    pub action_id: String,
    pub action_kind: PrivacyBudgetActionKind,
    pub lane_id: String,
    pub subject_id: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivacyBudgetActionStatus,
}

impl PrivacyBudgetAction {
    pub fn new(
        action_kind: PrivacyBudgetActionKind,
        lane_id: &str,
        subject_id: &str,
        reason_root: &str,
        evidence_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivacyBudgetAccountingResult<Self> {
        ensure_nonempty("lane id", lane_id)?;
        ensure_nonempty("subject id", subject_id)?;
        ensure_nonempty("reason root", reason_root)?;
        ensure_nonempty("evidence root", evidence_root)?;
        ensure_nonzero("privacy action ttl blocks", ttl_blocks)?;
        Ok(Self {
            action_id: privacy_budget_action_id(
                &action_kind,
                lane_id,
                subject_id,
                opened_at_height,
            ),
            action_kind,
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            reason_root: reason_root.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: PrivacyBudgetActionStatus::Open,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == PrivacyBudgetActionStatus::Open && height > self.expires_at_height {
            self.status = PrivacyBudgetActionStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_action",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "action_id": self.action_id,
            "action_kind": self.action_kind.as_str(),
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn action_root(&self) -> String {
        privacy_budget_payload_root("PRIVACY-BUDGET-ACTION", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        ensure_nonempty("privacy budget action id", &self.action_id)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("subject id", &self.subject_id)?;
        ensure_nonempty("reason root", &self.reason_root)?;
        ensure_nonempty("evidence root", &self.evidence_root)?;
        if self.expires_at_height < self.opened_at_height {
            return Err("privacy budget action expires before opening".to_string());
        }
        Ok(self.action_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccountingRoots {
    pub config_root: String,
    pub lane_root: String,
    pub account_budget_root: String,
    pub contract_budget_root: String,
    pub disclosure_ticket_root: String,
    pub fee_shield_grant_root: String,
    pub audit_disclosure_root: String,
    pub action_root: String,
    pub nullifier_root: String,
}

impl PrivacyBudgetAccountingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "account_budget_root": self.account_budget_root,
            "contract_budget_root": self.contract_budget_root,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "fee_shield_grant_root": self.fee_shield_grant_root,
            "audit_disclosure_root": self.audit_disclosure_root,
            "action_root": self.action_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn roots_root(&self) -> String {
        privacy_budget_payload_root("PRIVACY-BUDGET-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccountingCounters {
    pub lane_count: u64,
    pub live_lane_count: u64,
    pub account_budget_count: u64,
    pub contract_budget_count: u64,
    pub disclosure_ticket_count: u64,
    pub live_disclosure_ticket_count: u64,
    pub fee_shield_grant_count: u64,
    pub spendable_fee_shield_grant_count: u64,
    pub audit_disclosure_count: u64,
    pub open_action_count: u64,
    pub total_lane_budget_bps: u64,
    pub total_spent_budget_bps: u64,
    pub total_reserved_budget_bps: u64,
    pub total_fee_shield_budget_units: u64,
    pub available_fee_shield_units: u64,
}

impl PrivacyBudgetAccountingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "live_lane_count": self.live_lane_count,
            "account_budget_count": self.account_budget_count,
            "contract_budget_count": self.contract_budget_count,
            "disclosure_ticket_count": self.disclosure_ticket_count,
            "live_disclosure_ticket_count": self.live_disclosure_ticket_count,
            "fee_shield_grant_count": self.fee_shield_grant_count,
            "spendable_fee_shield_grant_count": self.spendable_fee_shield_grant_count,
            "audit_disclosure_count": self.audit_disclosure_count,
            "open_action_count": self.open_action_count,
            "total_lane_budget_bps": self.total_lane_budget_bps,
            "total_spent_budget_bps": self.total_spent_budget_bps,
            "total_reserved_budget_bps": self.total_reserved_budget_bps,
            "total_fee_shield_budget_units": self.total_fee_shield_budget_units,
            "available_fee_shield_units": self.available_fee_shield_units,
        })
    }

    pub fn counters_root(&self) -> String {
        privacy_budget_payload_root("PRIVACY-BUDGET-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccountingState {
    pub height: u64,
    pub config: PrivacyBudgetAccountingConfig,
    pub lanes: BTreeMap<String, PrivacyBudgetLane>,
    pub account_budgets: BTreeMap<String, AccountPrivacyBudget>,
    pub contract_budgets: BTreeMap<String, ContractPrivacyBudget>,
    pub disclosure_tickets: BTreeMap<String, DisclosureTicket>,
    pub fee_shield_grants: BTreeMap<String, FeeShieldGrant>,
    pub audit_disclosures: BTreeMap<String, AuditDisclosure>,
    pub actions: BTreeMap<String, PrivacyBudgetAction>,
    pub nullifier_index: BTreeMap<String, String>,
}

impl Default for PrivacyBudgetAccountingState {
    fn default() -> Self {
        Self::new(PrivacyBudgetAccountingConfig::default())
    }
}

impl PrivacyBudgetAccountingState {
    pub fn new(config: PrivacyBudgetAccountingConfig) -> Self {
        Self {
            height: 0,
            config,
            lanes: BTreeMap::new(),
            account_budgets: BTreeMap::new(),
            contract_budgets: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            fee_shield_grants: BTreeMap::new(),
            audit_disclosures: BTreeMap::new(),
            actions: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivacyBudgetAccountingResult<Self> {
        let config = PrivacyBudgetAccountingConfig::devnet();
        config.validate()?;
        let mut state = Self::new(config);
        state.set_height(192)?;

        let swap_lane = PrivacyBudgetLane::new(
            PrivacyBudgetDomain::PrivateSwap,
            PrivacyBudgetDomain::PrivateSwap.default_lane_key(),
            0,
            0,
            state.config.epoch_blocks,
            state.config.max_lane_budget_bps,
            1_000_000,
        )?;
        let bridge_lane = PrivacyBudgetLane::new(
            PrivacyBudgetDomain::MoneroBridge,
            PrivacyBudgetDomain::MoneroBridge.default_lane_key(),
            0,
            0,
            state.config.epoch_blocks,
            state.config.max_lane_budget_bps,
            1_500_000,
        )?;
        let swap_lane_id = swap_lane.lane_id.clone();
        let bridge_lane_id = bridge_lane.lane_id.clone();
        state.insert_lane(swap_lane)?;
        state.insert_lane(bridge_lane)?;

        let account_budget = AccountPrivacyBudget::new(
            "devnet-account-privacy-commitment-a",
            &swap_lane_id,
            0,
            state.config.max_account_budget_bps,
            &privacy_budget_string_root("DEVNET-NULLIFIER-ROOT", "account-a"),
            &privacy_budget_string_root("DEVNET-PQ-OWNER", "account-a"),
            &privacy_budget_string_root("DEVNET-VIEW-KEY-ROTATION", "account-a"),
        )?;
        let account_budget_id = account_budget.account_budget_id.clone();
        state.insert_account_budget(account_budget)?;

        let contract_budget = ContractPrivacyBudget::new(
            "devnet-contract-commitment-private-swap",
            &swap_lane_id,
            &privacy_budget_string_root("DEVNET-NAMESPACE", "private-swap"),
            &privacy_budget_string_root("DEVNET-SELECTORS", "swap_exact_private"),
            0,
            state.config.max_contract_budget_bps,
            true,
        )?;
        let contract_budget_id = contract_budget.contract_budget_id.clone();
        state.insert_contract_budget(contract_budget)?;

        let mut ticket = DisclosureTicket::new(
            &swap_lane_id,
            &account_budget_id,
            Some(contract_budget_id.clone()),
            PrivacyBudgetClass::RouteHint,
            PrivacyBudgetClass::RouteHint.default_weight_bps(),
            &privacy_budget_string_root("DEVNET-PURPOSE", "solver-routing"),
            &privacy_budget_string_root("DEVNET-SUBJECT", "swap-intent-a"),
            &privacy_budget_string_root("DEVNET-ENCRYPTED-PAYLOAD", "route-hint"),
            &privacy_budget_string_root("DEVNET-PQ-AUTH", "solver-a"),
            "devnet-disclosure-nullifier-a",
            state.height,
            state.config.disclosure_ttl_blocks,
        )?;
        ticket.authorize(PrivacyBudgetClass::RouteHint.default_weight_bps())?;
        state.insert_disclosure_ticket(ticket)?;

        let grant = FeeShieldGrant::new(
            "devnet-fee-shield-sponsor",
            &bridge_lane_id,
            &state.config.fee_asset_id,
            500_000,
            state.config.max_lane_budget_bps,
            state.config.default_rebate_bps,
            &privacy_budget_string_root("DEVNET-ELIGIBILITY", "bridge-withdrawals"),
            state.height,
            state.config.sponsor_ttl_blocks,
        )?;
        state.insert_fee_shield_grant(grant)?;

        let audit = AuditDisclosure::new(
            &swap_lane_id,
            &contract_budget_id,
            &privacy_budget_string_root("DEVNET-AUDIT-SUBJECT", "private-swap"),
            "devnet-auditor-commitment",
            &privacy_budget_string_root("DEVNET-AUDIT-DISCLOSURE", "bounded"),
            &privacy_budget_string_root("DEVNET-AUDIT-FINDING", "clean"),
            &privacy_budget_string_root("DEVNET-AUDIT-PQ-SIG", "auditor"),
            PrivacyBudgetClass::AuditFinding.default_weight_bps(),
            state.height,
            state.config.audit_ttl_blocks,
        )?;
        state.insert_audit_disclosure(audit)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivacyBudgetAccountingResult<String> {
        self.height = height;
        for lane in self.lanes.values_mut() {
            if lane.status == BudgetStatus::Active && height > lane.epoch_end_height {
                lane.status = BudgetStatus::Expired;
            }
        }
        for ticket in self.disclosure_tickets.values_mut() {
            ticket.set_height(height);
        }
        for grant in self.fee_shield_grants.values_mut() {
            grant.set_height(height);
        }
        for disclosure in self.audit_disclosures.values_mut() {
            disclosure.set_height(height);
        }
        for action in self.actions.values_mut() {
            action.set_height(height);
        }
        Ok(self.state_root())
    }

    pub fn insert_lane(
        &mut self,
        lane: PrivacyBudgetLane,
    ) -> PrivacyBudgetAccountingResult<String> {
        lane.validate()?;
        let lane_id = lane.lane_id.clone();
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_account_budget(
        &mut self,
        budget: AccountPrivacyBudget,
    ) -> PrivacyBudgetAccountingResult<String> {
        budget.validate()?;
        if !self.lanes.contains_key(&budget.lane_id) {
            return Err("account privacy budget references unknown lane".to_string());
        }
        let budget_id = budget.account_budget_id.clone();
        if let Some(lane) = self.lanes.get_mut(&budget.lane_id) {
            lane.account_ids.insert(budget_id.clone());
        }
        self.account_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_contract_budget(
        &mut self,
        budget: ContractPrivacyBudget,
    ) -> PrivacyBudgetAccountingResult<String> {
        budget.validate()?;
        if !self.lanes.contains_key(&budget.lane_id) {
            return Err("contract privacy budget references unknown lane".to_string());
        }
        let budget_id = budget.contract_budget_id.clone();
        if let Some(lane) = self.lanes.get_mut(&budget.lane_id) {
            lane.contract_ids.insert(budget_id.clone());
        }
        self.contract_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_disclosure_ticket(
        &mut self,
        ticket: DisclosureTicket,
    ) -> PrivacyBudgetAccountingResult<String> {
        ticket.validate()?;
        if self.nullifier_index.contains_key(&ticket.nullifier_hash) {
            return Err("privacy budget disclosure nullifier replay".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&ticket.lane_id)
            .ok_or_else(|| "disclosure ticket references unknown lane".to_string())?;
        if !self.account_budgets.contains_key(&ticket.account_budget_id) {
            return Err("disclosure ticket references unknown account budget".to_string());
        }
        if let Some(contract_budget_id) = &ticket.contract_budget_id {
            if !self.contract_budgets.contains_key(contract_budget_id) {
                return Err("disclosure ticket references unknown contract budget".to_string());
            }
        }
        let reserved = ticket
            .authorized_budget_bps
            .max(ticket.requested_budget_bps);
        lane.reserve_budget(reserved)?;
        if let Some(account) = self.account_budgets.get_mut(&ticket.account_budget_id) {
            if reserved > account.available_budget_bps() {
                return Err("account privacy budget exhausted".to_string());
            }
            account.reserved_budget_bps = account.reserved_budget_bps.saturating_add(reserved);
        }
        if let Some(contract_budget_id) = &ticket.contract_budget_id {
            if let Some(contract) = self.contract_budgets.get_mut(contract_budget_id) {
                if reserved > contract.available_budget_bps() {
                    return Err("contract privacy budget exhausted".to_string());
                }
                contract.reserved_budget_bps =
                    contract.reserved_budget_bps.saturating_add(reserved);
            }
        }
        let ticket_id = ticket.ticket_id.clone();
        self.nullifier_index
            .insert(ticket.nullifier_hash.clone(), ticket_id.clone());
        self.disclosure_tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn insert_fee_shield_grant(
        &mut self,
        grant: FeeShieldGrant,
    ) -> PrivacyBudgetAccountingResult<String> {
        grant.validate()?;
        if !self.lanes.contains_key(&grant.lane_id) {
            return Err("fee shield grant references unknown lane".to_string());
        }
        if grant.fee_asset_id != self.config.fee_asset_id {
            return Err("fee shield grant asset mismatch".to_string());
        }
        let grant_id = grant.grant_id.clone();
        self.fee_shield_grants.insert(grant_id.clone(), grant);
        Ok(grant_id)
    }

    pub fn insert_audit_disclosure(
        &mut self,
        disclosure: AuditDisclosure,
    ) -> PrivacyBudgetAccountingResult<String> {
        disclosure.validate()?;
        if !self.lanes.contains_key(&disclosure.lane_id) {
            return Err("audit disclosure references unknown lane".to_string());
        }
        let audit_id = disclosure.audit_id.clone();
        self.audit_disclosures.insert(audit_id.clone(), disclosure);
        Ok(audit_id)
    }

    pub fn insert_action(
        &mut self,
        action: PrivacyBudgetAction,
    ) -> PrivacyBudgetAccountingResult<String> {
        action.validate()?;
        if !self.lanes.contains_key(&action.lane_id) {
            return Err("privacy budget action references unknown lane".to_string());
        }
        let action_id = action.action_id.clone();
        self.actions.insert(action_id.clone(), action);
        Ok(action_id)
    }

    pub fn live_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.is_live_at(self.height))
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn live_ticket_ids(&self) -> Vec<String> {
        self.disclosure_tickets
            .values()
            .filter(|ticket| ticket.status.is_live())
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn available_fee_shield_units(&self) -> u64 {
        self.fee_shield_grants
            .values()
            .map(FeeShieldGrant::available_units)
            .sum()
    }

    pub fn roots(&self) -> PrivacyBudgetAccountingRoots {
        PrivacyBudgetAccountingRoots {
            config_root: self.config.config_root(),
            lane_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-LANE-SET",
                self.lanes
                    .values()
                    .map(PrivacyBudgetLane::public_record)
                    .collect(),
            ),
            account_budget_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-ACCOUNT-SET",
                self.account_budgets
                    .values()
                    .map(AccountPrivacyBudget::public_record)
                    .collect(),
            ),
            contract_budget_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-CONTRACT-SET",
                self.contract_budgets
                    .values()
                    .map(ContractPrivacyBudget::public_record)
                    .collect(),
            ),
            disclosure_ticket_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-DISCLOSURE-TICKET-SET",
                self.disclosure_tickets
                    .values()
                    .map(DisclosureTicket::public_record)
                    .collect(),
            ),
            fee_shield_grant_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-FEE-SHIELD-GRANT-SET",
                self.fee_shield_grants
                    .values()
                    .map(FeeShieldGrant::public_record)
                    .collect(),
            ),
            audit_disclosure_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-AUDIT-DISCLOSURE-SET",
                self.audit_disclosures
                    .values()
                    .map(AuditDisclosure::public_record)
                    .collect(),
            ),
            action_root: privacy_budget_record_root(
                "PRIVACY-BUDGET-ACTION-SET",
                self.actions
                    .values()
                    .map(PrivacyBudgetAction::public_record)
                    .collect(),
            ),
            nullifier_root: privacy_budget_string_map_root(
                "PRIVACY-BUDGET-NULLIFIER-INDEX",
                &self.nullifier_index,
            ),
        }
    }

    pub fn counters(&self) -> PrivacyBudgetAccountingCounters {
        PrivacyBudgetAccountingCounters {
            lane_count: self.lanes.len() as u64,
            live_lane_count: self.live_lane_ids().len() as u64,
            account_budget_count: self.account_budgets.len() as u64,
            contract_budget_count: self.contract_budgets.len() as u64,
            disclosure_ticket_count: self.disclosure_tickets.len() as u64,
            live_disclosure_ticket_count: self.live_ticket_ids().len() as u64,
            fee_shield_grant_count: self.fee_shield_grants.len() as u64,
            spendable_fee_shield_grant_count: self
                .fee_shield_grants
                .values()
                .filter(|grant| grant.status.spendable())
                .count() as u64,
            audit_disclosure_count: self.audit_disclosures.len() as u64,
            open_action_count: self
                .actions
                .values()
                .filter(|action| action.status == PrivacyBudgetActionStatus::Open)
                .count() as u64,
            total_lane_budget_bps: self.lanes.values().map(|lane| lane.max_budget_bps).sum(),
            total_spent_budget_bps: self.lanes.values().map(|lane| lane.spent_budget_bps).sum(),
            total_reserved_budget_bps: self
                .lanes
                .values()
                .map(|lane| lane.reserved_budget_bps)
                .sum(),
            total_fee_shield_budget_units: self
                .fee_shield_grants
                .values()
                .map(|grant| grant.budget_units)
                .sum(),
            available_fee_shield_units: self.available_fee_shield_units(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "privacy_budget_accounting_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_BUDGET_ACCOUNTING_PROTOCOL_VERSION,
            "schema_version": PRIVACY_BUDGET_ACCOUNTING_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        privacy_budget_accounting_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "privacy_budget_accounting_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn validate(&self) -> PrivacyBudgetAccountingResult<String> {
        self.config.validate()?;
        for (lane_id, lane) in &self.lanes {
            if lane_id != &lane.lane_id {
                return Err("privacy budget lane map key mismatch".to_string());
            }
            lane.validate()?;
        }
        for (budget_id, budget) in &self.account_budgets {
            if budget_id != &budget.account_budget_id {
                return Err("account privacy budget map key mismatch".to_string());
            }
            budget.validate()?;
            if !self.lanes.contains_key(&budget.lane_id) {
                return Err("account privacy budget lane missing".to_string());
            }
        }
        for (budget_id, budget) in &self.contract_budgets {
            if budget_id != &budget.contract_budget_id {
                return Err("contract privacy budget map key mismatch".to_string());
            }
            budget.validate()?;
            if !self.lanes.contains_key(&budget.lane_id) {
                return Err("contract privacy budget lane missing".to_string());
            }
        }
        for (ticket_id, ticket) in &self.disclosure_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("disclosure ticket map key mismatch".to_string());
            }
            ticket.validate()?;
            if !self.lanes.contains_key(&ticket.lane_id) {
                return Err("disclosure ticket lane missing".to_string());
            }
            if !self.account_budgets.contains_key(&ticket.account_budget_id) {
                return Err("disclosure ticket account budget missing".to_string());
            }
        }
        for (grant_id, grant) in &self.fee_shield_grants {
            if grant_id != &grant.grant_id {
                return Err("fee shield grant map key mismatch".to_string());
            }
            grant.validate()?;
            if !self.lanes.contains_key(&grant.lane_id) {
                return Err("fee shield grant lane missing".to_string());
            }
        }
        for (audit_id, audit) in &self.audit_disclosures {
            if audit_id != &audit.audit_id {
                return Err("audit disclosure map key mismatch".to_string());
            }
            audit.validate()?;
            if !self.lanes.contains_key(&audit.lane_id) {
                return Err("audit disclosure lane missing".to_string());
            }
        }
        for (action_id, action) in &self.actions {
            if action_id != &action.action_id {
                return Err("privacy budget action map key mismatch".to_string());
            }
            action.validate()?;
            if !self.lanes.contains_key(&action.lane_id) {
                return Err("privacy budget action lane missing".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn privacy_budget_accounting_state_root_from_record(record: &Value) -> String {
    privacy_budget_payload_root("PRIVACY-BUDGET-ACCOUNTING-STATE", record)
}

pub fn privacy_budget_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(domain, &[HashPart::Json(payload)], 32)
}

pub fn privacy_budget_string_root(domain: &str, value: &str) -> String {
    stable_hash_hex(domain, &[HashPart::Str(value)], 32)
}

pub fn privacy_budget_lane_id(
    domain: &PrivacyBudgetDomain,
    lane_key: &str,
    epoch_index: u64,
) -> String {
    stable_hash_hex(
        "PRIVACY-BUDGET-LANE-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(lane_key),
            HashPart::Int(epoch_index as i128),
        ],
        16,
    )
}

pub fn account_privacy_budget_id(
    account_commitment: &str,
    lane_id: &str,
    epoch_index: u64,
) -> String {
    stable_hash_hex(
        "ACCOUNT-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(epoch_index as i128),
        ],
        16,
    )
}

pub fn contract_privacy_budget_id(
    contract_commitment: &str,
    lane_id: &str,
    epoch_index: u64,
) -> String {
    stable_hash_hex(
        "CONTRACT-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(contract_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(epoch_index as i128),
        ],
        16,
    )
}

pub fn disclosure_ticket_id(
    lane_id: &str,
    account_budget_id: &str,
    contract_budget_id: &str,
    nullifier_hash: &str,
) -> String {
    stable_hash_hex(
        "DISCLOSURE-TICKET-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(account_budget_id),
            HashPart::Str(contract_budget_id),
            HashPart::Str(nullifier_hash),
        ],
        16,
    )
}

pub fn fee_shield_grant_id(
    sponsor_commitment: &str,
    lane_id: &str,
    created_at_height: u64,
) -> String {
    stable_hash_hex(
        "FEE-SHIELD-GRANT-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(created_at_height as i128),
        ],
        16,
    )
}

pub fn audit_disclosure_id(
    lane_id: &str,
    subject_id: &str,
    auditor_commitment: &str,
    opened_at_height: u64,
) -> String {
    stable_hash_hex(
        "AUDIT-DISCLOSURE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(auditor_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn privacy_budget_action_id(
    action_kind: &PrivacyBudgetActionKind,
    lane_id: &str,
    subject_id: &str,
    opened_at_height: u64,
) -> String {
    stable_hash_hex(
        "PRIVACY-BUDGET-ACTION-ID",
        &[
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn privacy_budget_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn privacy_budget_string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn privacy_budget_string_map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(label: &str, value: &str) -> PrivacyBudgetAccountingResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_nonzero(label: &str, value: u64) -> PrivacyBudgetAccountingResult<()> {
    if value == 0 {
        Err(format!("{label} must be nonzero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> PrivacyBudgetAccountingResult<()> {
    if value > PRIVACY_BUDGET_ACCOUNTING_MAX_BPS {
        Err(format!("{label} exceeds max bps"))
    } else {
        Ok(())
    }
}
