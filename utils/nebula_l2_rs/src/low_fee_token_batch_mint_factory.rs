use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeTokenBatchMintFactoryResult<T> = Result<T, String>;

pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION: &str =
    "nebula-low-fee-token-batch-mint-factory-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_SCHEMA_VERSION: &str =
    "nebula-low-fee-token-batch-mint-factory-state-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEVNET_HEIGHT: u64 = 6_144;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_LOW_FEE_LANE: &str = "private-token-batch-mint";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SPONSOR_ASSET_ID: &str = "wxmr-devnet";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_TEMPLATE_SCHEME: &str =
    "confidential-token-template-commitment-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SUPPLY_COMMITMENT_SCHEME: &str =
    "pedersen-supply-commitment-shake256-domain-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECIPIENT_COMMITMENT_SCHEME: &str =
    "stealth-recipient-batch-mint-commitment-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-batch-mint-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PQ_KEM_SUITE: &str = "ML-KEM-1024";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PROOF_SYSTEM: &str =
    "devnet-confidential-batch-mint-validity-proof-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECEIPT_SCHEME: &str =
    "private-token-batch-mint-receipt-v1";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_REGISTRY_ID: &str =
    "nebula-devnet-private-token-registry";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_AUDITOR_SET_ID: &str =
    "nebula-devnet-mint-factory-auditors";
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PRIVACY_SET_SIZE: u64 = 2_048;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MIN_ANONYMITY_SET: u64 = 512;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_ORDER_TTL_BLOCKS: u64 = 240;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 1_440;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_QUOTA_WINDOW_BLOCKS: u64 = 720;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_REGISTRY_TTL_BLOCKS: u64 = 7_200;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_MINTS_PER_ORDER: u64 = 4_096;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SUPPLY_BUCKET_UNITS: u64 =
    1_000_000_000_000_000;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_FEE_UNITS: u64 = 24;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 500_000;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SPONSOR_DISCOUNT_BPS: u64 = 9_200;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SYBIL_SCORE_BPS: u64 = 2_000;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_TEMPLATES: usize = 65_536;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_ORDERS: usize = 262_144;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_SPONSOR_BUCKETS: usize = 65_536;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_QUOTAS: usize = 262_144;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_AUTHORIZATIONS: usize = 524_288;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_RECEIPTS: usize = 524_288;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_PUBLICATIONS: usize = 262_144;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_NULLIFIERS: usize = 1_048_576;
pub const LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateStatus {
    Draft,
    Active,
    QuotaLimited,
    Paused,
    Frozen,
    Retired,
}

impl TemplateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::QuotaLimited => "quota_limited",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Active | Self::QuotaLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenPrivacyClass {
    ShieldedFungible,
    ConfidentialFungible,
    PrivateTransferableReceipt,
    SoulboundCredential,
    ContractBoundMint,
    GovernanceWeight,
}

impl TokenPrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedFungible => "shielded_fungible",
            Self::ConfidentialFungible => "confidential_fungible",
            Self::PrivateTransferableReceipt => "private_transferable_receipt",
            Self::SoulboundCredential => "soulbound_credential",
            Self::ContractBoundMint => "contract_bound_mint",
            Self::GovernanceWeight => "governance_weight",
        }
    }

    pub fn requires_transfer_hook(self) -> bool {
        matches!(self, Self::SoulboundCredential | Self::ContractBoundMint)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintOrderStatus {
    Queued,
    SponsorReserved,
    Packed,
    Proving,
    Published,
    Finalized,
    Expired,
    Cancelled,
    Rejected,
}

impl MintOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Packed => "packed",
            Self::Proving => "proving",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::SponsorReserved | Self::Packed | Self::Proving | Self::Published
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Expired | Self::Cancelled | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBucketStatus {
    Open,
    Reserved,
    Exhausted,
    Paused,
    Slashed,
    Expired,
}

impl SponsorBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaStatus {
    Available,
    Throttled,
    CoolingDown,
    Exhausted,
    Suspended,
}

impl QuotaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Throttled => "throttled",
            Self::CoolingDown => "cooling_down",
            Self::Exhausted => "exhausted",
            Self::Suspended => "suspended",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Available | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationSubject {
    Template,
    BatchMintOrder,
    SponsorBucket,
    RegistryPublication,
    Receipt,
    QuotaReset,
}

impl AuthorizationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::BatchMintOrder => "batch_mint_order",
            Self::SponsorBucket => "sponsor_bucket",
            Self::RegistryPublication => "registry_publication",
            Self::Receipt => "receipt",
            Self::QuotaReset => "quota_reset",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    RegistryPosted,
    Finalized,
    Disputed,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::RegistryPosted => "registry_posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }

    pub fn counts_as_minted(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::RegistryPosted | Self::Finalized
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    Staged,
    Published,
    Anchored,
    Finalized,
    Superseded,
    Rejected,
}

impl PublicationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Published => "published",
            Self::Anchored => "anchored",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub sponsor_asset_id: String,
    pub registry_id: String,
    pub auditor_set_id: String,
    pub template_commitment_scheme: String,
    pub supply_commitment_scheme: String,
    pub recipient_commitment_scheme: String,
    pub pq_authorization_suite: String,
    pub pq_kem_suite: String,
    pub proof_system: String,
    pub receipt_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set: u64,
    pub target_privacy_set_size: u64,
    pub order_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub quota_window_blocks: u64,
    pub registry_ttl_blocks: u64,
    pub max_mints_per_order: u64,
    pub max_supply_bucket_units: u64,
    pub max_fee_units: u64,
    pub sponsor_budget_units: u64,
    pub max_sponsor_discount_bps: u64,
    pub max_sybil_score_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_SCHEMA_VERSION.to_string(),
            low_fee_lane: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_asset_id: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SPONSOR_ASSET_ID.to_string(),
            registry_id: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_REGISTRY_ID.to_string(),
            auditor_set_id: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_AUDITOR_SET_ID.to_string(),
            template_commitment_scheme: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_TEMPLATE_SCHEME
                .to_string(),
            supply_commitment_scheme:
                LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SUPPLY_COMMITMENT_SCHEME.to_string(),
            recipient_commitment_scheme:
                LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECIPIENT_COMMITMENT_SCHEME.to_string(),
            pq_authorization_suite: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PQ_AUTH_SUITE
                .to_string(),
            pq_kem_suite: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PQ_KEM_SUITE.to_string(),
            proof_system: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PROOF_SYSTEM.to_string(),
            receipt_scheme: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECEIPT_SCHEME.to_string(),
            min_pq_security_bits: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MIN_ANONYMITY_SET,
            target_privacy_set_size: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_PRIVACY_SET_SIZE,
            order_ttl_blocks: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_ORDER_TTL_BLOCKS,
            receipt_ttl_blocks: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_RECEIPT_TTL_BLOCKS,
            quota_window_blocks: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_QUOTA_WINDOW_BLOCKS,
            registry_ttl_blocks: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_REGISTRY_TTL_BLOCKS,
            max_mints_per_order: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_MINTS_PER_ORDER,
            max_supply_bucket_units:
                LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SUPPLY_BUCKET_UNITS,
            max_fee_units: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_FEE_UNITS,
            sponsor_budget_units: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sponsor_discount_bps:
                LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SPONSOR_DISCOUNT_BPS,
            max_sybil_score_bps: LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEFAULT_MAX_SYBIL_SCORE_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_asset_id": self.sponsor_asset_id,
            "registry_id": self.registry_id,
            "auditor_set_id": self.auditor_set_id,
            "template_commitment_scheme": self.template_commitment_scheme,
            "supply_commitment_scheme": self.supply_commitment_scheme,
            "recipient_commitment_scheme": self.recipient_commitment_scheme,
            "pq_authorization_suite": self.pq_authorization_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "proof_system": self.proof_system,
            "receipt_scheme": self.receipt_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set": self.min_anonymity_set,
            "target_privacy_set_size": self.target_privacy_set_size,
            "order_ttl_blocks": self.order_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "quota_window_blocks": self.quota_window_blocks,
            "registry_ttl_blocks": self.registry_ttl_blocks,
            "max_mints_per_order": self.max_mints_per_order,
            "max_supply_bucket_units": self.max_supply_bucket_units,
            "max_fee_units": self.max_fee_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_sponsor_discount_bps": self.max_sponsor_discount_bps,
            "max_sybil_score_bps": self.max_sybil_score_bps
        })
    }

    pub fn validate(&self) -> LowFeeTokenBatchMintFactoryResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("low fee token batch mint factory config chain_id mismatch".to_string());
        }
        if self.protocol_version != LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION {
            return Err("low fee token batch mint factory protocol version mismatch".to_string());
        }
        if self.min_anonymity_set == 0 || self.target_privacy_set_size < self.min_anonymity_set {
            return Err("privacy set must cover the minimum anonymity set".to_string());
        }
        if self.order_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
            || self.quota_window_blocks == 0
            || self.registry_ttl_blocks == 0
        {
            return Err("factory ttl and quota windows must be non-zero".to_string());
        }
        if self.max_mints_per_order == 0
            || self.max_fee_units == 0
            || self.sponsor_budget_units == 0
        {
            return Err("factory limits and fee budgets must be non-zero".to_string());
        }
        if self.max_sponsor_discount_bps > LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_BPS
            || self.max_sybil_score_bps > LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_BPS
        {
            return Err("factory bps values exceed maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialTokenTemplate {
    pub template_id: String,
    pub issuer_commitment: String,
    pub token_symbol_hash: String,
    pub token_metadata_root: String,
    pub privacy_class: TokenPrivacyClass,
    pub status: TemplateStatus,
    pub supply_cap_commitment: String,
    pub mint_policy_root: String,
    pub transfer_hook_root: String,
    pub compliance_hook_root: String,
    pub royalty_policy_root: String,
    pub default_fee_bucket_id: String,
    pub quota_group_id: String,
    pub pq_admin_commitment: String,
    pub created_at_height: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialTokenTemplate {
    pub fn public_record(&self) -> Value {
        json!({
            "template_id": self.template_id,
            "issuer_commitment": self.issuer_commitment,
            "token_symbol_hash": self.token_symbol_hash,
            "token_metadata_root": self.token_metadata_root,
            "privacy_class": self.privacy_class.as_str(),
            "status": self.status.as_str(),
            "supply_cap_commitment": self.supply_cap_commitment,
            "mint_policy_root": self.mint_policy_root,
            "transfer_hook_root": self.transfer_hook_root,
            "compliance_hook_root": self.compliance_hook_root,
            "royalty_policy_root": self.royalty_policy_root,
            "default_fee_bucket_id": self.default_fee_bucket_id,
            "quota_group_id": self.quota_group_id,
            "pq_admin_commitment": self.pq_admin_commitment,
            "created_at_height": self.created_at_height,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self, config: &Config) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("template_id", &self.template_id)?;
        require_hash("issuer_commitment", &self.issuer_commitment)?;
        require_hash("token_symbol_hash", &self.token_symbol_hash)?;
        require_hash("token_metadata_root", &self.token_metadata_root)?;
        require_hash("supply_cap_commitment", &self.supply_cap_commitment)?;
        require_hash("mint_policy_root", &self.mint_policy_root)?;
        require_hash("transfer_hook_root", &self.transfer_hook_root)?;
        require_hash("compliance_hook_root", &self.compliance_hook_root)?;
        require_hash("royalty_policy_root", &self.royalty_policy_root)?;
        require_id("default_fee_bucket_id", &self.default_fee_bucket_id)?;
        require_id("quota_group_id", &self.quota_group_id)?;
        require_hash("pq_admin_commitment", &self.pq_admin_commitment)?;
        if self.activated_at_height < self.created_at_height {
            return Err(format!(
                "template {} activates before creation",
                self.template_id
            ));
        }
        if self.expires_at_height <= self.activated_at_height + config.order_ttl_blocks {
            return Err(format!(
                "template {} expires before a full order ttl can settle",
                self.template_id
            ));
        }
        if self.privacy_class.requires_transfer_hook()
            && self.transfer_hook_root == empty_root("LOW-FEE-TOKEN-BATCH-MINT-EMPTY-HOOK")
        {
            return Err(format!(
                "template {} requires a transfer hook",
                self.template_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchMintOrder {
    pub order_id: String,
    pub template_id: String,
    pub sponsor_bucket_id: String,
    pub quota_id: String,
    pub creator_commitment: String,
    pub recipient_set_root: String,
    pub confidential_amount_root: String,
    pub memo_ciphertext_root: String,
    pub authorization_root: String,
    pub proof_request_root: String,
    pub status: MintOrderStatus,
    pub mint_count: u64,
    pub supply_bucket_units: u64,
    pub max_fee_units: u64,
    pub fee_discount_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub packed_batch_id: String,
}

impl BatchMintOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "template_id": self.template_id,
            "sponsor_bucket_id": self.sponsor_bucket_id,
            "quota_id": self.quota_id,
            "creator_commitment": self.creator_commitment,
            "recipient_set_root": self.recipient_set_root,
            "confidential_amount_root": self.confidential_amount_root,
            "memo_ciphertext_root": self.memo_ciphertext_root,
            "authorization_root": self.authorization_root,
            "proof_request_root": self.proof_request_root,
            "status": self.status.as_str(),
            "mint_count": self.mint_count,
            "supply_bucket_units": self.supply_bucket_units,
            "max_fee_units": self.max_fee_units,
            "fee_discount_bps": self.fee_discount_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "packed_batch_id": self.packed_batch_id
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(
        &self,
        config: &Config,
        templates: &BTreeMap<String, ConfidentialTokenTemplate>,
    ) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("order_id", &self.order_id)?;
        require_known("template", &self.template_id, templates)?;
        require_id("sponsor_bucket_id", &self.sponsor_bucket_id)?;
        require_id("quota_id", &self.quota_id)?;
        require_hash("creator_commitment", &self.creator_commitment)?;
        require_hash("recipient_set_root", &self.recipient_set_root)?;
        require_hash("confidential_amount_root", &self.confidential_amount_root)?;
        require_hash("memo_ciphertext_root", &self.memo_ciphertext_root)?;
        require_hash("authorization_root", &self.authorization_root)?;
        require_hash("proof_request_root", &self.proof_request_root)?;
        if self.mint_count == 0 || self.mint_count > config.max_mints_per_order {
            return Err(format!("order {} mint count outside limits", self.order_id));
        }
        if self.supply_bucket_units == 0
            || self.supply_bucket_units > config.max_supply_bucket_units
        {
            return Err(format!(
                "order {} supply bucket outside limits",
                self.order_id
            ));
        }
        if self.max_fee_units == 0 || self.max_fee_units > config.max_fee_units {
            return Err(format!("order {} fee outside limits", self.order_id));
        }
        if self.fee_discount_bps > config.max_sponsor_discount_bps {
            return Err(format!(
                "order {} sponsor discount outside limits",
                self.order_id
            ));
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!("order {} expires before submission", self.order_id));
        }
        if self.expires_at_height - self.submitted_at_height > config.order_ttl_blocks {
            return Err(format!("order {} ttl exceeds config", self.order_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorFeeBucket {
    pub bucket_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_group_root: String,
    pub allowed_template_root: String,
    pub status: SponsorBucketStatus,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub discount_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorFeeBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_group_root": self.beneficiary_group_root,
            "allowed_template_root": self.allowed_template_root,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "discount_bps": self.discount_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self, config: &Config) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("bucket_id", &self.bucket_id)?;
        require_hash("sponsor_commitment", &self.sponsor_commitment)?;
        require_hash("beneficiary_group_root", &self.beneficiary_group_root)?;
        require_hash("allowed_template_root", &self.allowed_template_root)?;
        require_id("asset_id", &self.asset_id)?;
        if self.asset_id != config.sponsor_asset_id && self.asset_id != config.fee_asset_id {
            return Err(format!(
                "sponsor bucket {} uses unknown asset",
                self.bucket_id
            ));
        }
        if self.budget_units == 0 || self.budget_units > config.sponsor_budget_units {
            return Err(format!(
                "sponsor bucket {} budget outside limits",
                self.bucket_id
            ));
        }
        if self.consumed_units + self.reserved_units > self.budget_units {
            return Err(format!("sponsor bucket {} over reserved", self.bucket_id));
        }
        if self.discount_bps > config.max_sponsor_discount_bps {
            return Err(format!(
                "sponsor bucket {} discount outside limits",
                self.bucket_id
            ));
        }
        if self.min_privacy_set_size < config.min_anonymity_set {
            return Err(format!(
                "sponsor bucket {} privacy set below minimum",
                self.bucket_id
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("sponsor bucket {} has invalid ttl", self.bucket_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiSpamQuota {
    pub quota_id: String,
    pub quota_group_id: String,
    pub subject_commitment: String,
    pub credential_root: String,
    pub status: QuotaStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_orders: u64,
    pub used_orders: u64,
    pub max_mints: u64,
    pub used_mints: u64,
    pub sybil_score_bps: u64,
    pub nullifier_root: String,
}

impl AntiSpamQuota {
    pub fn public_record(&self) -> Value {
        json!({
            "quota_id": self.quota_id,
            "quota_group_id": self.quota_group_id,
            "subject_commitment": self.subject_commitment,
            "credential_root": self.credential_root,
            "status": self.status.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_orders": self.max_orders,
            "used_orders": self.used_orders,
            "max_mints": self.max_mints,
            "used_mints": self.used_mints,
            "sybil_score_bps": self.sybil_score_bps,
            "nullifier_root": self.nullifier_root
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self, config: &Config) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("quota_id", &self.quota_id)?;
        require_id("quota_group_id", &self.quota_group_id)?;
        require_hash("subject_commitment", &self.subject_commitment)?;
        require_hash("credential_root", &self.credential_root)?;
        require_hash("nullifier_root", &self.nullifier_root)?;
        if self.window_end_height <= self.window_start_height {
            return Err(format!("quota {} has invalid window", self.quota_id));
        }
        if self.window_end_height - self.window_start_height > config.quota_window_blocks {
            return Err(format!("quota {} window exceeds config", self.quota_id));
        }
        if self.max_orders == 0 || self.used_orders > self.max_orders {
            return Err(format!("quota {} order allowance invalid", self.quota_id));
        }
        if self.max_mints == 0 || self.used_mints > self.max_mints {
            return Err(format!("quota {} mint allowance invalid", self.quota_id));
        }
        if self.sybil_score_bps > config.max_sybil_score_bps {
            return Err(format!(
                "quota {} sybil score outside limits",
                self.quota_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqAuthorizationCommitment {
    pub authorization_id: String,
    pub subject_kind: AuthorizationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub nonce_commitment: String,
    pub expires_at_height: u64,
    pub authorized_at_height: u64,
}

impl PqAuthorizationCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "nonce_commitment": self.nonce_commitment,
            "expires_at_height": self.expires_at_height,
            "authorized_at_height": self.authorized_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("authorization_id", &self.authorization_id)?;
        require_id("subject_id", &self.subject_id)?;
        require_hash("subject_root", &self.subject_root)?;
        require_hash("signer_commitment", &self.signer_commitment)?;
        require_hash("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        require_hash("signature_commitment", &self.signature_commitment)?;
        require_hash("nonce_commitment", &self.nonce_commitment)?;
        if self.expires_at_height <= self.authorized_at_height {
            return Err(format!(
                "authorization {} expires before authorization",
                self.authorization_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MintReceipt {
    pub receipt_id: String,
    pub order_id: String,
    pub template_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub recipient_set_root: String,
    pub minted_supply_commitment: String,
    pub fee_receipt_root: String,
    pub proof_root: String,
    pub registry_publication_id: String,
    pub privacy_record_root: String,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
}

impl MintReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "order_id": self.order_id,
            "template_id": self.template_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "recipient_set_root": self.recipient_set_root,
            "minted_supply_commitment": self.minted_supply_commitment,
            "fee_receipt_root": self.fee_receipt_root,
            "proof_root": self.proof_root,
            "registry_publication_id": self.registry_publication_id,
            "privacy_record_root": self.privacy_record_root,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(
        &self,
        config: &Config,
        orders: &BTreeMap<String, BatchMintOrder>,
    ) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("receipt_id", &self.receipt_id)?;
        require_known("order", &self.order_id, orders)?;
        require_id("template_id", &self.template_id)?;
        require_id("batch_id", &self.batch_id)?;
        require_hash("recipient_set_root", &self.recipient_set_root)?;
        require_hash("minted_supply_commitment", &self.minted_supply_commitment)?;
        require_hash("fee_receipt_root", &self.fee_receipt_root)?;
        require_hash("proof_root", &self.proof_root)?;
        require_id("registry_publication_id", &self.registry_publication_id)?;
        require_hash("privacy_record_root", &self.privacy_record_root)?;
        if self.expires_at_height <= self.accepted_at_height {
            return Err(format!("receipt {} has invalid ttl", self.receipt_id));
        }
        if self.expires_at_height - self.accepted_at_height > config.receipt_ttl_blocks {
            return Err(format!("receipt {} ttl exceeds config", self.receipt_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryPublication {
    pub publication_id: String,
    pub registry_id: String,
    pub template_id: String,
    pub receipt_root: String,
    pub token_public_record_root: String,
    pub privacy_record_root: String,
    pub status: PublicationStatus,
    pub registry_epoch: u64,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl RegistryPublication {
    pub fn public_record(&self) -> Value {
        json!({
            "publication_id": self.publication_id,
            "registry_id": self.registry_id,
            "template_id": self.template_id,
            "receipt_root": self.receipt_root,
            "token_public_record_root": self.token_public_record_root,
            "privacy_record_root": self.privacy_record_root,
            "status": self.status.as_str(),
            "registry_epoch": self.registry_epoch,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self, config: &Config) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("publication_id", &self.publication_id)?;
        require_id("registry_id", &self.registry_id)?;
        require_id("template_id", &self.template_id)?;
        require_hash("receipt_root", &self.receipt_root)?;
        require_hash("token_public_record_root", &self.token_public_record_root)?;
        require_hash("privacy_record_root", &self.privacy_record_root)?;
        if self.registry_id != config.registry_id {
            return Err(format!(
                "publication {} targets unknown registry",
                self.publication_id
            ));
        }
        if self.expires_at_height <= self.published_at_height {
            return Err(format!(
                "publication {} has invalid ttl",
                self.publication_id
            ));
        }
        if self.expires_at_height - self.published_at_height > config.registry_ttl_blocks {
            return Err(format!(
                "publication {} ttl exceeds config",
                self.publication_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub cohort_root: String,
    pub amount_bucket_root: String,
    pub disclosure_policy_root: String,
    pub audit_hint_root: String,
    pub published_at_height: u64,
}

impl PrivacyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "cohort_root": self.cohort_root,
            "amount_bucket_root": self.amount_bucket_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "audit_hint_root": self.audit_hint_root,
            "published_at_height": self.published_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("record_id", &self.record_id)?;
        require_id("subject_kind", &self.subject_kind)?;
        require_id("subject_id", &self.subject_id)?;
        require_hash("cohort_root", &self.cohort_root)?;
        require_hash("amount_bucket_root", &self.amount_bucket_root)?;
        require_hash("disclosure_policy_root", &self.disclosure_policy_root)?;
        require_hash("audit_hint_root", &self.audit_hint_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FactoryEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub emitted_at_height: u64,
}

impl FactoryEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "emitted_at_height": self.emitted_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> LowFeeTokenBatchMintFactoryResult<()> {
        require_id("event_id", &self.event_id)?;
        require_id("event_kind", &self.event_kind)?;
        require_id("subject_id", &self.subject_id)?;
        require_hash("subject_root", &self.subject_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub template_root: String,
    pub order_root: String,
    pub sponsor_bucket_root: String,
    pub quota_root: String,
    pub authorization_root: String,
    pub receipt_root: String,
    pub publication_root: String,
    pub privacy_public_record_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "template_root": self.template_root,
            "order_root": self.order_root,
            "sponsor_bucket_root": self.sponsor_bucket_root,
            "quota_root": self.quota_root,
            "authorization_root": self.authorization_root,
            "receipt_root": self.receipt_root,
            "publication_root": self.publication_root,
            "privacy_public_record_root": self.privacy_public_record_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub templates: u64,
    pub active_templates: u64,
    pub live_orders: u64,
    pub finalized_orders: u64,
    pub sponsor_buckets: u64,
    pub spendable_sponsor_buckets: u64,
    pub quotas: u64,
    pub available_quotas: u64,
    pub authorizations: u64,
    pub receipts: u64,
    pub minted_receipts: u64,
    pub registry_publications: u64,
    pub privacy_public_records: u64,
    pub nullifiers: u64,
    pub events: u64,
    pub total_mint_count: u64,
    pub total_fee_units: u64,
    pub total_sponsored_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "templates": self.templates,
            "active_templates": self.active_templates,
            "live_orders": self.live_orders,
            "finalized_orders": self.finalized_orders,
            "sponsor_buckets": self.sponsor_buckets,
            "spendable_sponsor_buckets": self.spendable_sponsor_buckets,
            "quotas": self.quotas,
            "available_quotas": self.available_quotas,
            "authorizations": self.authorizations,
            "receipts": self.receipts,
            "minted_receipts": self.minted_receipts,
            "registry_publications": self.registry_publications,
            "privacy_public_records": self.privacy_public_records,
            "nullifiers": self.nullifiers,
            "events": self.events,
            "total_mint_count": self.total_mint_count,
            "total_fee_units": self.total_fee_units,
            "total_sponsored_units": self.total_sponsored_units
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub templates: BTreeMap<String, ConfidentialTokenTemplate>,
    pub orders: BTreeMap<String, BatchMintOrder>,
    pub sponsor_buckets: BTreeMap<String, SponsorFeeBucket>,
    pub quotas: BTreeMap<String, AntiSpamQuota>,
    pub authorizations: BTreeMap<String, PqAuthorizationCommitment>,
    pub receipts: BTreeMap<String, MintReceipt>,
    pub registry_publications: BTreeMap<String, RegistryPublication>,
    pub privacy_public_records: BTreeMap<String, PrivacyPublicRecord>,
    pub nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, FactoryEvent>,
}

impl State {
    pub fn devnet() -> LowFeeTokenBatchMintFactoryResult<Self> {
        let config = Config::devnet();
        let height = LOW_FEE_TOKEN_BATCH_MINT_FACTORY_DEVNET_HEIGHT;

        let template_a = make_template(
            "template-private-usdx",
            "issuer-nebula-stables",
            "pUSDX",
            TokenPrivacyClass::ConfidentialFungible,
            TemplateStatus::Active,
            "bucket-community-gas",
            "quota-community-minters",
            height - 420,
            height - 360,
            height + 36_000,
        );
        let template_b = make_template(
            "template-dev-grant-badge",
            "issuer-nebula-grants",
            "DGBADGE",
            TokenPrivacyClass::SoulboundCredential,
            TemplateStatus::QuotaLimited,
            "bucket-grant-gas",
            "quota-developer-grants",
            height - 390,
            height - 300,
            height + 28_800,
        );

        let mut templates = BTreeMap::new();
        templates.insert(template_a.template_id.clone(), template_a.clone());
        templates.insert(template_b.template_id.clone(), template_b.clone());

        let bucket_a = SponsorFeeBucket {
            bucket_id: "bucket-community-gas".to_string(),
            sponsor_commitment: commitment("sponsor", "nebula-community-treasury"),
            beneficiary_group_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-BENEFICIARIES",
                &["early-wallets", "private-liquidity-minters", "quest-cohort"],
            ),
            allowed_template_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-ALLOWED-TEMPLATES",
                &["template-private-usdx"],
            ),
            status: SponsorBucketStatus::Open,
            asset_id: config.sponsor_asset_id.clone(),
            budget_units: 300_000,
            reserved_units: 420,
            consumed_units: 8_800,
            discount_bps: 8_400,
            min_privacy_set_size: 2_048,
            opened_at_height: height - 300,
            expires_at_height: height + 5_000,
        };
        let bucket_b = SponsorFeeBucket {
            bucket_id: "bucket-grant-gas".to_string(),
            sponsor_commitment: commitment("sponsor", "nebula-developer-grants"),
            beneficiary_group_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-BENEFICIARIES",
                &["audited-contract-builders", "testnet-provers"],
            ),
            allowed_template_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-ALLOWED-TEMPLATES",
                &["template-dev-grant-badge"],
            ),
            status: SponsorBucketStatus::Reserved,
            asset_id: config.fee_asset_id.clone(),
            budget_units: 120_000,
            reserved_units: 240,
            consumed_units: 3_600,
            discount_bps: 9_000,
            min_privacy_set_size: 1_024,
            opened_at_height: height - 260,
            expires_at_height: height + 4_800,
        };
        let mut sponsor_buckets = BTreeMap::new();
        sponsor_buckets.insert(bucket_a.bucket_id.clone(), bucket_a);
        sponsor_buckets.insert(bucket_b.bucket_id.clone(), bucket_b);

        let quota_a = AntiSpamQuota {
            quota_id: "quota-community-minters-wallet-cohort-a".to_string(),
            quota_group_id: "quota-community-minters".to_string(),
            subject_commitment: commitment("quota-subject", "wallet-cohort-a"),
            credential_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-CREDENTIALS",
                &[
                    "human-uniqueness",
                    "wallet-age-30d",
                    "private-activity-score",
                ],
            ),
            status: QuotaStatus::Available,
            window_start_height: height - 120,
            window_end_height: height + 600,
            max_orders: 24,
            used_orders: 5,
            max_mints: 30_000,
            used_mints: 10_880,
            sybil_score_bps: 640,
            nullifier_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-QUOTA-NULLIFIERS",
                &["quota-nullifier-a", "quota-nullifier-b"],
            ),
        };
        let quota_b = AntiSpamQuota {
            quota_id: "quota-developer-grants-builders".to_string(),
            quota_group_id: "quota-developer-grants".to_string(),
            subject_commitment: commitment("quota-subject", "builder-cohort"),
            credential_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-CREDENTIALS",
                &["contract-developer", "auditor-attested", "grant-eligible"],
            ),
            status: QuotaStatus::Throttled,
            window_start_height: height - 90,
            window_end_height: height + 630,
            max_orders: 12,
            used_orders: 4,
            max_mints: 8_000,
            used_mints: 2_048,
            sybil_score_bps: 1_250,
            nullifier_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-QUOTA-NULLIFIERS",
                &["quota-nullifier-c"],
            ),
        };
        let mut quotas = BTreeMap::new();
        quotas.insert(quota_a.quota_id.clone(), quota_a);
        quotas.insert(quota_b.quota_id.clone(), quota_b);

        let order_a = make_order(
            &config,
            "order-usdx-community-001",
            "template-private-usdx",
            "bucket-community-gas",
            "quota-community-minters-wallet-cohort-a",
            MintOrderStatus::Published,
            8_192,
            819_200,
            12,
            8_400,
            height - 48,
            "batch-mint-devnet-17",
        );
        let order_b = make_order(
            &config,
            "order-usdx-community-002",
            "template-private-usdx",
            "bucket-community-gas",
            "quota-community-minters-wallet-cohort-a",
            MintOrderStatus::SponsorReserved,
            2_688,
            268_800,
            10,
            8_000,
            height - 12,
            "batch-mint-devnet-18",
        );
        let order_c = make_order(
            &config,
            "order-grant-badge-001",
            "template-dev-grant-badge",
            "bucket-grant-gas",
            "quota-developer-grants-builders",
            MintOrderStatus::Finalized,
            2_048,
            2_048,
            3,
            9_000,
            height - 96,
            "batch-mint-devnet-16",
        );
        let mut orders = BTreeMap::new();
        orders.insert(order_a.order_id.clone(), order_a.clone());
        orders.insert(order_b.order_id.clone(), order_b.clone());
        orders.insert(order_c.order_id.clone(), order_c.clone());

        let mut authorizations = BTreeMap::new();
        for (subject_kind, subject_id, subject_root, signer) in [
            (
                AuthorizationSubject::Template,
                template_a.template_id.as_str(),
                template_a.root(),
                "issuer-nebula-stables",
            ),
            (
                AuthorizationSubject::Template,
                template_b.template_id.as_str(),
                template_b.root(),
                "issuer-nebula-grants",
            ),
            (
                AuthorizationSubject::BatchMintOrder,
                order_a.order_id.as_str(),
                order_a.root(),
                "wallet-cohort-a",
            ),
            (
                AuthorizationSubject::BatchMintOrder,
                order_b.order_id.as_str(),
                order_b.root(),
                "wallet-cohort-a",
            ),
            (
                AuthorizationSubject::BatchMintOrder,
                order_c.order_id.as_str(),
                order_c.root(),
                "builder-cohort",
            ),
        ] {
            let authorization = make_authorization(
                subject_kind,
                subject_id,
                &subject_root,
                signer,
                height - 24,
                height + 720,
            );
            authorizations.insert(authorization.authorization_id.clone(), authorization);
        }

        let publication_a = make_publication(
            &config,
            "publication-usdx-devnet-001",
            "template-private-usdx",
            &order_a.root(),
            PublicationStatus::Anchored,
            17,
            height - 24,
        );
        let publication_b = make_publication(
            &config,
            "publication-grant-badge-devnet-001",
            "template-dev-grant-badge",
            &order_c.root(),
            PublicationStatus::Finalized,
            16,
            height - 84,
        );
        let mut registry_publications = BTreeMap::new();
        registry_publications.insert(publication_a.publication_id.clone(), publication_a.clone());
        registry_publications.insert(publication_b.publication_id.clone(), publication_b.clone());

        let receipt_a = make_receipt(
            &config,
            "receipt-usdx-community-001",
            &order_a,
            ReceiptStatus::RegistryPosted,
            &publication_a.publication_id,
            height - 22,
        );
        let receipt_b = make_receipt(
            &config,
            "receipt-grant-badge-001",
            &order_c,
            ReceiptStatus::Finalized,
            &publication_b.publication_id,
            height - 82,
        );
        let mut receipts = BTreeMap::new();
        receipts.insert(receipt_a.receipt_id.clone(), receipt_a);
        receipts.insert(receipt_b.receipt_id.clone(), receipt_b);

        let privacy_record_a = PrivacyPublicRecord {
            record_id: "privacy-record-usdx-community-001".to_string(),
            subject_kind: "registry_publication".to_string(),
            subject_id: publication_a.publication_id.clone(),
            cohort_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-PRIVACY-COHORT",
                &[
                    "wallet-age-30d",
                    "amount-bucket-mid",
                    "public-registry-safe",
                ],
            ),
            amount_bucket_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-AMOUNT-BUCKET",
                &["bucket-100", "bucket-250", "bucket-500"],
            ),
            disclosure_policy_root: commitment("disclosure-policy", "selective-auditor-only"),
            audit_hint_root: commitment("audit-hint", "usdx-community-mint"),
            published_at_height: height - 24,
        };
        let privacy_record_b = PrivacyPublicRecord {
            record_id: "privacy-record-grant-badge-001".to_string(),
            subject_kind: "registry_publication".to_string(),
            subject_id: publication_b.publication_id.clone(),
            cohort_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-PRIVACY-COHORT",
                &["builder-grant", "soulbound", "small-supply"],
            ),
            amount_bucket_root: leaf_root(
                "LOW-FEE-TOKEN-BATCH-MINT-AMOUNT-BUCKET",
                &["unit-badge"],
            ),
            disclosure_policy_root: commitment("disclosure-policy", "issuer-and-auditor"),
            audit_hint_root: commitment("audit-hint", "grant-badge-mint"),
            published_at_height: height - 84,
        };
        let mut privacy_public_records = BTreeMap::new();
        privacy_public_records.insert(privacy_record_a.record_id.clone(), privacy_record_a);
        privacy_public_records.insert(privacy_record_b.record_id.clone(), privacy_record_b);

        let nullifiers = [
            "mint-nullifier-usdx-community-001",
            "mint-nullifier-usdx-community-002",
            "mint-nullifier-grant-badge-001",
        ]
        .iter()
        .map(|value| commitment("mint-nullifier", value))
        .collect::<BTreeSet<_>>();

        let mut events = BTreeMap::new();
        for (event_kind, subject_id, subject_root, emitted_at_height) in [
            (
                "template_activated",
                template_a.template_id.as_str(),
                template_a.root(),
                template_a.activated_at_height,
            ),
            (
                "template_activated",
                template_b.template_id.as_str(),
                template_b.root(),
                template_b.activated_at_height,
            ),
            (
                "order_published",
                order_a.order_id.as_str(),
                order_a.root(),
                height - 24,
            ),
            (
                "order_finalized",
                order_c.order_id.as_str(),
                order_c.root(),
                height - 72,
            ),
        ] {
            let event = make_event(event_kind, subject_id, &subject_root, emitted_at_height);
            events.insert(event.event_id.clone(), event);
        }

        let state = Self {
            height,
            config,
            templates,
            orders,
            sponsor_buckets,
            quotas,
            authorizations,
            receipts,
            registry_publications,
            privacy_public_records,
            nullifiers,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeeTokenBatchMintFactoryResult<()> {
        self.config.validate()?;
        check_len(
            "templates",
            self.templates.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_TEMPLATES,
        )?;
        check_len(
            "orders",
            self.orders.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_ORDERS,
        )?;
        check_len(
            "sponsor buckets",
            self.sponsor_buckets.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_SPONSOR_BUCKETS,
        )?;
        check_len(
            "quotas",
            self.quotas.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_QUOTAS,
        )?;
        check_len(
            "authorizations",
            self.authorizations.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_AUTHORIZATIONS,
        )?;
        check_len(
            "receipts",
            self.receipts.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_RECEIPTS,
        )?;
        check_len(
            "registry publications",
            self.registry_publications.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_PUBLICATIONS,
        )?;
        check_len(
            "privacy public records",
            self.privacy_public_records.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_PUBLICATIONS,
        )?;
        check_len(
            "nullifiers",
            self.nullifiers.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_NULLIFIERS,
        )?;
        check_len(
            "events",
            self.events.len(),
            LOW_FEE_TOKEN_BATCH_MINT_FACTORY_MAX_EVENTS,
        )?;

        for (id, template) in &self.templates {
            require_key_match("template", id, &template.template_id)?;
            template.validate(&self.config)?;
        }
        for (id, bucket) in &self.sponsor_buckets {
            require_key_match("sponsor bucket", id, &bucket.bucket_id)?;
            bucket.validate(&self.config)?;
        }
        for (id, quota) in &self.quotas {
            require_key_match("quota", id, &quota.quota_id)?;
            quota.validate(&self.config)?;
        }
        for (id, order) in &self.orders {
            require_key_match("order", id, &order.order_id)?;
            order.validate(&self.config, &self.templates)?;
            require_known(
                "sponsor bucket",
                &order.sponsor_bucket_id,
                &self.sponsor_buckets,
            )?;
            require_known("quota", &order.quota_id, &self.quotas)?;
        }
        for (id, authorization) in &self.authorizations {
            require_key_match("authorization", id, &authorization.authorization_id)?;
            authorization.validate()?;
        }
        for (id, receipt) in &self.receipts {
            require_key_match("receipt", id, &receipt.receipt_id)?;
            receipt.validate(&self.config, &self.orders)?;
        }
        for (id, publication) in &self.registry_publications {
            require_key_match("publication", id, &publication.publication_id)?;
            publication.validate(&self.config)?;
            require_known("template", &publication.template_id, &self.templates)?;
        }
        for (id, record) in &self.privacy_public_records {
            require_key_match("privacy public record", id, &record.record_id)?;
            record.validate()?;
        }
        for nullifier in &self.nullifiers {
            require_hash("nullifier", nullifier)?;
        }
        for (id, event) in &self.events {
            require_key_match("event", id, &event.event_id)?;
            event.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeTokenBatchMintFactoryResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeTokenBatchMintFactoryResult<()> {
        if height < self.height {
            return Err("low fee token batch mint factory height cannot decrease".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            template_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-TEMPLATES",
                self.templates
                    .values()
                    .map(ConfidentialTokenTemplate::public_record),
            ),
            order_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-ORDERS",
                self.orders.values().map(BatchMintOrder::public_record),
            ),
            sponsor_bucket_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-SPONSOR-BUCKETS",
                self.sponsor_buckets
                    .values()
                    .map(SponsorFeeBucket::public_record),
            ),
            quota_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-QUOTAS",
                self.quotas.values().map(AntiSpamQuota::public_record),
            ),
            authorization_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(PqAuthorizationCommitment::public_record),
            ),
            receipt_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-RECEIPTS",
                self.receipts.values().map(MintReceipt::public_record),
            ),
            publication_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-PUBLICATIONS",
                self.registry_publications
                    .values()
                    .map(RegistryPublication::public_record),
            ),
            privacy_public_record_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-PRIVACY-PUBLIC-RECORDS",
                self.privacy_public_records
                    .values()
                    .map(PrivacyPublicRecord::public_record),
            ),
            nullifier_root: merkle_root(
                "LOW-FEE-TOKEN-BATCH-MINT-NULLIFIERS",
                &self
                    .nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
            event_root: map_root(
                "LOW-FEE-TOKEN-BATCH-MINT-EVENTS",
                self.events.values().map(FactoryEvent::public_record),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            templates: self.templates.len() as u64,
            active_templates: self
                .templates
                .values()
                .filter(|template| template.status.accepts_orders())
                .count() as u64,
            live_orders: self
                .orders
                .values()
                .filter(|order| order.status.live())
                .count() as u64,
            finalized_orders: self
                .orders
                .values()
                .filter(|order| order.status == MintOrderStatus::Finalized)
                .count() as u64,
            sponsor_buckets: self.sponsor_buckets.len() as u64,
            spendable_sponsor_buckets: self
                .sponsor_buckets
                .values()
                .filter(|bucket| bucket.status.spendable())
                .count() as u64,
            quotas: self.quotas.len() as u64,
            available_quotas: self
                .quotas
                .values()
                .filter(|quota| quota.status.accepts_orders())
                .count() as u64,
            authorizations: self.authorizations.len() as u64,
            receipts: self.receipts.len() as u64,
            minted_receipts: self
                .receipts
                .values()
                .filter(|receipt| receipt.status.counts_as_minted())
                .count() as u64,
            registry_publications: self.registry_publications.len() as u64,
            privacy_public_records: self.privacy_public_records.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            events: self.events.len() as u64,
            total_mint_count: self.orders.values().map(|order| order.mint_count).sum(),
            total_fee_units: self.orders.values().map(|order| order.max_fee_units).sum(),
            total_sponsored_units: self
                .sponsor_buckets
                .values()
                .map(|bucket| bucket.consumed_units + bucket.reserved_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "LOW-FEE-TOKEN-BATCH-MINT-FACTORY-STATE",
            &[
                HashPart::Str(&self.height.to_string()),
                HashPart::Json(&self.roots().public_record()),
                HashPart::Json(&self.counters().public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "privacy": {
                "public_records_are_commitment_only": true,
                "recipient_sets_are_merkle_roots": true,
                "amounts_are_bucketed_or_confidential": true,
                "pq_authorizations_are_commitments": true
            }
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "LOW-FEE-TOKEN-BATCH-MINT-FACTORY-RECORD",
        &[
            HashPart::Str(LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> LowFeeTokenBatchMintFactoryResult<State> {
    State::devnet()
}

fn make_template(
    template_id: &str,
    issuer: &str,
    symbol: &str,
    privacy_class: TokenPrivacyClass,
    status: TemplateStatus,
    bucket_id: &str,
    quota_group_id: &str,
    created_at_height: u64,
    activated_at_height: u64,
    expires_at_height: u64,
) -> ConfidentialTokenTemplate {
    ConfidentialTokenTemplate {
        template_id: template_id.to_string(),
        issuer_commitment: commitment("issuer", issuer),
        token_symbol_hash: commitment("symbol", symbol),
        token_metadata_root: record_root("metadata", template_id),
        privacy_class,
        status,
        supply_cap_commitment: commitment("supply-cap", template_id),
        mint_policy_root: record_root("mint-policy", template_id),
        transfer_hook_root: if privacy_class.requires_transfer_hook() {
            record_root("transfer-hook", template_id)
        } else {
            empty_root("LOW-FEE-TOKEN-BATCH-MINT-EMPTY-HOOK")
        },
        compliance_hook_root: record_root("compliance-hook", template_id),
        royalty_policy_root: record_root("royalty-policy", template_id),
        default_fee_bucket_id: bucket_id.to_string(),
        quota_group_id: quota_group_id.to_string(),
        pq_admin_commitment: commitment("pq-admin", issuer),
        created_at_height,
        activated_at_height,
        expires_at_height,
    }
}

fn make_order(
    config: &Config,
    order_id: &str,
    template_id: &str,
    sponsor_bucket_id: &str,
    quota_id: &str,
    status: MintOrderStatus,
    mint_count: u64,
    supply_bucket_units: u64,
    max_fee_units: u64,
    fee_discount_bps: u64,
    submitted_at_height: u64,
    packed_batch_id: &str,
) -> BatchMintOrder {
    BatchMintOrder {
        order_id: order_id.to_string(),
        template_id: template_id.to_string(),
        sponsor_bucket_id: sponsor_bucket_id.to_string(),
        quota_id: quota_id.to_string(),
        creator_commitment: commitment("creator", order_id),
        recipient_set_root: record_root("recipients", order_id),
        confidential_amount_root: record_root("amounts", order_id),
        memo_ciphertext_root: record_root("memos", order_id),
        authorization_root: record_root("authorizations", order_id),
        proof_request_root: record_root("proof-request", order_id),
        status,
        mint_count,
        supply_bucket_units,
        max_fee_units,
        fee_discount_bps,
        submitted_at_height,
        expires_at_height: submitted_at_height + config.order_ttl_blocks,
        packed_batch_id: packed_batch_id.to_string(),
    }
}

fn make_authorization(
    subject_kind: AuthorizationSubject,
    subject_id: &str,
    subject_root: &str,
    signer: &str,
    authorized_at_height: u64,
    expires_at_height: u64,
) -> PqAuthorizationCommitment {
    let authorization_id = domain_hash(
        "LOW-FEE-TOKEN-BATCH-MINT-AUTHORIZATION-ID",
        &[
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer),
        ],
        16,
    );
    PqAuthorizationCommitment {
        authorization_id,
        subject_kind,
        subject_id: subject_id.to_string(),
        subject_root: subject_root.to_string(),
        signer_commitment: commitment("signer", signer),
        pq_public_key_commitment: commitment("pq-public-key", signer),
        signature_commitment: commitment("pq-signature", subject_root),
        nonce_commitment: commitment("pq-nonce", subject_id),
        expires_at_height,
        authorized_at_height,
    }
}

fn make_publication(
    config: &Config,
    publication_id: &str,
    template_id: &str,
    receipt_root: &str,
    status: PublicationStatus,
    registry_epoch: u64,
    published_at_height: u64,
) -> RegistryPublication {
    RegistryPublication {
        publication_id: publication_id.to_string(),
        registry_id: config.registry_id.clone(),
        template_id: template_id.to_string(),
        receipt_root: receipt_root.to_string(),
        token_public_record_root: record_root("registry-token-public-record", publication_id),
        privacy_record_root: record_root("registry-privacy-record", publication_id),
        status,
        registry_epoch,
        published_at_height,
        expires_at_height: published_at_height + config.registry_ttl_blocks,
    }
}

fn make_receipt(
    config: &Config,
    receipt_id: &str,
    order: &BatchMintOrder,
    status: ReceiptStatus,
    publication_id: &str,
    accepted_at_height: u64,
) -> MintReceipt {
    MintReceipt {
        receipt_id: receipt_id.to_string(),
        order_id: order.order_id.clone(),
        template_id: order.template_id.clone(),
        batch_id: order.packed_batch_id.clone(),
        status,
        recipient_set_root: order.recipient_set_root.clone(),
        minted_supply_commitment: commitment("minted-supply", &order.order_id),
        fee_receipt_root: record_root("fee-receipt", receipt_id),
        proof_root: record_root("mint-proof", receipt_id),
        registry_publication_id: publication_id.to_string(),
        privacy_record_root: record_root("receipt-privacy-record", receipt_id),
        accepted_at_height,
        expires_at_height: accepted_at_height + config.receipt_ttl_blocks,
    }
}

fn make_event(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    emitted_at_height: u64,
) -> FactoryEvent {
    let event_id = domain_hash(
        "LOW-FEE-TOKEN-BATCH-MINT-EVENT-ID",
        &[
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(&emitted_at_height.to_string()),
        ],
        16,
    );
    FactoryEvent {
        event_id,
        event_kind: event_kind.to_string(),
        subject_id: subject_id.to_string(),
        subject_root: subject_root.to_string(),
        emitted_at_height,
    }
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}

fn leaf_root(domain: &str, leaves: &[&str]) -> String {
    merkle_root(
        domain,
        &leaves.iter().map(|leaf| json!(leaf)).collect::<Vec<_>>(),
    )
}

fn record_root(label: &str, value: &str) -> String {
    let record = json!({
        "label": label,
        "value": value,
        "protocol_version": LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION
    });
    domain_hash(
        "LOW-FEE-TOKEN-BATCH-MINT-RECORD-ROOT",
        &[HashPart::Json(&record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn commitment(label: &str, value: &str) -> String {
    domain_hash(
        "LOW-FEE-TOKEN-BATCH-MINT-COMMITMENT",
        &[
            HashPart::Str(LOW_FEE_TOKEN_BATCH_MINT_FACTORY_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn require_id(label: &str, value: &str) -> LowFeeTokenBatchMintFactoryResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    if value.len() > 160 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn require_hash(label: &str, value: &str) -> LowFeeTokenBatchMintFactoryResult<()> {
    require_id(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be a commitment-like value"));
    }
    Ok(())
}

fn require_key_match(label: &str, key: &str, value: &str) -> LowFeeTokenBatchMintFactoryResult<()> {
    if key != value {
        return Err(format!("{label} map key does not match embedded id"));
    }
    Ok(())
}

fn require_known<T>(
    label: &str,
    id: &str,
    map: &BTreeMap<String, T>,
) -> LowFeeTokenBatchMintFactoryResult<()> {
    if !map.contains_key(id) {
        return Err(format!("{label} {id} is unknown"));
    }
    Ok(())
}

fn check_len(label: &str, len: usize, max: usize) -> LowFeeTokenBatchMintFactoryResult<()> {
    if len > max {
        return Err(format!("{label} exceeds maximum"));
    }
    Ok(())
}
