use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialTokenIndexerResult<T> = Result<T, String>;

pub const CONFIDENTIAL_TOKEN_INDEXER_PROTOCOL_VERSION: &str =
    "nebula-l2-confidential-token-indexer-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_SCHEMA_VERSION: u64 = 1;
pub const CONFIDENTIAL_TOKEN_INDEXER_TOKEN_COMMITMENT_SCHEME: &str =
    "devnet-shake256-confidential-token-class-summary-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_TRANSFER_COMMITMENT_SCHEME: &str =
    "devnet-shake256-shielded-transfer-index-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_NULLIFIER_SCHEME: &str =
    "devnet-shake256-private-defi-nullifier-index-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_CONTRACT_EVENT_SCHEME: &str =
    "devnet-shake256-contract-event-commitment-index-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_DISCLOSURE_SCHEME: &str =
    "devnet-selective-token-disclosure-view-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_SPONSORSHIP_SCHEME: &str =
    "devnet-low-fee-private-indexing-sponsorship-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_VIEW_AUTH_SCHEME: &str =
    "ml-dsa-87-selective-disclosure-grant-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_PQ_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-sealed-index-view-v1";
pub const CONFIDENTIAL_TOKEN_INDEXER_DEVNET_HEIGHT: u64 = 144;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEVNET_NETWORK: &str = "nebula-monero-l2-devnet";
pub const CONFIDENTIAL_TOKEN_INDEXER_DEVNET_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const CONFIDENTIAL_TOKEN_INDEXER_DEVNET_SPONSOR_LANE: &str = "confidential-token-indexing";
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_FINALITY_DEPTH: u64 = 12;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_INDEX_SHARD_COUNT: u16 = 32;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_TRANSFERS_PER_BATCH: usize = 512;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_EVENTS_PER_CONTRACT: usize = 1_024;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_DISCLOSURES_PER_SUBJECT: usize = 32;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_LOW_FEE_UNIT_CAP: u64 = 2_500_000;
pub const CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_SPONSOR_UNIT_PRICE: u64 = 175;
pub const CONFIDENTIAL_TOKEN_INDEXER_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_TOKEN_INDEXER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialTokenKind {
    WrappedMonero,
    Stablecoin,
    Governance,
    Utility,
    LiquidityShare,
    VaultShare,
    Derivative,
    Receipt,
}

impl ConfidentialTokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::Stablecoin => "stablecoin",
            Self::Governance => "governance",
            Self::Utility => "utility",
            Self::LiquidityShare => "liquidity_share",
            Self::VaultShare => "vault_share",
            Self::Derivative => "derivative",
            Self::Receipt => "receipt",
        }
    }

    pub fn supports_defi(self) -> bool {
        matches!(
            self,
            Self::WrappedMonero
                | Self::Stablecoin
                | Self::LiquidityShare
                | Self::VaultShare
                | Self::Derivative
                | Self::Utility
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialTokenStatus {
    Draft,
    Active,
    IndexPaused,
    TransferPaused,
    Frozen,
    Deprecated,
    Retired,
}

impl ConfidentialTokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::IndexPaused => "index_paused",
            Self::TransferPaused => "transfer_paused",
            Self::Frozen => "frozen",
            Self::Deprecated => "deprecated",
            Self::Retired => "retired",
        }
    }

    pub fn indexable(self) -> bool {
        matches!(self, Self::Active | Self::TransferPaused | Self::Deprecated)
    }

    pub fn accepts_transfer(self) -> bool {
        matches!(self, Self::Active | Self::IndexPaused)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSupplyDisclosure {
    CommitmentOnly,
    BucketedSupply,
    AuditorViewable,
    PublicSupplyPrivateBalances,
    ReserveBacked,
}

impl ConfidentialSupplyDisclosure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::BucketedSupply => "bucketed_supply",
            Self::AuditorViewable => "auditor_viewable",
            Self::PublicSupplyPrivateBalances => "public_supply_private_balances",
            Self::ReserveBacked => "reserve_backed",
        }
    }

    pub fn requires_auditor_root(self) -> bool {
        matches!(self, Self::AuditorViewable | Self::ReserveBacked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedTransferStatus {
    Pending,
    Indexed,
    Settled,
    Rejected,
    Expired,
    Reorged,
}

impl ShieldedTransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Indexed => "indexed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Indexed)
    }

    pub fn final_status(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rejected | Self::Expired | Self::Reorged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Observed,
    Reserved,
    Consumed,
    Rejected,
    Reorged,
}

impl NullifierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Reorged => "reorged",
        }
    }

    pub fn spends_note(self) -> bool {
        matches!(self, Self::Reserved | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractEventKind {
    TokenMint,
    TokenBurn,
    ShieldedTransfer,
    SwapCommitment,
    LiquidityCommitment,
    LendingCommitment,
    LiquidationCommitment,
    OracleCommitment,
    GovernanceCommitment,
    CustomCommitment,
}

impl ContractEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::ShieldedTransfer => "shielded_transfer",
            Self::SwapCommitment => "swap_commitment",
            Self::LiquidityCommitment => "liquidity_commitment",
            Self::LendingCommitment => "lending_commitment",
            Self::LiquidationCommitment => "liquidation_commitment",
            Self::OracleCommitment => "oracle_commitment",
            Self::GovernanceCommitment => "governance_commitment",
            Self::CustomCommitment => "custom_commitment",
        }
    }

    pub fn changes_supply(self) -> bool {
        matches!(self, Self::TokenMint | Self::TokenBurn)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractEventStatus {
    Pending,
    Indexed,
    Disclosed,
    Disputed,
    Reorged,
    Pruned,
}

impl ContractEventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Indexed => "indexed",
            Self::Disclosed => "disclosed",
            Self::Disputed => "disputed",
            Self::Reorged => "reorged",
            Self::Pruned => "pruned",
        }
    }

    pub fn visible_in_public_root(self) -> bool {
        matches!(self, Self::Indexed | Self::Disclosed | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    TokenSummary,
    TransferTrace,
    NullifierMembership,
    ContractEvent,
    FeeSponsorship,
    AuditBundle,
    ComplianceReceipt,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenSummary => "token_summary",
            Self::TransferTrace => "transfer_trace",
            Self::NullifierMembership => "nullifier_membership",
            Self::ContractEvent => "contract_event",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::AuditBundle => "audit_bundle",
            Self::ComplianceReceipt => "compliance_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureViewStatus {
    Requested,
    Granted,
    Opened,
    Revoked,
    Expired,
    Disputed,
}

impl DisclosureViewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Granted => "granted",
            Self::Opened => "opened",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Requested | Self::Granted | Self::Opened)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorAccountStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipGrantStatus {
    Open,
    Allocated,
    Settled,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipGrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allocated => "allocated",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Open | Self::Allocated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexShardStatus {
    Open,
    Sealed,
    Compacting,
    Reorged,
    Retired,
}

impl IndexShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Compacting => "compacting",
            Self::Reorged => "reorged",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_records(self) -> bool {
        matches!(self, Self::Open | Self::Compacting)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenIndexerConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub network: String,
    pub fee_asset_id: String,
    pub sponsor_lane: String,
    pub epoch_blocks: u64,
    pub finality_depth: u64,
    pub disclosure_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub index_shard_count: u16,
    pub max_transfers_per_batch: usize,
    pub max_events_per_contract: usize,
    pub max_disclosures_per_subject: usize,
    pub low_fee_unit_cap: u64,
    pub sponsor_unit_price: u64,
    pub min_pq_security_bits: u16,
    pub token_commitment_scheme: String,
    pub transfer_commitment_scheme: String,
    pub nullifier_scheme: String,
    pub contract_event_scheme: String,
    pub disclosure_scheme: String,
    pub sponsorship_scheme: String,
    pub view_auth_scheme: String,
    pub pq_encryption_scheme: String,
}

impl ConfidentialTokenIndexerConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_TOKEN_INDEXER_PROTOCOL_VERSION.to_string(),
            schema_version: CONFIDENTIAL_TOKEN_INDEXER_SCHEMA_VERSION,
            network: CONFIDENTIAL_TOKEN_INDEXER_DEVNET_NETWORK.to_string(),
            fee_asset_id: CONFIDENTIAL_TOKEN_INDEXER_DEVNET_FEE_ASSET_ID.to_string(),
            sponsor_lane: CONFIDENTIAL_TOKEN_INDEXER_DEVNET_SPONSOR_LANE.to_string(),
            epoch_blocks: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_EPOCH_BLOCKS,
            finality_depth: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_FINALITY_DEPTH,
            disclosure_ttl_blocks: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            sponsorship_ttl_blocks: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            index_shard_count: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_INDEX_SHARD_COUNT,
            max_transfers_per_batch: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_TRANSFERS_PER_BATCH,
            max_events_per_contract: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_EVENTS_PER_CONTRACT,
            max_disclosures_per_subject:
                CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_MAX_DISCLOSURES_PER_SUBJECT,
            low_fee_unit_cap: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_LOW_FEE_UNIT_CAP,
            sponsor_unit_price: CONFIDENTIAL_TOKEN_INDEXER_DEFAULT_SPONSOR_UNIT_PRICE,
            min_pq_security_bits: CONFIDENTIAL_TOKEN_INDEXER_MIN_PQ_SECURITY_BITS,
            token_commitment_scheme: CONFIDENTIAL_TOKEN_INDEXER_TOKEN_COMMITMENT_SCHEME.to_string(),
            transfer_commitment_scheme: CONFIDENTIAL_TOKEN_INDEXER_TRANSFER_COMMITMENT_SCHEME
                .to_string(),
            nullifier_scheme: CONFIDENTIAL_TOKEN_INDEXER_NULLIFIER_SCHEME.to_string(),
            contract_event_scheme: CONFIDENTIAL_TOKEN_INDEXER_CONTRACT_EVENT_SCHEME.to_string(),
            disclosure_scheme: CONFIDENTIAL_TOKEN_INDEXER_DISCLOSURE_SCHEME.to_string(),
            sponsorship_scheme: CONFIDENTIAL_TOKEN_INDEXER_SPONSORSHIP_SCHEME.to_string(),
            view_auth_scheme: CONFIDENTIAL_TOKEN_INDEXER_VIEW_AUTH_SCHEME.to_string(),
            pq_encryption_scheme: CONFIDENTIAL_TOKEN_INDEXER_PQ_ENCRYPTION_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_indexer_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "network": self.network,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_lane": self.sponsor_lane,
            "epoch_blocks": self.epoch_blocks,
            "finality_depth": self.finality_depth,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "index_shard_count": self.index_shard_count,
            "max_transfers_per_batch": self.max_transfers_per_batch,
            "max_events_per_contract": self.max_events_per_contract,
            "max_disclosures_per_subject": self.max_disclosures_per_subject,
            "low_fee_unit_cap": self.low_fee_unit_cap,
            "sponsor_unit_price": self.sponsor_unit_price,
            "min_pq_security_bits": self.min_pq_security_bits,
            "schemes": {
                "token_commitment": self.token_commitment_scheme,
                "transfer_commitment": self.transfer_commitment_scheme,
                "nullifier": self.nullifier_scheme,
                "contract_event": self.contract_event_scheme,
                "disclosure": self.disclosure_scheme,
                "sponsorship": self.sponsorship_scheme,
                "view_auth": self.view_auth_scheme,
                "pq_encryption": self.pq_encryption_scheme,
            }
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.network, "network")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.sponsor_lane, "sponsor_lane")?;
        ensure_non_empty(&self.token_commitment_scheme, "token_commitment_scheme")?;
        ensure_non_empty(
            &self.transfer_commitment_scheme,
            "transfer_commitment_scheme",
        )?;
        ensure_non_empty(&self.nullifier_scheme, "nullifier_scheme")?;
        ensure_non_empty(&self.contract_event_scheme, "contract_event_scheme")?;
        ensure_non_empty(&self.disclosure_scheme, "disclosure_scheme")?;
        ensure_non_empty(&self.sponsorship_scheme, "sponsorship_scheme")?;
        ensure_non_empty(&self.view_auth_scheme, "view_auth_scheme")?;
        ensure_non_empty(&self.pq_encryption_scheme, "pq_encryption_scheme")?;
        ensure_positive(self.schema_version, "schema_version")?;
        ensure_positive(self.epoch_blocks, "epoch_blocks")?;
        ensure_positive(self.finality_depth, "finality_depth")?;
        ensure_positive(self.disclosure_ttl_blocks, "disclosure_ttl_blocks")?;
        ensure_positive(self.sponsorship_ttl_blocks, "sponsorship_ttl_blocks")?;
        ensure_positive(self.index_shard_count as u64, "index_shard_count")?;
        ensure_positive(
            self.max_transfers_per_batch as u64,
            "max_transfers_per_batch",
        )?;
        ensure_positive(
            self.max_events_per_contract as u64,
            "max_events_per_contract",
        )?;
        ensure_positive(
            self.max_disclosures_per_subject as u64,
            "max_disclosures_per_subject",
        )?;
        ensure_positive(self.low_fee_unit_cap, "low_fee_unit_cap")?;
        ensure_positive(self.sponsor_unit_price, "sponsor_unit_price")?;
        if self.min_pq_security_bits < CONFIDENTIAL_TOKEN_INDEXER_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below confidential token indexer floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenClassSummary {
    pub token_id: String,
    pub symbol_commitment: String,
    pub metadata_commitment: String,
    pub issuer_commitment: String,
    pub token_kind: ConfidentialTokenKind,
    pub status: ConfidentialTokenStatus,
    pub supply_disclosure: ConfidentialSupplyDisclosure,
    pub supply_commitment_root: String,
    pub reserve_commitment_root: String,
    pub auditor_set_root: String,
    pub policy_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub low_fee_eligible: bool,
    pub defi_enabled: bool,
    pub disclosure_bps: u64,
}

impl ConfidentialTokenClassSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol_commitment: &str,
        metadata_commitment: &str,
        issuer_commitment: &str,
        token_kind: ConfidentialTokenKind,
        supply_disclosure: ConfidentialSupplyDisclosure,
        supply_commitment_root: &str,
        reserve_commitment_root: &str,
        auditor_set_root: &str,
        policy_root: &str,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(symbol_commitment, "symbol_commitment")?;
        ensure_non_empty(metadata_commitment, "metadata_commitment")?;
        ensure_non_empty(issuer_commitment, "issuer_commitment")?;
        ensure_non_empty(supply_commitment_root, "supply_commitment_root")?;
        ensure_non_empty(policy_root, "policy_root")?;
        if supply_disclosure.requires_auditor_root() {
            ensure_non_empty(auditor_set_root, "auditor_set_root")?;
        }
        let token_id = confidential_token_class_id(
            symbol_commitment,
            metadata_commitment,
            issuer_commitment,
            height,
        );
        Ok(Self {
            token_id,
            symbol_commitment: symbol_commitment.to_string(),
            metadata_commitment: metadata_commitment.to_string(),
            issuer_commitment: issuer_commitment.to_string(),
            token_kind,
            status: ConfidentialTokenStatus::Draft,
            supply_disclosure,
            supply_commitment_root: supply_commitment_root.to_string(),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            auditor_set_root: auditor_set_root.to_string(),
            policy_root: policy_root.to_string(),
            created_at_height: height,
            updated_at_height: height,
            low_fee_eligible: token_kind.supports_defi(),
            defi_enabled: token_kind.supports_defi(),
            disclosure_bps: 0,
        })
    }

    pub fn activate(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if self.status.is_terminal() {
            return Err("retired token class cannot be activated".to_string());
        }
        self.status = ConfidentialTokenStatus::Active;
        self.updated_at_height = height;
        Ok(())
    }

    pub fn set_status(
        &mut self,
        status: ConfidentialTokenStatus,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<()> {
        if self.status.is_terminal() && status != ConfidentialTokenStatus::Retired {
            return Err("retired token class cannot transition".to_string());
        }
        self.status = status;
        self.updated_at_height = height;
        Ok(())
    }

    pub fn set_disclosure_bps(
        &mut self,
        disclosure_bps: u64,
    ) -> ConfidentialTokenIndexerResult<()> {
        ensure_bps(disclosure_bps, "disclosure_bps")?;
        self.disclosure_bps = disclosure_bps;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_class_summary",
            "chain_id": CHAIN_ID,
            "token_id": self.token_id,
            "symbol_commitment": self.symbol_commitment,
            "metadata_commitment": self.metadata_commitment,
            "issuer_commitment": self.issuer_commitment,
            "token_kind": self.token_kind.as_str(),
            "status": self.status.as_str(),
            "supply_disclosure": self.supply_disclosure.as_str(),
            "supply_commitment_root": self.supply_commitment_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "auditor_set_root": self.auditor_set_root,
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "low_fee_eligible": self.low_fee_eligible,
            "defi_enabled": self.defi_enabled,
            "disclosure_bps": self.disclosure_bps,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.token_id, "token_id")?;
        ensure_non_empty(&self.symbol_commitment, "symbol_commitment")?;
        ensure_non_empty(&self.metadata_commitment, "metadata_commitment")?;
        ensure_non_empty(&self.issuer_commitment, "issuer_commitment")?;
        ensure_non_empty(&self.supply_commitment_root, "supply_commitment_root")?;
        ensure_non_empty(&self.policy_root, "policy_root")?;
        ensure_height_range(
            self.created_at_height,
            self.updated_at_height,
            "token_class_summary",
        )?;
        ensure_bps(self.disclosure_bps, "disclosure_bps")?;
        if self.supply_disclosure.requires_auditor_root() {
            ensure_non_empty(&self.auditor_set_root, "auditor_set_root")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTransferIndexEntry {
    pub transfer_id: String,
    pub token_id: String,
    pub batch_id: String,
    pub source_commitment_root: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub amount_bucket_commitment: String,
    pub sender_view_tag: String,
    pub receiver_view_tag: String,
    pub status: ShieldedTransferStatus,
    pub indexed_at_height: u64,
    pub settled_at_height: u64,
    pub sponsor_grant_id: String,
    pub contract_event_ids: BTreeSet<String>,
}

impl ShieldedTransferIndexEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: &str,
        batch_id: &str,
        source_commitment_root: &str,
        output_commitment_root: &str,
        nullifier_root: &str,
        amount_bucket_commitment: &str,
        sender_view_tag: &str,
        receiver_view_tag: &str,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(token_id, "token_id")?;
        ensure_non_empty(batch_id, "batch_id")?;
        ensure_non_empty(source_commitment_root, "source_commitment_root")?;
        ensure_non_empty(output_commitment_root, "output_commitment_root")?;
        ensure_non_empty(nullifier_root, "nullifier_root")?;
        ensure_non_empty(amount_bucket_commitment, "amount_bucket_commitment")?;
        ensure_non_empty(sender_view_tag, "sender_view_tag")?;
        ensure_non_empty(receiver_view_tag, "receiver_view_tag")?;
        let transfer_id = shielded_transfer_index_id(
            token_id,
            batch_id,
            source_commitment_root,
            output_commitment_root,
            nullifier_root,
            height,
        );
        Ok(Self {
            transfer_id,
            token_id: token_id.to_string(),
            batch_id: batch_id.to_string(),
            source_commitment_root: source_commitment_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            amount_bucket_commitment: amount_bucket_commitment.to_string(),
            sender_view_tag: sender_view_tag.to_string(),
            receiver_view_tag: receiver_view_tag.to_string(),
            status: ShieldedTransferStatus::Pending,
            indexed_at_height: height,
            settled_at_height: 0,
            sponsor_grant_id: String::new(),
            contract_event_ids: BTreeSet::new(),
        })
    }

    pub fn settle(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if self.status.final_status() {
            return Err("finalized transfer cannot settle again".to_string());
        }
        if height < self.indexed_at_height {
            return Err("settlement height cannot precede indexed height".to_string());
        }
        self.status = ShieldedTransferStatus::Settled;
        self.settled_at_height = height;
        Ok(())
    }

    pub fn attach_sponsor(&mut self, sponsor_grant_id: &str) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(sponsor_grant_id, "sponsor_grant_id")?;
        self.sponsor_grant_id = sponsor_grant_id.to_string();
        Ok(())
    }

    pub fn attach_contract_event(&mut self, event_id: &str) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(event_id, "event_id")?;
        self.contract_event_ids.insert(event_id.to_string());
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_transfer_index_entry",
            "chain_id": CHAIN_ID,
            "transfer_id": self.transfer_id,
            "token_id": self.token_id,
            "batch_id": self.batch_id,
            "source_commitment_root": self.source_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_root": self.nullifier_root,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "sender_view_tag": self.sender_view_tag,
            "receiver_view_tag": self.receiver_view_tag,
            "status": self.status.as_str(),
            "indexed_at_height": self.indexed_at_height,
            "settled_at_height": self.settled_at_height,
            "sponsor_grant_id": self.sponsor_grant_id,
            "contract_event_ids": self.contract_event_ids.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.transfer_id, "transfer_id")?;
        ensure_non_empty(&self.token_id, "token_id")?;
        ensure_non_empty(&self.batch_id, "batch_id")?;
        ensure_non_empty(&self.source_commitment_root, "source_commitment_root")?;
        ensure_non_empty(&self.output_commitment_root, "output_commitment_root")?;
        ensure_non_empty(&self.nullifier_root, "nullifier_root")?;
        ensure_non_empty(&self.amount_bucket_commitment, "amount_bucket_commitment")?;
        ensure_non_empty(&self.sender_view_tag, "sender_view_tag")?;
        ensure_non_empty(&self.receiver_view_tag, "receiver_view_tag")?;
        if self.settled_at_height > 0 {
            ensure_height_range(
                self.indexed_at_height,
                self.settled_at_height,
                "shielded_transfer",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierIndexEntry {
    pub nullifier_id: String,
    pub nullifier_commitment: String,
    pub token_id: String,
    pub transfer_id: String,
    pub shard_id: String,
    pub status: NullifierStatus,
    pub observed_at_height: u64,
    pub consumed_at_height: u64,
    pub witness_root: String,
}

impl NullifierIndexEntry {
    pub fn new(
        nullifier_commitment: &str,
        token_id: &str,
        transfer_id: &str,
        shard_id: &str,
        witness_root: &str,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(nullifier_commitment, "nullifier_commitment")?;
        ensure_non_empty(token_id, "token_id")?;
        ensure_non_empty(transfer_id, "transfer_id")?;
        ensure_non_empty(shard_id, "shard_id")?;
        ensure_non_empty(witness_root, "witness_root")?;
        let nullifier_id = nullifier_index_id(
            nullifier_commitment,
            token_id,
            transfer_id,
            shard_id,
            height,
        );
        Ok(Self {
            nullifier_id,
            nullifier_commitment: nullifier_commitment.to_string(),
            token_id: token_id.to_string(),
            transfer_id: transfer_id.to_string(),
            shard_id: shard_id.to_string(),
            status: NullifierStatus::Observed,
            observed_at_height: height,
            consumed_at_height: 0,
            witness_root: witness_root.to_string(),
        })
    }

    pub fn consume(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if matches!(self.status, NullifierStatus::Consumed) {
            return Err("nullifier already consumed".to_string());
        }
        if height < self.observed_at_height {
            return Err("consumed height cannot precede observed height".to_string());
        }
        self.status = NullifierStatus::Consumed;
        self.consumed_at_height = height;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier_index_entry",
            "chain_id": CHAIN_ID,
            "nullifier_id": self.nullifier_id,
            "nullifier_commitment": self.nullifier_commitment,
            "token_id": self.token_id,
            "transfer_id": self.transfer_id,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
            "consumed_at_height": self.consumed_at_height,
            "witness_root": self.witness_root,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.nullifier_id, "nullifier_id")?;
        ensure_non_empty(&self.nullifier_commitment, "nullifier_commitment")?;
        ensure_non_empty(&self.token_id, "token_id")?;
        ensure_non_empty(&self.transfer_id, "transfer_id")?;
        ensure_non_empty(&self.shard_id, "shard_id")?;
        ensure_non_empty(&self.witness_root, "witness_root")?;
        if self.consumed_at_height > 0 {
            ensure_height_range(
                self.observed_at_height,
                self.consumed_at_height,
                "nullifier_index",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEventCommitment {
    pub event_id: String,
    pub contract_id: String,
    pub token_id: String,
    pub event_kind: ContractEventKind,
    pub status: ContractEventStatus,
    pub event_commitment: String,
    pub topic_root: String,
    pub payload_root: String,
    pub disclosure_hint_root: String,
    pub emitted_at_height: u64,
    pub indexed_at_height: u64,
    pub sequence: u64,
}

impl ContractEventCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: &str,
        token_id: &str,
        event_kind: ContractEventKind,
        event_commitment: &str,
        topic_root: &str,
        payload_root: &str,
        disclosure_hint_root: &str,
        emitted_at_height: u64,
        indexed_at_height: u64,
        sequence: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(contract_id, "contract_id")?;
        ensure_non_empty(token_id, "token_id")?;
        ensure_non_empty(event_commitment, "event_commitment")?;
        ensure_non_empty(topic_root, "topic_root")?;
        ensure_non_empty(payload_root, "payload_root")?;
        ensure_non_empty(disclosure_hint_root, "disclosure_hint_root")?;
        ensure_height_range(
            emitted_at_height,
            indexed_at_height,
            "contract_event_commitment",
        )?;
        let event_id = contract_event_commitment_id(
            contract_id,
            token_id,
            event_kind.as_str(),
            event_commitment,
            sequence,
        );
        Ok(Self {
            event_id,
            contract_id: contract_id.to_string(),
            token_id: token_id.to_string(),
            event_kind,
            status: ContractEventStatus::Pending,
            event_commitment: event_commitment.to_string(),
            topic_root: topic_root.to_string(),
            payload_root: payload_root.to_string(),
            disclosure_hint_root: disclosure_hint_root.to_string(),
            emitted_at_height,
            indexed_at_height,
            sequence,
        })
    }

    pub fn mark_indexed(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if height < self.emitted_at_height {
            return Err("indexed height cannot precede emitted height".to_string());
        }
        self.status = ContractEventStatus::Indexed;
        self.indexed_at_height = height;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_event_commitment",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "contract_id": self.contract_id,
            "token_id": self.token_id,
            "event_kind": self.event_kind.as_str(),
            "status": self.status.as_str(),
            "event_commitment": self.event_commitment,
            "topic_root": self.topic_root,
            "payload_root": self.payload_root,
            "disclosure_hint_root": self.disclosure_hint_root,
            "emitted_at_height": self.emitted_at_height,
            "indexed_at_height": self.indexed_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.event_id, "event_id")?;
        ensure_non_empty(&self.contract_id, "contract_id")?;
        ensure_non_empty(&self.token_id, "token_id")?;
        ensure_non_empty(&self.event_commitment, "event_commitment")?;
        ensure_non_empty(&self.topic_root, "topic_root")?;
        ensure_non_empty(&self.payload_root, "payload_root")?;
        ensure_non_empty(&self.disclosure_hint_root, "disclosure_hint_root")?;
        ensure_height_range(
            self.emitted_at_height,
            self.indexed_at_height,
            "contract_event_commitment",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureView {
    pub view_id: String,
    pub subject_commitment: String,
    pub grantee_commitment: String,
    pub scope: DisclosureScope,
    pub status: DisclosureViewStatus,
    pub encrypted_view_root: String,
    pub redaction_policy_root: String,
    pub authorization_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub access_count: u64,
}

impl SelectiveDisclosureView {
    pub fn new(
        subject_commitment: &str,
        grantee_commitment: &str,
        scope: DisclosureScope,
        encrypted_view_root: &str,
        redaction_policy_root: &str,
        authorization_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(subject_commitment, "subject_commitment")?;
        ensure_non_empty(grantee_commitment, "grantee_commitment")?;
        ensure_non_empty(encrypted_view_root, "encrypted_view_root")?;
        ensure_non_empty(redaction_policy_root, "redaction_policy_root")?;
        ensure_non_empty(authorization_root, "authorization_root")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let view_id = selective_disclosure_view_id(
            subject_commitment,
            grantee_commitment,
            scope.as_str(),
            encrypted_view_root,
            opened_at_height,
        );
        Ok(Self {
            view_id,
            subject_commitment: subject_commitment.to_string(),
            grantee_commitment: grantee_commitment.to_string(),
            scope,
            status: DisclosureViewStatus::Requested,
            encrypted_view_root: encrypted_view_root.to_string(),
            redaction_policy_root: redaction_policy_root.to_string(),
            authorization_root: authorization_root.to_string(),
            opened_at_height,
            expires_at_height,
            access_count: 0,
        })
    }

    pub fn grant(&mut self) {
        self.status = DisclosureViewStatus::Granted;
    }

    pub fn open(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if height > self.expires_at_height {
            self.status = DisclosureViewStatus::Expired;
            return Err("disclosure view expired".to_string());
        }
        self.status = DisclosureViewStatus::Opened;
        self.access_count = self.access_count.saturating_add(1);
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = DisclosureViewStatus::Revoked;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_view",
            "chain_id": CHAIN_ID,
            "view_id": self.view_id,
            "subject_commitment": self.subject_commitment,
            "grantee_commitment": self.grantee_commitment,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "encrypted_view_root": self.encrypted_view_root,
            "redaction_policy_root": self.redaction_policy_root,
            "authorization_root": self.authorization_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "access_count": self.access_count,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.view_id, "view_id")?;
        ensure_non_empty(&self.subject_commitment, "subject_commitment")?;
        ensure_non_empty(&self.grantee_commitment, "grantee_commitment")?;
        ensure_non_empty(&self.encrypted_view_root, "encrypted_view_root")?;
        ensure_non_empty(&self.redaction_policy_root, "redaction_policy_root")?;
        ensure_non_empty(&self.authorization_root, "authorization_root")?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "selective_disclosure_view",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexingSponsorAccount {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorAccountStatus,
    pub budget_commitment_root: String,
    pub allowed_token_root: String,
    pub lane: String,
    pub unit_price: u64,
    pub remaining_units: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl IndexingSponsorAccount {
    pub fn new(
        sponsor_commitment: &str,
        budget_commitment_root: &str,
        allowed_token_root: &str,
        lane: &str,
        unit_price: u64,
        remaining_units: u64,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(budget_commitment_root, "budget_commitment_root")?;
        ensure_non_empty(allowed_token_root, "allowed_token_root")?;
        ensure_non_empty(lane, "lane")?;
        ensure_positive(unit_price, "unit_price")?;
        let sponsor_id =
            indexing_sponsor_account_id(sponsor_commitment, budget_commitment_root, lane, height);
        Ok(Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            status: SponsorAccountStatus::Active,
            budget_commitment_root: budget_commitment_root.to_string(),
            allowed_token_root: allowed_token_root.to_string(),
            lane: lane.to_string(),
            unit_price,
            remaining_units,
            opened_at_height: height,
            updated_at_height: height,
        })
    }

    pub fn allocate_units(
        &mut self,
        units: u64,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<()> {
        if !self.status.can_sponsor() {
            return Err("sponsor account cannot allocate units".to_string());
        }
        ensure_positive(units, "units")?;
        if units > self.remaining_units {
            self.status = SponsorAccountStatus::Exhausted;
            return Err("sponsor account has insufficient units".to_string());
        }
        self.remaining_units = self.remaining_units.saturating_sub(units);
        self.updated_at_height = height;
        if self.remaining_units == 0 {
            self.status = SponsorAccountStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexing_sponsor_account",
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "budget_commitment_root": self.budget_commitment_root,
            "allowed_token_root": self.allowed_token_root,
            "lane": self.lane,
            "unit_price": self.unit_price,
            "remaining_units": self.remaining_units,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.sponsor_id, "sponsor_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(&self.budget_commitment_root, "budget_commitment_root")?;
        ensure_non_empty(&self.allowed_token_root, "allowed_token_root")?;
        ensure_non_empty(&self.lane, "lane")?;
        ensure_positive(self.unit_price, "unit_price")?;
        ensure_height_range(
            self.opened_at_height,
            self.updated_at_height,
            "indexing_sponsor_account",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexingSponsorshipGrant {
    pub grant_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub token_id: String,
    pub transfer_batch_root: String,
    pub status: SponsorshipGrantStatus,
    pub allocated_units: u64,
    pub consumed_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl IndexingSponsorshipGrant {
    pub fn new(
        sponsor_id: &str,
        beneficiary_commitment: &str,
        token_id: &str,
        transfer_batch_root: &str,
        allocated_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(sponsor_id, "sponsor_id")?;
        ensure_non_empty(beneficiary_commitment, "beneficiary_commitment")?;
        ensure_non_empty(token_id, "token_id")?;
        ensure_non_empty(transfer_batch_root, "transfer_batch_root")?;
        ensure_positive(allocated_units, "allocated_units")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let grant_id = indexing_sponsorship_grant_id(
            sponsor_id,
            beneficiary_commitment,
            token_id,
            transfer_batch_root,
            opened_at_height,
        );
        Ok(Self {
            grant_id,
            sponsor_id: sponsor_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            token_id: token_id.to_string(),
            transfer_batch_root: transfer_batch_root.to_string(),
            status: SponsorshipGrantStatus::Open,
            allocated_units,
            consumed_units: 0,
            opened_at_height,
            expires_at_height,
        })
    }

    pub fn consume(&mut self, units: u64) -> ConfidentialTokenIndexerResult<()> {
        ensure_positive(units, "units")?;
        let next = self.consumed_units.saturating_add(units);
        if next > self.allocated_units {
            return Err("sponsorship grant consumption exceeds allocation".to_string());
        }
        self.consumed_units = next;
        self.status = if self.consumed_units == self.allocated_units {
            SponsorshipGrantStatus::Exhausted
        } else {
            SponsorshipGrantStatus::Allocated
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexing_sponsorship_grant",
            "chain_id": CHAIN_ID,
            "grant_id": self.grant_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "token_id": self.token_id,
            "transfer_batch_root": self.transfer_batch_root,
            "status": self.status.as_str(),
            "allocated_units": self.allocated_units,
            "consumed_units": self.consumed_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.grant_id, "grant_id")?;
        ensure_non_empty(&self.sponsor_id, "sponsor_id")?;
        ensure_non_empty(&self.beneficiary_commitment, "beneficiary_commitment")?;
        ensure_non_empty(&self.token_id, "token_id")?;
        ensure_non_empty(&self.transfer_batch_root, "transfer_batch_root")?;
        ensure_positive(self.allocated_units, "allocated_units")?;
        if self.consumed_units > self.allocated_units {
            return Err("consumed_units cannot exceed allocated_units".to_string());
        }
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "indexing_sponsorship_grant",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialIndexShard {
    pub shard_id: String,
    pub shard_index: u16,
    pub epoch: u64,
    pub status: IndexShardStatus,
    pub token_root: String,
    pub transfer_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

impl ConfidentialIndexShard {
    pub fn new(
        shard_index: u16,
        epoch: u64,
        token_root: &str,
        transfer_root: &str,
        nullifier_root: &str,
        event_root: &str,
        height: u64,
    ) -> ConfidentialTokenIndexerResult<Self> {
        ensure_non_empty(token_root, "token_root")?;
        ensure_non_empty(transfer_root, "transfer_root")?;
        ensure_non_empty(nullifier_root, "nullifier_root")?;
        ensure_non_empty(event_root, "event_root")?;
        let shard_id = confidential_index_shard_id(shard_index, epoch, token_root, height);
        Ok(Self {
            shard_id,
            shard_index,
            epoch,
            status: IndexShardStatus::Open,
            token_root: token_root.to_string(),
            transfer_root: transfer_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            event_root: event_root.to_string(),
            opened_at_height: height,
            sealed_at_height: 0,
        })
    }

    pub fn seal(&mut self, height: u64) -> ConfidentialTokenIndexerResult<()> {
        if height < self.opened_at_height {
            return Err("sealed height cannot precede opened height".to_string());
        }
        self.status = IndexShardStatus::Sealed;
        self.sealed_at_height = height;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_index_shard",
            "chain_id": CHAIN_ID,
            "shard_id": self.shard_id,
            "shard_index": self.shard_index,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "token_root": self.token_root,
            "transfer_root": self.transfer_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<()> {
        ensure_non_empty(&self.shard_id, "shard_id")?;
        ensure_non_empty(&self.token_root, "token_root")?;
        ensure_non_empty(&self.transfer_root, "transfer_root")?;
        ensure_non_empty(&self.nullifier_root, "nullifier_root")?;
        ensure_non_empty(&self.event_root, "event_root")?;
        if self.sealed_at_height > 0 {
            ensure_height_range(
                self.opened_at_height,
                self.sealed_at_height,
                "confidential_index_shard",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenIndexerRoots {
    pub config_root: String,
    pub token_class_root: String,
    pub transfer_index_root: String,
    pub nullifier_index_root: String,
    pub contract_event_root: String,
    pub disclosure_view_root: String,
    pub sponsor_account_root: String,
    pub sponsorship_grant_root: String,
    pub shard_root: String,
}

impl ConfidentialTokenIndexerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_indexer_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "token_class_root": self.token_class_root,
            "transfer_index_root": self.transfer_index_root,
            "nullifier_index_root": self.nullifier_index_root,
            "contract_event_root": self.contract_event_root,
            "disclosure_view_root": self.disclosure_view_root,
            "sponsor_account_root": self.sponsor_account_root,
            "sponsorship_grant_root": self.sponsorship_grant_root,
            "shard_root": self.shard_root,
        })
    }

    pub fn roots_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-ROOTS",
            &[self.public_record()],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenIndexerCounters {
    pub token_classes: usize,
    pub active_token_classes: usize,
    pub shielded_transfers: usize,
    pub settled_transfers: usize,
    pub nullifiers: usize,
    pub consumed_nullifiers: usize,
    pub contract_events: usize,
    pub active_disclosures: usize,
    pub sponsor_accounts: usize,
    pub active_sponsor_accounts: usize,
    pub sponsorship_grants: usize,
    pub open_shards: usize,
    pub sponsored_units_remaining: u64,
}

impl ConfidentialTokenIndexerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_indexer_counters",
            "chain_id": CHAIN_ID,
            "token_classes": self.token_classes,
            "active_token_classes": self.active_token_classes,
            "shielded_transfers": self.shielded_transfers,
            "settled_transfers": self.settled_transfers,
            "nullifiers": self.nullifiers,
            "consumed_nullifiers": self.consumed_nullifiers,
            "contract_events": self.contract_events,
            "active_disclosures": self.active_disclosures,
            "sponsor_accounts": self.sponsor_accounts,
            "active_sponsor_accounts": self.active_sponsor_accounts,
            "sponsorship_grants": self.sponsorship_grants,
            "open_shards": self.open_shards,
            "sponsored_units_remaining": self.sponsored_units_remaining,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenIndexerState {
    pub height: u64,
    pub config: ConfidentialTokenIndexerConfig,
    pub token_classes: BTreeMap<String, ConfidentialTokenClassSummary>,
    pub transfer_index: BTreeMap<String, ShieldedTransferIndexEntry>,
    pub nullifier_index: BTreeMap<String, NullifierIndexEntry>,
    pub contract_events: BTreeMap<String, ContractEventCommitment>,
    pub disclosure_views: BTreeMap<String, SelectiveDisclosureView>,
    pub sponsor_accounts: BTreeMap<String, IndexingSponsorAccount>,
    pub sponsorship_grants: BTreeMap<String, IndexingSponsorshipGrant>,
    pub shards: BTreeMap<String, ConfidentialIndexShard>,
}

impl ConfidentialTokenIndexerState {
    pub fn devnet() -> ConfidentialTokenIndexerResult<Self> {
        let config = ConfidentialTokenIndexerConfig::devnet();
        let height = CONFIDENTIAL_TOKEN_INDEXER_DEVNET_HEIGHT;
        let empty_root = confidential_token_indexer_empty_root("CONFIDENTIAL-TOKEN-INDEXER-EMPTY");
        let mut state = Self {
            height,
            config,
            token_classes: BTreeMap::new(),
            transfer_index: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            contract_events: BTreeMap::new(),
            disclosure_views: BTreeMap::new(),
            sponsor_accounts: BTreeMap::new(),
            sponsorship_grants: BTreeMap::new(),
            shards: BTreeMap::new(),
        };

        let mut wxmr = ConfidentialTokenClassSummary::new(
            "commit:symbol:pxmr",
            "commit:metadata:wrapped-monero",
            "commit:issuer:monero-bridge",
            ConfidentialTokenKind::WrappedMonero,
            ConfidentialSupplyDisclosure::ReserveBacked,
            "root:supply:pxmr",
            "root:reserve:monero-watchtower-set",
            "root:auditor:threshold-viewers",
            "root:policy:pxmr-private-defi",
            height.saturating_sub(24),
        )?;
        wxmr.activate(height.saturating_sub(20))?;
        wxmr.set_disclosure_bps(125)?;
        state.insert_token_class(wxmr)?;

        let mut stable = ConfidentialTokenClassSummary::new(
            "commit:symbol:pusd",
            "commit:metadata:private-usd",
            "commit:issuer:private-stablecoin-controller",
            ConfidentialTokenKind::Stablecoin,
            ConfidentialSupplyDisclosure::AuditorViewable,
            "root:supply:pusd",
            "",
            "root:auditor:stablecoin-committee",
            "root:policy:pusd-private-defi",
            height.saturating_sub(18),
        )?;
        stable.activate(height.saturating_sub(16))?;
        stable.set_disclosure_bps(250)?;
        state.insert_token_class(stable)?;

        let shard = ConfidentialIndexShard::new(
            0,
            state.current_epoch(),
            &state.token_class_root(),
            &state.transfer_index_root(),
            &state.nullifier_index_root(),
            &state.contract_event_root(),
            height,
        )?;
        state.insert_shard(shard)?;

        let sponsor = IndexingSponsorAccount::new(
            "commit:sponsor:devnet-public-goods",
            "root:budget:devnet-indexing",
            &state.token_class_root(),
            &state.config.sponsor_lane,
            state.config.sponsor_unit_price,
            state.config.low_fee_unit_cap,
            height,
        )?;
        state.insert_sponsor_account(sponsor)?;

        let view = SelectiveDisclosureView::new(
            "commit:subject:devnet-audit-window",
            "commit:grantee:threshold-auditor-set",
            DisclosureScope::AuditBundle,
            &empty_root,
            "root:redaction:devnet-audit-minimal",
            "root:authorization:devnet-auditors",
            height,
            state.config.disclosure_ttl_blocks,
        )?;
        state.insert_disclosure_view(view)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn current_epoch(&self) -> u64 {
        if self.config.epoch_blocks == 0 {
            return 0;
        }
        self.height / self.config.epoch_blocks
    }

    pub fn roots(&self) -> ConfidentialTokenIndexerRoots {
        ConfidentialTokenIndexerRoots {
            config_root: confidential_token_indexer_record_root(
                "CONFIDENTIAL-TOKEN-INDEXER-CONFIG",
                &[self.config.public_record()],
            ),
            token_class_root: self.token_class_root(),
            transfer_index_root: self.transfer_index_root(),
            nullifier_index_root: self.nullifier_index_root(),
            contract_event_root: self.contract_event_root(),
            disclosure_view_root: self.disclosure_view_root(),
            sponsor_account_root: self.sponsor_account_root(),
            sponsorship_grant_root: self.sponsorship_grant_root(),
            shard_root: self.shard_root(),
        }
    }

    pub fn counters(&self) -> ConfidentialTokenIndexerCounters {
        ConfidentialTokenIndexerCounters {
            token_classes: self.token_classes.len(),
            active_token_classes: self
                .token_classes
                .values()
                .filter(|entry| entry.status.indexable())
                .count(),
            shielded_transfers: self.transfer_index.len(),
            settled_transfers: self
                .transfer_index
                .values()
                .filter(|entry| entry.status == ShieldedTransferStatus::Settled)
                .count(),
            nullifiers: self.nullifier_index.len(),
            consumed_nullifiers: self
                .nullifier_index
                .values()
                .filter(|entry| entry.status == NullifierStatus::Consumed)
                .count(),
            contract_events: self.contract_events.len(),
            active_disclosures: self
                .disclosure_views
                .values()
                .filter(|entry| entry.status.active())
                .count(),
            sponsor_accounts: self.sponsor_accounts.len(),
            active_sponsor_accounts: self
                .sponsor_accounts
                .values()
                .filter(|entry| entry.status.can_sponsor())
                .count(),
            sponsorship_grants: self.sponsorship_grants.len(),
            open_shards: self
                .shards
                .values()
                .filter(|entry| entry.status.accepts_records())
                .count(),
            sponsored_units_remaining: self
                .sponsor_accounts
                .values()
                .map(|entry| entry.remaining_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_token_indexer_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "current_epoch": self.current_epoch(),
            "protocol_version": self.config.protocol_version,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        confidential_token_indexer_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> ConfidentialTokenIndexerResult<String> {
        self.config.validate()?;
        for token_class in self.token_classes.values() {
            token_class.validate()?;
        }
        for transfer in self.transfer_index.values() {
            transfer.validate()?;
            if !self.token_classes.contains_key(&transfer.token_id) {
                return Err(format!(
                    "transfer {} references unknown token {}",
                    transfer.transfer_id, transfer.token_id
                ));
            }
            if self.transfer_index.len() > self.config.max_transfers_per_batch {
                return Err("transfer index exceeds max_transfers_per_batch".to_string());
            }
        }
        for nullifier in self.nullifier_index.values() {
            nullifier.validate()?;
            if !self.transfer_index.contains_key(&nullifier.transfer_id) {
                return Err(format!(
                    "nullifier {} references unknown transfer {}",
                    nullifier.nullifier_id, nullifier.transfer_id
                ));
            }
        }
        for event in self.contract_events.values() {
            event.validate()?;
            if !self.token_classes.contains_key(&event.token_id) {
                return Err(format!(
                    "contract event {} references unknown token {}",
                    event.event_id, event.token_id
                ));
            }
            let event_count = self
                .contract_events
                .values()
                .filter(|candidate| candidate.contract_id == event.contract_id)
                .count();
            if event_count > self.config.max_events_per_contract {
                return Err(format!(
                    "contract {} exceeds max_events_per_contract",
                    event.contract_id
                ));
            }
        }
        for view in self.disclosure_views.values() {
            view.validate()?;
            let view_count = self
                .disclosure_views
                .values()
                .filter(|candidate| candidate.subject_commitment == view.subject_commitment)
                .count();
            if view_count > self.config.max_disclosures_per_subject {
                return Err(format!(
                    "subject {} exceeds max_disclosures_per_subject",
                    view.subject_commitment
                ));
            }
        }
        for account in self.sponsor_accounts.values() {
            account.validate()?;
        }
        for grant in self.sponsorship_grants.values() {
            grant.validate()?;
            if !self.sponsor_accounts.contains_key(&grant.sponsor_id) {
                return Err(format!(
                    "grant {} references unknown sponsor {}",
                    grant.grant_id, grant.sponsor_id
                ));
            }
        }
        for shard in self.shards.values() {
            shard.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn insert_token_class(
        &mut self,
        token_class: ConfidentialTokenClassSummary,
    ) -> ConfidentialTokenIndexerResult<String> {
        token_class.validate()?;
        let token_id = token_class.token_id.clone();
        self.token_classes.insert(token_id.clone(), token_class);
        Ok(token_id)
    }

    pub fn insert_transfer(
        &mut self,
        transfer: ShieldedTransferIndexEntry,
    ) -> ConfidentialTokenIndexerResult<String> {
        transfer.validate()?;
        if !self.token_classes.contains_key(&transfer.token_id) {
            return Err("cannot insert transfer for unknown token".to_string());
        }
        if self.transfer_index.len() >= self.config.max_transfers_per_batch {
            return Err("cannot insert transfer beyond max_transfers_per_batch".to_string());
        }
        let transfer_id = transfer.transfer_id.clone();
        self.transfer_index.insert(transfer_id.clone(), transfer);
        Ok(transfer_id)
    }

    pub fn insert_nullifier(
        &mut self,
        nullifier: NullifierIndexEntry,
    ) -> ConfidentialTokenIndexerResult<String> {
        nullifier.validate()?;
        if !self.transfer_index.contains_key(&nullifier.transfer_id) {
            return Err("cannot insert nullifier for unknown transfer".to_string());
        }
        if self
            .nullifier_index
            .values()
            .any(|entry| entry.nullifier_commitment == nullifier.nullifier_commitment)
        {
            return Err("duplicate nullifier commitment".to_string());
        }
        let nullifier_id = nullifier.nullifier_id.clone();
        self.nullifier_index.insert(nullifier_id.clone(), nullifier);
        Ok(nullifier_id)
    }

    pub fn insert_contract_event(
        &mut self,
        event: ContractEventCommitment,
    ) -> ConfidentialTokenIndexerResult<String> {
        event.validate()?;
        if !self.token_classes.contains_key(&event.token_id) {
            return Err("cannot insert contract event for unknown token".to_string());
        }
        let event_count = self
            .contract_events
            .values()
            .filter(|candidate| candidate.contract_id == event.contract_id)
            .count();
        if event_count >= self.config.max_events_per_contract {
            return Err("cannot insert contract event beyond max_events_per_contract".to_string());
        }
        let event_id = event.event_id.clone();
        self.contract_events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn insert_disclosure_view(
        &mut self,
        view: SelectiveDisclosureView,
    ) -> ConfidentialTokenIndexerResult<String> {
        view.validate()?;
        let view_count = self
            .disclosure_views
            .values()
            .filter(|candidate| candidate.subject_commitment == view.subject_commitment)
            .count();
        if view_count >= self.config.max_disclosures_per_subject {
            return Err("cannot insert disclosure beyond max_disclosures_per_subject".to_string());
        }
        let view_id = view.view_id.clone();
        self.disclosure_views.insert(view_id.clone(), view);
        Ok(view_id)
    }

    pub fn insert_sponsor_account(
        &mut self,
        account: IndexingSponsorAccount,
    ) -> ConfidentialTokenIndexerResult<String> {
        account.validate()?;
        let sponsor_id = account.sponsor_id.clone();
        self.sponsor_accounts.insert(sponsor_id.clone(), account);
        Ok(sponsor_id)
    }

    pub fn insert_sponsorship_grant(
        &mut self,
        grant: IndexingSponsorshipGrant,
    ) -> ConfidentialTokenIndexerResult<String> {
        grant.validate()?;
        if !self.sponsor_accounts.contains_key(&grant.sponsor_id) {
            return Err("cannot insert grant for unknown sponsor".to_string());
        }
        let grant_id = grant.grant_id.clone();
        self.sponsorship_grants.insert(grant_id.clone(), grant);
        Ok(grant_id)
    }

    pub fn insert_shard(
        &mut self,
        shard: ConfidentialIndexShard,
    ) -> ConfidentialTokenIndexerResult<String> {
        shard.validate()?;
        let shard_id = shard.shard_id.clone();
        self.shards.insert(shard_id.clone(), shard);
        Ok(shard_id)
    }

    pub fn token_class(&self, token_id: &str) -> Option<&ConfidentialTokenClassSummary> {
        self.token_classes.get(token_id)
    }

    pub fn transfer(&self, transfer_id: &str) -> Option<&ShieldedTransferIndexEntry> {
        self.transfer_index.get(transfer_id)
    }

    pub fn nullifier_by_commitment(
        &self,
        nullifier_commitment: &str,
    ) -> Option<&NullifierIndexEntry> {
        self.nullifier_index
            .values()
            .find(|entry| entry.nullifier_commitment == nullifier_commitment)
    }

    pub fn active_disclosure_views_for_subject(
        &self,
        subject_commitment: &str,
    ) -> Vec<SelectiveDisclosureView> {
        self.disclosure_views
            .values()
            .filter(|entry| entry.subject_commitment == subject_commitment && entry.status.active())
            .cloned()
            .collect()
    }

    pub fn sponsored_transfers(&self) -> Vec<ShieldedTransferIndexEntry> {
        self.transfer_index
            .values()
            .filter(|entry| !entry.sponsor_grant_id.is_empty())
            .cloned()
            .collect()
    }

    fn token_class_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-TOKEN-CLASS-SET",
            &self
                .token_classes
                .values()
                .map(ConfidentialTokenClassSummary::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn transfer_index_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-TRANSFER-SET",
            &self
                .transfer_index
                .values()
                .map(ShieldedTransferIndexEntry::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn nullifier_index_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-NULLIFIER-SET",
            &self
                .nullifier_index
                .values()
                .map(NullifierIndexEntry::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn contract_event_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-CONTRACT-EVENT-SET",
            &self
                .contract_events
                .values()
                .map(ContractEventCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn disclosure_view_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-DISCLOSURE-VIEW-SET",
            &self
                .disclosure_views
                .values()
                .map(SelectiveDisclosureView::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn sponsor_account_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-SPONSOR-ACCOUNT-SET",
            &self
                .sponsor_accounts
                .values()
                .map(IndexingSponsorAccount::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn sponsorship_grant_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-SPONSORSHIP-GRANT-SET",
            &self
                .sponsorship_grants
                .values()
                .map(IndexingSponsorshipGrant::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn shard_root(&self) -> String {
        confidential_token_indexer_record_root(
            "CONFIDENTIAL-TOKEN-INDEXER-SHARD-SET",
            &self
                .shards
                .values()
                .map(ConfidentialIndexShard::public_record)
                .collect::<Vec<_>>(),
        )
    }
}

pub fn confidential_token_indexer_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-INDEXER-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn confidential_token_indexer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn confidential_token_indexer_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_TOKEN_INDEXER_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn confidential_token_indexer_string_set_root(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String(confidential_token_indexer_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn confidential_token_indexer_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn confidential_token_indexer_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn confidential_token_class_id(
    symbol_commitment: &str,
    metadata_commitment: &str,
    issuer_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(symbol_commitment),
            HashPart::Str(metadata_commitment),
            HashPart::Str(issuer_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn shielded_transfer_index_id(
    token_id: &str,
    batch_id: &str,
    source_commitment_root: &str,
    output_commitment_root: &str,
    nullifier_root: &str,
    indexed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-SHIELDED-TRANSFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(token_id),
            HashPart::Str(batch_id),
            HashPart::Str(source_commitment_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(indexed_at_height as i128),
        ],
        32,
    )
}

pub fn nullifier_index_id(
    nullifier_commitment: &str,
    token_id: &str,
    transfer_id: &str,
    shard_id: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier_commitment),
            HashPart::Str(token_id),
            HashPart::Str(transfer_id),
            HashPart::Str(shard_id),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn contract_event_commitment_id(
    contract_id: &str,
    token_id: &str,
    event_kind: &str,
    event_commitment: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-CONTRACT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(token_id),
            HashPart::Str(event_kind),
            HashPart::Str(event_commitment),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn selective_disclosure_view_id(
    subject_commitment: &str,
    grantee_commitment: &str,
    scope: &str,
    encrypted_view_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-DISCLOSURE-VIEW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(grantee_commitment),
            HashPart::Str(scope),
            HashPart::Str(encrypted_view_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn indexing_sponsor_account_id(
    sponsor_commitment: &str,
    budget_commitment_root: &str,
    lane: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-INDEXING-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(budget_commitment_root),
            HashPart::Str(lane),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn indexing_sponsorship_grant_id(
    sponsor_id: &str,
    beneficiary_commitment: &str,
    token_id: &str,
    transfer_batch_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-INDEXING-SPONSORSHIP-GRANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(token_id),
            HashPart::Str(transfer_batch_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_index_shard_id(
    shard_index: u16,
    epoch: u64,
    token_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-INDEX-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_index as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(token_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialTokenIndexerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> ConfidentialTokenIndexerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialTokenIndexerResult<()> {
    if value > CONFIDENTIAL_TOKEN_INDEXER_MAX_BPS {
        return Err(format!("{label} cannot exceed 10000 bps"));
    }
    Ok(())
}

fn ensure_height_range(start: u64, end: u64, label: &str) -> ConfidentialTokenIndexerResult<()> {
    if start > end {
        return Err(format!("{label} start height cannot exceed end height"));
    }
    Ok(())
}
