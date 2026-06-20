use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateStateRentMarketResult<T> = Result<T, String>;

pub const PRIVATE_STATE_RENT_MARKET_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_STATE_RENT_MARKET_PROTOCOL_LABEL: &str = "nebula-private-state-rent-market-v1";
pub const PRIVATE_STATE_RENT_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_STATE_RENT_MARKET_DEVNET_HEIGHT: u64 = 1_280;
pub const PRIVATE_STATE_RENT_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_STATE_RENT_MARKET_PQ_AUTH_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-state-rent";
pub const PRIVATE_STATE_RENT_MARKET_ENCRYPTION_SUITE: &str =
    "ml-kem-768+sealed-private-state-lease-v1";
pub const PRIVATE_STATE_RENT_MARKET_WITNESS_SCHEME: &str =
    "private-state-witness-availability-escrow-v1";
pub const PRIVATE_STATE_RENT_MARKET_ARCHIVE_SCHEME: &str = "shake256-archive-retrieval-proof-v1";
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_GRACE_BLOCKS: u64 = 144;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_RETENTION_BLOCKS: u64 = 43_200;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_RENT_PER_KIB_UNITS: u64 = 2;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_250;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_SUBSIDY_POOL_UNITS: u64 = 350_000;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_MIN_LEASE_BOND_UNITS: u64 = 4_000;
pub const PRIVATE_STATE_RENT_MARKET_DEFAULT_ARCHIVE_REWARD_UNITS: u64 = 250;
pub const PRIVATE_STATE_RENT_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    HotContract,
    WarmContract,
    ColdArchive,
    BridgeWitness,
    ProofArtifact,
    GovernanceRecord,
    EmergencyRecovery,
}

impl StorageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotContract => "hot_contract",
            Self::WarmContract => "warm_contract",
            Self::ColdArchive => "cold_archive",
            Self::BridgeWitness => "bridge_witness",
            Self::ProofArtifact => "proof_artifact",
            Self::GovernanceRecord => "governance_record",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn rent_multiplier_bps(self) -> u64 {
        match self {
            Self::HotContract => 15_000,
            Self::WarmContract => 10_000,
            Self::ColdArchive => 3_000,
            Self::BridgeWitness => 8_500,
            Self::ProofArtifact => 6_000,
            Self::GovernanceRecord => 2_500,
            Self::EmergencyRecovery => 1_000,
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 100,
            Self::BridgeWitness => 92,
            Self::HotContract => 88,
            Self::ProofArtifact => 76,
            Self::WarmContract => 70,
            Self::GovernanceRecord => 55,
            Self::ColdArchive => 35,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Requested,
    Active,
    Subsidized,
    Grace,
    Auctioning,
    Archived,
    Evicted,
    Recovered,
    Cancelled,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Subsidized => "subsidized",
            Self::Grace => "grace",
            Self::Auctioning => "auctioning",
            Self::Archived => "archived",
            Self::Evicted => "evicted",
            Self::Recovered => "recovered",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Active | Self::Subsidized | Self::Grace | Self::Auctioning
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Matched,
    Sponsored,
    Settled,
    Failed,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessEscrowStatus {
    Pending,
    Locked,
    Available,
    Challenged,
    Released,
    Slashed,
    Expired,
}

impl WitnessEscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Locked => "locked",
            Self::Available => "available",
            Self::Challenged => "challenged",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Locked | Self::Available | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveProofStatus {
    Pending,
    Verified,
    RetrievalReady,
    Challenged,
    Paid,
    Rejected,
    Expired,
}

impl ArchiveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::RetrievalReady => "retrieval_ready",
            Self::Challenged => "challenged",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateRentMarketConfig {
    pub epoch_blocks: u64,
    pub grace_blocks: u64,
    pub auction_window_blocks: u64,
    pub retention_blocks: u64,
    pub rent_per_kib_units: u64,
    pub low_fee_rebate_bps: u64,
    pub subsidy_pool_units: u64,
    pub min_lease_bond_units: u64,
    pub archive_reward_units: u64,
    pub pq_auth_suite: String,
    pub encryption_suite: String,
    pub witness_scheme: String,
    pub archive_scheme: String,
}

impl PrivateStateRentMarketConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_STATE_RENT_MARKET_DEFAULT_EPOCH_BLOCKS,
            grace_blocks: PRIVATE_STATE_RENT_MARKET_DEFAULT_GRACE_BLOCKS,
            auction_window_blocks: PRIVATE_STATE_RENT_MARKET_DEFAULT_AUCTION_WINDOW_BLOCKS,
            retention_blocks: PRIVATE_STATE_RENT_MARKET_DEFAULT_RETENTION_BLOCKS,
            rent_per_kib_units: PRIVATE_STATE_RENT_MARKET_DEFAULT_RENT_PER_KIB_UNITS,
            low_fee_rebate_bps: PRIVATE_STATE_RENT_MARKET_DEFAULT_LOW_FEE_REBATE_BPS,
            subsidy_pool_units: PRIVATE_STATE_RENT_MARKET_DEFAULT_SUBSIDY_POOL_UNITS,
            min_lease_bond_units: PRIVATE_STATE_RENT_MARKET_DEFAULT_MIN_LEASE_BOND_UNITS,
            archive_reward_units: PRIVATE_STATE_RENT_MARKET_DEFAULT_ARCHIVE_REWARD_UNITS,
            pq_auth_suite: PRIVATE_STATE_RENT_MARKET_PQ_AUTH_SUITE.to_string(),
            encryption_suite: PRIVATE_STATE_RENT_MARKET_ENCRYPTION_SUITE.to_string(),
            witness_scheme: PRIVATE_STATE_RENT_MARKET_WITNESS_SCHEME.to_string(),
            archive_scheme: PRIVATE_STATE_RENT_MARKET_ARCHIVE_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "grace_blocks": self.grace_blocks,
            "auction_window_blocks": self.auction_window_blocks,
            "retention_blocks": self.retention_blocks,
            "rent_per_kib_units": self.rent_per_kib_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "subsidy_pool_units": self.subsidy_pool_units,
            "min_lease_bond_units": self.min_lease_bond_units,
            "archive_reward_units": self.archive_reward_units,
            "pq_auth_suite": self.pq_auth_suite,
            "encryption_suite": self.encryption_suite,
            "witness_scheme": self.witness_scheme,
            "archive_scheme": self.archive_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        rent_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateStateRentMarketResult<()> {
        if self.epoch_blocks == 0
            || self.grace_blocks == 0
            || self.auction_window_blocks == 0
            || self.retention_blocks == 0
            || self.rent_per_kib_units == 0
            || self.min_lease_bond_units == 0
        {
            return Err("state rent config windows and economics must be positive".to_string());
        }
        if self.low_fee_rebate_bps > PRIVATE_STATE_RENT_MARKET_MAX_BPS {
            return Err("state rent low fee rebate exceeds maximum bps".to_string());
        }
        if self.pq_auth_suite.is_empty()
            || self.encryption_suite.is_empty()
            || self.witness_scheme.is_empty()
            || self.archive_scheme.is_empty()
        {
            return Err("state rent cryptographic suite identifiers cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStateLease {
    pub lease_id: String,
    pub contract_commitment: String,
    pub tenant_commitment: String,
    pub storage_class: StorageClass,
    pub encrypted_state_root: String,
    pub state_witness_root: String,
    pub size_kib: u64,
    pub paid_through_height: u64,
    pub grace_until_height: u64,
    pub bond_units: u64,
    pub rent_due_units: u64,
    pub status: LeaseStatus,
    pub pq_authorization_root: String,
    pub metadata_root: String,
}

impl EncryptedStateLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_label: &str,
        tenant_label: &str,
        storage_class: StorageClass,
        size_kib: u64,
        start_height: u64,
        prepaid_epochs: u64,
        bond_units: u64,
        config: &PrivateStateRentMarketConfig,
        metadata: &Value,
    ) -> Self {
        let contract_commitment = rent_hash("CONTRACT", &[HashPart::Str(contract_label)]);
        let tenant_commitment = rent_hash("TENANT", &[HashPart::Str(tenant_label)]);
        let encrypted_state_root = rent_hash(
            "ENCRYPTED-STATE",
            &[
                HashPart::Str(contract_label),
                HashPart::Str(tenant_label),
                HashPart::Str(storage_class.as_str()),
                HashPart::Int(size_kib as i128),
            ],
        );
        let state_witness_root = rent_hash(
            "STATE-WITNESS",
            &[
                HashPart::Str(&encrypted_state_root),
                HashPart::Str(config.witness_scheme.as_str()),
            ],
        );
        let paid_through_height =
            start_height.saturating_add(prepaid_epochs.saturating_mul(config.epoch_blocks));
        let rent_due_units = rent_due_units(size_kib, storage_class, config);
        let pq_authorization_root = rent_hash(
            "PQ-AUTH",
            &[
                HashPart::Str(&contract_commitment),
                HashPart::Str(&tenant_commitment),
                HashPart::Str(config.pq_auth_suite.as_str()),
            ],
        );
        let metadata_root = rent_hash("LEASE-METADATA", &[HashPart::Json(metadata)]);
        let lease_id = rent_hash(
            "LEASE-ID",
            &[
                HashPart::Str(&contract_commitment),
                HashPart::Str(&tenant_commitment),
                HashPart::Str(storage_class.as_str()),
                HashPart::Int(start_height as i128),
                HashPart::Str(&metadata_root),
            ],
        );
        Self {
            lease_id,
            contract_commitment,
            tenant_commitment,
            storage_class,
            encrypted_state_root,
            state_witness_root,
            size_kib,
            paid_through_height,
            grace_until_height: paid_through_height.saturating_add(config.grace_blocks),
            bond_units: bond_units.max(config.min_lease_bond_units),
            rent_due_units,
            status: LeaseStatus::Active,
            pq_authorization_root,
            metadata_root,
        }
    }

    pub fn with_status(mut self, status: LeaseStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "contract_commitment": self.contract_commitment,
            "tenant_commitment": self.tenant_commitment,
            "storage_class": self.storage_class.as_str(),
            "encrypted_state_root": self.encrypted_state_root,
            "state_witness_root": self.state_witness_root,
            "size_kib": self.size_kib,
            "paid_through_height": self.paid_through_height,
            "grace_until_height": self.grace_until_height,
            "bond_units": self.bond_units,
            "rent_due_units": self.rent_due_units,
            "status": self.status.as_str(),
            "pq_authorization_root": self.pq_authorization_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash("LEASE", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live(&self) -> bool {
        self.status.is_live()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessEscrow {
    pub escrow_id: String,
    pub lease_id: String,
    pub provider_commitment: String,
    pub witness_root: String,
    pub retention_until_height: u64,
    pub bond_units: u64,
    pub status: WitnessEscrowStatus,
    pub retrieval_policy_root: String,
}

impl StateWitnessEscrow {
    pub fn new(
        lease: &EncryptedStateLease,
        provider_label: &str,
        height: u64,
        bond_units: u64,
        config: &PrivateStateRentMarketConfig,
        policy: &Value,
    ) -> Self {
        let provider_commitment = rent_hash("WITNESS-PROVIDER", &[HashPart::Str(provider_label)]);
        let retrieval_policy_root = rent_hash("RETRIEVAL-POLICY", &[HashPart::Json(policy)]);
        let escrow_id = rent_hash(
            "WITNESS-ESCROW-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Str(&provider_commitment),
                HashPart::Str(&lease.state_witness_root),
            ],
        );
        Self {
            escrow_id,
            lease_id: lease.lease_id.clone(),
            provider_commitment,
            witness_root: lease.state_witness_root.clone(),
            retention_until_height: height.saturating_add(config.retention_blocks),
            bond_units,
            status: WitnessEscrowStatus::Locked,
            retrieval_policy_root,
        }
    }

    pub fn with_status(mut self, status: WitnessEscrowStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "lease_id": self.lease_id,
            "provider_commitment": self.provider_commitment,
            "witness_root": self.witness_root,
            "retention_until_height": self.retention_until_height,
            "bond_units": self.bond_units,
            "status": self.status.as_str(),
            "retrieval_policy_root": self.retrieval_policy_root,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash("WITNESS-ESCROW", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRentSubsidy {
    pub subsidy_id: String,
    pub lease_id: String,
    pub sponsor_commitment: String,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub rebate_bps: u64,
    pub expires_height: u64,
    pub policy_root: String,
}

impl LowFeeRentSubsidy {
    pub fn new(
        lease: &EncryptedStateLease,
        sponsor_label: &str,
        budget_units: u64,
        rebate_bps: u64,
        expires_height: u64,
        policy: &Value,
    ) -> Self {
        let sponsor_commitment = rent_hash("RENT-SPONSOR", &[HashPart::Str(sponsor_label)]);
        let policy_root = rent_hash("RENT-SUBSIDY-POLICY", &[HashPart::Json(policy)]);
        let subsidy_id = rent_hash(
            "RENT-SUBSIDY-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Str(&sponsor_commitment),
                HashPart::Int(budget_units as i128),
            ],
        );
        Self {
            subsidy_id,
            lease_id: lease.lease_id.clone(),
            sponsor_commitment,
            budget_units,
            consumed_units: 0,
            rebate_bps: rebate_bps.min(PRIVATE_STATE_RENT_MARKET_MAX_BPS),
            expires_height,
            policy_root,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subsidy_id": self.subsidy_id,
            "lease_id": self.lease_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "rebate_bps": self.rebate_bps,
            "expires_height": self.expires_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash(
            "LOW-FEE-RENT-SUBSIDY",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RentAuction {
    pub auction_id: String,
    pub lease_id: String,
    pub storage_class: StorageClass,
    pub minimum_bid_units: u64,
    pub winning_bid_units: u64,
    pub winner_commitment: Option<String>,
    pub opened_height: u64,
    pub closes_height: u64,
    pub status: AuctionStatus,
    pub sealed_bid_root: String,
}

impl RentAuction {
    pub fn new(
        lease: &EncryptedStateLease,
        opened_height: u64,
        config: &PrivateStateRentMarketConfig,
        sealed_bid_labels: &[&str],
    ) -> Self {
        let sealed_bid_root = string_set_root("SEALED-BIDS", sealed_bid_labels);
        let minimum_bid_units = lease
            .rent_due_units
            .saturating_add(config.archive_reward_units);
        let auction_id = rent_hash(
            "RENT-AUCTION-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&sealed_bid_root),
            ],
        );
        Self {
            auction_id,
            lease_id: lease.lease_id.clone(),
            storage_class: lease.storage_class,
            minimum_bid_units,
            winning_bid_units: 0,
            winner_commitment: None,
            opened_height,
            closes_height: opened_height.saturating_add(config.auction_window_blocks),
            status: AuctionStatus::Open,
            sealed_bid_root,
        }
    }

    pub fn with_winner(mut self, winner_label: &str, winning_bid_units: u64) -> Self {
        self.winner_commitment = Some(rent_hash("AUCTION-WINNER", &[HashPart::Str(winner_label)]));
        self.winning_bid_units = winning_bid_units.max(self.minimum_bid_units);
        self.status = AuctionStatus::Matched;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lease_id": self.lease_id,
            "storage_class": self.storage_class.as_str(),
            "minimum_bid_units": self.minimum_bid_units,
            "winning_bid_units": self.winning_bid_units,
            "winner_commitment": self.winner_commitment,
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "status": self.status.as_str(),
            "sealed_bid_root": self.sealed_bid_root,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash("RENT-AUCTION", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaRetentionTicket {
    pub ticket_id: String,
    pub lease_id: String,
    pub da_commitment_root: String,
    pub retention_until_height: u64,
    pub fee_units: u64,
    pub provider_quorum_root: String,
}

impl DaRetentionTicket {
    pub fn new(
        lease: &EncryptedStateLease,
        provider_labels: &[&str],
        height: u64,
        config: &PrivateStateRentMarketConfig,
    ) -> Self {
        let provider_quorum_root = string_set_root("DA-RETENTION-PROVIDERS", provider_labels);
        let da_commitment_root = rent_hash(
            "DA-COMMITMENT",
            &[
                HashPart::Str(&lease.encrypted_state_root),
                HashPart::Str(&provider_quorum_root),
            ],
        );
        let fee_units = rent_due_units(lease.size_kib, StorageClass::ColdArchive, config);
        let ticket_id = rent_hash(
            "DA-RETENTION-TICKET-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Str(&da_commitment_root),
                HashPart::Int(height as i128),
            ],
        );
        Self {
            ticket_id,
            lease_id: lease.lease_id.clone(),
            da_commitment_root,
            retention_until_height: height.saturating_add(config.retention_blocks),
            fee_units,
            provider_quorum_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lease_id": self.lease_id,
            "da_commitment_root": self.da_commitment_root,
            "retention_until_height": self.retention_until_height,
            "fee_units": self.fee_units,
            "provider_quorum_root": self.provider_quorum_root,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash(
            "DA-RETENTION-TICKET",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRetrievalProof {
    pub proof_id: String,
    pub lease_id: String,
    pub archive_provider_commitment: String,
    pub archive_root: String,
    pub retrieval_root: String,
    pub reward_units: u64,
    pub status: ArchiveProofStatus,
    pub posted_height: u64,
}

impl ArchiveRetrievalProof {
    pub fn new(
        lease: &EncryptedStateLease,
        provider_label: &str,
        posted_height: u64,
        reward_units: u64,
        status: ArchiveProofStatus,
    ) -> Self {
        let archive_provider_commitment =
            rent_hash("ARCHIVE-PROVIDER", &[HashPart::Str(provider_label)]);
        let archive_root = rent_hash(
            "ARCHIVE-ROOT",
            &[
                HashPart::Str(&lease.encrypted_state_root),
                HashPart::Str(&lease.state_witness_root),
            ],
        );
        let retrieval_root = rent_hash(
            "RETRIEVAL-ROOT",
            &[
                HashPart::Str(&archive_root),
                HashPart::Str(&archive_provider_commitment),
            ],
        );
        let proof_id = rent_hash(
            "ARCHIVE-PROOF-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Str(&archive_provider_commitment),
                HashPart::Int(posted_height as i128),
            ],
        );
        Self {
            proof_id,
            lease_id: lease.lease_id.clone(),
            archive_provider_commitment,
            archive_root,
            retrieval_root,
            reward_units,
            status,
            posted_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "lease_id": self.lease_id,
            "archive_provider_commitment": self.archive_provider_commitment,
            "archive_root": self.archive_root,
            "retrieval_root": self.retrieval_root,
            "reward_units": self.reward_units,
            "status": self.status.as_str(),
            "posted_height": self.posted_height,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash(
            "ARCHIVE-RETRIEVAL-PROOF",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStorageSponsorship {
    pub sponsorship_id: String,
    pub lease_id: String,
    pub monero_anchor_root: String,
    pub sponsor_commitment: String,
    pub piconero_budget: u64,
    pub claimed_piconero: u64,
    pub settlement_height: u64,
}

impl MoneroStorageSponsorship {
    pub fn new(
        lease: &EncryptedStateLease,
        sponsor_label: &str,
        piconero_budget: u64,
        settlement_height: u64,
        anchor_payload: &Value,
    ) -> Self {
        let sponsor_commitment =
            rent_hash("MONERO-STORAGE-SPONSOR", &[HashPart::Str(sponsor_label)]);
        let monero_anchor_root =
            rent_hash("MONERO-STORAGE-ANCHOR", &[HashPart::Json(anchor_payload)]);
        let sponsorship_id = rent_hash(
            "MONERO-STORAGE-SPONSORSHIP-ID",
            &[
                HashPart::Str(&lease.lease_id),
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&monero_anchor_root),
            ],
        );
        Self {
            sponsorship_id,
            lease_id: lease.lease_id.clone(),
            monero_anchor_root,
            sponsor_commitment,
            piconero_budget,
            claimed_piconero: 0,
            settlement_height,
        }
    }

    pub fn remaining_piconero(&self) -> u64 {
        self.piconero_budget.saturating_sub(self.claimed_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "lease_id": self.lease_id,
            "monero_anchor_root": self.monero_anchor_root,
            "sponsor_commitment": self.sponsor_commitment,
            "piconero_budget": self.piconero_budget,
            "claimed_piconero": self.claimed_piconero,
            "remaining_piconero": self.remaining_piconero(),
            "settlement_height": self.settlement_height,
        })
    }

    pub fn record_root(&self) -> String {
        rent_hash(
            "MONERO-STORAGE-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateRentMarketRoots {
    pub config_root: String,
    pub lease_root: String,
    pub witness_escrow_root: String,
    pub subsidy_root: String,
    pub auction_root: String,
    pub da_retention_root: String,
    pub archive_proof_root: String,
    pub monero_sponsorship_root: String,
}

impl PrivateStateRentMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lease_root": self.lease_root,
            "witness_escrow_root": self.witness_escrow_root,
            "subsidy_root": self.subsidy_root,
            "auction_root": self.auction_root,
            "da_retention_root": self.da_retention_root,
            "archive_proof_root": self.archive_proof_root,
            "monero_sponsorship_root": self.monero_sponsorship_root,
        })
    }

    pub fn state_root(&self) -> String {
        rent_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateRentMarketCounters {
    pub lease_count: u64,
    pub live_lease_count: u64,
    pub grace_lease_count: u64,
    pub auction_count: u64,
    pub open_auction_count: u64,
    pub witness_escrow_count: u64,
    pub active_witness_escrow_count: u64,
    pub subsidy_count: u64,
    pub archive_proof_count: u64,
    pub da_retention_ticket_count: u64,
    pub monero_sponsorship_count: u64,
    pub total_size_kib: u64,
    pub rent_due_units: u64,
    pub subsidy_available_units: u64,
    pub monero_sponsorship_available_piconero: u64,
}

impl PrivateStateRentMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_count": self.lease_count,
            "live_lease_count": self.live_lease_count,
            "grace_lease_count": self.grace_lease_count,
            "auction_count": self.auction_count,
            "open_auction_count": self.open_auction_count,
            "witness_escrow_count": self.witness_escrow_count,
            "active_witness_escrow_count": self.active_witness_escrow_count,
            "subsidy_count": self.subsidy_count,
            "archive_proof_count": self.archive_proof_count,
            "da_retention_ticket_count": self.da_retention_ticket_count,
            "monero_sponsorship_count": self.monero_sponsorship_count,
            "total_size_kib": self.total_size_kib,
            "rent_due_units": self.rent_due_units,
            "subsidy_available_units": self.subsidy_available_units,
            "monero_sponsorship_available_piconero": self.monero_sponsorship_available_piconero,
        })
    }

    pub fn state_root(&self) -> String {
        rent_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateRentMarketState {
    pub height: u64,
    pub config: PrivateStateRentMarketConfig,
    pub leases: BTreeMap<String, EncryptedStateLease>,
    pub witness_escrows: BTreeMap<String, StateWitnessEscrow>,
    pub subsidies: BTreeMap<String, LowFeeRentSubsidy>,
    pub auctions: BTreeMap<String, RentAuction>,
    pub da_retention_tickets: BTreeMap<String, DaRetentionTicket>,
    pub archive_proofs: BTreeMap<String, ArchiveRetrievalProof>,
    pub monero_sponsorships: BTreeMap<String, MoneroStorageSponsorship>,
}

impl PrivateStateRentMarketState {
    pub fn devnet() -> PrivateStateRentMarketResult<Self> {
        let config = PrivateStateRentMarketConfig::devnet();
        let height = PRIVATE_STATE_RENT_MARKET_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            config,
            leases: BTreeMap::new(),
            witness_escrows: BTreeMap::new(),
            subsidies: BTreeMap::new(),
            auctions: BTreeMap::new(),
            da_retention_tickets: BTreeMap::new(),
            archive_proofs: BTreeMap::new(),
            monero_sponsorships: BTreeMap::new(),
        };

        let hot = EncryptedStateLease::new(
            "private-dex-pool-state",
            "tenant-private-dex",
            StorageClass::HotContract,
            128,
            height.saturating_sub(300),
            2,
            12_500,
            &state.config,
            &json!({"contract": "private_dex", "lane": "hot"}),
        )
        .with_status(LeaseStatus::Subsidized);
        let bridge = EncryptedStateLease::new(
            "monero-bridge-witness-state",
            "tenant-bridge",
            StorageClass::BridgeWitness,
            384,
            height.saturating_sub(900),
            1,
            24_000,
            &state.config,
            &json!({"contract": "monero_bridge", "lane": "witness"}),
        )
        .with_status(LeaseStatus::Grace);
        let archive = EncryptedStateLease::new(
            "recursive-proof-archive-state",
            "tenant-prover",
            StorageClass::ProofArtifact,
            512,
            height.saturating_sub(1_200),
            1,
            18_000,
            &state.config,
            &json!({"contract": "proof_market", "lane": "archive"}),
        )
        .with_status(LeaseStatus::Auctioning);

        state.insert_lease(hot.clone())?;
        state.insert_lease(bridge.clone())?;
        state.insert_lease(archive.clone())?;

        let escrow_hot = StateWitnessEscrow::new(
            &hot,
            "state-witness-provider-a",
            height,
            9_000,
            &state.config,
            &json!({"retrieval": "owner_or_watchtower"}),
        )
        .with_status(WitnessEscrowStatus::Available);
        let escrow_bridge = StateWitnessEscrow::new(
            &bridge,
            "state-witness-provider-b",
            height,
            12_000,
            &state.config,
            &json!({"retrieval": "bridge_recovery_quorum"}),
        );
        state.insert_witness_escrow(escrow_hot)?;
        state.insert_witness_escrow(escrow_bridge)?;

        let subsidy = LowFeeRentSubsidy::new(
            &hot,
            "low-fee-storage-sponsor",
            40_000,
            state.config.low_fee_rebate_bps,
            hot.grace_until_height,
            &json!({"max_kib": 256, "class": "hot_contract"}),
        );
        state.insert_subsidy(subsidy)?;

        let auction = RentAuction::new(
            &archive,
            height.saturating_sub(8),
            &state.config,
            &["archive-bid-a", "archive-bid-b", "archive-bid-c"],
        )
        .with_winner(
            "archive-bid-b",
            archive.rent_due_units.saturating_add(2_000),
        );
        state.insert_auction(auction)?;

        let da_hot = DaRetentionTicket::new(
            &hot,
            &["da-provider-a", "da-provider-b", "da-provider-c"],
            height,
            &state.config,
        );
        let da_bridge = DaRetentionTicket::new(
            &bridge,
            &["da-provider-bridge-a", "da-provider-bridge-b"],
            height,
            &state.config,
        );
        state.insert_da_retention_ticket(da_hot)?;
        state.insert_da_retention_ticket(da_bridge)?;

        let archive_proof = ArchiveRetrievalProof::new(
            &archive,
            "archive-provider-z",
            height.saturating_sub(4),
            state.config.archive_reward_units,
            ArchiveProofStatus::RetrievalReady,
        );
        state.insert_archive_proof(archive_proof)?;

        let monero_sponsorship = MoneroStorageSponsorship::new(
            &bridge,
            "monero-storage-sponsor",
            8_000_000_000,
            height.saturating_sub(2),
            &json!({"txid_root": "devnet-storage-sponsor-tx", "confirmations": 16}),
        );
        state.insert_monero_sponsorship(monero_sponsorship)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateStateRentMarketResult<()> {
        if height < self.height {
            return Err("state rent market height cannot decrease".to_string());
        }
        self.height = height;
        for lease in self.leases.values_mut() {
            if lease.status.is_live() && height > lease.grace_until_height {
                lease.status = LeaseStatus::Auctioning;
            } else if matches!(lease.status, LeaseStatus::Active | LeaseStatus::Subsidized)
                && height > lease.paid_through_height
            {
                lease.status = LeaseStatus::Grace;
            }
        }
        for auction in self.auctions.values_mut() {
            if auction.status.is_open() && height > auction.closes_height {
                auction.status = AuctionStatus::Expired;
            }
        }
        for escrow in self.witness_escrows.values_mut() {
            if escrow.status.is_active() && height > escrow.retention_until_height {
                escrow.status = WitnessEscrowStatus::Expired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn insert_lease(&mut self, lease: EncryptedStateLease) -> PrivateStateRentMarketResult<()> {
        if lease.lease_id.is_empty() {
            return Err("state rent lease id cannot be empty".to_string());
        }
        self.leases.insert(lease.lease_id.clone(), lease);
        Ok(())
    }

    pub fn insert_witness_escrow(
        &mut self,
        escrow: StateWitnessEscrow,
    ) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&escrow.lease_id) {
            return Err("state rent witness escrow references unknown lease".to_string());
        }
        self.witness_escrows
            .insert(escrow.escrow_id.clone(), escrow);
        Ok(())
    }

    pub fn insert_subsidy(
        &mut self,
        subsidy: LowFeeRentSubsidy,
    ) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&subsidy.lease_id) {
            return Err("state rent subsidy references unknown lease".to_string());
        }
        self.subsidies.insert(subsidy.subsidy_id.clone(), subsidy);
        Ok(())
    }

    pub fn insert_auction(&mut self, auction: RentAuction) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&auction.lease_id) {
            return Err("state rent auction references unknown lease".to_string());
        }
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_da_retention_ticket(
        &mut self,
        ticket: DaRetentionTicket,
    ) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&ticket.lease_id) {
            return Err("state rent DA retention ticket references unknown lease".to_string());
        }
        self.da_retention_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        Ok(())
    }

    pub fn insert_archive_proof(
        &mut self,
        proof: ArchiveRetrievalProof,
    ) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&proof.lease_id) {
            return Err("state rent archive proof references unknown lease".to_string());
        }
        self.archive_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_monero_sponsorship(
        &mut self,
        sponsorship: MoneroStorageSponsorship,
    ) -> PrivateStateRentMarketResult<()> {
        if !self.leases.contains_key(&sponsorship.lease_id) {
            return Err("state rent Monero sponsorship references unknown lease".to_string());
        }
        self.monero_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn roots(&self) -> PrivateStateRentMarketRoots {
        PrivateStateRentMarketRoots {
            config_root: self.config.config_root(),
            lease_root: map_root(
                "LEASES",
                self.leases.values().map(EncryptedStateLease::public_record),
            ),
            witness_escrow_root: map_root(
                "WITNESS-ESCROWS",
                self.witness_escrows
                    .values()
                    .map(StateWitnessEscrow::public_record),
            ),
            subsidy_root: map_root(
                "SUBSIDIES",
                self.subsidies
                    .values()
                    .map(LowFeeRentSubsidy::public_record),
            ),
            auction_root: map_root(
                "AUCTIONS",
                self.auctions.values().map(RentAuction::public_record),
            ),
            da_retention_root: map_root(
                "DA-RETENTION",
                self.da_retention_tickets
                    .values()
                    .map(DaRetentionTicket::public_record),
            ),
            archive_proof_root: map_root(
                "ARCHIVE-PROOFS",
                self.archive_proofs
                    .values()
                    .map(ArchiveRetrievalProof::public_record),
            ),
            monero_sponsorship_root: map_root(
                "MONERO-SPONSORSHIPS",
                self.monero_sponsorships
                    .values()
                    .map(MoneroStorageSponsorship::public_record),
            ),
        }
    }

    pub fn counters(&self) -> PrivateStateRentMarketCounters {
        PrivateStateRentMarketCounters {
            lease_count: self.leases.len() as u64,
            live_lease_count: self.leases.values().filter(|lease| lease.is_live()).count() as u64,
            grace_lease_count: self
                .leases
                .values()
                .filter(|lease| lease.status == LeaseStatus::Grace)
                .count() as u64,
            auction_count: self.auctions.len() as u64,
            open_auction_count: self
                .auctions
                .values()
                .filter(|auction| auction.is_open())
                .count() as u64,
            witness_escrow_count: self.witness_escrows.len() as u64,
            active_witness_escrow_count: self
                .witness_escrows
                .values()
                .filter(|escrow| escrow.status.is_active())
                .count() as u64,
            subsidy_count: self.subsidies.len() as u64,
            archive_proof_count: self.archive_proofs.len() as u64,
            da_retention_ticket_count: self.da_retention_tickets.len() as u64,
            monero_sponsorship_count: self.monero_sponsorships.len() as u64,
            total_size_kib: self.leases.values().map(|lease| lease.size_kib).sum(),
            rent_due_units: self.leases.values().map(|lease| lease.rent_due_units).sum(),
            subsidy_available_units: self
                .subsidies
                .values()
                .map(LowFeeRentSubsidy::available_units)
                .sum(),
            monero_sponsorship_available_piconero: self
                .monero_sponsorships
                .values()
                .map(MoneroStorageSponsorship::remaining_piconero)
                .sum(),
        }
    }

    pub fn live_lease_ids(&self) -> Vec<String> {
        self.leases
            .values()
            .filter(|lease| lease.is_live())
            .map(|lease| lease.lease_id.clone())
            .collect()
    }

    pub fn open_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| auction.is_open())
            .map(|auction| auction.auction_id.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_state_rent_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STATE_RENT_MARKET_PROTOCOL_VERSION,
            "protocol_label": PRIVATE_STATE_RENT_MARKET_PROTOCOL_LABEL,
            "schema_version": PRIVATE_STATE_RENT_MARKET_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "leases": self.leases.values().map(EncryptedStateLease::public_record).collect::<Vec<_>>(),
            "witness_escrows": self.witness_escrows.values().map(StateWitnessEscrow::public_record).collect::<Vec<_>>(),
            "subsidies": self.subsidies.values().map(LowFeeRentSubsidy::public_record).collect::<Vec<_>>(),
            "auctions": self.auctions.values().map(RentAuction::public_record).collect::<Vec<_>>(),
            "da_retention_tickets": self.da_retention_tickets.values().map(DaRetentionTicket::public_record).collect::<Vec<_>>(),
            "archive_proofs": self.archive_proofs.values().map(ArchiveRetrievalProof::public_record).collect::<Vec<_>>(),
            "monero_sponsorships": self.monero_sponsorships.values().map(MoneroStorageSponsorship::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        private_state_rent_market_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateStateRentMarketResult<String> {
        self.config.validate()?;
        let mut lease_ids = BTreeSet::new();
        for lease in self.leases.values() {
            if lease.lease_id.is_empty()
                || lease.contract_commitment.is_empty()
                || lease.tenant_commitment.is_empty()
                || lease.encrypted_state_root.is_empty()
                || lease.state_witness_root.is_empty()
                || lease.pq_authorization_root.is_empty()
            {
                return Err("state rent lease contains empty commitments".to_string());
            }
            if lease.size_kib == 0 || lease.rent_due_units == 0 || lease.bond_units == 0 {
                return Err("state rent lease economics must be positive".to_string());
            }
            if lease.grace_until_height < lease.paid_through_height {
                return Err("state rent lease grace cannot precede paid-through height".to_string());
            }
            if !lease_ids.insert(lease.lease_id.clone()) {
                return Err("duplicate state rent lease id".to_string());
            }
        }
        for escrow in self.witness_escrows.values() {
            if !self.leases.contains_key(&escrow.lease_id) {
                return Err("state rent witness escrow references missing lease".to_string());
            }
            if escrow.bond_units == 0 || escrow.retention_until_height == 0 {
                return Err("state rent witness escrow economics must be positive".to_string());
            }
        }
        for subsidy in self.subsidies.values() {
            if !self.leases.contains_key(&subsidy.lease_id) {
                return Err("state rent subsidy references missing lease".to_string());
            }
            if subsidy.rebate_bps > PRIVATE_STATE_RENT_MARKET_MAX_BPS {
                return Err("state rent subsidy rebate exceeds maximum".to_string());
            }
        }
        for auction in self.auctions.values() {
            if !self.leases.contains_key(&auction.lease_id) {
                return Err("state rent auction references missing lease".to_string());
            }
            if auction.closes_height <= auction.opened_height {
                return Err("state rent auction close must exceed open height".to_string());
            }
        }
        for ticket in self.da_retention_tickets.values() {
            if !self.leases.contains_key(&ticket.lease_id) {
                return Err("state rent DA retention ticket references missing lease".to_string());
            }
            if ticket.fee_units == 0 || ticket.retention_until_height == 0 {
                return Err("state rent DA retention ticket economics must be positive".to_string());
            }
        }
        for proof in self.archive_proofs.values() {
            if !self.leases.contains_key(&proof.lease_id) {
                return Err("state rent archive proof references missing lease".to_string());
            }
        }
        for sponsorship in self.monero_sponsorships.values() {
            if !self.leases.contains_key(&sponsorship.lease_id) {
                return Err("state rent Monero sponsorship references missing lease".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_state_rent_market_state_root_from_record(record: &Value) -> String {
    rent_hash("STATE", &[HashPart::Json(record)])
}

fn rent_due_units(
    size_kib: u64,
    storage_class: StorageClass,
    config: &PrivateStateRentMarketConfig,
) -> u64 {
    size_kib
        .saturating_mul(config.rent_per_kib_units)
        .saturating_mul(storage_class.rent_multiplier_bps())
        .saturating_add(PRIVATE_STATE_RENT_MARKET_MAX_BPS - 1)
        / PRIVATE_STATE_RENT_MARKET_MAX_BPS
}

fn rent_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("PRIVATE-STATE-RENT-MARKET-{domain}"), parts, 32)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    rent_hash(domain, &[HashPart::Json(&json!(values))])
}

fn string_set_root(domain: &str, values: &[&str]) -> String {
    let mut values = values.to_vec();
    values.sort();
    rent_hash(domain, &[HashPart::Json(&json!(values))])
}
