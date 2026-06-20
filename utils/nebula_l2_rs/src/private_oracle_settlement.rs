use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateOracleSettlementResult<T> = Result<T, String>;

pub const PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_ID: &str = "nebula-private-oracle-settlement-v1";
pub const PRIVATE_ORACLE_SETTLEMENT_DEVNET_HEIGHT: u64 = 864;
pub const PRIVATE_ORACLE_SETTLEMENT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_ORACLE_SETTLEMENT_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_ORACLE_SETTLEMENT_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_ORACLE_SETTLEMENT_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_ORACLE_SETTLEMENT_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-encrypted-price-commitment-v1";
pub const PRIVATE_ORACLE_SETTLEMENT_TWAP_SCHEME: &str = "shielded-private-twap-lane-v1";
pub const PRIVATE_ORACLE_SETTLEMENT_BATCH_SCHEME: &str = "mev-resistant-private-oracle-batch-v1";
pub const PRIVATE_ORACLE_SETTLEMENT_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_ORACLE_SETTLEMENT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_TWAP_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_BATCH_INTERVAL_BLOCKS: u64 = 8;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REPORTER_BOND_UNITS: u64 = 150_000;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS: u64 = 6_700;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REPORTER_REWARD_BPS: u64 = 1_500;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 3;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 90_000;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_MARKETS: usize = 1_024;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_COMMITTEES: usize = 8_192;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_REPORTERS: usize = 65_536;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_COMMITMENTS: usize = 524_288;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_REVEALS: usize = 524_288;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_TWAP_LANES: usize = 16_384;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_CHALLENGES: usize = 262_144;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_SPONSORS: usize = 65_536;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_ANCHORS: usize = 131_072;
pub const PRIVATE_ORACLE_SETTLEMENT_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleMarketKind {
    Spot,
    PrivateTwap,
    LendingIndex,
    PerpFunding,
    StableSwap,
    VaultShare,
    MoneroReserve,
    EmergencyPeg,
}

impl OracleMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::PrivateTwap => "private_twap",
            Self::LendingIndex => "lending_index",
            Self::PerpFunding => "perp_funding",
            Self::StableSwap => "stable_swap",
            Self::VaultShare => "vault_share",
            Self::MoneroReserve => "monero_reserve",
            Self::EmergencyPeg => "emergency_peg",
        }
    }

    pub fn default_heartbeat_blocks(self) -> u64 {
        match self {
            Self::EmergencyPeg => 2,
            Self::Spot | Self::PerpFunding => 4,
            Self::PrivateTwap | Self::StableSwap => 8,
            Self::LendingIndex | Self::VaultShare => 16,
            Self::MoneroReserve => 12,
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyPeg => 100,
            Self::MoneroReserve => 95,
            Self::Spot => 90,
            Self::PerpFunding => 84,
            Self::StableSwap => 82,
            Self::PrivateTwap => 78,
            Self::LendingIndex => 72,
            Self::VaultShare => 70,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleRecordStatus {
    Draft,
    Active,
    Committed,
    RevealOpen,
    Revealed,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Paused,
    Retired,
}

impl OracleRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Committed => "committed",
            Self::RevealOpen => "reveal_open",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Committed | Self::RevealOpen | Self::Revealed
        )
    }

    pub fn accepts_commits(self) -> bool {
        matches!(self, Self::Active | Self::Committed | Self::RevealOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleSettlementMode {
    CommitReveal,
    ThresholdReveal,
    PrivateTwap,
    BatchAuction,
    ReserveAnchor,
    EmergencyFallback,
}

impl OracleSettlementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitReveal => "commit_reveal",
            Self::ThresholdReveal => "threshold_reveal",
            Self::PrivateTwap => "private_twap",
            Self::BatchAuction => "batch_auction",
            Self::ReserveAnchor => "reserve_anchor",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleChallengeKind {
    MissingReveal,
    InvalidOpening,
    BadPqSignature,
    CommitteeWeightFault,
    TwapDeviation,
    BatchOrderingFault,
    SponsorOverspend,
    MoneroAnchorMismatch,
    ReserveProofExpired,
}

impl OracleChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingReveal => "missing_reveal",
            Self::InvalidOpening => "invalid_opening",
            Self::BadPqSignature => "bad_pq_signature",
            Self::CommitteeWeightFault => "committee_weight_fault",
            Self::TwapDeviation => "twap_deviation",
            Self::BatchOrderingFault => "batch_ordering_fault",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::MoneroAnchorMismatch => "monero_anchor_mismatch",
            Self::ReserveProofExpired => "reserve_proof_expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleEventKind {
    MarketOpened,
    CommitteeRotated,
    PriceCommitted,
    RevealWindowOpened,
    ThresholdReached,
    TwapUpdated,
    BatchSettled,
    ReporterSlashed,
    SponsorDebited,
    MoneroAnchorPosted,
}

impl OracleEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketOpened => "market_opened",
            Self::CommitteeRotated => "committee_rotated",
            Self::PriceCommitted => "price_committed",
            Self::RevealWindowOpened => "reveal_window_opened",
            Self::ThresholdReached => "threshold_reached",
            Self::TwapUpdated => "twap_updated",
            Self::BatchSettled => "batch_settled",
            Self::ReporterSlashed => "reporter_slashed",
            Self::SponsorDebited => "sponsor_debited",
            Self::MoneroAnchorPosted => "monero_anchor_posted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleSettlementConfig {
    pub chain_id: String,
    pub protocol_version: u32,
    pub protocol_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub encryption_scheme: String,
    pub twap_scheme: String,
    pub batch_scheme: String,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub commitment_ttl_blocks: u64,
    pub twap_window_blocks: u64,
    pub batch_interval_blocks: u64,
    pub reporter_bond_units: u64,
    pub min_committee_weight_bps: u64,
    pub slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub low_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl Default for PrivateOracleSettlementConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION,
            protocol_id: PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_ID.to_string(),
            hash_suite: PRIVATE_ORACLE_SETTLEMENT_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_ORACLE_SETTLEMENT_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: PRIVATE_ORACLE_SETTLEMENT_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_ORACLE_SETTLEMENT_PQ_KEM_SCHEME.to_string(),
            encryption_scheme: PRIVATE_ORACLE_SETTLEMENT_ENCRYPTION_SCHEME.to_string(),
            twap_scheme: PRIVATE_ORACLE_SETTLEMENT_TWAP_SCHEME.to_string(),
            batch_scheme: PRIVATE_ORACLE_SETTLEMENT_BATCH_SCHEME.to_string(),
            fee_asset_id: PRIVATE_ORACLE_SETTLEMENT_FEE_ASSET_ID.to_string(),
            monero_network: PRIVATE_ORACLE_SETTLEMENT_MONERO_NETWORK.to_string(),
            reveal_window_blocks: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            commitment_ttl_blocks: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_COMMITMENT_TTL_BLOCKS,
            twap_window_blocks: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_TWAP_WINDOW_BLOCKS,
            batch_interval_blocks: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_BATCH_INTERVAL_BLOCKS,
            reporter_bond_units: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REPORTER_BOND_UNITS,
            min_committee_weight_bps: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS,
            slash_bps: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_SLASH_BPS,
            reporter_reward_bps: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_REPORTER_REWARD_BPS,
            low_fee_cap_units: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_LOW_FEE_CAP_UNITS,
            sponsor_budget_units: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_SPONSOR_BUDGET_UNITS,
            min_privacy_set_size: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }
}

impl PrivateOracleSettlementConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_oracle_settlement_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "encryption_scheme": self.encryption_scheme,
            "twap_scheme": self.twap_scheme,
            "batch_scheme": self.batch_scheme,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "reveal_window_blocks": self.reveal_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "commitment_ttl_blocks": self.commitment_ttl_blocks,
            "twap_window_blocks": self.twap_window_blocks,
            "batch_interval_blocks": self.batch_interval_blocks,
            "reporter_bond_units": self.reporter_bond_units,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "slash_bps": self.slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "low_fee_cap_units": self.low_fee_cap_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn config_root(&self) -> String {
        private_oracle_settlement_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<String> {
        ensure_non_empty(&self.chain_id, "oracle chain id")?;
        ensure_non_empty(&self.protocol_id, "oracle protocol id")?;
        ensure_non_empty(&self.hash_suite, "oracle hash suite")?;
        ensure_non_empty(&self.pq_signature_scheme, "oracle pq signature scheme")?;
        ensure_non_empty(&self.pq_backup_scheme, "oracle pq backup scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "oracle pq kem scheme")?;
        ensure_non_empty(&self.encryption_scheme, "oracle encryption scheme")?;
        ensure_non_empty(&self.twap_scheme, "oracle twap scheme")?;
        ensure_non_empty(&self.batch_scheme, "oracle batch scheme")?;
        ensure_non_empty(&self.fee_asset_id, "oracle fee asset id")?;
        ensure_non_empty(&self.monero_network, "oracle monero network")?;
        ensure_positive(self.reveal_window_blocks, "oracle reveal window")?;
        ensure_positive(self.challenge_window_blocks, "oracle challenge window")?;
        ensure_positive(self.commitment_ttl_blocks, "oracle commitment ttl")?;
        ensure_positive(self.twap_window_blocks, "oracle twap window")?;
        ensure_positive(self.batch_interval_blocks, "oracle batch interval")?;
        ensure_positive(self.reporter_bond_units, "oracle reporter bond")?;
        ensure_positive(self.min_privacy_set_size, "oracle privacy set size")?;
        ensure_bps(self.min_committee_weight_bps, "oracle committee weight bps")?;
        ensure_bps(self.slash_bps, "oracle slash bps")?;
        ensure_bps(self.reporter_reward_bps, "oracle reporter reward bps")?;
        if self.protocol_version != PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION {
            return Err("oracle settlement protocol version mismatch".to_string());
        }
        if self.min_committee_weight_bps == 0 {
            return Err("oracle committee weight threshold cannot be zero".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("oracle pq security bits below devnet floor".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleMarket {
    pub market_id: String,
    pub market_key: String,
    pub kind: OracleMarketKind,
    pub status: OracleRecordStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub settlement_asset_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub heartbeat_blocks: u64,
    pub stale_after_blocks: u64,
    pub max_deviation_bps: u64,
    pub priority: u64,
    pub opened_at_height: u64,
    pub metadata_root: String,
}

impl OracleMarket {
    pub fn devnet(
        market_key: &str,
        kind: OracleMarketKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        lane_id: &str,
        committee_id: &str,
        height: u64,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(market_key, "oracle market key")?;
        ensure_non_empty(base_asset_id, "oracle base asset id")?;
        ensure_non_empty(quote_asset_id, "oracle quote asset id")?;
        ensure_non_empty(lane_id, "oracle lane id")?;
        ensure_non_empty(committee_id, "oracle committee id")?;
        let heartbeat_blocks = kind.default_heartbeat_blocks();
        let stale_after_blocks = heartbeat_blocks.saturating_mul(4);
        let metadata_root = private_oracle_settlement_payload_root(
            "MARKET-METADATA",
            &json!({
                "market_key": market_key,
                "kind": kind.as_str(),
                "base_asset_id": base_asset_id,
                "quote_asset_id": quote_asset_id,
                "settlement_asset_id": PRIVATE_ORACLE_SETTLEMENT_FEE_ASSET_ID,
                "privacy_preserving": true,
                "confidential_defi": true,
            }),
        );
        let market_id = private_oracle_settlement_id(
            "MARKET-ID",
            &[
                HashPart::Str(market_key),
                HashPart::Str(kind.as_str()),
                HashPart::Str(base_asset_id),
                HashPart::Str(quote_asset_id),
                HashPart::Str(lane_id),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            market_id,
            market_key: market_key.to_string(),
            kind,
            status: OracleRecordStatus::Active,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            settlement_asset_id: PRIVATE_ORACLE_SETTLEMENT_FEE_ASSET_ID.to_string(),
            lane_id: lane_id.to_string(),
            committee_id: committee_id.to_string(),
            heartbeat_blocks,
            stale_after_blocks,
            max_deviation_bps: if kind == OracleMarketKind::EmergencyPeg {
                50
            } else {
                750
            },
            priority: kind.default_priority(),
            opened_at_height: height,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "market_key": self.market_key,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "heartbeat_blocks": self.heartbeat_blocks,
            "stale_after_blocks": self.stale_after_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "priority": self.priority,
            "opened_at_height": self.opened_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.market_id, "oracle market id")?;
        ensure_non_empty(&self.market_key, "oracle market key")?;
        ensure_non_empty(&self.base_asset_id, "oracle base asset id")?;
        ensure_non_empty(&self.quote_asset_id, "oracle quote asset id")?;
        ensure_non_empty(&self.settlement_asset_id, "oracle settlement asset id")?;
        ensure_non_empty(&self.lane_id, "oracle lane id")?;
        ensure_non_empty(&self.committee_id, "oracle market committee id")?;
        ensure_non_empty(&self.metadata_root, "oracle market metadata root")?;
        ensure_positive(self.heartbeat_blocks, "oracle market heartbeat")?;
        ensure_positive(self.stale_after_blocks, "oracle market stale window")?;
        ensure_bps(self.max_deviation_bps, "oracle market max deviation")?;
        if self.stale_after_blocks < self.heartbeat_blocks {
            return Err("oracle market stale window below heartbeat".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReporter {
    pub reporter_id: String,
    pub operator_commitment: String,
    pub pq_signing_key_commitment: String,
    pub pq_backup_key_commitment: String,
    pub stake_bond_units: u64,
    pub voting_weight_bps: u64,
    pub privacy_set_root: String,
    pub status: OracleRecordStatus,
    pub joined_at_height: u64,
}

impl OracleReporter {
    pub fn devnet(
        operator_label: &str,
        weight_bps: u64,
        bond_units: u64,
        height: u64,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(operator_label, "oracle reporter operator label")?;
        ensure_bps(weight_bps, "oracle reporter weight")?;
        ensure_positive(bond_units, "oracle reporter bond")?;
        let operator_commitment =
            private_oracle_settlement_commitment("reporter-operator", operator_label);
        let pq_signing_key_commitment =
            private_oracle_settlement_commitment("reporter-pq-signing-key", operator_label);
        let pq_backup_key_commitment =
            private_oracle_settlement_commitment("reporter-pq-backup-key", operator_label);
        let privacy_set_root = private_oracle_settlement_payload_root(
            "REPORTER-PRIVACY-SET",
            &json!({
                "operator_commitment": operator_commitment,
                "privacy_set_size": PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PRIVACY_SET_SIZE,
                "pq_security_bits": PRIVATE_ORACLE_SETTLEMENT_DEFAULT_MIN_PQ_SECURITY_BITS,
            }),
        );
        let reporter_id = private_oracle_settlement_id(
            "REPORTER-ID",
            &[
                HashPart::Str(&operator_commitment),
                HashPart::Str(&pq_signing_key_commitment),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            reporter_id,
            operator_commitment,
            pq_signing_key_commitment,
            pq_backup_key_commitment,
            stake_bond_units: bond_units,
            voting_weight_bps: weight_bps,
            privacy_set_root,
            status: OracleRecordStatus::Active,
            joined_at_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reporter_id": self.reporter_id,
            "operator_commitment": self.operator_commitment,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "pq_backup_key_commitment": self.pq_backup_key_commitment,
            "stake_bond_units": self.stake_bond_units,
            "voting_weight_bps": self.voting_weight_bps,
            "privacy_set_root": self.privacy_set_root,
            "status": self.status.as_str(),
            "joined_at_height": self.joined_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.reporter_id, "oracle reporter id")?;
        ensure_non_empty(
            &self.operator_commitment,
            "oracle reporter operator commitment",
        )?;
        ensure_non_empty(
            &self.pq_signing_key_commitment,
            "oracle reporter pq signing key",
        )?;
        ensure_non_empty(
            &self.pq_backup_key_commitment,
            "oracle reporter pq backup key",
        )?;
        ensure_non_empty(&self.privacy_set_root, "oracle reporter privacy set root")?;
        ensure_positive(self.stake_bond_units, "oracle reporter bond")?;
        ensure_bps(self.voting_weight_bps, "oracle reporter voting weight")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReporterCommittee {
    pub committee_id: String,
    pub committee_key: String,
    pub status: OracleRecordStatus,
    pub reporter_ids: Vec<String>,
    pub reporter_set_root: String,
    pub aggregate_pq_key_root: String,
    pub threshold_weight_bps: u64,
    pub active_weight_bps: u64,
    pub rotation_epoch: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl ReporterCommittee {
    pub fn devnet(
        committee_key: &str,
        reporter_ids: Vec<String>,
        threshold_weight_bps: u64,
        active_weight_bps: u64,
        height: u64,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(committee_key, "oracle committee key")?;
        ensure_string_set(&reporter_ids, "oracle committee reporters")?;
        ensure_bps(threshold_weight_bps, "oracle committee threshold")?;
        ensure_bps(active_weight_bps, "oracle committee active weight")?;
        if active_weight_bps < threshold_weight_bps {
            return Err("oracle committee active weight below threshold".to_string());
        }
        let reporter_set_root =
            private_oracle_settlement_string_set_root("COMMITTEE-REPORTERS", &reporter_ids);
        let aggregate_pq_key_root = private_oracle_settlement_payload_root(
            "COMMITTEE-AGGREGATE-PQ-KEY",
            &json!({
                "committee_key": committee_key,
                "reporter_set_root": reporter_set_root,
                "scheme": PRIVATE_ORACLE_SETTLEMENT_PQ_SIGNATURE_SCHEME,
            }),
        );
        let committee_id = private_oracle_settlement_id(
            "COMMITTEE-ID",
            &[
                HashPart::Str(committee_key),
                HashPart::Str(&reporter_set_root),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            committee_id,
            committee_key: committee_key.to_string(),
            status: OracleRecordStatus::Active,
            reporter_ids,
            reporter_set_root,
            aggregate_pq_key_root,
            threshold_weight_bps,
            active_weight_bps,
            rotation_epoch: height / 128,
            valid_from_height: height.saturating_sub(8),
            valid_until_height: height.saturating_add(2_880),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_key": self.committee_key,
            "status": self.status.as_str(),
            "reporter_ids": self.reporter_ids,
            "reporter_set_root": self.reporter_set_root,
            "aggregate_pq_key_root": self.aggregate_pq_key_root,
            "threshold_weight_bps": self.threshold_weight_bps,
            "active_weight_bps": self.active_weight_bps,
            "rotation_epoch": self.rotation_epoch,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.committee_id, "oracle committee id")?;
        ensure_non_empty(&self.committee_key, "oracle committee key")?;
        ensure_string_set(&self.reporter_ids, "oracle committee reporters")?;
        ensure_non_empty(
            &self.reporter_set_root,
            "oracle committee reporter set root",
        )?;
        ensure_non_empty(
            &self.aggregate_pq_key_root,
            "oracle committee aggregate pq key root",
        )?;
        ensure_bps(self.threshold_weight_bps, "oracle committee threshold")?;
        ensure_bps(self.active_weight_bps, "oracle committee active weight")?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "oracle committee validity",
        )?;
        if self.active_weight_bps < self.threshold_weight_bps {
            return Err("oracle committee active weight below threshold".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPriceCommitment {
    pub commitment_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub reporter_id: String,
    pub batch_id: String,
    pub encrypted_price_root: String,
    pub price_commitment_root: String,
    pub nonce_commitment: String,
    pub pq_signature_root: String,
    pub status: OracleRecordStatus,
    pub posted_at_height: u64,
    pub reveal_deadline_height: u64,
    pub expires_at_height: u64,
    pub fee_units: u64,
}

impl EncryptedPriceCommitment {
    pub fn devnet(
        market_id: &str,
        committee_id: &str,
        reporter_id: &str,
        batch_id: &str,
        height: u64,
        nonce: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(market_id, "oracle commitment market id")?;
        ensure_non_empty(committee_id, "oracle commitment committee id")?;
        ensure_non_empty(reporter_id, "oracle commitment reporter id")?;
        ensure_non_empty(batch_id, "oracle commitment batch id")?;
        let encrypted_price_root = private_oracle_settlement_payload_root(
            "ENCRYPTED-PRICE",
            &json!({
                "market_id": market_id,
                "reporter_id": reporter_id,
                "batch_id": batch_id,
                "scheme": config.encryption_scheme,
                "nonce": nonce,
            }),
        );
        let nonce_commitment =
            private_oracle_settlement_commitment("price-opening-nonce", &format!("{nonce}"));
        let price_commitment_root = private_oracle_settlement_payload_root(
            "PRICE-COMMITMENT",
            &json!({
                "market_id": market_id,
                "encrypted_price_root": encrypted_price_root,
                "nonce_commitment": nonce_commitment,
                "privacy_set_size": config.min_privacy_set_size,
            }),
        );
        let pq_signature_root = private_oracle_settlement_payload_root(
            "PRICE-COMMITMENT-PQ-SIGNATURE",
            &json!({
                "committee_id": committee_id,
                "reporter_id": reporter_id,
                "price_commitment_root": price_commitment_root,
                "scheme": config.pq_signature_scheme,
            }),
        );
        let commitment_id = private_oracle_settlement_id(
            "PRICE-COMMITMENT-ID",
            &[
                HashPart::Str(market_id),
                HashPart::Str(reporter_id),
                HashPart::Str(batch_id),
                HashPart::Str(&price_commitment_root),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            commitment_id,
            market_id: market_id.to_string(),
            committee_id: committee_id.to_string(),
            reporter_id: reporter_id.to_string(),
            batch_id: batch_id.to_string(),
            encrypted_price_root,
            price_commitment_root,
            nonce_commitment,
            pq_signature_root,
            status: OracleRecordStatus::Committed,
            posted_at_height: height,
            reveal_deadline_height: height.saturating_add(config.reveal_window_blocks),
            expires_at_height: height.saturating_add(config.commitment_ttl_blocks),
            fee_units: config.low_fee_cap_units,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "reporter_id": self.reporter_id,
            "batch_id": self.batch_id,
            "encrypted_price_root": self.encrypted_price_root,
            "price_commitment_root": self.price_commitment_root,
            "nonce_commitment": self.nonce_commitment,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "expires_at_height": self.expires_at_height,
            "fee_units": self.fee_units,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.commitment_id, "oracle price commitment id")?;
        ensure_non_empty(&self.market_id, "oracle price commitment market id")?;
        ensure_non_empty(&self.committee_id, "oracle price commitment committee id")?;
        ensure_non_empty(&self.reporter_id, "oracle price commitment reporter id")?;
        ensure_non_empty(&self.batch_id, "oracle price commitment batch id")?;
        ensure_non_empty(&self.encrypted_price_root, "oracle encrypted price root")?;
        ensure_non_empty(&self.price_commitment_root, "oracle price commitment root")?;
        ensure_non_empty(&self.nonce_commitment, "oracle nonce commitment")?;
        ensure_non_empty(&self.pq_signature_root, "oracle pq signature root")?;
        ensure_height_window(
            self.posted_at_height,
            self.reveal_deadline_height,
            "oracle reveal deadline",
        )?;
        ensure_height_window(
            self.posted_at_height,
            self.expires_at_height,
            "oracle commitment expiry",
        )?;
        if self.expires_at_height < self.reveal_deadline_height {
            return Err("oracle commitment expires before reveal deadline".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdRevealWindow {
    pub reveal_window_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub batch_id: String,
    pub commitment_ids: Vec<String>,
    pub revealed_commitment_ids: Vec<String>,
    pub threshold_weight_bps: u64,
    pub revealed_weight_bps: u64,
    pub aggregate_opening_root: String,
    pub status: OracleRecordStatus,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl ThresholdRevealWindow {
    pub fn devnet(
        market_id: &str,
        committee_id: &str,
        batch_id: &str,
        commitment_ids: Vec<String>,
        revealed_commitment_ids: Vec<String>,
        height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_string_set(&commitment_ids, "oracle reveal commitments")?;
        ensure_string_set(&revealed_commitment_ids, "oracle revealed commitments")?;
        let aggregate_opening_root = private_oracle_settlement_payload_root(
            "THRESHOLD-OPENING",
            &json!({
                "market_id": market_id,
                "committee_id": committee_id,
                "batch_id": batch_id,
                "revealed_commitment_ids": revealed_commitment_ids,
            }),
        );
        let reveal_window_id = private_oracle_settlement_id(
            "REVEAL-WINDOW-ID",
            &[
                HashPart::Str(market_id),
                HashPart::Str(committee_id),
                HashPart::Str(batch_id),
                HashPart::Str(&aggregate_opening_root),
                HashPart::Int(height as i128),
            ],
        );
        let revealed_weight_bps = config.min_committee_weight_bps.saturating_add(300);
        Ok(Self {
            reveal_window_id,
            market_id: market_id.to_string(),
            committee_id: committee_id.to_string(),
            batch_id: batch_id.to_string(),
            commitment_ids,
            revealed_commitment_ids,
            threshold_weight_bps: config.min_committee_weight_bps,
            revealed_weight_bps,
            aggregate_opening_root,
            status: OracleRecordStatus::Revealed,
            opened_at_height: height,
            closes_at_height: height.saturating_add(config.reveal_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reveal_window_id": self.reveal_window_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "batch_id": self.batch_id,
            "commitment_ids": self.commitment_ids,
            "revealed_commitment_ids": self.revealed_commitment_ids,
            "threshold_weight_bps": self.threshold_weight_bps,
            "revealed_weight_bps": self.revealed_weight_bps,
            "aggregate_opening_root": self.aggregate_opening_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.reveal_window_id, "oracle reveal window id")?;
        ensure_non_empty(&self.market_id, "oracle reveal market id")?;
        ensure_non_empty(&self.committee_id, "oracle reveal committee id")?;
        ensure_non_empty(&self.batch_id, "oracle reveal batch id")?;
        ensure_string_set(&self.commitment_ids, "oracle reveal commitments")?;
        ensure_string_set(&self.revealed_commitment_ids, "oracle revealed commitments")?;
        ensure_non_empty(
            &self.aggregate_opening_root,
            "oracle aggregate opening root",
        )?;
        ensure_bps(self.threshold_weight_bps, "oracle reveal threshold")?;
        ensure_bps(self.revealed_weight_bps, "oracle revealed weight")?;
        ensure_height_window(
            self.opened_at_height,
            self.closes_at_height,
            "oracle reveal window",
        )?;
        if self.revealed_weight_bps < self.threshold_weight_bps {
            return Err("oracle reveal window below threshold".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTwapLane {
    pub lane_id: String,
    pub lane_key: String,
    pub market_id: String,
    pub status: OracleRecordStatus,
    pub settlement_mode: OracleSettlementMode,
    pub window_blocks: u64,
    pub sample_count: u64,
    pub encrypted_sample_root: String,
    pub accumulator_root: String,
    pub last_update_height: u64,
}

impl PrivateTwapLane {
    pub fn devnet(
        lane_key: &str,
        market_hint: &str,
        height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(lane_key, "oracle twap lane key")?;
        ensure_non_empty(market_hint, "oracle twap lane market hint")?;
        let encrypted_sample_root = private_oracle_settlement_payload_root(
            "TWAP-ENCRYPTED-SAMPLES",
            &json!({
                "lane_key": lane_key,
                "market_hint": market_hint,
                "scheme": config.twap_scheme,
                "window_blocks": config.twap_window_blocks,
            }),
        );
        let accumulator_root = private_oracle_settlement_payload_root(
            "TWAP-ACCUMULATOR",
            &json!({
                "encrypted_sample_root": encrypted_sample_root,
                "sample_count": 12_u64,
                "confidential": true,
            }),
        );
        let lane_id = private_oracle_settlement_id(
            "TWAP-LANE-ID",
            &[
                HashPart::Str(lane_key),
                HashPart::Str(market_hint),
                HashPart::Str(&accumulator_root),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            lane_id,
            lane_key: lane_key.to_string(),
            market_id: String::new(),
            status: OracleRecordStatus::Active,
            settlement_mode: OracleSettlementMode::PrivateTwap,
            window_blocks: config.twap_window_blocks,
            sample_count: 12,
            encrypted_sample_root,
            accumulator_root,
            last_update_height: height,
        })
    }

    pub fn with_market_id(mut self, market_id: &str) -> Self {
        self.market_id = market_id.to_string();
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "market_id": self.market_id,
            "status": self.status.as_str(),
            "settlement_mode": self.settlement_mode.as_str(),
            "window_blocks": self.window_blocks,
            "sample_count": self.sample_count,
            "encrypted_sample_root": self.encrypted_sample_root,
            "accumulator_root": self.accumulator_root,
            "last_update_height": self.last_update_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.lane_id, "oracle twap lane id")?;
        ensure_non_empty(&self.lane_key, "oracle twap lane key")?;
        ensure_non_empty(&self.market_id, "oracle twap lane market id")?;
        ensure_non_empty(&self.encrypted_sample_root, "oracle twap encrypted samples")?;
        ensure_non_empty(&self.accumulator_root, "oracle twap accumulator")?;
        ensure_positive(self.window_blocks, "oracle twap window")?;
        ensure_positive(self.sample_count, "oracle twap samples")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevResistantBatch {
    pub batch_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub status: OracleRecordStatus,
    pub settlement_mode: OracleSettlementMode,
    pub encrypted_ordering_root: String,
    pub fair_ordering_proof_root: String,
    pub settlement_price_root: String,
    pub commitment_ids: Vec<String>,
    pub reveal_window_id: String,
    pub batch_height: u64,
    pub settle_after_height: u64,
    pub settled_at_height: u64,
    pub sponsored_fee_units: u64,
}

impl MevResistantBatch {
    pub fn pending(
        market_key: &str,
        committee_id: &str,
        height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(market_key, "oracle pending batch market key")?;
        ensure_non_empty(committee_id, "oracle pending batch committee id")?;
        let encrypted_ordering_root = private_oracle_settlement_payload_root(
            "BATCH-ENCRYPTED-ORDERING",
            &json!({
                "market_key": market_key,
                "committee_id": committee_id,
                "scheme": PRIVATE_ORACLE_SETTLEMENT_BATCH_SCHEME,
                "height": height,
            }),
        );
        let batch_id = private_oracle_settlement_id(
            "BATCH-ID",
            &[
                HashPart::Str(market_key),
                HashPart::Str(committee_id),
                HashPart::Str(&encrypted_ordering_root),
                HashPart::Int(height as i128),
            ],
        );
        let fair_ordering_proof_root =
            private_oracle_settlement_commitment("fair-ordering-proof", &batch_id);
        let settlement_price_root =
            private_oracle_settlement_commitment("pending-settlement-price", &batch_id);
        Ok(Self {
            batch_id,
            market_id: String::new(),
            committee_id: committee_id.to_string(),
            status: OracleRecordStatus::Committed,
            settlement_mode: OracleSettlementMode::BatchAuction,
            encrypted_ordering_root,
            fair_ordering_proof_root,
            settlement_price_root,
            commitment_ids: Vec::new(),
            reveal_window_id: String::new(),
            batch_height: height,
            settle_after_height: height.saturating_add(config.batch_interval_blocks),
            settled_at_height: 0,
            sponsored_fee_units: config.low_fee_cap_units,
        })
    }

    pub fn settle(
        mut self,
        market_id: &str,
        commitment_ids: Vec<String>,
        reveal_window_id: &str,
        settled_at_height: u64,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(market_id, "oracle batch market id")?;
        ensure_string_set(&commitment_ids, "oracle batch commitments")?;
        ensure_non_empty(reveal_window_id, "oracle batch reveal window id")?;
        self.market_id = market_id.to_string();
        self.commitment_ids = commitment_ids;
        self.reveal_window_id = reveal_window_id.to_string();
        self.settlement_price_root = private_oracle_settlement_payload_root(
            "BATCH-SETTLEMENT-PRICE",
            &json!({
                "batch_id": self.batch_id,
                "market_id": market_id,
                "reveal_window_id": reveal_window_id,
                "settled_at_height": settled_at_height,
            }),
        );
        self.status = OracleRecordStatus::Settled;
        self.settled_at_height = settled_at_height;
        Ok(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "settlement_mode": self.settlement_mode.as_str(),
            "encrypted_ordering_root": self.encrypted_ordering_root,
            "fair_ordering_proof_root": self.fair_ordering_proof_root,
            "settlement_price_root": self.settlement_price_root,
            "commitment_ids": self.commitment_ids,
            "reveal_window_id": self.reveal_window_id,
            "batch_height": self.batch_height,
            "settle_after_height": self.settle_after_height,
            "settled_at_height": self.settled_at_height,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.batch_id, "oracle batch id")?;
        ensure_non_empty(&self.market_id, "oracle batch market id")?;
        ensure_non_empty(&self.committee_id, "oracle batch committee id")?;
        ensure_non_empty(
            &self.encrypted_ordering_root,
            "oracle batch encrypted ordering",
        )?;
        ensure_non_empty(
            &self.fair_ordering_proof_root,
            "oracle batch ordering proof",
        )?;
        ensure_non_empty(&self.settlement_price_root, "oracle batch settlement price")?;
        ensure_string_set(&self.commitment_ids, "oracle batch commitments")?;
        ensure_non_empty(&self.reveal_window_id, "oracle batch reveal window")?;
        ensure_height_window(
            self.batch_height,
            self.settle_after_height,
            "oracle batch settlement delay",
        )?;
        if self.settled_at_height < self.settle_after_height {
            return Err("oracle batch settled before delay elapsed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleChallengeReceipt {
    pub receipt_id: String,
    pub challenge_kind: OracleChallengeKind,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub slashed_reporter_id: String,
    pub slash_units: u64,
    pub reward_units: u64,
    pub status: OracleRecordStatus,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
}

impl OracleChallengeReceipt {
    pub fn devnet(
        challenge_kind: OracleChallengeKind,
        target_id: &str,
        reporter_id: &str,
        opened_at_height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(target_id, "oracle challenge target id")?;
        ensure_non_empty(reporter_id, "oracle challenge reporter id")?;
        let challenger_commitment =
            private_oracle_settlement_commitment("oracle-challenger", target_id);
        let evidence_root = private_oracle_settlement_payload_root(
            "CHALLENGE-EVIDENCE",
            &json!({
                "challenge_kind": challenge_kind.as_str(),
                "target_id": target_id,
                "reporter_id": reporter_id,
                "opened_at_height": opened_at_height,
            }),
        );
        let receipt_id = private_oracle_settlement_id(
            "CHALLENGE-RECEIPT-ID",
            &[
                HashPart::Str(challenge_kind.as_str()),
                HashPart::Str(target_id),
                HashPart::Str(reporter_id),
                HashPart::Str(&evidence_root),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        let slash_units = bps_amount(config.reporter_bond_units, config.slash_bps);
        let reward_units = bps_amount(slash_units, config.reporter_reward_bps);
        Ok(Self {
            receipt_id,
            challenge_kind,
            target_id: target_id.to_string(),
            challenger_commitment,
            evidence_root,
            slashed_reporter_id: reporter_id.to_string(),
            slash_units,
            reward_units,
            status: OracleRecordStatus::Slashed,
            opened_at_height,
            resolved_at_height: opened_at_height.saturating_add(config.challenge_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "slashed_reporter_id": self.slashed_reporter_id,
            "slash_units": self.slash_units,
            "reward_units": self.reward_units,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.receipt_id, "oracle challenge receipt id")?;
        ensure_non_empty(&self.target_id, "oracle challenge target id")?;
        ensure_non_empty(&self.challenger_commitment, "oracle challenger commitment")?;
        ensure_non_empty(&self.evidence_root, "oracle challenge evidence root")?;
        ensure_non_empty(&self.slashed_reporter_id, "oracle slashed reporter")?;
        ensure_height_window(
            self.opened_at_height,
            self.resolved_at_height,
            "oracle challenge resolution",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSponsorBook {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: OracleRecordStatus,
    pub eligible_market_ids: Vec<String>,
    pub eligibility_root: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_update_units: u64,
    pub opened_at_height: u64,
}

impl OracleSponsorBook {
    pub fn devnet(
        sponsor_label: &str,
        eligible_market_ids: Vec<String>,
        height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(sponsor_label, "oracle sponsor label")?;
        ensure_string_set(&eligible_market_ids, "oracle sponsor markets")?;
        let sponsor_commitment =
            private_oracle_settlement_commitment("low-fee-oracle-sponsor", sponsor_label);
        let eligibility_root = private_oracle_settlement_payload_root(
            "SPONSOR-ELIGIBILITY",
            &json!({
                "sponsor_commitment": sponsor_commitment,
                "eligible_market_ids": eligible_market_ids,
                "low_fee_cap_units": config.low_fee_cap_units,
                "confidential_defi": true,
            }),
        );
        let sponsor_id = private_oracle_settlement_id(
            "SPONSOR-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&eligibility_root),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            sponsor_id,
            sponsor_commitment,
            status: OracleRecordStatus::Active,
            eligible_market_ids,
            eligibility_root,
            budget_units: config.sponsor_budget_units,
            spent_units: config.low_fee_cap_units.saturating_mul(3),
            max_fee_per_update_units: config.low_fee_cap_units,
            opened_at_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "eligible_market_ids": self.eligible_market_ids,
            "eligibility_root": self.eligibility_root,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "max_fee_per_update_units": self.max_fee_per_update_units,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.sponsor_id, "oracle sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment, "oracle sponsor commitment")?;
        ensure_string_set(&self.eligible_market_ids, "oracle sponsor markets")?;
        ensure_non_empty(&self.eligibility_root, "oracle sponsor eligibility root")?;
        ensure_positive(self.budget_units, "oracle sponsor budget")?;
        ensure_positive(self.max_fee_per_update_units, "oracle sponsor fee cap")?;
        if self.spent_units > self.budget_units {
            return Err("oracle sponsor spent units exceed budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroOracleAnchor {
    pub anchor_id: String,
    pub market_id: String,
    pub batch_id: String,
    pub monero_network: String,
    pub reserve_commitment_root: String,
    pub monero_block_root: String,
    pub monero_txid_root: String,
    pub view_key_attestation_root: String,
    pub status: OracleRecordStatus,
    pub monero_height: u64,
    pub posted_at_height: u64,
}

impl MoneroOracleAnchor {
    pub fn devnet(
        market_id: &str,
        batch_id: &str,
        monero_height: u64,
        posted_at_height: u64,
        config: &PrivateOracleSettlementConfig,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(market_id, "oracle monero anchor market id")?;
        ensure_non_empty(batch_id, "oracle monero anchor batch id")?;
        ensure_positive(monero_height, "oracle monero height")?;
        let reserve_commitment_root = private_oracle_settlement_payload_root(
            "MONERO-RESERVE-COMMITMENT",
            &json!({
                "market_id": market_id,
                "batch_id": batch_id,
                "monero_network": config.monero_network,
                "reserve_asset": "xmr",
                "confidential_reserve": true,
            }),
        );
        let monero_block_root =
            private_oracle_settlement_commitment("monero-block-root", &format!("{monero_height}"));
        let monero_txid_root = private_oracle_settlement_commitment("monero-txid-set", batch_id);
        let view_key_attestation_root = private_oracle_settlement_payload_root(
            "MONERO-VIEW-KEY-ATTESTATION",
            &json!({
                "reserve_commitment_root": reserve_commitment_root,
                "monero_block_root": monero_block_root,
                "monero_txid_root": monero_txid_root,
            }),
        );
        let anchor_id = private_oracle_settlement_id(
            "MONERO-ANCHOR-ID",
            &[
                HashPart::Str(market_id),
                HashPart::Str(batch_id),
                HashPart::Str(&reserve_commitment_root),
                HashPart::Int(monero_height as i128),
                HashPart::Int(posted_at_height as i128),
            ],
        );
        Ok(Self {
            anchor_id,
            market_id: market_id.to_string(),
            batch_id: batch_id.to_string(),
            monero_network: config.monero_network.clone(),
            reserve_commitment_root,
            monero_block_root,
            monero_txid_root,
            view_key_attestation_root,
            status: OracleRecordStatus::Active,
            monero_height,
            posted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "market_id": self.market_id,
            "batch_id": self.batch_id,
            "monero_network": self.monero_network,
            "reserve_commitment_root": self.reserve_commitment_root,
            "monero_block_root": self.monero_block_root,
            "monero_txid_root": self.monero_txid_root,
            "view_key_attestation_root": self.view_key_attestation_root,
            "status": self.status.as_str(),
            "monero_height": self.monero_height,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.anchor_id, "oracle monero anchor id")?;
        ensure_non_empty(&self.market_id, "oracle monero anchor market id")?;
        ensure_non_empty(&self.batch_id, "oracle monero anchor batch id")?;
        ensure_non_empty(&self.monero_network, "oracle monero network")?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "oracle reserve commitment root",
        )?;
        ensure_non_empty(&self.monero_block_root, "oracle monero block root")?;
        ensure_non_empty(&self.monero_txid_root, "oracle monero txid root")?;
        ensure_non_empty(
            &self.view_key_attestation_root,
            "oracle view key attestation root",
        )?;
        ensure_positive(self.monero_height, "oracle monero height")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleEvent {
    pub event_id: String,
    pub kind: OracleEventKind,
    pub subject_id: String,
    pub event_root: String,
    pub height: u64,
}

impl OracleEvent {
    pub fn devnet(
        kind: OracleEventKind,
        subject_id: &str,
        height: u64,
    ) -> PrivateOracleSettlementResult<Self> {
        ensure_non_empty(subject_id, "oracle event subject id")?;
        let event_root = private_oracle_settlement_payload_root(
            "EVENT",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "height": height,
            }),
        );
        let event_id = private_oracle_settlement_id(
            "EVENT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(&event_root),
                HashPart::Int(height as i128),
            ],
        );
        Ok(Self {
            event_id,
            kind,
            subject_id: subject_id.to_string(),
            event_root,
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "height": self.height,
        })
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<()> {
        ensure_non_empty(&self.event_id, "oracle event id")?;
        ensure_non_empty(&self.subject_id, "oracle event subject")?;
        ensure_non_empty(&self.event_root, "oracle event root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleSettlementRoots {
    pub config_root: String,
    pub market_root: String,
    pub reporter_root: String,
    pub committee_root: String,
    pub encrypted_commitment_root: String,
    pub reveal_window_root: String,
    pub private_twap_lane_root: String,
    pub mev_batch_root: String,
    pub challenge_receipt_root: String,
    pub sponsor_book_root: String,
    pub monero_anchor_root: String,
    pub event_root: String,
}

impl PrivateOracleSettlementRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "market_root": self.market_root,
            "reporter_root": self.reporter_root,
            "committee_root": self.committee_root,
            "encrypted_commitment_root": self.encrypted_commitment_root,
            "reveal_window_root": self.reveal_window_root,
            "private_twap_lane_root": self.private_twap_lane_root,
            "mev_batch_root": self.mev_batch_root,
            "challenge_receipt_root": self.challenge_receipt_root,
            "sponsor_book_root": self.sponsor_book_root,
            "monero_anchor_root": self.monero_anchor_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleSettlementCounters {
    pub market_count: u64,
    pub active_market_count: u64,
    pub reporter_count: u64,
    pub active_reporter_count: u64,
    pub committee_count: u64,
    pub encrypted_commitment_count: u64,
    pub live_commitment_count: u64,
    pub reveal_window_count: u64,
    pub threshold_revealed_window_count: u64,
    pub private_twap_lane_count: u64,
    pub mev_batch_count: u64,
    pub settled_batch_count: u64,
    pub challenge_receipt_count: u64,
    pub slashed_challenge_count: u64,
    pub sponsor_book_count: u64,
    pub active_sponsor_book_count: u64,
    pub monero_anchor_count: u64,
    pub event_count: u64,
    pub total_reporter_bond_units: u64,
    pub total_sponsored_fee_units: u64,
    pub total_slashed_units: u64,
}

impl PrivateOracleSettlementCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_count": self.market_count,
            "active_market_count": self.active_market_count,
            "reporter_count": self.reporter_count,
            "active_reporter_count": self.active_reporter_count,
            "committee_count": self.committee_count,
            "encrypted_commitment_count": self.encrypted_commitment_count,
            "live_commitment_count": self.live_commitment_count,
            "reveal_window_count": self.reveal_window_count,
            "threshold_revealed_window_count": self.threshold_revealed_window_count,
            "private_twap_lane_count": self.private_twap_lane_count,
            "mev_batch_count": self.mev_batch_count,
            "settled_batch_count": self.settled_batch_count,
            "challenge_receipt_count": self.challenge_receipt_count,
            "slashed_challenge_count": self.slashed_challenge_count,
            "sponsor_book_count": self.sponsor_book_count,
            "active_sponsor_book_count": self.active_sponsor_book_count,
            "monero_anchor_count": self.monero_anchor_count,
            "event_count": self.event_count,
            "total_reporter_bond_units": self.total_reporter_bond_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_slashed_units": self.total_slashed_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleSettlementState {
    pub height: u64,
    pub status: OracleRecordStatus,
    pub config: PrivateOracleSettlementConfig,
    pub markets: BTreeMap<String, OracleMarket>,
    pub reporters: BTreeMap<String, OracleReporter>,
    pub committees: BTreeMap<String, ReporterCommittee>,
    pub encrypted_commitments: BTreeMap<String, EncryptedPriceCommitment>,
    pub reveal_windows: BTreeMap<String, ThresholdRevealWindow>,
    pub private_twap_lanes: BTreeMap<String, PrivateTwapLane>,
    pub mev_batches: BTreeMap<String, MevResistantBatch>,
    pub challenge_receipts: BTreeMap<String, OracleChallengeReceipt>,
    pub sponsor_books: BTreeMap<String, OracleSponsorBook>,
    pub monero_anchors: BTreeMap<String, MoneroOracleAnchor>,
    pub events: BTreeMap<String, OracleEvent>,
}

impl PrivateOracleSettlementState {
    pub fn devnet() -> PrivateOracleSettlementResult<Self> {
        let config = PrivateOracleSettlementConfig::devnet();
        let height = PRIVATE_ORACLE_SETTLEMENT_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            status: OracleRecordStatus::Active,
            config,
            markets: BTreeMap::new(),
            reporters: BTreeMap::new(),
            committees: BTreeMap::new(),
            encrypted_commitments: BTreeMap::new(),
            reveal_windows: BTreeMap::new(),
            private_twap_lanes: BTreeMap::new(),
            mev_batches: BTreeMap::new(),
            challenge_receipts: BTreeMap::new(),
            sponsor_books: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            events: BTreeMap::new(),
        };

        let reporter_specs = [
            ("alpha", 1_700_u64),
            ("bravo", 1_650_u64),
            ("charlie", 1_550_u64),
            ("delta", 1_450_u64),
            ("echo", 1_350_u64),
            ("foxtrot", 1_300_u64),
            ("reserve", 1_000_u64),
        ];
        let mut reporter_ids = Vec::new();
        for (label, weight) in reporter_specs {
            let reporter = OracleReporter::devnet(
                label,
                weight,
                state.config.reporter_bond_units,
                height.saturating_sub(96),
            )?;
            reporter_ids.push(reporter.reporter_id.clone());
            insert_unique(
                &mut state.reporters,
                reporter.reporter_id.clone(),
                reporter,
                "oracle reporter",
            )?;
        }

        let committee = ReporterCommittee::devnet(
            "devnet-primary-oracle-committee",
            reporter_ids.clone(),
            state.config.min_committee_weight_bps,
            10_000,
            height.saturating_sub(80),
        )?;
        let committee_id = committee.committee_id.clone();
        insert_unique(
            &mut state.committees,
            committee.committee_id.clone(),
            committee,
            "oracle committee",
        )?;

        let mut xmr_lane = PrivateTwapLane::devnet(
            "private-twap-xmr-usd",
            "xmr-usd",
            height.saturating_sub(64),
            &state.config,
        )?;
        let mut dxmr_lane = PrivateTwapLane::devnet(
            "private-twap-dxmr-xmr",
            "dxmr-xmr",
            height.saturating_sub(64),
            &state.config,
        )?;
        let xmr_market = OracleMarket::devnet(
            "xmr-usd",
            OracleMarketKind::MoneroReserve,
            "asset:xmr",
            "asset:usd",
            &xmr_lane.lane_id,
            &committee_id,
            height.saturating_sub(64),
        )?;
        let dxmr_market = OracleMarket::devnet(
            "dxmr-xmr",
            OracleMarketKind::PrivateTwap,
            "asset:dxmr",
            "asset:xmr",
            &dxmr_lane.lane_id,
            &committee_id,
            height.saturating_sub(64),
        )?;
        xmr_lane = xmr_lane.with_market_id(&xmr_market.market_id);
        dxmr_lane = dxmr_lane.with_market_id(&dxmr_market.market_id);
        let market_ids = vec![xmr_market.market_id.clone(), dxmr_market.market_id.clone()];
        insert_unique(
            &mut state.private_twap_lanes,
            xmr_lane.lane_id.clone(),
            xmr_lane,
            "oracle twap lane",
        )?;
        insert_unique(
            &mut state.private_twap_lanes,
            dxmr_lane.lane_id.clone(),
            dxmr_lane,
            "oracle twap lane",
        )?;
        insert_unique(
            &mut state.markets,
            xmr_market.market_id.clone(),
            xmr_market,
            "oracle market",
        )?;
        insert_unique(
            &mut state.markets,
            dxmr_market.market_id.clone(),
            dxmr_market,
            "oracle market",
        )?;

        for market_id in &market_ids {
            let batch = MevResistantBatch::pending(
                market_id,
                &committee_id,
                height.saturating_sub(16),
                &state.config,
            )?;
            let mut commitment_ids = Vec::new();
            for (index, reporter_id) in reporter_ids.iter().take(5).enumerate() {
                let commitment = EncryptedPriceCommitment::devnet(
                    market_id,
                    &committee_id,
                    reporter_id,
                    &batch.batch_id,
                    height.saturating_sub(14),
                    (index as u64).saturating_add(1),
                    &state.config,
                )?;
                commitment_ids.push(commitment.commitment_id.clone());
                insert_unique(
                    &mut state.encrypted_commitments,
                    commitment.commitment_id.clone(),
                    commitment,
                    "oracle price commitment",
                )?;
            }
            let revealed_commitment_ids =
                commitment_ids.iter().take(4).cloned().collect::<Vec<_>>();
            let reveal_window = ThresholdRevealWindow::devnet(
                market_id,
                &committee_id,
                &batch.batch_id,
                commitment_ids.clone(),
                revealed_commitment_ids,
                height.saturating_sub(12),
                &state.config,
            )?;
            let settled_batch = batch.settle(
                market_id,
                commitment_ids,
                &reveal_window.reveal_window_id,
                height.saturating_sub(4),
            )?;
            insert_unique(
                &mut state.reveal_windows,
                reveal_window.reveal_window_id.clone(),
                reveal_window,
                "oracle reveal window",
            )?;
            insert_unique(
                &mut state.mev_batches,
                settled_batch.batch_id.clone(),
                settled_batch,
                "oracle mev batch",
            )?;
        }

        let challenge_target = state
            .encrypted_commitments
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "oracle devnet commitment set is empty".to_string())?;
        let slashed_reporter_id = reporter_ids
            .last()
            .cloned()
            .ok_or_else(|| "oracle devnet reporter set is empty".to_string())?;
        let challenge = OracleChallengeReceipt::devnet(
            OracleChallengeKind::MissingReveal,
            &challenge_target,
            &slashed_reporter_id,
            height.saturating_sub(40),
            &state.config,
        )?;
        insert_unique(
            &mut state.challenge_receipts,
            challenge.receipt_id.clone(),
            challenge,
            "oracle challenge receipt",
        )?;

        let sponsor = OracleSponsorBook::devnet(
            "devnet-oracle-sponsor",
            market_ids.clone(),
            height,
            &state.config,
        )?;
        insert_unique(
            &mut state.sponsor_books,
            sponsor.sponsor_id.clone(),
            sponsor,
            "oracle sponsor book",
        )?;

        let first_batch = state
            .mev_batches
            .values()
            .next()
            .ok_or_else(|| "oracle devnet batch set is empty".to_string())?;
        let anchor = MoneroOracleAnchor::devnet(
            &first_batch.market_id,
            &first_batch.batch_id,
            3_120_448,
            height.saturating_sub(3),
            &state.config,
        )?;
        insert_unique(
            &mut state.monero_anchors,
            anchor.anchor_id.clone(),
            anchor,
            "oracle monero anchor",
        )?;

        let first_market_id = market_ids
            .first()
            .ok_or_else(|| "oracle devnet market set is empty".to_string())?;
        for (kind, subject_id) in [
            (OracleEventKind::MarketOpened, first_market_id.as_str()),
            (OracleEventKind::CommitteeRotated, committee_id.as_str()),
            (OracleEventKind::BatchSettled, first_batch.batch_id.as_str()),
            (
                OracleEventKind::MoneroAnchorPosted,
                first_batch.batch_id.as_str(),
            ),
        ] {
            let event = OracleEvent::devnet(kind, subject_id, height)?;
            insert_unique(
                &mut state.events,
                event.event_id.clone(),
                event,
                "oracle event",
            )?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateOracleSettlementResult<()> {
        if height == 0 {
            return Err("oracle settlement height must be positive".to_string());
        }
        if height < self.height {
            return Err("oracle settlement height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()?;
        Ok(())
    }

    pub fn roots(&self) -> PrivateOracleSettlementRoots {
        PrivateOracleSettlementRoots {
            config_root: self.config.config_root(),
            market_root: map_root(
                "MARKETS",
                &public_map(&self.markets, OracleMarket::public_record),
            ),
            reporter_root: map_root(
                "REPORTERS",
                &public_map(&self.reporters, OracleReporter::public_record),
            ),
            committee_root: map_root(
                "COMMITTEES",
                &public_map(&self.committees, ReporterCommittee::public_record),
            ),
            encrypted_commitment_root: map_root(
                "ENCRYPTED-COMMITMENTS",
                &public_map(
                    &self.encrypted_commitments,
                    EncryptedPriceCommitment::public_record,
                ),
            ),
            reveal_window_root: map_root(
                "REVEAL-WINDOWS",
                &public_map(&self.reveal_windows, ThresholdRevealWindow::public_record),
            ),
            private_twap_lane_root: map_root(
                "PRIVATE-TWAP-LANES",
                &public_map(&self.private_twap_lanes, PrivateTwapLane::public_record),
            ),
            mev_batch_root: map_root(
                "MEV-BATCHES",
                &public_map(&self.mev_batches, MevResistantBatch::public_record),
            ),
            challenge_receipt_root: map_root(
                "CHALLENGE-RECEIPTS",
                &public_map(
                    &self.challenge_receipts,
                    OracleChallengeReceipt::public_record,
                ),
            ),
            sponsor_book_root: map_root(
                "SPONSOR-BOOKS",
                &public_map(&self.sponsor_books, OracleSponsorBook::public_record),
            ),
            monero_anchor_root: map_root(
                "MONERO-ANCHORS",
                &public_map(&self.monero_anchors, MoneroOracleAnchor::public_record),
            ),
            event_root: map_root(
                "EVENTS",
                &public_map(&self.events, OracleEvent::public_record),
            ),
        }
    }

    pub fn counters(&self) -> PrivateOracleSettlementCounters {
        PrivateOracleSettlementCounters {
            market_count: self.markets.len() as u64,
            active_market_count: self
                .markets
                .values()
                .filter(|market| market.status.accepts_commits())
                .count() as u64,
            reporter_count: self.reporters.len() as u64,
            active_reporter_count: self
                .reporters
                .values()
                .filter(|reporter| reporter.status == OracleRecordStatus::Active)
                .count() as u64,
            committee_count: self.committees.len() as u64,
            encrypted_commitment_count: self.encrypted_commitments.len() as u64,
            live_commitment_count: self
                .encrypted_commitments
                .values()
                .filter(|commitment| commitment.status.live())
                .count() as u64,
            reveal_window_count: self.reveal_windows.len() as u64,
            threshold_revealed_window_count: self
                .reveal_windows
                .values()
                .filter(|window| window.revealed_weight_bps >= window.threshold_weight_bps)
                .count() as u64,
            private_twap_lane_count: self.private_twap_lanes.len() as u64,
            mev_batch_count: self.mev_batches.len() as u64,
            settled_batch_count: self
                .mev_batches
                .values()
                .filter(|batch| batch.status == OracleRecordStatus::Settled)
                .count() as u64,
            challenge_receipt_count: self.challenge_receipts.len() as u64,
            slashed_challenge_count: self
                .challenge_receipts
                .values()
                .filter(|receipt| receipt.status == OracleRecordStatus::Slashed)
                .count() as u64,
            sponsor_book_count: self.sponsor_books.len() as u64,
            active_sponsor_book_count: self
                .sponsor_books
                .values()
                .filter(|sponsor| sponsor.status == OracleRecordStatus::Active)
                .count() as u64,
            monero_anchor_count: self.monero_anchors.len() as u64,
            event_count: self.events.len() as u64,
            total_reporter_bond_units: self
                .reporters
                .values()
                .map(|reporter| reporter.stake_bond_units)
                .sum(),
            total_sponsored_fee_units: self
                .mev_batches
                .values()
                .map(|batch| batch.sponsored_fee_units)
                .sum::<u64>()
                .saturating_add(
                    self.sponsor_books
                        .values()
                        .map(|sponsor| sponsor.spent_units)
                        .sum::<u64>(),
                ),
            total_slashed_units: self
                .challenge_receipts
                .values()
                .map(|receipt| receipt.slash_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_oracle_settlement_state",
            "height": self.height,
            "status": self.status.as_str(),
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "markets": public_map(&self.markets, OracleMarket::public_record),
            "reporters": public_map(&self.reporters, OracleReporter::public_record),
            "committees": public_map(&self.committees, ReporterCommittee::public_record),
            "encrypted_commitments": public_map(
                &self.encrypted_commitments,
                EncryptedPriceCommitment::public_record
            ),
            "reveal_windows": public_map(&self.reveal_windows, ThresholdRevealWindow::public_record),
            "private_twap_lanes": public_map(&self.private_twap_lanes, PrivateTwapLane::public_record),
            "mev_batches": public_map(&self.mev_batches, MevResistantBatch::public_record),
            "challenge_receipts": public_map(
                &self.challenge_receipts,
                OracleChallengeReceipt::public_record
            ),
            "sponsor_books": public_map(&self.sponsor_books, OracleSponsorBook::public_record),
            "monero_anchors": public_map(&self.monero_anchors, MoneroOracleAnchor::public_record),
            "events": public_map(&self.events, OracleEvent::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        private_oracle_settlement_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateOracleSettlementResult<String> {
        self.config.validate()?;
        ensure_positive(self.height, "oracle settlement state height")?;
        if !matches!(
            self.status,
            OracleRecordStatus::Active | OracleRecordStatus::Paused
        ) {
            return Err("oracle settlement state status is invalid".to_string());
        }
        ensure_capacity(
            self.markets.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_MARKETS,
            "oracle markets",
        )?;
        ensure_capacity(
            self.committees.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_COMMITTEES,
            "oracle committees",
        )?;
        ensure_capacity(
            self.reporters.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_REPORTERS,
            "oracle reporters",
        )?;
        ensure_capacity(
            self.encrypted_commitments.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_COMMITMENTS,
            "oracle encrypted commitments",
        )?;
        ensure_capacity(
            self.reveal_windows.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_REVEALS,
            "oracle reveal windows",
        )?;
        ensure_capacity(
            self.private_twap_lanes.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_TWAP_LANES,
            "oracle twap lanes",
        )?;
        ensure_capacity(
            self.mev_batches.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_BATCHES,
            "oracle mev batches",
        )?;
        ensure_capacity(
            self.challenge_receipts.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_CHALLENGES,
            "oracle challenges",
        )?;
        ensure_capacity(
            self.sponsor_books.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_SPONSORS,
            "oracle sponsors",
        )?;
        ensure_capacity(
            self.monero_anchors.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_ANCHORS,
            "oracle monero anchors",
        )?;
        ensure_capacity(
            self.events.len(),
            PRIVATE_ORACLE_SETTLEMENT_MAX_EVENTS,
            "oracle events",
        )?;

        for reporter in self.reporters.values() {
            reporter.validate()?;
        }
        for committee in self.committees.values() {
            committee.validate()?;
            ensure_references(
                &committee.reporter_ids,
                &self.reporters,
                "oracle committee reporter",
            )?;
        }
        for market in self.markets.values() {
            market.validate()?;
            ensure_key_exists(
                &self.committees,
                &market.committee_id,
                "oracle market committee",
            )?;
            ensure_key_exists(
                &self.private_twap_lanes,
                &market.lane_id,
                "oracle market twap lane",
            )?;
        }
        for lane in self.private_twap_lanes.values() {
            lane.validate()?;
            ensure_key_exists(&self.markets, &lane.market_id, "oracle twap lane market")?;
        }
        for commitment in self.encrypted_commitments.values() {
            commitment.validate()?;
            ensure_key_exists(
                &self.markets,
                &commitment.market_id,
                "oracle commitment market",
            )?;
            ensure_key_exists(
                &self.committees,
                &commitment.committee_id,
                "oracle commitment committee",
            )?;
            ensure_key_exists(
                &self.reporters,
                &commitment.reporter_id,
                "oracle commitment reporter",
            )?;
        }
        for reveal_window in self.reveal_windows.values() {
            reveal_window.validate()?;
            ensure_key_exists(
                &self.markets,
                &reveal_window.market_id,
                "oracle reveal window market",
            )?;
            ensure_key_exists(
                &self.committees,
                &reveal_window.committee_id,
                "oracle reveal window committee",
            )?;
            ensure_references(
                &reveal_window.commitment_ids,
                &self.encrypted_commitments,
                "oracle reveal commitment",
            )?;
            ensure_references(
                &reveal_window.revealed_commitment_ids,
                &self.encrypted_commitments,
                "oracle revealed commitment",
            )?;
        }
        for batch in self.mev_batches.values() {
            batch.validate()?;
            ensure_key_exists(&self.markets, &batch.market_id, "oracle batch market")?;
            ensure_key_exists(
                &self.committees,
                &batch.committee_id,
                "oracle batch committee",
            )?;
            ensure_key_exists(
                &self.reveal_windows,
                &batch.reveal_window_id,
                "oracle batch reveal window",
            )?;
            ensure_references(
                &batch.commitment_ids,
                &self.encrypted_commitments,
                "oracle batch commitment",
            )?;
        }
        for receipt in self.challenge_receipts.values() {
            receipt.validate()?;
            ensure_key_exists(
                &self.reporters,
                &receipt.slashed_reporter_id,
                "oracle slashed reporter",
            )?;
        }
        for sponsor in self.sponsor_books.values() {
            sponsor.validate()?;
            ensure_references(
                &sponsor.eligible_market_ids,
                &self.markets,
                "oracle sponsor market",
            )?;
        }
        for anchor in self.monero_anchors.values() {
            anchor.validate()?;
            ensure_key_exists(
                &self.markets,
                &anchor.market_id,
                "oracle monero anchor market",
            )?;
            ensure_key_exists(
                &self.mev_batches,
                &anchor.batch_id,
                "oracle monero anchor batch",
            )?;
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_oracle_settlement_state_root_from_record(record: &Value) -> String {
    private_oracle_settlement_record_root("STATE", record)
}

pub fn private_oracle_settlement_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-ORACLE-SETTLEMENT-{domain}"),
        &[
            HashPart::Int(PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION as i128),
            HashPart::Str(PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_oracle_settlement_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-ORACLE-SETTLEMENT-{domain}"),
        &[
            HashPart::Int(PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_oracle_settlement_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-ORACLE-SETTLEMENT-COMMITMENT-{domain}"),
        &[
            HashPart::Int(PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION as i128),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_oracle_settlement_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    private_oracle_settlement_payload_root(domain, &Value::Array(records))
}

fn private_oracle_settlement_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut owned_parts = Vec::with_capacity(parts.len().saturating_add(1));
    owned_parts.push(HashPart::Int(
        PRIVATE_ORACLE_SETTLEMENT_PROTOCOL_VERSION as i128,
    ));
    for part in parts {
        owned_parts.push(match part {
            HashPart::Bytes(value) => HashPart::Bytes(*value),
            HashPart::Str(value) => HashPart::Str(*value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(*value),
        });
    }
    domain_hash(
        &format!("PRIVATE-ORACLE-SETTLEMENT-{domain}"),
        &owned_parts,
        32,
    )
}

fn public_map<T>(map: &BTreeMap<String, T>, record_fn: fn(&T) -> Value) -> BTreeMap<String, Value> {
    map.iter()
        .map(|(key, value)| (key.clone(), record_fn(value)))
        .collect()
}

fn map_root(label: &str, map: &BTreeMap<String, Value>) -> String {
    private_oracle_settlement_payload_root(label, &json!(map))
}

fn bps_amount(value: u64, bps: u64) -> u64 {
    (((value as u128) * (bps as u128)) / (PRIVATE_ORACLE_SETTLEMENT_MAX_BPS as u128))
        .min(u64::MAX as u128) as u64
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateOracleSettlementResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateOracleSettlementResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateOracleSettlementResult<()> {
    if value > PRIVATE_ORACLE_SETTLEMENT_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> PrivateOracleSettlementResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> PrivateOracleSettlementResult<()> {
    if len > max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateOracleSettlementResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_key_exists<T>(
    map: &BTreeMap<String, T>,
    key: &str,
    label: &str,
) -> PrivateOracleSettlementResult<()> {
    ensure_non_empty(key, label)?;
    if !map.contains_key(key) {
        return Err(format!("{label} is missing"));
    }
    Ok(())
}

fn ensure_references<T>(
    ids: &[String],
    map: &BTreeMap<String, T>,
    label: &str,
) -> PrivateOracleSettlementResult<()> {
    ensure_string_set(ids, label)?;
    for id in ids {
        ensure_key_exists(map, id, label)?;
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivateOracleSettlementResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} duplicate id"));
    }
    map.insert(id, record);
    Ok(())
}
