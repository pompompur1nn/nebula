use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqOracleAttestationRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PROTOCOL_ID: &str =
    "nebula-private-l2-pq-oracle-attestation-runtime-v1";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PRIVACY_PROOF_SYSTEM: &str =
    "private-oracle-observation-range-proof-v1";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_BATCH_PROOF_SYSTEM: &str =
    "pq-oracle-committee-batch-attestation-v1";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_RECEIPT_SCHEME: &str =
    "low-fee-sponsored-oracle-receipt-v1";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_COMMITTEE_ID: &str =
    "private-l2-pq-oracle-devnet-committee";
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_HEIGHT: u64 = 31_104;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_OBSERVATION_TTL_BLOCKS: u64 = 40;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_RISK_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_COMMITTEE_MEMBERS: u64 = 5;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_FAST_QUORUM_BPS: u64 = 7_500;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 8_500;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_SPONSOR_FEE_CAP_UNITS: u64 = 4;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 250_000;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MAX_DEVIATION_BPS: u64 = 800;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_CAUTION_DEVIATION_BPS: u64 = 350;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_NULLIFIER_RETENTION_BLOCKS: u64 = 14_400;
pub const PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleFeedKind {
    XmrUsdSpot,
    XmrBtcSpot,
    TokenPrice,
    AmmTwap,
    LendingCollateral,
    PerpIndex,
    PerpFunding,
    StablecoinPeg,
    MoneroReserveCoverage,
    ProofFee,
    DataAvailabilityFee,
    SequencerLatency,
    SettlementGas,
}

impl OracleFeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmrUsdSpot => "xmr_usd_spot",
            Self::XmrBtcSpot => "xmr_btc_spot",
            Self::TokenPrice => "token_price",
            Self::AmmTwap => "amm_twap",
            Self::LendingCollateral => "lending_collateral",
            Self::PerpIndex => "perp_index",
            Self::PerpFunding => "perp_funding",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::MoneroReserveCoverage => "monero_reserve_coverage",
            Self::ProofFee => "proof_fee",
            Self::DataAvailabilityFee => "data_availability_fee",
            Self::SequencerLatency => "sequencer_latency",
            Self::SettlementGas => "settlement_gas",
        }
    }

    pub fn default_heartbeat_blocks(self) -> u64 {
        match self {
            Self::XmrUsdSpot | Self::XmrBtcSpot | Self::TokenPrice | Self::PerpIndex => 4,
            Self::AmmTwap | Self::PerpFunding | Self::StablecoinPeg => 8,
            Self::LendingCollateral | Self::MoneroReserveCoverage => 12,
            Self::ProofFee | Self::DataAvailabilityFee | Self::SequencerLatency => 16,
            Self::SettlementGas => 24,
        }
    }

    pub fn supports_fast_settlement(self) -> bool {
        matches!(
            self,
            Self::XmrUsdSpot
                | Self::XmrBtcSpot
                | Self::TokenPrice
                | Self::AmmTwap
                | Self::PerpIndex
                | Self::PerpFunding
                | Self::StablecoinPeg
                | Self::SequencerLatency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Active,
    Caution,
    Paused,
    Quarantined,
    Retired,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Caution => "caution",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_observations(self) -> bool {
        matches!(self, Self::Active | Self::Caution)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    PriceObserver,
    RiskAttester,
    BatchAggregator,
    SettlementPublisher,
    FeeSponsor,
    Watchtower,
    EmergencySigner,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceObserver => "price_observer",
            Self::RiskAttester => "risk_attester",
            Self::BatchAggregator => "batch_aggregator",
            Self::SettlementPublisher => "settlement_publisher",
            Self::FeeSponsor => "fee_sponsor",
            Self::Watchtower => "watchtower",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeMemberStatus {
    Pending,
    Active,
    Degraded,
    Suspended,
    Slashed,
    Retired,
}

impl CommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Clear,
    Caution,
    RaiseMargin,
    ClampPrice,
    HaltLiquidations,
    QuarantineFeed,
    EmergencyStop,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Caution => "caution",
            Self::RaiseMargin => "raise_margin",
            Self::ClampPrice => "clamp_price",
            Self::HaltLiquidations => "halt_liquidations",
            Self::QuarantineFeed => "quarantine_feed",
            Self::EmergencyStop => "emergency_stop",
        }
    }

    pub fn severity(self) -> u64 {
        match self {
            Self::Clear => 0,
            Self::Caution => 1,
            Self::RaiseMargin => 2,
            Self::ClampPrice => 3,
            Self::HaltLiquidations => 4,
            Self::QuarantineFeed => 5,
            Self::EmergencyStop => 6,
        }
    }

    pub fn restricts_settlement(self) -> bool {
        matches!(
            self,
            Self::ClampPrice | Self::HaltLiquidations | Self::QuarantineFeed | Self::EmergencyStop
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Requested,
    Observed,
    Aggregated,
    RiskAttested,
    SettlementReady,
    Published,
    Replayed,
    Rejected,
    Expired,
}

impl UpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Observed => "observed",
            Self::Aggregated => "aggregated",
            Self::RiskAttested => "risk_attested",
            Self::SettlementReady => "settlement_ready",
            Self::Published => "published",
            Self::Replayed => "replayed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    Counted,
    Duplicate,
    Replayed,
    Rejected,
    Expired,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::Replayed => "replayed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_batch(self) -> bool {
        matches!(self, Self::Submitted | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Prepared,
    Sponsored,
    Published,
    Audited,
    Disputed,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Sponsored => "sponsored",
            Self::Published => "published",
            Self::Audited => "audited",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    FeedRegistered,
    MemberRegistered,
    SponsorRegistered,
    ObservationSubmitted,
    BatchAggregated,
    RiskWindowAttested,
    ReceiptPublished,
    ReplayRejected,
    NullifierConsumed,
}

impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeedRegistered => "feed_registered",
            Self::MemberRegistered => "member_registered",
            Self::SponsorRegistered => "sponsor_registered",
            Self::ObservationSubmitted => "observation_submitted",
            Self::BatchAggregated => "batch_aggregated",
            Self::RiskWindowAttested => "risk_window_attested",
            Self::ReceiptPublished => "receipt_published",
            Self::ReplayRejected => "replay_rejected",
            Self::NullifierConsumed => "nullifier_consumed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub epoch_blocks: u64,
    pub observation_ttl_blocks: u64,
    pub risk_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub min_committee_members: u64,
    pub quorum_bps: u64,
    pub fast_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub sponsor_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub max_deviation_bps: u64,
    pub caution_deviation_bps: u64,
    pub nullifier_retention_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_NETWORK.to_string(),
            asset_id: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_ASSET_ID.to_string(),
            committee_id: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_COMMITTEE_ID.to_string(),
            epoch_blocks: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            observation_ttl_blocks:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_OBSERVATION_TTL_BLOCKS,
            risk_window_blocks: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_RISK_WINDOW_BLOCKS,
            receipt_ttl_blocks: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            fast_settlement_blocks:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS,
            min_committee_members:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_COMMITTEE_MEMBERS,
            quorum_bps: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_QUORUM_BPS,
            fast_quorum_bps: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_FAST_QUORUM_BPS,
            emergency_quorum_bps:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_EMERGENCY_QUORUM_BPS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            sponsor_fee_cap_units:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_SPONSOR_FEE_CAP_UNITS,
            sponsor_budget_units:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_deviation_bps: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_MAX_DEVIATION_BPS,
            caution_deviation_bps:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_CAUTION_DEVIATION_BPS,
            nullifier_retention_blocks:
                PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEFAULT_NULLIFIER_RETENTION_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "epoch_blocks": self.epoch_blocks,
            "observation_ttl_blocks": self.observation_ttl_blocks,
            "risk_window_blocks": self.risk_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "min_committee_members": self.min_committee_members,
            "quorum_bps": self.quorum_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "sponsor_fee_cap_units": self.sponsor_fee_cap_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_deviation_bps": self.max_deviation_bps,
            "caution_deviation_bps": self.caution_deviation_bps,
            "nullifier_retention_blocks": self.nullifier_retention_blocks,
        })
    }

    pub fn id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-ORACLE-CONFIG-ID",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub feed_sequence: u64,
    pub member_sequence: u64,
    pub sponsor_sequence: u64,
    pub observation_sequence: u64,
    pub batch_sequence: u64,
    pub risk_sequence: u64,
    pub receipt_sequence: u64,
    pub event_sequence: u64,
    pub rejected_replays: u64,
    pub consumed_nullifiers: u64,
    pub sponsored_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_sequence": self.feed_sequence,
            "member_sequence": self.member_sequence,
            "sponsor_sequence": self.sponsor_sequence,
            "observation_sequence": self.observation_sequence,
            "batch_sequence": self.batch_sequence,
            "risk_sequence": self.risk_sequence,
            "receipt_sequence": self.receipt_sequence,
            "event_sequence": self.event_sequence,
            "rejected_replays": self.rejected_replays,
            "consumed_nullifiers": self.consumed_nullifiers,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub feed_root: String,
    pub member_root: String,
    pub sponsor_root: String,
    pub observation_root: String,
    pub counted_observation_root: String,
    pub batch_root: String,
    pub risk_window_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "feed_root": self.feed_root,
            "member_root": self.member_root,
            "sponsor_root": self.sponsor_root,
            "observation_root": self.observation_root,
            "counted_observation_root": self.counted_observation_root,
            "batch_root": self.batch_root,
            "risk_window_root": self.risk_window_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterFeedRequest {
    pub label: String,
    pub kind: OracleFeedKind,
    pub quote_asset_id: String,
    pub base_asset_commitment: String,
    pub privacy_domain: String,
    pub committee_root: String,
    pub decimals: u8,
    pub heartbeat_blocks: u64,
    pub max_deviation_bps: u64,
    pub min_privacy_set_size: u64,
    pub fast_settlement: bool,
    pub sponsor_eligible: bool,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterMemberRequest {
    pub label: String,
    pub operator_commitment: String,
    pub roles: BTreeSet<CommitteeRole>,
    pub pq_public_key_root: String,
    pub stake_commitment: String,
    pub security_bits: u16,
    pub joined_at_height: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterSponsorRequest {
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub max_fee_per_update_units: u64,
    pub authorization_root: String,
    pub opened_at_height: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitPrivateObservationRequest {
    pub feed_id: String,
    pub observer_id: String,
    pub encrypted_value_root: String,
    pub value_commitment: String,
    pub range_proof_root: String,
    pub confidence_bps: u64,
    pub privacy_set_size: u64,
    pub source_commitment_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier: String,
    pub replay_domain: String,
    pub pq_signature_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateObservationBatchRequest {
    pub feed_id: String,
    pub aggregator_id: String,
    pub observation_ids: Vec<String>,
    pub median_commitment: String,
    pub dispersion_commitment: String,
    pub price_root: String,
    pub privacy_preserving_risk_root: String,
    pub settlement_feed_root: String,
    pub batch_proof_root: String,
    pub fast_settlement: bool,
    pub aggregated_at_height: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestRiskWindowRequest {
    pub feed_id: String,
    pub batch_id: String,
    pub attester_id: String,
    pub verdict: RiskVerdict,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub risk_root: String,
    pub guardrail_root: String,
    pub deviation_bps: u64,
    pub quorum_weight: u64,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishLowFeeOracleReceiptRequest {
    pub feed_id: String,
    pub batch_id: String,
    pub risk_window_id: String,
    pub sponsor_id: String,
    pub publisher_id: String,
    pub fee_units: u64,
    pub settlement_lane_root: String,
    pub receipt_payload_root: String,
    pub publish_height: u64,
    pub expires_at_height: u64,
    pub nullifier: String,
    pub replay_domain: String,
    pub pq_signature_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedRecord {
    pub feed_id: String,
    pub label: String,
    pub kind: OracleFeedKind,
    pub status: FeedStatus,
    pub quote_asset_id: String,
    pub base_asset_commitment: String,
    pub privacy_domain: String,
    pub committee_root: String,
    pub decimals: u8,
    pub heartbeat_blocks: u64,
    pub max_deviation_bps: u64,
    pub min_privacy_set_size: u64,
    pub fast_settlement: bool,
    pub sponsor_eligible: bool,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub latest_batch_id: Option<String>,
    pub latest_risk_window_id: Option<String>,
    pub latest_receipt_id: Option<String>,
}

impl FeedRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "label": self.label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "quote_asset_id": self.quote_asset_id,
            "base_asset_commitment": self.base_asset_commitment,
            "privacy_domain": self.privacy_domain,
            "committee_root": self.committee_root,
            "decimals": self.decimals,
            "heartbeat_blocks": self.heartbeat_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fast_settlement": self.fast_settlement,
            "sponsor_eligible": self.sponsor_eligible,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "latest_batch_id": self.latest_batch_id,
            "latest_risk_window_id": self.latest_risk_window_id,
            "latest_receipt_id": self.latest_receipt_id,
        })
    }

    pub fn id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-ORACLE-FEED-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMemberRecord {
    pub member_id: String,
    pub label: String,
    pub operator_commitment: String,
    pub roles: BTreeSet<CommitteeRole>,
    pub status: CommitteeMemberStatus,
    pub pq_public_key_root: String,
    pub stake_commitment: String,
    pub security_bits: u16,
    pub joined_at_height: u64,
    pub observations_counted: u64,
    pub batches_aggregated: u64,
    pub risk_attestations: u64,
    pub receipts_published: u64,
}

impl CommitteeMemberRecord {
    pub fn public_record(&self) -> Value {
        let roles = self
            .roles
            .iter()
            .map(|role| json!(role.as_str()))
            .collect::<Vec<_>>();
        json!({
            "member_id": self.member_id,
            "label": self.label,
            "operator_commitment": self.operator_commitment,
            "roles": roles,
            "status": self.status.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "stake_commitment": self.stake_commitment,
            "security_bits": self.security_bits,
            "joined_at_height": self.joined_at_height,
            "observations_counted": self.observations_counted,
            "batches_aggregated": self.batches_aggregated,
            "risk_attestations": self.risk_attestations,
            "receipts_published": self.receipts_published,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorRecord {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub status: SponsorStatus,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_update_units: u64,
    pub authorization_root: String,
    pub opened_at_height: u64,
}

impl SponsorRecord {
    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "status": self.status.as_str(),
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_fee_per_update_units": self.max_fee_per_update_units,
            "authorization_root": self.authorization_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub observation_id: String,
    pub feed_id: String,
    pub observer_id: String,
    pub status: ObservationStatus,
    pub encrypted_value_root: String,
    pub value_commitment: String,
    pub range_proof_root: String,
    pub confidence_bps: u64,
    pub privacy_set_size: u64,
    pub source_commitment_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_hash: String,
    pub replay_fence: String,
    pub pq_signature_root: String,
}

impl ObservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "feed_id": self.feed_id,
            "observer_id": self.observer_id,
            "status": self.status.as_str(),
            "encrypted_value_root": self.encrypted_value_root,
            "value_commitment": self.value_commitment,
            "range_proof_root": self.range_proof_root,
            "confidence_bps": self.confidence_bps,
            "privacy_set_size": self.privacy_set_size,
            "source_commitment_root": self.source_commitment_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_hash": self.nullifier_hash,
            "replay_fence": self.replay_fence,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservationBatchRecord {
    pub batch_id: String,
    pub feed_id: String,
    pub aggregator_id: String,
    pub status: UpdateStatus,
    pub observation_root: String,
    pub counted_weight: u64,
    pub quorum_bps: u64,
    pub median_commitment: String,
    pub dispersion_commitment: String,
    pub price_root: String,
    pub privacy_preserving_risk_root: String,
    pub settlement_feed_root: String,
    pub batch_proof_root: String,
    pub fast_settlement: bool,
    pub aggregated_at_height: u64,
}

impl ObservationBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "feed_id": self.feed_id,
            "aggregator_id": self.aggregator_id,
            "status": self.status.as_str(),
            "observation_root": self.observation_root,
            "counted_weight": self.counted_weight,
            "quorum_bps": self.quorum_bps,
            "median_commitment": self.median_commitment,
            "dispersion_commitment": self.dispersion_commitment,
            "price_root": self.price_root,
            "privacy_preserving_risk_root": self.privacy_preserving_risk_root,
            "settlement_feed_root": self.settlement_feed_root,
            "batch_proof_root": self.batch_proof_root,
            "fast_settlement": self.fast_settlement,
            "aggregated_at_height": self.aggregated_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskWindowRecord {
    pub risk_window_id: String,
    pub feed_id: String,
    pub batch_id: String,
    pub attester_id: String,
    pub verdict: RiskVerdict,
    pub status: UpdateStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub risk_root: String,
    pub guardrail_root: String,
    pub deviation_bps: u64,
    pub quorum_weight: u64,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
}

impl RiskWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_window_id": self.risk_window_id,
            "feed_id": self.feed_id,
            "batch_id": self.batch_id,
            "attester_id": self.attester_id,
            "verdict": self.verdict.as_str(),
            "status": self.status.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "risk_root": self.risk_root,
            "guardrail_root": self.guardrail_root,
            "deviation_bps": self.deviation_bps,
            "quorum_weight": self.quorum_weight,
            "pq_signature_root": self.pq_signature_root,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeOracleReceiptRecord {
    pub receipt_id: String,
    pub feed_id: String,
    pub batch_id: String,
    pub risk_window_id: String,
    pub sponsor_id: String,
    pub publisher_id: String,
    pub status: ReceiptStatus,
    pub fee_units: u64,
    pub settlement_lane_root: String,
    pub receipt_payload_root: String,
    pub publish_height: u64,
    pub expires_at_height: u64,
    pub nullifier_hash: String,
    pub replay_fence: String,
    pub pq_signature_root: String,
}

impl LowFeeOracleReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "feed_id": self.feed_id,
            "batch_id": self.batch_id,
            "risk_window_id": self.risk_window_id,
            "sponsor_id": self.sponsor_id,
            "publisher_id": self.publisher_id,
            "status": self.status.as_str(),
            "fee_units": self.fee_units,
            "settlement_lane_root": self.settlement_lane_root,
            "receipt_payload_root": self.receipt_payload_root,
            "publish_height": self.publish_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_hash": self.nullifier_hash,
            "replay_fence": self.replay_fence,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEventRecord {
    pub event_id: String,
    pub sequence: u64,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub actor_id: String,
    pub height: u64,
    pub event_root: String,
}

impl RuntimeEventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "actor_id": self.actor_id,
            "height": self.height,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub feeds: BTreeMap<String, FeedRecord>,
    pub committee_members: BTreeMap<String, CommitteeMemberRecord>,
    pub sponsors: BTreeMap<String, SponsorRecord>,
    pub observations: BTreeMap<String, ObservationRecord>,
    pub batches: BTreeMap<String, ObservationBatchRecord>,
    pub risk_windows: BTreeMap<String, RiskWindowRecord>,
    pub receipts: BTreeMap<String, LowFeeOracleReceiptRecord>,
    pub events: Vec<RuntimeEventRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub replay_fences: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            feeds: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            observations: BTreeMap::new(),
            batches: BTreeMap::new(),
            risk_windows: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: Vec::new(),
            consumed_nullifiers: BTreeSet::new(),
            replay_fences: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let mut observer_roles = BTreeSet::new();
        observer_roles.insert(CommitteeRole::PriceObserver);
        observer_roles.insert(CommitteeRole::RiskAttester);
        observer_roles.insert(CommitteeRole::BatchAggregator);
        observer_roles.insert(CommitteeRole::SettlementPublisher);
        observer_roles.insert(CommitteeRole::Watchtower);

        for label in [
            "devnet-oracle-alpha",
            "devnet-oracle-beta",
            "devnet-oracle-gamma",
            "devnet-oracle-delta",
            "devnet-oracle-epsilon",
        ] {
            let _ = state.register_member(RegisterMemberRequest {
                label: label.to_string(),
                operator_commitment: commitment_id("DEVNET-ORACLE-OPERATOR", label),
                roles: observer_roles.clone(),
                pq_public_key_root: commitment_id("DEVNET-ORACLE-PQ-KEY", label),
                stake_commitment: commitment_id("DEVNET-ORACLE-STAKE", label),
                security_bits: 256,
                joined_at_height: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_HEIGHT,
                nonce: format!("{label}-member-nonce"),
            });
        }

        let _ = state.register_sponsor(RegisterSponsorRequest {
            sponsor_commitment: commitment_id("DEVNET-ORACLE-SPONSOR", "low-fee-pool"),
            fee_asset_id: state.config.asset_id.clone(),
            budget_units: state.config.sponsor_budget_units,
            max_fee_per_update_units: state.config.sponsor_fee_cap_units,
            authorization_root: commitment_id("DEVNET-ORACLE-SPONSOR-AUTH", "low-fee-pool"),
            opened_at_height: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_HEIGHT,
            nonce: "devnet-low-fee-sponsor-nonce".to_string(),
        });

        let _ = state.register_feed(RegisterFeedRequest {
            label: "XMR/USD private fast settlement".to_string(),
            kind: OracleFeedKind::XmrUsdSpot,
            quote_asset_id: "asset:usd".to_string(),
            base_asset_commitment: commitment_id("DEVNET-ORACLE-ASSET", "xmr"),
            privacy_domain: "monero-l2-private-price".to_string(),
            committee_root: state.active_committee_root(),
            decimals: 8,
            heartbeat_blocks: OracleFeedKind::XmrUsdSpot.default_heartbeat_blocks(),
            max_deviation_bps: state.config.max_deviation_bps,
            min_privacy_set_size: state.config.min_privacy_set_size,
            fast_settlement: true,
            sponsor_eligible: true,
            metadata_root: commitment_id("DEVNET-ORACLE-FEED-METADATA", "xmr-usd"),
            opened_at_height: PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_DEVNET_HEIGHT,
            nonce: "devnet-xmr-usd-feed-nonce".to_string(),
        });

        state
    }

    pub fn register_feed(
        &mut self,
        request: RegisterFeedRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<FeedRecord> {
        ensure_not_empty("label", &request.label)?;
        ensure_not_empty("quote_asset_id", &request.quote_asset_id)?;
        ensure_not_empty("base_asset_commitment", &request.base_asset_commitment)?;
        ensure_not_empty("committee_root", &request.committee_root)?;
        ensure_bps("max_deviation_bps", request.max_deviation_bps)?;
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("feed privacy set is below runtime minimum".to_string());
        }
        if request.fast_settlement && !request.kind.supports_fast_settlement() {
            return Err("feed kind does not support fast settlement".to_string());
        }
        let replay_fence = feed_replay_fence(&request);
        self.consume_replay_fence(&replay_fence)?;

        self.counters.feed_sequence = self.counters.feed_sequence.saturating_add(1);
        let feed_id = feed_id(self.counters.feed_sequence, &request);
        let record = FeedRecord {
            feed_id: feed_id.clone(),
            label: request.label,
            kind: request.kind,
            status: FeedStatus::Active,
            quote_asset_id: request.quote_asset_id,
            base_asset_commitment: request.base_asset_commitment,
            privacy_domain: request.privacy_domain,
            committee_root: request.committee_root,
            decimals: request.decimals,
            heartbeat_blocks: request.heartbeat_blocks,
            max_deviation_bps: request.max_deviation_bps,
            min_privacy_set_size: request.min_privacy_set_size,
            fast_settlement: request.fast_settlement,
            sponsor_eligible: request.sponsor_eligible,
            metadata_root: request.metadata_root,
            opened_at_height: request.opened_at_height,
            latest_batch_id: None,
            latest_risk_window_id: None,
            latest_receipt_id: None,
        };
        self.feeds.insert(feed_id.clone(), record.clone());
        let actor_id = self.config.committee_id.clone();
        self.push_event(
            RuntimeEventKind::FeedRegistered,
            &feed_id,
            &actor_id,
            record.opened_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn register_member(
        &mut self,
        request: RegisterMemberRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<CommitteeMemberRecord> {
        ensure_not_empty("label", &request.label)?;
        ensure_not_empty("operator_commitment", &request.operator_commitment)?;
        ensure_not_empty("pq_public_key_root", &request.pq_public_key_root)?;
        if request.roles.is_empty() {
            return Err("committee member must have at least one role".to_string());
        }
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("committee member pq security bits below runtime minimum".to_string());
        }
        let replay_fence = member_replay_fence(&request);
        self.consume_replay_fence(&replay_fence)?;

        self.counters.member_sequence = self.counters.member_sequence.saturating_add(1);
        let member_id = member_id(self.counters.member_sequence, &request);
        let record = CommitteeMemberRecord {
            member_id: member_id.clone(),
            label: request.label,
            operator_commitment: request.operator_commitment,
            roles: request.roles,
            status: CommitteeMemberStatus::Active,
            pq_public_key_root: request.pq_public_key_root,
            stake_commitment: request.stake_commitment,
            security_bits: request.security_bits,
            joined_at_height: request.joined_at_height,
            observations_counted: 0,
            batches_aggregated: 0,
            risk_attestations: 0,
            receipts_published: 0,
        };
        self.committee_members
            .insert(member_id.clone(), record.clone());
        let actor_id = self.config.committee_id.clone();
        self.push_event(
            RuntimeEventKind::MemberRegistered,
            &member_id,
            &actor_id,
            record.joined_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn register_sponsor(
        &mut self,
        request: RegisterSponsorRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<SponsorRecord> {
        ensure_not_empty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_not_empty("fee_asset_id", &request.fee_asset_id)?;
        ensure_not_empty("authorization_root", &request.authorization_root)?;
        if request.budget_units == 0 {
            return Err("sponsor budget must be non-zero".to_string());
        }
        if request.max_fee_per_update_units > self.config.sponsor_fee_cap_units {
            return Err("sponsor fee cap exceeds runtime cap".to_string());
        }
        let replay_fence = sponsor_replay_fence(&request);
        self.consume_replay_fence(&replay_fence)?;

        self.counters.sponsor_sequence = self.counters.sponsor_sequence.saturating_add(1);
        let sponsor_id = sponsor_id(self.counters.sponsor_sequence, &request);
        let record = SponsorRecord {
            sponsor_id: sponsor_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            fee_asset_id: request.fee_asset_id,
            status: SponsorStatus::Active,
            budget_units: request.budget_units,
            spent_units: 0,
            max_fee_per_update_units: request.max_fee_per_update_units,
            authorization_root: request.authorization_root,
            opened_at_height: request.opened_at_height,
        };
        self.sponsors.insert(sponsor_id.clone(), record.clone());
        let actor_id = self.config.committee_id.clone();
        self.push_event(
            RuntimeEventKind::SponsorRegistered,
            &sponsor_id,
            &actor_id,
            record.opened_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn submit_private_observation(
        &mut self,
        request: SubmitPrivateObservationRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<ObservationRecord> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "unknown feed".to_string())?;
        if !feed.status.accepts_observations() {
            return Err("feed does not accept observations".to_string());
        }
        let member = self
            .committee_members
            .get(&request.observer_id)
            .ok_or_else(|| "unknown observer".to_string())?;
        ensure_member_role(member, CommitteeRole::PriceObserver)?;
        ensure_member_live(member)?;
        ensure_bps("confidence_bps", request.confidence_bps)?;
        if request.privacy_set_size < feed.min_privacy_set_size {
            return Err("observation privacy set below feed minimum".to_string());
        }
        if request.expires_at_height <= request.observed_at_height {
            return Err("observation expiry must be after observation height".to_string());
        }
        if request
            .expires_at_height
            .saturating_sub(request.observed_at_height)
            > self.config.observation_ttl_blocks
        {
            return Err("observation ttl exceeds runtime ttl".to_string());
        }

        let nullifier_hash = nullifier_hash("OBSERVATION", &request.nullifier);
        if self.consumed_nullifiers.contains(&nullifier_hash) {
            self.counters.rejected_replays = self.counters.rejected_replays.saturating_add(1);
            self.push_replay_event(
                &request.feed_id,
                &request.observer_id,
                request.observed_at_height,
            );
            return Err("observation nullifier already consumed".to_string());
        }
        let replay_fence = observation_replay_fence(&request);
        self.consume_replay_fence(&replay_fence)?;
        self.consume_nullifier(
            &nullifier_hash,
            &request.feed_id,
            &request.observer_id,
            request.observed_at_height,
        );

        self.counters.observation_sequence = self.counters.observation_sequence.saturating_add(1);
        let observation_id = observation_id(self.counters.observation_sequence, &request);
        let record = ObservationRecord {
            observation_id: observation_id.clone(),
            feed_id: request.feed_id,
            observer_id: request.observer_id,
            status: ObservationStatus::Submitted,
            encrypted_value_root: request.encrypted_value_root,
            value_commitment: request.value_commitment,
            range_proof_root: request.range_proof_root,
            confidence_bps: request.confidence_bps,
            privacy_set_size: request.privacy_set_size,
            source_commitment_root: request.source_commitment_root,
            observed_at_height: request.observed_at_height,
            expires_at_height: request.expires_at_height,
            nullifier_hash,
            replay_fence,
            pq_signature_root: request.pq_signature_root,
        };
        self.observations
            .insert(observation_id.clone(), record.clone());
        if let Some(member) = self.committee_members.get_mut(&record.observer_id) {
            member.observations_counted = member.observations_counted.saturating_add(1);
        }
        self.push_event(
            RuntimeEventKind::ObservationSubmitted,
            &observation_id,
            &record.observer_id.clone(),
            record.observed_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn aggregate_observation_batch(
        &mut self,
        request: AggregateObservationBatchRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<ObservationBatchRecord> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "unknown feed".to_string())?;
        if !feed.status.accepts_observations() {
            return Err("feed does not accept aggregation".to_string());
        }
        if request.fast_settlement && !feed.fast_settlement {
            return Err("feed does not allow fast settlement batches".to_string());
        }
        let aggregator = self
            .committee_members
            .get(&request.aggregator_id)
            .ok_or_else(|| "unknown aggregator".to_string())?;
        ensure_member_role(aggregator, CommitteeRole::BatchAggregator)?;
        ensure_member_live(aggregator)?;
        if request.observation_ids.is_empty() {
            return Err("batch must include observations".to_string());
        }

        let mut leaves = Vec::with_capacity(request.observation_ids.len());
        let mut unique_observers = BTreeSet::new();
        let mut counted_weight = 0_u64;
        for observation_id in &request.observation_ids {
            let observation = self
                .observations
                .get(observation_id)
                .ok_or_else(|| format!("unknown observation {observation_id}"))?;
            if observation.feed_id != request.feed_id {
                return Err("batch contains observation for another feed".to_string());
            }
            if !observation.status.counts_for_batch() {
                return Err("batch contains non-countable observation".to_string());
            }
            if observation.expires_at_height < request.aggregated_at_height {
                return Err("batch contains expired observation".to_string());
            }
            unique_observers.insert(observation.observer_id.clone());
            leaves.push(observation.public_record());
        }
        counted_weight = counted_weight.saturating_add(unique_observers.len() as u64);
        if counted_weight < self.config.min_committee_members {
            return Err("batch has insufficient unique committee observations".to_string());
        }
        let quorum_bps = quorum_bps(counted_weight, self.voting_member_count());
        let required_bps = if request.fast_settlement {
            self.config.fast_quorum_bps
        } else {
            self.config.quorum_bps
        };
        if quorum_bps < required_bps {
            return Err("batch quorum below required threshold".to_string());
        }

        self.counters.batch_sequence = self.counters.batch_sequence.saturating_add(1);
        let observation_root = merkle_root("PRIVATE-L2-PQ-ORACLE-BATCH-OBSERVATIONS", &leaves);
        let batch_id = batch_id(
            self.counters.batch_sequence,
            &request.feed_id,
            &observation_root,
            &request.nonce,
        );
        let record = ObservationBatchRecord {
            batch_id: batch_id.clone(),
            feed_id: request.feed_id,
            aggregator_id: request.aggregator_id,
            status: UpdateStatus::Aggregated,
            observation_root,
            counted_weight,
            quorum_bps,
            median_commitment: request.median_commitment,
            dispersion_commitment: request.dispersion_commitment,
            price_root: request.price_root,
            privacy_preserving_risk_root: request.privacy_preserving_risk_root,
            settlement_feed_root: request.settlement_feed_root,
            batch_proof_root: request.batch_proof_root,
            fast_settlement: request.fast_settlement,
            aggregated_at_height: request.aggregated_at_height,
        };
        for observation_id in request.observation_ids {
            if let Some(observation) = self.observations.get_mut(&observation_id) {
                observation.status = ObservationStatus::Counted;
            }
        }
        if let Some(feed) = self.feeds.get_mut(&record.feed_id) {
            feed.latest_batch_id = Some(batch_id.clone());
        }
        if let Some(member) = self.committee_members.get_mut(&record.aggregator_id) {
            member.batches_aggregated = member.batches_aggregated.saturating_add(1);
        }
        self.batches.insert(batch_id.clone(), record.clone());
        self.push_event(
            RuntimeEventKind::BatchAggregated,
            &batch_id,
            &record.aggregator_id.clone(),
            record.aggregated_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn attest_risk_window(
        &mut self,
        request: AttestRiskWindowRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<RiskWindowRecord> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "unknown feed".to_string())?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if batch.feed_id != request.feed_id {
            return Err("risk window batch/feed mismatch".to_string());
        }
        let attester = self
            .committee_members
            .get(&request.attester_id)
            .ok_or_else(|| "unknown risk attester".to_string())?;
        ensure_member_role(attester, CommitteeRole::RiskAttester)?;
        ensure_member_live(attester)?;
        if request.window_end_height <= request.window_start_height {
            return Err("risk window end must be after start".to_string());
        }
        if request
            .window_end_height
            .saturating_sub(request.window_start_height)
            > self.config.risk_window_blocks
        {
            return Err("risk window exceeds runtime maximum".to_string());
        }
        if request.deviation_bps > feed.max_deviation_bps
            && request.verdict.severity() < RiskVerdict::Caution.severity()
        {
            return Err("high deviation requires at least caution verdict".to_string());
        }
        let required_bps = if request.verdict == RiskVerdict::EmergencyStop {
            self.config.emergency_quorum_bps
        } else if batch.fast_settlement {
            self.config.fast_quorum_bps
        } else {
            self.config.quorum_bps
        };
        let attained_bps = quorum_bps(request.quorum_weight, self.voting_member_count());
        if attained_bps < required_bps {
            return Err("risk attestation quorum below threshold".to_string());
        }

        self.counters.risk_sequence = self.counters.risk_sequence.saturating_add(1);
        let risk_window_id = risk_window_id(
            self.counters.risk_sequence,
            &request.feed_id,
            &request.batch_id,
            &request.risk_root,
            &request.nonce,
        );
        let status = if request.verdict.restricts_settlement() {
            UpdateStatus::RiskAttested
        } else {
            UpdateStatus::SettlementReady
        };
        let record = RiskWindowRecord {
            risk_window_id: risk_window_id.clone(),
            feed_id: request.feed_id,
            batch_id: request.batch_id,
            attester_id: request.attester_id,
            verdict: request.verdict,
            status,
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            risk_root: request.risk_root,
            guardrail_root: request.guardrail_root,
            deviation_bps: request.deviation_bps,
            quorum_weight: request.quorum_weight,
            pq_signature_root: request.pq_signature_root,
            attested_at_height: request.attested_at_height,
        };
        if let Some(batch) = self.batches.get_mut(&record.batch_id) {
            batch.status = record.status;
        }
        if let Some(feed) = self.feeds.get_mut(&record.feed_id) {
            feed.latest_risk_window_id = Some(risk_window_id.clone());
            feed.status = match record.verdict {
                RiskVerdict::Clear => FeedStatus::Active,
                RiskVerdict::Caution | RiskVerdict::RaiseMargin | RiskVerdict::ClampPrice => {
                    FeedStatus::Caution
                }
                RiskVerdict::HaltLiquidations | RiskVerdict::QuarantineFeed => {
                    FeedStatus::Quarantined
                }
                RiskVerdict::EmergencyStop => FeedStatus::Paused,
            };
        }
        if let Some(member) = self.committee_members.get_mut(&record.attester_id) {
            member.risk_attestations = member.risk_attestations.saturating_add(1);
        }
        self.risk_windows
            .insert(risk_window_id.clone(), record.clone());
        self.push_event(
            RuntimeEventKind::RiskWindowAttested,
            &risk_window_id,
            &record.attester_id.clone(),
            record.attested_at_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn publish_low_fee_oracle_receipt(
        &mut self,
        request: PublishLowFeeOracleReceiptRequest,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<LowFeeOracleReceiptRecord> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "unknown feed".to_string())?;
        if !feed.sponsor_eligible {
            return Err("feed is not sponsor eligible".to_string());
        }
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if batch.feed_id != request.feed_id {
            return Err("receipt batch/feed mismatch".to_string());
        }
        let risk_window = self
            .risk_windows
            .get(&request.risk_window_id)
            .ok_or_else(|| "unknown risk window".to_string())?;
        if risk_window.batch_id != request.batch_id {
            return Err("receipt risk window/batch mismatch".to_string());
        }
        if risk_window.verdict.restricts_settlement() {
            return Err("risk verdict restricts settlement publication".to_string());
        }
        let publisher = self
            .committee_members
            .get(&request.publisher_id)
            .ok_or_else(|| "unknown publisher".to_string())?;
        ensure_member_role(publisher, CommitteeRole::SettlementPublisher)?;
        ensure_member_live(publisher)?;
        let sponsor = self
            .sponsors
            .get(&request.sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        if !sponsor.status.can_sponsor() {
            return Err("sponsor cannot publish receipts".to_string());
        }
        if request.fee_units > sponsor.max_fee_per_update_units {
            return Err("receipt fee exceeds sponsor update cap".to_string());
        }
        if request.fee_units > sponsor.remaining_units() {
            return Err("receipt fee exceeds sponsor remaining budget".to_string());
        }
        if request.expires_at_height <= request.publish_height {
            return Err("receipt expiry must be after publish height".to_string());
        }
        if request
            .expires_at_height
            .saturating_sub(request.publish_height)
            > self.config.receipt_ttl_blocks
        {
            return Err("receipt ttl exceeds runtime ttl".to_string());
        }

        let nullifier_hash = nullifier_hash("RECEIPT", &request.nullifier);
        if self.consumed_nullifiers.contains(&nullifier_hash) {
            self.counters.rejected_replays = self.counters.rejected_replays.saturating_add(1);
            self.push_replay_event(
                &request.feed_id,
                &request.publisher_id,
                request.publish_height,
            );
            return Err("receipt nullifier already consumed".to_string());
        }
        let replay_fence = receipt_replay_fence(&request);
        self.consume_replay_fence(&replay_fence)?;
        self.consume_nullifier(
            &nullifier_hash,
            &request.feed_id,
            &request.publisher_id,
            request.publish_height,
        );

        self.counters.receipt_sequence = self.counters.receipt_sequence.saturating_add(1);
        let receipt_id = receipt_id(
            self.counters.receipt_sequence,
            &request.feed_id,
            &request.batch_id,
            &request.risk_window_id,
            &request.receipt_payload_root,
            &request.nonce,
        );
        let record = LowFeeOracleReceiptRecord {
            receipt_id: receipt_id.clone(),
            feed_id: request.feed_id,
            batch_id: request.batch_id,
            risk_window_id: request.risk_window_id,
            sponsor_id: request.sponsor_id,
            publisher_id: request.publisher_id,
            status: ReceiptStatus::Published,
            fee_units: request.fee_units,
            settlement_lane_root: request.settlement_lane_root,
            receipt_payload_root: request.receipt_payload_root,
            publish_height: request.publish_height,
            expires_at_height: request.expires_at_height,
            nullifier_hash,
            replay_fence,
            pq_signature_root: request.pq_signature_root,
        };
        if let Some(sponsor) = self.sponsors.get_mut(&record.sponsor_id) {
            sponsor.spent_units = sponsor.spent_units.saturating_add(record.fee_units);
            if sponsor.remaining_units() == 0 {
                sponsor.status = SponsorStatus::Exhausted;
            }
        }
        if let Some(batch) = self.batches.get_mut(&record.batch_id) {
            batch.status = UpdateStatus::Published;
        }
        if let Some(feed) = self.feeds.get_mut(&record.feed_id) {
            feed.latest_receipt_id = Some(receipt_id.clone());
        }
        if let Some(member) = self.committee_members.get_mut(&record.publisher_id) {
            member.receipts_published = member.receipts_published.saturating_add(1);
        }
        self.counters.sponsored_fee_units = self
            .counters
            .sponsored_fee_units
            .saturating_add(record.fee_units);
        self.receipts.insert(receipt_id.clone(), record.clone());
        self.push_event(
            RuntimeEventKind::ReceiptPublished,
            &receipt_id,
            &record.publisher_id.clone(),
            record.publish_height,
            &record.public_record(),
        );
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let feed_records = self
            .feeds
            .values()
            .map(FeedRecord::public_record)
            .collect::<Vec<_>>();
        let member_records = self
            .committee_members
            .values()
            .map(CommitteeMemberRecord::public_record)
            .collect::<Vec<_>>();
        let sponsor_records = self
            .sponsors
            .values()
            .map(SponsorRecord::public_record)
            .collect::<Vec<_>>();
        let observation_records = self
            .observations
            .values()
            .map(ObservationRecord::public_record)
            .collect::<Vec<_>>();
        let counted_observation_records = self
            .observations
            .values()
            .filter(|record| record.status == ObservationStatus::Counted)
            .map(ObservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(ObservationBatchRecord::public_record)
            .collect::<Vec<_>>();
        let risk_window_records = self
            .risk_windows
            .values()
            .map(RiskWindowRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(LowFeeOracleReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .iter()
            .map(RuntimeEventRecord::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|value| json!(value))
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_fences
            .iter()
            .map(|value| json!(value))
            .collect::<Vec<_>>();

        let config_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-CONFIG",
            &[self.config.public_record()],
        );
        let counter_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-COUNTERS",
            &[self.counters.public_record()],
        );
        let feed_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-FEEDS", &feed_records);
        let member_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-MEMBERS", &member_records);
        let sponsor_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-SPONSORS", &sponsor_records);
        let observation_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-OBSERVATIONS",
            &observation_records,
        );
        let counted_observation_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-COUNTED-OBSERVATIONS",
            &counted_observation_records,
        );
        let batch_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-BATCHES", &batch_records);
        let risk_window_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-RISK-WINDOWS",
            &risk_window_records,
        );
        let receipt_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-RECEIPTS", &receipt_records);
        let event_root = merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-EVENTS", &event_records);
        let nullifier_root =
            merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-NULLIFIERS", &nullifier_records);
        let replay_fence_root =
            merkle_root("PRIVATE-L2-PQ-ORACLE-STATE-REPLAY-FENCES", &replay_records);
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-ORACLE-STATE-PUBLIC-RECORDS",
            &[
                json!(config_root),
                json!(counter_root),
                json!(feed_root),
                json!(member_root),
                json!(sponsor_root),
                json!(observation_root),
                json!(counted_observation_root),
                json!(batch_root),
                json!(risk_window_root),
                json!(receipt_root),
                json!(event_root),
                json!(nullifier_root),
                json!(replay_fence_root),
            ],
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-ORACLE-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PROTOCOL_ID),
                HashPart::Str(&public_record_root),
            ],
            32,
        );

        Roots {
            config_root,
            counter_root,
            feed_root,
            member_root,
            sponsor_root,
            observation_root,
            counted_observation_root,
            batch_root,
            risk_window_root,
            receipt_root,
            event_root,
            nullifier_root,
            replay_fence_root,
            public_record_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_id": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PROTOCOL_ID,
            "schema_version": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_HASH_SUITE,
            "pq_signature_scheme": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_SIGNATURE_SCHEME,
            "pq_backup_scheme": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_BACKUP_SCHEME,
            "pq_kem_scheme": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PQ_KEM_SCHEME,
            "privacy_proof_system": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PRIVACY_PROOF_SYSTEM,
            "batch_proof_system": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_BATCH_PROOF_SYSTEM,
            "receipt_scheme": PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_RECEIPT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn active_committee_root(&self) -> String {
        let records = self
            .committee_members
            .values()
            .filter(|member| member.status.can_attest())
            .map(CommitteeMemberRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-L2-PQ-ORACLE-ACTIVE-COMMITTEE", &records)
    }

    pub fn voting_member_count(&self) -> u64 {
        self.committee_members
            .values()
            .filter(|member| member.status.can_attest())
            .count() as u64
    }

    fn consume_replay_fence(
        &mut self,
        replay_fence: &str,
    ) -> PrivateL2PqOracleAttestationRuntimeResult<()> {
        if self.replay_fences.contains(replay_fence) {
            self.counters.rejected_replays = self.counters.rejected_replays.saturating_add(1);
            return Err("replay fence already consumed".to_string());
        }
        self.replay_fences.insert(replay_fence.to_string());
        Ok(())
    }

    fn consume_nullifier(
        &mut self,
        nullifier_hash: &str,
        subject_id: &str,
        actor_id: &str,
        height: u64,
    ) {
        self.consumed_nullifiers.insert(nullifier_hash.to_string());
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        self.push_event(
            RuntimeEventKind::NullifierConsumed,
            subject_id,
            actor_id,
            height,
            &json!({ "nullifier_hash": nullifier_hash }),
        );
    }

    fn push_replay_event(&mut self, subject_id: &str, actor_id: &str, height: u64) {
        self.push_event(
            RuntimeEventKind::ReplayRejected,
            subject_id,
            actor_id,
            height,
            &json!({
                "subject_id": subject_id,
                "actor_id": actor_id,
                "height": height,
                "rejected_replays": self.counters.rejected_replays,
            }),
        );
    }

    fn push_event(
        &mut self,
        kind: RuntimeEventKind,
        subject_id: &str,
        actor_id: &str,
        height: u64,
        payload: &Value,
    ) {
        self.counters.event_sequence = self.counters.event_sequence.saturating_add(1);
        let event_root = domain_hash(
            "PRIVATE-L2-PQ-ORACLE-EVENT-PAYLOAD",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
            32,
        );
        let event_id = event_id(
            self.counters.event_sequence,
            kind,
            subject_id,
            actor_id,
            &event_root,
        );
        self.events.push(RuntimeEventRecord {
            event_id,
            sequence: self.counters.event_sequence,
            kind,
            subject_id: subject_id.to_string(),
            actor_id: actor_id.to_string(),
            height,
            event_root,
        });
    }
}

pub fn public_record_hash(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-PUBLIC-RECORD-HASH",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_l2_pq_oracle_state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_feed_id(sequence: u64, request: &RegisterFeedRequest) -> String {
    feed_id(sequence, request)
}

pub fn deterministic_observation_id(
    sequence: u64,
    request: &SubmitPrivateObservationRequest,
) -> String {
    observation_id(sequence, request)
}

pub fn deterministic_batch_id(
    sequence: u64,
    feed_id: &str,
    observation_root: &str,
    nonce: &str,
) -> String {
    batch_id(sequence, feed_id, observation_root, nonce)
}

pub fn deterministic_risk_window_id(
    sequence: u64,
    feed_id: &str,
    batch_id: &str,
    risk_root: &str,
    nonce: &str,
) -> String {
    risk_window_id(sequence, feed_id, batch_id, risk_root, nonce)
}

pub fn deterministic_receipt_id(
    sequence: u64,
    feed_id: &str,
    batch_id: &str,
    risk_window_id: &str,
    receipt_payload_root: &str,
    nonce: &str,
) -> String {
    receipt_id(
        sequence,
        feed_id,
        batch_id,
        risk_window_id,
        receipt_payload_root,
        nonce,
    )
}

fn ensure_not_empty(label: &str, value: &str) -> PrivateL2PqOracleAttestationRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> PrivateL2PqOracleAttestationRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds max basis points"))
    } else {
        Ok(())
    }
}

fn ensure_member_live(
    member: &CommitteeMemberRecord,
) -> PrivateL2PqOracleAttestationRuntimeResult<()> {
    if member.status.can_attest() {
        Ok(())
    } else {
        Err("committee member cannot attest".to_string())
    }
}

fn ensure_member_role(
    member: &CommitteeMemberRecord,
    role: CommitteeRole,
) -> PrivateL2PqOracleAttestationRuntimeResult<()> {
    if member.roles.contains(&role) {
        Ok(())
    } else {
        Err(format!("committee member lacks role {}", role.as_str()))
    }
}

fn quorum_bps(weight: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    weight.saturating_mul(PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_MAX_BPS) / total
}

fn feed_id(sequence: u64, request: &RegisterFeedRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.label),
            HashPart::Str(&request.quote_asset_id),
            HashPart::Str(&request.base_asset_commitment),
            HashPart::Str(&request.privacy_domain),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn member_id(sequence: u64, request: &RegisterMemberRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn sponsor_id(sequence: u64, request: &RegisterSponsorRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn observation_id(sequence: u64, request: &SubmitPrivateObservationRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.observer_id),
            HashPart::Str(&request.value_commitment),
            HashPart::Str(&request.range_proof_root),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn batch_id(sequence: u64, feed_id: &str, observation_root: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(feed_id),
            HashPart::Str(observation_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn risk_window_id(
    sequence: u64,
    feed_id: &str,
    batch_id: &str,
    risk_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-RISK-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(feed_id),
            HashPart::Str(batch_id),
            HashPart::Str(risk_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn receipt_id(
    sequence: u64,
    feed_id: &str,
    batch_id: &str,
    risk_window_id: &str,
    receipt_payload_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(feed_id),
            HashPart::Str(batch_id),
            HashPart::Str(risk_window_id),
            HashPart::Str(receipt_payload_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn event_id(
    sequence: u64,
    kind: RuntimeEventKind,
    subject_id: &str,
    actor_id: &str,
    event_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(actor_id),
            HashPart::Str(event_root),
        ],
        32,
    )
}

fn feed_replay_fence(request: &RegisterFeedRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-FEED-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.label),
            HashPart::Str(&request.quote_asset_id),
            HashPart::Str(&request.base_asset_commitment),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn member_replay_fence(request: &RegisterMemberRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-MEMBER-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn sponsor_replay_fence(request: &RegisterSponsorRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-SPONSOR-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.authorization_root),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn observation_replay_fence(request: &SubmitPrivateObservationRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-OBSERVATION-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.replay_domain),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.observer_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn receipt_replay_fence(request: &PublishLowFeeOracleReceiptRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-RECEIPT-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.replay_domain),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.risk_window_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.nonce),
        ],
        32,
    )
}

fn nullifier_hash(scope: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

fn commitment_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ORACLE_ATTESTATION_RUNTIME_PROTOCOL_ID),
            HashPart::Str(label),
        ],
        32,
    )
}
