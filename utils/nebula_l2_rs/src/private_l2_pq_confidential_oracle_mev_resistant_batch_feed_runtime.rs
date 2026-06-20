use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialOracleMevResistantBatchFeedRuntimeResult<T> = Result<T>;
pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-oracle-mev-resistant-batch-feed-runtime-v1";
pub const PQ_CONFIDENTIAL_ORACLE_MEV_RESISTANT_BATCH_FEED_PROTOCOL: &str =
    "pq-confidential-oracle-mev-resistant-batch-feed-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-confidential-feed-observation-v1";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-feed-committee-v1";
pub const OBSERVATION_ENCRYPTION_SUITE: &str = "pq-sealed-feed-observation-envelope-v1";
pub const REVEAL_WINDOW_SUITE: &str = "threshold-delay-feed-reveal-window-v1";
pub const PRICE_PROOF_SUITE: &str = "zk-defi-confidential-price-proof-v1";
pub const RECURSIVE_RECEIPT_SUITE: &str = "recursive-feed-proof-receipt-v1";
pub const NULLIFIER_FENCE_SUITE: &str = "feed-nullifier-fence-root-v1";
pub const SPONSOR_REBATE_SUITE: &str = "low-fee-feed-sponsor-rebate-v1";
pub const SLASHING_EVIDENCE_SUITE: &str = "pq-signed-feed-slashing-challenge-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_ID: &str = "pq-confidential-feed-devnet-committee";
pub const DEVNET_FEED_NAMESPACE: &str = "nebula.private.defi.feeds.devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_210_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_720_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_OBSERVATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_COMMIT_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 3;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_SUBSCRIPTION_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 5_760;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 1_200;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 450;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_MIN_SIGNER_BOND_MICRO_UNITS: u64 = 6_000_000;
pub const DEFAULT_MIN_BATCHER_BOND_MICRO_UNITS: u64 = 8_000_000;
pub const MAX_FEEDS: usize = 262_144;
pub const MAX_OBSERVATIONS: usize = 8_388_608;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_COMMITTEE_MEMBERS: usize = 1_048_576;
pub const MAX_SUBSCRIPTIONS: usize = 4_194_304;
pub const MAX_PRICE_PROOFS: usize = 4_194_304;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_SLA_SNAPSHOTS: usize = 2_097_152;
pub const MAX_FENCES: usize = 8_388_608;
pub const MAX_EVIDENCE: usize = 2_097_152;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    SpotPrice,
    TwapPrice,
    Volatility,
    FundingRate,
    ReserveProof,
    LiquidityDepth,
    LiquidationIndex,
    BridgeHealth,
    StablecoinPeg,
    GasFeeIndex,
    MoneroFeeIndex,
    EmergencyCircuit,
}

impl FeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpotPrice => "spot_price",
            Self::TwapPrice => "twap_price",
            Self::Volatility => "volatility",
            Self::FundingRate => "funding_rate",
            Self::ReserveProof => "reserve_proof",
            Self::LiquidityDepth => "liquidity_depth",
            Self::LiquidationIndex => "liquidation_index",
            Self::BridgeHealth => "bridge_health",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::GasFeeIndex => "gas_fee_index",
            Self::MoneroFeeIndex => "monero_fee_index",
            Self::EmergencyCircuit => "emergency_circuit",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyCircuit => 1_000,
            Self::BridgeHealth => 940,
            Self::ReserveProof => 900,
            Self::LiquidationIndex => 880,
            Self::SpotPrice => 840,
            Self::TwapPrice => 800,
            Self::StablecoinPeg => 780,
            Self::LiquidityDepth => 740,
            Self::Volatility => 700,
            Self::FundingRate => 660,
            Self::MoneroFeeIndex => 620,
            Self::GasFeeIndex => 580,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Proposed,
    Active,
    Paused,
    Retiring,
    Retired,
    Challenged,
}
impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Challenged => "challenged",
        }
    }
    pub fn accepts_observations(self) -> bool {
        matches!(self, Self::Active | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    Committed,
    Queued,
    Revealed,
    Aggregated,
    Proven,
    Settled,
    Rejected,
    Expired,
    Slashed,
}
impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Committed => "committed",
            Self::Queued => "queued",
            Self::Revealed => "revealed",
            Self::Aggregated => "aggregated",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Committed
                | Self::Queued
                | Self::Revealed
                | Self::Aggregated
                | Self::Proven
        )
    }
    pub fn batchable(self) -> bool {
        matches!(self, Self::Committed | Self::Queued | Self::Revealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    DelayLocked,
    RevealReady,
    Revealed,
    Aggregated,
    Proven,
    Settled,
    Challenged,
    Slashed,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::DelayLocked => "delay_locked",
            Self::RevealReady => "reveal_ready",
            Self::Revealed => "revealed",
            Self::Aggregated => "aggregated",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Signer,
    Revealer,
    Aggregator,
    PriceVerifier,
    PrivacyWatcher,
    FeeSponsor,
    SlashingJudge,
    EmergencySigner,
}
impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signer => "signer",
            Self::Revealer => "revealer",
            Self::Aggregator => "aggregator",
            Self::PriceVerifier => "price_verifier",
            Self::PrivacyWatcher => "privacy_watcher",
            Self::FeeSponsor => "fee_sponsor",
            Self::SlashingJudge => "slashing_judge",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionTier {
    FreeTrial,
    Retail,
    Pro,
    Contract,
    MarketMaker,
    LiquidationKeeper,
    BridgeCritical,
    Emergency,
}
impl SubscriptionTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreeTrial => "free_trial",
            Self::Retail => "retail",
            Self::Pro => "pro",
            Self::Contract => "contract",
            Self::MarketMaker => "market_maker",
            Self::LiquidationKeeper => "liquidation_keeper",
            Self::BridgeCritical => "bridge_critical",
            Self::Emergency => "emergency",
        }
    }
    pub fn min_rebate_bps(self) -> u64 {
        match self {
            Self::Emergency | Self::BridgeCritical => 12,
            Self::LiquidationKeeper => 10,
            Self::MarketMaker => 8,
            Self::Contract => 7,
            Self::Pro => 5,
            Self::Retail => 3,
            Self::FreeTrial => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    SpotPrice,
    Twap,
    Reserve,
    Liquidation,
    Funding,
    Volatility,
    RecursiveBatch,
    BridgeGuard,
}
impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpotPrice => "spot_price",
            Self::Twap => "twap",
            Self::Reserve => "reserve",
            Self::Liquidation => "liquidation",
            Self::Funding => "funding",
            Self::Volatility => "volatility",
            Self::RecursiveBatch => "recursive_batch",
            Self::BridgeGuard => "bridge_guard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    SponsorCovered,
    SlaMet,
    BatchAmortized,
    KeeperCritical,
    BridgeCritical,
    EmergencyCircuit,
    SubscriptionCredit,
}
impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorCovered => "sponsor_covered",
            Self::SlaMet => "sla_met",
            Self::BatchAmortized => "batch_amortized",
            Self::KeeperCritical => "keeper_critical",
            Self::BridgeCritical => "bridge_critical",
            Self::EmergencyCircuit => "emergency_circuit",
            Self::SubscriptionCredit => "subscription_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    ObservationNullifier,
    SubscriberNullifier,
    FeedEpoch,
    RevealKey,
    PriceProof,
    SponsorNote,
    ChallengeReplay,
}
impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObservationNullifier => "observation_nullifier",
            Self::SubscriberNullifier => "subscriber_nullifier",
            Self::FeedEpoch => "feed_epoch",
            Self::RevealKey => "reveal_key",
            Self::PriceProof => "price_proof",
            Self::SponsorNote => "sponsor_note",
            Self::ChallengeReplay => "challenge_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceReason {
    Equivocation,
    EarlyReveal,
    LateReveal,
    BadPriceProof,
    CommitteeWithholding,
    SlaBreach,
    NullifierReuse,
    SponsorDefault,
    InvalidRecursiveReceipt,
}
impl EvidenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::EarlyReveal => "early_reveal",
            Self::LateReveal => "late_reveal",
            Self::BadPriceProof => "bad_price_proof",
            Self::CommitteeWithholding => "committee_withholding",
            Self::SlaBreach => "sla_breach",
            Self::NullifierReuse => "nullifier_reuse",
            Self::SponsorDefault => "sponsor_default",
            Self::InvalidRecursiveReceipt => "invalid_recursive_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    UnderReview,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}
impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_kem_suite: String,
    pub pq_signature_suite: String,
    pub observation_encryption_suite: String,
    pub reveal_window_suite: String,
    pub price_proof_suite: String,
    pub recursive_receipt_suite: String,
    pub nullifier_fence_suite: String,
    pub sponsor_rebate_suite: String,
    pub slashing_evidence_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub feed_namespace: String,
    pub committee_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub observation_ttl_blocks: u64,
    pub commit_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub subscription_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub max_latency_ms: u64,
    pub soft_latency_ms: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_committee_weight: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_signer_bond_micro_units: u64,
    pub min_batcher_bond_micro_units: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            observation_encryption_suite: OBSERVATION_ENCRYPTION_SUITE.to_string(),
            reveal_window_suite: REVEAL_WINDOW_SUITE.to_string(),
            price_proof_suite: PRICE_PROOF_SUITE.to_string(),
            recursive_receipt_suite: RECURSIVE_RECEIPT_SUITE.to_string(),
            nullifier_fence_suite: NULLIFIER_FENCE_SUITE.to_string(),
            sponsor_rebate_suite: SPONSOR_REBATE_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            feed_namespace: DEVNET_FEED_NAMESPACE.to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            observation_ttl_blocks: DEFAULT_OBSERVATION_TTL_BLOCKS,
            commit_window_blocks: DEFAULT_COMMIT_WINDOW_BLOCKS,
            reveal_window_blocks: DEFAULT_REVEAL_WINDOW_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            subscription_ttl_blocks: DEFAULT_SUBSCRIPTION_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            evidence_ttl_blocks: DEFAULT_EVIDENCE_TTL_BLOCKS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_signer_bond_micro_units: DEFAULT_MIN_SIGNER_BOND_MICRO_UNITS,
            min_batcher_bond_micro_units: DEFAULT_MIN_BATCHER_BOND_MICRO_UNITS,
        }
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("feed_namespace", &self.feed_namespace)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below minimum",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        require(
            self.commit_window_blocks > 0 && self.reveal_window_blocks > 0,
            "windows must be non-zero",
        )?;
        require(
            self.settlement_window_blocks >= self.reveal_window_blocks,
            "settlement window too short",
        )?;
        require(
            is_valid_bps(self.quorum_bps) && is_valid_bps(self.strong_quorum_bps),
            "quorum bps out of range",
        )?;
        require(
            self.strong_quorum_bps >= self.quorum_bps,
            "strong quorum below quorum",
        )?;
        require(
            is_valid_bps(self.max_user_fee_bps)
                && is_valid_bps(self.target_rebate_bps)
                && is_valid_bps(self.sponsor_cover_bps),
            "fee bps out of range",
        )?;
        require(
            self.soft_latency_ms <= self.max_latency_ms,
            "soft latency above max latency",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"config","protocol_version":self.protocol_version,"schema_version":self.schema_version,"chain_id":self.chain_id,"hash_suite":self.hash_suite,"pq_kem_suite":self.pq_kem_suite,"pq_signature_suite":self.pq_signature_suite,"observation_encryption_suite":self.observation_encryption_suite,"reveal_window_suite":self.reveal_window_suite,"price_proof_suite":self.price_proof_suite,"recursive_receipt_suite":self.recursive_receipt_suite,"nullifier_fence_suite":self.nullifier_fence_suite,"sponsor_rebate_suite":self.sponsor_rebate_suite,"slashing_evidence_suite":self.slashing_evidence_suite,"l2_network":self.l2_network,"monero_network":self.monero_network,"feed_namespace":self.feed_namespace,"committee_id":self.committee_id,"min_pq_security_bits":self.min_pq_security_bits,"min_privacy_set_size":self.min_privacy_set_size,"batch_privacy_set_size":self.batch_privacy_set_size,"observation_ttl_blocks":self.observation_ttl_blocks,"commit_window_blocks":self.commit_window_blocks,"reveal_window_blocks":self.reveal_window_blocks,"settlement_window_blocks":self.settlement_window_blocks,"subscription_ttl_blocks":self.subscription_ttl_blocks,"proof_ttl_blocks":self.proof_ttl_blocks,"rebate_ttl_blocks":self.rebate_ttl_blocks,"evidence_ttl_blocks":self.evidence_ttl_blocks,"max_latency_ms":self.max_latency_ms,"soft_latency_ms":self.soft_latency_ms,"quorum_bps":self.quorum_bps,"strong_quorum_bps":self.strong_quorum_bps,"min_committee_weight":self.min_committee_weight,"max_user_fee_bps":self.max_user_fee_bps,"target_rebate_bps":self.target_rebate_bps,"sponsor_cover_bps":self.sponsor_cover_bps,"min_signer_bond_micro_units":self.min_signer_bond_micro_units,"min_batcher_bond_micro_units":self.min_batcher_bond_micro_units})
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_feed_sequence: u64,
    pub next_observation_sequence: u64,
    pub next_batch_sequence: u64,
    pub next_member_sequence: u64,
    pub next_subscription_sequence: u64,
    pub next_price_proof_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_receipt_sequence: u64,
    pub next_sla_sequence: u64,
    pub next_fence_sequence: u64,
    pub next_evidence_sequence: u64,
    pub next_event_sequence: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({"kind":"counters","next_feed_sequence":self.next_feed_sequence,"next_observation_sequence":self.next_observation_sequence,"next_batch_sequence":self.next_batch_sequence,"next_member_sequence":self.next_member_sequence,"next_subscription_sequence":self.next_subscription_sequence,"next_price_proof_sequence":self.next_price_proof_sequence,"next_rebate_sequence":self.next_rebate_sequence,"next_receipt_sequence":self.next_receipt_sequence,"next_sla_sequence":self.next_sla_sequence,"next_fence_sequence":self.next_fence_sequence,"next_evidence_sequence":self.next_evidence_sequence,"next_event_sequence":self.next_event_sequence})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeedDefinition {
    pub feed_id: String,
    pub sequence: u64,
    pub namespace: String,
    pub symbol: String,
    pub kind: FeedKind,
    pub status: FeedStatus,
    pub sponsor_commitment: String,
    pub asset_pair_root: String,
    pub policy_root: String,
    pub min_observations: u64,
    pub max_staleness_blocks: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}
impl FeedDefinition {
    pub fn new(
        sequence: u64,
        namespace: &str,
        symbol: &str,
        kind: FeedKind,
        sponsor_commitment: &str,
        asset_pair_root: &str,
        policy_root: &str,
        created_at_height: u64,
    ) -> Self {
        Self {
            feed_id: feed_id(sequence, namespace, symbol, kind, asset_pair_root),
            sequence,
            namespace: namespace.to_string(),
            symbol: symbol.to_string(),
            kind,
            status: FeedStatus::Active,
            sponsor_commitment: sponsor_commitment.to_string(),
            asset_pair_root: asset_pair_root.to_string(),
            policy_root: policy_root.to_string(),
            min_observations: 7,
            max_staleness_blocks: 16,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            created_at_height,
            updated_at_height: created_at_height,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("feed_id", &self.feed_id)?;
        require_non_empty("namespace", &self.namespace)?;
        require_non_empty("symbol", &self.symbol)?;
        require_hash_like("sponsor_commitment", &self.sponsor_commitment)?;
        require_hash_like("asset_pair_root", &self.asset_pair_root)?;
        require_hash_like("policy_root", &self.policy_root)?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "feed privacy set too small",
        )?;
        require(
            self.min_observations > 0,
            "min observations must be non-zero",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"feed_definition","feed_id":self.feed_id,"sequence":self.sequence,"namespace":self.namespace,"symbol":self.symbol,"feed_kind":self.kind.as_str(),"status":self.status.as_str(),"sponsor_commitment":self.sponsor_commitment,"asset_pair_root":self.asset_pair_root,"policy_root":self.policy_root,"min_observations":self.min_observations,"max_staleness_blocks":self.max_staleness_blocks,"privacy_set_size":self.privacy_set_size,"created_at_height":self.created_at_height,"updated_at_height":self.updated_at_height})
    }
    pub fn record_root(&self) -> String {
        public_record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedObservation {
    pub observation_id: String,
    pub sequence: u64,
    pub feed_id: String,
    pub signer_id: String,
    pub batch_id: Option<String>,
    pub status: ObservationStatus,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub observation_nullifier: String,
    pub subscriber_hint_root: String,
    pub fee_micro_units: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub commit_deadline_height: u64,
    pub reveal_deadline_height: u64,
}
impl EncryptedObservation {
    pub fn new(
        sequence: u64,
        feed_id: &str,
        signer_id: &str,
        encrypted_payload_root: &str,
        ciphertext_commitment: &str,
        observation_nullifier: &str,
        subscriber_hint_root: &str,
        fee_micro_units: u64,
        submitted_at_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            observation_id: observation_id(
                sequence,
                feed_id,
                signer_id,
                encrypted_payload_root,
                observation_nullifier,
            ),
            sequence,
            feed_id: feed_id.to_string(),
            signer_id: signer_id.to_string(),
            batch_id: None,
            status: ObservationStatus::Submitted,
            encrypted_payload_root: encrypted_payload_root.to_string(),
            ciphertext_commitment: ciphertext_commitment.to_string(),
            observation_nullifier: observation_nullifier.to_string(),
            subscriber_hint_root: subscriber_hint_root.to_string(),
            fee_micro_units,
            pq_security_bits: config.min_pq_security_bits,
            submitted_at_height,
            commit_deadline_height: submitted_at_height + config.commit_window_blocks,
            reveal_deadline_height: submitted_at_height
                + config.commit_window_blocks
                + config.reveal_window_blocks,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("observation_id", &self.observation_id)?;
        require_non_empty("feed_id", &self.feed_id)?;
        require_non_empty("signer_id", &self.signer_id)?;
        require_hash_like("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_hash_like("ciphertext_commitment", &self.ciphertext_commitment)?;
        require_hash_like("observation_nullifier", &self.observation_nullifier)?;
        require_hash_like("subscriber_hint_root", &self.subscriber_hint_root)?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "observation pq security too low",
        )?;
        require(
            self.commit_deadline_height <= self.reveal_deadline_height,
            "bad observation windows",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"encrypted_observation","observation_id":self.observation_id,"sequence":self.sequence,"feed_id":self.feed_id,"signer_id":self.signer_id,"batch_id":self.batch_id,"status":self.status.as_str(),"encrypted_payload_root":self.encrypted_payload_root,"ciphertext_commitment":self.ciphertext_commitment,"observation_nullifier":self.observation_nullifier,"subscriber_hint_root":self.subscriber_hint_root,"fee_micro_units":self.fee_micro_units,"pq_security_bits":self.pq_security_bits,"submitted_at_height":self.submitted_at_height,"commit_deadline_height":self.commit_deadline_height,"reveal_deadline_height":self.reveal_deadline_height})
    }
    pub fn record_root(&self) -> String {
        public_record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub feed_id: String,
    pub status: BatchStatus,
    pub observation_ids: Vec<String>,
    pub committee_root: String,
    pub commit_root: String,
    pub reveal_key_commitment: String,
    pub aggregate_ciphertext_root: String,
    pub reveal_transcript_root: String,
    pub opened_at_height: u64,
    pub reveal_height: u64,
    pub settlement_height: u64,
    pub total_fee_micro_units: u64,
    pub total_weight: u64,
}
impl RevealBatch {
    pub fn new(
        sequence: u64,
        feed_id: &str,
        observation_ids: Vec<String>,
        committee_root: &str,
        commit_root: &str,
        reveal_key_commitment: &str,
        aggregate_ciphertext_root: &str,
        opened_at_height: u64,
        config: &Config,
    ) -> Self {
        let reveal_height = opened_at_height + config.commit_window_blocks;
        Self {
            batch_id: batch_id(sequence, feed_id, commit_root, opened_at_height),
            sequence,
            feed_id: feed_id.to_string(),
            status: BatchStatus::Open,
            observation_ids,
            committee_root: committee_root.to_string(),
            commit_root: commit_root.to_string(),
            reveal_key_commitment: reveal_key_commitment.to_string(),
            aggregate_ciphertext_root: aggregate_ciphertext_root.to_string(),
            reveal_transcript_root: empty_root("reveal-transcript"),
            opened_at_height,
            reveal_height,
            settlement_height: reveal_height + config.settlement_window_blocks,
            total_fee_micro_units: 0,
            total_weight: 0,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("feed_id", &self.feed_id)?;
        require_hash_like("committee_root", &self.committee_root)?;
        require_hash_like("commit_root", &self.commit_root)?;
        require_hash_like("reveal_key_commitment", &self.reveal_key_commitment)?;
        require_hash_like("aggregate_ciphertext_root", &self.aggregate_ciphertext_root)?;
        require_hash_like("reveal_transcript_root", &self.reveal_transcript_root)?;
        require(
            self.settlement_height >= self.reveal_height + config.reveal_window_blocks,
            "settlement before reveal window",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"reveal_batch","batch_id":self.batch_id,"sequence":self.sequence,"feed_id":self.feed_id,"status":self.status.as_str(),"observation_ids":self.observation_ids,"committee_root":self.committee_root,"commit_root":self.commit_root,"reveal_key_commitment":self.reveal_key_commitment,"aggregate_ciphertext_root":self.aggregate_ciphertext_root,"reveal_transcript_root":self.reveal_transcript_root,"opened_at_height":self.opened_at_height,"reveal_height":self.reveal_height,"settlement_height":self.settlement_height,"total_fee_micro_units":self.total_fee_micro_units,"total_weight":self.total_weight})
    }
    pub fn record_root(&self) -> String {
        public_record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub sequence: u64,
    pub operator_commitment: String,
    pub role: CommitteeRole,
    pub signing_key_commitment: String,
    pub encryption_key_commitment: String,
    pub bond_commitment: String,
    pub weight: u64,
    pub reputation: u64,
    pub active: bool,
    pub joined_at_height: u64,
    pub slashed_micro_units: u64,
}
impl CommitteeMember {
    pub fn new(
        sequence: u64,
        operator_commitment: &str,
        role: CommitteeRole,
        signing_key_commitment: &str,
        encryption_key_commitment: &str,
        bond_commitment: &str,
        weight: u64,
        joined_at_height: u64,
    ) -> Self {
        Self {
            member_id: committee_member_id(
                sequence,
                operator_commitment,
                role,
                signing_key_commitment,
            ),
            sequence,
            operator_commitment: operator_commitment.to_string(),
            role,
            signing_key_commitment: signing_key_commitment.to_string(),
            encryption_key_commitment: encryption_key_commitment.to_string(),
            bond_commitment: bond_commitment.to_string(),
            weight,
            reputation: 1_000,
            active: true,
            joined_at_height,
            slashed_micro_units: 0,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("member_id", &self.member_id)?;
        require_hash_like("operator_commitment", &self.operator_commitment)?;
        require_hash_like("signing_key_commitment", &self.signing_key_commitment)?;
        require_hash_like("encryption_key_commitment", &self.encryption_key_commitment)?;
        require_hash_like("bond_commitment", &self.bond_commitment)?;
        require(self.weight > 0, "committee member weight is zero")
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"committee_member","member_id":self.member_id,"sequence":self.sequence,"operator_commitment":self.operator_commitment,"role":self.role.as_str(),"signing_key_commitment":self.signing_key_commitment,"encryption_key_commitment":self.encryption_key_commitment,"bond_commitment":self.bond_commitment,"weight":self.weight,"reputation":self.reputation,"active":self.active,"joined_at_height":self.joined_at_height,"slashed_micro_units":self.slashed_micro_units})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateFeedSubscription {
    pub subscription_id: String,
    pub sequence: u64,
    pub feed_id: String,
    pub subscriber_commitment: String,
    pub tier: SubscriptionTier,
    pub view_key_commitment: String,
    pub spend_limit_commitment: String,
    pub nullifier_root: String,
    pub paid_through_height: u64,
    pub max_fee_bps: u64,
    pub active: bool,
    pub created_at_height: u64,
}
impl PrivateFeedSubscription {
    pub fn new(
        sequence: u64,
        feed_id: &str,
        subscriber_commitment: &str,
        tier: SubscriptionTier,
        view_key_commitment: &str,
        spend_limit_commitment: &str,
        nullifier_root: &str,
        created_at_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            subscription_id: subscription_id(
                sequence,
                feed_id,
                subscriber_commitment,
                nullifier_root,
            ),
            sequence,
            feed_id: feed_id.to_string(),
            subscriber_commitment: subscriber_commitment.to_string(),
            tier,
            view_key_commitment: view_key_commitment.to_string(),
            spend_limit_commitment: spend_limit_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            paid_through_height: created_at_height + config.subscription_ttl_blocks,
            max_fee_bps: config.max_user_fee_bps,
            active: true,
            created_at_height,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("subscription_id", &self.subscription_id)?;
        require_non_empty("feed_id", &self.feed_id)?;
        require_hash_like("subscriber_commitment", &self.subscriber_commitment)?;
        require_hash_like("view_key_commitment", &self.view_key_commitment)?;
        require_hash_like("spend_limit_commitment", &self.spend_limit_commitment)?;
        require_hash_like("nullifier_root", &self.nullifier_root)?;
        require(
            is_valid_bps(self.max_fee_bps) && self.max_fee_bps <= config.max_user_fee_bps,
            "subscription fee too high",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_feed_subscription","subscription_id":self.subscription_id,"sequence":self.sequence,"feed_id":self.feed_id,"subscriber_commitment":self.subscriber_commitment,"tier":self.tier.as_str(),"view_key_commitment":self.view_key_commitment,"spend_limit_commitment":self.spend_limit_commitment,"nullifier_root":self.nullifier_root,"paid_through_height":self.paid_through_height,"max_fee_bps":self.max_fee_bps,"active":self.active,"created_at_height":self.created_at_height})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefiPriceProof {
    pub proof_id: String,
    pub sequence: u64,
    pub feed_id: String,
    pub batch_id: String,
    pub proof_kind: ProofKind,
    pub price_commitment: String,
    pub confidence_interval_root: String,
    pub proof_root: String,
    pub verifier_committee_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub quorum_bps: u64,
}
impl DefiPriceProof {
    pub fn new(
        sequence: u64,
        feed_id: &str,
        batch_id: &str,
        proof_kind: ProofKind,
        price_commitment: &str,
        confidence_interval_root: &str,
        proof_root: &str,
        verifier_committee_root: &str,
        valid_from_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            proof_id: price_proof_id(sequence, feed_id, batch_id, proof_kind, proof_root),
            sequence,
            feed_id: feed_id.to_string(),
            batch_id: batch_id.to_string(),
            proof_kind,
            price_commitment: price_commitment.to_string(),
            confidence_interval_root: confidence_interval_root.to_string(),
            proof_root: proof_root.to_string(),
            verifier_committee_root: verifier_committee_root.to_string(),
            valid_from_height,
            valid_until_height: valid_from_height + config.proof_ttl_blocks,
            quorum_bps: config.quorum_bps,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("proof_id", &self.proof_id)?;
        require_non_empty("feed_id", &self.feed_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_hash_like("price_commitment", &self.price_commitment)?;
        require_hash_like("confidence_interval_root", &self.confidence_interval_root)?;
        require_hash_like("proof_root", &self.proof_root)?;
        require_hash_like("verifier_committee_root", &self.verifier_committee_root)?;
        require(
            is_valid_bps(self.quorum_bps) && self.quorum_bps >= config.quorum_bps,
            "price proof quorum too low",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"defi_price_proof","proof_id":self.proof_id,"sequence":self.sequence,"feed_id":self.feed_id,"batch_id":self.batch_id,"proof_kind":self.proof_kind.as_str(),"price_commitment":self.price_commitment,"confidence_interval_root":self.confidence_interval_root,"proof_root":self.proof_root,"verifier_committee_root":self.verifier_committee_root,"valid_from_height":self.valid_from_height,"valid_until_height":self.valid_until_height,"quorum_bps":self.quorum_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub subscription_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub reason: RebateReason,
    pub rebate_note_root: String,
    pub amount_micro_units: u64,
    pub fee_reduction_bps: u64,
    pub expires_at_height: u64,
    pub claimed: bool,
}
impl SponsorRebate {
    pub fn new(
        sequence: u64,
        subscription_id: &str,
        batch_id: &str,
        sponsor_commitment: &str,
        reason: RebateReason,
        rebate_note_root: &str,
        amount_micro_units: u64,
        fee_reduction_bps: u64,
        current_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            rebate_id: rebate_id(
                sequence,
                subscription_id,
                batch_id,
                reason,
                rebate_note_root,
            ),
            sequence,
            subscription_id: subscription_id.to_string(),
            batch_id: batch_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            reason,
            rebate_note_root: rebate_note_root.to_string(),
            amount_micro_units,
            fee_reduction_bps,
            expires_at_height: current_height + config.rebate_ttl_blocks,
            claimed: false,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("subscription_id", &self.subscription_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_hash_like("sponsor_commitment", &self.sponsor_commitment)?;
        require_hash_like("rebate_note_root", &self.rebate_note_root)?;
        require(
            is_valid_bps(self.fee_reduction_bps),
            "rebate bps out of range",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"sponsor_rebate","rebate_id":self.rebate_id,"sequence":self.sequence,"subscription_id":self.subscription_id,"batch_id":self.batch_id,"sponsor_commitment":self.sponsor_commitment,"reason":self.reason.as_str(),"rebate_note_root":self.rebate_note_root,"amount_micro_units":self.amount_micro_units,"fee_reduction_bps":self.fee_reduction_bps,"expires_at_height":self.expires_at_height,"claimed":self.claimed})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub parent_receipt_id: Option<String>,
    pub accumulator_root: String,
    pub proof_receipt_root: String,
    pub covered_batch_count: u64,
    pub covered_observation_count: u64,
    pub recursion_depth: u64,
    pub verifier_id: String,
    pub accepted_at_height: u64,
}
impl RecursiveProofReceipt {
    pub fn new(
        sequence: u64,
        batch_id: &str,
        parent_receipt_id: Option<String>,
        accumulator_root: &str,
        proof_receipt_root: &str,
        covered_batch_count: u64,
        covered_observation_count: u64,
        recursion_depth: u64,
        verifier_id: &str,
        accepted_at_height: u64,
    ) -> Self {
        Self {
            receipt_id: receipt_id(sequence, batch_id, accumulator_root, proof_receipt_root),
            sequence,
            batch_id: batch_id.to_string(),
            parent_receipt_id,
            accumulator_root: accumulator_root.to_string(),
            proof_receipt_root: proof_receipt_root.to_string(),
            covered_batch_count,
            covered_observation_count,
            recursion_depth,
            verifier_id: verifier_id.to_string(),
            accepted_at_height,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_hash_like("accumulator_root", &self.accumulator_root)?;
        require_hash_like("proof_receipt_root", &self.proof_receipt_root)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require(self.covered_batch_count > 0, "receipt covers no batches")
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"recursive_proof_receipt","receipt_id":self.receipt_id,"sequence":self.sequence,"batch_id":self.batch_id,"parent_receipt_id":self.parent_receipt_id,"accumulator_root":self.accumulator_root,"proof_receipt_root":self.proof_receipt_root,"covered_batch_count":self.covered_batch_count,"covered_observation_count":self.covered_observation_count,"recursion_depth":self.recursion_depth,"verifier_id":self.verifier_id,"accepted_at_height":self.accepted_at_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencySlaSnapshot {
    pub snapshot_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub feed_id: String,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub max_latency_ms: u64,
    pub missed_reveals: u64,
    pub observed_count: u64,
    pub sla_met: bool,
    pub snapshot_root: String,
    pub recorded_at_height: u64,
}
impl LatencySlaSnapshot {
    pub fn new(
        sequence: u64,
        batch_id: &str,
        feed_id: &str,
        p50_latency_ms: u64,
        p95_latency_ms: u64,
        max_latency_ms: u64,
        missed_reveals: u64,
        observed_count: u64,
        snapshot_root: &str,
        recorded_at_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            snapshot_id: sla_snapshot_id(sequence, batch_id, feed_id, snapshot_root),
            sequence,
            batch_id: batch_id.to_string(),
            feed_id: feed_id.to_string(),
            p50_latency_ms,
            p95_latency_ms,
            max_latency_ms,
            missed_reveals,
            observed_count,
            sla_met: p95_latency_ms <= config.max_latency_ms && missed_reveals == 0,
            snapshot_root: snapshot_root.to_string(),
            recorded_at_height,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("snapshot_id", &self.snapshot_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("feed_id", &self.feed_id)?;
        require_hash_like("snapshot_root", &self.snapshot_root)?;
        require(
            self.p50_latency_ms <= self.p95_latency_ms
                && self.p95_latency_ms <= self.max_latency_ms,
            "latency percentiles out of order",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"latency_sla_snapshot","snapshot_id":self.snapshot_id,"sequence":self.sequence,"batch_id":self.batch_id,"feed_id":self.feed_id,"p50_latency_ms":self.p50_latency_ms,"p95_latency_ms":self.p95_latency_ms,"max_latency_ms":self.max_latency_ms,"missed_reveals":self.missed_reveals,"observed_count":self.observed_count,"sla_met":self.sla_met,"snapshot_root":self.snapshot_root,"recorded_at_height":self.recorded_at_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub sequence: u64,
    pub kind: FenceKind,
    pub namespace: String,
    pub subject_id: String,
    pub nullifier_root: String,
    pub spent_nullifiers: BTreeSet<String>,
    pub expires_at_height: u64,
    pub active: bool,
}
impl NullifierFence {
    pub fn new(
        sequence: u64,
        kind: FenceKind,
        namespace: &str,
        subject_id: &str,
        nullifier_root: &str,
        current_height: u64,
        ttl: u64,
    ) -> Self {
        Self {
            fence_id: fence_id(sequence, kind, namespace, subject_id, nullifier_root),
            sequence,
            kind,
            namespace: namespace.to_string(),
            subject_id: subject_id.to_string(),
            nullifier_root: nullifier_root.to_string(),
            spent_nullifiers: BTreeSet::new(),
            expires_at_height: current_height + ttl,
            active: true,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("fence_id", &self.fence_id)?;
        require_non_empty("namespace", &self.namespace)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_hash_like("nullifier_root", &self.nullifier_root)
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"nullifier_fence","fence_id":self.fence_id,"sequence":self.sequence,"fence_kind":self.kind.as_str(),"namespace":self.namespace,"subject_id":self.subject_id,"nullifier_root":self.nullifier_root,"spent_nullifiers":self.spent_nullifiers,"expires_at_height":self.expires_at_height,"active":self.active})
    }
    pub fn contains(&self, nullifier: &str) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub reason: EvidenceReason,
    pub status: EvidenceStatus,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub accused_member_id: String,
    pub evidence_root: String,
    pub slash_amount_micro_units: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}
impl ChallengeEvidence {
    pub fn new(
        sequence: u64,
        reason: EvidenceReason,
        subject_id: &str,
        challenger_commitment: &str,
        accused_member_id: &str,
        evidence_root: &str,
        slash_amount_micro_units: u64,
        submitted_at_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            evidence_id: evidence_id(sequence, reason, subject_id, evidence_root),
            sequence,
            reason,
            status: EvidenceStatus::Submitted,
            subject_id: subject_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            accused_member_id: accused_member_id.to_string(),
            evidence_root: evidence_root.to_string(),
            slash_amount_micro_units,
            submitted_at_height,
            expires_at_height: submitted_at_height + config.evidence_ttl_blocks,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("evidence_id", &self.evidence_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_hash_like("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("accused_member_id", &self.accused_member_id)?;
        require_hash_like("evidence_root", &self.evidence_root)?;
        require(self.slash_amount_micro_units > 0, "slash amount is zero")
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"challenge_evidence","evidence_id":self.evidence_id,"sequence":self.sequence,"reason":self.reason.as_str(),"status":self.status.as_str(),"subject_id":self.subject_id,"challenger_commitment":self.challenger_commitment,"accused_member_id":self.accused_member_id,"evidence_root":self.evidence_root,"slash_amount_micro_units":self.slash_amount_micro_units,"submitted_at_height":self.submitted_at_height,"expires_at_height":self.expires_at_height})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub sequence: u64,
    pub kind: String,
    pub subject_id: String,
    pub details_root: String,
    pub height: u64,
    pub state_root_after: String,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({"kind":"runtime_event","event_id":self.event_id,"sequence":self.sequence,"event_kind":self.kind,"subject_id":self.subject_id,"details_root":self.details_root,"height":self.height,"state_root_after":self.state_root_after})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub feed_root: String,
    pub observation_root: String,
    pub batch_root: String,
    pub committee_root: String,
    pub subscription_root: String,
    pub price_proof_root: String,
    pub rebate_root: String,
    pub receipt_root: String,
    pub sla_root: String,
    pub fence_root: String,
    pub evidence_root: String,
    pub event_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({"kind":"roots","feed_root":self.feed_root,"observation_root":self.observation_root,"batch_root":self.batch_root,"committee_root":self.committee_root,"subscription_root":self.subscription_root,"price_proof_root":self.price_proof_root,"rebate_root":self.rebate_root,"receipt_root":self.receipt_root,"sla_root":self.sla_root,"fence_root":self.fence_root,"evidence_root":self.evidence_root,"event_root":self.event_root,"state_root":self.state_root})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub feeds: BTreeMap<String, FeedDefinition>,
    pub observations: BTreeMap<String, EncryptedObservation>,
    pub batches: BTreeMap<String, RevealBatch>,
    pub committee: BTreeMap<String, CommitteeMember>,
    pub subscriptions: BTreeMap<String, PrivateFeedSubscription>,
    pub price_proofs: BTreeMap<String, DefiPriceProof>,
    pub rebates: BTreeMap<String, SponsorRebate>,
    pub receipts: BTreeMap<String, RecursiveProofReceipt>,
    pub sla_snapshots: BTreeMap<String, LatencySlaSnapshot>,
    pub fences: BTreeMap<String, NullifierFence>,
    pub evidence: BTreeMap<String, ChallengeEvidence>,
    pub events: Vec<RuntimeEvent>,
    pub used_nullifiers: BTreeSet<String>,
    pub sponsor_budget_remaining_micro_units: u64,
}
impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_l2_height,
            current_monero_height,
            feeds: BTreeMap::new(),
            observations: BTreeMap::new(),
            batches: BTreeMap::new(),
            committee: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            price_proofs: BTreeMap::new(),
            rebates: BTreeMap::new(),
            receipts: BTreeMap::new(),
            sla_snapshots: BTreeMap::new(),
            fences: BTreeMap::new(),
            evidence: BTreeMap::new(),
            events: Vec::new(),
            used_nullifiers: BTreeSet::new(),
            sponsor_budget_remaining_micro_units: 90_000_000,
        })
    }
    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT).expect("devnet");
        let h = state.current_l2_height;
        let root_a = deterministic_root("devnet-asset-xmr-usdc");
        let policy = deterministic_root("devnet-feed-policy");
        let sponsor = deterministic_root("devnet-sponsor");
        let feed = FeedDefinition::new(
            1,
            DEVNET_FEED_NAMESPACE,
            "XMR/USDC",
            FeedKind::SpotPrice,
            &sponsor,
            &root_a,
            &policy,
            h,
        );
        state.register_feed(feed).expect("feed");
        let signer = CommitteeMember::new(
            1,
            &deterministic_root("operator-a"),
            CommitteeRole::Signer,
            &deterministic_root("sign-a"),
            &deterministic_root("enc-a"),
            &deterministic_root("bond-a"),
            5,
            h,
        );
        let signer_id = signer.member_id.clone();
        state.register_committee_member(signer).expect("signer");
        let revealer = CommitteeMember::new(
            2,
            &deterministic_root("operator-b"),
            CommitteeRole::Revealer,
            &deterministic_root("sign-b"),
            &deterministic_root("enc-b"),
            &deterministic_root("bond-b"),
            5,
            h,
        );
        state.register_committee_member(revealer).expect("revealer");
        let agg = CommitteeMember::new(
            3,
            &deterministic_root("operator-c"),
            CommitteeRole::Aggregator,
            &deterministic_root("sign-c"),
            &deterministic_root("enc-c"),
            &deterministic_root("bond-c"),
            5,
            h,
        );
        state.register_committee_member(agg).expect("agg");
        let feed_id = state.feeds.keys().next().cloned().expect("feed id");
        let sub = PrivateFeedSubscription::new(
            1,
            &feed_id,
            &deterministic_root("subscriber-a"),
            SubscriptionTier::LiquidationKeeper,
            &deterministic_root("view-a"),
            &deterministic_root("limit-a"),
            &deterministic_root("sub-nullifiers"),
            h,
            &state.config,
        );
        let sub_id = sub.subscription_id.clone();
        state.add_subscription(sub).expect("sub");
        let obs = EncryptedObservation::new(
            1,
            &feed_id,
            &signer_id,
            &deterministic_root("payload-a"),
            &deterministic_root("cipher-a"),
            &deterministic_root("obs-nullifier-a"),
            &deterministic_root("hint-a"),
            120,
            h,
            &state.config,
        );
        let obs_id = obs.observation_id.clone();
        state.submit_observation(obs).expect("obs");
        let batch = RevealBatch::new(
            1,
            &feed_id,
            vec![obs_id.clone()],
            &state.committee_root(),
            &deterministic_root("commit-a"),
            &deterministic_root("reveal-key-a"),
            &deterministic_root("agg-cipher-a"),
            h,
            &state.config,
        );
        let batch_id = batch.batch_id.clone();
        state.open_batch(batch).expect("batch");
        state
            .attach_observation_to_batch(&obs_id, &batch_id)
            .expect("attach");
        state.seal_batch(&batch_id).expect("seal");
        state.current_l2_height += state.config.commit_window_blocks;
        state.mark_batch_reveal_ready(&batch_id).expect("ready");
        state
            .reveal_batch(&batch_id, &deterministic_root("reveal-transcript-a"))
            .expect("reveal");
        let proof = DefiPriceProof::new(
            1,
            &feed_id,
            &batch_id,
            ProofKind::SpotPrice,
            &deterministic_root("price-a"),
            &deterministic_root("ci-a"),
            &deterministic_root("proof-a"),
            &state.committee_root(),
            state.current_l2_height,
            &state.config,
        );
        state.accept_price_proof(proof).expect("proof");
        let receipt = RecursiveProofReceipt::new(
            1,
            &batch_id,
            None,
            &deterministic_root("acc-a"),
            &deterministic_root("receipt-a"),
            1,
            1,
            0,
            &signer_id,
            state.current_l2_height,
        );
        state.accept_receipt(receipt).expect("receipt");
        let sla = LatencySlaSnapshot::new(
            1,
            &batch_id,
            &feed_id,
            180,
            410,
            900,
            0,
            1,
            &deterministic_root("sla-a"),
            state.current_l2_height,
            &state.config,
        );
        state.record_sla_snapshot(sla).expect("sla");
        let rebate = SponsorRebate::new(
            1,
            &sub_id,
            &batch_id,
            &sponsor,
            RebateReason::KeeperCritical,
            &deterministic_root("rebate-a"),
            40,
            10,
            state.current_l2_height,
            &state.config,
        );
        state.issue_rebate(rebate).expect("rebate");
        state
    }
    pub fn public_record_without_roots(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_oracle_mev_resistant_batch_feed_state","config":self.config.public_record(),"counters":self.counters.public_record(),"current_l2_height":self.current_l2_height,"current_monero_height":self.current_monero_height,"feeds":self.feeds.values().map(|v|v.public_record()).collect::<Vec<_>>(),"observations":self.observations.values().map(|v|v.public_record()).collect::<Vec<_>>(),"batches":self.batches.values().map(|v|v.public_record()).collect::<Vec<_>>(),"committee":self.committee.values().map(|v|v.public_record()).collect::<Vec<_>>(),"subscriptions":self.subscriptions.values().map(|v|v.public_record()).collect::<Vec<_>>(),"price_proofs":self.price_proofs.values().map(|v|v.public_record()).collect::<Vec<_>>(),"rebates":self.rebates.values().map(|v|v.public_record()).collect::<Vec<_>>(),"receipts":self.receipts.values().map(|v|v.public_record()).collect::<Vec<_>>(),"sla_snapshots":self.sla_snapshots.values().map(|v|v.public_record()).collect::<Vec<_>>(),"fences":self.fences.values().map(|v|v.public_record()).collect::<Vec<_>>(),"evidence":self.evidence.values().map(|v|v.public_record()).collect::<Vec<_>>(),"events":self.events.iter().map(|v|v.public_record()).collect::<Vec<_>>(),"used_nullifiers":self.used_nullifiers,"sponsor_budget_remaining_micro_units":self.sponsor_budget_remaining_micro_units})
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(values) = &mut record {
            values.insert("roots".to_string(), self.roots().public_record());
        }
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_roots())
    }
    pub fn roots(&self) -> Roots {
        Roots {
            feed_root: self.feed_root(),
            observation_root: self.observation_root(),
            batch_root: self.batch_root(),
            committee_root: self.committee_root(),
            subscription_root: self.subscription_root(),
            price_proof_root: self.price_proof_root(),
            rebate_root: self.rebate_root(),
            receipt_root: self.receipt_root(),
            sla_root: self.sla_root(),
            fence_root: self.fence_root(),
            evidence_root: self.evidence_root(),
            event_root: self.event_root(),
            state_root: self.state_root(),
        }
    }
    pub fn feed_root(&self) -> String {
        records_root(
            "feeds",
            self.feeds.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn observation_root(&self) -> String {
        records_root(
            "observations",
            self.observations
                .values()
                .map(|v| v.public_record())
                .collect(),
        )
    }
    pub fn batch_root(&self) -> String {
        records_root(
            "batches",
            self.batches.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn committee_root(&self) -> String {
        records_root(
            "committee",
            self.committee.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn subscription_root(&self) -> String {
        records_root(
            "subscriptions",
            self.subscriptions
                .values()
                .map(|v| v.public_record())
                .collect(),
        )
    }
    pub fn price_proof_root(&self) -> String {
        records_root(
            "price-proofs",
            self.price_proofs
                .values()
                .map(|v| v.public_record())
                .collect(),
        )
    }
    pub fn rebate_root(&self) -> String {
        records_root(
            "rebates",
            self.rebates.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn receipt_root(&self) -> String {
        records_root(
            "receipts",
            self.receipts.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn sla_root(&self) -> String {
        records_root(
            "sla",
            self.sla_snapshots
                .values()
                .map(|v| v.public_record())
                .collect(),
        )
    }
    pub fn fence_root(&self) -> String {
        records_root(
            "fences",
            self.fences.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn evidence_root(&self) -> String {
        records_root(
            "evidence",
            self.evidence.values().map(|v| v.public_record()).collect(),
        )
    }
    pub fn event_root(&self) -> String {
        records_root(
            "events",
            self.events.iter().map(|v| v.public_record()).collect(),
        )
    }
    pub fn register_feed(&mut self, feed: FeedDefinition) -> Result<()> {
        require(self.feeds.len() < MAX_FEEDS, "feed registry full")?;
        feed.validate(&self.config)?;
        require(!self.feeds.contains_key(&feed.feed_id), "feed exists")?;
        self.counters.next_feed_sequence = self.counters.next_feed_sequence.max(feed.sequence + 1);
        let id = feed.feed_id.clone();
        self.feeds.insert(id.clone(), feed);
        self.emit_event("feed_registered", &id)
    }
    pub fn register_committee_member(&mut self, member: CommitteeMember) -> Result<()> {
        require(
            self.committee.len() < MAX_COMMITTEE_MEMBERS,
            "committee registry full",
        )?;
        member.validate()?;
        require(
            !self.committee.contains_key(&member.member_id),
            "member exists",
        )?;
        self.counters.next_member_sequence =
            self.counters.next_member_sequence.max(member.sequence + 1);
        let id = member.member_id.clone();
        self.committee.insert(id.clone(), member);
        self.emit_event("committee_member_registered", &id)
    }
    pub fn add_subscription(&mut self, subscription: PrivateFeedSubscription) -> Result<()> {
        require(
            self.subscriptions.len() < MAX_SUBSCRIPTIONS,
            "subscription registry full",
        )?;
        subscription.validate(&self.config)?;
        require(
            self.feeds.contains_key(&subscription.feed_id),
            "unknown feed",
        )?;
        require(
            !self
                .subscriptions
                .contains_key(&subscription.subscription_id),
            "subscription exists",
        )?;
        self.counters.next_subscription_sequence = self
            .counters
            .next_subscription_sequence
            .max(subscription.sequence + 1);
        let id = subscription.subscription_id.clone();
        self.subscriptions.insert(id.clone(), subscription);
        self.emit_event("subscription_added", &id)
    }
    pub fn submit_observation(&mut self, observation: EncryptedObservation) -> Result<()> {
        require(
            self.observations.len() < MAX_OBSERVATIONS,
            "observation registry full",
        )?;
        observation.validate(&self.config)?;
        let feed = self
            .feeds
            .get(&observation.feed_id)
            .ok_or_else(|| "unknown feed".to_string())?;
        require(
            feed.status.accepts_observations(),
            "feed does not accept observations",
        )?;
        require(
            self.committee.contains_key(&observation.signer_id),
            "unknown signer",
        )?;
        require(
            !self
                .used_nullifiers
                .contains(&observation.observation_nullifier),
            "observation nullifier already used",
        )?;
        self.used_nullifiers
            .insert(observation.observation_nullifier.clone());
        self.counters.next_observation_sequence = self
            .counters
            .next_observation_sequence
            .max(observation.sequence + 1);
        let id = observation.observation_id.clone();
        self.observations.insert(id.clone(), observation);
        self.emit_event("observation_submitted", &id)
    }
    pub fn open_batch(&mut self, batch: RevealBatch) -> Result<()> {
        require(self.batches.len() < MAX_BATCHES, "batch registry full")?;
        batch.validate(&self.config)?;
        require(self.feeds.contains_key(&batch.feed_id), "unknown feed")?;
        require(!self.batches.contains_key(&batch.batch_id), "batch exists")?;
        self.counters.next_batch_sequence =
            self.counters.next_batch_sequence.max(batch.sequence + 1);
        let id = batch.batch_id.clone();
        self.batches.insert(id.clone(), batch);
        self.emit_event("batch_opened", &id)
    }
    pub fn attach_observation_to_batch(
        &mut self,
        observation_id: &str,
        batch_id: &str,
    ) -> Result<()> {
        let batch_feed = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?
            .feed_id
            .clone();
        let obs = self
            .observations
            .get_mut(observation_id)
            .ok_or_else(|| "unknown observation".to_string())?;
        require(obs.feed_id == batch_feed, "feed mismatch")?;
        require(
            obs.status.batchable() || obs.status == ObservationStatus::Submitted,
            "observation not batchable",
        )?;
        obs.status = ObservationStatus::Queued;
        obs.batch_id = Some(batch_id.to_string());
        if let Some(batch) = self.batches.get_mut(batch_id) {
            if !batch.observation_ids.iter().any(|id| id == observation_id) {
                batch.observation_ids.push(observation_id.to_string());
            }
            batch.total_fee_micro_units = batch
                .total_fee_micro_units
                .saturating_add(obs.fee_micro_units);
        }
        self.emit_event("observation_attached", observation_id)
    }
    pub fn seal_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        require(batch.status == BatchStatus::Open, "batch not open")?;
        require(!batch.observation_ids.is_empty(), "empty batch")?;
        batch.status = BatchStatus::Sealed;
        for id in batch.observation_ids.clone() {
            if let Some(obs) = self.observations.get_mut(&id) {
                obs.status = ObservationStatus::Committed;
            }
        }
        self.emit_event("batch_sealed", batch_id)
    }
    pub fn mark_batch_reveal_ready(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        require(
            matches!(batch.status, BatchStatus::Sealed | BatchStatus::DelayLocked),
            "batch not sealable for reveal",
        )?;
        require(
            self.current_l2_height >= batch.reveal_height,
            "reveal height not reached",
        )?;
        batch.status = BatchStatus::RevealReady;
        self.emit_event("batch_reveal_ready", batch_id)
    }
    pub fn reveal_batch(&mut self, batch_id: &str, reveal_transcript_root: &str) -> Result<()> {
        require_hash_like("reveal_transcript_root", reveal_transcript_root)?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        require(
            batch.status == BatchStatus::RevealReady,
            "batch not reveal ready",
        )?;
        batch.status = BatchStatus::Revealed;
        batch.reveal_transcript_root = reveal_transcript_root.to_string();
        for id in batch.observation_ids.clone() {
            if let Some(obs) = self.observations.get_mut(&id) {
                obs.status = ObservationStatus::Revealed;
            }
        }
        self.emit_event("batch_revealed", batch_id)
    }
    pub fn accept_price_proof(&mut self, proof: DefiPriceProof) -> Result<()> {
        require(
            self.price_proofs.len() < MAX_PRICE_PROOFS,
            "price proof registry full",
        )?;
        proof.validate(&self.config)?;
        require(self.batches.contains_key(&proof.batch_id), "unknown batch")?;
        self.counters.next_price_proof_sequence = self
            .counters
            .next_price_proof_sequence
            .max(proof.sequence + 1);
        if let Some(batch) = self.batches.get_mut(&proof.batch_id) {
            batch.status = BatchStatus::Proven;
            for id in batch.observation_ids.clone() {
                if let Some(obs) = self.observations.get_mut(&id) {
                    obs.status = ObservationStatus::Proven;
                }
            }
        }
        let id = proof.proof_id.clone();
        self.price_proofs.insert(id.clone(), proof);
        self.emit_event("price_proof_accepted", &id)
    }
    pub fn issue_rebate(&mut self, rebate: SponsorRebate) -> Result<()> {
        require(self.rebates.len() < MAX_REBATES, "rebate registry full")?;
        rebate.validate()?;
        require(
            self.subscriptions.contains_key(&rebate.subscription_id),
            "unknown subscription",
        )?;
        require(self.batches.contains_key(&rebate.batch_id), "unknown batch")?;
        require(
            self.sponsor_budget_remaining_micro_units >= rebate.amount_micro_units,
            "sponsor budget exhausted",
        )?;
        self.sponsor_budget_remaining_micro_units -= rebate.amount_micro_units;
        self.counters.next_rebate_sequence =
            self.counters.next_rebate_sequence.max(rebate.sequence + 1);
        let id = rebate.rebate_id.clone();
        self.rebates.insert(id.clone(), rebate);
        self.emit_event("rebate_issued", &id)
    }
    pub fn accept_receipt(&mut self, receipt: RecursiveProofReceipt) -> Result<()> {
        require(self.receipts.len() < MAX_RECEIPTS, "receipt registry full")?;
        receipt.validate()?;
        require(
            self.batches.contains_key(&receipt.batch_id),
            "unknown batch",
        )?;
        self.counters.next_receipt_sequence = self
            .counters
            .next_receipt_sequence
            .max(receipt.sequence + 1);
        let id = receipt.receipt_id.clone();
        self.receipts.insert(id.clone(), receipt);
        self.emit_event("recursive_receipt_accepted", &id)
    }
    pub fn record_sla_snapshot(&mut self, snapshot: LatencySlaSnapshot) -> Result<()> {
        require(
            self.sla_snapshots.len() < MAX_SLA_SNAPSHOTS,
            "sla registry full",
        )?;
        snapshot.validate()?;
        self.counters.next_sla_sequence =
            self.counters.next_sla_sequence.max(snapshot.sequence + 1);
        let id = snapshot.snapshot_id.clone();
        self.sla_snapshots.insert(id.clone(), snapshot);
        self.emit_event("sla_snapshot_recorded", &id)
    }
    pub fn add_fence(&mut self, fence: NullifierFence) -> Result<()> {
        require(self.fences.len() < MAX_FENCES, "fence registry full")?;
        fence.validate()?;
        self.counters.next_fence_sequence =
            self.counters.next_fence_sequence.max(fence.sequence + 1);
        let id = fence.fence_id.clone();
        self.fences.insert(id.clone(), fence);
        self.emit_event("fence_added", &id)
    }
    pub fn spend_fence_nullifier(&mut self, fence_id: &str, nullifier: &str) -> Result<()> {
        require_hash_like("nullifier", nullifier)?;
        let fence = self
            .fences
            .get_mut(fence_id)
            .ok_or_else(|| "unknown fence".to_string())?;
        require(fence.active, "fence inactive")?;
        require(!fence.contains(nullifier), "fence nullifier already spent")?;
        fence.spent_nullifiers.insert(nullifier.to_string());
        self.used_nullifiers.insert(nullifier.to_string());
        self.emit_event("fence_nullifier_spent", fence_id)
    }
    pub fn submit_evidence(&mut self, evidence: ChallengeEvidence) -> Result<()> {
        require(self.evidence.len() < MAX_EVIDENCE, "evidence registry full")?;
        evidence.validate()?;
        self.counters.next_evidence_sequence = self
            .counters
            .next_evidence_sequence
            .max(evidence.sequence + 1);
        let id = evidence.evidence_id.clone();
        self.evidence.insert(id.clone(), evidence);
        self.emit_event("evidence_submitted", &id)
    }
    pub fn accept_evidence_and_slash(&mut self, evidence_id: &str) -> Result<()> {
        let (member_id, amount) = {
            let ev = self
                .evidence
                .get_mut(evidence_id)
                .ok_or_else(|| "unknown evidence".to_string())?;
            require(
                matches!(
                    ev.status,
                    EvidenceStatus::Submitted | EvidenceStatus::UnderReview
                ),
                "evidence not open",
            )?;
            ev.status = EvidenceStatus::Slashed;
            (ev.accused_member_id.clone(), ev.slash_amount_micro_units)
        };
        let member = self
            .committee
            .get_mut(&member_id)
            .ok_or_else(|| "unknown accused member".to_string())?;
        member.slashed_micro_units = member.slashed_micro_units.saturating_add(amount);
        member.reputation = member.reputation.saturating_sub(amount.min(1_000));
        if member.reputation == 0 {
            member.active = false;
        }
        self.emit_event("evidence_slashed", evidence_id)
    }
    pub fn expire_height(&mut self, new_l2_height: u64, new_monero_height: u64) -> Result<()> {
        require(
            new_l2_height >= self.current_l2_height,
            "l2 height regression",
        )?;
        require(
            new_monero_height >= self.current_monero_height,
            "monero height regression",
        )?;
        self.current_l2_height = new_l2_height;
        self.current_monero_height = new_monero_height;
        for obs in self.observations.values_mut() {
            if obs.status.live()
                && obs.reveal_deadline_height + self.config.observation_ttl_blocks < new_l2_height
            {
                obs.status = ObservationStatus::Expired;
            }
        }
        for sub in self.subscriptions.values_mut() {
            if sub.paid_through_height < new_l2_height {
                sub.active = false;
            }
        }
        for fence in self.fences.values_mut() {
            if fence.expires_at_height < new_l2_height {
                fence.active = false;
            }
        }
        self.emit_event("height_advanced", &new_l2_height.to_string())
    }
    fn emit_event(&mut self, kind: &str, subject_id: &str) -> Result<()> {
        let seq = self.counters.next_event_sequence;
        self.counters.next_event_sequence += 1;
        let details_root =
            deterministic_root(&format!("{kind}:{subject_id}:{}", self.current_l2_height));
        let event = RuntimeEvent {
            event_id: event_id(seq, kind, subject_id, &details_root),
            sequence: seq,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            details_root,
            height: self.current_l2_height,
            state_root_after: self.state_root(),
        };
        self.events.push(event);
        if self.events.len() > MAX_EVENTS {
            self.events.remove(0);
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn public_record_root(record: &Value) -> String {
    root_from_record("PUBLIC-RECORD", record)
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}
pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn empty_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-EMPTY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-DETERMINISTIC",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &records)
}
pub fn feed_id(
    sequence: u64,
    namespace: &str,
    symbol: &str,
    kind: FeedKind,
    asset_pair_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(namespace),
            HashPart::Str(symbol),
            HashPart::Str(kind.as_str()),
            HashPart::Str(asset_pair_root),
        ],
        32,
    )
}
pub fn observation_id(
    sequence: u64,
    feed_id: &str,
    signer_id: &str,
    encrypted_payload_root: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(feed_id),
            HashPart::Str(signer_id),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(nullifier),
        ],
        32,
    )
}
pub fn batch_id(sequence: u64, feed_id: &str, commit_root: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(feed_id),
            HashPart::Str(commit_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn committee_member_id(
    sequence: u64,
    operator_commitment: &str,
    role: CommitteeRole,
    signing_key_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(operator_commitment),
            HashPart::Str(role.as_str()),
            HashPart::Str(signing_key_commitment),
        ],
        32,
    )
}
pub fn subscription_id(
    sequence: u64,
    feed_id: &str,
    subscriber_commitment: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-SUBSCRIPTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(feed_id),
            HashPart::Str(subscriber_commitment),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}
pub fn price_proof_id(
    sequence: u64,
    feed_id: &str,
    batch_id: &str,
    proof_kind: ProofKind,
    proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-PRICE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(feed_id),
            HashPart::Str(batch_id),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(proof_root),
        ],
        32,
    )
}
pub fn rebate_id(
    sequence: u64,
    subscription_id: &str,
    batch_id: &str,
    reason: RebateReason,
    rebate_note_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(subscription_id),
            HashPart::Str(batch_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(rebate_note_root),
        ],
        32,
    )
}
pub fn receipt_id(
    sequence: u64,
    batch_id: &str,
    accumulator_root: &str,
    proof_receipt_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(batch_id),
            HashPart::Str(accumulator_root),
            HashPart::Str(proof_receipt_root),
        ],
        32,
    )
}
pub fn sla_snapshot_id(
    sequence: u64,
    batch_id: &str,
    feed_id: &str,
    snapshot_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-SLA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(batch_id),
            HashPart::Str(feed_id),
            HashPart::Str(snapshot_root),
        ],
        32,
    )
}
pub fn fence_id(
    sequence: u64,
    kind: FenceKind,
    namespace: &str,
    subject_id: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(namespace),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}
pub fn evidence_id(
    sequence: u64,
    reason: EvidenceReason,
    subject_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(reason.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}
pub fn event_id(sequence: u64, kind: &str, subject_id: &str, details_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ORACLE-MEV-RESISTANT-BATCH-FEED-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(details_root),
        ],
        32,
    )
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn require_non_empty(name: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{name} must not be empty"),
    )
}
fn require_hash_like(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    require(value.len() >= 16, &format!("{name} must be hash-like"))
}
fn is_valid_bps(value: u64) -> bool {
    value <= MAX_BPS
}
