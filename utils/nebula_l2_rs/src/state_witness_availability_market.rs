use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type StateWitnessAvailabilityMarketResult<T> = Result<T, String>;

pub const STATE_WITNESS_AVAILABILITY_MARKET_PROTOCOL_VERSION: &str =
    "nebula-state-witness-availability-market-v1";
pub const STATE_WITNESS_AVAILABILITY_MARKET_SCHEMA_VERSION: u64 = 1;
pub const STATE_WITNESS_AVAILABILITY_MARKET_HASH_SUITE: &str = "SHAKE256";
pub const STATE_WITNESS_AVAILABILITY_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const STATE_WITNESS_AVAILABILITY_MARKET_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const STATE_WITNESS_AVAILABILITY_MARKET_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const STATE_WITNESS_AVAILABILITY_MARKET_ENCRYPTION_SCHEME: &str =
    "ml-kem-768-xchacha20poly1305-witness-envelope-v1";
pub const STATE_WITNESS_AVAILABILITY_MARKET_COMMITMENT_SCHEME: &str =
    "shake256-state-witness-shard-commitment-v1";
pub const STATE_WITNESS_AVAILABILITY_MARKET_CACHE_SCHEME: &str =
    "shake256-prover-cache-availability-v1";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_HOT_RETENTION_BLOCKS: u64 = 96;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_WARM_RETENTION_BLOCKS: u64 = 720;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_RETENTION_BLOCKS: u64 = 14_400;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_TICKET_TTL_BLOCKS: u64 = 12;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_BID_TTL_BLOCKS: u64 = 18;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_OFFER_TTL_BLOCKS: u64 = 24;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CACHE_TTL_BLOCKS: u64 = 256;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_SLASH_BPS: u64 = 1_500;
pub const STATE_WITNESS_AVAILABILITY_MARKET_WITHHELD_WITNESS_SLASH_BPS: u64 = 3_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_BAD_DECRYPTION_SLASH_BPS: u64 = 2_500;
pub const STATE_WITNESS_AVAILABILITY_MARKET_STALE_CACHE_SLASH_BPS: u64 = 1_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_REPORTER_REWARD_BPS: u64 = 2_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_SPONSOR_REFUND_BPS: u64 = 5_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS: u64 = 10_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_SHARDS_PER_BATCH: u64 = 8_192;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_SHARD_BYTES: u64 = 32 * 1024;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_ENVELOPE_BYTES: u64 = 64 * 1024;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_LOW_FEE_FLOOR_UNITS: u64 = 2;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_HOT_FEE_PER_KIB: u64 = 3;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_WARM_FEE_PER_KIB: u64 = 1;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_FEE_PER_KIB: u64 = 1;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_RETRIEVAL_FEE_UNITS: u64 = 2;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CACHE_HIT_TARGET_BPS: u64 = 9_500;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_PQ_SECURITY_BITS: u16 = 128;
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_OPERATOR_ID: &str =
    "nebula-state-witness-market-operator-devnet";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_HOT_PROVIDER_ID: &str =
    "nebula-state-witness-hot-provider-devnet";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_COLD_PROVIDER_ID: &str =
    "nebula-state-witness-cold-provider-devnet";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_PROVER_ID: &str =
    "nebula-state-witness-prover-devnet";
pub const STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_WATCHTOWER_ID: &str =
    "nebula-state-witness-watchtower-devnet";

pub const STATE_WITNESS_STATUS_ACTIVE: &str = "active";
pub const STATE_WITNESS_STATUS_PAUSED: &str = "paused";
pub const STATE_WITNESS_STATUS_PENDING: &str = "pending";
pub const STATE_WITNESS_STATUS_OPEN: &str = "open";
pub const STATE_WITNESS_STATUS_OFFERED: &str = "offered";
pub const STATE_WITNESS_STATUS_ACCEPTED: &str = "accepted";
pub const STATE_WITNESS_STATUS_RESERVED: &str = "reserved";
pub const STATE_WITNESS_STATUS_ENCRYPTED: &str = "encrypted";
pub const STATE_WITNESS_STATUS_RETRIEVABLE: &str = "retrievable";
pub const STATE_WITNESS_STATUS_RETRIEVED: &str = "retrieved";
pub const STATE_WITNESS_STATUS_PARTIAL: &str = "partial";
pub const STATE_WITNESS_STATUS_CACHED: &str = "cached";
pub const STATE_WITNESS_STATUS_VERIFIED: &str = "verified";
pub const STATE_WITNESS_STATUS_CHALLENGED: &str = "challenged";
pub const STATE_WITNESS_STATUS_SLASHED: &str = "slashed";
pub const STATE_WITNESS_STATUS_SETTLED: &str = "settled";
pub const STATE_WITNESS_STATUS_REJECTED: &str = "rejected";
pub const STATE_WITNESS_STATUS_EXPIRED: &str = "expired";
pub const STATE_WITNESS_STATUS_SPONSORED: &str = "sponsored";
pub const STATE_WITNESS_STATUS_EXHAUSTED: &str = "exhausted";
pub const STATE_WITNESS_STATUS_DISMISSED: &str = "dismissed";
pub const STATE_WITNESS_STATUS_REVOKED: &str = "revoked";

const VALID_MARKET_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_ACTIVE,
    STATE_WITNESS_STATUS_PAUSED,
    STATE_WITNESS_STATUS_CHALLENGED,
];
const VALID_SHARD_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_PENDING,
    STATE_WITNESS_STATUS_ACCEPTED,
    STATE_WITNESS_STATUS_ENCRYPTED,
    STATE_WITNESS_STATUS_RETRIEVABLE,
    STATE_WITNESS_STATUS_CACHED,
    STATE_WITNESS_STATUS_EXPIRED,
    STATE_WITNESS_STATUS_SLASHED,
];
const VALID_OFFER_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_OPEN,
    STATE_WITNESS_STATUS_OFFERED,
    STATE_WITNESS_STATUS_ACCEPTED,
    STATE_WITNESS_STATUS_RESERVED,
    STATE_WITNESS_STATUS_RETRIEVABLE,
    STATE_WITNESS_STATUS_REJECTED,
    STATE_WITNESS_STATUS_EXPIRED,
];
const VALID_BID_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_OPEN,
    STATE_WITNESS_STATUS_ACCEPTED,
    STATE_WITNESS_STATUS_RESERVED,
    STATE_WITNESS_STATUS_RETRIEVED,
    STATE_WITNESS_STATUS_REJECTED,
    STATE_WITNESS_STATUS_EXPIRED,
];
const VALID_CACHE_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_PENDING,
    STATE_WITNESS_STATUS_CACHED,
    STATE_WITNESS_STATUS_VERIFIED,
    STATE_WITNESS_STATUS_CHALLENGED,
    STATE_WITNESS_STATUS_EXPIRED,
    STATE_WITNESS_STATUS_SLASHED,
];
const VALID_RECEIPT_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_ACCEPTED,
    STATE_WITNESS_STATUS_PARTIAL,
    STATE_WITNESS_STATUS_VERIFIED,
    STATE_WITNESS_STATUS_REJECTED,
    STATE_WITNESS_STATUS_EXPIRED,
];
const VALID_TICKET_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_OPEN,
    STATE_WITNESS_STATUS_RESERVED,
    STATE_WITNESS_STATUS_RETRIEVED,
    STATE_WITNESS_STATUS_PARTIAL,
    STATE_WITNESS_STATUS_REJECTED,
    STATE_WITNESS_STATUS_EXPIRED,
];
const VALID_EVIDENCE_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_OPEN,
    STATE_WITNESS_STATUS_VERIFIED,
    STATE_WITNESS_STATUS_SETTLED,
    STATE_WITNESS_STATUS_DISMISSED,
    STATE_WITNESS_STATUS_REJECTED,
];
const VALID_SPONSORSHIP_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_ACTIVE,
    STATE_WITNESS_STATUS_SPONSORED,
    STATE_WITNESS_STATUS_PAUSED,
    STATE_WITNESS_STATUS_EXHAUSTED,
    STATE_WITNESS_STATUS_EXPIRED,
    STATE_WITNESS_STATUS_REVOKED,
];
const VALID_TIER_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_ACTIVE,
    STATE_WITNESS_STATUS_PAUSED,
    STATE_WITNESS_STATUS_EXHAUSTED,
    STATE_WITNESS_STATUS_EXPIRED,
];
const VALID_PUBLIC_RECORD_STATUSES: &[&str] = &[
    STATE_WITNESS_STATUS_ACTIVE,
    STATE_WITNESS_STATUS_PAUSED,
    STATE_WITNESS_STATUS_EXPIRED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateWitnessDomain {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiSwap,
    Lending,
    ContractCall,
    NftMint,
    Governance,
    FeeRebate,
    RecursiveProof,
    EmergencyExit,
}

impl StateWitnessDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::ContractCall => "contract_call",
            Self::NftMint => "nft_mint",
            Self::Governance => "governance",
            Self::FeeRebate => "fee_rebate",
            Self::RecursiveProof => "recursive_proof",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::MoneroBridge => 96,
            Self::PrivateTransfer => 92,
            Self::DefiSwap => 88,
            Self::Lending => 84,
            Self::ContractCall => 80,
            Self::TokenTransfer => 76,
            Self::FeeRebate => 74,
            Self::RecursiveProof => 70,
            Self::NftMint => 62,
            Self::Governance => 50,
        }
    }

    pub fn default_lane_key(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private-transfer-witness",
            Self::MoneroBridge => "monero-bridge-witness",
            Self::TokenTransfer => "token-transfer-witness",
            Self::DefiSwap => "defi-swap-witness",
            Self::Lending => "lending-witness",
            Self::ContractCall => "contract-call-witness",
            Self::NftMint => "nft-mint-witness",
            Self::Governance => "governance-witness",
            Self::FeeRebate => "fee-rebate-witness",
            Self::RecursiveProof => "recursive-proof-witness",
            Self::EmergencyExit => "emergency-exit-witness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPrivacyMode {
    FullyShielded,
    NullifierOnly,
    AggregateOnly,
    PublicInputsOnly,
    EmergencyReveal,
}

impl WitnessPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::NullifierOnly => "nullifier_only",
            Self::AggregateOnly => "aggregate_only",
            Self::PublicInputsOnly => "public_inputs_only",
            Self::EmergencyReveal => "emergency_reveal",
        }
    }

    pub fn disclosure_bps(self) -> u64 {
        match self {
            Self::FullyShielded => 0,
            Self::NullifierOnly => 100,
            Self::AggregateOnly => 250,
            Self::PublicInputsOnly => 750,
            Self::EmergencyReveal => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessShardKind {
    AccountDelta,
    ContractStorage,
    TokenBalance,
    LiquidityPosition,
    BridgeQueue,
    NullifierSet,
    EventLog,
    ProverHint,
    RecursiveAccumulator,
}

impl WitnessShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountDelta => "account_delta",
            Self::ContractStorage => "contract_storage",
            Self::TokenBalance => "token_balance",
            Self::LiquidityPosition => "liquidity_position",
            Self::BridgeQueue => "bridge_queue",
            Self::NullifierSet => "nullifier_set",
            Self::EventLog => "event_log",
            Self::ProverHint => "prover_hint",
            Self::RecursiveAccumulator => "recursive_accumulator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessTierKind {
    Hot,
    Warm,
    Cold,
    Archive,
}

impl WitnessTierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Archive => "archive",
        }
    }

    pub fn default_retention_blocks(self) -> u64 {
        match self {
            Self::Hot => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_HOT_RETENTION_BLOCKS,
            Self::Warm => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_WARM_RETENTION_BLOCKS,
            Self::Cold => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_RETENTION_BLOCKS,
            Self::Archive => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_RETENTION_BLOCKS * 4,
        }
    }

    pub fn default_fee_per_kib(self) -> u64 {
        match self {
            Self::Hot => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_HOT_FEE_PER_KIB,
            Self::Warm => STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_WARM_FEE_PER_KIB,
            Self::Cold | Self::Archive => {
                STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_FEE_PER_KIB
            }
        }
    }

    pub fn latency_target_ms(self) -> u64 {
        match self {
            Self::Hot => 150,
            Self::Warm => 1_000,
            Self::Cold => 5_000,
            Self::Archive => 30_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPurpose {
    Proving,
    Verification,
    LightClient,
    Watchtower,
    Recovery,
    Audit,
}

impl RetrievalPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proving => "proving",
            Self::Verification => "verification",
            Self::LightClient => "light_client",
            Self::Watchtower => "watchtower",
            Self::Recovery => "recovery",
            Self::Audit => "audit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    WithheldWitness,
    BadDecryptionShare,
    InvalidShardCommitment,
    StaleProverCache,
    FalseAvailabilityClaim,
    ReplayTicket,
    OverpricedSponsoredRetrieval,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithheldWitness => "withheld_witness",
            Self::BadDecryptionShare => "bad_decryption_share",
            Self::InvalidShardCommitment => "invalid_shard_commitment",
            Self::StaleProverCache => "stale_prover_cache",
            Self::FalseAvailabilityClaim => "false_availability_claim",
            Self::ReplayTicket => "replay_ticket",
            Self::OverpricedSponsoredRetrieval => "overpriced_sponsored_retrieval",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::WithheldWitness => STATE_WITNESS_AVAILABILITY_MARKET_WITHHELD_WITNESS_SLASH_BPS,
            Self::BadDecryptionShare => STATE_WITNESS_AVAILABILITY_MARKET_BAD_DECRYPTION_SLASH_BPS,
            Self::StaleProverCache => STATE_WITNESS_AVAILABILITY_MARKET_STALE_CACHE_SLASH_BPS,
            Self::InvalidShardCommitment | Self::FalseAvailabilityClaim => {
                STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_SLASH_BPS
            }
            Self::ReplayTicket | Self::OverpricedSponsoredRetrieval => 500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessAvailabilityMarketConfig {
    pub default_fee_asset_id: String,
    pub hot_retention_blocks: u64,
    pub warm_retention_blocks: u64,
    pub cold_retention_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub offer_ttl_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_shards_per_batch: u64,
    pub max_shard_bytes: u64,
    pub max_envelope_bytes: u64,
    pub low_fee_floor_units: u64,
    pub default_retrieval_fee_units: u64,
    pub sponsor_rebate_bps: u64,
    pub reporter_reward_bps: u64,
    pub sponsor_refund_bps: u64,
    pub cache_hit_target_bps: u64,
    pub max_bps: u64,
    pub pq_security_bits: u16,
}

impl Default for StateWitnessAvailabilityMarketConfig {
    fn default() -> Self {
        Self {
            default_fee_asset_id: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_FEE_ASSET_ID
                .to_string(),
            hot_retention_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_HOT_RETENTION_BLOCKS,
            warm_retention_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_WARM_RETENTION_BLOCKS,
            cold_retention_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_COLD_RETENTION_BLOCKS,
            ticket_ttl_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_TICKET_TTL_BLOCKS,
            bid_ttl_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_BID_TTL_BLOCKS,
            offer_ttl_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_OFFER_TTL_BLOCKS,
            cache_ttl_blocks: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CACHE_TTL_BLOCKS,
            challenge_window_blocks:
                STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_shards_per_batch: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_SHARDS_PER_BATCH,
            max_shard_bytes: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_SHARD_BYTES,
            max_envelope_bytes: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_ENVELOPE_BYTES,
            low_fee_floor_units: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_LOW_FEE_FLOOR_UNITS,
            default_retrieval_fee_units:
                STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_RETRIEVAL_FEE_UNITS,
            sponsor_rebate_bps: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_SPONSOR_REBATE_BPS,
            reporter_reward_bps: STATE_WITNESS_AVAILABILITY_MARKET_REPORTER_REWARD_BPS,
            sponsor_refund_bps: STATE_WITNESS_AVAILABILITY_MARKET_SPONSOR_REFUND_BPS,
            cache_hit_target_bps: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_CACHE_HIT_TARGET_BPS,
            max_bps: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS,
            pq_security_bits: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_PQ_SECURITY_BITS,
        }
    }
}

impl StateWitnessAvailabilityMarketConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "default_fee_asset_id": self.default_fee_asset_id,
            "hot_retention_blocks": self.hot_retention_blocks,
            "warm_retention_blocks": self.warm_retention_blocks,
            "cold_retention_blocks": self.cold_retention_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "offer_ttl_blocks": self.offer_ttl_blocks,
            "cache_ttl_blocks": self.cache_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_shards_per_batch": self.max_shards_per_batch,
            "max_shard_bytes": self.max_shard_bytes,
            "max_envelope_bytes": self.max_envelope_bytes,
            "low_fee_floor_units": self.low_fee_floor_units,
            "default_retrieval_fee_units": self.default_retrieval_fee_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "sponsor_refund_bps": self.sponsor_refund_bps,
            "cache_hit_target_bps": self.cache_hit_target_bps,
            "max_bps": self.max_bps,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn config_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("default fee asset id", &self.default_fee_asset_id)?;
        if self.hot_retention_blocks == 0
            || self.warm_retention_blocks < self.hot_retention_blocks
            || self.cold_retention_blocks < self.warm_retention_blocks
        {
            return Err("witness retention blocks must be ordered hot <= warm <= cold".to_string());
        }
        if self.ticket_ttl_blocks == 0
            || self.bid_ttl_blocks == 0
            || self.offer_ttl_blocks == 0
            || self.cache_ttl_blocks == 0
            || self.challenge_window_blocks == 0
        {
            return Err("witness market TTL and challenge windows must be non-zero".to_string());
        }
        if self.max_shards_per_batch == 0
            || self.max_shard_bytes == 0
            || self.max_envelope_bytes == 0
        {
            return Err("witness market byte and shard limits must be non-zero".to_string());
        }
        if self.sponsor_rebate_bps > self.max_bps
            || self.reporter_reward_bps > self.max_bps
            || self.sponsor_refund_bps > self.max_bps
            || self.cache_hit_target_bps > self.max_bps
        {
            return Err("witness market bps values exceed max bps".to_string());
        }
        if self.pq_security_bits < 128 {
            return Err("witness market requires at least 128-bit PQ security".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessTierPolicy {
    pub tier_id: String,
    pub tier: WitnessTierKind,
    pub provider_id: String,
    pub status: String,
    pub lane_keys: BTreeSet<String>,
    pub max_shard_bytes: u64,
    pub max_shards: u64,
    pub retention_blocks: u64,
    pub target_latency_ms: u64,
    pub fee_per_kib_units: u64,
    pub stake_bond_units: u64,
    pub available_capacity_bytes: u64,
    pub reserved_capacity_bytes: u64,
    pub pq_key_commitment: String,
    pub endpoint_commitment: String,
}

impl WitnessTierPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tier: WitnessTierKind,
        provider_id: &str,
        lane_keys: &[String],
        max_shard_bytes: u64,
        max_shards: u64,
        retention_blocks: u64,
        fee_per_kib_units: u64,
        stake_bond_units: u64,
        available_capacity_bytes: u64,
        pq_key_commitment: &str,
        endpoint_commitment: &str,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("provider id", provider_id)?;
        ensure_non_empty("tier PQ key commitment", pq_key_commitment)?;
        ensure_non_empty("tier endpoint commitment", endpoint_commitment)?;
        if lane_keys.is_empty() {
            return Err("witness tier policy requires lane keys".to_string());
        }
        let lane_set = lane_keys.iter().cloned().collect::<BTreeSet<_>>();
        let tier_id = state_witness_tier_id(tier, provider_id, &lane_set, pq_key_commitment);
        let tier_policy = Self {
            tier_id,
            tier,
            provider_id: provider_id.to_string(),
            status: STATE_WITNESS_STATUS_ACTIVE.to_string(),
            lane_keys: lane_set,
            max_shard_bytes,
            max_shards,
            retention_blocks,
            target_latency_ms: tier.latency_target_ms(),
            fee_per_kib_units,
            stake_bond_units,
            available_capacity_bytes,
            reserved_capacity_bytes: 0,
            pq_key_commitment: pq_key_commitment.to_string(),
            endpoint_commitment: endpoint_commitment.to_string(),
        };
        tier_policy.validate()?;
        Ok(tier_policy)
    }

    pub fn devnet(tier: WitnessTierKind, provider_id: &str, lane_keys: &[String]) -> Self {
        let lane_set = lane_keys.iter().cloned().collect::<BTreeSet<_>>();
        Self {
            tier_id: state_witness_tier_id(
                tier,
                provider_id,
                &lane_set,
                &devnet_hash("STATE-WITNESS-DEVNET-TIER-PQ-KEY", provider_id),
            ),
            tier,
            provider_id: provider_id.to_string(),
            status: STATE_WITNESS_STATUS_ACTIVE.to_string(),
            lane_keys: lane_set,
            max_shard_bytes: STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_SHARD_BYTES,
            max_shards: 4_096,
            retention_blocks: tier.default_retention_blocks(),
            target_latency_ms: tier.latency_target_ms(),
            fee_per_kib_units: tier.default_fee_per_kib(),
            stake_bond_units: match tier {
                WitnessTierKind::Hot => 250_000,
                WitnessTierKind::Warm => 150_000,
                WitnessTierKind::Cold => 100_000,
                WitnessTierKind::Archive => 75_000,
            },
            available_capacity_bytes: match tier {
                WitnessTierKind::Hot => 512 * 1024 * 1024,
                WitnessTierKind::Warm => 2 * 1024 * 1024 * 1024,
                WitnessTierKind::Cold | WitnessTierKind::Archive => 8 * 1024 * 1024 * 1024,
            },
            reserved_capacity_bytes: 0,
            pq_key_commitment: devnet_hash("STATE-WITNESS-DEVNET-TIER-PQ-KEY", provider_id),
            endpoint_commitment: devnet_hash("STATE-WITNESS-DEVNET-TIER-ENDPOINT", provider_id),
        }
    }

    pub fn available_bytes(&self) -> u64 {
        self.available_capacity_bytes
            .saturating_sub(self.reserved_capacity_bytes)
    }

    pub fn can_serve_lane(&self, lane_key: &str) -> bool {
        self.status == STATE_WITNESS_STATUS_ACTIVE && self.lane_keys.contains(lane_key)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "tier_id": self.tier_id,
            "tier": self.tier.as_str(),
            "provider_id": self.provider_id,
            "status": self.status,
            "lane_keys": self.lane_keys.iter().cloned().collect::<Vec<_>>(),
            "max_shard_bytes": self.max_shard_bytes,
            "max_shards": self.max_shards,
            "retention_blocks": self.retention_blocks,
            "target_latency_ms": self.target_latency_ms,
            "fee_per_kib_units": self.fee_per_kib_units,
            "stake_bond_units": self.stake_bond_units,
            "available_capacity_bytes": self.available_capacity_bytes,
            "reserved_capacity_bytes": self.reserved_capacity_bytes,
            "available_bytes": self.available_bytes(),
            "pq_key_commitment": self.pq_key_commitment,
            "endpoint_commitment": self.endpoint_commitment,
        })
    }

    pub fn tier_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-TIER", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("tier id", &self.tier_id)?;
        ensure_non_empty("tier provider id", &self.provider_id)?;
        ensure_status(&self.status, VALID_TIER_STATUSES, "witness tier status")?;
        ensure_non_empty("tier PQ key commitment", &self.pq_key_commitment)?;
        ensure_non_empty("tier endpoint commitment", &self.endpoint_commitment)?;
        if self.lane_keys.is_empty() {
            return Err("witness tier requires at least one lane key".to_string());
        }
        for lane_key in &self.lane_keys {
            ensure_non_empty("tier lane key", lane_key)?;
        }
        if self.max_shard_bytes == 0 || self.max_shards == 0 || self.retention_blocks == 0 {
            return Err("witness tier limits must be non-zero".to_string());
        }
        if self.target_latency_ms == 0 {
            return Err("witness tier latency target must be non-zero".to_string());
        }
        if self.reserved_capacity_bytes > self.available_capacity_bytes {
            return Err("witness tier reserved capacity exceeds available capacity".to_string());
        }
        Ok(self.tier_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessShard {
    pub shard_id: String,
    pub batch_id: String,
    pub lane_key: String,
    pub domain: StateWitnessDomain,
    pub shard_kind: WitnessShardKind,
    pub tier: WitnessTierKind,
    pub shard_index: u64,
    pub shard_count: u64,
    pub byte_len: u64,
    pub unencrypted_commitment: String,
    pub encrypted_commitment: String,
    pub opening_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub nullifier_root: String,
    pub provider_id: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
    pub priority: u64,
    pub tags: BTreeSet<String>,
}

impl WitnessShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        lane_key: &str,
        domain: StateWitnessDomain,
        shard_kind: WitnessShardKind,
        tier: WitnessTierKind,
        shard_index: u64,
        shard_count: u64,
        byte_len: u64,
        unencrypted_commitment: &str,
        encrypted_commitment: &str,
        opening_root: &str,
        state_root_before: &str,
        state_root_after: &str,
        nullifier_root: &str,
        provider_id: &str,
        posted_at_height: u64,
        retention_blocks: u64,
        priority: u64,
        tags: &[String],
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("witness batch id", batch_id)?;
        ensure_non_empty("witness lane key", lane_key)?;
        ensure_non_empty("witness unencrypted commitment", unencrypted_commitment)?;
        ensure_non_empty("witness encrypted commitment", encrypted_commitment)?;
        ensure_non_empty("witness opening root", opening_root)?;
        ensure_non_empty("witness state root before", state_root_before)?;
        ensure_non_empty("witness state root after", state_root_after)?;
        ensure_non_empty("witness nullifier root", nullifier_root)?;
        ensure_non_empty("witness provider id", provider_id)?;
        if shard_count == 0 || shard_index >= shard_count {
            return Err("witness shard index must be within shard count".to_string());
        }
        if byte_len == 0 {
            return Err("witness shard byte length must be non-zero".to_string());
        }
        let tag_set = tags.iter().cloned().collect::<BTreeSet<_>>();
        let shard_id = state_witness_shard_id(
            batch_id,
            lane_key,
            domain,
            shard_kind,
            shard_index,
            encrypted_commitment,
        );
        let shard = Self {
            shard_id,
            batch_id: batch_id.to_string(),
            lane_key: lane_key.to_string(),
            domain,
            shard_kind,
            tier,
            shard_index,
            shard_count,
            byte_len,
            unencrypted_commitment: unencrypted_commitment.to_string(),
            encrypted_commitment: encrypted_commitment.to_string(),
            opening_root: opening_root.to_string(),
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            nullifier_root: nullifier_root.to_string(),
            provider_id: provider_id.to_string(),
            posted_at_height,
            expires_at_height: posted_at_height.saturating_add(retention_blocks),
            status: STATE_WITNESS_STATUS_ENCRYPTED.to_string(),
            priority,
            tags: tag_set,
        };
        shard.validate()?;
        Ok(shard)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && matches!(
                self.status.as_str(),
                STATE_WITNESS_STATUS_ACCEPTED
                    | STATE_WITNESS_STATUS_ENCRYPTED
                    | STATE_WITNESS_STATUS_RETRIEVABLE
                    | STATE_WITNESS_STATUS_CACHED
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "batch_id": self.batch_id,
            "lane_key": self.lane_key,
            "domain": self.domain.as_str(),
            "shard_kind": self.shard_kind.as_str(),
            "tier": self.tier.as_str(),
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "byte_len": self.byte_len,
            "unencrypted_commitment": self.unencrypted_commitment,
            "encrypted_commitment": self.encrypted_commitment,
            "opening_root": self.opening_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "nullifier_root": self.nullifier_root,
            "provider_id": self.provider_id,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
            "priority": self.priority,
            "tags": self.tags.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn shard_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-SHARD", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("witness shard id", &self.shard_id)?;
        ensure_non_empty("witness batch id", &self.batch_id)?;
        ensure_non_empty("witness lane key", &self.lane_key)?;
        ensure_status(&self.status, VALID_SHARD_STATUSES, "witness shard status")?;
        ensure_non_empty(
            "witness unencrypted commitment",
            &self.unencrypted_commitment,
        )?;
        ensure_non_empty("witness encrypted commitment", &self.encrypted_commitment)?;
        ensure_non_empty("witness opening root", &self.opening_root)?;
        ensure_non_empty("witness state root before", &self.state_root_before)?;
        ensure_non_empty("witness state root after", &self.state_root_after)?;
        ensure_non_empty("witness nullifier root", &self.nullifier_root)?;
        ensure_non_empty("witness provider id", &self.provider_id)?;
        if self.shard_count == 0 || self.shard_index >= self.shard_count {
            return Err("witness shard index exceeds shard count".to_string());
        }
        if self.byte_len == 0 {
            return Err("witness shard byte length must be non-zero".to_string());
        }
        if self.expires_at_height < self.posted_at_height {
            return Err("witness shard expiry precedes posted height".to_string());
        }
        Ok(self.shard_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWitnessOffer {
    pub offer_id: String,
    pub shard_id: String,
    pub batch_id: String,
    pub provider_id: String,
    pub tier_id: String,
    pub lane_key: String,
    pub domain: StateWitnessDomain,
    pub tier: WitnessTierKind,
    pub encryption_scheme: String,
    pub kem_ciphertext_root: String,
    pub encrypted_payload_root: String,
    pub access_policy_root: String,
    pub asking_fee_units: u64,
    pub fee_asset_id: String,
    pub min_retrieval_height: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
    pub privacy_mode: WitnessPrivacyMode,
    pub sponsor_eligible: bool,
}

impl EncryptedWitnessOffer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard: &WitnessShard,
        tier_id: &str,
        kem_ciphertext_root: &str,
        encrypted_payload_root: &str,
        access_policy_root: &str,
        asking_fee_units: u64,
        fee_asset_id: &str,
        posted_at_height: u64,
        offer_ttl_blocks: u64,
        privacy_mode: WitnessPrivacyMode,
        sponsor_eligible: bool,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("offer tier id", tier_id)?;
        ensure_non_empty("offer KEM ciphertext root", kem_ciphertext_root)?;
        ensure_non_empty("offer encrypted payload root", encrypted_payload_root)?;
        ensure_non_empty("offer access policy root", access_policy_root)?;
        ensure_non_empty("offer fee asset id", fee_asset_id)?;
        let offer_id = state_witness_offer_id(
            &shard.shard_id,
            &shard.provider_id,
            tier_id,
            kem_ciphertext_root,
            posted_at_height,
        );
        let offer = Self {
            offer_id,
            shard_id: shard.shard_id.clone(),
            batch_id: shard.batch_id.clone(),
            provider_id: shard.provider_id.clone(),
            tier_id: tier_id.to_string(),
            lane_key: shard.lane_key.clone(),
            domain: shard.domain,
            tier: shard.tier,
            encryption_scheme: STATE_WITNESS_AVAILABILITY_MARKET_ENCRYPTION_SCHEME.to_string(),
            kem_ciphertext_root: kem_ciphertext_root.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            access_policy_root: access_policy_root.to_string(),
            asking_fee_units,
            fee_asset_id: fee_asset_id.to_string(),
            min_retrieval_height: posted_at_height,
            posted_at_height,
            expires_at_height: posted_at_height.saturating_add(offer_ttl_blocks),
            status: STATE_WITNESS_STATUS_OPEN.to_string(),
            privacy_mode,
            sponsor_eligible,
        };
        offer.validate()?;
        Ok(offer)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && matches!(
                self.status.as_str(),
                STATE_WITNESS_STATUS_OPEN
                    | STATE_WITNESS_STATUS_OFFERED
                    | STATE_WITNESS_STATUS_ACCEPTED
                    | STATE_WITNESS_STATUS_RESERVED
                    | STATE_WITNESS_STATUS_RETRIEVABLE
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "offer_id": self.offer_id,
            "shard_id": self.shard_id,
            "batch_id": self.batch_id,
            "provider_id": self.provider_id,
            "tier_id": self.tier_id,
            "lane_key": self.lane_key,
            "domain": self.domain.as_str(),
            "tier": self.tier.as_str(),
            "encryption_scheme": self.encryption_scheme,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "access_policy_root": self.access_policy_root,
            "asking_fee_units": self.asking_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "min_retrieval_height": self.min_retrieval_height,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
            "privacy_mode": self.privacy_mode.as_str(),
            "sponsor_eligible": self.sponsor_eligible,
        })
    }

    pub fn offer_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-OFFER", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("witness offer id", &self.offer_id)?;
        ensure_non_empty("witness offer shard id", &self.shard_id)?;
        ensure_non_empty("witness offer batch id", &self.batch_id)?;
        ensure_non_empty("witness offer provider id", &self.provider_id)?;
        ensure_non_empty("witness offer tier id", &self.tier_id)?;
        ensure_non_empty("witness offer lane key", &self.lane_key)?;
        ensure_non_empty("witness offer encryption scheme", &self.encryption_scheme)?;
        ensure_non_empty(
            "witness offer KEM ciphertext root",
            &self.kem_ciphertext_root,
        )?;
        ensure_non_empty(
            "witness offer encrypted payload root",
            &self.encrypted_payload_root,
        )?;
        ensure_non_empty("witness offer access policy root", &self.access_policy_root)?;
        ensure_non_empty("witness offer fee asset id", &self.fee_asset_id)?;
        ensure_status(
            &self.status,
            VALID_OFFER_STATUSES,
            "encrypted witness offer status",
        )?;
        if self.expires_at_height < self.posted_at_height {
            return Err("witness offer expiry precedes posting height".to_string());
        }
        if self.min_retrieval_height < self.posted_at_height {
            return Err("witness offer min retrieval precedes posting height".to_string());
        }
        Ok(self.offer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityBid {
    pub bid_id: String,
    pub offer_id: String,
    pub shard_id: String,
    pub requester_id: String,
    pub purpose: RetrievalPurpose,
    pub max_fee_units: u64,
    pub fee_asset_id: String,
    pub desired_tier: WitnessTierKind,
    pub max_latency_ms: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub accepted_offer_root: String,
    pub sponsor_id: Option<String>,
    pub status: String,
    pub priority: u64,
}

impl AvailabilityBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer: &EncryptedWitnessOffer,
        requester_id: &str,
        purpose: RetrievalPurpose,
        max_fee_units: u64,
        desired_tier: WitnessTierKind,
        max_latency_ms: u64,
        requested_at_height: u64,
        bid_ttl_blocks: u64,
        sponsor_id: Option<String>,
        priority: u64,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("availability bid requester id", requester_id)?;
        if max_latency_ms == 0 {
            return Err("availability bid max latency must be non-zero".to_string());
        }
        let offer_root = offer.offer_root();
        let bid_id = state_witness_bid_id(
            &offer.offer_id,
            requester_id,
            purpose,
            max_fee_units,
            requested_at_height,
        );
        let bid = Self {
            bid_id,
            offer_id: offer.offer_id.clone(),
            shard_id: offer.shard_id.clone(),
            requester_id: requester_id.to_string(),
            purpose,
            max_fee_units,
            fee_asset_id: offer.fee_asset_id.clone(),
            desired_tier,
            max_latency_ms,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(bid_ttl_blocks),
            accepted_offer_root: offer_root,
            sponsor_id,
            status: STATE_WITNESS_STATUS_OPEN.to_string(),
            priority,
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && matches!(
                self.status.as_str(),
                STATE_WITNESS_STATUS_OPEN
                    | STATE_WITNESS_STATUS_ACCEPTED
                    | STATE_WITNESS_STATUS_RESERVED
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "offer_id": self.offer_id,
            "shard_id": self.shard_id,
            "requester_id": self.requester_id,
            "purpose": self.purpose.as_str(),
            "max_fee_units": self.max_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "desired_tier": self.desired_tier.as_str(),
            "max_latency_ms": self.max_latency_ms,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "accepted_offer_root": self.accepted_offer_root,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "priority": self.priority,
        })
    }

    pub fn bid_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-AVAILABILITY-BID", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("availability bid id", &self.bid_id)?;
        ensure_non_empty("availability bid offer id", &self.offer_id)?;
        ensure_non_empty("availability bid shard id", &self.shard_id)?;
        ensure_non_empty("availability bid requester id", &self.requester_id)?;
        ensure_non_empty("availability bid fee asset id", &self.fee_asset_id)?;
        ensure_non_empty(
            "availability bid accepted offer root",
            &self.accepted_offer_root,
        )?;
        ensure_status(&self.status, VALID_BID_STATUSES, "availability bid status")?;
        if self.max_latency_ms == 0 {
            return Err("availability bid max latency must be non-zero".to_string());
        }
        if self.expires_at_height < self.requested_at_height {
            return Err("availability bid expiry precedes request height".to_string());
        }
        Ok(self.bid_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverCacheCommitment {
    pub cache_id: String,
    pub prover_id: String,
    pub shard_ids: BTreeSet<String>,
    pub batch_id: String,
    pub lane_key: String,
    pub cache_tier: WitnessTierKind,
    pub cache_root: String,
    pub cache_manifest_root: String,
    pub prefetch_hint_root: String,
    pub byte_len: u64,
    pub cache_hit_bps: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ProverCacheCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_id: &str,
        shards: &[WitnessShard],
        cache_tier: WitnessTierKind,
        cache_manifest_root: &str,
        prefetch_hint_root: &str,
        cache_hit_bps: u64,
        posted_at_height: u64,
        cache_ttl_blocks: u64,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("prover cache prover id", prover_id)?;
        ensure_non_empty("prover cache manifest root", cache_manifest_root)?;
        ensure_non_empty("prover cache prefetch hint root", prefetch_hint_root)?;
        if shards.is_empty() {
            return Err("prover cache commitment requires shards".to_string());
        }
        let first = shards
            .first()
            .ok_or_else(|| "prover cache commitment requires shards".to_string())?;
        let shard_ids = shards
            .iter()
            .map(|shard| shard.shard_id.clone())
            .collect::<BTreeSet<_>>();
        let shard_records = shards
            .iter()
            .map(WitnessShard::public_record)
            .collect::<Vec<_>>();
        let cache_root = merkle_root("STATE-WITNESS-PROVER-CACHE-SHARDS", &shard_records);
        let byte_len = shards
            .iter()
            .fold(0_u64, |total, shard| total.saturating_add(shard.byte_len));
        let cache_id = state_witness_cache_id(prover_id, &cache_root, posted_at_height);
        let commitment = Self {
            cache_id,
            prover_id: prover_id.to_string(),
            shard_ids,
            batch_id: first.batch_id.clone(),
            lane_key: first.lane_key.clone(),
            cache_tier,
            cache_root,
            cache_manifest_root: cache_manifest_root.to_string(),
            prefetch_hint_root: prefetch_hint_root.to_string(),
            byte_len,
            cache_hit_bps,
            posted_at_height,
            expires_at_height: posted_at_height.saturating_add(cache_ttl_blocks),
            status: STATE_WITNESS_STATUS_CACHED.to_string(),
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && matches!(
                self.status.as_str(),
                STATE_WITNESS_STATUS_CACHED | STATE_WITNESS_STATUS_VERIFIED
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cache_id": self.cache_id,
            "prover_id": self.prover_id,
            "shard_ids": self.shard_ids.iter().cloned().collect::<Vec<_>>(),
            "batch_id": self.batch_id,
            "lane_key": self.lane_key,
            "cache_tier": self.cache_tier.as_str(),
            "cache_root": self.cache_root,
            "cache_manifest_root": self.cache_manifest_root,
            "prefetch_hint_root": self.prefetch_hint_root,
            "byte_len": self.byte_len,
            "cache_hit_bps": self.cache_hit_bps,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn cache_commitment_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-PROVER-CACHE", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("prover cache id", &self.cache_id)?;
        ensure_non_empty("prover cache prover id", &self.prover_id)?;
        ensure_non_empty("prover cache batch id", &self.batch_id)?;
        ensure_non_empty("prover cache lane key", &self.lane_key)?;
        ensure_non_empty("prover cache root", &self.cache_root)?;
        ensure_non_empty("prover cache manifest root", &self.cache_manifest_root)?;
        ensure_non_empty("prover cache prefetch hint root", &self.prefetch_hint_root)?;
        ensure_status(
            &self.status,
            VALID_CACHE_STATUSES,
            "prover cache commitment status",
        )?;
        if self.shard_ids.is_empty() {
            return Err("prover cache commitment requires shard ids".to_string());
        }
        if self.byte_len == 0 {
            return Err("prover cache byte length must be non-zero".to_string());
        }
        if self.cache_hit_bps > STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS {
            return Err("prover cache hit bps exceeds max bps".to_string());
        }
        if self.expires_at_height < self.posted_at_height {
            return Err("prover cache expiry precedes posted height".to_string());
        }
        Ok(self.cache_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessDaSamplingReceipt {
    pub receipt_id: String,
    pub shard_id: String,
    pub offer_id: String,
    pub sampler_id: String,
    pub sampled_at_height: u64,
    pub response_height: u64,
    pub opening_root: String,
    pub sample_proof_root: String,
    pub returned: bool,
    pub latency_ms: u64,
    pub status: String,
}

impl WitnessDaSamplingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer: &EncryptedWitnessOffer,
        sampler_id: &str,
        sampled_at_height: u64,
        response_height: u64,
        opening_root: &str,
        sample_proof_root: &str,
        returned: bool,
        latency_ms: u64,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("witness sampling sampler id", sampler_id)?;
        ensure_non_empty("witness sampling opening root", opening_root)?;
        ensure_non_empty("witness sampling proof root", sample_proof_root)?;
        let receipt_id = state_witness_sampling_receipt_id(
            &offer.offer_id,
            sampler_id,
            sampled_at_height,
            sample_proof_root,
        );
        let receipt = Self {
            receipt_id,
            shard_id: offer.shard_id.clone(),
            offer_id: offer.offer_id.clone(),
            sampler_id: sampler_id.to_string(),
            sampled_at_height,
            response_height,
            opening_root: opening_root.to_string(),
            sample_proof_root: sample_proof_root.to_string(),
            returned,
            latency_ms,
            status: if returned {
                STATE_WITNESS_STATUS_VERIFIED.to_string()
            } else {
                STATE_WITNESS_STATUS_PARTIAL.to_string()
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "shard_id": self.shard_id,
            "offer_id": self.offer_id,
            "sampler_id": self.sampler_id,
            "sampled_at_height": self.sampled_at_height,
            "response_height": self.response_height,
            "opening_root": self.opening_root,
            "sample_proof_root": self.sample_proof_root,
            "returned": self.returned,
            "latency_ms": self.latency_ms,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-DA-SAMPLING-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("witness sampling receipt id", &self.receipt_id)?;
        ensure_non_empty("witness sampling shard id", &self.shard_id)?;
        ensure_non_empty("witness sampling offer id", &self.offer_id)?;
        ensure_non_empty("witness sampling sampler id", &self.sampler_id)?;
        ensure_non_empty("witness sampling opening root", &self.opening_root)?;
        ensure_non_empty("witness sampling proof root", &self.sample_proof_root)?;
        ensure_status(
            &self.status,
            VALID_RECEIPT_STATUSES,
            "witness DA sampling receipt status",
        )?;
        if self.response_height < self.sampled_at_height {
            return Err("witness sampling response precedes sample height".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalTicket {
    pub ticket_id: String,
    pub bid_id: String,
    pub offer_id: String,
    pub shard_id: String,
    pub requester_id: String,
    pub provider_id: String,
    pub purpose: RetrievalPurpose,
    pub fee_units: u64,
    pub sponsored_units: u64,
    pub fee_asset_id: String,
    pub retrieval_key_commitment: String,
    pub access_token_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed_at_height: Option<u64>,
    pub status: String,
}

impl RetrievalTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bid: &AvailabilityBid,
        offer: &EncryptedWitnessOffer,
        retrieval_key_commitment: &str,
        access_token_root: &str,
        issued_at_height: u64,
        ticket_ttl_blocks: u64,
        sponsored_units: u64,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("retrieval ticket key commitment", retrieval_key_commitment)?;
        ensure_non_empty("retrieval ticket access token root", access_token_root)?;
        if bid.offer_id != offer.offer_id || bid.shard_id != offer.shard_id {
            return Err("retrieval ticket bid and offer mismatch".to_string());
        }
        let fee_units = offer.asking_fee_units.min(bid.max_fee_units);
        let ticket_id = state_witness_retrieval_ticket_id(
            &bid.bid_id,
            &offer.offer_id,
            &bid.requester_id,
            retrieval_key_commitment,
            issued_at_height,
        );
        let ticket = Self {
            ticket_id,
            bid_id: bid.bid_id.clone(),
            offer_id: offer.offer_id.clone(),
            shard_id: offer.shard_id.clone(),
            requester_id: bid.requester_id.clone(),
            provider_id: offer.provider_id.clone(),
            purpose: bid.purpose,
            fee_units,
            sponsored_units,
            fee_asset_id: bid.fee_asset_id.clone(),
            retrieval_key_commitment: retrieval_key_commitment.to_string(),
            access_token_root: access_token_root.to_string(),
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ticket_ttl_blocks),
            redeemed_at_height: None,
            status: STATE_WITNESS_STATUS_RESERVED.to_string(),
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn redeem(&mut self, height: u64) -> StateWitnessAvailabilityMarketResult<String> {
        if height > self.expires_at_height {
            self.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            return Err("retrieval ticket expired before redemption".to_string());
        }
        self.redeemed_at_height = Some(height);
        self.status = STATE_WITNESS_STATUS_RETRIEVED.to_string();
        Ok(self.ticket_root())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && matches!(
                self.status.as_str(),
                STATE_WITNESS_STATUS_OPEN | STATE_WITNESS_STATUS_RESERVED
            )
    }

    pub fn payable_units(&self) -> u64 {
        self.fee_units.saturating_sub(self.sponsored_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "bid_id": self.bid_id,
            "offer_id": self.offer_id,
            "shard_id": self.shard_id,
            "requester_id": self.requester_id,
            "provider_id": self.provider_id,
            "purpose": self.purpose.as_str(),
            "fee_units": self.fee_units,
            "sponsored_units": self.sponsored_units,
            "payable_units": self.payable_units(),
            "fee_asset_id": self.fee_asset_id,
            "retrieval_key_commitment": self.retrieval_key_commitment,
            "access_token_root": self.access_token_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "redeemed_at_height": self.redeemed_at_height,
            "status": self.status,
        })
    }

    pub fn ticket_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-RETRIEVAL-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("retrieval ticket id", &self.ticket_id)?;
        ensure_non_empty("retrieval ticket bid id", &self.bid_id)?;
        ensure_non_empty("retrieval ticket offer id", &self.offer_id)?;
        ensure_non_empty("retrieval ticket shard id", &self.shard_id)?;
        ensure_non_empty("retrieval ticket requester id", &self.requester_id)?;
        ensure_non_empty("retrieval ticket provider id", &self.provider_id)?;
        ensure_non_empty("retrieval ticket fee asset id", &self.fee_asset_id)?;
        ensure_non_empty(
            "retrieval ticket key commitment",
            &self.retrieval_key_commitment,
        )?;
        ensure_non_empty(
            "retrieval ticket access token root",
            &self.access_token_root,
        )?;
        ensure_status(
            &self.status,
            VALID_TICKET_STATUSES,
            "retrieval ticket status",
        )?;
        if self.sponsored_units > self.fee_units {
            return Err("retrieval ticket sponsored units exceed fee units".to_string());
        }
        if self.expires_at_height < self.issued_at_height {
            return Err("retrieval ticket expiry precedes issue height".to_string());
        }
        if let Some(redeemed_at_height) = self.redeemed_at_height {
            if redeemed_at_height < self.issued_at_height {
                return Err("retrieval ticket redemption precedes issue height".to_string());
            }
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessSlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingEvidenceKind,
    pub reporter_id: String,
    pub accused_provider_id: String,
    pub shard_id: String,
    pub offer_id: String,
    pub ticket_id: Option<String>,
    pub cache_id: Option<String>,
    pub observed_root: String,
    pub expected_root: String,
    pub evidence_payload_root: String,
    pub submitted_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub status: String,
}

impl StateWitnessSlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: SlashingEvidenceKind,
        reporter_id: &str,
        accused_provider_id: &str,
        shard_id: &str,
        offer_id: &str,
        ticket_id: Option<String>,
        cache_id: Option<String>,
        observed_root: &str,
        expected_root: &str,
        evidence_payload: &Value,
        submitted_at_height: u64,
        challenge_window_blocks: u64,
        reporter_reward_bps: u64,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("slashing reporter id", reporter_id)?;
        ensure_non_empty("slashing accused provider id", accused_provider_id)?;
        ensure_non_empty("slashing shard id", shard_id)?;
        ensure_non_empty("slashing offer id", offer_id)?;
        ensure_non_empty("slashing observed root", observed_root)?;
        ensure_non_empty("slashing expected root", expected_root)?;
        let evidence_payload_root =
            state_witness_payload_root("STATE-WITNESS-SLASHING-PAYLOAD", evidence_payload);
        let evidence_id = state_witness_slashing_evidence_id(
            kind,
            reporter_id,
            accused_provider_id,
            shard_id,
            observed_root,
            expected_root,
        );
        let evidence = Self {
            evidence_id,
            kind,
            reporter_id: reporter_id.to_string(),
            accused_provider_id: accused_provider_id.to_string(),
            shard_id: shard_id.to_string(),
            offer_id: offer_id.to_string(),
            ticket_id,
            cache_id,
            observed_root: observed_root.to_string(),
            expected_root: expected_root.to_string(),
            evidence_payload_root,
            submitted_at_height,
            challenge_expires_at_height: submitted_at_height
                .saturating_add(challenge_window_blocks),
            slash_bps: kind.slash_bps(),
            reporter_reward_bps,
            status: STATE_WITNESS_STATUS_OPEN.to_string(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "reporter_id": self.reporter_id,
            "accused_provider_id": self.accused_provider_id,
            "shard_id": self.shard_id,
            "offer_id": self.offer_id,
            "ticket_id": self.ticket_id,
            "cache_id": self.cache_id,
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "evidence_payload_root": self.evidence_payload_root,
            "submitted_at_height": self.submitted_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "slash_bps": self.slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("slashing evidence id", &self.evidence_id)?;
        ensure_non_empty("slashing reporter id", &self.reporter_id)?;
        ensure_non_empty("slashing accused provider id", &self.accused_provider_id)?;
        ensure_non_empty("slashing shard id", &self.shard_id)?;
        ensure_non_empty("slashing offer id", &self.offer_id)?;
        ensure_non_empty("slashing observed root", &self.observed_root)?;
        ensure_non_empty("slashing expected root", &self.expected_root)?;
        ensure_non_empty(
            "slashing evidence payload root",
            &self.evidence_payload_root,
        )?;
        ensure_status(
            &self.status,
            VALID_EVIDENCE_STATUSES,
            "state witness slashing evidence status",
        )?;
        if self.slash_bps > STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS
            || self.reporter_reward_bps > STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS
        {
            return Err("slashing evidence bps exceeds max bps".to_string());
        }
        if self.challenge_expires_at_height < self.submitted_at_height {
            return Err("slashing challenge expiry precedes submitted height".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub lane_key: String,
    pub domain: StateWitnessDomain,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_ticket_units: u64,
    pub rebate_bps: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub eligibility_root: String,
    pub nullifier_root: String,
    pub status: String,
}

impl WitnessFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        lane_key: &str,
        domain: StateWitnessDomain,
        fee_asset_id: &str,
        budget_units: u64,
        max_fee_per_ticket_units: u64,
        rebate_bps: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        eligibility_root: &str,
        nullifier_root: &str,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("witness sponsor id", sponsor_id)?;
        ensure_non_empty("witness sponsorship lane key", lane_key)?;
        ensure_non_empty("witness sponsorship fee asset id", fee_asset_id)?;
        ensure_non_empty("witness sponsorship eligibility root", eligibility_root)?;
        ensure_non_empty("witness sponsorship nullifier root", nullifier_root)?;
        let sponsorship_id = state_witness_sponsorship_id(
            sponsor_id,
            lane_key,
            domain,
            fee_asset_id,
            eligibility_root,
            starts_at_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            lane_key: lane_key.to_string(),
            domain,
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            spent_units: 0,
            max_fee_per_ticket_units,
            rebate_bps,
            starts_at_height,
            expires_at_height,
            eligibility_root: eligibility_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            status: STATE_WITNESS_STATUS_ACTIVE.to_string(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn spendable_at(&self, height: u64) -> bool {
        self.status == STATE_WITNESS_STATUS_ACTIVE
            && height >= self.starts_at_height
            && height <= self.expires_at_height
            && self.available_units() > 0
    }

    pub fn sponsor_amount(&self, requested_units: u64) -> u64 {
        let capped = requested_units.min(self.max_fee_per_ticket_units);
        let rebated = capped
            .saturating_mul(self.rebate_bps)
            .saturating_div(STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS);
        rebated.min(self.available_units())
    }

    pub fn apply_ticket(&mut self, ticket_units: u64) -> u64 {
        let sponsored = self.sponsor_amount(ticket_units);
        self.spent_units = self.spent_units.saturating_add(sponsored);
        if self.available_units() == 0 {
            self.status = STATE_WITNESS_STATUS_EXHAUSTED.to_string();
        } else if sponsored > 0 {
            self.status = STATE_WITNESS_STATUS_SPONSORED.to_string();
        }
        sponsored
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "lane_key": self.lane_key,
            "domain": self.domain.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_per_ticket_units": self.max_fee_per_ticket_units,
            "rebate_bps": self.rebate_bps,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "eligibility_root": self.eligibility_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("witness sponsorship id", &self.sponsorship_id)?;
        ensure_non_empty("witness sponsorship sponsor id", &self.sponsor_id)?;
        ensure_non_empty("witness sponsorship lane key", &self.lane_key)?;
        ensure_non_empty("witness sponsorship fee asset id", &self.fee_asset_id)?;
        ensure_non_empty(
            "witness sponsorship eligibility root",
            &self.eligibility_root,
        )?;
        ensure_non_empty("witness sponsorship nullifier root", &self.nullifier_root)?;
        ensure_status(
            &self.status,
            VALID_SPONSORSHIP_STATUSES,
            "witness fee sponsorship status",
        )?;
        if self.spent_units > self.budget_units {
            return Err("witness sponsorship spent units exceed budget".to_string());
        }
        if self.max_fee_per_ticket_units == 0 {
            return Err("witness sponsorship max fee per ticket must be non-zero".to_string());
        }
        if self.rebate_bps > STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS {
            return Err("witness sponsorship rebate bps exceeds max bps".to_string());
        }
        if self.expires_at_height < self.starts_at_height {
            return Err("witness sponsorship expiry precedes start".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub published_at_height: u64,
    pub subject_root: String,
    pub summary_root: String,
    pub status: String,
}

impl StateWitnessPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        published_at_height: u64,
        subject_root: &str,
        summary: &str,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        ensure_non_empty("state witness public record kind", record_kind)?;
        ensure_non_empty("state witness public record subject id", subject_id)?;
        ensure_non_empty("state witness public record subject root", subject_root)?;
        ensure_non_empty("state witness public record summary", summary)?;
        let summary_root = state_witness_string_root("STATE-WITNESS-PUBLIC-SUMMARY", summary);
        let record_id = state_witness_public_record_id(
            record_kind,
            subject_id,
            subject_root,
            &summary_root,
            published_at_height,
        );
        let record = Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            published_at_height,
            subject_root: subject_root.to_string(),
            summary_root,
            status: STATE_WITNESS_STATUS_ACTIVE.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "published_at_height": self.published_at_height,
            "subject_root": self.subject_root,
            "summary_root": self.summary_root,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_non_empty("state witness public record id", &self.record_id)?;
        ensure_non_empty("state witness public record kind", &self.record_kind)?;
        ensure_non_empty("state witness public record subject id", &self.subject_id)?;
        ensure_non_empty(
            "state witness public record subject root",
            &self.subject_root,
        )?;
        ensure_non_empty(
            "state witness public record summary root",
            &self.summary_root,
        )?;
        ensure_status(
            &self.status,
            VALID_PUBLIC_RECORD_STATUSES,
            "state witness public record status",
        )?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessAvailabilityMarketRoots {
    pub config_root: String,
    pub tier_policy_root: String,
    pub witness_shard_root: String,
    pub encrypted_offer_root: String,
    pub availability_bid_root: String,
    pub prover_cache_root: String,
    pub da_sampling_receipt_root: String,
    pub retrieval_ticket_root: String,
    pub slashing_evidence_root: String,
    pub fee_sponsorship_root: String,
    pub public_record_root: String,
    pub live_hot_witness_root: String,
    pub lane_index_root: String,
}

impl StateWitnessAvailabilityMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "tier_policy_root": self.tier_policy_root,
            "witness_shard_root": self.witness_shard_root,
            "encrypted_offer_root": self.encrypted_offer_root,
            "availability_bid_root": self.availability_bid_root,
            "prover_cache_root": self.prover_cache_root,
            "da_sampling_receipt_root": self.da_sampling_receipt_root,
            "retrieval_ticket_root": self.retrieval_ticket_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "public_record_root": self.public_record_root,
            "live_hot_witness_root": self.live_hot_witness_root,
            "lane_index_root": self.lane_index_root,
        })
    }

    pub fn roots_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessAvailabilityMarketCounters {
    pub tier_policy_count: u64,
    pub witness_shard_count: u64,
    pub encrypted_offer_count: u64,
    pub availability_bid_count: u64,
    pub prover_cache_count: u64,
    pub da_sampling_receipt_count: u64,
    pub retrieval_ticket_count: u64,
    pub slashing_evidence_count: u64,
    pub fee_sponsorship_count: u64,
    pub public_record_count: u64,
    pub live_shard_count: u64,
    pub live_hot_shard_count: u64,
    pub live_offer_count: u64,
    pub live_bid_count: u64,
    pub live_ticket_count: u64,
    pub active_sponsorship_count: u64,
    pub total_witness_bytes: u64,
    pub total_encrypted_offer_fees: u64,
    pub total_ticket_fees: u64,
    pub total_sponsored_units: u64,
    pub total_cache_bytes: u64,
    pub average_cache_hit_bps: u64,
    pub sampled_receipt_count: u64,
    pub missing_receipt_count: u64,
    pub open_slashing_evidence_count: u64,
}

impl StateWitnessAvailabilityMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "tier_policy_count": self.tier_policy_count,
            "witness_shard_count": self.witness_shard_count,
            "encrypted_offer_count": self.encrypted_offer_count,
            "availability_bid_count": self.availability_bid_count,
            "prover_cache_count": self.prover_cache_count,
            "da_sampling_receipt_count": self.da_sampling_receipt_count,
            "retrieval_ticket_count": self.retrieval_ticket_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "fee_sponsorship_count": self.fee_sponsorship_count,
            "public_record_count": self.public_record_count,
            "live_shard_count": self.live_shard_count,
            "live_hot_shard_count": self.live_hot_shard_count,
            "live_offer_count": self.live_offer_count,
            "live_bid_count": self.live_bid_count,
            "live_ticket_count": self.live_ticket_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "total_witness_bytes": self.total_witness_bytes,
            "total_encrypted_offer_fees": self.total_encrypted_offer_fees,
            "total_ticket_fees": self.total_ticket_fees,
            "total_sponsored_units": self.total_sponsored_units,
            "total_cache_bytes": self.total_cache_bytes,
            "average_cache_hit_bps": self.average_cache_hit_bps,
            "sampled_receipt_count": self.sampled_receipt_count,
            "missing_receipt_count": self.missing_receipt_count,
            "open_slashing_evidence_count": self.open_slashing_evidence_count,
        })
    }

    pub fn counters_root(&self) -> String {
        state_witness_payload_root("STATE-WITNESS-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWitnessAvailabilityMarketState {
    pub height: u64,
    pub status: String,
    pub config: StateWitnessAvailabilityMarketConfig,
    pub tier_policies: BTreeMap<String, WitnessTierPolicy>,
    pub witness_shards: BTreeMap<String, WitnessShard>,
    pub encrypted_offers: BTreeMap<String, EncryptedWitnessOffer>,
    pub availability_bids: BTreeMap<String, AvailabilityBid>,
    pub prover_caches: BTreeMap<String, ProverCacheCommitment>,
    pub da_sampling_receipts: BTreeMap<String, WitnessDaSamplingReceipt>,
    pub retrieval_tickets: BTreeMap<String, RetrievalTicket>,
    pub slashing_evidence: BTreeMap<String, StateWitnessSlashingEvidence>,
    pub fee_sponsorships: BTreeMap<String, WitnessFeeSponsorship>,
    pub public_records: BTreeMap<String, StateWitnessPublicRecord>,
}

impl Default for StateWitnessAvailabilityMarketState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateWitnessAvailabilityMarketState {
    pub fn new() -> Self {
        Self {
            height: 0,
            status: STATE_WITNESS_STATUS_ACTIVE.to_string(),
            config: StateWitnessAvailabilityMarketConfig::default(),
            tier_policies: BTreeMap::new(),
            witness_shards: BTreeMap::new(),
            encrypted_offers: BTreeMap::new(),
            availability_bids: BTreeMap::new(),
            prover_caches: BTreeMap::new(),
            da_sampling_receipts: BTreeMap::new(),
            retrieval_tickets: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: StateWitnessAvailabilityMarketConfig,
    ) -> StateWitnessAvailabilityMarketResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> StateWitnessAvailabilityMarketResult<Self> {
        let mut state = Self::with_config(StateWitnessAvailabilityMarketConfig::devnet())?;
        state.set_height(128)?;

        let private_lane = StateWitnessDomain::PrivateTransfer
            .default_lane_key()
            .to_string();
        let bridge_lane = StateWitnessDomain::MoneroBridge
            .default_lane_key()
            .to_string();
        let defi_lane = StateWitnessDomain::DefiSwap.default_lane_key().to_string();
        let contract_lane = StateWitnessDomain::ContractCall
            .default_lane_key()
            .to_string();
        let recursive_lane = StateWitnessDomain::RecursiveProof
            .default_lane_key()
            .to_string();

        let hot_tier = WitnessTierPolicy::devnet(
            WitnessTierKind::Hot,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_HOT_PROVIDER_ID,
            &[
                private_lane.clone(),
                bridge_lane.clone(),
                defi_lane.clone(),
                contract_lane.clone(),
            ],
        );
        let cold_tier = WitnessTierPolicy::devnet(
            WitnessTierKind::Cold,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_COLD_PROVIDER_ID,
            &[
                private_lane.clone(),
                bridge_lane.clone(),
                defi_lane.clone(),
                recursive_lane.clone(),
            ],
        );
        let hot_tier_id = hot_tier.tier_id.clone();
        let cold_tier_id = cold_tier.tier_id.clone();
        state.register_tier_policy(hot_tier)?;
        state.register_tier_policy(cold_tier)?;

        let private_sponsorship = WitnessFeeSponsorship::new(
            "devnet-private-witness-sponsor",
            &private_lane,
            StateWitnessDomain::PrivateTransfer,
            &state.config.default_fee_asset_id,
            1_000_000,
            20,
            state.config.sponsor_rebate_bps,
            0,
            state.config.cold_retention_blocks,
            &devnet_hash("STATE-WITNESS-DEVNET-SPONSOR-ELIGIBILITY", "private"),
            &devnet_hash("STATE-WITNESS-DEVNET-SPONSOR-NULLIFIER", "private"),
        )?;
        let bridge_sponsorship = WitnessFeeSponsorship::new(
            "devnet-bridge-witness-sponsor",
            &bridge_lane,
            StateWitnessDomain::MoneroBridge,
            &state.config.default_fee_asset_id,
            2_000_000,
            36,
            state.config.sponsor_rebate_bps,
            0,
            state.config.cold_retention_blocks,
            &devnet_hash("STATE-WITNESS-DEVNET-SPONSOR-ELIGIBILITY", "bridge"),
            &devnet_hash("STATE-WITNESS-DEVNET-SPONSOR-NULLIFIER", "bridge"),
        )?;
        let private_sponsorship_id = private_sponsorship.sponsorship_id.clone();
        state.open_fee_sponsorship(private_sponsorship)?;
        state.open_fee_sponsorship(bridge_sponsorship)?;

        let private_shards = devnet_witness_shards(
            "devnet-private-transfer-batch-128",
            &private_lane,
            StateWitnessDomain::PrivateTransfer,
            WitnessShardKind::AccountDelta,
            WitnessTierKind::Hot,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_HOT_PROVIDER_ID,
            state.height,
            state.config.hot_retention_blocks,
            4,
        )?;
        let bridge_shards = devnet_witness_shards(
            "devnet-monero-bridge-batch-128",
            &bridge_lane,
            StateWitnessDomain::MoneroBridge,
            WitnessShardKind::BridgeQueue,
            WitnessTierKind::Hot,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_HOT_PROVIDER_ID,
            state.height,
            state.config.hot_retention_blocks,
            3,
        )?;
        let defi_shards = devnet_witness_shards(
            "devnet-defi-swap-batch-128",
            &defi_lane,
            StateWitnessDomain::DefiSwap,
            WitnessShardKind::LiquidityPosition,
            WitnessTierKind::Cold,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_COLD_PROVIDER_ID,
            state.height.saturating_sub(1),
            state.config.cold_retention_blocks,
            3,
        )?;

        for shard in private_shards
            .iter()
            .chain(bridge_shards.iter())
            .chain(defi_shards.iter())
            .cloned()
        {
            state.publish_witness_shard(shard)?;
        }

        let private_offer_id = {
            let shard = private_shards
                .first()
                .ok_or_else(|| "devnet private shard missing".to_string())?;
            let offer = EncryptedWitnessOffer::new(
                shard,
                &hot_tier_id,
                &devnet_hash("STATE-WITNESS-DEVNET-KEM", "private-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-PAYLOAD", "private-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-ACCESS", "private-0"),
                9,
                &state.config.default_fee_asset_id,
                state.height,
                state.config.offer_ttl_blocks,
                WitnessPrivacyMode::FullyShielded,
                true,
            )?;
            state.publish_encrypted_offer(offer)?
        };
        let bridge_offer_id = {
            let shard = bridge_shards
                .first()
                .ok_or_else(|| "devnet bridge shard missing".to_string())?;
            let offer = EncryptedWitnessOffer::new(
                shard,
                &hot_tier_id,
                &devnet_hash("STATE-WITNESS-DEVNET-KEM", "bridge-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-PAYLOAD", "bridge-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-ACCESS", "bridge-0"),
                16,
                &state.config.default_fee_asset_id,
                state.height,
                state.config.offer_ttl_blocks,
                WitnessPrivacyMode::AggregateOnly,
                true,
            )?;
            state.publish_encrypted_offer(offer)?
        };
        let defi_offer_id = {
            let shard = defi_shards
                .first()
                .ok_or_else(|| "devnet defi shard missing".to_string())?;
            let offer = EncryptedWitnessOffer::new(
                shard,
                &cold_tier_id,
                &devnet_hash("STATE-WITNESS-DEVNET-KEM", "defi-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-PAYLOAD", "defi-0"),
                &devnet_hash("STATE-WITNESS-DEVNET-ACCESS", "defi-0"),
                6,
                &state.config.default_fee_asset_id,
                state.height,
                state.config.offer_ttl_blocks,
                WitnessPrivacyMode::FullyShielded,
                false,
            )?;
            state.publish_encrypted_offer(offer)?
        };

        let private_bid_id = state.submit_availability_bid(
            &private_offer_id,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_PROVER_ID,
            RetrievalPurpose::Proving,
            12,
            WitnessTierKind::Hot,
            120,
            Some(private_sponsorship_id),
            100,
        )?;
        let bridge_bid_id = state.submit_availability_bid(
            &bridge_offer_id,
            "devnet-bridge-recursive-prover",
            RetrievalPurpose::Proving,
            20,
            WitnessTierKind::Hot,
            160,
            None,
            98,
        )?;
        state.submit_availability_bid(
            &defi_offer_id,
            "devnet-defi-watchtower",
            RetrievalPurpose::Watchtower,
            8,
            WitnessTierKind::Cold,
            5_000,
            None,
            80,
        )?;

        let private_ticket_id = state.issue_retrieval_ticket(
            &private_bid_id,
            &devnet_hash("STATE-WITNESS-DEVNET-RETRIEVAL-KEY", "private"),
            &devnet_hash("STATE-WITNESS-DEVNET-ACCESS-TOKEN", "private"),
        )?;
        let bridge_ticket_id = state.issue_retrieval_ticket(
            &bridge_bid_id,
            &devnet_hash("STATE-WITNESS-DEVNET-RETRIEVAL-KEY", "bridge"),
            &devnet_hash("STATE-WITNESS-DEVNET-ACCESS-TOKEN", "bridge"),
        )?;
        state.redeem_retrieval_ticket(&private_ticket_id, state.height.saturating_add(1))?;

        let private_offer = state
            .encrypted_offers
            .get(&private_offer_id)
            .cloned()
            .ok_or_else(|| "devnet private offer missing".to_string())?;
        state.record_da_sampling_receipt(WitnessDaSamplingReceipt::new(
            &private_offer,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_WATCHTOWER_ID,
            state.height,
            state.height.saturating_add(1),
            &private_offer.access_policy_root,
            &devnet_hash("STATE-WITNESS-DEVNET-SAMPLING-PROOF", "private"),
            true,
            87,
        )?)?;

        let bridge_offer = state
            .encrypted_offers
            .get(&bridge_offer_id)
            .cloned()
            .ok_or_else(|| "devnet bridge offer missing".to_string())?;
        let bridge_receipt = WitnessDaSamplingReceipt::new(
            &bridge_offer,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_WATCHTOWER_ID,
            state.height,
            state.height.saturating_add(2),
            &bridge_offer.access_policy_root,
            &devnet_hash("STATE-WITNESS-DEVNET-SAMPLING-PROOF", "bridge"),
            false,
            240,
        )?;
        state.record_da_sampling_receipt(bridge_receipt)?;

        state.commit_prover_cache(ProverCacheCommitment::new(
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_PROVER_ID,
            &private_shards,
            WitnessTierKind::Hot,
            &devnet_hash("STATE-WITNESS-DEVNET-CACHE-MANIFEST", "private"),
            &devnet_hash("STATE-WITNESS-DEVNET-PREFETCH", "private"),
            9_800,
            state.height,
            state.config.cache_ttl_blocks,
        )?)?;

        let evidence = StateWitnessSlashingEvidence::new(
            SlashingEvidenceKind::WithheldWitness,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_WATCHTOWER_ID,
            STATE_WITNESS_AVAILABILITY_MARKET_DEVNET_HOT_PROVIDER_ID,
            &bridge_offer.shard_id,
            &bridge_offer.offer_id,
            Some(bridge_ticket_id),
            None,
            &devnet_hash("STATE-WITNESS-DEVNET-OBSERVED", "bridge-missing"),
            &bridge_offer.encrypted_payload_root,
            &json!({
                "ticket": "bridge ticket not fulfilled inside low-latency window",
                "latency_ms": 240,
                "target_ms": WitnessTierKind::Hot.latency_target_ms(),
            }),
            state.height.saturating_add(2),
            state.config.challenge_window_blocks,
            state.config.reporter_reward_bps,
        )?;
        let evidence_id = evidence.evidence_id.clone();
        state.submit_slashing_evidence(evidence)?;
        state.settle_slashing_evidence(&evidence_id)?;

        let snapshot_root = state.state_root();
        state.publish_public_record(StateWitnessPublicRecord::new(
            "market_snapshot",
            "devnet-state-witness-availability-market",
            state.height,
            &snapshot_root,
            "low-latency encrypted state witness market with hot cache, DA sampling, sponsorship, and slashing",
        )?)?;
        state.publish_public_record(StateWitnessPublicRecord::new(
            "retrieval_ticket",
            &private_ticket_id,
            state.height,
            &state.retrieval_ticket_root(),
            "private transfer witness ticket retrieved under sponsored low-fee policy",
        )?)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> StateWitnessAvailabilityMarketResult<String> {
        self.height = height;
        for shard in self.witness_shards.values_mut() {
            if height > shard.expires_at_height && shard.is_live_at(shard.expires_at_height) {
                shard.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        for offer in self.encrypted_offers.values_mut() {
            if height > offer.expires_at_height && offer.is_live_at(offer.expires_at_height) {
                offer.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        for bid in self.availability_bids.values_mut() {
            if height > bid.expires_at_height && bid.is_live_at(bid.expires_at_height) {
                bid.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        for cache in self.prover_caches.values_mut() {
            if height > cache.expires_at_height && cache.is_live_at(cache.expires_at_height) {
                cache.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        for ticket in self.retrieval_tickets.values_mut() {
            if height > ticket.expires_at_height && ticket.is_live_at(ticket.expires_at_height) {
                ticket.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.fee_sponsorships.values_mut() {
            if height > sponsorship.expires_at_height
                && matches!(
                    sponsorship.status.as_str(),
                    STATE_WITNESS_STATUS_ACTIVE | STATE_WITNESS_STATUS_SPONSORED
                )
            {
                sponsorship.status = STATE_WITNESS_STATUS_EXPIRED.to_string();
            }
        }
        Ok(self.state_root())
    }

    pub fn set_status(&mut self, status: &str) -> StateWitnessAvailabilityMarketResult<String> {
        ensure_status(status, VALID_MARKET_STATUSES, "state witness market status")?;
        self.status = status.to_string();
        Ok(self.state_root())
    }

    pub fn register_tier_policy(
        &mut self,
        policy: WitnessTierPolicy,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = policy.validate()?;
        insert_unique_record(
            &mut self.tier_policies,
            policy.tier_id.clone(),
            policy,
            "witness tier policy",
        )?;
        Ok(root)
    }

    pub fn publish_witness_shard(
        &mut self,
        shard: WitnessShard,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = shard.validate()?;
        if shard.byte_len > self.config.max_shard_bytes {
            return Err("witness shard exceeds configured max shard bytes".to_string());
        }
        let tier = self
            .tier_policies
            .values()
            .find(|tier| tier.provider_id == shard.provider_id && tier.tier == shard.tier)
            .ok_or_else(|| "witness shard references unknown provider tier".to_string())?;
        if !tier.can_serve_lane(&shard.lane_key) {
            return Err("witness shard provider tier cannot serve lane".to_string());
        }
        if shard
            .expires_at_height
            .saturating_sub(shard.posted_at_height)
            > tier.retention_blocks
        {
            return Err("witness shard retention exceeds tier retention".to_string());
        }
        insert_unique_record(
            &mut self.witness_shards,
            shard.shard_id.clone(),
            shard,
            "witness shard",
        )?;
        Ok(root)
    }

    pub fn publish_encrypted_offer(
        &mut self,
        mut offer: EncryptedWitnessOffer,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let shard = self
            .witness_shards
            .get_mut(&offer.shard_id)
            .ok_or_else(|| "encrypted witness offer references unknown shard".to_string())?;
        if shard.provider_id != offer.provider_id || shard.lane_key != offer.lane_key {
            return Err("encrypted witness offer shard/provider lane mismatch".to_string());
        }
        let tier = self
            .tier_policies
            .get(&offer.tier_id)
            .ok_or_else(|| "encrypted witness offer references unknown tier".to_string())?;
        if !tier.can_serve_lane(&offer.lane_key) {
            return Err("encrypted witness offer tier cannot serve lane".to_string());
        }
        if offer.asking_fee_units < self.config.low_fee_floor_units {
            offer.asking_fee_units = self.config.low_fee_floor_units;
        }
        let root = offer.validate()?;
        shard.status = STATE_WITNESS_STATUS_RETRIEVABLE.to_string();
        insert_unique_record(
            &mut self.encrypted_offers,
            offer.offer_id.clone(),
            offer,
            "encrypted witness offer",
        )?;
        Ok(root)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_availability_bid(
        &mut self,
        offer_id: &str,
        requester_id: &str,
        purpose: RetrievalPurpose,
        max_fee_units: u64,
        desired_tier: WitnessTierKind,
        max_latency_ms: u64,
        sponsor_id: Option<String>,
        priority: u64,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let offer = self
            .encrypted_offers
            .get(offer_id)
            .ok_or_else(|| "availability bid references unknown offer".to_string())?
            .clone();
        if !offer.is_live_at(self.height) {
            return Err("availability bid references inactive offer".to_string());
        }
        if max_fee_units < offer.asking_fee_units {
            return Err("availability bid max fee below offer ask".to_string());
        }
        if let Some(sponsor_id) = &sponsor_id {
            let sponsorship = self
                .fee_sponsorships
                .get(sponsor_id)
                .ok_or_else(|| "availability bid references unknown sponsorship".to_string())?;
            if sponsorship.lane_key != offer.lane_key || !sponsorship.spendable_at(self.height) {
                return Err("availability bid sponsorship is not spendable for lane".to_string());
            }
        }
        let bid = AvailabilityBid::new(
            &offer,
            requester_id,
            purpose,
            max_fee_units,
            desired_tier,
            max_latency_ms,
            self.height,
            self.config.bid_ttl_blocks,
            sponsor_id,
            priority,
        )?;
        let bid_id = bid.bid_id.clone();
        insert_unique_record(
            &mut self.availability_bids,
            bid_id.clone(),
            bid,
            "availability bid",
        )?;
        Ok(bid_id)
    }

    pub fn issue_retrieval_ticket(
        &mut self,
        bid_id: &str,
        retrieval_key_commitment: &str,
        access_token_root: &str,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let bid = self
            .availability_bids
            .get(bid_id)
            .ok_or_else(|| "retrieval ticket references unknown bid".to_string())?
            .clone();
        let offer = self
            .encrypted_offers
            .get(&bid.offer_id)
            .ok_or_else(|| "retrieval ticket references unknown offer".to_string())?
            .clone();
        if !bid.is_live_at(self.height) || !offer.is_live_at(self.height) {
            return Err("retrieval ticket requires live bid and offer".to_string());
        }
        let mut sponsored_units = 0_u64;
        if let Some(sponsor_id) = &bid.sponsor_id {
            let sponsorship = self
                .fee_sponsorships
                .get_mut(sponsor_id)
                .ok_or_else(|| "retrieval ticket references unknown sponsorship".to_string())?;
            if sponsorship.spendable_at(self.height) {
                sponsored_units = sponsorship.apply_ticket(offer.asking_fee_units);
            }
        }
        let ticket = RetrievalTicket::new(
            &bid,
            &offer,
            retrieval_key_commitment,
            access_token_root,
            self.height,
            self.config.ticket_ttl_blocks,
            sponsored_units,
        )?;
        let ticket_id = ticket.ticket_id.clone();
        if let Some(bid) = self.availability_bids.get_mut(bid_id) {
            bid.status = STATE_WITNESS_STATUS_RESERVED.to_string();
        }
        if let Some(offer) = self.encrypted_offers.get_mut(&bid.offer_id) {
            offer.status = STATE_WITNESS_STATUS_RESERVED.to_string();
        }
        insert_unique_record(
            &mut self.retrieval_tickets,
            ticket_id.clone(),
            ticket,
            "retrieval ticket",
        )?;
        Ok(ticket_id)
    }

    pub fn redeem_retrieval_ticket(
        &mut self,
        ticket_id: &str,
        height: u64,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let ticket = self
            .retrieval_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown retrieval ticket".to_string())?;
        ticket.redeem(height)?;
        if let Some(bid) = self.availability_bids.get_mut(&ticket.bid_id) {
            bid.status = STATE_WITNESS_STATUS_RETRIEVED.to_string();
        }
        if let Some(offer) = self.encrypted_offers.get_mut(&ticket.offer_id) {
            offer.status = STATE_WITNESS_STATUS_RETRIEVABLE.to_string();
        }
        Ok(ticket.ticket_root())
    }

    pub fn commit_prover_cache(
        &mut self,
        cache: ProverCacheCommitment,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = cache.validate()?;
        for shard_id in &cache.shard_ids {
            if !self.witness_shards.contains_key(shard_id) {
                return Err("prover cache references unknown shard".to_string());
            }
        }
        insert_unique_record(
            &mut self.prover_caches,
            cache.cache_id.clone(),
            cache,
            "prover cache commitment",
        )?;
        Ok(root)
    }

    pub fn record_da_sampling_receipt(
        &mut self,
        receipt: WitnessDaSamplingReceipt,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = receipt.validate()?;
        if !self.witness_shards.contains_key(&receipt.shard_id) {
            return Err("witness DA sampling receipt references unknown shard".to_string());
        }
        if !self.encrypted_offers.contains_key(&receipt.offer_id) {
            return Err("witness DA sampling receipt references unknown offer".to_string());
        }
        insert_unique_record(
            &mut self.da_sampling_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "witness DA sampling receipt",
        )?;
        Ok(root)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        evidence: StateWitnessSlashingEvidence,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = evidence.validate()?;
        if !self.witness_shards.contains_key(&evidence.shard_id) {
            return Err("slashing evidence references unknown shard".to_string());
        }
        if !self.encrypted_offers.contains_key(&evidence.offer_id) {
            return Err("slashing evidence references unknown offer".to_string());
        }
        if let Some(ticket_id) = &evidence.ticket_id {
            if !self.retrieval_tickets.contains_key(ticket_id) {
                return Err("slashing evidence references unknown ticket".to_string());
            }
        }
        if let Some(cache_id) = &evidence.cache_id {
            if !self.prover_caches.contains_key(cache_id) {
                return Err("slashing evidence references unknown cache".to_string());
            }
        }
        insert_unique_record(
            &mut self.slashing_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "state witness slashing evidence",
        )?;
        Ok(root)
    }

    pub fn settle_slashing_evidence(
        &mut self,
        evidence_id: &str,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| "unknown state witness slashing evidence".to_string())?;
        evidence.status = STATE_WITNESS_STATUS_SETTLED.to_string();
        if let Some(shard) = self.witness_shards.get_mut(&evidence.shard_id) {
            shard.status = STATE_WITNESS_STATUS_SLASHED.to_string();
        }
        if let Some(cache_id) = &evidence.cache_id {
            if let Some(cache) = self.prover_caches.get_mut(cache_id) {
                cache.status = STATE_WITNESS_STATUS_SLASHED.to_string();
            }
        }
        Ok(evidence.evidence_root())
    }

    pub fn open_fee_sponsorship(
        &mut self,
        sponsorship: WitnessFeeSponsorship,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = sponsorship.validate()?;
        insert_unique_record(
            &mut self.fee_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "witness fee sponsorship",
        )?;
        Ok(root)
    }

    pub fn publish_public_record(
        &mut self,
        record: StateWitnessPublicRecord,
    ) -> StateWitnessAvailabilityMarketResult<String> {
        let root = record.validate()?;
        insert_unique_record(
            &mut self.public_records,
            record.record_id.clone(),
            record,
            "state witness public record",
        )?;
        Ok(root)
    }

    pub fn tier_policy_root(&self) -> String {
        witness_tier_policy_set_root(&self.tier_policies.values().cloned().collect::<Vec<_>>())
    }

    pub fn witness_shard_root(&self) -> String {
        witness_shard_set_root(&self.witness_shards.values().cloned().collect::<Vec<_>>())
    }

    pub fn encrypted_offer_root(&self) -> String {
        encrypted_witness_offer_set_root(
            &self.encrypted_offers.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn availability_bid_root(&self) -> String {
        availability_bid_set_root(&self.availability_bids.values().cloned().collect::<Vec<_>>())
    }

    pub fn prover_cache_root(&self) -> String {
        prover_cache_commitment_set_root(&self.prover_caches.values().cloned().collect::<Vec<_>>())
    }

    pub fn da_sampling_receipt_root(&self) -> String {
        witness_da_sampling_receipt_set_root(
            &self
                .da_sampling_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn retrieval_ticket_root(&self) -> String {
        retrieval_ticket_set_root(&self.retrieval_tickets.values().cloned().collect::<Vec<_>>())
    }

    pub fn slashing_evidence_root(&self) -> String {
        state_witness_slashing_evidence_set_root(
            &self.slashing_evidence.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn fee_sponsorship_root(&self) -> String {
        witness_fee_sponsorship_set_root(
            &self.fee_sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        state_witness_public_record_set_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn live_hot_witness_root(&self) -> String {
        let leaves = self
            .witness_shards
            .values()
            .filter(|shard| shard.tier == WitnessTierKind::Hot && shard.is_live_at(self.height))
            .map(|shard| Value::String(shard.shard_id.clone()))
            .collect::<Vec<_>>();
        merkle_root("STATE-WITNESS-LIVE-HOT-WITNESS", &leaves)
    }

    pub fn lane_index_root(&self) -> String {
        let mut lane_records = BTreeMap::<String, Vec<String>>::new();
        for shard in self.witness_shards.values() {
            lane_records
                .entry(shard.lane_key.clone())
                .or_default()
                .push(shard.shard_id.clone());
        }
        let leaves = lane_records
            .into_iter()
            .map(|(lane_key, shard_ids)| {
                json!({
                    "lane_key": lane_key,
                    "shard_ids": shard_ids,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("STATE-WITNESS-LANE-INDEX", &leaves)
    }

    pub fn roots(&self) -> StateWitnessAvailabilityMarketRoots {
        StateWitnessAvailabilityMarketRoots {
            config_root: self.config.config_root(),
            tier_policy_root: self.tier_policy_root(),
            witness_shard_root: self.witness_shard_root(),
            encrypted_offer_root: self.encrypted_offer_root(),
            availability_bid_root: self.availability_bid_root(),
            prover_cache_root: self.prover_cache_root(),
            da_sampling_receipt_root: self.da_sampling_receipt_root(),
            retrieval_ticket_root: self.retrieval_ticket_root(),
            slashing_evidence_root: self.slashing_evidence_root(),
            fee_sponsorship_root: self.fee_sponsorship_root(),
            public_record_root: self.public_record_root(),
            live_hot_witness_root: self.live_hot_witness_root(),
            lane_index_root: self.lane_index_root(),
        }
    }

    pub fn counters(&self) -> StateWitnessAvailabilityMarketCounters {
        let mut counters = StateWitnessAvailabilityMarketCounters {
            tier_policy_count: self.tier_policies.len() as u64,
            witness_shard_count: self.witness_shards.len() as u64,
            encrypted_offer_count: self.encrypted_offers.len() as u64,
            availability_bid_count: self.availability_bids.len() as u64,
            prover_cache_count: self.prover_caches.len() as u64,
            da_sampling_receipt_count: self.da_sampling_receipts.len() as u64,
            retrieval_ticket_count: self.retrieval_tickets.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            fee_sponsorship_count: self.fee_sponsorships.len() as u64,
            public_record_count: self.public_records.len() as u64,
            ..StateWitnessAvailabilityMarketCounters::default()
        };
        let mut cache_hit_total = 0_u64;
        for shard in self.witness_shards.values() {
            if shard.is_live_at(self.height) {
                counters.live_shard_count = counters.live_shard_count.saturating_add(1);
                if shard.tier == WitnessTierKind::Hot {
                    counters.live_hot_shard_count = counters.live_hot_shard_count.saturating_add(1);
                }
            }
            counters.total_witness_bytes =
                counters.total_witness_bytes.saturating_add(shard.byte_len);
        }
        for offer in self.encrypted_offers.values() {
            if offer.is_live_at(self.height) {
                counters.live_offer_count = counters.live_offer_count.saturating_add(1);
            }
            counters.total_encrypted_offer_fees = counters
                .total_encrypted_offer_fees
                .saturating_add(offer.asking_fee_units);
        }
        for bid in self.availability_bids.values() {
            if bid.is_live_at(self.height) {
                counters.live_bid_count = counters.live_bid_count.saturating_add(1);
            }
        }
        for cache in self.prover_caches.values() {
            counters.total_cache_bytes = counters.total_cache_bytes.saturating_add(cache.byte_len);
            cache_hit_total = cache_hit_total.saturating_add(cache.cache_hit_bps);
        }
        if !self.prover_caches.is_empty() {
            counters.average_cache_hit_bps =
                cache_hit_total.saturating_div(self.prover_caches.len() as u64);
        }
        for receipt in self.da_sampling_receipts.values() {
            if receipt.returned {
                counters.sampled_receipt_count = counters.sampled_receipt_count.saturating_add(1);
            } else {
                counters.missing_receipt_count = counters.missing_receipt_count.saturating_add(1);
            }
        }
        for ticket in self.retrieval_tickets.values() {
            if ticket.is_live_at(self.height) {
                counters.live_ticket_count = counters.live_ticket_count.saturating_add(1);
            }
            counters.total_ticket_fees =
                counters.total_ticket_fees.saturating_add(ticket.fee_units);
            counters.total_sponsored_units = counters
                .total_sponsored_units
                .saturating_add(ticket.sponsored_units);
        }
        for evidence in self.slashing_evidence.values() {
            if evidence.status == STATE_WITNESS_STATUS_OPEN {
                counters.open_slashing_evidence_count =
                    counters.open_slashing_evidence_count.saturating_add(1);
            }
        }
        for sponsorship in self.fee_sponsorships.values() {
            if sponsorship.spendable_at(self.height) {
                counters.active_sponsorship_count =
                    counters.active_sponsorship_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "state_witness_availability_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_WITNESS_AVAILABILITY_MARKET_PROTOCOL_VERSION,
            "schema_version": STATE_WITNESS_AVAILABILITY_MARKET_SCHEMA_VERSION,
            "hash_suite": STATE_WITNESS_AVAILABILITY_MARKET_HASH_SUITE,
            "pq_signature_scheme": STATE_WITNESS_AVAILABILITY_MARKET_PQ_SIGNATURE_SCHEME,
            "pq_backup_scheme": STATE_WITNESS_AVAILABILITY_MARKET_PQ_BACKUP_SCHEME,
            "pq_kem_scheme": STATE_WITNESS_AVAILABILITY_MARKET_PQ_KEM_SCHEME,
            "commitment_scheme": STATE_WITNESS_AVAILABILITY_MARKET_COMMITMENT_SCHEME,
            "cache_scheme": STATE_WITNESS_AVAILABILITY_MARKET_CACHE_SCHEME,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_witness_availability_market_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "state_witness_availability_market_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn validate(&self) -> StateWitnessAvailabilityMarketResult<String> {
        self.config.validate()?;
        ensure_status(
            &self.status,
            VALID_MARKET_STATUSES,
            "state witness market status",
        )?;
        for (tier_id, tier) in &self.tier_policies {
            if tier_id != &tier.tier_id {
                return Err("witness tier policy map key mismatch".to_string());
            }
            tier.validate()?;
        }
        for (shard_id, shard) in &self.witness_shards {
            if shard_id != &shard.shard_id {
                return Err("witness shard map key mismatch".to_string());
            }
            shard.validate()?;
            if shard.byte_len > self.config.max_shard_bytes {
                return Err("witness shard exceeds configured max shard bytes".to_string());
            }
            if !self
                .tier_policies
                .values()
                .any(|tier| tier.provider_id == shard.provider_id && tier.tier == shard.tier)
            {
                return Err("witness shard references unknown tier provider".to_string());
            }
        }
        for (offer_id, offer) in &self.encrypted_offers {
            if offer_id != &offer.offer_id {
                return Err("encrypted witness offer map key mismatch".to_string());
            }
            offer.validate()?;
            let shard = self
                .witness_shards
                .get(&offer.shard_id)
                .ok_or_else(|| "encrypted offer references unknown shard".to_string())?;
            if shard.provider_id != offer.provider_id
                || shard.lane_key != offer.lane_key
                || shard.domain != offer.domain
            {
                return Err("encrypted offer shard linkage mismatch".to_string());
            }
            if !self.tier_policies.contains_key(&offer.tier_id) {
                return Err("encrypted offer references unknown tier".to_string());
            }
            if offer.privacy_mode.disclosure_bps()
                > STATE_WITNESS_AVAILABILITY_MARKET_DEFAULT_MAX_BPS
            {
                return Err("encrypted offer privacy disclosure exceeds max".to_string());
            }
        }
        for (bid_id, bid) in &self.availability_bids {
            if bid_id != &bid.bid_id {
                return Err("availability bid map key mismatch".to_string());
            }
            bid.validate()?;
            let offer = self
                .encrypted_offers
                .get(&bid.offer_id)
                .ok_or_else(|| "availability bid references unknown offer".to_string())?;
            if offer.shard_id != bid.shard_id {
                return Err("availability bid offer shard mismatch".to_string());
            }
            if let Some(sponsor_id) = &bid.sponsor_id {
                if !self.fee_sponsorships.contains_key(sponsor_id) {
                    return Err("availability bid references unknown sponsorship".to_string());
                }
            }
        }
        for (cache_id, cache) in &self.prover_caches {
            if cache_id != &cache.cache_id {
                return Err("prover cache map key mismatch".to_string());
            }
            cache.validate()?;
            for shard_id in &cache.shard_ids {
                if !self.witness_shards.contains_key(shard_id) {
                    return Err("prover cache references unknown shard".to_string());
                }
            }
        }
        for (receipt_id, receipt) in &self.da_sampling_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("witness DA sampling receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.witness_shards.contains_key(&receipt.shard_id) {
                return Err("witness DA sampling receipt references unknown shard".to_string());
            }
            if !self.encrypted_offers.contains_key(&receipt.offer_id) {
                return Err("witness DA sampling receipt references unknown offer".to_string());
            }
        }
        for (ticket_id, ticket) in &self.retrieval_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("retrieval ticket map key mismatch".to_string());
            }
            ticket.validate()?;
            if !self.availability_bids.contains_key(&ticket.bid_id) {
                return Err("retrieval ticket references unknown bid".to_string());
            }
            if !self.encrypted_offers.contains_key(&ticket.offer_id) {
                return Err("retrieval ticket references unknown offer".to_string());
            }
        }
        for (evidence_id, evidence) in &self.slashing_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err("slashing evidence map key mismatch".to_string());
            }
            evidence.validate()?;
            if !self.witness_shards.contains_key(&evidence.shard_id) {
                return Err("slashing evidence references unknown shard".to_string());
            }
            if !self.encrypted_offers.contains_key(&evidence.offer_id) {
                return Err("slashing evidence references unknown offer".to_string());
            }
        }
        for (sponsorship_id, sponsorship) in &self.fee_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("fee sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
        }
        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err("state witness public record map key mismatch".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn state_witness_availability_market_state_root_from_record(record: &Value) -> String {
    state_witness_payload_root("STATE-WITNESS-AVAILABILITY-MARKET-STATE", record)
}

pub fn state_witness_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(domain, &[HashPart::Json(payload)], 32)
}

pub fn state_witness_string_root(domain: &str, value: &str) -> String {
    stable_hash_hex(domain, &[HashPart::Str(value)], 32)
}

pub fn devnet_hash(domain: &str, label: &str) -> String {
    stable_hash_hex(domain, &[HashPart::Str(label)], 32)
}

pub fn state_witness_tier_id(
    tier: WitnessTierKind,
    provider_id: &str,
    lane_keys: &BTreeSet<String>,
    pq_key_commitment: &str,
) -> String {
    let lanes = lane_keys.iter().cloned().collect::<Vec<_>>();
    stable_hash_hex(
        "STATE-WITNESS-TIER-ID",
        &[
            HashPart::Str(tier.as_str()),
            HashPart::Str(provider_id),
            HashPart::Json(&json!(lanes)),
            HashPart::Str(pq_key_commitment),
        ],
        32,
    )
}

pub fn state_witness_shard_id(
    batch_id: &str,
    lane_key: &str,
    domain: StateWitnessDomain,
    shard_kind: WitnessShardKind,
    shard_index: u64,
    encrypted_commitment: &str,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-SHARD-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(lane_key),
            HashPart::Str(domain.as_str()),
            HashPart::Str(shard_kind.as_str()),
            HashPart::Int(shard_index as i128),
            HashPart::Str(encrypted_commitment),
        ],
        32,
    )
}

pub fn state_witness_offer_id(
    shard_id: &str,
    provider_id: &str,
    tier_id: &str,
    kem_ciphertext_root: &str,
    posted_at_height: u64,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-OFFER-ID",
        &[
            HashPart::Str(shard_id),
            HashPart::Str(provider_id),
            HashPart::Str(tier_id),
            HashPart::Str(kem_ciphertext_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn state_witness_bid_id(
    offer_id: &str,
    requester_id: &str,
    purpose: RetrievalPurpose,
    max_fee_units: u64,
    requested_at_height: u64,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-BID-ID",
        &[
            HashPart::Str(offer_id),
            HashPart::Str(requester_id),
            HashPart::Str(purpose.as_str()),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

pub fn state_witness_cache_id(prover_id: &str, cache_root: &str, posted_at_height: u64) -> String {
    stable_hash_hex(
        "STATE-WITNESS-CACHE-ID",
        &[
            HashPart::Str(prover_id),
            HashPart::Str(cache_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn state_witness_sampling_receipt_id(
    offer_id: &str,
    sampler_id: &str,
    sampled_at_height: u64,
    sample_proof_root: &str,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-SAMPLING-RECEIPT-ID",
        &[
            HashPart::Str(offer_id),
            HashPart::Str(sampler_id),
            HashPart::Int(sampled_at_height as i128),
            HashPart::Str(sample_proof_root),
        ],
        32,
    )
}

pub fn state_witness_retrieval_ticket_id(
    bid_id: &str,
    offer_id: &str,
    requester_id: &str,
    retrieval_key_commitment: &str,
    issued_at_height: u64,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-RETRIEVAL-TICKET-ID",
        &[
            HashPart::Str(bid_id),
            HashPart::Str(offer_id),
            HashPart::Str(requester_id),
            HashPart::Str(retrieval_key_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn state_witness_slashing_evidence_id(
    kind: SlashingEvidenceKind,
    reporter_id: &str,
    accused_provider_id: &str,
    shard_id: &str,
    observed_root: &str,
    expected_root: &str,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(reporter_id),
            HashPart::Str(accused_provider_id),
            HashPart::Str(shard_id),
            HashPart::Str(observed_root),
            HashPart::Str(expected_root),
        ],
        32,
    )
}

pub fn state_witness_sponsorship_id(
    sponsor_id: &str,
    lane_key: &str,
    domain: StateWitnessDomain,
    fee_asset_id: &str,
    eligibility_root: &str,
    starts_at_height: u64,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_key),
            HashPart::Str(domain.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Str(eligibility_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn state_witness_public_record_id(
    record_kind: &str,
    subject_id: &str,
    subject_root: &str,
    summary_root: &str,
    published_at_height: u64,
) -> String {
    stable_hash_hex(
        "STATE-WITNESS-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(summary_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn witness_tier_policy_set_root(records: &[WitnessTierPolicy]) -> String {
    merkle_root(
        "STATE-WITNESS-TIER-POLICY-SET",
        &records
            .iter()
            .map(WitnessTierPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn witness_shard_set_root(records: &[WitnessShard]) -> String {
    merkle_root(
        "STATE-WITNESS-SHARD-SET",
        &records
            .iter()
            .map(WitnessShard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn encrypted_witness_offer_set_root(records: &[EncryptedWitnessOffer]) -> String {
    merkle_root(
        "STATE-WITNESS-ENCRYPTED-OFFER-SET",
        &records
            .iter()
            .map(EncryptedWitnessOffer::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn availability_bid_set_root(records: &[AvailabilityBid]) -> String {
    merkle_root(
        "STATE-WITNESS-AVAILABILITY-BID-SET",
        &records
            .iter()
            .map(AvailabilityBid::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn prover_cache_commitment_set_root(records: &[ProverCacheCommitment]) -> String {
    merkle_root(
        "STATE-WITNESS-PROVER-CACHE-SET",
        &records
            .iter()
            .map(ProverCacheCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn witness_da_sampling_receipt_set_root(records: &[WitnessDaSamplingReceipt]) -> String {
    merkle_root(
        "STATE-WITNESS-DA-SAMPLING-RECEIPT-SET",
        &records
            .iter()
            .map(WitnessDaSamplingReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn retrieval_ticket_set_root(records: &[RetrievalTicket]) -> String {
    merkle_root(
        "STATE-WITNESS-RETRIEVAL-TICKET-SET",
        &records
            .iter()
            .map(RetrievalTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_witness_slashing_evidence_set_root(
    records: &[StateWitnessSlashingEvidence],
) -> String {
    merkle_root(
        "STATE-WITNESS-SLASHING-EVIDENCE-SET",
        &records
            .iter()
            .map(StateWitnessSlashingEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn witness_fee_sponsorship_set_root(records: &[WitnessFeeSponsorship]) -> String {
    merkle_root(
        "STATE-WITNESS-FEE-SPONSORSHIP-SET",
        &records
            .iter()
            .map(WitnessFeeSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_witness_public_record_set_root(records: &[StateWitnessPublicRecord]) -> String {
    merkle_root(
        "STATE-WITNESS-PUBLIC-RECORD-SET",
        &records
            .iter()
            .map(StateWitnessPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn devnet_witness_shards(
    batch_id: &str,
    lane_key: &str,
    domain: StateWitnessDomain,
    shard_kind: WitnessShardKind,
    tier: WitnessTierKind,
    provider_id: &str,
    posted_at_height: u64,
    retention_blocks: u64,
    shard_count: u64,
) -> StateWitnessAvailabilityMarketResult<Vec<WitnessShard>> {
    if shard_count == 0 {
        return Err("devnet witness shards require non-zero shard count".to_string());
    }
    let mut shards = Vec::new();
    for shard_index in 0..shard_count {
        let label = format!("{batch_id}:{lane_key}:{shard_index}");
        shards.push(WitnessShard::new(
            batch_id,
            lane_key,
            domain,
            shard_kind,
            tier,
            shard_index,
            shard_count,
            8_192 + shard_index.saturating_mul(512),
            &devnet_hash("STATE-WITNESS-DEVNET-UNENCRYPTED", &label),
            &devnet_hash("STATE-WITNESS-DEVNET-ENCRYPTED", &label),
            &devnet_hash("STATE-WITNESS-DEVNET-OPENING", &label),
            &devnet_hash("STATE-WITNESS-DEVNET-STATE-BEFORE", batch_id),
            &devnet_hash("STATE-WITNESS-DEVNET-STATE-AFTER", batch_id),
            &devnet_hash("STATE-WITNESS-DEVNET-NULLIFIER", batch_id),
            provider_id,
            posted_at_height,
            retention_blocks,
            domain.default_priority(),
            &[
                domain.as_str().to_string(),
                tier.as_str().to_string(),
                "devnet".to_string(),
            ],
        )?);
    }
    Ok(shards)
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> StateWitnessAvailabilityMarketResult<()> {
    if records.contains_key(&key) {
        return Err(format!("duplicate {label}"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> StateWitnessAvailabilityMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_status(
    status: &str,
    allowed: &[&str],
    label: &str,
) -> StateWitnessAvailabilityMarketResult<()> {
    if allowed.iter().any(|candidate| candidate == &status) {
        Ok(())
    } else {
        Err(format!("{label} has invalid status {status}"))
    }
}
